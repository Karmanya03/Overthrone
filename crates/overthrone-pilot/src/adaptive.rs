//! Adaptive engine — Reacts to execution results, re-scores attack
//! paths, and decides whether to retry, skip, or pivot to alternatives.
//!
//! When a step fails, the adaptive engine:
//! 1. Classifies the failure (auth, network, detection, not_found)
//! 2. Decides: retry / skip / substitute / re-plan
//! 3. Updates priority scores for remaining steps
//! 4. Optionally triggers new enumeration to find new paths

use crate::goals::{AttackGoal, EngagementState};
use crate::planner::{AttackPlan, PlanStep, PlannedAction, StepResult};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Failure Classification
// ═══════════════════════════════════════════════════════════

/// Classified failure reason from a step execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureClass {
    /// Authentication failed — wrong creds or locked out
    AuthFailure,
    /// Network/connectivity issue — host unreachable
    NetworkError,
    /// Access denied — insufficient privileges
    AccessDenied,
    /// Target not found — service/object doesn't exist
    NotFound,
    /// Detection — action was likely blocked by security controls
    Detected,
    /// Timeout — operation took too long
    Timeout,
    /// Unknown / unclassified error
    Unknown,
}

impl FailureClass {
    /// Classify a failure from the error output string
    pub fn classify(output: &str) -> Self {
        let lower = output.to_lowercase();

        if lower.contains("auth") && lower.contains("fail")
            || lower.contains("logon failure")
            || lower.contains("wrong password")
            || lower.contains("pre-auth failed")
            || lower.contains("kdc_err_preauth_failed")
            || lower.contains("status_logon_failure")
            || lower.contains("invalid credentials")
        {
            return Self::AuthFailure;
        }

        if lower.contains("access denied")
            || lower.contains("status_access_denied")
            || lower.contains("insufficient")
            || lower.contains("privilege")
            || lower.contains("not allowed")
            || lower.contains("unauthorized")
        {
            return Self::AccessDenied;
        }

        if lower.contains("unreachable")
            || lower.contains("connection refused")
            || lower.contains("cannot reach")
            || lower.contains("connect failed")
            || lower.contains("network error")
            || lower.contains("no route")
            || lower.contains("reset by peer")
        {
            return Self::NetworkError;
        }

        if lower.contains("not found")
            || lower.contains("no such")
            || lower.contains("does not exist")
            || lower.contains("unknown principal")
            || lower.contains("c_principal_unknown")
            || lower.contains("s_principal_unknown")
        {
            return Self::NotFound;
        }

        if lower.contains("blocked")
            || lower.contains("quarantine")
            || lower.contains("antivirus")
            || lower.contains("defender")
            || lower.contains("amsi")
            || lower.contains("applocker")
            || lower.contains("constrained language")
            || lower.contains("script block logging")
        {
            return Self::Detected;
        }

        if lower.contains("timeout") || lower.contains("timed out") || lower.contains("deadline") {
            return Self::Timeout;
        }

        Self::Unknown
    }

    /// Human-readable label
    pub fn label(&self) -> &'static str {
        match self {
            Self::AuthFailure => "AUTH_FAIL",
            Self::NetworkError => "NET_ERROR",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::NotFound => "NOT_FOUND",
            Self::Detected => "DETECTED",
            Self::Timeout => "TIMEOUT",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Whether this failure is potentially transient (worth retrying)
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::NetworkError | Self::Timeout)
    }

    /// Whether this failure suggests we should avoid similar actions
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Detected | Self::AccessDenied)
    }
}

impl std::fmt::Display for FailureClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ═══════════════════════════════════════════════════════════
// Adaptive Decision
// ═══════════════════════════════════════════════════════════

/// What the adaptive engine decided to do after a step outcome
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptiveDecision {
    /// Continue to the next step as planned
    Continue,
    /// Retry the same step (with optional modifications)
    Retry {
        delay_secs: u64,
        modify: Option<StepModification>,
    },
    /// Skip this step and proceed
    Skip { reason: String },
    /// Substitute a different action for this step
    Substitute { replacement: PlannedAction },
    /// Re-plan from scratch with updated state
    Replan { reason: String },
    /// Abort the entire operation
    Abort { reason: String },
    /// Pause and wait for operator input
    PauseForOperator { message: String },
}

/// Modifications to apply when retrying
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepModification {
    /// Use different credentials
    SwapCredentials,
    /// Increase timeout
    ExtendTimeout,
    /// Use a stealthier method variant
    ReduceNoise,
    /// Try a different execution method (e.g., WMI instead of SMBExec)
    AlternateMethod,
}

// ═══════════════════════════════════════════════════════════
// Adaptive Engine
// ═══════════════════════════════════════════════════════════

/// The adaptive engine evaluates outcomes and adjusts the plan
pub struct AdaptiveEngine {
    /// Maximum retries per step before giving up
    #[allow(dead_code)] // Configuration field used in future retry logic
    max_retries: u32,
    /// Maximum total re-plans before aborting
    max_replans: u32,
    /// Current re-plan count
    replan_count: u32,
    /// Stealth mode — prefer quieter alternatives
    stealth: bool,
    /// Actions that have been permanently blacklisted
    blacklisted_actions: Vec<String>,
    /// Hosts that are unreachable
    dead_hosts: Vec<String>,
    /// Methods blocked by security controls on specific hosts
    blocked_methods: Vec<(String, String)>, // (host, method)
    /// Running tally of consecutive failures
    consecutive_failures: u32,
    /// Max consecutive failures before triggering re-plan
    failure_threshold: u32,
}

impl AdaptiveEngine {
    pub fn new(stealth: bool) -> Self {
        Self {
            max_retries: 3,
            max_replans: 5,
            replan_count: 0,
            stealth,
            blacklisted_actions: Vec::new(),
            dead_hosts: Vec::new(),
            blocked_methods: Vec::new(),
            consecutive_failures: 0,
            failure_threshold: 3,
        }
    }

    /// Reset consecutive failure counter (called on success)
    pub fn reset_failure_streak(&mut self) {
        self.consecutive_failures = 0;
    }

    /// Get the current consecutive failure count (used by Q-learner).
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Get list of failed/blacklisted action identifiers
    pub fn failed_actions(&self) -> &[String] {
        &self.blacklisted_actions
    }

    /// Whether we've exhausted all re-plan attempts
    pub fn replans_exhausted(&self) -> bool {
        self.replan_count >= self.max_replans
    }

    /// Evaluate a step result and decide what to do next
    pub fn evaluate(
        &mut self,
        step: &PlanStep,
        result: &StepResult,
        state: &EngagementState,
        goal: &AttackGoal,
    ) -> AdaptiveDecision {
        // ── Success path ──
        if result.success {
            self.reset_failure_streak();

            // Check if goal was achieved by this step
            let goal_status = state.evaluate_goal(goal);
            if goal_status.is_success() {
                info!(
                    "  {} Goal achieved after step: {}",
                    "🎯".green().bold(),
                    step.description
                );
                return AdaptiveDecision::Continue;
            }

            // If this step yielded new creds or admin hosts, consider re-planning
            // to take advantage of new capabilities
            if result.new_credentials > 0 || result.new_admin_hosts > 0 {
                info!(
                    "  {} New capabilities: +{} creds, +{} admin hosts → may re-plan",
                    "🔄".cyan(),
                    result.new_credentials,
                    result.new_admin_hosts
                );
                // Don't burn a re-plan on this; the runner will re-evaluate
            }

            return AdaptiveDecision::Continue;
        }

        // ── Failure path ──
        self.consecutive_failures += 1;
        let failure = FailureClass::classify(&result.output);

        warn!(
            "  {} Step failed [{}]: {} (attempt {}/{})",
            "⚠".yellow(),
            failure.label().red(),
            step.description,
            step.retries + 1,
            step.max_retries
        );

        // Classify and decide
        match failure {
            FailureClass::AuthFailure => self.handle_auth_failure(step, state),
            FailureClass::NetworkError => self.handle_network_error(step),
            FailureClass::AccessDenied => self.handle_access_denied(step, state),
            FailureClass::NotFound => self.handle_not_found(step),
            FailureClass::Detected => self.handle_detected(step),
            FailureClass::Timeout => self.handle_timeout(step),
            FailureClass::Unknown => self.handle_unknown(step),
        }
    }

    // ═══════════════════════════════════════════════════════
    // Per-failure-class handlers
    // ═══════════════════════════════════════════════════════

    fn handle_auth_failure(
        &mut self,
        _step: &PlanStep,
        state: &EngagementState,
    ) -> AdaptiveDecision {
        // If we have alternate credentials, try swapping
        if state.credentials.len() > 1 {
            info!(
                "  {} Auth failed — trying alternate credentials",
                "🔄".cyan()
            );
            return AdaptiveDecision::Retry {
                delay_secs: 2,
                modify: Some(StepModification::SwapCredentials),
            };
        }

        // No alternatives — skip and maybe re-plan if too many failures
        if self.consecutive_failures >= self.failure_threshold {
            self.trigger_replan("multiple auth failures — need new credentials")
        } else {
            AdaptiveDecision::Skip {
                reason: "Authentication failed, no alternate creds".to_string(),
            }
        }
    }

    fn handle_network_error(&mut self, step: &PlanStep) -> AdaptiveDecision {
        // Extract target from step action
        let target = self.extract_target(&step.action);

        if step.retries < step.max_retries {
            info!(
                "  {} Network error — retrying in 5s (transient)",
                "🔄".cyan()
            );
            AdaptiveDecision::Retry {
                delay_secs: 5,
                modify: Some(StepModification::ExtendTimeout),
            }
        } else {
            // Mark host as dead
            if let Some(host) = target
                && !self.dead_hosts.contains(&host)
            {
                self.dead_hosts.push(host.clone());
                warn!("  {} Host marked unreachable: {}", "☠".red(), host);
            }
            AdaptiveDecision::Skip {
                reason: "Host unreachable after retries".to_string(),
            }
        }
    }

    fn handle_access_denied(
        &mut self,
        step: &PlanStep,
        state: &EngagementState,
    ) -> AdaptiveDecision {
        // If we have higher-priv creds, swap
        if state.credentials.values().any(|c| c.is_admin) {
            return AdaptiveDecision::Retry {
                delay_secs: 1,
                modify: Some(StepModification::SwapCredentials),
            };
        }

        // Certain actions can be substituted with less-privileged alternatives
        if let Some(alt) = self.find_lower_priv_alternative(&step.action) {
            info!(
                "  {} Access denied — substituting lower-priv alternative",
                "🔄".cyan()
            );
            return AdaptiveDecision::Substitute { replacement: alt };
        }

        // Otherwise, we need more privileges — re-plan
        self.trigger_replan("access denied — need privilege escalation")
    }

    fn handle_not_found(&mut self, step: &PlanStep) -> AdaptiveDecision {
        // Target doesn't exist — skip, don't retry
        self.blacklisted_actions.push(step.id.clone());
        AdaptiveDecision::Skip {
            reason: "Target not found — skipping".to_string(),
        }
    }

    fn handle_detected(&mut self, step: &PlanStep) -> AdaptiveDecision {
        let target = self.extract_target(&step.action);

        warn!(
            "  {} DETECTION: {} was likely caught by security controls",
            "🚨".red().bold(),
            step.description
        );

        // Blacklist this method on this host
        if let Some(host) = target.clone() {
            let method = self.extract_method_name(&step.action);
            self.blocked_methods.push((host, method));
        }

        if self.stealth {
            // In stealth mode, try a quieter alternative
            if let Some(alt) = self.find_stealthier_alternative(&step.action) {
                info!("  {} Detected — trying stealthier method", "🔇".yellow());
                return AdaptiveDecision::Substitute { replacement: alt };
            }

            // If no alternatives, pause for operator
            return AdaptiveDecision::PauseForOperator {
                message: format!(
                    "Action '{}' was detected. Continue or abort?",
                    step.description
                ),
            };
        }

        // Non-stealth: just skip and continue
        AdaptiveDecision::Skip {
            reason: "Action detected by security controls".to_string(),
        }
    }

    fn handle_timeout(&mut self, step: &PlanStep) -> AdaptiveDecision {
        if step.retries < step.max_retries {
            AdaptiveDecision::Retry {
                delay_secs: 3,
                modify: Some(StepModification::ExtendTimeout),
            }
        } else {
            AdaptiveDecision::Skip {
                reason: "Timeout after max retries".to_string(),
            }
        }
    }

    fn handle_unknown(&mut self, step: &PlanStep) -> AdaptiveDecision {
        if step.retries < step.max_retries {
            AdaptiveDecision::Retry {
                delay_secs: 2,
                modify: None,
            }
        } else if self.consecutive_failures >= self.failure_threshold {
            self.trigger_replan("too many unknown failures")
        } else {
            AdaptiveDecision::Skip {
                reason: "Unknown failure after retries".to_string(),
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    // Re-planning
    // ═══════════════════════════════════════════════════════

    fn trigger_replan(&mut self, reason: &str) -> AdaptiveDecision {
        self.replan_count += 1;

        if self.replan_count > self.max_replans {
            warn!(
                "  {} Re-plan limit reached ({}/{})",
                "✗".red(),
                self.replan_count,
                self.max_replans
            );
            return AdaptiveDecision::Abort {
                reason: format!(
                    "Exhausted all {} re-plan attempts. Last failure: {}",
                    self.max_replans, reason
                ),
            };
        }

        info!(
            "  {} Re-planning ({}/{}) — {}",
            "🔄".blue().bold(),
            self.replan_count,
            self.max_replans,
            reason
        );
        self.consecutive_failures = 0;

        AdaptiveDecision::Replan {
            reason: reason.to_string(),
        }
    }

    // ═══════════════════════════════════════════════════════
    // Alternative Finders
    // ═══════════════════════════════════════════════════════

    /// Find a lower-privilege alternative for an action (public wrapper for Q-learner).
    pub fn find_lower_priv_alternative_pub(&self, action: &PlannedAction) -> Option<PlannedAction> {
        self.find_lower_priv_alternative(action)
    }

    /// Find a stealthier alternative for an action (public wrapper for Q-learner).
    pub fn find_stealthier_alternative_pub(&self, action: &PlannedAction) -> Option<PlannedAction> {
        self.find_stealthier_alternative(action)
    }

    /// Find a lower-privilege alternative for an action
    fn find_lower_priv_alternative(&self, action: &PlannedAction) -> Option<PlannedAction> {
        match action {
            // If PsExec fails (needs admin shares), try WMI
            PlannedAction::PsExec { target, command } => Some(PlannedAction::WmiExec {
                target: target.clone(),
                command: command.clone(),
            }),
            // If SMBExec fails, try WinRM
            PlannedAction::SmbExec { target, command } => Some(PlannedAction::WinRmExec {
                target: target.clone(),
                command: command.clone(),
            }),
            // If WMI fails, try WinRM
            PlannedAction::WmiExec { target, command } => Some(PlannedAction::WinRmExec {
                target: target.clone(),
                command: command.clone(),
            }),
            // NTDS dump requires DA — try SAM as fallback
            PlannedAction::DumpNtds { target } => Some(PlannedAction::DumpSam {
                target: target.clone(),
            }),
            // DCSync requires replication rights — try remote NTDS dump
            PlannedAction::DcsSync { .. } => None,
            _ => None,
        }
    }

    /// Find a stealthier alternative for an action
    fn find_stealthier_alternative(&self, action: &PlannedAction) -> Option<PlannedAction> {
        match action {
            // PSExec creates a visible service → use SMBExec (fileless) or WMI
            PlannedAction::PsExec { target, command } => Some(PlannedAction::WmiExec {
                target: target.clone(),
                command: command.clone(),
            }),
            // SMBExec (service cmd) → WinRM (PowerShell remoting, less logged)
            PlannedAction::SmbExec { target, command } => Some(PlannedAction::WinRmExec {
                target: target.clone(),
                command: command.clone(),
            }),
            // WMI detected → try WinRM
            PlannedAction::WmiExec { target, command } => Some(PlannedAction::WinRmExec {
                target: target.clone(),
                command: command.clone(),
            }),
            // Password spray detected → add jitter via Sleep + retry
            PlannedAction::PasswordSpray { users, password } => {
                if users.len() > 10 {
                    // Split into smaller batches (return first batch)
                    Some(PlannedAction::PasswordSpray {
                        users: users[..users.len() / 2].to_vec(),
                        password: password.clone(),
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Extract execution method name for tracking blocked methods
    fn extract_method_name(&self, action: &PlannedAction) -> String {
        match action {
            PlannedAction::PsExec { .. } => "psexec".to_string(),
            PlannedAction::SmbExec { .. } => "smbexec".to_string(),
            PlannedAction::WmiExec { .. } => "wmiexec".to_string(),
            PlannedAction::WinRmExec { .. } => "winrm".to_string(),
            PlannedAction::PasswordSpray { .. } => "spray".to_string(),
            PlannedAction::Kerberoast { .. } => "kerberoast".to_string(),
            PlannedAction::AsRepRoast { .. } => "asreproast".to_string(),
            PlannedAction::DcsSync { .. } => "dcsync".to_string(),
            other => format!("{:?}", other)
                .split('{')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_lowercase(),
        }
    }

    /// Extract target host from an action (if applicable)
    fn extract_target(&self, action: &PlannedAction) -> Option<String> {
        match action {
            PlannedAction::PsExec { target, .. }
            | PlannedAction::SmbExec { target, .. }
            | PlannedAction::WmiExec { target, .. }
            | PlannedAction::WinRmExec { target, .. }
            | PlannedAction::ExecCommand { target, .. }
            | PlannedAction::DumpSam { target }
            | PlannedAction::DumpLsa { target }
            | PlannedAction::DumpNtds { target }
            | PlannedAction::DumpDcc2 { target }
            | PlannedAction::EnumerateShares { target }
            | PlannedAction::Coerce { target, .. } => Some(target.clone()),
            _ => None,
        }
    }

    // ═══════════════════════════════════════════════════════
    // Plan Adjustment
    // ═══════════════════════════════════════════════════════

    /// Adjust remaining plan steps based on accumulated knowledge.
    /// Called before each step to prune dead paths.
    pub fn adjust_plan(&self, plan: &mut AttackPlan, state: &EngagementState) {
        let dead_hosts = &self.dead_hosts;
        let blocked = &self.blocked_methods;

        plan.steps.retain(|step| {
            // Remove steps targeting dead hosts
            if let Some(target) = self.extract_target(&step.action) {
                if dead_hosts.contains(&target) {
                    debug!(
                        "  {} Pruned step (dead host): {}",
                        "✂".dimmed(),
                        step.description
                    );
                    return false;
                }

                // Remove blocked method+host combos
                let method = self.extract_method_name(&step.action);
                if blocked.contains(&(target.clone(), method)) {
                    debug!(
                        "  {} Pruned step (blocked): {}",
                        "✂".dimmed(),
                        step.description
                    );
                    return false;
                }
            }

            // Remove already-blacklisted steps
            if self.blacklisted_actions.contains(&step.id) {
                debug!(
                    "  {} Pruned step (blacklisted): {}",
                    "✂".dimmed(),
                    step.description
                );
                return false;
            }

            true
        });

        // Boost priority of steps that leverage newly acquired credentials
        if state.has_any_admin() {
            for step in &mut plan.steps {
                match &step.action {
                    PlannedAction::DumpLsa { .. }
                    | PlannedAction::DumpSam { .. }
                    | PlannedAction::DcsSync { .. }
                    | PlannedAction::DumpNtds { .. } => {
                        step.priority += 20;
                    }
                    PlannedAction::SmbExec { .. }
                    | PlannedAction::PsExec { .. }
                    | PlannedAction::WmiExec { .. } => {
                        step.priority += 10;
                    }
                    _ => {}
                }
            }

            // Re-sort by priority
            plan.steps.sort_by(|a, b| b.priority.cmp(&a.priority));
        }
    }

    /// Generate a summary of adaptive decisions made during the engagement
    pub fn summary(&self) -> AdaptiveSummary {
        AdaptiveSummary {
            total_replans: self.replan_count,
            dead_hosts: self.dead_hosts.clone(),
            blocked_methods: self.blocked_methods.clone(),
            blacklisted_actions: self.blacklisted_actions.clone(),
        }
    }
}

/// Summary of all adaptive decisions for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveSummary {
    pub total_replans: u32,
    pub dead_hosts: Vec<String>,
    pub blocked_methods: Vec<(String, String)>,
    pub blacklisted_actions: Vec<String>,
}

impl std::fmt::Display for AdaptiveSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  Re-plans:   {}", self.total_replans)?;
        if !self.dead_hosts.is_empty() {
            writeln!(f, "  Dead hosts: {}", self.dead_hosts.join(", "))?;
        }
        if !self.blocked_methods.is_empty() {
            for (method, reason) in &self.blocked_methods {
                writeln!(f, "  Blocked:    {} ({})", method, reason)?;
            }
        }
        if !self.blacklisted_actions.is_empty() {
            writeln!(f, "  Blacklist:  {}", self.blacklisted_actions.join(", "))?;
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
// Credential Rotation for Retries
// ═══════════════════════════════════════════════════════════

/// Pick the next credential to try from the engagement state.
/// Returns (username, secret, is_hash).
pub fn rotate_credential(
    state: &EngagementState,
    current_user: &str,
) -> Option<(String, String, bool)> {
    // Find a different credential than the current one
    for cred in state.credentials.values() {
        if cred.username != current_user {
            let is_hash = cred.secret_type == crate::goals::SecretType::NtHash;
            return Some((cred.username.clone(), cred.secret.clone(), is_hash));
        }
    }
    None
}
