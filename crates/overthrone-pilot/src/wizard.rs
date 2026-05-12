//! Interactive Wizard Mode — Guides users through AD attacks with
//! pause points, decision prompts, and manual intervention options.
//!
//! Flow:
//!   1. Enumerate → Show results → Prompt to continue
//!   2. Attack    → Show captured hashes → Prompt to crack
//!   3. Escalate  → Show new creds → Prompt to switch
//!   4. Lateral   → Show admin access → Prompt to exploit
//!   5. Loot      → Show compromised data → Complete
//!
//! Features:
//!   - Real-time progress indicators (indicatif)
//!   - Checkpoint save/resume (serde_json)
//!   - Credential selection menus
//!   - Manual override at any stage
//!   - Comprehensive logging with comfy-table

use crate::adaptive::{AdaptiveDecision, AdaptiveEngine};
use crate::executor::{self, ExecContext};
use crate::goals::{AttackGoal, CompromisedCred, EngagementState, SecretType};
use crate::planner::{PlanStep, Planner};
#[cfg(feature = "qlearn")]
use crate::qlearner::{AdaptiveMode, AdaptiveQLearner, EngagementStateKey, decision_to_action};
use crate::runner::{AutoPwnConfig, AutoPwnConfigSnapshot, AutoPwnResult, Stage};
use crate::trail::TrailWriter;
use chrono::{DateTime, Utc};
use colored::Colorize;
use comfy_table::{Attribute, Cell, Color as TableColor, Table, presets::UTF8_FULL};
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;
use tokio::fs;
use tracing::{error, info, warn};

// ═══════════════════════════════════════════════════════════
// Wizard Session — serializable checkpoint form
// ═══════════════════════════════════════════════════════════

/// Serializable snapshot of a WizardSession (for checkpoint save/load).
/// Uses AutoPwnConfigSnapshot so Credentials private field is captured.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WizardSessionSnapshot {
    session_id: String,
    config: AutoPwnConfigSnapshot,
    state: EngagementState,
    current_stage: Stage,
    completed_stages: Vec<Stage>,
    checkpoint_path: PathBuf,
    started_at: DateTime<Utc>,
    pause_after_stage: bool,
    auto_crack: bool,
    max_pause_secs: Option<u64>,
}

// ═══════════════════════════════════════════════════════════
// Wizard Session — Main interactive controller
// ═══════════════════════════════════════════════════════════

pub struct WizardSession {
    pub session_id: String,
    pub config: AutoPwnConfig,
    pub state: EngagementState,
    pub current_stage: Stage,
    pub completed_stages: Vec<Stage>,
    pub checkpoint_path: PathBuf,
    pub started_at: DateTime<Utc>,
    pub pause_after_stage: bool,
    pub auto_crack: bool,
    pub max_pause_secs: Option<u64>,
}

impl WizardSession {
    pub fn new(config: AutoPwnConfig, checkpoint_dir: Option<PathBuf>) -> Self {
        let session_id = format!("wiz_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        let checkpoint_path = checkpoint_dir
            .unwrap_or_else(|| PathBuf::from("./checkpoints"))
            .join(format!("{}.json", session_id));

        let mut state = EngagementState::new();
        state.domain = Some(config.creds.domain.clone());
        state.dc_ip = Some(config.dc_host.clone());

        Self {
            session_id,
            config,
            state,
            current_stage: Stage::Enumerate,
            completed_stages: Vec::new(),
            checkpoint_path,
            started_at: Utc::now(),
            pause_after_stage: true,
            auto_crack: true,
            max_pause_secs: Some(300),
        }
    }

    /// Load a WizardSession from a checkpoint file.
    pub async fn from_checkpoint(path: PathBuf) -> Result<Self> {
        let data = fs::read_to_string(&path)
            .await
            .map_err(|e| OverthroneError::custom(format!("Failed to read checkpoint: {}", e)))?;
        let snap: WizardSessionSnapshot = serde_json::from_str(&data)
            .map_err(|e| OverthroneError::custom(format!("Failed to parse checkpoint: {}", e)))?;

        let config = AutoPwnConfig::from_snapshot(snap.config);
        info!(
            "✓ Resumed session: {} from {}",
            snap.session_id.bold(),
            path.display()
        );

        Ok(Self {
            session_id: snap.session_id,
            config,
            state: snap.state,
            current_stage: snap.current_stage,
            completed_stages: snap.completed_stages,
            checkpoint_path: snap.checkpoint_path,
            started_at: snap.started_at,
            pause_after_stage: snap.pause_after_stage,
            auto_crack: snap.auto_crack,
            max_pause_secs: snap.max_pause_secs,
        })
    }

    /// Save current state to checkpoint JSON.
    pub async fn save_checkpoint(&self) -> Result<()> {
        if let Some(parent) = self.checkpoint_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                OverthroneError::custom(format!("Failed to create checkpoint dir: {}", e))
            })?;
        }

        let snap = WizardSessionSnapshot {
            session_id: self.session_id.clone(),
            config: self.config.to_snapshot(),
            state: self.state.clone(),
            current_stage: self.current_stage,
            completed_stages: self.completed_stages.clone(),
            checkpoint_path: self.checkpoint_path.clone(),
            started_at: self.started_at,
            pause_after_stage: self.pause_after_stage,
            auto_crack: self.auto_crack,
            max_pause_secs: self.max_pause_secs,
        };

        let json = serde_json::to_string_pretty(&snap)
            .map_err(|e| OverthroneError::custom(format!("Failed to serialize session: {}", e)))?;
        fs::write(&self.checkpoint_path, json)
            .await
            .map_err(|e| OverthroneError::custom(format!("Failed to write checkpoint: {}", e)))?;

        info!(
            "💾 Checkpoint saved: {}",
            self.checkpoint_path.display().to_string().dimmed()
        );
        Ok(())
    }

    // ── Main wizard run ──
    pub async fn run(&mut self) -> Result<AutoPwnResult> {
        let wall_start = Instant::now();
        print_wizard_banner(&self.config);

        let goal = self.config.goal();
        let trail = match TrailWriter::start(
            "Wizard",
            &self.config.creds.domain,
            &self.config.dc_host,
            &goal.describe(),
            !self.completed_stages.is_empty(),
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
                warn!("wizard trail file initialization failed: {e}");
                None
            }
        };
        let planner = Planner::new(self.config.stealth);
        let mut adaptive = AdaptiveEngine::new(self.config.stealth);
        #[cfg(feature = "qlearn")]
        let mut qlearner: Option<AdaptiveQLearner> = match self.config.adaptive_mode {
            AdaptiveMode::QLearning | AdaptiveMode::Hybrid => {
                let ql =
                    AdaptiveQLearner::load(self.config.stealth, self.config.q_table_path.clone());
                println!(
                    "  {} Wizard Q-learner loaded (mode={:?}, states={}, ε={:.3})",
                    "QL".bold().magenta(),
                    self.config.adaptive_mode,
                    ql.q_table_size(),
                    ql.epsilon()
                );
                Some(ql)
            }
            AdaptiveMode::Heuristic => None,
        };
        let mut ctx = self.config.exec_context();

        // ── LDAP Pre-flight Check ──
        if !self.config.dry_run {
            println!(
                "  {} Pre-flight LDAP connectivity check...",
                "PRE".bold().cyan()
            );
            if ctx.use_hash {
                println!(
                    "  {} LDAP pre-flight skipped (pass-the-hash mode).",
                    "!".yellow().bold()
                );
                ctx.ldap_available = false;
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
                            "✓".green().bold(),
                            session.bind_type
                        );
                        let _ = session.disconnect().await;
                    }
                    Err(e) => {
                        println!("  {} LDAP pre-flight failed: {}", "✗".red().bold(), e);
                        println!(
                            "  {} LDAP-dependent enumeration steps will be skipped.",
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

        let all_stages = vec![
            Stage::Enumerate,
            Stage::Attack,
            Stage::Escalate,
            Stage::Lateral,
            Stage::Loot,
        ];

        for stage in all_stages {
            // Skip already-completed stages (resume support)
            if self.completed_stages.contains(&stage) {
                info!("⏭  Skipping completed stage: {}", stage);
                continue;
            }

            if stage > self.config.max_stage {
                info!("⊘ Stage {} exceeds max_stage, stopping", stage);
                break;
            }

            self.current_stage = stage;
            print_stage_banner(stage);

            // Build plan and filter to this stage
            let mut plan = planner.plan(
                &goal,
                &self.state,
                adaptive.failed_actions(),
                ctx.ldap_available,
            );
            adaptive.adjust_plan(&mut plan, &self.state);

            let stage_steps: Vec<PlanStep> = plan
                .steps
                .iter()
                .filter(|s| s.stage == stage && !s.executed)
                .cloned()
                .collect();

            if stage_steps.is_empty() {
                info!("  {} No actions planned for stage {}", "ℹ".blue(), stage);
                self.completed_stages.push(stage);
                self.save_checkpoint().await?;
                continue;
            }

            if let Some(writer) = &trail {
                writer.append_stage(stage, stage_steps.len());
            }

            info!(
                "  {} {} planned actions",
                stage_steps.len().to_string().bold(),
                stage
            );

            // Progress bar for stage
            let pb = ProgressBar::new(stage_steps.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("  {spinner:.cyan} [{bar:30.cyan/dim}] {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("█▓░"),
            );

            let mut need_replan = false;

            for mut step in stage_steps {
                pb.set_message(step.description.clone());

                let result = executor::execute_step(&step, &ctx, &mut self.state).await;
                steps_executed += 1;

                if result.success {
                    steps_succeeded += 1;
                } else {
                    steps_failed += 1;
                }

                step.executed = true;
                step.result = Some(result.clone());
                if let Some(writer) = &trail {
                    writer.append_step(&step, &result, &self.state);
                }

                #[cfg(feature = "qlearn")]
                let pre_state_key = qlearner.as_ref().map(|ql| {
                    EngagementStateKey::encode(
                        &self.state,
                        &step,
                        &result,
                        self.config.stealth,
                        ql.consecutive_failures(),
                    )
                });

                #[cfg(feature = "qlearn")]
                if let (Some(ql), Some(key)) = (&qlearner, &pre_state_key) {
                    let state_snapshot = AdaptiveQLearner::format_state_snapshot(key, ql.epsilon());
                    println!(
                        "  {}  {} state={{{}}}",
                        "│".dimmed(),
                        "[QL]".magenta().bold(),
                        state_snapshot.dimmed(),
                    );
                    if let Some(writer) = &trail {
                        writer.append_decision("QL state", state_snapshot);
                    }
                }

                #[cfg(feature = "qlearn")]
                let decision = if let Some(ref mut ql) = qlearner {
                    ql.evaluate(&step, &result, &self.state, &goal)
                } else {
                    adaptive.evaluate(&step, &result, &self.state, &goal)
                };
                #[cfg(not(feature = "qlearn"))]
                let decision = adaptive.evaluate(&step, &result, &self.state, &goal);

                #[cfg(feature = "qlearn")]
                if let Some(ref ql) = qlearner
                    && let Some((action, q_val, exploring)) = ql.last_decision_meta()
                {
                    let decision_snapshot =
                        AdaptiveQLearner::format_decision(action, *q_val, *exploring);
                    println!(
                        "  {}  {} -> {}",
                        "│".dimmed(),
                        "[QL]".magenta().bold(),
                        decision_snapshot.cyan(),
                    );
                    if let Some(writer) = &trail {
                        writer.append_decision("QL decision", decision_snapshot);
                    }
                }

                #[cfg(feature = "qlearn")]
                if let (Some(ql), Some(pre_key)) = (&mut qlearner, &pre_state_key) {
                    let goal_achieved = self.state.evaluate_goal(&goal).is_success();
                    let reward =
                        AdaptiveQLearner::compute_reward(&result, goal_achieved, &decision);
                    let action = decision_to_action(&decision);
                    let post_key = EngagementStateKey::encode(
                        &self.state,
                        &step,
                        &result,
                        self.config.stealth,
                        ql.consecutive_failures(),
                    );
                    ql.record_outcome(pre_key, &action, reward, &post_key);
                    let reward_snapshot =
                        format!("reward={:+.1} table={} states", reward, ql.q_table_size());
                    println!(
                        "  {}  {} reward={:+.1} table={} states",
                        "│".dimmed(),
                        "[QL]".magenta().bold(),
                        reward,
                        ql.q_table_size(),
                    );
                    if let Some(writer) = &trail {
                        writer.append_decision("QL reward", reward_snapshot);
                    }
                }

                if let Some(writer) = &trail {
                    writer.append_decision("Wizard decision", format!("{:?}", decision));
                }

                match decision {
                    AdaptiveDecision::Replan { reason } => {
                        warn!("  🔄 Re-planning: {}", reason);
                        need_replan = true;
                        break;
                    }
                    AdaptiveDecision::Abort { reason } => {
                        error!("  ✗ Aborting: {}", reason);
                        pb.finish_with_message("Aborted".to_string());
                        if let Some(writer) = &trail {
                            writer.append_final(
                                &self.state,
                                format!(
                                    "Wizard aborted: {}. Steps executed: `{}`. Succeeded: `{}`. Failed: `{}`.",
                                    reason, steps_executed, steps_succeeded, steps_failed
                                ),
                            );
                        }
                        #[cfg(feature = "qlearn")]
                        if let Some(ref mut ql) = qlearner {
                            ql.end_episode();
                            if let Err(e) = ql.save() {
                                warn!("Wizard Q-learner save failed: {e}");
                            }
                        }
                        return self
                            .finalize(
                                goal,
                                wall_start,
                                steps_executed,
                                steps_succeeded,
                                steps_failed,
                            )
                            .await;
                    }
                    _ => {}
                }

                pb.inc(1);
                ctx.jitter().await;
            }

            pb.finish_with_message(format!("{} complete", stage));

            // Mark stage done + persist checkpoint
            self.completed_stages.push(stage);
            self.display_stage_results(stage).await?;
            self.save_checkpoint().await?;

            // Early exit if goal achieved
            if self.state.evaluate_goal(&goal).is_success() {
                info!(
                    "\n  {} {} achieved!",
                    "🎯".bold(),
                    goal.describe().green().bold()
                );
                break;
            }

            // Interactive prompt between stages
            if self.pause_after_stage && !need_replan {
                let decision = self.prompt_stage_transition(stage, &mut ctx).await?;
                match decision {
                    StageDecision::Continue => continue,
                    StageDecision::Skip => {
                        info!("  ⏭ Skipping to next stage");
                        continue;
                    }
                    StageDecision::Abort => {
                        info!("  ⏹ User aborted");
                        break;
                    }
                    StageDecision::SwitchCreds(cred) => {
                        info!("  🔑 Switching to: {}", cred.username.bold());
                        ctx.override_creds = Some((
                            cred.username.clone(),
                            cred.secret.clone(),
                            cred.secret_type == SecretType::NtHash,
                        ));
                    }
                    StageDecision::Replan => {
                        info!("  🔄 Re-planning from current state");
                    }
                }
            }
        }

        let mut final_summary = format!(
            "Wizard completed. Steps executed: `{}`. Succeeded: `{}`. Failed: `{}`. Duration: `{}` seconds.",
            steps_executed,
            steps_succeeded,
            steps_failed,
            wall_start.elapsed().as_secs()
        );
        #[cfg(feature = "qlearn")]
        if let Some(ref ql) = qlearner {
            final_summary.push_str(&format!(" Q-learner: {}", ql.session_summary()));
        }
        if let Some(writer) = &trail {
            writer.append_final(&self.state, final_summary);
        }

        #[cfg(feature = "qlearn")]
        if let Some(ref mut ql) = qlearner {
            ql.end_episode();
            if let Err(e) = ql.save() {
                warn!("Wizard Q-learner save failed: {e}");
            }
        }

        self.finalize(
            goal,
            wall_start,
            steps_executed,
            steps_succeeded,
            steps_failed,
        )
        .await
    }

    // ── Stage results display ──
    async fn display_stage_results(&self, stage: Stage) -> Result<()> {
        println!("\n{}", "═══ STAGE RESULTS ═══".bold().cyan());

        match stage {
            Stage::Enumerate => {
                let mut table = Table::new();
                table
                    .load_preset(UTF8_FULL)
                    .set_header(vec!["Category", "Count", "Notable"]);

                table.add_row(vec![
                    Cell::new("Users").fg(TableColor::Cyan),
                    Cell::new(self.state.users.len()),
                    Cell::new(format!(
                        "{} admin★",
                        self.state.users.iter().filter(|u| u.admin_count).count()
                    ))
                    .fg(TableColor::Yellow),
                ]);
                table.add_row(vec![
                    Cell::new("Computers").fg(TableColor::Cyan),
                    Cell::new(self.state.computers.len()),
                    Cell::new(format!(
                        "{} DCs",
                        self.state.computers.iter().filter(|c| c.is_dc).count()
                    ))
                    .fg(TableColor::Red),
                ]);
                table.add_row(vec![
                    Cell::new("Kerberoastable").fg(TableColor::Cyan),
                    Cell::new(self.state.kerberoastable.len()).fg(TableColor::Yellow),
                    Cell::new(if self.state.kerberoastable.is_empty() {
                        "-"
                    } else {
                        "Ready to roast"
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("AS-REP Roastable").fg(TableColor::Cyan),
                    Cell::new(self.state.asrep_roastable.len()).fg(TableColor::Yellow),
                    Cell::new(if self.state.asrep_roastable.is_empty() {
                        "-"
                    } else {
                        "Ready to roast"
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("Password Policy").fg(TableColor::Cyan),
                    Cell::new(if self.state.password_policy.is_some() {
                        "known"
                    } else {
                        "unknown"
                    }),
                    Cell::new(self.state.spray_risk_summary()).fg(TableColor::Yellow),
                ]);
                table.add_row(vec![
                    Cell::new("GPOs").fg(TableColor::Cyan),
                    Cell::new(self.state.gpo_details.len().max(self.state.gpos.len())),
                    Cell::new(format!(
                        "{} changed/linked policies tracked",
                        self.state.gpo_details.len()
                    )),
                ]);
                table.add_row(vec![
                    Cell::new("LAPS").fg(TableColor::Cyan),
                    Cell::new(self.state.readable_laps_count()).fg(TableColor::Green),
                    Cell::new("Readable local admin passwords"),
                ]);
                table.add_row(vec![
                    Cell::new("Delegations").fg(TableColor::Cyan),
                    Cell::new(self.state.delegation_count()).fg(TableColor::Yellow),
                    Cell::new(format!(
                        "{} constrained / {} RBCD",
                        self.state.constrained_delegation.len(),
                        self.state.rbcd_targets.len()
                    )),
                ]);
                table.add_row(vec![
                    Cell::new("Unconstrained Deleg").fg(TableColor::Cyan),
                    Cell::new(self.state.unconstrained_delegation.len()).fg(TableColor::Red),
                    Cell::new(if self.state.unconstrained_delegation.is_empty() {
                        "-"
                    } else {
                        "High-value targets"
                    }),
                ]);

                println!("{}", table);
            }

            Stage::Attack => {
                let new_creds: Vec<_> = self
                    .state
                    .credentials
                    .values()
                    .filter(|c| c.source.contains("roast") || c.source.contains("spray"))
                    .collect();

                if !new_creds.is_empty() {
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL).set_header(vec![
                        "Username",
                        "Type",
                        "Hash/Password",
                        "Source",
                    ]);

                    for cred in new_creds.iter().take(10) {
                        let secret_preview = if cred.secret.len() > 32 {
                            format!("{}...", &cred.secret[..32])
                        } else {
                            cred.secret.clone()
                        };
                        table.add_row(vec![
                            Cell::new(&cred.username)
                                .fg(TableColor::Cyan)
                                .add_attribute(Attribute::Bold),
                            Cell::new(format!("{:?}", cred.secret_type)).fg(TableColor::Yellow),
                            Cell::new(secret_preview).fg(TableColor::Red),
                            Cell::new(&cred.source).fg(TableColor::DarkGrey),
                        ]);
                    }
                    println!("{}", table);
                    info!(
                        "  ✓ Total credentials captured: {}",
                        new_creds.len().to_string().bold().green()
                    );

                    // NtHash covers both NTLM hashes and Kerberoast RC4 ticket hashes.
                    // AesKey covers AES Kerberos ticket hashes.
                    let hash_count = new_creds
                        .iter()
                        .filter(|c| {
                            matches!(c.secret_type, SecretType::NtHash | SecretType::AesKey)
                        })
                        .count();

                    if hash_count > 0 && self.auto_crack {
                        println!("\n🔓 Found {} hashes", hash_count.to_string().bold());
                        if self
                            .prompt_yes_no("Attempt offline cracking?", true)
                            .await?
                        {
                            info!("  ⚙  Cracking queued — runs as part of CrackHashes step");
                        }
                    }
                } else {
                    info!("  {} No new credentials captured", "ℹ".blue());
                }
            }

            Stage::Escalate => {
                if !self.state.admin_hosts.is_empty() {
                    let mut table = Table::new();
                    table
                        .load_preset(UTF8_FULL)
                        .set_header(vec!["Admin Access Host", "Loot Available"]);

                    for host in self.state.admin_hosts.iter().take(10) {
                        let loot = self
                            .state
                            .loot
                            .iter()
                            .filter(|l| l.source == *host)
                            .map(|l| l.loot_type.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        table.add_row(vec![
                            Cell::new(host)
                                .fg(TableColor::Green)
                                .add_attribute(Attribute::Bold),
                            Cell::new(if loot.is_empty() { "None yet" } else { &loot }),
                        ]);
                    }
                    println!("{}", table);
                } else {
                    info!("  {} No admin access gained yet", "ℹ".yellow());
                }
            }

            Stage::Lateral => {
                let dc_access =
                    self.state.admin_hosts.iter().any(|h| {
                        h.contains("dc") || Some(h.as_str()) == self.state.dc_ip.as_deref()
                    });
                if dc_access {
                    info!(
                        "  {} {} DC ACCESS ACHIEVED",
                        "✓".green().bold(),
                        "🎯".bold()
                    );
                } else {
                    info!("  {} Lateral movement in progress", "ℹ".yellow());
                }
            }

            Stage::Loot => {
                if !self.state.loot.is_empty() {
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL).set_header(vec![
                        "Type",
                        "Source",
                        "Entries",
                        "Timestamp",
                    ]);

                    for item in &self.state.loot {
                        table.add_row(vec![
                            Cell::new(&item.loot_type)
                                .fg(TableColor::Red)
                                .add_attribute(Attribute::Bold),
                            Cell::new(&item.source),
                            Cell::new(item.entries).fg(TableColor::Yellow),
                            Cell::new(item.collected_at.format("%H:%M:%S").to_string())
                                .fg(TableColor::DarkGrey),
                        ]);
                    }
                    println!("{}", table);

                    let total_entries: usize = self.state.loot.iter().map(|l| l.entries).sum();
                    info!(
                        "  💰 Total loot: {} items, {} entries",
                        self.state.loot.len().to_string().bold().green(),
                        total_entries.to_string().bold().yellow()
                    );
                }
            }

            Stage::Cleanup => {
                info!("  🧹 Cleanup stage");
            }
        }

        println!("{}", "══════════════════════".cyan());
        Ok(())
    }

    // ── Interactive stage transition prompt ──
    async fn prompt_stage_transition(
        &self,
        completed_stage: Stage,
        ctx: &mut ExecContext,
    ) -> Result<StageDecision> {
        println!();

        // Offer credential switch if new creds appeared this stage
        let current_user = ctx.effective_creds().0.to_string();
        let available_creds: Vec<_> = self
            .state
            .credentials
            .values()
            .filter(|c| c.username != current_user)
            .collect();

        if !available_creds.is_empty() && completed_stage == Stage::Attack {
            println!(
                "🔑 {} new credential(s) available",
                available_creds.len().to_string().bold()
            );
            if self
                .prompt_yes_no("Switch to a different credential?", false)
                .await?
            {
                return self.prompt_credential_selection(&available_creds).await;
            }
        }

        let next_stage = match completed_stage {
            Stage::Enumerate => Stage::Attack,
            Stage::Attack => Stage::Escalate,
            Stage::Escalate => Stage::Lateral,
            Stage::Lateral => Stage::Loot,
            _ => return Ok(StageDecision::Continue),
        };

        println!(
            "\n{} {} → {}",
            "Next:".bold(),
            completed_stage.to_string().dimmed(),
            next_stage.to_string().bold().cyan()
        );

        print!("Continue? [Y/n/skip/abort/replan]: ");
        io::stdout().flush().unwrap();

        let input = self.read_input_with_timeout().await?;
        match input.trim().to_lowercase().as_str() {
            "" | "y" | "yes" => Ok(StageDecision::Continue),
            "n" | "no" | "skip" => Ok(StageDecision::Skip),
            "abort" | "quit" | "exit" => Ok(StageDecision::Abort),
            "replan" => Ok(StageDecision::Replan),
            _ => {
                warn!("  Invalid choice, continuing...");
                Ok(StageDecision::Continue)
            }
        }
    }

    async fn prompt_credential_selection(
        &self,
        creds: &[&CompromisedCred],
    ) -> Result<StageDecision> {
        println!("\n{}", "Available Credentials:".bold());
        for (idx, cred) in creds.iter().enumerate() {
            let preview = if cred.secret_type == SecretType::Password {
                cred.secret.chars().take(20).collect::<String>()
            } else {
                format!("{:?} hash", cred.secret_type)
            };
            println!(
                "  {} {} → {} ({})",
                format!("[{}]", idx + 1).bold().cyan(),
                cred.username.bold(),
                preview.red(),
                cred.source.dimmed()
            );
        }
        println!("  {} Keep current", "[0]".bold().dimmed());
        print!("\nSelect [0-{}]: ", creds.len());
        io::stdout().flush().unwrap();

        let input = self.read_input_with_timeout().await?;
        let choice = input.trim().parse::<usize>().unwrap_or(0);

        if choice > 0 && choice <= creds.len() {
            Ok(StageDecision::SwitchCreds((*creds[choice - 1]).clone()))
        } else {
            Ok(StageDecision::Continue)
        }
    }

    async fn prompt_yes_no(&self, question: &str, default: bool) -> Result<bool> {
        let prompt = if default {
            format!("{} [Y/n]: ", question)
        } else {
            format!("{} [y/N]: ", question)
        };
        print!("{}", prompt);
        io::stdout().flush().unwrap();

        let input = self.read_input_with_timeout().await?;
        Ok(match input.trim().to_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            "n" | "no" => false,
            _ => default,
        })
    }

    async fn read_input_with_timeout(&self) -> Result<String> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        if let Some(timeout_secs) = self.max_pause_secs {
            match tokio::time::timeout(tokio::time::Duration::from_secs(timeout_secs), async {
                let stdin = tokio::io::stdin();
                let mut reader = BufReader::new(stdin);
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .await
                    .map_err(|e| OverthroneError::custom(format!("stdin: {}", e)))?;
                Ok::<String, OverthroneError>(line)
            })
            .await
            {
                Ok(Ok(input)) => Ok(input),
                Ok(Err(e)) => Err(e),
                Err(_) => {
                    warn!("\n  ⏱ Input timeout ({}s), auto-continuing", timeout_secs);
                    Ok(String::new())
                }
            }
        } else {
            let mut line = String::new();
            io::stdin()
                .read_line(&mut line)
                .map_err(|e| OverthroneError::custom(format!("stdin: {}", e)))?;
            Ok(line)
        }
    }

    async fn finalize(
        &self,
        goal: AttackGoal,
        wall_start: Instant,
        steps_executed: usize,
        steps_succeeded: usize,
        steps_failed: usize,
    ) -> Result<AutoPwnResult> {
        use crate::adaptive::AdaptiveSummary;

        let duration_secs = wall_start.elapsed().as_secs();
        let finished_at = Utc::now();
        let final_status = self.state.evaluate_goal(&goal);
        let da_achieved = final_status.is_success() || self.state.has_domain_admin;

        println!(
            "\n{}",
            "╔══════════════════════════════════════════════╗"
                .bold()
                .green()
        );
        println!(
            "{}",
            "║         WIZARD — FINAL REPORT                ║"
                .bold()
                .green()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════════════╝"
                .bold()
                .green()
        );

        self.state.print_summary();

        println!(
            "  Goal:       {} → {}",
            goal.describe().bold(),
            if da_achieved {
                "ACHIEVED".green().bold()
            } else {
                "NOT ACHIEVED".red()
            }
        );
        println!(
            "  Stages:     {} completed",
            self.completed_stages.len().to_string().bold()
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
                format!(
                    "ACHIEVED ({})",
                    self.state.da_user.as_deref().unwrap_or("?")
                )
                .green()
                .bold()
                .to_string()
            } else {
                "NOT ACHIEVED".red().to_string()
            }
        );

        if da_achieved {
            let _ = fs::remove_file(&self.checkpoint_path).await;
            info!("  🗑  Checkpoint cleaned up (goal achieved)");
        }

        Ok(AutoPwnResult {
            domain_admin_achieved: da_achieved,
            goal_status: final_status,
            state: self.state.clone(),
            adaptive_summary: AdaptiveSummary {
                total_replans: 0,
                dead_hosts: vec![],
                blocked_methods: vec![],
                blacklisted_actions: vec![],
            },
            duration_secs,
            started_at: self.started_at,
            finished_at,
            steps_executed,
            steps_succeeded,
            steps_failed,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// Stage Decision
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub enum StageDecision {
    Continue,
    Skip,
    Abort,
    SwitchCreds(CompromisedCred),
    Replan,
}

// ═══════════════════════════════════════════════════════════
// UI Helpers
// ═══════════════════════════════════════════════════════════

fn print_wizard_banner(config: &AutoPwnConfig) {
    println!(
        "\n{}",
        "╔══════════════════════════════════════════════╗"
            .bold()
            .magenta()
    );
    println!(
        "{}",
        "║      OVERTHRONE — INTERACTIVE WIZARD         ║"
            .bold()
            .magenta()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════╝"
            .bold()
            .magenta()
    );
    println!("\n  Target:   {}", config.target.bold().cyan());
    println!("  DC:       {}", config.dc_host.bold());
    println!("  Domain:   {}", config.creds.domain.bold());
    println!("  User:     {}", config.creds.username.bold());
    println!(
        "  Stealth:  {}",
        if config.stealth {
            "ON".green()
        } else {
            "OFF".yellow()
        }
    );
    println!();
}

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
