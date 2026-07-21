//! Autonomous attack chain entry point.
//!
//! The `auto-pwn` CLI subcommand dispatches here, which delegates to
//! `overthrone_pilot::runner` for plan--execute loops, Q-learning adaptation,
//! playbook execution, and session management.

use crate::banner;
use colored::Colorize;

/// Remote execution method preference.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ExecMethod {
 #[value(name = "ps-exec", alias = "psexec")]
 PsExec,
 #[value(name = "smb-exec", alias = "smbexec")]
 SmbExec,
 #[value(name = "wmi-exec", alias = "wmiexec")]
 WmiExec,
 #[value(name = "win-rm", alias = "winrm")]
 WinRm,
 Auto,
}

impl std::fmt::Display for ExecMethod {
 fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
 match self {
 Self::PsExec => write!(f, "psexec"),
 Self::SmbExec => write!(f, "smbexec"),
 Self::WmiExec => write!(f, "wmiexec"),
 Self::WinRm => write!(f, "winrm"),
 Self::Auto => write!(f, "auto"),
 }
 }
}

/// CLI-argument shim that feeds into the pilot runner.
/// Constructed by `cmd_autopwn` in main.rs from parsed subcommand fields.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AutoPwnArgs {
 pub target: String,
 pub method: ExecMethod,
 pub stealth: bool,
 pub dry_run: bool,
 pub max_stage: MaxStageArg,
 pub adaptive: AdaptiveModeArg,
 pub q_table: String,
 pub jitter_ms: u64,
 pub ldaps: bool,
 pub timeout: u64,
 pub playbook: Option<PlaybookArg>,
 pub config: Option<String>,
 pub resume: Option<String>,
 pub bootstrap_no_creds: bool,
 pub userlist: Option<String>,
 pub use_ldap: bool,
 pub concurrency: usize,
 pub no_dc_verify: bool,
 pub no_dc_verify_dns: bool,
}

/// Maximum stage the autonomous pipeline should attempt to reach.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum MaxStageArg {
 Enumerate,
 Attack,
 Escalate,
 Lateral,
 Loot,
 Cleanup,
}

/// Adaptive planning engine mode.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum AdaptiveModeArg {
 /// Pure heuristic engine (original)
 Heuristic,
 /// Pure Q-learning (falls back to heuristic for unknown states)
 Qlearning,
 /// Hybrid -- Q-learner with epsilon-greedy heuristic fallback (recommended)
 Hybrid,
}

/// Predefined playbooks.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum PlaybookArg {
 FullRecon,
 RoastAndCrack,
 DelegationAbuse,
 RbcdChain,
 CoerceAndRelay,
 LateralPivot,
 DcSyncDump,
 GoldenTicket,
 FullAutoPwn,
}

/// Build the [`overthrone_pilot::runner::AutoPwnConfig`] from CLI arguments
/// and credentials, then run the pilot.
#[allow(dead_code)]
pub async fn run(
 dc: String,
 creds: Option<crate::auth::Credentials>,
 discovered_domain: Option<String>,
 args: &AutoPwnArgs,
 initial_state: Option<overthrone_pilot::goals::EngagementState>,
) -> i32 {
 let pilot_exec = match args.method {
 ExecMethod::Auto => overthrone_pilot::runner::ExecMethod::Auto,
 ExecMethod::PsExec => overthrone_pilot::runner::ExecMethod::PsExec,
 ExecMethod::SmbExec => overthrone_pilot::runner::ExecMethod::SmbExec,
 ExecMethod::WmiExec => overthrone_pilot::runner::ExecMethod::WmiExec,
 ExecMethod::WinRm => overthrone_pilot::runner::ExecMethod::WinRm,
 };

 let pilot_stage = match args.max_stage {
 MaxStageArg::Enumerate => overthrone_pilot::runner::Stage::Enumerate,
 MaxStageArg::Attack => overthrone_pilot::runner::Stage::Attack,
 MaxStageArg::Escalate => overthrone_pilot::runner::Stage::Escalate,
 MaxStageArg::Lateral => overthrone_pilot::runner::Stage::Lateral,
 MaxStageArg::Loot => overthrone_pilot::runner::Stage::Loot,
 MaxStageArg::Cleanup => overthrone_pilot::runner::Stage::Cleanup,
 };

 let pilot_creds = if let Some(creds) = creds.as_ref() {
 if let Some(hash) = creds.nthash() {
 overthrone_pilot::runner::Credentials::ntlm_hash(&creds.domain, &creds.username, hash)
 } else {
 overthrone_pilot::runner::Credentials::password(
 &creds.domain,
 &creds.username,
 creds.password().unwrap_or(""),
 )
 }
 } else {
 let domain = discovered_domain.clone().unwrap_or_default();
 overthrone_pilot::runner::Credentials::password(&domain, "", "")
 };

 let pilot_config = overthrone_pilot::runner::AutoPwnConfig {
 dc_host: dc.clone(),
 creds: pilot_creds,
 target: args.target.clone(),
 max_stage: pilot_stage,
 stealth: args.stealth,
 dry_run: args.dry_run,
 exec_method: pilot_exec,
 jitter_ms: args.jitter_ms,
 use_ldaps: args.ldaps,
 timeout: args.timeout,
 userlist: args.userlist.clone(),
 #[cfg(feature = "qlearn")]
 adaptive_mode: match args.adaptive {
 AdaptiveModeArg::Heuristic => overthrone_pilot::qlearner::AdaptiveMode::Heuristic,
 AdaptiveModeArg::Qlearning => overthrone_pilot::qlearner::AdaptiveMode::QLearning,
 AdaptiveModeArg::Hybrid => overthrone_pilot::qlearner::AdaptiveMode::Hybrid,
 },
 #[cfg(feature = "qlearn")]
 q_table_path: std::path::PathBuf::from(&args.q_table),
 initial_state,
 dc_verify: overthrone_pilot::dc_verify::DcVerifyConfig {
 skip_dns: args.no_dc_verify_dns,
 ..Default::default()
 },
 enable_concurrent: false,
 opsec_profile: overthrone_pilot::planner::OpsecProfile::default(),
 multi_dc: overthrone_pilot::planner::MultiDcConfig::default(),
 };

 let pilot_domain_display = match creds {
 Some(ref c) => c.domain.clone(),
 None => discovered_domain.clone().unwrap_or_default(),
 };

 println!("{} Target: {}", "[*]".bright_black(), args.target.cyan());
 println!("{} DC: {}", "[+]".bright_black(), dc.cyan());
 if !pilot_domain_display.is_empty() {
 println!(
 "{} Domain: {}",
 "[net]".bright_black(),
 pilot_domain_display.cyan()
 );
 }
 println!("{} Method: {:?}", "[cfg]".bright_black(), args.method);
 println!(
 "{} Max Stage: {:?}",
 "[stats]".bright_black(),
 args.max_stage
 );
 println!("{} Adaptive: {:?}", "[info]".bright_black(), args.adaptive);
 println!(
 "{} Stealth: {}",
 "[+]".bright_black(),
 if args.stealth {
 "ON".green()
 } else {
 "OFF".yellow()
 }
 );
 println!(
 "{} Dry Run: {}",
 "[log]".bright_black(),
 if args.dry_run {
 "YES".yellow()
 } else {
 "NO".dimmed()
 }
 );
 println!();

 // If a playbook was requested, run that instead of goal-driven autopwn
 if let Some(pb) = args.playbook {
 let playbook_id = match pb {
 PlaybookArg::FullRecon => overthrone_pilot::playbook::PlaybookId::FullRecon,
 PlaybookArg::RoastAndCrack => overthrone_pilot::playbook::PlaybookId::RoastAndCrack,
 PlaybookArg::DelegationAbuse => overthrone_pilot::playbook::PlaybookId::DelegationAbuse,
 PlaybookArg::RbcdChain => overthrone_pilot::playbook::PlaybookId::RbcdChain,
 PlaybookArg::CoerceAndRelay => overthrone_pilot::playbook::PlaybookId::CoerceAndRelay,
 PlaybookArg::LateralPivot => overthrone_pilot::playbook::PlaybookId::LateralPivot,
 PlaybookArg::DcSyncDump => overthrone_pilot::playbook::PlaybookId::DcSyncDump,
 PlaybookArg::GoldenTicket => {
 overthrone_pilot::playbook::PlaybookId::GoldenTicketPersist
 }
 PlaybookArg::FullAutoPwn => overthrone_pilot::playbook::PlaybookId::FullAutoPwn,
 };
 banner::print_info(&format!("Running playbook: {}", playbook_id));
 let result = overthrone_pilot::runner::run_playbook(playbook_id, &pilot_config).await;
 if result.domain_admin_achieved {
 banner::print_da_achieved(result.state.da_user.as_deref().unwrap_or("unknown"), &dc);
 return 0;
 }
 banner::print_info("Playbook completed");
 return if result.steps_succeeded > 0 { 0 } else { 1 };
 }

 // Run the full autonomous attack chain via pilot runner
 let result = overthrone_pilot::runner::run(pilot_config).await;

 // Auto-save session state
 {
 let save_path = overthrone_pilot::session::auto_session_path(
 &dc,
 result.state.domain.as_deref().unwrap_or("unknown"),
 );
 match overthrone_pilot::session::save_session(&save_path, &result.state) {
 Ok(_) => banner::print_info(&format!("Session saved -> {}", save_path.display())),
 Err(e) => banner::print_warn(&format!("Could not save session: {}", e)),
 }
 }

 if result.domain_admin_achieved {
 0
 } else {
 println!(
 "\n{} Goal not achieved. {} steps succeeded, {} failed.",
 "[!]".yellow().bold(),
 result.steps_succeeded.to_string().green(),
 result.steps_failed.to_string().red(),
 );
 1
 }
}
