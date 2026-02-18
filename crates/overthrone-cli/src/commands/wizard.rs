//! Wizard command — Interactive AD engagement mode
//!
//! Usage:
//!   ovt wizard --target "Domain Admins" --dc-host 10.10.10.1 --domain corp.local -u student -p Lab123!
//!   ovt wizard --resume ./checkpoints/wiz_20260218_210530.json
//!   ovt wizard --target DA --skip-enum --from-file enum.json

use clap::Parser;
use colored::Colorize;
use overthrone_pilot::runner::{AutoPwnConfig, Credentials, ExecMethod, Stage};
use overthrone_pilot::WizardSession;
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Debug, Clone, Parser)]
#[command(about = "Interactive wizard mode for AD engagements")]
pub struct WizardArgs {
    /// Target goal: \"Domain Admins\", \"ntds\", \"<hostname>\", \"<username>\"
    #[arg(short, long)]
    pub target: Option<String>,

    /// Domain controller IP or hostname
    #[arg(long, env = "OT_DC_HOST")]
    pub dc_host: Option<String>,

    /// Domain name (e.g., corp.local)
    #[arg(short, long, env = "OT_DOMAIN")]
    pub domain: Option<String>,

    /// Username for authentication
    #[arg(short, long, env = "OT_USERNAME")]
    pub username: Option<String>,

    /// Password
    #[arg(short, long, env = "OT_PASSWORD")]
    pub password: Option<String>,

    /// Use NTLM hash instead of password
    #[arg(long, env = "OT_NT_HASH")]
    pub nt_hash: Option<String>,

    /// Resume from checkpoint file
    #[arg(long, value_name = "FILE")]
    pub resume: Option<PathBuf>,

    /// Checkpoint directory (default: ./checkpoints)
    #[arg(long, default_value = "./checkpoints")]
    pub checkpoint_dir: PathBuf,

    /// Maximum stage to reach
    #[arg(long, value_enum, default_value = "loot")]
    pub max_stage: StageArg,

    /// Skip enumeration stage (requires --from-file)
    #[arg(long)]
    pub skip_enum: bool,

    /// Load enumeration state from JSON (output of `ovt enum all -o json`)
    #[arg(long, value_name = "FILE")]
    pub from_file: Option<PathBuf>,

    /// Disable pause after each stage (fully automated)
    #[arg(long)]
    pub no_pause: bool,

    /// Disable automatic hash cracking prompts
    #[arg(long)]
    pub no_auto_crack: bool,

    /// Seconds to wait for input before auto-continuing (0 = no timeout)
    #[arg(long, default_value = "300")]
    pub pause_timeout: u64,

    /// Stealth mode (low-noise actions, extra jitter)
    #[arg(long)]
    pub stealth: bool,

    /// Dry run — plan and display, no execution
    #[arg(long)]
    pub dry_run: bool,

    /// Preferred remote execution method
    #[arg(short = 'm', long, value_enum, default_value = "auto")]
    pub exec_method: ExecMethodArg,

    /// Jitter between operations (milliseconds)
    #[arg(long, default_value = "1000")]
    pub jitter_ms: u64,

    /// Use LDAPS (port 636)
    #[arg(long)]
    pub ldaps: bool,

    /// Per-step operation timeout (seconds)
    #[arg(long, default_value = "30")]
    pub timeout: u64,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum StageArg {
    Enumerate,
    Attack,
    Escalate,
    Lateral,
    Loot,
    Cleanup,
}

impl From<StageArg> for Stage {
    fn from(arg: StageArg) -> Self {
        match arg {
            StageArg::Enumerate => Stage::Enumerate,
            StageArg::Attack    => Stage::Attack,
            StageArg::Escalate  => Stage::Escalate,
            StageArg::Lateral   => Stage::Lateral,
            StageArg::Loot      => Stage::Loot,
            StageArg::Cleanup   => Stage::Cleanup,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ExecMethodArg {
    Auto,
    Psexec,
    Smbexec,
    Wmiexec,
    Winrm,
}

impl From<ExecMethodArg> for ExecMethod {
    fn from(arg: ExecMethodArg) -> Self {
        match arg {
            ExecMethodArg::Auto    => ExecMethod::Auto,
            ExecMethodArg::Psexec  => ExecMethod::PsExec,
            ExecMethodArg::Smbexec => ExecMethod::SmbExec,
            ExecMethodArg::Wmiexec => ExecMethod::WmiExec,
            ExecMethodArg::Winrm   => ExecMethod::WinRm,
        }
    }
}

pub async fn run(args: WizardArgs) -> anyhow::Result<()> {
    // ── Resume path ──
    if let Some(checkpoint_path) = args.resume {
        info!("Resuming wizard from {}", checkpoint_path.display());

        let mut session = WizardSession::from_checkpoint(checkpoint_path).await
            .map_err(|e| anyhow::anyhow!("Failed to load checkpoint: {}", e))?;

        if args.no_pause      { session.pause_after_stage = false; }
        if args.no_auto_crack { session.auto_crack = false; }
        session.max_pause_secs = if args.pause_timeout == 0 { None } else { Some(args.pause_timeout) };

        let result = session.run().await
            .map_err(|e| anyhow::anyhow!("Wizard execution failed: {}", e))?;

        if result.domain_admin_achieved {
            println!("\n{}", "SUCCESS: Domain Admin achieved!".green().bold());
        } else {
            println!("\n{}", "Wizard completed (goal not achieved)".yellow());
        }
        return Ok(());
    }

    // ── New session — validate required args ──
    let target  = args.target.ok_or_else(|| anyhow::anyhow!("--target is required (or use --resume)"))?;
    let dc_host = args.dc_host.ok_or_else(|| anyhow::anyhow!("--dc-host / OT_DC_HOST required"))?;
    let domain  = args.domain.ok_or_else(|| anyhow::anyhow!("--domain / OT_DOMAIN required"))?;
    let username = args.username.ok_or_else(|| anyhow::anyhow!("--username / OT_USERNAME required"))?;

    let creds = if let Some(hash) = args.nt_hash {
        info!("Using NTLM hash authentication");
        Credentials::ntlm_hash(&domain, &username, &hash)
    } else {
        let password = args.password
            .ok_or_else(|| anyhow::anyhow!("--password or --nt-hash required"))?;
        Credentials::password(&domain, &username, &password)
    };

    let config = AutoPwnConfig {
        dc_host,
        creds,
        target,
        max_stage: args.max_stage.into(),
        stealth:     args.stealth,
        dry_run:     args.dry_run,
        exec_method: args.exec_method.into(),
        jitter_ms:   args.jitter_ms,
        use_ldaps:   args.ldaps,
        timeout:     args.timeout,
    };

    let mut session = WizardSession::new(config, Some(args.checkpoint_dir));
    session.pause_after_stage = !args.no_pause;
    session.auto_crack        = !args.no_auto_crack;
    session.max_pause_secs    = if args.pause_timeout == 0 { None } else { Some(args.pause_timeout) };

    // ── Skip enum if requested ──
    if args.skip_enum {
        let state_file = args.from_file
            .ok_or_else(|| anyhow::anyhow!("--from-file required with --skip-enum"))?;

        info!("Loading state from {}", state_file.display());
        let state_json = tokio::fs::read_to_string(&state_file).await
            .map_err(|e| anyhow::anyhow!("Failed to read state file: {}", e))?;
        session.state = serde_json::from_str(&state_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse state JSON: {}", e))?;

        session.current_stage = Stage::Attack;
        session.completed_stages.push(Stage::Enumerate);
        info!("Loaded {} users, {} computers — skipping enum",
            session.state.users.len(), session.state.computers.len());
    }

    // ── Run ──
    let checkpoint_path = session.checkpoint_path.clone();
    let result = session.run().await
        .map_err(|e| anyhow::anyhow!("Wizard execution failed: {}", e))?;

    if result.domain_admin_achieved {
        println!("\n{}", "SUCCESS: Domain Admin achieved!".green().bold());
        std::process::exit(0);
    } else {
        println!("\n{}", "Wizard completed (goal not achieved)".yellow());
        println!("  Resume with: ovt wizard --resume {}", checkpoint_path.display());
        std::process::exit(1);
    }
}
