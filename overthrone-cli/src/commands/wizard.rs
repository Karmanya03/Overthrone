//! Wizard command — Interactive AD engagement mode
//!
//! Usage:
//!   ovt wizard --target "Domain Admins"
//!   ovt wizard --resume ./checkpoints/wiz_20260218_210530.json
//!   ovt wizard --target DA --skip-enum --no-pause

use clap::Parser;
use colored::Colorize;
use overthrone_pilot::runner::{AutoPwnConfig, Credentials, ExecMethod, Stage};
use overthrone_pilot::wizard::WizardSession;
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(about = "Interactive wizard mode for AD engagements")]
pub struct WizardArgs {
    /// Target goal: "Domain Admins", "ntds", "<hostname>", "<username>"
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

    /// Password (use --nt-hash for hash)
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

    /// Skip enumeration stage (use existing state file)
    #[arg(long)]
    pub skip_enum: bool,

    /// Load state from JSON file (output from `ovt enum all -o json`)
    #[arg(long, value_name = "FILE")]
    pub from_file: Option<PathBuf>,

    /// Disable pause after each stage (auto-continue)
    #[arg(long)]
    pub no_pause: bool,

    /// Disable automatic hash cracking
    #[arg(long)]
    pub no_auto_crack: bool,

    /// Maximum pause time in seconds before auto-continue (0 = no timeout)
    #[arg(long, default_value = "300")]
    pub pause_timeout: u64,

    /// Enable stealth mode (low-noise actions only)
    #[arg(long)]
    pub stealth: bool,

    /// Dry run (plan only, no execution)
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

    /// Operation timeout per step (seconds)
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// Force specific lateral movement method
    #[arg(long, value_enum)]
    pub lateral_method: Option<ExecMethodArg>,
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
            StageArg::Attack => Stage::Attack,
            StageArg::Escalate => Stage::Escalate,
            StageArg::Lateral => Stage::Lateral,
            StageArg::Loot => Stage::Loot,
            StageArg::Cleanup => Stage::Cleanup,
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
            ExecMethodArg::Auto => ExecMethod::Auto,
            ExecMethodArg::Psexec => ExecMethod::PsExec,
            ExecMethodArg::Smbexec => ExecMethod::SmbExec,
            ExecMethodArg::Wmiexec => ExecMethod::WmiExec,
            ExecMethodArg::Winrm => ExecMethod::WinRm,
        }
    }
}

pub async fn run(args: WizardArgs) -> anyhow::Result<()> {
    // Resume from checkpoint if specified
    if let Some(checkpoint_path) = args.resume {
        info!("Resuming wizard from {}", checkpoint_path.display());
        
        let mut session = WizardSession::from_checkpoint(checkpoint_path).await
            .map_err(|e| anyhow::anyhow!("Failed to load checkpoint: {}", e))?;

        // Apply any CLI overrides
        if args.no_pause {
            session.pause_after_stage = false;
        }
        if args.no_auto_crack {
            session.auto_crack = false;
        }
        if args.pause_timeout == 0 {
            session.max_pause_secs = None;
        } else {
            session.max_pause_secs = Some(args.pause_timeout);
        }

        let result = session.run().await
            .map_err(|e| anyhow::anyhow!("Wizard execution failed: {}", e))?;

        if result.domain_admin_achieved {
            println!("\n{}", "SUCCESS: Domain Admin achieved!".green().bold());
        } else {
            println!("\n{}", "Wizard completed (goal not achieved)".yellow());
        }

        return Ok(());
    }

    // New wizard session - validate required args
    let target = args.target
        .ok_or_else(|| anyhow::anyhow!("--target is required (or use --resume)"))?;

    let dc_host = args.dc_host
        .ok_or_else(|| anyhow::anyhow!("--dc-host is required (or set OT_DC_HOST)"))?;

    let domain = args.domain
        .ok_or_else(|| anyhow::anyhow!("--domain is required (or set OT_DOMAIN)"))?;

    let username = args.username
        .ok_or_else(|| anyhow::anyhow!("--username is required (or set OT_USERNAME)"))?;

    // Build credentials
    let creds = if let Some(hash) = args.nt_hash {
        info!("Using NTLM hash authentication");
        Credentials::ntlm_hash(&domain, &username, &hash)
    } else {
        let password = args.password
            .ok_or_else(|| anyhow::anyhow!("--password or --nt-hash is required (or set OT_PASSWORD/OT_NT_HASH)"))?;
        Credentials::password(&domain, &username, &password)
    };

    // Build AutoPwnConfig
    let config = AutoPwnConfig {
        dc_host,
        creds,
        target,
        max_stage: args.max_stage.into(),
        stealth: args.stealth,
        dry_run: args.dry_run,
        exec_method: args.exec_method.into(),
        jitter_ms: args.jitter_ms,
        use_ldaps: args.ldaps,
        timeout: args.timeout,
    };

    // Create wizard session
    let mut session = WizardSession::new(config, Some(args.checkpoint_dir));
    
    // Apply options
    session.pause_after_stage = !args.no_pause;
    session.auto_crack = !args.no_auto_crack;
    
    if args.pause_timeout == 0 {
        session.max_pause_secs = None;
    } else {
        session.max_pause_secs = Some(args.pause_timeout);
    }

    // Skip enumeration if requested
    if args.skip_enum {
        session.current_stage = Stage::Attack;
        session.completed_stages.push(Stage::Enumerate);
        info!("Skipping enumeration stage (--skip-enum)");

        // Load state from file if provided
        if let Some(state_file) = args.from_file {
            info!("Loading state from {}", state_file.display());
            let state_json = tokio::fs::read_to_string(&state_file).await
                .map_err(|e| anyhow::anyhow!("Failed to read state file: {}", e))?;
            
            session.state = serde_json::from_str(&state_json)
                .map_err(|e| anyhow::anyhow!("Failed to parse state JSON: {}", e))?;
            
            info!("Loaded {} users, {} computers", 
                session.state.users.len(), 
                session.state.computers.len());
        } else {
            error!("--from-file is required when using --skip-enum");
            return Err(anyhow::anyhow!("Cannot skip enumeration without state file"));
        }
    }

    // Run the wizard
    let result = session.run().await
        .map_err(|e| anyhow::anyhow!("Wizard execution failed: {}", e))?;

    // Final status
    if result.domain_admin_achieved {
        println!("\n{}", "SUCCESS: Domain Admin achieved!".green().bold());
        std::process::exit(0);
    } else {
        println!("\n{}", "Wizard completed (goal not achieved)".yellow());
        println!("  Resume with: ovt wizard --resume {}", session.checkpoint_path.display());
        std::process::exit(1);
    }
}
