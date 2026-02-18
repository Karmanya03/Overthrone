//! Overthrone CLI — Active Directory Offensive Toolkit

mod auth;
mod autopwn;
mod banner;
mod commands;

use auth::{AuthMethod, Credentials};
use autopwn::ExecMethod;
use clap::{Parser, Subcommand};
use colored::Colorize;
use overthrone_core::proto::{kerberos, ldap, smb::SmbSession};
use overthrone_pilot::executor::execute_step;
use overthrone_pilot::goals::EngagementState;
use overthrone_pilot::planner::{PlannedAction, PlanStep};
use tracing_subscriber::{fmt, EnvFilter};

// ═══════════════════════════════════════════════════════
// CLI Definition
// ═══════════════════════════════════════════════════════

#[derive(Parser)]
#[command(name = "overthrone", version, about = "Active Directory Offensive Toolkit",
    long_about = "Overthrone — AD enumeration, attack path analysis, and exploitation framework.\nBuilt in Rust for speed and stealth.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 'H', long, global = true, env = "OT_DC_HOST")]
    dc_host: Option<String>,

    #[arg(short, long, global = true, env = "OT_DOMAIN")]
    domain: Option<String>,

    #[arg(short, long, global = true, env = "OT_USERNAME")]
    username: Option<String>,

    #[arg(short, long, global = true, env = "OT_PASSWORD", hide_env_values = true)]
    password: Option<String>,

    #[arg(long, global = true, env = "OT_NTHASH", hide_env_values = true)]
    nt_hash: Option<String>,

    #[arg(long, global = true, env = "KRB5CCNAME")]
    ticket: Option<String>,

    #[arg(short = 'A', long, global = true, value_enum, default_value = "password")]
    auth_method: AuthMethod,

    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, global = true, value_enum, default_value = "text")]
    output: OutputFormat,

    #[arg(short = 'O', long, global = true)]
    outfile: Option<String>,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive wizard mode for AD engagements
    Wizard {
        #[command(flatten)]
        args: commands::wizard::WizardArgs,
    },
    Enum {
        #[arg(value_enum)]
        target: EnumTarget,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value = "false")]
        include_disabled: bool,
    },
    Kerberos {
        #[command(subcommand)]
        action: KerberosAction,
    },
    Smb {
        #[command(subcommand)]
        action: SmbAction,
    },
    Exec {
        #[arg(short, long, value_enum, default_value = "auto")]
        method: ExecMethod,
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        command: String,
    },
    Graph {
        #[command(subcommand)]
        action: GraphAction,
    },
    Spray {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        userlist: String,
        #[arg(long, default_value = "1")]
        delay: u64,
        #[arg(long, default_value = "0")]
        jitter: u64,
    },
    #[command(name = "auto-pwn")]
    AutoPwn {
        #[arg(short, long, default_value = "Domain Admins")]
        target: String,
        #[arg(short, long, value_enum, default_value = "auto")]
        method: ExecMethod,
        #[arg(long, default_value = "false")]
        stealth: bool,
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },
    Dump {
        #[arg(short, long)]
        target: String,
        #[arg(value_enum)]
        source: DumpSource,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum EnumTarget {
    Users,
    Computers,
    Groups,
    Trusts,
    Spns,
    Asrep,
    Delegations,
    Gpos,
    All,
}

#[derive(Subcommand)]
enum KerberosAction {
    Roast {
        #[arg(long)]
        spn: Option<String>,
    },
    AsrepRoast,
    GetTgt,
    GetTgs {
        #[arg(long)]
        spn: String,
    },
}

#[derive(Subcommand)]
enum SmbAction {
    Shares {
        #[arg(short, long)]
        target: String,
    },
    Admin {
        #[arg(short, long)]
        targets: String,
    },
    Spider {
        #[arg(short, long)]
        target: String,
        #[arg(long, default_value = ".kdbx,.key,.pem,.config,.ps1,.rdp")]
        extensions: String,
    },
    Get {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        path: String,
    },
    Put {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        local: String,
        #[arg(short, long)]
        remote: String,
    },
}

#[derive(Subcommand)]
enum GraphAction {
    Build,
    Path {
        #[arg(short, long)]
        from: String,
        #[arg(short, long)]
        to: String,
    },
    PathToDa {
        #[arg(short, long)]
        from: String,
    },
    Stats,
    Export {
        #[arg(short, long, default_value = "graph.json")]
        output: String,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum DumpSource {
    Sam,
    Lsa,
    Ntds,
    Dcc2,
}

// ═══════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_target(false)
        .compact()
        .init();

    banner::print_banner();

    let exit_code = match &cli.command {
        Commands::Wizard { args } => match commands::wizard::run(args.clone()).await {
            Ok(()) => 0,
            Err(e) => {
                banner::print_fail(&format!("Wizard error: {}", e));
                1
            }
        },
        Commands::Enum {
            target,
            filter,
            include_disabled,
        } => cmd_enum(&cli, target.clone(), filter.clone(), *include_disabled).await,
        Commands::Kerberos { action } => cmd_kerberos(&cli, action).await,
        Commands::Smb { action } => cmd_smb(&cli, action).await,
        Commands::Exec {
            method,
            target,
            command,
        } => cmd_exec(&cli, method.clone(), target, command).await,
        Commands::Graph { action } => cmd_graph(action).await,
        Commands::Spray {
            password,
            userlist,
            delay,
            jitter,
        } => cmd_spray(&cli, password, userlist, *delay, *jitter).await,
        Commands::AutoPwn {
            target,
            method,
            stealth,
            dry_run,
        } => cmd_autopwn(&cli, target, method.clone(), *stealth, *dry_run).await,
        Commands::Dump { target, source } => cmd_dump(&cli, target, source.clone()).await,
    };

    std::process::exit(exit_code);
}

// ═══════════════════════════════════════════════════════
// Credential / DC helpers
// ═══════════════════════════════════════════════════════

fn require_creds(cli: &Cli) -> Result<Credentials, i32> {
    let domain = cli.domain.as_deref().unwrap_or_else(|| {
        banner::print_fail("--domain is required");
        std::process::exit(1)
    });
    let username = cli.username.as_deref().unwrap_or_else(|| {
        banner::print_fail("--username is required");
        std::process::exit(1)
    });
    Credentials::from_args(
        domain,
        username,
        cli.password.as_deref(),
        cli.nt_hash.as_deref(),
        cli.ticket.as_deref(),
        Some(cli.auth_method.clone()),
    )
    .map_err(|e| {
        banner::print_fail(&format!("Auth error: {}", e));
        1
    })
}

fn require_dc(cli: &Cli) -> Result<String, i32> {
    cli.dc_host.clone().ok_or_else(|| {
        banner::print_fail("--dc-host is required");
        1
    })
}

// Rest of the file stays the same - include all enum, kerberos, smb, exec, spray, autopwn, dump, graph functions

// [THE REST OF THE ORIGINAL main.rs CONTINUES HERE - all the async fn cmd_* functions]
// I'm omitting them for brevity but they remain unchanged

// ... (all the other cmd_* functions from the original file)
