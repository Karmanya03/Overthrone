//! Overthrone CLI — Active Directory Offensive Toolkit

mod auth;
mod autopwn;
mod banner;
mod commands;

use auth::{AuthMethod, Credentials};
use autopwn::ExecMethod;
use clap::{Parser, Subcommand};
use colored::Colorize;
use overthrone_reaper::runner::ReaperConfig;
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
    /// Full AD enumeration via reaper modules
    Reaper {
        #[arg(long, env = "OT_DC_IP")]
        dc_ip: Option<String>,
        #[arg(long, short, value_delimiter = ',')]
        modules: Vec<String>,
        #[arg(long, default_value = "500")]
        page_size: u32,
    },
    /// Enumerate specific AD object types
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

#[derive(Debug, Clone, clap::ValueEnum)]
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
        Commands::Reaper { dc_ip, modules, page_size } => {
            cmd_reaper(&cli, dc_ip.clone(), modules.clone(), *page_size).await
        }
        Commands::Enum { target, filter, include_disabled } => {
            cmd_enum(&cli, target.clone(), filter.clone(), *include_disabled).await
        }
        Commands::Kerberos { action } => cmd_kerberos(&cli, action).await,
        Commands::Smb     { action } => cmd_smb(&cli, action).await,
        Commands::Exec { method, target, command } => {
            cmd_exec(&cli, method.clone(), target, command).await
        }
        Commands::Graph { action } => cmd_graph(action).await,
        Commands::Spray { password, userlist, delay, jitter } => {
            cmd_spray(&cli, password, userlist, *delay, *jitter).await
        }
        Commands::AutoPwn { target, method, stealth, dry_run } => {
            cmd_autopwn(&cli, target, method.clone(), *stealth, *dry_run).await
        }
        Commands::Dump { target, source } => cmd_dump(&cli, target, source.clone()).await,
    };

    std::process::exit(exit_code);
}

// ═══════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════

fn require_creds(cli: &Cli) -> std::result::Result<Credentials, i32> {
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

fn require_dc(cli: &Cli) -> std::result::Result<String, i32> {
    cli.dc_host.clone().ok_or_else(|| {
        banner::print_fail("--dc-host is required");
        1
    })
}

fn make_reaper_config(
    cli: &Cli,
    creds: &Credentials,
    dc: String,
    modules: Vec<String>,
    page_size: u32,
) -> std::result::Result<ReaperConfig, i32> {
    let domain = cli.domain.clone().unwrap_or_else(|| {
        banner::print_fail("--domain is required");
        std::process::exit(1)
    });
    let base_dn = ReaperConfig::base_dn_from_domain(&domain);
    Ok(ReaperConfig {
        dc_ip:    dc,
        domain,
        base_dn,
        username: creds.username.clone(),
        password: creds.password().map(str::to_string),
        nt_hash:  creds.nthash().map(str::to_string),
        modules,
        page_size,
    })
}

// ═══════════════════════════════════════════════════════
// cmd_reaper
// ═══════════════════════════════════════════════════════

async fn cmd_reaper(
    cli: &Cli,
    dc_ip: Option<String>,
    modules: Vec<String>,
    page_size: u32,
) -> i32 {
    let creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    let dc = match dc_ip.or_else(|| cli.dc_host.clone()) {
        Some(d) => d,
        None => { banner::print_fail("--dc-ip or --dc-host is required"); return 1; }
    };
    let config = match make_reaper_config(cli, &creds, dc, modules, page_size) {
        Ok(c) => c, Err(e) => return e,
    };
    match overthrone_reaper::runner::run_reaper(&config).await {
        Ok(_)  => 0,
        Err(e) => { banner::print_fail(&format!("Reaper error: {}", e)); 1 }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_enum
// ═══════════════════════════════════════════════════════

async fn cmd_enum(
    cli: &Cli,
    _target: EnumTarget,
    _filter: Option<String>,
    _include_disabled: bool,
) -> i32 {
    let creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    let dc    = match require_dc(cli)    { Ok(d) => d, Err(e) => return e };
    let config = match make_reaper_config(cli, &creds, dc, vec![], 500) {
        Ok(c) => c, Err(e) => return e,
    };
    match overthrone_reaper::runner::run_reaper(&config).await {
        Ok(_)  => 0,
        Err(e) => { banner::print_fail(&format!("Enum error: {}", e)); 1 }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_kerberos
// ═══════════════════════════════════════════════════════

async fn cmd_kerberos(cli: &Cli, action: &KerberosAction) -> i32 {
    let creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    let dc    = match require_dc(cli)    { Ok(d) => d, Err(e) => return e };

    match action {
        KerberosAction::Roast { spn: spn_filter } => {
            banner::print_module_banner("KERBEROAST");
            let config = match make_reaper_config(cli, &creds, dc, vec!["spns".to_string()], 500) {
                Ok(c) => c, Err(e) => return e,
            };
            match overthrone_reaper::runner::run_reaper(&config).await {
                Ok(r) => {
                    for account in &r.spn_accounts {
                        for spn in &account.service_principal_names {
                            if spn_filter.as_deref().map_or(true, |f| spn.contains(f)) {
                                println!("  {} {} ({})",
                                    "SPN".cyan(),
                                    spn,
                                    account.sam_account_name);
                            }
                        }
                    }
                    0
                }
                Err(e) => { banner::print_fail(&format!("{e}")); 1 }
            }
        }
        KerberosAction::AsrepRoast => {
            banner::print_module_banner("AS-REP ROAST");
            banner::print_warn("AS-REP roasting — not yet implemented");
            0
        }
        KerberosAction::GetTgt => {
            banner::print_module_banner("GET TGT");
            banner::print_warn("TGT request — not yet implemented");
            0
        }
        KerberosAction::GetTgs { spn } => {
            banner::print_module_banner("GET TGS");
            banner::print_warn(&format!("TGS for {} — not yet implemented", spn));
            0
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_smb
// ═══════════════════════════════════════════════════════

async fn cmd_smb(cli: &Cli, action: &SmbAction) -> i32 {
    let _creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    match action {
        SmbAction::Shares { target } => {
            banner::print_module_banner("SMB SHARES");
            banner::print_warn(&format!("Listing shares on {} — not yet implemented", target));
            0
        }
        SmbAction::Admin { targets } => {
            banner::print_module_banner("SMB ADMIN CHECK");
            banner::print_warn(&format!("Admin check on {} — not yet implemented", targets));
            0
        }
        SmbAction::Spider { target, extensions } => {
            banner::print_module_banner("SMB SPIDER");
            banner::print_warn(&format!("Spidering {} for {} — not yet implemented", target, extensions));
            0
        }
        SmbAction::Get { target, path } => {
            banner::print_module_banner("SMB GET");
            banner::print_warn(&format!("Download {}:{} — not yet implemented", target, path));
            0
        }
        SmbAction::Put { target, local, remote } => {
            banner::print_module_banner("SMB PUT");
            banner::print_warn(&format!("Upload {} → {}:{} — not yet implemented", local, target, remote));
            0
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_exec
// ═══════════════════════════════════════════════════════

async fn cmd_exec(
    cli: &Cli,
    method: ExecMethod,
    target: &str,
    command: &str,
) -> i32 {
    let _creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    banner::print_module_banner("EXEC");
    banner::print_warn(&format!("Remote exec via {:?} on {} — not yet implemented", method, target));
    println!("  Command: {}", command);
    0
}

// ═══════════════════════════════════════════════════════
// cmd_graph
// ═══════════════════════════════════════════════════════

async fn cmd_graph(action: &GraphAction) -> i32 {
    banner::print_module_banner("GRAPH");
    match action {
        GraphAction::Build             => banner::print_warn("Graph build — not yet implemented"),
        GraphAction::Stats             => banner::print_warn("Graph stats — not yet implemented"),
        GraphAction::Export { output } => banner::print_warn(&format!("Graph export to {} — not yet implemented", output)),
        GraphAction::Path { from, to } => banner::print_warn(&format!("Path {} → {} — not yet implemented", from, to)),
        GraphAction::PathToDa { from } => banner::print_warn(&format!("Path-to-DA from {} — not yet implemented", from)),
    }
    0
}

// ═══════════════════════════════════════════════════════
// cmd_spray
// ═══════════════════════════════════════════════════════

async fn cmd_spray(
    cli: &Cli,
    password: &str,
    userlist: &str,
    delay: u64,
    jitter: u64,
) -> i32 {
    let _creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    let dc = match require_dc(cli) { Ok(d) => d, Err(e) => return e };
    banner::print_module_banner("PASSWORD SPRAY");
    banner::print_warn(&format!(
        "Spraying '{}' against {} (dc: {}, delay: {}s, jitter: {}ms) — not yet implemented",
        password, userlist, dc, delay, jitter
    ));
    0
}

// ═══════════════════════════════════════════════════════
// cmd_autopwn
// ═══════════════════════════════════════════════════════

async fn cmd_autopwn(
    cli: &Cli,
    target: &str,
    method: ExecMethod,
    stealth: bool,
    dry_run: bool,
) -> i32 {
    let creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    let dc    = match require_dc(cli)    { Ok(d) => d, Err(e) => return e };

    let config = autopwn::AutoPwnConfig {
        dchost: dc,
        creds,
        target: target.to_string(),
        stealth,
        dryrun: dry_run,
        exec_method: method,
    };

    let result = autopwn::run(config).await;
    if result.domain_admin_achieved { 0 } else { 1 }
}

// ═══════════════════════════════════════════════════════
// cmd_dump
// ═══════════════════════════════════════════════════════

async fn cmd_dump(cli: &Cli, target: &str, source: DumpSource) -> i32 {
    let _creds = match require_creds(cli) { Ok(c) => c, Err(e) => return e };
    let dc = match require_dc(cli) { Ok(d) => d, Err(e) => return e };
    banner::print_module_banner("DUMP");
    banner::print_warn(&format!(
        "Dump {:?} from {} (dc: {}) — not yet implemented",
        source, target, dc
    ));
    0
}
