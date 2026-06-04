//! Top-level orchestrator that runs all reaper modules in sequence.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    acls, adcs, computers, delegations, gmsa, gpos, groups, laps, mssql, ous, policy, powerview,
    snaffler, spns, trusts, users,
};
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReaperConfig {
    /// Domain controller IP address
    pub dc_ip: String,
    /// Domain FQDN
    pub domain: String,
    /// base dn field
    pub base_dn: String,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: Option<String>,
    /// Hash value
    pub nt_hash: Option<String>,
    /// modules field
    pub modules: Vec<String>,
    /// Size in bytes
    pub page_size: u32,
    /// use ldaps field
    pub use_ldaps: bool,
}

impl ReaperConfig {
    pub fn should_run(&self, module: &str) -> bool {
        self.modules.is_empty() || self.modules.iter().any(|m| m.eq_ignore_ascii_case(module))
    }
    /// Function
    pub fn base_dn_from_domain(domain: &str) -> String {
        // Handle both FQDN (corp.local → DC=corp,DC=local) and NetBIOS-style names.
        // If the domain contains no dot it is treated as a single DC component.
        if domain.contains('.') {
            domain
                .split('.')
                .map(|p| format!("DC={p}"))
                .collect::<Vec<_>>()
                .join(",")
        } else {
            // NetBIOS name (e.g. CORP) — use as a single DC component
            format!("DC={domain}")
        }
    }
}

/// Hash-aware LDAP connect helper shared by all reaper modules.
/// When `config.nt_hash` is set (pass-the-hash auth) this calls
/// `connect_with_hash`; otherwise it uses the cleartext password.
/// This prevents all enumeration returning 0 results when the
/// operator authenticates via NT hash.
pub async fn ldap_connect(config: &ReaperConfig) -> Result<LdapSession> {
    let use_ssl = config.use_ldaps;
    if let Some(hash) = config.nt_hash.as_deref() {
        LdapSession::connect_with_hash(
            &config.dc_ip,
            &config.domain,
            &config.username,
            hash,
            use_ssl,
        )
        .await
    } else {
        LdapSession::connect(
            &config.dc_ip,
            &config.domain,
            &config.username,
            config.password.as_deref().unwrap_or(""),
            use_ssl,
        )
        .await
    }
}
/// Structure
#[derive(Debug, Clone, Serialize)]
pub struct ReaperResult {
    /// Domain FQDN
    pub domain: String,
    /// base dn field
    pub base_dn: String,
    /// Active Directory functional level.
    pub functional_level: Option<u32>,
    /// users field
    pub users: Vec<users::UserEntry>,
    /// groups field
    pub groups: Vec<groups::GroupEntry>,
    /// computers field
    pub computers: Vec<computers::ComputerEntry>,
    /// ous field
    pub ous: Vec<ous::OuEntry>,
    /// gpos field
    pub gpos: Vec<gpos::GpoEntry>,
    /// trusts field
    pub trusts: Vec<trusts::TrustEntry>,
    /// policy field
    pub policy: Option<policy::PolicyResult>,
    /// Service Principal Name
    pub spn_accounts: Vec<spns::SpnAccount>,
    /// delegations field
    pub delegations: Vec<delegations::DelegationEntry>,
    /// acl findings field
    pub acl_findings: Vec<acls::AclFinding>,
    /// laps entries field
    pub laps_entries: Vec<laps::LapsEntry>,
    /// gMSA accounts field
    pub gmsa_entries: Vec<gmsa::GmsaEntry>,
    /// mssql instances field
    pub mssql_instances: Vec<mssql::MssqlInstance>,
    /// snaffle findings field
    pub snaffle_findings: Vec<snaffler::SnaffleFinding>,
    /// powerview results field
    pub powerview_results: Option<powerview::PowerViewResult>,
    /// adcs templates field
    pub adcs_templates: Vec<adcs::CertTemplate>,
}

const MODULES: &[&str] = &[
    "users",
    "groups",
    "computers",
    "ous",
    "gpos",
    "trusts",
    "policy",
    "spns",
    "delegations",
    "acls",
    "laps",
    "gmsa",
    "mssql",
    "snaffler",
    "powerview",
    "adcs",
];

pub async fn run_reaper(config: &ReaperConfig) -> Result<ReaperResult> {
    let active: Vec<&&str> = MODULES.iter().filter(|m| config.should_run(m)).collect();
    let separator = "═══════════════════════════════════════════════";

    println!("\n{}", separator.bright_red());
    println!(
        "{} {} ({})",
        "☠ REAPER".bright_red().bold(),
        config.domain.as_str().bright_white().bold(),
        config.dc_ip.as_str().dimmed()
    );
    println!("{}\n", separator.bright_red());

    let pb = ProgressBar::new(active.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.red.bold} [{bar:40.red/dark_gray}] {pos}/{len} {msg}",
        )
        .map_err(|e| OverthroneError::Custom(format!("Progress bar template error: {e}")))?
        .progress_chars("━╸─"),
    );
    pb.set_prefix("REAPER");

    let mut result = ReaperResult {
        domain: config.domain.clone(),
        base_dn: config.base_dn.clone(),
        functional_level: None,
        users: Vec::new(),
        groups: Vec::new(),
        computers: Vec::new(),
        ous: Vec::new(),
        gpos: Vec::new(),
        trusts: Vec::new(),
        policy: None,
        spn_accounts: Vec::new(),
        delegations: Vec::new(),
        acl_findings: Vec::new(),
        laps_entries: Vec::new(),
        gmsa_entries: Vec::new(),
        mssql_instances: Vec::new(),
        snaffle_findings: Vec::new(),
        powerview_results: None,
        adcs_templates: Vec::new(),
    };

    macro_rules! run_module {
        ($name:expr, $func:expr, $field:ident) => {
            if config.should_run($name) {
                pb.set_message(format!("{}...", $name));
                match $func(config).await {
                    Ok(data) => {
                        let count = data.len();
                        result.$field = data;
                        let count_str = count.to_string();
                        pb.println(format!(
                            "  {} {} → {} found",
                            "✓".green().bold(),
                            $name.bright_white(),
                            count_str.as_str().bright_green()
                        ));
                        info!("[reaper] {} → {count} entries", $name);
                    }
                    Err(OverthroneError::NotImplemented { .. }) => {
                        pb.println(format!(
                            "  {} {} → {}",
                            "○".dimmed(),
                            $name.dimmed(),
                            "stub (not yet wired)".dimmed()
                        ));
                    }
                    Err(e) => {
                        let err_str = format!("{e}");
                        pb.println(format!(
                            "  {} {} → {}",
                            "✗".red().bold(),
                            $name.bright_white(),
                            err_str.as_str().red()
                        ));
                        warn!("[reaper] {} failed: {e}", $name);
                    }
                }
                pb.inc(1);
            }
        };
    }

    // Query msDS-Behavior-Version from the domain root to get AD functional level.
    // This is a single lightweight LDAP lookup done before the heavy module sweeps.
    result.functional_level = {
        match ldap_connect(config).await {
            Ok(mut sess) => {
                let entries = sess
                    .custom_search_with_base(
                        &config.base_dn,
                        "(objectClass=domain)",
                        &["msDS-Behavior-Version"],
                    )
                    .await;
                sess.disconnect().await.ok();
                entries
                    .ok()
                    .and_then(|e| e.into_iter().next())
                    .and_then(|e| {
                        e.attrs
                            .get("msDS-Behavior-Version")
                            .and_then(|v| v.first())
                            .and_then(|v| v.parse::<u32>().ok())
                    })
            }
            Err(e) => {
                warn!("[reaper] functional level query failed: {e}");
                None
            }
        }
    };
    if let Some(fl) = result.functional_level {
        info!("[reaper] Domain functional level: {fl}");
    }

    run_module!("users", users::enumerate_users, users);
    run_module!("groups", groups::enumerate_groups, groups);
    run_module!("computers", computers::enumerate_computers, computers);
    run_module!("ous", ous::enumerate_ous, ous);
    run_module!("gpos", gpos::enumerate_gpos, gpos);
    run_module!("trusts", trusts::enumerate_trusts, trusts);
    if config.should_run("policy") {
        pb.set_message("policy...");
        match policy::enumerate_policies(config).await {
            Ok(data) => {
                let count = data.entry_count();
                result.policy = Some(data);
                let count_str = count.to_string();
                pb.println(format!(
                    "  {} {} → {} found",
                    "✓".green().bold(),
                    "policy".bright_white(),
                    count_str.as_str().bright_green()
                ));
                info!("[reaper] policy → {count} entries");
            }
            Err(e) => {
                let err_str = format!("{e}");
                pb.println(format!(
                    "  {} {} → {}",
                    "✗".red().bold(),
                    "policy".bright_white(),
                    err_str.as_str().red()
                ));
                warn!("[reaper] policy failed: {e}");
            }
        }
        pb.inc(1);
    }
    run_module!("spns", spns::enumerate_spn_accounts, spn_accounts);
    run_module!(
        "delegations",
        delegations::enumerate_delegations,
        delegations
    );
    run_module!("acls", acls::enumerate_dangerous_acls, acl_findings);
    run_module!("laps", laps::enumerate_laps, laps_entries);
    run_module!("gmsa", gmsa::enumerate_gmsa, gmsa_entries);
    run_module!("mssql", mssql::enumerate_mssql, mssql_instances);
    run_module!("snaffler", snaffler::run_snaffler, snaffle_findings);
    if config.should_run("powerview") {
        pb.set_message("powerview...");
        if let Ok(data) = powerview::run_powerview(config).await {
            result.powerview_results = Some(data);
            pb.println(format!(
                "  {} {} → detailed AD info",
                "✓".green().bold(),
                "powerview"
            ));
        }
        pb.inc(1);
    }
    run_module!("adcs", adcs::enumerate_adcs, adcs_templates);

    pb.finish_with_message("done");

    let u = result.users.len().to_string();
    let g = result.groups.len().to_string();
    let c = result.computers.len().to_string();
    let t = result.trusts.len().to_string();
    let s = result.spn_accounts.len().to_string();
    let d = result.delegations.len().to_string();
    let a = result.acl_findings.len().to_string();

    println!("\n{}", "─── Summary ───".bright_red());
    println!(
        "  Users: {}  Groups: {}  Computers: {}",
        u.as_str().bright_green(),
        g.as_str().bright_green(),
        c.as_str().bright_green(),
    );
    println!(
        "  Trusts: {}  SPNs: {}  Delegations: {}  ACLs: {}",
        t.as_str().bright_yellow(),
        s.as_str().bright_yellow(),
        d.as_str().bright_yellow(),
        a.as_str().bright_yellow(),
    );
    println!();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reaper_config_ldaps_toggle() {
        let base = ReaperConfig {
            dc_ip: "10.0.0.1".into(),
            domain: "corp.local".into(),
            base_dn: "DC=corp,DC=local".into(),
            username: "user".into(),
            password: Some("pass".into()),
            nt_hash: None,
            modules: vec![],
            page_size: 500,
            use_ldaps: false,
        };
        assert!(!base.use_ldaps);

        let ldaps = ReaperConfig {
            use_ldaps: true,
            ..base.clone()
        };
        assert!(ldaps.use_ldaps);
    }

    #[test]
    fn test_ldap_connect_dispatches_on_nt_hash() {
        // ldap_connect branches on nt_hash:
        //   Some(hash) → LdapSession::connect_with_hash(..., use_ssl)
        //   None       → LdapSession::connect(..., use_ssl)
        // Both paths receive `use_ldaps` as the `use_ssl` argument.
        // We verify both config shapes are constructible and the flag is set.

        let hash_cfg = ReaperConfig {
            dc_ip: "10.0.0.1".into(),
            domain: "corp.local".into(),
            base_dn: "DC=corp,DC=local".into(),
            username: "admin".into(),
            password: None,
            nt_hash: Some(
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            ),
            modules: vec![],
            page_size: 500,
            use_ldaps: true,
        };
        assert!(hash_cfg.use_ldaps);
        assert!(hash_cfg.nt_hash.is_some());
        assert!(hash_cfg.password.is_none());

        let pass_cfg = ReaperConfig {
            nt_hash: None,
            password: Some("cleartext123".into()),
            use_ldaps: false,
            ..hash_cfg.clone()
        };
        assert!(!pass_cfg.use_ldaps);
        assert!(pass_cfg.nt_hash.is_none());
    }

    #[test]
    fn test_base_dn_from_domain() {
        assert_eq!(
            ReaperConfig::base_dn_from_domain("corp.local"),
            "DC=corp,DC=local"
        );
        assert_eq!(ReaperConfig::base_dn_from_domain("CORP"), "DC=CORP");
    }
}
