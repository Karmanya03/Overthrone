//! Top-level orchestrator that runs all reaper modules in sequence.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    acls, adcs, computers, delegations, gpos, groups, laps, mssql, ous, spns, trusts, users,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaperConfig {
    pub dc_ip: String,
    pub domain: String,
    pub base_dn: String,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    pub modules: Vec<String>,
    pub page_size: u32,
}

impl ReaperConfig {
    pub fn should_run(&self, module: &str) -> bool {
        self.modules.is_empty() || self.modules.iter().any(|m| m.eq_ignore_ascii_case(module))
    }

    pub fn base_dn_from_domain(domain: &str) -> String {
        domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReaperResult {
    pub domain: String,
    pub base_dn: String,
    pub users: Vec<users::UserEntry>,
    pub groups: Vec<groups::GroupEntry>,
    pub computers: Vec<computers::ComputerEntry>,
    pub ous: Vec<ous::OuEntry>,
    pub gpos: Vec<gpos::GpoEntry>,
    pub trusts: Vec<trusts::TrustEntry>,
    pub spn_accounts: Vec<spns::SpnAccount>,
    pub delegations: Vec<delegations::DelegationEntry>,
    pub acl_findings: Vec<acls::AclFinding>,
    pub laps_entries: Vec<laps::LapsEntry>,
    pub mssql_instances: Vec<mssql::MssqlInstance>,
    pub adcs_templates: Vec<adcs::CertTemplate>,
}

const MODULES: &[&str] = &[
    "users",
    "groups",
    "computers",
    "ous",
    "gpos",
    "trusts",
    "spns",
    "delegations",
    "acls",
    "laps",
    "mssql",
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
        .unwrap()
        .progress_chars("━╸─"),
    );
    pb.set_prefix("REAPER");

    let mut result = ReaperResult {
        domain: config.domain.clone(),
        base_dn: config.base_dn.clone(),
        users: Vec::new(),
        groups: Vec::new(),
        computers: Vec::new(),
        ous: Vec::new(),
        gpos: Vec::new(),
        trusts: Vec::new(),
        spn_accounts: Vec::new(),
        delegations: Vec::new(),
        acl_findings: Vec::new(),
        laps_entries: Vec::new(),
        mssql_instances: Vec::new(),
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

    run_module!("users", users::enumerate_users, users);
    run_module!("groups", groups::enumerate_groups, groups);
    run_module!("computers", computers::enumerate_computers, computers);
    run_module!("ous", ous::enumerate_ous, ous);
    run_module!("gpos", gpos::enumerate_gpos, gpos);
    run_module!("trusts", trusts::enumerate_trusts, trusts);
    run_module!("spns", spns::enumerate_spn_accounts, spn_accounts);
    run_module!(
        "delegations",
        delegations::enumerate_delegations,
        delegations
    );
    run_module!("acls", acls::enumerate_dangerous_acls, acl_findings);
    run_module!("laps", laps::enumerate_laps, laps_entries);
    run_module!("mssql", mssql::enumerate_mssql, mssql_instances);
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
