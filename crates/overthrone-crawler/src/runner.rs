//! Top-level orchestrator for the crawler pipeline.
//! Takes ReaperResult data and runs analysis modules.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_reaper::runner::ReaperResult;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{escalation, foreign, mssql_links, pam, sid_filter, trust_map};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerConfig {
    pub dc_ip: String,
    pub domain: String,
    pub base_dn: String,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    /// Additional DC IPs for trusted domains
    pub trusted_dc_ips: Vec<TrustedDc>,
    /// Which modules to run (empty = all)
    pub modules: Vec<String>,
    /// Max trust traversal depth
    pub max_depth: u32,
    /// Whether to attempt authentication to trusted domains
    pub auto_pivot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDc {
    pub domain: String,
    pub dc_ip: String,
}

impl CrawlerConfig {
    pub fn should_run(&self, module: &str) -> bool {
        self.modules.is_empty() || self.modules.iter().any(|m| m.eq_ignore_ascii_case(module))
    }

    /// Build a CrawlerConfig from a ReaperConfig.
    pub fn from_reaper(reaper: &overthrone_reaper::runner::ReaperConfig) -> Self {
        CrawlerConfig {
            dc_ip: reaper.dc_ip.clone(),
            domain: reaper.domain.clone(),
            base_dn: reaper.base_dn.clone(),
            username: reaper.username.clone(),
            password: reaper.password.clone(),
            nt_hash: reaper.nt_hash.clone(),
            trusted_dc_ips: Vec::new(),
            modules: Vec::new(),
            max_depth: 5,
            auto_pivot: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawlerResult {
    pub domain: String,
    pub trust_map: trust_map::TrustGraph,
    pub foreign_memberships: Vec<foreign::ForeignMembership>,
    pub escalation_paths: Vec<escalation::EscalationPath>,
    pub sid_filter_findings: Vec<sid_filter::SidFilterFinding>,
    pub mssql_chains: Vec<mssql_links::MssqlLinkChain>,
    pub pam_findings: Vec<pam::PamFinding>,
    // interrealm only when the feature is enabled
    #[cfg(feature = "interrealm")]
    pub interrealm_attacks: Vec<crate::interrealm::InterRealmAttack>,
}

/// Run the full crawler analysis pipeline on reaper data.
pub async fn run_crawler(
    config: &CrawlerConfig,
    reaper_data: &ReaperResult,
) -> Result<CrawlerResult> {
    let sep = "═".repeat(72);
    println!("{}", sep.bright_cyan());
    println!(
        " {} — {} ({})",
        "CRAWLER".bright_cyan().bold(),
        config.domain.as_str().bright_white().bold(),
        config.dc_ip.as_str().dimmed()
    );
    println!("{}", sep.bright_cyan());

    let total_modules = 6u64; // 7 if interrealm is enabled
    let pb = ProgressBar::new(total_modules);
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.cyan.bold} [{bar:40.cyan/dark_gray}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );
    pb.set_prefix("CRAWLER");

    // ── 1. Build trust graph ──
    pb.set_message("trust_map...");
    let graph = trust_map::build_trust_graph(&config.domain, &reaper_data.trusts);
    let graph_summary = format!(
        "{} domains, {} trusts",
        graph.domains.len(),
        graph.trusts.len()
    );
    pb.println(format!(
        " {} {} — {}",
        "✓".green().bold(),
        "trust_map".bright_white(),
        graph_summary.as_str().bright_green()
    ));
    pb.inc(1);

    // ── 2. Foreign memberships (offline DN-based analysis) ──
    pb.set_message("foreign...");
    let foreign_memberships =
        foreign::analyze_foreign_memberships(&config.domain, &reaper_data.groups);
    let fm_count = foreign_memberships.len().to_string();
    pb.println(format!(
        " {} {} — {} found",
        "✓".green().bold(),
        "foreign".bright_white(),
        fm_count.as_str().bright_green()
    ));
    pb.inc(1);

    // ── 3. Escalation paths ──
    pb.set_message("escalation...");
    let escalation_paths =
        escalation::find_escalation_paths(&graph, &foreign_memberships, reaper_data);
    let esc_count = escalation_paths.len().to_string();
    pb.println(format!(
        " {} {} — {} paths",
        "✓".green().bold(),
        "escalation".bright_white(),
        esc_count.as_str().bright_green()
    ));
    pb.inc(1);

    // ── 4. SID filtering analysis ──
    pb.set_message("sid_filter...");
    let sid_filter_findings = sid_filter::analyze_sid_filtering(&config.domain, &graph);
    let sf_count = sid_filter_findings.len().to_string();
    pb.println(format!(
        " {} {} — {} findings",
        "✓".green().bold(),
        "sid_filter".bright_white(),
        sf_count.as_str().bright_green()
    ));
    pb.inc(1);

    // ── 5. MSSQL link chains ──
    pb.set_message("mssql_links...");
    let mssql_chains =
        mssql_links::build_mssql_chains(&config.domain, &reaper_data.mssql_instances);
    let ms_count = mssql_chains.len().to_string();
    pb.println(format!(
        " {} {} — {} chains",
        "✓".green().bold(),
        "mssql_links".bright_white(),
        ms_count.as_str().bright_green()
    ));
    pb.inc(1);

    // ── 6. PAM trusts ──
    pb.set_message("pam...");
    let pam_findings = pam::analyze_pam_trusts(&config.domain, &graph);
    let pam_count = pam_findings.len().to_string();
    pb.println(format!(
        " {} {} — {} findings",
        "✓".green().bold(),
        "pam".bright_white(),
        pam_count.as_str().bright_green()
    ));
    pb.inc(1);

    // ── 7. Inter-realm attacks (only with feature) ──
    #[cfg(feature = "interrealm")]
    let interrealm_attacks = {
        pb.set_message("interrealm...");
        let attacks = crate::interrealm::find_interrealm_attacks(&config.domain, &graph);
        let ir_count = attacks.len().to_string();
        pb.println(format!(
            " {} {} — {} attacks",
            "✓".green().bold(),
            "interrealm".bright_white(),
            ir_count.as_str().bright_green()
        ));
        attacks
    };

    pb.finish_with_message("done!");

    // ── Summary ──
    let total_findings = foreign_memberships.len()
        + escalation_paths.len()
        + sid_filter_findings.len()
        + mssql_chains.len()
        + pam_findings.len();
    let total_str = total_findings.to_string();

    println!("\n┌─ Crawler Summary ─────────────────────────────┐");
    println!(
        "│ Trust graph: {} domains, {} trusts",
        graph.domains.len().to_string().as_str().bright_green(),
        graph.trusts.len().to_string().as_str().bright_green(),
    );
    println!("│ Total findings: {}", total_str.as_str().bright_yellow());
    println!("└───────────────────────────────────────────────┘\n");

    Ok(CrawlerResult {
        domain: config.domain.clone(),
        trust_map: graph,
        foreign_memberships,
        escalation_paths,
        sid_filter_findings,
        mssql_chains,
        pam_findings,
        #[cfg(feature = "interrealm")]
        interrealm_attacks,
    })
}
