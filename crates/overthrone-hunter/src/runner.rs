//! Top-level orchestrator — dispatches all Kerberos attack actions and
//! collects results into a unified HuntReport.

use crate::asreproast::{AsRepRoastConfig, AsRepRoastResult};
use crate::coerce::{CoerceConfig, CoerceResult};
use crate::constrained::{ConstrainedConfig, ConstrainedResult};
use crate::kerberoast::{KerberoastConfig, KerberoastResult};
use crate::rbcd::{RbcdConfig, RbcdResult};
use crate::tickets::TicketRequest;
use crate::unconstrained::{UnconstrainedConfig, UnconstrainedResult};
use chrono::{DateTime, Utc};
use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::TicketGrantingData;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{error, info, warn};

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

/// Global hunt configuration shared across all sub-modules
#[derive(Debug, Clone)]
pub struct HuntConfig {
    /// Domain controller IP
    pub dc_ip: String,
    /// Target AD domain (e.g., "corp.local")
    pub domain: String,
    /// Authentication username
    pub username: String,
    /// Authentication secret (password or NT hash)
    pub secret: String,
    /// Whether `secret` is an NTLM hash rather than a password
    pub use_hash: bool,
    /// LDAP base DN (auto-derived from domain if None)
    pub base_dn: Option<String>,
    /// Use LDAPS (636) instead of LDAP (389)
    pub use_ldaps: bool,
    /// Output directory for results
    pub output_dir: PathBuf,
    /// Max concurrent operations
    pub concurrency: usize,
    /// Request timeout in seconds
    pub timeout: u64,
    /// Jitter between requests (ms) to avoid detection
    pub jitter_ms: u64,
    /// Pre-obtained TGT (skip re-authentication if provided)
    pub tgt: Option<TicketGrantingData>,
}

impl HuntConfig {
    /// Derive base DN from domain: "corp.local" → "DC=corp,DC=local"
    pub fn derive_base_dn(&self) -> String {
        if let Some(ref dn) = self.base_dn {
            return dn.clone();
        }
        self.domain
            .split('.')
            .map(|part| format!("DC={part}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Apply jitter delay between operations
    pub async fn apply_jitter(&self) {
        if self.jitter_ms > 0 {
            let jitter = rand::random::<u64>() % self.jitter_ms;
            tokio::time::sleep(tokio::time::Duration::from_millis(jitter)).await;
        }
    }
}

/// What action the hunter should perform
#[derive(Debug, Clone)]
pub enum HuntAction {
    /// Enumerate & roast DONT_REQ_PREAUTH accounts
    AsRepRoast(AsRepRoastConfig),
    /// Enumerate SPN accounts & extract TGS hashes
    Kerberoast(KerberoastConfig),
    /// Abuse constrained delegation via S4U chain
    ConstrainedDelegation(ConstrainedConfig),
    /// Discover unconstrained delegation hosts
    UnconstrainedDelegation(UnconstrainedConfig),
    /// Perform RBCD attack
    Rbcd(RbcdConfig),
    /// Authentication coercion attacks
    Coerce(CoerceConfig),
    /// Ticket operations (request, convert, import/export)
    Ticket(TicketRequest),
    /// Run all enumeration scans
    FullScan,
}

// ═══════════════════════════════════════════════════════════
// Report
// ═══════════════════════════════════════════════════════════

/// Unified report from all hunt actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    pub domain: String,
    pub dc_ip: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub asreproast: Option<AsRepRoastResult>,
    pub kerberoast: Option<KerberoastResult>,
    pub constrained: Option<ConstrainedResult>,
    pub unconstrained: Option<UnconstrainedResult>,
    pub rbcd: Option<RbcdResult>,
    pub coerce: Option<CoerceResult>,
    pub errors: Vec<String>,
}

impl HuntReport {
    fn new(config: &HuntConfig) -> Self {
        Self {
            domain: config.domain.clone(),
            dc_ip: config.dc_ip.clone(),
            started_at: Utc::now(),
            completed_at: None,
            asreproast: None,
            kerberoast: None,
            constrained: None,
            unconstrained: None,
            rbcd: None,
            coerce: None,
            errors: Vec::new(),
        }
    }

    /// Total number of findings across all modules
    pub fn total_findings(&self) -> usize {
        let mut count = 0;
        if let Some(ref r) = self.asreproast {
            count += r.hashes.len();
        }
        if let Some(ref r) = self.kerberoast {
            count += r.hashes.len();
        }
        if let Some(ref r) = self.constrained {
            count += r.delegatable_accounts.len();
        }
        if let Some(ref r) = self.unconstrained {
            count += r.vulnerable_hosts.len();
        }
        if let Some(ref r) = self.rbcd
            && r.success
        {
            count += 1;
        }
        if let Some(ref r) = self.coerce {
            count += r.successful_coercions.len();
        }
        count
    }

    /// Pretty-print the report summary
    pub fn print_summary(&self) {
        println!("\n{}", "═══ HUNT REPORT ═══".bold().cyan());
        println!("  Domain:  {}", self.domain.bold());
        println!("  DC:      {}", self.dc_ip);
        println!(
            "  Started: {}",
            self.started_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        if let Some(completed) = self.completed_at {
            let duration = completed - self.started_at;
            println!("  Duration: {}s", duration.num_seconds());
        }
        println!();

        if let Some(ref r) = self.asreproast {
            println!(
                "  {} AS-REP Roast: {} hashes from {} targets",
                if r.hashes.is_empty() {
                    "✗".red()
                } else {
                    "✓".green()
                },
                r.hashes.len().to_string().bold(),
                r.users_checked,
            );
        }
        if let Some(ref r) = self.kerberoast {
            println!(
                "  {} Kerberoast:   {} hashes from {} SPNs",
                if r.hashes.is_empty() {
                    "✗".red()
                } else {
                    "✓".green()
                },
                r.hashes.len().to_string().bold(),
                r.spns_checked,
            );
        }
        if let Some(ref r) = self.constrained {
            println!(
                "  {} Constrained:  {} delegatable accounts",
                if r.delegatable_accounts.is_empty() {
                    "✗".red()
                } else {
                    "✓".green()
                },
                r.delegatable_accounts.len().to_string().bold(),
            );
        }
        if let Some(ref r) = self.unconstrained {
            println!(
                "  {} Unconstrained: {} vulnerable hosts",
                if r.vulnerable_hosts.is_empty() {
                    "✗".red()
                } else {
                    "✓".green()
                },
                r.vulnerable_hosts.len().to_string().bold(),
            );
        }
        if let Some(ref r) = self.rbcd {
            println!(
                "  {} RBCD: {}",
                if r.success {
                    "✓".green()
                } else {
                    "✗".red()
                },
                if r.success {
                    "delegation configured"
                } else {
                    "not performed"
                },
            );
        }
        if let Some(ref r) = self.coerce {
            println!(
                "  {} Coerce: {}/{} methods succeeded",
                if r.successful_coercions.is_empty() {
                    "✗".red()
                } else {
                    "✓".green()
                },
                r.successful_coercions.len(),
                r.methods_attempted,
            );
        }

        if !self.errors.is_empty() {
            println!("\n  {} Errors:", "⚠".yellow());
            for e in &self.errors {
                println!("    • {}", e.red());
            }
        }

        println!(
            "\n  {} Total findings: {}",
            "→".cyan(),
            self.total_findings().to_string().bold()
        );
        println!("{}\n", "═══════════════════".cyan());
    }

    /// Export report to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(OverthroneError::custom)
    }

    /// Save report to file
    pub async fn save(&self, path: &std::path::Path) -> Result<()> {
        let json = self.to_json()?;
        tokio::fs::write(path, &json).await?;
        info!("Report saved to {}", path.display());
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
// Main Dispatcher
// ═══════════════════════════════════════════════════════════

/// Run one or more hunt actions and produce a unified report.
pub async fn run_hunt(config: &HuntConfig, actions: &[HuntAction]) -> Result<HuntReport> {
    let mut report = HuntReport::new(config);
    info!("Starting hunt against {} ({})", config.domain, config.dc_ip);

    for action in actions {
        match action {
            HuntAction::AsRepRoast(ac) => match crate::asreproast::run(config, ac).await {
                Ok(result) => report.asreproast = Some(result),
                Err(e) => {
                    error!("AS-REP Roast failed: {e}");
                    report.errors.push(format!("asreproast: {e}"));
                }
            },
            HuntAction::Kerberoast(kc) => match crate::kerberoast::run(config, kc).await {
                Ok(result) => report.kerberoast = Some(result),
                Err(e) => {
                    error!("Kerberoast failed: {e}");
                    report.errors.push(format!("kerberoast: {e}"));
                }
            },
            HuntAction::ConstrainedDelegation(cc) => {
                match crate::constrained::run(config, cc).await {
                    Ok(result) => report.constrained = Some(result),
                    Err(e) => {
                        error!("Constrained delegation scan failed: {e}");
                        report.errors.push(format!("constrained: {e}"));
                    }
                }
            }
            HuntAction::UnconstrainedDelegation(uc) => {
                match crate::unconstrained::run(config, uc).await {
                    Ok(result) => report.unconstrained = Some(result),
                    Err(e) => {
                        error!("Unconstrained delegation scan failed: {e}");
                        report.errors.push(format!("unconstrained: {e}"));
                    }
                }
            }
            HuntAction::Rbcd(rc) => match crate::rbcd::run(config, rc).await {
                Ok(result) => report.rbcd = Some(result),
                Err(e) => {
                    error!("RBCD attack failed: {e}");
                    report.errors.push(format!("rbcd: {e}"));
                }
            },
            HuntAction::Coerce(cc) => match crate::coerce::run(config, cc).await {
                Ok(result) => report.coerce = Some(result),
                Err(e) => {
                    error!("Coercion failed: {e}");
                    report.errors.push(format!("coerce: {e}"));
                }
            },
            HuntAction::Ticket(tr) => match crate::tickets::handle_request(config, tr).await {
                Ok(_) => info!("Ticket operation completed"),
                Err(e) => {
                    error!("Ticket operation failed: {e}");
                    report.errors.push(format!("ticket: {e}"));
                }
            },
            HuntAction::FullScan => {
                info!("Running full enumeration scan...");
                // AS-REP Roast — auto-enumerate
                let asrep_cfg = AsRepRoastConfig::default();
                match crate::asreproast::run(config, &asrep_cfg).await {
                    Ok(r) => report.asreproast = Some(r),
                    Err(e) => report.errors.push(format!("asreproast: {e}")),
                }

                // Kerberoast — auto-enumerate
                let kerb_cfg = KerberoastConfig::default();
                match crate::kerberoast::run(config, &kerb_cfg).await {
                    Ok(r) => report.kerberoast = Some(r),
                    Err(e) => report.errors.push(format!("kerberoast: {e}")),
                }

                // Constrained delegation — enumerate
                let cd_cfg = ConstrainedConfig::default();
                match crate::constrained::run(config, &cd_cfg).await {
                    Ok(r) => report.constrained = Some(r),
                    Err(e) => report.errors.push(format!("constrained: {e}")),
                }

                // Unconstrained delegation — enumerate
                let ud_cfg = UnconstrainedConfig::default();
                match crate::unconstrained::run(config, &ud_cfg).await {
                    Ok(r) => report.unconstrained = Some(r),
                    Err(e) => report.errors.push(format!("unconstrained: {e}")),
                }
            }
        }
        config.apply_jitter().await;
    }

    report.completed_at = Some(Utc::now());
    report.print_summary();

    // Auto-save if output dir is set
    let report_path = config.output_dir.join(format!(
        "hunt_{}_{}.json",
        config.domain.replace('.', "_"),
        Utc::now().format("%Y%m%d_%H%M%S")
    ));
    if let Err(e) = report.save(&report_path).await {
        warn!("Could not save report: {e}");
    }

    Ok(report)
}
