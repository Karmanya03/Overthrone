//! Unconstrained Delegation discovery — Enumerate computers and users
//! with TRUSTED_FOR_DELEGATION that cache forwarded TGTs in memory.
//!
//! These hosts store TGTs of any user who authenticates to them,
//! making them high-value targets for credential theft.

use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::Result;
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use tracing::info;

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
            domain_controllers.push(host);
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
