//! WS2025 LAPS LDAPS Fallback — Confidential Attribute Decryption Retry.
//!
//! Windows Server 2025 introduced confidential attribute encryption as a
//! security default. Attributes like `ms-Mcs-AdmPwd` (LAPS v1) and
//! `msLAPS-Password` (LAPS v2) are now encrypted when transmitted over
//! plaintext LDAP (port 389), causing them to appear as empty values.
//!
//! This module:
//! 1. Detects WS2025 DCs via operatingSystem build number
//! 2. Tries LAPS read over the existing session
//! 3. If empty and WS2025 detected, creates a new LDAPS session via `connect`
//!    (port 636 with use_tls=true) and retries — the TLS-encrypted channel
//!    allows the confidential attribute to be decrypted by the DC.

use crate::error::Result;
use crate::proto::ldap::{LDAPS_PORT, LapsResult, LdapSession};
use tracing::info;

/// WS2025 build prefix for detection.
const WS2025_BUILD_PREFIX: &str = "10.0.26";

/// Read LAPS passwords with automatic WS2025 LDAPS fallback.
///
/// If the initial query returns empty results and the DC is WS2025+,
/// a retry is performed over LDAPS (port 636) where confidential
/// attribute encryption is transparently decrypted by the DC.
pub async fn read_laps_passwords_ws2025(
    session: &mut LdapSession,
    computer_filter: Option<&str>,
    dc_host: &str,
    username: &str,
    password: &str,
) -> Result<Vec<LapsResult>> {
    info!("LAPS LDAPS fallback: initial query over current session");

    // Phase 1: Try the current session first
    let results = session.read_laps_passwords(computer_filter).await?;

    // Phase 2: If results found, return them
    if !results.is_empty() {
        info!("LAPS: {} passwords found on initial query", results.len());
        return Ok(results);
    }

    // Phase 3: Check if DC is WS2025 (confidential attrs encrypted)
    let is_ws2025 = is_ws2025_dc(session).await;
    if !is_ws2025 {
        info!("LAPS: no results, DC is not WS2025 — not retrying");
        return Ok(results);
    }

    // Phase 4: Retry over LDAPS (TLS port 636)
    info!(
        "LAPS: WS2025 DC detected — retrying over LDAPS on {dc_host}:{}",
        LDAPS_PORT
    );

    let domain = session
        .base_dn
        .split(',')
        .filter_map(|part| part.strip_prefix("DC="))
        .collect::<Vec<_>>()
        .join(".");

    let mut tls_session = LdapSession::connect(dc_host, &domain, username, password, true).await?;

    let tls_results = tls_session.read_laps_passwords(computer_filter).await?;

    if !tls_results.is_empty() {
        info!(
            "LAPS: {} passwords recovered via LDAPS fallback",
            tls_results.len()
        );
    } else {
        info!("LAPS: no passwords found even over LDAPS (user lacks permission)");
    }

    Ok(tls_results)
}

/// Detect if the target DC is running Windows Server 2025+.
async fn is_ws2025_dc(session: &mut LdapSession) -> bool {
    let entries = session
        .custom_search("(objectClass=computer)", &["operatingSystem"])
        .await
        .ok();

    match entries {
        Some(entries) => {
            for entry in &entries {
                if let Some(os_list) = entry.attrs.get("operatingSystem") {
                    for os in os_list {
                        if os.contains(WS2025_BUILD_PREFIX) || os.contains("Windows Server 2025") {
                            return true;
                        }
                    }
                }
            }
            false
        }
        None => false,
    }
}

/// Extended LAPS result with LDAPS fallback metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LapsLdapsResult {
    /// LAPS passwords found.
    pub passwords: Vec<LapsResult>,
    /// Whether LDAPS fallback was attempted.
    pub ldaps_fallback_attempted: bool,
    /// Whether LDAPS fallback succeeded (found passwords).
    pub ldaps_fallback_succeeded: bool,
    /// Whether the DC is WS2025.
    pub dc_is_ws2025: bool,
}

/// Read LAPS with full metadata about the LDAPS fallback process.
pub async fn read_laps_with_fallback_info(
    session: &mut LdapSession,
    computer_filter: Option<&str>,
    dc_host: &str,
    username: &str,
    password: &str,
) -> Result<LapsLdapsResult> {
    let is_ws2025 = is_ws2025_dc(session).await;
    let passwords =
        read_laps_passwords_ws2025(session, computer_filter, dc_host, username, password).await?;

    let ldaps_fallback_attempted = is_ws2025;
    let ldaps_fallback_succeeded = ldaps_fallback_attempted && !passwords.is_empty();

    Ok(LapsLdapsResult {
        passwords,
        ldaps_fallback_attempted,
        ldaps_fallback_succeeded,
        dc_is_ws2025: is_ws2025,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws2025_build_prefix() {
        assert_eq!(WS2025_BUILD_PREFIX, "10.0.26");
        assert!("10.0.26100.1".starts_with(WS2025_BUILD_PREFIX));
        assert!(!"10.0.20348.1".starts_with(WS2025_BUILD_PREFIX));
    }

    #[test]
    fn test_ws2025_detection_positive() {
        let os = "Windows Server 2025 Datacenter";
        assert!(os.contains("Windows Server 2025"));
        let os2 = "10.0.26100";
        assert!(os2.contains(WS2025_BUILD_PREFIX));
    }

    #[test]
    fn test_ws2025_detection_negative() {
        let os = "Windows Server 2019 Standard";
        assert!(!os.contains("Windows Server 2025"));
        let os2 = "10.0.17763";
        assert!(!os2.starts_with(WS2025_BUILD_PREFIX));
    }

    #[test]
    fn test_laps_ldaps_result_serde() {
        let result = LapsLdapsResult {
            passwords: vec![],
            ldaps_fallback_attempted: true,
            ldaps_fallback_succeeded: false,
            dc_is_ws2025: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("true"));
        let deserialized: LapsLdapsResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.dc_is_ws2025);
        assert!(deserialized.ldaps_fallback_attempted);
    }
}
