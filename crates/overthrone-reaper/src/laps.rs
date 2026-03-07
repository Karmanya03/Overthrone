//! LAPS (Local Administrator Password Solution) enumeration.
//!
//! Supports:
//! - LAPS v1: `ms-Mcs-AdmPwd` (plaintext string)
//! - LAPS v2 unencrypted: `msLAPS-Password` (JSON blob with account name + password)
//! - LAPS v2 encrypted: `msLAPS-EncryptedPassword` (CNG-DPAPI blob, stored for later decryption)

use crate::runner::ReaperConfig;
use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsEntry {
    pub computer_name: String,
    pub distinguished_name: String,
    /// Decrypted/readable password (from v1 or v2-plaintext).
    pub password: Option<String>,
    /// Human-readable expiration timestamp.
    pub expiration: Option<String>,
    /// Raw expiration value (Windows FILETIME) before conversion.
    pub expiration_raw: Option<String>,
    pub is_laps_v2: bool,
    /// For v2 plaintext JSON: the managed account name (e.g. "Administrator").
    pub managed_account: Option<String>,
    /// For v2 encrypted: the raw CNG-DPAPI blob, stored for later decryption
    /// once DPAPI backup keys are recovered (e.g. post-DCSync).
    pub encrypted_blob: Option<Vec<u8>>,
    /// Source of the password: "v1", "v2-plaintext", "v2-encrypted", or "none".
    pub source: LapsSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LapsSource {
    /// LAPS v1 — `ms-Mcs-AdmPwd` plaintext string
    V1,
    /// LAPS v2 — `msLAPS-Password` JSON blob (unencrypted)
    V2Plaintext,
    /// LAPS v2 — `msLAPS-EncryptedPassword` CNG-DPAPI blob
    V2Encrypted,
    /// LAPS attributes detected but password not readable with current creds
    Detected,
}

impl std::fmt::Display for LapsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LapsSource::V1 => write!(f, "v1"),
            LapsSource::V2Plaintext => write!(f, "v2-plaintext"),
            LapsSource::V2Encrypted => write!(f, "v2-encrypted"),
            LapsSource::Detected => write!(f, "detected-no-read"),
        }
    }
}

/// Parsed LAPS v2 plaintext JSON from `msLAPS-Password`.
///
/// Microsoft's schema:
/// ```json
/// {"n":"Administrator","t":"2024-01-15T12:00:00.0000000Z","p":"RandomP@ss!"}
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct LapsV2Json {
    /// Account name managed by LAPS (usually "Administrator").
    #[serde(rename = "n")]
    account_name: String,
    /// Timestamp when the password was set (ISO 8601).
    #[serde(rename = "t")]
    #[allow(dead_code)] // deserialized but not yet consumed
    timestamp: String,
    /// The actual plaintext password.
    #[serde(rename = "p")]
    password: String,
}

/// Parsed header from `msLAPS-EncryptedPassword` blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsV2EncryptedHeader {
    /// Password update timestamp (Windows FILETIME, 100ns intervals since 1601-01-01).
    pub update_timestamp: i64,
    /// Flags field.
    pub flags: u32,
    /// Size of the remaining encrypted payload in bytes.
    pub payload_size: usize,
}

// ═══════════════════════════════════════════════════════════
//  LDAP Helpers
// ═══════════════════════════════════════════════════════════

pub fn laps_filter() -> String {
    // Match computers that have any LAPS attribute populated.
    "(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))".to_string()
}

const LAPS_ATTRS: &[&str] = &[
    "sAMAccountName",
    "distinguishedName",
    "ms-Mcs-AdmPwd",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
    "msLAPS-PasswordExpirationTime",
];

// ═══════════════════════════════════════════════════════════
//  Core Enumeration
// ═══════════════════════════════════════════════════════════

pub async fn enumerate_laps(config: &ReaperConfig) -> Result<Vec<LapsEntry>> {
    info!(
        "[laps] Querying {} for LAPS-enabled computers",
        config.dc_ip
    );

    let mut conn = crate::runner::ldap_connect(config).await?;

    let filter = laps_filter();
    let attr_refs: Vec<&str> = LAPS_ATTRS.to_vec();

    let entries = match conn.custom_search(&filter, &attr_refs).await {
        Ok(e) => e,
        Err(e) => {
            // LAPS attributes may not exist in schema — fall back to all computers
            warn!(
                "[laps] Primary LAPS query failed ({}), trying all computers",
                e
            );
            match conn
                .custom_search("(objectCategory=computer)", &attr_refs)
                .await
            {
                Ok(e2) => e2,
                Err(e2) => {
                    warn!("[laps] Fallback computer query also failed: {}", e2);
                    let _ = conn.disconnect().await;
                    return Err(e2);
                }
            }
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        // ── Extract raw attribute values ──────────────────────

        let v1_pwd = entry
            .attrs
            .get("ms-Mcs-AdmPwd")
            .and_then(|v| v.first())
            .cloned();

        let v2_pwd_raw = entry
            .attrs
            .get("msLAPS-Password")
            .and_then(|v| v.first())
            .cloned();

        let has_encrypted = entry.attrs.contains_key("msLAPS-EncryptedPassword");

        let encrypted_raw = entry
            .attrs
            .get("msLAPS-EncryptedPassword")
            .and_then(|v| v.first())
            .cloned();

        // Check if LAPS is deployed at all on this computer
        let has_laps = v1_pwd.is_some() || v2_pwd_raw.is_some() || has_encrypted;
        if !has_laps {
            continue;
        }

        let computer_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.clone());

        // ── Parse expiration timestamps ──────────────────────

        let expiration_raw = entry
            .attrs
            .get("ms-Mcs-AdmPwdExpirationTime")
            .or_else(|| entry.attrs.get("msLAPS-PasswordExpirationTime"))
            .and_then(|v| v.first())
            .cloned();

        let expiration = expiration_raw.as_deref().and_then(filetime_to_string);

        // ── Determine source + extract password ──────────────

        let (password, managed_account, encrypted_blob, source) = if let Some(ref v1) = v1_pwd {
            // LAPS v1: plaintext string directly
            (Some(v1.clone()), None, None, LapsSource::V1)
        } else if let Some(ref v2_json_str) = v2_pwd_raw {
            // LAPS v2 plaintext: JSON blob
            match parse_laps_v2_json(v2_json_str) {
                Ok(parsed) => (
                    Some(parsed.password),
                    Some(parsed.account_name),
                    None,
                    LapsSource::V2Plaintext,
                ),
                Err(e) => {
                    warn!(
                        "[laps]  {} → msLAPS-Password JSON parse failed: {}",
                        computer_name, e
                    );
                    // Fall back to storing the raw string as-is
                    (
                        Some(v2_json_str.clone()),
                        None,
                        None,
                        LapsSource::V2Plaintext,
                    )
                }
            }
        } else if has_encrypted {
            // LAPS v2 encrypted: CNG-DPAPI blob
            let blob_bytes = encrypted_raw
                .as_ref()
                .map(|s| parse_encrypted_blob_bytes(s));

            if let Some(ref bytes) = blob_bytes
                && let Some(header) = parse_laps_v2_encrypted_header(bytes)
            {
                debug!(
                    "[laps]  {} → v2 encrypted blob: {} bytes, flags={:#x}, ts={}",
                    computer_name,
                    header.payload_size,
                    header.flags,
                    filetime_to_string_i64(header.update_timestamp).unwrap_or_else(|| "?".into()),
                );
            }

            (None, None, blob_bytes, LapsSource::V2Encrypted)
        } else {
            (None, None, None, LapsSource::Detected)
        };

        // ── Log result ───────────────────────────────────────

        match &source {
            LapsSource::V1 => {
                info!(
                    "[laps]  {} → v1 password readable ({} chars)",
                    computer_name,
                    password.as_ref().map(|p| p.len()).unwrap_or(0)
                );
            }
            LapsSource::V2Plaintext => {
                info!(
                    "[laps]  {} → v2 plaintext password readable (account: {})",
                    computer_name,
                    managed_account.as_deref().unwrap_or("?")
                );
            }
            LapsSource::V2Encrypted => {
                info!(
                    "[laps]  {} → v2 ENCRYPTED blob stored ({} bytes) — needs DPAPI key to decrypt",
                    computer_name,
                    encrypted_blob.as_ref().map(|b| b.len()).unwrap_or(0)
                );
            }
            LapsSource::Detected => {
                info!(
                    "[laps]  {} → LAPS deployed (password not readable with current creds)",
                    computer_name
                );
            }
        }

        results.push(LapsEntry {
            computer_name,
            distinguished_name: entry.dn.clone(),
            password,
            expiration,
            expiration_raw,
            is_laps_v2: source != LapsSource::V1 && source != LapsSource::Detected,
            managed_account,
            encrypted_blob,
            source,
        });
    }

    let _ = conn.disconnect().await;

    let readable = results.iter().filter(|e| e.password.is_some()).count();
    let encrypted = results
        .iter()
        .filter(|e| e.source == LapsSource::V2Encrypted)
        .count();

    info!(
        "[laps] Found {} LAPS-enabled computers ({} passwords readable, {} encrypted blobs stored)",
        results.len(),
        readable,
        encrypted
    );

    Ok(results)
}

// ═══════════════════════════════════════════════════════════
//  LAPS v2 JSON Parsing
// ═══════════════════════════════════════════════════════════

/// Parse the `msLAPS-Password` JSON blob.
///
/// Format: `{"n":"Administrator","t":"2024-01-15T12:00:00Z","p":"P@ssw0rd!"}`
fn parse_laps_v2_json(json_str: &str) -> Result<LapsV2Json> {
    serde_json::from_str::<LapsV2Json>(json_str)
        .map_err(|e| OverthroneError::Custom(format!("LAPS v2 JSON parse error: {e}")))
}

// ═══════════════════════════════════════════════════════════
//  LAPS v2 Encrypted Blob Handling
// ═══════════════════════════════════════════════════════════

/// Convert the LDAP string representation of `msLAPS-EncryptedPassword` to raw bytes.
///
/// LDAP may return this as a base64 string or as a hex-encoded octet string,
/// depending on the client library. We try both.
fn parse_encrypted_blob_bytes(raw: &str) -> Vec<u8> {
    // Try base64 first
    if let Ok(decoded) =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw.trim())
    {
        return decoded;
    }

    // Try hex
    if raw.len().is_multiple_of(2)
        && raw.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(decoded) = hex::decode(raw)
    {
        return decoded;
    }

    // Last resort: treat as raw UTF-8 bytes
    raw.as_bytes().to_vec()
}

/// Parse the header of a LAPS v2 encrypted blob.
///
/// Structure:
/// ```text
/// [0..8]   : Update timestamp (FILETIME, little-endian i64)
/// [8..12]  : Flags (u32, little-endian)
/// [12..]   : CNG-DPAPI encrypted payload
/// ```
pub fn parse_laps_v2_encrypted_header(blob: &[u8]) -> Option<LapsV2EncryptedHeader> {
    if blob.len() < 16 {
        return None;
    }

    let update_timestamp = i64::from_le_bytes(blob[0..8].try_into().ok()?);
    let flags = u32::from_le_bytes(blob[8..12].try_into().ok()?);
    let payload_size = blob.len() - 12;

    Some(LapsV2EncryptedHeader {
        update_timestamp,
        flags,
        payload_size,
    })
}

/// Attempt to decrypt a LAPS v2 encrypted blob using a DPAPI backup key.
///
/// Uses the DPAPI module from overthrone-core to decrypt LAPS v2 encrypted passwords.
/// After DCSync or LSA secrets extraction, the DPAPI domain backup key
/// can be used to decrypt these blobs.
///
/// The inner CNG-DPAPI structure contains:
/// 1. DPAPI blob header (version, provider GUID)
/// 2. Master Key GUID reference
/// 3. AES-256-GCM encrypted payload
///
/// The decrypted payload is a JSON string: `{"n":"Admin","t":"...","p":"password"}`
pub fn decrypt_laps_v2_blob(blob: &[u8], dpapi_backup_key: &[u8]) -> Result<LapsV2Json> {
    use overthrone_core::crypto::{DpapiBackupKey, LapsDecryptor};

    let _header = parse_laps_v2_encrypted_header(blob).ok_or_else(|| {
        OverthroneError::Decryption("LAPS v2 encrypted blob too short for header".into())
    })?;

    // The LAPS v2 blob format:
    // - Bytes 0-11: LAPS header (version, timestamp, flags, size)
    // - Bytes 12+: CNG-DPAPI encrypted blob
    let dpapi_blob_data = &blob[12..];

    // Parse the DPAPI encrypted blob
    let encrypted_blob = LapsDecryptor::parse_encrypted_blob(dpapi_blob_data)?;

    // Create DPAPI backup key structure
    // Note: The GUID is extracted from the blob itself during decryption
    let backup_key = DpapiBackupKey {
        guid: [0u8; 16], // Will be extracted from blob
        key_material: dpapi_backup_key.to_vec(),
    };

    // Decrypt using the DPAPI module
    let credentials = LapsDecryptor::decrypt(&encrypted_blob, &backup_key)?;

    // Convert to LapsV2Json format
    // Note: The timestamp from DPAPI is u64, but LapsV2Json expects a string
    Ok(LapsV2Json {
        account_name: credentials.account_name,
        password: credentials.password,
        timestamp: credentials.update_timestamp.to_string(),
    })
}

// ═══════════════════════════════════════════════════════════
//  Timestamp Utilities
// ═══════════════════════════════════════════════════════════

/// Convert a Windows FILETIME string to a human-readable UTC timestamp.
///
/// Windows FILETIME = 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
/// Unix epoch starts at 1970-01-01 00:00:00 UTC = 11644473600 seconds later.
pub fn filetime_to_string(filetime_str: &str) -> Option<String> {
    let ft: i64 = filetime_str.parse().ok()?;
    filetime_to_string_i64(ft)
}

/// Convert a raw i64 FILETIME value to a human-readable UTC timestamp.
fn filetime_to_string_i64(ft: i64) -> Option<String> {
    if ft <= 0 {
        return Some("Never".to_string());
    }
    // FILETIME is in 100ns units; convert to seconds
    let secs_since_1601 = ft / 10_000_000;
    // Offset from 1601-01-01 to 1970-01-01 in seconds
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let unix_secs = secs_since_1601 - EPOCH_DIFF;

    if unix_secs < 0 {
        return Some("Before-1970".to_string());
    }

    // Manual UTC formatting (avoids requiring chrono dependency)
    // For production use, consider chrono::NaiveDateTime::from_timestamp_opt
    let days = unix_secs / 86400;
    let time_of_day = unix_secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since 1970-01-01 (civil calendar)
    let (year, month, day) = civil_from_days(days);

    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, seconds
    ))
}

/// Convert days since 1970-01-01 to (year, month, day).
/// Algorithm from Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ═══════════════════════════════════════════════════════════
//  Legacy Compatibility
// ═══════════════════════════════════════════════════════════

/// Parse a LAPS entry from a raw attribute map (kept for compatibility with older callers).
pub fn parse_laps_entry(attrs: &std::collections::HashMap<String, Vec<String>>) -> LapsEntry {
    let v1_pwd = attrs.get("ms-Mcs-AdmPwd").and_then(|v| v.first()).cloned();
    let v2_pwd_raw = attrs
        .get("msLAPS-Password")
        .and_then(|v| v.first())
        .cloned();
    let has_encrypted = attrs.contains_key("msLAPS-EncryptedPassword");

    let encrypted_raw = attrs
        .get("msLAPS-EncryptedPassword")
        .and_then(|v| v.first())
        .cloned();

    let (password, managed_account, encrypted_blob, source) = if let Some(ref v1) = v1_pwd {
        (Some(v1.clone()), None, None, LapsSource::V1)
    } else if let Some(ref v2_json) = v2_pwd_raw {
        match parse_laps_v2_json(v2_json) {
            Ok(parsed) => (
                Some(parsed.password),
                Some(parsed.account_name),
                None,
                LapsSource::V2Plaintext,
            ),
            Err(_) => (Some(v2_json.clone()), None, None, LapsSource::V2Plaintext),
        }
    } else if has_encrypted {
        let blob = encrypted_raw.map(|s| parse_encrypted_blob_bytes(&s));
        (None, None, blob, LapsSource::V2Encrypted)
    } else {
        (None, None, None, LapsSource::Detected)
    };

    let expiration_raw = attrs
        .get("ms-Mcs-AdmPwdExpirationTime")
        .or_else(|| attrs.get("msLAPS-PasswordExpirationTime"))
        .and_then(|v| v.first())
        .cloned();

    let expiration = expiration_raw.as_deref().and_then(filetime_to_string);

    LapsEntry {
        computer_name: attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        distinguished_name: attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        password,
        expiration,
        expiration_raw,
        is_laps_v2: source != LapsSource::V1 && source != LapsSource::Detected,
        managed_account,
        encrypted_blob,
        source,
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_laps_v2_json() {
        let json = r#"{"n":"Administrator","t":"2024-01-15T12:00:00.0000000Z","p":"S3cretP@ss!"}"#;
        let parsed = parse_laps_v2_json(json).unwrap();
        assert_eq!(parsed.account_name, "Administrator");
        assert_eq!(parsed.password, "S3cretP@ss!");
        assert!(parsed.timestamp.contains("2024"));
    }

    #[test]
    fn test_parse_laps_v2_json_custom_account() {
        // Some orgs rename the managed account
        let json = r#"{"n":"LocalAdmin","t":"2025-06-01T00:00:00Z","p":"xK9#mL2@"}"#;
        let parsed = parse_laps_v2_json(json).unwrap();
        assert_eq!(parsed.account_name, "LocalAdmin");
        assert_eq!(parsed.password, "xK9#mL2@");
    }

    #[test]
    fn test_parse_laps_v2_json_invalid() {
        let bad = "not json at all";
        assert!(parse_laps_v2_json(bad).is_err());
    }

    #[test]
    fn test_filetime_to_string() {
        // 133500000000000000 ≈ 2023-12-19
        let result = filetime_to_string("133500000000000000");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("UTC"));
        assert!(s.contains("2023") || s.contains("2024")); // approximate
    }

    #[test]
    fn test_filetime_zero() {
        let result = filetime_to_string("0");
        assert_eq!(result, Some("Never".to_string()));
    }

    #[test]
    fn test_filetime_invalid() {
        assert!(filetime_to_string("not_a_number").is_none());
    }

    #[test]
    fn test_encrypted_header_parse() {
        // Fake 20-byte blob: 8 bytes timestamp + 4 bytes flags + 8 bytes payload
        let mut blob = Vec::new();
        blob.extend_from_slice(&133500000000000000i64.to_le_bytes()); // timestamp
        blob.extend_from_slice(&0x00000001u32.to_le_bytes()); // flags
        blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]); // payload

        let header = parse_laps_v2_encrypted_header(&blob).unwrap();
        assert_eq!(header.update_timestamp, 133500000000000000);
        assert_eq!(header.flags, 1);
        assert_eq!(header.payload_size, 8);
    }

    #[test]
    fn test_encrypted_header_too_short() {
        let blob = vec![0u8; 10]; // less than 16 bytes
        assert!(parse_laps_v2_encrypted_header(&blob).is_none());
    }

    #[test]
    fn test_civil_from_days() {
        // 1970-01-01 = day 0
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-01-01 = day 10957
        assert_eq!(civil_from_days(10957), (2000, 1, 1));
    }

    #[test]
    fn test_parse_laps_entry_v1_compat() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["DC01$".to_string()]);
        attrs.insert(
            "distinguishedName".to_string(),
            vec!["CN=DC01,OU=DCs,DC=corp,DC=local".to_string()],
        );
        attrs.insert(
            "ms-Mcs-AdmPwd".to_string(),
            vec!["PlainTextPass123".to_string()],
        );

        let entry = parse_laps_entry(&attrs);
        assert_eq!(entry.computer_name, "DC01$");
        assert_eq!(entry.password, Some("PlainTextPass123".to_string()));
        assert_eq!(entry.source, LapsSource::V1);
        assert!(!entry.is_laps_v2);
        assert!(entry.managed_account.is_none());
    }

    #[test]
    fn test_parse_laps_entry_v2_json_compat() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["SRV01$".to_string()]);
        attrs.insert(
            "distinguishedName".to_string(),
            vec!["CN=SRV01,OU=Servers,DC=corp,DC=local".to_string()],
        );
        attrs.insert(
            "msLAPS-Password".to_string(),
            vec![r#"{"n":"Administrator","t":"2025-01-01T00:00:00Z","p":"MyP@ss"}"#.to_string()],
        );

        let entry = parse_laps_entry(&attrs);
        assert_eq!(entry.computer_name, "SRV01$");
        assert_eq!(entry.password, Some("MyP@ss".to_string()));
        assert_eq!(entry.managed_account, Some("Administrator".to_string()));
        assert_eq!(entry.source, LapsSource::V2Plaintext);
        assert!(entry.is_laps_v2);
    }
}
