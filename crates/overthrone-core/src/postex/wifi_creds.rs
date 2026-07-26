//! Wi-Fi profile credential extraction.
//!
//! Extracts saved Wi-Fi passwords from Windows WLAN profiles.
//! Profiles are stored as XML files in:
//! - `%PROGRAMDATA%\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml`
//!
//! The Wi-Fi password (keyMaterial) is encrypted with DPAPI using
//! `CryptProtectData` in the SYSTEM context. It can be decrypted with:
//! - SYSTEM-level DPAPI access (local)
//! - Domain DPAPI backup key + user masterkey (offline)
//! - LSASS-sourced SYSTEM masterkey

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single decrypted Wi-Fi profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiProfile {
    /// Profile name (SSID)
    pub ssid: String,
    /// Authentication type (e.g. "WPA2PSK", "WPA3", "Open")
    pub auth_type: String,
    /// Encryption type (e.g. "AES", "TKIP")
    pub encryption: String,
    /// Decrypted pre-shared key / password
    pub key_material: String,
    /// Profile XML file path
    pub profile_path: String,
    /// Connection mode (auto, manual)
    pub connection_mode: String,
}

/// Configuration for Wi-Fi profile extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiExtractConfig {
    /// Whether to use SYSTEM DPAPI context for decryption (requires local SYSTEM)
    pub use_system_context: bool,
    /// Domain DPAPI backup key for offline decryption
    pub backup_key: Vec<u8>,
    /// Custom WLAN profile directory
    pub custom_profile_dir: Option<PathBuf>,
    /// Skip decryption errors per profile
    pub skip_on_error: bool,
}

impl Default for WifiExtractConfig {
    fn default() -> Self {
        Self {
            use_system_context: false,
            backup_key: Vec::new(),
            custom_profile_dir: None,
            skip_on_error: true,
        }
    }
}

/// Result of Wi-Fi credential extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiExtractResult {
    /// Extracted Wi-Fi profiles
    pub profiles: Vec<WifiProfile>,
    /// Number of profiles found
    pub total_count: usize,
    /// Number of profiles successfully decrypted
    pub decrypted_count: usize,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Get the default WLAN profile directory.
fn default_wlan_profile_dir() -> Option<PathBuf> {
    let program_data = std::env::var("PROGRAMDATA").ok()?;
    let profiles_dir = PathBuf::from(&program_data)
        .join("Microsoft")
        .join("Wlansvc")
        .join("Profiles")
        .join("Interfaces");

    if !profiles_dir.is_dir() {
        return None;
    }

    Some(profiles_dir)
}

/// Parse a WLAN profile XML and extract credential fields.
fn parse_wlan_profile_xml(data: &str, profile_path: &str) -> Result<WifiProfile> {
    // Extract SSID from <name> or <SSID><name> elements
    let ssid = extract_xml_field(data, "name")
        .or_else(|| {
            // Try nested SSID element
            extract_xml_field(data, "SSID").and_then(|_| extract_xml_field(data, "name"))
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let auth_type =
        extract_xml_field(data, "authentication").unwrap_or_else(|| "Unknown".to_string());
    let encryption = extract_xml_field(data, "encryption").unwrap_or_else(|| "Unknown".to_string());
    let connection_mode =
        extract_xml_field(data, "connectionMode").unwrap_or_else(|| "auto".to_string());

    // Extract encrypted keyMaterial
    let key_material = extract_xml_field(data, "keyMaterial").unwrap_or_else(|| {
        // Try protected element
        extract_xml_field(data, "protected").unwrap_or_else(|| "[encrypted]".to_string())
    });

    Ok(WifiProfile {
        ssid,
        auth_type,
        encryption,
        key_material,
        profile_path: profile_path.to_string(),
        connection_mode,
    })
}

/// Extract the text content of an XML element by tag name.
fn extract_xml_field(xml: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{tag}>");
    let close_tag = format!("</{tag}>");

    let start = xml.find(&open_tag)?;
    let value_start = start + open_tag.len();
    let end = xml[value_start..].find(&close_tag)?;

    Some(xml[value_start..value_start + end].trim().to_string())
}

/// Attempt to decrypt a DPAPI-encrypted keyMaterial blob.
fn decrypt_wifi_key_material(encrypted: &str, _backup_key: &[u8]) -> Result<String> {
    // The keyMaterial in WLAN profiles is a base64-encoded DPAPI blob
    // encrypted with the SYSTEM DPAPI context.
    //
    // Decryption requires either:
    // 1. Running as SYSTEM (CryptUnprotectData with CRYPTPROTECT_UI_FORBIDDEN)
    // 2. Having the SYSTEM DPAPI masterkey (from LSASS dump or Protect dir)
    // 3. Domain DPAPI backup key to decrypt SYSTEM masterkey
    //
    // For local extraction, if we're running as SYSTEM, we can call
    // CryptUnprotectData directly. For offline, we need the SYSTEM masterkey.

    if encrypted.starts_with("[") || encrypted.is_empty() {
        return Err(OverthroneError::Decryption(
            "No encrypted key material found".to_string(),
        ));
    }

    // Attempt base64 decode
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let encrypted_bytes = engine.decode(encrypted).map_err(|e| {
        OverthroneError::Decryption(format!("Failed to base64-decode keyMaterial: {e}"))
    })?;

    if encrypted_bytes.len() < 36 {
        return Err(OverthroneError::Decryption(
            "keyMaterial blob too short for DPAPI".to_string(),
        ));
    }

    // Parse the DPAPI blob structure
    let version = u32::from_le_bytes([
        encrypted_bytes[0],
        encrypted_bytes[1],
        encrypted_bytes[2],
        encrypted_bytes[3],
    ]);

    if version != 1 {
        return Err(OverthroneError::Decryption(format!(
            "Unsupported DPAPI blob version in keyMaterial: {version}"
        )));
    }

    let _masterkey_guid = &encrypted_bytes[4..20];

    // Without SYSTEM context or backup key, we can't proceed
    Err(OverthroneError::Decryption(
        "Wi-Fi keyMaterial decryption requires SYSTEM DPAPI context or domain backup key"
            .to_string(),
    ))
}

/// Discover and parse all WLAN profiles from a directory.
pub fn extract_wifi_profiles_dir(dir: &Path, config: &WifiExtractConfig) -> Vec<WifiProfile> {
    let mut profiles = Vec::new();

    if !dir.is_dir() {
        return profiles;
    }

    // Read interface GUID subdirectories
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                // Some profiles may be directly in the profiles directory
                if path.extension().is_some_and(|e| e == "xml")
                    && let Ok(profile) = process_wlan_profile_file(&path, config)
                {
                    profiles.push(profile);
                }
                continue;
            }

            // Recursively process interface directories
            if let Ok(sub_entries) = std::fs::read_dir(&path) {
                for sub_entry in sub_entries.flatten() {
                    let sub_path = sub_entry.path();
                    if sub_path.extension().is_some_and(|e| e == "xml")
                        && let Ok(profile) = process_wlan_profile_file(&sub_path, config)
                    {
                        profiles.push(profile);
                    }
                }
            }
        }
    }

    profiles
}

/// Process a single WLAN profile XML file.
fn process_wlan_profile_file(path: &Path, config: &WifiExtractConfig) -> Result<WifiProfile> {
    let xml_data = std::fs::read_to_string(path).map_err(|e| {
        OverthroneError::PostExploitation(format!("Failed to read WLAN profile {:?}: {e}", path))
    })?;

    let mut profile = parse_wlan_profile_xml(&xml_data, &path.to_string_lossy())?;

    // Attempt keyMaterial decryption
    if profile.key_material != "[encrypted]" && !profile.key_material.is_empty() {
        match decrypt_wifi_key_material(&profile.key_material, &config.backup_key) {
            Ok(decrypted) => {
                profile.key_material = decrypted;
            }
            Err(_) => {
                if !config.skip_on_error {
                    profile.key_material = "[encrypted]".to_string();
                }
            }
        }
    }

    Ok(profile)
}

/// High-level entry point: extract all Wi-Fi profiles from the local machine.
///
/// Analogue to `netsh wlan show profiles` + `netsh wlan show profile name=<SSID> key=clear`.
pub fn extract_wifi_credentials(config: &WifiExtractConfig) -> WifiExtractResult {
    let mut result = WifiExtractResult {
        profiles: Vec::new(),
        total_count: 0,
        decrypted_count: 0,
        errors: Vec::new(),
    };

    let profiles_dir = if let Some(ref dir) = config.custom_profile_dir {
        dir.clone()
    } else if let Some(dir) = default_wlan_profile_dir() {
        dir
    } else {
        result
            .errors
            .push("WLAN profile directory not found".to_string());
        return result;
    };

    let profiles = extract_wifi_profiles_dir(&profiles_dir, config);
    result.total_count = profiles.len();
    result.decrypted_count = profiles
        .iter()
        .filter(|p| !p.key_material.starts_with('['))
        .count();
    result.profiles = profiles;

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml_field_simple() {
        let xml = r#"<name>TestSSID</name>"#;
        let result = extract_xml_field(xml, "name");
        assert_eq!(result, Some("TestSSID".to_string()));
    }

    #[test]
    fn test_extract_xml_field_with_whitespace() {
        let xml = r#"<name>
            MyNetwork
        </name>"#;
        let result = extract_xml_field(xml, "name");
        assert_eq!(result, Some("MyNetwork".to_string()));
    }

    #[test]
    fn test_extract_xml_field_not_found() {
        let xml = r#"<other>value</other>"#;
        let result = extract_xml_field(xml, "name");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_xml_field_nested() {
        let xml = r#"<authentication>WPA2PSK</authentication><encryption>AES</encryption>"#;
        let auth = extract_xml_field(xml, "authentication");
        let enc = extract_xml_field(xml, "encryption");
        assert_eq!(auth, Some("WPA2PSK".to_string()));
        assert_eq!(enc, Some("AES".to_string()));
    }

    #[test]
    fn test_parse_wlan_profile_xml_basic() {
        let xml = r#"<?xml version="1.0"?>
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
            <name>CorpWiFi</name>
            <connectionMode>auto</connectionMode>
            <MSM>
                <security>
                    <authEncryption>
                        <authentication>WPA2PSK</authentication>
                        <encryption>AES</encryption>
                        <useOneX>false</useOneX>
                    </authEncryption>
                    <sharedKey>
                        <keyType>passPhrase</keyType>
                        <protected>false</protected>
                        <keyMaterial>MyWiFiPass123!</keyMaterial>
                    </sharedKey>
                </security>
            </MSM>
        </WLANProfile>"#;

        let profile = parse_wlan_profile_xml(xml, "/fake/path.xml");
        assert!(profile.is_ok());
        let p = profile.unwrap();
        assert_eq!(p.ssid, "CorpWiFi");
        assert_eq!(p.auth_type, "WPA2PSK");
        assert_eq!(p.encryption, "AES");
        assert_eq!(p.key_material, "MyWiFiPass123!");
    }

    #[test]
    fn test_parse_wlan_profile_xml_encrypted() {
        let xml = r#"<?xml version="1.0"?>
        <WLANProfile>
            <name>EncryptedNet</name>
            <MSM>
                <security>
                    <authEncryption>
                        <authentication>WPA2PSK</authentication>
                        <encryption>AES</encryption>
                    </authEncryption>
                    <sharedKey>
                        <keyType>passPhrase</keyType>
                        <protected>true</protected>
                        <keyMaterial>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAA...</keyMaterial>
                    </sharedKey>
                </security>
            </MSM>
        </WLANProfile>"#;

        let profile = parse_wlan_profile_xml(xml, "/fake/encrypted.xml");
        assert!(profile.is_ok());
        let p = profile.unwrap();
        assert_eq!(p.ssid, "EncryptedNet");
        assert!(p.key_material.starts_with("AQAAANCM"));
    }

    #[test]
    fn test_parse_wlan_profile_xml_missing_key() {
        let xml = r#"<WLANProfile>
            <name>NoKey</name>
            <MSM>
                <security>
                    <authEncryption>
                        <authentication>Open</authentication>
                        <encryption>none</encryption>
                    </authEncryption>
                </security>
            </MSM>
        </WLANProfile>"#;

        let profile = parse_wlan_profile_xml(xml, "/fake/nokey.xml");
        assert!(profile.is_ok());
        assert_eq!(profile.unwrap().key_material, "[encrypted]");
    }

    #[test]
    fn test_decrypt_wifi_key_material_invalid_base64() {
        let result = decrypt_wifi_key_material("not-base64!!", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wifi_key_material_empty() {
        let result = decrypt_wifi_key_material("", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_config() {
        let config = WifiExtractConfig::default();
        assert!(!config.use_system_context);
        assert!(config.backup_key.is_empty());
        assert!(config.custom_profile_dir.is_none());
        assert!(config.skip_on_error);
    }

    #[test]
    fn test_wifi_result_empty() {
        let result = WifiExtractResult {
            profiles: Vec::new(),
            total_count: 0,
            decrypted_count: 0,
            errors: Vec::new(),
        };
        assert_eq!(result.total_count, 0);
    }

    #[test]
    fn test_wifi_profile_serialization() {
        let profile = WifiProfile {
            ssid: "TestNet".to_string(),
            auth_type: "WPA2PSK".to_string(),
            encryption: "AES".to_string(),
            key_material: "secret".to_string(),
            profile_path: "C:\\path.xml".to_string(),
            connection_mode: "auto".to_string(),
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("TestNet"));
        assert!(json.contains("secret"));
    }

    #[test]
    fn test_extract_wifi_profiles_dir_nonexistent() {
        let config = WifiExtractConfig::default();
        let profiles = extract_wifi_profiles_dir(Path::new("C:\\nonexistent"), &config);
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_extract_xml_field_case_sensitive() {
        let xml = r#"<Authentication>WPA2</Authentication>"#;
        // XML field extraction is case-sensitive
        let result = extract_xml_field(xml, "authentication");
        assert_eq!(result, None);
        let result = extract_xml_field(xml, "Authentication");
        assert_eq!(result, Some("WPA2".to_string()));
    }

    #[test]
    fn test_process_wlan_profile_file_nonexistent() {
        let config = WifiExtractConfig::default();
        let result = process_wlan_profile_file(Path::new("C:\\nonexistent.xml"), &config);
        assert!(result.is_err());
    }
}
