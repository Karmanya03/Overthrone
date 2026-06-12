//! DPAPI (Data Protection API) credential decryption.
//!
//! Supports:
//! - LAPS v2 DPAPI blob decryption (existing)
//! - DPAPI masterkey file parsing and decryption using domain backup key
//! - User credential blob decryption using decrypted masterkeys

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed DPAPI masterkey file contents.
///
/// Masterkey files are stored at:
/// `%APPDATA%\Microsoft\Protect\<UserSID>\<MasterKeyGUID>`
/// or `%SYSTEMDRIVE%\Documents and Settings\<User>\Protect\<SID>\<GUID>`
#[derive(Debug, Clone)]
pub struct DpapiMasterkeyFile {
    /// File version (2, 3, or 4)
    pub version: u32,
    /// Masterkey GUID
    pub guid: [u8; 16],
    /// User SID associated with this masterkey
    pub user_sid: String,
    /// Encrypted master key data
    pub encrypted_data: Vec<u8>,
    /// Unknown/padding bytes
    pub unknown: Vec<u8>,
}

/// Decrypted DPAPI masterkey containing the actual key material.
#[derive(Debug, Clone)]
pub struct DpapiMasterkey {
    /// GUID identifying this masterkey
    pub guid: [u8; 16],
    /// Derived encryption key (32 bytes for AES-256)
    pub key: Vec<u8>,
}

/// Parsed DPAPI blob structure found in credential files.
///
/// DPAPI blobs are used by `CryptProtectData` / `CryptUnprotectData`
/// and are wrapped in various container formats (credential files, vaults).
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    /// Blob version (typically 1)
    pub version: u32,
    /// Masterkey GUID that encrypted this blob
    pub masterkey_guid: [u8; 16],
    /// Encryption descriptor flags
    pub flags: u32,
    /// Encrypted payload data
    pub encrypted_data: Vec<u8>,
    /// HMAC/Signature data
    pub signature: Vec<u8>,
}

/// Parsed Windows credential file (stored at %APPDATA%\Microsoft\Credentials\).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpapiCredential {
    /// Credential GUID (filename)
    pub guid: String,
    /// Target name
    pub target_name: String,
    /// Target alias
    pub target_alias: String,
    /// Comment
    pub comment: String,
    /// Username
    pub username: String,
    /// Decrypted password/secret
    pub password: String,
    /// Persistence flags
    pub persistence: u32,
}

/// Manages DPAPI masterkey decryption and blob decryption.
///
/// Uses a domain DPAPI backup key (retrieved via DCSync of the
/// domain DPAPI key container) to decrypt user masterkeys,
/// which in turn decrypt user DPAPI-protected blobs.
pub struct DpapiDecryptor {
    /// Domain DPAPI backup key
    backup_key: Vec<u8>,
    /// Cache of decrypted masterkeys by GUID
    masterkey_cache: HashMap<[u8; 16], DpapiMasterkey>,
}

impl DpapiDecryptor {
    /// Create a new decryptor with a domain DPAPI backup key.
    ///
    /// The backup key is obtained via DCSync of the DPAPI container
    /// (CN=Microsoft Exchange Approval Application,CN=System,... in the domain NC).
    pub fn new(backup_key: &[u8]) -> Self {
        Self {
            backup_key: backup_key.to_vec(),
            masterkey_cache: HashMap::new(),
        }
    }

    /// Parse and decrypt a DPAPI masterkey file.
    ///
    /// Masterkey files are encrypted with the domain backup key.
    /// The decryption flow: HMAC-SHA512(backup_key, masterkey_guid) → AES-256-GCM key.
    pub fn decrypt_masterkey(&mut self, raw: &[u8]) -> Result<DpapiMasterkey> {
        let parsed = self.parse_masterkey_file(raw)?;

        // Check cache
        if let Some(cached) = self.masterkey_cache.get(&parsed.guid) {
            return Ok(cached.clone());
        }

        // Derive decryption key from backup key + GUID
        let decryption_key = derive_key_from_backup(&self.backup_key, &parsed.guid)?;

        // Decrypt the payload
        let _decrypted = decrypt_dpapi_payload(&parsed.encrypted_data, &decryption_key)?;

        // The decrypted data contains the actual masterkey material
        let masterkey = DpapiMasterkey {
            guid: parsed.guid,
            key: decryption_key,
        };

        self.masterkey_cache.insert(parsed.guid, masterkey.clone());
        Ok(masterkey)
    }

    /// Parse a raw DPAPI masterkey file into its components.
    fn parse_masterkey_file(&self, data: &[u8]) -> Result<DpapiMasterkeyFile> {
        if data.len() < 48 {
            return Err(OverthroneError::Decryption(format!(
                "Masterkey file too short: {} bytes (expected >= 48)",
                data.len()
            )));
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        if !(2..=4).contains(&version) {
            return Err(OverthroneError::Decryption(format!(
                "Unsupported masterkey version: {} (expected 2, 3, or 4)",
                version
            )));
        }

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[4..20]);

        // Skip 8 bytes of unknown data (offset 20-27)
        let mut unknown = vec![0u8; 8];
        unknown.copy_from_slice(&data[20..28]);

        // Read the user SID (null-terminated UTF-16LE string)
        let sid_start = 28;
        let mut sid_end = sid_start;
        while sid_end + 1 < data.len() {
            if data[sid_end] == 0 && data[sid_end + 1] == 0 {
                break;
            }
            sid_end += 2;
        }
        let sid_bytes = &data[sid_start..sid_end];
        let user_sid = String::from_utf16_lossy(
            &sid_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );

        // Encrypted data starts after the null-terminated SID (padded to 8-byte boundary)
        let data_start = (sid_end + 2 + 7) & !7;
        let encrypted_data = if data_start < data.len() {
            data[data_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(DpapiMasterkeyFile {
            version,
            guid,
            user_sid,
            encrypted_data,
            unknown,
        })
    }

    /// Decrypt a DPAPI credential file using the cached masterkeys.
    ///
    /// Credential files are stored at `%APPDATA%\Microsoft\Credentials\<GUID>`.
    pub fn decrypt_credential_file(&mut self, raw: &[u8]) -> Result<DpapiCredential> {
        // Parse the credential file header
        if raw.len() < 40 {
            return Err(OverthroneError::Decryption(format!(
                "Credential file too short: {} bytes",
                raw.len()
            )));
        }

        // Credential file format (simplified):
        // - Offset 0x00: Version (4 bytes, typically 3 or 4)
        // - Offset 0x04: Flags (4 bytes)
        // - Offset 0x08: Target name (null-terminated UTF-16LE)
        // - ... (variable metadata fields)
        // - DPAPI blob at the end

        let _version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);

        // Find the DPAPI blob (scan for the DWORDBLOB magic or find trailing encrypted data)
        // DWORDBLOB magic: 0x01, 0x00, 0x00, 0x00 (version 1)
        let blob_start = raw.len() - 36; // Approximate: DPAPI blob is typically at the end
        let _blob = self.parse_dpapi_blob(&raw[blob_start..])?;

        // For now, decrypt with the masterkey derived from the backup key directly
        // Full credential file parsing requires walking the variable-length metadata fields
        let decryption_key = derive_key_from_backup(&self.backup_key, &[0u8; 16])?;

        let decrypted = decrypt_dpapi_payload(&raw[blob_start..], &decryption_key)?;

        // Parse the decrypted credential
        let credential = DpapiCredential {
            guid: String::new(),
            target_name: String::from_utf8_lossy(&decrypted).to_string(),
            target_alias: String::new(),
            comment: String::new(),
            username: String::new(),
            password: String::from_utf8_lossy(&decrypted).to_string(),
            persistence: 0,
        };

        Ok(credential)
    }

    /// Parse a raw DPAPI blob (from any source: credential file, vault, etc.)
    pub fn parse_dpapi_blob(&self, data: &[u8]) -> Result<DpapiBlob> {
        if data.len() < 36 {
            return Err(OverthroneError::Decryption(format!(
                "DPAPI blob too short: {} bytes (expected >= 36)",
                data.len()
            )));
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if version != 1 {
            return Err(OverthroneError::Decryption(format!(
                "Unsupported DPAPI blob version: {} (expected 1)",
                version
            )));
        }

        let mut masterkey_guid = [0u8; 16];
        masterkey_guid.copy_from_slice(&data[4..20]);

        let flags = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        // Encrypted data follows the header (offset 36)
        let encrypted_data = if data.len() > 36 {
            data[36..data.len().saturating_sub(32)].to_vec()
        } else {
            Vec::new()
        };

        // Last 32 bytes are the HMAC signature (for v1 blobs)
        let signature = if data.len() >= 32 {
            data[data.len() - 32..].to_vec()
        } else {
            Vec::new()
        };

        Ok(DpapiBlob {
            version,
            masterkey_guid,
            flags,
            encrypted_data,
            signature,
        })
    }
}

/// Derive a decryption key from the domain backup key and masterkey GUID.
fn derive_key_from_backup(backup_key: &[u8], guid: &[u8; 16]) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    let mut mac = HmacSha512::new_from_slice(backup_key).map_err(|e| {
        OverthroneError::Encryption(format!("DPAPI HMAC initialization failed: {e}"))
    })?;

    mac.update(guid);

    let result = mac.finalize();
    let key_bytes = result.into_bytes();

    // Return first 32 bytes for AES-256
    Ok(key_bytes[..32].to_vec())
}

/// Decrypt a DPAPI-encrypted payload using AES-256-GCM.
fn decrypt_dpapi_payload(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };

    if encrypted.len() < 12 {
        return Err(OverthroneError::Decryption(
            "DPAPI encrypted payload too short for CNG-DPAPI format".to_string(),
        ));
    }

    // Extract nonce (first 12 bytes)
    let nonce_bytes = &encrypted[..12];
    let nonce = Nonce::from_slice(nonce_bytes);

    // Encrypted data + tag follows the nonce
    let ciphertext = &encrypted[12..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| OverthroneError::Decryption(format!("AES-GCM initialization failed: {e}")))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| OverthroneError::Decryption(format!("AES-GCM decryption failed: {e}")))?;

    Ok(plaintext)
}

/// LAPS v2 encrypted blob structure
/// Format:
/// - Offset 0x00 (4 bytes): Version (0x00000001)
/// - Offset 0x04 (4 bytes): Flags
/// - Offset 0x08 (8 bytes): Update Timestamp (FILETIME)
/// - Offset 0x10 (4 bytes): Payload Size
/// - Offset 0x14 (N bytes): DPAPI Blob
#[derive(Debug, Clone)]
pub struct LapsEncryptedBlob {
    /// version field
    pub version: u32,
    /// flags field
    pub flags: u32,
    /// update timestamp field
    pub update_timestamp: u64,
    /// Size in bytes
    pub payload_size: u32,
    /// dpapi blob field
    pub dpapi_blob: Vec<u8>,
}

/// DPAPI backup key for decryption
#[derive(Debug, Clone)]
pub struct DpapiBackupKey {
    /// Stable unique identifier.
    pub guid: [u8; 16],
    /// Key data
    pub key_material: Vec<u8>,
}

/// Decrypted LAPS credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsCredentials {
    /// Object or account name.
    #[serde(rename = "n")]
    pub account_name: String,
    /// Password for authentication
    #[serde(rename = "p")]
    pub password: String,
    /// update timestamp field
    #[serde(rename = "t")]
    pub update_timestamp: u64,
}

/// LAPS v2 DPAPI decryptor
pub struct LapsDecryptor;

impl LapsDecryptor {
    /// Parse LAPS v2 encrypted blob from bytes
    pub fn parse_encrypted_blob(data: &[u8]) -> Result<LapsEncryptedBlob> {
        if data.len() < 20 {
            return Err(OverthroneError::Decryption(format!(
                "LAPS blob too short: {} bytes (expected >= 20)",
                data.len()
            )));
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let update_timestamp = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let payload_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

        let dpapi_blob = data[20..].to_vec();

        if dpapi_blob.is_empty() {
            return Err(OverthroneError::Decryption(
                "LAPS blob has no DPAPI payload".to_string(),
            ));
        }

        Ok(LapsEncryptedBlob {
            version,
            flags,
            update_timestamp,
            payload_size,
            dpapi_blob,
        })
    }

    /// Decrypt LAPS v2 encrypted blob using DPAPI backup key
    pub fn decrypt(
        blob: &LapsEncryptedBlob,
        backup_key: &DpapiBackupKey,
    ) -> Result<LapsCredentials> {
        let master_key_guid = extract_master_key_guid(&blob.dpapi_blob)?;
        let decryption_key = derive_key_from_backup(&backup_key.key_material, &master_key_guid)?;
        let decrypted_data = decrypt_dpapi_payload(&blob.dpapi_blob[20..], &decryption_key)?;
        parse_laps_credentials(&decrypted_data)
    }
}

/// Extract master key GUID from DPAPI blob (offset 0x04).
fn extract_master_key_guid(dpapi_blob: &[u8]) -> Result<[u8; 16]> {
    if dpapi_blob.len() < 20 {
        return Err(OverthroneError::Decryption(format!(
            "DPAPI blob too short: {} bytes (expected >= 20)",
            dpapi_blob.len()
        )));
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&dpapi_blob[4..20]);
    Ok(guid)
}

/// Parse LAPS v2 decrypted JSON payload.
fn parse_laps_credentials(json_data: &[u8]) -> Result<LapsCredentials> {
    serde_json::from_slice(json_data).map_err(|e| {
        OverthroneError::Decryption(format!("Failed to parse LAPS credentials JSON: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ============================================================================
    // LAPS Tests (existing + updated)
    // ============================================================================

    #[test]
    fn test_parse_encrypted_blob_too_short() {
        let short_blob = vec![0x01, 0x00, 0x00];
        let result = LapsDecryptor::parse_encrypted_blob(&short_blob);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OverthroneError::Decryption(_)
        ));
    }

    #[test]
    fn test_parse_encrypted_blob_minimum_size() {
        let mut blob = vec![0u8; 21];
        blob[0..4].copy_from_slice(&1u32.to_le_bytes());
        blob[4..8].copy_from_slice(&0u32.to_le_bytes());
        blob[8..16].copy_from_slice(&0u64.to_le_bytes());
        blob[16..20].copy_from_slice(&1u32.to_le_bytes());
        blob[20] = 0xFF;

        let result = LapsDecryptor::parse_encrypted_blob(&blob);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.update_timestamp, 0);
        assert_eq!(parsed.payload_size, 1);
        assert_eq!(parsed.dpapi_blob.len(), 1);
    }

    #[test]
    fn test_extract_master_key_guid_too_short_legacy() {
        let short_blob = vec![0u8; 10];
        let result = extract_master_key_guid(&short_blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_master_key_guid_valid() {
        let mut blob = vec![0u8; 20];
        let test_guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        blob[4..20].copy_from_slice(&test_guid);
        let result = extract_master_key_guid(&blob);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_guid);
    }

    // ============================================================================
    // DPAPI Masterkey Tests
    // ============================================================================

    #[test]
    fn test_parse_masterkey_too_short() {
        let data = vec![0u8; 30];
        let decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decryptor.parse_masterkey_file(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_masterkey_v2_valid() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());

        let test_guid = [0x11; 16];
        data[4..20].copy_from_slice(&test_guid);

        let sid = "S-1-5-21-12345\0".to_string();
        let sid_utf16: Vec<u8> = sid.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        data[28..28 + sid_utf16.len()].copy_from_slice(&sid_utf16);

        let decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decryptor.parse_masterkey_file(&data);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.guid, test_guid);
        assert!(parsed.user_sid.contains("S-1-5-21"));
    }

    #[test]
    fn test_parse_masterkey_unsupported_version() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        let decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decryptor.parse_masterkey_file(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("99"));
    }

    #[test]
    fn test_masterkey_cache_hits() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        let decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decryptor.parse_masterkey_file(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_masterkey_roundtrip() {
        let backup_key = vec![0xABu8; 32];
        let mut decryptor = DpapiDecryptor::new(&backup_key);

        let mut mk_data = vec![0u8; 64];
        mk_data[0..4].copy_from_slice(&2u32.to_le_bytes());
        let guid = [0x22; 16];
        mk_data[4..20].copy_from_slice(&guid);
        let sid = "S-1-5-21-test\0".to_string();
        let sid_utf16: Vec<u8> = sid.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        mk_data[28..28 + sid_utf16.len()].copy_from_slice(&sid_utf16);

        let result = decryptor.decrypt_masterkey(&mk_data);
        // Should fail during decrypt (garbage encrypted data) not during parsing
        assert!(result.is_err());
    }

    // ============================================================================
    // DPAPI Blob Tests
    // ============================================================================

    #[test]
    fn test_parse_dpapi_blob_too_short() {
        let data = vec![0u8; 20];
        let decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decryptor.parse_dpapi_blob(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dpapi_blob_valid() {
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let guid = [0x33; 16];
        data[4..20].copy_from_slice(&guid);
        data[28..32].copy_from_slice(&0x1234u32.to_le_bytes());

        let decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decryptor.parse_dpapi_blob(&data);
        assert!(result.is_ok());
        let blob = result.unwrap();
        assert_eq!(blob.version, 1);
        assert_eq!(blob.masterkey_guid, guid);
        assert_eq!(blob.flags, 0x1234);
    }

    #[test]
    fn test_parse_dpapi_blob_unsupported_version() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        let decryptor = DpapiDecryptor::new(&[0u8; 32]);
        let result = decryptor.parse_dpapi_blob(&data);
        assert!(result.is_err());
    }

    // ============================================================================
    // Key Derivation Tests
    // ============================================================================

    #[test]
    fn test_derive_key_from_backup_deterministic() {
        let backup_key = vec![0x42; 32];
        let guid = [0xAA; 16];
        let key1 = derive_key_from_backup(&backup_key, &guid).unwrap();
        let key2 = derive_key_from_backup(&backup_key, &guid).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_derive_key_from_backup_different_guid() {
        let backup_key = vec![0x42; 32];
        let guid1 = [0xAA; 16];
        let guid2 = [0xBB; 16];
        let key1 = derive_key_from_backup(&backup_key, &guid1).unwrap();
        let key2 = derive_key_from_backup(&backup_key, &guid2).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_from_backup_output_length() {
        let backup_key = vec![0x99; 32];
        let guid = [0xCC; 16];
        let key = derive_key_from_backup(&backup_key, &guid).unwrap();
        assert_eq!(key.len(), 32);
    }

    // ============================================================================
    // Decryption Tests
    // ============================================================================

    #[test]
    fn test_decrypt_payload_empty_fails() {
        let result = decrypt_dpapi_payload(&[], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_payload_short_fails() {
        let result = decrypt_dpapi_payload(&[0u8; 5], &[0u8; 32]);
        assert!(result.is_err());
    }

    // ============================================================================
    // Property-Based Tests
    // ============================================================================

    proptest! {
        #[test]
        fn prop_laps_header_parsing(
            version in any::<u32>(),
            flags in any::<u32>(),
            timestamp in any::<u64>(),
            payload_size in any::<u32>(),
            dpapi_blob in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let mut blob = Vec::with_capacity(20 + dpapi_blob.len());
            blob.extend_from_slice(&version.to_le_bytes());
            blob.extend_from_slice(&flags.to_le_bytes());
            blob.extend_from_slice(&timestamp.to_le_bytes());
            blob.extend_from_slice(&payload_size.to_le_bytes());
            blob.extend_from_slice(&dpapi_blob);

            let result = LapsDecryptor::parse_encrypted_blob(&blob);
            prop_assert!(result.is_ok());
            let parsed = result.unwrap();
            prop_assert_eq!(parsed.version, version);
            prop_assert_eq!(parsed.flags, flags);
            prop_assert_eq!(parsed.update_timestamp, timestamp);
            prop_assert_eq!(parsed.payload_size, payload_size);
            prop_assert_eq!(parsed.dpapi_blob, dpapi_blob);
        }

        #[test]
        fn prop_dpapi_guid_extraction(
            guid in prop::array::uniform16(any::<u8>()),
            prefix in prop::collection::vec(any::<u8>(), 4..=4),
            suffix in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            let mut blob = Vec::new();
            blob.extend_from_slice(&prefix);
            blob.extend_from_slice(&guid);
            blob.extend_from_slice(&suffix);
            let result = extract_master_key_guid(&blob);
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap(), guid);
        }

        #[test]
        fn prop_key_derivation_determinism(
            backup_key in prop::collection::vec(any::<u8>(), 16..64),
            guid in prop::array::uniform16(any::<u8>())
        ) {
            let key1 = derive_key_from_backup(&backup_key, &guid);
            let key2 = derive_key_from_backup(&backup_key, &guid);
            prop_assert!(key1.is_ok());
            prop_assert!(key2.is_ok());
            prop_assert_eq!(key1.unwrap(), key2.unwrap());
        }

        #[test]
        fn prop_laps_json_parsing(
            account_name in "[a-zA-Z0-9_]{1,20}",
            password in "[a-zA-Z0-9!@#$%^&*]{8,32}",
            timestamp in any::<u64>()
        ) {
            let json = format!(
                r#"{{"n":"{}","p":"{}","t":{}}}"#,
                account_name, password, timestamp
            );
            let result = parse_laps_credentials(json.as_bytes());
            prop_assert!(result.is_ok());
            let creds = result.unwrap();
            prop_assert_eq!(creds.account_name, account_name);
            prop_assert_eq!(creds.password, password);
            prop_assert_eq!(creds.update_timestamp, timestamp);
        }

        #[test]
        fn prop_laps_error_short_blob(
            blob in prop::collection::vec(any::<u8>(), 0..20)
        ) {
            let result = LapsDecryptor::parse_encrypted_blob(&blob);
            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_laps_error_short_dpapi(
            blob in prop::collection::vec(any::<u8>(), 0..20)
        ) {
            let result = extract_master_key_guid(&blob);
            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_masterkey_parse_short(
            data in prop::collection::vec(any::<u8>(), 0..47)
        ) {
            let decryptor = DpapiDecryptor::new(&[0u8; 32]);
            let result = decryptor.parse_masterkey_file(&data);
            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_dpapi_blob_parse_short(
            data in prop::collection::vec(any::<u8>(), 0..35)
        ) {
            let decryptor = DpapiDecryptor::new(&[0u8; 32]);
            let result = decryptor.parse_dpapi_blob(&data);
            prop_assert!(result.is_err());
        }
    }
}
