use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};

/// LAPS v2 encrypted blob structure
///
/// Format:
/// - Offset 0x00 (4 bytes): Version (0x00000001)
/// - Offset 0x04 (4 bytes): Flags
/// - Offset 0x08 (8 bytes): Update Timestamp (FILETIME)
/// - Offset 0x10 (4 bytes): Payload Size
/// - Offset 0x14 (N bytes): DPAPI Blob
#[derive(Debug, Clone)]
pub struct LapsEncryptedBlob {
    pub version: u32,
    pub flags: u32,
    pub update_timestamp: u64,
    pub payload_size: u32,
    pub dpapi_blob: Vec<u8>,
}

/// DPAPI backup key for decryption
#[derive(Debug, Clone)]
pub struct DpapiBackupKey {
    pub guid: [u8; 16],
    pub key_material: Vec<u8>,
}

/// Decrypted LAPS credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsCredentials {
    #[serde(rename = "n")]
    pub account_name: String,
    #[serde(rename = "p")]
    pub password: String,
    #[serde(rename = "t")]
    pub update_timestamp: u64,
}

/// LAPS v2 DPAPI decryptor
pub struct LapsDecryptor;

impl LapsDecryptor {
    /// Parse LAPS v2 encrypted blob from bytes
    ///
    /// # Arguments
    /// * `data` - Raw encrypted blob bytes
    ///
    /// # Returns
    /// * `Ok(LapsEncryptedBlob)` - Parsed blob structure
    /// * `Err(OverthroneError)` - If blob is malformed or too short
    pub fn parse_encrypted_blob(data: &[u8]) -> Result<LapsEncryptedBlob> {
        // Minimum size: 4 (version) + 4 (flags) + 8 (timestamp) + 4 (size) = 20 bytes
        if data.len() < 20 {
            return Err(OverthroneError::Decryption(format!(
                "LAPS blob too short: {} bytes (expected >= 20)",
                data.len()
            )));
        }

        // Parse header fields (little-endian)
        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let update_timestamp = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let payload_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

        // Extract DPAPI blob (remaining bytes after header)
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
    ///
    /// # Arguments
    /// * `blob` - Parsed encrypted blob
    /// * `backup_key` - DPAPI backup key
    ///
    /// # Returns
    /// * `Ok(LapsCredentials)` - Decrypted credentials
    /// * `Err(OverthroneError)` - If decryption fails
    pub fn decrypt(
        blob: &LapsEncryptedBlob,
        backup_key: &DpapiBackupKey,
    ) -> Result<LapsCredentials> {
        // Extract master key GUID from DPAPI blob
        let master_key_guid = Self::extract_master_key_guid(&blob.dpapi_blob)?;

        // Derive decryption key from backup key and master key GUID
        let decryption_key =
            Self::derive_decryption_key(&backup_key.key_material, &master_key_guid)?;

        // Decrypt the payload using AES-256-GCM
        let decrypted_data = Self::decrypt_payload(&blob.dpapi_blob, &decryption_key)?;

        // Parse decrypted JSON payload
        Self::parse_credentials(&decrypted_data)
    }

    /// Extract master key GUID from DPAPI blob
    ///
    /// DPAPI blob structure:
    /// - Offset 0x00 (4 bytes): Version
    /// - Offset 0x04 (16 bytes): Master Key GUID
    /// - Offset 0x14 (4 bytes): Algorithm ID
    /// - Offset 0x18 (N bytes): Encrypted Data
    /// - Offset 0x?? (32 bytes): HMAC
    fn extract_master_key_guid(dpapi_blob: &[u8]) -> Result<[u8; 16]> {
        if dpapi_blob.len() < 20 {
            return Err(OverthroneError::Decryption(format!(
                "DPAPI blob too short: {} bytes (expected >= 20)",
                dpapi_blob.len()
            )));
        }

        // Extract GUID from offset 0x04
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&dpapi_blob[4..20]);

        Ok(guid)
    }

    /// Derive decryption key from backup key and master key GUID
    ///
    /// Uses HMAC-SHA512(backup_key, master_key_guid) to derive the key
    fn derive_decryption_key(backup_key: &[u8], master_key_guid: &[u8; 16]) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let mut mac = HmacSha512::new_from_slice(backup_key).map_err(|e| {
            OverthroneError::Encryption(format!("HMAC initialization failed: {}", e))
        })?;

        mac.update(master_key_guid);

        let result = mac.finalize();
        let key_bytes = result.into_bytes();

        // Return first 32 bytes for AES-256
        Ok(key_bytes[..32].to_vec())
    }

    /// Decrypt payload using AES-256-GCM
    ///
    /// Extracts nonce and encrypted data from DPAPI blob, then decrypts
    fn decrypt_payload(dpapi_blob: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };

        // DPAPI blob structure for CNG-DPAPI:
        // - Header (20 bytes): version + guid + algorithm
        // - Nonce (12 bytes): GCM nonce
        // - Encrypted data + tag (N bytes)

        if dpapi_blob.len() < 32 {
            return Err(OverthroneError::Decryption(
                "DPAPI blob too short for CNG-DPAPI format".to_string(),
            ));
        }

        // Extract nonce (12 bytes after header)
        let nonce_bytes = &dpapi_blob[20..32];
        let nonce = Nonce::from_slice(nonce_bytes);

        // Extract encrypted data (everything after nonce)
        let encrypted_data = &dpapi_blob[32..];

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            OverthroneError::Decryption(format!("AES-GCM initialization failed: {}", e))
        })?;

        // Decrypt
        let plaintext = cipher.decrypt(nonce, encrypted_data).map_err(|e| {
            OverthroneError::Decryption(format!("AES-GCM decryption failed: {}", e))
        })?;

        Ok(plaintext)
    }

    /// Parse decrypted JSON payload
    ///
    /// Expected JSON format:
    /// ```json
    /// {
    ///   "n": "account_name",
    ///   "p": "password",
    ///   "t": 132345678901234567
    /// }
    /// ```
    fn parse_credentials(json_data: &[u8]) -> Result<LapsCredentials> {
        serde_json::from_slice(json_data).map_err(|e| {
            OverthroneError::Decryption(format!("Failed to parse LAPS credentials JSON: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ============================================================================
    // Unit Tests
    // ============================================================================

    #[test]
    fn test_parse_encrypted_blob_too_short() {
        let short_blob = vec![0x01, 0x00, 0x00]; // Only 3 bytes
        let result = LapsDecryptor::parse_encrypted_blob(&short_blob);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OverthroneError::Decryption(_)
        ));
    }

    #[test]
    fn test_parse_encrypted_blob_minimum_size() {
        // Create a minimal valid blob (20 bytes header + 1 byte payload)
        let mut blob = vec![0u8; 21];
        blob[0..4].copy_from_slice(&1u32.to_le_bytes()); // version = 1
        blob[4..8].copy_from_slice(&0u32.to_le_bytes()); // flags = 0
        blob[8..16].copy_from_slice(&0u64.to_le_bytes()); // timestamp = 0
        blob[16..20].copy_from_slice(&1u32.to_le_bytes()); // payload_size = 1
        blob[20] = 0xFF; // dummy DPAPI blob

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
    fn test_extract_master_key_guid_too_short() {
        let short_blob = vec![0u8; 10];
        let result = LapsDecryptor::extract_master_key_guid(&short_blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_master_key_guid_valid() {
        let mut blob = vec![0u8; 20];
        // Set a known GUID at offset 4
        let test_guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        blob[4..20].copy_from_slice(&test_guid);

        let result = LapsDecryptor::extract_master_key_guid(&blob);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_guid);
    }

    // ============================================================================
    // Property-Based Tests
    // ============================================================================

    // Property 2: LAPS Header Parsing
    // For any valid header values, parsing should succeed and preserve all fields
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
    }

    // Property 3: DPAPI Master Key GUID Extraction
    // For any DPAPI blob >= 20 bytes, GUID extraction should succeed and return bytes at offset 4-20
    proptest! {
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

            let result = LapsDecryptor::extract_master_key_guid(&blob);
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap(), guid);
        }
    }

    // Property 4: DPAPI Key Derivation Determinism
    // For the same inputs, key derivation should always produce the same output
    proptest! {
        #[test]
        fn prop_dpapi_key_derivation_determinism(
            backup_key in prop::collection::vec(any::<u8>(), 16..64),
            guid in prop::array::uniform16(any::<u8>())
        ) {
            let key1 = LapsDecryptor::derive_decryption_key(&backup_key, &guid);
            let key2 = LapsDecryptor::derive_decryption_key(&backup_key, &guid);

            prop_assert!(key1.is_ok());
            prop_assert!(key2.is_ok());
            prop_assert_eq!(key1.unwrap(), key2.unwrap());
        }
    }

    // Property 5: LAPS JSON Parsing
    // For any valid JSON with required fields, parsing should succeed
    proptest! {
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

            let result = LapsDecryptor::parse_credentials(json.as_bytes());
            prop_assert!(result.is_ok());

            let creds = result.unwrap();
            prop_assert_eq!(creds.account_name, account_name);
            prop_assert_eq!(creds.password, password);
            prop_assert_eq!(creds.update_timestamp, timestamp);
        }
    }

    // Property 6: LAPS Error Handling for Malformed Input
    // For blobs shorter than 20 bytes, parsing should fail
    proptest! {
        #[test]
        fn prop_laps_error_handling_short_blob(
            blob in prop::collection::vec(any::<u8>(), 0..20)
        ) {
            let result = LapsDecryptor::parse_encrypted_blob(&blob);
            prop_assert!(result.is_err());
        }
    }

    // Property 7: LAPS Error Handling for Invalid Keys
    // For DPAPI blobs shorter than 20 bytes, GUID extraction should fail
    proptest! {
        #[test]
        fn prop_laps_error_handling_short_dpapi_blob(
            blob in prop::collection::vec(any::<u8>(), 0..20)
        ) {
            let result = LapsDecryptor::extract_master_key_guid(&blob);
            prop_assert!(result.is_err());
        }
    }
}
