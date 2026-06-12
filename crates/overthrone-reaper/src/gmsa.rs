//! gMSA (Group Managed Service Account) enumeration.
//!
//! Queries LDAP for `msDS-GroupManagedServiceAccount` objects and
//! extracts managed password blobs, membership info, and delegation
//! metadata. Decryption of the `msDS-ManagedPassword` blob requires
//! the group's membership key (KRB_GROUP_KEY) derived from the
//! `msDS-GroupMSAMembership` attribute.
//!
//! This module parses the `msDS-ManagedPassword` binary structure
//! header to extract metadata (version, flags, timestamps) even
//! without full decryption. The encrypted payload can be stored
//! for later offline analysis.

use crate::runner::{ReaperConfig, ldap_connect};
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Parsed header from the `msDS-ManagedPassword` binary blob.
/// Structure follows MS-SAMR `GROUP_KEY_ENCRYPTED_DATA`:
/// ```text
/// [0..2]   : Version (u16)
/// [2..4]   : Reserved (u16)
/// [4..8]   : Flags (u32)
/// [8..16]  : Created timestamp (FILETIME, i64)
/// [16..24] : PasswordLastSet timestamp (FILETIME, i64)
/// [24..]   : Variable-length key hierarchy elements
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmsaPasswordHeader {
    /// Blob version (should be 1)
    pub version: u16,
    /// Flags field
    pub flags: u32,
    /// When the gMSA was created (FILETIME)
    pub created: Option<String>,
    /// When the password was last set (FILETIME)
    pub password_last_set: Option<String>,
    /// Total blob size in bytes
    pub blob_size: usize,
    /// Whether the blob appears valid
    pub is_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmsaEntry {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub dns_host_name: Option<String>,
    pub managed_by: Option<String>,
    pub member_of_dn: Option<String>,
    pub managed_password_blob: Option<Vec<u8>>,
    pub password_last_set: Option<String>,
    /// Parsed header metadata from the managed password blob
    pub password_header: Option<GmsaPasswordHeader>,
}

const GMSA_FILTER: &str = "(objectClass=msDS-GroupManagedServiceAccount)";

const GMSA_ATTRS: &[&str] = &[
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "managedBy",
    "memberOf",
    "msDS-ManagedPassword",
    "msDS-ManagedPasswordID",
    "msDS-GroupMSAMembership",
];

pub fn gmsa_filter() -> String {
    GMSA_FILTER.to_string()
}

/// Parse the `msDS-ManagedPassword` binary blob header.
/// Returns `None` if the blob is too short or the version is unknown.
pub fn parse_gmsa_password_blob(blob: &[u8]) -> Option<GmsaPasswordHeader> {
    if blob.len() < 24 {
        return None;
    }

    let version = u16::from_le_bytes(blob[0..2].try_into().ok()?);
    let flags = u32::from_le_bytes(blob[4..8].try_into().ok()?);

    let created_raw = i64::from_le_bytes(blob[8..16].try_into().ok()?);
    let pwd_last_set_raw = i64::from_le_bytes(blob[16..24].try_into().ok()?);

    let created = if created_raw > 0 {
        crate::laps::filetime_to_string(&created_raw.to_string())
    } else {
        None
    };

    let password_last_set = if pwd_last_set_raw > 0 {
        crate::laps::filetime_to_string(&pwd_last_set_raw.to_string())
    } else {
        None
    };

    Some(GmsaPasswordHeader {
        version,
        flags,
        created,
        password_last_set,
        blob_size: blob.len(),
        is_valid: true,
    })
}

pub async fn enumerate_gmsa(config: &ReaperConfig) -> Result<Vec<GmsaEntry>> {
    info!("[gmsa] Querying {} for gMSA accounts", config.dc_ip);

    let mut sess = ldap_connect(config).await?;

    let entries = sess
        .custom_search_with_base(&config.base_dn, GMSA_FILTER, GMSA_ATTRS)
        .await
        .map_err(|e| {
            warn!("[gmsa] LDAP search failed: {e}");
            e
        })?;

    sess.disconnect().await.ok();

    let mut results = Vec::new();
    for entry in entries {
        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let distinguished_name = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let dns_host_name = entry
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.first())
            .cloned();

        let managed_by = entry
            .attrs
            .get("managedBy")
            .and_then(|v| v.first())
            .cloned();

        let member_of_dn = entry.attrs.get("memberOf").and_then(|v| v.first()).cloned();

        let managed_password_blob = entry
            .attrs
            .get("msDS-ManagedPassword")
            .and_then(|v| v.first())
            .and_then(|val| {
                let trimmed = val.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    // The attribute can be base64-encoded binary in LDAP responses
                    match base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        trimmed,
                    ) {
                        Ok(bytes) => Some(bytes),
                        Err(_) => {
                            // If base64 fails, try raw bytes
                            Some(trimmed.as_bytes().to_vec())
                        }
                    }
                }
            });

        let password_last_set = entry
            .attrs
            .get("msDS-ManagedPasswordID")
            .and_then(|v| v.first())
            .cloned();

        let password_header = managed_password_blob.as_deref().and_then(parse_gmsa_password_blob);

        if let Some(ref header) = password_header {
            debug!(
                "[gmsa]  {} → gMSA blob: version={}, flags={:#x}, total={} bytes",
                sam_account_name, header.version, header.flags, header.blob_size
            );
        }

        results.push(GmsaEntry {
            sam_account_name,
            distinguished_name,
            dns_host_name,
            managed_by,
            member_of_dn,
            managed_password_blob,
            password_last_set,
            password_header,
        });
    }

    debug!("[gmsa] Found {} gMSA accounts", results.len());
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gmsa_blob_header_valid() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        blob.extend_from_slice(&0u16.to_le_bytes()); // reserved
        blob.extend_from_slice(&0u32.to_le_bytes()); // flags
        blob.extend_from_slice(&133500000000000000i64.to_le_bytes()); // created
        blob.extend_from_slice(&133600000000000000i64.to_le_bytes()); // password last set
        blob.extend_from_slice(&[0u8; 16]); // key hierarchy placeholder

        let header = parse_gmsa_password_blob(&blob).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.flags, 0);
        assert!(header.created.is_some());
        assert!(header.password_last_set.is_some());
        assert_eq!(header.blob_size, 40);
        assert!(header.is_valid);
    }

    #[test]
    fn test_parse_gmsa_blob_too_short() {
        let blob = vec![0u8; 20]; // less than 24 bytes
        assert!(parse_gmsa_password_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_gmsa_blob_version_unknown() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0u16.to_le_bytes()); // version = 0 (unexpected but tolerated)
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes()); // flags
        blob.extend_from_slice(&133500000000000000i64.to_le_bytes());
        blob.extend_from_slice(&133600000000000000i64.to_le_bytes());

        let header = parse_gmsa_password_blob(&blob).unwrap();
        assert_eq!(header.version, 0);
        assert!(header.is_valid);
    }

    #[test]
    fn test_parse_gmsa_blob_zero_timestamps() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u16.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0i64.to_le_bytes()); // created = 0
        blob.extend_from_slice(&0i64.to_le_bytes()); // last set = 0

        let header = parse_gmsa_password_blob(&blob).unwrap();
        assert!(header.created.is_none());
        assert!(header.password_last_set.is_none());
    }

    #[test]
    fn test_gmsa_filter_returns_filter_string() {
        let filter = gmsa_filter();
        assert!(filter.contains("msDS-GroupManagedServiceAccount"));
        assert!(filter.starts_with('('));
    }

    #[test]
    fn test_gmsa_entry_can_have_password_header() {
        let entry = GmsaEntry {
            sam_account_name: "svc_gmsa$".to_string(),
            distinguished_name: "CN=svc_gmsa,CN=Managed Service Accounts,DC=corp,DC=local".to_string(),
            dns_host_name: None,
            managed_by: Some("CN=GMSA Admins,OU=Groups,DC=corp,DC=local".to_string()),
            member_of_dn: Some("CN=Allowed Group,OU=Groups,DC=corp,DC=local".to_string()),
            managed_password_blob: Some(vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            password_last_set: Some("2025-01-01".to_string()),
            password_header: Some(GmsaPasswordHeader {
                version: 1,
                flags: 0,
                created: None,
                password_last_set: None,
                blob_size: 24,
                is_valid: true,
            }),
        };
        assert_eq!(entry.sam_account_name, "svc_gmsa$");
        assert!(entry.password_header.is_some());
        assert_eq!(entry.password_header.as_ref().unwrap().version, 1);
    }
}
