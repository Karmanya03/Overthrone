//! gMSA (Group Managed Service Account) enumeration.
//!
//! Queries LDAP for `msDS-GroupManagedServiceAccount` objects and
//! extracts managed password blobs, membership info, and delegation
//! metadata. Decryption of the `msDS-ManagedPassword` blob requires
//! the group's membership key (KRB_GROUP_KEY) derived from the
//! `msDS-GroupMSAMembership` attribute.

use crate::runner::{ReaperConfig, ldap_connect};
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmsaEntry {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub dns_host_name: Option<String>,
    pub managed_by: Option<String>,
    pub member_of_dn: Option<String>,
    pub managed_password_blob: Option<Vec<u8>>,
    pub password_last_set: Option<String>,
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

        results.push(GmsaEntry {
            sam_account_name,
            distinguished_name,
            dns_host_name,
            managed_by,
            member_of_dn,
            managed_password_blob,
            password_last_set,
        });
    }

    debug!("[gmsa] Found {} gMSA accounts", results.len());
    Ok(results)
}
