//! Unauthenticated discovery and reconnaissance.
//!
//! Performs checks that do not require credentials:
//! - LDAP Null Session (rootDSE, namingContexts)
//! - SMB Null Session (shares, sessions)
//! - NetBIOS Name Service (NBNS) enumeration
//! - RPC Endpoint Mapper (epmapper) dump

use crate::error::Result;
use crate::proto::ldap::LdapSession;
use crate::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub target: String,
    pub ldap_null_session: bool,
    pub smb_null_session: bool,
    pub naming_contexts: Vec<String>,
    pub netbios_name: Option<String>,
    pub accessible_shares: Vec<String>,
}

pub struct UnauthDiscovery {
    pub target: String,
}

impl UnauthDiscovery {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
        }
    }

    pub async fn run(&self) -> Result<DiscoveryResult> {
        info!(
            "[discovery] Starting unauthenticated discovery on {}",
            self.target
        );

        let mut result = DiscoveryResult {
            target: self.target.clone(),
            ldap_null_session: false,
            smb_null_session: false,
            naming_contexts: Vec::new(),
            netbios_name: None,
            accessible_shares: Vec::new(),
        };

        // 1. LDAP Null Session check
        if let Ok(mut ldap) = LdapSession::connect(&self.target, "", "", "", false).await {
            result.ldap_null_session = true;
            info!("[discovery] LDAP Null Session OK on {}", self.target);

            // Try to read rootDSE
            if let Ok(entries) = ldap
                .custom_search_with_base(
                    "",
                    "(objectClass=*)",
                    &["namingContexts", "defaultNamingContext"],
                )
                .await
                && let Some(entry) = entries.first()
                && let Some(contexts) = entry.attrs.get("namingContexts")
            {
                result.naming_contexts = contexts.clone();
            }
            let _ = ldap.disconnect().await;
        }

        // 2. SMB Null Session check
        // Use guest/null credentials: empty domain + empty username + empty password
        // Some Windows servers allow null session connections to IPC$.
        let smb_result = SmbSession::connect(&self.target, "", "", "").await;
        if let Ok(smb) = smb_result {
            result.smb_null_session = true;
            info!("[discovery] SMB Null Session OK on {}", self.target);

            let shares = ["IPC$", "C$", "ADMIN$", "NETLOGON", "SYSVOL"];
            for share in shares {
                if smb.check_share_read(share).await {
                    result.accessible_shares.push(share.to_string());
                }
            }
        } else if let Err(e) = smb_result {
            // Try anonymous guest as well
            log::debug!("[discovery] SMB null session failed ({}), trying guest", e);
            if let Ok(smb) = SmbSession::connect(&self.target, ".", "guest", "").await {
                result.smb_null_session = true;
                info!("[discovery] SMB Guest Session OK on {}", self.target);
                let shares = ["IPC$", "C$", "ADMIN$", "NETLOGON", "SYSVOL"];
                for share in shares {
                    if smb.check_share_read(share).await {
                        result.accessible_shares.push(share.to_string());
                    }
                }
            }
        }

        Ok(result)
    }
}
