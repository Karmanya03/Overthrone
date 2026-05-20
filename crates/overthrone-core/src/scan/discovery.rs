//! Unauthenticated discovery and reconnaissance.
//!
//! Performs checks that do not require credentials:
//! - LDAP rootDSE pre-bind probe (works even when anonymous bind is disabled)
//! - LDAP Null Session (rootDSE, namingContexts)
//! - SMB Null Session (shares, sessions)
//! - NetBIOS Name Service (NBNS) enumeration
//! - RPC Endpoint Mapper (epmapper) dump

use crate::error::Result;
use crate::proto::ldap::{LdapSession, probe_rootdse_raw};
use crate::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use tracing::info;
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    /// Target domain FQDN
    pub target: String,
    /// ldap null session field
    pub ldap_null_session: bool,
    /// ldap rootdse probe succeeded (pre-bind, no auth)
    pub ldap_rootdse_probe: bool,
    /// smb null session field
    pub smb_null_session: bool,
    /// naming contexts field
    pub naming_contexts: Vec<String>,
    /// dns host name from rootDSE
    pub dns_hostname: Option<String>,
    /// supported SASL mechanisms
    pub supported_sasl_mechs: Vec<String>,
    /// Object or account name.
    pub netbios_name: Option<String>,
    /// accessible shares field
    pub accessible_shares: Vec<String>,
}
/// Data structure used by this module.
pub struct UnauthDiscovery {
    /// Target domain FQDN
    pub target: String,
}

impl UnauthDiscovery {
    /// Runs this module operation.
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
            ldap_rootdse_probe: false,
            smb_null_session: false,
            naming_contexts: Vec::new(),
            dns_hostname: None,
            supported_sasl_mechs: Vec::new(),
            netbios_name: None,
            accessible_shares: Vec::new(),
        };

        // 1. LDAP rootDSE pre-bind probe (works without any bind, even on Windows 2025)
        match probe_rootdse_raw(&self.target, false).await {
            Ok(rootdse) => {
                result.ldap_rootdse_probe = true;
                result.dns_hostname = rootdse.dns_domain_name.clone();
                result.supported_sasl_mechs = rootdse.supported_sasl_mechanisms.clone();
                result.naming_contexts = rootdse.naming_contexts.clone();
                info!(
                    "[discovery] rootDSE probe OK on {}: domain={:?}, sasl={:?}",
                    self.target, rootdse.dns_domain_name, rootdse.supported_sasl_mechanisms
                );
            }
            Err(e) => {
                info!("[discovery] rootDSE probe failed on {}: {}", self.target, e);
            }
        }

        // 2. LDAP Null Session check (anonymous bind — may fail on Windows 2025)
        if let Ok(mut ldap) = LdapSession::connect_anonymous(&self.target, "", false).await {
            result.ldap_null_session = true;
            info!("[discovery] LDAP Null Session OK on {}", self.target);

            // Try to read rootDSE for naming contexts
            if result.naming_contexts.is_empty()
                && let Ok(entries) = ldap
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

        // 3. SMB Null Session check
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
