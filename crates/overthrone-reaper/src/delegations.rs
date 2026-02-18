//! Delegation enumeration — unconstrained, constrained, RBCD.

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegationType {
    Unconstrained,
    Constrained,
    ConstrainedWithProtocolTransition,
    ResourceBased,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEntry {
    pub principal: String,
    pub distinguished_name: String,
    pub delegation_type: DelegationType,
    pub targets: Vec<String>,
    pub enabled: bool,
}

pub fn delegation_filter() -> String {
    "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))".to_string()
}

// UAC bits
const UAC_TRUSTED_FOR_DELEGATION: u32   = 0x00080000; // unconstrained
const UAC_TRUSTED_TO_AUTH: u32          = 0x01000000; // constrained w/ T2A4D
const UAC_NOT_DELEGATED: u32            = 0x00100000;
const UAC_DISABLED: u32                 = 0x00000002;

pub async fn enumerate_delegations(config: &ReaperConfig) -> Result<Vec<DelegationEntry>> {
    info!("[delegations] Querying {} for delegation configs", config.dc_ip);

    let mut conn = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    ).await?;

    let filter = delegation_filter();
    let attrs = &[
        "sAMAccountName",
        "distinguishedName",
        "userAccountControl",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ];

    let entries = match conn.custom_search(&filter, attrs).await {
        Ok(e) => e,
        Err(e) => {
            warn!("[delegations] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let principal = entry.attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.clone());

        let dn = entry.dn.clone();

        let uac: u32 = entry.attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let enabled = uac & UAC_DISABLED == 0;

        let constrained_targets: Vec<String> = entry.attrs
            .get("msDS-AllowedToDelegateTo")
            .cloned()
            .unwrap_or_default();

        let has_rbcd = entry.attrs
            .contains_key("msDS-AllowedToActOnBehalfOfOtherIdentity");

        // ── Unconstrained delegation (TRUSTED_FOR_DELEGATION, not DC)
        if uac & UAC_TRUSTED_FOR_DELEGATION != 0 {
            results.push(DelegationEntry {
                principal: principal.clone(),
                distinguished_name: dn.clone(),
                delegation_type: DelegationType::Unconstrained,
                targets: vec![],
                enabled,
            });
        }

        // ── Constrained delegation (with or without protocol transition)
        if !constrained_targets.is_empty() {
            let dtype = if uac & UAC_TRUSTED_TO_AUTH != 0 {
                DelegationType::ConstrainedWithProtocolTransition
            } else {
                DelegationType::Constrained
            };
            results.push(DelegationEntry {
                principal: principal.clone(),
                distinguished_name: dn.clone(),
                delegation_type: dtype,
                targets: constrained_targets,
                enabled,
            });
        }

        // ── Resource-Based Constrained Delegation
        if has_rbcd {
            results.push(DelegationEntry {
                principal: principal.clone(),
                distinguished_name: dn.clone(),
                delegation_type: DelegationType::ResourceBased,
                targets: vec!["(encoded in msDS-AllowedToActOnBehalfOfOtherIdentity)".into()],
                enabled,
            });
        }
    }

    let _ = conn.disconnect().await;

    info!("[delegations] Found {} delegation entries", results.len());
    Ok(results)
}
