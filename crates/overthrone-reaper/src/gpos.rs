//! Group Policy Object enumeration.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoEntry {
    pub display_name: String,
    pub distinguished_name: String,
    pub gpc_file_sys_path: Option<String>,
    pub flags: u32,
    pub version: u32,
}

pub fn gpo_filter() -> String {
    "(objectCategory=groupPolicyContainer)".to_string()
}

pub async fn enumerate_gpos(config: &ReaperConfig) -> Result<Vec<GpoEntry>> {
    info!("[gpos] Querying {} for GPOs", config.dc_ip);

    let mut conn = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    )
    .await?;

    let filter = gpo_filter();
    let attrs = &[
        "displayName",
        "distinguishedName",
        "gPCFileSysPath",
        "flags",
        "versionNumber",
        "cn",
        "whenChanged",
    ];

    let entries = match conn.custom_search(&filter, attrs).await {
        Ok(e) => e,
        Err(e) => {
            warn!("[gpos] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let display_name = entry
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| entry.attrs.get("cn").and_then(|v| v.first()).cloned())
            .unwrap_or_else(|| entry.dn.clone());

        let flags: u32 = entry
            .attrs
            .get("flags")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let version: u32 = entry
            .attrs
            .get("versionNumber")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let gpc_path = entry
            .attrs
            .get("gPCFileSysPath")
            .and_then(|v| v.first())
            .cloned();

        info!(
            "[gpos]  {} → {}",
            display_name,
            gpc_path.as_deref().unwrap_or("(no SYSVOL path)")
        );

        results.push(GpoEntry {
            display_name,
            distinguished_name: entry.dn.clone(),
            gpc_file_sys_path: gpc_path,
            flags,
            version,
        });
    }

    let _ = conn.disconnect().await;

    info!("[gpos] Found {} GPOs", results.len());
    Ok(results)
}
