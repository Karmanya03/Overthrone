//! Organizational Unit enumeration.

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuEntry {
    pub name: String,
    pub distinguished_name: String,
    pub description: Option<String>,
    pub linked_gpos: Vec<String>,
}

pub fn ou_filter() -> String {
    "(objectCategory=organizationalUnit)".to_string()
}

pub async fn enumerate_ous(config: &ReaperConfig) -> Result<Vec<OuEntry>> {
    info!("[ous] Querying {} for organizational units", config.dc_ip);

    let mut conn = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    ).await?;

    let filter = ou_filter();
    let attrs = &[
        "ou",
        "distinguishedName",
        "description",
        "gPLink",
        "gPOptions",
        "name",
    ];

    let entries = match conn.custom_search(&filter, attrs).await {
        Ok(e) => e,
        Err(e) => {
            warn!("[ous] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let name = entry.attrs
            .get("ou")
            .or_else(|| entry.attrs.get("name"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.clone());

        let description = entry.attrs
            .get("description")
            .and_then(|v| v.first())
            .cloned();

        // gPLink contains semicolon-separated GPO DNs like
        // [LDAP://CN={GUID},CN=Policies,...;0][...]
        let linked_gpos: Vec<String> = entry.attrs
            .get("gPLink")
            .and_then(|v| v.first())
            .map(|s| {
                s.split(']')
                    .filter(|seg| seg.starts_with('['))
                    .filter_map(|seg| {
                        let inner = seg.trim_start_matches('[');
                        inner.split(';').next().map(|dn| {
                            dn.trim_start_matches("LDAP://").to_string()
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        info!("[ous]  {} (linked GPOs: {})", name, linked_gpos.len());

        results.push(OuEntry {
            name,
            distinguished_name: entry.dn.clone(),
            description,
            linked_gpos,
        });
    }

    let _ = conn.disconnect().await;

    info!("[ous] Found {} organizational units", results.len());
    Ok(results)
}
