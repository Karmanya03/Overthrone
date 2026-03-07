//! MSSQL instance enumeration via SPN scanning.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlInstance {
    pub service_account: String,
    pub distinguished_name: String,
    pub spn: String,
    pub hostname: Option<String>,
    pub instance_name: Option<String>,
    pub port: Option<u16>,
    pub enabled: bool,
}

impl MssqlInstance {
    /// Parse a MSSQLSvc SPN into its components.
    /// Format: MSSQLSvc/<host>:<port|instance>
    pub fn from_spn(spn: &str, account: &str, dn: &str, enabled: bool) -> Self {
        let parts: Vec<&str> = spn.splitn(2, '/').collect();
        let (hostname, instance, port) = if parts.len() == 2 {
            let target = parts[1];
            if let Some((host, rest)) = target.split_once(':') {
                let port = rest.parse::<u16>().ok();
                let instance = if port.is_none() {
                    Some(rest.to_string())
                } else {
                    None
                };
                (Some(host.to_string()), instance, port)
            } else {
                (Some(target.to_string()), None, None)
            }
        } else {
            (None, None, None)
        };

        MssqlInstance {
            service_account: account.to_string(),
            distinguished_name: dn.to_string(),
            spn: spn.to_string(),
            hostname,
            instance_name: instance,
            port,
            enabled,
        }
    }
}

pub fn mssql_filter() -> String {
    // Include user accounts, computer accounts, and MSA/gMSA accounts that may
    // run MSSQL services. Limiting to objectCategory=person misses computer-hosted
    // SQL instances and Managed Service Accounts.
    "(&(servicePrincipalName=MSSQLSvc/*)(|(objectCategory=person)(objectCategory=computer)(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount)))".to_string()
}

pub async fn enumerate_mssql(config: &ReaperConfig) -> Result<Vec<MssqlInstance>> {
    info!(
        "[mssql] Querying {} for MSSQL service accounts",
        config.dc_ip
    );

    let mut conn = crate::runner::ldap_connect(config).await?;

    let filter = mssql_filter();
    let attrs = &[
        "sAMAccountName",
        "distinguishedName",
        "servicePrincipalName",
        "userAccountControl",
        "pwdLastSet",
        "adminCount",
    ];

    let entries = match conn.custom_search(&filter, attrs).await {
        Ok(e) => e,
        Err(e) => {
            warn!("[mssql] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let account = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.clone());

        let uac: u32 = entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let enabled = uac & 0x0002 == 0; // bit 1 = ACCOUNTDISABLE

        let spns: Vec<String> = entry
            .attrs
            .get("servicePrincipalName")
            .cloned()
            .unwrap_or_default();

        for spn in &spns {
            // Only include MSSQLSvc SPNs
            if !spn.to_uppercase().starts_with("MSSQLSVC/") {
                continue;
            }

            let instance = MssqlInstance::from_spn(spn, &account, &entry.dn, enabled);

            info!(
                "[mssql]  {} → {} (host: {}, port: {:?})",
                account,
                spn,
                instance.hostname.as_deref().unwrap_or("?"),
                instance.port
            );

            results.push(instance);
        }
    }

    let _ = conn.disconnect().await;

    info!(
        "[mssql] Found {} MSSQL instances across {} accounts",
        results.len(),
        entries.len()
    );
    Ok(results)
}
