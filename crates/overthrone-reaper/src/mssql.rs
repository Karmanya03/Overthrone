//! MSSQL instance enumeration via SPN scanning.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use overthrone_core::mssql::{LinkCrawler, LinkCrawlerConfig, MssqlClient, MssqlConfig};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlInstance {
    /// Item count
    pub service_account: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Service Principal Name
    pub spn: String,
    /// Object or account name.
    pub hostname: Option<String>,
    /// Object or account name.
    pub instance_name: Option<String>,
    /// Port number
    pub port: Option<u16>,
    /// enabled field
    pub enabled: bool,
    /// audit result field
    pub audit_result: Option<MssqlAuditResult>,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlAuditResult {
    /// is sysadmin field
    pub is_sysadmin: bool,
    /// xp cmdshell enabled field
    pub xp_cmdshell_enabled: bool,
    /// can impersonate sa field
    pub can_impersonate_sa: bool,
    /// links field
    pub links: Vec<String>,
}

impl MssqlInstance {
    /// Parse a MSSQLSvc SPN into its components.
    /// Format: `MSSQLSvc/<host>:<port|instance>`
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
            audit_result: None,
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

            let mut instance = MssqlInstance::from_spn(spn, &account, &entry.dn, enabled);
            instance.audit_result = None;

            info!(
                "[mssql]  {} → {} (host: {}, port: {:?})",
                account,
                spn,
                instance.hostname.as_deref().unwrap_or("?"),
                instance.port
            );

            // Optional: perform deep audit if credentials are available
            if let (Some(host), Some(pass)) = (&instance.hostname, &config.password) {
                let mssql_config = MssqlConfig {
                    server: host.clone(),
                    port: instance.port.unwrap_or(1433),
                    domain: Some(config.domain.clone()),
                    username: Some(config.username.clone()),
                    password: Some(pass.clone()),
                    ..Default::default()
                };

                if let Ok(mut client) = MssqlClient::connect(mssql_config).await {
                    debug!("[mssql] Connected to {}, performing audit", host);
                    let mut audit = MssqlAuditResult {
                        is_sysadmin: false,
                        xp_cmdshell_enabled: false,
                        can_impersonate_sa: false,
                        links: Vec::new(),
                    };

                    // Check sysadmin
                    if let Ok(res) = client.query("SELECT IS_SRVROLEMEMBER('sysadmin')").await
                        && let Some(val) = res.get(0, 0).and_then(|v| v.as_deref())
                    {
                        audit.is_sysadmin = val == "1";
                    }

                    // Check xp_cmdshell
                    if audit.is_sysadmin
                        && let Ok(res) = client
                            .query(
                                "SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell'",
                            )
                            .await
                        && let Some(val) = res.get(0, 0).and_then(|v| v.as_deref())
                    {
                        audit.xp_cmdshell_enabled = val == "1";
                    }

                    // Crawl links (PowerUpSQL-style)
                    let mut crawler = LinkCrawler::new(&mut client, LinkCrawlerConfig::default());
                    if let Ok(crawl_res) = crawler.crawl().await {
                        audit.links = crawl_res.nodes.keys().cloned().collect();
                    }

                    instance.audit_result = Some(audit);
                }
            }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mssql_filter() {
        let f = mssql_filter();
        assert!(f.contains("servicePrincipalName=MSSQLSvc/*"));
        assert!(f.contains("objectCategory=person"));
        assert!(f.contains("objectCategory=computer"));
        assert!(f.contains("msDS-GroupManagedServiceAccount"));
    }

    #[test]
    fn test_from_spn_host_port() {
        let inst = MssqlInstance::from_spn(
            "MSSQLSvc/sql01.contoso.com:1433",
            "svc_sql",
            "CN=SQL,DC=c",
            true,
        );
        assert_eq!(inst.hostname.as_deref(), Some("sql01.contoso.com"));
        assert_eq!(inst.port, Some(1433));
        assert!(inst.instance_name.is_none());
        assert_eq!(inst.service_account, "svc_sql");
        assert!(inst.enabled);
    }

    #[test]
    fn test_from_spn_host_instance() {
        let inst = MssqlInstance::from_spn(
            "MSSQLSvc/sql02.contoso.com:NAMEDINST",
            "svc_sql2",
            "CN=SQL2,DC=c",
            false,
        );
        assert_eq!(inst.hostname.as_deref(), Some("sql02.contoso.com"));
        assert!(inst.port.is_none());
        assert_eq!(inst.instance_name.as_deref(), Some("NAMEDINST"));
        assert!(!inst.enabled);
    }

    #[test]
    fn test_from_spn_host_only() {
        let inst = MssqlInstance::from_spn(
            "MSSQLSvc/sql03.contoso.com",
            "svc_sql3",
            "CN=SQL3,DC=c",
            true,
        );
        assert_eq!(inst.hostname.as_deref(), Some("sql03.contoso.com"));
        assert!(inst.port.is_none());
        assert!(inst.instance_name.is_none());
    }

    #[test]
    fn test_from_spn_malformed() {
        let inst = MssqlInstance::from_spn("not-a-valid-spn", "svc", "CN=Bad,DC=c", true);
        assert!(inst.hostname.is_none());
        assert!(inst.port.is_none());
        assert!(inst.instance_name.is_none());
        assert_eq!(inst.spn, "not-a-valid-spn");
    }
}
