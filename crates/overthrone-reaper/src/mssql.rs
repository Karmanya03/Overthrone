//! MSSQL instance enumeration via SPN scanning.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

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
    pub fn from_spn(spn: &str, account: &str, dn: &str, enabled: bool) -> Self {
        let parts: Vec<&str> = spn.splitn(2, '/').collect();
        let (hostname, instance, port) = if parts.len() == 2 {
            let target = parts[1];
            if let Some((host, rest)) = target.split_once(':') {
                let port = rest.parse::<u16>().ok();
                let instance = if port.is_none() { Some(rest.to_string()) } else { None };
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
    "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=MSSQLSvc/*))".to_string()
}

pub async fn enumerate_mssql(config: &ReaperConfig) -> Result<Vec<MssqlInstance>> {
    info!("[mssql] Querying {} for MSSQL service accounts", config.dc_ip);
    Err(OverthroneError::NotImplemented { module: "reaper::mssql".into() })
}
