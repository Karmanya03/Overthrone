//! SPN enumeration — finds Kerberoastable accounts.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpnAccount {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub service_principal_names: Vec<String>,
    pub enabled: bool,
    pub admin_count: bool,
    pub password_last_set: Option<String>,
}

impl SpnAccount {
    pub fn is_high_value_target(&self) -> bool {
        self.enabled && self.admin_count
    }
}

pub fn spn_filter() -> String {
    "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))".to_string()
}

pub async fn enumerate_spn_accounts(config: &ReaperConfig) -> Result<Vec<SpnAccount>> {
    info!("[spns] Querying {} for Kerberoastable accounts", config.dc_ip);
    Err(OverthroneError::NotImplemented { module: "reaper::spns".into() })
}
