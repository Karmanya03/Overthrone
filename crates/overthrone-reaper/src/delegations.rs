//! Delegation enumeration — unconstrained, constrained, RBCD.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

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

pub async fn enumerate_delegations(config: &ReaperConfig) -> Result<Vec<DelegationEntry>> {
    info!("[delegations] Querying {} for delegation configs", config.dc_ip);
    Err(OverthroneError::NotImplemented { module: "reaper::delegations".into() })
}
