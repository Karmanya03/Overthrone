//! Domain trust enumeration.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustDirection {
    Inbound,
    Outbound,
    Bidirectional,
    Unknown(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustType {
    ParentChild,
    External,
    Forest,
    CrossLink,
    Unknown(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub target_domain: String,
    pub direction: TrustDirection,
    pub trust_type: TrustType,
    pub transitive: bool,
    pub sid_filtering_enabled: bool,
    pub tgt_delegation_enabled: bool,
}

pub fn trust_filter() -> String {
    "(objectClass=trustedDomain)".to_string()
}

pub async fn enumerate_trusts(config: &ReaperConfig) -> Result<Vec<TrustEntry>> {
    info!("[trusts] Querying {} for domain trusts", config.dc_ip);
    Err(OverthroneError::NotImplemented { module: "reaper::trusts".into() })
}
