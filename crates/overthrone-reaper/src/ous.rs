//! Organizational Unit enumeration.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

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
    Err(OverthroneError::NotImplemented { module: "reaper::ous".into() })
}
