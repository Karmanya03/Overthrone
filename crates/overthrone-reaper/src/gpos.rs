//! Group Policy Object enumeration.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

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
    Err(OverthroneError::NotImplemented { module: "reaper::gpos".into() })
}
