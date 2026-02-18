//! Dangerous ACL enumeration — GenericAll, WriteDACL, WriteOwner, etc.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DangerousRight {
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    ForceChangePassword,
    AddMembers,
    ReadLapsPassword,
    ReadGmsaPassword,
    DcSync,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclFinding {
    pub principal: String,
    pub principal_sid: Option<String>,
    pub target: String,
    pub target_dn: String,
    pub right: DangerousRight,
    pub is_inherited: bool,
}

pub async fn enumerate_dangerous_acls(config: &ReaperConfig) -> Result<Vec<AclFinding>> {
    info!("[acls] Querying {} for dangerous ACLs", config.dc_ip);
    Err(OverthroneError::NotImplemented { module: "reaper::acls".into() })
}
