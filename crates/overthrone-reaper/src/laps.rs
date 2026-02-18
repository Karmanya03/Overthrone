//! LAPS (Local Administrator Password Solution) enumeration.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsEntry {
    pub computer_name: String,
    pub distinguished_name: String,
    pub password: Option<String>,
    pub expiration: Option<String>,
    pub is_laps_v2: bool,
}

pub fn laps_filter() -> String {
    "(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))".to_string()
}

pub fn laps_attributes() -> Vec<String> {
    [
        "sAMAccountName", "distinguishedName", "ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password",
        "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
    ].iter().map(|s| s.to_string()).collect()
}

pub async fn enumerate_laps(config: &ReaperConfig) -> Result<Vec<LapsEntry>> {
    info!("[laps] Querying {} for LAPS-enabled computers", config.dc_ip);
    Err(OverthroneError::NotImplemented { module: "reaper::laps".into() })
}

pub fn parse_laps_entry(attrs: &HashMap<String, Vec<String>>) -> LapsEntry {
    let v1_pwd = first_val(attrs, "ms-Mcs-AdmPwd");
    let v2_pwd = first_val(attrs, "msLAPS-Password");
    let is_v2 = v2_pwd.is_some() || attrs.contains_key("msLAPS-EncryptedPassword");

    LapsEntry {
        computer_name: first_val(attrs, "sAMAccountName").unwrap_or_default(),
        distinguished_name: first_val(attrs, "distinguishedName").unwrap_or_default(),
        password: v1_pwd.or(v2_pwd),
        expiration: first_val(attrs, "ms-Mcs-AdmPwdExpirationTime")
            .or_else(|| first_val(attrs, "msLAPS-PasswordExpirationTime")),
        is_laps_v2: is_v2,
    }
}

fn first_val(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|v| v.first().cloned())
}
