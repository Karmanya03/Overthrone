//! LAPS (Local Administrator Password Solution) enumeration.

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsEntry {
    pub computer_name: String,
    pub distinguished_name: String,
    pub password: Option<String>,
    pub expiration: Option<String>,
    pub is_laps_v2: bool,
}

pub fn laps_filter() -> String {
    // Match computers that have either LAPS v1 (ms-Mcs-AdmPwd) or v2 (msLAPS-Password /
    // msLAPS-EncryptedPassword) attributes populated.
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

    let mut conn = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    ).await?;

    // First try the specific LAPS filter (only returns computers where we can READ the password).
    // If the calling account lacks permission, LDAP returns the computer object but omits the
    // password attribute — so we also fall back to querying all computers for LAPS presence.
    let filter = laps_filter();
    let attr_refs: Vec<&str> = [
        "sAMAccountName", "distinguishedName", "ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password",
        "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
    ].to_vec();

    let entries = match conn.custom_search(&filter, &attr_refs).await {
        Ok(e) => e,
        Err(e) => {
            // LAPS attributes may not exist in schema — fall back gracefully
            warn!("[laps] Primary LAPS query failed ({}), trying all computers", e);
            // Query all computers; password attributes will just be absent
            match conn.custom_search("(objectCategory=computer)", &attr_refs).await {
                Ok(e2) => e2,
                Err(e2) => {
                    warn!("[laps] Fallback computer query also failed: {}", e2);
                    let _ = conn.disconnect().await;
                    return Err(e2);
                }
            }
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let v1_pwd = entry.attrs
            .get("ms-Mcs-AdmPwd")
            .and_then(|v| v.first())
            .cloned();

        let v2_pwd = entry.attrs
            .get("msLAPS-Password")
            .and_then(|v| v.first())
            .cloned();

        let encrypted = entry.attrs
            .contains_key("msLAPS-EncryptedPassword");

        let password = v1_pwd.clone().or_else(|| v2_pwd.clone());
        let is_v2 = v2_pwd.is_some() || encrypted;

        // Only include if LAPS is actually deployed on this computer
        // (at minimum the attribute exists, even if our account can't read it)
        let has_laps = entry.attrs.contains_key("ms-Mcs-AdmPwd")
            || entry.attrs.contains_key("msLAPS-Password")
            || entry.attrs.contains_key("msLAPS-EncryptedPassword");

        if !has_laps && password.is_none() {
            continue;
        }

        let computer_name = entry.attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.clone());

        let expiration = entry.attrs
            .get("ms-Mcs-AdmPwdExpirationTime")
            .or_else(|| entry.attrs.get("msLAPS-PasswordExpirationTime"))
            .and_then(|v| v.first())
            .cloned();

        if let Some(ref pwd) = password {
            info!("[laps]  {} → password readable ({} bytes)", computer_name, pwd.len());
        } else {
            info!("[laps]  {} → LAPS deployed (password not readable with current creds)", computer_name);
        }

        results.push(LapsEntry {
            computer_name,
            distinguished_name: entry.dn.clone(),
            password,
            expiration,
            is_laps_v2: is_v2,
        });
    }

    let _ = conn.disconnect().await;

    let readable = results.iter().filter(|e| e.password.is_some()).count();
    info!("[laps] Found {} LAPS-enabled computers ({} passwords readable)",
        results.len(), readable);
    Ok(results)
}

/// Parse a LAPS entry from a raw attribute map (kept for compatibility with older callers).
pub fn parse_laps_entry(
    attrs: &std::collections::HashMap<String, Vec<String>>,
) -> LapsEntry {
    let v1_pwd = attrs.get("ms-Mcs-AdmPwd").and_then(|v| v.first()).cloned();
    let v2_pwd = attrs.get("msLAPS-Password").and_then(|v| v.first()).cloned();
    let is_v2  = v2_pwd.is_some() || attrs.contains_key("msLAPS-EncryptedPassword");

    LapsEntry {
        computer_name: attrs.get("sAMAccountName").and_then(|v| v.first())
            .cloned().unwrap_or_default(),
        distinguished_name: attrs.get("distinguishedName").and_then(|v| v.first())
            .cloned().unwrap_or_default(),
        password: v1_pwd.or(v2_pwd),
        expiration: attrs.get("ms-Mcs-AdmPwdExpirationTime")
            .or_else(|| attrs.get("msLAPS-PasswordExpirationTime"))
            .and_then(|v| v.first()).cloned(),
        is_laps_v2: is_v2,
    }
}
