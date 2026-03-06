//! Domain user enumeration via LDAP.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

pub const UAC_DISABLED: u32 = 0x0002;
pub const UAC_LOCKOUT: u32 = 0x0010;
pub const UAC_PASSWD_NOTREQD: u32 = 0x0020;
pub const UAC_PASSWD_CANT_CHANGE: u32 = 0x0040;
pub const UAC_NORMAL_ACCOUNT: u32 = 0x0200;
pub const UAC_DONT_EXPIRE_PASSWD: u32 = 0x10000;
pub const UAC_DONT_REQ_PREAUTH: u32 = 0x400000;
pub const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x80000;
pub const UAC_NOT_DELEGATED: u32 = 0x100000;
pub const UAC_USE_DES_KEY_ONLY: u32 = 0x200000;
pub const UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x1000000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub user_principal_name: Option<String>,
    pub mail: Option<String>,
    pub member_of: Vec<String>,
    pub uac_flags: u32,
    pub enabled: bool,
    pub admin_count: bool,
    pub last_logon: Option<String>,
    pub last_password_change: Option<String>,
    pub password_never_expires: bool,
    pub dont_require_preauth: bool,
    pub service_principal_names: Vec<String>,
    pub sid: Option<String>,
}

impl UserEntry {
    pub fn is_kerberoastable(&self) -> bool {
        self.enabled && !self.service_principal_names.is_empty()
    }

    pub fn is_asrep_roastable(&self) -> bool {
        self.enabled && self.dont_require_preauth
    }

    pub fn is_high_value(&self) -> bool {
        self.admin_count
            || self.member_of.iter().any(|g| {
                let lower = g.to_lowercase();
                lower.contains("domain admins")
                    || lower.contains("enterprise admins")
                    || lower.contains("schema admins")
                    || lower.contains("administrators")
                    || lower.contains("account operators")
                    || lower.contains("backup operators")
            })
    }

    pub fn from_uac(uac: u32) -> (bool, bool, bool) {
        let enabled = uac & UAC_DISABLED == 0;
        let pwd_never_expires = uac & UAC_DONT_EXPIRE_PASSWD != 0;
        let no_preauth = uac & UAC_DONT_REQ_PREAUTH != 0;
        (enabled, pwd_never_expires, no_preauth)
    }
}

pub fn user_filter() -> String {
    "(&(objectCategory=person)(objectClass=user))".to_string()
}

pub fn user_attributes() -> Vec<String> {
    [
        "sAMAccountName",
        "distinguishedName",
        "displayName",
        "description",
        "userPrincipalName",
        "mail",
        "memberOf",
        "userAccountControl",
        "adminCount",
        "lastLogonTimestamp",
        "pwdLastSet",
        "servicePrincipalName",
        "objectSid",
        "whenCreated",
        "whenChanged",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub async fn enumerate_users(config: &ReaperConfig) -> Result<Vec<UserEntry>> {
    info!("[users] Querying {} for domain users", config.dc_ip);

    let mut conn = overthrone_core::proto::ldap::LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    )
    .await?;

    let filter = user_filter();
    let attr_list = user_attributes();
    let attrs: Vec<&str> = attr_list.iter().map(|s| s.as_str()).collect();

    let entries = match conn.custom_search(&filter, &attrs).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("[users] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();
    for entry in &entries {
        results.push(parse_user_entry(&entry.attrs));
    }

    let _ = conn.disconnect().await;
    info!("[users] Found {} domain users", results.len());
    Ok(results)
}

pub fn parse_user_entry(attrs: &HashMap<String, Vec<String>>) -> UserEntry {
    let uac: u32 = first_val(attrs, "userAccountControl")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let (enabled, pwd_never_expires, no_preauth) = UserEntry::from_uac(uac);

    UserEntry {
        sam_account_name: first_val(attrs, "sAMAccountName").unwrap_or_default(),
        distinguished_name: first_val(attrs, "distinguishedName").unwrap_or_default(),
        display_name: first_val(attrs, "displayName"),
        description: first_val(attrs, "description"),
        user_principal_name: first_val(attrs, "userPrincipalName"),
        mail: first_val(attrs, "mail"),
        member_of: attrs.get("memberOf").cloned().unwrap_or_default(),
        uac_flags: uac,
        enabled,
        admin_count: first_val(attrs, "adminCount")
            .map(|v| v == "1")
            .unwrap_or(false),
        last_logon: first_val(attrs, "lastLogonTimestamp"),
        last_password_change: first_val(attrs, "pwdLastSet"),
        password_never_expires: pwd_never_expires,
        dont_require_preauth: no_preauth,
        service_principal_names: attrs
            .get("servicePrincipalName")
            .cloned()
            .unwrap_or_default(),
        sid: first_val(attrs, "objectSid"),
    }
}

fn first_val(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|v| v.first().cloned())
}
