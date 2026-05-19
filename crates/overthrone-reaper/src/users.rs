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
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserEntry {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Object or account name.
    pub display_name: Option<String>,
    /// description field
    pub description: Option<String>,
    /// Object or account name.
    pub user_principal_name: Option<String>,
    /// mail field
    pub mail: Option<String>,
    /// member of field
    pub member_of: Vec<String>,
    /// uac flags field
    pub uac_flags: u32,
    /// enabled field
    pub enabled: bool,
    /// Item count
    pub admin_count: bool,
    /// last logon field
    pub last_logon: Option<String>,
    /// Password for authentication
    pub last_password_change: Option<String>,
    /// Item count
    pub bad_pwd_count: Option<u32>,
    /// bad pwd time field
    pub bad_pwd_time: Option<String>,
    /// lockout time field
    pub lockout_time: Option<String>,
    /// Item count
    pub account_expires: Option<String>,
    /// Item count
    pub logon_count: Option<u32>,
    /// when created field
    pub when_created: Option<String>,
    /// when changed field
    pub when_changed: Option<String>,
    /// Password for authentication
    pub password_never_expires: bool,
    /// dont require preauth field
    pub dont_require_preauth: bool,
    /// Object or account name.
    pub service_principal_names: Vec<String>,
    /// Security Identifier
    pub sid: Option<String>,
    /// msDS-AllowedToDelegateTo — constrained delegation targets for this user.
    pub allowed_to_delegate_to: Vec<String>,
    /// True when msDS-AllowedToActOnBehalfOfOtherIdentity is present (RBCD configured).
    pub has_rbcd: bool,
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
    /// Function
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
        "badPwdCount",
        "badPwdTime",
        "lockoutTime",
        "accountExpires",
        "logonCount",
        "servicePrincipalName",
        "objectSid",
        "whenCreated",
        "whenChanged",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub async fn enumerate_users(config: &ReaperConfig) -> Result<Vec<UserEntry>> {
    info!("[users] Querying {} for domain users", config.dc_ip);

    let mut conn = crate::runner::ldap_connect(config).await?;

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
        bad_pwd_count: first_val(attrs, "badPwdCount").and_then(|v| v.parse().ok()),
        bad_pwd_time: first_val(attrs, "badPwdTime"),
        lockout_time: first_val(attrs, "lockoutTime"),
        account_expires: first_val(attrs, "accountExpires"),
        logon_count: first_val(attrs, "logonCount").and_then(|v| v.parse().ok()),
        when_created: first_val(attrs, "whenCreated"),
        when_changed: first_val(attrs, "whenChanged"),
        password_never_expires: pwd_never_expires,
        dont_require_preauth: no_preauth,
        service_principal_names: attrs
            .get("servicePrincipalName")
            .cloned()
            .unwrap_or_default(),
        sid: first_val(attrs, "objectSid"),
        allowed_to_delegate_to: attrs
            .get("msDS-AllowedToDelegateTo")
            .cloned()
            .unwrap_or_default(),
        has_rbcd: attrs.contains_key("msDS-AllowedToActOnBehalfOfOtherIdentity"),
    }
}

fn first_val(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|v| v.first().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_filter() {
        assert_eq!(
            user_filter(),
            "(&(objectCategory=person)(objectClass=user))"
        );
    }

    #[test]
    fn test_from_uac_normal() {
        let (enabled, pwd_never, no_preauth) = UserEntry::from_uac(0x0200);
        assert!(enabled);
        assert!(!pwd_never);
        assert!(!no_preauth);
    }

    #[test]
    fn test_from_uac_disabled() {
        let (enabled, pwd_never, no_preauth) = UserEntry::from_uac(0x0202);
        assert!(!enabled);
        assert!(!pwd_never);
        assert!(!no_preauth);
    }

    #[test]
    fn test_from_uac_dont_expire() {
        let (enabled, pwd_never, no_preauth) = UserEntry::from_uac(0x10200);
        assert!(enabled);
        assert!(pwd_never);
        assert!(!no_preauth);
    }

    #[test]
    fn test_from_uac_no_preauth() {
        let (enabled, pwd_never, no_preauth) = UserEntry::from_uac(0x400200);
        assert!(enabled);
        assert!(!pwd_never);
        assert!(no_preauth);
    }

    #[test]
    fn test_from_uac_all_flags() {
        let (enabled, pwd_never, no_preauth) = UserEntry::from_uac(0x410202);
        assert!(!enabled);
        assert!(pwd_never);
        assert!(no_preauth);
    }

    #[test]
    fn test_from_uac_zero() {
        let (enabled, pwd_never, no_preauth) = UserEntry::from_uac(0);
        assert!(enabled);
        assert!(!pwd_never);
        assert!(!no_preauth);
    }

    #[test]
    fn test_is_kerberoastable_enabled_with_spns() {
        let u = UserEntry {
            enabled: true,
            service_principal_names: vec!["HTTP/srv.contoso.com".into()],
            ..Default::default()
        };
        assert!(u.is_kerberoastable());
    }

    #[test]
    fn test_is_kerberoastable_enabled_no_spns() {
        let u = UserEntry {
            enabled: true,
            service_principal_names: vec![],
            ..Default::default()
        };
        assert!(!u.is_kerberoastable());
    }

    #[test]
    fn test_is_kerberoastable_disabled_with_spns() {
        let u = UserEntry {
            enabled: false,
            service_principal_names: vec!["HTTP/srv.contoso.com".into()],
            ..Default::default()
        };
        assert!(!u.is_kerberoastable());
    }

    #[test]
    fn test_is_asrep_roastable_enabled_no_preauth() {
        let u = UserEntry {
            enabled: true,
            dont_require_preauth: true,
            ..Default::default()
        };
        assert!(u.is_asrep_roastable());
    }

    #[test]
    fn test_is_asrep_roastable_enabled_with_preauth() {
        let u = UserEntry {
            enabled: true,
            dont_require_preauth: false,
            ..Default::default()
        };
        assert!(!u.is_asrep_roastable());
    }

    #[test]
    fn test_is_asrep_roastable_disabled_no_preauth() {
        let u = UserEntry {
            enabled: false,
            dont_require_preauth: true,
            ..Default::default()
        };
        assert!(!u.is_asrep_roastable());
    }

    #[test]
    fn test_is_high_value_admin_count() {
        let u = UserEntry {
            admin_count: true,
            ..Default::default()
        };
        assert!(u.is_high_value());
    }

    #[test]
    fn test_is_high_value_member_of_domain_admins() {
        let u = UserEntry {
            admin_count: false,
            member_of: vec!["CN=Domain Admins,CN=Users,DC=contoso,DC=com".into()],
            ..Default::default()
        };
        assert!(u.is_high_value());
    }

    #[test]
    fn test_is_high_value_member_of_enterprise_admins() {
        let u = UserEntry {
            admin_count: false,
            member_of: vec!["CN=Enterprise Admins,CN=Builtin,DC=contoso,DC=com".into()],
            ..Default::default()
        };
        assert!(u.is_high_value());
    }

    #[test]
    fn test_is_high_value_no_match() {
        let u = UserEntry {
            admin_count: false,
            member_of: vec!["CN=Sales,CN=Users,DC=contoso,DC=com".into()],
            ..Default::default()
        };
        assert!(!u.is_high_value());
    }

    #[test]
    fn test_is_high_value_empty_member_of() {
        let u = UserEntry {
            admin_count: false,
            member_of: vec![],
            ..Default::default()
        };
        assert!(!u.is_high_value());
    }

    #[test]
    fn test_user_attributes_contains_key_fields() {
        let attrs = user_attributes();
        assert!(attrs.contains(&"sAMAccountName".to_string()));
        assert!(attrs.contains(&"userAccountControl".to_string()));
        assert!(attrs.contains(&"servicePrincipalName".to_string()));
        assert!(attrs.contains(&"objectSid".to_string()));
        assert!(attrs.contains(&"adminCount".to_string()));
    }
}
