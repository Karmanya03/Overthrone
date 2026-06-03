//! SPN enumeration — finds Kerberoastable accounts.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpnAccount {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Object or account name.
    pub service_principal_names: Vec<String>,
    /// enabled field
    pub enabled: bool,
    /// Item count
    pub admin_count: bool,
    /// Password for authentication
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
    info!(
        "[spns] Querying {} for Kerberoastable accounts",
        config.dc_ip
    );

    let mut conn = crate::runner::ldap_connect(config).await?;

    let filter = spn_filter();
    let attrs = &[
        "sAMAccountName",
        "distinguishedName",
        "servicePrincipalName",
        "userAccountControl",
        "adminCount",
        "pwdLastSet",
    ];

    let entries = match conn.custom_search(&filter, attrs).await {
        Ok(e) => e,
        Err(e) => {
            warn!("[spns] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let sam = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        // Skip the krbtgt account — it has an SPN but is not Kerberoastable in the traditional sense
        if sam.to_lowercase() == "krbtgt" {
            continue;
        }

        let uac: u32 = entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let enabled = uac & 0x0002 == 0;
        let admin_count = entry
            .attrs
            .get("adminCount")
            .and_then(|v| v.first())
            .map(|v| v == "1")
            .unwrap_or(false);

        let spns: Vec<String> = entry
            .attrs
            .get("servicePrincipalName")
            .cloned()
            .unwrap_or_default();

        let pwd_last_set = entry
            .attrs
            .get("pwdLastSet")
            .and_then(|v| v.first())
            .cloned();

        info!(
            "[spns]  {} — {} SPN(s){}",
            sam,
            spns.len(),
            if admin_count { " [adminCount=1]" } else { "" }
        );

        results.push(SpnAccount {
            sam_account_name: sam,
            distinguished_name: entry.dn.clone(),
            service_principal_names: spns,
            enabled,
            admin_count,
            password_last_set: pwd_last_set,
        });
    }

    let _ = conn.disconnect().await;

    info!("[spns] Found {} Kerberoastable accounts", results.len());
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spn_filter() {
        assert_eq!(
            spn_filter(),
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        );
    }

    #[test]
    fn test_is_high_value_target_enabled_admin() {
        let s = SpnAccount {
            enabled: true,
            admin_count: true,
            ..Default::default()
        };
        assert!(s.is_high_value_target());
    }

    #[test]
    fn test_is_high_value_target_disabled_admin() {
        let s = SpnAccount {
            enabled: false,
            admin_count: true,
            ..Default::default()
        };
        assert!(!s.is_high_value_target());
    }

    #[test]
    fn test_is_high_value_target_enabled_not_admin() {
        let s = SpnAccount {
            enabled: true,
            admin_count: false,
            ..Default::default()
        };
        assert!(!s.is_high_value_target());
    }

    #[test]
    fn test_is_high_value_target_disabled_not_admin() {
        let s = SpnAccount {
            enabled: false,
            admin_count: false,
            ..Default::default()
        };
        assert!(!s.is_high_value_target());
    }
}
