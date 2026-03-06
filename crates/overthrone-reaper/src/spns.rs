//! SPN enumeration — finds Kerberoastable accounts.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpnAccount {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub service_principal_names: Vec<String>,
    pub enabled: bool,
    pub admin_count: bool,
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

    let mut conn = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    )
    .await?;

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
