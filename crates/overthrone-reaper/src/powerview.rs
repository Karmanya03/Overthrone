//! PowerView-like advanced Active Directory enumeration.
//!
//! Provides granular queries for GPO settings, OU structures, ACL paths,
//! and user/computer properties that are not covered by basic modules.

use crate::runner::{ReaperConfig, ldap_connect};
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoDetailedInfo {
    pub display_name: String,
    pub gpo_guid: String,
    pub path: String,
    pub status: String,
    pub linked_to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDetailedInfo {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub sid: String,
    pub pwd_last_set: String,
    pub last_logon: String,
    pub member_of: Vec<String>,
    pub properties: std::collections::HashMap<String, String>,
}

pub struct PowerView {
    config: ReaperConfig,
}

impl PowerView {
    pub fn new(config: ReaperConfig) -> Self {
        Self { config }
    }

    pub async fn get_gpo_details(&self) -> Result<Vec<GpoDetailedInfo>> {
        info!("[powerview] Enumerating detailed GPO information");
        let mut ldap = ldap_connect(&self.config).await?;

        // Query for GPOs and their links
        let filter = "(objectCategory=groupPolicyContainer)";
        let attrs = ["displayName", "cn", "gPCFileSysPath", "flags"];
        let entries = ldap.custom_search(filter, &attrs).await?;

        let mut gpos = Vec::new();
        for entry in entries {
            let display_name = entry
                .attrs
                .get("displayName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let guid = entry
                .attrs
                .get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let path = entry
                .attrs
                .get("gPCFileSysPath")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let flags = entry
                .attrs
                .get("flags")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);

            let status = match flags {
                0 => "Enabled",
                1 => "User Configuration Disabled",
                2 => "Computer Configuration Disabled",
                3 => "All Settings Disabled",
                _ => "Unknown",
            };

            gpos.push(GpoDetailedInfo {
                display_name,
                gpo_guid: guid,
                path,
                status: status.to_string(),
                linked_to: Vec::new(), // Will be populated by OU search
            });
        }

        // Now find where they are linked (gPLink attribute on OUs and Domain)
        let link_filter = "(|(objectCategory=organizationalUnit)(objectCategory=domainDNS))";
        let link_attrs = ["distinguishedName", "gPLink"];
        let link_entries = ldap.custom_search(link_filter, &link_attrs).await?;

        for entry in link_entries {
            if let Some(links) = entry.attrs.get("gPLink").and_then(|v| v.first()) {
                let dn = entry
                    .attrs
                    .get("distinguishedName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                // gPLink format: [LDAP://CN={GUID},...;FLAGS][...]
                for link in links.split('[') {
                    if link.is_empty() {
                        continue;
                    }
                    for gpo in &mut gpos {
                        if link.to_lowercase().contains(&gpo.gpo_guid.to_lowercase()) {
                            gpo.linked_to.push(dn.clone());
                        }
                    }
                }
            }
        }

        let _ = ldap.disconnect().await;
        Ok(gpos)
    }

    pub async fn get_user_properties(
        &self,
        username: Option<&str>,
    ) -> Result<Vec<UserDetailedInfo>> {
        info!("[powerview] Querying detailed user properties");
        let mut ldap = ldap_connect(&self.config).await?;

        let filter = if let Some(u) = username {
            format!(
                "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
                u
            )
        } else {
            "(&(objectCategory=person)(objectClass=user))".to_string()
        };

        let attrs = [
            "sAMAccountName",
            "distinguishedName",
            "objectSid",
            "pwdLastSet",
            "lastLogonTimestamp",
            "memberOf",
            "description",
            "userPrincipalName",
            "adminCount",
            "userAccountControl",
        ];

        let entries = ldap.custom_search(&filter, &attrs).await?;
        let mut users = Vec::new();

        for entry in entries {
            let sam = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let dn = entry
                .attrs
                .get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            // Convert SID bytes to string if available
            let sid = "S-1-5-...".to_string(); // Placeholder for actual SID parsing logic

            let mut properties = std::collections::HashMap::new();
            for (k, v) in &entry.attrs {
                if let Some(val) = v.first() {
                    properties.insert(k.clone(), val.clone());
                }
            }

            users.push(UserDetailedInfo {
                sam_account_name: sam,
                distinguished_name: dn,
                sid,
                pwd_last_set: entry
                    .attrs
                    .get("pwdLastSet")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
                last_logon: entry
                    .attrs
                    .get("lastLogonTimestamp")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
                member_of: entry.attrs.get("memberOf").cloned().unwrap_or_default(),
                properties,
            });
        }

        let _ = ldap.disconnect().await;
        Ok(users)
    }
}

pub async fn run_powerview(config: &ReaperConfig) -> Result<PowerViewResult> {
    let pv = PowerView::new(config.clone());
    let gpos = pv.get_gpo_details().await?;
    let users = pv.get_user_properties(None).await?;

    Ok(PowerViewResult {
        gpo_details: gpos,
        user_details: users,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerViewResult {
    pub gpo_details: Vec<GpoDetailedInfo>,
    pub user_details: Vec<UserDetailedInfo>,
}
