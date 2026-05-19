//! PowerView-like advanced Active Directory enumeration.
//!
//! Provides granular queries for GPO settings, OU structures, ACL paths,
//! and user/computer properties that are not covered by basic modules.

use crate::runner::{ReaperConfig, ldap_connect};
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::info;
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoDetailedInfo {
    /// Object or account name.
    pub display_name: String,
    /// Stable unique identifier.
    pub gpo_guid: String,
    /// Filesystem path.
    pub path: String,
    /// status field
    pub status: String,
    /// linked to field
    pub linked_to: Vec<String>,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDetailedInfo {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Security Identifier
    pub sid: String,
    /// pwd last set field
    pub pwd_last_set: String,
    /// last logon field
    pub last_logon: String,
    /// member of field
    pub member_of: Vec<String>,
    /// properties field
    pub properties: std::collections::HashMap<String, String>,
}
/// Structure
pub struct PowerView {
    config: ReaperConfig,
}

impl PowerView {
    /// Runs this module operation.
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
            let sid = entry
                .attrs
                .get("objectSid")
                .and_then(|v| v.first())
                .map(|raw| sid_bytes_to_string(raw.as_bytes()))
                .unwrap_or_else(|| "S-1-5-...".to_string());

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
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerViewResult {
    /// gpo details field
    pub gpo_details: Vec<GpoDetailedInfo>,
    /// user details field
    pub user_details: Vec<UserDetailedInfo>,
}

/// Convert raw binary SID bytes (from LDAP objectSid) into standard string format S-R-IA-SA-...
/// Binary SID structure:
///   bytes[0] = Revision (usually 1)
///   bytes[1] = SubAuthorityCount
///   bytes[2..8] = IdentifierAuthority (6 bytes, big-endian)
///   bytes[8..] = SubAuthorities (4 bytes each, little-endian)
fn sid_bytes_to_string(raw: &[u8]) -> String {
    if raw.len() < 8 {
        return format!("S-{:?}", hex::encode(raw));
    }
    let revision = raw[0];
    let count = raw[1] as usize;
    let ia = u64::from_be_bytes([0, 0, raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]]);
    let mut sid = format!("S-{}-{}", revision, ia);
    for i in 0..count {
        let offset = 8 + i * 4;
        if offset + 4 <= raw.len() {
            let sub_auth = u32::from_le_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]);
            sid.push_str(&format!("-{}", sub_auth));
        }
    }
    sid
}
