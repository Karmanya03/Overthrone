//! Domain group enumeration via LDAP.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEntry {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    pub member_of: Vec<String>,
    pub group_type: GroupKind,
    pub admin_count: bool,
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupKind {
    DomainLocal,
    Global,
    Universal,
    BuiltIn,
    Unknown(i64),
}

impl GroupKind {
    pub fn from_group_type(gt: i64) -> Self {
        // The high bit (0x80000000) is the GROUP_TYPE_SECURITY_ENABLED flag.
        // Mask it off with 0x7FFFFFFF to isolate the group scope/type bits.
        // Note: this mask is intentional and correct for both 32-bit and 64-bit
        // parsed values; only the lower 32 bits are meaningful per MS-ADTS §2.2.16.
        let base = if gt < 0 { gt & 0x7FFF_FFFF } else { gt };
        match base & 0xF {
            2 => Self::Global,
            4 => Self::DomainLocal,
            8 => Self::Universal,
            _ if base == 1 => Self::BuiltIn,
            _ => Self::Unknown(gt),
        }
    }
}

impl GroupEntry {
    pub fn is_privileged(&self) -> bool {
        let lower = self.sam_account_name.to_lowercase();
        matches!(
            lower.as_str(),
            "domain admins"
                | "enterprise admins"
                | "schema admins"
                | "administrators"
                | "account operators"
                | "backup operators"
                | "server operators"
                | "print operators"
                | "dnsadmins"
                | "group policy creator owners"
                | "domain controllers"
                | "cert publishers"
                | "exchange windows permissions"
        ) || self.admin_count
    }
}

pub fn group_filter() -> String {
    "(objectCategory=group)".to_string()
}

pub fn group_attributes() -> Vec<String> {
    [
        "sAMAccountName",
        "distinguishedName",
        "description",
        "member",
        "memberOf",
        "groupType",
        "adminCount",
        "objectSid",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub async fn enumerate_groups(config: &ReaperConfig) -> Result<Vec<GroupEntry>> {
    info!("[groups] Querying {} for domain groups", config.dc_ip);

    let mut conn = overthrone_core::proto::ldap::LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    )
    .await?;

    let filter = group_filter();
    let attr_list = group_attributes();
    let attrs: Vec<&str> = attr_list.iter().map(|s| s.as_str()).collect();

    let entries = match conn.custom_search(&filter, &attrs).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("[groups] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();
    for entry in &entries {
        results.push(parse_group_entry(&entry.attrs));
    }

    let _ = conn.disconnect().await;
    info!("[groups] Found {} domain groups", results.len());
    Ok(results)
}

pub fn parse_group_entry(attrs: &HashMap<String, Vec<String>>) -> GroupEntry {
    let gt: i64 = first_val(attrs, "groupType")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    GroupEntry {
        sam_account_name: first_val(attrs, "sAMAccountName").unwrap_or_default(),
        distinguished_name: first_val(attrs, "distinguishedName").unwrap_or_default(),
        description: first_val(attrs, "description"),
        members: attrs.get("member").cloned().unwrap_or_default(),
        member_of: attrs.get("memberOf").cloned().unwrap_or_default(),
        group_type: GroupKind::from_group_type(gt),
        admin_count: first_val(attrs, "adminCount")
            .map(|v| v == "1")
            .unwrap_or(false),
        sid: first_val(attrs, "objectSid"),
    }
}

fn first_val(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|v| v.first().cloned())
}
