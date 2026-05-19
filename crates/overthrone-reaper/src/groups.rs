//! Domain group enumeration via LDAP.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupEntry {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// description field
    pub description: Option<String>,
    /// members field
    pub members: Vec<String>,
    /// member of field
    pub member_of: Vec<String>,
    /// Classification for this object.
    pub group_type: GroupKind,
    /// Item count
    pub admin_count: bool,
    /// Security Identifier
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum GroupKind {
    /// `Global` variant
    #[default]
    Global,
    /// `DomainLocal` variant
    DomainLocal,
    /// `Universal` variant
    Universal,
    /// `BuiltIn` variant
    BuiltIn,
    /// `Unknown` variant
    Unknown(i64),
}

impl GroupKind {
    /// Runs this module operation.
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

    let mut conn = crate::runner::ldap_connect(config).await?;

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

/// Resolve all groups a principal (user or group DN) is a *transitive* member of.
/// Uses the AD-specific `LDAP_MATCHING_RULE_IN_CHAIN` OID
/// (1.2.840.113556.1.4.1941) which AD evaluates server-side and returns
/// every group in the ancestry chain, including nested parents.
/// Returns a `Vec<String>` of distinguished names of every group the
/// principal is a member of (directly or indirectly).
pub async fn resolve_nested_memberships(
    config: &ReaperConfig,
    principal_dn: &str,
) -> Result<Vec<String>> {
    if principal_dn.is_empty() {
        tracing::warn!("[groups] resolve_nested_memberships called with empty DN");
        return Ok(Vec::new());
    }

    let mut conn = crate::runner::ldap_connect(config).await?;

    // The LDAP_MATCHING_RULE_IN_CHAIN OID resolves transitive group membership.
    let filter = format!(
        "(member:1.2.840.113556.1.4.1941:={})",
        ldap_escape_dn(principal_dn)
    );
    let attrs = &["distinguishedName", "sAMAccountName"];

    let entries = match conn.custom_search(&filter, attrs).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("[groups] Nested membership query failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let dns: Vec<String> = entries.iter().map(|e| e.dn.clone()).collect();
    let _ = conn.disconnect().await;
    Ok(dns)
}

/// Escape a DN for use inside an LDAP filter value (RFC 4515 §3).
/// Parentheses and backslashes must be escaped.
fn ldap_escape_dn(dn: &str) -> String {
    let mut out = String::with_capacity(dn.len() + 4);
    for ch in dn.chars() {
        match ch {
            '\\' => out.push_str("\\5c"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '*' => out.push_str("\\2a"),
            '\0' => out.push_str("\\00"),
            other => out.push(other),
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_filter() {
        assert_eq!(group_filter(), "(objectCategory=group)");
    }

    #[test]
    fn test_from_group_type_global() {
        assert!(matches!(GroupKind::from_group_type(2), GroupKind::Global));
    }

    #[test]
    fn test_from_group_type_domain_local() {
        assert!(matches!(
            GroupKind::from_group_type(4),
            GroupKind::DomainLocal
        ));
    }

    #[test]
    fn test_from_group_type_universal() {
        assert!(matches!(
            GroupKind::from_group_type(8),
            GroupKind::Universal
        ));
    }

    #[test]
    fn test_from_group_type_builtin() {
        assert!(matches!(GroupKind::from_group_type(1), GroupKind::BuiltIn));
    }

    #[test]
    fn test_from_group_type_security_enabled() {
        assert!(matches!(
            GroupKind::from_group_type(0x8000_0002),
            GroupKind::Global
        ));
        assert!(matches!(
            GroupKind::from_group_type(0x8000_0004),
            GroupKind::DomainLocal
        ));
        assert!(matches!(
            GroupKind::from_group_type(0x8000_0008),
            GroupKind::Universal
        ));
    }

    #[test]
    fn test_from_group_type_negative() {
        let neg = -2147483646i64;
        assert!(matches!(GroupKind::from_group_type(neg), GroupKind::Global));
    }

    #[test]
    fn test_from_group_type_unknown() {
        assert!(matches!(
            GroupKind::from_group_type(99),
            GroupKind::Unknown(99)
        ));
    }

    #[test]
    fn test_from_group_type_zero() {
        assert!(matches!(
            GroupKind::from_group_type(0),
            GroupKind::Unknown(0)
        ));
    }

    #[test]
    fn test_is_privileged_domain_admins() {
        let g = GroupEntry {
            sam_account_name: "Domain Admins".into(),
            ..Default::default()
        };
        assert!(g.is_privileged());
    }

    #[test]
    fn test_is_privileged_case_insensitive() {
        let g = GroupEntry {
            sam_account_name: "DOMAIN ADMINS".into(),
            ..Default::default()
        };
        assert!(g.is_privileged());
    }

    #[test]
    fn test_is_privileged_non_privileged() {
        let g = GroupEntry {
            sam_account_name: "Sales Team".into(),
            ..Default::default()
        };
        assert!(!g.is_privileged());
    }

    #[test]
    fn test_is_privileged_admin_count() {
        let g = GroupEntry {
            sam_account_name: "Custom Group".into(),
            admin_count: true,
            ..Default::default()
        };
        assert!(g.is_privileged());
    }

    #[test]
    fn test_ldap_escape_dn_parentheses() {
        assert_eq!(ldap_escape_dn("CN=Test(User)"), "CN=Test\\28User\\29");
    }

    #[test]
    fn test_ldap_escape_dn_backslash() {
        assert_eq!(ldap_escape_dn("CN=Test\\User"), "CN=Test\\5cUser");
    }

    #[test]
    fn test_ldap_escape_dn_asterisk() {
        assert_eq!(ldap_escape_dn("CN=*Test"), "CN=\\2aTest");
    }

    #[test]
    fn test_ldap_escape_dn_null() {
        assert_eq!(ldap_escape_dn("CN=Test\0"), "CN=Test\\00");
    }

    #[test]
    fn test_ldap_escape_dn_noop() {
        assert_eq!(
            ldap_escape_dn("CN=Normal,DC=contoso,DC=com"),
            "CN=Normal,DC=contoso,DC=com"
        );
    }

    #[test]
    fn test_group_attributes_contains_key_fields() {
        let attrs = group_attributes();
        assert!(attrs.contains(&"sAMAccountName".to_string()));
        assert!(attrs.contains(&"groupType".to_string()));
        assert!(attrs.contains(&"objectSid".to_string()));
        assert!(attrs.contains(&"member".to_string()));
    }
}
