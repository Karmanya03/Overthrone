//! Foreign trust enumeration and Foreign Security Principal (FSP) resolution.
//!
//! Maps all inter-forest trust relationships, identifies attack-relevant
//! misconfigurations (disabled SID filtering, bidirectional trusts), and
//! resolves foreign group memberships that enable lateral movement.

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::types::{Sid, TrustDirection, TrustType};
use overthrone_reaper::groups::GroupEntry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────
// Trust relationship model
// ─────────────────────────────────────────────────

/// Complete trust relationship with all attack-relevant attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRelationship {
    /// Trusted domain NetBIOS name
    pub name: String,
    /// Trusted domain FQDN
    pub fqdn: String,
    /// Domain SID of the trusted domain
    pub domain_sid: String,
    /// Trust direction (Inbound/Outbound/Bidirectional)
    pub direction: String,
    /// Trust type (Forest/External/Parent-Child etc.)
    pub trust_type: String,
    /// Raw trustAttributes bitmask
    pub trust_attributes: u32,
    /// Whether SID filtering is effectively enabled
    pub sid_filtering: bool,
    /// Whether selective authentication is configured
    pub selective_auth: bool,
    /// Whether this is a forest-transitive trust
    pub forest_transitive: bool,
    /// Whether TGT delegation is enabled (attack vector when SID filtering is on)
    pub tgt_delegation: bool,
    /// Distinguished name of the TDO
    pub tdo_dn: String,
    /// Attack notes / recommendations
    pub attack_notes: Vec<String>,
}

/// Trust attribute flags (MS-ADTS 6.1.6.7.9)
pub mod trust_attrs {
    pub const NON_TRANSITIVE: u32 = 0x0000_0001;
    pub const UPLEVEL_ONLY: u32 = 0x0000_0002;
    pub const QUARANTINED_DOMAIN: u32 = 0x0000_0004;
    pub const FOREST_TRANSITIVE: u32 = 0x0000_0008;
    pub const CROSS_ORGANIZATION: u32 = 0x0000_0010;
    pub const WITHIN_FOREST: u32 = 0x0000_0020;
    pub const TREAT_AS_EXTERNAL: u32 = 0x0000_0040;
    pub const USES_RC4_ENCRYPTION: u32 = 0x0000_0080;
    pub const USES_AES_KEYS: u32 = 0x0000_0100;
    pub const CROSS_ORG_NO_TGT_DELEG: u32 = 0x0000_0200;
    pub const PIM_TRUST: u32 = 0x0000_0400;
}

// ─────────────────────────────────────────────────
// Foreign Security Principal
// ─────────────────────────────────────────────────

/// A user/group from another forest with local group membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignSecurityPrincipal {
    /// The SID of the foreign principal
    pub sid: String,
    /// Distinguished name of the FSP object in CN=ForeignSecurityPrincipals
    pub dn: String,
    /// Local groups this FSP is a member of
    pub member_of: Vec<String>,
    /// Resolved name (if we can reach the foreign domain)
    pub resolved_name: Option<String>,
    /// Source domain
    pub source_domain: Option<String>,
}

// ─────────────────────────────────────────────────
// Foreign group membership (offline, from reaper GroupEntry data)
// ─────────────────────────────────────────────────

/// A cross-domain group membership found by DN analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignMembership {
    pub foreign_principal: String,
    pub foreign_domain: String,
    pub foreign_sid: Option<String>,
    pub local_group: String,
    pub local_group_dn: String,
    pub local_domain: String,
    pub is_privileged_group: bool,
}

impl ForeignMembership {
    pub fn is_high_value(&self) -> bool {
        self.is_privileged_group
    }
}

/// Well-known privileged group names (case-insensitive match).
const PRIVILEGED_GROUPS: &[&str] = &[
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "dnsadmins",
    "group policy creator owners",
    "domain controllers",
    "cert publishers",
    "exchange windows permissions",
    "exchange trusted subsystem",
    "organization management",
];

// ─────────────────────────────────────────────────
// Cross-forest group membership
// ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossForestMembership {
    pub local_group_name: String,
    pub local_group_dn: String,
    pub group_type: i32,
    pub foreign_member_sids: Vec<String>,
    pub is_privileged: bool,
}

// ═══════════════════════════════════════════════════
// OFFLINE ANALYSIS — works with reaper GroupEntry data (no LDAP needed)
// ═══════════════════════════════════════════════════

/// Analyze reaper group data for foreign (cross-domain) memberships.
///
/// This is the primary offline analysis function that works purely from
/// reaper enumeration data without needing live LDAP connectivity.
pub fn analyze_foreign_memberships(
    source_domain: &str,
    groups: &[GroupEntry],
) -> Vec<ForeignMembership> {
    let _source_upper = source_domain.to_uppercase();
    let mut findings = Vec::new();

    info!(
        "[foreign] Analyzing {} groups for foreign members",
        groups.len()
    );

    for group in groups {
        let group_domain = domain_from_dn(&group.distinguished_name);

        // Check each member DN
        for member_dn in &group.members {
            let member_domain = domain_from_dn(member_dn);

            // If the member is from a different domain, it's a foreign membership
            if !member_domain.is_empty()
                && !group_domain.is_empty()
                && member_domain.to_uppercase() != group_domain.to_uppercase()
            {
                let member_name = cn_from_dn(member_dn);
                let is_privileged =
                    is_privileged_group_name(&group.sam_account_name) || group.admin_count;

                debug!(
                    "[foreign] {} ({}) → {} ({}) [privileged={}]",
                    member_name, member_domain, group.sam_account_name, group_domain, is_privileged
                );

                findings.push(ForeignMembership {
                    foreign_principal: member_name,
                    foreign_domain: member_domain,
                    foreign_sid: None,
                    local_group: group.sam_account_name.clone(),
                    local_group_dn: group.distinguished_name.clone(),
                    local_domain: group_domain.clone(),
                    is_privileged_group: is_privileged,
                });
            }
        }
    }

    // Sort: privileged first
    findings.sort_by(|a, b| b.is_privileged_group.cmp(&a.is_privileged_group));

    info!(
        "[foreign] Found {} foreign memberships ({} privileged)",
        findings.len(),
        findings.iter().filter(|f| f.is_privileged_group).count()
    );

    findings
}

// ═══════════════════════════════════════════════════
// LIVE ENUMERATION — requires LDAP connectivity
// These functions are gated because overthrone_core::proto::ldap
// doesn't export search/LdapEntry yet.
// ═══════════════════════════════════════════════════

/// Enumerate all trust relationships from the current domain (LIVE LDAP).
///
/// Queries the trustedDomain objects in AD and parses trustAttributes
/// to determine SID filtering status, TGT delegation, and other
/// attack-relevant configuration.
pub async fn enumerate_trusts(domain: &str, _dc_ip: &str) -> Result<Vec<TrustRelationship>> {
    // TODO: implement live LDAP query once overthrone_core::proto::ldap is ready.
    //
    // The implementation should:
    //   1. Connect to DC via LDAP
    //   2. Search base_dn for (objectClass=trustedDomain)
    //   3. Parse trustAttributes bitmask to determine:
    //      - SID filtering (QUARANTINED_DOMAIN / absence of TREAT_AS_EXTERNAL on forest trust)
    //      - TGT delegation (absence of CROSS_ORG_NO_TGT_DELEG)
    //      - Forest transitivity (FOREST_TRANSITIVE flag)
    //   4. Build TrustRelationship with attack_notes

    let base_dn = domain_to_dn(domain);
    warn!(
        "[foreign] enumerate_trusts: LDAP not yet implemented, returning empty (base_dn={})",
        base_dn
    );
    Ok(Vec::new())
}

/// Enumerate all Foreign Security Principals and their local group memberships (LIVE LDAP).
pub async fn enumerate_foreign_principals(
    domain: &str,
    _dc_ip: &str,
) -> Result<Vec<ForeignSecurityPrincipal>> {
    // TODO: implement live LDAP query once overthrone_core::proto::ldap is ready.
    //
    // The implementation should:
    //   1. Search CN=ForeignSecurityPrincipals,<base_dn> for (objectClass=foreignSecurityPrincipal)
    //   2. Read objectSid, distinguishedName, memberOf
    //   3. Filter out well-known SIDs (S-1-1-0, S-1-5-11, etc.)
    //   4. Build ForeignSecurityPrincipal entries

    let base_dn = format!("CN=ForeignSecurityPrincipals,{}", domain_to_dn(domain));
    warn!(
        "[foreign] enumerate_foreign_principals: LDAP not yet implemented (base_dn={})",
        base_dn
    );
    Ok(Vec::new())
}

/// Try to resolve foreign SIDs to names by querying the foreign domain (LIVE LDAP).
pub async fn resolve_foreign_sids(
    principals: &mut [ForeignSecurityPrincipal],
    _foreign_domains: &HashMap<String, String>,
) -> Result<usize> {
    // TODO: implement once live LDAP cross-domain queries work.
    //
    // For each principal:
    //   1. Extract domain SID (strip RID)
    //   2. Look up domain FQDN from foreign_domains map
    //   3. LDAP search that domain for (objectSid=<hex_encoded_sid>)
    //   4. Set resolved_name and source_domain on match

    warn!(
        "[foreign] resolve_foreign_sids: LDAP not yet implemented, skipping {} principals",
        principals.len()
    );
    Ok(0)
}

/// Enumerate cross-forest group memberships for a specific foreign domain (LIVE LDAP).
pub async fn enumerate_cross_forest_memberships(
    _local_domain: &str,
    _foreign_domain_sid: &str,
) -> Result<Vec<CrossForestMembership>> {
    // TODO: implement once live LDAP search works.
    //
    // The implementation should:
    //   1. Search for groups whose member attribute contains FSPs from the foreign domain
    //   2. Extract foreign SIDs from member DNs
    //   3. Check if the group is privileged

    warn!("[foreign] enumerate_cross_forest_memberships: LDAP not yet implemented");
    Ok(Vec::new())
}

/// Resolve a single SID to a name by querying the foreign domain's LDAP.
async fn _resolve_sid_in_domain(sid: &Sid, domain: &str) -> Result<String> {
    let base_dn = domain_to_dn(domain);
    let sid_bytes_hex = sid
        .to_bytes()
        .iter()
        .map(|b| format!("\\{:02x}", b))
        .collect::<String>();
    let filter = format!("(objectSid={})", sid_bytes_hex);

    // TODO: ldap::search(base_dn, Subtree, filter, &["sAMAccountName"]).await?
    //       then extract sAMAccountName from first entry

    Err(OverthroneError::custom(format!(
        "SID {} resolution not yet implemented (would query {} with {})",
        sid, base_dn, filter
    )))
}

// ═══════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════

/// Convert domain FQDN to Distinguished Name.
/// "child.corp.local" → "DC=child,DC=corp,DC=local"
fn domain_to_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",")
}

/// Extract domain from a Distinguished Name.
/// "CN=jdoe,OU=Users,DC=child,DC=corp,DC=local" → "child.corp.local"
fn domain_from_dn(dn: &str) -> String {
    dn.split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.to_uppercase().starts_with("DC=") {
                Some(trimmed[3..].to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Extract CN (common name) from a Distinguished Name.
/// "CN=John Doe,OU=Users,DC=corp,DC=local" → "John Doe"
fn cn_from_dn(dn: &str) -> String {
    dn.split(',')
        .find(|part| part.trim().to_uppercase().starts_with("CN="))
        .map(|part| part.trim()[3..].to_string())
        .unwrap_or_else(|| dn.to_string())
}

/// Check if a SID is a well-known boring SID.
fn _is_well_known_sid(sid: &Sid) -> bool {
    let s = sid.to_string();
    matches!(
        s.as_str(),
        "S-1-1-0"   // Everyone
        | "S-1-5-11"  // Authenticated Users
        | "S-1-5-7"   // Anonymous Logon
        | "S-1-5-14"  // Remote Interactive Logon
        | "S-1-5-18" // SYSTEM
    )
}

/// Extract domain SID portion from a full SID (strip last RID).
fn _extract_domain_from_sid(_sid: &Sid) -> Option<String> {
    // Can't resolve domain name from SID alone without a lookup table.
    // Return None — the caller maps via foreign_domains HashMap.
    None
}

/// Extract a SID from a Foreign Security Principal DN.
/// "CN=S-1-5-21-123456-789012-345678-1104,CN=ForeignSecurityPrincipals,DC=corp,DC=local"
/// → Some(Sid)
fn _extract_sid_from_fsp_dn(dn: &str) -> Option<Sid> {
    dn.split(',')
        .next()
        .and_then(|cn| cn.strip_prefix("CN="))
        .and_then(|s| Sid::from_string(s))
}

/// Check if a group name is in the privileged set.
fn is_privileged_group_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    PRIVILEGED_GROUPS.iter().any(|&pg| lower == pg)
}

/// Check if a group is privileged by name or DN.
fn _is_privileged_group(name: &str, dn: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("admin")
        || lower == "domain admins"
        || lower == "enterprise admins"
        || lower == "schema admins"
        || lower == "account operators"
        || lower == "backup operators"
        || lower == "server operators"
        || lower == "print operators"
        || dn.to_lowercase().contains("cn=builtin,")
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_attr_flags() {
        let attrs = trust_attrs::FOREST_TRANSITIVE | trust_attrs::USES_AES_KEYS;
        assert!(attrs & trust_attrs::FOREST_TRANSITIVE != 0);
        assert!(attrs & trust_attrs::QUARANTINED_DOMAIN == 0);
    }

    #[test]
    fn test_extract_sid_from_fsp_dn() {
        let dn =
            "CN=S-1-5-21-123456-789012-345678-1104,CN=ForeignSecurityPrincipals,DC=corp,DC=local";
        let sid = _extract_sid_from_fsp_dn(dn);
        assert!(sid.is_some());
        assert_eq!(
            sid.unwrap().to_string(),
            "S-1-5-21-123456-789012-345678-1104"
        );
    }

    #[test]
    fn test_is_privileged_group() {
        assert!(_is_privileged_group(
            "Domain Admins",
            "CN=Domain Admins,CN=Users,DC=corp,DC=local"
        ));
        assert!(!_is_privileged_group(
            "HR Team",
            "CN=HR Team,OU=Groups,DC=corp,DC=local"
        ));
    }

    #[test]
    fn test_domain_from_dn() {
        assert_eq!(
            domain_from_dn("CN=jdoe,OU=Users,DC=child,DC=corp,DC=local"),
            "child.corp.local"
        );
    }

    #[test]
    fn test_domain_to_dn() {
        assert_eq!(
            domain_to_dn("child.corp.local"),
            "DC=child,DC=corp,DC=local"
        );
    }

    #[test]
    fn test_cn_from_dn() {
        assert_eq!(
            cn_from_dn("CN=John Doe,OU=Users,DC=corp,DC=local"),
            "John Doe"
        );
    }

    #[test]
    fn test_foreign_membership_detection() {
        let groups = vec![GroupEntry {
            sam_account_name: "Domain Admins".to_string(),
            distinguished_name: "CN=Domain Admins,CN=Users,DC=parent,DC=corp,DC=local".to_string(),
            members: vec![
                "CN=childadmin,OU=Users,DC=child,DC=corp,DC=local".to_string(),
                "CN=localuser,OU=Users,DC=parent,DC=corp,DC=local".to_string(),
            ],
            admin_count: true,
            description: String::new(),
            object_sid: String::new(),
            group_type: 0,
        }];

        let results = analyze_foreign_memberships("parent.corp.local", &groups);
        // Only the child domain member should be flagged
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].foreign_principal, "childadmin");
        assert_eq!(results[0].foreign_domain, "child.corp.local");
        assert!(results[0].is_privileged_group);
    }
}
