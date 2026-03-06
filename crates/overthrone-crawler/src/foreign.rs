//! Foreign trust enumeration and Foreign Security Principal (FSP) resolution.
//!
//! Maps all inter-forest trust relationships, identifies attack-relevant
//! misconfigurations (disabled SID filtering, bidirectional trusts), and
//! resolves foreign group memberships that enable lateral movement.

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::types::Sid;
use overthrone_reaper::groups::GroupEntry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

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
pub async fn enumerate_trusts(domain: &str, dc_ip: &str) -> Result<Vec<TrustRelationship>> {
    use overthrone_core::proto::ldap::LdapSession;

    info!("[foreign] Enumerating trusts from {} ({})", domain, dc_ip);

    // Connect to LDAP (anonymous bind for trust enumeration)
    let mut conn = LdapSession::connect(dc_ip, domain, "", "", false).await?;

    // Enumerate trusts using the built-in method
    let ad_trusts = conn.enumerate_trusts().await?;
    
    let _ = conn.disconnect().await;

    let mut results = Vec::new();
    for trust in ad_trusts {
        let attrs = trust.trust_attributes;
        
        // Determine SID filtering status
        let sid_filtering = if attrs & trust_attrs::QUARANTINED_DOMAIN != 0 {
            true // Explicitly quarantined
        } else if attrs & trust_attrs::FOREST_TRANSITIVE != 0 {
            // Forest trust - SID filtering depends on TREAT_AS_EXTERNAL
            attrs & trust_attrs::TREAT_AS_EXTERNAL != 0
        } else {
            // External trust - SID filtering is on by default
            true
        };

        // Check TGT delegation
        let tgt_delegation = attrs & trust_attrs::CROSS_ORG_NO_TGT_DELEG == 0;

        // Check selective authentication
        let selective_auth = attrs & trust_attrs::CROSS_ORGANIZATION != 0;

        // Check forest transitivity
        let forest_transitive = attrs & trust_attrs::FOREST_TRANSITIVE != 0;

        // Build attack notes
        let mut attack_notes = Vec::new();
        
        if !sid_filtering {
            attack_notes.push("⚠️ SID filtering is DISABLED - full domain compromise possible".to_string());
        }
        
        if tgt_delegation && sid_filtering {
            attack_notes.push("⚠️ TGT delegation enabled with SID filtering - potential bypass via delegation".to_string());
        }
        
        if trust.trust_direction.to_string().contains("Bidirectional") {
            attack_notes.push("ℹ️ Bidirectional trust - compromise in either direction affects both domains".to_string());
        }
        
        if forest_transitive {
            attack_notes.push("ℹ️ Forest-transitive trust - access may extend to entire forest".to_string());
        }

        let trust_name = trust.flat_name.clone().unwrap_or_else(|| trust.trust_partner.clone());

        results.push(TrustRelationship {
            name: trust_name.clone(),
            fqdn: trust.trust_partner.clone(),
            domain_sid: String::new(), // SID not available in AdTrust
            direction: trust.trust_direction.to_string(),
            trust_type: trust.trust_type.to_string(),
            trust_attributes: attrs,
            sid_filtering,
            selective_auth,
            forest_transitive,
            tgt_delegation,
            tdo_dn: format!("CN={},CN=System,{}", trust_name, domain_to_dn(domain)),
            attack_notes,
        });
    }

    info!("[foreign] Found {} trust relationships", results.len());
    Ok(results)
}

/// Enumerate all Foreign Security Principals and their local group memberships (LIVE LDAP).
pub async fn enumerate_foreign_principals(
    domain: &str,
    dc_ip: &str,
) -> Result<Vec<ForeignSecurityPrincipal>> {
    use overthrone_core::proto::ldap::LdapSession;

    info!("[foreign] Enumerating Foreign Security Principals from {}", domain);

    let mut conn = LdapSession::connect(dc_ip, domain, "", "", false).await?;

    let base_dn = format!("CN=ForeignSecurityPrincipals,{}", domain_to_dn(domain));
    let filter = "(objectClass=foreignSecurityPrincipal)";
    let attrs = vec!["objectSid", "distinguishedName", "memberOf"];

    let entries = conn.custom_search_with_base(&base_dn, filter, &attrs).await?;
    
    let _ = conn.disconnect().await;

    let mut results = Vec::new();
    for entry in entries {
        // Extract SID from attributes
        let sid_str = entry.attrs.get("objectSid")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        // Skip well-known SIDs
        if is_well_known_sid_str(&sid_str) {
            continue;
        }

        let dn = entry.attrs.get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let member_of = entry.attrs.get("memberOf")
            .cloned()
            .unwrap_or_default();

        results.push(ForeignSecurityPrincipal {
            sid: sid_str,
            dn,
            member_of,
            resolved_name: None,
            source_domain: None,
        });
    }

    info!("[foreign] Found {} Foreign Security Principals", results.len());
    Ok(results)
}

/// Try to resolve foreign SIDs to names by querying the foreign domain (LIVE LDAP).
pub async fn resolve_foreign_sids(
    principals: &mut [ForeignSecurityPrincipal],
    foreign_domains: &HashMap<String, String>,
) -> Result<usize> {
    

    let mut resolved_count = 0;

    for principal in principals.iter_mut() {
        // Extract domain SID (strip RID)
        let domain_sid = extract_domain_sid(&principal.sid);
        
        // Look up domain FQDN from foreign_domains map
        if let Some(domain_fqdn) = foreign_domains.get(&domain_sid) {
            // Try to resolve the SID in that domain
            match resolve_sid_in_foreign_domain(&principal.sid, domain_fqdn).await {
                Ok(name) => {
                    principal.resolved_name = Some(name);
                    principal.source_domain = Some(domain_fqdn.clone());
                    resolved_count += 1;
                    debug!("[foreign] Resolved {} → {}", principal.sid, principal.resolved_name.as_ref().unwrap());
                }
                Err(e) => {
                    debug!("[foreign] Failed to resolve {}: {}", principal.sid, e);
                }
            }
        }
    }

    info!("[foreign] Resolved {}/{} foreign SIDs", resolved_count, principals.len());
    Ok(resolved_count)
}

/// Resolve a single SID in a foreign domain
async fn resolve_sid_in_foreign_domain(sid_str: &str, domain: &str) -> Result<String> {
    use overthrone_core::proto::ldap::LdapSession;

    // Try anonymous bind first
    let mut conn = LdapSession::connect("", domain, "", "", false).await?;

    let base_dn = domain_to_dn(domain);
    let filter = format!("(objectSid={})", sid_str);
    let attrs = vec!["sAMAccountName", "name"];

    let entries = conn.custom_search_with_base(&base_dn, &filter, &attrs).await?;
    
    let _ = conn.disconnect().await;

    if let Some(entry) = entries.first() {
        let name = entry.attrs.get("sAMAccountName")
            .or_else(|| entry.attrs.get("name"))
            .and_then(|v| v.first())
            .cloned()
            .ok_or_else(|| OverthroneError::custom("No name found for SID"))?;
        
        Ok(name)
    } else {
        Err(OverthroneError::custom(format!("SID {} not found in domain {}", sid_str, domain)))
    }
}

/// Enumerate cross-forest group memberships for a specific foreign domain (LIVE LDAP).
pub async fn enumerate_cross_forest_memberships(
    local_domain: &str,
    foreign_domain_sid: &str,
) -> Result<Vec<CrossForestMembership>> {
    use overthrone_core::proto::ldap::LdapSession;

    info!("[foreign] Enumerating cross-forest memberships for domain SID {}", foreign_domain_sid);

    let mut conn = LdapSession::connect("", local_domain, "", "", false).await?;

    // Search for groups with foreign members
    let base_dn = domain_to_dn(local_domain);
    let filter = "(objectClass=group)";
    let attrs = vec!["sAMAccountName", "distinguishedName", "member", "groupType", "adminCount"];

    let entries = conn.custom_search_with_base(&base_dn, filter, &attrs).await?;
    
    let _ = conn.disconnect().await;

    let mut results = Vec::new();
    
    for entry in entries {
        let members = entry.attrs.get("member").cloned().unwrap_or_default();
        
        // Filter members that are FSPs from the target foreign domain
        let foreign_sids: Vec<String> = members.iter()
            .filter_map(|member_dn| {
                if member_dn.contains("CN=ForeignSecurityPrincipals") {
                    extract_sid_from_fsp_dn_str(member_dn)
                } else {
                    None
                }
            })
            .filter(|sid| sid.starts_with(foreign_domain_sid))
            .collect();

        if !foreign_sids.is_empty() {
            let group_name = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let group_dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let group_type = entry.attrs.get("groupType")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);

            let admin_count = entry.attrs.get("adminCount")
                .and_then(|v| v.first())
                .map(|v| v == "1")
                .unwrap_or(false);

            let is_privileged = is_privileged_group_name(&group_name) || admin_count;

            results.push(CrossForestMembership {
                local_group_name: group_name,
                local_group_dn: group_dn,
                group_type,
                foreign_member_sids: foreign_sids,
                is_privileged,
            });
        }
    }

    info!("[foreign] Found {} groups with cross-forest memberships", results.len());
    Ok(results)
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
    is_well_known_sid_str(&s)
}

/// Check if a SID string is a well-known boring SID.
fn is_well_known_sid_str(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-1-0"   // Everyone
        | "S-1-5-11"  // Authenticated Users
        | "S-1-5-7"   // Anonymous Logon
        | "S-1-5-14"  // Remote Interactive Logon
        | "S-1-5-18"  // SYSTEM
        | "S-1-5-32-544" // Administrators (built-in)
        | "S-1-5-32-545" // Users (built-in)
    )
}

/// Extract domain SID portion from a full SID string (strip last RID).
fn extract_domain_sid(sid: &str) -> String {
    // SID format: S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ-RID
    // Domain SID: S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ
    if let Some(last_dash) = sid.rfind('-') {
        sid[..last_dash].to_string()
    } else {
        sid.to_string()
    }
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
        .and_then(Sid::from_string)
}

/// Extract a SID string from a Foreign Security Principal DN.
fn extract_sid_from_fsp_dn_str(dn: &str) -> Option<String> {
    dn.split(',')
        .next()
        .and_then(|cn| cn.strip_prefix("CN="))
        .map(|s| s.to_string())
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
        use overthrone_reaper::groups::GroupKind;
        
        let groups = vec![GroupEntry {
            sam_account_name: "Domain Admins".to_string(),
            distinguished_name: "CN=Domain Admins,CN=Users,DC=parent,DC=corp,DC=local".to_string(),
            members: vec![
                "CN=childadmin,OU=Users,DC=child,DC=corp,DC=local".to_string(),
                "CN=localuser,OU=Users,DC=parent,DC=corp,DC=local".to_string(),
            ],
            member_of: vec![],
            admin_count: true,
            description: Some("Domain Admins".to_string()),
            sid: Some("S-1-5-21-123456-789012-345678-512".to_string()),
            group_type: GroupKind::Global,
        }];

        let results = analyze_foreign_memberships("parent.corp.local", &groups);
        // Only the child domain member should be flagged
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].foreign_principal, "childadmin");
        assert_eq!(results[0].foreign_domain, "child.corp.local");
        assert!(results[0].is_privileged_group);
    }
}
