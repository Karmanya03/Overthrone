//! Foreign group membership analysis.
//!
//! Finds users/groups from one domain that are members of groups
//! in another domain by comparing the domain components of
//! distinguished names.

use overthrone_reaper::groups::GroupEntry;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

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

/// Well-known privileged group names (case-insensitive match)
const PRIVILEGED_GROUPS: &[&str] = &[
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "server operators", "print operators", "dnsadmins",
    "group policy creator owners", "domain controllers",
    "cert publishers", "exchange windows permissions",
    "exchange trusted subsystem", "organization management",
];

/// Analyze reaper group data for foreign (cross-domain) memberships.
pub fn analyze_foreign_memberships(
    source_domain: &str,
    groups: &[GroupEntry],
) -> Vec<ForeignMembership> {
    let source_upper = source_domain.to_uppercase();
    let mut findings = Vec::new();

    info!("[foreign] Analyzing {} groups for foreign members", groups.len());

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
                let is_privileged = is_privileged_group(&group.sam_account_name)
                    || group.admin_count;

                debug!("[foreign] {} ({}) → {} ({}) [privileged={}]",
                    member_name, member_domain,
                    group.sam_account_name, group_domain, is_privileged
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

    info!("[foreign] Found {} foreign memberships ({} privileged)",
        findings.len(),
        findings.iter().filter(|f| f.is_privileged_group).count()
    );

    findings
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

/// Check if a group name is in the privileged set
fn is_privileged_group(name: &str) -> bool {
    let lower = name.to_lowercase();
    PRIVILEGED_GROUPS.iter().any(|&pg| lower == pg)
}
