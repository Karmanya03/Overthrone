//! PAM (Privileged Access Management) trust analysis.
//!
//! Detects PAM trusts and analyzes their configuration for
//! abuse potential including shadow principal misconfigurations.

use crate::trust_map::{TrustGraph, TrustKind};
use serde::{Deserialize, Serialize};
use tracing::info;
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowPrincipal {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Security Identifier
    pub shadow_sid: String,
    /// member of field
    pub member_of: Vec<String>,
    /// ttl seconds field
    pub ttl_seconds: u64,
}

impl ShadowPrincipal {
    pub fn is_permanent(&self) -> bool {
        self.ttl_seconds == 0
    }

    pub fn is_privileged(&self) -> bool {
        self.member_of.iter().any(|g| {
            let lower = g.to_lowercase();
            lower.contains("domain admins")
                || lower.contains("enterprise admins")
                || lower.contains("administrators")
        })
    }

    pub fn is_dangerous(&self) -> bool {
        (self.is_permanent() || self.ttl_seconds > 86400) && self.is_privileged()
    }
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PamFinding {
    /// Domain FQDN
    pub bastion_domain: String,
    /// Domain FQDN
    pub production_domain: String,
    /// Classification for this object.
    pub finding_type: PamFindingType,
    /// shadow principals field
    pub shadow_principals: Vec<ShadowPrincipal>,
    /// risk level field
    pub risk_level: String,
    /// description field
    pub description: String,
    /// remediation field
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PamFindingType {
    /// PAM trust detected -- informational
    PamTrustDetected,
    /// PAM trust exists but no filtering (exploitable)
    PamTrustNoFiltering,
    /// Non-PAM trust configuration with PAM-like risks
    TrustEscalationRisk,
    /// No PAM trusts found
    NoPamTrustsFound,
}

/// Shadow principals live under this container
pub fn shadow_principal_base_dn(config_dn: &str) -> String {
    format!("CN=Shadow Principal Configuration,CN=Services,{config_dn}")
}

pub fn shadow_principal_filter() -> String {
    "(objectClass=msDS-ShadowPrincipal)".to_string()
}

/// Analyze the trust graph for PAM trust configurations and risks.
pub fn analyze_pam_trusts(source_domain: &str, graph: &TrustGraph) -> Vec<PamFinding> {
    let mut findings = Vec::new();
    let source_upper = source_domain.to_uppercase();

    info!(
        "[pam] Analyzing PAM trust configuration for {}",
        source_domain
    );

    // Check each trust for PAM characteristics
    let mut pam_trusts_found = false;

    for trust in &graph.trusts {
        // -- Explicit PAM trusts --
        if trust.is_pam_trust {
            pam_trusts_found = true;

            let (risk, finding_type) = if !trust.sid_filtering {
                ("CRITICAL", PamFindingType::PamTrustNoFiltering)
            } else {
                ("HIGH", PamFindingType::PamTrustDetected)
            };

            findings.push(PamFinding {
                bastion_domain: trust.source_domain.clone(),
                production_domain: trust.target_domain.clone(),
                finding_type,
                shadow_principals: Vec::new(), // populated when LDAP is wired
                risk_level: risk.into(),
                description: format!(
                    "PAM trust detected: {} -> {}. {}Shadow principals in the bastion forest \
                     can obtain temporary (or permanent) privileged group memberships in the \
                     production forest. {}",
                    trust.source_domain,
                    trust.target_domain,
                    if !trust.sid_filtering {
                        "SID filtering is DISABLED -- shadow principals can inject arbitrary SIDs. "
                    } else {
                        ""
                    },
                    if trust.tgt_delegation {
                        "TGT delegation is enabled -- bastion accounts can request TGTs for production resources."
                    } else {
                        "TGT delegation is disabled."
                    }
                ),
                remediation: if !trust.sid_filtering {
                    format!(
                        "1. Enable SID filtering on the PAM trust: \
                         netdom trust {} /domain:{} /quarantine:yes\n\
                         2. Audit all shadow principals in CN=Shadow Principal Configuration\n\
                         3. Ensure all shadow principals have appropriate TTL (< 1 hour recommended)\n\
                         4. Remove any permanent (TTL=0) shadow principal mappings to privileged groups",
                        trust.source_domain, trust.target_domain
                    )
                } else {
                    "1. Regularly audit shadow principal TTLs -- ensure none are permanent\n\
                     2. Monitor shadow principal creation events (Event ID 4929)\n\
                     3. Restrict who can create/modify shadow principals via ACLs\n\
                     4. Consider implementing just-in-time access workflows".into()
                },
            });
        }

        // -- Forest trusts that could be converted to PAM (risk assessment) --
        if trust.trust_type == TrustKind::Forest
            && trust.direction.allows_outbound()
            && !trust.is_pam_trust
            && trust.source_domain == source_upper
        {
            findings.push(PamFinding {
                bastion_domain: trust.source_domain.clone(),
                production_domain: trust.target_domain.clone(),
                finding_type: PamFindingType::TrustEscalationRisk,
                shadow_principals: Vec::new(),
                risk_level: "INFO".into(),
                description: format!(
                    "Forest trust {} -> {} could potentially be reconfigured as a PAM trust. \
                     If an attacker gains forest admin, they could establish a PAM trust \
                     to create persistent shadow principal access.",
                    trust.source_domain, trust.target_domain
                ),
                remediation: "Monitor for trust attribute changes (Event ID 4706, 4707). \
                    Restrict forest admin access. Implement trust modification alerting."
                    .into(),
            });
        }
    }

    // If no PAM trusts found at all, note that
    if !pam_trusts_found && !graph.trusts.is_empty() {
        findings.push(PamFinding {
            bastion_domain: source_domain.to_string(),
            production_domain: String::new(),
            finding_type: PamFindingType::NoPamTrustsFound,
            shadow_principals: Vec::new(),
            risk_level: "OK".into(),
            description: "No PAM trusts detected in the environment. \
                Shadow principal-based attacks are not applicable."
                .into(),
            remediation: "No action needed for PAM-specific risks.".into(),
        });
    }

    info!(
        "[pam] {} PAM findings ({} critical)",
        findings.len(),
        findings
            .iter()
            .filter(|f| f.risk_level == "CRITICAL")
            .count()
    );

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_map::{TrustDirection, TrustEdge, TrustGraph, TrustKind};

    fn make_trust(is_pam: bool, filtering: bool) -> TrustEdge {
        TrustEdge {
            source_domain: "BASTION".into(),
            target_domain: "PROD".into(),
            direction: TrustDirection::Bidirectional,
            trust_type: TrustKind::Forest,
            transitive: true,
            sid_filtering: filtering,
            tgt_delegation: true,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: is_pam,
        }
    }

    #[test]
    fn test_shadow_principal_permanent() {
        let sp = ShadowPrincipal {
            name: "adm".into(),
            distinguished_name: "CN=adm,...".into(),
            shadow_sid: "S-1-5-21-...".into(),
            member_of: vec!["CN=Domain Admins,...".into()],
            ttl_seconds: 0,
        };
        assert!(sp.is_permanent());
        assert!(sp.is_privileged());
        assert!(sp.is_dangerous());
    }

    #[test]
    fn test_shadow_principal_not_dangerous() {
        let sp = ShadowPrincipal {
            name: "user".into(),
            distinguished_name: "CN=user,...".into(),
            shadow_sid: "S-1-5-21-...".into(),
            member_of: vec!["CN=Users,...".into()],
            ttl_seconds: 3600,
        };
        assert!(!sp.is_permanent());
        assert!(!sp.is_privileged());
        assert!(!sp.is_dangerous());
    }

    #[test]
    fn test_shadow_principal_long_ttl_privileged() {
        let sp = ShadowPrincipal {
            name: "adm".into(),
            distinguished_name: "CN=adm,...".into(),
            shadow_sid: "S-1-5-21-...".into(),
            member_of: vec!["CN=Enterprise Admins,...".into()],
            ttl_seconds: 90000,
        };
        assert!(sp.is_dangerous());
    }

    #[test]
    fn test_shadow_principal_base_dn() {
        let dn = shadow_principal_base_dn("DC=corp,DC=local");
        assert_eq!(
            dn,
            "CN=Shadow Principal Configuration,CN=Services,DC=corp,DC=local"
        );
    }

    #[test]
    fn test_shadow_principal_filter() {
        assert_eq!(
            shadow_principal_filter(),
            "(objectClass=msDS-ShadowPrincipal)"
        );
    }

    #[test]
    fn test_analyze_pam_trusts_no_trusts() {
        let g = TrustGraph::new();
        let findings = analyze_pam_trusts("CORP", &g);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_analyze_pam_trusts_with_pam() {
        let mut g = TrustGraph::new();
        g.add_trust(make_trust(true, false));
        let findings = analyze_pam_trusts("BASTION", &g);
        let crit: Vec<_> = findings
            .iter()
            .filter(|f| f.risk_level == "CRITICAL")
            .collect();
        assert_eq!(crit.len(), 1);
    }

    #[test]
    fn test_analyze_pam_trusts_pam_with_filtering() {
        let mut g = TrustGraph::new();
        g.add_trust(make_trust(true, true));
        let findings = analyze_pam_trusts("BASTION", &g);
        let high: Vec<_> = findings.iter().filter(|f| f.risk_level == "HIGH").collect();
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn test_analyze_pam_trusts_no_pam_found() {
        let mut g = TrustGraph::new();
        g.add_trust(make_trust(false, true));
        let findings = analyze_pam_trusts("BASTION", &g);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.finding_type, PamFindingType::NoPamTrustsFound))
        );
    }
}
