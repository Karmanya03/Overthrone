//! PAM (Privileged Access Management) trust analysis.
//!
//! Detects PAM trusts and analyzes their configuration for
//! abuse potential including shadow principal misconfigurations.

use crate::trust_map::{TrustGraph, TrustKind};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowPrincipal {
    pub name: String,
    pub distinguished_name: String,
    pub shadow_sid: String,
    pub member_of: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PamFinding {
    pub bastion_domain: String,
    pub production_domain: String,
    pub finding_type: PamFindingType,
    pub shadow_principals: Vec<ShadowPrincipal>,
    pub risk_level: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PamFindingType {
    /// PAM trust detected — informational
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
pub fn analyze_pam_trusts(
    source_domain: &str,
    graph: &TrustGraph,
) -> Vec<PamFinding> {
    let mut findings = Vec::new();
    let source_upper = source_domain.to_uppercase();

    info!("[pam] Analyzing PAM trust configuration for {}", source_domain);

    // Check each trust for PAM characteristics
    let mut pam_trusts_found = false;

    for trust in &graph.trusts {
        // ── Explicit PAM trusts ──
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
                    "PAM trust detected: {} → {}. {}Shadow principals in the bastion forest \
                     can obtain temporary (or permanent) privileged group memberships in the \
                     production forest. {}",
                    trust.source_domain,
                    trust.target_domain,
                    if !trust.sid_filtering {
                        "SID filtering is DISABLED — shadow principals can inject arbitrary SIDs. "
                    } else {
                        ""
                    },
                    if trust.tgt_delegation {
                        "TGT delegation is enabled — bastion accounts can request TGTs for production resources."
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
                    "1. Regularly audit shadow principal TTLs — ensure none are permanent\n\
                     2. Monitor shadow principal creation events (Event ID 4929)\n\
                     3. Restrict who can create/modify shadow principals via ACLs\n\
                     4. Consider implementing just-in-time access workflows".into()
                },
            });
        }

        // ── Forest trusts that could be converted to PAM (risk assessment) ──
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
                    "Forest trust {} → {} could potentially be reconfigured as a PAM trust. \
                     If an attacker gains forest admin, they could establish a PAM trust \
                     to create persistent shadow principal access.",
                    trust.source_domain, trust.target_domain
                ),
                remediation: "Monitor for trust attribute changes (Event ID 4706, 4707). \
                    Restrict forest admin access. Implement trust modification alerting.".into(),
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
                Shadow principal-based attacks are not applicable.".into(),
            remediation: "No action needed for PAM-specific risks.".into(),
        });
    }

    info!("[pam] {} PAM findings ({} critical)",
        findings.len(),
        findings.iter().filter(|f| f.risk_level == "CRITICAL").count()
    );

    findings
}
