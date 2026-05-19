//! SID filtering analysis across trust boundaries.
//!
//! Checks each trust for SID filtering status and generates
//! findings with risk assessments and remediation guidance.

use crate::trust_map::{TrustDirection, TrustGraph, TrustKind};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SidFilterStatus {
    /// `Enabled` variant
    Enabled,
    /// `Disabled` variant
    Disabled,
    /// `Partial` variant
    Partial {
        #[allow(missing_docs)]
        note: String,
    },
    /// `NotApplicable` variant
    NotApplicable {
        #[allow(missing_docs)]
        reason: String,
    },
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidFilterFinding {
    /// Source domain FQDN
    pub source_domain: String,
    /// Target domain FQDN
    pub target_domain: String,
    /// Classification for this object.
    pub trust_type: String,
    /// trust direction field
    pub trust_direction: String,
    /// filter status field
    pub filter_status: SidFilterStatus,
    /// exploitable field
    pub exploitable: bool,
    /// risk level field
    pub risk_level: String,
    /// attack description field
    pub attack_description: String,
    /// remediation field
    pub remediation: String,
}

impl SidFilterFinding {
    pub fn is_critical(&self) -> bool {
        matches!(self.filter_status, SidFilterStatus::Disabled) && self.exploitable
    }
}

/// Analyze SID filtering status on every trust in the graph.
pub fn analyze_sid_filtering(_source_domain: &str, graph: &TrustGraph) -> Vec<SidFilterFinding> {
    let mut findings = Vec::new();

    info!(
        "[sid_filter] Analyzing SID filtering on {} trusts",
        graph.trusts.len()
    );

    for trust in &graph.trusts {
        let trust_type_str = match &trust.trust_type {
            TrustKind::ParentChild => "Parent-Child",
            TrustKind::External => "External",
            TrustKind::Forest => "Forest",
            TrustKind::CrossLink => "Cross-Link",
            TrustKind::Mit => "MIT/Kerberos",
            TrustKind::Unknown(_v) => "Unknown",
        };

        let direction_str = match &trust.direction {
            TrustDirection::Inbound => "Inbound",
            TrustDirection::Outbound => "Outbound",
            TrustDirection::Bidirectional => "Bidirectional",
            TrustDirection::Unknown(_) => "Unknown",
        };

        // Determine the finding based on trust type and SID filtering status
        let finding = match (&trust.trust_type, trust.sid_filtering) {
            // ── Parent-Child: SID filtering is OFF by design ──
            (TrustKind::ParentChild, false) => {
                SidFilterFinding {
                    source_domain: trust.source_domain.clone(),
                    target_domain: trust.target_domain.clone(),
                    trust_type: trust_type_str.to_string(),
                    trust_direction: direction_str.to_string(),
                    filter_status: SidFilterStatus::NotApplicable {
                        reason: "Intra-forest parent-child trusts do not use SID filtering by design".into(),
                    },
                    exploitable: trust.direction.allows_outbound(),
                    risk_level: "INFO".into(),
                    attack_description: format!(
                        "Parent-child trust to {} — SID filtering is disabled by design within \
                         a forest. An attacker with DA in {} can forge tickets with EA SID.",
                        trust.target_domain, trust.source_domain
                    ),
                    remediation: "This is expected behavior for intra-forest trusts. \
                        Protect Domain Admin accounts in all child domains to prevent \
                        forest-wide compromise via SID history injection.".into(),
                }
            }

            (TrustKind::ParentChild, true) => {
                SidFilterFinding {
                    source_domain: trust.source_domain.clone(),
                    target_domain: trust.target_domain.clone(),
                    trust_type: trust_type_str.to_string(),
                    trust_direction: direction_str.to_string(),
                    filter_status: SidFilterStatus::Enabled,
                    exploitable: false,
                    risk_level: "INFO".into(),
                    attack_description: "SID filtering is enabled on a parent-child trust — unusual configuration.".into(),
                    remediation: "Verify this is intentional. SID filtering on intra-forest trusts can break functionality.".into(),
                }
            }

            // ── External/Forest trust WITHOUT SID filtering = CRITICAL ──
            (TrustKind::External | TrustKind::Forest, false) => {
                let can_exploit = trust.direction.allows_outbound();
                SidFilterFinding {
                    source_domain: trust.source_domain.clone(),
                    target_domain: trust.target_domain.clone(),
                    trust_type: trust_type_str.to_string(),
                    trust_direction: direction_str.to_string(),
                    filter_status: SidFilterStatus::Disabled,
                    exploitable: can_exploit,
                    risk_level: if can_exploit { "CRITICAL" } else { "HIGH" }.into(),
                    attack_description: format!(
                        "{} trust to {} has SID filtering DISABLED. {} \
                         An attacker with DA in {} can forge inter-realm tickets \
                         with arbitrary SIDs (Domain Admins, Enterprise Admins) \
                         from the target domain.",
                        trust_type_str, trust.target_domain,
                        if can_exploit {
                            "Trust allows outbound authentication — DIRECTLY EXPLOITABLE."
                        } else {
                            "Trust is inbound-only — exploitation requires pivot."
                        },
                        trust.source_domain
                    ),
                    remediation: format!(
                        "IMMEDIATELY enable SID filtering on this trust:\n\
                         netdom trust {} /domain:{} /quarantine:yes /userD:admin /passwordD:*\n\n\
                         Alternatively, enable selective authentication to restrict \
                         which accounts can authenticate across this trust.",
                        trust.source_domain, trust.target_domain
                    ),
                }
            }

            // ── External/Forest trust WITH SID filtering = OK ──
            (TrustKind::External | TrustKind::Forest, true) => {
                SidFilterFinding {
                    source_domain: trust.source_domain.clone(),
                    target_domain: trust.target_domain.clone(),
                    trust_type: trust_type_str.to_string(),
                    trust_direction: direction_str.to_string(),
                    filter_status: SidFilterStatus::Enabled,
                    exploitable: false,
                    risk_level: "OK".into(),
                    attack_description: format!(
                        "{} trust to {} has SID filtering enabled — \
                         SID history injection is blocked.",
                        trust_type_str, trust.target_domain
                    ),
                    remediation: "No action needed. SID filtering is correctly configured.".into(),
                }
            }

            // ── Other trust types ──
            (_, sid_filtered) => {
                SidFilterFinding {
                    source_domain: trust.source_domain.clone(),
                    target_domain: trust.target_domain.clone(),
                    trust_type: trust_type_str.to_string(),
                    trust_direction: direction_str.to_string(),
                    filter_status: if sid_filtered {
                        SidFilterStatus::Enabled
                    } else {
                        SidFilterStatus::Disabled
                    },
                    exploitable: !sid_filtered && trust.direction.allows_outbound(),
                    risk_level: if !sid_filtered { "MEDIUM" } else { "OK" }.into(),
                    attack_description: format!(
                        "{} trust to {} — SID filtering: {}",
                        trust_type_str, trust.target_domain,
                        if sid_filtered { "enabled" } else { "disabled" }
                    ),
                    remediation: if !sid_filtered {
                        "Consider enabling SID filtering on this trust.".into()
                    } else {
                        "No action needed.".into()
                    },
                }
            }
        };

        debug!(
            "[sid_filter] {} → {} : {} ({})",
            finding.source_domain, finding.target_domain, finding.risk_level, trust_type_str
        );

        findings.push(finding);
    }

    // Sort: CRITICAL first
    findings.sort_by_key(|a| risk_priority(&a.risk_level));

    info!(
        "[sid_filter] {} findings ({} critical, {} ok)",
        findings.len(),
        findings
            .iter()
            .filter(|f| f.risk_level == "CRITICAL")
            .count(),
        findings.iter().filter(|f| f.risk_level == "OK").count(),
    );

    findings
}

fn risk_priority(level: &str) -> u8 {
    match level {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "INFO" => 3,
        "OK" => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_map::{TrustDirection, TrustEdge, TrustGraph, TrustKind};

    fn make_edge(
        source: &str,
        target: &str,
        filtering: bool,
        direction: TrustDirection,
        kind: TrustKind,
    ) -> TrustEdge {
        let within = kind == TrustKind::ParentChild;
        TrustEdge {
            source_domain: source.into(),
            target_domain: target.into(),
            direction,
            trust_type: kind,
            transitive: true,
            sid_filtering: filtering,
            tgt_delegation: false,
            is_within_forest: within,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        }
    }

    #[test]
    fn test_is_critical_true() {
        let f = SidFilterFinding {
            source_domain: "A".into(),
            target_domain: "B".into(),
            trust_type: "External".into(),
            trust_direction: "Outbound".into(),
            filter_status: SidFilterStatus::Disabled,
            exploitable: true,
            risk_level: "CRITICAL".into(),
            attack_description: "".into(),
            remediation: "".into(),
        };
        assert!(f.is_critical());
    }

    #[test]
    fn test_is_critical_filtered() {
        let f = SidFilterFinding {
            source_domain: "A".into(),
            target_domain: "B".into(),
            trust_type: "External".into(),
            trust_direction: "Outbound".into(),
            filter_status: SidFilterStatus::Enabled,
            exploitable: false,
            risk_level: "OK".into(),
            attack_description: "".into(),
            remediation: "".into(),
        };
        assert!(!f.is_critical());
    }

    #[test]
    fn test_is_critical_not_exploitable() {
        let f = SidFilterFinding {
            source_domain: "A".into(),
            target_domain: "B".into(),
            trust_type: "External".into(),
            trust_direction: "Outbound".into(),
            filter_status: SidFilterStatus::Disabled,
            exploitable: false,
            risk_level: "HIGH".into(),
            attack_description: "".into(),
            remediation: "".into(),
        };
        assert!(!f.is_critical());
    }

    #[test]
    fn test_risk_priority_ordering() {
        assert_eq!(risk_priority("CRITICAL"), 0);
        assert_eq!(risk_priority("HIGH"), 1);
        assert_eq!(risk_priority("MEDIUM"), 2);
        assert_eq!(risk_priority("INFO"), 3);
        assert_eq!(risk_priority("OK"), 4);
        assert_eq!(risk_priority("UNKNOWN"), 5);
    }

    #[test]
    fn test_analyze_sid_filtering_empty_graph() {
        let g = TrustGraph::new();
        let findings = analyze_sid_filtering("CORP", &g);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_analyze_sid_filtering_external_critical() {
        let mut g = TrustGraph::new();
        g.add_trust(make_edge(
            "CORP",
            "OTHER",
            false,
            TrustDirection::Bidirectional,
            TrustKind::External,
        ));
        let findings = analyze_sid_filtering("CORP", &g);
        let crit: Vec<_> = findings.iter().filter(|f| f.is_critical()).collect();
        assert_eq!(crit.len(), 1);
        assert_eq!(crit[0].risk_level, "CRITICAL");
    }

    #[test]
    fn test_analyze_sid_filtering_parent_child() {
        let mut g = TrustGraph::new();
        g.add_trust(make_edge(
            "CHILD",
            "PARENT",
            false,
            TrustDirection::Bidirectional,
            TrustKind::ParentChild,
        ));
        let findings = analyze_sid_filtering("CHILD", &g);
        assert!(findings.iter().any(|f| f.risk_level == "INFO"));
    }

    #[test]
    fn test_analyze_sid_filtering_external_sid_filtered() {
        let mut g = TrustGraph::new();
        g.add_trust(make_edge(
            "CORP",
            "OTHER",
            true,
            TrustDirection::Bidirectional,
            TrustKind::External,
        ));
        let findings = analyze_sid_filtering("CORP", &g);
        let ok: Vec<_> = findings.iter().filter(|f| f.risk_level == "OK").collect();
        assert_eq!(ok.len(), 1);
    }
}
