//! Cross-domain privilege escalation path detection.
//!
//! Combines trust graph analysis with reaper data to identify
//! concrete escalation paths across trust boundaries.

use crate::foreign::ForeignMembership;
use crate::trust_map::{TrustGraph, TrustKind};
use overthrone_reaper::delegations::DelegationType;
use overthrone_reaper::runner::ReaperResult;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationTechnique {
    SidHistoryInjection,
    UnconstrainedDelegation { computer: String },
    ConstrainedDelegation { source: String, target_spn: String },
    ResourceBasedConstrainedDelegation { target_computer: String },
    ForeignGroupMembership { principal: String, group: String },
    PamTrustAbuse,
    TrustKeyForging,
    MssqlLinkChain { service_account: String },
    CrossDomainAdcs { template: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationHop {
    pub from_domain: String,
    pub to_domain: String,
    pub technique: EscalationTechnique,
    pub prerequisite: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPath {
    pub source_domain: String,
    pub target_domain: String,
    pub hops: Vec<EscalationHop>,
    pub total_hops: usize,
    pub requires_da: bool,
    pub description: String,
}

impl EscalationPath {
    pub fn difficulty(&self) -> &'static str {
        if self.hops.len() == 1 && !self.requires_da {
            "EASY"
        } else if self.requires_da {
            "HARD"
        } else {
            "MEDIUM"
        }
    }
}

/// Analyze all available data to find cross-domain escalation paths.
pub fn find_escalation_paths(
    trust_graph: &TrustGraph,
    foreign_memberships: &[ForeignMembership],
    reaper: &ReaperResult,
) -> Vec<EscalationPath> {
    let mut paths = Vec::new();

    info!("[escalation] Analyzing escalation paths...");

    // ── 1. SID History Injection via unfiltered trusts ──
    for trust in &trust_graph.trusts {
        if !trust.sid_filtering && trust.direction.allows_outbound() {
            let requires_da = trust.is_within_forest;
            paths.push(EscalationPath {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                hops: vec![EscalationHop {
                    from_domain: trust.source_domain.clone(),
                    to_domain: trust.target_domain.clone(),
                    technique: EscalationTechnique::SidHistoryInjection,
                    prerequisite: if requires_da {
                        "Domain Admin in source domain (for trust key extraction)".into()
                    } else {
                        "Any compromised user + Golden Ticket capability".into()
                    },
                    risk_level: "CRITICAL".into(),
                }],
                total_hops: 1,
                requires_da,
                description: format!(
                    "SID history injection: forge ticket with {}'s Enterprise/Domain Admin SID via {} trust (SID filtering DISABLED)",
                    trust.target_domain,
                    if trust.is_within_forest { "intra-forest" } else { "external" }
                ),
            });
        }
    }

    // ── 2. Trust Key Forging (parent-child) ──
    for trust in &trust_graph.trusts {
        if trust.trust_type == TrustKind::ParentChild && trust.direction.allows_outbound() {
            paths.push(EscalationPath {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                hops: vec![EscalationHop {
                    from_domain: trust.source_domain.clone(),
                    to_domain: trust.target_domain.clone(),
                    technique: EscalationTechnique::TrustKeyForging,
                    prerequisite: "Domain Admin in child domain (DCSync the trust account krbtgt)".into(),
                    risk_level: "HIGH".into(),
                }],
                total_hops: 1,
                requires_da: true,
                description: format!(
                    "Parent-child trust key forging: DCSync trust account, forge inter-realm TGT to {} with EA SID in SID history",
                    trust.target_domain
                ),
            });
        }
    }

    // ── 3. Foreign group membership in privileged groups ──
    for fm in foreign_memberships {
        if fm.is_privileged_group {
            paths.push(EscalationPath {
                source_domain: fm.foreign_domain.to_uppercase(),
                target_domain: fm.local_domain.to_uppercase(),
                hops: vec![EscalationHop {
                    from_domain: fm.foreign_domain.to_uppercase(),
                    to_domain: fm.local_domain.to_uppercase(),
                    technique: EscalationTechnique::ForeignGroupMembership {
                        principal: fm.foreign_principal.clone(),
                        group: fm.local_group.clone(),
                    },
                    prerequisite: format!(
                        "Compromise '{}' in {}",
                        fm.foreign_principal, fm.foreign_domain
                    ),
                    risk_level: "HIGH".into(),
                }],
                total_hops: 1,
                requires_da: false,
                description: format!(
                    "Foreign principal '{}' from {} is a member of privileged group '{}' in {}",
                    fm.foreign_principal, fm.foreign_domain, fm.local_group, fm.local_domain
                ),
            });
        }
    }

    // ── 4. Unconstrained delegation hosts ──
    for computer in &reaper.computers {
        if computer.unconstrained_delegation && computer.enabled && !computer.is_domain_controller {
            // Any trust that allows inbound auth to us = we can capture their TGTs
            for trust in &trust_graph.trusts {
                if trust.direction.allows_inbound() || trust.direction.allows_outbound() {
                    paths.push(EscalationPath {
                        source_domain: reaper.domain.to_uppercase(),
                        target_domain: trust.target_domain.clone(),
                        hops: vec![EscalationHop {
                            from_domain: reaper.domain.to_uppercase(),
                            to_domain: trust.target_domain.clone(),
                            technique: EscalationTechnique::UnconstrainedDelegation {
                                computer: computer.sam_account_name.clone(),
                            },
                            prerequisite: format!(
                                "Admin access to {} + coerce auth from {} DC",
                                computer.sam_account_name, trust.target_domain
                            ),
                            risk_level: "HIGH".into(),
                        }],
                        total_hops: 1,
                        requires_da: false,
                        description: format!(
                            "Unconstrained delegation on {} can capture TGTs from {} via print spooler/petitpotam coercion",
                            computer.sam_account_name, trust.target_domain
                        ),
                    });
                }
            }
        }
    }

    // ── 5. Constrained delegation crossing trust boundaries ──
    for deleg in &reaper.delegations {
        if !deleg.enabled {
            continue;
        }
        for target_spn in &deleg.targets {
            // Check if the SPN target is in a different domain
            let target_host = spn_hostname(target_spn);
            // If the target hostname doesn't match our domain, it might cross a trust
            if !target_host
                .to_uppercase()
                .ends_with(&format!(".{}", reaper.domain.to_uppercase()))
            {
                let target_domain =
                    domain_from_hostname(&target_host).unwrap_or_else(|| "UNKNOWN".to_string());
                let technique = match deleg.delegation_type {
                    DelegationType::ResourceBased => {
                        EscalationTechnique::ResourceBasedConstrainedDelegation {
                            target_computer: target_host.clone(),
                        }
                    }
                    _ => EscalationTechnique::ConstrainedDelegation {
                        source: deleg.principal.clone(),
                        target_spn: target_spn.clone(),
                    },
                };

                paths.push(EscalationPath {
                    source_domain: reaper.domain.to_uppercase(),
                    target_domain: target_domain.to_uppercase(),
                    hops: vec![EscalationHop {
                        from_domain: reaper.domain.to_uppercase(),
                        to_domain: target_domain.to_uppercase(),
                        technique,
                        prerequisite: format!("Compromise '{}'", deleg.principal),
                        risk_level: "HIGH".into(),
                    }],
                    total_hops: 1,
                    requires_da: false,
                    description: format!(
                        "Cross-domain constrained delegation: {} → {} (S4U2Proxy)",
                        deleg.principal, target_spn
                    ),
                });
            }
        }
    }

    // ── 6. MSSQL service accounts crossing domains ──
    for instance in &reaper.mssql_instances {
        if let Some(ref hostname) = instance.hostname
            && !hostname
                .to_uppercase()
                .ends_with(&format!(".{}", reaper.domain.to_uppercase()))
        {
            let target_domain =
                domain_from_hostname(hostname).unwrap_or_else(|| "UNKNOWN".to_string());
            paths.push(EscalationPath {
                source_domain: reaper.domain.to_uppercase(),
                target_domain: target_domain.to_uppercase(),
                hops: vec![EscalationHop {
                    from_domain: reaper.domain.to_uppercase(),
                    to_domain: target_domain.to_uppercase(),
                    technique: EscalationTechnique::MssqlLinkChain {
                        service_account: instance.service_account.clone(),
                    },
                    prerequisite: format!(
                        "Kerberoast/compromise '{}' + MSSQL access",
                        instance.service_account
                    ),
                    risk_level: "MEDIUM".into(),
                }],
                total_hops: 1,
                requires_da: false,
                description: format!(
                    "MSSQL service account '{}' has SPN for cross-domain host {}",
                    instance.service_account, hostname
                ),
            });
        }
    }

    // ── 7. Vulnerable ADCS templates ──
    for template in &reaper.adcs_templates {
        if !template.vulnerabilities.is_empty() && template.enrollee_supplies_subject {
            // ESC1 can be used cross-domain if enrollment is open
            for trust in &trust_graph.trusts {
                if trust.direction.allows_inbound() {
                    paths.push(EscalationPath {
                        source_domain: trust.target_domain.clone(),
                        target_domain: reaper.domain.to_uppercase(),
                        hops: vec![EscalationHop {
                            from_domain: trust.target_domain.clone(),
                            to_domain: reaper.domain.to_uppercase(),
                            technique: EscalationTechnique::CrossDomainAdcs {
                                template: template.name.clone(),
                            },
                            prerequisite: format!(
                                "User in {} with enrollment rights on template '{}'",
                                trust.target_domain, template.name
                            ),
                            risk_level: "CRITICAL".into(),
                        }],
                        total_hops: 1,
                        requires_da: false,
                        description: format!(
                            "Vulnerable ADCS template '{}' ({}) exploitable cross-domain from {}",
                            template.name,
                            template.vulnerabilities.join(", "),
                            trust.target_domain
                        ),
                    });
                }
            }
        }
    }

    // Sort by hop count, then by requires_da (easier first)
    paths.sort_by(|a, b| {
        a.total_hops
            .cmp(&b.total_hops)
            .then(a.requires_da.cmp(&b.requires_da))
    });

    info!(
        "[escalation] Found {} escalation paths ({} easy, {} hard)",
        paths.len(),
        paths.iter().filter(|p| p.difficulty() == "EASY").count(),
        paths.iter().filter(|p| p.difficulty() == "HARD").count(),
    );

    paths
}

/// Extract hostname from an SPN like "MSSQLSvc/host.domain.com:1433"
fn spn_hostname(spn: &str) -> String {
    spn.split_once('/')
        .map(|x| x.1)
        .unwrap_or(spn)
        .split(':')
        .next()
        .unwrap_or(spn)
        .to_string()
}

/// Guess domain from an FQDN: "dc01.child.corp.local" → "child.corp.local"
fn domain_from_hostname(hostname: &str) -> Option<String> {
    let parts: Vec<&str> = hostname.splitn(2, '.').collect();
    if parts.len() == 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}
