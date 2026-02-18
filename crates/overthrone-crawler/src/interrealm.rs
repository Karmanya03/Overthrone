//! Inter-realm / cross-forest Kerberos attack path analysis.
//!
//! Identifies concrete Kerberos attack vectors that exploit
//! trust relationships for cross-domain compromise.

use crate::trust_map::{TrustGraph, TrustKind, TrustDirection};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterRealmTechnique {
    /// Forge inter-realm TGT using extracted trust key
    TrustKeyTgt {
        source_realm: String,
        target_realm: String,
        key_type: String,
    },
    /// Inject SIDs into inter-realm TGT's PAC
    SidHistoryForging {
        injected_sid: String,
        target_group: String,
    },
    /// Exploit referral processing weaknesses
    ReferralAbuse,
    /// Cross-forest constrained delegation via S4U
    CrossForestDelegation {
        source_principal: String,
        target_spn: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterRealmAttack {
    pub source_domain: String,
    pub target_domain: String,
    pub technique: InterRealmTechnique,
    pub prerequisites: Vec<String>,
    pub impact: String,
    pub risk_level: String,
    pub description: String,
    pub tools: Vec<String>,
}

impl InterRealmAttack {
    pub fn achieves_admin(&self) -> bool {
        let lower = self.impact.to_lowercase();
        lower.contains("admin") || lower.contains("enterprise")
    }
}

/// Analyze each trust in the graph for inter-realm Kerberos attack vectors.
pub fn find_interrealm_attacks(
    source_domain: &str,
    graph: &TrustGraph,
) -> Vec<InterRealmAttack> {
    let mut attacks = Vec::new();
    let source_upper = source_domain.to_uppercase();

    info!("[interrealm] Analyzing inter-realm attack vectors from {}", source_domain);

    for trust in &graph.trusts {
        // Only analyze trusts originating from our domain
        if trust.source_domain != source_upper {
            continue;
        }
        if !trust.direction.allows_outbound() {
            continue;
        }

        // ── Parent-Child: Trust Key TGT Forging ──
        if trust.trust_type == TrustKind::ParentChild {
            attacks.push(InterRealmAttack {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                technique: InterRealmTechnique::TrustKeyTgt {
                    source_realm: trust.source_domain.clone(),
                    target_realm: trust.target_domain.clone(),
                    key_type: if trust.uses_aes { "AES256" } else { "RC4" }.into(),
                },
                prerequisites: vec![
                    format!("Domain Admin in {}", trust.source_domain),
                    "DCSync to extract inter-realm trust key (krbtgt/TARGET@SOURCE)".into(),
                ],
                impact: format!("Enterprise Admin in {} forest", trust.target_domain),
                risk_level: "HIGH".into(),
                description: format!(
                    "Extract trust key via DCSync of '{}\\krbtgt' trust account, \
                     forge inter-realm TGT with Enterprise Admins SID in ExtraSids field",
                    trust.target_domain
                ),
                tools: vec![
                    "mimikatz: lsadump::dcsync /domain:{} /user:TRUST$".into(),
                    "ticketer.py -nthash <hash> -domain-sid <sid> -extra-sid <EA-SID> -domain <source>".into(),
                    "rubeus.exe golden /rc4:<hash> /domain:<source> /sid:<sid> /sids:<EA-SID> /user:Administrator".into(),
                ],
            });

            // SID history injection if no filtering
            if !trust.sid_filtering {
                attacks.push(InterRealmAttack {
                    source_domain: trust.source_domain.clone(),
                    target_domain: trust.target_domain.clone(),
                    technique: InterRealmTechnique::SidHistoryForging {
                        injected_sid: format!("<{}-519>", trust.target_domain),
                        target_group: "Enterprise Admins".into(),
                    },
                    prerequisites: vec![
                        format!("Domain Admin in {}", trust.source_domain),
                        "Trust key or Golden Ticket capability".into(),
                    ],
                    impact: format!("Enterprise Admin in {}", trust.target_domain),
                    risk_level: "CRITICAL".into(),
                    description: format!(
                        "Parent-child trust with NO SID filtering: inject Enterprise Admins SID \
                         ({}-519) into inter-realm TGT ExtraSids. Automatic EA access.",
                        trust.target_domain
                    ),
                    tools: vec![
                        "mimikatz: kerberos::golden /sids:<parent-EA-SID>".into(),
                        "ticketer.py -extra-sid <parent-domain-SID>-519".into(),
                    ],
                });
            }
        }

        // ── Forest Trust: SID History if unfiltered ──
        if trust.trust_type == TrustKind::Forest && !trust.sid_filtering {
            attacks.push(InterRealmAttack {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                technique: InterRealmTechnique::SidHistoryForging {
                    injected_sid: format!("<{}-512>", trust.target_domain),
                    target_group: "Domain Admins".into(),
                },
                prerequisites: vec![
                    format!("Domain Admin in {}", trust.source_domain),
                    "Forest trust key".into(),
                ],
                impact: format!("Domain Admin in {} (cross-forest)", trust.target_domain),
                risk_level: "CRITICAL".into(),
                description: format!(
                    "Cross-forest trust {} → {} has SID filtering DISABLED. \
                     Can inject Domain Admins SID from target forest into inter-realm ticket.",
                    trust.source_domain, trust.target_domain
                ),
                tools: vec![
                    "ticketer.py -extra-sid <target-DA-SID> -domain <source>".into(),
                ],
            });
        }

        // ── External Trust: Limited but still useful ──
        if trust.trust_type == TrustKind::External
            && !trust.sid_filtering {
                attacks.push(InterRealmAttack {
                    source_domain: trust.source_domain.clone(),
                    target_domain: trust.target_domain.clone(),
                    technique: InterRealmTechnique::SidHistoryForging {
                        injected_sid: format!("<{}-512>", trust.target_domain),
                        target_group: "Domain Admins".into(),
                    },
                    prerequisites: vec![
                        format!("Domain Admin in {}", trust.source_domain),
                    ],
                    impact: format!("Domain Admin in {}", trust.target_domain),
                    risk_level: "CRITICAL".into(),
                    description: format!(
                        "External trust to {} with SID filtering DISABLED — \
                         SID history injection possible",
                        trust.target_domain
                    ),
                    tools: vec![
                        "ticketer.py with -extra-sid targeting DA SID".into(),
                    ],
                });
            }

        // ── RC4-only trusts (weaker crypto, easier to bruteforce) ──
        if trust.uses_rc4 && !trust.uses_aes {
            attacks.push(InterRealmAttack {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                technique: InterRealmTechnique::TrustKeyTgt {
                    source_realm: trust.source_domain.clone(),
                    target_realm: trust.target_domain.clone(),
                    key_type: "RC4 (NTLM - weaker)".into(),
                },
                prerequisites: vec![
                    format!("Domain Admin in {}", trust.source_domain),
                    "RC4 trust key (easier to extract than AES)".into(),
                ],
                impact: format!("Authenticated access to {}", trust.target_domain),
                risk_level: "MEDIUM".into(),
                description: format!(
                    "Trust {} → {} uses RC4 only (no AES). RC4 trust keys are \
                     NTLM hashes — easier to extract and use for ticket forging.",
                    trust.source_domain, trust.target_domain
                ),
                tools: vec![
                    "secretsdump.py to extract trust key".into(),
                    "mimikatz: lsadump::trust /patch".into(),
                ],
            });
        }
    }

    // Sort: CRITICAL first
    attacks.sort_by(|a, b| {
        risk_priority(&a.risk_level).cmp(&risk_priority(&b.risk_level))
    });

    info!("[interrealm] Found {} inter-realm attack vectors ({} critical)",
        attacks.len(),
        attacks.iter().filter(|a| a.risk_level == "CRITICAL").count()
    );

    attacks
}

fn risk_priority(level: &str) -> u8 {
    match level {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}
