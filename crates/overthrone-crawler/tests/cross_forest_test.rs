//! Unit tests for cross-forest attack opportunity detection.
//!
//! All tests are offline; they use manually crafted TrustGraph / ForeignMembership
//! objects rather than live enumeration data.

use overthrone_crawler::{
    find_cross_forest_opportunities, build_trust_key_guidance,
    CrossForestTechnique, ForeignMembership, Severity,
};
use overthrone_crawler::trust_map::{TrustDirection, TrustEdge, TrustGraph, TrustKind};

// ─────────────────────────────────────────────────────────
//  Test helpers
// ─────────────────────────────────────────────────────────

/// Build a minimal outbound TrustEdge with configurable sid_filtering flag.
fn outbound_forest_trust(source: &str, target: &str, sid_filtering: bool) -> TrustEdge {
    TrustEdge {
        source_domain: source.to_string(),
        target_domain: target.to_string(),
        direction: TrustDirection::Outbound,
        trust_type: TrustKind::Forest,
        transitive: true,
        sid_filtering,
        tgt_delegation: false,
        is_within_forest: false,
        uses_aes: true,
        uses_rc4: false,
        is_pam_trust: false,
    }
}

/// Build an outbound external trust with configurable sid_filtering flag.
fn outbound_external_trust(source: &str, target: &str, sid_filtering: bool) -> TrustEdge {
    TrustEdge {
        source_domain: source.to_string(),
        target_domain: target.to_string(),
        direction: TrustDirection::Outbound,
        trust_type: TrustKind::External,
        transitive: true,
        sid_filtering,
        tgt_delegation: false,
        is_within_forest: false,
        uses_aes: true,
        uses_rc4: false,
        is_pam_trust: false,
    }
}

/// Build a privileged foreign group membership test fixture.
fn privileged_foreign_membership(
    principal: &str,
    foreign_domain: &str,
    local_group: &str,
    local_domain: &str,
) -> ForeignMembership {
    ForeignMembership {
        foreign_principal: principal.to_string(),
        foreign_domain: foreign_domain.to_string(),
        foreign_sid: None,
        local_group: local_group.to_string(),
        local_group_dn: format!(
            "CN={local_group},CN=Users,DC={},DC=local",
            local_domain.split('.').next().unwrap_or(local_domain)
        ),
        local_domain: local_domain.to_string(),
        is_privileged_group: true,
    }
}

// ═══════════════════════════════════════════════════════════
//  Empty inputs → empty output
// ═══════════════════════════════════════════════════════════

#[test]
fn test_empty_trust_graph_no_opportunities() {
    let graph = TrustGraph::new();
    let opps = find_cross_forest_opportunities(&graph, &[]);
    assert!(opps.is_empty(), "Empty graph must produce no opportunities");
}

#[test]
fn test_empty_memberships_and_no_interesting_trusts() {
    let mut graph = TrustGraph::new();
    // Inbound trust only — cannot leverage outbound
    graph.trusts.push(TrustEdge {
        source_domain: "target.local".to_string(),
        target_domain: "source.local".to_string(),
        direction: TrustDirection::Inbound,
        trust_type: TrustKind::Forest,
        transitive: true,
        sid_filtering: true,
        tgt_delegation: false,
        is_within_forest: false,
        uses_aes: true,
        uses_rc4: false,
        is_pam_trust: false,
    });
    let opps = find_cross_forest_opportunities(&graph, &[]);
    assert!(
        opps.is_empty(),
        "Inbound-only trust with SID filtering enabled must produce no opportunities"
    );
}

// ═══════════════════════════════════════════════════════════
//  SID filtering disabled → SidHistoryGoldenTicket
// ═══════════════════════════════════════════════════════════

#[test]
fn test_no_sid_filtering_produces_sid_history_opportunity() {
    let mut graph = TrustGraph::new();
    graph.trusts.push(outbound_forest_trust("source.local", "target.local", false));
    let opps = find_cross_forest_opportunities(&graph, &[]);

    let techniques: Vec<&CrossForestTechnique> = opps.iter().map(|o| &o.technique).collect();
    assert!(
        techniques.contains(&&CrossForestTechnique::SidHistoryGoldenTicket),
        "SID filtering disabled must trigger SidHistoryGoldenTicket; got: {techniques:?}"
    );
}

#[test]
fn test_forest_trust_no_sid_filter_severity_is_high() {
    // External (cross-forest) trust without SID filtering = High severity
    let mut graph = TrustGraph::new();
    graph.trusts.push(outbound_forest_trust("source.local", "target.local", false));
    let opps = find_cross_forest_opportunities(&graph, &[]);

    let sid_hist = opps
        .iter()
        .find(|o| o.technique == CrossForestTechnique::SidHistoryGoldenTicket)
        .expect("Must have a SidHistoryGoldenTicket opportunity");

    // External (non-within-forest) trust → High severity
    assert!(
        sid_hist.severity == Severity::High || sid_hist.severity == Severity::Critical,
        "Severity must be at least High for cross-forest SID history attack, got {:?}",
        sid_hist.severity
    );
}

#[test]
fn test_sid_filtering_enabled_no_sid_history_opportunity() {
    let mut graph = TrustGraph::new();
    graph.trusts.push(outbound_forest_trust("source.local", "target.local", true));
    let opps = find_cross_forest_opportunities(&graph, &[]);

    let has_sid_hist = opps
        .iter()
        .any(|o| o.technique == CrossForestTechnique::SidHistoryGoldenTicket);
    assert!(
        !has_sid_hist,
        "SID filtering enabled must NOT produce SidHistoryGoldenTicket"
    );
}

// ═══════════════════════════════════════════════════════════
//  TGT delegation with SID filtering → TgtDelegationAbuse
// ═══════════════════════════════════════════════════════════

#[test]
fn test_tgt_delegation_with_sid_filtering_produces_delegation_opportunity() {
    let mut graph = TrustGraph::new();
    graph.trusts.push(TrustEdge {
        source_domain: "source.local".to_string(),
        target_domain: "target.local".to_string(),
        direction: TrustDirection::Outbound,
        trust_type: TrustKind::Forest,
        transitive: true,
        sid_filtering: true,    // SID filtering ON
        tgt_delegation: true,   // TGT delegation ON → S4U2Proxy path
        is_within_forest: false,
        uses_aes: true,
        uses_rc4: false,
        is_pam_trust: false,
    });
    let opps = find_cross_forest_opportunities(&graph, &[]);

    let has_tgt = opps
        .iter()
        .any(|o| o.technique == CrossForestTechnique::TgtDelegationAbuse);
    assert!(
        has_tgt,
        "TGT delegation with SID filtering must produce TgtDelegationAbuse opportunity"
    );
}

// ═══════════════════════════════════════════════════════════
//  Foreign privileged membership
// ═══════════════════════════════════════════════════════════

#[test]
fn test_privileged_foreign_membership_detected() {
    let graph = TrustGraph::new();
    let fm = privileged_foreign_membership(
        "evil_user",
        "evil.local",
        "Domain Admins",
        "corp.local",
    );
    let opps = find_cross_forest_opportunities(&graph, &[fm]);

    assert!(
        !opps.is_empty(),
        "Privileged foreign membership must create at least one opportunity"
    );
    assert_eq!(
        opps[0].severity,
        Severity::Critical,
        "Privileged group membership must be Critical severity"
    );
    assert!(
        matches!(
            &opps[0].technique,
            CrossForestTechnique::ForeignPrivilegedMembership { .. }
        ),
        "Technique must be ForeignPrivilegedMembership"
    );
}

#[test]
fn test_non_privileged_membership_produces_no_opportunity() {
    let graph = TrustGraph::new();
    let fm = ForeignMembership {
        foreign_principal: "regular_user".to_string(),
        foreign_domain: "other.local".to_string(),
        foreign_sid: None,
        local_group: "HR".to_string(),
        local_group_dn: "CN=HR,CN=Users,DC=corp,DC=local".to_string(),
        local_domain: "corp.local".to_string(),
        is_privileged_group: false,
    };
    let opps = find_cross_forest_opportunities(&graph, &[fm]);
    assert!(
        opps.is_empty(),
        "Non-privileged membership must not produce any opportunities"
    );
}

// ═══════════════════════════════════════════════════════════
//  External trust with no SID filtering
// ═══════════════════════════════════════════════════════════

#[test]
fn test_external_trust_no_sid_filtering_produces_external_trust_opportunity() {
    let mut graph = TrustGraph::new();
    graph
        .trusts
        .push(outbound_external_trust("source.local", "target.local", false));
    let opps = find_cross_forest_opportunities(&graph, &[]);

    let has_ext = opps
        .iter()
        .any(|o| o.technique == CrossForestTechnique::ExternalTrustNoFilter);
    assert!(
        has_ext,
        "External trust with no SID filtering must produce ExternalTrustNoFilter opportunity"
    );
}

// ═══════════════════════════════════════════════════════════
//  Severity ordering
// ═══════════════════════════════════════════════════════════

#[test]
fn test_results_sorted_by_severity_descending() {
    let mut graph = TrustGraph::new();
    // Forest trust, no SID filtering (High)
    graph.trusts.push(outbound_forest_trust("source.local", "target.local", false));
    // Privileged foreign membership (Critical)
    let fm = privileged_foreign_membership(
        "attacker",
        "evil.local",
        "Domain Admins",
        "corp.local",
    );
    let opps = find_cross_forest_opportunities(&graph, &[fm]);

    assert!(!opps.is_empty());
    // Verify descending order
    for w in opps.windows(2) {
        assert!(
            w[0].severity >= w[1].severity,
            "Opportunities must be sorted Critical→High→Medium→Low; found {:?} before {:?}",
            w[0].severity,
            w[1].severity
        );
    }
}

#[test]
fn test_critical_before_high() {
    let mut graph = TrustGraph::new();
    graph.trusts.push(outbound_forest_trust("a.local", "b.local", false));
    let fm = privileged_foreign_membership("u", "evil.local", "Domain Admins", "corp.local");
    let opps = find_cross_forest_opportunities(&graph, &[fm]);

    // First item must be Critical (from privileged membership)
    assert_eq!(
        opps[0].severity,
        Severity::Critical,
        "Critical-severity opportunity must come first"
    );
}

// ═══════════════════════════════════════════════════════════
//  build_trust_key_guidance
// ═══════════════════════════════════════════════════════════

#[test]
fn test_trust_key_guidance_dcsync_contains_target_dollar() {
    let guidance = build_trust_key_guidance("source.local", "10.0.0.1", "target.local");
    // Trust account is TARGET$ (NETBIOS name of target + $)
    assert!(
        guidance.dcsync_command.contains("TARGET$"),
        "dcsync_command must reference trust account 'TARGET$', got: {}",
        guidance.dcsync_command
    );
}

#[test]
fn test_trust_key_guidance_contains_dc_ip() {
    let guidance = build_trust_key_guidance("source.local", "192.168.1.100", "target.local");
    assert!(
        guidance.dcsync_command.contains("192.168.1.100"),
        "dcsync_command must contain the DC IP address"
    );
}

#[test]
fn test_trust_key_guidance_source_and_target_set() {
    let guidance = build_trust_key_guidance("source.local", "10.10.0.1", "target.local");
    assert_eq!(guidance.source_domain, "source.local");
    assert_eq!(guidance.target_domain, "target.local");
}

#[test]
fn test_trust_key_guidance_secretsdump_command_present() {
    let guidance = build_trust_key_guidance("source.local", "10.0.0.1", "target.local");
    // secretsdump_command should be non-empty
    assert!(
        !guidance.secretsdump_command.is_empty(),
        "secretsdump_command must be populated"
    );
}
