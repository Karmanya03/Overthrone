//! Graph construction from reaper enumeration data.
//!
//! Converts `ReaperResult` (from the reaper crate) into core LDAP types
//! and feeds them into `AttackGraph::ingest_enumeration`.

use crate::graph::{AdNode, AttackGraph, EdgeType, NodeType};
use crate::proto::ldap::{
    AdComputer, AdGroup, AdTrust, AdUser, DomainEnumeration, TrustDirection, TrustType,
};
use tracing::info;

/// Build an `AttackGraph` directly from reaper enumeration output.
///
/// This is the primary entry point for converting reaper data into
/// an attack graph. It converts reaper-specific types into core LDAP
/// types and then delegates to `AttackGraph::ingest_enumeration`.
pub fn build_from_reaper(
    domain: &str,
    base_dn: &str,
    users: &[impl ReaperUser],
    groups: &[impl ReaperGroup],
    computers: &[impl ReaperComputer],
    trusts: &[impl ReaperTrust],
) -> AttackGraph {
    info!("[builder] Building attack graph from reaper data");

    let ad_users: Vec<AdUser> = users.iter().map(|u| u.to_ad_user()).collect();
    let ad_computers: Vec<AdComputer> = computers.iter().map(|c| c.to_ad_computer()).collect();
    let ad_groups: Vec<AdGroup> = groups.iter().map(|g| g.to_ad_group()).collect();
    let ad_trusts: Vec<AdTrust> = trusts.iter().map(|t| t.to_ad_trust()).collect();

    // Derive kerberoastable / asrep roastable from user attributes
    let kerberoastable: Vec<AdUser> = ad_users
        .iter()
        .filter(|u| u.enabled && !u.service_principal_names.is_empty())
        .cloned()
        .collect();

    let asrep_roastable: Vec<AdUser> = ad_users
        .iter()
        .filter(|u| u.enabled && u.dont_req_preauth)
        .cloned()
        .collect();

    let unconstrained_delegation: Vec<AdComputer> = ad_computers
        .iter()
        .filter(|c| c.unconstrained_delegation)
        .cloned()
        .collect();

    let constrained_delegation_users: Vec<AdUser> = ad_users
        .iter()
        .filter(|u| u.constrained_delegation)
        .cloned()
        .collect();

    let constrained_delegation_computers: Vec<AdComputer> = ad_computers
        .iter()
        .filter(|c| c.constrained_delegation)
        .cloned()
        .collect();

    let enumeration = DomainEnumeration {
        domain: domain.to_string(),
        base_dn: base_dn.to_string(),
        users: ad_users,
        computers: ad_computers,
        groups: ad_groups,
        trusts: ad_trusts,
        kerberoastable,
        asrep_roastable,
        unconstrained_delegation,
        constrained_delegation_users,
        constrained_delegation_computers,
        domain_admins: Vec::new(), // Populated during ingest via group resolution
    };

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&enumeration);

    let stats = graph.stats();
    info!(
        "[builder] Graph built: {} nodes, {} edges",
        stats.total_nodes, stats.total_edges
    );

    graph
}

// ═══════════════════════════════════════════════════════════
//  Conversion Traits
// ═══════════════════════════════════════════════════════════

/// Trait for converting reaper user types to core `AdUser`
pub trait ReaperUser {
    fn to_ad_user(&self) -> AdUser;
}

/// Trait for converting reaper group types to core `AdGroup`
pub trait ReaperGroup {
    fn to_ad_group(&self) -> AdGroup;
}

/// Trait for converting reaper computer types to core `AdComputer`
pub trait ReaperComputer {
    fn to_ad_computer(&self) -> AdComputer;
}

/// Trait for converting reaper trust types to core `AdTrust`
pub trait ReaperTrust {
    fn to_ad_trust(&self) -> AdTrust;
}

// ═══════════════════════════════════════════════════════════
//  Blanket Implementations for Core Types
// ═══════════════════════════════════════════════════════════

// AdUser → AdUser (identity, for direct use with core types)
impl ReaperUser for AdUser {
    fn to_ad_user(&self) -> AdUser {
        self.clone()
    }
}

impl ReaperGroup for AdGroup {
    fn to_ad_group(&self) -> AdGroup {
        self.clone()
    }
}

impl ReaperComputer for AdComputer {
    fn to_ad_computer(&self) -> AdComputer {
        self.clone()
    }
}

impl ReaperTrust for AdTrust {
    fn to_ad_trust(&self) -> AdTrust {
        self.clone()
    }
}

// ═══════════════════════════════════════════════════════════
//  Convenience: Build from DomainEnumeration directly
// ═══════════════════════════════════════════════════════════

/// Build an `AttackGraph` from a `DomainEnumeration` (core LDAP types)
pub fn build_from_enumeration(data: &DomainEnumeration) -> AttackGraph {
    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(data);

    let stats = graph.stats();
    info!(
        "[builder] Graph built from enumeration: {} nodes, {} edges",
        stats.total_nodes, stats.total_edges
    );

    graph
}

// ═══════════════════════════════════════════════════════════
//  Graph Enrichment
// ═══════════════════════════════════════════════════════════

/// Add ACL-based edges to an existing graph from reaper ACL findings.
/// `findings` should be tuples of (source_name, target_name, right_type).
pub fn enrich_with_acls(
    graph: &mut AttackGraph,
    domain: &str,
    findings: &[(String, String, String)],
) {
    for (source, target, right) in findings {
        let edge_type = match right.as_str() {
            "GenericAll" => EdgeType::GenericAll,
            "GenericWrite" => EdgeType::GenericWrite,
            "WriteOwner" => EdgeType::WriteOwner,
            "WriteDacl" => EdgeType::WriteDacl,
            "ForceChangePassword" => EdgeType::ForceChangePassword,
            "AddMembers" | "Self" => EdgeType::AddMembers,
            "ReadLAPSPassword" => EdgeType::ReadLapsPassword,
            "ReadGMSAPassword" => EdgeType::ReadGmsaPassword,
            "Owns" => EdgeType::Owns,
            other => EdgeType::Custom(other.to_string()),
        };

        graph.add_acl_edge(source, target, domain, edge_type);
    }
}
