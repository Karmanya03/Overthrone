//! Unit tests for the attack-path graph engine.
//!
//! Tests node/edge management, case-insensitive lookup, Dijkstra shortest-path
//! computation, high-value target analytics, and graph statistics.
//! All tests are offline (no LDAP / DC required).

use overthrone_core::graph::{AdNode, AttackGraph, EdgeType, NodeType};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────
//  Test helpers
// ─────────────────────────────────────────────────────────

fn user_node(name: &str, domain: &str) -> AdNode {
    AdNode {
        name: name.to_string(),
        node_type: NodeType::User,
        domain: domain.to_string(),
        distinguished_name: None,
        enabled: true,
        properties: HashMap::new(),
    }
}

fn computer_node(name: &str, domain: &str) -> AdNode {
    AdNode {
        name: name.to_string(),
        node_type: NodeType::Computer,
        domain: domain.to_string(),
        distinguished_name: None,
        enabled: true,
        properties: HashMap::new(),
    }
}

fn group_node(name: &str, domain: &str) -> AdNode {
    AdNode {
        name: name.to_string(),
        node_type: NodeType::Group,
        domain: domain.to_string(),
        distinguished_name: None,
        enabled: true,
        properties: HashMap::new(),
    }
}

fn domain_node(name: &str) -> AdNode {
    AdNode {
        name: name.to_string(),
        node_type: NodeType::Domain,
        domain: name.to_string(),
        distinguished_name: None,
        enabled: true,
        properties: HashMap::new(),
    }
}

// ═══════════════════════════════════════════════════════════
//  Graph construction
// ═══════════════════════════════════════════════════════════

#[test]
fn test_new_graph_starts_empty() {
    let g = AttackGraph::new();
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn test_add_node_increments_count() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    assert_eq!(g.node_count(), 1);
}

#[test]
fn test_add_multiple_distinct_nodes() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(user_node("bob", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    assert_eq!(g.node_count(), 3);
}

#[test]
fn test_add_duplicate_node_is_idempotent() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(user_node("alice", "corp.local")); // same key
    assert_eq!(g.node_count(), 1, "Duplicate nodes must collapse to one");
}

// ═══════════════════════════════════════════════════════════
//  add_edge_by_name
// ═══════════════════════════════════════════════════════════

#[test]
fn test_add_edge_between_existing_nodes_succeeds() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    let added = g.add_edge_by_name(
        "alice",
        "corp.local",
        "DC01",
        "corp.local",
        EdgeType::AdminTo,
    );
    assert!(added, "Edge between two existing nodes must return true");
    assert_eq!(g.edge_count(), 1);
}

#[test]
fn test_add_edge_where_source_missing_returns_false() {
    let mut g = AttackGraph::new();
    g.add_node(computer_node("DC01", "corp.local"));
    let added = g.add_edge_by_name(
        "missing",
        "corp.local",
        "DC01",
        "corp.local",
        EdgeType::AdminTo,
    );
    assert!(!added);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn test_add_edge_where_target_missing_returns_false() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    let added = g.add_edge_by_name(
        "alice",
        "corp.local",
        "missing",
        "corp.local",
        EdgeType::AdminTo,
    );
    assert!(!added);
}

// ═══════════════════════════════════════════════════════════
//  find_node
// ═══════════════════════════════════════════════════════════

#[test]
fn test_find_node_by_full_key_uppercase() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("Alice", "CORP.LOCAL"));
    assert!(g.find_node("ALICE@CORP.LOCAL").is_some());
}

#[test]
fn test_find_node_case_insensitive_lookup() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("Alice", "corp.local"));
    // find_node normalises to uppercase before searching
    assert!(g.find_node("alice@corp.local").is_some());
    assert!(g.find_node("ALICE@CORP.LOCAL").is_some());
}

#[test]
fn test_find_node_missing_key_returns_none() {
    let g = AttackGraph::new();
    assert!(g.find_node("nobody@nowhere.test").is_none());
}

#[test]
fn test_find_node_prefix_fuzzy_match() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    // Fuzzy prefix fallback: searching for just "alice" should match "ALICE@CORP.LOCAL"
    let idx = g.find_node("alice");
    assert!(idx.is_some(), "Prefix match should find 'alice@corp.local'");
}

// ═══════════════════════════════════════════════════════════
//  shortest_path
// ═══════════════════════════════════════════════════════════

#[test]
fn test_shortest_path_single_hop() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    g.add_edge_by_name(
        "alice",
        "corp.local",
        "DC01",
        "corp.local",
        EdgeType::AdminTo,
    );

    let path = g
        .shortest_path("ALICE@CORP.LOCAL", "DC01@CORP.LOCAL")
        .unwrap();
    assert_eq!(path.hop_count, 1, "Direct edge should produce 1 hop");
    assert_eq!(path.source, "alice");
    assert_eq!(path.target, "DC01");
    assert_eq!(path.total_cost, EdgeType::AdminTo.default_cost());
}

#[test]
fn test_shortest_path_two_hops() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(computer_node("WS01", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    g.add_edge_by_name(
        "alice",
        "corp.local",
        "WS01",
        "corp.local",
        EdgeType::AdminTo,
    );
    g.add_edge_by_name(
        "WS01",
        "corp.local",
        "DC01",
        "corp.local",
        EdgeType::AdminTo,
    );

    let path = g
        .shortest_path("ALICE@CORP.LOCAL", "DC01@CORP.LOCAL")
        .unwrap();
    assert_eq!(path.hop_count, 2);
    assert_eq!(
        path.total_cost,
        EdgeType::AdminTo.default_cost() * 2,
        "Two AdminTo hops should sum costs"
    );
}

#[test]
fn test_shortest_path_prefers_lower_cost_route() {
    // Two paths: direct AdminTo (cost 1) vs two-hop MemberOf+AdminTo (cost 0+1=1)
    // The direct route should win (same cost, but length 1 < 2).
    // At minimum, both should resolve without error.
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(group_node("Domain Admins", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    // Direct path: alice → DC01 (cost 1)
    g.add_edge_by_name(
        "alice",
        "corp.local",
        "DC01",
        "corp.local",
        EdgeType::AdminTo,
    );
    // Indirect path: alice → Domain Admins (MemberOf, cost 0) → DC01 (AdminTo, cost 1)
    g.add_edge_by_name(
        "alice",
        "corp.local",
        "Domain Admins",
        "corp.local",
        EdgeType::MemberOf,
    );
    g.add_edge_by_name(
        "Domain Admins",
        "corp.local",
        "DC01",
        "corp.local",
        EdgeType::AdminTo,
    );

    let path = g
        .shortest_path("ALICE@CORP.LOCAL", "DC01@CORP.LOCAL")
        .unwrap();
    // Total cost must be ≤ 1 (the direct hop cost)
    assert!(
        path.total_cost <= EdgeType::AdminTo.default_cost(),
        "Shortest path cost must be ≤ direct hop cost, got {}",
        path.total_cost
    );
}

#[test]
fn test_shortest_path_no_path_returns_err() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    // Nodes exist but no edge between them

    assert!(
        g.shortest_path("ALICE@CORP.LOCAL", "DC01@CORP.LOCAL")
            .is_err(),
        "No path between disconnected nodes must return Err"
    );
}

#[test]
fn test_shortest_path_source_not_found_returns_err() {
    let mut g = AttackGraph::new();
    g.add_node(computer_node("DC01", "corp.local"));
    assert!(
        g.shortest_path("GHOST@CORP.LOCAL", "DC01@CORP.LOCAL")
            .is_err()
    );
}

#[test]
fn test_shortest_path_target_not_found_returns_err() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    assert!(
        g.shortest_path("ALICE@CORP.LOCAL", "GHOST@CORP.LOCAL")
            .is_err()
    );
}

// ═══════════════════════════════════════════════════════════
//  paths_to_da
// ═══════════════════════════════════════════════════════════

#[test]
fn test_paths_to_da_returns_empty_when_no_da_group() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    // "Domain Admins" node does not exist

    let paths = g.paths_to_da("ALICE@CORP.LOCAL", "corp.local");
    assert!(
        paths.is_empty(),
        "No 'Domain Admins' node → must return empty Vec"
    );
}

#[test]
fn test_paths_to_da_finds_path_when_direct_edge_exists() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(group_node("Domain Admins", "corp.local"));
    g.add_edge_by_name(
        "alice",
        "corp.local",
        "Domain Admins",
        "corp.local",
        EdgeType::MemberOf,
    );

    let paths = g.paths_to_da("ALICE@CORP.LOCAL", "corp.local");
    assert!(
        !paths.is_empty(),
        "Direct MemberOf to Domain Admins must produce at least one path"
    );
}

// ═══════════════════════════════════════════════════════════
//  GraphStats
// ═══════════════════════════════════════════════════════════

#[test]
fn test_stats_counts_node_types_correctly() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(user_node("bob", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    g.add_node(domain_node("corp.local"));

    let stats = g.stats();
    assert_eq!(stats.users, 2);
    assert_eq!(stats.computers, 1);
    assert_eq!(stats.domains, 1);
    assert_eq!(stats.groups, 0);
    assert_eq!(stats.total_nodes, 4);
    assert_eq!(stats.total_edges, 0);
}

#[test]
fn test_stats_counts_edges() {
    let mut g = AttackGraph::new();
    g.add_node(user_node("alice", "corp.local"));
    g.add_node(computer_node("DC01", "corp.local"));
    g.add_edge_by_name(
        "alice",
        "corp.local",
        "DC01",
        "corp.local",
        EdgeType::AdminTo,
    );

    let stats = g.stats();
    assert_eq!(stats.total_edges, 1);
}

// ═══════════════════════════════════════════════════════════
//  EdgeType semantics
// ═══════════════════════════════════════════════════════════

#[test]
fn test_edge_type_memberof_cost_is_zero() {
    assert_eq!(EdgeType::MemberOf.default_cost(), 0);
}

#[test]
fn test_edge_type_adminto_cost_is_one() {
    assert_eq!(EdgeType::AdminTo.default_cost(), 1);
}

#[test]
fn test_edge_type_adminto_is_traversable() {
    assert!(EdgeType::AdminTo.is_traversable());
}

#[test]
fn test_edge_type_hasspn_is_not_traversable() {
    assert!(
        !EdgeType::HasSpn.is_traversable(),
        "HasSpn is a marker, not a traversable relationship"
    );
}

#[test]
fn test_edge_type_dontreqpreauth_not_traversable() {
    assert!(!EdgeType::DontReqPreauth.is_traversable());
}

#[test]
fn test_trusted_by_cost_is_4() {
    assert_eq!(EdgeType::TrustedBy.default_cost(), 4);
}

// ═══════════════════════════════════════════════════════════
//  high_value_targets
// ═══════════════════════════════════════════════════════════

#[test]
fn test_high_value_targets_empty_graph() {
    let g = AttackGraph::new();
    let hvt = g.high_value_targets(5);
    assert!(hvt.is_empty());
}

#[test]
fn test_high_value_targets_respects_limit() {
    let mut g = AttackGraph::new();
    for i in 0..10 {
        g.add_node(user_node(&format!("user{i}"), "corp.local"));
    }
    let hvt = g.high_value_targets(3);
    assert!(hvt.len() <= 3, "Must return at most top_n results");
}
