//! Shortest path and all-paths computation using petgraph.
//!
//! Convenience wrappers around `AttackGraph` methods for common
//! attack path queries.

use crate::error::Result;
use crate::graph::{AttackGraph, AttackPath, GraphStats, NodeType};

/// High-level path-finding interface wrapping `AttackGraph`.
pub struct PathFinder<'a> {
    graph: &'a AttackGraph,
}

impl<'a> PathFinder<'a> {
    /// Create a new PathFinder for the given graph
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self { graph }
    }

    /// Find the shortest attack path between two nodes by name
    pub fn shortest_path(&self, from: &str, to: &str) -> Result<AttackPath> {
        self.graph.shortest_path(from, to)
    }

    /// Find all shortest paths from a compromised node to Domain Admins
    pub fn paths_to_da(&self, from: &str, domain: &str) -> Vec<AttackPath> {
        self.graph.paths_to_da(from, domain)
    }

    /// Get graph statistics
    pub fn stats(&self) -> GraphStats {
        self.graph.stats()
    }

    /// Find reachable Kerberoastable accounts from a given starting node
    pub fn reachable_kerberoastable(&self, from: &str) -> Vec<String> {
        self.graph.reachable_kerberoastable(from)
    }

    /// Find reachable unconstrained delegation targets from a given starting node
    pub fn reachable_unconstrained_delegation(&self, from: &str) -> Vec<String> {
        self.graph.reachable_unconstrained_delegation(from)
    }

    /// Get the highest-value targets in the graph
    pub fn high_value_targets(&self, top_n: usize) -> Vec<(String, NodeType, usize)> {
        self.graph.high_value_targets(top_n)
    }

    /// Export the graph to JSON
    pub fn export_json(&self) -> Result<String> {
        self.graph.export_json()
    }

    /// Find paths from a compromised node to all high-value targets
    pub fn paths_to_high_value(
        &self,
        from: &str,
        top_n: usize,
    ) -> Vec<(String, Option<AttackPath>)> {
        let hvts = self.graph.high_value_targets(top_n);
        hvts.into_iter()
            .map(|(name, _node_type, _edges)| {
                let path = self.graph.shortest_path(from, &name).ok();
                (name, path)
            })
            .collect()
    }

    /// Get all attack paths sorted by cost (cheapest first)
    pub fn cheapest_paths_to_da(&self, from: &str, domain: &str) -> Vec<AttackPath> {
        let mut paths = self.graph.paths_to_da(from, domain);
        paths.sort_by_key(|p| p.total_cost);
        paths
    }
}
