//! Pre-built BloodHound-style graph analysis queries.
//!
//! Provides high-level analysis functions for automated attack path discovery,
//! inspired by BloodHound's Cypher query library. All analysis is performed
//! in-memory on the `AttackGraph` using petgraph's Dijkstra.

use crate::graph::{AttackGraph, AttackPath, EdgeType, GraphStats, NodeType};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A node discovered by an analysis query, with its identifying info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisNode {
    /// Name of the node
    pub name: String,
    /// Node type classification
    pub node_type: NodeType,
    /// Domain FQDN
    pub domain: String,
    /// Distinguised name (if available)
    pub distinguished_name: Option<String>,
    /// Whether the node is enabled
    pub enabled: bool,
    /// Custom properties (SPNs, UAC flags, OS, etc.)
    pub properties: HashMap<String, String>,
}

/// Severity rating for a finding in the analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A single finding from the analysis, with context and severity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisFinding {
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub affected_nodes: Vec<AnalysisNode>,
    pub remediation: Option<String>,
}

/// Comprehensive analysis report from running all pre-built queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Graph statistics
    pub stats: GraphStats,
    /// Kerberoastable users (HasSPN)
    pub kerberoastable_users: Vec<AnalysisNode>,
    /// AS-REP roastable users (DontReqPreauth)
    pub asrep_roastable_users: Vec<AnalysisNode>,
    /// Computers with unconstrained delegation
    pub unconstrained_delegation: Vec<AnalysisNode>,
    /// Principals with constrained delegation (AllowedToDelegate edges)
    pub constrained_delegation: Vec<AnalysisNode>,
    /// Computers where DA has active sessions
    pub da_sessions: Vec<AnalysisNode>,
    /// Cheapest attack paths to Domain Admins (by category)
    pub cheapest_da_paths: Vec<AttackPath>,
    /// High-value targets ranked by degree
    pub high_value_targets: Vec<AnalysisNode>,
    /// Summarized findings with severity
    pub findings: Vec<AnalysisFinding>,
}

impl AnalysisNode {
    fn from_graph(name: &str, domain: &str, graph: &AttackGraph) -> Option<Self> {
        let key = format!("{}@{}", name.to_uppercase(), domain.to_uppercase());
        if let Some(idx) = graph.find_node(&key) {
            graph.stats();
            if let Some(node) = graph.get_node(idx) {
                return Some(Self {
                    name: node.name.clone(),
                    node_type: node.node_type.clone(),
                    domain: node.domain.clone(),
                    distinguished_name: node.distinguished_name.clone(),
                    enabled: node.enabled,
                    properties: node.properties.clone(),
                });
            }
        }
        None
    }
}

/// Analysis engine for pre-built BloodHound-style Cypher queries.
///
/// Provides methods for common attack path analysis patterns:
/// - Finding kerberoastable / AS-REP roastable users
/// - Finding delegation abuse targets
/// - Finding cheapest paths to high-value targets
/// - Comprehensive full-graph analysis reports
pub struct GraphAnalysisEngine<'a> {
    graph: &'a AttackGraph,
}

impl<'a> GraphAnalysisEngine<'a> {
    /// Create a new analysis engine for the given graph.
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self { graph }
    }

    // ═════════════════════════════════════════════════════════
    //  Pre-built Node Queries
    // ═════════════════════════════════════════════════════════

    /// Find all kerberoastable users (those with a `HasSpn` outgoing edge).
    pub fn all_kerberoastable(&self) -> Vec<AnalysisNode> {
        self.graph
            .graph()
            .node_indices()
            .filter(|&idx| {
                let node = &self.graph.graph()[idx];
                node.node_type == NodeType::User
                    && self
                        .graph
                        .graph()
                        .edges_directed(idx, petgraph::Direction::Outgoing)
                        .any(|e| *e.weight() == EdgeType::HasSpn)
            })
            .map(|idx| {
                let node = &self.graph.graph()[idx];
                AnalysisNode {
                    name: node.name.clone(),
                    node_type: node.node_type.clone(),
                    domain: node.domain.clone(),
                    distinguished_name: node.distinguished_name.clone(),
                    enabled: node.enabled,
                    properties: node.properties.clone(),
                }
            })
            .collect()
    }

    /// Find all AS-REP roastable users (those with `DontReqPreauth` enabled).
    pub fn all_asrep_roastable(&self) -> Vec<AnalysisNode> {
        self.graph
            .graph()
            .node_indices()
            .filter(|&idx| {
                let node = &self.graph.graph()[idx];
                node.node_type == NodeType::User
                    && node
                        .properties
                        .get("dont_req_preauth")
                        .map(|v| v == "true")
                        .unwrap_or(false)
            })
            .map(|idx| {
                let node = &self.graph.graph()[idx];
                AnalysisNode {
                    name: node.name.clone(),
                    node_type: node.node_type.clone(),
                    domain: node.domain.clone(),
                    distinguished_name: node.distinguished_name.clone(),
                    enabled: node.enabled,
                    properties: node.properties.clone(),
                }
            })
            .collect()
    }

    /// Find all computers with unconstrained delegation enabled.
    pub fn all_unconstrained_delegation(&self) -> Vec<AnalysisNode> {
        self.graph
            .graph()
            .node_indices()
            .filter(|&idx| {
                let node = &self.graph.graph()[idx];
                node.node_type == NodeType::Computer
                    && node
                        .properties
                        .get("unconstrained_delegation")
                        .map(|v| v == "true")
                        .unwrap_or(false)
            })
            .map(|idx| {
                let node = &self.graph.graph()[idx];
                AnalysisNode {
                    name: node.name.clone(),
                    node_type: node.node_type.clone(),
                    domain: node.domain.clone(),
                    distinguished_name: node.distinguished_name.clone(),
                    enabled: node.enabled,
                    properties: node.properties.clone(),
                }
            })
            .collect()
    }

    /// Find all principals with constrained delegation
    /// (target of an `AllowedToDelegate` edge).
    pub fn all_constrained_delegation(&self) -> Vec<AnalysisNode> {
        self.graph
            .graph()
            .node_indices()
            .filter(|&idx| {
                self.graph
                    .graph()
                    .edges_directed(idx, petgraph::Direction::Incoming)
                    .any(|e| *e.weight() == EdgeType::AllowedToDelegate)
            })
            .map(|idx| {
                let node = &self.graph.graph()[idx];
                AnalysisNode {
                    name: node.name.clone(),
                    node_type: node.node_type.clone(),
                    domain: node.domain.clone(),
                    distinguished_name: node.distinguished_name.clone(),
                    enabled: node.enabled,
                    properties: node.properties.clone(),
                }
            })
            .collect()
    }

    /// Find all computers where Domain Admin users have active sessions.
    pub fn all_da_sessions(&self) -> Vec<AnalysisNode> {
        let da_group_names: Vec<String> = self
            .graph
            .graph()
            .node_indices()
            .filter(|&idx| {
                let node = &self.graph.graph()[idx];
                node.node_type == NodeType::Group
                    && node.name.to_lowercase().contains("domain admin")
            })
            .flat_map(|da_group_idx| {
                // Find members of this DA group
                self.graph
                    .graph()
                    .edges_directed(da_group_idx, petgraph::Direction::Incoming)
                    .filter(|e| *e.weight() == EdgeType::MemberOf)
                    .map(|e| {
                        let src = &self.graph.graph()[e.source()];
                        format!("{}@{}", src.name.to_uppercase(), src.domain.to_uppercase())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        if da_group_names.is_empty() {
            return Vec::new();
        }

        self.graph
            .graph()
            .node_indices()
            .filter(|&idx| {
                let node = &self.graph.graph()[idx];
                if node.node_type != NodeType::Computer {
                    return false;
                }
                // Check if any DA has a session on this computer
                self.graph
                    .graph()
                    .edges_directed(idx, petgraph::Direction::Incoming)
                    .filter(|e| *e.weight() == EdgeType::HasSession)
                    .any(|e| {
                        let src = &self.graph.graph()[e.source()];
                        let src_key =
                            format!("{}@{}", src.name.to_uppercase(), src.domain.to_uppercase());
                        da_group_names.contains(&src_key)
                    })
            })
            .map(|idx| {
                let node = &self.graph.graph()[idx];
                AnalysisNode {
                    name: node.name.clone(),
                    node_type: node.node_type.clone(),
                    domain: node.domain.clone(),
                    distinguished_name: node.distinguished_name.clone(),
                    enabled: node.enabled,
                    properties: node.properties.clone(),
                }
            })
            .collect()
    }

    // ═════════════════════════════════════════════════════════
    //  Path Analysis
    // ═════════════════════════════════════════════════════════

    /// Find cheapest attack paths from all reachable sources to a target.
    pub fn cheapest_paths_to_target(&self, target: &str, limit: usize) -> Vec<AttackPath> {
        let tgt_idx = match self.graph.find_node(target) {
            Some(idx) => idx,
            None => return Vec::new(),
        };

        let edge_paths = self.graph.shortest_paths_to(tgt_idx, limit);
        let mut paths = Vec::with_capacity(edge_paths.len());

        for edge_idx_list in &edge_paths {
            if edge_idx_list.is_empty() {
                continue;
            }
            // Reconstruct source and target names from the first and last edges
            let src_node = edge_idx_list
                .first()
                .and_then(|eid| self.graph.graph().edge_endpoints(*eid))
                .and_then(|(src, _)| self.graph.get_node(src))
                .map(|n| format!("{}@{}", n.name, n.domain))
                .unwrap_or_else(|| "unknown".to_string());

            let tgt_node = edge_idx_list
                .last()
                .and_then(|eid| self.graph.graph().edge_endpoints(*eid))
                .and_then(|(_, tgt)| self.graph.get_node(tgt))
                .map(|n| format!("{}@{}", n.name, n.domain))
                .unwrap_or_else(|| target.to_string());

            let mut hops = Vec::with_capacity(edge_idx_list.len());
            let mut total_cost = 0u32;

            for &eid in edge_idx_list {
                if let Some((src, tgt)) = self.graph.graph().edge_endpoints(eid) {
                    let weight = self.graph.graph()[eid].clone();
                    let cost = weight.default_cost();
                    total_cost += cost;

                    let src_type = self.graph.graph()[src].node_type.clone();
                    let tgt_type = self.graph.graph()[tgt].node_type.clone();
                    let src_name = self.graph.graph()[src].name.clone();
                    let tgt_name = self.graph.graph()[tgt].name.clone();

                    use crate::graph::PathHop;
                    hops.push(PathHop {
                        source: src_name,
                        source_type: src_type,
                        edge: weight,
                        target: tgt_name,
                        target_type: tgt_type,
                        cost,
                    });
                }
            }

            paths.push(AttackPath {
                source: src_node,
                target: tgt_node,
                total_cost,
                hop_count: hops.len(),
                hops,
            });
        }

        paths.sort_by_key(|p| p.total_cost);
        paths
    }

    /// Find cheapest paths from all reachable sources to Domain Admins.
    pub fn cheapest_paths_to_da(&self, domain: &str, limit: usize) -> Vec<AttackPath> {
        // Find DA group nodes
        let da_groups: Vec<_> = self
            .graph
            .graph()
            .node_indices()
            .filter(|&idx| {
                let node = &self.graph.graph()[idx];
                node.node_type == NodeType::Group
                    && node.domain.to_uppercase() == domain.to_uppercase()
                    && (node.name.to_lowercase().contains("domain admin")
                        || node.name.to_lowercase().contains("enterprise admin")
                        || node.name.to_lowercase().contains("administrators"))
            })
            .collect();

        if da_groups.is_empty() {
            return Vec::new();
        }

        let mut all_paths = Vec::new();
        for &da_group in &da_groups {
            let edge_paths = self
                .graph
                .shortest_paths_to(da_group, limit / da_groups.len().max(1));
            for edge_idx_list in &edge_paths {
                if edge_idx_list.is_empty() {
                    continue;
                }
                let src_node = edge_idx_list
                    .first()
                    .and_then(|eid| self.graph.graph().edge_endpoints(*eid))
                    .and_then(|(src, _)| self.graph.get_node(src))
                    .map(|n| format!("{}@{}", n.name, n.domain))
                    .unwrap_or_default();

                let tgt_name = self
                    .graph
                    .get_node(da_group)
                    .map(|n| format!("{}@{}", n.name, n.domain))
                    .unwrap_or_else(|| "DA".to_string());

                let mut hops = Vec::with_capacity(edge_idx_list.len());
                let mut total_cost = 0u32;

                for &eid in edge_idx_list {
                    if let Some((src, tgt)) = self.graph.graph().edge_endpoints(eid) {
                        let weight = self.graph.graph()[eid].clone();
                        let cost = weight.default_cost();
                        total_cost += cost;
                        let src_type = self.graph.graph()[src].node_type.clone();
                        let tgt_type = self.graph.graph()[tgt].node_type.clone();

                        use crate::graph::PathHop;
                        hops.push(PathHop {
                            source: self.graph.graph()[src].name.clone(),
                            source_type: src_type,
                            edge: weight,
                            target: self.graph.graph()[tgt].name.clone(),
                            target_type: tgt_type,
                            cost,
                        });
                    }
                }

                all_paths.push(AttackPath {
                    source: src_node,
                    target: tgt_name,
                    total_cost,
                    hop_count: hops.len(),
                    hops,
                });
            }
        }

        all_paths.sort_by_key(|p| p.total_cost);
        all_paths.truncate(limit);
        all_paths
    }

    // ═════════════════════════════════════════════════════════
    //  Comprehensive Analysis
    // ═════════════════════════════════════════════════════════

    /// Run all pre-built queries and produce a comprehensive report.
    pub fn analyze_all(&self, domain: &str) -> AnalysisReport {
        let stats = self.graph.stats();
        let kerberoastable = self.all_kerberoastable();
        let asrep = self.all_asrep_roastable();
        let unconstrained = self.all_unconstrained_delegation();
        let constrained = self.all_constrained_delegation();
        let da_sessions = self.all_da_sessions();
        let high_value_targets = self
            .graph
            .high_value_targets(20)
            .into_iter()
            .filter_map(|(name, _node_type, _degree)| {
                let (n, d) = name.split_once('@').unwrap_or((&name, ""));
                AnalysisNode::from_graph(n, d, self.graph)
            })
            .collect::<Vec<_>>();

        let cheapest_da_paths = self.cheapest_paths_to_da(domain, 25);

        // Generate findings
        let mut findings = Vec::new();

        if !kerberoastable.is_empty() {
            findings.push(AnalysisFinding {
                title: "Kerberoastable Users".into(),
                description: format!(
                    "{} users have Service Principal Names (SPNs) and are kerberoastable — TGS tickets can be requested and cracked offline",
                    kerberoastable.len()
                ),
                severity: FindingSeverity::High,
                affected_nodes: kerberoastable.clone(),
                remediation: Some("Ensure service accounts have complex, rotating passwords (120+ chars recommended); consider Group Managed Service Accounts (gMSA)".into()),
            });
        }

        if !asrep.is_empty() {
            findings.push(AnalysisFinding {
                title: "AS-REP Roastable Users".into(),
                description: format!(
                    "{} users have UF_DONT_REQUIRE_PREAUTH set — AS-REP responses can be requested and cracked offline without knowing the password",
                    asrep.len()
                ),
                severity: FindingSeverity::Critical,
                affected_nodes: asrep.clone(),
                remediation: Some("Enable Kerberos pre-authentication for all affected accounts; review why pre-auth was disabled".into()),
            });
        }

        if !unconstrained.is_empty() {
            findings.push(AnalysisFinding {
                title: "Unconstrained Delegation".into(),
                description: format!(
                    "{} computers have unconstrained delegation enabled — any user with admin access to these computers can steal TGTs for any principal",
                    unconstrained.len()
                ),
                severity: FindingSeverity::Critical,
                affected_nodes: unconstrained.clone(),
                remediation: Some("Replace unconstrained delegation with constrained delegation or resource-based constrained delegation (RBCD)".into()),
            });
        }

        if !constrained.is_empty() {
            findings.push(AnalysisFinding {
                title: "Constrained Delegation Targets".into(),
                description: format!(
                    "{} principals are targets of constrained delegation — compromised services can impersonate users to the delegated services",
                    constrained.len()
                ),
                severity: FindingSeverity::High,
                affected_nodes: constrained.clone(),
                remediation: Some("Review constrained delegation configurations; use protocol transition only when necessary; monitor for abuse".into()),
            });
        }

        if !da_sessions.is_empty() {
            findings.push(AnalysisFinding {
                title: "Domain Admin Sessions".into(),
                description: format!(
                    "{} computers have active Domain Admin sessions — DA token theft risk via LSASS dumping or Kerberos ticket extraction",
                    da_sessions.len()
                ),
                severity: FindingSeverity::Critical,
                affected_nodes: da_sessions.clone(),
                remediation: Some("Implement Protected Users group; restrict DA logons to dedicated admin workstations (PAW/DAW); enable Credential Guard".into()),
            });
        }

        if !cheapest_da_paths.is_empty() {
            let min_cost = cheapest_da_paths.first().map(|p| p.total_cost).unwrap_or(0);
            let avg_cost = cheapest_da_paths.iter().map(|p| p.total_cost).sum::<u32>() as f64
                / cheapest_da_paths.len() as f64;
            findings.push(AnalysisFinding {
                title: "Attack Paths to Domain Admin".into(),
                description: format!(
                    "{} distinct attack paths to DA found — cheapest cost: {}, average cost: {:.1}",
                    cheapest_da_paths.len(), min_cost, avg_cost
                ),
                severity: FindingSeverity::Critical,
                affected_nodes: cheapest_da_paths
                    .iter()
                    .filter_map(|p| AnalysisNode::from_graph(&p.source, "", self.graph))
                    .chain(
                        cheapest_da_paths
                            .iter()
                            .filter_map(|p| AnalysisNode::from_graph(&p.target, "", self.graph)),
                    )
                    .collect::<Vec<_>>(),
                remediation: Some("Review attack paths above and break the lowest-cost chains by removing unnecessary permissions, disabling unused accounts, and segmenting administrative access".into()),
            });
        }

        AnalysisReport {
            stats,
            kerberoastable_users: kerberoastable,
            asrep_roastable_users: asrep,
            unconstrained_delegation: unconstrained,
            constrained_delegation: constrained,
            da_sessions,
            cheapest_da_paths,
            high_value_targets,
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AdNode, AttackGraph, EdgeType, NodeType};

    fn build_test_graph() -> AttackGraph {
        let mut g = AttackGraph::new();
        g.metadata
            .insert("domain".to_string(), "corp.local".to_string());

        // Add users
        g.add_node(AdNode {
            name: "user1".into(),
            node_type: NodeType::User,
            domain: "corp.local".into(),
            distinguished_name: None,
            enabled: true,
            properties: HashMap::new(),
        });
        g.add_node(AdNode {
            name: "user_kerb".into(),
            node_type: NodeType::User,
            domain: "corp.local".into(),
            distinguished_name: None,
            enabled: true,
            properties: HashMap::new(),
        });
        g.add_node(AdNode {
            name: "user_asrep".into(),
            node_type: NodeType::User,
            domain: "corp.local".into(),
            distinguished_name: None,
            enabled: true,
            properties: {
                let mut m = HashMap::new();
                m.insert("dont_req_preauth".into(), "true".into());
                m
            },
        });

        // Add computers
        g.add_node(AdNode {
            name: "pc1".into(),
            node_type: NodeType::Computer,
            domain: "corp.local".into(),
            distinguished_name: None,
            enabled: true,
            properties: HashMap::new(),
        });
        g.add_node(AdNode {
            name: "dc1".into(),
            node_type: NodeType::Computer,
            domain: "corp.local".into(),
            distinguished_name: None,
            enabled: true,
            properties: {
                let mut m = HashMap::new();
                m.insert("unconstrained_delegation".into(), "true".into());
                m
            },
        });

        // Add groups
        g.add_node(AdNode {
            name: "Domain Admins".into(),
            node_type: NodeType::Group,
            domain: "corp.local".into(),
            distinguished_name: None,
            enabled: true,
            properties: HashMap::new(),
        });
        g.add_node(AdNode {
            name: "Domain Users".into(),
            node_type: NodeType::Group,
            domain: "corp.local".into(),
            distinguished_name: None,
            enabled: true,
            properties: HashMap::new(),
        });

        // Add edges
        g.add_edge_by_name(
            "user1",
            "corp.local",
            "Domain Users",
            "corp.local",
            EdgeType::MemberOf,
        );
        g.add_edge_by_name(
            "user_kerb",
            "corp.local",
            "pc1",
            "corp.local",
            EdgeType::HasSpn,
        );
        g.add_edge_by_name(
            "user1",
            "corp.local",
            "pc1",
            "corp.local",
            EdgeType::AdminTo,
        );
        g.add_edge_by_name("pc1", "corp.local", "dc1", "corp.local", EdgeType::AdminTo);
        g.add_edge_by_name(
            "dc1",
            "corp.local",
            "Domain Admins",
            "corp.local",
            EdgeType::MemberOf,
        );
        g.add_edge_by_name(
            "user1",
            "corp.local",
            "dc1",
            "corp.local",
            EdgeType::HasSession,
        );

        g
    }

    fn build_analysis_engine() -> GraphAnalysisEngine<'static> {
        // We build the graph on the heap to get a static lifetime for testing
        let g = Box::new(build_test_graph());
        let g_ref: &'static AttackGraph = Box::leak(g);
        GraphAnalysisEngine::new(g_ref)
    }

    #[test]
    fn test_all_kerberoastable() {
        let engine = build_analysis_engine();
        let users = engine.all_kerberoastable();
        // user_kerb has a HasSpn edge (to pc1), so should be found
        assert_eq!(
            users.len(),
            1,
            "Expected 1 kerberoastable user, got {}",
            users.len()
        );
        assert_eq!(users[0].name, "user_kerb");
    }

    #[test]
    fn test_all_asrep_roastable() {
        let engine = build_analysis_engine();
        let users = engine.all_asrep_roastable();
        assert_eq!(
            users.len(),
            1,
            "Expected 1 AS-REP roastable user, got {}",
            users.len()
        );
        assert_eq!(users[0].name, "user_asrep");
    }

    #[test]
    fn test_all_unconstrained_delegation() {
        let engine = build_analysis_engine();
        let nodes = engine.all_unconstrained_delegation();
        assert_eq!(
            nodes.len(),
            1,
            "Expected 1 unconstrained delegation node, got {}",
            nodes.len()
        );
        assert_eq!(nodes[0].name, "dc1");
    }

    #[test]
    fn test_all_constrained_delegation_empty() {
        let engine = build_analysis_engine();
        let nodes = engine.all_constrained_delegation();
        assert_eq!(
            nodes.len(),
            0,
            "Expected 0 constrained delegation nodes, got {}",
            nodes.len()
        );
    }

    #[test]
    fn test_all_da_sessions() {
        let engine = build_analysis_engine();
        let nodes = engine.all_da_sessions();
        // user1 has a session on dc1 but user1 is not a DA
        let da_computers: Vec<_> = nodes.iter().filter(|n| n.name == "dc1").collect();
        // user1 is not a Domain Admin yet (it's only in Domain Users)
        assert_eq!(
            da_computers.len(),
            0,
            "DC1 should not have DA sessions (user1 is not DA)"
        );
    }

    #[test]
    fn test_cheapest_paths_to_da() {
        let engine = build_analysis_engine();
        let paths = engine.cheapest_paths_to_da("corp.local", 5);
        // user1 -> pc1 -> dc1 -> Domain Admins (MemberOf/AdminTo have 0 cost)
        assert!(!paths.is_empty(), "Expected at least 1 path to DA");
        // Path should exist (cost >= 0 since MemberOf has default_cost = 0)
        assert!(paths[0].hop_count >= 1, "Path should have at least 1 hop");
    }

    #[test]
    fn test_analyze_all() {
        let engine = build_analysis_engine();
        let report = engine.analyze_all("corp.local");
        assert_eq!(report.kerberoastable_users.len(), 1);
        assert_eq!(report.asrep_roastable_users.len(), 1);
        assert_eq!(report.unconstrained_delegation.len(), 1);
        assert!(
            report.stats.total_nodes >= 6,
            "Should have at least 6 nodes"
        );
        assert!(!report.findings.is_empty(), "Should have findings");
        assert!(
            report.findings.iter().any(|f| f.title.contains("AS-REP")),
            "AS-REP finding should be present"
        );
    }

    #[test]
    fn test_analysis_node_serde_roundtrip() {
        let node = AnalysisNode {
            name: "test_user".into(),
            node_type: NodeType::User,
            domain: "corp.local".into(),
            distinguished_name: Some("CN=test_user,DC=corp,DC=local".into()),
            enabled: true,
            properties: {
                let mut m = HashMap::new();
                m.insert("spn".into(), "HTTP/svc".into());
                m
            },
        };
        let json = serde_json::to_string(&node).unwrap();
        let deserialized: AnalysisNode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test_user");
        assert_eq!(deserialized.node_type, NodeType::User);
        assert_eq!(deserialized.properties.get("spn").unwrap(), "HTTP/svc");
    }

    #[test]
    fn test_analysis_report_serde() {
        let engine = build_analysis_engine();
        let report = engine.analyze_all("corp.local");
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.len() > 100, "JSON output should be non-trivial");
        let deserialized: AnalysisReport = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.kerberoastable_users.len(),
            report.kerberoastable_users.len()
        );
    }
}
