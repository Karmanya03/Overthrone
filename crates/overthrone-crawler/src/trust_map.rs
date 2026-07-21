//! AD trust relationship mapping -- builds a directed graph of domain trusts
//! from reaper enumeration data.

use overthrone_reaper::trusts::{
    TrustDirection as ReaperDirection, TrustEntry, TrustType as ReaperType,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// -- Trust attribute constants --
pub const TRUST_ATTR_NON_TRANSITIVE: u32 = 0x0001;
pub const TRUST_ATTR_QUARANTINED: u32 = 0x0004;
pub const TRUST_ATTR_FOREST_TRANSITIVE: u32 = 0x0008;
pub const TRUST_ATTR_WITHIN_FOREST: u32 = 0x0020;
pub const TRUST_ATTR_TREAT_AS_EXTERNAL: u32 = 0x0040;
pub const TRUST_ATTR_USES_RC4: u32 = 0x0080;
pub const TRUST_ATTR_USES_AES: u32 = 0x0100;
pub const TRUST_ATTR_CROSS_ORG_NO_TGT: u32 = 0x0200;
pub const TRUST_ATTR_PIM_TRUST: u32 = 0x0400;
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainNode {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub netbios_name: Option<String>,
    /// Domain FQDN
    pub domain_sid: Option<String>,
    /// Object or account name.
    pub forest_name: Option<String>,
    /// Active Directory functional level.
    pub functional_level: Option<String>,
    /// Domain FQDN
    pub is_root_domain: bool,
    /// enumerated field
    pub enumerated: bool,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    /// Source domain FQDN
    pub source_domain: String,
    /// Target domain FQDN
    pub target_domain: String,
    /// direction field
    pub direction: TrustDirection,
    /// Classification for this object.
    pub trust_type: TrustKind,
    /// transitive field
    pub transitive: bool,
    /// Security Identifier
    pub sid_filtering: bool,
    /// tgt delegation field
    pub tgt_delegation: bool,
    /// is within forest field
    pub is_within_forest: bool,
    /// uses aes field
    pub uses_aes: bool,
    /// uses rc4 field
    pub uses_rc4: bool,
    /// is pam trust field
    pub is_pam_trust: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustDirection {
    /// `Inbound` variant
    Inbound,
    /// `Outbound` variant
    Outbound,
    /// `Bidirectional` variant
    Bidirectional,
    /// `Unknown` variant
    Unknown(u32),
}

impl TrustDirection {
    pub fn allows_outbound(&self) -> bool {
        matches!(self, Self::Outbound | Self::Bidirectional)
    }

    pub fn allows_inbound(&self) -> bool {
        matches!(self, Self::Inbound | Self::Bidirectional)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustKind {
    /// `ParentChild` variant
    ParentChild,
    /// `External` variant
    External,
    /// `Forest` variant
    Forest,
    /// `CrossLink` variant
    CrossLink,
    /// `Mit` variant
    Mit,
    /// `Unknown` variant
    Unknown(u32),
}

impl TrustEdge {
    /// Convert from reaper's TrustEntry
    fn from_reaper(source_domain: &str, entry: &TrustEntry) -> Self {
        let src = if source_domain.is_empty() {
            warn!("[trust_map] Empty source_domain in TrustEdge::from_reaper");
            String::new()
        } else {
            source_domain.to_uppercase()
        };
        let tgt = if entry.target_domain.is_empty() {
            warn!("[trust_map] Empty target_domain in TrustEdge::from_reaper");
            String::new()
        } else {
            entry.target_domain.to_uppercase()
        };
        let direction = match &entry.direction {
            ReaperDirection::Inbound => TrustDirection::Inbound,
            ReaperDirection::Outbound => TrustDirection::Outbound,
            ReaperDirection::Bidirectional => TrustDirection::Bidirectional,
            ReaperDirection::Unknown(v) => TrustDirection::Unknown(*v),
        };

        let trust_type = match &entry.trust_type {
            ReaperType::ParentChild => TrustKind::ParentChild,
            ReaperType::External => TrustKind::External,
            ReaperType::Forest => TrustKind::Forest,
            ReaperType::CrossLink => TrustKind::CrossLink,
            ReaperType::Unknown(v) => TrustKind::Unknown(*v),
        };

        let is_within_forest = trust_type == TrustKind::ParentChild;

        TrustEdge {
            source_domain: src,
            target_domain: tgt,
            direction,
            trust_type,
            transitive: entry.transitive,
            sid_filtering: entry.sid_filtering_enabled,
            tgt_delegation: entry.tgt_delegation_enabled,
            is_within_forest,
            // Default assumptions -- refined when raw attrs are available
            uses_aes: true,
            uses_rc4: !entry.tgt_delegation_enabled, // heuristic
            is_pam_trust: false,
        }
    }

    pub fn is_exploitable(&self) -> bool {
        self.direction.allows_outbound() && self.transitive && !self.sid_filtering
    }

    pub fn risk_level(&self) -> &'static str {
        if self.is_pam_trust {
            "CRITICAL"
        } else if !self.sid_filtering && self.direction.allows_outbound() {
            if !self.is_within_forest {
                "CRITICAL"
            } else {
                "HIGH"
            }
        } else if self.direction.allows_outbound() && self.transitive {
            "MEDIUM"
        } else {
            "LOW"
        }
    }
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGraph {
    /// Domain FQDN
    pub domains: Vec<DomainNode>,
    /// trusts field
    pub trusts: Vec<TrustEdge>,
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustGraph {
    /// Runs this module operation.
    pub fn new() -> Self {
        TrustGraph {
            domains: Vec::new(),
            trusts: Vec::new(),
        }
    }

    pub fn add_domain(&mut self, node: DomainNode) {
        if node.name.is_empty() {
            warn!("[trust_map] Attempted to add domain with empty name -- skipping");
            return;
        }
        let upper = node.name.to_uppercase();
        if !self.domains.iter().any(|d| d.name.to_uppercase() == upper) {
            self.domains.push(node);
        }
    }

    pub fn add_trust(&mut self, edge: TrustEdge) {
        if edge.source_domain.is_empty() || edge.target_domain.is_empty() {
            warn!(
                "[trust_map] Attempted to add trust with empty source/target domain -- skipping (src='{}', tgt='{}')",
                edge.source_domain, edge.target_domain
            );
            return;
        }
        let exists = self.trusts.iter().any(|t| {
            t.source_domain == edge.source_domain && t.target_domain == edge.target_domain
        });
        if !exists {
            self.trusts.push(edge);
        }
    }

    /// BFS: find all domains reachable via outbound transitive trusts
    pub fn reachable_from(&self, domain: &str) -> Vec<String> {
        if domain.is_empty() {
            warn!("[trust_map] Empty domain passed to reachable_from");
            return vec![String::new()];
        }
        let start = domain.to_uppercase();
        if !self.domains.iter().any(|d| d.name.to_uppercase() == start)
            && !self
                .trusts
                .iter()
                .any(|t| t.source_domain == start || t.target_domain == start)
        {
            debug!(
                "[trust_map] Domain '{}' not found in graph -- returning self-only",
                domain
            );
        }
        let mut visited = vec![start.clone()];
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start);

        while let Some(current) = queue.pop_front() {
            for trust in &self.trusts {
                if trust.source_domain == current
                    && trust.direction.allows_outbound()
                    && trust.transitive
                    && !visited.contains(&trust.target_domain)
                {
                    visited.push(trust.target_domain.clone());
                    queue.push_back(trust.target_domain.clone());
                }
                // Bidirectional trusts: also traverse inbound edges
                if trust.target_domain == current
                    && trust.direction.allows_inbound()
                    && trust.transitive
                    && !visited.contains(&trust.source_domain)
                {
                    visited.push(trust.source_domain.clone());
                    queue.push_back(trust.source_domain.clone());
                }
            }
        }
        visited
    }

    /// All trusts where SID filtering is disabled (dangerous on external/forest trusts)
    pub fn unfiltered_trusts(&self) -> Vec<&TrustEdge> {
        self.trusts
            .iter()
            .filter(|t| !t.sid_filtering && t.direction.allows_outbound())
            .collect()
    }

    /// All PAM trusts
    pub fn pam_trusts(&self) -> Vec<&TrustEdge> {
        self.trusts.iter().filter(|t| t.is_pam_trust).collect()
    }

    /// Trusts that can be used for outbound lateral movement
    pub fn outbound_trusts_from(&self, domain: &str) -> Vec<&TrustEdge> {
        let upper = domain.to_uppercase();
        self.trusts
            .iter()
            .filter(|t| t.source_domain == upper && t.direction.allows_outbound())
            .collect()
    }

    /// Find a specific trust edge between two domains
    pub fn find_trust(&self, source: &str, target: &str) -> Option<&TrustEdge> {
        let src = source.to_uppercase();
        let tgt = target.to_uppercase();
        self.trusts
            .iter()
            .find(|t| t.source_domain == src && t.target_domain == tgt)
    }

    /// Get domain node by name
    pub fn get_domain(&self, name: &str) -> Option<&DomainNode> {
        let upper = name.to_uppercase();
        self.domains.iter().find(|d| d.name.to_uppercase() == upper)
    }

    /// Print textual trust map
    pub fn print_map(&self) {
        for domain in &self.domains {
            let outbound: Vec<_> = self
                .trusts
                .iter()
                .filter(|t| t.source_domain == domain.name.to_uppercase())
                .collect();

            let tag = if domain.enumerated {
                "enumerated"
            } else {
                "discovered"
            };
            println!("  {} ({})", domain.name, tag);

            for t in outbound {
                let arrow = match &t.direction {
                    TrustDirection::Bidirectional => "<-->",
                    TrustDirection::Outbound => "--->",
                    TrustDirection::Inbound => "<---",
                    TrustDirection::Unknown(_) => "???",
                };
                let mut flags = Vec::new();
                if t.sid_filtering {
                    flags.push("SID-filtered");
                } else {
                    flags.push("NO-filter");
                }
                if !t.transitive {
                    flags.push("non-transitive");
                }
                if t.is_pam_trust {
                    flags.push("PAM");
                }
                let flag_str = format!("[{}]", flags.join("]["));
                println!(
                    "    {} {} {} ({})",
                    arrow,
                    t.target_domain,
                    flag_str,
                    t.risk_level()
                );
            }
        }
    }
}

/// Build the trust graph from reaper's trust enumeration data.
pub fn build_trust_graph(source_domain: &str, trust_entries: &[TrustEntry]) -> TrustGraph {
    let mut graph = TrustGraph::new();

    info!(
        "[trust_map] Building trust graph from {} trust entries",
        trust_entries.len()
    );

    if trust_entries.is_empty() {
        debug!("[trust_map] No trust entries provided -- graph will contain only the source domain");
    }

    if source_domain.is_empty() {
        warn!("[trust_map] Empty source_domain -- graph will have no source node");
    }

    // Add the source domain as a node
    graph.add_domain(DomainNode {
        name: source_domain.to_uppercase(),
        netbios_name: None,
        domain_sid: None,
        forest_name: None,
        functional_level: None,
        is_root_domain: true, // assume until proven otherwise
        enumerated: true,
    });

    // Convert each reaper TrustEntry into a crawler TrustEdge
    for entry in trust_entries {
        // Add the target domain as a node
        graph.add_domain(DomainNode {
            name: entry.target_domain.to_uppercase(),
            netbios_name: None,
            domain_sid: None,
            forest_name: None,
            functional_level: None,
            is_root_domain: false,
            enumerated: false,
        });

        // Create the trust edge
        let edge = TrustEdge::from_reaper(source_domain, entry);
        debug!(
            "[trust_map] {} --{:?}--> {} [filter={}, transitive={}]",
            edge.source_domain,
            edge.direction,
            edge.target_domain,
            edge.sid_filtering,
            edge.transitive
        );
        graph.add_trust(edge);

        // If bidirectional, also add the reverse edge
        if matches!(entry.direction, ReaperDirection::Bidirectional) {
            let reverse = TrustEdge {
                source_domain: entry.target_domain.to_uppercase(),
                target_domain: source_domain.to_uppercase(),
                direction: TrustDirection::Bidirectional,
                trust_type: match &entry.trust_type {
                    ReaperType::ParentChild => TrustKind::ParentChild,
                    ReaperType::External => TrustKind::External,
                    ReaperType::Forest => TrustKind::Forest,
                    ReaperType::CrossLink => TrustKind::CrossLink,
                    ReaperType::Unknown(v) => TrustKind::Unknown(*v),
                },
                transitive: entry.transitive,
                sid_filtering: entry.sid_filtering_enabled,
                tgt_delegation: entry.tgt_delegation_enabled,
                is_within_forest: matches!(entry.trust_type, ReaperType::ParentChild),
                uses_aes: true,
                uses_rc4: false,
                is_pam_trust: false,
            };
            graph.add_trust(reverse);
        }
    }

    // Detect if source domain is NOT root (if it has a parent-child trust where it's the child)
    let _has_parent = graph.trusts.iter().any(|t| {
        t.source_domain == source_domain.to_uppercase()
            && t.trust_type == TrustKind::ParentChild
            && t.direction.allows_outbound()
    });
    // If it has a parent-child outbound trust, it might be a child domain
    // (root domains have parent-child trusts inbound from children)

    let reachable = graph.reachable_from(source_domain);
    info!(
        "[trust_map] {} domains reachable from {}",
        reachable.len(),
        source_domain
    );

    graph
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_constants() {
        assert_eq!(TRUST_ATTR_NON_TRANSITIVE, 0x0001);
        assert_eq!(TRUST_ATTR_QUARANTINED, 0x0004);
        assert_eq!(TRUST_ATTR_FOREST_TRANSITIVE, 0x0008);
        assert_eq!(TRUST_ATTR_WITHIN_FOREST, 0x0020);
        assert_eq!(TRUST_ATTR_TREAT_AS_EXTERNAL, 0x0040);
        assert_eq!(TRUST_ATTR_USES_RC4, 0x0080);
        assert_eq!(TRUST_ATTR_USES_AES, 0x0100);
        assert_eq!(TRUST_ATTR_CROSS_ORG_NO_TGT, 0x0200);
        assert_eq!(TRUST_ATTR_PIM_TRUST, 0x0400);
    }

    #[test]
    fn test_trust_direction_allows_outbound() {
        assert!(TrustDirection::Outbound.allows_outbound());
        assert!(TrustDirection::Bidirectional.allows_outbound());
        assert!(!TrustDirection::Inbound.allows_outbound());
        assert!(!TrustDirection::Unknown(0).allows_outbound());
    }

    #[test]
    fn test_trust_direction_allows_inbound() {
        assert!(TrustDirection::Inbound.allows_inbound());
        assert!(TrustDirection::Bidirectional.allows_inbound());
        assert!(!TrustDirection::Outbound.allows_inbound());
        assert!(!TrustDirection::Unknown(0).allows_inbound());
    }

    #[test]
    fn test_trust_edge_exploitable_critical() {
        let edge = TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Bidirectional,
            trust_type: TrustKind::External,
            transitive: true,
            sid_filtering: false,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        };
        assert!(edge.is_exploitable());
        assert_eq!(edge.risk_level(), "CRITICAL");
    }

    #[test]
    fn test_trust_edge_not_exploitable() {
        let edge = TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Bidirectional,
            trust_type: TrustKind::External,
            transitive: true,
            sid_filtering: true,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        };
        assert!(!edge.is_exploitable());
    }

    #[test]
    fn test_trust_edge_pam_risk() {
        let edge = TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Bidirectional,
            trust_type: TrustKind::Forest,
            transitive: true,
            sid_filtering: true,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: true,
        };
        assert_eq!(edge.risk_level(), "CRITICAL");
    }

    #[test]
    fn test_trust_graph_new_empty() {
        let g = TrustGraph::new();
        assert!(g.domains.is_empty());
        assert!(g.trusts.is_empty());
    }

    #[test]
    fn test_trust_graph_add_domain() {
        let mut g = TrustGraph::new();
        g.add_domain(DomainNode {
            name: "CORP".into(),
            netbios_name: None,
            domain_sid: None,
            forest_name: None,
            functional_level: None,
            is_root_domain: true,
            enumerated: true,
        });
        assert_eq!(g.domains.len(), 1);
        g.add_domain(DomainNode {
            name: "corp".into(),
            netbios_name: None,
            domain_sid: None,
            forest_name: None,
            functional_level: None,
            is_root_domain: false,
            enumerated: false,
        });
        assert_eq!(g.domains.len(), 1); // duplicate (case-insensitive)
    }

    #[test]
    fn test_trust_graph_add_trust_dedup() {
        let mut g = TrustGraph::new();
        let edge = TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Outbound,
            trust_type: TrustKind::External,
            transitive: true,
            sid_filtering: false,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        };
        g.add_trust(edge);
        let edge2 = TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Outbound,
            trust_type: TrustKind::External,
            transitive: true,
            sid_filtering: false,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        };
        g.add_trust(edge2);
        assert_eq!(g.trusts.len(), 1);
    }

    #[test]
    fn test_reachable_from() {
        let mut g = TrustGraph::new();
        g.add_trust(TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Outbound,
            trust_type: TrustKind::Forest,
            transitive: true,
            sid_filtering: true,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        });
        g.add_trust(TrustEdge {
            source_domain: "B".into(),
            target_domain: "C".into(),
            direction: TrustDirection::Outbound,
            trust_type: TrustKind::Forest,
            transitive: true,
            sid_filtering: true,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        });
        let reachable = g.reachable_from("A");
        assert!(reachable.contains(&"A".to_string()));
        assert!(reachable.contains(&"B".to_string()));
        assert!(reachable.contains(&"C".to_string()));
    }

    #[test]
    fn test_unfiltered_trusts() {
        let mut g = TrustGraph::new();
        g.add_trust(TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Outbound,
            trust_type: TrustKind::External,
            transitive: true,
            sid_filtering: false,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        });
        g.add_trust(TrustEdge {
            source_domain: "A".into(),
            target_domain: "C".into(),
            direction: TrustDirection::Outbound,
            trust_type: TrustKind::External,
            transitive: true,
            sid_filtering: true,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        });
        assert_eq!(g.unfiltered_trusts().len(), 1);
    }

    #[test]
    fn test_find_trust() {
        let mut g = TrustGraph::new();
        g.add_trust(TrustEdge {
            source_domain: "A".into(),
            target_domain: "B".into(),
            direction: TrustDirection::Outbound,
            trust_type: TrustKind::Forest,
            transitive: true,
            sid_filtering: true,
            tgt_delegation: false,
            is_within_forest: false,
            uses_aes: true,
            uses_rc4: false,
            is_pam_trust: false,
        });
        assert!(g.find_trust("A", "B").is_some());
        assert!(g.find_trust("A", "C").is_none());
    }

    #[test]
    fn test_get_domain() {
        let mut g = TrustGraph::new();
        g.add_domain(DomainNode {
            name: "CORP.LOCAL".into(),
            netbios_name: None,
            domain_sid: None,
            forest_name: None,
            functional_level: None,
            is_root_domain: true,
            enumerated: true,
        });
        assert!(g.get_domain("corp.local").is_some());
        assert!(g.get_domain("other.com").is_none());
    }
}
