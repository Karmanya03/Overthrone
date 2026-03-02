//! AD trust relationship mapping — builds a directed graph of domain trusts
//! from reaper enumeration data.

use overthrone_reaper::trusts::{TrustEntry, TrustDirection as ReaperDirection, TrustType as ReaperType};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

// ── Trust attribute constants ──
pub const TRUST_ATTR_NON_TRANSITIVE: u32 = 0x0001;
pub const TRUST_ATTR_QUARANTINED: u32 = 0x0004;
pub const TRUST_ATTR_FOREST_TRANSITIVE: u32 = 0x0008;
pub const TRUST_ATTR_WITHIN_FOREST: u32 = 0x0020;
pub const TRUST_ATTR_TREAT_AS_EXTERNAL: u32 = 0x0040;
pub const TRUST_ATTR_USES_RC4: u32 = 0x0080;
pub const TRUST_ATTR_USES_AES: u32 = 0x0100;
pub const TRUST_ATTR_CROSS_ORG_NO_TGT: u32 = 0x0200;
pub const TRUST_ATTR_PIM_TRUST: u32 = 0x0400;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainNode {
    pub name: String,
    pub netbios_name: Option<String>,
    pub domain_sid: Option<String>,
    pub forest_name: Option<String>,
    pub functional_level: Option<String>,
    pub is_root_domain: bool,
    pub enumerated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    pub source_domain: String,
    pub target_domain: String,
    pub direction: TrustDirection,
    pub trust_type: TrustKind,
    pub transitive: bool,
    pub sid_filtering: bool,
    pub tgt_delegation: bool,
    pub is_within_forest: bool,
    pub uses_aes: bool,
    pub uses_rc4: bool,
    pub is_pam_trust: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustDirection {
    Inbound,
    Outbound,
    Bidirectional,
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
    ParentChild,
    External,
    Forest,
    CrossLink,
    Mit,
    Unknown(u32),
}

impl TrustEdge {
    /// Convert from reaper's TrustEntry
    fn from_reaper(source_domain: &str, entry: &TrustEntry) -> Self {
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
            source_domain: source_domain.to_uppercase(),
            target_domain: entry.target_domain.to_uppercase(),
            direction,
            trust_type,
            transitive: entry.transitive,
            sid_filtering: entry.sid_filtering_enabled,
            tgt_delegation: entry.tgt_delegation_enabled,
            is_within_forest,
            // Default assumptions — refined when raw attrs are available
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
            if !self.is_within_forest { "CRITICAL" } else { "HIGH" }
        } else if self.direction.allows_outbound() && self.transitive {
            "MEDIUM"
        } else {
            "LOW"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGraph {
    pub domains: Vec<DomainNode>,
    pub trusts: Vec<TrustEdge>,
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustGraph {
    pub fn new() -> Self {
        TrustGraph { domains: Vec::new(), trusts: Vec::new() }
    }

    pub fn add_domain(&mut self, node: DomainNode) {
        let upper = node.name.to_uppercase();
        if !self.domains.iter().any(|d| d.name.to_uppercase() == upper) {
            self.domains.push(node);
        }
    }

    pub fn add_trust(&mut self, edge: TrustEdge) {
        let exists = self.trusts.iter().any(|t| {
            t.source_domain == edge.source_domain && t.target_domain == edge.target_domain
        });
        if !exists {
            self.trusts.push(edge);
        }
    }

    /// BFS: find all domains reachable via outbound transitive trusts
    pub fn reachable_from(&self, domain: &str) -> Vec<String> {
        let start = domain.to_uppercase();
        let mut visited = vec![start.clone()];
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start);

        while let Some(current) = queue.pop_front() {
            for trust in &self.trusts {
                if trust.source_domain == current
                    && trust.direction.allows_outbound()
                    && trust.transitive
                    && !visited.contains(&trust.target_domain) {
                        visited.push(trust.target_domain.clone());
                        queue.push_back(trust.target_domain.clone());
                    }
                // Bidirectional trusts: also traverse inbound edges
                if trust.target_domain == current
                    && trust.direction.allows_inbound()
                    && trust.transitive
                    && !visited.contains(&trust.source_domain) {
                        visited.push(trust.source_domain.clone());
                        queue.push_back(trust.source_domain.clone());
                    }
            }
        }
        visited
    }

    /// All trusts where SID filtering is disabled (dangerous on external/forest trusts)
    pub fn unfiltered_trusts(&self) -> Vec<&TrustEdge> {
        self.trusts.iter()
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
        self.trusts.iter()
            .filter(|t| t.source_domain == upper && t.direction.allows_outbound())
            .collect()
    }

    /// Find a specific trust edge between two domains
    pub fn find_trust(&self, source: &str, target: &str) -> Option<&TrustEdge> {
        let src = source.to_uppercase();
        let tgt = target.to_uppercase();
        self.trusts.iter().find(|t| t.source_domain == src && t.target_domain == tgt)
    }

    /// Get domain node by name
    pub fn get_domain(&self, name: &str) -> Option<&DomainNode> {
        let upper = name.to_uppercase();
        self.domains.iter().find(|d| d.name.to_uppercase() == upper)
    }

    /// Print textual trust map
    pub fn print_map(&self) {
        for domain in &self.domains {
            let outbound: Vec<_> = self.trusts.iter()
                .filter(|t| t.source_domain == domain.name.to_uppercase())
                .collect();

            let tag = if domain.enumerated { "enumerated" } else { "discovered" };
            println!("  {} ({})", domain.name, tag);

            for t in outbound {
                let arrow = match &t.direction {
                    TrustDirection::Bidirectional => "<-->",
                    TrustDirection::Outbound => "--->",
                    TrustDirection::Inbound => "<---",
                    TrustDirection::Unknown(_) => "???",
                };
                let mut flags = Vec::new();
                if t.sid_filtering { flags.push("SID-filtered"); }
                else { flags.push("NO-filter"); }
                if !t.transitive { flags.push("non-transitive"); }
                if t.is_pam_trust { flags.push("PAM"); }
                let flag_str = format!("[{}]", flags.join("]["));
                println!("    {} {} {} ({})", arrow, t.target_domain, flag_str, t.risk_level());
            }
        }
    }
}

/// Build the trust graph from reaper's trust enumeration data.
pub fn build_trust_graph(source_domain: &str, trust_entries: &[TrustEntry]) -> TrustGraph {
    let mut graph = TrustGraph::new();

    info!("[trust_map] Building trust graph from {} trust entries", trust_entries.len());

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
        debug!("[trust_map] {} --{:?}--> {} [filter={}, transitive={}]",
            edge.source_domain, edge.direction, edge.target_domain,
            edge.sid_filtering, edge.transitive
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
    let has_parent = graph.trusts.iter().any(|t| {
        t.source_domain == source_domain.to_uppercase()
            && t.trust_type == TrustKind::ParentChild
            && t.direction.allows_outbound()
    });
    // If it has a parent-child outbound trust, it might be a child domain
    // (root domains have parent-child trusts inbound from children)

    let reachable = graph.reachable_from(source_domain);
    info!("[trust_map] {} domains reachable from {}",
        reachable.len(), source_domain
    );

    graph
}
