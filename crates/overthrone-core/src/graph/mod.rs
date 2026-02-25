//! Attack path graph engine for Active Directory environments.
//!
//! Models AD objects (users, computers, groups, domains) as nodes and
//! relationships (MemberOf, AdminTo, HasSession, etc.) as directed edges.
//! Computes shortest attack paths using Dijkstra/BFS, similar to BloodHound.
//!
//! Uses the `petgraph` crate for the underlying graph data structure.
use crate::error::{OverthroneError, Result};
use crate::proto::ldap::{AdComputer, AdGroup, AdTrust, AdUser, DomainEnumeration, TrustDirection};
use petgraph::Direction;
use petgraph::algo::dijkstra;
use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use tracing::{debug, info, warn};
// use hashbrown::HashMap as HashBrownMap;

// ═══════════════════════════════════════════════════════════
//  Type Aliases
// ═══════════════════════════════════════════════════════════

/// Node identifier in the attack graph
pub type NodeId = NodeIndex;

/// Edge identifier in the attack graph
pub type EdgeId = EdgeIndex;

// Re-export EdgeRef trait for use in TUI and other modules
pub use petgraph::visit::EdgeRef;

// ═══════════════════════════════════════════════════════════
//  Node & Edge Types
// ═══════════════════════════════════════════════════════════

/// Type of an AD object in the graph
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    User,
    Computer,
    Group,
    Domain,
    Gpo,
    Ou,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "User"),
            Self::Computer => write!(f, "Computer"),
            Self::Group => write!(f, "Group"),
            Self::Domain => write!(f, "Domain"),
            Self::Gpo => write!(f, "GPO"),
            Self::Ou => write!(f, "OU"),
        }
    }
}

/// An AD object node in the attack graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdNode {
    pub name: String,
    pub node_type: NodeType,
    pub domain: String,
    pub distinguished_name: Option<String>,
    pub enabled: bool,
    /// Custom properties (UAC flags, SPNs, OS, etc.)
    pub properties: HashMap<String, String>,
}

impl std::fmt::Display for AdNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.node_type, self.name)
    }
}

/// Relationship (edge) types modeled after BloodHound
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeType {
    // ── Group Membership ──
    MemberOf,

    // ── Local Admin / Sessions ──
    AdminTo,
    HasSession,
    CanRDP,
    CanPSRemote,
    ExecuteDCOM,
    SQLAdmin,

    // ── ACL-Based ──
    GenericAll,
    GenericWrite,
    WriteOwner,
    WriteDacl,
    ForceChangePassword,
    AddMembers,
    AddSelf,
    ReadLapsPassword,
    ReadGmsaPassword,

    // ── Kerberos Delegation ──
    AllowedToDelegate,
    AllowedToAct,
    HasSidHistory,

    // ── DCSync / Replication ──
    DcSync,
    GetChanges,
    GetChangesAll,

    // ── Domain Trust ──
    TrustedBy,

    // ── Kerberoasting / AS-REP ──
    HasSpn,
    DontReqPreauth,

    // ── GPO ──
    GpoLink,
    Contains,

    // ── Generic ──
    Owns,
    Custom(String),
}

impl EdgeType {
    /// Whether this edge type represents a traversable attack path.
    /// Marker edges (HasSpn, DontReqPreauth) are not traversable - they
    /// indicate properties, not exploitable relationships.
    pub fn is_traversable(&self) -> bool {
        match self {
            // Marker edges - not traversable
            Self::HasSpn => false,
            Self::DontReqPreauth => false,
            // All other edges are traversable
            _ => true,
        }
    }

    /// Default "cost" for this edge type when computing shortest paths.
    /// Lower cost = more desirable / easier to exploit.
    pub fn default_cost(&self) -> u32 {
        match self {
            // Free traversals (no exploit required)
            Self::MemberOf => 0,
            Self::HasSidHistory => 0,
            Self::Contains => 0,

            // Very easy / direct compromise
            Self::AdminTo => 1,
            Self::DcSync => 1,
            Self::GenericAll => 1,
            Self::ForceChangePassword => 1,
            Self::Owns => 1,
            Self::WriteDacl => 1,
            Self::WriteOwner => 1,
            Self::AllowedToDelegate => 1,
            Self::AllowedToAct => 1,

            // Moderate effort
            Self::HasSession => 2,
            Self::GenericWrite => 2,
            Self::AddMembers => 2,
            Self::AddSelf => 2,
            Self::ReadLapsPassword => 2,
            Self::ReadGmsaPassword => 2,
            Self::GetChanges => 2,
            Self::GetChangesAll => 2,

            // Requires additional steps
            Self::CanRDP => 3,
            Self::CanPSRemote => 3,
            Self::ExecuteDCOM => 3,
            Self::SQLAdmin => 3,
            Self::GpoLink => 3,

            // Offline cracking required
            Self::HasSpn => 5,
            Self::DontReqPreauth => 5,

            // Cross-domain
            Self::TrustedBy => 4,

            Self::Custom(_) => 10,
        }
    }
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Attack Path Results
// ═══════════════════════════════════════════════════════════

/// A single hop in an attack path
#[derive(Debug, Clone, Serialize)]
pub struct PathHop {
    pub source: String,
    pub source_type: NodeType,
    pub edge: EdgeType,
    pub target: String,
    pub target_type: NodeType,
    pub cost: u32,
}

/// A complete attack path from source to target
#[derive(Debug, Clone, Serialize)]
pub struct AttackPath {
    pub source: String,
    pub target: String,
    pub total_cost: u32,
    pub hop_count: usize,
    pub hops: Vec<PathHop>,
}

impl std::fmt::Display for AttackPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Attack Path: {} → {} (cost: {}, hops: {})",
            self.source, self.target, self.total_cost, self.hop_count
        )?;
        for (i, hop) in self.hops.iter().enumerate() {
            writeln!(
                f,
                "  [{}] {} --[{}]--> {}",
                i + 1,
                hop.source,
                hop.edge,
                hop.target
            )?;
        }
        Ok(())
    }
}

/// Statistics about the attack graph
#[derive(Debug, Clone, Serialize)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub users: usize,
    pub computers: usize,
    pub groups: usize,
    pub domains: usize,
    pub edge_type_counts: HashMap<String, usize>,
}

// ═══════════════════════════════════════════════════════════
//  Attack Graph
// ═══════════════════════════════════════════════════════════

/// The core attack path graph engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraph {
    graph: DiGraph<AdNode, EdgeType>,
    /// Maps "NAME@DOMAIN" (uppercase) → NodeIndex for fast lookup
    node_index: HashMap<String, NodeIndex>,
    /// Maps DN (uppercase) → NodeIndex for DN-based edge resolution
    dn_index: HashMap<String, NodeIndex>,
    /// Domain/config metadata (lockout thresholds, password policies, etc.)
    metadata: HashMap<String, String>,
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGraph {
    pub fn new() -> Self {
        AttackGraph {
            graph: DiGraph::new(),
            node_index: HashMap::new(),
            dn_index: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Load an AttackGraph from a JSON file.
    pub fn from_json_file(path: &str) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            OverthroneError::Graph(format!("Failed to open graph file {path}: {e}"))
        })?;
        let reader = std::io::BufReader::new(file);
        let graph: Self = serde_json::from_reader(reader)
            .map_err(|e| OverthroneError::Graph(format!("Failed to parse graph JSON: {e}")))?;
        Ok(graph)
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    // ── Node Management ──────────────────────────────────

    /// Add a node. Returns existing index if already present.
    pub fn add_node(&mut self, node: AdNode) -> NodeIndex {
        let key = node_key(&node.name, &node.domain);

        if let Some(&idx) = self.node_index.get(&key) {
            return idx;
        }

        let dn = node.distinguished_name.clone();
        let idx = self.graph.add_node(node);
        self.node_index.insert(key, idx);

        if let Some(dn) = dn {
            self.dn_index.insert(dn.to_uppercase(), idx);
        }
        idx
    }

    /// Add edge between two nodes by name@domain keys
    pub fn add_edge_by_name(
        &mut self,
        source_name: &str,
        source_domain: &str,
        target_name: &str,
        target_domain: &str,
        edge_type: EdgeType,
    ) -> bool {
        let src_key = node_key(source_name, source_domain);
        let tgt_key = node_key(target_name, target_domain);

        if let (Some(&src), Some(&tgt)) =
            (self.node_index.get(&src_key), self.node_index.get(&tgt_key))
        {
            self.graph.add_edge(src, tgt, edge_type);
            true
        } else {
            false
        }
    }

    /// Add edge between two nodes using Distinguished Names
    pub fn add_edge_by_dn(
        &mut self,
        source_dn: &str,
        target_dn: &str,
        edge_type: EdgeType,
    ) -> bool {
        let src_key = source_dn.to_uppercase();
        let tgt_key = target_dn.to_uppercase();

        if let (Some(&src), Some(&tgt)) = (self.dn_index.get(&src_key), self.dn_index.get(&tgt_key))
        {
            self.graph.add_edge(src, tgt, edge_type);
            true
        } else {
            false
        }
    }

    /// Resolve a node by name (case-insensitive, tries key then DN then prefix)
    pub fn find_node(&self, name: &str) -> Option<NodeIndex> {
        let upper = name.to_uppercase();

        if let Some(&idx) = self.node_index.get(&upper) {
            return Some(idx);
        }
        if let Some(&idx) = self.dn_index.get(&upper) {
            return Some(idx);
        }

        // Fuzzy prefix match
        self.node_index
            .iter()
            .find(|(k, _idx): &(&String, &NodeIndex)| k.starts_with(&upper))
            .map(|(_, &idx)| idx)
    }

    pub fn get_node(&self, idx: NodeIndex) -> Option<&AdNode> {
        self.graph.node_weight(idx)
    }

    // ── Ingest from LDAP Enumeration ─────────────────────

    /// Build the attack graph from a full domain enumeration.
    /// Primary entry point for populating the graph.
    pub fn ingest_enumeration(&mut self, data: &DomainEnumeration) {
        info!("Ingesting enumeration for domain: {}", data.domain);

        // 1. Domain node
        self.add_node(AdNode {
            name: data.domain.clone(),
            node_type: NodeType::Domain,
            domain: data.domain.clone(),
            distinguished_name: Some(data.base_dn.clone()),
            enabled: true,
            properties: HashMap::new(),
        });

        // 2. Users → 3. Computers → 4. Groups
        for user in &data.users {
            self.ingest_user(user, &data.domain);
        }
        for computer in &data.computers {
            self.ingest_computer(computer, &data.domain);
        }
        for group in &data.groups {
            self.ingest_group(group, &data.domain);
        }

        // 5. MemberOf edges
        self.resolve_memberships(&data.users, &data.groups, &data.domain);

        // 6. Delegation edges
        self.resolve_delegation(&data.users, &data.computers, &data.domain);

        // 7. Trust edges
        for trust in &data.trusts {
            self.ingest_trust(trust, &data.domain);
        }

        // 8. Kerberoastable / AS-REP Roastable markers
        for user in &data.kerberoastable {
            self.add_edge_by_name(
                &user.sam_account_name,
                &data.domain,
                &data.domain,
                &data.domain,
                EdgeType::HasSpn,
            );
        }
        for user in &data.asrep_roastable {
            self.add_edge_by_name(
                &user.sam_account_name,
                &data.domain,
                &data.domain,
                &data.domain,
                EdgeType::DontReqPreauth,
            );
        }

        info!(
            "Graph: {} nodes, {} edges",
            self.node_count(),
            self.edge_count()
        );
    }

    fn ingest_user(&mut self, user: &AdUser, domain: &str) {
        let mut properties = HashMap::new();
        properties.insert("sam_account_name".into(), user.sam_account_name.clone());
        // ✅ REMOVED: user.sid (doesn't exist)
        // ✅ REMOVED: user.display_name (doesn't exist)
        if let Some(ref upn) = user.user_principal_name {
            properties.insert("upn".into(), upn.clone());
        }
        properties.insert("uac".into(), user.user_account_control.to_string());

        if let Some(ref desc) = user.description {
            properties.insert("description".into(), desc.clone());
        }
        if !user.service_principal_names.is_empty() {
            properties.insert("spns".into(), user.service_principal_names.join(";"));
        }
        if user.admin_count {
            properties.insert("admin_count".into(), "true".into());
        }
        if !user.allowed_to_delegate_to.is_empty() {
            properties.insert(
                "delegation_targets".into(),
                user.allowed_to_delegate_to.join(";"),
            );
        }
        if user.dont_req_preauth {
            properties.insert("dont_req_preauth".into(), "true".into());
        }

        self.add_node(AdNode {
            name: user.sam_account_name.clone(),
            node_type: NodeType::User,
            domain: domain.to_string(),
            distinguished_name: Some(user.distinguished_name.clone()),
            enabled: user.enabled,
            properties,
        });
        debug!("Ingested user: {}@{}", user.sam_account_name, domain);
    }

    fn ingest_computer(&mut self, computer: &AdComputer, domain: &str) {
        let mut properties = HashMap::new();
        properties.insert("sam_account_name".into(), computer.sam_account_name.clone());
        // ✅ REMOVED: computer.sid (doesn't exist)
        if let Some(ref hostname) = computer.dns_hostname {
            properties.insert("dns_hostname".into(), hostname.clone());
        }
        if let Some(ref os) = computer.operating_system {
            properties.insert("operating_system".into(), os.clone());
        }
        if let Some(ref ver) = computer.os_version {
            properties.insert("os_version".into(), ver.clone());
        }
        if computer.unconstrained_delegation {
            properties.insert("unconstrained_delegation".into(), "true".into());
        }
        if !computer.allowed_to_delegate_to.is_empty() {
            properties.insert(
                "delegation_targets".into(),
                computer.allowed_to_delegate_to.join(";"),
            );
        }
        properties.insert("uac".into(), computer.user_account_control.to_string());

        self.add_node(AdNode {
            name: computer.sam_account_name.clone(),
            node_type: NodeType::Computer,
            domain: domain.to_string(),
            distinguished_name: Some(computer.distinguished_name.clone()),
            // ✅ FIX: derive enabled from UAC (bit 0x2 = ACCOUNTDISABLE)
            enabled: (computer.user_account_control & 0x0002) == 0,
            properties,
        });
        debug!(
            "Ingested computer: {}@{}",
            computer.sam_account_name, domain
        );
    }

    fn ingest_group(&mut self, group: &AdGroup, domain: &str) {
        let mut properties = HashMap::new();
        properties.insert("sam_account_name".into(), group.sam_account_name.clone());
        // ✅ REMOVED: group.sid (doesn't exist)
        if let Some(ref desc) = group.description {
            properties.insert("description".into(), desc.clone());
        }
        if group.admin_count {
            properties.insert("admin_count".into(), "true".into());
        }
        properties.insert("member_count".into(), group.members.len().to_string());

        self.add_node(AdNode {
            name: group.sam_account_name.clone(),
            node_type: NodeType::Group,
            domain: domain.to_string(),
            distinguished_name: Some(group.distinguished_name.clone()),
            enabled: true,
            properties,
        });
        debug!("Ingested group: {}@{}", group.sam_account_name, domain);
    }

    fn ingest_trust(&mut self, trust: &AdTrust, source_domain: &str) {
        // ✅ FIX: trust_partner, not target_domain_name
        let target = &trust.trust_partner;

        let mut properties = HashMap::new();
        properties.insert("trust_direction".into(), trust.trust_direction.to_string());
        properties.insert("trust_type".into(), trust.trust_type.to_string());
        properties.insert(
            "trust_attributes".into(),
            trust.trust_attributes.to_string(),
        );
        if let Some(ref flat) = trust.flat_name {
            properties.insert("flat_name".into(), flat.clone());
        }

        // Ensure the foreign domain exists as a node
        self.add_node(AdNode {
            name: target.clone(),
            node_type: NodeType::Domain,
            domain: target.clone(),
            distinguished_name: None,
            enabled: true,
            properties,
        });

        // ✅ FIX: Match on TrustDirection enum, not integers
        match &trust.trust_direction {
            TrustDirection::Inbound => {
                // Inbound — the foreign domain trusts us (they → us)
                self.add_edge_by_name(
                    target,
                    target,
                    source_domain,
                    source_domain,
                    EdgeType::TrustedBy,
                );
            }
            TrustDirection::Outbound => {
                // Outbound — we trust them (us → they)
                self.add_edge_by_name(
                    source_domain,
                    source_domain,
                    target,
                    target,
                    EdgeType::TrustedBy,
                );
            }
            TrustDirection::Bidirectional => {
                self.add_edge_by_name(
                    target,
                    target,
                    source_domain,
                    source_domain,
                    EdgeType::TrustedBy,
                );
                self.add_edge_by_name(
                    source_domain,
                    source_domain,
                    target,
                    target,
                    EdgeType::TrustedBy,
                );
            }
            other => {
                warn!(
                    "Unhandled trust direction {:?} for domain {}",
                    other, target
                );
            }
        }

        debug!(
            "Ingested trust: {} → {} (direction={})",
            source_domain, target, trust.trust_direction
        );
    }

    fn resolve_memberships(&mut self, users: &[AdUser], groups: &[AdGroup], domain: &str) {
        let mut edge_count = 0usize;

        // User → Group (MemberOf) via user.member_of DNs
        for user in users {
            for group_dn in &user.member_of {
                if self.add_edge_by_dn(&user.distinguished_name, group_dn, EdgeType::MemberOf) {
                    edge_count += 1;
                } else {
                    // Fallback: try resolving by extracting CN from the DN
                    if let Some(cn) = extract_cn(group_dn)
                        && self.add_edge_by_name(
                            &user.sam_account_name,
                            domain,
                            &cn,
                            domain,
                            EdgeType::MemberOf,
                        )
                    {
                        edge_count += 1;
                    }
                }
            }
        }

        // Group → Group (nested group membership) via group.member_of DNs
        for group in groups {
            for parent_dn in &group.member_of {
                if self.add_edge_by_dn(&group.distinguished_name, parent_dn, EdgeType::MemberOf) {
                    edge_count += 1;
                } else if let Some(cn) = extract_cn(parent_dn)
                    && self.add_edge_by_name(
                        &group.sam_account_name,
                        domain,
                        &cn,
                        domain,
                        EdgeType::MemberOf,
                    )
                {
                    edge_count += 1;
                }
            }
        }

        debug!("Resolved {} MemberOf edges", edge_count);
    }

    fn resolve_delegation(&mut self, users: &[AdUser], computers: &[AdComputer], domain: &str) {
        let mut edge_count = 0usize;

        // Constrained delegation from users
        for user in users {
            for spn_target in &user.allowed_to_delegate_to {
                // SPN format is typically "service/hostname" — extract the hostname
                let target_host = spn_target
                    .split('/')
                    .nth(1)
                    .unwrap_or(spn_target)
                    .split('.')
                    .next()
                    .unwrap_or(spn_target)
                    .to_uppercase();

                // Try matching against computer SAM names (strip trailing $)
                let target_key = if target_host.ends_with('$') {
                    target_host.clone()
                } else {
                    format!("{}$", target_host)
                };

                if self.add_edge_by_name(
                    &user.sam_account_name,
                    domain,
                    &target_key,
                    domain,
                    EdgeType::AllowedToDelegate,
                ) {
                    edge_count += 1;
                } else if self.add_edge_by_name(
                    &user.sam_account_name,
                    domain,
                    &target_host,
                    domain,
                    EdgeType::AllowedToDelegate,
                ) {
                    edge_count += 1;
                }
            }
        }

        // Constrained delegation from computers
        for computer in computers {
            for spn_target in &computer.allowed_to_delegate_to {
                let target_host = spn_target
                    .split('/')
                    .nth(1)
                    .unwrap_or(spn_target)
                    .split('.')
                    .next()
                    .unwrap_or(spn_target)
                    .to_uppercase();

                if self.add_edge_by_name(
                    &computer.sam_account_name,
                    domain,
                    &target_host,
                    domain,
                    EdgeType::AllowedToDelegate,
                ) || self.add_edge_by_name(
                    &computer.sam_account_name,
                    domain,
                    &format!("{}$", target_host),
                    domain,
                    EdgeType::AllowedToDelegate,
                ) {
                    edge_count += 1;
                }
            }

            // Unconstrained delegation → AllowedToAct edge to the domain itself
            if computer.unconstrained_delegation {
                self.add_edge_by_name(
                    &computer.sam_account_name,
                    domain,
                    domain,
                    domain,
                    EdgeType::AllowedToAct,
                );
                edge_count += 1;
            }
        }

        debug!("Resolved {} delegation edges", edge_count);
    }

    // ── Manual Edge Ingestion ─────────────────────────────

    /// Add a session edge: user has an active session on the computer
    pub fn add_session(&mut self, username: &str, computer: &str, domain: &str) {
        self.add_edge_by_name(computer, domain, username, domain, EdgeType::HasSession);
    }

    /// Add a local admin edge
    pub fn add_local_admin(&mut self, principal: &str, computer: &str, domain: &str) {
        self.add_edge_by_name(principal, domain, computer, domain, EdgeType::AdminTo);
    }

    /// Add an ACL-based edge
    pub fn add_acl_edge(&mut self, source: &str, target: &str, domain: &str, edge_type: EdgeType) {
        self.add_edge_by_name(source, domain, target, domain, edge_type);
    }

    // ── Shortest Path Queries ─────────────────────────────

    /// Find the shortest attack path between two nodes.
    /// Uses Dijkstra with edge-type-based costs.
    /// Filters out non-traversable edges (markers like HasSpn, DontReqPreauth).
    pub fn shortest_path(&self, from: &str, to: &str) -> Result<AttackPath> {
        let src_idx = self
            .find_node(from)
            .ok_or_else(|| OverthroneError::NodeNotFound(from.to_string()))?;
        let tgt_idx = self
            .find_node(to)
            .ok_or_else(|| OverthroneError::NodeNotFound(to.to_string()))?;

        let pet_costs = dijkstra(&self.graph, src_idx, Some(tgt_idx), |e| {
            // Non-traversable edges get infinite cost (effectively filtered out)
            if !e.weight().is_traversable() {
                u32::MAX
            } else {
                e.weight().default_cost()
            }
        });

        // Convert petgraph's hashbrown::HashMap to std::collections::HashMap
        let costs: std::collections::HashMap<_, _> = pet_costs.into_iter().collect();

        let total_cost = costs.get(&tgt_idx).ok_or_else(|| OverthroneError::NoPath {
            from: from.into(),
            to: to.into(),
        })?;

        let hops = self.reconstruct_path(src_idx, tgt_idx, &costs)?;

        let src_node = self.get_node(src_idx).unwrap();
        let tgt_node = self.get_node(tgt_idx).unwrap();

        Ok(AttackPath {
            source: src_node.name.clone(),
            target: tgt_node.name.clone(),
            total_cost: *total_cost,
            hop_count: hops.len(),
            hops,
        })
    }

    /// Reconstruct path by backtracking from target through predecessors
    fn reconstruct_path(
        &self,
        src: NodeIndex,
        tgt: NodeIndex,
        costs: &HashMap<NodeIndex, u32>,
    ) -> Result<Vec<PathHop>> {
        let mut path = Vec::new();
        let mut current = tgt;

        while current != src {
            let current_cost = costs.get(&current).copied().unwrap_or(u32::MAX);
            let mut found = false;

            for edge in self.graph.edges_directed(current, Direction::Incoming) {
                let neighbor = edge.source();
                let edge_cost = edge.weight().default_cost();

                if let Some(&neighbor_cost) = costs.get(&neighbor)
                    && neighbor_cost + edge_cost == current_cost
                {
                    let src_node = self.get_node(neighbor).unwrap();
                    let tgt_node = self.get_node(current).unwrap();

                    path.push(PathHop {
                        source: src_node.name.clone(),
                        source_type: src_node.node_type.clone(),
                        edge: edge.weight().clone(),
                        target: tgt_node.name.clone(),
                        target_type: tgt_node.node_type.clone(),
                        cost: edge_cost,
                    });
                    current = neighbor;
                    found = true;
                    break;
                }
            }

            if !found {
                return Err(OverthroneError::Graph("Path reconstruction failed".into()));
            }
        }

        path.reverse();
        Ok(path)
    }

    // ── High-Value Target Queries ─────────────────────────

    /// Find shortest paths from compromised node to ALL Domain Admin members
    pub fn paths_to_da(&self, from: &str, domain: &str) -> Vec<AttackPath> {
        let da_key = node_key("Domain Admins", domain);
        let da_idx = match self.node_index.get(&da_key) {
            Some(&idx) => idx,
            None => {
                warn!("Domain Admins not found");
                return Vec::new();
            }
        };

        let mut paths = Vec::new();

        // Direct path to DA group
        if let Ok(p) = self.shortest_path(from, &format!("Domain Admins@{domain}")) {
            paths.push(p);
        }

        // Paths to each DA member
        for edge in self.graph.edges_directed(da_idx, Direction::Incoming) {
            if *edge.weight() == EdgeType::MemberOf {
                let member = self.get_node(edge.source()).unwrap();
                if let Ok(p) =
                    self.shortest_path(from, &format!("{}@{}", member.name, member.domain))
                {
                    paths.push(p);
                }
            }
        }

        paths.sort_by_key(|p| p.total_cost);
        paths
    }

    pub fn reachable_kerberoastable(&self, from: &str) -> Vec<String> {
        let src_idx = match self.find_node(from) {
            Some(idx) => idx,
            None => return Vec::new(),
        };

        // Dijkstra from source — finds all reachable nodes with costs
        let pet_costs = dijkstra(&self.graph, src_idx, None, |e| e.weight().default_cost());
        let costs: std::collections::HashMap<_, _> = pet_costs.into_iter().collect();

        let mut kerberoastable = Vec::new();
        for &idx in costs.keys() {
            // Check if this node has an outgoing HasSpn edge
            let has_spn = self
                .graph
                .edges_directed(idx, Direction::Outgoing)
                .any(|e| *e.weight() == EdgeType::HasSpn);

            if has_spn && let Some(node) = self.get_node(idx) {
                kerberoastable.push(format!("{}@{}", node.name, node.domain));
            }
        }

        kerberoastable.sort();
        kerberoastable
    }

    pub fn reachable_unconstrained_delegation(&self, from: &str) -> Vec<String> {
        let src_idx = match self.find_node(from) {
            Some(idx) => idx,
            None => return Vec::new(),
        };

        let pet_costs = dijkstra(&self.graph, src_idx, None, |e| e.weight().default_cost());
        let costs: std::collections::HashMap<_, _> = pet_costs.into_iter().collect();

        let mut unconstrained = Vec::new();
        for &idx in costs.keys() {
            if let Some(node) = self.get_node(idx)
                && node.node_type == NodeType::Computer
                && node
                    .properties
                    .get("unconstrained_delegation")
                    .map(|v| v == "true")
                    .unwrap_or(false)
            {
                unconstrained.push(format!("{}@{}", node.name, node.domain));
            }
        }

        unconstrained.sort();
        unconstrained
    }

    // ── Graph Analytics & Export ──────────────────────────

    /// Graph statistics
    pub fn stats(&self) -> GraphStats {
        let mut edge_counts: HashMap<String, usize> = HashMap::new();
        for edge in self.graph.edge_weights() {
            *edge_counts.entry(format!("{edge}")).or_insert(0) += 1;
        }

        let (mut users, mut computers, mut groups, mut domains) = (0, 0, 0, 0);
        for node in self.graph.node_weights() {
            match node.node_type {
                NodeType::User => users += 1,
                NodeType::Computer => computers += 1,
                NodeType::Group => groups += 1,
                NodeType::Domain => domains += 1,
                _ => {}
            }
        }

        GraphStats {
            total_nodes: self.graph.node_count(),
            total_edges: self.graph.edge_count(),
            users,
            computers,
            groups,
            domains,
            edge_type_counts: edge_counts,
        }
    }

    pub fn high_value_targets(&self, top_n: usize) -> Vec<(String, NodeType, usize)> {
        let mut degrees: Vec<(NodeIndex, usize)> = self
            .graph
            .node_indices()
            .map(|idx| {
                let in_deg = self.graph.edges_directed(idx, Direction::Incoming).count();
                let out_deg = self.graph.edges_directed(idx, Direction::Outgoing).count();
                (idx, in_deg + out_deg)
            })
            .collect();

        // Sort descending by degree, take top N
        degrees.sort_by(|a, b| b.1.cmp(&a.1));
        degrees.truncate(top_n);

        degrees
            .into_iter()
            .filter_map(|(idx, degree)| {
                self.get_node(idx).map(|n| {
                    (
                        format!("{}@{}", n.name, n.domain),
                        n.node_type.clone(),
                        degree,
                    )
                })
            })
            .collect()
    }

    pub fn export_json(&self) -> Result<String> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        for idx in self.graph.node_indices() {
            let node = self.graph.node_weight(idx).unwrap();
            nodes.push(serde_json::json!({
                "id": format!("{}@{}", node.name, node.domain),
                "label": node.name,
                "type": format!("{}", node.node_type),
                "domain": node.domain,
                "dn": node.distinguished_name,
                "enabled": node.enabled,
                "properties": node.properties,
            }));
        }

        for edge in self.graph.edge_references() {
            let src = self.graph.node_weight(edge.source()).unwrap();
            let tgt = self.graph.node_weight(edge.target()).unwrap();
            edges.push(serde_json::json!({
                "source": format!("{}@{}", src.name, src.domain),
                "target": format!("{}@{}", tgt.name, tgt.domain),
                "relationship": format!("{}", edge.weight()),
                "cost": edge.weight().default_cost(),
            }));
        }

        let stats = self.stats();
        serde_json::to_string_pretty(&serde_json::json!({
            "metadata": {
                "total_nodes": stats.total_nodes,
                "total_edges": stats.total_edges,
                "users": stats.users,
                "computers": stats.computers,
                "groups": stats.groups,
                "domains": stats.domains,
            },
            "nodes": nodes,
            "edges": edges,
        }))
        .map_err(|e| OverthroneError::Graph(format!("JSON serialization failed: {e}")))
    }

    /// Export graph in BloodHound-compatible JSON format.
    /// Produces data compatible with BloodHound CE import.
    pub fn export_bloodhound(&self) -> Result<String> {
        let mut users = Vec::new();
        let mut computers = Vec::new();
        let mut groups = Vec::new();
        let mut domains = Vec::new();
        let mut gpos = Vec::new();
        let mut ous = Vec::new();

        // Categorize nodes by type
        for idx in self.graph.node_indices() {
            let node = self.graph.node_weight(idx).unwrap();
            let object_id = format!("{}@{}", node.name, node.domain);

            let props = &node.properties;

            match node.node_type {
                NodeType::User => {
                    users.push(serde_json::json!({
                        "ObjectIdentifier": object_id,
                        "Name": node.name,
                        "Domain": node.domain,
                        "Enabled": node.enabled,
                        "IsAdminCount": props.get("admin_count").map(|v| v == "true").unwrap_or(false),
                        "IsHasSPN": props.contains_key("spns"),
                        "IsDONTREQPREAUTH": props.get("dont_req_preauth").map(|v| v == "true").unwrap_or(false),
                        "HasSIDHistory": props.get("sid_history").is_some(),
                    }));
                }
                NodeType::Computer => {
                    computers.push(serde_json::json!({
                        "ObjectIdentifier": object_id,
                        "Name": node.name,
                        "Domain": node.domain,
                        "Enabled": node.enabled,
                        "IsDC": props.get("is_dc").map(|v| v == "true").unwrap_or(false),
                        "IsUnconstrainedDelegation": props.get("unconstrained_delegation").map(|v| v == "true").unwrap_or(false),
                        "DNSHostName": props.get("dns_hostname").cloned().unwrap_or_default(),
                        "OperatingSystem": props.get("operating_system").cloned().unwrap_or_default(),
                    }));
                }
                NodeType::Group => {
                    groups.push(serde_json::json!({
                        "ObjectIdentifier": object_id,
                        "Name": node.name,
                        "Domain": node.domain,
                        "IsAdminCount": props.get("admin_count").map(|v| v == "true").unwrap_or(false),
                        "MemberCount": props.get("member_count").and_then(|v| v.parse().ok()).unwrap_or(0),
                    }));
                }
                NodeType::Domain => {
                    domains.push(serde_json::json!({
                        "ObjectIdentifier": object_id,
                        "Name": node.name,
                    }));
                }
                NodeType::Gpo => {
                    gpos.push(serde_json::json!({
                        "ObjectIdentifier": object_id,
                        "Name": node.name,
                        "Domain": node.domain,
                    }));
                }
                NodeType::Ou => {
                    ous.push(serde_json::json!({
                        "ObjectIdentifier": object_id,
                        "Name": node.name,
                        "Domain": node.domain,
                    }));
                }
            }
        }

        // Build ACL edges (BloodHound format)
        let mut aces = Vec::new();
        let mut has_sessions = Vec::new();
        let mut member_of = Vec::new();
        let mut admin_to = Vec::new();
        let mut all_edges = Vec::new();

        for edge in self.graph.edge_references() {
            let src = self.graph.node_weight(edge.source()).unwrap();
            let tgt = self.graph.node_weight(edge.target()).unwrap();
            let src_id = format!("{}@{}", src.name, src.domain);
            let tgt_id = format!("{}@{}", tgt.name, tgt.domain);

            let edge_entry = serde_json::json!({
                "Source": src_id,
                "Target": tgt_id,
                "Type": format!("{}", edge.weight()),
            });
            all_edges.push(edge_entry.clone());

            // Categorize by edge type for BloodHound format
            match edge.weight() {
                EdgeType::MemberOf => {
                    member_of.push(serde_json::json!({
                        "ObjectIdentifier": src_id,
                        "GroupSID": tgt_id,
                    }));
                }
                EdgeType::HasSession => {
                    has_sessions.push(serde_json::json!({
                        "ComputerSID": src_id,
                        "UserSID": tgt_id,
                    }));
                }
                EdgeType::AdminTo => {
                    admin_to.push(serde_json::json!({
                        "ObjectIdentifier": src_id,
                        "ComputerSID": tgt_id,
                    }));
                }
                // ACL-based edges
                EdgeType::GenericAll
                | EdgeType::GenericWrite
                | EdgeType::WriteOwner
                | EdgeType::WriteDacl
                | EdgeType::ForceChangePassword
                | EdgeType::AddMembers
                | EdgeType::AddSelf
                | EdgeType::Owns => {
                    aces.push(serde_json::json!({
                        "PrincipalSID": src_id,
                        "ObjectSID": tgt_id,
                        "RightName": format!("{}", edge.weight()),
                        "IsInherited": false,
                    }));
                }
                _ => {}
            }
        }

        // Build BloodHound-compatible structure
        serde_json::to_string_pretty(&serde_json::json!({
            "meta": {
                "type": "BloodHoundData",
                "version": 5,
                "collector": "Overthrone",
            },
            "data": {
                "users": users,
                "computers": computers,
                "groups": groups,
                "domains": domains,
                "gpos": gpos,
                "ous": ous,
            },
            "edges": {
                "all": all_edges,
                "memberof": member_of,
                "hassession": has_sessions,
                "adminto": admin_to,
                "aces": aces,
            },
        }))
        .map_err(|e| OverthroneError::Graph(format!("BloodHound export failed: {e}")))
    }

    /// Get an iterator over all nodes in the graph.
    pub fn nodes(&self) -> impl Iterator<Item = (NodeIndex, &AdNode)> {
        self.graph
            .node_indices()
            .map(move |idx| (idx, &self.graph[idx]))
    }

    /// Get domain/config metadata (lockout thresholds, etc.)
    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    // ── Additional methods for TUI support ──────────────────

    /// Get all edges in the graph
    pub fn edges(&self) -> impl Iterator<Item = petgraph::graph::EdgeReference<'_, EdgeType>> + '_ {
        self.graph.edge_references()
    }

    /// Get edges originating from a node
    pub fn edges_from(&self, node: NodeIndex) -> impl Iterator<Item = petgraph::graph::EdgeReference<'_, EdgeType>> + '_ {
        self.graph
            .edges_directed(node, Direction::Outgoing)
    }

    /// Get edges pointing to a node
    pub fn edges_to(&self, node: NodeIndex) -> impl Iterator<Item = petgraph::graph::EdgeReference<'_, EdgeType>> + '_ {
        self.graph
            .edges_directed(node, Direction::Incoming)
    }

    /// Get an edge by its EdgeIndex
    pub fn get_edge(&self, edge_id: EdgeIndex) -> Option<&EdgeType> {
        self.graph.edge_weight(edge_id)
    }

    /// Get nodes of a specific type
    pub fn nodes_of_type(&self, node_type: NodeType) -> impl Iterator<Item = (NodeIndex, &AdNode)> + '_ {
        self.nodes()
            .filter(move |(_, node)| node.node_type == node_type)
    }

    /// Count attack paths (simplified - counts high-value targets)
    pub fn attack_path_count(&self) -> usize {
        self.nodes()
            .filter(|(_, node)| {
                // High-value targets: Domain Admins, Enterprise Admins, etc.
                node.name.to_lowercase().contains("admin") ||
                node.name.to_lowercase().contains("domain") ||
                node.properties.get("high_value").map_or(false, |v| v == "true")
            })
            .count()
    }

    /// Count domains in the graph
    pub fn domain_count(&self) -> usize {
        self.nodes_of_type(NodeType::Domain).count()
    }

    /// Count trust relationships
    pub fn trust_count(&self) -> usize {
        self.edges()
            .filter(|e| matches!(e.weight(), EdgeType::TrustedBy))
            .count()
    }

    /// Find shortest paths to a target (returns multiple paths)
    pub fn shortest_paths_to(&self, target: NodeIndex, limit: usize) -> Vec<Vec<EdgeIndex>> {
        // This is a simplified implementation - returns paths from all nodes
        let mut paths = Vec::new();
        
        for (source_idx, _) in self.nodes() {
            if source_idx == target {
                continue;
            }
            
            // Use Dijkstra to find shortest path
            let costs = dijkstra(
                &self.graph,
                source_idx,
                Some(target),
                |e| e.weight().default_cost(),
            );
            
            if costs.contains_key(&target) {
                // Reconstruct path (simplified - just mark that a path exists)
                // In a full implementation, we'd track the actual edges
                paths.push(vec![]);
                if paths.len() >= limit {
                    break;
                }
            }
        }
        
        paths
    }
}

fn node_key(name: &str, domain: &str) -> String {
    format!("{}@{}", name.to_uppercase(), domain.to_uppercase())
}

/// Extract the CN (Common Name) from an AD Distinguished Name.
///
/// Example: `"CN=Domain Admins,CN=Users,DC=corp,DC=local"` → `"Domain Admins"`
///
/// Returns `None` if no CN= component is found.
fn extract_cn(dn: &str) -> Option<String> {
    for part in dn.split(',') {
        let trimmed = part.trim();
        if trimmed.len() > 3 && trimmed[..3].eq_ignore_ascii_case("CN=") {
            return Some(trimmed[3..].to_string());
        }
    }
    None
}
