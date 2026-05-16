//! Graph loader and pathing for the web viewer.
//!
//! Supports Overthrone export JSON and BloodHound collections.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const EDGE_KEYS: &[&str] = &[
    "MemberOf",
    "Members",
    "Aces",
    "AdminTo",
    "HasSession",
    "CanRDP",
    "CanPSRemote",
    "ExecuteDCOM",
    "SQLAdmin",
    "GenericAll",
    "GenericWrite",
    "WriteOwner",
    "WriteDacl",
    "ForceChangePassword",
    "AddMembers",
    "AddSelf",
    "AllExtendedRights",
    "CreateChild",
    "WriteSelf",
    "ReadLapsPassword",
    "ReadLapsPasswordExpiry",
    "ReadGmsaPassword",
    "AllowedToDelegate",
    "AllowedToAct",
    "HasSidHistory",
    "DcSync",
    "GetChanges",
    "GetChangesAll",
    "TrustedBy",
    "HasSpn",
    "DontReqPreauth",
    "GpoLink",
    "Contains",
    "Owns",
    "Sessions",
    "LocalAdmins",
    "RemoteDesktopUsers",
    "RDPUsers",
    "DcomUsers",
    "DCOMUsers",
    "PSRemoteUsers",
    "SQLAdminUsers",
    "PrivilegedSessions",
    "RegistrySessions",
    "Trusts",
    "Links",
    "ChildObjects",
    "ContainedBy",
    "HasSIDHistory",
    "SPNTargets",
    "GPOChanges",
    "WriteSPN",
    "WriteAllowedToDelegateTo",
    "AddAllowedToAct",
    "WriteAccountRestrictions",
    "WriteLogonScript",
    "WriteProfilePath",
    "WriteScriptPath",
    "WriteDnsHostName",
    "WriteServicePrincipalName",
    "WriteKeyCredentialLink",
    "WriteMsDsKeyCredentialLink",
    "AddKeyCredentialLink",
    "WriteAltSecurityIdentities",
    "WriteUserParameters",
    "WritePwdProperties",
    "WriteLockoutThreshold",
    "WriteMinPwdLength",
    "WritePwdHistoryLength",
    "WritePwdComplexity",
    "WritePwdReversibleEncryption",
    "WritePwdAge",
    "WriteLockoutDuration",
    "WriteLockoutObservationWindow",
    "WriteGPLink",
    "WriteUserCertificate",
    "EnrollCertificate",
    "WriteProperty",
    "ADCSESC1",
    "ADCSESC2",
    "ADCSESC3",
    "ADCSESC4",
    "ADCSESC5",
    "ADCSESC6",
    "ADCSESC7",
    "ADCSESC8",
    "ADCSESC9",
    "ADCSESC10",
    "ADCSESC11",
    "ADCSESC12",
    "ADCSESC13",
    "ADCSESC14",
    "ADCSESC15",
    "ADCSESC16",
    "ManageCA",
    "ManageCertificates",
    "ManageCertTemplate",
    "Enroll",
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GraphLoadMetrics {
    pub parse_ms: u128,
    pub build_ms: u128,
    pub index_ms: u128,
    pub layout_ms: u128,
    pub total_ms: u128,
    pub node_count: usize,
    pub edge_count: usize,
    pub file_bytes: u64,
}

#[derive(Debug)]
struct PerfTimer {
    start: Instant,
    #[allow(dead_code)]
    label: &'static str,
}

impl PerfTimer {
    fn start(label: &'static str) -> Self {
        Self {
            start: Instant::now(),
            label,
        }
    }

    fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }
}

#[derive(Clone, Debug)]
pub struct ViewerNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub domain: Option<String>,
    pub distinguished_name: Option<String>,
    pub enabled: Option<bool>,
    pub high_value: bool,
    pub owned: bool,
    pub properties: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewerEdge {
    pub source: usize,
    pub target: usize,
    pub relationship: String,
    pub cost: u32,
    #[allow(dead_code)]
    pub properties: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovt_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovt_command_desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ace_details: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ViewerStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub users: usize,
    pub computers: usize,
    pub groups: usize,
    pub domains: usize,
    pub gpos: usize,
    pub ous: usize,
    pub cert_templates: usize,
    pub high_value: usize,
    pub owned: usize,
}

#[derive(Clone, Debug)]
pub struct ViewerGraph {
    nodes: Vec<ViewerNode>,
    edges: Vec<ViewerEdge>,
    outgoing: Vec<Vec<usize>>,
    incoming: Vec<Vec<usize>>,
    #[allow(dead_code)]
    relationships: Vec<String>,
    stats: ViewerStats,
    lookup: HashMap<String, usize>,
    search_index: Vec<SearchIndexEntry>,
    pub load_metrics: Option<GraphLoadMetrics>,
}

#[derive(Clone, Debug)]
struct SearchIndexEntry {
    idx: usize,
    primary: String,
    label: String,
    id: String,
    domain: String,
    distinguished_name: String,
    haystack: String,
    kind: String,
    high_value: bool,
    owned: bool,
}

#[derive(Clone, Debug)]
pub struct PathHop {
    pub source_idx: usize,
    pub target_idx: usize,
    pub relationship: String,
    pub cost: u32,
}

#[derive(Clone, Debug)]
pub struct PathResult {
    pub source_idx: usize,
    pub target_idx: usize,
    pub total_cost: u32,
    pub hops: Vec<PathHop>,
}

impl ViewerGraph {
    pub fn from_sources(sources: &[String]) -> Result<Self, String> {
        let expanded = expand_sources(sources)?;
        if expanded.is_empty() {
            return Err("no JSON files matched the provided input".to_string());
        }

        let total_timer = PerfTimer::start("total");
        let mut parse_ms = 0u128;
        let mut build_ms = 0u128;
        let mut file_bytes = 0u64;
        let mut builder = GraphBuilder::new();
        for path in expanded {
            file_bytes =
                file_bytes.saturating_add(fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0));

            let parse_timer = PerfTimer::start("parse");
            let raw = fs::read_to_string(&path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| format!("failed to parse {} as JSON: {e}", path.display()))?;
            parse_ms = parse_ms.saturating_add(parse_timer.elapsed_ms());

            let build_timer = PerfTimer::start("build");
            if let Err(e) = builder.ingest_value(&path, &value) {
                tracing::warn!("Skipping {}: {}", path.display(), e);
            }
            build_ms = build_ms.saturating_add(build_timer.elapsed_ms());
        }

        let index_timer = PerfTimer::start("index");
        let mut graph = builder.finish()?;
        let index_ms = index_timer.elapsed_ms();
        graph.load_metrics = Some(GraphLoadMetrics {
            parse_ms,
            build_ms,
            index_ms,
            layout_ms: 0,
            total_ms: total_timer.elapsed_ms(),
            node_count: graph.stats.total_nodes,
            edge_count: graph.stats.total_edges,
            file_bytes,
        });

        Ok(graph)
    }

    pub fn nodes(&self) -> impl Iterator<Item = (usize, &ViewerNode)> {
        self.nodes.iter().enumerate()
    }

    pub fn edges(&self) -> impl Iterator<Item = &ViewerEdge> {
        self.edges.iter()
    }

    #[allow(dead_code)]
    pub fn relationships(&self) -> &[String] {
        &self.relationships
    }

    pub fn stats(&self) -> &ViewerStats {
        &self.stats
    }

    pub fn get_node(&self, idx: usize) -> Option<&ViewerNode> {
        self.nodes.get(idx)
    }

    pub fn edge(&self, idx: usize) -> Option<&ViewerEdge> {
        self.edges.get(idx)
    }

    pub fn outgoing(&self, idx: usize) -> Option<&Vec<usize>> {
        self.outgoing.get(idx)
    }

    pub fn incoming(&self, idx: usize) -> Option<&Vec<usize>> {
        self.incoming.get(idx)
    }

    pub fn resolve_node(&self, query: &str) -> Option<usize> {
        let query = query.trim();
        if query.is_empty() {
            return None;
        }

        let normalized = normalize_lookup(query);
        if let Some(&idx) = self.lookup.get(&normalized) {
            return Some(idx);
        }

        if let Some((_, name)) = query.rsplit_once('\\') {
            let key = normalize_lookup(name);
            if let Some(&idx) = self.lookup.get(&key) {
                return Some(idx);
            }
        }

        if let Some((name, _domain)) = query.split_once('@') {
            let key = normalize_lookup(name);
            if let Some(&idx) = self.lookup.get(&key) {
                return Some(idx);
            }
        }

        for (key, idx) in &self.lookup {
            if key.starts_with(&normalized) {
                return Some(*idx);
            }
        }

        self.nodes
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.label.to_ascii_uppercase().contains(&normalized)
                    || node.id.to_ascii_uppercase().contains(&normalized)
                    || node
                        .domain
                        .as_ref()
                        .is_some_and(|domain| domain.to_ascii_uppercase().contains(&normalized))
            })
            .map(|(idx, _)| idx)
    }

    pub fn search_nodes(&self, query: &str, kinds: &[String], limit: usize) -> Vec<usize> {
        let query = normalize_lookup(query);
        if query.is_empty() {
            return Vec::new();
        }

        let allowed: HashSet<String> = kinds
            .iter()
            .map(|kind| normalize_kind(kind).to_ascii_lowercase())
            .collect();
        let use_kind_filter = !allowed.is_empty();

        let mut ranked = Vec::new();
        for entry in &self.search_index {
            if use_kind_filter && !allowed.contains(&entry.kind.to_ascii_lowercase()) {
                continue;
            }

            let score = if entry.primary.starts_with(&query) || entry.label.starts_with(&query) {
                0u8
            } else if entry.id.starts_with(&query)
                || entry.domain.starts_with(&query)
                || entry.distinguished_name.starts_with(&query)
            {
                1
            } else if entry.haystack.contains(&query) {
                2
            } else {
                continue;
            };

            ranked.push((
                score,
                Reverse(entry.high_value || entry.owned),
                entry.primary.len(),
                entry.idx,
            ));
        }

        ranked.sort_by_key(|(score, hv, len, idx)| (*score, *hv, *len, *idx));
        ranked
            .into_iter()
            .take(limit.max(1))
            .map(|(_, _, _, idx)| idx)
            .collect()
    }

    pub fn shortest_path(&self, from: &str, to: &str) -> Option<PathResult> {
        let start = self.resolve_node(from)?;
        let goal = self.resolve_node(to)?;

        if start == goal {
            return Some(PathResult {
                source_idx: start,
                target_idx: goal,
                total_cost: 0,
                hops: Vec::new(),
            });
        }

        let mut dist = vec![u32::MAX; self.nodes.len()];
        let mut prev: Vec<Option<(usize, usize)>> = vec![None; self.nodes.len()];
        let mut heap = BinaryHeap::new();

        dist[start] = 0;
        heap.push((Reverse(0u32), start));

        while let Some((Reverse(cost), idx)) = heap.pop() {
            if idx == goal {
                break;
            }
            if cost != dist[idx] {
                continue;
            }

            for edge_idx in self.outgoing.get(idx).into_iter().flatten() {
                let edge = &self.edges[*edge_idx];
                if !edge_traversable(&edge.relationship) {
                    continue;
                }
                let next = edge.target;
                let next_cost = cost.saturating_add(edge.cost);
                if next_cost < dist[next] {
                    dist[next] = next_cost;
                    prev[next] = Some((idx, *edge_idx));
                    heap.push((Reverse(next_cost), next));
                }
            }
        }

        if dist[goal] == u32::MAX {
            return None;
        }

        let mut hops_rev = Vec::new();
        let mut current = goal;
        while current != start {
            let (prev_idx, edge_idx) = prev[current]?;
            let edge = &self.edges[edge_idx];
            hops_rev.push(PathHop {
                source_idx: prev_idx,
                target_idx: current,
                relationship: edge.relationship.clone(),
                cost: edge.cost,
            });
            current = prev_idx;
        }
        hops_rev.reverse();

        Some(PathResult {
            source_idx: start,
            target_idx: goal,
            total_cost: dist[goal],
            hops: hops_rev,
        })
    }
}

#[allow(clippy::type_complexity)]
struct GraphBuilder {
    nodes: Vec<ViewerNode>,
    edges: Vec<(String, String, String, BTreeMap<String, String>)>,
    index: HashMap<String, usize>,
}

impl GraphBuilder {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            index: HashMap::new(),
        }
    }

    fn ingest_value(&mut self, path: &Path, value: &Value) -> Result<(), String> {
        if value.get("nodes").is_some() && value.get("edges").is_some() {
            return self.ingest_overthrone_flat(value);
        }

        if value
            .pointer("/meta/type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.eq_ignore_ascii_case("BloodHoundData"))
        {
            return self.ingest_overthrone_bloodhound(value);
        }

        if value.get("data").is_some_and(Value::is_array) {
            return self.ingest_bloodhound_collection(value);
        }

        if let Some(items) = value.as_array() {
            for item in items {
                self.ingest_value(path, item)?;
            }
            return Ok(());
        }

        Err(format!(
            "{} is not an Overthrone graph export or BloodHound JSON collection",
            path.display()
        ))
    }

    fn ingest_overthrone_flat(&mut self, value: &Value) -> Result<(), String> {
        let nodes = value
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| "Overthrone graph JSON is missing nodes[]".to_string())?;

        for node in nodes {
            let id = string_field(node, &["id"])
                .or_else(|| string_field(node, &["label", "name"]))
                .ok_or_else(|| "graph node is missing id".to_string())?;
            let label = string_field(node, &["label", "name"]).unwrap_or_else(|| id.clone());
            let kind = string_field(node, &["type", "kind", "node_type"])
                .unwrap_or_else(|| "Unknown".to_string());
            let domain = string_field(node, &["domain"]);
            let distinguished_name = string_field(node, &["dn", "distinguished_name"]);
            let enabled = bool_field(node, &["enabled"]);
            let mut properties = BTreeMap::new();

            if let Some(props) = ci_get(node, "properties") {
                flatten_properties("", props, &mut properties, 0);
            }
            for key in ["id", "label", "type", "domain", "dn", "enabled"] {
                if let Some(v) = ci_get(node, key).and_then(value_to_display) {
                    properties.entry(key.to_string()).or_insert(v);
                }
            }

            self.add_node(ViewerNode {
                id,
                label,
                kind: normalize_kind(&kind),
                domain,
                distinguished_name,
                enabled,
                high_value: false,
                owned: false,
                properties,
            });
        }

        for edge in value
            .get("edges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let source = string_field(edge, &["source", "Source"])
                .ok_or_else(|| "graph edge is missing source".to_string())?;
            let target = string_field(edge, &["target", "Target"])
                .ok_or_else(|| "graph edge is missing target".to_string())?;
            let relationship = string_field(edge, &["relationship", "type", "Type"])
                .unwrap_or_else(|| "Relationship".to_string());
            let mut properties = BTreeMap::new();
            flatten_properties("", edge, &mut properties, 0);
            self.add_edge(source, target, relationship, properties);
        }

        Ok(())
    }

    fn ingest_overthrone_bloodhound(&mut self, value: &Value) -> Result<(), String> {
        let data = value
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| "BloodHoundData export is missing data object".to_string())?;

        for (kind, collection) in data {
            let Some(items) = collection.as_array() else {
                continue;
            };
            for item in items {
                self.add_bloodhound_node(kind, item)?;
            }
        }

        if let Some(edges) = value.get("edges").and_then(Value::as_object) {
            for (bucket, collection) in edges {
                for item in collection.as_array().into_iter().flatten() {
                    match bucket.to_ascii_lowercase().as_str() {
                        "all" => {
                            let Some(source) = string_field(item, &["Source", "source"]) else {
                                continue;
                            };
                            let Some(target) = string_field(item, &["Target", "target"]) else {
                                continue;
                            };
                            let relationship = string_field(item, &["Type", "type"])
                                .unwrap_or_else(|| "Relationship".to_string());
                            self.add_edge(source, target, relationship, edge_props(item));
                        }
                        "memberof" => {
                            self.add_edge_from_fields(
                                item,
                                &["ObjectIdentifier", "Source"],
                                &["GroupSID", "Target"],
                                "MemberOf",
                            );
                        }
                        "hassession" => {
                            self.add_edge_from_fields(
                                item,
                                &["ComputerSID", "Source"],
                                &["UserSID", "Target"],
                                "HasSession",
                            );
                        }
                        "adminto" => {
                            self.add_edge_from_fields(
                                item,
                                &["ObjectIdentifier", "Source"],
                                &["ComputerSID", "Target"],
                                "AdminTo",
                            );
                        }
                        "aces" => {
                            let relationship = string_field(item, &["RightName"])
                                .unwrap_or_else(|| "Aces".to_string());
                            self.add_edge_from_fields_dynamic(
                                item,
                                &["PrincipalSID", "Source"],
                                &["ObjectSID", "ObjectIdentifier", "Target"],
                                &relationship,
                            );
                        }
                        _ => {
                            self.ingest_generic_edge_collection(bucket, item);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn ingest_bloodhound_collection(&mut self, value: &Value) -> Result<(), String> {
        let kind = value
            .pointer("/meta/type")
            .and_then(Value::as_str)
            .unwrap_or("objects");
        let data = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| "BloodHound collection is missing data[]".to_string())?;

        for item in data {
            self.add_bloodhound_node(kind, item)?;
        }

        for item in data {
            if let Some(current) = object_id(item) {
                self.ingest_bloodhound_object_edges(&current, item);
            }
        }

        Ok(())
    }

    fn add_bloodhound_node(&mut self, kind: &str, item: &Value) -> Result<(), String> {
        let id = object_id(item)
            .ok_or_else(|| format!("{} entry is missing ObjectIdentifier/name", kind))?;
        let props = ci_get(item, "Properties");
        let label = string_field(item, &["Name", "name", "Label"])
            .or_else(|| props.and_then(|p| string_field(p, &["name", "samaccountname"])))
            .unwrap_or_else(|| id.clone());
        let domain = string_field(item, &["Domain", "domain"])
            .or_else(|| props.and_then(|p| string_field(p, &["domain"])));
        let distinguished_name =
            string_field(item, &["DistinguishedName", "distinguishedname", "dn"])
                .or_else(|| props.and_then(|p| string_field(p, &["distinguishedname", "dn"])));
        let enabled = bool_field(item, &["Enabled", "enabled"])
            .or_else(|| props.and_then(|p| bool_field(p, &["enabled"])));

        let mut properties = BTreeMap::new();
        if let Some(properties_value) = props {
            flatten_properties("", properties_value, &mut properties, 0);
        }
        for key in ["ObjectIdentifier", "Name", "Domain"] {
            if let Some(v) = ci_get(item, key).and_then(value_to_display) {
                properties.entry(key.to_string()).or_insert(v);
            }
        }
        for edge_key in EDGE_KEYS {
            if let Some(v) = ci_get(item, edge_key) {
                properties.insert(
                    format!("{}.count", edge_key),
                    collection_count(v).to_string(),
                );
            }
        }

        self.add_node(ViewerNode {
            id,
            label,
            kind: normalize_kind(kind),
            domain,
            distinguished_name,
            enabled,
            high_value: false,
            owned: false,
            properties,
        });

        Ok(())
    }

    fn ingest_bloodhound_object_edges(&mut self, current_id: &str, item: &Value) {
        for key in EDGE_KEYS {
            let Some(value) = ci_get(item, key) else {
                continue;
            };

            match key.to_ascii_lowercase().as_str() {
                "members" => {
                    for target in edge_targets(value) {
                        self.add_edge(
                            target.id,
                            current_id.to_string(),
                            "MemberOf".to_string(),
                            target.properties,
                        );
                    }
                }
                "aces" => {
                    for ace in value.as_array().into_iter().flatten() {
                        let Some(principal) = string_field(
                            ace,
                            &["PrincipalSID", "PrincipalObjectIdentifier", "Source"],
                        ) else {
                            continue;
                        };
                        let relationship = string_field(ace, &["RightName", "Right", "Type"])
                            .unwrap_or_else(|| "Aces".to_string());
                        self.add_edge(
                            principal,
                            current_id.to_string(),
                            relationship,
                            edge_props(ace),
                        );
                    }
                }
                "adminto" => self.add_targets_as_edges(value, current_id, "AdminTo", false),
                "hassession" => self.add_targets_as_edges(value, current_id, "HasSession", false),
                "canrdp" => self.add_targets_as_edges(value, current_id, "CanRDP", false),
                "canpsremote" => self.add_targets_as_edges(value, current_id, "CanPSRemote", false),
                "executedcom" => self.add_targets_as_edges(value, current_id, "ExecuteDCOM", false),
                "sqladmin" => self.add_targets_as_edges(value, current_id, "SQLAdmin", false),
                "localadmins" => self.add_targets_as_edges(value, current_id, "AdminTo", true),
                "remotedesktopusers" | "rdpusers" => {
                    self.add_targets_as_edges(value, current_id, "CanRDP", true)
                }
                "dcomusers" => self.add_targets_as_edges(value, current_id, "ExecuteDCOM", true),
                "psremoteusers" => {
                    self.add_targets_as_edges(value, current_id, "CanPSRemote", true)
                }
                "sqladminusers" => self.add_targets_as_edges(value, current_id, "SQLAdmin", true),
                "allowedtoact" => {
                    self.add_targets_as_edges(value, current_id, "AllowedToAct", true)
                }
                "sessions" | "privilegedsessions" | "registrysessions" => {
                    self.add_targets_as_edges(value, current_id, "HasSession", false)
                }
                "trusts" => {
                    for target in edge_targets(value) {
                        let target_id = target.id;
                        self.ensure_node(&target_id, &target_id, "Domain");
                        self.add_edge(
                            current_id.to_string(),
                            target_id,
                            "TrustedBy".to_string(),
                            target.properties,
                        );
                    }
                }
                "childobjects" => self.add_targets_as_edges(value, current_id, "Contains", false),
                "links" | "gpochanges" => {
                    self.add_targets_as_edges(value, current_id, "GpoLink", false)
                }
                "containedby" => self.add_targets_as_edges(value, current_id, "Contains", true),
                other => {
                    let relationship = relationship_name(other);
                    self.add_targets_as_edges(value, current_id, &relationship, false);
                }
            }
        }
    }

    fn add_targets_as_edges(
        &mut self,
        value: &Value,
        current_id: &str,
        relationship: &str,
        target_to_current: bool,
    ) {
        for target in edge_targets(value) {
            if target_to_current {
                self.add_edge(
                    target.id,
                    current_id.to_string(),
                    relationship.to_string(),
                    target.properties,
                );
            } else {
                self.add_edge(
                    current_id.to_string(),
                    target.id,
                    relationship.to_string(),
                    target.properties,
                );
            }
        }
    }

    fn ingest_generic_edge_collection(&mut self, relationship: &str, item: &Value) {
        let source = string_field(
            item,
            &["Source", "source", "PrincipalSID", "ObjectIdentifier"],
        );
        let target = string_field(
            item,
            &["Target", "target", "ObjectSID", "ComputerSID", "GroupSID"],
        );
        if let (Some(source), Some(target)) = (source, target) {
            let rel = string_field(item, &["Type", "type", "RightName"])
                .unwrap_or_else(|| relationship_name(relationship));
            self.add_edge(source, target, rel, edge_props(item));
        }
    }

    fn add_edge_from_fields(
        &mut self,
        item: &Value,
        source_keys: &[&str],
        target_keys: &[&str],
        relationship: &str,
    ) {
        self.add_edge_from_fields_dynamic(item, source_keys, target_keys, relationship);
    }

    fn add_edge_from_fields_dynamic(
        &mut self,
        item: &Value,
        source_keys: &[&str],
        target_keys: &[&str],
        relationship: &str,
    ) {
        if let (Some(source), Some(target)) = (
            string_field(item, source_keys),
            string_field(item, target_keys),
        ) {
            self.add_edge(source, target, relationship.to_string(), edge_props(item));
        }
    }

    fn add_node(&mut self, mut node: ViewerNode) -> usize {
        node.high_value = is_high_value(&node);
        node.owned = is_owned(&node);

        let key = normalize_id(&node.id);
        if let Some(&idx) = self.index.get(&key) {
            let existing = &mut self.nodes[idx];
            if existing.kind == "Unknown" && node.kind != "Unknown" {
                existing.kind = node.kind;
            }
            if existing.label == existing.id && node.label != node.id {
                existing.label = node.label;
            }
            existing.domain = existing.domain.clone().or(node.domain);
            existing.distinguished_name = existing
                .distinguished_name
                .clone()
                .or(node.distinguished_name);
            existing.enabled = existing.enabled.or(node.enabled);
            existing.high_value |= node.high_value;
            existing.owned |= node.owned;
            for (k, v) in node.properties {
                existing.properties.entry(k).or_insert(v);
            }
            return idx;
        }

        let idx = self.nodes.len();
        self.index.insert(key, idx);
        self.nodes.push(node);
        idx
    }

    fn ensure_node(&mut self, id: &str, label: &str, kind: &str) -> usize {
        let node = ViewerNode {
            id: id.to_string(),
            label: label.to_string(),
            kind: normalize_kind(kind),
            domain: None,
            distinguished_name: None,
            enabled: None,
            high_value: false,
            owned: false,
            properties: BTreeMap::from([("unresolved".to_string(), "true".to_string())]),
        };
        self.add_node(node)
    }

    fn add_edge(
        &mut self,
        source: String,
        target: String,
        relationship: String,
        properties: BTreeMap<String, String>,
    ) {
        if source.trim().is_empty() || target.trim().is_empty() {
            return;
        }
        self.ensure_node(&source, &source, "Unknown");
        self.ensure_node(&target, &target, "Unknown");
        self.edges
            .push((source, target, relationship_name(&relationship), properties));
    }

    fn finish(self) -> Result<ViewerGraph, String> {
        let mut outgoing = vec![Vec::new(); self.nodes.len()];
        let mut incoming = vec![Vec::new(); self.nodes.len()];
        let mut visual_edges = Vec::new();
        let mut rel_counts: HashMap<String, usize> = HashMap::new();

        for (source, target, relationship, properties) in self.edges {
            let Some(&source_idx) = self.index.get(&normalize_id(&source)) else {
                continue;
            };
            let Some(&target_idx) = self.index.get(&normalize_id(&target)) else {
                continue;
            };

            let idx = visual_edges.len();
            outgoing[source_idx].push(idx);
            incoming[target_idx].push(idx);
            *rel_counts.entry(relationship.clone()).or_default() += 1;
            let annotation = annotate_viewer_edge(
                &relationship,
                &properties,
                &self.nodes[source_idx],
                &self.nodes[target_idx],
            );
            visual_edges.push(ViewerEdge {
                source: source_idx,
                target: target_idx,
                cost: relationship_cost(&relationship),
                relationship,
                properties,
                ovt_command: annotation.ovt_command,
                ovt_command_desc: annotation.ovt_command_desc,
                severity: annotation.severity,
                guidance: annotation.guidance,
                ace_details: annotation.ace_details,
            });
        }

        let mut relationships: Vec<String> = rel_counts.into_keys().collect();
        relationships.sort_by_key(|a| a.to_ascii_lowercase());

        let mut stats = ViewerStats {
            total_nodes: self.nodes.len(),
            total_edges: visual_edges.len(),
            ..ViewerStats::default()
        };

        for node in &self.nodes {
            match node.kind.as_str() {
                "User" => stats.users += 1,
                "Computer" => stats.computers += 1,
                "Group" => stats.groups += 1,
                "Domain" => stats.domains += 1,
                "GPO" => stats.gpos += 1,
                "OU" => stats.ous += 1,
                "CertTemplate" => stats.cert_templates += 1,
                _ => {}
            }
            if node.high_value {
                stats.high_value += 1;
            }
            if node.owned {
                stats.owned += 1;
            }
        }

        let mut lookup = HashMap::new();
        let mut search_index = Vec::with_capacity(self.nodes.len());
        for (idx, node) in self.nodes.iter().enumerate() {
            add_lookup(&mut lookup, &node.id, idx);
            add_lookup(&mut lookup, &node.label, idx);
            let display = node_search_display(node);
            if let Some(domain) = &node.domain
                && !node.label.contains('@')
            {
                add_lookup(&mut lookup, &format!("{}@{}", node.label, domain), idx);
            }
            if let Some(dn) = &node.distinguished_name {
                add_lookup(&mut lookup, dn, idx);
            }
            let domain = node.domain.clone().unwrap_or_default();
            let distinguished_name = node.distinguished_name.clone().unwrap_or_default();
            let primary = normalize_lookup(&display);
            let label = normalize_lookup(&node.label);
            let id = normalize_lookup(&node.id);
            let domain_norm = normalize_lookup(&domain);
            let dn_norm = normalize_lookup(&distinguished_name);
            let haystack = format!("{primary} {label} {id} {domain_norm} {dn_norm}");
            search_index.push(SearchIndexEntry {
                idx,
                primary,
                label,
                id,
                domain: domain_norm,
                distinguished_name: dn_norm,
                haystack,
                kind: node.kind.clone(),
                high_value: node.high_value,
                owned: node.owned,
            });
        }

        Ok(ViewerGraph {
            nodes: self.nodes,
            edges: visual_edges,
            outgoing,
            incoming,
            relationships,
            stats,
            lookup,
            search_index,
            load_metrics: None,
        })
    }
}

#[derive(Debug)]
struct EdgeTarget {
    id: String,
    properties: BTreeMap<String, String>,
}

fn edge_targets(value: &Value) -> Vec<EdgeTarget> {
    match value {
        Value::Array(items) => items.iter().flat_map(edge_targets).collect(),
        Value::Object(_) => {
            if let Some(results) = ci_get(value, "Results") {
                return edge_targets(results);
            }

            let target = string_field(
                value,
                &[
                    "ObjectIdentifier",
                    "ObjectId",
                    "ObjectID",
                    "MemberId",
                    "MemberSID",
                    "PrincipalSID",
                    "TargetSID",
                    "TargetSid",
                    "TargetObjectIdentifier",
                    "ComputerSID",
                    "UserSID",
                    "GroupSID",
                    "TargetDomainName",
                    "Name",
                ],
            );

            target
                .map(|id| {
                    vec![EdgeTarget {
                        id,
                        properties: edge_props(value),
                    }]
                })
                .unwrap_or_default()
        }
        Value::String(id) if !id.trim().is_empty() => vec![EdgeTarget {
            id: id.clone(),
            properties: BTreeMap::new(),
        }],
        _ => Vec::new(),
    }
}

fn expand_sources(sources: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for source in sources {
        let path = PathBuf::from(source);
        if !path.exists() {
            return Err(format!("source file does not exist: {}", path.display()));
        }
        if path.is_dir() {
            let mut entries = fs::read_dir(&path)
                .map_err(|e| format!("failed to read directory {}: {e}", path.display()))?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|entry| {
                    entry
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                })
                .collect::<Vec<_>>();
            entries.sort();
            paths.extend(entries);
        } else if !path.exists() {
            return Err(format!("source file does not exist: {}", path.display()));
        } else {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn object_id(value: &Value) -> Option<String> {
    string_field(
        value,
        &[
            "ObjectIdentifier",
            "objectid",
            "ObjectId",
            "ObjectID",
            "id",
            "ID",
            "Name",
        ],
    )
    .or_else(|| {
        ci_get(value, "Properties").and_then(|props| {
            string_field(
                props,
                &[
                    "objectid",
                    "objectsid",
                    "securityidentifier",
                    "name",
                    "samaccountname",
                ],
            )
        })
    })
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| ci_get(value, key).and_then(value_to_display))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "null")
}

fn bool_field(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        let value = ci_get(value, key)?;
        match value {
            Value::Bool(v) => Some(*v),
            Value::String(v) => match v.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            },
            Value::Number(v) => v.as_u64().map(|n| n != 0),
            _ => None,
        }
    })
}

fn ci_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let obj = value.as_object()?;
    obj.get(key).or_else(|| {
        obj.iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    })
}

fn value_to_display(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(v) => Some(v.to_string()),
        Value::Number(v) => Some(v.to_string()),
        other => serde_json::to_string(other)
            .ok()
            .map(|s| truncate_owned(s, 320)),
    }
}

fn flatten_properties(
    prefix: &str,
    value: &Value,
    out: &mut BTreeMap<String, String>,
    depth: usize,
) {
    if depth > 3 {
        if let Some(display) = value_to_display(value) {
            out.insert(prefix.to_string(), display);
        }
        return;
    }

    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let full_key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                if EDGE_KEYS
                    .iter()
                    .any(|edge_key| edge_key.eq_ignore_ascii_case(key))
                {
                    out.insert(
                        format!("{full_key}.count"),
                        collection_count(value).to_string(),
                    );
                    continue;
                }
                flatten_properties(&full_key, value, out, depth + 1);
            }
        }
        _ => {
            if let Some(display) = value_to_display(value) {
                out.insert(prefix.to_string(), display);
            }
        }
    }
}

fn edge_props(value: &Value) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();
    flatten_properties("", value, &mut props, 0);
    props
}

fn collection_count(value: &Value) -> usize {
    if let Some(items) = value.as_array() {
        return items.len();
    }
    if let Some(results) = ci_get(value, "Results").and_then(Value::as_array) {
        return results.len();
    }
    if value.is_null() { 0 } else { 1 }
}

fn normalize_id(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_lookup(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn add_lookup(lookup: &mut HashMap<String, usize>, key: &str, idx: usize) {
    let key = normalize_lookup(key);
    if !key.is_empty() {
        lookup.entry(key).or_insert(idx);
    }
}

fn node_search_display(node: &ViewerNode) -> String {
    if let Some(domain) = &node.domain
        && !node.label.contains('@')
    {
        return format!("{}@{}", node.label, domain);
    }
    node.label.clone()
}

#[derive(Clone, Debug)]
struct EdgeComputedAnnotation {
    ovt_command: Option<String>,
    ovt_command_desc: Option<String>,
    severity: Option<u8>,
    guidance: Option<String>,
    ace_details: Option<String>,
}

fn annotate_viewer_edge(
    relationship: &str,
    properties: &BTreeMap<String, String>,
    source: &ViewerNode,
    target: &ViewerNode,
) -> EdgeComputedAnnotation {
    let (severity, guidance) = viewer_edge_security_guidance(relationship);
    let (ovt_command, ovt_command_desc) =
        viewer_edge_ovt_command(relationship, properties, source, target);

    EdgeComputedAnnotation {
        ovt_command: Some(ovt_command),
        ovt_command_desc: Some(ovt_command_desc),
        severity: Some(severity),
        guidance: Some(guidance.to_string()),
        ace_details: viewer_edge_ace_details(relationship, properties, source, target),
    }
}

fn viewer_property_value_ci(
    properties: &BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        properties
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn viewer_node_domain(node: &ViewerNode) -> String {
    node.domain.clone().unwrap_or_else(|| "UNKNOWN".to_string())
}

fn viewer_node_display_name(node: &ViewerNode) -> String {
    if let Some(domain) = &node.domain
        && !node.label.contains('@')
    {
        return format!("{}@{}", node.label, domain);
    }
    node.label.clone()
}

fn viewer_node_sid(node: &ViewerNode) -> String {
    viewer_property_value_ci(
        &node.properties,
        &[
            "objectsid",
            "objectid",
            "securityidentifier",
            "ObjectIdentifier",
        ],
    )
    .unwrap_or_else(|| node.id.clone())
}

fn adcs_esc_number(relationship: &str) -> Option<String> {
    let lower = relationship.to_ascii_lowercase();
    let suffix = lower.strip_prefix("adcsesc")?;
    suffix
        .chars()
        .all(|ch| ch.is_ascii_digit())
        .then(|| suffix.to_string())
}

fn viewer_edge_ace_details(
    relationship: &str,
    properties: &BTreeMap<String, String>,
    source: &ViewerNode,
    target: &ViewerNode,
) -> Option<String> {
    let mut details = Vec::new();
    if let Some(principal) = viewer_property_value_ci(
        properties,
        &[
            "PrincipalSID",
            "PrincipalObjectIdentifier",
            "Principalsid",
            "Source",
        ],
    ) {
        details.push(format!("principal={principal}"));
    }
    if let Some(right) = viewer_property_value_ci(properties, &["RightName", "Right", "Type"]) {
        details.push(format!("right={right}"));
    } else if !relationship.eq_ignore_ascii_case("Relationship") {
        details.push(format!("right={relationship}"));
    }
    if let Some(object_type) = viewer_property_value_ci(
        properties,
        &[
            "ObjectType",
            "InheritedObjectType",
            "ObjectClass",
            "ObjectTypeGuid",
        ],
    ) {
        details.push(format!("object_type={object_type}"));
    }
    if let Some(ace_type) = viewer_property_value_ci(properties, &["AceType", "ACEType"]) {
        details.push(format!("ace_type={ace_type}"));
    }
    if let Some(flags) = viewer_property_value_ci(properties, &["AceFlags", "Flags"]) {
        details.push(format!("flags={flags}"));
    }
    if let Some(inherited) = viewer_property_value_ci(properties, &["IsInherited", "Inherited"]) {
        details.push(format!("inherited={inherited}"));
    }
    if let Some(scope) = viewer_property_value_ci(properties, &["AppliesTo", "AppliesToType"]) {
        details.push(format!("scope={scope}"));
    }
    if let Some(template) = viewer_property_value_ci(properties, &["Template", "TemplateName"]) {
        details.push(format!("template={template}"));
    }
    if let Some(ca) =
        viewer_property_value_ci(properties, &["CA", "CAName", "CertificateAuthority"])
    {
        details.push(format!("ca={ca}"));
    }

    if details.is_empty() {
        return None;
    }

    Some(format!(
        "{} -> {} [{}]",
        viewer_node_display_name(source),
        viewer_node_display_name(target),
        details.join(", ")
    ))
}

fn viewer_edge_ovt_command(
    relationship: &str,
    properties: &BTreeMap<String, String>,
    source: &ViewerNode,
    target: &ViewerNode,
) -> (String, String) {
    let target_sid = viewer_node_sid(target);
    let target_name = target.label.clone();
    let target_display = viewer_node_display_name(target);
    let source_domain = viewer_node_domain(source);
    let template = viewer_property_value_ci(properties, &["Template", "TemplateName"])
        .unwrap_or_else(|| "<TEMPLATE>".to_string());
    let ca = viewer_property_value_ci(properties, &["CA", "CAName", "CertificateAuthority"])
        .unwrap_or_else(|| "<CA_HOST>".to_string());

    match relationship.to_ascii_lowercase().as_str() {
        "genericall" | "genericwrite" | "allextendedrights" | "writeproperty" => (
            format!("ovt powerview acls --sid {target_sid}"),
            format!("Review ACLs on {target_display} and scope the write primitive before acting."),
        ),
        "writedacl" => (
            format!("ovt acls writedacl --target {}", target.id),
            format!(
                "Add a tightly scoped ACE on {target_display}, complete the action, then restore the original ACL."
            ),
        ),
        "writeowner" | "owns" => (
            format!("ovt acls writedacl --target {}", target.id),
            format!(
                "Take ownership of {target_display}, modify the DACL, then restore the original owner."
            ),
        ),
        "forcechangepassword" => (
            format!(
                "ovt acl force-password --target {} --password <NEW_PASSWORD>",
                target.id
            ),
            format!(
                "Reset the password for {target_display}; noisy, so prefer a controlled window."
            ),
        ),
        "addmembers" => (
            format!(
                "ovt acl add-member --group {} --member <YOUR_ACCOUNT>",
                target.id
            ),
            format!(
                "Add a single principal to {target_display} and remove it immediately after the dependent action."
            ),
        ),
        "addself" => (
            format!("ovt acl add-self --group {}", target.id),
            format!("Self-add access to {target_display}; scope it tightly and clean up quickly."),
        ),
        "createchild" => (
            format!("ovt acls writedacl --target {}", target.id),
            format!(
                "CreateChild on {target_display}; only create disposable test objects and remove them."
            ),
        ),
        "writeself" => (
            format!("ovt powerview acls --sid {target_sid}"),
            format!(
                "Validated self-write on {target_display}; confirm the exact attribute before use."
            ),
        ),
        "readlapspassword" | "readlapspasswordexpiry" | "readlapsencryptedpassword" => (
            format!("ovt laps read --computer {target_name} --target-dc {source_domain}"),
            format!(
                "Read LAPS material for {target_display}; treat the value as credential material."
            ),
        ),
        "readgmsapassword" => (
            format!("ovt powerview acls --sid {target_sid}"),
            format!(
                "gMSA password path on {target_display}; map the service identity reach before using it."
            ),
        ),
        "allowedtodelegate" => (
            format!("ovt powerview delegations --target {}", target.id),
            format!("Enumerate constrained delegation on {target_display} before any S4U testing."),
        ),
        "allowedtoact" | "addallowedtoact" => (
            format!("ovt acls add-allowed-to-act --target {}", target.id),
            format!(
                "RBCD on {target_display}; use a controlled machine account and remove the ACE after validation."
            ),
        ),
        "writeallowedtodelegateto" => (
            format!("ovt acls writedacl --target {}", target.id),
            format!(
                "Delegation write on {target_display}; record and restore the original service list."
            ),
        ),
        "dcsync" | "getchanges" | "getchangesall" | "getchangesinfilteredset" => (
            format!(
                "ovt adcs dcsync --target {} --domain {source_domain}",
                target.id
            ),
            format!(
                "Replication rights on {target_display}; prefer targeted secret retrieval over a full DCSync."
            ),
        ),
        "writespn" | "writeserviceprincipalname" => (
            format!("ovt acl write-spn --target {} --spn <SPN>", target.id),
            format!(
                "SPN write on {target_display}; use one temporary SPN, collect a single TGS, then restore the original."
            ),
        ),
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => (
            format!(
                "ovt acl shadow-creds --target {} --cert <CERT_FILE>",
                target.id
            ),
            format!(
                "Shadow credentials on {target_display}; add a controlled KeyCredentialLink, authenticate, then remove it."
            ),
        ),
        "writealtsecurityidentities" => (
            format!("ovt adcs alt-sid --target {}", target.id),
            format!(
                "Certificate mapping write on {target_display}; verify policy and restore original values."
            ),
        ),
        "writeaccountrestrictions" => (
            format!("ovt acl modify --target {} --restrictions", target.id),
            format!(
                "Account restrictions write on {target_display}; inspect the target class first."
            ),
        ),
        "writelogonscript" | "writeprofilepath" | "writescriptpath" => (
            format!("ovt acl write-script --target {}", target.id),
            format!("Script path write on {target_display}; keep payloads minimal and reversible."),
        ),
        "writednshostname" => (
            format!("ovt acl write-dnshost --target {}", target.id),
            format!(
                "DNS hostname write on {target_display}; validate SPN and delegation side effects first."
            ),
        ),
        "writepwdproperties"
        | "writelockoutthreshold"
        | "writeminpwdlength"
        | "writepwdhistorylength"
        | "writepwdcomplexity"
        | "writepwdreversibleencryption"
        | "writepwdage"
        | "writelockoutduration"
        | "writelockoutobservationwindow" => (
            format!("ovt acl modify --target {} --pwd-policy", target.id),
            format!(
                "Password policy write on {target_display}; document the original policy and prefer a read-only proof."
            ),
        ),
        "writegplink" => (
            format!("ovt gpo link --target {} --gpo <GPO_ID>", target.id),
            format!(
                "GPLink write on {target_display}; validate scope, inheritance, filtering, and rollback first."
            ),
        ),
        "enrollcertificate" | "enroll" => (
            format!(
                "ovt adcs enroll --template {template} --target {}",
                target.id
            ),
            format!(
                "Certificate enrollment on {target_display}; inspect EKUs, subject supply, approval, and enrollment rights."
            ),
        ),
        "enrollonbehalfof" => (
            format!(
                "ovt adcs enroll --template {template} --target {}",
                target.id
            ),
            format!(
                "Enrollment-agent path on {target_display}; validate template constraints and approval settings."
            ),
        ),
        "manageca" => (
            format!("ovt adcs manage-ca --ca {ca}"),
            format!(
                "ManageCA rights on {target_display}; record CA configuration and restore every changed flag."
            ),
        ),
        "managecertificates" => (
            format!("ovt adcs manage-certificates --ca {ca}"),
            format!(
                "ManageCertificates rights on {target_display}; validate officer scope and pending request risk."
            ),
        ),
        "managecerttemplate" => (
            format!("ovt adcs template --template {template} --inspect"),
            format!(
                "Certificate template control on {target_display}; inspect and restore template ACLs and flags."
            ),
        ),
        "hasspn" => (
            "ovt kerberoast --spn <SPN>".to_string(),
            format!(
                "Kerberoast marker on {target_display}; request one scoped ticket and crack offline."
            ),
        ),
        "dontreqpreauth" => (
            format!("ovt asrep --user {}", target.label),
            format!(
                "AS-REP roast marker on {target_display}; collect once and avoid repeated online queries."
            ),
        ),
        "adminto" => (
            format!("ovt exec --target {} --method auto", target.id),
            format!(
                "Local admin on {target_display}; choose the lowest-volume execution primitive."
            ),
        ),
        "canrdp" => (
            format!("ovt exec --target {} --method rdp", target.id),
            format!("RDP on {target_display}; visible but useful for validation."),
        ),
        "canpsremote" => (
            format!("ovt exec --target {} --method psremote", target.id),
            format!(
                "PowerShell Remoting on {target_display}; keep commands host-scoped and low-volume."
            ),
        ),
        "executedcom" => (
            format!("ovt exec --target {} --method dcom", target.id),
            format!("DCOM on {target_display}; reserve for approved execution phases."),
        ),
        "sqladmin" => (
            format!(
                "ovt mssql --target {} --query 'SELECT @@version'",
                target.id
            ),
            format!(
                "SQL admin on {target_display}; check linked servers, xp_cmdshell, impersonation, and CLR."
            ),
        ),
        "hassession" => (
            format!("ovt exec --target {} --method token", target.id),
            format!("Session on {target_display}; verify freshness before token impersonation."),
        ),
        "trustedby" => (
            format!(
                "ovt move trust --domain {source_domain} --target {}",
                target.id
            ),
            format!(
                "Cross-domain trust from {source_domain}; confirm direction, SID filtering, and transitive scope."
            ),
        ),
        "memberof" | "memberoftierzero" | "memberoftier0" => (
            format!("ovt powerview members --group {} --recurse", target.id),
            format!(
                "Membership in {target_display}; inspect nested memberships for escalation paths."
            ),
        ),
        "contains" => (
            format!("ovt powerview container --target {}", target.id),
            format!("Containment of {target_display}; useful for GPO inheritance and OU scope."),
        ),
        "gpolink" => (
            format!("ovt gpo status --target {}", target.id),
            format!("GPO link on {target_display}; review linked OUs and security filtering."),
        ),
        "hassidhistory" => (
            format!("ovt move sid-history --target {}", target.id),
            format!(
                "SIDHistory on {target_display}; validate effective membership and cross-domain effects."
            ),
        ),
        _ if adcs_esc_number(relationship).is_some() => {
            let esc_num = adcs_esc_number(relationship).unwrap_or_else(|| "N".to_string());
            (
                format!("ovt adcs esc{esc_num} --ca {ca} --template {template}"),
                format!(
                    "ADCS ESC{esc_num} path to {target_display}; verify EKUs, SAN policy, and mapping before use."
                ),
            )
        }
        _ => {
            let safe_rel = relationship.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
            (
                format!("ovt powerview acls --sid {target_sid} --edge-type {safe_rel}"),
                format!(
                    "Review the {relationship} relationship on {target_display}; confirm directionality and validate the abuse primitive before acting."
                ),
            )
        }
    }
}

fn viewer_edge_security_guidance(relationship: &str) -> (u8, &'static str) {
    match relationship.to_ascii_lowercase().as_str() {
        "genericall" => (
            1,
            "Full control. Password reset, DACL edit, group modification, and shadow credentials are common abuse paths.",
        ),
        "genericwrite" => (
            2,
            "Write access. Inspect SPN, delegation, logon script, certificate mapping, and shadow credential options.",
        ),
        "writedacl" => (
            1,
            "DACL write. Add only the scoped ACE needed for validation and restore the original ACL.",
        ),
        "writeowner" | "owns" => (
            1,
            "Ownership control. Preserve the original owner, modify DACL only as needed, and restore ownership.",
        ),
        "forcechangepassword" => (
            2,
            "Password reset edge. Useful but noisy; use only with approval and clear rollback notes.",
        ),
        "addmembers" | "addself" => (
            2,
            "Group membership control. Add the smallest required principal and remove it immediately after validation.",
        ),
        "allextendedrights" => (
            1,
            "Extended rights. May enable password reset or DCSync depending on target object scope.",
        ),
        "createchild" => (
            3,
            "CreateChild. Validate object class scope before creating disposable test objects.",
        ),
        "writeself" => (
            2,
            "Validated self-write. Confirm the exact attribute or validated write before acting.",
        ),
        "readlapspassword" | "readlapspasswordexpiry" | "readlapsencryptedpassword" => (
            2,
            "LAPS read. Treat recovered or derived values as credential material.",
        ),
        "readgmsapassword" => (
            2,
            "gMSA read. Derive the managed password only after mapping where the service identity has reach.",
        ),
        "allowedtoact" | "addallowedtoact" => (
            1,
            "Resource-based constrained delegation. Use a controlled machine account and clean up the value.",
        ),
        "allowedtodelegate" => (
            2,
            "Constrained delegation. Enumerate allowed services and request only scoped S4U tickets.",
        ),
        "writeallowedtodelegateto" => (
            1,
            "Delegation write. Record and restore the original msDS-AllowedToDelegateTo service list.",
        ),
        "dcsync" | "getchanges" | "getchangesall" | "getchangesinfilteredset" => (
            1,
            "Replication rights. Domain-impacting path; prefer targeted retrieval over full-domain dumping.",
        ),
        "writespn" | "writeserviceprincipalname" => (
            2,
            "SPN write. Use one temporary SPN, collect one TGS, then restore the original SPN set.",
        ),
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => (
            1,
            "Shadow credentials. Add a controlled key credential, authenticate, then remove it.",
        ),
        "writealtsecurityidentities" => (
            1,
            "Certificate mapping write. Verify mapping policy and restore original altSecurityIdentities values.",
        ),
        "writeaccountrestrictions" => (
            2,
            "Account restriction write. Inspect target class and delegation impact before changing attributes.",
        ),
        "writelogonscript" | "writeprofilepath" | "writescriptpath" => (
            2,
            "Script path write. Visible execution path; keep payloads minimal and reversible.",
        ),
        "writednshostname" => (
            3,
            "DNS hostname write. Validate DNS, SPN, and delegation side effects first.",
        ),
        "writepwdproperties"
        | "writelockoutthreshold"
        | "writeminpwdlength"
        | "writepwdhistorylength"
        | "writepwdcomplexity"
        | "writepwdreversibleencryption"
        | "writepwdage"
        | "writelockoutduration"
        | "writelockoutobservationwindow" => (
            3,
            "Password policy write. Domain-visible and disruptive; document original settings first.",
        ),
        "writegplink" | "gpolink" => (
            2,
            "GPO control. Review linked OUs, inheritance, enforcement, security filtering, and rollback.",
        ),
        "enrollcertificate" | "enroll" => (
            2,
            "Certificate enrollment. Review EKUs, subject supply, approval, and enrollment rights.",
        ),
        "enrollonbehalfof" => (
            1,
            "Enrollment agent path. Validate template constraints and approval settings before requesting on behalf of another principal.",
        ),
        "manageca" | "managecertificates" | "managecerttemplate" => (
            1,
            "ADCS management control. CA or template configuration changes can unlock certificate abuse paths; record and restore changes.",
        ),
        "adminto" => (
            2,
            "Local admin. Prefer low-volume execution and host-scoped validation.",
        ),
        "canrdp" => (
            3,
            "Interactive logon path. Useful but visible; prefer non-interactive validation when possible.",
        ),
        "canpsremote" => (
            3,
            "PowerShell Remoting. Validate WinRM reachability and keep commands constrained.",
        ),
        "executedcom" => (
            3,
            "DCOM execution. High telemetry; reserve for approved execution phases.",
        ),
        "sqladmin" => (
            2,
            "SQL admin. Check linked servers, xp_cmdshell, impersonation, CLR, and database trust chains.",
        ),
        "hassession" => (
            3,
            "Session edge. Verify freshness before relying on token impersonation.",
        ),
        "hasspn" => (
            4,
            "Kerberoast marker. Request scoped tickets and crack offline.",
        ),
        "dontreqpreauth" => (
            4,
            "AS-REP roast marker. Collect once and avoid repeated online queries.",
        ),
        "trustedby" | "trustedtoauth" => (
            2,
            "Trust relationship. Confirm direction, SID filtering, selective auth, and transitivity.",
        ),
        "hassidhistory" => (
            3,
            "SIDHistory. Validate effective privileges and cross-domain effects.",
        ),
        "memberoftierzero" | "memberoftier0" => (
            1,
            "Tier-zero membership. Treat as domain-impacting and verify nested group expansion.",
        ),
        "memberof" => (
            5,
            "Membership edge. Mostly context, but nested memberships often bridge privilege paths.",
        ),
        "contains" => (
            5,
            "Containment edge. Useful for GPO inheritance, OU scope, and object placement.",
        ),
        _ if adcs_esc_number(relationship).is_some() => (
            1,
            "ADCS ESC path. Validate certificate template, CA configuration, mapping, and rollback requirements.",
        ),
        _ => (
            4,
            "Review relationship properties, confirm directionality, and validate the exact abuse primitive before acting.",
        ),
    }
}

fn normalize_kind(raw: &str) -> String {
    match raw
        .trim()
        .trim_end_matches('s')
        .to_ascii_lowercase()
        .as_str()
    {
        "user" => "User".to_string(),
        "computer" => "Computer".to_string(),
        "group" => "Group".to_string(),
        "domain" => "Domain".to_string(),
        "gpo" => "GPO".to_string(),
        "ou" => "OU".to_string(),
        "container" => "Container".to_string(),
        "certtemplate" | "certificatetemplate" | "template" => "CertTemplate".to_string(),
        "enterpriseca" | "ca" | "certificateauthority" => "EnterpriseCA".to_string(),
        "unknown" | "" => "Unknown".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                None => "Unknown".to_string(),
            }
        }
    }
}

fn relationship_name(raw: &str) -> String {
    let cleaned = raw
        .trim()
        .trim_start_matches("Custom(")
        .trim_end_matches(')')
        .replace([' ', '-', '_'], "");

    match cleaned.to_ascii_lowercase().as_str() {
        "memberof" => "MemberOf",
        "adminto" | "localadmins" => "AdminTo",
        "hassession" | "sessions" => "HasSession",
        "canrdp" | "rdpusers" | "remotedesktopusers" => "CanRDP",
        "canpsremote" | "psremoteusers" => "CanPSRemote",
        "executedcom" | "dcomusers" => "ExecuteDCOM",
        "sqladmin" | "sqladminusers" => "SQLAdmin",
        "genericall" => "GenericAll",
        "genericwrite" => "GenericWrite",
        "writeowner" => "WriteOwner",
        "writedacl" => "WriteDacl",
        "forcechangepassword" => "ForceChangePassword",
        "addmembers" => "AddMembers",
        "addself" => "AddSelf",
        "allextendedrights" => "AllExtendedRights",
        "createchild" => "CreateChild",
        "writeself" => "WriteSelf",
        "readlapspassword" => "ReadLapsPassword",
        "readlapspasswordexpiry" | "readlapsencryptedpassword" => "ReadLapsPasswordExpiry",
        "readgmsapassword" => "ReadGmsaPassword",
        "allowedtodelegate" => "AllowedToDelegate",
        "writeallowedtodelegateto" => "WriteAllowedToDelegateTo",
        "allowedtoact" => "AllowedToAct",
        "addallowedtoact" => "AddAllowedToAct",
        "hassidhistory" => "HasSidHistory",
        "dcsync" => "DcSync",
        "getchanges" => "GetChanges",
        "getchangesall" => "GetChangesAll",
        "trustedby" | "trusts" => "TrustedBy",
        "hasspn" | "spntargets" => "HasSpn",
        "dontreqpreauth" => "DontReqPreauth",
        "gpolink" | "links" | "gpochanges" => "GpoLink",
        "contains" | "childobjects" => "Contains",
        "owns" => "Owns",
        "writespn" => "WriteSPN",
        "writeaccountrestrictions" => "WriteAccountRestrictions",
        "writelogonscript" => "WriteLogonScript",
        "writeprofilepath" => "WriteProfilePath",
        "writescriptpath" => "WriteScriptPath",
        "writednshostname" => "WriteDnsHostName",
        "writeserviceprincipalname" => "WriteServicePrincipalName",
        "writekeycredentiallink" => "WriteKeyCredentialLink",
        "writemsdskeycredentiallink" => "WriteMsDsKeyCredentialLink",
        "addkeycredentiallink" => "AddKeyCredentialLink",
        "writealtsecurityidentities" => "WriteAltSecurityIdentities",
        "writeuserparameters" => "WriteUserParameters",
        "writepwdproperties" => "WritePwdProperties",
        "writelockoutthreshold" => "WriteLockoutThreshold",
        "writeminpwdlength" => "WriteMinPwdLength",
        "writepwdhistorylength" => "WritePwdHistoryLength",
        "writepwdcomplexity" => "WritePwdComplexity",
        "writepwdreversibleencryption" => "WritePwdReversibleEncryption",
        "writepwdage" => "WritePwdAge",
        "writelockoutduration" => "WriteLockoutDuration",
        "writelockoutobservationwindow" => "WriteLockoutObservationWindow",
        "writegplink" => "WriteGPLink",
        "writeusercertificate" => "WriteUserCertificate",
        "enrollcertificate" => "EnrollCertificate",
        "enroll" => "EnrollCertificate",
        "enrollonbehalfof" => "EnrollOnBehalfOf",
        "manageca" => "ManageCA",
        "managecertificates" => "ManageCertificates",
        "managecerttemplate" => "ManageCertTemplate",
        "adcsesc1" => "AdcsEsc1",
        "adcsesc2" => "AdcsEsc2",
        "adcsesc3" => "AdcsEsc3",
        "adcsesc4" => "AdcsEsc4",
        "adcsesc5" => "AdcsEsc5",
        "adcsesc6" => "AdcsEsc6",
        "adcsesc7" => "AdcsEsc7",
        "adcsesc8" => "AdcsEsc8",
        "adcsesc9" => "AdcsEsc9",
        "adcsesc10" => "AdcsEsc10",
        "adcsesc11" => "AdcsEsc11",
        "adcsesc12" => "AdcsEsc12",
        "adcsesc13" => "AdcsEsc13",
        "adcsesc14" => "AdcsEsc14",
        "adcsesc15" => "AdcsEsc15",
        "adcsesc16" => "AdcsEsc16",
        "writeproperty" => "WriteProperty",
        "" => "Relationship",
        _ => return cleaned,
    }
    .to_string()
}

fn relationship_cost(relationship: &str) -> u32 {
    match relationship.to_ascii_lowercase().as_str() {
        "memberof" | "hassidhistory" | "contains" => 0,
        "adminto"
        | "dcsync"
        | "genericall"
        | "forcechangepassword"
        | "owns"
        | "writedacl"
        | "writeowner"
        | "allowedtodelegate"
        | "allowedtoact"
        | "addallowedtoact"
        | "writeallowedtodelegateto"
        | "manageca"
        | "managecertificates"
        | "managecerttemplate"
        | "enrollonbehalfof"
        | "adcsesc1"
        | "adcsesc2"
        | "adcsesc3"
        | "adcsesc4"
        | "adcsesc5"
        | "adcsesc6"
        | "adcsesc7"
        | "adcsesc8"
        | "adcsesc9"
        | "adcsesc10"
        | "adcsesc11"
        | "adcsesc12"
        | "adcsesc13"
        | "adcsesc14"
        | "adcsesc15"
        | "adcsesc16" => 1,
        "hassession" | "genericwrite" | "addmembers" | "addself" | "readlapspassword"
        | "readgmsapassword" | "getchanges" | "getchangesall" | "enrollcertificate" => 2,
        "canrdp" | "canpsremote" | "executedcom" | "sqladmin" | "gpolink" => 3,
        "trustedby" => 4,
        "hasspn" | "dontreqpreauth" => 5,
        _ => 10,
    }
}

fn edge_traversable(relationship: &str) -> bool {
    !matches!(
        relationship.to_ascii_lowercase().as_str(),
        "hasspn" | "dontreqpreauth" | "spntargets"
    )
}

fn is_high_value(node: &ViewerNode) -> bool {
    let label = node.label.to_ascii_uppercase();
    let id = node.id.to_ascii_uppercase();
    let label_or_id = format!("{label} {id}");

    if node.kind == "Domain" {
        return true;
    }

    if node.kind == "CertTemplate"
        && (label_or_id.contains("ESC")
            || property_truthy(
                &node.properties,
                &[
                    "vulnerable",
                    "enabled",
                    "enrolleesuppliessubject",
                    "clientauth",
                ],
            ))
    {
        return true;
    }

    if [
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "SCHEMA ADMINS",
        "ADMINISTRATORS",
        "ACCOUNT OPERATORS",
        "BACKUP OPERATORS",
        "KRBTGT",
    ]
    .iter()
    .any(|needle| label_or_id.contains(needle))
    {
        return true;
    }

    bool_property(
        &node.properties,
        &[
            "highvalue",
            "high_value",
            "isdc",
            "admincount",
            "isadmincount",
        ],
    )
}

fn is_owned(node: &ViewerNode) -> bool {
    bool_property(
        &node.properties,
        &["owned", "pwned", "compromised", "isowned", "highvalueowned"],
    )
}

fn bool_property(properties: &BTreeMap<String, String>, names: &[&str]) -> bool {
    properties.iter().any(|(key, value)| {
        names.iter().any(|name| key.eq_ignore_ascii_case(name))
            && matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
    })
}

fn property_truthy(properties: &BTreeMap<String, String>, names: &[&str]) -> bool {
    properties.iter().any(|(key, value)| {
        names.iter().any(|name| key.eq_ignore_ascii_case(name))
            && matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
    })
}

fn truncate_owned(mut s: String, max: usize) -> String {
    if s.len() > max {
        s.truncate(max.saturating_sub(3));
        s.push_str("...");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::ViewerGraph;

    #[test]
    fn demo_bloodhound_hierarchy_fixture_loads_and_paths() {
        let fixture = format!(
            "{}/../../docs/bloodhound-hierarchy-demo.json",
            env!("CARGO_MANIFEST_DIR")
        );
        if !std::path::Path::new(&fixture).exists() {
            eprintln!("Skipping demo fixture test: file not found at {}", fixture);
            return;
        }
        let graph = ViewerGraph::from_sources(&[fixture]).expect("demo fixture should load");
        assert_eq!(graph.stats().users, 4);
        assert_eq!(graph.stats().groups, 5);
        assert_eq!(graph.stats().domains, 1);
        assert!(graph.stats().total_edges >= 11);

        let path = graph
            .shortest_path("CONTRACTINGF@INTERNAL.LOCAL", "INTERNAL.LOCAL")
            .expect("demo fixture should expose a membership-to-domain path");
        assert!(!path.hops.is_empty());
    }
}
