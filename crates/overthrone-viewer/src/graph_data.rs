//! Graph loader and pathing for the web viewer.
//!
//! Supports Overthrone export JSON and BloodHound collections.

use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

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
];

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

#[derive(Clone, Debug)]
pub struct ViewerEdge {
    pub source: usize,
    pub target: usize,
    pub relationship: String,
    pub cost: u32,
    #[allow(dead_code)]
    pub properties: BTreeMap<String, String>,
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

        let mut builder = GraphBuilder::new();
        for path in expanded {
            let raw = fs::read_to_string(&path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            let value: Value = serde_json::from_str(&raw)
                .map_err(|e| format!("failed to parse {} as JSON: {e}", path.display()))?;
            builder.ingest_value(&path, &value)?;
        }

        builder.finish()
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
            visual_edges.push(ViewerEdge {
                source: source_idx,
                target: target_idx,
                cost: relationship_cost(&relationship),
                relationship,
                properties,
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
        | "allowedtoact" => 1,
        "hassession" | "genericwrite" | "addmembers" | "addself" | "readlapspassword"
        | "readgmsapassword" | "getchanges" | "getchangesall" => 2,
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
