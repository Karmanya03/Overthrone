//! Local BloodHound-style graph viewer.
//!
//! This module intentionally stays pure Rust: JSON import, graph model,
//! layout, and interactive rendering all run locally with zero Neo4j, web
//! server, browser, or JavaScript dependency.

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    backend::CrosstermBackend,
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
        canvas::{Canvas, Line as CanvasLine, Points},
    },
};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::f64::consts::TAU;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

#[derive(Debug, Clone)]
struct VisualNode {
    id: String,
    label: String,
    kind: String,
    domain: Option<String>,
    distinguished_name: Option<String>,
    enabled: Option<bool>,
    high_value: bool,
    owned: bool,
    properties: BTreeMap<String, String>,
    raw: Value,
}

#[derive(Debug, Clone)]
struct VisualEdge {
    source: usize,
    target: usize,
    relationship: String,
    properties: BTreeMap<String, String>,
    raw: Value,
}

#[derive(Debug, Clone, Copy)]
struct Point {
    x: f64,
    y: f64,
}

#[derive(Debug, Clone, Default)]
struct GraphStats {
    nodes: usize,
    edges: usize,
    users: usize,
    computers: usize,
    groups: usize,
    domains: usize,
    cert_templates: usize,
    high_value: usize,
    owned: usize,
}

#[derive(Debug, Clone)]
struct VisualGraph {
    sources: Vec<String>,
    nodes: Vec<VisualNode>,
    edges: Vec<VisualEdge>,
    outgoing: Vec<Vec<usize>>,
    incoming: Vec<Vec<usize>>,
    relationships: Vec<String>,
    stats: GraphStats,
}

impl VisualGraph {
    fn from_sources(sources: &[String]) -> Result<Self, String> {
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

    fn node_degree(&self, idx: usize) -> usize {
        self.outgoing.get(idx).map_or(0, Vec::len) + self.incoming.get(idx).map_or(0, Vec::len)
    }

    fn edge_traversable(edge: &VisualEdge) -> bool {
        !matches!(
            edge.relationship.to_ascii_lowercase().as_str(),
            "hasspn" | "dontreqpreauth" | "spntargets"
        )
    }

    fn shortest_path_to_high_value(&self, start: usize) -> Option<(Vec<usize>, Vec<usize>)> {
        if start >= self.nodes.len() {
            return None;
        }

        let mut queue = VecDeque::new();
        let mut visited = vec![false; self.nodes.len()];
        let mut previous: Vec<Option<(usize, usize)>> = vec![None; self.nodes.len()];

        visited[start] = true;
        queue.push_back(start);

        let mut target = None;
        while let Some(node_idx) = queue.pop_front() {
            if node_idx != start && self.nodes[node_idx].high_value {
                target = Some(node_idx);
                break;
            }

            for &edge_idx in &self.outgoing[node_idx] {
                let edge = &self.edges[edge_idx];
                if !Self::edge_traversable(edge) {
                    continue;
                }
                if !visited[edge.target] {
                    visited[edge.target] = true;
                    previous[edge.target] = Some((node_idx, edge_idx));
                    queue.push_back(edge.target);
                }
            }
        }

        let mut current = target?;
        let mut nodes = vec![current];
        let mut edges = Vec::new();

        while current != start {
            let (prev, edge_idx) = previous[current]?;
            edges.push(edge_idx);
            current = prev;
            nodes.push(current);
        }

        nodes.reverse();
        edges.reverse();
        Some((nodes, edges))
    }
}

#[allow(clippy::type_complexity)]
struct GraphBuilder {
    nodes: Vec<VisualNode>,
    edges: Vec<(String, String, String, BTreeMap<String, String>, Value)>,
    index: HashMap<String, usize>,
    sources: Vec<String>,
}

impl GraphBuilder {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            index: HashMap::new(),
            sources: Vec::new(),
        }
    }

    fn ingest_value(&mut self, path: &Path, value: &Value) -> Result<(), String> {
        self.sources.push(path.display().to_string());

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

            self.add_node(VisualNode {
                id,
                label,
                kind: normalize_kind(&kind),
                domain,
                distinguished_name,
                enabled,
                high_value: false,
                owned: false,
                properties,
                raw: node.clone(),
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
            self.add_edge(source, target, relationship, properties, edge.clone());
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
                            self.add_edge(
                                source,
                                target,
                                relationship,
                                edge_props(item),
                                item.clone(),
                            );
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

        self.add_node(VisualNode {
            id,
            label,
            kind: normalize_kind(kind),
            domain,
            distinguished_name,
            enabled,
            high_value: false,
            owned: false,
            properties,
            raw: item.clone(),
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
                            target.raw,
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
                            ace.clone(),
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
                            target.raw,
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
                    target.raw,
                );
            } else {
                self.add_edge(
                    current_id.to_string(),
                    target.id,
                    relationship.to_string(),
                    target.properties,
                    target.raw,
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
            self.add_edge(source, target, rel, edge_props(item), item.clone());
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
            self.add_edge(
                source,
                target,
                relationship.to_string(),
                edge_props(item),
                item.clone(),
            );
        }
    }

    fn add_node(&mut self, mut node: VisualNode) -> usize {
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
            if existing.raw.is_null() {
                existing.raw = node.raw;
            }
            return idx;
        }

        let idx = self.nodes.len();
        self.index.insert(key, idx);
        self.nodes.push(node);
        idx
    }

    fn ensure_node(&mut self, id: &str, label: &str, kind: &str) -> usize {
        let node = VisualNode {
            id: id.to_string(),
            label: label.to_string(),
            kind: normalize_kind(kind),
            domain: None,
            distinguished_name: None,
            enabled: None,
            high_value: false,
            owned: false,
            properties: BTreeMap::from([("unresolved".to_string(), "true".to_string())]),
            raw: Value::Null,
        };
        self.add_node(node)
    }

    fn add_edge(
        &mut self,
        source: String,
        target: String,
        relationship: String,
        properties: BTreeMap<String, String>,
        raw: Value,
    ) {
        if source.trim().is_empty() || target.trim().is_empty() {
            return;
        }
        self.ensure_node(&source, &source, "Unknown");
        self.ensure_node(&target, &target, "Unknown");
        self.edges.push((
            source,
            target,
            relationship_name(&relationship),
            properties,
            raw,
        ));
    }

    fn finish(self) -> Result<VisualGraph, String> {
        let mut outgoing = vec![Vec::new(); self.nodes.len()];
        let mut incoming = vec![Vec::new(); self.nodes.len()];
        let mut visual_edges = Vec::new();
        let mut rel_counts: HashMap<String, usize> = HashMap::new();

        for (source, target, relationship, properties, raw) in self.edges {
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
            visual_edges.push(VisualEdge {
                source: source_idx,
                target: target_idx,
                relationship,
                properties,
                raw,
            });
        }

        let mut relationships: Vec<String> = rel_counts.into_keys().collect();
        relationships.sort_by_key(|a| a.to_ascii_lowercase());

        let mut stats = GraphStats {
            nodes: self.nodes.len(),
            edges: visual_edges.len(),
            ..GraphStats::default()
        };

        for node in &self.nodes {
            match node.kind.as_str() {
                "User" => stats.users += 1,
                "Computer" => stats.computers += 1,
                "Group" => stats.groups += 1,
                "Domain" => stats.domains += 1,
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

        Ok(VisualGraph {
            sources: self.sources,
            nodes: self.nodes,
            edges: visual_edges,
            outgoing,
            incoming,
            relationships,
            stats,
        })
    }
}

#[derive(Debug)]
struct EdgeTarget {
    id: String,
    properties: BTreeMap<String, String>,
    raw: Value,
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
                        raw: value.clone(),
                    }]
                })
                .unwrap_or_default()
        }
        Value::String(id) if !id.trim().is_empty() => vec![EdgeTarget {
            id: id.clone(),
            properties: BTreeMap::new(),
            raw: value.clone(),
        }],
        _ => Vec::new(),
    }
}

fn expand_sources(sources: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for source in sources {
        let path = PathBuf::from(source);
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

fn is_high_value(node: &VisualNode) -> bool {
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

fn is_owned(node: &VisualNode) -> bool {
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

fn truncate_owned(mut s: String, max: usize) -> String {
    if s.len() > max {
        s.truncate(max.saturating_sub(3));
        s.push_str("...");
    }
    s
}

fn truncate_label(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut output: String = s.chars().take(max.saturating_sub(1)).collect();
    output.push('~');
    output
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn compute_layout(graph: &VisualGraph) -> Vec<Point> {
    let n = graph.nodes.len();
    if n == 0 {
        return Vec::new();
    }

    let mut totals: HashMap<&str, usize> = HashMap::new();
    for node in &graph.nodes {
        *totals.entry(node.kind.as_str()).or_default() += 1;
    }

    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut points = Vec::with_capacity(n);
    for node in &graph.nodes {
        let total = *totals.get(node.kind.as_str()).unwrap_or(&n).max(&1);
        let idx = seen.entry(node.kind.as_str()).or_default();
        let base_angle = (*idx as f64 / total as f64) * TAU;
        let jitter = (stable_hash(&node.id) % 1000) as f64 / 1000.0 * 0.22;
        let radius =
            kind_radius(&node.kind) + ((stable_hash(&node.label) % 100) as f64 / 100.0) * 12.0;
        points.push(Point {
            x: (base_angle + jitter).cos() * radius,
            y: (base_angle + jitter).sin() * radius,
        });
        *idx += 1;
    }

    let iterations = if n <= 150 {
        180
    } else if n <= 700 {
        90
    } else {
        35
    };

    for iter in 0..iterations {
        let alpha = 1.0 - (iter as f64 / iterations as f64);
        for edge in &graph.edges {
            let source = edge.source;
            let target = edge.target;
            if source == target {
                continue;
            }
            let dx = points[target].x - points[source].x;
            let dy = points[target].y - points[source].y;
            let dist = (dx * dx + dy * dy).sqrt().max(0.1);
            let desired = if graph.nodes[source].kind == graph.nodes[target].kind {
                18.0
            } else {
                26.0
            };
            let force = (dist - desired) * 0.0028 * alpha;
            let fx = dx / dist * force;
            let fy = dy / dist * force;
            points[source].x += fx;
            points[source].y += fy;
            points[target].x -= fx;
            points[target].y -= fy;
        }

        if n <= 450 && iter % 3 == 0 {
            for i in 0..n {
                for j in (i + 1)..n {
                    let dx = points[j].x - points[i].x;
                    let dy = points[j].y - points[i].y;
                    let dist2 = (dx * dx + dy * dy).max(0.1);
                    if dist2 > 900.0 {
                        continue;
                    }
                    let force = 2.2 / dist2 * alpha;
                    points[i].x -= dx * force;
                    points[i].y -= dy * force;
                    points[j].x += dx * force;
                    points[j].y += dy * force;
                }
            }
        }
    }

    let center_x = points.iter().map(|p| p.x).sum::<f64>() / n as f64;
    let center_y = points.iter().map(|p| p.y).sum::<f64>() / n as f64;
    for point in &mut points {
        point.x -= center_x;
        point.y -= center_y;
    }

    points
}

fn kind_radius(kind: &str) -> f64 {
    match kind {
        "Domain" => 8.0,
        "Group" => 34.0,
        "OU" | "GPO" | "Container" => 50.0,
        "Computer" => 68.0,
        "User" => 88.0,
        _ => 108.0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Graph,
    Nodes,
    Edges,
    Details,
}

impl Focus {
    fn next(self) -> Self {
        match self {
            Self::Graph => Self::Nodes,
            Self::Nodes => Self::Edges,
            Self::Edges => Self::Details,
            Self::Details => Self::Graph,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Graph => "graph",
            Self::Nodes => "nodes",
            Self::Edges => "edges",
            Self::Details => "details",
        }
    }
}

struct ViewerApp {
    graph: VisualGraph,
    layout: Vec<Point>,
    focus: Focus,
    selected_node: Option<usize>,
    selected_edge: Option<usize>,
    camera_x: f64,
    camera_y: f64,
    zoom: f64,
    search_mode: bool,
    search_text: String,
    relationship_filter: Option<usize>,
    high_value_only: bool,
    owned_only: bool,
    attack_edges_only: bool,
    neighborhood_only: bool,
    show_help: bool,
    details_scroll: u16,
    last_drag: Option<(u16, u16)>,
    path_nodes: Vec<usize>,
    path_edges: Vec<usize>,
    status: String,
    should_quit: bool,
}

impl ViewerApp {
    fn new(graph: VisualGraph) -> Self {
        let layout = compute_layout(&graph);
        let selected_node = graph
            .nodes
            .iter()
            .position(|node| node.owned)
            .or_else(|| graph.nodes.iter().position(|node| node.high_value))
            .or_else(|| (!graph.nodes.is_empty()).then_some(0));

        let mut app = Self {
            graph,
            layout,
            focus: Focus::Graph,
            selected_node,
            selected_edge: None,
            camera_x: 0.0,
            camera_y: 0.0,
            zoom: 1.0,
            search_mode: false,
            search_text: String::new(),
            relationship_filter: None,
            high_value_only: false,
            owned_only: false,
            attack_edges_only: false,
            neighborhood_only: false,
            show_help: false,
            details_scroll: 0,
            last_drag: None,
            path_nodes: Vec::new(),
            path_edges: Vec::new(),
            status: "Loaded graph. Press ? for keys, / to search, q to quit.".to_string(),
            should_quit: false,
        };
        app.center_on_selection();
        app.refresh_path();
        app
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if self.search_mode {
            self.handle_search_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('?') => self.show_help = !self.show_help,
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Graph => Focus::Details,
                    Focus::Nodes => Focus::Graph,
                    Focus::Edges => Focus::Nodes,
                    Focus::Details => Focus::Edges,
                };
            }
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.status =
                    "Search mode: type to filter nodes, Enter selects first match, Esc exits."
                        .to_string();
            }
            KeyCode::Char('+') | KeyCode::Char('=') => self.zoom = (self.zoom * 1.18).min(8.0),
            KeyCode::Char('-') => self.zoom = (self.zoom / 1.18).max(0.15),
            KeyCode::Char('0') => {
                self.zoom = 1.0;
                self.center_on_selection();
            }
            KeyCode::Home => {
                self.camera_x = 0.0;
                self.camera_y = 0.0;
                self.zoom = 1.0;
            }
            KeyCode::Char('r') => self.cycle_relationship_filter(),
            KeyCode::Char('a') => {
                self.attack_edges_only = !self.attack_edges_only;
                self.ensure_selected_node_visible();
                self.status = if self.attack_edges_only {
                    "Attack-edge lens on: hiding low-signal membership/container markers."
                        .to_string()
                } else {
                    "Attack-edge lens off: showing every visible relationship.".to_string()
                };
            }
            KeyCode::Char('g') => {
                self.neighborhood_only = !self.neighborhood_only;
                self.ensure_selected_node_visible();
                self.status = if self.neighborhood_only {
                    "Neighborhood lens on: selected object plus direct edges only.".to_string()
                } else {
                    "Neighborhood lens off: showing the whole filtered graph.".to_string()
                };
            }
            KeyCode::Char('v') => {
                self.high_value_only = !self.high_value_only;
                self.ensure_selected_node_visible();
            }
            KeyCode::Char('o') => {
                self.owned_only = !self.owned_only;
                self.ensure_selected_node_visible();
            }
            KeyCode::Char('c') => {
                self.search_text.clear();
                self.high_value_only = false;
                self.owned_only = false;
                self.attack_edges_only = false;
                self.neighborhood_only = false;
                self.relationship_filter = None;
                self.status = "Cleared graph filters.".to_string();
            }
            KeyCode::Enter => {
                self.center_on_selection();
                self.refresh_path();
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_active(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_active(1),
            KeyCode::Left | KeyCode::Char('h') => self.left_action(),
            KeyCode::Right | KeyCode::Char('l') => self.right_action(),
            KeyCode::PageUp => self.details_scroll = self.details_scroll.saturating_sub(8),
            KeyCode::PageDown => self.details_scroll = self.details_scroll.saturating_add(8),
            _ => {}
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent, terminal_area: Rect) {
        if self.search_mode {
            return;
        }

        let areas = compute_ui_areas(terminal_area);
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if rect_contains(areas.graph, mouse.column, mouse.row) {
                    self.zoom = (self.zoom * 1.12).min(8.0);
                    self.focus = Focus::Graph;
                } else if rect_contains(areas.details, mouse.column, mouse.row) {
                    self.details_scroll = self.details_scroll.saturating_sub(3);
                    self.focus = Focus::Details;
                } else {
                    self.move_active(-1);
                }
            }
            MouseEventKind::ScrollDown => {
                if rect_contains(areas.graph, mouse.column, mouse.row) {
                    self.zoom = (self.zoom / 1.12).max(0.15);
                    self.focus = Focus::Graph;
                } else if rect_contains(areas.details, mouse.column, mouse.row) {
                    self.details_scroll = self.details_scroll.saturating_add(3);
                    self.focus = Focus::Details;
                } else {
                    self.move_active(1);
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                self.last_drag = Some((mouse.column, mouse.row));
                if rect_contains(areas.graph, mouse.column, mouse.row) {
                    self.focus = Focus::Graph;
                    if let Some(idx) = self.node_at_mouse(mouse.column, mouse.row, areas.graph) {
                        self.selected_node = Some(idx);
                        self.refresh_path();
                        self.status = format!("Selected {}", self.graph.nodes[idx].label);
                    }
                } else if rect_contains(areas.nodes, mouse.column, mouse.row) {
                    self.focus = Focus::Nodes;
                    self.select_node_row(mouse.row, areas.nodes);
                } else if rect_contains(areas.edges, mouse.column, mouse.row) {
                    self.focus = Focus::Edges;
                    self.select_edge_row(mouse.row, areas.edges);
                } else if rect_contains(areas.details, mouse.column, mouse.row) {
                    self.focus = Focus::Details;
                }
            }
            MouseEventKind::Down(MouseButton::Right) if rect_contains(areas.graph, mouse.column, mouse.row) => {
                self.focus = Focus::Graph;
                if let Some(idx) = self.node_at_mouse(mouse.column, mouse.row, areas.graph) {
                    self.selected_node = Some(idx);
                    self.center_on_selection();
                    self.refresh_path();
                    self.status = format!(
                        "Centered {} and refreshed high-value path.",
                        self.graph.nodes[idx].label
                    );
                }
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                if self.focus == Focus::Graph
                    && rect_contains(areas.graph, mouse.column, mouse.row)
                    && let Some((last_x, last_y)) = self.last_drag
                {
                    self.pan_by_mouse_delta(
                        mouse.column as i32 - last_x as i32,
                        mouse.row as i32 - last_y as i32,
                        areas.graph,
                    );
                    self.last_drag = Some((mouse.column, mouse.row));
                }
            }
            MouseEventKind::Up(_) => self.last_drag = None,
            _ => {}
        }
    }

    fn select_node_row(&mut self, row: u16, area: Rect) {
        let inner = inner_rect(area);
        if !rect_contains(inner, area.x.saturating_add(1), row) || row < inner.y {
            return;
        }
        let pos = (row - inner.y) as usize;
        let nodes = self.filtered_nodes();
        if let Some(idx) = nodes.get(pos).copied() {
            self.selected_node = Some(idx);
            self.refresh_path();
            self.status = format!("Selected {}", self.graph.nodes[idx].label);
        }
    }

    fn select_edge_row(&mut self, row: u16, area: Rect) {
        let inner = inner_rect(area);
        if !rect_contains(inner, area.x.saturating_add(1), row) || row < inner.y {
            return;
        }
        let pos = (row - inner.y) as usize;
        let edges = self.panel_edges();
        if let Some(idx) = edges.get(pos).copied() {
            self.selected_edge = Some(idx);
            let edge = &self.graph.edges[idx];
            self.selected_node = Some(edge.source);
            self.status = format!(
                "Selected edge {} -> {} ({})",
                self.graph.nodes[edge.source].label,
                self.graph.nodes[edge.target].label,
                edge.relationship
            );
        }
    }

    fn node_at_mouse(&self, column: u16, row: u16, graph_area: Rect) -> Option<usize> {
        let world = self.mouse_to_world(column, row, graph_area)?;
        let threshold = (3.0 / self.zoom.max(0.35)).max(0.85);
        self.graph
            .nodes
            .iter()
            .enumerate()
            .filter(|(idx, _)| self.node_visible(*idx))
            .filter_map(|(idx, _)| {
                let point = self.layout[idx];
                let distance = ((point.x - world.x).powi(2) + (point.y - world.y).powi(2)).sqrt();
                (distance <= threshold).then_some((idx, distance))
            })
            .min_by(|(_, left), (_, right)| left.partial_cmp(right).unwrap_or(Ordering::Equal))
            .map(|(idx, _)| idx)
    }

    fn mouse_to_world(&self, column: u16, row: u16, graph_area: Rect) -> Option<Point> {
        let inner = inner_rect(graph_area);
        if !rect_contains(inner, column, row) {
            return None;
        }
        let width = inner.width.max(1) as f64;
        let height = inner.height.max(1) as f64;
        let x_span = (graph_area.width.max(20) as f64) / (2.0 * self.zoom);
        let y_span = (graph_area.height.max(10) as f64) / self.zoom;
        let x_ratio = (column.saturating_sub(inner.x) as f64) / width;
        let y_ratio = (row.saturating_sub(inner.y) as f64) / height;
        Some(Point {
            x: self.camera_x - x_span + (2.0 * x_span * x_ratio),
            y: self.camera_y + y_span - (2.0 * y_span * y_ratio),
        })
    }

    fn pan_by_mouse_delta(&mut self, dx: i32, dy: i32, graph_area: Rect) {
        let inner = inner_rect(graph_area);
        let x_span = (graph_area.width.max(20) as f64) / (2.0 * self.zoom);
        let y_span = (graph_area.height.max(10) as f64) / self.zoom;
        let world_per_col = (2.0 * x_span) / inner.width.max(1) as f64;
        let world_per_row = (2.0 * y_span) / inner.height.max(1) as f64;
        self.camera_x -= dx as f64 * world_per_col;
        self.camera_y += dy as f64 * world_per_row;
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.search_mode = false;
                self.status = "Search closed; filter remains active. Press c to clear.".to_string();
            }
            KeyCode::Enter => {
                self.search_mode = false;
                if let Some(first) = self.filtered_nodes().first().copied() {
                    self.selected_node = Some(first);
                    self.center_on_selection();
                    self.refresh_path();
                    self.status = format!("Selected first match for '{}'.", self.search_text);
                } else {
                    self.status = format!("No node matched '{}'.", self.search_text);
                }
            }
            KeyCode::Backspace => {
                self.search_text.pop();
                self.ensure_selected_node_visible();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.search_text.clear();
                self.ensure_selected_node_visible();
            }
            KeyCode::Char(c) => {
                self.search_text.push(c);
                self.ensure_selected_node_visible();
            }
            _ => {}
        }
    }

    fn move_active(&mut self, delta: isize) {
        match self.focus {
            Focus::Graph => {
                self.camera_y += if delta < 0 { 8.0 } else { -8.0 } / self.zoom;
            }
            Focus::Nodes => self.move_node(delta),
            Focus::Edges => self.move_edge(delta),
            Focus::Details => {
                if delta < 0 {
                    self.details_scroll = self.details_scroll.saturating_sub(1);
                } else {
                    self.details_scroll = self.details_scroll.saturating_add(1);
                }
            }
        }
    }

    fn left_action(&mut self) {
        match self.focus {
            Focus::Graph => self.camera_x -= 10.0 / self.zoom,
            Focus::Nodes => self.move_node(-1),
            Focus::Edges => self.move_edge(-1),
            Focus::Details => self.details_scroll = self.details_scroll.saturating_sub(4),
        }
    }

    fn right_action(&mut self) {
        match self.focus {
            Focus::Graph => self.camera_x += 10.0 / self.zoom,
            Focus::Nodes => self.move_node(1),
            Focus::Edges => self.move_edge(1),
            Focus::Details => self.details_scroll = self.details_scroll.saturating_add(4),
        }
    }

    fn move_node(&mut self, delta: isize) {
        let nodes = self.filtered_nodes();
        if nodes.is_empty() {
            self.selected_node = None;
            return;
        }
        let pos = self
            .selected_node
            .and_then(|selected| nodes.iter().position(|idx| *idx == selected))
            .unwrap_or(0);
        let new_pos = wrap_index(pos, delta, nodes.len());
        self.selected_node = Some(nodes[new_pos]);
        self.selected_edge = None;
        self.details_scroll = 0;
        self.center_on_selection();
        self.refresh_path();
    }

    fn move_edge(&mut self, delta: isize) {
        let edges = self.panel_edges();
        if edges.is_empty() {
            self.selected_edge = None;
            return;
        }
        let pos = self
            .selected_edge
            .and_then(|selected| edges.iter().position(|idx| *idx == selected))
            .unwrap_or(0);
        self.selected_edge = Some(edges[wrap_index(pos, delta, edges.len())]);
        self.details_scroll = 0;
    }

    fn cycle_relationship_filter(&mut self) {
        if self.graph.relationships.is_empty() {
            self.relationship_filter = None;
            return;
        }
        self.relationship_filter = match self.relationship_filter {
            None => Some(0),
            Some(idx) if idx + 1 < self.graph.relationships.len() => Some(idx + 1),
            Some(_) => None,
        };
        let label = self
            .relationship_filter
            .map(|idx| self.graph.relationships[idx].clone())
            .unwrap_or_else(|| "all relationships".to_string());
        self.status = format!("Relationship filter: {label}");
    }

    fn ensure_selected_node_visible(&mut self) {
        let nodes = self.filtered_nodes();
        if nodes.is_empty() {
            self.selected_node = None;
        } else if self
            .selected_node
            .is_none_or(|selected| !nodes.contains(&selected))
        {
            self.selected_node = Some(nodes[0]);
        }
        self.selected_edge = None;
        self.refresh_path();
    }

    fn center_on_selection(&mut self) {
        if let Some(idx) = self.selected_node
            && let Some(point) = self.layout.get(idx)
        {
            self.camera_x = point.x;
            self.camera_y = point.y;
        }
    }

    fn refresh_path(&mut self) {
        self.path_nodes.clear();
        self.path_edges.clear();
        if let Some(start) = self.selected_node
            && let Some((nodes, edges)) = self.graph.shortest_path_to_high_value(start)
        {
            self.path_nodes = nodes;
            self.path_edges = edges;
        }
    }

    fn node_visible(&self, idx: usize) -> bool {
        let Some(node) = self.graph.nodes.get(idx) else {
            return false;
        };
        if self.neighborhood_only && !self.node_in_selected_neighborhood(idx) {
            return false;
        }
        if self.high_value_only && !node.high_value {
            return false;
        }
        if self.owned_only && !node.owned {
            return false;
        }
        true
    }

    fn node_in_selected_neighborhood(&self, idx: usize) -> bool {
        let Some(selected) = self.selected_node else {
            return true;
        };
        if idx == selected || self.path_nodes.contains(&idx) {
            return true;
        }
        self.graph.outgoing[selected]
            .iter()
            .chain(self.graph.incoming[selected].iter())
            .any(|edge_idx| {
                let edge = &self.graph.edges[*edge_idx];
                edge.source == idx || edge.target == idx
            })
    }

    fn edge_visible(&self, idx: usize) -> bool {
        let Some(edge) = self.graph.edges.get(idx) else {
            return false;
        };
        if self.attack_edges_only
            && !self.path_edges.contains(&idx)
            && !relationship_is_attack_edge(&edge.relationship)
        {
            return false;
        }
        if self.neighborhood_only
            && let Some(selected) = self.selected_node
            && edge.source != selected
            && edge.target != selected
            && !self.path_edges.contains(&idx)
        {
            return false;
        }
        if let Some(rel_idx) = self.relationship_filter
            && self.graph.relationships.get(rel_idx) != Some(&edge.relationship)
            && !self.path_edges.contains(&idx)
        {
            return false;
        }
        (self.node_visible(edge.source) && self.node_visible(edge.target))
            || self.path_edges.contains(&idx)
    }

    fn node_matches_search(&self, idx: usize) -> bool {
        if self.search_text.is_empty() {
            return true;
        }
        let needle = self.search_text.to_ascii_lowercase();
        let node = &self.graph.nodes[idx];
        node.id.to_ascii_lowercase().contains(&needle)
            || node.label.to_ascii_lowercase().contains(&needle)
            || node.kind.to_ascii_lowercase().contains(&needle)
            || node
                .domain
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains(&needle)
            || node.properties.iter().any(|(key, value)| {
                key.to_ascii_lowercase().contains(&needle)
                    || value.to_ascii_lowercase().contains(&needle)
            })
    }

    fn filtered_nodes(&self) -> Vec<usize> {
        let mut nodes = (0..self.graph.nodes.len())
            .filter(|idx| self.node_visible(*idx) && self.node_matches_search(*idx))
            .collect::<Vec<_>>();
        nodes.sort_by(|a, b| {
            self.graph.nodes[*b]
                .high_value
                .cmp(&self.graph.nodes[*a].high_value)
                .then_with(|| self.graph.node_degree(*b).cmp(&self.graph.node_degree(*a)))
                .then_with(|| {
                    self.graph.nodes[*a]
                        .label
                        .to_ascii_lowercase()
                        .cmp(&self.graph.nodes[*b].label.to_ascii_lowercase())
                })
        });
        nodes
    }

    fn panel_edges(&self) -> Vec<usize> {
        let mut edges = if let Some(node_idx) = self.selected_node {
            self.graph.outgoing[node_idx]
                .iter()
                .chain(self.graph.incoming[node_idx].iter())
                .copied()
                .filter(|idx| self.edge_visible(*idx))
                .collect::<Vec<_>>()
        } else {
            (0..self.graph.edges.len())
                .filter(|idx| self.edge_visible(*idx))
                .collect::<Vec<_>>()
        };

        edges.sort_by(|a, b| {
            let a_path = self.path_edges.contains(a);
            let b_path = self.path_edges.contains(b);
            b_path.cmp(&a_path).then_with(|| {
                self.graph.edges[*a]
                    .relationship
                    .cmp(&self.graph.edges[*b].relationship)
            })
        });
        edges
    }
}

fn wrap_index(pos: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    match delta.cmp(&0) {
        Ordering::Less => (pos + len - ((-delta) as usize % len)) % len,
        Ordering::Equal => pos,
        Ordering::Greater => (pos + delta as usize) % len,
    }
}

pub fn run(sources: &[String]) -> io::Result<()> {
    let graph = VisualGraph::from_sources(sources).map_err(io_other)?;
    let mut app = ViewerApp::new(graph);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut ViewerApp) -> io::Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| draw(frame, app))?;
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => app.handle_key(key),
                Event::Mouse(mouse) => {
                    let size = terminal.size()?;
                    app.handle_mouse(mouse, Rect::new(0, 0, size.width, size.height));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn io_other(message: String) -> io::Error {
    io::Error::other(message)
}

#[derive(Debug, Clone, Copy)]
struct UiAreas {
    graph: Rect,
    nodes: Rect,
    edges: Rect,
    details: Rect,
}

fn compute_ui_areas(area: Rect) -> UiAreas {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(root[1]);

    let side = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(32),
            Constraint::Percentage(28),
            Constraint::Percentage(40),
        ])
        .split(columns[1]);

    UiAreas {
        graph: columns[0],
        nodes: side[0],
        edges: side[1],
        details: side[2],
    }
}

fn rect_contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x
        && column < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

fn inner_rect(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    )
}

fn draw(frame: &mut Frame, app: &mut ViewerApp) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    draw_header(frame, root[0], app);
    draw_main(frame, root[1], app);
    draw_status(frame, root[2], app);

    if app.show_help {
        draw_help(frame, frame.area());
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &ViewerApp) {
    let source = if app.graph.sources.len() == 1 {
        app.graph.sources[0].clone()
    } else {
        format!("{} JSON files", app.graph.sources.len())
    };
    let filter = app
        .relationship_filter
        .and_then(|idx| app.graph.relationships.get(idx))
        .cloned()
        .unwrap_or_else(|| "all".to_string());
    let lenses = format!(
        "{}{}",
        if app.attack_edges_only { " attack" } else { "" },
        if app.neighborhood_only {
            " neighborhood"
        } else {
            ""
        }
    );
    let lenses = if lenses.is_empty() {
        " lenses all".to_string()
    } else {
        format!(" lenses{}", lenses)
    };

    let line = Line::from(vec![
        Span::styled(
            "Overthrone Graph View  ",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "nodes {}  edges {}  users {}  computers {}  groups {}  domains {}  certtpl {}  ",
            app.graph.stats.nodes,
            app.graph.stats.edges,
            app.graph.stats.users,
            app.graph.stats.computers,
            app.graph.stats.groups,
            app.graph.stats.domains,
            app.graph.stats.cert_templates,
        )),
        Span::styled(
            format!(
                "high-value {}  owned {}  ",
                app.graph.stats.high_value, app.graph.stats.owned
            ),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(format!("rel {filter}"), Style::default().fg(Color::Cyan)),
        Span::styled(lenses, Style::default().fg(Color::LightMagenta)),
    ]);

    let header = Paragraph::new(vec![line, Line::from(source)]).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Local Rust BloodHound Viewer "),
    );
    frame.render_widget(header, area);
}

fn draw_main(frame: &mut Frame, area: Rect, app: &mut ViewerApp) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    draw_graph(frame, columns[0], app);

    let side = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(32),
            Constraint::Percentage(28),
            Constraint::Percentage(40),
        ])
        .split(columns[1]);

    draw_nodes(frame, side[0], app);
    draw_edges(frame, side[1], app);
    draw_details(frame, side[2], app);
}

fn draw_graph(frame: &mut Frame, area: Rect, app: &ViewerApp) {
    let x_span = (area.width.max(20) as f64) / (2.0 * app.zoom);
    let y_span = (area.height.max(10) as f64) / app.zoom;
    let title = format!(
        " Graph [{}] zoom {:.2}x path {} ",
        if app.focus == Focus::Graph {
            "focus"
        } else {
            "view"
        },
        app.zoom,
        app.path_edges.len()
    );

    let canvas = Canvas::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(focus_border(app.focus == Focus::Graph)),
        )
        .x_bounds([app.camera_x - x_span, app.camera_x + x_span])
        .y_bounds([app.camera_y - y_span, app.camera_y + y_span])
        .paint(|ctx| {
            for (idx, edge) in app.graph.edges.iter().enumerate() {
                if !app.edge_visible(idx) {
                    continue;
                }
                let source = app.layout[edge.source];
                let target = app.layout[edge.target];
                ctx.draw(&CanvasLine {
                    x1: source.x,
                    y1: source.y,
                    x2: target.x,
                    y2: target.y,
                    color: edge_color(&edge.relationship, app.path_edges.contains(&idx)),
                });
                if app.path_edges.contains(&idx)
                    || app.selected_edge == Some(idx)
                    || (app.neighborhood_only
                        && app.selected_node.is_some_and(|selected| {
                            edge.source == selected || edge.target == selected
                        }))
                    || app.zoom >= 1.45
                {
                    let (risk, risk_color) = relationship_risk(&edge.relationship);
                    ctx.print(
                        (source.x + target.x) / 2.0,
                        (source.y + target.y) / 2.0,
                        Span::styled(
                            format!("{} [{}]", truncate_label(&edge.relationship, 18), risk),
                            Style::default().fg(risk_color),
                        ),
                    );
                }
            }

            for (idx, node) in app.graph.nodes.iter().enumerate() {
                if !app.node_visible(idx) {
                    continue;
                }
                let point = app.layout[idx];
                let selected = app.selected_node == Some(idx);
                let on_path = app.path_nodes.contains(&idx);
                let color = node_color(node, selected, on_path);
                ctx.draw(&Points {
                    coords: &[(point.x, point.y)],
                    color,
                });
                ctx.print(
                    point.x,
                    point.y,
                    Span::styled(
                        node_glyph(&node.kind),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                );
                if selected || node.high_value || app.zoom >= 0.65 {
                    ctx.print(
                        point.x + 1.8,
                        point.y + 0.6,
                        Span::styled(
                            format!(
                                "{} {}",
                                node_glyph(&node.kind),
                                truncate_label(&node.label, 18)
                            ),
                            Style::default().fg(color),
                        ),
                    );
                }
            }
        });

    frame.render_widget(canvas, area);
}

fn draw_nodes(frame: &mut Frame, area: Rect, app: &ViewerApp) {
    let nodes = app.filtered_nodes();
    let selected_pos = app
        .selected_node
        .and_then(|idx| nodes.iter().position(|candidate| *candidate == idx));
    let mut state = ListState::default();
    state.select(selected_pos);

    let items = nodes
        .iter()
        .take(500)
        .map(|idx| {
            let node = &app.graph.nodes[*idx];
            let flags = format!(
                "{}{}",
                if node.high_value { "*" } else { " " },
                if node.owned { "!" } else { " " }
            );
            ListItem::new(Line::from(vec![
                Span::styled(flags, Style::default().fg(Color::Yellow)),
                Span::raw(" "),
                Span::styled(
                    node_glyph(&node.kind),
                    Style::default().fg(kind_color(&node.kind)),
                ),
                Span::raw(" "),
                Span::styled(
                    truncate_label(&node.label, 44),
                    Style::default().fg(kind_color(&node.kind)),
                ),
                Span::raw(format!(" ({})", app.graph.node_degree(*idx))),
            ]))
        })
        .collect::<Vec<_>>();

    let title = if app.search_text.is_empty() {
        format!(
            " Nodes [{}] {} shown ",
            focus_label(app.focus == Focus::Nodes),
            nodes.len()
        )
    } else {
        format!(
            " Nodes [{}] filter '{}' {} shown ",
            focus_label(app.focus == Focus::Nodes),
            app.search_text,
            nodes.len()
        )
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(focus_border(app.focus == Focus::Nodes)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_edges(frame: &mut Frame, area: Rect, app: &ViewerApp) {
    let edges = app.panel_edges();
    let selected_pos = app
        .selected_edge
        .and_then(|idx| edges.iter().position(|candidate| *candidate == idx));
    let mut state = ListState::default();
    state.select(selected_pos);

    let items = edges
        .iter()
        .take(500)
        .map(|idx| {
            let edge = &app.graph.edges[*idx];
            let source = &app.graph.nodes[edge.source];
            let target = &app.graph.nodes[edge.target];
            let marker = if app.path_edges.contains(idx) {
                "*"
            } else {
                " "
            };
            let (risk, risk_color) = relationship_risk(&edge.relationship);
            ListItem::new(Line::from(vec![
                Span::styled(marker, Style::default().fg(Color::LightRed)),
                Span::raw(" "),
                Span::styled(
                    &edge.relationship,
                    Style::default().fg(edge_color(&edge.relationship, false)),
                ),
                Span::raw(" "),
                Span::styled(format!("[{risk}]"), Style::default().fg(risk_color)),
                Span::raw("  "),
                Span::raw(truncate_label(&source.label, 18)),
                Span::raw(" -> "),
                Span::raw(truncate_label(&target.label, 18)),
            ]))
        })
        .collect::<Vec<_>>();

    let title = format!(
        " Edges [{}] {} shown ",
        focus_label(app.focus == Focus::Edges),
        edges.len()
    );
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(focus_border(app.focus == Focus::Edges)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_details(frame: &mut Frame, area: Rect, app: &ViewerApp) {
    let content = detail_lines(app);
    let details = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Details [{}] ",
                    focus_label(app.focus == Focus::Details)
                ))
                .border_style(focus_border(app.focus == Focus::Details)),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.details_scroll, 0));
    frame.render_widget(details, area);
}

fn detail_lines(app: &ViewerApp) -> Vec<Line<'static>> {
    if let Some(edge_idx) = app.selected_edge
        && let Some(edge) = app.graph.edges.get(edge_idx)
    {
        return edge_detail_lines(app, edge_idx, edge);
    }

    if let Some(node_idx) = app.selected_node
        && let Some(node) = app.graph.nodes.get(node_idx)
    {
        return node_detail_lines(app, node_idx, node);
    }

    vec![Line::from("No node selected.")]
}

fn node_detail_lines(app: &ViewerApp, node_idx: usize, node: &VisualNode) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            node.label.clone(),
            Style::default()
                .fg(kind_color(&node.kind))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("ID: {}", node.id)),
        Line::from(format!("Type: {}", node.kind)),
        Line::from(format!("Domain: {}", node.domain.as_deref().unwrap_or("-"))),
        Line::from(format!(
            "DN: {}",
            node.distinguished_name.as_deref().unwrap_or("-")
        )),
        Line::from(format!(
            "Enabled: {}  High value: {}  Owned: {}",
            node.enabled.map_or("-".to_string(), |v| v.to_string()),
            node.high_value,
            node.owned
        )),
        Line::from(format!(
            "Degree: {} outgoing / {} incoming",
            app.graph.outgoing[node_idx].len(),
            app.graph.incoming[node_idx].len()
        )),
        Line::from(""),
    ];

    let insights = node_insight_lines(node);
    if !insights.is_empty() {
        lines.push(Line::from(Span::styled(
            "Operator notes:",
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        )));
        lines.extend(insights);
        lines.push(Line::from(""));
    }

    if !app.path_edges.is_empty() {
        lines.push(Line::from(Span::styled(
            "Shortest visible path to high-value:",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        )));
        for edge_idx in &app.path_edges {
            let edge = &app.graph.edges[*edge_idx];
            let source = &app.graph.nodes[edge.source];
            let target = &app.graph.nodes[edge.target];
            lines.push(Line::from(format!(
                "  {} --{}--> {}",
                source.label, edge.relationship, target.label
            )));
        }
        lines.push(Line::from(""));
    }

    lines.push(Line::from(Span::styled(
        "Outbound relationships:",
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    )));
    for edge_idx in app.graph.outgoing[node_idx].iter().take(20) {
        let edge = &app.graph.edges[*edge_idx];
        let target = &app.graph.nodes[edge.target];
        let (risk, _) = relationship_risk(&edge.relationship);
        lines.push(Line::from(format!(
            "  {} [{}] -> {}",
            edge.relationship, risk, target.label
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Inbound relationships:",
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    )));
    for edge_idx in app.graph.incoming[node_idx].iter().take(20) {
        let edge = &app.graph.edges[*edge_idx];
        let source = &app.graph.nodes[edge.source];
        let (risk, _) = relationship_risk(&edge.relationship);
        lines.push(Line::from(format!(
            "  {} -> {} [{}]",
            source.label, edge.relationship, risk
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Properties:",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    for (key, value) in node.properties.iter().take(120) {
        lines.push(Line::from(format!("  {key}: {value}")));
    }

    if let Ok(raw) = serde_json::to_string_pretty(&node.raw)
        && raw != "null"
    {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Raw JSON:",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )));
        for line in raw.lines().take(80) {
            lines.push(Line::from(format!("  {line}")));
        }
    }

    lines
}

fn node_insight_lines(node: &VisualNode) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    if node.high_value {
        out.push(Line::from(
            "  * High-value object: prioritize path review and blast-radius notes.",
        ));
    }
    if node.owned {
        out.push(Line::from(
            "  * Owned/controlled: good source for path-to-high-value analysis.",
        ));
    }
    if property_truthy(&node.properties, &["admincount", "AdminCount"]) {
        out.push(Line::from(
            "  * adminCount=1: protected-account/adminSDHolder-adjacent object.",
        ));
    }
    if property_present(&node.properties, &["serviceprincipalnames", "spn", "SPNs"]) {
        out.push(Line::from(
            "  * SPN-bearing object: Kerberoast/targeted SPN paths may matter.",
        ));
    }
    if property_truthy(
        &node.properties,
        &["dontreqpreauth", "DoesNotRequirePreAuth"],
    ) {
        out.push(Line::from("  * Pre-auth disabled: AS-REP roast marker."));
    }
    if let Some(bad_pwd) = property_value(&node.properties, &["badpwdcount", "badPwdCount"]) {
        out.push(Line::from(format!(
            "  * badPwdCount={bad_pwd}: spray planner should treat this account carefully."
        )));
    }
    if property_non_zero(&node.properties, &["lockouttime", "lockoutTime"]) {
        out.push(Line::from(
            "  * lockoutTime is set: account may be locked or recently locked.",
        ));
    }
    if property_present(
        &node.properties,
        &[
            "ms-Mcs-AdmPwd",
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
        ],
    ) {
        out.push(Line::from(
            "  * LAPS material present in properties: check read/decrypt rights and freshness.",
        ));
    }
    out
}

fn property_value<'a>(properties: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|wanted| {
        properties
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.as_str())
    })
}

fn property_present(properties: &BTreeMap<String, String>, keys: &[&str]) -> bool {
    property_value(properties, keys).is_some_and(|value| {
        let trimmed = value.trim();
        !trimmed.is_empty() && trimmed != "[]" && trimmed != "null"
    })
}

fn property_truthy(properties: &BTreeMap<String, String>, keys: &[&str]) -> bool {
    property_value(properties, keys).is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y"
        )
    })
}

fn property_non_zero(properties: &BTreeMap<String, String>, keys: &[&str]) -> bool {
    property_value(properties, keys).is_some_and(|value| {
        let trimmed = value.trim();
        !trimmed.is_empty() && trimmed != "0" && !trimmed.eq_ignore_ascii_case("never")
    })
}

fn edge_detail_lines(app: &ViewerApp, edge_idx: usize, edge: &VisualEdge) -> Vec<Line<'static>> {
    let source = &app.graph.nodes[edge.source];
    let target = &app.graph.nodes[edge.target];
    let (risk, risk_color) = relationship_risk(&edge.relationship);
    let mut lines = vec![
        Line::from(Span::styled(
            format!("{} edge #{}", edge.relationship, edge_idx),
            Style::default()
                .fg(edge_color(&edge.relationship, false))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("Source: {} ({})", source.label, source.kind)),
        Line::from(format!("Target: {} ({})", target.label, target.kind)),
        Line::from(vec![
            Span::raw("Risk/Lens: "),
            Span::styled(
                risk,
                Style::default().fg(risk_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(format!("Impact: {}", relationship_hint(&edge.relationship))),
        Line::from(format!(
            "Traversable: {}",
            VisualGraph::edge_traversable(edge)
        )),
        Line::from(format!(
            "Highlighted path: {}",
            app.path_edges.contains(&edge_idx)
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Properties:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    for (key, value) in edge.properties.iter().take(120) {
        lines.push(Line::from(format!("  {key}: {value}")));
    }

    if let Ok(raw) = serde_json::to_string_pretty(&edge.raw)
        && raw != "null"
    {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Raw JSON:",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )));
        for line in raw.lines().take(80) {
            lines.push(Line::from(format!("  {line}")));
        }
    }

    lines
}

fn draw_status(frame: &mut Frame, area: Rect, app: &ViewerApp) {
    let mode = if app.search_mode {
        format!("SEARCH: {}", app.search_text)
    } else {
        format!(
            "focus={}  keys: Tab focus | arrows/jkhl move | +/- zoom | mouse click/drag/wheel | / search | r rel | a attack | g neighborhood | c clear | ? help | q quit",
            app.focus.label()
        )
    };
    let status = Paragraph::new(vec![
        Line::from(mode),
        Line::from(Span::styled(
            app.status.clone(),
            Style::default().fg(Color::DarkGray),
        )),
    ]);
    frame.render_widget(status, area);
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(72, 58, area);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(Span::styled(
            "Overthrone Graph View",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(
            "This is a local Rust BloodHound-style viewer: no Neo4j, no browser, no web server.",
        ),
        Line::from(""),
        Line::from("Navigation"),
        Line::from("  Tab / Shift+Tab  switch graph, node, edge, and detail panes"),
        Line::from("  arrows or hjkl    pan graph or move through selected pane"),
        Line::from("  mouse             click nodes/list rows, drag graph, wheel zoom/scroll"),
        Line::from("  +/-               zoom graph"),
        Line::from("  0                 center selected node"),
        Line::from("  Home              reset camera to graph origin"),
        Line::from("  Enter             center selected node and refresh high-value path"),
        Line::from(""),
        Line::from("Analysis"),
        Line::from("  /                 search all node labels, ids, domains, and properties"),
        Line::from("  r                 cycle relationship filter"),
        Line::from(
            "  a                 attack-edge lens: hide low-signal membership/container noise",
        ),
        Line::from("  g                 neighborhood lens: selected node plus direct edges"),
        Line::from("  v                 show only high-value objects"),
        Line::from("  o                 show only owned/compromised objects"),
        Line::from("  c                 clear filters"),
        Line::from(""),
        Line::from("Legend"),
        Line::from("  U user  C computer  G group  D domain  P GPO  O OU  * high-value  ! owned"),
        Line::from(
            "  Bright red edges are the shortest path from the selected node to a high-value target.",
        ),
        Line::from("  Edge list tags: critical/high/medium/context/roast-marker/policy-control."),
        Line::from(
            "  Details pane adds ACL impact hints, LAPS/gMSA/SPN markers, and lockout telemetry.",
        ),
        Line::from(""),
        Line::from("Press ? to close this help."),
    ];
    let help = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Help "))
        .wrap(Wrap { trim: false });
    frame.render_widget(help, popup);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn focus_label(active: bool) -> &'static str {
    if active { "focus" } else { "view" }
}

fn focus_border(active: bool) -> Style {
    if active {
        Style::default().fg(Color::LightRed)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn node_glyph(kind: &str) -> &'static str {
    match kind {
        "User" => "U",
        "Computer" => "C",
        "Group" => "G",
        "Domain" => "D",
        "GPO" => "P",
        "OU" => "O",
        "Container" => "N",
        "CertTemplate" => "T",
        _ => "?",
    }
}

fn kind_color(kind: &str) -> Color {
    match kind {
        "User" => Color::Green,
        "Computer" => Color::Blue,
        "Group" => Color::Yellow,
        "Domain" => Color::Magenta,
        "GPO" => Color::Cyan,
        "CertTemplate" => Color::LightMagenta,
        "OU" | "Container" => Color::Gray,
        _ => Color::White,
    }
}

fn node_color(node: &VisualNode, selected: bool, on_path: bool) -> Color {
    if selected {
        return Color::White;
    }
    if node.owned {
        return Color::LightGreen;
    }
    if on_path {
        return Color::LightRed;
    }
    if node.high_value {
        return Color::LightYellow;
    }
    kind_color(&node.kind)
}

fn edge_color(relationship: &str, highlighted: bool) -> Color {
    if highlighted {
        return Color::LightRed;
    }
    match relationship.to_ascii_lowercase().as_str() {
        "memberof" | "contains" => Color::DarkGray,
        "adminto"
        | "genericall"
        | "dcsync"
        | "forcechangepassword"
        | "allextendedrights"
        | "addallowedtoact" => Color::Red,
        "genericwrite"
        | "writedacl"
        | "writeowner"
        | "owns"
        | "writekeycredentiallink"
        | "writemsdskeycredentiallink"
        | "addkeycredentiallink"
        | "writespn"
        | "writeallowedtodelegateto"
        | "writeaccountrestrictions"
        | "writegplink"
        | "writeusercertificate" => Color::LightRed,
        "hassession" => Color::Yellow,
        "canrdp" | "canpsremote" | "executedcom" | "sqladmin" => Color::Cyan,
        "allowedtodelegate" | "allowedtoact" => Color::Blue,
        "readlapspassword" | "readlapspasswordexpiry" | "readgmsapassword" => Color::Magenta,
        "addmembers" | "addself" | "writeself" | "createchild" => Color::Yellow,
        rel if rel.starts_with("writepwd") || rel.starts_with("writelockout") => {
            Color::LightMagenta
        }
        "trustedby" => Color::Magenta,
        "gpolink" => Color::LightBlue,
        _ => Color::Gray,
    }
}

fn relationship_is_attack_edge(relationship: &str) -> bool {
    !matches!(
        relationship.to_ascii_lowercase().as_str(),
        "memberof" | "contains" | "gpolink" | "hasspn" | "dontreqpreauth"
    )
}

fn relationship_risk(relationship: &str) -> (&'static str, Color) {
    match relationship.to_ascii_lowercase().as_str() {
        "adminto"
        | "genericall"
        | "dcsync"
        | "forcechangepassword"
        | "allextendedrights"
        | "addallowedtoact"
        | "allowedtoact" => ("critical", Color::Red),
        "genericwrite"
        | "writedacl"
        | "writeowner"
        | "owns"
        | "writekeycredentiallink"
        | "writemsdskeycredentiallink"
        | "addkeycredentiallink"
        | "writespn"
        | "writeallowedtodelegateto"
        | "allowedtodelegate"
        | "writeaccountrestrictions"
        | "writegplink"
        | "writeusercertificate" => ("high", Color::LightRed),
        "readlapspassword"
        | "readlapspasswordexpiry"
        | "readgmsapassword"
        | "addmembers"
        | "addself"
        | "writeself"
        | "createchild"
        | "canrdp"
        | "canpsremote"
        | "executedcom"
        | "sqladmin" => ("medium", Color::Yellow),
        "memberof" | "contains" | "gpolink" => ("context", Color::DarkGray),
        "hasspn" | "dontreqpreauth" => ("roast marker", Color::Cyan),
        rel if rel.starts_with("writepwd") || rel.starts_with("writelockout") => {
            ("policy control", Color::LightMagenta)
        }
        _ => ("review", Color::Gray),
    }
}

fn relationship_hint(relationship: &str) -> &'static str {
    match relationship.to_ascii_lowercase().as_str() {
        "genericall" => {
            "Full control over the object: password reset, membership, DACL, ownership."
        }
        "genericwrite" => {
            "Write non-protected attributes: SPN, KeyCredentialLink, scripts, delegation pivots."
        }
        "writedacl" => {
            "Can modify the DACL; common path is granting controlled principal stronger rights."
        }
        "writeowner" | "owns" => "Ownership can become DACL control, then stronger object control.",
        "forcechangepassword" => {
            "Can reset the target account password without knowing the old password."
        }
        "addmembers" => "Can add a controlled principal to the target group.",
        "addself" | "writeself" => "Validated self-write, often enough to add self to a group.",
        "allextendedrights" => {
            "Broad extended rights: may include password reset, replication, LAPS/gMSA reads."
        }
        "createchild" => {
            "Can create child objects in a container/OU; useful for computer/GPO setup paths."
        }
        "dcsync" | "getchangesall" => {
            "Replication-class right: can read directory secrets when combined correctly."
        }
        "getchanges" => {
            "Partial replication right; often needs GetChangesAll for full credential replication."
        }
        "readlapspassword" => "Can read legacy or Windows LAPS local admin secret where exposed.",
        "readlapspasswordexpiry" => {
            "Windows LAPS encrypted-password path; check decryptability and key access."
        }
        "readgmsapassword" => {
            "Can read gMSA password material and derive service-account credentials."
        }
        "allowedtodelegate" => {
            "Constrained delegation path via S4U when target service and SPNs line up."
        }
        "allowedtoact" | "addallowedtoact" => {
            "RBCD path: abuse resource-based delegation to impersonate to target."
        }
        "writeallowedtodelegateto" => "Can alter constrained delegation target SPNs.",
        "writespn" | "writeserviceprincipalname" => {
            "Can set SPN for targeted Kerberoasting or service identity abuse."
        }
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => {
            "Shadow Credentials path: add key material then authenticate with PKINIT."
        }
        "writeaccountrestrictions" => {
            "Can alter auth/account flags such as preauth, delegation, lockout behavior."
        }
        "writealtsecurityidentities" => "Certificate mapping path via altSecurityIdentities.",
        "writegplink" => "Can link a GPO to scope; impact depends on GPO content and inheritance.",
        "writeusercertificate" | "enrollcertificate" => {
            "Certificate abuse surface; review template and mapping rules."
        }
        "adminto" => "Local admin on target computer.",
        "hassession" => {
            "User session on a computer; useful for credential/material access planning."
        }
        "canrdp" => "Interactive remote desktop access is available.",
        "canpsremote" => "PowerShell remoting access is available.",
        "executedcom" => "DCOM execution path is available.",
        "sqladmin" => {
            "SQL administrative path; may lead to command execution or credential material."
        }
        rel if rel.starts_with("writepwd") || rel.starts_with("writelockout") => {
            "Domain policy control: affects spray safety, lockout behavior, and password hygiene."
        }
        "hasspn" => "Kerberoast marker: account has SPNs.",
        "dontreqpreauth" => {
            "AS-REP roast marker: account does not require Kerberos pre-authentication."
        }
        "memberof" => "Group membership edge.",
        "contains" => "Container/OU/domain hierarchy edge.",
        "gpolink" => "GPO link edge; review enforced/inheritance details.",
        _ => "Custom relationship. Inspect raw properties and source collector semantics.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build_from(value: Value) -> VisualGraph {
        let mut builder = GraphBuilder::new();
        builder
            .ingest_value(Path::new("sample.json"), &value)
            .expect("ingest should succeed");
        builder.finish().expect("finish should succeed")
    }

    #[test]
    fn parses_overthrone_flat_export() {
        let graph = build_from(json!({
            "metadata": {"domain": "corp.local"},
            "nodes": [
                {"id": "alice@corp.local", "label": "alice", "type": "User", "domain": "corp.local"},
                {"id": "Domain Admins@corp.local", "label": "Domain Admins", "type": "Group", "domain": "corp.local"}
            ],
            "edges": [
                {"source": "alice@corp.local", "target": "Domain Admins@corp.local", "relationship": "MemberOf"}
            ]
        }));

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        assert!(graph.nodes.iter().any(|node| node.high_value));
    }

    #[test]
    fn parses_bloodhound_collection_membership() {
        let graph = build_from(json!({
            "meta": {"type": "groups", "count": 1, "version": 5},
            "data": [{
                "ObjectIdentifier": "S-1-GROUP",
                "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "domain": "CORP.LOCAL", "highvalue": true},
                "Members": [{"MemberId": "S-1-USER", "MemberType": "User"}],
                "Aces": [{"PrincipalSID": "S-1-HELPDESK", "RightName": "GenericAll"}]
            }]
        }));

        assert_eq!(graph.nodes.len(), 3);
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.relationship == "MemberOf")
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.relationship == "GenericAll")
        );
    }

    #[test]
    fn finds_shortest_path_to_high_value() {
        let graph = build_from(json!({
            "nodes": [
                {"id": "u", "label": "u", "type": "User"},
                {"id": "g", "label": "Domain Admins", "type": "Group"}
            ],
            "edges": [{"source": "u", "target": "g", "relationship": "MemberOf"}]
        }));
        let start = graph.nodes.iter().position(|node| node.id == "u").unwrap();
        let path = graph.shortest_path_to_high_value(start).unwrap();
        assert_eq!(path.1.len(), 1);
    }

    #[test]
    fn maps_new_acl_relationships_and_attack_lens() {
        assert_eq!(relationship_name("WriteSPN"), "WriteSPN");
        assert_eq!(
            relationship_name("Write-KeyCredentialLink"),
            "WriteKeyCredentialLink"
        );
        assert_eq!(relationship_name("AddAllowedToAct"), "AddAllowedToAct");
        assert_eq!(
            relationship_name("ReadLapsPasswordExpiry"),
            "ReadLapsPasswordExpiry"
        );
        assert!(relationship_is_attack_edge("WriteSPN"));
        assert!(!relationship_is_attack_edge("MemberOf"));
        assert!(relationship_hint("WritePwdComplexity").contains("Domain policy"));
    }

    #[test]
    fn cert_templates_are_counted_and_high_value_when_vulnerable() {
        let graph = build_from(json!({
            "nodes": [{
                "id": "ESC1-User@corp.local",
                "label": "ESC1-User",
                "type": "CertTemplate",
                "properties": {"vulnerable": true}
            }],
            "edges": []
        }));

        assert_eq!(graph.stats.cert_templates, 1);
        assert!(graph.nodes[0].high_value);
        assert_eq!(node_glyph(&graph.nodes[0].kind), "T");
    }
}
