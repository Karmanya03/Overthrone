//! Embedded web server for the graph viewer.
//!
//! Serves a single-page BloodHound-style application with D3.js force-directed
//! graph visualization, node search, attack path finder, and detail panels.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::graph_data::{PathResult, ViewerEdge, ViewerGraph, ViewerNode, ViewerStats};

/// Embedded HTML content (built from static/index.html)
const INDEX_HTML: &str = include_str!("static/index.html");

/// Loaded graph bundle
#[derive(Clone)]
struct GraphBundle {
    id: String,
    label: String,
    sources: Vec<String>,
    file_bytes: u64,
}

/// Shared application state
struct AppState {
    graphs: Vec<GraphBundle>,
    default_graph: String,
    cache: RwLock<HashMap<String, Arc<ViewerGraph>>>,
}

const AUTO_NODE_LIMIT: usize = 3500;
const AUTO_NODE_THRESHOLD: usize = 4500;
const AUTO_EDGE_PER_NODE: usize = 6;
const MAX_NODE_LIMIT: usize = 20000;
const MAX_EDGE_LIMIT: usize = 120000;

// ============================================================
//  API Response Types
// ============================================================

#[derive(Serialize)]
struct GraphInfo {
    id: String,
    label: String,
    sources: Vec<String>,
    file_bytes: u64,
    loaded: bool,
    stats: Option<StatsResponse>,
}

#[derive(Serialize)]
struct GraphResponse {
    graph_id: String,
    label: String,
    sources: Vec<String>,
    stats: StatsResponse,
    rendered_nodes: usize,
    rendered_edges: usize,
    truncated: bool,
    node_limit: usize,
    edge_limit: usize,
    nodes: Vec<NodeResponse>,
    edges: Vec<EdgeResponse>,
}

#[derive(Serialize)]
struct StatsResponse {
    total_nodes: usize,
    total_edges: usize,
    users: usize,
    computers: usize,
    groups: usize,
    domains: usize,
    gpos: usize,
    ous: usize,
    cert_templates: usize,
    high_value: usize,
    owned: usize,
}

#[derive(Serialize)]
struct NodeResponse {
    id: String,
    label: String,
    display_name: String,
    #[serde(rename = "type")]
    node_type: String,
    domain: String,
    distinguished_name: Option<String>,
    enabled: Option<bool>,
    high_value: bool,
    owned: bool,
}

#[derive(Serialize)]
struct EdgeResponse {
    source: String,
    target: String,
    relationship: String,
    cost: u32,
    severity: u8,
    guidance: String,
}

#[derive(Serialize)]
struct NodeDetail {
    id: String,
    label: String,
    display_name: String,
    #[serde(rename = "type")]
    node_type: String,
    domain: String,
    distinguished_name: Option<String>,
    enabled: Option<bool>,
    high_value: bool,
    owned: bool,
    properties: BTreeMap<String, String>,
    security_notes: Vec<DetailNote>,
    connections: Vec<Connection>,
}

#[derive(Serialize)]
struct Connection {
    target_id: String,
    target_label: String,
    target_display: String,
    target_type: String,
    target_domain: String,
    relationship: String,
    direction: String,
    cost: u32,
    severity: u8,
    guidance: String,
    properties: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct DetailNote {
    title: String,
    severity: u8,
    body: String,
}

#[derive(Serialize)]
struct SearchResult {
    id: String,
    label: String,
    display_name: String,
    #[serde(rename = "type")]
    node_type: String,
    domain: String,
}

#[derive(Deserialize)]
struct PathRequest {
    from: String,
    to: String,
}

#[derive(Serialize)]
struct PathResponse {
    found: bool,
    source_id: String,
    source_label: String,
    source_display: String,
    source_type: String,
    target_id: String,
    target_label: String,
    target_display: String,
    target_type: String,
    stats: StatsResponse,
    rendered_nodes: usize,
    rendered_edges: usize,
    truncated: bool,
    node_limit: usize,
    edge_limit: usize,
    total_cost: u32,
    hop_count: usize,
    hops: Vec<HopResponse>,
    nodes: Vec<NodeResponse>,
    edges: Vec<EdgeResponse>,
}

#[derive(Serialize)]
struct HopResponse {
    source_id: String,
    source_label: String,
    source_display: String,
    source_type: String,
    target_id: String,
    target_label: String,
    target_display: String,
    target_type: String,
    relationship: String,
    cost: u32,
    severity: u8,
    guidance: String,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    graph: Option<String>,
    types: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct GraphQuery {
    graph: Option<String>,
    limit: Option<usize>,
    edges: Option<usize>,
    focus: Option<String>,
    types: Option<String>,
}

// ============================================================
//  Helpers
// ============================================================

fn node_domain(node: &ViewerNode) -> String {
    node.domain.clone().unwrap_or_else(|| "UNKNOWN".to_string())
}

fn node_display_name(node: &ViewerNode) -> String {
    if let Some(domain) = &node.domain {
        if node.label.contains('@') {
            node.label.clone()
        } else {
            format!("{}@{}", node.label, domain)
        }
    } else {
        node.label.clone()
    }
}

fn node_type_str(node: &ViewerNode) -> String {
    node.kind.clone()
}

fn stats_response(stats: &ViewerStats) -> StatsResponse {
    StatsResponse {
        total_nodes: stats.total_nodes,
        total_edges: stats.total_edges,
        users: stats.users,
        computers: stats.computers,
        groups: stats.groups,
        domains: stats.domains,
        gpos: stats.gpos,
        ous: stats.ous,
        cert_templates: stats.cert_templates,
        high_value: stats.high_value,
        owned: stats.owned,
    }
}

fn resolve_node_limit(limit: Option<usize>, total_nodes: usize) -> usize {
    match limit {
        Some(0) => total_nodes,
        Some(n) => n.min(MAX_NODE_LIMIT).min(total_nodes),
        None => {
            if total_nodes <= AUTO_NODE_THRESHOLD {
                total_nodes
            } else {
                AUTO_NODE_LIMIT.min(total_nodes)
            }
        }
    }
}

fn resolve_edge_limit(
    limit: Option<usize>,
    node_limit: usize,
    total_nodes: usize,
    total_edges: usize,
) -> usize {
    if node_limit >= total_nodes {
        return total_edges;
    }

    match limit {
        Some(0) => total_edges,
        Some(n) => n.min(MAX_EDGE_LIMIT).min(total_edges),
        None => node_limit
            .saturating_mul(AUTO_EDGE_PER_NODE)
            .min(MAX_EDGE_LIMIT)
            .min(total_edges),
    }
}

fn parse_type_filter(types: Option<&str>) -> Vec<String> {
    types
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty() && !item.eq_ignore_ascii_case("all"))
        .map(normalize_node_type_filter)
        .collect()
}

fn normalize_node_type_filter(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "user" | "users" => "User",
        "computer" | "computers" | "host" | "hosts" => "Computer",
        "group" | "groups" => "Group",
        "domain" | "domains" => "Domain",
        "gpo" | "gpos" => "GPO",
        "ou" | "ous" => "OU",
        "container" | "containers" => "Container",
        "certtemplate" | "cert-template" | "cert_template" | "template" | "templates" => {
            "CertTemplate"
        }
        "ca" | "certauthority" | "cert-authority" | "cert_authority" | "enterprise_ca" => {
            "EnterpriseCA"
        }
        other => other,
    }
    .to_string()
}

fn node_matches_type_filter(node: &ViewerNode, type_filter: &[String]) -> bool {
    type_filter.is_empty()
        || type_filter
            .iter()
            .any(|kind| node.kind.eq_ignore_ascii_case(kind))
}

fn select_graph_nodes(
    graph: &ViewerGraph,
    node_limit: usize,
    type_filter: &[String],
) -> Vec<usize> {
    let total_nodes = graph.stats().total_nodes;
    let eligible: Vec<usize> = graph
        .nodes()
        .filter_map(|(idx, node)| node_matches_type_filter(node, type_filter).then_some(idx))
        .collect();

    if node_limit >= eligible.len() {
        return eligible;
    }

    let mut degrees = vec![0usize; total_nodes];
    for edge in graph.edges() {
        if edge.source < total_nodes && edge.target < total_nodes {
            degrees[edge.source] += 1;
            degrees[edge.target] += 1;
        }
    }

    let mut selected = Vec::new();
    let mut selected_mask = vec![false; total_nodes];

    for (idx, node) in graph.nodes() {
        if node_matches_type_filter(node, type_filter)
            && (node.high_value || node.owned || node.kind.eq_ignore_ascii_case("domain"))
        {
            selected.push(idx);
            selected_mask[idx] = true;
        }
    }

    if selected.len() >= node_limit {
        selected.truncate(node_limit);
        return selected;
    }

    let mut remaining: Vec<usize> = (0..total_nodes)
        .filter(|idx| {
            !selected_mask[*idx]
                && graph
                    .get_node(*idx)
                    .is_some_and(|node| node_matches_type_filter(node, type_filter))
        })
        .collect();
    remaining.sort_by_key(|idx| Reverse(degrees[*idx]));

    for idx in remaining.into_iter().take(node_limit - selected.len()) {
        selected.push(idx);
    }

    selected
}

fn edge_is_important(relationship: &str) -> bool {
    !matches!(
        relationship.to_ascii_lowercase().as_str(),
        "memberof" | "contains" | "hasspn" | "dontreqpreauth"
    )
}

fn push_selected_node(
    graph: &ViewerGraph,
    selected: &mut Vec<usize>,
    selected_mask: &mut [bool],
    idx: usize,
    type_filter: &[String],
    force: bool,
) -> bool {
    if selected_mask.get(idx).copied().unwrap_or(true) {
        return false;
    }

    if !force
        && !graph
            .get_node(idx)
            .is_some_and(|node| node_matches_type_filter(node, type_filter))
    {
        return false;
    }

    selected_mask[idx] = true;
    selected.push(idx);
    true
}

fn select_focus_nodes(
    graph: &ViewerGraph,
    focus_idx: usize,
    node_limit: usize,
    type_filter: &[String],
) -> Vec<usize> {
    let total_nodes = graph.stats().total_nodes;
    let target = node_limit.max(1).min(total_nodes);
    let mut selected = Vec::with_capacity(target);
    let mut selected_mask = vec![false; total_nodes];

    push_selected_node(
        graph,
        &mut selected,
        &mut selected_mask,
        focus_idx,
        type_filter,
        true,
    );

    let mut incident = Vec::new();
    if let Some(edges) = graph.outgoing(focus_idx) {
        incident.extend(edges.iter().copied());
    }
    if let Some(edges) = graph.incoming(focus_idx) {
        incident.extend(edges.iter().copied());
    }
    incident.sort_by_key(|edge_idx| {
        graph.edge(*edge_idx).map_or((1u8, u32::MAX), |edge| {
            (
                if edge_is_important(&edge.relationship) {
                    0
                } else {
                    1
                },
                edge.cost,
            )
        })
    });

    for edge_idx in incident {
        if selected.len() >= target {
            break;
        }
        let Some(edge) = graph.edge(edge_idx) else {
            continue;
        };
        let neighbor = if edge.source == focus_idx {
            edge.target
        } else {
            edge.source
        };
        push_selected_node(
            graph,
            &mut selected,
            &mut selected_mask,
            neighbor,
            type_filter,
            false,
        );
    }

    if selected.len() < target {
        let first_hop = selected.clone();
        let mut second_hop_edges = Vec::new();
        for idx in first_hop {
            if let Some(edges) = graph.outgoing(idx) {
                second_hop_edges.extend(edges.iter().copied());
            }
            if let Some(edges) = graph.incoming(idx) {
                second_hop_edges.extend(edges.iter().copied());
            }
        }
        second_hop_edges.sort_by_key(|edge_idx| {
            graph.edge(*edge_idx).map_or((1u8, u32::MAX), |edge| {
                (
                    if edge_is_important(&edge.relationship) {
                        0
                    } else {
                        1
                    },
                    edge.cost,
                )
            })
        });

        for edge_idx in second_hop_edges {
            if selected.len() >= target {
                break;
            }
            let Some(edge) = graph.edge(edge_idx) else {
                continue;
            };
            if selected_mask.get(edge.source).copied().unwrap_or(false) {
                push_selected_node(
                    graph,
                    &mut selected,
                    &mut selected_mask,
                    edge.target,
                    type_filter,
                    false,
                );
            }
            if selected.len() >= target {
                break;
            }
            if selected_mask.get(edge.target).copied().unwrap_or(false) {
                push_selected_node(
                    graph,
                    &mut selected,
                    &mut selected_mask,
                    edge.source,
                    type_filter,
                    false,
                );
            }
        }
    }

    selected
}

fn edge_security_guidance(relationship: &str) -> (u8, &'static str) {
    match relationship.to_ascii_lowercase().as_str() {
        "genericall" => (
            1,
            "Full control. Common abuse paths include password reset, DACL edit, group modification, or shadow credentials. Capture the original state before changing anything.",
        ),
        "genericwrite" => (
            2,
            "Write access. Look for targeted Kerberoast, shadow credentials, SPN writes, logon script changes, or certificate mapping depending on the target type.",
        ),
        "writedacl" => (
            1,
            "DACL write. Add a tightly scoped ACE for the controlled principal, perform the operation, then restore the original ACL from your notes.",
        ),
        "writeowner" | "owns" => (
            1,
            "Ownership control. Taking ownership usually enables a follow-up DACL write; preserve current owner and restore it after validation.",
        ),
        "forcechangepassword" => (
            2,
            "Password reset edge. Useful for takeover but noisy; prefer a maintenance window or controlled lab validation when possible.",
        ),
        "addmembers" | "addself" => (
            2,
            "Group membership control. Add only the required principal and remove it quickly after the dependent action completes.",
        ),
        "allextendedrights" => (
            1,
            "Extended rights. On users this can enable password reset; on domain objects it may combine with replication rights for DCSync.",
        ),
        "getchanges" | "getchangesall" | "getchangesinfilteredset" | "dcsync" => (
            1,
            "Replication rights. Validate whether the principal can perform DCSync and treat the target as domain-impacting.",
        ),
        "readlapspassword" => (
            2,
            "LAPS read. Recover local admin material for the target computer, then prefer remote management paths that match the engagement rules.",
        ),
        "readgmsapassword" => (
            2,
            "gMSA read. Derive the managed account secret and map where that service identity has reach before using it.",
        ),
        "allowedtoact" => (
            1,
            "Resource-based constrained delegation. Pair with a controlled machine account to impersonate to the target service.",
        ),
        "allowedtodelegate" => (
            2,
            "Constrained delegation. Enumerate allowed services and test S4U paths against the target with minimal ticket requests.",
        ),
        "adminto" => (
            2,
            "Local admin. Prefer stealthy execution choices, avoid broad service creation, and document the host-specific evidence.",
        ),
        "canrdp" => (
            3,
            "Interactive logon. Useful for validation but visible; prefer non-interactive checks unless the scenario requires RDP.",
        ),
        "canpsremote" => (
            3,
            "PowerShell Remoting. Validate WinRM reachability and use constrained, low-volume commands.",
        ),
        "executedcom" => (
            3,
            "DCOM execution. Can be loud on EDR; reserve for approved execution phases and collect host telemetry expectations first.",
        ),
        "sqladmin" => (
            2,
            "SQL admin. Check linked servers, xp_cmdshell state, impersonation chains, and database trust relationships.",
        ),
        "hasspn" => (
            4,
            "Kerberoast marker. Request only scoped service tickets and prioritize high-value or weakly managed service accounts.",
        ),
        "dontreqpreauth" => (
            4,
            "AS-REP roast marker. Offline attack path; avoid repeated online queries after collecting the roastable principal list.",
        ),
        "gpoadmin" | "gpolink" | "gpocontributor" => (
            2,
            "GPO control. Review linked OUs and security filtering before changing policy; use rollback-ready edits.",
        ),
        "trustedby" | "trustedtoauth" => (
            2,
            "Trust relationship. Confirm direction, SID filtering, selective auth, and transitive scope before planning cross-domain movement.",
        ),
        "memberoftierzero" | "memberoftier0" => (
            1,
            "Tier-zero membership path. Treat as domain-impacting and verify nested group expansion carefully.",
        ),
        "memberof" => (
            5,
            "Membership edge. Usually context, but nested high-value memberships can become the bridge to privilege.",
        ),
        "contains" => (
            5,
            "Containment edge. Useful for scoping GPO inheritance, OU ownership, and where principals live.",
        ),
        _ => (
            4,
            "Review the ACE or relationship properties, confirm directionality, and validate the exact abuse primitive before acting.",
        ),
    }
}

fn edge_response(graph: &ViewerGraph, edge: &ViewerEdge) -> Option<EdgeResponse> {
    let src = graph.get_node(edge.source)?;
    let tgt = graph.get_node(edge.target)?;
    let (severity, guidance) = edge_security_guidance(&edge.relationship);
    Some(EdgeResponse {
        source: src.id.clone(),
        target: tgt.id.clone(),
        relationship: edge.relationship.clone(),
        cost: edge.cost,
        severity,
        guidance: guidance.to_string(),
    })
}

fn node_security_notes(graph: &ViewerGraph, node_idx: usize) -> Vec<DetailNote> {
    let mut notes = Vec::new();
    let mut seen = HashSet::new();

    for edge_idx in graph
        .outgoing(node_idx)
        .into_iter()
        .flatten()
        .chain(graph.incoming(node_idx).into_iter().flatten())
    {
        let Some(edge) = graph.edge(*edge_idx) else {
            continue;
        };
        let (severity, guidance) = edge_security_guidance(&edge.relationship);
        if severity > 3 || !seen.insert(edge.relationship.to_ascii_lowercase()) {
            continue;
        }
        notes.push(DetailNote {
            title: format!("{} relationship", edge.relationship),
            severity,
            body: guidance.to_string(),
        });
        if notes.len() >= 8 {
            break;
        }
    }

    if let Some(node) = graph.get_node(node_idx) {
        for (key, value) in &node.properties {
            let lower = key.to_ascii_lowercase();
            if lower.contains("aces")
                || lower.contains("acl")
                || lower.contains("owner")
                || lower.contains("dacl")
            {
                if value.trim().is_empty() || value == "0" {
                    continue;
                }
                notes.push(DetailNote {
                    title: key.clone(),
                    severity: 3,
                    body: format!(
                        "{}. Review the raw value, identify trustee/object type/inherited scope, and prefer reversible changes.",
                        value
                    ),
                });
                if notes.len() >= 12 {
                    break;
                }
            }
        }
    }

    notes
}

fn resolve_bundle<'a>(
    state: &'a AppState,
    graph_id: Option<&str>,
) -> Result<&'a GraphBundle, StatusCode> {
    if let Some(id) = graph_id {
        return state
            .graphs
            .iter()
            .find(|graph| graph.id == id)
            .ok_or(StatusCode::NOT_FOUND);
    }

    state
        .graphs
        .iter()
        .find(|graph| graph.id == state.default_graph)
        .or_else(|| state.graphs.first())
        .ok_or(StatusCode::NOT_FOUND)
}

async fn load_graph(
    state: &AppState,
    graph_id: Option<&str>,
) -> Result<(GraphBundle, Arc<ViewerGraph>), StatusCode> {
    let bundle = resolve_bundle(state, graph_id)?.clone();

    if let Some(graph) = state.cache.read().await.get(&bundle.id).cloned() {
        return Ok((bundle, graph));
    }

    let mut cache = state.cache.write().await;
    if let Some(graph) = cache.get(&bundle.id).cloned() {
        return Ok((bundle, graph));
    }

    let graph = ViewerGraph::from_sources(&bundle.sources).map_err(|e| {
        warn!("failed to load graph {}: {}", bundle.label, e);
        StatusCode::UNPROCESSABLE_ENTITY
    })?;
    let graph = Arc::new(graph);
    cache.insert(bundle.id.clone(), Arc::clone(&graph));
    Ok((bundle, graph))
}

fn graph_label_from_source(source: &str) -> String {
    let path = Path::new(source);
    if path.is_dir() {
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(source)
            .to_string()
    } else {
        path.file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or(source)
            .to_string()
    }
}

fn graph_id_from_label(label: &str) -> String {
    let mut id = String::new();
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            id.push(ch.to_ascii_lowercase());
        } else if matches!(ch, ' ' | '-' | '_' | '.') && !id.ends_with('-') {
            id.push('-');
        }
    }
    id.trim_matches('-').to_string()
}

fn expand_graph_sources(sources: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for source in sources {
        let path = PathBuf::from(source);
        if !path.exists() {
            return Err(anyhow!("graph source does not exist: {}", path.display()));
        }

        if path.is_dir() {
            let mut entries = fs::read_dir(&path)?
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

fn build_graph_bundles(sources: &[String]) -> Result<Vec<GraphBundle>> {
    if sources.is_empty() {
        return Err(anyhow!("no graph sources provided"));
    }

    let mut bundles = Vec::new();
    let mut seen_ids = HashSet::new();
    let paths = expand_graph_sources(sources)?;

    if paths.is_empty() {
        return Err(anyhow!("no JSON graph files found in the provided input"));
    }

    for (idx, path) in paths.iter().enumerate() {
        let source = path.display().to_string();
        let label = graph_label_from_source(&source);
        let mut base_id = graph_id_from_label(&label);
        if base_id.is_empty() {
            base_id = format!("graph-{}", idx + 1);
        }
        let mut graph_id = base_id.clone();
        let mut counter = 2;
        while seen_ids.contains(&graph_id) {
            graph_id = format!("{}-{}", base_id, counter);
            counter += 1;
        }
        seen_ids.insert(graph_id.clone());

        bundles.push(GraphBundle {
            id: graph_id,
            label,
            sources: vec![source],
            file_bytes: fs::metadata(path).map(|meta| meta.len()).unwrap_or(0),
        });
    }

    Ok(bundles)
}

fn graph_nodes(graph: &ViewerGraph, selected: &HashSet<usize>) -> Vec<NodeResponse> {
    graph
        .nodes()
        .filter_map(|(idx, node)| {
            if !selected.contains(&idx) {
                return None;
            }
            Some(NodeResponse {
                id: node.id.clone(),
                label: node.label.clone(),
                display_name: node_display_name(node),
                node_type: node_type_str(node),
                domain: node_domain(node),
                distinguished_name: node.distinguished_name.clone(),
                enabled: node.enabled,
                high_value: node.high_value,
                owned: node.owned,
            })
        })
        .collect()
}

fn graph_edges(
    graph: &ViewerGraph,
    selected: &HashSet<usize>,
    edge_limit: usize,
) -> Vec<EdgeResponse> {
    let mut important = Vec::new();
    let mut normal = Vec::new();

    for edge in graph.edges() {
        if !selected.contains(&edge.source) || !selected.contains(&edge.target) {
            continue;
        }
        let Some(response) = edge_response(graph, edge) else {
            continue;
        };
        if edge_is_important(&edge.relationship) {
            important.push(response);
        } else {
            normal.push(response);
        }
    }

    let total = important.len() + normal.len();
    let target = edge_limit.min(total);
    let mut edges = Vec::with_capacity(target);
    edges.extend(important.into_iter().take(target));
    if edges.len() < target {
        edges.extend(normal.into_iter().take(target - edges.len()));
    }

    edges
}

fn path_response(graph: &ViewerGraph, path: PathResult) -> PathResponse {
    let source = graph.get_node(path.source_idx);
    let target = graph.get_node(path.target_idx);
    let mut selected_set = HashSet::new();
    selected_set.insert(path.source_idx);
    selected_set.insert(path.target_idx);
    for hop in &path.hops {
        selected_set.insert(hop.source_idx);
        selected_set.insert(hop.target_idx);
    }

    let nodes = graph_nodes(graph, &selected_set);
    let edges: Vec<EdgeResponse> = path
        .hops
        .iter()
        .filter_map(|hop| {
            graph
                .edges()
                .find(|edge| {
                    edge.source == hop.source_idx
                        && edge.target == hop.target_idx
                        && edge.relationship == hop.relationship
                })
                .and_then(|edge| edge_response(graph, edge))
        })
        .collect();

    let (source_id, source_label, source_display, source_type) = source
        .map(|node| {
            (
                node.id.clone(),
                node.label.clone(),
                node_display_name(node),
                node_type_str(node),
            )
        })
        .unwrap_or_else(|| {
            (
                String::new(),
                String::new(),
                String::new(),
                "Unknown".to_string(),
            )
        });

    let (target_id, target_label, target_display, target_type) = target
        .map(|node| {
            (
                node.id.clone(),
                node.label.clone(),
                node_display_name(node),
                node_type_str(node),
            )
        })
        .unwrap_or_else(|| {
            (
                String::new(),
                String::new(),
                String::new(),
                "Unknown".to_string(),
            )
        });

    let hops: Vec<HopResponse> = path
        .hops
        .into_iter()
        .filter_map(|hop| {
            let source_node = graph.get_node(hop.source_idx)?;
            let target_node = graph.get_node(hop.target_idx)?;
            let (severity, guidance) = edge_security_guidance(&hop.relationship);
            Some(HopResponse {
                source_id: source_node.id.clone(),
                source_label: source_node.label.clone(),
                source_display: node_display_name(source_node),
                source_type: node_type_str(source_node),
                target_id: target_node.id.clone(),
                target_label: target_node.label.clone(),
                target_display: node_display_name(target_node),
                target_type: node_type_str(target_node),
                relationship: hop.relationship,
                cost: hop.cost,
                severity,
                guidance: guidance.to_string(),
            })
        })
        .collect();
    let rendered_nodes = nodes.len();
    let rendered_edges = edges.len();

    PathResponse {
        found: true,
        source_id,
        source_label,
        source_display,
        source_type,
        target_id,
        target_label,
        target_display,
        target_type,
        stats: stats_response(graph.stats()),
        rendered_nodes,
        rendered_edges,
        truncated: rendered_nodes < graph.stats().total_nodes
            || rendered_edges < graph.stats().total_edges,
        node_limit: rendered_nodes,
        edge_limit: rendered_edges,
        total_cost: path.total_cost,
        hop_count: hops.len(),
        hops,
        nodes,
        edges,
    }
}

// ============================================================
//  Route Handlers
// ============================================================

/// GET / — Serve the embedded SPA
async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// GET /api/graphs — List available graphs
async fn list_graphs(State(state): State<Arc<AppState>>) -> Json<Vec<GraphInfo>> {
    let cache = state.cache.read().await;
    let graphs = state
        .graphs
        .iter()
        .map(|bundle| {
            let cached = cache.get(&bundle.id);
            GraphInfo {
                id: bundle.id.clone(),
                label: bundle.label.clone(),
                sources: bundle.sources.clone(),
                file_bytes: bundle.file_bytes,
                loaded: cached.is_some(),
                stats: cached.map(|graph| stats_response(graph.stats())),
            }
        })
        .collect();

    Json(graphs)
}

/// GET /api/graph — Full graph data for D3 rendering
async fn get_graph(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<GraphResponse>, StatusCode> {
    let (bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;

    let total_nodes = graph.stats().total_nodes;
    let total_edges = graph.stats().total_edges;
    let type_filter = parse_type_filter(query.types.as_deref());
    let node_limit = resolve_node_limit(query.limit, total_nodes);
    let edge_limit = resolve_edge_limit(query.edges, node_limit, total_nodes, total_edges);
    let selected_nodes = if let Some(focus) = query.focus.as_deref() {
        let focus_idx = graph.resolve_node(focus).ok_or(StatusCode::NOT_FOUND)?;
        select_focus_nodes(&graph, focus_idx, node_limit, &type_filter)
    } else {
        select_graph_nodes(&graph, node_limit, &type_filter)
    };
    let selected_set: HashSet<usize> = selected_nodes.into_iter().collect();

    let nodes = graph_nodes(&graph, &selected_set);
    let edges = graph_edges(&graph, &selected_set, edge_limit);
    let truncated = nodes.len() < total_nodes || edges.len() < total_edges;

    Ok(Json(GraphResponse {
        graph_id: bundle.id.clone(),
        label: bundle.label.clone(),
        sources: bundle.sources.clone(),
        stats: stats_response(graph.stats()),
        rendered_nodes: nodes.len(),
        rendered_edges: edges.len(),
        truncated,
        node_limit,
        edge_limit,
        nodes,
        edges,
    }))
}

/// GET /api/node/:id — Detail view for a single node
async fn get_node_detail(
    State(state): State<Arc<AppState>>,
    AxumPath(nid): AxumPath<String>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<NodeDetail>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;

    let node_idx = graph.resolve_node(&nid).ok_or(StatusCode::NOT_FOUND)?;
    let node = graph.get_node(node_idx).ok_or(StatusCode::NOT_FOUND)?;

    let mut connections = Vec::new();

    for edge_idx in graph.outgoing(node_idx).into_iter().flatten() {
        let Some(edge) = graph.edge(*edge_idx) else {
            continue;
        };
        if let Some(tgt) = graph.get_node(edge.target) {
            connections.push(Connection {
                target_id: tgt.id.clone(),
                target_label: tgt.label.clone(),
                target_display: node_display_name(tgt),
                target_type: node_type_str(tgt),
                target_domain: node_domain(tgt),
                relationship: edge.relationship.clone(),
                direction: "outgoing".to_string(),
                cost: edge.cost,
                severity: edge_security_guidance(&edge.relationship).0,
                guidance: edge_security_guidance(&edge.relationship).1.to_string(),
                properties: edge.properties.clone(),
            });
        }
    }

    for edge_idx in graph.incoming(node_idx).into_iter().flatten() {
        let Some(edge) = graph.edge(*edge_idx) else {
            continue;
        };
        if let Some(src) = graph.get_node(edge.source) {
            connections.push(Connection {
                target_id: src.id.clone(),
                target_label: src.label.clone(),
                target_display: node_display_name(src),
                target_type: node_type_str(src),
                target_domain: node_domain(src),
                relationship: edge.relationship.clone(),
                direction: "incoming".to_string(),
                cost: edge.cost,
                severity: edge_security_guidance(&edge.relationship).0,
                guidance: edge_security_guidance(&edge.relationship).1.to_string(),
                properties: edge.properties.clone(),
            });
        }
    }

    Ok(Json(NodeDetail {
        id: node.id.clone(),
        label: node.label.clone(),
        display_name: node_display_name(node),
        node_type: node_type_str(node),
        domain: node_domain(node),
        distinguished_name: node.distinguished_name.clone(),
        enabled: node.enabled,
        high_value: node.high_value,
        owned: node.owned,
        properties: node.properties.clone(),
        security_notes: node_security_notes(&graph, node_idx),
        connections,
    }))
}

/// GET /api/search?q=... — Search nodes by name
async fn search_nodes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;
    let type_filter = parse_type_filter(query.types.as_deref());
    let limit = query.limit.unwrap_or(75).clamp(1, 100);

    let results: Vec<SearchResult> = graph
        .search_nodes(&query.q, &type_filter, limit)
        .into_iter()
        .filter_map(|idx| graph.get_node(idx))
        .map(|node| SearchResult {
            id: node.id.clone(),
            label: node.label.clone(),
            display_name: node_display_name(node),
            node_type: node_type_str(node),
            domain: node_domain(node),
        })
        .collect();

    Ok(Json(results))
}

/// POST /api/path — Find shortest attack path between two nodes
async fn find_path(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
    Json(req): Json<PathRequest>,
) -> Result<Json<PathResponse>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;

    if let Some(path) = graph.shortest_path(&req.from, &req.to) {
        return Ok(Json(path_response(&graph, path)));
    }

    Ok(Json(PathResponse {
        found: false,
        source_id: req.from.clone(),
        source_label: req.from.clone(),
        source_display: req.from.clone(),
        source_type: "Unknown".to_string(),
        target_id: req.to.clone(),
        target_label: req.to.clone(),
        target_display: req.to.clone(),
        target_type: "Unknown".to_string(),
        stats: stats_response(graph.stats()),
        rendered_nodes: 0,
        rendered_edges: 0,
        truncated: graph.stats().total_nodes > 0 || graph.stats().total_edges > 0,
        node_limit: 0,
        edge_limit: 0,
        total_cost: 0,
        hop_count: 0,
        hops: Vec::new(),
        nodes: Vec::new(),
        edges: Vec::new(),
    }))
}

/// GET /api/stats — Quick stats summary
async fn get_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<StatsResponse>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;
    Ok(Json(stats_response(graph.stats())))
}

// ============================================================
//  Public API
// ============================================================

/// Launch the viewer web server.
///
/// Loads the graph from the given sources, starts an Axum HTTP server on the
/// specified port (or a free port if 0), and opens the browser.
pub async fn launch(sources: &[String], port: u16) -> Result<()> {
    let graphs = build_graph_bundles(sources)?;

    for graph in &graphs {
        info!(
            "Indexed graph {}: {} bytes from {}",
            graph.label,
            graph.file_bytes,
            graph.sources.join(", ")
        );
    }

    let default_graph = graphs
        .first()
        .map(|graph| graph.id.clone())
        .unwrap_or_else(|| "graph-1".to_string());

    let state = Arc::new(AppState {
        graphs,
        default_graph,
        cache: RwLock::new(HashMap::new()),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(index))
        .route("/api/graphs", get(list_graphs))
        .route("/api/graph", get(get_graph))
        .route("/api/node/{node_id}", get(get_node_detail))
        .route("/api/search", get(search_nodes))
        .route("/api/path", post(find_path))
        .route("/api/stats", get(get_stats))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;
    let url = format!("http://{}", actual_addr);

    info!("Graph viewer running at {}", url);
    println!("\n  Overthrone Graph Viewer");
    println!("  ------------------------");
    println!("  {}", url);
    println!("  Press Ctrl+C to stop.\n");

    // Open browser (non-blocking, ignore errors)
    let _ = open::that(&url);

    axum::serve(listener, app).await?;
    Ok(())
}
