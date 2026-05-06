//! Embedded web server for the graph viewer.
//!
//! Serves a single-page BloodHound-style application with D3.js force-directed
//! graph visualization, node search, attack path finder, and detail panels.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::graph_data::{PathResult, ViewerGraph, ViewerNode, ViewerStats};

/// Embedded HTML content (built from static/index.html)
const INDEX_HTML: &str = include_str!("static/index.html");

/// Loaded graph bundle
struct GraphBundle {
    id: String,
    label: String,
    sources: Vec<String>,
    graph: Arc<ViewerGraph>,
}

/// Shared application state
struct AppState {
    graphs: Vec<GraphBundle>,
    default_graph: String,
}

// ============================================================
//  API Response Types
// ============================================================

#[derive(Serialize)]
struct GraphInfo {
    id: String,
    label: String,
    sources: Vec<String>,
    stats: StatsResponse,
}

#[derive(Serialize)]
struct GraphResponse {
    graph_id: String,
    label: String,
    sources: Vec<String>,
    stats: StatsResponse,
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
    total_cost: u32,
    hop_count: usize,
    hops: Vec<HopResponse>,
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
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    graph: Option<String>,
}

#[derive(Deserialize)]
struct GraphQuery {
    graph: Option<String>,
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

fn resolve_graph<'a>(
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

fn build_graph_bundles(sources: &[String]) -> Result<Vec<GraphBundle>> {
    if sources.is_empty() {
        return Err(anyhow!("no graph sources provided"));
    }

    let mut bundles = Vec::new();
    let mut seen_ids = HashSet::new();

    for (idx, source) in sources.iter().enumerate() {
        let graph =
            ViewerGraph::from_sources(std::slice::from_ref(source)).map_err(|e| anyhow!(e))?;
        let label = graph_label_from_source(source);
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
            sources: graph.sources().to_vec(),
            graph: Arc::new(graph),
        });
    }

    Ok(bundles)
}

fn graph_nodes(graph: &ViewerGraph) -> Vec<NodeResponse> {
    graph
        .nodes()
        .map(|(_, node)| NodeResponse {
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
        .collect()
}

fn graph_edges(graph: &ViewerGraph) -> Vec<EdgeResponse> {
    graph
        .edges()
        .filter_map(|edge| {
            let src = graph.get_node(edge.source)?;
            let tgt = graph.get_node(edge.target)?;
            Some(EdgeResponse {
                source: src.id.clone(),
                target: tgt.id.clone(),
                relationship: edge.relationship.clone(),
                cost: edge.cost,
            })
        })
        .collect()
}

fn path_response(graph: &ViewerGraph, path: PathResult) -> PathResponse {
    let source = graph.get_node(path.source_idx);
    let target = graph.get_node(path.target_idx);

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
            })
        })
        .collect();

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
        total_cost: path.total_cost,
        hop_count: hops.len(),
        hops,
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
    let graphs = state
        .graphs
        .iter()
        .map(|graph| GraphInfo {
            id: graph.id.clone(),
            label: graph.label.clone(),
            sources: graph.sources.clone(),
            stats: stats_response(graph.graph.stats()),
        })
        .collect();

    Json(graphs)
}

/// GET /api/graph — Full graph data for D3 rendering
async fn get_graph(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<GraphResponse>, StatusCode> {
    let bundle = resolve_graph(&state, query.graph.as_deref())?;
    let graph = &bundle.graph;

    Ok(Json(GraphResponse {
        graph_id: bundle.id.clone(),
        label: bundle.label.clone(),
        sources: bundle.sources.clone(),
        stats: stats_response(graph.stats()),
        nodes: graph_nodes(graph),
        edges: graph_edges(graph),
    }))
}

/// GET /api/node/:id — Detail view for a single node
async fn get_node_detail(
    State(state): State<Arc<AppState>>,
    AxumPath(nid): AxumPath<String>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<NodeDetail>, StatusCode> {
    let bundle = resolve_graph(&state, query.graph.as_deref())?;
    let graph = &bundle.graph;

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
        connections,
    }))
}

/// GET /api/search?q=... — Search nodes by name
async fn search_nodes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    let bundle = resolve_graph(&state, query.graph.as_deref())?;
    let graph = &bundle.graph;
    let q = query.q.trim().to_ascii_uppercase();

    let results: Vec<SearchResult> = graph
        .nodes()
        .filter(|(_, node)| {
            node.label.to_ascii_uppercase().contains(&q)
                || node.id.to_ascii_uppercase().contains(&q)
                || node
                    .domain
                    .as_ref()
                    .is_some_and(|domain| domain.to_ascii_uppercase().contains(&q))
                || node
                    .distinguished_name
                    .as_ref()
                    .is_some_and(|dn| dn.to_ascii_uppercase().contains(&q))
        })
        .take(75)
        .map(|(_, node)| SearchResult {
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
    let bundle = resolve_graph(&state, query.graph.as_deref())?;
    let graph = &bundle.graph;

    if let Some(path) = graph.shortest_path(&req.from, &req.to) {
        return Ok(Json(path_response(graph, path)));
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
        total_cost: 0,
        hop_count: 0,
        hops: Vec::new(),
    }))
}

/// GET /api/stats — Quick stats summary
async fn get_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<StatsResponse>, StatusCode> {
    let bundle = resolve_graph(&state, query.graph.as_deref())?;
    Ok(Json(stats_response(bundle.graph.stats())))
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
        let stats = graph.graph.stats();
        info!(
            "Loaded graph {}: {} nodes, {} edges",
            graph.label, stats.total_nodes, stats.total_edges
        );
    }

    let default_graph = graphs
        .first()
        .map(|graph| graph.id.clone())
        .unwrap_or_else(|| "graph-1".to_string());

    let state = Arc::new(AppState {
        graphs,
        default_graph,
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
