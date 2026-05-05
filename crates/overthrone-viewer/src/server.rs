//! Embedded web server for the graph viewer.
//!
//! Serves a single-page BloodHound-style application with D3.js force-directed
//! graph visualization, node search, attack path finder, and detail panels.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use overthrone_core::graph::{AttackGraph, EdgeRef, NodeType};

/// Embedded HTML content (built from static/index.html)
const INDEX_HTML: &str = include_str!("static/index.html");

/// Shared application state
struct AppState {
    graph: Arc<AttackGraph>,
}

// ============================================================
//  API Response Types
// ============================================================

#[derive(Serialize)]
struct GraphResponse {
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
}

#[derive(Serialize)]
struct NodeResponse {
    id: String,
    label: String,
    #[serde(rename = "type")]
    node_type: String,
    domain: String,
    enabled: bool,
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
    #[serde(rename = "type")]
    node_type: String,
    domain: String,
    enabled: bool,
    properties: std::collections::HashMap<String, String>,
    connections: Vec<Connection>,
}

#[derive(Serialize)]
struct Connection {
    target: String,
    relationship: String,
    direction: String,
}

#[derive(Serialize)]
struct SearchResult {
    id: String,
    label: String,
    #[serde(rename = "type")]
    node_type: String,
}

#[derive(Deserialize)]
struct PathRequest {
    from: String,
    to: String,
}

#[derive(Serialize)]
struct PathResponse {
    found: bool,
    source: String,
    target: String,
    total_cost: u32,
    hop_count: usize,
    hops: Vec<HopResponse>,
}

#[derive(Serialize)]
struct HopResponse {
    source: String,
    source_type: String,
    target: String,
    target_type: String,
    relationship: String,
    cost: u32,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

// ============================================================
//  Helpers
// ============================================================

/// Build "NAME@DOMAIN" identifier for a node
fn node_id(name: &str, domain: &str) -> String {
    format!("{}@{}", name, domain)
}

/// Convert NodeType enum to string
fn node_type_str(nt: &NodeType) -> String {
    match nt {
        NodeType::User => "User",
        NodeType::Computer => "Computer",
        NodeType::Group => "Group",
        NodeType::Domain => "Domain",
        NodeType::Gpo => "GPO",
        NodeType::Ou => "OU",
        NodeType::CertTemplate => "CertTemplate",
    }
    .to_string()
}

// ============================================================
//  Route Handlers
// ============================================================

/// GET / — Serve the embedded SPA
async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// GET /api/graph — Full graph data for D3 rendering
async fn get_graph(State(state): State<Arc<AppState>>) -> Json<GraphResponse> {
    let graph = &state.graph;
    let stats = graph.stats();

    let nodes: Vec<NodeResponse> = graph
        .nodes()
        .map(|(_, node)| NodeResponse {
            id: node_id(&node.name, &node.domain),
            label: node.name.clone(),
            node_type: node_type_str(&node.node_type),
            domain: node.domain.clone(),
            enabled: node.enabled,
        })
        .collect();

    let edges: Vec<EdgeResponse> = graph
        .edges()
        .map(|edge_ref| {
            let src = graph.get_node(edge_ref.source()).unwrap();
            let tgt = graph.get_node(edge_ref.target()).unwrap();
            EdgeResponse {
                source: node_id(&src.name, &src.domain),
                target: node_id(&tgt.name, &tgt.domain),
                relationship: format!("{}", edge_ref.weight()),
                cost: edge_ref.weight().default_cost(),
            }
        })
        .collect();

    Json(GraphResponse {
        stats: StatsResponse {
            total_nodes: stats.total_nodes,
            total_edges: stats.total_edges,
            users: stats.users,
            computers: stats.computers,
            groups: stats.groups,
            domains: stats.domains,
            gpos: stats.gpos,
            ous: stats.ous,
            cert_templates: stats.cert_templates,
        },
        nodes,
        edges,
    })
}

/// GET /api/node/:id — Detail view for a single node
async fn get_node_detail(
    State(state): State<Arc<AppState>>,
    Path(nid): Path<String>,
) -> Result<Json<NodeDetail>, StatusCode> {
    let graph = &state.graph;

    let node_idx = graph.find_node(&nid).ok_or(StatusCode::NOT_FOUND)?;
    let node = graph.get_node(node_idx).ok_or(StatusCode::NOT_FOUND)?;

    let id = node_id(&node.name, &node.domain);

    // Collect outgoing connections
    let mut connections = Vec::new();
    for edge_ref in graph.edges_from(node_idx) {
        if let Some(tgt) = graph.get_node(edge_ref.target()) {
            connections.push(Connection {
                target: node_id(&tgt.name, &tgt.domain),
                relationship: format!("{}", edge_ref.weight()),
                direction: "outgoing".to_string(),
            });
        }
    }

    // Collect incoming connections
    for edge_ref in graph.edges_to(node_idx) {
        if let Some(src) = graph.get_node(edge_ref.source()) {
            connections.push(Connection {
                target: node_id(&src.name, &src.domain),
                relationship: format!("{}", edge_ref.weight()),
                direction: "incoming".to_string(),
            });
        }
    }

    Ok(Json(NodeDetail {
        id,
        label: node.name.clone(),
        node_type: node_type_str(&node.node_type),
        domain: node.domain.clone(),
        enabled: node.enabled,
        properties: node.properties.clone(),
        connections,
    }))
}

/// GET /api/search?q=... — Search nodes by name
async fn search_nodes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Json<Vec<SearchResult>> {
    let graph = &state.graph;
    let q = query.q.to_uppercase();

    let results: Vec<SearchResult> = graph
        .nodes()
        .filter(|(_, node)| {
            node.name.to_uppercase().contains(&q) || node.domain.to_uppercase().contains(&q)
        })
        .take(50)
        .map(|(_, node)| SearchResult {
            id: node_id(&node.name, &node.domain),
            label: node.name.clone(),
            node_type: node_type_str(&node.node_type),
        })
        .collect();

    Json(results)
}

/// POST /api/path — Find shortest attack path between two nodes
async fn find_path(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PathRequest>,
) -> Json<PathResponse> {
    let graph = &state.graph;

    match graph.shortest_path(&req.from, &req.to) {
        Ok(path) => Json(PathResponse {
            found: true,
            source: path.source,
            target: path.target,
            total_cost: path.total_cost,
            hop_count: path.hop_count,
            hops: path
                .hops
                .into_iter()
                .map(|hop| HopResponse {
                    source: hop.source,
                    source_type: format!("{}", hop.source_type),
                    target: hop.target,
                    target_type: format!("{}", hop.target_type),
                    relationship: format!("{}", hop.edge),
                    cost: hop.cost,
                })
                .collect(),
        }),
        Err(_) => Json(PathResponse {
            found: false,
            source: req.from,
            target: req.to,
            total_cost: 0,
            hop_count: 0,
            hops: Vec::new(),
        }),
    }
}

/// GET /api/stats — Quick stats summary
async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let stats = state.graph.stats();
    Json(StatsResponse {
        total_nodes: stats.total_nodes,
        total_edges: stats.total_edges,
        users: stats.users,
        computers: stats.computers,
        groups: stats.groups,
        domains: stats.domains,
        gpos: stats.gpos,
        ous: stats.ous,
        cert_templates: stats.cert_templates,
    })
}

// ============================================================
//  Public API
// ============================================================

/// Launch the viewer web server.
///
/// Loads the graph from the given path, starts an Axum HTTP server on the
/// specified port (or a free port if 0), and opens the browser.
pub async fn launch(graph_path: &str, port: u16) -> Result<()> {
    let graph = AttackGraph::from_json_path(graph_path)?;
    let stats = graph.stats();
    info!(
        "Loaded graph: {} nodes, {} edges",
        stats.total_nodes, stats.total_edges
    );

    let state = Arc::new(AppState {
        graph: Arc::new(graph),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(index))
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
    println!("\n  🩸 Overthrone Graph Viewer");
    println!("  ─────────────────────────");
    println!("  🌐 {}", url);
    println!("  Press Ctrl+C to stop.\n");

    // Open browser (non-blocking, ignore errors)
    let _ = open::that(&url);

    axum::serve(listener, app).await?;
    Ok(())
}
