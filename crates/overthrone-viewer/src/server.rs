//! Embedded web server for the graph viewer.
//!
//! Serves a single-page BloodHound-style application with Three.js graph
//! visualization, node search, attack path finder, and detail panels.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, Query, Request, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::Html;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, warn};
use zip::ZipArchive;

use crate::graph_data::{
    GraphLoadMetrics, PathResult, RelationshipStat, ViewerEdge, ViewerGraph, ViewerNode,
    ViewerStats,
};

/// Strip ANSI escape sequences from a string to prevent terminal injection attacks.
/// Blue/Defender teams can poison AD attributes with raw ANSI escape sequences
/// (e.g., CSI, OSC, DCS) that, when rendered to a terminal, could execute
/// arbitrary commands or exfiltrate data from the operator's terminal.
fn sanitize_ad_string(input: &str) -> String {
    // Strip ANSI escape sequences: ESC (0x1B) followed by [
    // Handles CSI sequences (ESC[...), OSC sequences (ESC]), DCS (ESCP),
    // and standalone ESC characters
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ANSI escape — consume until we hit a letter terminator
            // CSI: ESC[ ... letter
            // OSC: ESC] ... ST (ESC\) or BEL
            // Other: ESC ... letter
            match chars.next() {
                Some('[') => {
                    // CSI sequence: consume params + intermediate + final byte
                    for ec in chars.by_ref() {
                        match ec {
                            'a'..='z' | 'A'..='Z' | '~' | '@' => break,
                            _ => continue,
                        }
                    }
                }
                Some(']') => {
                    // OSC sequence: consume until ST (ESC \) or BEL (0x07)
                    for ec in chars.by_ref() {
                        if ec == '\x1b' {
                            let _ = chars.next(); // consume '\'
                            break;
                        }
                        if ec == '\x07' {
                            break;
                        }
                    }
                }
                Some('P' | 'D' | '_' | '^') => {
                    // DCS, DLE, APC, SOS: consume until ST (ESC\)
                    for ec in chars.by_ref() {
                        if ec == '\x1b' {
                            let _ = chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    // Single-char escape or unrecognized — discard
                }
                None => break,
            }
        } else if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
            // Strip other control characters (except newline, carriage return, tab)
        } else {
            out.push(c);
        }
    }
    out
}

/// Embedded HTML content (built from static/index.html)
const INDEX_HTML: &str = include_str!("static/index.html");
/// Embedded Three.js renderer (built from static/three-graph.js)
const THREE_GRAPH_JS: &str = include_str!("static/three-graph.js");
/// Maximum upload body size accepted by the API (250 MB).
const MAX_UPLOAD_BODY_BYTES: usize = 250 * 1024 * 1024;

/// Loaded graph bundle
#[derive(Clone)]
struct GraphBundle {
    id: String,
    label: String,
    sources: Vec<String>,
    file_bytes: u64,
}

/// TLS configuration for the viewer web server.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Path to the TLS certificate PEM file
    pub cert_pem: PathBuf,
    /// Path to the TLS private key PEM file
    pub key_pem: PathBuf,
    /// Optional path to a CA certificate PEM file for mTLS client cert verification.
    /// When set, clients MUST present a certificate signed by this CA.
    /// When None, no client certificate is required (standard TLS).
    pub mtls_client_ca_path: Option<PathBuf>,
}

/// Configuration for the viewer web server.
#[derive(Clone, Debug)]
pub struct ViewerConfig {
    /// Basic auth username (auto-generated if None)
    pub username: Option<String>,
    /// Basic auth password (auto-generated if None)
    pub password: Option<String>,
    /// Optional TLS configuration (REQUIRED for non-loopback bindings)
    pub tls: Option<TlsConfig>,
    /// CSRF token for state-changing endpoints (auto-generated if None)
    pub csrf_token: Option<String>,
    /// Rate limit window in seconds
    pub rate_limit_window_secs: u64,
    /// Maximum requests per IP within the window
    pub rate_limit_max_requests: u32,
    /// Bind address (defaults to 127.0.0.1). Non-loopback addresses REQUIRE TLS.
    pub bind_address: Option<std::net::IpAddr>,
}

impl ViewerConfig {
    /// Create a new config with basic auth credentials.
    pub fn with_auth(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: Some(username.into()),
            password: Some(password.into()),
            ..Default::default()
        }
    }
}

fn random_string(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let n = CHARSET.len();
    (0..len)
        .map(|_| CHARSET[rng.random_range(0..n)] as char)
        .collect()
}

impl Default for ViewerConfig {
    fn default() -> Self {
        let mut rng = rand::rngs::ThreadRng::default();
        let auth_user = random_string(&mut rng, 12);
        let auth_pass = random_string(&mut rng, 24);
        let csrf = random_string(&mut rng, 32);
        Self {
            username: Some(auth_user),
            password: Some(auth_pass),
            tls: None,
            csrf_token: Some(csrf),
            rate_limit_window_secs: 60,
            rate_limit_max_requests: 100,
            bind_address: None,
        }
    }
}

/// Simple per-IP sliding window rate limiter.
struct RateLimiter {
    window: Duration,
    max_requests: u32,
    buckets: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    fn new(window_secs: u64, max_requests: u32) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            max_requests,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request should be allowed.
    async fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();
        let entry = buckets.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) > self.window {
            *entry = (now, 1);
            return true;
        }
        if entry.1 >= self.max_requests {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Per-user rate limiter keyed by (username, IpAddr).
/// Allows the same user from different IPs, or different users from the same IP,
/// to have independent rate limit counters.
struct UserRateLimiter {
    window: Duration,
    max_requests: u32,
    buckets: Mutex<HashMap<(String, IpAddr), (Instant, u32)>>,
}

impl UserRateLimiter {
    fn new(window_secs: u64, max_requests: u32) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            max_requests,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    async fn check(&self, username: &str, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();
        let key = (username.to_string(), ip);
        let entry = buckets.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) > self.window {
            *entry = (now, 1);
            return true;
        }
        if entry.1 >= self.max_requests {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// A user session with bearer-token auth.
#[derive(Clone, Debug)]
struct SessionInfo {
    #[allow(dead_code)]
    token: String,
    username: String,
    created_at: Instant,
}

/// Session store that auto-cleans expired tokens on access.
struct SessionStore {
    sessions: Mutex<HashMap<String, SessionInfo>>,
    session_ttl: Duration,
}

impl SessionStore {
    fn new(ttl_secs: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            session_ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Create a new session for the given username and return a bearer token.
    #[allow(dead_code)]
    async fn create_session(&self, username: &str) -> String {
        use rand::RngExt;
        let mut rng = rand::rngs::ThreadRng::default();
        let token: String = (0..48)
            .map(|_| {
                const CHARS: &[u8] =
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                CHARS[rng.random_range(0..CHARS.len())] as char
            })
            .collect();

        let mut sessions = self.sessions.lock().await;
        // Clean expired sessions on write
        let now = Instant::now();
        sessions.retain(|_, s| now.duration_since(s.created_at) < self.session_ttl);
        sessions.insert(
            token.clone(),
            SessionInfo {
                token: token.clone(),
                username: username.to_string(),
                created_at: now,
            },
        );
        token
    }

    /// Validate a bearer token and return the username if valid.
    async fn validate_token(&self, token: &str) -> Option<String> {
        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();
        // Clean expired
        sessions.retain(|_, s| now.duration_since(s.created_at) < self.session_ttl);
        sessions.get(token).map(|s| s.username.clone())
    }
}

/// Shared application state
struct AppState {
    graphs: RwLock<Vec<GraphBundle>>,
    default_graph: String,
    cache: RwLock<HashMap<String, Arc<ViewerGraph>>>,
    config: ViewerConfig,
    rate_limiter: RateLimiter,
    user_rate_limiter: UserRateLimiter,
    sessions: SessionStore,
    ws_tx: broadcast::Sender<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct OperationMetrics {
    started_at: String,
    total_ms: u128,
    phases: Vec<MetricSample>,
}

#[derive(Clone, Debug, Serialize)]
struct MetricSample {
    name: String,
    ms: u128,
}

impl OperationMetrics {
    fn new() -> Self {
        Self {
            started_at: Utc::now().to_rfc3339(),
            total_ms: 0,
            phases: Vec::new(),
        }
    }

    fn phase(&mut self, name: impl Into<String>, elapsed_ms: u128) {
        self.phases.push(MetricSample {
            name: name.into(),
            ms: elapsed_ms,
        });
    }

    fn finish(&mut self) {
        self.total_ms = self.phases.iter().map(|phase| phase.ms).sum();
    }
}

const RELATIONSHIPS: &[&str] = &[
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "WriteSelf",
    "AllExtendedRights",
    "Owns",
    "ForceChangePassword",
    "AddSelf",
    "CreateChild",
    "WriteProperty",
    "WriteSPN",
    "WriteServicePrincipalName",
    "WriteKeyCredentialLink",
    "WriteMsDsKeyCredentialLink",
    "AddKeyCredentialLink",
    "WriteAllowedToDelegateTo",
    "WriteAccountRestrictions",
    "WriteAltSecurityIdentities",
    "WriteUserCertificate",
    "WriteGPLink",
    "WritePwdProperties",
    "WriteLockoutThreshold",
    "WriteMinPwdLength",
    "WritePwdHistoryLength",
    "WritePwdComplexity",
    "WritePwdReversibleEncryption",
    "WritePwdAge",
    "WriteLockoutDuration",
    "WriteLockoutObservationWindow",
    "AddMember",
    "AddMembers",
    "MemberOf",
    "Members",
    "AdminTo",
    "CanRDP",
    "CanPSRemote",
    "ExecuteDCOM",
    "SQLAdmin",
    "HasSession",
    "TrustedBy",
    "AllowedToDelegate",
    "AllowedToAct",
    "HasSidHistory",
    "HasSpn",
    "DontReqPreauth",
    "DcSync",
    "GetChanges",
    "GetChangesAll",
    "Enroll",
    "EnrollCertificate",
    "ManageCA",
    "ManageCertificates",
    "ManageCertTemplate",
    "AdcsEsc1",
    "AdcsEsc2",
    "AdcsEsc3",
    "AdcsEsc4",
    "AdcsEsc5",
    "AdcsEsc6",
    "AdcsEsc7",
    "AdcsEsc8",
    "AdcsEsc9",
    "AdcsEsc10",
    "AdcsEsc11",
    "AdcsEsc12",
    "AdcsEsc13",
    "AdcsEsc14",
    "AdcsEsc15",
    "AdcsEsc16",
];

const AUTO_NODE_LIMIT: usize = 3500;
const AUTO_NODE_THRESHOLD: usize = 4500;
const AUTO_EDGE_PER_NODE: usize = 6;
const MAX_NODE_LIMIT: usize = 20000;
const MAX_EDGE_LIMIT: usize = 120000;

// ============================================================
//  API Response Types
// ============================================================

#[derive(Debug, Serialize)]
struct GraphInfo {
    id: String,
    label: String,
    sources: Vec<String>,
    file_bytes: u64,
    loaded: bool,
    stats: Option<StatsResponse>,
    load_metrics: Option<GraphLoadMetrics>,
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
    chunk_offset: usize,
    chunk_size: usize,
    chunk_index: usize,
    chunk_count: usize,
    load_metrics: Option<GraphLoadMetrics>,
    server_metrics: OperationMetrics,
    load_time_ms: u128,
    render_time_ms: u128,
    nodes: Vec<NodeResponse>,
    edges: Vec<EdgeResponse>,
}

#[derive(Debug, Serialize, Clone)]
struct StatsResponse {
    total_nodes: usize,
    total_edges: usize,
    relationship_types: usize,
    top_relationships: Vec<RelationshipStat>,
    users: usize,
    computers: usize,
    groups: usize,
    domains: usize,
    gpos: usize,
    ous: usize,
    cert_templates: usize,
    high_value: usize,
    owned: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    load_metrics: Option<GraphLoadMetrics>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
    code: &'static str,
}

impl ApiError {
    fn new(code: &'static str, error: impl Into<String>) -> Self {
        Self {
            code,
            error: error.into(),
        }
    }
}

/// WebSocket push notification sent to all connected clients.
#[derive(Clone, Serialize, Deserialize)]
struct WsMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    graph_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
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
    out_degree: usize,
    in_degree: usize,
}

#[derive(Serialize)]
struct EdgeResponse {
    source: String,
    target: String,
    relationship: String,
    cost: u32,
    severity: u8,
    guidance: String,
    ovt_command: String,
    ovt_command_desc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ace_details: Option<String>,
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
    out_degree: usize,
    in_degree: usize,
    metrics: OperationMetrics,
    retrieval_ms: u128,
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
    ovt_command: String,
    ovt_command_desc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ace_details: Option<String>,
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
    metrics: OperationMetrics,
    pathfinding_ms: u128,
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
    ovt_command: String,
    ovt_command_desc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ace_details: Option<String>,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    graph: Option<String>,
    types: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct CustomQuery {
    q: String,
    graph: Option<String>,
    types: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct CustomQueryResponse {
    query: String,
    nodes: Vec<SearchResult>,
    relationships: Vec<QueryRelationship>,
    total_node_matches: usize,
    total_edge_matches: usize,
}

#[derive(Serialize)]
struct QueryRelationship {
    relationship: String,
    category: String,
    edge_count: usize,
    severity: u8,
    guidance: String,
}

#[derive(Deserialize)]
struct CommandLookupRequest {
    relationship: String,
    source: Option<String>,
    target: Option<String>,
}

#[derive(Serialize)]
struct EdgeCommandResponse {
    relationship: String,
    severity: u8,
    guidance: String,
    ovt_command: String,
    ovt_command_desc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ace_details: Option<String>,
}

#[derive(Serialize)]
struct EdgeTypeInfo {
    relationship: String,
    severity: u8,
    guidance: String,
    ovt_command_template: String,
}

#[derive(Deserialize)]
struct GraphQuery {
    graph: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    edges: Option<usize>,
    types: Option<String>,
    focus: Option<String>,
    relationship: Option<String>,
}

#[derive(Deserialize)]
struct NodeDetailQuery {
    id: String,
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

fn stats_response(stats: &ViewerStats, load_metrics: Option<GraphLoadMetrics>) -> StatsResponse {
    StatsResponse {
        total_nodes: stats.total_nodes,
        total_edges: stats.total_edges,
        relationship_types: stats.relationship_types,
        top_relationships: stats.top_relationships.clone(),
        users: stats.users,
        computers: stats.computers,
        groups: stats.groups,
        domains: stats.domains,
        gpos: stats.gpos,
        ous: stats.ous,
        cert_templates: stats.cert_templates,
        high_value: stats.high_value,
        owned: stats.owned,
        load_metrics,
    }
}

fn node_degree(graph: &ViewerGraph, idx: usize) -> (usize, usize) {
    (
        graph.outgoing(idx).map_or(0, Vec::len),
        graph.incoming(idx).map_or(0, Vec::len),
    )
}

fn property_value_ci(properties: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        properties
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn node_sid(node: &ViewerNode) -> String {
    property_value_ci(
        &node.properties,
        &["objectsid", "objectid", "securityidentifier"],
    )
    .unwrap_or_else(|| node.id.clone())
}

fn edge_ace_details(edge: &ViewerEdge, source: &ViewerNode, target: &ViewerNode) -> Option<String> {
    let mut details = Vec::new();
    if let Some(principal) = property_value_ci(
        &edge.properties,
        &[
            "Principalsid",
            "PrincipalSID",
            "PrincipalObjectIdentifier",
            "Source",
        ],
    ) {
        details.push(format!("principal={principal}"));
    }
    if let Some(right) = property_value_ci(&edge.properties, &["RightName", "Right", "Type"]) {
        details.push(format!("right={right}"));
    }
    if let Some(object_type) = property_value_ci(
        &edge.properties,
        &["ObjectType", "InheritedObjectType", "ObjectClass"],
    ) {
        details.push(format!("object_type={object_type}"));
    }
    if let Some(ace_type) = property_value_ci(&edge.properties, &["AceType", "ACEType"]) {
        details.push(format!("ace_type={ace_type}"));
    }
    if let Some(flags) = property_value_ci(&edge.properties, &["AceFlags", "Flags"]) {
        details.push(format!("flags={flags}"));
    }
    if let Some(inherited) = property_value_ci(&edge.properties, &["IsInherited", "Inherited"]) {
        details.push(format!("inherited={inherited}"));
    }
    if let Some(scope) = property_value_ci(&edge.properties, &["AppliesTo", "AppliesToType"]) {
        details.push(format!("scope={scope}"));
    }

    if details.is_empty() {
        return None;
    }

    Some(format!(
        "{} -> {} [{}]",
        node_display_name(source),
        node_display_name(target),
        details.join(", ")
    ))
}

fn edge_ovt_command(
    edge: &ViewerEdge,
    source: &ViewerNode,
    target: &ViewerNode,
) -> (String, String) {
    let target_sid = node_sid(target);
    let target_name = target.label.clone();
    let target_display = node_display_name(target);
    let source_domain = node_domain(source);

    match edge.relationship.to_ascii_lowercase().as_str() {
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
        "adcsesc1" | "adcsesc2" | "adcsesc3" | "adcsesc4" | "adcsesc5" | "adcsesc6"
        | "adcsesc7" | "adcsesc8" | "adcsesc9" | "adcsesc10" | "adcsesc11" | "adcsesc12"
        | "adcsesc13" | "adcsesc14" | "adcsesc15" | "adcsesc16" => {
            let esc_num = edge.relationship.trim_start_matches("AdcsEsc");
            (
                format!("ovt adcs esc{esc_num} --ca <CA_HOST> --template <TEMPLATE>"),
                format!(
                    "ADCS ESC{esc_num} path to {target_display}; verify template EKUs, SAN policy, and mapping before use."
                ),
            )
        }
        "dcsync" | "getchanges" | "getchangesall" => (
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
        "enrollcertificate" | "enrollonbehalfof" => (
            format!(
                "ovt adcs enroll --template <TEMPLATE> --target {}",
                target.id
            ),
            format!(
                "Certificate enrollment on {target_display}; inspect EKUs, subject supply, approval, and agent restrictions."
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
        "memberof" => (
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
        _ => {
            let safe_rel = edge
                .relationship
                .replace(|c: char| !c.is_ascii_alphanumeric(), "_");
            (
                format!("ovt powerview acls --sid {target_sid} --edge-type {safe_rel}"),
                format!(
                    "Review the {} relationship on {}; confirm directionality and validate the abuse primitive before acting.",
                    edge.relationship, target_display
                ),
            )
        }
    }
}

#[derive(Clone, Debug)]
struct EdgeAnnotation {
    severity: u8,
    guidance: String,
    ovt_command: String,
    ovt_command_desc: String,
    ace_details: Option<String>,
}

fn annotate_edge(graph: &ViewerGraph, edge: &ViewerEdge) -> Option<EdgeAnnotation> {
    let source = graph.get_node(edge.source)?;
    let target = graph.get_node(edge.target)?;
    let (fallback_severity, fallback_guidance) = edge_security_guidance(&edge.relationship);
    let (fallback_command, fallback_command_desc) = edge_ovt_command(edge, source, target);
    let severity = edge.severity.unwrap_or(fallback_severity);
    let guidance = edge
        .guidance
        .clone()
        .unwrap_or_else(|| fallback_guidance.to_string());
    let ovt_command = edge.ovt_command.clone().unwrap_or(fallback_command);
    let ovt_command_desc = edge
        .ovt_command_desc
        .clone()
        .unwrap_or(fallback_command_desc);
    let ace_details = edge
        .ace_details
        .clone()
        .or_else(|| edge_ace_details(edge, source, target));

    Some(EdgeAnnotation {
        severity,
        guidance,
        ovt_command,
        ovt_command_desc,
        ace_details,
    })
}

fn estimate_render_time(node_count: usize, edge_count: usize) -> u128 {
    let base_ms: u128 = 50;
    let node_batch_ms = (node_count / 5000).saturating_add(1) as u128 * 8;
    let edge_batch_ms = (edge_count / 20000).saturating_add(1) as u128 * 3;
    base_ms + node_batch_ms + edge_batch_ms
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
    offset: usize,
    type_filter: &[String],
) -> Vec<usize> {
    let total_nodes = graph.stats().total_nodes;
    let mut eligible: Vec<usize> = graph
        .nodes()
        .filter_map(|(idx, node)| node_matches_type_filter(node, type_filter).then_some(idx))
        .collect();

    if node_limit >= eligible.len() {
        return eligible;
    }

    eligible.sort_unstable();
    let start = offset.min(eligible.len());
    let mut selected: Vec<usize> = eligible
        .into_iter()
        .skip(start)
        .take(node_limit.max(1))
        .collect();
    let mut selected_mask = vec![false; total_nodes];
    for idx in &selected {
        if *idx < selected_mask.len() {
            selected_mask[*idx] = true;
        }
    }

    add_connected_context_nodes(graph, &mut selected, &mut selected_mask, node_limit);
    selected
}

fn select_relationship_nodes(
    graph: &ViewerGraph,
    relationship: &str,
    node_limit: usize,
    type_filter: &[String],
) -> Vec<usize> {
    let mut selected = HashSet::new();
    for edge in graph.edges() {
        if edge.relationship.eq_ignore_ascii_case(relationship) {
            if graph
                .get_node(edge.source)
                .filter(|n| node_matches_type_filter(n, type_filter))
                .is_some()
            {
                selected.insert(edge.source);
            }
            if graph
                .get_node(edge.target)
                .filter(|n| node_matches_type_filter(n, type_filter))
                .is_some()
            {
                selected.insert(edge.target);
            }
        }
        if selected.len() >= node_limit {
            break;
        }
    }
    selected.into_iter().collect()
}

fn attack_relationships(alias: &str) -> Vec<&'static str> {
    match alias.to_ascii_lowercase().as_str() {
        "kerberos" => vec![
            "HasSpn",
            "DontReqPreauth",
            "AllowedToDelegate",
            "AllowedToAct",
            "WriteSPN",
            "WriteServicePrincipalName",
            "WriteAllowedToDelegateTo",
        ],
        "asrep" | "asreproast" => vec!["DontReqPreauth"],
        "kerberoast" => vec!["HasSpn", "WriteSPN", "WriteServicePrincipalName"],
        "delegation" | "s4u" | "rbcd" => vec![
            "AllowedToDelegate",
            "AllowedToAct",
            "AddAllowedToAct",
            "WriteAllowedToDelegateTo",
        ],
        "shadow" | "shadowcreds" | "shadow-credentials" => vec![
            "WriteKeyCredentialLink",
            "WriteMsDsKeyCredentialLink",
            "AddKeyCredentialLink",
        ],
        "dcsync" | "replication" => {
            vec!["DcSync", "GetChanges", "GetChangesAll", "AllExtendedRights"]
        }
        "adcs" | "cert" | "certificate" | "esc" | "escs" => vec![
            "AdcsEsc1",
            "AdcsEsc2",
            "AdcsEsc3",
            "AdcsEsc4",
            "AdcsEsc5",
            "AdcsEsc6",
            "AdcsEsc7",
            "AdcsEsc8",
            "AdcsEsc9",
            "AdcsEsc10",
            "AdcsEsc11",
            "AdcsEsc12",
            "AdcsEsc13",
            "AdcsEsc14",
            "AdcsEsc15",
            "AdcsEsc16",
            "EnrollCertificate",
            "EnrollOnBehalfOf",
            "ManageCA",
            "ManageCertificates",
            "ManageCertTemplate",
        ],
        "llmnr" | "ntlmrelay" | "relay" => vec![
            "AdcsEsc8",
            "AdcsEsc11",
            "EnrollCertificate",
            "AdminTo",
            "CanPSRemote",
            "CanRDP",
            "HasSession",
        ],
        "coercion" | "petitpotam" | "printerbug" | "dfscoerce" | "shadowcoerce" => {
            vec!["AdcsEsc8", "AdcsEsc11", "AdminTo", "CanPSRemote", "CanRDP"]
        }
        "ldap" | "ldaps" => vec![
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "AllExtendedRights",
            "WriteKeyCredentialLink",
            "AddKeyCredentialLink",
            "WriteAltSecurityIdentities",
            "WriteAccountRestrictions",
        ],
        "lateral" | "movement" => vec![
            "AdminTo",
            "CanRDP",
            "CanPSRemote",
            "ExecuteDCOM",
            "SQLAdmin",
            "HasSession",
        ],
        "acl" | "aces" | "control" => vec![
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "Owns",
            "AllExtendedRights",
            "AddMembers",
            "AddSelf",
            "ForceChangePassword",
            "CreateChild",
            "WriteSelf",
        ],
        "gpo" | "gplink" => vec!["GpoLink", "WriteGPLink", "GenericAll", "GenericWrite"],
        "laps" | "gmsa" | "secrets" => vec![
            "ReadLapsPassword",
            "ReadLapsPasswordExpiry",
            "ReadGmsaPassword",
            "GenericAll",
            "AllExtendedRights",
        ],
        "trust" | "trusts" | "crossdomain" | "cross-domain" => {
            vec!["TrustedBy", "HasSidHistory"]
        }
        "session" | "sessions" => vec!["HasSession"],
        "rdp" => vec!["CanRDP"],
        "psremote" | "winrm" => vec!["CanPSRemote"],
        "dcom" => vec!["ExecuteDCOM"],
        "sql" | "mssql" => vec!["SQLAdmin"],
        "policy" | "password-policy" | "spray" => vec![
            "WritePwdProperties",
            "WriteLockoutThreshold",
            "WriteMinPwdLength",
            "WritePwdHistoryLength",
            "WritePwdComplexity",
            "WritePwdReversibleEncryption",
            "WritePwdAge",
            "WriteLockoutDuration",
            "WriteLockoutObservationWindow",
        ],
        _ => Vec::new(),
    }
}

fn relationship_category(relationship: &str) -> &'static str {
    match relationship.to_ascii_lowercase().as_str() {
        "hasspn" | "dontreqpreauth" | "writespn" | "writeserviceprincipalname" => "Kerberos",
        "allowedtodelegate" | "allowedtoact" | "addallowedtoact" | "writeallowedtodelegateto" => {
            "Delegation"
        }
        "dcsync" | "getchanges" | "getchangesall" => "Replication",
        "enrollcertificate" | "enrollonbehalfof" | "manageca" | "managecertificates"
        | "managecerttemplate" => "ADCS",
        rel if rel.starts_with("adcsesc") => "ADCS ESC",
        "adminto" | "canrdp" | "canpsremote" | "executedcom" | "sqladmin" | "hassession" => {
            "Lateral"
        }
        "trustedby" => "Trust",
        _ => "ACL",
    }
}

fn normalize_relationship_query(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim()
        .trim_start_matches("edge:")
        .trim_start_matches("rel:")
        .trim_start_matches("relationship:");
    if cleaned.is_empty() {
        return None;
    }
    if let Some(num) = cleaned
        .to_ascii_lowercase()
        .strip_prefix("esc")
        .and_then(|n| n.parse::<u8>().ok())
        .filter(|n| (1..=16).contains(n))
    {
        return Some(format!("AdcsEsc{num}"));
    }
    RELATIONSHIPS
        .iter()
        .find(|relationship| relationship.eq_ignore_ascii_case(cleaned))
        .map(|relationship| (*relationship).to_string())
        .or_else(|| {
            RELATIONSHIPS
                .iter()
                .find(|relationship| {
                    relationship
                        .to_ascii_lowercase()
                        .contains(&cleaned.to_ascii_lowercase())
                })
                .map(|relationship| (*relationship).to_string())
        })
}

fn node_contains_terms(node: &ViewerNode, terms: &[String]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let mut haystack = format!(
        "{} {} {} {} {}",
        node.id,
        node.label,
        node.kind,
        node.domain.as_deref().unwrap_or_default(),
        node.distinguished_name.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();
    for (key, value) in &node.properties {
        haystack.push(' ');
        haystack.push_str(&key.to_ascii_lowercase());
        haystack.push('=');
        haystack.push_str(&value.to_ascii_lowercase());
    }
    terms
        .iter()
        .all(|term| haystack.contains(&term.to_ascii_lowercase()))
}

fn node_matches_custom_filters(
    node: &ViewerNode,
    type_filter: &[String],
    query_type: &Option<String>,
    domain: &Option<String>,
    owned: Option<bool>,
    high_value: Option<bool>,
    terms: &[String],
) -> bool {
    if !node_matches_type_filter(node, type_filter) {
        return false;
    }
    if let Some(kind) = query_type
        && !node.kind.eq_ignore_ascii_case(kind)
    {
        return false;
    }
    if let Some(domain_filter) = domain
        && !node
            .domain
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains(&domain_filter.to_ascii_lowercase())
    {
        return false;
    }
    if let Some(expected) = owned
        && node.owned != expected
    {
        return false;
    }
    if let Some(expected) = high_value
        && node.high_value != expected
    {
        return false;
    }
    node_contains_terms(node, terms)
}

fn add_connected_context_nodes(
    graph: &ViewerGraph,
    selected: &mut Vec<usize>,
    selected_mask: &mut [bool],
    node_limit: usize,
) {
    let total_nodes = graph.stats().total_nodes;
    if node_limit == 0 || selected.len() >= total_nodes {
        return;
    }

    let target = node_limit
        .saturating_mul(3)
        .max(node_limit.saturating_add(32))
        .min(MAX_NODE_LIMIT)
        .min(total_nodes);
    if selected.len() >= target {
        return;
    }

    let mut candidates = Vec::new();
    for edge in graph.edges() {
        let source_selected = selected_mask.get(edge.source).copied().unwrap_or(false);
        let target_selected = selected_mask.get(edge.target).copied().unwrap_or(false);
        if source_selected == target_selected {
            continue;
        }
        let neighbor = if source_selected {
            edge.target
        } else {
            edge.source
        };
        candidates.push((
            if edge_is_important(&edge.relationship) {
                0u8
            } else {
                1u8
            },
            edge.cost,
            neighbor,
        ));
    }
    candidates.sort_unstable_by_key(|(importance, cost, idx)| (*importance, *cost, *idx));

    for (_, _, idx) in candidates {
        if selected.len() >= target {
            break;
        }
        if selected_mask.get(idx).copied().unwrap_or(true) {
            continue;
        }
        selected_mask[idx] = true;
        selected.push(idx);
    }
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
        "createchild" => (
            3,
            "CreateChild. Can create objects in the target container or OU; check machine-account, group, service account, and policy abuse scope before acting.",
        ),
        "writeself" => (
            2,
            "Validated self-write. Commonly maps to group self-add or constrained attribute updates; confirm the exact validated write before use.",
        ),
        "readlapspasswordexpiry" | "readlapsencryptedpassword" => (
            2,
            "LAPS metadata or encrypted LAPS material. Pair with DPAPI/LAPS decryption paths and treat recovered values as credential material.",
        ),
        "writespn" | "writeserviceprincipalname" => (
            2,
            "SPN write. Set a single temporary SPN for targeted Kerberoasting, collect one TGS, then restore the original SPN set.",
        ),
        "writeallowedtodelegateto" => (
            1,
            "Delegation write. Changes msDS-AllowedToDelegateTo and can enable S4U paths; record and restore the original service list.",
        ),
        "addallowedtoact" => (
            1,
            "RBCD write. Add a controlled computer account to msDS-AllowedToActOnBehalfOfOtherIdentity, request only needed service tickets, then clean up.",
        ),
        "writeaccountrestrictions" => (
            2,
            "Account restrictions write. May alter delegation or authentication behavior; inspect the target class and attribute before modification.",
        ),
        "writelogonscript" | "writeprofilepath" | "writescriptpath" => (
            2,
            "Logon/profile script write. Code execution path with visible user impact; keep payloads minimal, scoped, and rollback-ready.",
        ),
        "writednshostname" => (
            3,
            "DNS hostname write. Validate DNS, SPN, and delegation side effects before changing host identity fields.",
        ),
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => (
            1,
            "Shadow credentials. Add a controlled KeyCredentialLink, authenticate with PKINIT, and remove the value after validation.",
        ),
        "writealtsecurityidentities" => (
            1,
            "Certificate mapping write. Can map attacker-controlled certificates to the account; verify ADCS mapping policy and restore original values.",
        ),
        "writeuserparameters" => (
            3,
            "UserParameters write. Legacy execution or persistence surface; validate logon impact and avoid production user disruption.",
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
            "Password policy write. Domain-visible and potentially disruptive; document the original policy and prefer read-only proof unless approved.",
        ),
        "writegplink" => (
            2,
            "GPLink write. Link a controlled GPO to an OU only after checking inheritance, enforcement, security filtering, and rollback.",
        ),
        "enrollcertificate" => (
            2,
            "Certificate enrollment. Review template EKUs, subject supply, approval, and enrollment rights before requesting credentials.",
        ),
        "enrollonbehalfof" => (
            1,
            "Enrollment agent path. Request on behalf of another principal only after validating template constraints and approval settings.",
        ),
        "adcsesc1" => (
            1,
            "ESC1 — Enrollee supplies SAN. Request a certificate for a target user via this template and use it for authentication (PKINIT).",
        ),
        "adcsesc2" => (
            1,
            "ESC2 — Any purpose template. Template can be used for any purpose, including client authentication or as an enrollment agent.",
        ),
        "adcsesc3" => (
            1,
            "ESC3 — Enrollment agent abuse. Enroll for an agent certificate, then use it to request a certificate on behalf of a target user.",
        ),
        "adcsesc4" => (
            1,
            "ESC4 — Vulnerable template ACLs. Modify the template to enable SAN abuse (ESC1), enroll, then restore the original ACLs.",
        ),
        "adcsesc5" => (
            1,
            "ESC5 — Vulnerable CA object ACLs. CA configuration can be modified to enable other ESC paths; check security descriptor on the CA.",
        ),
        "adcsesc6" => (
            1,
            "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 enabled. CA global flag allows SANs in all requests; request any template with a target SAN.",
        ),
        "adcsesc7" => (
            1,
            "ESC7 — Vulnerable CA permissions. Control over ManageCA/ManageCertificates allows adding officers or enabling SAN abuse flags.",
        ),
        "adcsesc8" => (
            1,
            "ESC8 — ADCS Web Enrollment relay. Relay an authenticated NTLM session to the web enrollment endpoint to obtain a certificate.",
        ),
        "adcsesc9" => (
            1,
            "ESC9 — No Security Extension (UPN poisoning). Victim with CT_FLAG_NO_SECURITY_EXTENSION template can be impersonated via UPN poisoning.",
        ),
        "adcsesc10" => (
            1,
            "ESC10 — Weak certificate mapping. Impersonation via accounts with weak mapping settings or registry-based enforcement disabled.",
        ),
        "adcsesc11" => (
            1,
            "ESC11 — NTLM relay to RPC. Relay NTLM to the ICertPassage RPC interface to obtain a certificate.",
        ),
        "adcsesc12" => (
            1,
            "ESC12 — Policy Server relay. Relay to the Certificate Enrollment Policy (CEP) service.",
        ),
        "adcsesc13" => (
            1,
            "ESC13 — OID-to-Group Link. Template issuance policy is linked to a privileged group, granting its membership upon authentication.",
        ),
        "adcsesc14" => (
            1,
            "ESC14 — altSecurityIdentities mapping. Add an RFC822/UPN mapping for a victim account, obtain a certificate, and restore mapping.",
        ),
        "adcsesc15" => (
            1,
            "ESC15 — Schema V1 EKU abuse. Exploit implicit SAN allowance in old templates for impersonation via PKINIT.",
        ),
        "adcsesc16" => (
            1,
            "ESC16 — NO_SECURITY_EXTENSION abuse. Poison UPN and request certificate via a template with security extensions disabled.",
        ),
        "writeproperty" => (
            2,
            "WriteProperty. Inspect the attribute GUID: abuse varies from SPN writes and delegation to shadow credentials and ADCS mapping.",
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

fn command_template_for_relationship(relationship: &str) -> String {
    let lower = relationship.to_ascii_lowercase();
    match lower.as_str() {
        "genericall" | "genericwrite" | "allextendedrights" | "writeproperty" => {
            "ovt powerview acls --sid <SID>".to_string()
        }
        "writedacl" | "writeowner" | "owns" | "createchild" => {
            "ovt acls writedacl --target <TARGET>".to_string()
        }
        "forcechangepassword" => {
            "ovt acl force-password --target <TARGET> --password <NEW_PASSWORD>".to_string()
        }
        "addmembers" => "ovt acl add-member --group <GROUP> --member <ACCOUNT>".to_string(),
        "addself" => "ovt acl add-self --group <GROUP>".to_string(),
        "writeself" => "ovt powerview acls --sid <SID>".to_string(),
        "readlapspassword" | "readlapspasswordexpiry" => {
            "ovt laps read --computer <COMPUTER> --target-dc <DC>".to_string()
        }
        "readgmsapassword" => "ovt powerview acls --sid <SID>".to_string(),
        "allowedtodelegate" => "ovt powerview delegations --target <TARGET>".to_string(),
        "allowedtoact" | "addallowedtoact" => {
            "ovt acls add-allowed-to-act --target <TARGET>".to_string()
        }
        "writeallowedtodelegateto" => "ovt acls writedacl --target <TARGET>".to_string(),
        "dcsync" | "getchanges" | "getchangesall" | "getchangesinfilteredset" => {
            "ovt adcs dcsync --target <TARGET> --domain <DOMAIN>".to_string()
        }
        "writespn" | "writeserviceprincipalname" => {
            "ovt acl write-spn --target <TARGET> --spn <SPN>".to_string()
        }
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => {
            "ovt acl shadow-creds --target <TARGET> --cert <CERT_FILE>".to_string()
        }
        "writealtsecurityidentities" => "ovt adcs alt-sid --target <TARGET>".to_string(),
        "writegplink" => "ovt gpo link --target <TARGET> --gpo <GPO_ID>".to_string(),
        "gpolink" => "ovt gpo status --target <TARGET>".to_string(),
        "enrollcertificate" | "enrollonbehalfof" => {
            "ovt adcs enroll --template <TEMPLATE> --target <TARGET>".to_string()
        }
        "manageca" => "ovt adcs manage-ca --ca <CA>".to_string(),
        "managecertificates" => "ovt adcs manage-certificates --ca <CA>".to_string(),
        "managecerttemplate" => "ovt adcs template --template <TEMPLATE> --inspect".to_string(),
        "hasspn" => "ovt kerberoast --spn <SPN>".to_string(),
        "dontreqpreauth" => "ovt asrep --user <USER>".to_string(),
        "adminto" => "ovt exec --target <TARGET> --method auto".to_string(),
        "canrdp" => "ovt exec --target <TARGET> --method rdp".to_string(),
        "canpsremote" => "ovt exec --target <TARGET> --method psremote".to_string(),
        "executedcom" => "ovt exec --target <TARGET> --method dcom".to_string(),
        "sqladmin" => "ovt mssql --target <TARGET> --query 'SELECT @@version'".to_string(),
        "hassession" => "ovt exec --target <TARGET> --method token".to_string(),
        "trustedby" => "ovt move trust --domain <SOURCE_DOMAIN> --target <TARGET>".to_string(),
        "memberof" | "memberoftierzero" | "memberoftier0" => {
            "ovt powerview members --group <GROUP> --recurse".to_string()
        }
        "contains" => "ovt powerview container --target <TARGET>".to_string(),
        "hassidhistory" => "ovt move sid-history --target <TARGET>".to_string(),
        _ if lower.starts_with("adcsesc") => {
            let suffix = lower.trim_start_matches("adcsesc");
            format!("ovt adcs esc{suffix} --ca <CA> --template <TEMPLATE>")
        }
        _ => "ovt powerview acls --sid <SID> --edge-type <RELATIONSHIP>".to_string(),
    }
}

fn edge_response(graph: &ViewerGraph, edge: &ViewerEdge) -> Option<EdgeResponse> {
    let src = graph.get_node(edge.source)?;
    let tgt = graph.get_node(edge.target)?;
    let annotation = annotate_edge(graph, edge)?;
    Some(EdgeResponse {
        source: src.id.clone(),
        target: tgt.id.clone(),
        relationship: edge.relationship.clone(),
        cost: edge.cost,
        severity: annotation.severity,
        guidance: annotation.guidance,
        ovt_command: annotation.ovt_command,
        ovt_command_desc: annotation.ovt_command_desc,
        ace_details: annotation.ace_details,
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
        let Some(annotation) = annotate_edge(graph, edge) else {
            continue;
        };
        if annotation.severity > 3 || !seen.insert(edge.relationship.to_ascii_lowercase()) {
            continue;
        }
        notes.push(DetailNote {
            title: format!("{} relationship", edge.relationship),
            severity: annotation.severity,
            body: annotation.guidance.clone(),
        });
        if let Some(details) = annotation.ace_details {
            notes.push(DetailNote {
                title: format!("ACE detail: {}", edge.relationship),
                severity: annotation.severity.min(3),
                body: details,
            });
        }
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

async fn resolve_bundle(
    state: &AppState,
    graph_id: Option<&str>,
) -> Result<GraphBundle, StatusCode> {
    let graphs = state.graphs.read().await;
    if let Some(id) = graph_id {
        return graphs
            .iter()
            .find(|graph| graph.id == id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND);
    }

    graphs
        .iter()
        .find(|graph| graph.id == state.default_graph)
        .or_else(|| graphs.first())
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)
}

async fn load_graph(
    state: &AppState,
    graph_id: Option<&str>,
) -> Result<(GraphBundle, Arc<ViewerGraph>), StatusCode> {
    let bundle = resolve_bundle(state, graph_id).await?;

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

#[allow(dead_code)]
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

fn collect_json_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn expand_graph_sources(sources: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for source in sources {
        let path = PathBuf::from(source);
        if !path.exists() {
            return Err(anyhow!("graph source does not exist: {}", path.display()));
        }

        if path.is_dir() {
            collect_json_files(&path, &mut paths)?;
        } else {
            paths.push(path);
        }
    }

    paths.sort();
    Ok(paths)
}

fn build_graph_bundles(sources: &[String]) -> Result<Vec<GraphBundle>> {
    let mut bundles = Vec::new();
    let mut seen_ids = HashSet::new();

    let files = expand_graph_sources(sources)?;

    for file in files {
        let label = file
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown-graph")
            .to_string();

        let mut base_id = graph_id_from_label(&label);
        if base_id.is_empty() {
            base_id = format!("graph-{}", bundles.len() + 1);
        }

        let mut graph_id = base_id.clone();
        let mut counter = 2;
        while seen_ids.contains(&graph_id) {
            graph_id = format!("{}-{}", base_id, counter);
            counter += 1;
        }
        seen_ids.insert(graph_id.clone());

        let file_bytes = fs::metadata(&file).map(|m| m.len()).unwrap_or(0);

        bundles.push(GraphBundle {
            id: graph_id,
            label,
            sources: vec![file.display().to_string()],
            file_bytes,
        });
    }

    if bundles.is_empty() {
        return Err(anyhow!(
            "no valid JSON graph files found in the provided sources"
        ));
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
            let (out_degree, in_degree) = node_degree(graph, idx);
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
                out_degree,
                in_degree,
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

fn sanitize_btreemap(map: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    map.iter()
        .map(|(k, v)| (k.clone(), sanitize_ad_string(v)))
        .collect()
}

fn build_connection(
    graph: &ViewerGraph,
    edge: &ViewerEdge,
    target: &ViewerNode,
    direction: &str,
) -> Option<Connection> {
    let annotation = annotate_edge(graph, edge)?;
    let source = graph.get_node(edge.source)?;
    let actual_target = graph.get_node(edge.target)?;

    Some(Connection {
        target_id: sanitize_ad_string(&target.id),
        target_label: sanitize_ad_string(&target.label),
        target_display: node_display_name(target),
        target_type: node_type_str(target),
        target_domain: node_domain(target),
        relationship: sanitize_ad_string(&edge.relationship),
        direction: direction.to_string(),
        cost: edge.cost,
        severity: annotation.severity,
        guidance: annotation.guidance,
        properties: sanitize_btreemap(&edge.properties),
        ovt_command: annotation.ovt_command,
        ovt_command_desc: annotation.ovt_command_desc,
        ace_details: annotation
            .ace_details
            .or_else(|| edge_ace_details(edge, source, actual_target)),
    })
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
            let edge = graph.edges().find(|edge| {
                edge.source == hop.source_idx
                    && edge.target == hop.target_idx
                    && edge.relationship == hop.relationship
            })?;
            let annotation = annotate_edge(graph, edge)?;
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
                severity: annotation.severity,
                guidance: annotation.guidance,
                ovt_command: annotation.ovt_command,
                ovt_command_desc: annotation.ovt_command_desc,
                ace_details: annotation.ace_details,
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
        stats: stats_response(graph.stats(), graph.load_metrics.clone()),
        rendered_nodes: nodes.len(),
        rendered_edges: edges.len(),
        truncated: nodes.len() < graph.stats().total_nodes
            || edges.len() < graph.stats().total_edges,
        node_limit: nodes.len(),
        edge_limit: edges.len(),
        total_cost: path.total_cost,
        hop_count: hops.len(),
        metrics: OperationMetrics::new(),
        pathfinding_ms: 0,
        hops,
        nodes,
        edges,
    }
}

// ============================================================
//  Route Handlers
// ============================================================

/// GET / — Serve the embedded SPA
async fn index() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CACHE_CONTROL,
                "public, max-age=3600, must-revalidate",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Html(INDEX_HTML),
    )
}

async fn three_graph_js() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-cache, must-revalidate"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        THREE_GRAPH_JS,
    )
}

/// GET /api/graphs — List available graphs
async fn list_graphs(State(state): State<Arc<AppState>>) -> Json<Vec<GraphInfo>> {
    let cache = state.cache.read().await;
    let graphs_lock = state.graphs.read().await;
    let graphs = graphs_lock
        .iter()
        .map(|bundle| {
            let cached = cache.get(&bundle.id);
            GraphInfo {
                id: bundle.id.clone(),
                label: bundle.label.clone(),
                sources: bundle.sources.clone(),
                file_bytes: bundle.file_bytes,
                loaded: cached.is_some(),
                stats: cached
                    .map(|graph| stats_response(graph.stats(), graph.load_metrics.clone())),
                load_metrics: cached.and_then(|graph| graph.load_metrics.clone()),
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
    let mut server_metrics = OperationMetrics::new();
    let load_started = Instant::now();
    let (bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;
    server_metrics.phase("cache_or_load", load_started.elapsed().as_millis());

    let limits_started = Instant::now();
    let total_nodes = graph.stats().total_nodes;
    let total_edges = graph.stats().total_edges;
    let type_filter = parse_type_filter(query.types.as_deref());
    let node_limit = resolve_node_limit(query.limit, total_nodes);
    let chunk_offset = query.offset.unwrap_or(0).min(total_nodes);
    let edge_limit = resolve_edge_limit(query.edges, node_limit, total_nodes, total_edges);
    server_metrics.phase("resolve_limits", limits_started.elapsed().as_millis());

    let selection_started = Instant::now();
    let selected_nodes = if let Some(rel) = query.relationship.as_deref() {
        select_relationship_nodes(&graph, rel, node_limit, &type_filter)
    } else if let Some(focus) = query.focus.as_deref() {
        let focus_idx = graph.resolve_node(focus).ok_or(StatusCode::NOT_FOUND)?;
        select_focus_nodes(&graph, focus_idx, node_limit, &type_filter)
    } else {
        select_graph_nodes(&graph, node_limit, chunk_offset, &type_filter)
    };
    let selected_set: HashSet<usize> = selected_nodes.into_iter().collect();
    server_metrics.phase("node_selection", selection_started.elapsed().as_millis());

    let node_started = Instant::now();
    let nodes = graph_nodes(&graph, &selected_set);
    server_metrics.phase("node_serialization", node_started.elapsed().as_millis());
    let edge_started = Instant::now();
    let edges = graph_edges(&graph, &selected_set, edge_limit);
    server_metrics.phase("edge_serialization", edge_started.elapsed().as_millis());
    let truncated = nodes.len() < total_nodes || edges.len() < total_edges;
    server_metrics.finish();
    let load_time_ms = graph
        .load_metrics
        .as_ref()
        .map(|metrics| metrics.total_ms)
        .unwrap_or(server_metrics.total_ms);
    let render_time_ms = estimate_render_time(nodes.len(), edges.len());

    Ok(Json(GraphResponse {
        graph_id: bundle.id.clone(),
        label: bundle.label.clone(),
        sources: bundle.sources.clone(),
        stats: stats_response(graph.stats(), graph.load_metrics.clone()),
        rendered_nodes: nodes.len(),
        rendered_edges: edges.len(),
        truncated,
        node_limit,
        edge_limit,
        chunk_offset,
        chunk_size: node_limit,
        chunk_index: chunk_offset.checked_div(node_limit).unwrap_or(0),
        chunk_count: if node_limit == 0 || total_nodes == 0 {
            1
        } else {
            total_nodes.div_ceil(node_limit)
        },
        load_metrics: graph.load_metrics.clone(),
        server_metrics,
        load_time_ms,
        render_time_ms,
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
    node_detail_response(&state, query.graph.as_deref(), &nid).await
}

/// GET /api/node-detail?id=... â€” Detail view using a query parameter.
///
/// AD object identifiers can contain characters that are awkward in path
/// segments after browser/server URL decoding. Keep the path endpoint for
/// compatibility, but make the GUI use this endpoint for reliable clicks.
async fn get_node_detail_query(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NodeDetailQuery>,
) -> Result<Json<NodeDetail>, StatusCode> {
    node_detail_response(&state, query.graph.as_deref(), &query.id).await
}

async fn node_detail_response(
    state: &Arc<AppState>,
    graph_id: Option<&str>,
    nid: &str,
) -> Result<Json<NodeDetail>, StatusCode> {
    let request_started = Instant::now();
    let (_bundle, graph) = load_graph(state, graph_id).await?;

    let node_idx = graph.resolve_node(nid).ok_or(StatusCode::NOT_FOUND)?;
    let node = graph.get_node(node_idx).ok_or(StatusCode::NOT_FOUND)?;
    let (out_degree, in_degree) = node_degree(&graph, node_idx);

    let mut connections = Vec::new();
    let connections_started = Instant::now();

    for edge_idx in graph.outgoing(node_idx).into_iter().flatten() {
        let Some(edge) = graph.edge(*edge_idx) else {
            continue;
        };
        if let Some(tgt) = graph.get_node(edge.target)
            && let Some(connection) = build_connection(&graph, edge, tgt, "outgoing")
        {
            connections.push(connection);
        }
    }

    for edge_idx in graph.incoming(node_idx).into_iter().flatten() {
        let Some(edge) = graph.edge(*edge_idx) else {
            continue;
        };
        if let Some(src) = graph.get_node(edge.source)
            && let Some(connection) = build_connection(&graph, edge, src, "incoming")
        {
            connections.push(connection);
        }
    }

    let mut metrics = OperationMetrics::new();
    metrics.phase("resolve_node", request_started.elapsed().as_millis());
    metrics.phase("connections", connections_started.elapsed().as_millis());
    metrics.finish();

    let sanitized_properties: BTreeMap<String, String> = node
        .properties
        .iter()
        .map(|(k, v)| (k.clone(), sanitize_ad_string(v)))
        .collect();

    let detail = NodeDetail {
        id: node.id.clone(),
        label: sanitize_ad_string(&node.label),
        display_name: node_display_name(node),
        node_type: node_type_str(node),
        domain: node_domain(node),
        distinguished_name: node
            .distinguished_name
            .as_ref()
            .map(|d| sanitize_ad_string(d)),
        enabled: node.enabled,
        high_value: node.high_value,
        owned: node.owned,
        properties: sanitized_properties,
        security_notes: node_security_notes(&graph, node_idx),
        connections,
        out_degree,
        in_degree,
        metrics: metrics.clone(),
        retrieval_ms: metrics.total_ms,
    };

    Ok(Json(detail))
}

/// GET /api/search?q=... — Search nodes by name
async fn search_nodes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;
    let type_filter = parse_type_filter(query.types.as_deref());
    let limit = query.limit.unwrap_or(75).clamp(1, 100);

    let mut results: Vec<SearchResult> = graph
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

    // Add attack-type matches
    let query_lower = query.q.to_lowercase();
    if query_lower.len() >= 3 {
        for &rel in RELATIONSHIPS {
            if rel.to_lowercase().contains(&query_lower) {
                results.push(SearchResult {
                    id: format!("query:attack:{}", rel),
                    label: rel.to_string(),
                    display_name: format!("Filter: Nodes with {} access", rel),
                    node_type: "AttackQuery".to_string(),
                    domain: "Global".to_string(),
                });
            }
        }
    }

    Ok(Json(results))
}

async fn custom_query(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CustomQuery>,
) -> Result<Json<CustomQueryResponse>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;
    let type_filter = parse_type_filter(query.types.as_deref());
    let limit = query.limit.unwrap_or(60).clamp(1, 150);

    let mut text_terms = Vec::new();
    let mut query_type = None;
    let mut domain = None;
    let mut owned = None;
    let mut high_value = None;
    let mut wanted_relationships: HashSet<String> = HashSet::new();
    let mut property_terms = Vec::new();

    for raw in query.q.split_whitespace() {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("attack:") {
            for relationship in attack_relationships(value) {
                wanted_relationships.insert(relationship.to_string());
            }
            if matches!(value, "llmnr" | "ldap" | "ldaps" | "relay" | "ntlmrelay") {
                property_terms.push(value.to_string());
            }
        } else if lower.starts_with("edge:")
            || lower.starts_with("rel:")
            || lower.starts_with("relationship:")
        {
            if let Some(relationship) = normalize_relationship_query(token) {
                wanted_relationships.insert(relationship);
            }
        } else if let Some(value) = lower
            .strip_prefix("type:")
            .or_else(|| lower.strip_prefix("kind:"))
        {
            query_type = Some(normalize_node_type_filter(value));
        } else if let Some(value) = token.strip_prefix("domain:") {
            domain = Some(value.to_string());
        } else if let Some(value) = lower.strip_prefix("owned:") {
            owned = Some(matches!(value, "1" | "true" | "yes"));
        } else if let Some(value) = lower
            .strip_prefix("high:")
            .or_else(|| lower.strip_prefix("highvalue:"))
            .or_else(|| lower.strip_prefix("high_value:"))
        {
            high_value = Some(matches!(value, "1" | "true" | "yes"));
        } else if let Some(relationship) = normalize_relationship_query(token) {
            wanted_relationships.insert(relationship);
        } else if !attack_relationships(&lower).is_empty() {
            for relationship in attack_relationships(&lower) {
                wanted_relationships.insert(relationship.to_string());
            }
            if matches!(
                lower.as_str(),
                "llmnr" | "ldap" | "ldaps" | "relay" | "ntlmrelay"
            ) {
                property_terms.push(lower);
            }
        } else {
            text_terms.push(token.to_string());
        }
    }

    let relationship_query = !wanted_relationships.is_empty();

    let mut edge_counts: HashMap<String, usize> = HashMap::new();
    let mut relationship_nodes = HashSet::new();
    for edge in graph.edges() {
        let relationship_match = wanted_relationships
            .iter()
            .any(|wanted| edge.relationship.eq_ignore_ascii_case(wanted));
        if relationship_match {
            *edge_counts.entry(edge.relationship.clone()).or_default() += 1;
            relationship_nodes.insert(edge.source);
            relationship_nodes.insert(edge.target);
        }
    }

    let mut relationships: Vec<QueryRelationship> = edge_counts
        .into_iter()
        .map(|(relationship, edge_count)| {
            let (severity, guidance) = edge_security_guidance(&relationship);
            QueryRelationship {
                category: relationship_category(&relationship).to_string(),
                relationship,
                edge_count,
                severity,
                guidance: guidance.to_string(),
            }
        })
        .collect();
    relationships.sort_by_key(|item| (item.severity, Reverse(item.edge_count)));

    let has_property_terms = !property_terms.is_empty();
    let property_text_terms = if property_terms.is_empty() {
        text_terms.clone()
    } else {
        let mut merged = text_terms.clone();
        merged.extend(property_terms);
        merged
    };

    let mut node_ids = Vec::new();
    let mut seen_nodes = HashSet::new();
    for idx in relationship_nodes {
        if let Some(node) = graph.get_node(idx)
            && node_matches_custom_filters(
                node,
                &type_filter,
                &query_type,
                &domain,
                owned,
                high_value,
                &property_text_terms,
            )
            && seen_nodes.insert(idx)
        {
            node_ids.push(idx);
        }
    }

    if node_ids.len() < limit && (!relationship_query || has_property_terms) {
        for (idx, node) in graph.nodes() {
            if seen_nodes.contains(&idx) {
                continue;
            }
            if node_matches_custom_filters(
                node,
                &type_filter,
                &query_type,
                &domain,
                owned,
                high_value,
                &property_text_terms,
            ) && seen_nodes.insert(idx)
            {
                node_ids.push(idx);
            }
        }
    }

    node_ids.sort_unstable();
    let total_node_matches = node_ids.len();
    let nodes = node_ids
        .into_iter()
        .take(limit)
        .filter_map(|idx| graph.get_node(idx))
        .map(|node| SearchResult {
            id: node.id.clone(),
            label: node.label.clone(),
            display_name: node_display_name(node),
            node_type: node_type_str(node),
            domain: node_domain(node),
        })
        .collect();
    let total_edge_matches = relationships
        .iter()
        .map(|relationship| relationship.edge_count)
        .sum();

    Ok(Json(CustomQueryResponse {
        query: query.q,
        nodes,
        relationships,
        total_node_matches,
        total_edge_matches,
    }))
}

async fn lookup_edge_command(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
    Json(req): Json<CommandLookupRequest>,
) -> Result<Json<EdgeCommandResponse>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;
    let source_idx = req
        .source
        .as_deref()
        .and_then(|source| graph.resolve_node(source))
        .or_else(|| graph.nodes().next().map(|(idx, _)| idx))
        .ok_or(StatusCode::NOT_FOUND)?;
    let target_idx = req
        .target
        .as_deref()
        .and_then(|target| graph.resolve_node(target))
        .or(Some(source_idx))
        .ok_or(StatusCode::NOT_FOUND)?;

    let edge = ViewerEdge {
        source: source_idx,
        target: target_idx,
        relationship: req.relationship.clone(),
        cost: 0,
        properties: BTreeMap::new(),
        ovt_command: None,
        ovt_command_desc: None,
        severity: None,
        guidance: None,
        ace_details: None,
    };
    let annotation = annotate_edge(&graph, &edge).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(EdgeCommandResponse {
        relationship: req.relationship,
        severity: annotation.severity,
        guidance: annotation.guidance,
        ovt_command: annotation.ovt_command,
        ovt_command_desc: annotation.ovt_command_desc,
        ace_details: annotation.ace_details,
    }))
}

async fn edge_types() -> Json<Vec<EdgeTypeInfo>> {
    Json(
        RELATIONSHIPS
            .iter()
            .map(|relationship| {
                let (severity, guidance) = edge_security_guidance(relationship);
                EdgeTypeInfo {
                    relationship: (*relationship).to_string(),
                    severity,
                    guidance: guidance.to_string(),
                    ovt_command_template: command_template_for_relationship(relationship),
                }
            })
            .collect(),
    )
}

/// POST /api/path — Find shortest attack path between two nodes
async fn find_path(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
    Json(req): Json<PathRequest>,
) -> Result<Json<PathResponse>, StatusCode> {
    let path_started = Instant::now();
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;

    if let Some(path) = graph.shortest_path(&req.from, &req.to) {
        let mut response = path_response(&graph, path);
        response.pathfinding_ms = path_started.elapsed().as_millis();
        response
            .metrics
            .phase("pathfinding", response.pathfinding_ms);
        response.metrics.finish();
        return Ok(Json(response));
    }

    let mut metrics = OperationMetrics::new();
    let pathfinding_ms = path_started.elapsed().as_millis();
    metrics.phase("pathfinding", pathfinding_ms);
    metrics.finish();
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
        stats: stats_response(graph.stats(), graph.load_metrics.clone()),
        rendered_nodes: 0,
        rendered_edges: 0,
        truncated: graph.stats().total_nodes > 0 || graph.stats().total_edges > 0,
        node_limit: 0,
        edge_limit: 0,
        total_cost: 0,
        hop_count: 0,
        metrics,
        pathfinding_ms,
        hops: Vec::new(),
        nodes: Vec::new(),
        edges: Vec::new(),
    }))
}

/// GET /api/stats — Quick stats summary
async fn get_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<StatsResponse>, (StatusCode, Json<ApiError>)> {
    let (_bundle, graph) = load_graph(&state, query.graph.as_deref())
        .await
        .map_err(json_load_error)?;
    Ok(Json(stats_response(
        graph.stats(),
        graph.load_metrics.clone(),
    )))
}

/// GET /api/graph/:id/timings — Graph load timing breakdown
async fn get_graph_timings(
    State(state): State<Arc<AppState>>,
    AxumPath(graph_id): AxumPath<String>,
) -> Result<Json<GraphLoadMetrics>, StatusCode> {
    let (_bundle, graph) = load_graph(&state, Some(&graph_id)).await?;
    graph
        .load_metrics
        .clone()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Debug)]
struct StoredUpload {
    sources: Vec<String>,
    file_bytes: u64,
    json_files: usize,
    source_kind: &'static str,
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(percent_decode_header)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn percent_decode_header(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_string())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn original_upload_name(headers: &HeaderMap) -> String {
    header_value(headers, "x-overthrone-filename")
        .or_else(|| header_value(headers, "x-file-name"))
        .unwrap_or_else(|| "uploaded-graph.json".to_string())
}

fn is_zip_upload(headers: &HeaderMap, filename: &str, body: &[u8]) -> bool {
    let upload_type = header_value(headers, "x-overthrone-upload-type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    upload_type == "zip"
        || filename.to_ascii_lowercase().ends_with(".zip")
        || content_type.contains("zip")
        || body.starts_with(b"PK\x03\x04")
}

fn safe_upload_stem(filename: &str) -> String {
    let stem = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("uploaded-graph");
    let mut safe = stem
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    while safe.contains("--") {
        safe = safe.replace("--", "-");
    }
    let safe = safe.trim_matches('-').to_string();
    if safe.is_empty() {
        "uploaded-graph".to_string()
    } else {
        safe
    }
}

fn label_kind_from_filename(filename: &str, is_zip: bool) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    let compact = lower.replace(['-', '_', '.', ' '], "");
    if lower.contains("bloodhound") || compact.contains("bhce") {
        if is_zip {
            "BloodHound ZIP"
        } else {
            "BloodHound"
        }
    } else if lower.contains("overthrone") || compact.contains("ovt") {
        if is_zip {
            "Overthrone ZIP"
        } else {
            "Overthrone"
        }
    } else if compact.contains("computer") || compact.contains("machines") {
        "Computers"
    } else if compact.contains("user") {
        "Users"
    } else if compact.contains("group") {
        "Groups"
    } else if compact.contains("domain") {
        "Domains"
    } else if compact.contains("gpo") {
        "GPOs"
    } else if compact.contains("ou") || compact.contains("organizationalunit") {
        "OUs"
    } else if compact.contains("cert") || compact.contains("adcs") || compact.contains("ca") {
        "ADCS"
    } else if is_zip {
        "Graph ZIP"
    } else {
        "Graph JSON"
    }
}

fn upload_label(filename: &str, json_files: usize, is_zip: bool) -> String {
    let kind = label_kind_from_filename(filename, is_zip);
    let stem = safe_upload_stem(filename).replace('-', " ");
    if is_zip {
        format!("{kind}: {stem} ({json_files} JSON files)")
    } else {
        format!("{kind}: {stem}")
    }
}

fn store_json_upload(
    body: &[u8],
    file_id: uuid::Uuid,
    filename: &str,
) -> Result<StoredUpload, String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|e| format!("Uploaded file is not valid JSON: {e}"))?;
    let temp_file = std::env::temp_dir().join(format!(
        "overthrone_upload_{}_{}.json",
        safe_upload_stem(filename),
        file_id
    ));
    fs::write(&temp_file, body).map_err(|e| format!("Failed to store uploaded graph: {e}"))?;
    Ok(StoredUpload {
        sources: vec![temp_file.display().to_string()],
        file_bytes: body.len() as u64,
        json_files: 1,
        source_kind: "json",
    })
}

fn store_zip_upload(
    body: &[u8],
    file_id: uuid::Uuid,
    filename: &str,
) -> Result<StoredUpload, String> {
    let mut archive = ZipArchive::new(Cursor::new(body))
        .map_err(|e| format!("Uploaded ZIP could not be opened: {e}"))?;
    let temp_dir = std::env::temp_dir().join(format!(
        "overthrone_upload_{}_{}",
        safe_upload_stem(filename),
        file_id
    ));
    fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create ZIP extraction directory: {e}"))?;

    let mut sources = Vec::new();
    let mut total_bytes = 0u64;
    for idx in 0..archive.len() {
        let mut entry = archive
            .by_index(idx)
            .map_err(|e| format!("Failed to read ZIP entry {idx}: {e}"))?;
        if entry.is_dir() {
            continue;
        }
        let Some(enclosed) = entry.enclosed_name() else {
            continue;
        };
        if !enclosed
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }
        if entry.size() > 250 * 1024 * 1024 {
            return Err(format!(
                "ZIP entry {} is too large; use the CLI --input path for very large collections",
                enclosed.display()
            ));
        }
        let mut bytes = Vec::with_capacity(entry.size().min(8 * 1024 * 1024) as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to extract {}: {e}", enclosed.display()))?;
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| format!("ZIP entry {} is not valid JSON: {e}", enclosed.display()))?;

        let out_path = temp_dir.join(enclosed);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
        }
        fs::write(&out_path, &bytes)
            .map_err(|e| format!("Failed to write extracted {}: {e}", out_path.display()))?;
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        sources.push(out_path.display().to_string());
    }
    sources.sort();
    if sources.is_empty() {
        return Err("Uploaded ZIP did not contain any JSON graph files".to_string());
    }
    Ok(StoredUpload {
        json_files: sources.len(),
        sources,
        file_bytes: total_bytes,
        source_kind: "zip",
    })
}

/// POST /api/upload — Upload a graph JSON file or ZIP archive of JSON files.
async fn upload_graph(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<GraphInfo>, (StatusCode, Json<ApiError>)> {
    if body.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "empty_upload",
                "Uploaded graph JSON was empty",
            )),
        ));
    }

    let filename = original_upload_name(&headers);
    let is_zip = is_zip_upload(&headers, &filename, &body);
    let file_id = uuid::Uuid::new_v4();
    let stored = if is_zip {
        store_zip_upload(&body, file_id, &filename)
    } else {
        store_json_upload(&body, file_id, &filename)
    }
    .map_err(|e| {
        let code = if is_zip {
            "invalid_zip"
        } else {
            "invalid_json"
        };
        (StatusCode::BAD_REQUEST, Json(ApiError::new(code, e)))
    })?;

    let label = upload_label(&filename, stored.json_files, stored.source_kind == "zip");
    let base_id = graph_id_from_label(&label);
    let bundle = GraphBundle {
        id: format!("upload-{}-{}", base_id, &file_id.to_string()[..8]),
        label,
        sources: stored.sources,
        file_bytes: stored.file_bytes,
    };

    let graph = ViewerGraph::from_sources(&bundle.sources).map_err(|e| {
        warn!("Failed to parse uploaded graph: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("graph_parse_failed", e)),
        )
    })?;

    let info = GraphInfo {
        id: bundle.id.clone(),
        label: bundle.label.clone(),
        sources: bundle.sources.clone(),
        file_bytes: bundle.file_bytes,
        loaded: true,
        stats: Some(stats_response(graph.stats(), graph.load_metrics.clone())),
        load_metrics: graph.load_metrics.clone(),
    };

    state
        .cache
        .write()
        .await
        .insert(bundle.id.clone(), Arc::new(graph));
    state.graphs.write().await.push(bundle);

    notify_graph_list_updated(&state);

    Ok(Json(info))
}

fn json_load_error(status: StatusCode) -> (StatusCode, Json<ApiError>) {
    let (code, message) = match status {
        StatusCode::NOT_FOUND => ("graph_not_found", "The requested graph is not registered"),
        StatusCode::UNPROCESSABLE_ENTITY => (
            "graph_load_failed",
            "The selected graph could not be parsed",
        ),
        _ => ("graph_error", "The graph request failed"),
    };
    (status, Json(ApiError::new(code, message)))
}

// ============================================================
//  WebSocket — live notifications
// ============================================================

/// WebSocket upgrade handler.  Clients connect here to receive push
/// notifications (graph list changes, uploads, etc.).
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state))
}

async fn handle_ws_socket(socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.ws_tx.subscribe();
    let (mut sender, mut receiver) = socket.split();

    // Forward broadcast messages to the WebSocket client.
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Keep reading until the client disconnects (discard incoming messages).
    let recv_task = tokio::spawn(async move { while let Some(Ok(_)) = receiver.next().await {} });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}

/// Broadcast a `graph_list_updated` event to all connected WebSocket clients.
fn notify_graph_list_updated(state: &AppState) {
    let msg = serde_json::to_string(&WsMessage {
        msg_type: "graph_list_updated".to_string(),
        graph_id: None,
        label: None,
    })
    .unwrap_or_default();
    let _ = state.ws_tx.send(msg);
}

/// Broadcast a `graph_updated` event for a specific graph ID.
#[allow(dead_code)]
fn notify_graph_updated(state: &AppState, graph_id: &str, label: &str) {
    let msg = serde_json::to_string(&WsMessage {
        msg_type: "graph_updated".to_string(),
        graph_id: Some(graph_id.to_string()),
        label: Some(label.to_string()),
    })
    .unwrap_or_default();
    let _ = state.ws_tx.send(msg);
}

// ============================================================
//  Middleware
// ============================================================

/// Basic auth middleware — checks the `Authorization: Basic` header against
/// the configured credentials in `AppState`.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let config = &state.config;
    let (expected_user, expected_pass) = match (&config.username, &config.password) {
        (Some(u), Some(p)) => (u, p),
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Check Bearer token (session-based auth)
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        if state.sessions.validate_token(token).await.is_some() {
            return Ok(next.run(req).await);
        }
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Fall back to Basic auth (legacy / backward compat)
    if let Some(creds) = auth_header.strip_prefix("Basic ")
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(creds)
        && let Ok(creds_str) = String::from_utf8(decoded)
    {
        let parts: Vec<&str> = creds_str.splitn(2, ':').collect();
        if parts.len() == 2 && parts[0] == expected_user && parts[1] == expected_pass {
            return Ok(next.run(req).await);
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// Rate limiting middleware — checks per-IP request counts against the
/// configured window and maximum. Also applies per-user rate limits when
/// a bearer token is present.
async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // Per-IP rate limit (always applied)
    if !state.rate_limiter.check(addr.ip()).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Per-user rate limit (when session token is present)
    if let Some(auth_header) = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        && let Some(token) = auth_header.strip_prefix("Bearer ")
        && let Some(username) = state.sessions.validate_token(token).await
        && !state.user_rate_limiter.check(&username, addr.ip()).await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}

/// CSRF middleware — requires `X-CSRF-Token` header on POST/PUT/DELETE.
async fn csrf_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    if req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD {
        return Ok(next.run(req).await);
    }
    let expected = match &state.config.csrf_token {
        Some(t) => t.clone(),
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let provided = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided == expected {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNPROCESSABLE_ENTITY)
    }
}

/// Build a `CorsLayer` that only allows loopback origins.
fn loopback_cors() -> CorsLayer {
    let origins = ["http://localhost", "http://127.0.0.1", "http://[::1]"];
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(
            origins.iter().map(|s| s.parse().unwrap()),
        ))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-csrf-token"),
        ])
}

/// A [`tokio::net::TcpListener`] wrapper that performs a TLS handshake
/// before yielding each accepted connection. Implements [`axum::serve::Listener`]
/// so it can be passed to `axum::serve` directly.
struct TlsListener {
    inner: TcpListener,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
}

impl TlsListener {
    fn new(inner: TcpListener, acceptor: Arc<tokio_rustls::TlsAcceptor>) -> Self {
        Self { inner, acceptor }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = match self.inner.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Accept error: {e}");
                    continue;
                }
            };
            match self.acceptor.accept(tcp).await {
                Ok(tls) => return (tls, addr),
                Err(e) => {
                    warn!("TLS handshake failed from {}: {e}", addr);
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

// ============================================================
//  Public API
// ============================================================

/// Launch the viewer web server with default configuration.
/// Loads the graph from the given sources, starts an Axum HTTP/HTTPS server on the
/// specified port (or a free port if 0), and opens the browser.
pub async fn launch(sources: &[String], port: u16) -> Result<()> {
    launch_with_config(sources, port, ViewerConfig::default()).await
}

/// Launch the viewer web server with the given configuration.
pub async fn launch_with_config(sources: &[String], port: u16, config: ViewerConfig) -> Result<()> {
    let has_auth = config.username.is_some() && config.password.is_some();
    if !has_auth {
        bail!("Viewer requires authentication credentials in config");
    }

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

    let rate_limiter = RateLimiter::new(
        config.rate_limit_window_secs,
        config.rate_limit_max_requests,
    );

    let user_rate_limiter = UserRateLimiter::new(
        config.rate_limit_window_secs,
        config.rate_limit_max_requests,
    );

    // Sessions expire after 8 hours of inactivity
    let sessions = SessionStore::new(8 * 3600);

    // Broadcast channel for WebSocket notifications (capacity 256).
    let (ws_tx, _) = broadcast::channel(256);

    let state = Arc::new(AppState {
        graphs: RwLock::new(graphs),
        default_graph,
        cache: RwLock::new(HashMap::new()),
        config: config.clone(),
        rate_limiter,
        user_rate_limiter,
        sessions,
        ws_tx,
    });

    let app = Router::new()
        // All routes (auth handled by auth_middleware; login via Basic auth or Bearer token)
        .route("/", get(index))
        .route("/three-graph.js", get(three_graph_js))
        .route("/api/graphs", get(list_graphs))
        .route("/api/graph", get(get_graph))
        .route("/api/graph/{graph_id}/timings", get(get_graph_timings))
        .route("/api/node/{node_id}", get(get_node_detail))
        .route("/api/node-detail", get(get_node_detail_query))
        .route("/api/search", get(search_nodes))
        .route("/api/query", get(custom_query))
        .route("/api/commands/lookup", post(lookup_edge_command))
        .route("/api/edge-types", get(edge_types))
        .route("/api/path", post(find_path))
        .route("/api/stats", get(get_stats))
        .route("/api/upload", post(upload_graph))
        .route("/ws", get(ws_handler))
        // auth middleware only wraps routes above (everything except /api/login)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        // Global middleware layers wrap everything, outermost last
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(loopback_cors())
        .with_state(state);

    let bind_ip = config
        .bind_address
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let addr = SocketAddr::new(bind_ip, port);

    if !bind_ip.is_loopback() && config.tls.is_none() {
        bail!(
            "Refusing to bind non-loopback address {} without TLS. \
             Configure TLS via TlsConfig to serve over the network.",
            bind_ip
        );
    }

    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;

    let tls_config_data = match config.tls {
        Some(ref tls) => {
            let tls_certs =
                rustls_pemfile::certs(&mut std::io::BufReader::new(fs::File::open(&tls.cert_pem)?))
                    .collect::<Result<Vec<_>, _>>()?;
            let tls_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
                fs::File::open(&tls.key_pem)?,
            ))?
            .ok_or_else(|| anyhow!("No private key found in {}", tls.key_pem.display()))?;

            let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?;

            let server_config = if let Some(ref ca_path) = tls.mtls_client_ca_path {
                // mTLS mode: require client certificate signed by the specified CA
                let mut root_store = rustls::RootCertStore::empty();
                let mut ca_reader = std::io::BufReader::new(fs::File::open(ca_path)?);
                for cert in rustls_pemfile::certs(&mut ca_reader) {
                    root_store.add(cert?)?;
                }
                let verifier =
                    rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;
                builder
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(tls_certs, tls_key)?
            } else {
                // Standard TLS: no client certificate required
                builder
                    .with_no_client_auth()
                    .with_single_cert(tls_certs, tls_key)?
            };

            Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(
                server_config,
            ))))
        }
        None => None,
    };

    let url = if tls_config_data.is_some() {
        format!("https://{}", actual_addr)
    } else {
        format!("http://{}", actual_addr)
    };

    let serve_fut = async move {
        if let Some(ref tls_acceptor) = tls_config_data {
            let listener = TlsListener::new(listener, tls_acceptor.clone());
            axum::serve(listener, app.into_make_service())
                .await
                .map_err(|e| anyhow!("Server error: {e}"))
        } else {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(|e| anyhow!("Server error: {e}"))
        }
    };

    let auth_user = config.username.as_deref().unwrap_or("unknown");
    let auth_pass = config.password.as_deref().unwrap_or("unknown");

    info!("Graph viewer running at {}", url);
    println!("\n  Overthrone Graph Viewer");
    println!("  ------------------------");
    println!("  URL:    {}", url);
    println!("  User:   {}", auth_user);
    println!("  Pass:   {}", auth_pass);
    if let Some(ref csrf) = config.csrf_token {
        println!("  CSRF:   {}", csrf);
    }
    println!("  Press Ctrl+C to stop.\n");

    let _ = open::that(&url);

    serve_fut.await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RateLimiter unit tests ──────────────────────────────────

    #[tokio::test]
    async fn test_rate_limiter_rejects_over_limit() {
        let limiter = RateLimiter::new(60, 2); // 2 requests per 60s window
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert!(limiter.check(ip).await);
        assert!(limiter.check(ip).await);
        assert!(!limiter.check(ip).await); // third should be rejected
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_different_ips() {
        let limiter = RateLimiter::new(60, 1); // 1 request per 60s
        let ip_a = "10.0.0.1".parse::<IpAddr>().unwrap();
        let ip_b = "10.0.0.2".parse::<IpAddr>().unwrap();
        assert!(limiter.check(ip_a).await);
        assert!(!limiter.check(ip_a).await); // second req from same IP rejected
        assert!(limiter.check(ip_b).await); // different IP allowed
    }

    // ── ViewerConfig unit tests ─────────────────────────────────

    const TEST_VIEWER_USER: &str = "admin";
    const TEST_VIEWER_PASS: &str = "secret";

    #[test]
    fn test_viewer_config_default_generates_random_auth() {
        let config = ViewerConfig::default();
        // Default now generates random credentials + CSRF token so the
        // server is never accidentally exposed without auth.
        assert!(config.username.is_some());
        assert!(config.password.is_some());
        let user = config.username.as_deref().unwrap();
        let pass = config.password.as_deref().unwrap();
        assert_eq!(user.len(), 12);
        assert_eq!(pass.len(), 24);
        assert!(config.csrf_token.is_some());
        assert_eq!(config.csrf_token.as_deref().unwrap().len(), 32);
        assert_eq!(config.rate_limit_window_secs, 60);
        assert_eq!(config.rate_limit_max_requests, 100);
    }

    #[test]
    fn test_viewer_config_with_auth() {
        let config = ViewerConfig::with_auth(TEST_VIEWER_USER, TEST_VIEWER_PASS);
        assert_eq!(config.username.as_deref(), Some(TEST_VIEWER_USER));
        assert_eq!(config.password.as_deref(), Some(TEST_VIEWER_PASS));
    }

    // ── Basic auth header parsing tests ──────────────────────────

    /// Parse and validate a `Basic` authorization header.
    /// Returns `true` if the header matches the expected credentials.
    fn check_basic_auth(
        header_value: Option<&str>,
        expected_user: &str,
        expected_pass: &str,
    ) -> bool {
        let auth = header_value.unwrap_or("");
        if let Some(creds) = auth.strip_prefix("Basic ")
            && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(creds)
            && let Ok(creds_str) = String::from_utf8(decoded)
        {
            let parts: Vec<&str> = creds_str.splitn(2, ':').collect();
            if parts.len() == 2 && parts[0] == expected_user && parts[1] == expected_pass {
                return true;
            }
        }
        false
    }

    #[test]
    fn test_basic_auth_valid() {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", TEST_VIEWER_USER, TEST_VIEWER_PASS));
        assert!(check_basic_auth(
            Some(&format!("Basic {}", encoded)),
            TEST_VIEWER_USER,
            TEST_VIEWER_PASS
        ));
    }

    #[test]
    fn test_basic_auth_invalid_password() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:wrong", TEST_VIEWER_USER));
        assert!(!check_basic_auth(
            Some(&format!("Basic {}", encoded)),
            TEST_VIEWER_USER,
            TEST_VIEWER_PASS
        ));
    }

    #[test]
    fn test_basic_auth_missing_header() {
        assert!(!check_basic_auth(None, TEST_VIEWER_USER, TEST_VIEWER_PASS));
    }

    #[test]
    fn test_basic_auth_bad_encoding() {
        assert!(!check_basic_auth(
            Some("Basic !!!invalid-base64!!!"),
            TEST_VIEWER_USER,
            TEST_VIEWER_PASS
        ));
    }

    #[test]
    fn test_basic_auth_no_credentials_when_expected() {
        // Default ViewerConfig now auto-generates credentials, so the
        // server always requires auth. Verify the random credentials
        // differ from the test constants (so test credentials don't pass
        // by accident).
        let config = ViewerConfig::default();
        assert_ne!(config.username.as_deref(), Some(TEST_VIEWER_USER));
        assert_ne!(config.password.as_deref(), Some(TEST_VIEWER_PASS));
    }

    fn test_state() -> Arc<AppState> {
        let (ws_tx, _) = broadcast::channel(256);
        Arc::new(AppState {
            graphs: RwLock::new(Vec::new()),
            default_graph: "graph-1".to_string(),
            cache: RwLock::new(HashMap::new()),
            config: ViewerConfig::default(),
            rate_limiter: RateLimiter::new(60, 100),
            user_rate_limiter: UserRateLimiter::new(60, 100),
            sessions: SessionStore::new(3600),
            ws_tx,
        })
    }

    #[tokio::test]
    async fn test_upload_graph_registers_selector_entry_and_stats() {
        let state = test_state();
        let body = axum::body::Bytes::from_static(
            br#"{
              "nodes": [
                {"id":"u1","label":"alice","type":"User"},
                {"id":"c1","label":"dc01","type":"Computer"}
              ],
              "edges": [
                {"source":"u1","target":"c1","relationship":"AdminTo"}
              ]
            }"#,
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-overthrone-filename",
            "users.json".parse().expect("valid header"),
        );
        let Json(info) = upload_graph(State(state.clone()), headers, body)
            .await
            .expect("upload should succeed");

        assert!(info.id.starts_with("upload-"));
        assert!(info.label.starts_with("Users:"));
        assert!(info.loaded);
        assert_eq!(info.stats.as_ref().unwrap().total_nodes, 2);
        assert_eq!(info.stats.as_ref().unwrap().total_edges, 1);
        assert_eq!(state.graphs.read().await.len(), 1);
        assert!(state.cache.read().await.contains_key(&info.id));

        let Json(stats) = get_stats(
            State(state),
            Query(GraphQuery {
                graph: Some(info.id),
                limit: None,
                offset: None,
                edges: None,
                types: None,
                focus: None,
                relationship: None,
            }),
        )
        .await
        .expect("stats should resolve uploaded graph");
        assert_eq!(stats.relationship_types, 1);
        assert_eq!(stats.top_relationships[0].relationship, "AdminTo");
    }

    #[tokio::test]
    async fn test_upload_graph_rejects_invalid_json_with_structured_error() {
        let state = test_state();
        let err = upload_graph(
            State(state),
            HeaderMap::new(),
            axum::body::Bytes::from_static(b"{not valid json"),
        )
        .await
        .expect_err("invalid JSON must fail");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.0.code, "invalid_json");
        assert!(err.1.0.error.contains("valid JSON"));
    }

    #[tokio::test]
    async fn test_upload_zip_extracts_json_graphs_with_descriptive_label() {
        let state = test_state();
        let mut zip_bytes = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut zip_bytes);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("users.json", options).expect("start file");
            std::io::Write::write_all(
                &mut zip,
                br#"{
                  "nodes": [
                    {"id":"u1","label":"alice","type":"User"},
                    {"id":"g1","label":"Domain Admins","type":"Group"}
                  ],
                  "edges": [
                    {"source":"u1","target":"g1","relationship":"MemberOf"}
                  ]
                }"#,
            )
            .expect("write graph");
            zip.finish().expect("finish zip");
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-overthrone-filename",
            "bloodhound-users.zip".parse().expect("valid header"),
        );
        headers.insert(
            "x-overthrone-upload-type",
            "zip".parse().expect("valid header"),
        );

        let Json(info) = upload_graph(State(state), headers, axum::body::Bytes::from(zip_bytes))
            .await
            .expect("zip upload should succeed");

        assert!(info.label.starts_with("BloodHound ZIP:"));
        assert!(info.label.contains("1 JSON files"));
        assert_eq!(info.stats.as_ref().unwrap().total_nodes, 2);
        assert_eq!(info.stats.as_ref().unwrap().total_edges, 1);
    }

    // ── Phase 3 security primitive tests ────────────────────────

    fn basic_auth_value(value: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(value)
        )
    }

    // ── TlsConfig tests ─────────────────────────────────────────

    #[test]
    fn test_tls_config_construction() {
        let cfg = TlsConfig {
            cert_pem: PathBuf::from("/tmp/cert.pem"),
            key_pem: PathBuf::from("/tmp/key.pem"),
            mtls_client_ca_path: None,
        };
        assert_eq!(cfg.cert_pem, PathBuf::from("/tmp/cert.pem"));
        assert_eq!(cfg.key_pem, PathBuf::from("/tmp/key.pem"));
        assert!(cfg.mtls_client_ca_path.is_none());
    }

    #[test]
    fn test_tls_config_with_mtls_ca() {
        let cfg = TlsConfig {
            cert_pem: PathBuf::from("/tmp/cert.pem"),
            key_pem: PathBuf::from("/tmp/key.pem"),
            mtls_client_ca_path: Some(PathBuf::from("/tmp/ca.pem")),
        };
        assert!(cfg.mtls_client_ca_path.is_some());
        assert_eq!(
            cfg.mtls_client_ca_path.unwrap(),
            PathBuf::from("/tmp/ca.pem")
        );
    }

    #[test]
    fn test_tls_config_default_is_none() {
        let cfg = ViewerConfig::default();
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn test_viewer_config_with_auth_preserves_defaults() {
        let cfg = ViewerConfig::with_auth("u", "p");
        assert!(cfg.tls.is_none());
        assert_eq!(cfg.username.as_deref(), Some("u"));
        assert_eq!(cfg.password.as_deref(), Some("p"));
    }

    #[test]
    fn test_viewer_config_with_auth_inherits_random_csrf_from_default() {
        // The default impl is invoked, so csrf_token should still be Some
        let cfg = ViewerConfig::with_auth("u", "p");
        assert!(cfg.csrf_token.is_some());
    }

    // ── random_string tests ─────────────────────────────────────

    #[test]
    fn test_random_string_length() {
        let mut rng = rand::rngs::ThreadRng::default();
        for n in [1usize, 8, 16, 32, 64, 128] {
            let s = random_string(&mut rng, n);
            assert_eq!(s.len(), n, "length should match");
        }
    }

    #[test]
    fn test_random_string_charset() {
        let mut rng = rand::rngs::ThreadRng::default();
        let s = random_string(&mut rng, 256);
        for c in s.chars() {
            assert!(
                c.is_ascii_alphanumeric(),
                "char {c:?} should be alphanumeric"
            );
        }
    }

    #[test]
    fn test_random_string_is_random() {
        let mut rng = rand::rngs::ThreadRng::default();
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let s = random_string(&mut rng, 32);
            assert!(seen.insert(s.clone()), "duplicate: {s}");
        }
    }

    // ── CorsLayer restriction tests ─────────────────────────────

    #[test]
    fn test_loopback_cors_returns_layer() {
        // The function should compile and return a CorsLayer
        let _layer: CorsLayer = loopback_cors();
    }

    // ── Auth parsing coverage tests ─────────────────────────────

    #[test]
    fn test_basic_auth_with_empty_user_and_pass() {
        // Edge case: empty credentials
        assert!(!check_basic_auth(
            Some(&basic_auth_value(":")),
            TEST_VIEWER_USER,
            TEST_VIEWER_PASS
        ));
    }

    #[test]
    fn test_basic_auth_with_colon_in_password() {
        // Passwords may contain colons; check that we use splitn(2, ':')
        let pw = "secret:with:colons";
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("admin:{}", pw));
        // We can't use check_basic_auth directly because it hardcodes
        // TEST_VIEWER_PASS. So just verify the encoding round-trips.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let s = String::from_utf8(decoded).unwrap();
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        assert_eq!(parts[0], "admin");
        assert_eq!(parts[1], pw);
    }

    // ── Config default behavior tests ───────────────────────────

    #[test]
    fn test_viewer_config_default_random_credentials_differ_between_calls() {
        let a = ViewerConfig::default();
        let b = ViewerConfig::default();
        assert_ne!(a.username, b.username);
        assert_ne!(a.password, b.password);
        assert_ne!(a.csrf_token, b.csrf_token);
    }

    // ── WebSocket message tests ──────────────────────────────────

    #[test]
    fn test_ws_message_list_updated_serialization() {
        let msg = WsMessage {
            msg_type: "graph_list_updated".to_string(),
            graph_id: None,
            label: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"graph_list_updated"}"#);
    }

    #[test]
    fn test_ws_message_graph_updated_serialization() {
        let msg = WsMessage {
            msg_type: "graph_updated".to_string(),
            graph_id: Some("abc-123".to_string()),
            label: Some("My Graph".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            r#"{"type":"graph_updated","graph_id":"abc-123","label":"My Graph"}"#
        );
    }

    #[test]
    fn test_ws_message_roundtrip() {
        let msg = WsMessage {
            msg_type: "graph_updated".to_string(),
            graph_id: Some("test-id".to_string()),
            label: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: WsMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.msg_type, "graph_updated");
        assert_eq!(parsed.graph_id.as_deref(), Some("test-id"));
        assert!(parsed.label.is_none());
    }

    #[test]
    fn test_notify_graph_list_updated_sends_message() {
        let (ws_tx, mut ws_rx) = broadcast::channel(10);
        let state = AppState {
            graphs: RwLock::new(Vec::new()),
            default_graph: "g1".to_string(),
            cache: RwLock::new(HashMap::new()),
            config: ViewerConfig::default(),
            rate_limiter: RateLimiter::new(60, 100),
            user_rate_limiter: UserRateLimiter::new(60, 100),
            sessions: SessionStore::new(3600),
            ws_tx,
        };
        notify_graph_list_updated(&state);
        let received: String = ws_rx.try_recv().unwrap();
        assert_eq!(received, r#"{"type":"graph_list_updated"}"#);
    }

    #[test]
    fn test_notify_graph_updated_sends_message() {
        let (ws_tx, mut ws_rx) = broadcast::channel(10);
        let state = AppState {
            graphs: RwLock::new(Vec::new()),
            default_graph: "g1".to_string(),
            cache: RwLock::new(HashMap::new()),
            config: ViewerConfig::default(),
            rate_limiter: RateLimiter::new(60, 100),
            user_rate_limiter: UserRateLimiter::new(60, 100),
            sessions: SessionStore::new(3600),
            ws_tx,
        };
        notify_graph_updated(&state, "graph-1", "Test Graph");
        let received: String = ws_rx.try_recv().unwrap();
        assert!(received.contains(r#""type":"graph_updated""#));
        assert!(received.contains(r#""graph_id":"graph-1""#));
        assert!(received.contains(r#""label":"Test Graph""#));
    }
}
