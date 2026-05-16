use overthrone_core::graph::{AttackGraph, EdgeId, EdgeRef, NodeId, NodeType};
use overthrone_reaper::acls::AclFinding;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Application state for the TUI
pub struct App {
    pub graph: Arc<Mutex<AttackGraph>>,
    pub selected_node: Option<NodeId>,
    pub highlighted_path: Vec<EdgeId>,
    pub filter_text: String,
    pub filter_active: bool,
    pub camera_x: f64,
    pub camera_y: f64,
    pub zoom: f64,
    pub active_tab: Tab,
    pub logs: Vec<LogEntry>,
    pub max_logs: usize,
    pub should_quit: bool,
    pub layout: HashMap<NodeId, (f64, f64)>,
    pub stats: GraphStats,
    pub node_scroll: usize,
    pub path_scroll: usize,
    pub trust_scroll: usize,
    pub detail_scroll: usize,
    pub log_scroll: usize,
    pub acl_scroll: usize,
    pub overview_scroll: usize,
    pub current_path: Option<overthrone_core::graph::AttackPath>,
    pub acl_findings: Option<Vec<AclFinding>>,
    // Visibility toggles for graph nodes
    pub show_users: bool,
    pub show_computers: bool,
    pub show_groups: bool,
    pub show_domains: bool,
    pub show_gpos: bool,
    pub show_ous: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Graph,
    Nodes,
    Paths,
    Logs,
    Trusts,
}

impl Tab {
    pub fn all() -> &'static [Tab] {
        &[Tab::Graph, Tab::Nodes, Tab::Paths, Tab::Logs, Tab::Trusts]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Graph => "📊 Graph",
            Tab::Nodes => "🖥 Nodes",
            Tab::Paths => "⚔ Paths",
            Tab::Logs => "📋 Logs",
            Tab::Trusts => "🌐 Trusts",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub module: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // TUI log severity levels
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Success,
    Attack,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // Populated from graph analysis
pub struct GraphStats {
    pub total_nodes: usize,
    pub users: usize,
    pub computers: usize,
    pub groups: usize,
    pub gpos: usize,
    pub ous: usize,
    pub edges: usize,
    pub attack_paths: usize,
    pub domains: usize,
    pub trusts: usize,
}

fn add_repulsive_force(
    forces: &mut HashMap<NodeId, (f64, f64)>,
    n1: NodeId,
    n2: NodeId,
    x1: f64,
    y1: f64,
    x2: f64,
    y2: f64,
    k: f64,
) {
    let dx = x1 - x2;
    let dy = y1 - y2;
    let dist = (dx * dx + dy * dy).sqrt().max(0.1);
    let force = (k * k) / dist;
    let fx = (dx / dist) * force;
    let fy = (dy / dist) * force;

    let left = forces.entry(n1).or_insert((0.0, 0.0));
    left.0 += fx;
    left.1 += fy;

    let right = forces.entry(n2).or_insert((0.0, 0.0));
    right.0 -= fx;
    right.1 -= fy;
}

impl App {
    pub fn new(graph: Arc<Mutex<AttackGraph>>) -> Self {
        Self {
            graph,
            selected_node: None,
            camera_x: 0.0,
            camera_y: 0.0,
            zoom: 1.0,
            active_tab: Tab::Graph,
            logs: Vec::new(),
            max_logs: 500,
            should_quit: false,
            layout: HashMap::new(),
            filter_text: String::new(),
            filter_active: false,
            stats: GraphStats::default(),
            highlighted_path: Vec::new(),
            node_scroll: 0,
            path_scroll: 0,
            trust_scroll: 0,
            detail_scroll: 0,
            log_scroll: 0,
            acl_scroll: 0,
            overview_scroll: 0,
            current_path: None,
            acl_findings: None,
            // Default: show all node types
            show_users: true,
            show_computers: true,
            show_groups: true,
            show_domains: true,
            show_gpos: true,
            show_ous: true,
        }
    }

    /// Update layout positions using force-directed algorithm
    pub fn update_layout(&mut self) {
        let (nodes, edges) = {
            let graph = self.graph.lock().unwrap();
            (
                graph.nodes().map(|(id, _)| id).collect::<Vec<_>>(),
                graph
                    .edges()
                    .map(|edge| (edge.source(), edge.target()))
                    .collect::<Vec<_>>(),
            )
        };

        if nodes.is_empty() {
            self.refresh_stats();
            return;
        }

        // Initialize new nodes at random positions
        for &id in &nodes {
            self.layout.entry(id).or_insert_with(|| {
                let angle = (id.index() as f64) * 2.4; // golden angle spread
                let radius = 20.0 + (id.index() as f64).sqrt() * 10.0;
                (radius * angle.cos(), radius * angle.sin())
            });
        }

        let active_nodes: HashSet<NodeId> = nodes.iter().copied().collect();
        self.layout
            .retain(|node_id, _| active_nodes.contains(node_id));

        // Force-directed iteration (Fruchterman-Reingold simplified).
        // Large graphs use a spatial grid for repulsion so the TUI stays responsive.
        let k = if nodes.len() > 5000 {
            18.0
        } else if nodes.len() > 1500 {
            14.0
        } else {
            8.0
        };
        let iterations = if nodes.len() > 5000 {
            1
        } else if nodes.len() > 1200 {
            2
        } else {
            4
        };
        let use_grid = nodes.len() > 650;
        let cell_size = k * 8.0;
        let edge_step = (edges.len() / 30_000).max(1);

        for _ in 0..iterations {
            let mut forces: HashMap<NodeId, (f64, f64)> = HashMap::new();

            if use_grid {
                let mut grid: HashMap<(i64, i64), Vec<NodeId>> = HashMap::new();
                for &node in &nodes {
                    if let Some(&(x, y)) = self.layout.get(&node) {
                        grid.entry(((x / cell_size) as i64, (y / cell_size) as i64))
                            .or_default()
                            .push(node);
                    }
                }

                for &n1 in &nodes {
                    let Some(&(x1, y1)) = self.layout.get(&n1) else {
                        continue;
                    };
                    let cx = (x1 / cell_size) as i64;
                    let cy = (y1 / cell_size) as i64;
                    for gx in cx - 1..=cx + 1 {
                        for gy in cy - 1..=cy + 1 {
                            let Some(bucket) = grid.get(&(gx, gy)) else {
                                continue;
                            };
                            for &n2 in bucket.iter().take(96) {
                                if n2.index() <= n1.index() {
                                    continue;
                                }
                                let Some(&(x2, y2)) = self.layout.get(&n2) else {
                                    continue;
                                };
                                add_repulsive_force(&mut forces, n1, n2, x1, y1, x2, y2, k);
                            }
                        }
                    }
                }
            } else {
                // Repulsive forces between all pairs for small graphs.
                for (i, &n1) in nodes.iter().enumerate() {
                    let (x1, y1) = self.layout[&n1];
                    for &n2 in &nodes[i + 1..] {
                        let (x2, y2) = self.layout[&n2];
                        add_repulsive_force(&mut forces, n1, n2, x1, y1, x2, y2, k);
                    }
                }
            }

            // Attractive forces along edges
            for &(source, target) in edges.iter().step_by(edge_step) {
                if let (Some(&(x1, y1)), Some(&(x2, y2))) =
                    (self.layout.get(&source), self.layout.get(&target))
                {
                    let dx = x2 - x1;
                    let dy = y2 - y1;
                    let dist = (dx * dx + dy * dy).sqrt().max(0.1);
                    let force = (dist * dist) / k;
                    let fx = (dx / dist) * force;
                    let fy = (dy / dist) * force;

                    let e = forces.entry(source).or_insert((0.0, 0.0));
                    e.0 += fx * 0.5;
                    e.1 += fy * 0.5;

                    let e = forces.entry(target).or_insert((0.0, 0.0));
                    e.0 -= fx * 0.5;
                    e.1 -= fy * 0.5;
                }
            }

            // Apply forces with cooling
            let temp = if nodes.len() > 1500 { 1.35 } else { 2.0 };
            for (&node, &(fx, fy)) in &forces {
                if let Some(pos) = self.layout.get_mut(&node) {
                    let mag = (fx * fx + fy * fy).sqrt().max(0.01);
                    let capped = mag.min(temp);
                    pos.0 += (fx / mag) * capped;
                    pos.1 += (fy / mag) * capped;
                }
            }
        }

        self.refresh_stats();
    }

    pub fn refresh_stats(&mut self) {
        let graph = self.graph.lock().unwrap();
        self.stats = GraphStats {
            total_nodes: graph.node_count(),
            users: graph.nodes_of_type(NodeType::User).count(),
            computers: graph.nodes_of_type(NodeType::Computer).count(),
            groups: graph.nodes_of_type(NodeType::Group).count(),
            gpos: graph.nodes_of_type(NodeType::Gpo).count(),
            ous: graph.nodes_of_type(NodeType::Ou).count(),
            edges: graph.edge_count(),
            attack_paths: graph.attack_path_count(),
            domains: graph.domain_count(),
            trusts: graph.trust_count(),
        };
    }

    pub fn push_log(&mut self, level: LogLevel, module: &str, msg: &str) {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        self.logs.push(LogEntry {
            timestamp: ts,
            level,
            module: module.to_string(),
            message: msg.to_string(),
        });
        if self.logs.len() > self.max_logs {
            self.logs.remove(0);
        }
    }

    pub fn next_tab(&mut self) {
        let tabs = Tab::all();
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[(idx + 1) % tabs.len()];
    }

    pub fn prev_tab(&mut self) {
        let tabs = Tab::all();
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[(idx + tabs.len() - 1) % tabs.len()];
    }

    pub fn pan(&mut self, dx: f64, dy: f64) {
        self.camera_x += dx / self.zoom;
        self.camera_y += dy / self.zoom;
    }

    pub fn zoom_in(&mut self) {
        self.zoom = (self.zoom * 1.2).min(5.0);
    }

    pub fn zoom_out(&mut self) {
        self.zoom = (self.zoom / 1.2).max(0.2);
    }
}
