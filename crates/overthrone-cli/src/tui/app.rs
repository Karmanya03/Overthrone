#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use overthrone_core::graph::{AttackGraph, EdgeId, EdgeRef, EdgeType, NodeId, NodeType};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Application state for the TUI
pub struct App {
    /// Shared attack graph (updated by crawler thread)
    pub graph: Arc<Mutex<AttackGraph>>,
    /// Currently selected node
    pub selected_node: Option<NodeId>,
    /// Camera offset for graph panning
    pub camera_x: f64,
    pub camera_y: f64,
    /// Zoom level (1.0 = default)
    pub zoom: f64,
    /// Active tab
    pub active_tab: Tab,
    /// Log messages buffer
    pub logs: Vec<LogEntry>,
    /// Max log lines to keep
    pub max_logs: usize,
    /// Whether the app should quit
    pub should_quit: bool,
    /// Node positions (force-directed layout)
    pub layout: HashMap<NodeId, (f64, f64)>,
    /// Search/filter text
    pub filter_text: String,
    /// Is filter input active
    pub filter_active: bool,
    /// Stats snapshot
    pub stats: GraphStats,
    /// Selected attack path (highlighted edges)
    pub highlighted_path: Vec<EdgeId>,
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
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Success,
    Attack,
}

#[derive(Debug, Clone, Default)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub users: usize,
    pub computers: usize,
    pub groups: usize,
    pub edges: usize,
    pub attack_paths: usize,
    pub domains: usize,
    pub trusts: usize,
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
        }
    }

    /// Update layout positions using force-directed algorithm
    pub fn update_layout(&mut self) {
        let graph = self.graph.lock().unwrap();
        let nodes: Vec<NodeId> = graph.nodes().map(|(id, _)| id).collect();

        // Initialize new nodes at random positions
        for &id in &nodes {
            self.layout.entry(id).or_insert_with(|| {
                let angle = (id.index() as f64) * 2.4; // golden angle spread
                let radius = 20.0 + (id.index() as f64).sqrt() * 10.0;
                (radius * angle.cos(), radius * angle.sin())
            });
        }

        // Force-directed iteration (Fruchterman-Reingold simplified)
        let k = 8.0; // optimal distance
        let iterations = 5; // per frame

        for _ in 0..iterations {
            let mut forces: HashMap<NodeId, (f64, f64)> = HashMap::new();

            // Repulsive forces between all pairs
            for (i, &n1) in nodes.iter().enumerate() {
                let (x1, y1) = self.layout[&n1];
                let mut fx = 0.0;
                let mut fy = 0.0;

                for &n2 in &nodes[i + 1..] {
                    let (x2, y2) = self.layout[&n2];
                    let dx = x1 - x2;
                    let dy = y1 - y2;
                    let dist = (dx * dx + dy * dy).sqrt().max(0.1);
                    let force = (k * k) / dist;
                    fx += (dx / dist) * force;
                    fy += (dy / dist) * force;

                    let e = forces.entry(n2).or_insert((0.0, 0.0));
                    e.0 -= (dx / dist) * force;
                    e.1 -= (dy / dist) * force;
                }

                let e = forces.entry(n1).or_insert((0.0, 0.0));
                e.0 += fx;
                e.1 += fy;
            }

            // Attractive forces along edges
            for edge in graph.edges() {
                if let (Some(&(x1, y1)), Some(&(x2, y2))) =
                    (self.layout.get(&edge.source()), self.layout.get(&edge.target()))
                {
                    let dx = x2 - x1;
                    let dy = y2 - y1;
                    let dist = (dx * dx + dy * dy).sqrt().max(0.1);
                    let force = (dist * dist) / k;
                    let fx = (dx / dist) * force;
                    let fy = (dy / dist) * force;

                    let e = forces.entry(edge.source()).or_insert((0.0, 0.0));
                    e.0 += fx * 0.5;
                    e.1 += fy * 0.5;

                    let e = forces.entry(edge.target()).or_insert((0.0, 0.0));
                    e.0 -= fx * 0.5;
                    e.1 -= fy * 0.5;
                }
            }

            // Apply forces with cooling
            let temp = 2.0;
            for (&node, &(fx, fy)) in &forces {
                if let Some(pos) = self.layout.get_mut(&node) {
                    let mag = (fx * fx + fy * fy).sqrt().max(0.01);
                    let capped = mag.min(temp);
                    pos.0 += (fx / mag) * capped;
                    pos.1 += (fy / mag) * capped;
                }
            }
        }

        drop(graph);
        self.refresh_stats();
    }

    pub fn refresh_stats(&mut self) {
        let graph = self.graph.lock().unwrap();
        self.stats = GraphStats {
            total_nodes: graph.node_count(),
            users: graph.nodes_of_type(NodeType::User).count(),
            computers: graph.nodes_of_type(NodeType::Computer).count(),
            groups: graph.nodes_of_type(NodeType::Group).count(),
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
