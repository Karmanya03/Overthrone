//! Interactive hierarchical BloodHound tree viewer.

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    time::Duration,
};

use crate::bloodhound_viewer::{
    VisualEdge, VisualGraph, VisualNode, edge_color, io_other, kind_color, node_glyph,
    node_insight_lines, relationship_hint, relationship_is_attack_edge, relationship_risk,
    truncate_label, wrap_index,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TreeKey {
    Domain(String),
    Kind { domain: String, kind: String },
    Node(usize),
    Outgoing(usize),
    Incoming(usize),
    Edge { edge: usize, outbound: bool },
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Domain,
    Kind,
    Node,
    EdgeGroup,
    Edge,
    Empty,
}

#[derive(Debug, Clone)]
struct TreeRow {
    key: TreeKey,
    parent: Option<TreeKey>,
    depth: usize,
    title: String,
    meta: String,
    node: Option<usize>,
    edge: Option<usize>,
    kind: RowKind,
}

impl TreeRow {
    fn new(
        key: TreeKey,
        parent: Option<TreeKey>,
        depth: usize,
        title: impl Into<String>,
        meta: impl Into<String>,
        kind: RowKind,
    ) -> Self {
        Self {
            key,
            parent,
            depth,
            title: title.into(),
            meta: meta.into(),
            node: None,
            edge: None,
            kind,
        }
    }

    fn with_node(mut self, node: usize) -> Self {
        self.node = Some(node);
        self
    }

    fn with_edge(mut self, edge: usize) -> Self {
        self.edge = Some(edge);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeFocus {
    Tree,
    Details,
}

impl TreeFocus {
    fn next(self) -> Self {
        match self {
            Self::Tree => Self::Details,
            Self::Details => Self::Tree,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Details => "details",
        }
    }
}

#[derive(Debug)]
struct TreeApp {
    graph: VisualGraph,
    focus: TreeFocus,
    expanded: BTreeSet<TreeKey>,
    cursor: usize,
    selected_node: Option<usize>,
    selected_edge: Option<usize>,
    search_mode: bool,
    search_text: String,
    high_value_only: bool,
    owned_only: bool,
    attack_edges_only: bool,
    show_help: bool,
    details_scroll: u16,
    path_nodes: Vec<usize>,
    path_edges: Vec<usize>,
    status: String,
    should_quit: bool,
}

impl TreeApp {
    fn new(graph: VisualGraph) -> Self {
        let selected_node = graph
            .nodes
            .iter()
            .position(|node| node.owned)
            .or_else(|| graph.nodes.iter().position(|node| node.high_value))
            .or_else(|| (!graph.nodes.is_empty()).then_some(0));

        let mut expanded = default_expanded_keys(&graph, selected_node);
        if let Some(idx) = selected_node {
            expanded.insert(TreeKey::Node(idx));
            expanded.insert(TreeKey::Outgoing(idx));
            expanded.insert(TreeKey::Incoming(idx));
        }

        let status = if graph.nodes.is_empty() {
            "No nodes loaded. Check that the input is BloodHound or Overthrone JSON.".to_string()
        } else {
            "Tree loaded. Enter expands, / searches, a/v/o filter, q quits.".to_string()
        };

        let mut app = Self {
            graph,
            focus: TreeFocus::Tree,
            expanded,
            cursor: 0,
            selected_node,
            selected_edge: None,
            search_mode: false,
            search_text: String::new(),
            high_value_only: false,
            owned_only: false,
            attack_edges_only: false,
            show_help: false,
            details_scroll: 0,
            path_nodes: Vec::new(),
            path_edges: Vec::new(),
            status,
            should_quit: false,
        };
        app.refresh_path();
        app.cursor = app.cursor_for_selection().unwrap_or(0);
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
            KeyCode::Tab | KeyCode::BackTab => self.focus = self.focus.next(),
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.status =
                    "Search mode. Type to filter the tree, Enter accepts, Esc closes.".to_string();
            }
            KeyCode::Char('a') => {
                self.attack_edges_only = !self.attack_edges_only;
                self.status = if self.attack_edges_only {
                    "Attack-edge lens on for relationship rows.".to_string()
                } else {
                    "Attack-edge lens off; all relationship rows are visible.".to_string()
                };
            }
            KeyCode::Char('v') => {
                self.high_value_only = !self.high_value_only;
                self.ensure_cursor_valid();
                self.status = if self.high_value_only {
                    "Showing high-value objects only.".to_string()
                } else {
                    "High-value object filter cleared.".to_string()
                };
            }
            KeyCode::Char('o') => {
                self.owned_only = !self.owned_only;
                self.ensure_cursor_valid();
                self.status = if self.owned_only {
                    "Showing owned/controlled objects only.".to_string()
                } else {
                    "Owned object filter cleared.".to_string()
                };
            }
            KeyCode::Char('c') => {
                self.search_text.clear();
                self.high_value_only = false;
                self.owned_only = false;
                self.attack_edges_only = false;
                self.ensure_cursor_valid();
                self.status = "Cleared tree filters.".to_string();
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_current(),
            KeyCode::Right | KeyCode::Char('l') => self.expand_current(),
            KeyCode::Left | KeyCode::Char('h') => self.collapse_current(),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::Home => {
                self.cursor = 0;
                self.select_cursor();
            }
            KeyCode::End => {
                let len = self.rows().len();
                if len > 0 {
                    self.cursor = len - 1;
                    self.select_cursor();
                }
            }
            KeyCode::PageUp => self.page(-10),
            KeyCode::PageDown => self.page(10),
            _ => {}
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.search_mode = false;
                self.status = "Search closed; filter remains active until c clears it.".to_string();
            }
            KeyCode::Enter => {
                self.search_mode = false;
                self.ensure_cursor_valid();
                self.status = if self.search_text.is_empty() {
                    "Search cleared.".to_string()
                } else {
                    format!("Filtered tree by '{}'.", self.search_text)
                };
            }
            KeyCode::Backspace => {
                self.search_text.pop();
                self.ensure_cursor_valid();
            }
            KeyCode::Char(c) => {
                self.search_text.push(c);
                self.ensure_cursor_valid();
            }
            _ => {}
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent, area: Rect) {
        let areas = compute_ui_areas(area);
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if rect_contains(areas.tree, mouse.column, mouse.row) {
                    self.move_cursor(-3);
                } else if rect_contains(areas.details, mouse.column, mouse.row) {
                    self.details_scroll = self.details_scroll.saturating_sub(3);
                }
            }
            MouseEventKind::ScrollDown => {
                if rect_contains(areas.tree, mouse.column, mouse.row) {
                    self.move_cursor(3);
                } else if rect_contains(areas.details, mouse.column, mouse.row) {
                    self.details_scroll = self.details_scroll.saturating_add(3);
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if rect_contains(areas.tree, mouse.column, mouse.row) {
                    let row = mouse
                        .row
                        .saturating_sub(inner_rect(areas.tree).y)
                        .saturating_add(self.visible_scroll_hint() as u16)
                        as usize;
                    let len = self.rows().len();
                    if len > 0 {
                        self.cursor = row.min(len - 1);
                        self.focus = TreeFocus::Tree;
                        self.select_cursor();
                    }
                } else if rect_contains(areas.details, mouse.column, mouse.row) {
                    self.focus = TreeFocus::Details;
                }
            }
            MouseEventKind::Down(MouseButton::Right) => self.toggle_current(),
            _ => {}
        }
    }

    fn visible_scroll_hint(&self) -> usize {
        let rows = self.rows();
        self.cursor
            .saturating_sub(8)
            .min(rows.len().saturating_sub(1))
    }

    fn page(&mut self, delta: isize) {
        match self.focus {
            TreeFocus::Tree => self.move_cursor(delta),
            TreeFocus::Details => {
                if delta.is_negative() {
                    self.details_scroll = self
                        .details_scroll
                        .saturating_sub(delta.unsigned_abs() as u16);
                } else {
                    self.details_scroll = self.details_scroll.saturating_add(delta as u16);
                }
            }
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        let len = self.rows().len();
        if len == 0 {
            return;
        }
        self.cursor = wrap_index(self.cursor.min(len - 1), delta, len);
        self.select_cursor();
    }

    fn toggle_current(&mut self) {
        if let Some(row) = self.current_row() {
            if is_expandable(&row.key) {
                if self.expanded.contains(&row.key) {
                    self.expanded.remove(&row.key);
                } else {
                    self.expanded.insert(row.key.clone());
                }
            }
            self.select_cursor();
        }
    }

    fn expand_current(&mut self) {
        if let Some(row) = self.current_row()
            && is_expandable(&row.key)
        {
            self.expanded.insert(row.key);
        }
    }

    fn collapse_current(&mut self) {
        if let Some(row) = self.current_row() {
            if is_expandable(&row.key) && self.expanded.remove(&row.key) {
                return;
            }
            if let Some(parent) = row.parent {
                self.expanded.remove(&parent);
                if let Some(pos) = self
                    .rows()
                    .iter()
                    .position(|candidate| candidate.key == parent)
                {
                    self.cursor = pos;
                    self.select_cursor();
                }
            }
        }
    }

    fn select_cursor(&mut self) {
        let Some(row) = self.current_row() else {
            self.selected_node = None;
            self.selected_edge = None;
            return;
        };

        if let Some(edge_idx) = row.edge {
            self.selected_edge = Some(edge_idx);
            let edge = &self.graph.edges[edge_idx];
            self.selected_node = row.node.or(Some(edge.target));
        } else if let Some(node_idx) = row.node {
            self.selected_node = Some(node_idx);
            self.selected_edge = None;
        }
        self.details_scroll = 0;
        self.refresh_path();
    }

    fn current_row(&self) -> Option<TreeRow> {
        self.rows().get(self.cursor).cloned()
    }

    fn ensure_cursor_valid(&mut self) {
        let rows = self.rows();
        if rows.is_empty() {
            self.cursor = 0;
            self.selected_node = None;
            self.selected_edge = None;
            return;
        }
        self.cursor = self.cursor.min(rows.len() - 1);
        if let Some(pos) = self.cursor_for_selection() {
            self.cursor = pos;
        }
        self.select_cursor();
    }

    fn cursor_for_selection(&self) -> Option<usize> {
        let rows = self.rows();
        if let Some(edge_idx) = self.selected_edge
            && let Some(pos) = rows.iter().position(|row| row.edge == Some(edge_idx))
        {
            return Some(pos);
        }
        self.selected_node.and_then(|node_idx| {
            rows.iter()
                .position(|row| row.key == TreeKey::Node(node_idx))
        })
    }

    fn refresh_path(&mut self) {
        self.path_nodes.clear();
        self.path_edges.clear();
        if let Some(node_idx) = self.selected_node
            && let Some((nodes, edges)) = self.graph.shortest_path_to_high_value(node_idx)
        {
            self.path_nodes = nodes;
            self.path_edges = edges;
        }
    }

    fn rows(&self) -> Vec<TreeRow> {
        let buckets = self.domain_kind_buckets();
        let mut rows = Vec::new();

        for (domain, kind_map) in buckets {
            let domain_key = TreeKey::Domain(domain.clone());
            let domain_count = kind_map.values().map(Vec::len).sum::<usize>();
            rows.push(TreeRow::new(
                domain_key.clone(),
                None,
                0,
                domain.clone(),
                format!("{domain_count} objects"),
                RowKind::Domain,
            ));

            if !self.expanded.contains(&domain_key) {
                continue;
            }

            let mut kinds = kind_map.into_iter().collect::<Vec<_>>();
            kinds.sort_by(|(left, _), (right, _)| {
                kind_rank(left)
                    .cmp(&kind_rank(right))
                    .then_with(|| left.cmp(right))
            });

            for (kind, mut nodes) in kinds {
                nodes.sort_by(|left, right| self.node_sort(*left, *right));
                let kind_key = TreeKey::Kind {
                    domain: domain.clone(),
                    kind: kind.clone(),
                };
                rows.push(TreeRow::new(
                    kind_key.clone(),
                    Some(domain_key.clone()),
                    1,
                    kind.clone(),
                    format!("{} objects", nodes.len()),
                    RowKind::Kind,
                ));

                if !self.expanded.contains(&kind_key) {
                    continue;
                }

                for node_idx in nodes {
                    let node = &self.graph.nodes[node_idx];
                    let node_key = TreeKey::Node(node_idx);
                    let flags = format!(
                        "{}{} degree {}",
                        if node.high_value { "*" } else { " " },
                        if node.owned { "!" } else { " " },
                        self.graph.node_degree(node_idx)
                    );
                    rows.push(
                        TreeRow::new(
                            node_key.clone(),
                            Some(kind_key.clone()),
                            2,
                            node.label.clone(),
                            flags,
                            RowKind::Node,
                        )
                        .with_node(node_idx),
                    );

                    if !self.expanded.contains(&node_key) {
                        continue;
                    }

                    self.push_relationship_group(&mut rows, node_idx, true, node_key.clone());
                    self.push_relationship_group(&mut rows, node_idx, false, node_key);
                }
            }
        }

        if rows.is_empty() {
            rows.push(TreeRow::new(
                TreeKey::Empty,
                None,
                0,
                "No matching objects",
                "clear filters or load a different graph",
                RowKind::Empty,
            ));
        }

        rows
    }

    fn push_relationship_group(
        &self,
        rows: &mut Vec<TreeRow>,
        node_idx: usize,
        outbound: bool,
        parent: TreeKey,
    ) {
        let edge_indices = self.edge_indices(node_idx, outbound);
        let group_key = if outbound {
            TreeKey::Outgoing(node_idx)
        } else {
            TreeKey::Incoming(node_idx)
        };
        let title = if outbound {
            "Outbound relationships"
        } else {
            "Inbound relationships"
        };
        rows.push(
            TreeRow::new(
                group_key.clone(),
                Some(parent),
                3,
                title,
                format!("{} visible", edge_indices.len()),
                RowKind::EdgeGroup,
            )
            .with_node(node_idx),
        );

        if !self.expanded.contains(&group_key) {
            return;
        }

        for edge_idx in edge_indices {
            let edge = &self.graph.edges[edge_idx];
            let peer = if outbound { edge.target } else { edge.source };
            let peer_node = &self.graph.nodes[peer];
            let arrow = if outbound { "->" } else { "<-" };
            rows.push(
                TreeRow::new(
                    TreeKey::Edge {
                        edge: edge_idx,
                        outbound,
                    },
                    Some(group_key.clone()),
                    4,
                    format!(
                        "{} {} {}",
                        edge.relationship,
                        arrow,
                        truncate_label(&peer_node.label, 56)
                    ),
                    peer_node.kind.clone(),
                    RowKind::Edge,
                )
                .with_node(peer)
                .with_edge(edge_idx),
            );
        }
    }

    fn domain_kind_buckets(&self) -> BTreeMap<String, BTreeMap<String, Vec<usize>>> {
        let mut buckets: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
        for (idx, node) in self.graph.nodes.iter().enumerate() {
            if !self.node_visible(idx, node) {
                continue;
            }
            let domain = node
                .domain
                .clone()
                .unwrap_or_else(|| "(unknown domain)".to_string());
            buckets
                .entry(domain)
                .or_default()
                .entry(node.kind.clone())
                .or_default()
                .push(idx);
        }
        buckets
    }

    fn node_sort(&self, left: usize, right: usize) -> std::cmp::Ordering {
        let left_node = &self.graph.nodes[left];
        let right_node = &self.graph.nodes[right];
        right_node
            .high_value
            .cmp(&left_node.high_value)
            .then_with(|| right_node.owned.cmp(&left_node.owned))
            .then_with(|| {
                self.graph
                    .node_degree(right)
                    .cmp(&self.graph.node_degree(left))
            })
            .then_with(|| left_node.label.cmp(&right_node.label))
    }

    fn node_visible(&self, _idx: usize, node: &VisualNode) -> bool {
        if self.high_value_only && !node.high_value {
            return false;
        }
        if self.owned_only && !node.owned {
            return false;
        }
        if self.search_text.is_empty() {
            return true;
        }

        let needle = self.search_text.to_ascii_lowercase();
        node.id.to_ascii_lowercase().contains(&needle)
            || node.label.to_ascii_lowercase().contains(&needle)
            || node.kind.to_ascii_lowercase().contains(&needle)
            || node
                .domain
                .as_ref()
                .is_some_and(|domain| domain.to_ascii_lowercase().contains(&needle))
            || node
                .distinguished_name
                .as_ref()
                .is_some_and(|dn| dn.to_ascii_lowercase().contains(&needle))
            || node.properties.iter().any(|(key, value)| {
                key.to_ascii_lowercase().contains(&needle)
                    || value.to_ascii_lowercase().contains(&needle)
            })
    }

    fn edge_indices(&self, node_idx: usize, outbound: bool) -> Vec<usize> {
        let edges = if outbound {
            self.graph.outgoing.get(node_idx)
        } else {
            self.graph.incoming.get(node_idx)
        };
        let mut out = edges
            .into_iter()
            .flatten()
            .copied()
            .filter(|edge_idx| self.edge_visible(*edge_idx))
            .collect::<Vec<_>>();
        out.sort_by(|left, right| {
            self.path_edges
                .contains(right)
                .cmp(&self.path_edges.contains(left))
                .then_with(|| {
                    self.graph.edges[*left]
                        .relationship
                        .cmp(&self.graph.edges[*right].relationship)
                })
        });
        out
    }

    fn edge_visible(&self, edge_idx: usize) -> bool {
        let Some(edge) = self.graph.edges.get(edge_idx) else {
            return false;
        };
        if self.attack_edges_only
            && !self.path_edges.contains(&edge_idx)
            && !relationship_is_attack_edge(&edge.relationship)
        {
            return false;
        }
        true
    }

    fn detail_lines(&self) -> Vec<Line<'static>> {
        if let Some(edge_idx) = self.selected_edge
            && let Some(edge) = self.graph.edges.get(edge_idx)
        {
            return self.edge_detail_lines(edge_idx, edge);
        }

        if let Some(node_idx) = self.selected_node
            && let Some(node) = self.graph.nodes.get(node_idx)
        {
            return self.node_detail_lines(node_idx, node);
        }

        vec![
            Line::from(Span::styled(
                "Graph summary",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("Sources: {}", self.graph.sources.join(", "))),
            Line::from(format!("Nodes: {}", self.graph.stats.nodes)),
            Line::from(format!("Edges: {}", self.graph.stats.edges)),
        ]
    }

    fn node_detail_lines(&self, node_idx: usize, node: &VisualNode) -> Vec<Line<'static>> {
        let mut lines = vec![
            Line::from(Span::styled(
                format!("{} {}", node_glyph(&node.kind), node.label),
                Style::default()
                    .fg(kind_color(&node.kind))
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("Type: {}", node.kind)),
            Line::from(format!("Id: {}", node.id)),
            Line::from(format!(
                "Domain: {}",
                node.domain.as_deref().unwrap_or("(unknown)")
            )),
            Line::from(format!(
                "Distinguished name: {}",
                node.distinguished_name
                    .as_deref()
                    .unwrap_or("(not present)")
            )),
            Line::from(format!(
                "Enabled: {}",
                node.enabled
                    .map(|enabled| enabled.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            )),
            Line::from(format!(
                "Degree: {} outbound, {} inbound, {} total",
                self.graph.outgoing.get(node_idx).map_or(0, Vec::len),
                self.graph.incoming.get(node_idx).map_or(0, Vec::len),
                self.graph.node_degree(node_idx)
            )),
            Line::from(format!("High-value: {}", node.high_value)),
            Line::from(format!("Owned/controlled: {}", node.owned)),
            Line::from(""),
            Line::from(Span::styled(
                "Operator notes",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        ];

        let insights = node_insight_lines(node);
        if insights.is_empty() {
            lines.push(Line::from("  No special risk markers found in this node."));
        } else {
            lines.extend(insights);
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Path to high-value",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        if self.path_edges.is_empty() {
            lines.push(Line::from(
                "  No traversable high-value path found from this node.",
            ));
        } else {
            lines.push(Line::from(format!("  {} hops", self.path_edges.len())));
            for edge_idx in &self.path_edges {
                let edge = &self.graph.edges[*edge_idx];
                let target = &self.graph.nodes[edge.target];
                lines.push(Line::from(format!(
                    "  {} -> {} ({})",
                    edge.relationship, target.label, target.kind
                )));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Properties",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        if node.properties.is_empty() {
            lines.push(Line::from("  (none)"));
        } else {
            for (key, value) in node.properties.iter().take(140) {
                lines.push(Line::from(format!("  {key}: {value}")));
            }
        }
        push_raw_json(&mut lines, &node.raw);
        lines
    }

    fn edge_detail_lines(&self, edge_idx: usize, edge: &VisualEdge) -> Vec<Line<'static>> {
        let source = &self.graph.nodes[edge.source];
        let target = &self.graph.nodes[edge.target];
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
                "ACE context: {}",
                ace_context_note(&edge.relationship).unwrap_or(
                    "this row may be ACE-backed; verify the original DACL before changing it"
                )
            )),
            Line::from(format!(
                "Traversable in path search: {}",
                VisualGraph::edge_traversable(edge)
            )),
            Line::from(format!(
                "Highlighted path edge: {}",
                self.path_edges.contains(&edge_idx)
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Properties",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        ];
        if edge.properties.is_empty() {
            lines.push(Line::from("  (none)"));
        } else {
            for (key, value) in edge.properties.iter().take(140) {
                lines.push(Line::from(format!("  {key}: {value}")));
            }
        }
        push_raw_json(&mut lines, &edge.raw);
        lines
    }
}

#[derive(Debug, Clone, Copy)]
struct UiAreas {
    tree: Rect,
    details: Rect,
    path: Rect,
}

pub fn run(sources: &[String]) -> io::Result<()> {
    let graph = VisualGraph::from_sources(sources).map_err(io_other)?;
    let mut app = TreeApp::new(graph);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut TreeApp) -> io::Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;
        if app.should_quit {
            break;
        }
        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(key) => app.handle_key(key),
                Event::Mouse(mouse) => {
                    let size = terminal.size()?;
                    let area = Rect::new(0, 0, size.width, size.height);
                    app.handle_mouse(mouse, area);
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
    Ok(())
}

fn draw(frame: &mut Frame, app: &mut TreeApp) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let body = compute_ui_areas(root[1]);
    draw_header(frame, root[0], app);
    draw_tree(frame, body.tree, app);
    draw_details(frame, body.details, app);
    draw_path(frame, body.path, app);
    draw_status(frame, root[2], app);

    if app.show_help {
        draw_help(frame, frame.area());
    }
}

fn compute_ui_areas(area: Rect) -> UiAreas {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
        .split(area);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(columns[1]);
    UiAreas {
        tree: columns[0],
        details: right[0],
        path: right[1],
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let filters = active_filters(app);
    let line = Line::from(vec![
        Span::styled(
            "Overthrone Tree View  ",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "nodes {}  edges {}  high-value {}  owned {}  domains {}  filters {}",
            app.graph.stats.nodes,
            app.graph.stats.edges,
            app.graph.stats.high_value,
            app.graph.stats.owned,
            app.graph.stats.domains,
            filters
        )),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::BOTTOM)),
        area,
    );
}

fn draw_tree(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let rows = app.rows();
    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(app.cursor.min(rows.len() - 1)));
    }

    let items = rows
        .iter()
        .map(|row| ListItem::new(tree_row_line(row, app)))
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Tree [{}] {} rows ",
                    focus_label(app.focus == TreeFocus::Tree),
                    rows.len()
                ))
                .border_style(focus_border(app.focus == TreeFocus::Tree)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_details(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let paragraph = Paragraph::new(app.detail_lines())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Details [{}] ",
                    focus_label(app.focus == TreeFocus::Details)
                ))
                .border_style(focus_border(app.focus == TreeFocus::Details)),
        )
        .scroll((app.details_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn draw_path(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let mut lines = Vec::new();
    if let Some(node_idx) = app.selected_node {
        let node = &app.graph.nodes[node_idx];
        lines.push(Line::from(Span::styled(
            format!("Selected: {}", node.label),
            Style::default()
                .fg(kind_color(&node.kind))
                .add_modifier(Modifier::BOLD),
        )));
    }
    if app.path_edges.is_empty() {
        lines.push(Line::from(
            "No traversable high-value path is known from this selection.",
        ));
    } else {
        lines.push(Line::from(format!("Path hops: {}", app.path_edges.len())));
        for edge_idx in app.path_edges.iter().take(12) {
            let edge = &app.graph.edges[*edge_idx];
            let target = &app.graph.nodes[edge.target];
            lines.push(Line::from(format!(
                "{} -> {}",
                edge.relationship,
                truncate_label(&target.label, 52)
            )));
        }
    }
    let block = Block::default().borders(Borders::ALL).title(" Path ");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_status(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let mode = if app.search_mode {
        format!("SEARCH: {}", app.search_text)
    } else {
        format!(
            "focus={}  keys: Enter expand | Left/Right collapse/expand | arrows/jk move | / search | a attack | v high | o owned | c clear | ? help | q quit",
            app.focus.label()
        )
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(mode),
            Line::from(Span::styled(
                app.status.clone(),
                Style::default().fg(Color::DarkGray),
            )),
        ]),
        area,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(74, 62, area);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(Span::styled(
            "Overthrone Tree View",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("A Rust-native hierarchical explorer for BloodHound and Overthrone JSON."),
        Line::from(""),
        Line::from("Navigation"),
        Line::from("  Up/Down or j/k     move through the tree"),
        Line::from("  Enter or Space     expand or collapse the selected row"),
        Line::from("  Left/Right or h/l  collapse or expand"),
        Line::from("  Tab                switch tree and details focus"),
        Line::from("  PageUp/PageDown    page tree or scroll details"),
        Line::from(""),
        Line::from("Analysis"),
        Line::from("  /                  search nodes by label, id, domain, DN, or property"),
        Line::from("  a                  show attack-edge relationship rows only"),
        Line::from("  v                  show high-value nodes only"),
        Line::from("  o                  show owned/controlled nodes only"),
        Line::from("  c                  clear filters"),
        Line::from(""),
        Line::from("Structure"),
        Line::from("  Domain -> object type -> object -> outbound/inbound relationships"),
        Line::from("  ACE/DACL-backed edges surface in the details pane with rollback hints."),
        Line::from("  Names stay in tree/details panes so the graph canvas stays clean."),
        Line::from(""),
        Line::from("Press ? to close this help."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Help "))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn tree_row_line(row: &TreeRow, app: &TreeApp) -> Line<'static> {
    let indent = "  ".repeat(row.depth);
    let expanded = app.expanded.contains(&row.key);
    let marker = if is_expandable(&row.key) {
        if expanded { "-" } else { "+" }
    } else {
        " "
    };
    let style = match row.kind {
        RowKind::Domain => Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
        RowKind::Kind => Style::default().fg(Color::Cyan),
        RowKind::Node => {
            let color = row
                .node
                .and_then(|idx| app.graph.nodes.get(idx))
                .map(|node| kind_color(&node.kind))
                .unwrap_or(Color::White);
            Style::default().fg(color)
        }
        RowKind::EdgeGroup => Style::default().fg(Color::Gray),
        RowKind::Edge => {
            let color = if let Some(idx) = row.edge {
                app.graph
                    .edges
                    .get(idx)
                    .map(|edge| edge_color(&edge.relationship, app.path_edges.contains(&idx)))
                    .unwrap_or(Color::White)
            } else {
                Color::White
            };
            Style::default().fg(color)
        }
        RowKind::Empty => Style::default().fg(Color::DarkGray),
    };

    let glyph = row
        .node
        .and_then(|idx| app.graph.nodes.get(idx))
        .map(|node| node_glyph(&node.kind))
        .unwrap_or(" ");

    Line::from(vec![
        Span::raw(indent),
        Span::styled(marker, Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled(glyph, style),
        Span::raw(" "),
        Span::styled(truncate_label(&row.title, 78), style),
        Span::styled(
            format!("  {}", row.meta),
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

fn ace_context_note(relationship: &str) -> Option<&'static str> {
    let normalized = relationship
        .trim()
        .replace([' ', '-', '_'], "")
        .to_ascii_lowercase();

    match normalized.as_str() {
        "genericall" | "genericwrite" => {
            Some("this is an ACE-backed permission edge; preserve the original ACL before changes")
        }
        "writedacl" | "writeowner" | "owns" => {
            Some("this is a DACL/ACE mutation path; capture and restore the original ACL after use")
        }
        "writeproperty" | "writeself" | "addmembers" | "addself" => Some(
            "this is an attribute or group ACE; verify the exact right before modifying the object",
        ),
        "allowedtoact" | "allowedtodelegate" => Some(
            "this is a delegation ACE; keep the original entry and remove any test ACE when finished",
        ),
        "readlapspassword" | "readgmsapassword" => Some(
            "this is an ACL-backed read primitive; treat the retrieved value as credential material",
        ),
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => {
            Some("this is a shadow-credentials ACE path; keep the temporary value tightly scoped")
        }
        "writealtsecurityidentities" => Some(
            "this is a certificate-mapping ACE path; restore the original mapping after validation",
        ),
        "writegplink" => Some(
            "this is a GPO link ACE; verify scope, inheritance, and rollback before any change",
        ),
        _ => None,
    }
}

fn default_expanded_keys(graph: &VisualGraph, selected_node: Option<usize>) -> BTreeSet<TreeKey> {
    let mut expanded = BTreeSet::new();
    for node in &graph.nodes {
        let domain = node
            .domain
            .clone()
            .unwrap_or_else(|| "(unknown domain)".to_string());
        expanded.insert(TreeKey::Domain(domain.clone()));
        expanded.insert(TreeKey::Kind {
            domain,
            kind: node.kind.clone(),
        });
    }
    if let Some(node_idx) = selected_node {
        expanded.insert(TreeKey::Node(node_idx));
    }
    expanded
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "Domain" => 0,
        "Group" => 1,
        "User" => 2,
        "Computer" => 3,
        "OU" => 4,
        "GPO" => 5,
        "Container" => 6,
        "CertTemplate" => 7,
        _ => 20,
    }
}

fn is_expandable(key: &TreeKey) -> bool {
    matches!(
        key,
        TreeKey::Domain(_)
            | TreeKey::Kind { .. }
            | TreeKey::Node(_)
            | TreeKey::Outgoing(_)
            | TreeKey::Incoming(_)
    )
}

fn active_filters(app: &TreeApp) -> String {
    let mut filters = Vec::new();
    if !app.search_text.is_empty() {
        filters.push(format!("search '{}'", app.search_text));
    }
    if app.high_value_only {
        filters.push("high-value".to_string());
    }
    if app.owned_only {
        filters.push("owned".to_string());
    }
    if app.attack_edges_only {
        filters.push("attack-edges".to_string());
    }
    if filters.is_empty() {
        "all".to_string()
    } else {
        filters.join(", ")
    }
}

fn push_raw_json(lines: &mut Vec<Line<'static>>, value: &serde_json::Value) {
    if let Ok(raw) = serde_json::to_string_pretty(value)
        && raw != "null"
    {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Raw JSON",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )));
        for line in raw.lines().take(80) {
            lines.push(Line::from(format!("  {line}")));
        }
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
