// Tree viewer - hierarchical node list display with search and navigation
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind, MouseEvent, MouseEventKind, MouseButton},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    backend::Backend,
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap, ListState},
    Frame, Terminal,
};
use std::io;
use std::time::Duration;

use crate::bloodhound_viewer;

use crate::bloodhound_viewer::{
    io_other, draw_help, focus_label, focus_border, node_glyph, kind_color, wrap_index,
    VisualGraph, Focus, VisualNode,
};

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

#[derive(Debug, Clone, Copy)]
struct UiAreas {
    graph: Rect,
    nodes: Rect,
    edges: Rect,
    details: Rect,
}

pub fn rect_contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x
        && column < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

pub fn inner_rect(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    )
}

#[derive(Debug)]
struct TreeApp {
    graph: VisualGraph,
    focus: Focus,
    selected_node: Option<usize>,
    search_mode: bool,
    search_text: String,
    show_help: bool,
    status: String,
    should_quit: bool,
    // Filtering options
    high_value_only: bool,
    owned_only: bool,
    // View state
    details_scroll: u16,
    last_drag: Option<(u16, u16)>,
    // Path finding
    path_nodes: Vec<usize>,
    path_edges: Vec<usize>,
}

impl TreeApp {
    fn new(graph: VisualGraph) -> Self {
        let selected_node = graph.nodes.iter().position(|n| n.owned)
            .or_else(|| graph.nodes.iter().position(|n| n.high_value))
            .or_else(|| (!graph.nodes.is_empty()).then_some(0));
        let status = if graph.nodes.is_empty() {
            "Warning: 0 nodes loaded. Press ? for help, q to quit.".to_string()
        } else {
            "Tree view. Press ? for help, q to quit.".to_string()
        };
        Self {
            graph,
            focus: Focus::Graph,
            selected_node,
            search_mode: false,
            search_text: String::new(),
            show_help: false,
            status,
            should_quit: false,
            high_value_only: false,
            owned_only: false,
            details_scroll: 0,
            last_drag: None,
            path_nodes: Vec::new(),
            path_edges: Vec::new(),
        }
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
                self.status = "Search: type to filter nodes, Enter selects first match, Esc exits.".to_string();
            }
            KeyCode::Char('v') => {
                self.high_value_only = !self.high_value_only;
                self.ensure_selected_node_visible();
                self.status = if self.high_value_only {
                    "Showing only high-value objects.".to_string()
                } else {
                    "Showing all objects.".to_string()
                };
            }
            KeyCode::Char('o') => {
                self.owned_only = !self.owned_only;
                self.ensure_selected_node_visible();
                self.status = if self.owned_only {
                    "Showing only owned/compromised objects.".to_string()
                } else {
                    "Showing all objects.".to_string()
                };
            }
            KeyCode::Char('c') => {
                self.search_text.clear();
                self.high_value_only = false;
                self.owned_only = false;
                self.status = "Cleared all filters.".to_string();
            }
            KeyCode::Enter => {
                self.refresh_path();
                self.status = "Refreshed high-value path.".to_string();
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_active(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_active(1),
            KeyCode::PageUp => self.details_scroll = self.details_scroll.saturating_sub(8),
            KeyCode::PageDown => self.details_scroll = self.details_scroll.saturating_add(8),
            _ => {}
        }
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
                    self.status = format!("Selected first match for '{}'.", self.search_text);
                } else {
                    self.status = format!("No node matched '{}'.", self.search_text);
                }
            }
            KeyCode::Backspace => {
                self.search_text.pop();
                self.ensure_selected_node_visible();
            }
            KeyCode::Char(c) => {
                self.search_text.push(c);
                self.ensure_selected_node_visible();
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.graph.nodes.is_empty() {
            return;
        }
        let pos = self.selected_node.unwrap_or(0);
        let len = self.graph.nodes.len();
        let new_pos = wrap_index(pos, delta, len);
        self.selected_node = Some(new_pos);
    }

    fn move_active(&mut self, delta: isize) {
        match self.focus {
            Focus::Graph => {
                self.move_selection(delta);
            }
            Focus::Nodes => self.move_selection(delta),
            Focus::Edges => {
                if let Some(node_idx) = self.selected_node {
                    let edges: Vec<usize> = self.graph.outgoing[node_idx]
                        .iter()
                        .chain(self.graph.incoming[node_idx].iter())
                        .copied()
                        .collect();
                    if !edges.is_empty() {
                        let edge = &self.graph.edges[edges[0]];
                        let target = &self.graph.nodes[edge.target()];
                        self.status = format!("Edge: {} -> {}", self.graph.nodes[edge.source()].label, target.label);
                    }
                }
            }
            Focus::Details => {
                if delta < 0 {
                    self.details_scroll = self.details_scroll.saturating_sub(1);
                } else {
                    self.details_scroll = self.details_scroll.saturating_add(1);
                }
            }
        }
    }

    fn ensure_selected_node_visible(&mut self) {
        let nodes = self.filtered_nodes();
        if nodes.is_empty() {
            self.selected_node = None;
        } else if self.selected_node.is_none_or(|selected| !nodes.contains(&selected)) {
            self.selected_node = Some(nodes[0]);
        }
    }

    fn refresh_path(&mut self) {
        self.path_nodes.clear();
        self.path_edges.clear();
        if let Some(start) = self.selected_node {
            if let Some((nodes, edges)) = self.graph.shortest_path_to_high_value(start) {
                self.path_nodes = nodes;
                self.path_edges = edges;
            }
        }
    }

    fn node_visible(&self, idx: usize) -> bool {
        let Some(node) = self.graph.nodes.get(idx) else {
            return false;
        };
        if self.high_value_only && !node.high_value {
            return false;
        }
        if self.owned_only && !node.owned {
            return false;
        }
        true
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
            || node.domain.as_deref().unwrap_or_default().to_ascii_lowercase().contains(&needle)
    }

    fn filtered_nodes(&self) -> Vec<usize> {
        let mut nodes: Vec<usize> = (0..self.graph.nodes.len())
            .filter(|idx| self.node_visible(*idx) && self.node_matches_search(*idx))
            .collect();
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

    fn handle_mouse(&mut self, mouse: MouseEvent, terminal_area: Rect) {
        if self.search_mode {
            return;
        }

        let areas = compute_ui_areas(terminal_area);
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if rect_contains(areas.graph, mouse.column, mouse.row) {
                    self.focus = Focus::Graph;
                } else if rect_contains(areas.nodes, mouse.column, mouse.row) {
                    self.focus = Focus::Nodes;
                    self.move_active(-1);
                } else {
                    self.move_active(-1);
                }
            }
            MouseEventKind::ScrollDown => {
                if rect_contains(areas.graph, mouse.column, mouse.row) {
                    self.focus = Focus::Graph;
                } else if rect_contains(areas.nodes, mouse.column, mouse.row) {
                    self.focus = Focus::Nodes;
                    self.move_active(1);
                } else {
                    self.move_active(1);
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if rect_contains(areas.nodes, mouse.column, mouse.row) {
                    self.focus = Focus::Nodes;
                    self.select_node_row(mouse.row, areas.nodes);
                }
            }
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
}

pub fn run(sources: &[String]) -> io::Result<()> {
    let graph = VisualGraph::from_sources(sources).map_err(io_other)?;
    let mut app = TreeApp::new(graph);
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    let result = run_loop(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    result
}

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut TreeApp) -> io::Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| draw(frame, app))?;
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            app.handle_key(key);
        }
        if let Ok(Event::Mouse(mouse)) = event::read() {
            let size = terminal.size()?;
            app.handle_mouse(mouse, Rect::new(0, 0, size.width, size.height));
        }
    }
    Ok(())
}

fn draw(frame: &mut Frame, app: &mut TreeApp) {
    let chunks = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(12), Constraint::Length(2)].as_ref())
        .split(frame.area());
    draw_header(frame, chunks[0], app);
    
    let side = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[1]);
    
    draw_tree(frame, side[0], app);
    draw_details(frame, side[1], app);
    
    draw_status(frame, chunks[2], app);
    if app.show_help { draw_help(frame, frame.area()); }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let title = Line::from(vec![
        Span::styled("Overthrone Tree View  ", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        Span::raw(format!("nodes {}  edges {}  users {}  computers {}  groups {}  domains {}",
            app.graph.stats.nodes, app.graph.stats.edges, app.graph.stats.users,
            app.graph.stats.computers, app.graph.stats.groups, app.graph.stats.domains)),
    ]);
    let source = if app.graph.sources.len() == 1 {
        app.graph.sources[0].clone()
    } else { format!("{} files", app.graph.sources.len()) };
    let header = Paragraph::new(vec![title, Line::from(source)])
        .block(Block::default().borders(Borders::ALL).title(" Tree Viewer "));
    frame.render_widget(header, area);
}

fn draw_tree(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let items: Vec<_> = app.filtered_nodes().iter().map(|&idx| {
        let n = &app.graph.nodes[idx];
        let flags = format!("{}{}", if n.high_value { "*" } else { " " }, if n.owned { "!" } else { " " });
        let line = format!("{}{} {} ({})", flags, node_glyph(&n.kind), n.label, n.kind);
        ListItem::new(Line::from(vec![
            Span::styled(flags, Style::default().fg(Color::Yellow)),
            Span::raw(" "),
            Span::styled(line, Style::default().fg(kind_color(&n.kind))),
        ]))
    }).collect();
    let selected_pos = app.selected_node.and_then(|idx| {
        app.filtered_nodes().iter().position(|&candidate| candidate == idx)
    });
    let mut state = ListState::default().with_selected(selected_pos);
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Nodes ").border_style(focus_border(app.focus == Focus::Graph)))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_status(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let mode = if app.search_mode {
        format!("SEARCH: {}", app.search_text)
    } else {
        let filter_info = if app.high_value_only && app.owned_only {
            " [high-value+owned]"
        } else if app.high_value_only {
            " [high-value]"
        } else if app.owned_only {
            " [owned]"
        } else {
            ""
        };
        format!("focus={}  / search | j/k move | v/high-value | o/owned | c/clear | Enter/path | ? help | q quit{}",
            focus_label(app.focus == Focus::Graph), filter_info)
    };
    let status = Paragraph::new(vec![
        Line::from(mode),
        Line::from(Span::styled(app.status.clone(), Style::default().fg(Color::DarkGray))),
    ]);
    frame.render_widget(status, area);
}

fn draw_details(frame: &mut Frame, area: Rect, app: &TreeApp) {
    let content = detail_lines(app);
    let details = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Details ").border_style(focus_border(app.focus == Focus::Details)))
        .wrap(Wrap { trim: false })
        .scroll((app.details_scroll, 0));
    frame.render_widget(details, area);
}

fn detail_lines(app: &TreeApp) -> Vec<Line<'static>> {
    if let Some(node_idx) = app.selected_node {
        if let Some(node) = app.graph.nodes.get(node_idx) {
            return node_detail_lines(app, node_idx, node);
        }
    }
    vec![Line::from("No node selected.")]
}

fn node_detail_lines(app: &TreeApp, node_idx: usize, node: &VisualNode) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            node.label.clone(),
            Style::default().fg(kind_color(&node.kind)).add_modifier(Modifier::BOLD),
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

    let insights = bloodhound_viewer::node_insight_lines(node);
    if !insights.is_empty() {
        lines.push(Line::from(Span::styled(
            "Operator notes:",
            Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD),
        )));
        lines.extend(insights);
        lines.push(Line::from(""));
    }

    if !app.path_edges.is_empty() {
        lines.push(Line::from(Span::styled(
            "Shortest visible path to high-value:",
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        )));
        for edge_idx in &app.path_edges {
            let edge = &app.graph.edges[*edge_idx];
            let source = &app.graph.nodes[edge.source()];
            let target = &app.graph.nodes[edge.target()];
            lines.push(Line::from(format!(
                "  {} --{}--> {}",
                source.label, edge.relationship(), target.label
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
        let target = &app.graph.nodes[edge.target()];
        let (risk, _) = bloodhound_viewer::relationship_risk(edge.relationship());
        lines.push(Line::from(format!(
            "  {} [{}] -> {}",
            edge.relationship(), risk, target.label
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Inbound relationships:",
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
    )));
    for edge_idx in app.graph.incoming[node_idx].iter().take(20) {
        let edge = &app.graph.edges[*edge_idx];
        let source = &app.graph.nodes[edge.source()];
        let (risk, _) = bloodhound_viewer::relationship_risk(edge.relationship());
        lines.push(Line::from(format!(
            "  {} -> {} [{}]",
            source.label, edge.relationship(), risk
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Properties:",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
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
            Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
        )));
        for line in raw.lines().take(80) {
            lines.push(Line::from(format!("  {line}")));
        }
    }

    lines
}





