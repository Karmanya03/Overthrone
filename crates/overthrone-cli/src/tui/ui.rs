use crate::tui::app::{App, LogLevel, Tab};
use crate::tui::graph_view;
use overthrone_core::graph::{EdgeRef, EdgeType, NodeType};
use ratatui::prelude::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{
 Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
 Tabs,
};
use tracing::warn;

/// Main UI draw function -- called every frame
pub fn draw(f: &mut Frame, app: &App) {
 let chunks = Layout::default()
 .direction(Direction::Vertical)
 .constraints([
 Constraint::Length(3), // Tab bar + stats
 Constraint::Min(10), // Main content
 Constraint::Length(1), // Status bar
 ])
 .split(f.area());

 draw_header(f, chunks[0], app);
 draw_main(f, chunks[1], app);
 draw_status_bar(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
 let tabs: Vec<Line> = Tab::all()
 .iter()
 .map(|t| {
 let style = if *t == app.active_tab {
 Style::default()
 .fg(Color::Cyan)
 .add_modifier(Modifier::BOLD)
 } else {
 Style::default().fg(Color::DarkGray)
 };
 Line::from(Span::styled(t.label(), style))
 })
 .collect();

 let tab_bar = Tabs::new(tabs)
 .block(
 Block::default()
 .title(format!(
 "  OVERTHRONE -- {} nodes | {} edges | {} paths | vis: u/c/g/d/p/o ",
 app.stats.total_nodes, app.stats.edges, app.stats.attack_paths
 ))
 .borders(Borders::ALL)
 .border_style(Style::default().fg(Color::Red)),
 )
 .select(
 Tab::all()
 .iter()
 .position(|t| *t == app.active_tab)
 .unwrap_or(0),
 )
 .highlight_style(
 Style::default()
 .fg(Color::Cyan)
 .add_modifier(Modifier::BOLD),
 );

 f.render_widget(tab_bar, area);
}

fn draw_main(f: &mut Frame, area: Rect, app: &App) {
 match app.active_tab {
 Tab::Graph => draw_graph_tab(f, area, app),
 Tab::Nodes => draw_nodes_tab(f, area, app),
 Tab::Paths => draw_paths_tab(f, area, app),
 Tab::Logs => draw_logs_tab(f, area, app),
 Tab::Trusts => draw_trusts_tab(f, area, app),
 }
}

fn draw_graph_tab(f: &mut Frame, area: Rect, app: &App) {
 if app.show_legend {
 let chunks = Layout::default()
 .direction(Direction::Vertical)
 .constraints([
 Constraint::Min(10), // Graph + detail
 Constraint::Length(14), // Legend overlay
 ])
 .split(area);
 let inner = Layout::default()
 .direction(Direction::Horizontal)
 .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
 .split(chunks[0]);
 graph_view::render_graph(f, inner[0], app);
 graph_view::render_node_detail(f, inner[1], app);
 graph_view::render_legend(f, chunks[1]);
 } else {
 let chunks = Layout::default()
 .direction(Direction::Horizontal)
 .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
 .split(area);
 graph_view::render_graph(f, chunks[0], app);
 graph_view::render_node_detail(f, chunks[1], app);
 }
}

fn draw_nodes_tab(f: &mut Frame, area: Rect, app: &App) {
 // If ACL findings are available, show them in a sub-panel
 if app.acl_findings.is_some() {
 let chunks = Layout::default()
 .direction(Direction::Vertical)
 .constraints([
 Constraint::Percentage(50), // Node table
 Constraint::Percentage(50), // ACL findings
 ])
 .split(area);
 draw_node_table(f, chunks[0], app);
 graph_view::render_acl_findings(f, chunks[1], app);
 } else {
 draw_node_table(f, area, app);
 }
}

fn draw_node_table(f: &mut Frame, area: Rect, app: &App) {
 let graph = app.graph.lock().unwrap_or_else(|e| {
 warn!("Mutex poisoned in UI -- recovering data");
 e.into_inner()
 });
 let mut rows = Vec::new();

 for (node_id, node) in graph.nodes() {
 let name_match = app.filter_text.is_empty()
 || node
 .name
 .to_lowercase()
 .contains(&app.filter_text.to_lowercase());
 if !name_match {
 continue;
 }

 let type_color = match node.node_type {
 NodeType::User => Color::Green,
 NodeType::Computer => Color::Blue,
 NodeType::Group => Color::Yellow,
 NodeType::Domain => Color::Magenta,
 NodeType::Gpo => Color::Cyan,
 NodeType::Ou => Color::Gray,
 NodeType::CertTemplate => Color::LightMagenta,
 };

 let outbound = graph.edges_from(node_id).count();
 let inbound = graph.edges_to(node_id).count();

 rows.push(Row::new(vec![
 Cell::from(format!("{}", node_id.index())),
 Cell::from(Span::styled(
 format!("{:?}", node.node_type),
 Style::default().fg(type_color),
 )),
 Cell::from(&*node.name),
 Cell::from(&*node.domain),
 Cell::from(format!("{}", outbound)).style(if outbound > 0 {
 Style::default().fg(Color::Red)
 } else {
 Style::default()
 }),
 Cell::from(format!("{}", inbound)),
 Cell::from("") // Removed compromised field as it doesn't exist in AdNode
 .style(Style::default().fg(Color::LightRed)),
 ]));
 }

 let header = Row::new(vec![
 Cell::from("ID").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Type").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Name").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Domain").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Out->").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("<-In").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Pwned").style(Style::default().add_modifier(Modifier::BOLD)),
 ])
 .height(1)
 .bottom_margin(1);

 let filter_title = if app.filter_text.is_empty() {
 " Nodes (/ to search) ".to_string()
 } else {
 format!(
 " Nodes [filter: '{}'] ({} matches) ",
 app.filter_text,
 rows.len()
 )
 };

 let table = Table::new(
 rows.clone(),
 [
 Constraint::Length(6),
 Constraint::Length(12),
 Constraint::Percentage(30),
 Constraint::Percentage(20),
 Constraint::Length(6),
 Constraint::Length(6),
 Constraint::Length(6),
 ],
 )
 .header(header)
 .block(
 Block::default()
 .title(filter_title)
 .borders(Borders::ALL)
 .border_style(Style::default().fg(Color::Yellow)),
 )
 .row_highlight_style(Style::default().bg(Color::DarkGray));

 f.render_widget(table, area);

 let scrollbar = Scrollbar::default()
 .orientation(ScrollbarOrientation::VerticalRight)
 .begin_symbol(Some("^"))
 .end_symbol(Some("v"));
 let mut scrollbar_state = ScrollbarState::new(rows.len()).position(app.node_scroll);
 f.render_stateful_widget(
 scrollbar,
 area.inner(Margin {
 vertical: 1,
 horizontal: 0,
 }),
 &mut scrollbar_state,
 );
}

fn draw_paths_tab(f: &mut Frame, area: Rect, app: &App) {
 let chunks = Layout::default()
 .direction(Direction::Vertical)
 .constraints([
 Constraint::Length(3), // Stats bar
 Constraint::Length(3), // Computed path section
 Constraint::Min(5), // Attack paths list
 ])
 .split(area);

 let stats_text = format!(
 "  Shortest paths to DA: {} | Total attack edges: {} | Domains: {} ",
 app.stats.attack_paths, app.stats.edges, app.stats.domains
 );
 let stats = Paragraph::new(stats_text)
 .block(
 Block::default()
 .borders(Borders::ALL)
 .border_style(Style::default().fg(Color::Red)),
 )
 .style(Style::default().fg(Color::LightRed));
 f.render_widget(stats, chunks[0]);

 // Render computed attack path
 graph_view::render_paths(f, chunks[1], app);

 // Render high-value target enumeration from graph
 let graph = app.graph.lock().unwrap_or_else(|e| {
 warn!("Mutex poisoned in UI -- recovering data");
 e.into_inner()
 });

 let mut path_lines: Vec<Line> = Vec::new();

 let high_value_targets: Vec<_> = graph
 .nodes()
 .filter(|(_, n)| {
 n.name.to_lowercase().contains("admin")
 || n.name.to_lowercase().contains("domain")
 || n.properties.get("high_value").is_some_and(|v| v == "true")
 })
 .collect();

 for (target_id, target) in &high_value_targets {
 path_lines.push(Line::from(vec![
 Span::styled(
 format!("{} ", target.name),
 Style::default()
 .fg(Color::LightRed)
 .add_modifier(Modifier::BOLD),
 ),
 Span::styled(
 format!("({:?})", target.node_type),
 Style::default().fg(Color::DarkGray),
 ),
 ]));

 let paths = graph.shortest_paths_to(*target_id, 5);
 for (i, _path) in paths.iter().enumerate() {
 path_lines.push(Line::from(vec![
 Span::styled(format!(" #{} ", i + 1), Style::default().fg(Color::Cyan)),
 Span::styled("(path exists)", Style::default().fg(Color::Yellow)),
 ]));

 path_lines.push(Line::from(""));
 }

 if paths.is_empty() {
 path_lines.push(Line::from(Span::styled(
 " (no path found from current foothold)",
 Style::default().fg(Color::DarkGray),
 )));
 }

 path_lines.push(Line::from(""));
 }

 let paths_list = Paragraph::new(path_lines)
 .block(
 Block::default()
 .title(" High-Value Targets ")
 .borders(Borders::ALL)
 .border_style(Style::default().fg(Color::Red)),
 )
 .scroll((app.path_scroll as u16, 0));
 f.render_widget(paths_list, chunks[2]);

 let scrollbar = Scrollbar::default()
 .orientation(ScrollbarOrientation::VerticalRight)
 .begin_symbol(Some("^"))
 .end_symbol(Some("v"));
 let mut scrollbar_state = ScrollbarState::new(200).position(app.path_scroll);
 f.render_stateful_widget(
 scrollbar,
 chunks[2].inner(Margin {
 vertical: 1,
 horizontal: 0,
 }),
 &mut scrollbar_state,
 );
}

fn draw_logs_tab(f: &mut Frame, area: Rect, app: &App) {
 let log_lines: Vec<Line> = app
 .logs
 .iter()
 .map(|entry| {
 let (level_str, level_color) = match entry.level {
 LogLevel::Info => ("INFO ", Color::Cyan),
 LogLevel::Warn => ("WARN ", Color::Yellow),
 LogLevel::Error => ("ERROR", Color::Red),
 LogLevel::Success => (" OK ", Color::Green),
 LogLevel::Attack => (" ATK ", Color::LightRed),
 };

 Line::from(vec![
 Span::styled(
 format!("{} ", entry.timestamp),
 Style::default().fg(Color::DarkGray),
 ),
 Span::styled(
 format!("[{}] ", level_str),
 Style::default().fg(level_color),
 ),
 Span::styled(
 format!("{}: ", entry.module),
 Style::default().fg(Color::Blue),
 ),
 Span::raw(&entry.message),
 ])
 })
 .collect();

 let logs_widget = Paragraph::new(log_lines)
 .block(
 Block::default()
 .title(format!("  Logs ({} entries) ", app.logs.len()))
 .borders(Borders::ALL)
 .border_style(Style::default().fg(Color::Green)),
 )
 .scroll((app.log_scroll as u16, 0));

 f.render_widget(logs_widget, area);

 let scrollbar = Scrollbar::default()
 .orientation(ScrollbarOrientation::VerticalRight)
 .begin_symbol(Some("^"))
 .end_symbol(Some("v"));
 let mut scrollbar_state = ScrollbarState::new(app.logs.len()).position(app.log_scroll);
 f.render_stateful_widget(
 scrollbar,
 area.inner(Margin {
 vertical: 1,
 horizontal: 0,
 }),
 &mut scrollbar_state,
 );
}

fn draw_trusts_tab(f: &mut Frame, area: Rect, app: &App) {
 let graph = app.graph.lock().unwrap_or_else(|e| {
 warn!("Mutex poisoned in UI -- recovering data");
 e.into_inner()
 });

 let mut rows = Vec::new();

 for (node_id, node) in graph.nodes() {
 if !matches!(node.node_type, NodeType::Domain) {
 continue;
 }

 let trust_edges: Vec<_> = graph
 .edges_from(node_id)
 .filter(|e| matches!(e.weight(), EdgeType::TrustedBy))
 .collect();

 for edge in &trust_edges {
 let target = match graph.get_node(edge.target()) {
 Some(t) => t,
 None => continue,
 };

 let direction_str = if graph
 .edges_from(edge.target())
 .any(|e| e.target() == node_id && matches!(e.weight(), EdgeType::TrustedBy))
 {
 "<-> Bidirectional"
 } else {
 "-> Outbound"
 };

 rows.push(Row::new(vec![
 Cell::from(&*node.name),
 Cell::from(direction_str),
 Cell::from(&*target.name),
 Cell::from("Unknown"),
 Cell::from("❓"),
 Cell::from("--"),
 ]));
 }
 }

 let header = Row::new(vec![
 Cell::from("Source").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Direction").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Target").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Type").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("SID Filter").style(Style::default().add_modifier(Modifier::BOLD)),
 Cell::from("Attack").style(Style::default().add_modifier(Modifier::BOLD)),
 ])
 .height(1)
 .bottom_margin(1);

 let table = Table::new(
 rows.clone(),
 [
 Constraint::Percentage(20),
 Constraint::Length(16),
 Constraint::Percentage(20),
 Constraint::Length(12),
 Constraint::Length(10),
 Constraint::Length(14),
 ],
 )
 .header(header)
 .block(
 Block::default()
 .title("  Domain Trusts ")
 .borders(Borders::ALL)
 .border_style(Style::default().fg(Color::Magenta)),
 );

 f.render_widget(table, area);

 let scrollbar = Scrollbar::default()
 .orientation(ScrollbarOrientation::VerticalRight)
 .begin_symbol(Some("^"))
 .end_symbol(Some("v"));
 let mut scrollbar_state = ScrollbarState::new(rows.len()).position(app.trust_scroll);
 f.render_stateful_widget(
 scrollbar,
 area.inner(Margin {
 vertical: 1,
 horizontal: 0,
 }),
 &mut scrollbar_state,
 );
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
 let status_spans = vec![
 Span::styled(
 " q",
 Style::default()
 .fg(Color::Yellow)
 .add_modifier(Modifier::BOLD),
 ),
 Span::raw(" quit "),
 Span::styled(
 "Tab",
 Style::default()
 .fg(Color::Yellow)
 .add_modifier(Modifier::BOLD),
 ),
 Span::raw(" switch "),
 Span::styled(
 "hjkl/^v<-->",
 Style::default()
 .fg(Color::Yellow)
 .add_modifier(Modifier::BOLD),
 ),
 Span::raw(" pan "),
 Span::styled(
 "+/-",
 Style::default()
 .fg(Color::Yellow)
 .add_modifier(Modifier::BOLD),
 ),
 Span::raw(" zoom "),
 Span::styled(
 "/",
 Style::default()
 .fg(Color::Yellow)
 .add_modifier(Modifier::BOLD),
 ),
 Span::raw(" search "),
 Span::styled(
 "0",
 Style::default()
 .fg(Color::Yellow)
 .add_modifier(Modifier::BOLD),
 ),
 Span::raw(" reset view "),
 // Filter indicator
 if app.filter_active {
 Span::styled(
 format!("  filter: {}_", app.filter_text),
 Style::default().fg(Color::Cyan),
 )
 } else {
 Span::raw("")
 },
 // Visibility toggle indicators
 Span::raw(" | "),
 Span::styled(
 format!("u:{}", if app.show_users { "[+]" } else { "[-]" }),
 Style::default().fg(if app.show_users {
 Color::Green
 } else {
 Color::DarkGray
 }),
 ),
 Span::raw(" "),
 Span::styled(
 format!("c:{}", if app.show_computers { "[+]" } else { "[-]" }),
 Style::default().fg(if app.show_computers {
 Color::Blue
 } else {
 Color::DarkGray
 }),
 ),
 Span::raw(" "),
 Span::styled(
 format!("g:{}", if app.show_groups { "[+]" } else { "[-]" }),
 Style::default().fg(if app.show_groups {
 Color::Yellow
 } else {
 Color::DarkGray
 }),
 ),
 Span::raw(" "),
 Span::styled(
 format!("d:{}", if app.show_domains { "[+]" } else { "[-]" }),
 Style::default().fg(if app.show_domains {
 Color::Magenta
 } else {
 Color::DarkGray
 }),
 ),
 ];

 let status_bar =
 Paragraph::new(Line::from(status_spans)).style(Style::default().bg(Color::DarkGray));

 f.render_widget(status_bar, area);
}
