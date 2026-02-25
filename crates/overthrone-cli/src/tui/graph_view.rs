use crate::tui::app::App;
use overthrone_core::graph::{EdgeRef, EdgeType, NodeType};
use ratatui::prelude::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{
    Block, Borders, Paragraph,
    canvas::{Canvas, Line as CanvasLine, Points},
};

/// Render the attack graph on a Canvas widget
pub fn render_graph(f: &mut Frame, area: Rect, app: &App) {
    let graph = app.graph.lock().unwrap();

    let x_min = app.camera_x - (area.width as f64) / (2.0 * app.zoom);
    let x_max = app.camera_x + (area.width as f64) / (2.0 * app.zoom);
    let y_min = app.camera_y - (area.height as f64) / (app.zoom);
    let y_max = app.camera_y + (area.height as f64) / (app.zoom);

    let canvas = Canvas::default()
        .block(
            Block::default()
                .title(format!(
                    " Attack Graph — {} nodes, {} edges [zoom: {:.1}x] ",
                    app.stats.total_nodes, app.stats.edges, app.zoom
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .x_bounds([x_min, x_max])
        .y_bounds([y_min, y_max])
        .paint(|ctx| {
            // Draw edges first (below nodes)
            for edge in graph.edges() {
                if let (Some(&(x1, y1)), Some(&(x2, y2))) =
                    (app.layout.get(&edge.source()), app.layout.get(&edge.target()))
                {
                    let color =
                        edge_color(edge.weight(), app.highlighted_path.contains(&edge.id()));
                    ctx.draw(&CanvasLine {
                        x1,
                        y1,
                        x2,
                        y2,
                        color,
                    });
                }
            }

            // Draw nodes
            for (node_id, node) in graph.nodes() {
                if let Some(&(x, y)) = app.layout.get(&node_id) {
                    let (color, marker) =
                        node_style(&node.node_type, app.selected_node == Some(node_id));

                    ctx.draw(&Points {
                        coords: &[(x, y)],
                        color,
                    });

                    // Label
                    let label = truncate_label(&node.name, 12);
                    ctx.print(
                        x + 1.0,
                        y + 0.5,
                        Span::styled(format!("{} {}", marker, label), Style::default().fg(color)),
                    );
                }
            }
        });

    f.render_widget(canvas, area);
}

fn node_style(node_type: &NodeType, selected: bool) -> (Color, &'static str) {
    let base = match node_type {
        NodeType::User => (Color::Green, "👤"),
        NodeType::Computer => (Color::Blue, "🖥"),
        NodeType::Group => (Color::Yellow, "👥"),
        NodeType::Domain => (Color::Magenta, "🏰"),
        NodeType::Gpo => (Color::Cyan, "📜"),
        NodeType::Ou => (Color::Gray, "📁"),
    };

    if selected {
        (Color::White, base.1)
    } else {
        base
    }
}

fn edge_color(edge_type: &EdgeType, highlighted: bool) -> Color {
    if highlighted {
        return Color::LightRed;
    }
    match edge_type {
        EdgeType::MemberOf => Color::DarkGray,
        EdgeType::AdminTo => Color::Red,
        EdgeType::HasSession => Color::Yellow,
        EdgeType::CanRDP => Color::Cyan,
        EdgeType::CanPSRemote => Color::Blue,
        EdgeType::GenericAll => Color::LightRed,
        EdgeType::WriteDacl => Color::LightRed,
        EdgeType::WriteOwner => Color::LightRed,
        EdgeType::DcSync => Color::Magenta,
        EdgeType::TrustedBy => Color::LightMagenta,
        EdgeType::Contains => Color::DarkGray,
        _ => Color::Gray,
    }
}

fn truncate_label(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}

/// Render the node detail panel (sidebar)
pub fn render_node_detail(f: &mut Frame, area: Rect, app: &App) {
    let graph = app.graph.lock().unwrap();

    let content = if let Some(node_id) = app.selected_node {
        if let Some(node) = graph.get_node(node_id) {
            let mut lines = vec![
                Line::from(Span::styled(
                    &node.name,
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(format!("Type: {:?}", node.node_type)),
                Line::from(format!("ID: {}", node_id.index())),
                Line::from(""),
            ];

            // Outbound edges (this node can attack...)
            let outbound: Vec<_> = graph.edges_from(node_id).collect();
            if !outbound.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("→ Outbound ({})", outbound.len()),
                    Style::default().fg(Color::Red),
                )));
                for edge in outbound.iter().take(10) {
                    if let Some(target) = graph.get_node(edge.target()) {
                        lines.push(Line::from(format!(
                            "  {:?} → {}",
                            edge.weight(), target.name
                        )));
                    }
                }
            }

            // Inbound edges (...can be attacked by)
            let inbound: Vec<_> = graph.edges_to(node_id).collect();
            if !inbound.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("← Inbound ({})", inbound.len()),
                    Style::default().fg(Color::Green),
                )));
                for edge in inbound.iter().take(10) {
                    if let Some(source) = graph.get_node(edge.source()) {
                        lines.push(Line::from(format!(
                            "  {} {:?} →",
                            source.name, edge.weight()
                        )));
                    }
                }
            }

            lines
        } else {
            vec![Line::from("Node not found")]
        }
    } else {
        vec![
            Line::from("No node selected"),
            Line::from(""),
            Line::from("Click or use Enter to select"),
        ]
    };

    let panel = Paragraph::new(content).block(
        Block::default()
            .title(" Node Detail ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );

    f.render_widget(panel, area);
}
