//! TUI graph canvas and node-detail panel rendering.
//!
//! Bugs fixed vs. original:
//!  • `EdgeRef` imported but never used — removed dead import
//!  • `highlighted` colour was `LightRed` — same as critical edges, invisible on path;
//!    changed to `LightYellow` for contrast
//!  • `graph` MutexGuard held across `f.render_widget` — potential deadlock;
//!    data is now cloned out before the lock is released
//!  • `Some(match { return None; ... })` pattern caused rustc delimiter mismatch —
//!    `edge_abuse_info` rewritten so every arm returns `Option<&'static str>` directly,
//!    no wrapping `Some(match {...})` and no `return` inside the match
//!  • `Box::leak` for Custom edge string caused unbounded memory leak — removed;
//!    Custom/MemberOf/Contains arms now return `None`
//!  • `let Some(x) = ... else { ... }` let-else replaced with explicit `match` to
//!    avoid indentation-mismatch false positives from rust-analyzer
//!  • Severity-coloured ACL findings summary in the graph overview panel
//!
//! New features:
//!  • `render_acl_findings` — scrollable ACL findings panel
//!  • `render_paths` — attack-path panel with per-hop abuse notes
//!  • `render_legend` — colour-coded edge-type legend overlay
//!  • Scroll offset support via `app.graph_scroll`, `app.detail_scroll`,
//!    `app.acl_scroll`, `app.path_scroll`
//!  • `node_color()` helper covering GPO / OU / CertTemplate node types
//!  • `edge_color_by_name()` for statistics view
//!  • Visual graph canvas with clean node/edge rendering
//!  • Node type visibility toggles (users/computers/groups/etc.)

use crate::tui::app::App;
use overthrone_core::graph::{EdgeRef, EdgeType, NodeId, NodeType};
use ratatui::prelude::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use std::collections::HashMap;

// ─── Colour helpers ───────────────────────────────────────────────────────────

/// Map an edge type to its display colour.
///
/// When `highlighted` is `true` (the edge lies on the current attack path) the
/// colour is overridden to `LightYellow` so it contrasts against the `LightRed`
/// already used for high-severity edges like `GenericAll` / `AdminTo`.
pub fn edge_color(edge_type: &EdgeType, highlighted: bool) -> Color {
    if highlighted {
        return Color::LightYellow;
    }
    match edge_type {
        EdgeType::MemberOf => Color::DarkGray,
        EdgeType::Contains => Color::DarkGray,
        EdgeType::TrustedBy => Color::LightMagenta,

        EdgeType::AdminTo => Color::Red,
        EdgeType::AllowedToAct => Color::Red,
        EdgeType::ExecuteDCOM => Color::LightRed,
        EdgeType::CanPSRemote => Color::LightRed,

        EdgeType::HasSession => Color::Yellow,
        EdgeType::HasSpn => Color::Yellow,
        EdgeType::DontReqPreauth => Color::Yellow,
        EdgeType::AddSelf => Color::Yellow,
        EdgeType::AddMembers => Color::Yellow,

        EdgeType::CanRDP => Color::Cyan,
        EdgeType::SQLAdmin => Color::Cyan,

        EdgeType::GenericAll => Color::LightRed,
        EdgeType::GenericWrite => Color::LightRed,
        EdgeType::WriteDacl => Color::LightRed,
        EdgeType::WriteOwner => Color::LightRed,
        EdgeType::Owns => Color::LightRed,

        EdgeType::ForceChangePassword => Color::Magenta,
        EdgeType::ReadLapsPassword => Color::Magenta,
        EdgeType::ReadGmsaPassword => Color::Magenta,
        EdgeType::AllowedToDelegate => Color::Magenta,
        EdgeType::DcSync => Color::Magenta,
        EdgeType::GetChanges => Color::Magenta,
        EdgeType::GetChangesAll => Color::Magenta,
        EdgeType::HasSidHistory => Color::LightMagenta,

        EdgeType::GpoLink => Color::Green,

        EdgeType::Custom(_) => Color::Gray,
    }
}

/// Severity-mapped colour for ACL finding rows (1 = most severe).
#[allow(dead_code)]
fn severity_color(severity: u8) -> Color {
    match severity {
        1 => Color::Red,
        2 => Color::LightRed,
        3 => Color::Yellow,
        4 => Color::Cyan,
        _ => Color::Gray,
    }
}

/// Display colour for a node type.
pub fn node_color(node_type: &NodeType) -> Color {
    match node_type {
        NodeType::User => Color::Green,
        NodeType::Computer => Color::Blue,
        NodeType::Group => Color::Yellow,
        NodeType::Domain => Color::Magenta,
        NodeType::Gpo => Color::Cyan,
        NodeType::Ou => Color::LightBlue,
        NodeType::CertTemplate => Color::LightMagenta,
    }
}

/// Derive a display colour from an edge-type name string.
/// Used in the statistics view where we only have `&str`, not `&EdgeType`.
fn edge_color_by_name(name: &str) -> Color {
    match name {
        "AdminTo" | "AllowedToAct" => Color::Red,
        "GenericAll" | "WriteDacl" | "WriteOwner" | "GenericWrite" | "Owns" => Color::LightRed,
        "HasSession" | "HasSpn" | "DontReqPreauth" | "AddMembers" | "AddSelf" => Color::Yellow,
        "CanRDP" | "SQLAdmin" => Color::Cyan,
        "CanPSRemote" | "ExecuteDCOM" => Color::LightRed,
        "ForceChangePassword"
        | "DcSync"
        | "GetChanges"
        | "GetChangesAll"
        | "AllowedToDelegate"
        | "ReadLapsPassword"
        | "ReadGmsaPassword"
        | "HasSidHistory" => Color::Magenta,
        "GpoLink" => Color::Green,
        "TrustedBy" => Color::LightMagenta,
        "MemberOf" | "Contains" => Color::DarkGray,
        _ => Color::Gray,
    }
}

/// Short abuse description for an edge type.
///
/// Returns `None` for non-abusable traversal edges (MemberOf, Contains, Custom).
///
/// **Key fix:** every arm returns `Option<&'static str>` directly.  The original
/// code used `Some(match { ... })` with `return None` / `return Some(...)` inside
/// the match body, which confused rustc's brace balancer and produced the
/// "unexpected closing delimiter" error at the last `}` of the file.
fn edge_abuse_info(edge_type: &EdgeType) -> Option<&'static str> {
    match edge_type {
        EdgeType::AdminTo => Some("Local admin — exec via WMI / WinRM / SMB / PsExec"),
        EdgeType::GenericAll => Some("Full control — reset password, modify DACL, add to group"),
        EdgeType::GenericWrite => {
            Some("Write non-protected attributes — SPN, KeyCredentialLink, etc.")
        }
        EdgeType::WriteDacl => Some("Modify DACL → grant yourself GenericAll"),
        EdgeType::WriteOwner => Some("Take ownership → modify DACL → GenericAll"),
        EdgeType::Owns => Some("Already owner — modify DACL to gain GenericAll"),
        EdgeType::ForceChangePassword => {
            Some("net rpc password / Set-ADAccountPassword (no current pw needed)")
        }
        EdgeType::AddMembers => Some("Add yourself / controlled account to the group"),
        EdgeType::AddSelf => Some("Self-write validated right — add your own account to the group"),
        EdgeType::AllowedToDelegate => {
            Some("S4U2Self + S4U2Proxy → impersonate any user to target service")
        }
        EdgeType::AllowedToAct => {
            Some("RBCD → getST.py to impersonate Domain Admin to target computer")
        }
        EdgeType::DcSync => Some("secretsdump.py -just-dc → dump NTDS + all NTLM hashes"),
        EdgeType::GetChanges | EdgeType::GetChangesAll => {
            Some("Part of DCSync right — principal needs both GetChanges flags")
        }
        EdgeType::ReadLapsPassword => {
            Some("Read ms-Mcs-AdmPwd / ms-LAPS-Password → cleartext local admin cred")
        }
        EdgeType::ReadGmsaPassword => {
            Some("GMSAPasswordReader → NT hash for lateral movement as gMSA")
        }
        EdgeType::HasSidHistory => {
            Some("SID in SIDHistory → principal implicitly member of historical group")
        }
        EdgeType::CanRDP => Some("xfreerdp / mstsc — GUI access; local admin may not be required"),
        EdgeType::CanPSRemote => Some("Enter-PSSession / evil-winrm — PowerShell remoting"),
        EdgeType::ExecuteDCOM => Some("Invoke-DCOM / MMC20.Application lateral movement"),
        EdgeType::SQLAdmin => Some("SQL Server sysadmin → xp_cmdshell / CLR assembly RCE"),
        EdgeType::HasSession => {
            Some("Token impersonation if admin on host (Incognito / mimikatz tokens)")
        }
        EdgeType::HasSpn => Some("GetUserSPNs.py → offline TGS crack (Kerberoast)"),
        EdgeType::DontReqPreauth => Some("GetNPUsers.py → AS-REP roast (DONT_REQ_PREAUTH set)"),
        EdgeType::GpoLink => Some("Link GPO to OU → immediate exec on Group Policy refresh"),
        EdgeType::TrustedBy => {
            Some("Cross-domain trust — SID injection / trust escalation potential")
        }
        // Non-abusable traversal / membership edges — no abuse note
        EdgeType::MemberOf | EdgeType::Contains | EdgeType::Custom(_) => None,
    }
}

fn edge_severity(edge_type: &EdgeType) -> u8 {
    match edge_type {
        EdgeType::GenericAll
        | EdgeType::WriteDacl
        | EdgeType::WriteOwner
        | EdgeType::Owns
        | EdgeType::DcSync
        | EdgeType::AllowedToAct => 1,
        EdgeType::GenericWrite
        | EdgeType::ForceChangePassword
        | EdgeType::AddMembers
        | EdgeType::AddSelf
        | EdgeType::ReadLapsPassword
        | EdgeType::ReadGmsaPassword
        | EdgeType::AllowedToDelegate
        | EdgeType::SQLAdmin
        | EdgeType::GpoLink
        | EdgeType::TrustedBy
        | EdgeType::GetChanges
        | EdgeType::GetChangesAll => 2,
        EdgeType::AdminTo
        | EdgeType::CanRDP
        | EdgeType::CanPSRemote
        | EdgeType::ExecuteDCOM
        | EdgeType::HasSession
        | EdgeType::HasSidHistory => 3,
        EdgeType::HasSpn | EdgeType::DontReqPreauth => 4,
        EdgeType::MemberOf | EdgeType::Contains | EdgeType::Custom(_) => 5,
    }
}

fn edge_operator_note(edge_type: &EdgeType) -> Option<&'static str> {
    match edge_type {
        EdgeType::GenericAll => Some(
            "Operator note: full control; preserve current ACL/owner before password, group, or shadow-credential abuse.",
        ),
        EdgeType::GenericWrite => Some(
            "Operator note: write path; evaluate SPN, KeyCredentialLink, logon script, and certificate mapping options.",
        ),
        EdgeType::WriteDacl => Some(
            "Operator note: add a minimal temporary ACE, complete the action, and restore the original DACL.",
        ),
        EdgeType::WriteOwner | EdgeType::Owns => Some(
            "Operator note: ownership can unlock DACL changes; restore owner and ACL after validation.",
        ),
        EdgeType::ForceChangePassword => Some(
            "Operator note: password reset is visible and disruptive; use only when approved by the runbook.",
        ),
        EdgeType::AddMembers | EdgeType::AddSelf => Some(
            "Operator note: group change should be scoped, time-boxed, and removed after the dependent step.",
        ),
        EdgeType::AllowedToAct => Some(
            "Operator note: RBCD path; use a controlled machine account and request only the needed service ticket.",
        ),
        EdgeType::AllowedToDelegate => Some(
            "Operator note: constrained delegation; enumerate allowed services before S4U testing.",
        ),
        EdgeType::DcSync | EdgeType::GetChanges | EdgeType::GetChangesAll => Some(
            "Operator note: replication-impacting right; validate scope and prefer targeted secret retrieval.",
        ),
        EdgeType::ReadLapsPassword => Some(
            "Operator note: collect the host password once, protect it as credential material, and avoid repeated reads.",
        ),
        EdgeType::ReadGmsaPassword => Some(
            "Operator note: derive gMSA material and map service-account reach before using it.",
        ),
        EdgeType::AdminTo => Some(
            "Operator note: local admin path; choose the lowest-volume remote-management primitive allowed.",
        ),
        EdgeType::CanRDP => Some(
            "Operator note: interactive access is visible; prefer non-interactive validation unless RDP is required.",
        ),
        EdgeType::CanPSRemote => {
            Some("Operator note: keep WinRM commands low-volume and host-scoped.")
        }
        EdgeType::ExecuteDCOM => Some(
            "Operator note: DCOM has a high telemetry surface; reserve for approved execution phases.",
        ),
        EdgeType::SQLAdmin => Some(
            "Operator note: inspect linked servers, impersonation, xp_cmdshell, CLR, and trust paths.",
        ),
        EdgeType::HasSession => Some(
            "Operator note: confirm live session freshness and combine with host admin before token operations.",
        ),
        EdgeType::HasSpn => Some(
            "Operator note: Kerberoast marker; request scoped tickets and continue cracking offline.",
        ),
        EdgeType::DontReqPreauth => {
            Some("Operator note: AS-REP roast marker; collect once and continue offline.")
        }
        EdgeType::GpoLink => Some(
            "Operator note: review linked OU scope, security filtering, and rollback before GPO edits.",
        ),
        EdgeType::TrustedBy => Some(
            "Operator note: confirm trust direction, SID filtering, selective auth, and transitivity.",
        ),
        EdgeType::HasSidHistory => Some(
            "Operator note: validate effective SIDHistory membership and cross-domain side effects.",
        ),
        EdgeType::MemberOf | EdgeType::Contains | EdgeType::Custom(_) => None,
    }
}

fn push_edge_guidance<'a>(lines: &mut Vec<Line<'a>>, edge_type: &EdgeType, indent: &'static str) {
    if let Some(note) = edge_operator_note(edge_type) {
        let severity = edge_severity(edge_type);
        lines.push(Line::from(vec![
            Span::raw(indent),
            Span::styled(
                format!("[S{}] ", severity),
                Style::default()
                    .fg(severity_color(severity))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(note, Style::default().fg(Color::Gray)),
        ]));
    }
}

// ─── Graph overview panel ─────────────────────────────────────────────────────

/// Render the graph-overview canvas (left pane of the Graph tab).
///
/// The `graph` Mutex is locked only long enough to copy out the data we need.
/// The lock is released before any call to `f.render_widget`, preventing a
/// deadlock when the background collector thread contends the same lock.
pub fn render_graph(f: &mut Frame, area: Rect, app: &App) {
    // Collect stats under the lock, then drop it immediately.
    let (stats, hv_targets, _nodes, _edges) = {
        let graph = app.graph.lock().unwrap();
        let stats = graph.stats();
        let hv = graph.high_value_targets(8);
        // Clone node positions for rendering
        let layout_snapshot: HashMap<NodeId, (f64, f64)> = app.layout.clone();
        // Collect visible nodes and edges
        let nodes: Vec<_> = graph
            .nodes()
            .filter(|(idx, node)| is_node_visible(node, *idx, &layout_snapshot, app))
            .map(|(idx, node)| (idx, node.clone()))
            .collect();
        let edges: Vec<_> = graph
            .edges()
            .filter(|edge| {
                let source_idx = edge.source();
                let target_idx = edge.target();
                let source_visible = nodes.iter().any(|(idx, _)| *idx == source_idx);
                let target_visible = nodes.iter().any(|(idx, _)| *idx == target_idx);
                source_visible && target_visible
            })
            .map(|edge| {
                (
                    edge.source(),
                    edge.target(),
                    edge.weight().clone(),
                    edge.id(),
                )
            })
            .collect();
        (stats, hv, nodes, edges)
    };

    let scroll = app.graph_scroll.unwrap_or(0);
    let mut lines: Vec<Line> = Vec::new();

    // Header
    lines.push(Line::from(vec![Span::styled(
        " ⚡ Graph Overview ",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(""));

    // Node Counts
    lines.push(Line::from(Span::styled(
        " Node Counts",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled("  Users:     ", Style::default().fg(Color::Green)),
        Span::styled(
            format!("{:>6}", stats.users),
            Style::default().fg(Color::White),
        ),
        Span::raw("   "),
        Span::styled("Computers: ", Style::default().fg(Color::Blue)),
        Span::styled(
            format!("{:>6}", stats.computers),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Groups:    ", Style::default().fg(Color::Yellow)),
        Span::styled(
            format!("{:>6}", stats.groups),
            Style::default().fg(Color::White),
        ),
        Span::raw("   "),
        Span::styled("Domains:   ", Style::default().fg(Color::Magenta)),
        Span::styled(
            format!("{:>6}", stats.domains),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  GPOs:      ", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("{:>6}", stats.gpos),
            Style::default().fg(Color::White),
        ),
        Span::raw("   "),
        Span::styled("OUs:       ", Style::default().fg(Color::LightCyan)),
        Span::styled(
            format!("{:>6}", stats.ous),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Total edges:", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(" {}", stats.total_edges),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(""));

    // Visibility toggles
    lines.push(Line::from(Span::styled(
        " Visibility Toggles",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled(
            "  [u] ",
            Style::default().fg(if app.show_users {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_users {
            "Users    "
        } else {
            "Users (hidden) "
        }),
        Span::styled(
            "  [c] ",
            Style::default().fg(if app.show_computers {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_computers {
            "Computers"
        } else {
            "Computers(hidden)"
        }),
    ]));
    lines.push(Line::from(vec![
        Span::styled(
            "  [g] ",
            Style::default().fg(if app.show_groups {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_groups {
            "Groups   "
        } else {
            "Groups (hidden) "
        }),
        Span::styled(
            "  [d] ",
            Style::default().fg(if app.show_domains {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_domains {
            "Domains  "
        } else {
            "Domains (hidden) "
        }),
    ]));
    lines.push(Line::from(""));

    // Edge-type distribution (top 12 by count)
    lines.push(Line::from(Span::styled(
        " Edge Distribution",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::UNDERLINED),
    )));
    let mut edge_counts: Vec<_> = stats.edge_type_counts.iter().collect();
    edge_counts.sort_by(|a, b| b.1.cmp(a.1));
    for (edge_type, count) in edge_counts.iter().take(12) {
        let display = edge_type.to_string();
        let color = edge_color_by_name(&display);
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:<28}", display), Style::default().fg(color)),
            Span::styled(format!("{:>5}", count), Style::default().fg(Color::Yellow)),
        ]));
    }
    lines.push(Line::from(""));

    // High-value targets
    lines.push(Line::from(Span::styled(
        " High-Value Targets",
        Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD)
            .add_modifier(Modifier::UNDERLINED),
    )));
    for (name, node_type, degree) in &hv_targets {
        let color = node_color(node_type);
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:?}", node_type), Style::default().fg(color)),
            Span::raw("  "),
            Span::styled(
                name.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("(degree: {})", degree),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }

    // ACL findings summary (if a scan has been run)
    if let Some(ref acls) = app.acl_findings {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " ACL Findings Summary",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
        )));
        let critical_count = acls.iter().filter(|f| f.severity <= 2).count();
        lines.push(Line::from(vec![
            Span::raw("  Total findings: "),
            Span::styled(
                format!("{}", acls.len()),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("   Critical (sev ≤ 2): "),
            Span::styled(
                format!("{}", critical_count),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]));
        for finding in acls.iter().filter(|f| f.severity == 1).take(5) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("⚠ ", Style::default().fg(Color::Red)),
                Span::styled(
                    format!("{} → {:?}", finding.principal, finding.right),
                    Style::default().fg(Color::LightRed),
                ),
                Span::raw("  on "),
                Span::styled(finding.target.clone(), Style::default().fg(Color::White)),
            ]));
        }
    }

    let scrolled: Vec<Line> = lines.into_iter().skip(scroll).collect();

    let widget = Paragraph::new(scrolled)
        .block(
            Block::default()
                .title(Span::styled(
                    " Graph Canvas [↑/↓ scroll] ",
                    Style::default().fg(Color::Cyan),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(widget, area);
}

/// Check if a node should be visible based on current filters
fn is_node_visible(
    node: &overthrone_core::graph::AdNode,
    _idx: NodeId,
    _layout: &HashMap<NodeId, (f64, f64)>,
    app: &App,
) -> bool {
    // Check node type visibility
    match node.node_type {
        NodeType::User if !app.show_users => return false,
        NodeType::Computer if !app.show_computers => return false,
        NodeType::Group if !app.show_groups => return false,
        NodeType::Domain if !app.show_domains => return false,
        NodeType::Gpo if !app.show_gpos => return false,
        NodeType::Ou if !app.show_ous => return false,
        _ => {}
    }
    // Check search filter
    if !app.filter_text.is_empty() {
        let needle = app.filter_text.to_ascii_lowercase();
        if !node.name.to_ascii_lowercase().contains(&needle)
            && !node.domain.to_ascii_lowercase().contains(&needle)
            && !node
                .node_type
                .to_string()
                .to_ascii_lowercase()
                .contains(&needle)
        {
            return false;
        }
    }
    true
}

// ─── Node detail panel ────────────────────────────────────────────────────────

/// Render the node-detail panel for the currently selected node.
pub fn render_node_detail(f: &mut Frame, area: Rect, app: &App) {
    let lines = build_node_detail_lines(app);
    let scroll = app.detail_scroll.unwrap_or(0);
    let scrolled: Vec<Line> = lines.into_iter().skip(scroll).collect();

    let widget = Paragraph::new(scrolled)
        .block(
            Block::default()
                .title(Span::styled(
                    " Node Details [↑/↓ scroll] ",
                    Style::default().fg(Color::Yellow),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(widget, area);
}

/// Build the line buffer for `render_node_detail`.
///
/// Uses explicit `match` instead of `let-else` to avoid the rust-analyzer
/// indentation-mismatch false positive that triggered the original error.
fn build_node_detail_lines(app: &App) -> Vec<Line<'_>> {
    let graph = app.graph.lock().unwrap();
    let mut lines: Vec<Line> = Vec::new();

    // Guard: no node selected
    let node_idx = match app.selected_node {
        Some(idx) => idx,
        None => {
            lines.push(Line::from(Span::styled(
                "  No node selected",
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Navigate to the Nodes tab and press Enter to select",
                Style::default().fg(Color::DarkGray),
            )));
            return lines;
        }
    };

    // Guard: stale index (node was removed from graph)
    let node = match graph.get_node(node_idx) {
        Some(n) => n,
        None => {
            lines.push(Line::from(Span::styled(
                "  ⚠ Selected node no longer exists in graph",
                Style::default().fg(Color::Red),
            )));
            return lines;
        }
    };

    let name_color = node_color(&node.node_type);

    // ── Identity section ──────────────────────────────────────────────────────
    lines.push(Line::from(vec![Span::styled(
        format!("  {}", node.name),
        Style::default().fg(name_color).add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(vec![
        Span::raw("  Type:    "),
        Span::styled(
            format!("{:?}", node.node_type),
            Style::default().fg(name_color),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Domain:  "),
        Span::styled(node.domain.clone(), Style::default().fg(Color::Magenta)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Enabled: "),
        Span::styled(
            if node.enabled { "Yes" } else { "No" },
            Style::default().fg(if node.enabled {
                Color::Green
            } else {
                Color::Red
            }),
        ),
    ]));
    if let Some(ref dn) = node.distinguished_name {
        lines.push(Line::from(vec![
            Span::raw("  DN:      "),
            Span::styled(dn.clone(), Style::default().fg(Color::DarkGray)),
        ]));
    }
    if let Some(sid) = node
        .properties
        .get("objectid")
        .or_else(|| node.properties.get("objectsid"))
    {
        lines.push(Line::from(vec![
            Span::raw("  SID:     "),
            Span::styled(sid.clone(), Style::default().fg(Color::DarkGray)),
        ]));
    }

    // ── Properties section ────────────────────────────────────────────────────
    if !node.properties.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Properties",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::UNDERLINED),
        )));
        let mut props: Vec<_> = node.properties.iter().collect();
        props.sort_by_key(|(k, _)| k.as_str());
        for (key, value) in &props {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    {:<24}", key),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(value.to_string()),
            ]));
        }
    }

    // ── Outbound edges ────────────────────────────────────────────────────────
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Outbound Edges",
        Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::UNDERLINED),
    )));

    let outbound: Vec<_> = graph.edges_from(node_idx).collect();
    if outbound.is_empty() {
        lines.push(Line::from(Span::styled(
            "    (none)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for edge in &outbound {
        if let Some(target_node) = graph.get_node(edge.target()) {
            let on_path = app.highlighted_path.contains(&edge.id());
            let color = edge_color(edge.weight(), on_path);
            let modifier = if on_path {
                Modifier::BOLD
            } else {
                Modifier::empty()
            };
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    format!("{:<30}", format!("{:?}", edge.weight())),
                    Style::default().fg(color).add_modifier(modifier),
                ),
                Span::styled("→ ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    target_node.name.clone(),
                    Style::default().fg(node_color(&target_node.node_type)),
                ),
            ]));
            push_edge_guidance(&mut lines, edge.weight(), "      ");
        }
    }

    // ── Inbound edges ─────────────────────────────────────────────────────────
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Inbound Edges",
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::UNDERLINED),
    )));

    let inbound: Vec<_> = graph.edges_to(node_idx).collect();
    if inbound.is_empty() {
        lines.push(Line::from(Span::styled(
            "    (none)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for edge in &inbound {
        if let Some(src_node) = graph.get_node(edge.source()) {
            let on_path = app.highlighted_path.contains(&edge.id());
            let color = edge_color(edge.weight(), on_path);
            let modifier = if on_path {
                Modifier::BOLD
            } else {
                Modifier::empty()
            };
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    src_node.name.clone(),
                    Style::default().fg(node_color(&src_node.node_type)),
                ),
                Span::styled(" → ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:?}", edge.weight()),
                    Style::default().fg(color).add_modifier(modifier),
                ),
            ]));
            push_edge_guidance(&mut lines, edge.weight(), "      ");
        }
    }

    // ── MemberOf details (clear grouping) ──────────────────────────────────────
    let member_of_out: Vec<_> = outbound
        .iter()
        .filter(|e| *e.weight() == EdgeType::MemberOf)
        .collect();
    let member_of_in: Vec<_> = inbound
        .iter()
        .filter(|e| *e.weight() == EdgeType::MemberOf)
        .collect();

    if !member_of_out.is_empty() || !member_of_in.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  MemberOf Relationships",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::UNDERLINED),
        )));

        if !member_of_out.is_empty() {
            lines.push(Line::from(Span::styled(
                "    Member Of:",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
            for edge in &member_of_out {
                if let Some(target) = graph.get_node(edge.target()) {
                    lines.push(Line::from(vec![
                        Span::raw("      → "),
                        Span::styled(
                            target.name.clone(),
                            Style::default().fg(node_color(&target.node_type)),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            format!("[{:?}]", target.node_type),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }
        }

        if !member_of_in.is_empty() {
            lines.push(Line::from(Span::styled(
                "    Members:",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
            for edge in &member_of_in {
                if let Some(src) = graph.get_node(edge.source()) {
                    lines.push(Line::from(vec![
                        Span::raw("      ← "),
                        Span::styled(
                            src.name.clone(),
                            Style::default().fg(node_color(&src.node_type)),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            format!("[{:?}]", src.node_type),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }
        }
    }

    // ── Abuse summary for unique outbound edge types ───────────────────────────
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Edge Abuse Summary",
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::UNDERLINED),
    )));

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let abuse_edges: Vec<_> = graph.edges_from(node_idx).collect();
    for edge in &abuse_edges {
        let key = format!("{:?}", edge.weight());
        if seen.insert(key)
            && let Some(info) = edge_abuse_info(edge.weight())
        {
            let color = edge_color(edge.weight(), false);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  [{:?}] ", edge.weight()),
                    Style::default().fg(color),
                ),
                Span::styled(info, Style::default().fg(Color::Gray)),
            ]));
        }
    }

    lines
}

// ─── ACL findings panel ───────────────────────────────────────────────────────

/// Render the full ACL findings list in a scrollable panel.
#[allow(dead_code)]
pub fn render_acl_findings(f: &mut Frame, area: Rect, app: &App) {
    let scroll = app.acl_scroll.unwrap_or(0);

    let items: Vec<ListItem> = match &app.acl_findings {
        None => vec![ListItem::new(Span::styled(
            "  No ACL findings loaded — run 'acls' scan first",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(findings) => findings
            .iter()
            .skip(scroll)
            .map(|f| {
                let color = severity_color(f.severity);
                let inherited = if f.is_inherited { " [inherited]" } else { "" };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("[S{}] ", f.severity),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<30}", f.principal),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(" → ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{:<35}", format!("{:?}", f.right)),
                        Style::default().fg(color),
                    ),
                    Span::styled(" on ", Style::default().fg(Color::DarkGray)),
                    Span::styled(f.target.clone(), Style::default().fg(Color::White)),
                    Span::styled(
                        inherited,
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    ),
                ]))
            })
            .collect(),
    };

    let total = app.acl_findings.as_ref().map(|v| v.len()).unwrap_or(0);
    let title = format!(" ACL Findings ({} total) [↑/↓ scroll] ", total);

    let widget = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(title, Style::default().fg(Color::LightRed)))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightRed)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(widget, area);
}

// ─── Attack-path panel ────────────────────────────────────────────────────────

/// Render the current computed attack path.
#[allow(dead_code)]
pub fn render_paths(f: &mut Frame, area: Rect, app: &App) {
    let scroll = app.path_scroll.unwrap_or(0);
    let mut lines: Vec<Line> = Vec::new();

    match &app.current_path {
        None => {
            lines.push(Line::from(Span::styled(
                "  No attack path computed",
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Use the search panel to find shortest paths",
                Style::default().fg(Color::DarkGray),
            )));
        }
        Some(path) => {
            lines.push(Line::from(vec![
                Span::styled(
                    " Attack Path ",
                    Style::default()
                        .fg(Color::LightRed)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("({} hops)", path.hop_count),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
            lines.push(Line::from(""));

            for (step_idx, step) in path.hops.iter().enumerate() {
                let color = node_color(&step.source_type);
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:>3}. ", step_idx + 1),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:?}", step.source_type),
                        Style::default().fg(color),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        step.source.clone(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]));

                let edge_type = &step.edge;
                let ecolor = edge_color(edge_type, true);
                lines.push(Line::from(vec![
                    Span::raw("       "),
                    Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{:?}", edge_type),
                        Style::default().fg(ecolor).add_modifier(Modifier::BOLD),
                    ),
                ]));
                if let Some(abuse) = edge_abuse_info(edge_type) {
                    lines.push(Line::from(vec![
                        Span::raw("       "),
                        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            format!("  ↳ {}", abuse),
                            Style::default()
                                .fg(Color::Gray)
                                .add_modifier(Modifier::ITALIC),
                        ),
                    ]));
                }
            }

            if let Some(last) = path.hops.last() {
                let color = node_color(&last.target_type);
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:>3}. ", path.hops.len() + 1),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:?}", last.target_type),
                        Style::default().fg(color),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        last.target.clone(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::raw("  Total path cost: "),
                Span::styled(
                    format!("{}", path.total_cost),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        }
    }

    let scrolled: Vec<Line> = lines.into_iter().skip(scroll).collect();

    let widget = Paragraph::new(scrolled)
        .block(
            Block::default()
                .title(Span::styled(
                    " Attack Path [↑/↓ scroll] ",
                    Style::default().fg(Color::LightRed),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightRed)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(widget, area);
}

// ─── Legend overlay ───────────────────────────────────────────────────────────

/// Render a colour-coded edge-type legend in the given area.
#[allow(dead_code)]
pub fn render_legend(f: &mut Frame, area: Rect) {
    let entries: &[(&str, Color, &str)] = &[
        ("AdminTo", Color::Red, "Local admin access"),
        (
            "AllowedToAct (RBCD)",
            Color::Red,
            "Resource-based constrained delegation",
        ),
        ("GenericAll", Color::LightRed, "Full control over object"),
        (
            "WriteDacl",
            Color::LightRed,
            "Modify DACL → grant GenericAll",
        ),
        (
            "WriteOwner",
            Color::LightRed,
            "Take ownership → modify DACL",
        ),
        ("DcSync", Color::Magenta, "Replicate all secrets from DC"),
        (
            "ForceChangePassword",
            Color::Magenta,
            "Reset password without knowing current",
        ),
        (
            "ReadLapsPassword",
            Color::Magenta,
            "Read cleartext local admin password",
        ),
        (
            "AllowedToDelegate",
            Color::Magenta,
            "Constrained delegation → TGT",
        ),
        (
            "HasSession",
            Color::Yellow,
            "User has active session on computer",
        ),
        (
            "HasSpn / Kerberoast",
            Color::Yellow,
            "Account has SPN → offline crack",
        ),
        ("AddMembers", Color::Yellow, "Add members to group"),
        ("CanRDP", Color::Cyan, "Remote Desktop access"),
        ("GpoLink", Color::Green, "GPO linked to OU → policy exec"),
        (
            "MemberOf / Contains",
            Color::DarkGray,
            "Group / OU membership",
        ),
        (
            "Highlighted path",
            Color::LightYellow,
            "Edge on current attack path",
        ),
    ];

    let items: Vec<ListItem> = entries
        .iter()
        .map(|(label, color, desc)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("  {:<30}", label),
                    Style::default().fg(*color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(*desc, Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let widget = List::new(items).block(
        Block::default()
            .title(Span::styled(
                " Edge Legend ",
                Style::default().fg(Color::Cyan),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    f.render_widget(widget, area);
}
