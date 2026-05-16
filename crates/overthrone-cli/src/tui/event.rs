use crate::tui::app::{App, Tab};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

pub struct EventLoop;

impl EventLoop {
    /// Process pending terminal events (non-blocking)
    pub fn poll(app: &mut App, timeout: Duration) -> std::io::Result<bool> {
        if !event::poll(timeout)? {
            return Ok(false);
        }

        match event::read()? {
            Event::Key(key) => Self::handle_key(app, key),
            Event::Mouse(mouse) => Self::handle_mouse(app, mouse),
            Event::Resize(_, _) => {} // ratatui handles this
            _ => {}
        }

        Ok(true)
    }

    fn handle_key(app: &mut App, key: KeyEvent) {
        // If filter input is active, route to text input
        if app.filter_active {
            match key.code {
                KeyCode::Esc => {
                    app.filter_active = false;
                    app.filter_text.clear();
                }
                KeyCode::Enter => {
                    app.filter_active = false;
                }
                KeyCode::Backspace => {
                    app.filter_text.pop();
                }
                KeyCode::Char(c) => {
                    app.filter_text.push(c);
                }
                _ => {}
            }
            return;
        }

        match key.code {
            // Quit
            KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.should_quit = true;
            }

            // Scrolling
            KeyCode::PageUp => {
                match app.active_tab {
                    Tab::Nodes => app.node_scroll = app.node_scroll.saturating_sub(10),
                    Tab::Paths => app.path_scroll = app.path_scroll.saturating_sub(10),
                    Tab::Logs => app.log_scroll = app.log_scroll.saturating_sub(10),
                    Tab::Trusts => app.trust_scroll = app.trust_scroll.saturating_sub(10),
                    Tab::Graph => {
                        // Graph tab has multiple scrollable areas, but we scroll Detail or Overview
                        app.detail_scroll = app.detail_scroll.saturating_sub(10);
                        app.overview_scroll = app.overview_scroll.saturating_sub(10);
                        app.acl_scroll = app.acl_scroll.saturating_sub(10);
                    }
                }
            }
            KeyCode::PageDown => match app.active_tab {
                Tab::Nodes => app.node_scroll = app.node_scroll.saturating_add(10),
                Tab::Paths => app.path_scroll = app.path_scroll.saturating_add(10),
                Tab::Logs => app.log_scroll = app.log_scroll.saturating_add(10),
                Tab::Trusts => app.trust_scroll = app.trust_scroll.saturating_add(10),
                Tab::Graph => {
                    app.detail_scroll = app.detail_scroll.saturating_add(10);
                    app.overview_scroll = app.overview_scroll.saturating_add(10);
                    app.acl_scroll = app.acl_scroll.saturating_add(10);
                }
            },

            // Tab navigation
            KeyCode::Tab => app.next_tab(),
            KeyCode::BackTab => app.prev_tab(),
            KeyCode::Char('1') => app.active_tab = Tab::Graph,
            KeyCode::Char('2') => app.active_tab = Tab::Nodes,
            KeyCode::Char('3') => app.active_tab = Tab::Paths,
            KeyCode::Char('4') => app.active_tab = Tab::Logs,
            KeyCode::Char('5') => app.active_tab = Tab::Trusts,

            // Graph navigation / Scrolling
            KeyCode::Left | KeyCode::Char('h') => {
                if app.active_tab == Tab::Graph {
                    app.pan(-5.0, 0.0);
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if app.active_tab == Tab::Graph {
                    app.pan(5.0, 0.0);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => match app.active_tab {
                Tab::Graph => {
                    app.pan(0.0, -5.0);
                    app.detail_scroll = app.detail_scroll.saturating_sub(1);
                    app.overview_scroll = app.overview_scroll.saturating_sub(1);
                    app.acl_scroll = app.acl_scroll.saturating_sub(1);
                }
                Tab::Nodes => app.node_scroll = app.node_scroll.saturating_sub(1),
                Tab::Paths => app.path_scroll = app.path_scroll.saturating_sub(1),
                Tab::Logs => app.log_scroll = app.log_scroll.saturating_sub(1),
                Tab::Trusts => app.trust_scroll = app.trust_scroll.saturating_sub(1),
            },
            KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
                Tab::Graph => {
                    app.pan(0.0, 5.0);
                    app.detail_scroll = app.detail_scroll.saturating_add(1);
                    app.overview_scroll = app.overview_scroll.saturating_add(1);
                    app.acl_scroll = app.acl_scroll.saturating_add(1);
                }
                Tab::Nodes => app.node_scroll = app.node_scroll.saturating_add(1),
                Tab::Paths => app.path_scroll = app.path_scroll.saturating_add(1),
                Tab::Logs => app.log_scroll = app.log_scroll.saturating_add(1),
                Tab::Trusts => app.trust_scroll = app.trust_scroll.saturating_add(1),
            },

            // Zoom
            KeyCode::Char('+') | KeyCode::Char('=') => app.zoom_in(),
            KeyCode::Char('-') => app.zoom_out(),
            KeyCode::Char('0') => {
                app.zoom = 1.0;
                app.camera_x = 0.0;
                app.camera_y = 0.0;
            }

            // Search
            KeyCode::Char('/') => {
                app.filter_active = true;
                app.filter_text.clear();
            }

            // Node selection
            KeyCode::Enter => {
                // Select node under cursor (handled by graph_view)
            }

            // Graph visibility toggles
            KeyCode::Char('u') | KeyCode::Char('U') => app.show_users = !app.show_users,
            KeyCode::Char('c') | KeyCode::Char('C') => app.show_computers = !app.show_computers,
            KeyCode::Char('g') | KeyCode::Char('G') => app.show_groups = !app.show_groups,
            KeyCode::Char('d') | KeyCode::Char('D') => app.show_domains = !app.show_domains,
            KeyCode::Char('p') | KeyCode::Char('P') => app.show_gpos = !app.show_gpos,
            KeyCode::Char('o') | KeyCode::Char('O') => {
                app.show_ous = !app.show_ous;
            }

            _ => {}
        }
    }

    fn handle_mouse(app: &mut App, mouse: crossterm::event::MouseEvent) {
        use crossterm::event::MouseEventKind;
        match mouse.kind {
            MouseEventKind::ScrollUp => app.zoom_in(),
            MouseEventKind::ScrollDown => app.zoom_out(),
            MouseEventKind::Drag(crossterm::event::MouseButton::Left) => {
                app.pan(mouse.column as f64 * 0.5, mouse.row as f64 * 0.5);
            }
            _ => {}
        }
    }
}
