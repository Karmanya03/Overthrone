use crate::tui::app::App;
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

            // Tab navigation
            KeyCode::Tab => app.next_tab(),
            KeyCode::BackTab => app.prev_tab(),
            KeyCode::Char('1') => app.active_tab = super::app::Tab::Graph,
            KeyCode::Char('2') => app.active_tab = super::app::Tab::Nodes,
            KeyCode::Char('3') => app.active_tab = super::app::Tab::Paths,
            KeyCode::Char('4') => app.active_tab = super::app::Tab::Logs,
            KeyCode::Char('5') => app.active_tab = super::app::Tab::Trusts,

            // Graph navigation
            KeyCode::Left | KeyCode::Char('h') => app.pan(-5.0, 0.0),
            KeyCode::Right | KeyCode::Char('l') => app.pan(5.0, 0.0),
            KeyCode::Up | KeyCode::Char('k') => app.pan(0.0, -5.0),
            KeyCode::Down | KeyCode::Char('j') => app.pan(0.0, 5.0),

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
