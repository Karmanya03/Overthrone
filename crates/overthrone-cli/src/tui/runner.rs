//! TUI runner — initializes terminal, spawns crawler, runs render loop

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use overthrone_core::graph::AttackGraph;
use overthrone_core::{OverthroneError, Result};
use ratatui::backend::CrosstermBackend;
use ratatui::prelude::*;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

use super::app::App;
use super::event::EventLoop;
use super::ui;

/// Target frame rate
const FPS: u64 = 30;

/// Launch the interactive TUI
///
/// `graph` is a shared reference to the attack graph being populated
/// by the crawler in a background thread.
pub fn run_tui(graph: Arc<Mutex<AttackGraph>>) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(graph);

    app.push_log(
        super::app::LogLevel::Info,
        "tui",
        "Overthrone TUI started. Waiting for crawler data...",
    );

    // Main loop
    let tick_rate = Duration::from_millis(1000 / FPS);
    let mut last_tick = Instant::now();

    loop {
        // Draw
        terminal.draw(|f| {
            ui::draw(f, &app);
        })?;

        // Handle events
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        EventLoop::poll(&mut app, timeout)?;

        if app.should_quit {
            break;
        }

        // Tick: update layout + stats
        if last_tick.elapsed() >= tick_rate {
            app.update_layout();
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

/// Launch TUI alongside an async crawler task
///
/// This spawns the crawler on a tokio task and runs the TUI on the main thread.
pub async fn run_tui_with_crawler(
    graph: Arc<Mutex<AttackGraph>>,
    domain: &str,
    credentials: &crate::auth::Credentials,
) -> Result<()> {
    let graph_clone = Arc::clone(&graph);
    let domain = domain.to_string();
    let _creds = credentials.clone();

    // Spawn crawler in background (simplified - actual crawler integration would go here)
    let _crawler_handle = tokio::spawn(async move {
        info!("[tui] Starting crawler for {} in background", domain);
        // TODO: Integrate actual crawler when available
        // let mut crawler = overthrone_crawler::CrawlerRunner::new(&domain, &creds, graph_clone);
        // crawler.run_full().await
        Ok::<(), OverthroneError>(())
    });

    // Run TUI on main thread (blocking)
    let _tui_result = tokio::task::spawn_blocking(move || run_tui(graph))
        .await
        .map_err(|e| OverthroneError::Internal(format!("TUI thread error: {e}")))??;

    // Wait for crawler to finish (or it gets cancelled when TUI exits)
    // crawler_handle.abort();

    Ok(())
}
