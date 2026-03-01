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
use tracing::{info, warn};

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
    let domain_str = domain.to_string();
    let creds = credentials.clone();

    // Spawn crawler in background
    let crawler_handle = tokio::spawn(async move {
        info!("[tui] Starting crawler for {} in background", domain_str);
        
        // Build crawler config from credentials
        let crawler_config = overthrone_crawler::runner::CrawlerConfig {
            dc_ip: "".to_string(), // Would need to be passed in or resolved
            domain: domain_str.clone(),
            base_dn: format!("DC={}", domain_str.replace('.', ",DC=")),
            username: creds.username.clone(),
            password: match &creds.auth {
                crate::auth::AuthData::Password(p) => Some(p.clone()),
                _ => None,
            },
            nt_hash: match &creds.auth {
                crate::auth::AuthData::NtlmHash(h) => Some(h.clone()),
                _ => None,
            },
            trusted_dc_ips: Vec::new(),
            modules: Vec::new(),
            max_depth: 5,
            auto_pivot: false,
        };

        // Note: Full integration requires running reaper first to get ReaperResult
        // For now, we create a minimal ReaperResult for demonstration
        let reaper_data = overthrone_reaper::runner::ReaperResult {
            domain: domain_str.clone(),
            base_dn: crawler_config.base_dn.clone(),
            users: Vec::new(),
            groups: Vec::new(),
            computers: Vec::new(),
            ous: Vec::new(),
            gpos: Vec::new(),
            trusts: Vec::new(),
            spn_accounts: Vec::new(),
            delegations: Vec::new(),
            acl_findings: Vec::new(),
            laps_entries: Vec::new(),
            mssql_instances: Vec::new(),
            adcs_templates: Vec::new(),
        };

        // Run crawler analysis
        match overthrone_crawler::runner::run_crawler(&crawler_config, &reaper_data).await {
            Ok(crawler_result) => {
                info!("[tui] Crawler completed: {} findings", 
                    crawler_result.foreign_memberships.len() + 
                    crawler_result.escalation_paths.len() +
                    crawler_result.sid_filter_findings.len() +
                    crawler_result.mssql_chains.len() +
                    crawler_result.pam_findings.len()
                );
                
                // Update graph with crawler findings
                // This would integrate the crawler results into the attack graph
                let graph_lock = graph_clone.lock().unwrap();
                for path in &crawler_result.escalation_paths {
                    info!("[tui] Found escalation path: {:?}", path);
                    // Add nodes and edges to graph based on escalation paths
                    // graph_lock.add_node(...);
                    // graph_lock.add_edge(...);
                }
            }
            Err(e) => {
                warn!("[tui] Crawler error: {}", e);
            }
        }
        
        Ok::<(), OverthroneError>(())
    });

    // Run TUI on main thread (blocking)
    let _tui_result = tokio::task::spawn_blocking(move || run_tui(graph))
        .await
        .map_err(|e| OverthroneError::Internal(format!("TUI thread error: {e}")))??;

    // Wait for crawler to finish (or it gets cancelled when TUI exits)
    crawler_handle.abort();

    Ok(())
}
