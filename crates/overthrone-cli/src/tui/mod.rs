//! Interactive TUI with live attack graph visualization
//!
//! Renders the Overthrone attack graph in real-time as the crawler
//! discovers nodes (users, computers, groups) and edges (attack paths).
//! Also provides the TUI Wizard for interactive module selection.

pub mod app;
pub mod event;
pub mod graph_view;
pub mod runner;
pub mod ui;
pub mod wizard_app;
pub mod wizard_runner;
