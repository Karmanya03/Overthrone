//! Interactive TUI with live attack graph visualization
//!
//! Renders the Overthrone attack graph in real-time as the crawler
//! discovers nodes (users, computers, groups) and edges (attack paths).

pub mod app;
pub mod event;
pub mod graph_view;
pub mod runner;
pub mod ui;
