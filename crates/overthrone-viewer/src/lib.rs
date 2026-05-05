//! BloodHound-style graph viewer for Overthrone.
//!
//! Launches a local HTTP server that serves an interactive graph visualization
//! in the browser. No Neo4j, no Python, no JVM — pure Rust.

pub mod server;

pub use server::launch;