//! BloodHound-style graph viewer for Overthrone.
//!
//! Launches a local HTTP server that serves an interactive graph visualization
//! in the browser. No Neo4j, no Python, no JVM — pure Rust.

mod graph_data;

/// Interactive graph visualization server module.
pub mod server;

/// TLS configuration for HTTPS serving.
pub use server::TlsConfig;
/// Server configuration (auth, rate limiting, TLS).
pub use server::ViewerConfig;
/// Launch the graph viewer server on the default address.
pub use server::launch;
/// Launch the graph viewer server with custom configuration.
pub use server::launch_with_config;
