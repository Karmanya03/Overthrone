#![allow(unused, dead_code)] // Suppress warnings during development

pub mod adcs;
pub mod c2; // ← Export C2 module
pub mod config;
pub mod crypto;
pub mod error;
pub mod exec; // ← This now points to exec/mod.rs (which has all types)
pub mod graph;
pub mod mssql;
pub mod output;
pub mod plugin; // ← NEW: wire in the plugin module
pub mod proto;
pub mod scan;
pub mod sccm;
pub mod types;

// Re-export commonly used items
pub use config::{AuthConfig, OutputFormat, OverthroneConfig};
pub use error::{OverthroneError, Result};
