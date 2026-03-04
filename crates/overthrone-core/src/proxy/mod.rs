//! Network proxying & pivoting module.
//!
//! Provides:
//! - **SOCKS5 proxy server** for tunneling tools through compromised hosts
//! - **TCP port forwarding** (local ↔ remote) for lateral movement
//!
//! Both implementations are fully async (tokio) and support multiple
//! concurrent connections.

pub mod portfwd;
pub mod socks5;

pub use portfwd::{PortForward, PortForwardConfig};
pub use socks5::{Socks5Config, Socks5Server};
