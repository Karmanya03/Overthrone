//! WinRM (WS-Management) remote execution.
//!
//! - **Windows**: Native Win32 API (WSMan*)
//! - **Linux/macOS**: Pure Rust WS-Man over HTTP with NTLM via ntlmclient

#[cfg(windows)]
#[path = "windows.rs"]
mod win;
#[cfg(not(windows))]
mod wsman;

#[cfg(windows)]
pub use win::WinRmExecutor;
#[cfg(not(windows))]
pub use wsman::WinRmExecutor;
