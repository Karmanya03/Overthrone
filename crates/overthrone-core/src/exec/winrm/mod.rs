//! WinRM (WS-Management) remote execution.
//!
//! - **Windows**: Native Win32 API (WSMan*)
//! - **Linux/macOS**: Pure Rust WS-Man over HTTP with NTLM via ntlmclient

#[cfg(windows)]
mod windows;
#[cfg(not(windows))]
mod wsman;

#[cfg(windows)]
pub use windows::WinRmExecutor;
#[cfg(not(windows))]
pub use wsman::WinRmExecutor;
