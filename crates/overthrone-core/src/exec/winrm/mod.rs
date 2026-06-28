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

use crate::error::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Probe whether a WinRM listener is alive on the target.
/// Sends a minimal HTTP GET to port 5985 and checks for a WinRM-like response
/// (expects HTTP 401 with WWW-Authenticate header).
pub async fn probe_winrm(target: &str) -> Result<String> {
    let addr = format!("{target}:5985");
    let mut stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => return Ok(format!("WinRM HTTP unreachable: {e}")),
    };

    let request =
        format!("GET /wsman HTTP/1.1\r\nHost: {target}:5985\r\nConnection: close\r\n\r\n");
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        return Ok(format!("WinRM send failed: {e}"));
    }

    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp.contains("401") || resp.contains("WWW-Authenticate") {
                Ok("WinRM HTTP — responsive (401 with auth challenge)".to_string())
            } else if resp.contains("200") || resp.contains("Microsoft-HTTPAPI") {
                Ok("WinRM HTTP — responsive".to_string())
            } else {
                Ok(format!(
                    "WinRM HTTP — unexpected response: {}",
                    resp.lines().next().unwrap_or("(empty)")
                ))
            }
        }
        Ok(Ok(_)) => Ok("WinRM HTTP — empty response".to_string()),
        Ok(Err(e)) => Ok(format!("WinRM read error: {e}")),
        Err(_) => Ok("WinRM HTTP — timeout (no response)".to_string()),
    }
}
