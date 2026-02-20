//! Remote command execution module.
//!
//! Provides multiple lateral movement execution methods:
//! - PSExec-style (SMB service creation)
//! - SmbExec (command-only, no binary drop)
//! - WinRM (WS-Management via native Win32 API or pure Rust)
//! - WMI (Win32_Process Create, with SCM fallback)
//! - AtExec (Scheduled Tasks via ATSVC)
//!
//! Each method implements the `RemoteExecutor` trait for a unified interface.
//! All methods are cross-platform (Linux/macOS/Windows).

pub mod atexec;
pub mod psexec;
pub mod smbexec;
pub mod winrm;
pub mod wmiexec;

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Output from a remote command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub method: ExecMethod,
}

/// Which execution method was used
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecMethod {
    PsExec,
    SmbExec,
    WinRM,
    WmiExec,
    AtExec,
}

impl std::fmt::Display for ExecMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PsExec  => write!(f, "PSExec"),
            Self::SmbExec => write!(f, "SMBExec"),
            Self::WinRM   => write!(f, "WinRM"),
            Self::WmiExec => write!(f, "WMIExec"),
            Self::AtExec  => write!(f, "AtExec"),
        }
    }
}

/// Credentials for remote execution
#[derive(Debug, Clone)]
pub struct ExecCredentials {
    pub domain: String,
    pub username: String,
    pub password: String,
    /// Optional: NTLM hash for pass-the-hash (hex string)
    pub nt_hash: Option<String>,
}

/// Unified trait for all remote execution methods
#[async_trait]
pub trait RemoteExecutor: Send + Sync {
    /// The execution method this executor uses
    fn method(&self) -> ExecMethod;

    /// Execute a single command on the remote target
    async fn execute(&self, target: &str, command: &str) -> Result<ExecOutput>;

    /// Execute a PowerShell command (base64-encoded for transport)
    async fn execute_powershell(&self, target: &str, script: &str) -> Result<ExecOutput> {
        let encoded = base64_encode_ps(script);
        let cmd = format!("powershell.exe -NoP -NonI -Enc {encoded}");
        self.execute(target, &cmd).await
    }

    /// Check if this execution method is available against the target
    async fn check_available(&self, target: &str) -> bool;

    /// Clean up any artifacts left on the target
    async fn cleanup(&self, target: &str) -> Result<()> {
        Ok(()) // default: no cleanup needed
    }
}

/// Base64-encode a PowerShell script for -EncodedCommand
fn base64_encode_ps(script: &str) -> String {
    use base64::Engine;
    // PowerShell expects UTF-16LE encoded base64
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

/// Try all available execution methods in order of stealth
/// 
/// Order: WinRM → AtExec → SmbExec → PSExec → WMI (most reliable/stealthy first)
pub async fn auto_exec(
    target: &str,
    command: &str,
    creds: &ExecCredentials,
) -> Result<ExecOutput> {
    use tracing::info;

    // Order: WinRM → AtExec → SmbExec → PsExec → WMI (most reliable first)
    let executors: Vec<Box<dyn RemoteExecutor>> = vec![
        Box::new(winrm::WinRmExecutor::new(creds.clone())),
        Box::new(atexec::AtExecutor::new(creds.clone())),
        Box::new(smbexec::SmbExecutor::new(creds.clone())),
        Box::new(psexec::PsExecutor::new(creds.clone())),
        Box::new(wmiexec::WmiExecutor::new(creds.clone())),
    ];

    for executor in &executors {
        if executor.check_available(target).await {
            info!("exec: Using {} for {target}", executor.method());
            return executor.execute(target, command).await;
        }
    }

    Err(crate::error::OverthroneError::Exec(format!(
        "No execution method available for {target}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_powershell() {
        let script = "Write-Host 'test'";
        let encoded = base64_encode_ps(script);
        
        // Should be base64 of UTF-16LE
        assert!(encoded.len() > script.len());
        assert!(base64::engine::general_purpose::STANDARD.decode(&encoded).is_ok());
    }

    #[test]
    fn test_exec_method_display() {
        assert_eq!(ExecMethod::PsExec.to_string(), "PSExec");
        assert_eq!(ExecMethod::WinRM.to_string(), "WinRM");
        assert_eq!(ExecMethod::WmiExec.to_string(), "WMIExec");
        assert_eq!(ExecMethod::SmbExec.to_string(), "SMBExec");
    }
}
