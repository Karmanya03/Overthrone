//! Interactive shell implementation
//!
//! Provides persistent shell sessions via WinRM, SMB, and WMI.
//! Similar to evil-winrm but integrated into Overthrone.
//!
//! Each shell type delegates to its real executor:
//! - **WinRM**: `WinRmExecutor::execute()` (SOAP/WSMan on Linux, Win32 API on Windows)
//! - **SMB**: `smbexec::exec_command()` via a persistent `SmbSession`
//! - **WMI**: `wmiexec::exec_command()` via SCM fallback over SMB

use crate::error::{OverthroneError, Result};
use crate::exec::ExecCredentials;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, warn};

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

/// Shell connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellType {
    /// WinRM/PSRemoting shell
    Winrm,
    /// SMB-based shell (via psexec-style)
    Smb,
    /// WMI-based shell
    Wmi,
}

impl std::fmt::Display for ShellType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Winrm => write!(f, "WinRM"),
            Self::Smb => write!(f, "SMB"),
            Self::Wmi => write!(f, "WMI"),
        }
    }
}

/// Shell configuration
#[derive(Debug, Clone)]
pub struct ShellConfig {
    pub target: String,
    pub shell_type: ShellType,
    pub timeout: Duration,
    /// Credentials for authentication (required for real connections)
    pub credentials: Option<ExecCredentials>,
}

/// Backend state held once connected
enum ShellBackend {
    /// WinRM — stores credentials; each `execute` call delegates to `WinRmExecutor`
    Winrm {
        creds: ExecCredentials,
    },
    /// SMB — keeps a persistent `SmbSession` for command-per-service execution
    Smb {
        session: crate::proto::smb::SmbSession,
    },
    /// WMI — keeps a persistent `SmbSession` for SCM-fallback execution
    Wmi {
        session: crate::proto::smb::SmbSession,
    },
}

/// Interactive shell session
pub struct InteractiveShell {
    config: ShellConfig,
    session_id: String,
    last_output: String,
    command_count: u32,
    backend: Option<ShellBackend>,
}

/// Shell command result
#[derive(Debug, Clone)]
pub struct ShellResult {
    pub success: bool,
    pub output: String,
    pub exit_code: Option<i32>,
    pub execution_time_ms: u64,
}

// ═══════════════════════════════════════════════════════════
// Interactive Shell Implementation
// ═══════════════════════════════════════════════════════════

impl InteractiveShell {
    /// Connect to target and establish shell session
    pub async fn connect(config: ShellConfig) -> Result<Self> {
        info!(
            "Establishing {} shell session to {}",
            config.shell_type, config.target
        );

        // Validate target format
        if config.target.is_empty() {
            return Err(OverthroneError::Exec {
                target: "unknown".to_string(),
                reason: "Empty target specified".to_string(),
            });
        }

        // Attempt connection based on shell type
        let (session_id, backend) = match config.shell_type {
            ShellType::Winrm => Self::connect_winrm(&config).await?,
            ShellType::Smb => Self::connect_smb(&config).await?,
            ShellType::Wmi => Self::connect_wmi(&config).await?,
        };

        info!("Shell session established: {}", session_id);

        Ok(Self {
            config,
            session_id,
            last_output: String::new(),
            command_count: 0,
            backend: Some(backend),
        })
    }

    /// Execute command in shell session
    pub async fn execute(&mut self, command: &str) -> Result<String> {
        self.command_count += 1;
        let cmd_id = format!("cmd-{}", self.command_count);

        debug!(
            "Executing command {} in session {}: {}",
            cmd_id, self.session_id, command
        );

        let start = std::time::Instant::now();

        let result = match self.backend.as_ref() {
            Some(ShellBackend::Winrm { .. }) => self.execute_winrm(command).await,
            Some(ShellBackend::Smb { .. }) => self.execute_smb(command).await,
            Some(ShellBackend::Wmi { .. }) => self.execute_wmi(command).await,
            None => Err(OverthroneError::Exec {
                target: self.config.target.clone(),
                reason: "No backend connected".to_string(),
            }),
        };

        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok(output) => {
                self.last_output = output.clone();
                info!("Command {} completed in {}ms", cmd_id, elapsed);
                Ok(output)
            }
            Err(e) => {
                error!("Command {} failed: {}", cmd_id, e);
                Err(e)
            }
        }
    }

    /// Get session information
    pub fn session_info(&self) -> ShellSessionInfo {
        ShellSessionInfo {
            session_id: self.session_id.clone(),
            target: self.config.target.clone(),
            shell_type: self.config.shell_type,
            command_count: self.command_count,
        }
    }

    /// Close shell session
    pub async fn close(self) -> Result<()> {
        info!("Closing shell session {}", self.session_id);

        match self.config.shell_type {
            ShellType::Winrm => self.close_winrm().await,
            ShellType::Smb => self.close_smb().await,
            ShellType::Wmi => self.close_wmi().await,
        }
    }

    // ═══════════════════════════════════════════════════════
    // Credential helper
    // ═══════════════════════════════════════════════════════

    fn require_creds(config: &ShellConfig) -> Result<&ExecCredentials> {
        config.credentials.as_ref().ok_or_else(|| OverthroneError::Exec {
            target: config.target.clone(),
            reason: "Credentials required for connection".to_string(),
        })
    }

    // ═══════════════════════════════════════════════════════
    // WinRM Implementation — delegates to WinRmExecutor
    // ═══════════════════════════════════════════════════════

    async fn connect_winrm(config: &ShellConfig) -> Result<(String, ShellBackend)> {
        debug!("Connecting to WinRM endpoint on {}", config.target);

        let creds = Self::require_creds(config)?.clone();

        // Verify WinRM is accessible (port check)
        Self::check_winrm_access(config).await?;

        // Probe with a lightweight command to confirm auth works
        let executor = crate::exec::winrm::WinRmExecutor::new(creds.clone());
        let probe = <crate::exec::winrm::WinRmExecutor as crate::exec::RemoteExecutor>::execute(
            &executor,
            &config.target,
            "hostname",
        )
        .await;

        match probe {
            Ok(out) => debug!("WinRM probe OK: {}", out.stdout.trim()),
            Err(e) => {
                warn!("WinRM probe failed ({}), continuing anyway", e);
            }
        }

        let session_id = format!("winrm-{:08x}", rand::random::<u32>());
        Ok((session_id, ShellBackend::Winrm { creds }))
    }

    async fn check_winrm_access(config: &ShellConfig) -> Result<()> {
        let winrm_port = 5985;
        let winrm_ssl_port = 5986;
        let timeout = Duration::from_secs(5);

        let addr = format!("{}:{}", config.target, winrm_port);
        if let Ok(Ok(_)) = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
            debug!("WinRM HTTP port (5985) is accessible");
            return Ok(());
        }

        let addr_ssl = format!("{}:{}", config.target, winrm_ssl_port);
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr_ssl)).await {
            Ok(Ok(_)) => {
                debug!("WinRM HTTPS port (5986) is accessible");
                Ok(())
            }
            _ => Err(OverthroneError::Exec {
                target: config.target.clone(),
                reason: "WinRM ports (5985/5986) not accessible".to_string(),
            }),
        }
    }

    async fn execute_winrm(&self, command: &str) -> Result<String> {
        let creds = match &self.backend {
            Some(ShellBackend::Winrm { creds }) => creds.clone(),
            _ => unreachable!(),
        };

        debug!("Executing via WinRM: {}", command);

        let executor = crate::exec::winrm::WinRmExecutor::new(creds);
        let output = <crate::exec::winrm::WinRmExecutor as crate::exec::RemoteExecutor>::execute(
            &executor,
            &self.config.target,
            command,
        )
        .await?;

        let mut result = output.stdout;
        if !output.stderr.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&output.stderr);
        }
        Ok(result)
    }

    async fn close_winrm(&self) -> Result<()> {
        debug!("Closing WinRM session {}", self.session_id);
        // WinRM is stateless per-command; nothing to tear down
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // SMB Implementation — persistent SmbSession + smbexec
    // ═══════════════════════════════════════════════════════

    async fn connect_smb(config: &ShellConfig) -> Result<(String, ShellBackend)> {
        debug!("Connecting via SMB to {}", config.target);

        let creds = Self::require_creds(config)?;

        let session = crate::proto::smb::SmbSession::connect(
            &config.target,
            &creds.domain,
            &creds.username,
            &creds.password,
        )
        .await?;

        // Verify admin share access
        if !session.check_share_read("C$").await && !session.check_share_read("ADMIN$").await {
            warn!("SMB: Connected but no admin share access — commands may fail");
        }

        let session_id = format!("smb-{:08x}", rand::random::<u32>());
        Ok((session_id, ShellBackend::Smb { session }))
    }

    async fn execute_smb(&self, command: &str) -> Result<String> {
        let session = match &self.backend {
            Some(ShellBackend::Smb { session }) => session,
            _ => unreachable!(),
        };

        debug!("Executing via SMB: {}", command);

        let result = crate::exec::smbexec::exec_command(session, command).await?;
        Ok(result.output)
    }

    async fn close_smb(&self) -> Result<()> {
        debug!("Closing SMB session {}", self.session_id);
        // SmbSession is dropped when InteractiveShell is dropped.
        // Any cleanup on the service side was already done per-command in smbexec.
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // WMI Implementation — persistent SmbSession + wmiexec
    // ═══════════════════════════════════════════════════════

    async fn connect_wmi(config: &ShellConfig) -> Result<(String, ShellBackend)> {
        debug!("Connecting via WMI to {}", config.target);

        let creds = Self::require_creds(config)?;

        let session = crate::proto::smb::SmbSession::connect(
            &config.target,
            &creds.domain,
            &creds.username,
            &creds.password,
        )
        .await?;

        if !session.check_share_read("C$").await && !session.check_share_read("ADMIN$").await {
            warn!("WMI: Connected but no admin share access — commands may fail");
        }

        let session_id = format!("wmi-{:08x}", rand::random::<u32>());
        Ok((session_id, ShellBackend::Wmi { session }))
    }

    async fn execute_wmi(&self, command: &str) -> Result<String> {
        let session = match &self.backend {
            Some(ShellBackend::Wmi { session }) => session,
            _ => unreachable!(),
        };

        debug!("Executing via WMI: {}", command);

        let result = crate::exec::wmiexec::exec_command(session, command).await?;
        Ok(result.output)
    }

    async fn close_wmi(&self) -> Result<()> {
        debug!("Closing WMI session {}", self.session_id);
        Ok(())
    }
}

/// Shell session information
#[derive(Debug, Clone)]
pub struct ShellSessionInfo {
    pub session_id: String,
    pub target: String,
    pub shell_type: ShellType,
    pub command_count: u32,
}

// ═══════════════════════════════════════════════════════════
// Shell Pool for Multiple Sessions
// ═══════════════════════════════════════════════════════════

/// Manages multiple shell sessions
pub struct ShellPool {
    sessions: HashMap<String, InteractiveShell>,
    max_sessions: usize,
}

impl ShellPool {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Add a new session to the pool
    pub async fn add_session(&mut self, shell: InteractiveShell) -> Result<String> {
        if self.sessions.len() >= self.max_sessions {
            return Err(OverthroneError::Exec {
                target: "pool".to_string(),
                reason: format!("Maximum sessions ({}) reached", self.max_sessions),
            });
        }

        let session_id = shell.session_id.clone();
        self.sessions.insert(session_id.clone(), shell);

        Ok(session_id)
    }

    /// Get a mutable reference to a session
    pub fn get_session(&mut self, session_id: &str) -> Option<&mut InteractiveShell> {
        self.sessions.get_mut(session_id)
    }

    /// Remove and close a session
    pub async fn remove_session(&mut self, session_id: &str) -> Result<()> {
        if let Some(shell) = self.sessions.remove(session_id) {
            shell.close().await?;
        }
        Ok(())
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<ShellSessionInfo> {
        self.sessions.values().map(|s| s.session_info()).collect()
    }

    /// Close all sessions
    pub async fn close_all(mut self) {
        for (id, shell) in self.sessions.drain() {
            if let Err(e) = shell.close().await {
                warn!("Error closing session {}: {}", id, e);
            }
        }
    }
}

use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shell_config() {
        let config = ShellConfig {
            target: "dc01.corp.local".to_string(),
            shell_type: ShellType::Winrm,
            timeout: Duration::from_secs(30),
            credentials: None,
        };

        assert_eq!(config.target, "dc01.corp.local");
        assert_eq!(config.shell_type, ShellType::Winrm);
    }

    #[test]
    fn test_shell_type_display() {
        assert_eq!(format!("{}", ShellType::Winrm), "WinRM");
        assert_eq!(format!("{}", ShellType::Smb), "SMB");
        assert_eq!(format!("{}", ShellType::Wmi), "WMI");
    }

    #[tokio::test]
    async fn test_shell_pool() {
        let mut pool = ShellPool::new(5);
        assert!(pool.sessions.is_empty());

        // Create a shell (no backend — unit-test only)
        let shell = InteractiveShell {
            config: ShellConfig {
                target: "test".to_string(),
                shell_type: ShellType::Winrm,
                timeout: Duration::from_secs(30),
                credentials: None,
            },
            session_id: "test-123".to_string(),
            last_output: String::new(),
            command_count: 0,
            backend: None,
        };

        let id = pool.add_session(shell).await.unwrap();
        assert_eq!(id, "test-123");
        assert_eq!(pool.sessions.len(), 1);

        let sessions = pool.list_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].target, "test");
    }
}
