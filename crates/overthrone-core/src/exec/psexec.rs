//! PSExec-style remote execution via SCM (Service Control Manager).
//!
//! Flow: Deploy binary → Create service → Start service → Read output → Cleanup.
//! Uses SMB named pipe `\pipe\svcctl` for DCE/RPC to the SCM.

use crate::error::{OverthroneError, Result};
use crate::proto::smb::SmbSession;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  DCE/RPC Constants for SVCCTL
// ═══════════════════════════════════════════════════════════

const SVCCTL_PIPE: &str = "svcctl";

/// DCE/RPC bind packet header (v5.0, little-endian)
const DCERPC_VERSION: u8 = 5;
const DCERPC_VERSION_MINOR: u8 = 0;

/// Packet types
const DCERPC_BIND: u8 = 11;
const DCERPC_REQUEST: u8 = 0;

/// SVCCTL operation numbers
const OP_OPEN_SC_MANAGER_W: u16 = 15;
const OP_CREATE_SERVICE_W: u16 = 12;
const OP_START_SERVICE_W: u16 = 19;
const OP_DELETE_SERVICE: u16 = 2;
const OP_CLOSE_SERVICE_HANDLE: u16 = 0;
#[allow(dead_code)] // SVCCTL opcode kept for protocol completeness
const OP_OPEN_SERVICE_W: u16 = 16;

/// SVCCTL interface UUID: 367ABB81-9844-35F1-AD32-98F038001003
const SVCCTL_UUID: [u8; 16] = [
    0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35, 0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03,
];
const SVCCTL_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x00]; // v2.0

/// NDR transfer syntax UUID
const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
const NDR_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

/// Service type: Win32 own process
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;
/// Start type: demand start
const SERVICE_DEMAND_START: u32 = 0x00000003;
/// Error control: ignore
const SERVICE_ERROR_IGNORE: u32 = 0x00000000;
/// Desired access: full
const SC_MANAGER_ALL_ACCESS: u32 = 0x000F003F;
const SERVICE_ALL_ACCESS: u32 = 0x000F01FF;

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// Configuration for a PSExec-style execution
pub struct PsExecConfig {
    /// Service name to create on the target
    pub service_name: String,
    /// Display name for the service
    pub display_name: String,
    /// Command to execute (becomes the service binary path)
    pub command: String,
    /// Whether to delete the service after execution
    pub cleanup: bool,
}

impl Default for PsExecConfig {
    fn default() -> Self {
        let id = rand::random::<u16>();
        PsExecConfig {
            service_name: format!("OvThr{:04X}", id),
            display_name: format!("OvThr{:04X}", id),
            command: String::new(),
            cleanup: true,
        }
    }
}

/// Result of a PSExec operation
#[derive(Debug)]
pub struct PsExecResult {
    pub target: String,
    pub service_name: String,
    pub command: String,
    pub success: bool,
    pub output: Option<String>,
}

// ═══════════════════════════════════════════════════════════
//  DCE/RPC Packet Builders
// ═══════════════════════════════════════════════════════════

/// Build a DCE/RPC bind request for SVCCTL
fn build_bind_packet() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(72);

    // Header
    pkt.push(DCERPC_VERSION); // version
    pkt.push(DCERPC_VERSION_MINOR); // minor version
    pkt.push(DCERPC_BIND); // packet type
    pkt.push(0x03); // flags: first + last frag
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation (LE)
    // frag_length placeholder (offset 8-9) - fill later
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

    // Abstract syntax: SVCCTL
    pkt.extend_from_slice(&SVCCTL_UUID);
    pkt.extend_from_slice(&SVCCTL_VERSION);

    // Transfer syntax: NDR
    pkt.extend_from_slice(&NDR_UUID);
    pkt.extend_from_slice(&NDR_VERSION);

    // Fix frag length
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;

    pkt
}

/// Build a DCE/RPC request packet with given opnum and stub data
fn build_request_packet(opnum: u16, stub: &[u8], call_id: u32) -> Vec<u8> {
    let header_len = 24u16;
    let frag_len = header_len + stub.len() as u16;

    let mut pkt = Vec::with_capacity(frag_len as usize);

    // Header
    pkt.push(DCERPC_VERSION);
    pkt.push(DCERPC_VERSION_MINOR);
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

/// Build OpenSCManagerW stub
fn build_open_scmanager_stub(target: &str) -> Vec<u8> {
    let mut stub = Vec::new();

    // lpMachineName (pointer + string)
    stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent id
    stub.extend_from_slice(&ndr_string(&format!("\\\\{}", target)));

    // lpDatabaseName (null pointer)
    stub.extend_from_slice(&0u32.to_le_bytes());

    // dwDesiredAccess
    stub.extend_from_slice(&SC_MANAGER_ALL_ACCESS.to_le_bytes());

    stub
}

/// Build CreateServiceW stub
fn build_create_service_stub(
    scm_handle: &[u8; 20],
    service_name: &str,
    display_name: &str,
    binary_path: &str,
) -> Vec<u8> {
    let mut stub = Vec::new();

    // hSCManager (20-byte policy handle)
    stub.extend_from_slice(scm_handle);

    // lpServiceName
    stub.extend_from_slice(&ndr_string(service_name));

    // lpDisplayName (pointer + string)
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&ndr_string(display_name));

    // dwDesiredAccess
    stub.extend_from_slice(&SERVICE_ALL_ACCESS.to_le_bytes());

    // dwServiceType
    stub.extend_from_slice(&SERVICE_WIN32_OWN_PROCESS.to_le_bytes());

    // dwStartType
    stub.extend_from_slice(&SERVICE_DEMAND_START.to_le_bytes());

    // dwErrorControl
    stub.extend_from_slice(&SERVICE_ERROR_IGNORE.to_le_bytes());

    // lpBinaryPathName
    stub.extend_from_slice(&ndr_string(binary_path));

    // lpLoadOrderGroup (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // lpdwTagId (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // lpDependencies (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // cbBufSize (0)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // lpServiceStartName (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // lpPassword (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // cbPasswordSize (0)
    stub.extend_from_slice(&0u32.to_le_bytes());

    stub
}

/// Build StartServiceW stub
fn build_start_service_stub(service_handle: &[u8; 20]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(service_handle);
    stub.extend_from_slice(&0u32.to_le_bytes()); // argc
    stub.extend_from_slice(&0u32.to_le_bytes()); // argv (null)
    stub
}

/// Build DeleteService stub
fn build_delete_service_stub(service_handle: &[u8; 20]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(service_handle);
    stub
}

/// Build CloseServiceHandle stub
fn build_close_handle_stub(handle: &[u8; 20]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(handle);
    stub
}

/// Extract a 20-byte handle from a DCE/RPC response stub
fn extract_handle(response: &[u8]) -> Result<[u8; 20]> {
    // Response stub starts at offset 24 (after DCE/RPC header)
    let stub_offset = 24;
    if response.len() < stub_offset + 24 {
        return Err(OverthroneError::Smb(
            "DCE/RPC response too short for handle extraction".into(),
        ));
    }

    let mut handle = [0u8; 20];
    handle.copy_from_slice(&response[stub_offset..stub_offset + 20]);

    // Check return code (last 4 bytes of stub)
    let rc_offset = response.len() - 4;
    let rc = u32::from_le_bytes([
        response[rc_offset],
        response[rc_offset + 1],
        response[rc_offset + 2],
        response[rc_offset + 3],
    ]);

    if rc != 0 {
        return Err(OverthroneError::Smb(format!(
            "SCM operation failed with NTSTATUS 0x{:08X}",
            rc
        )));
    }

    Ok(handle)
}

// ═══════════════════════════════════════════════════════════
//  PSExec Execution
// ═══════════════════════════════════════════════════════════

/// Execute a command on a remote host using PSExec-style SCM service creation.
///
/// Requires local admin access (C$ or ADMIN$ share writable).
pub async fn execute(session: &SmbSession, config: &PsExecConfig) -> Result<PsExecResult> {
    info!(
        "PSExec: Executing on {} as service '{}'",
        session.target, config.service_name
    );

    let mut scm_handle: Option<[u8; 20]> = None;
    let mut svc_handle: Option<[u8; 20]> = None;

    let result = execute_inner(session, config, &mut scm_handle, &mut svc_handle).await;

    // Always attempt cleanup
    if config.cleanup {
        cleanup(session, &scm_handle, &svc_handle).await;
    }

    result
}

async fn execute_inner(
    session: &SmbSession,
    config: &PsExecConfig,
    scm_handle: &mut Option<[u8; 20]>,
    svc_handle: &mut Option<[u8; 20]>,
) -> Result<PsExecResult> {
    // Step 1: Bind to SVCCTL
    info!("PSExec: Binding to SVCCTL pipe");
    let bind_pkt = build_bind_packet();
    let bind_resp = session.pipe_transact(SVCCTL_PIPE, &bind_pkt).await?;
    debug!("PSExec: Bind response: {} bytes", bind_resp.len());

    // Step 2: OpenSCManagerW
    info!("PSExec: Opening SCM on {}", session.target);
    let open_stub = build_open_scmanager_stub(&session.target);
    let open_pkt = build_request_packet(OP_OPEN_SC_MANAGER_W, &open_stub, 1);
    let open_resp = session.pipe_transact(SVCCTL_PIPE, &open_pkt).await?;
    let scm = extract_handle(&open_resp)?;
    *scm_handle = Some(scm);
    info!("PSExec: SCM handle acquired");

    // Step 3: CreateServiceW
    info!("PSExec: Creating service '{}'", config.service_name);
    let create_stub = build_create_service_stub(
        &scm,
        &config.service_name,
        &config.display_name,
        &config.command,
    );
    let create_pkt = build_request_packet(OP_CREATE_SERVICE_W, &create_stub, 2);
    let create_resp = session.pipe_transact(SVCCTL_PIPE, &create_pkt).await?;
    let svc = extract_handle(&create_resp)?;
    *svc_handle = Some(svc);
    info!("PSExec: Service '{}' created", config.service_name);

    // Step 4: StartServiceW
    info!("PSExec: Starting service '{}'", config.service_name);
    let start_stub = build_start_service_stub(&svc);
    let start_pkt = build_request_packet(OP_START_SERVICE_W, &start_stub, 3);
    let start_resp = session.pipe_transact(SVCCTL_PIPE, &start_pkt).await?;

    // Check if start succeeded (return code at end of stub)
    let started = if start_resp.len() >= 28 {
        let rc = u32::from_le_bytes([
            start_resp[start_resp.len() - 4],
            start_resp[start_resp.len() - 3],
            start_resp[start_resp.len() - 2],
            start_resp[start_resp.len() - 1],
        ]);
        // 0 = success, 0x420 = ERROR_SERVICE_ALREADY_RUNNING
        rc == 0 || rc == 0x420
    } else {
        false
    };

    if started {
        info!(
            "PSExec: Service '{}' started successfully",
            config.service_name
        );
    } else {
        warn!("PSExec: Service start may have failed");
    }

    // Step 5: Try to read output (if command redirected output to a file)
    let output = try_read_output(session, &config.service_name).await;

    Ok(PsExecResult {
        target: session.target.clone(),
        service_name: config.service_name.clone(),
        command: config.command.clone(),
        success: started,
        output,
    })
}

/// Attempt to read command output from a well-known output file
async fn try_read_output(session: &SmbSession, service_name: &str) -> Option<String> {
    let output_file = format!("Windows\\Temp\\{}.out", service_name);

    // Small delay for command to complete
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Try reading from C$ or ADMIN$
    for share in &["C$", "ADMIN$"] {
        let path = if *share == "ADMIN$" {
            format!("Temp\\{}.out", service_name)
        } else {
            output_file.clone()
        };

        if let Ok(data) = session.read_file(share, &path).await {
            // Cleanup output file
            let _ = session.delete_file(share, &path).await;
            return Some(String::from_utf8_lossy(&data).to_string());
        }
    }

    None
}

/// Cleanup: delete service and close handles
async fn cleanup(
    session: &SmbSession,
    scm_handle: &Option<[u8; 20]>,
    svc_handle: &Option<[u8; 20]>,
) {
    // Delete the service
    if let Some(svc) = svc_handle {
        let del_stub = build_delete_service_stub(svc);
        let del_pkt = build_request_packet(OP_DELETE_SERVICE, &del_stub, 10);
        match session.pipe_transact(SVCCTL_PIPE, &del_pkt).await {
            Ok(_) => info!("PSExec: Service deleted"),
            Err(e) => warn!("PSExec: Failed to delete service: {e}"),
        }

        // Close service handle
        let close_stub = build_close_handle_stub(svc);
        let close_pkt = build_request_packet(OP_CLOSE_SERVICE_HANDLE, &close_stub, 11);
        let _ = session.pipe_transact(SVCCTL_PIPE, &close_pkt).await;
    }

    // Close SCM handle
    if let Some(scm) = scm_handle {
        let close_stub = build_close_handle_stub(scm);
        let close_pkt = build_request_packet(OP_CLOSE_SERVICE_HANDLE, &close_stub, 12);
        let _ = session.pipe_transact(SVCCTL_PIPE, &close_pkt).await;
    }
}

/// Convenience: execute a single command via PSExec
pub async fn exec_command(session: &SmbSession, command: &str) -> Result<PsExecResult> {
    let mut config = PsExecConfig::default();
    // Wrap command so output is captured to a file
    config.command = format!(
        "cmd.exe /C {} > C:\\Windows\\Temp\\{}.out 2>&1",
        command, config.service_name
    );
    execute(session, &config).await
}

// ═══════════════════════════════════════════════════════════
//  Executor Implementation
// ═══════════════════════════════════════════════════════════

pub struct PsExecutor {
    creds: super::ExecCredentials,
}

impl PsExecutor {
    pub fn new(creds: super::ExecCredentials) -> Self {
        Self { creds }
    }
}

#[async_trait::async_trait]
impl super::RemoteExecutor for PsExecutor {
    fn method(&self) -> super::ExecMethod {
        super::ExecMethod::PsExec
    }

    async fn execute(
        &self,
        target: &str,
        command: &str,
    ) -> crate::error::Result<super::ExecOutput> {
        info!("PsExecutor: Executing command on {}", target);

        // Create SMB session
        let session = SmbSession::connect(
            target,
            &self.creds.username,
            &self.creds.password,
            &self.creds.domain,
        )
        .await?;

        // Execute via PSExec
        let result = exec_command(&session, command).await?;

        Ok(super::ExecOutput {
            stdout: result.output.unwrap_or_default(),
            stderr: String::new(),
            exit_code: Some(if result.success { 0 } else { 1 }),
            method: super::ExecMethod::PsExec,
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
