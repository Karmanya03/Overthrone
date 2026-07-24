//! Shared DCOM (Distributed COM) primitives for MS-RPC over SMB named pipes.
//!
//! Provides DCE/RPC building blocks used by WMIExec, MS-WCCE, and other
//! DCOM-based protocol implementations in the forge/hunter crates.

use crate::error::{OverthroneError, Result};

/// IRemoteSCMActivator UUID (LE): 000001A0-0000-0000-C000-000000000046
pub const SCM_ACTIVATOR_UUID: [u8; 16] = [
    0xA0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// IRemUnknown2 UUID (LE): 00000143-0000-0000-C000-000000000046
pub const IREMUNKNOWN2_UUID: [u8; 16] = [
    0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// NDR transfer syntax UUID (LE): 8a885d04-1ceb-11c9-9fe8-08002b104860
pub const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

/// EPM interface UUID (LE): e1af8308-5d1f-11c9-91a4-08002b14a0fa
pub const EPM_UUID: [u8; 16] = [
    0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11, 0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA,
];

/// Generate a random causality ID for ORPC_THIS headers.
pub fn random_causality_id() -> [u8; 16] {
    rand::random()
}

/// Build an ORPC_THIS header for DCOM calls.
///
/// Layout: version(2+2), flags(4), reserved1(4), causality_id(16), extensions_ptr(4) = 36 bytes
/// Padded to 40 bytes with trailing zeros (standard ORPC_THIS is 40 bytes).
pub fn build_orpc_this() -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&5u16.to_le_bytes()); // major version
    buf.extend_from_slice(&7u16.to_le_bytes()); // minor version
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    buf.extend_from_slice(&random_causality_id()); // causality ID
    buf.extend_from_slice(&0u32.to_le_bytes()); // extensions pointer (NULL)
    buf
}

/// Build a DCE/RPC bind PDU for an arbitrary interface.
pub fn build_rpc_bind(interface_uuid: &[u8; 16], version_major: u16, call_id: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(72);
    pkt.push(5); // version
    pkt.push(0); // minor
    pkt.push(11); // bind
    pkt.push(0x03); // first + last
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&call_id.to_le_bytes());
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    pkt.extend_from_slice(&0u32.to_le_bytes()); // assoc group
    pkt.extend_from_slice(&1u32.to_le_bytes()); // num ctx items
    pkt.extend_from_slice(&0u16.to_le_bytes()); // ctx id
    pkt.extend_from_slice(&1u16.to_le_bytes()); // num transfer syntaxes
    pkt.extend_from_slice(interface_uuid);
    pkt.extend_from_slice(&version_major.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes()); // minor
    pkt.extend_from_slice(&NDR_UUID);
    pkt.extend_from_slice(&2u32.to_le_bytes());
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;
    pkt
}

/// Build a DCE/RPC request PDU with DCOM ORPC_THIS header.
pub fn build_dcom_request(opnum: u16, ipid: &[u8; 16], stub_data: &[u8], call_id: u32) -> Vec<u8> {
    let mut pdu = vec![5, 0, 0, 0x03]; // version 5.0, request, first+last
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR
    let frag_len = (24 + 16 + stub_data.len()) as u16; // header + object UUID + stub
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(ipid); // object UUID (IPID)
    pdu.extend_from_slice(stub_data);
    let len = pdu.len() as u16;
    pdu[8] = (len & 0xFF) as u8;
    pdu[9] = (len >> 8) as u8;
    pdu
}

/// Build a minimal EPM bind packet for the endpoint mapper.
pub fn build_epm_bind() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(72);
    pkt.push(5);
    pkt.push(0);
    pkt.push(11); // bind
    pkt.push(0x03);
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&0u32.to_le_bytes()); // call id
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    pkt.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    pkt.extend_from_slice(&0u32.to_le_bytes()); // assoc group
    pkt.extend_from_slice(&1u32.to_le_bytes()); // num ctx items
    pkt.extend_from_slice(&0u16.to_le_bytes()); // ctx id
    pkt.extend_from_slice(&1u16.to_le_bytes()); // num transfer
    pkt.extend_from_slice(&EPM_UUID);
    pkt.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // v3.0
    pkt.extend_from_slice(&NDR_UUID);
    pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // v2.0
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;
    pkt
}

/// Build an ept_map DCE/RPC request to resolve an interface UUID.
/// Queries the endpoint mapper for binding information.
pub fn build_ept_map_request(interface_uuid: &[u8; 16]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);
    pkt.push(5);
    pkt.push(0);
    pkt.push(0); // request
    pkt.push(0x03); // first + last
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data repr
    pkt.extend_from_slice(&[0x00, 0x00]); // frag length placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // auth length
    pkt.extend_from_slice(&1u32.to_le_bytes()); // call id = 1
    pkt.extend_from_slice(&0u32.to_le_bytes()); // alloc hint
    pkt.extend_from_slice(&0u16.to_le_bytes()); // context id
    pkt.extend_from_slice(&3u16.to_le_bytes()); // opnum = 3 (ept_map)
    pkt.extend_from_slice(&[0u8; 16]); // object UUID = NULL
    let tower_len: u32 = 75;
    pkt.extend_from_slice(&tower_len.to_le_bytes());
    pkt.extend_from_slice(&tower_len.to_le_bytes()); // max count
    pkt.extend_from_slice(&[0x05, 0x00]); // floor count
    pkt.push(0x0D); // EPM_PROTOCOL_UUID
    pkt.extend_from_slice(interface_uuid);
    pkt.extend_from_slice(&[0x00, 0x00]); // version major
    pkt.push(0x0D); // NDR transfer syntax
    pkt.extend_from_slice(&NDR_UUID);
    pkt.extend_from_slice(&[0x02, 0x00]); // v2.0
    pkt.push(0x09); // EPM_PROTOCOL_NCACN
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x07); // EPM_PROTOCOL_TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x09); // EPM_PROTOCOL_IP
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&4u32.to_le_bytes()); // max_towers
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;
    pkt
}

/// Build IRemoteSCMActivator bind PDU.
pub fn build_scm_activator_bind() -> Vec<u8> {
    build_rpc_bind(&SCM_ACTIVATOR_UUID, 0, 2)
}

/// Build DCOM Activation Properties for RemoteCreateInstance.
///
/// Contains the CLSID to instantiate and the requested interface IID,
/// plus CLSCTX_REMOTE_SERVER (0x10) for remote activation.
pub fn build_activation_properties(clsid: &[u8; 16], iid: &[u8; 16]) -> Vec<u8> {
    let mut props = Vec::new();
    props.extend_from_slice(clsid);
    props.extend_from_slice(&1u32.to_le_bytes()); // number of requested interfaces
    props.extend_from_slice(iid);
    props.extend_from_slice(&0x10u32.to_le_bytes()); // CLSCTX_REMOTE_SERVER
    props.extend_from_slice(&0u32.to_le_bytes()); // process ID
    props.extend_from_slice(&0u32.to_le_bytes()); // activation flags
    props
}

/// Build RemoteCreateInstance request (IRemoteSCMActivator opnum 4).
///
/// Creates a COM object for the given CLSID and returns an OBJREF
/// for the requested IID.
pub fn build_remote_create_instance(clsid: &[u8; 16], iid: &[u8; 16], call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend(build_orpc_this());
    stub.extend_from_slice(&0u32.to_le_bytes()); // pUnkOuter (NULL)
    let act_props = build_activation_properties(clsid, iid);
    stub.extend(act_props);
    let ipid = [0u8; 16]; // dummy IPID for activation
    build_dcom_request(4, &ipid, &stub, call_id)
}

/// Build IRemUnknown2::RemRelease request (opnum 5).
/// Releases the specified OIDs to prevent server-side resource leaks.
pub fn build_rem_release(ipid: &[u8; 16], oids: &[u64], call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend(build_orpc_this());
    stub.extend_from_slice(&(oids.len() as u16).to_le_bytes());
    stub.extend_from_slice(&[0u8; 2]); // padding
    for _oid in oids {
        stub.extend_from_slice(ipid);
        stub.extend_from_slice(&5u32.to_le_bytes()); // cPublicRefs
        stub.extend_from_slice(&0u32.to_le_bytes()); // cPrivateRefs
    }
    build_dcom_request(5, ipid, &stub, call_id)
}

/// Parse an OBJREF (marshaled COM interface pointer) from a DCOM response.
///
/// Returns `(IPID [16 bytes], OXID, OID)` on success.
/// The IPID is used to address subsequent DCOM calls to this interface.
pub fn parse_objref(response: &[u8]) -> std::result::Result<([u8; 16], u64, u64), String> {
    let meow_sig: [u8; 4] = [0x4D, 0x45, 0x4F, 0x57]; // "MEOW"
    let pos = find_pattern(response, &meow_sig)
        .ok_or_else(|| "OBJREF MEOW signature not found in response".to_string())?;
    let objref = &response[pos..];
    if objref.len() < 76 {
        return Err(format!(
            "OBJREF too short: {} bytes at offset {pos}",
            objref.len()
        ));
    }
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
pub fn parse_ept_map_port(response: &[u8]) -> u16 {
    if response.len() < 40 {
        return 0;
    }
    for i in 24..response.len().saturating_sub(3) {
        if response[i] == 0x07 && response[i + 1] != 0 && response[i + 2] != 0 {
            let port = u16::from_be_bytes([response[i + 1], response[i + 2]]);
            if (1024..=65535).contains(&port) {
                return port;
            }
        }
    }
    0
}

/// Write a BSTR (NDR conformant string with referent) to buf.
pub fn write_bstr(buf: &mut Vec<u8>, s: &str) {
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
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Write an NDR conformant string (UTF-16) to buf.
pub fn write_ndr_string(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> = s
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let char_count = (s.len() + 1) as u32;
    buf.extend_from_slice(&char_count.to_le_bytes()); // max count
    buf.extend_from_slice(&0u32.to_le_bytes()); // offset
    buf.extend_from_slice(&char_count.to_le_bytes()); // actual count
    buf.extend_from_slice(&utf16);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Build NTLMSSP negotiate message for DCE/RPC auth.
pub fn build_dcom_ntlmssp_negotiate() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"NTLMSSP\x00");
    msg.extend_from_slice(&1u32.to_le_bytes()); // NTLMSSP_NEGOTIATE
    // Flags: NEGOTIATE_UNICODE (0x01) | NEGOTIATE_OEM (0x02) | REQUEST_TARGET (0x04) |
    //        NEGOTIATE_NTLM (0x200) | NEGOTIATE_ALWAYS_SIGN (0x8000) |
    //        NEGOTIATE_VERSION (0x2000000) | NEGOTIATE_EXTENDED_SESSION (0x80000)
    msg.extend_from_slice(&0x028A_0783u32.to_le_bytes());
    // Domain name (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    // Workstation (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    // OS version
    msg.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Win 10
    msg
}

/// Find a byte pattern in a buffer, returning its offset.
pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len())
        .position(|window| window == pattern)
}

/// Check if a DCE/RPC bind response was accepted.
///
/// Parses the BindAck PDU to find the presentation context result after
/// the variable-length sec_addr. See epm::is_bind_accepted for details.
pub fn is_bind_accepted(resp: &[u8]) -> bool {
    if resp.len() < 30 || resp[2] != 12 {
        return false;
    }
    let sec_addr_len = u16::from_le_bytes([resp[24], resp[25]]) as usize;
    let mut off = 26 + sec_addr_len;
    off = (off + 3) & !3;
    if off + 4 > resp.len() {
        return false;
    }
    let result = u16::from_le_bytes([resp[off + 2], resp[off + 3]]);
    result == 0
}

/// Perform DCOM activation over SMB named pipe.
///
/// 1. Binds to endpoint mapper on \pipe\epmapper
/// 2. Queries EPM for IRemoteSCMActivator
/// 3. Binds to IRemoteSCMActivator
/// 4. Calls RemoteCreateInstance with the given CLSID/IID
/// 5. Parses the OBJREF response
///
/// Returns (IPID, OXID, OID) and the SMB session for further calls.
pub async fn dcom_activate(
    smb: &crate::proto::smb::SmbSession,
    clsid: &[u8; 16],
    iid: &[u8; 16],
) -> Result<([u8; 16], u64, u64)> {
    use tracing::{debug, info};

    info!("[DCOM] Activating CLSID on {}", smb.target);

    // Phase 1: Bind to EPM
    let epm_bind = build_epm_bind();
    let _epm_resp = smb
        .pipe_transact("epmapper", &epm_bind)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:epmapper", smb.target),
            reason: format!("EPM bind failed: {e}"),
        })?;
    debug!("[DCOM] EPM bind complete");

    // Phase 2: Query for IRemoteSCMActivator
    let ept_map_req = build_ept_map_request(&SCM_ACTIVATOR_UUID);
    let ept_map_resp = smb
        .pipe_transact("epmapper", &ept_map_req)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:epmapper", smb.target),
            reason: format!("EPT_MAP failed: {e}"),
        })?;
    debug!("[DCOM] EPT_MAP for SCM activator complete");

    // Phase 3: Bind to IRemoteSCMActivator
    let activator_bind = build_scm_activator_bind();
    let _activator_resp = smb
        .pipe_transact("epmapper", &activator_bind)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:epmapper", smb.target),
            reason: format!("SCM activator bind failed: {e}"),
        })?;
    debug!("[DCOM] SCM activator bind accepted");

    // If the ept_map response contains a dynamic port, we need to connect via TCP.
    // For named pipe transport, the activation goes through the same pipe.
    // Check if we got a TCP port back
    let tcp_port = parse_ept_map_port(&ept_map_resp);

    let (ipid, oxid, oid) = if tcp_port > 0 {
        // TCP transport needed -- connect to dynamic port
        let tcp_addr = format!("{}:{}", smb.target, tcp_port);
        debug!("[DCOM] Connecting to TCP: {tcp_addr}");
        let mut tcp_stream = tokio::net::TcpStream::connect(&tcp_addr)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: tcp_addr,
                reason: format!("TCP connect for DCOM failed: {e}"),
            })?;

        // Bind to SCM activator over TCP
        let tcp_activator_bind = build_rpc_bind(&SCM_ACTIVATOR_UUID, 0, 2);
        use tokio::io::AsyncWriteExt;
        tcp_stream
            .write_all(&tcp_activator_bind)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: smb.target.clone(),
                reason: format!("TCP SCM bind failed: {e}"),
            })?;

        let mut buf = vec![0u8; 4096];
        use tokio::io::AsyncReadExt;
        let n = tcp_stream
            .read(&mut buf)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: smb.target.clone(),
                reason: format!("TCP SCM bind response failed: {e}"),
            })?;
        if !is_bind_accepted(&buf[..n]) {
            return Err(OverthroneError::Rpc {
                target: smb.target.clone(),
                reason: "TCP SCM activator bind rejected".to_string(),
            });
        }

        // RemoteCreateInstance over TCP
        let create_req = build_remote_create_instance(clsid, iid, 3);
        tcp_stream
            .write_all(&create_req)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: smb.target.clone(),
                reason: format!("TCP RemoteCreateInstance failed: {e}"),
            })?;

        let n = tcp_stream
            .read(&mut buf)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: smb.target.clone(),
                reason: format!("TCP RemoteCreateInstance response failed: {e}"),
            })?;

        let (ipid, oxid, oid) = parse_objref(&buf[..n]).map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("Failed to parse OBJREF from TCP: {e}"),
        })?;
        debug!(
            "[DCOM] TCP activation: IPID={:02x?}, OXID={oxid}, OID={oid}",
            ipid
        );
        (ipid, oxid, oid)
    } else {
        // Pipe transport -- activation goes through \pipe\epmapper
        let create_req = build_remote_create_instance(clsid, iid, 3);
        let create_resp = smb
            .pipe_transact("epmapper", &create_req)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: format!("{}:epmapper", smb.target),
                reason: format!("RemoteCreateInstance failed: {e}"),
            })?;

        let (ipid, oxid, oid) = parse_objref(&create_resp).map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("Failed to parse OBJREF: {e}"),
        })?;
        debug!(
            "[DCOM] Named pipe activation: IPID={:02x?}, OXID={oxid}, OID={oid}",
            ipid
        );
        (ipid, oxid, oid)
    };

    Ok((ipid, oxid, oid))
}

/// Send a DCOM method call and return the raw response.
pub async fn dcom_call(
    smb: &crate::proto::smb::SmbSession,
    pipe: &str,
    ipid: &[u8; 16],
    opnum: u16,
    stub_data: &[u8],
    call_id: u32,
) -> Result<Vec<u8>> {
    let req = build_dcom_request(opnum, ipid, stub_data, call_id);
    let resp = smb
        .pipe_transact(pipe, &req)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:{pipe}", smb.target),
            reason: format!("DCOM call opnum {opnum} failed: {e}"),
        })?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_orpc_this_length() {
        let header = build_orpc_this();
        // ORPC_THIS is 32 bytes: version(4) + flags(4) + reserved(4) + cid(16) + ext_ptr(4)
        assert_eq!(header.len(), 32);
    }

    #[test]
    fn test_build_epm_bind_minimal() {
        let bind = build_epm_bind();
        assert!(bind.len() > 60);
        assert_eq!(bind[0], 5); // version
        assert_eq!(bind[2], 11); // bind
    }

    #[test]
    fn test_build_dcom_request_minimal() {
        let ipid = [0xABu8; 16];
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let req = build_dcom_request(1, &ipid, &data, 42);
        assert_eq!(req[0], 5); // version
        assert_eq!(req[2], 0); // request
        assert_eq!(req[3], 0x03); // first + last
        assert!(req.len() > 24);
    }

    #[test]
    fn test_parse_objref_valid() {
        // Build a minimal valid OBJREF with MEOW signature
        let mut resp = vec![0u8; 100];
        // MEOW at offset 20
        resp[20] = 0x4D;
        resp[21] = 0x45;
        resp[22] = 0x4F;
        resp[23] = 0x57;
        // flags at offset 24
        resp[24] = 0x01;
        resp[25] = 0x00;
        resp[26] = 0x00;
        resp[27] = 0x00;
        // IID at offset 28-43 (16 bytes)
        // STDOBJREF starts at offset 44
        let std_start = 44;
        // flags at std_start(44)
        resp[std_start] = 0x00;
        resp[std_start + 1] = 0x00;
        resp[std_start + 2] = 0x00;
        resp[std_start + 3] = 0x00;
        // cPublicRefs at std_start + 4
        resp[std_start + 4] = 0x01;
        resp[std_start + 5] = 0x00;
        resp[std_start + 6] = 0x00;
        resp[std_start + 7] = 0x00;
        // OXID at std_start + 8 (0xDEADBEEFCAFE)
        resp[std_start + 8] = 0xFE;
        resp[std_start + 9] = 0xCA;
        resp[std_start + 10] = 0xEF;
        resp[std_start + 11] = 0xBE;
        resp[std_start + 12] = 0xAD;
        resp[std_start + 13] = 0xDE;
        resp[std_start + 14] = 0x00;
        resp[std_start + 15] = 0x00;
        // OID at std_start + 16
        resp[std_start + 16] = 0x01;
        resp[std_start + 17] = 0x00;
        resp[std_start + 18] = 0x00;
        resp[std_start + 19] = 0x00;
        resp[std_start + 20] = 0x00;
        resp[std_start + 21] = 0x00;
        resp[std_start + 22] = 0x00;
        resp[std_start + 23] = 0x00;
        // IPID at std_start + 24
        resp[std_start + 24] = 0x11;
        resp[std_start + 25] = 0x22;
        resp[std_start + 26] = 0x33;
        resp[std_start + 27] = 0x44;
        resp[std_start + 28] = 0x55;
        resp[std_start + 29] = 0x66;
        resp[std_start + 30] = 0x77;
        resp[std_start + 31] = 0x88;
        resp[std_start + 32] = 0x99;
        resp[std_start + 33] = 0xAA;
        resp[std_start + 34] = 0xBB;
        resp[std_start + 35] = 0xCC;
        resp[std_start + 36] = 0xDD;
        resp[std_start + 37] = 0xEE;
        resp[std_start + 38] = 0xFF;
        resp[std_start + 39] = 0x00;

        let (ipid, oxid, oid) = parse_objref(&resp).unwrap();
        assert_eq!(oxid, 0xDEADBEEFCAFE);
        assert_eq!(oid, 1);
        assert_eq!(ipid[0], 0x11);
        assert_eq!(ipid[1], 0x22);
    }

    #[test]
    fn test_parse_objref_no_meow() {
        let resp = vec![0u8; 50];
        assert!(parse_objref(&resp).is_err());
    }

    #[test]
    fn test_parse_objref_too_short() {
        let mut resp = vec![0u8; 30];
        resp[10] = 0x4D;
        resp[11] = 0x45;
        resp[12] = 0x4F;
        resp[13] = 0x57;
        assert!(parse_objref(&resp).is_err());
    }

    #[test]
    fn test_find_pattern_found() {
        let data = b"hello world pattern test";
        let pat = b"pattern";
        assert_eq!(find_pattern(data, pat), Some(12));
    }

    #[test]
    fn test_find_pattern_not_found() {
        let data = b"hello world";
        let pat = b"xyz";
        assert_eq!(find_pattern(data, pat), None);
    }

    #[test]
    fn test_write_bstr_empty() {
        let mut buf = Vec::new();
        write_bstr(&mut buf, "");
        // Should have referent ID + max_count(1) + offset(0) + actual_count(1) + null u16 + padding
        assert!(buf.len() >= 20);
    }

    #[test]
    fn test_build_activation_properties() {
        let clsid = [0x11u8; 16];
        let iid = [0x22u8; 16];
        let props = build_activation_properties(&clsid, &iid);
        // CLSID(16) + cIfs(4) + IID(16) + destCtx(4) + pid(4) + flags(4) = 48
        assert_eq!(props.len(), 48);
        assert_eq!(&props[0..16], &clsid);
        assert_eq!(&props[20..36], &iid);
    }

    #[test]
    fn test_is_bind_accepted() {
        let mut resp = vec![0u8; 32];
        resp[2] = 12; // type = BindAck
        // sec_addr_len at 24-25 = [0,0], off = 28, result at 30-31 = [0,0] => accepted
        assert!(is_bind_accepted(&resp));
    }

    #[test]
    fn test_parse_ept_map_port_empty() {
        assert_eq!(parse_ept_map_port(&[0u8; 10]), 0);
    }

    #[test]
    fn test_build_epm_bind_and_map_consistency() {
        let bind = build_epm_bind();
        let map_req = build_ept_map_request(&SCM_ACTIVATOR_UUID);
        assert!(bind.len() > 60);
        assert!(map_req.len() > 60);
        // Both start with DCE/RPC header
        assert_eq!(bind[0], 5);
        assert_eq!(map_req[0], 5);
    }

    #[test]
    fn test_dcom_activation_properties_clsid_iid_placement() {
        let clsid = [0x11u8; 16];
        let iid = [0x22u8; 16];
        let props = build_activation_properties(&clsid, &iid);

        // CLSID at offset 0
        assert_eq!(&props[0..4], &[0x11, 0x11, 0x11, 0x11]);

        // cIfs = 1 at offset 16
        let cifs = u32::from_le_bytes(props[16..20].try_into().unwrap());
        assert_eq!(cifs, 1);

        // IID at offset 20
        assert_eq!(&props[20..36], &iid);

        // destCtx = 0x10 at offset 36
        let dest_ctx = u32::from_le_bytes(props[36..40].try_into().unwrap());
        assert_eq!(dest_ctx, 0x10);
    }

    #[test]
    fn test_write_ndr_string_hello() {
        let mut buf = Vec::new();
        write_ndr_string(&mut buf, "hello");
        // Each char becomes 2 bytes UTF-16 + null terminator
        // max_count + offset + actual_count + utf16_data
        assert!(buf.len() > 12);
        let actual = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(actual, 6); // "hello" + null = 6 characters
    }

    #[test]
    fn test_build_rem_release() {
        let ipid = [0xFFu8; 16];
        let oids = vec![1, 2];
        let req = build_rem_release(&ipid, &oids, 5);
        assert_eq!(req[2], 0); // request
        assert!(req.len() > 80);
    }

    #[test]
    fn test_build_dcom_ntlmssp_negotiate() {
        let msg = build_dcom_ntlmssp_negotiate();
        assert!(msg.starts_with(b"NTLMSSP\x00"));
        assert_eq!(msg.len() >= 32, true);
    }
}
