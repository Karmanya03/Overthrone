//! MS-RPC null session enumeration via SMB IPC$ named pipes.
//!
//! Performs unauthenticated RPC enumeration through:
//! - LSARPC (Local Security Authority Remote Protocol) — domain info, policy, SID translation
//! - SRVSVC (Server Service) — share enumeration, session enumeration
//! - EPMAPPER (Endpoint Mapper) — RPC endpoint discovery
//! - SAMR (Security Account Manager Remote) — user/group enumeration (see rid.rs)
//!
//! These techniques work when the target allows null session access to IPC$.

use crate::error::{OverthroneError, Result};
use crate::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Results from MS-RPC null session enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNullSessionResult {
    /// Target host
    pub target: String,
    /// LSARPC domain information
    pub lsa_domain_info: Option<LsaDomainInfo>,
    /// LSARPC policy information
    pub lsa_policy_info: Option<LsaPolicyInfo>,
    /// SRVSVC share list
    pub srvsvc_shares: Vec<SrvShare>,
    /// EPMAPPER endpoint list
    pub epmapper_endpoints: Vec<EpEndpoint>,
}

/// LSARPC domain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaDomainInfo {
    /// Domain name
    pub name: String,
    /// DNS domain name
    pub dns_domain: Option<String>,
    /// Domain SID
    pub domain_sid: Option<String>,
    /// Domain controller name
    pub dc_name: Option<String>,
}

/// LSARPC policy information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaPolicyInfo {
    /// Minimum password length
    pub min_password_length: Option<u32>,
    /// Password history length
    pub password_history: Option<u32>,
    /// Maximum password age (days)
    pub max_password_age: Option<u32>,
    /// Minimum password age (days)
    pub min_password_age: Option<u32>,
    /// Lockout threshold
    pub lockout_threshold: Option<u32>,
    /// Lockout duration (minutes)
    pub lockout_duration: Option<u32>,
    /// Lockout observation window (minutes)
    pub lockout_window: Option<u32>,
}

/// SRVSVC share information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrvShare {
    /// Share name
    pub name: String,
    /// Share type
    pub share_type: String,
    /// Remark/comment
    pub remark: Option<String>,
}

/// EPMAPPER endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpEndpoint {
    /// Interface UUID
    pub interface_uuid: String,
    /// Protocol sequence
    pub protocol: String,
    /// Endpoint string
    pub endpoint: String,
}

// ═══════════════════════════════════════════════════════════
//  RPC Bind Helpers
// ═══════════════════════════════════════════════════════════

/// Build DCE/RPC bind request for a given interface UUID.
pub fn build_rpc_bind(
    interface_uuid: &[u8; 16],
    version_major: u16,
    version_minor: u16,
) -> Vec<u8> {
    let mut buf = Vec::new();
    // RPC header
    buf.extend_from_slice(&[5, 0]); // version 5.0
    buf.push(11); // packet type = Bind
    buf.push(3); // flags = first+last
    buf.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation (little-endian, ASCII)
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
    // Interface UUID
    buf.extend_from_slice(interface_uuid);
    buf.extend_from_slice(&version_major.to_le_bytes());
    buf.extend_from_slice(&version_minor.to_le_bytes());
    // NDR transfer syntax: 8a885d04-1ceb-11c9-9fe8-08002b104860
    buf.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    buf.extend_from_slice(&2u32.to_le_bytes()); // version
    buf
}

/// Build DCE/RPC request PDU with opnum and stub data.
pub fn build_rpc_request(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    let mut pdu = vec![5, 0, 0, 0x03]; // version 5.0, type=Request, flags=first+last
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR data representation
    let frag_len = (24 + stub_data.len()) as u16;
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call ID
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context ID
    pdu.extend_from_slice(&opnum.to_le_bytes()); // opnum
    pdu.extend_from_slice(stub_data);
    pdu
}

/// Check if RPC bind was accepted.
pub fn is_bind_accepted(resp: &[u8]) -> bool {
    resp.len() > 30 && resp[28] == 0 && resp[29] == 0
}

/// Extract RPC handle from response (20-byte handle at offset 28).
fn extract_handle(resp: &[u8]) -> Option<[u8; 20]> {
    if resp.len() < 48 {
        return None;
    }
    let mut handle = [0u8; 20];
    handle.copy_from_slice(&resp[28..48]);
    if handle.iter().all(|&b| b == 0) {
        return None;
    }
    Some(handle)
}

/// Build RPC close handle request (opnum 0 for most interfaces).
fn build_close_handle(handle: &[u8]) -> Vec<u8> {
    build_rpc_request(0, handle)
}

// ═══════════════════════════════════════════════════════════
//  NDR Encoding Helpers
// ═══════════════════════════════════════════════════════════

pub fn ndr_conformant_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let count = utf16.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes()); // max count
    out.extend_from_slice(&0u32.to_le_bytes()); // offset
    out.extend_from_slice(&count.to_le_bytes()); // actual count
    out.extend_from_slice(&bytes);
    // Pad to 4-byte boundary
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

// ═══════════════════════════════════════════════════════════
//  Interface UUIDs
// ═══════════════════════════════════════════════════════════

/// LSARPC: 12345778-1234-abcd-ef00-0123456789ab
const LSARPC_UUID: [u8; 16] = [
    0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];

/// SRVSVC: 4b324fc8-1670-01d3-1278-5a47bf6ee188
const SRVSVC_UUID: [u8; 16] = [
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
];

/// EPMAPPER: e1af8308-5d1f-11c9-91a4-08002b14a0fa
const EPMAPPER_UUID: [u8; 16] = [
    0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
];

// ═══════════════════════════════════════════════════════════
//  LSARPC Operations
// ═══════════════════════════════════════════════════════════

/// LsarOpenPolicy2 (opnum 44)
fn build_lsa_open_policy2(system_name: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    // Root directory handle (null)
    stub.extend_from_slice(&[0u8; 20]);
    // Object attributes
    stub.extend_from_slice(&0u32.to_le_bytes()); // length
    stub.extend_from_slice(&0u32.to_le_bytes()); // root dir
    let sys_name_ptr = if !system_name.is_empty() {
        0x00020000u32
    } else {
        0
    };
    stub.extend_from_slice(&sys_name_ptr.to_le_bytes()); // object name
    stub.extend_from_slice(&0u32.to_le_bytes()); // attributes
    stub.extend_from_slice(&0u32.to_le_bytes()); // security descriptor
    stub.extend_from_slice(&0u32.to_le_bytes()); // security quality of service
    if !system_name.is_empty() {
        stub.extend_from_slice(&ndr_conformant_string(system_name));
    }
    stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // access mask
    build_rpc_request(44, &stub)
}

/// LsarQueryInformationPolicy (opnum 6)
fn build_lsa_query_info_policy(handle: &[u8], info_class: u16) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(handle);
    stub.extend_from_slice(&info_class.to_le_bytes());
    build_rpc_request(6, &stub)
}

/// LsarClose (opnum 0)
fn build_lsa_close(handle: &[u8]) -> Vec<u8> {
    build_close_handle(handle)
}

// ═══════════════════════════════════════════════════════════
//  SRVSVC Operations
// ═══════════════════════════════════════════════════════════

/// NetrShareEnum (opnum 15) — enumerate shares
fn build_srvsvc_share_enum(server: &str, level: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    // Server UNC name
    let server_ptr = if !server.is_empty() { 0x00020000u32 } else { 0 };
    stub.extend_from_slice(&server_ptr.to_le_bytes());
    if !server.is_empty() {
        stub.extend_from_slice(&ndr_conformant_string(server));
    }
    // Info level
    stub.extend_from_slice(&level.to_le_bytes());
    // Buffer pointer
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    // Preferred max length
    stub.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // Total entries / resume handle
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    build_rpc_request(15, &stub)
}

// ═══════════════════════════════════════════════════════════
//  EPMAPPER Operations
// ═══════════════════════════════════════════════════════════

/// EpmMap (opnum 2) — enumerate endpoints
fn build_epm_map(max_entries: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    // Map command (lookup)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // Max entries
    stub.extend_from_slice(&max_entries.to_le_bytes());
    // Inquiry context (null for first call)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // Object UUID (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&[0u8; 16]);
    // Interface UUID (null = all)
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&[0u8; 16]);
    // Version (any)
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    // Protocol sequence (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // Endpoint (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // Network address (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // Options (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    build_rpc_request(2, &stub)
}

// ═══════════════════════════════════════════════════════════
//  Response Parsers
// ═══════════════════════════════════════════════════════════

fn parse_lsa_domain_info(resp: &[u8]) -> Option<LsaDomainInfo> {
    if resp.len() < 60 {
        return None;
    }
    // LSA_POLICY_INFORMATION response structure
    // After RPC header (24 bytes), the stub contains:
    // - status (4 bytes)
    // - domain name info (NDR string)
    // - DNS domain name info (NDR string)
    // - DC name (NDR string)
    // - domain SID (NDR structure)

    let stub_start = 24usize;
    let status = u32::from_le_bytes([
        resp[stub_start],
        resp[stub_start + 1],
        resp[stub_start + 2],
        resp[stub_start + 3],
    ]);
    if status != 0 {
        return None;
    }

    // Try to extract domain name from the response
    // This is a simplified parser — full NDR parsing is complex
    let mut info = LsaDomainInfo {
        name: String::new(),
        dns_domain: None,
        domain_sid: None,
        dc_name: None,
    };

    // Look for NDR string patterns in the response
    // NDR string: max_count(4) + offset(4) + actual_count(4) + UTF-16 data
    let mut i = stub_start + 4;
    while i < resp.len().saturating_sub(12) {
        let max_count = u32::from_le_bytes([resp[i], resp[i + 1], resp[i + 2], resp[i + 3]]);
        if max_count > 0 && max_count < 256 {
            let offset = u32::from_le_bytes([resp[i + 4], resp[i + 5], resp[i + 6], resp[i + 7]]);
            let actual = u32::from_le_bytes([resp[i + 8], resp[i + 9], resp[i + 10], resp[i + 11]]);
            if actual > 0 && actual == max_count && offset == 0 {
                let data_start = i + 12;
                if data_start + (actual as usize) * 2 <= resp.len() {
                    let bytes = &resp[data_start..data_start + (actual as usize) * 2];
                    let name = String::from_utf16_lossy(
                        &bytes
                            .chunks_exact(2)
                            .filter_map(|c| {
                                if c.len() == 2 {
                                    Some(u16::from_le_bytes([c[0], c[1]]))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>(),
                    );
                    if !name.is_empty() && name != "\0" {
                        if info.name.is_empty() {
                            info.name = name.trim_matches('\0').to_string();
                        } else if info.dns_domain.is_none() {
                            info.dns_domain = Some(name.trim_matches('\0').to_string());
                        }
                        i += 12 + (actual as usize) * 2;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }

    if info.name.is_empty() {
        None
    } else {
        Some(info)
    }
}

fn parse_srvsvc_shares(resp: &[u8]) -> Vec<SrvShare> {
    let mut shares = Vec::new();
    if resp.len() < 40 {
        return shares;
    }

    let stub_start = 24usize;
    // Status
    let status = u32::from_le_bytes([
        resp[stub_start],
        resp[stub_start + 1],
        resp[stub_start + 2],
        resp[stub_start + 3],
    ]);
    if status != 0 {
        return shares;
    }

    // Share count
    let count = u32::from_le_bytes([
        resp[stub_start + 4],
        resp[stub_start + 5],
        resp[stub_start + 6],
        resp[stub_start + 7],
    ]) as usize;

    if count == 0 || count > 500 {
        return shares;
    }

    // Parse share entries (level 1: name + type + remark)
    // Each entry has pointers to strings, strings are at the end
    let entries_start = stub_start + 8;
    let string_start = entries_start + count * 12; // 3 pointers per entry

    for i in 0..count {
        let entry_offset = entries_start + i * 12;
        if entry_offset + 12 > resp.len() {
            break;
        }

        let name_ptr = u32::from_le_bytes([
            resp[entry_offset],
            resp[entry_offset + 1],
            resp[entry_offset + 2],
            resp[entry_offset + 3],
        ]);
        let share_type = u32::from_le_bytes([
            resp[entry_offset + 4],
            resp[entry_offset + 5],
            resp[entry_offset + 6],
            resp[entry_offset + 7],
        ]);
        let remark_ptr = u32::from_le_bytes([
            resp[entry_offset + 8],
            resp[entry_offset + 9],
            resp[entry_offset + 10],
            resp[entry_offset + 11],
        ]);

        let share_type_str = match share_type {
            0 => "Disk",
            1 => "Print Queue",
            2 => "Device",
            3 => "IPC",
            0x80000000 => "Special",
            0x80000001 => "Special Print",
            0x80000002 => "Special Device",
            0x80000003 => "Special IPC",
            _ => "Unknown",
        };

        let mut share = SrvShare {
            name: String::new(),
            share_type: share_type_str.to_string(),
            remark: None,
        };

        // Extract name string
        if name_ptr != 0 {
            let str_offset = string_start + ((name_ptr & 0xFFFF) as usize) * 2;
            if str_offset + 12 <= resp.len() {
                let actual = u32::from_le_bytes([
                    resp[str_offset + 8],
                    resp[str_offset + 9],
                    resp[str_offset + 10],
                    resp[str_offset + 11],
                ]) as usize;
                if actual > 0 && str_offset + 12 + actual * 2 <= resp.len() {
                    let bytes = &resp[str_offset + 12..str_offset + 12 + actual * 2];
                    let name = String::from_utf16_lossy(
                        &bytes
                            .chunks_exact(2)
                            .filter_map(|c| {
                                if c.len() == 2 {
                                    Some(u16::from_le_bytes([c[0], c[1]]))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>(),
                    );
                    share.name = name.trim_matches('\0').to_string();
                }
            }
        }

        // Extract remark string
        if remark_ptr != 0 {
            let str_offset = string_start + ((remark_ptr & 0xFFFF) as usize) * 2;
            if str_offset + 12 <= resp.len() {
                let actual = u32::from_le_bytes([
                    resp[str_offset + 8],
                    resp[str_offset + 9],
                    resp[str_offset + 10],
                    resp[str_offset + 11],
                ]) as usize;
                if actual > 0 && str_offset + 12 + actual * 2 <= resp.len() {
                    let bytes = &resp[str_offset + 12..str_offset + 12 + actual * 2];
                    let remark = String::from_utf16_lossy(
                        &bytes
                            .chunks_exact(2)
                            .filter_map(|c| {
                                if c.len() == 2 {
                                    Some(u16::from_le_bytes([c[0], c[1]]))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>(),
                    );
                    let remark = remark.trim_matches('\0').to_string();
                    if !remark.is_empty() {
                        share.remark = Some(remark);
                    }
                }
            }
        }

        if !share.name.is_empty() {
            shares.push(share);
        }
    }

    shares
}

fn parse_epm_endpoints(resp: &[u8]) -> Vec<EpEndpoint> {
    let mut endpoints = Vec::new();
    if resp.len() < 40 {
        return endpoints;
    }

    let stub_start = 24usize;
    let status = u32::from_le_bytes([
        resp[stub_start],
        resp[stub_start + 1],
        resp[stub_start + 2],
        resp[stub_start + 3],
    ]);
    if status != 0 {
        return endpoints;
    }

    // Count of entries
    let count = u32::from_le_bytes([
        resp[stub_start + 4],
        resp[stub_start + 5],
        resp[stub_start + 6],
        resp[stub_start + 7],
    ]) as usize;

    if count == 0 || count > 500 {
        return endpoints;
    }

    // Simplified: extract known endpoint patterns from the response
    // Full EPM parsing is complex; here we look for common patterns
    for i in stub_start..resp.len().saturating_sub(30) {
        // Look for protocol sequence "ncacn_ip_tcp"
        if resp[i..].windows(12).any(|w| w == b"ncacn_ip_tcp") {
            // Found an endpoint entry
            // Extract the endpoint string (e.g., "49664")
            let proto_end = i + 12;
            if proto_end + 4 <= resp.len() {
                let ep_len = u16::from_le_bytes([resp[proto_end], resp[proto_end + 1]]) as usize;
                if ep_len > 0 && ep_len < 50 && proto_end + 4 + ep_len * 2 <= resp.len() {
                    let ep_bytes = &resp[proto_end + 4..proto_end + 4 + ep_len * 2];
                    let endpoint = String::from_utf16_lossy(
                        &ep_bytes
                            .chunks_exact(2)
                            .filter_map(|c| {
                                if c.len() == 2 {
                                    Some(u16::from_le_bytes([c[0], c[1]]))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>(),
                    );
                    let endpoint = endpoint.trim_matches('\0').to_string();
                    if !endpoint.is_empty() {
                        endpoints.push(EpEndpoint {
                            interface_uuid: "unknown".to_string(),
                            protocol: "ncacn_ip_tcp".to_string(),
                            endpoint,
                        });
                    }
                }
            }
        }
    }

    endpoints
}

// ═══════════════════════════════════════════════════════════
//  Main Entry Point
// ═══════════════════════════════════════════════════════════

/// Perform MS-RPC null session enumeration against a target.
/// Attempts to connect via SMB null session and enumerate via LSARPC, SRVSVC, and EPMAPPER.
pub async fn rpc_null_session_enumeration(target: &str) -> Result<RpcNullSessionResult> {
    info!("[RPC] Starting null session enumeration on {target}");

    let mut result = RpcNullSessionResult {
        target: target.to_string(),
        lsa_domain_info: None,
        lsa_policy_info: None,
        srvsvc_shares: Vec::new(),
        epmapper_endpoints: Vec::new(),
    };

    // Connect via SMB null session
    let smb = match SmbSession::connect(target, "", "", "").await {
        Ok(s) => s,
        Err(_) => SmbSession::connect(target, ".", "guest", "")
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB null session failed: {e}")))?,
    };

    // 1. LSARPC — domain information
    match enumerate_lsa(&smb).await {
        Ok(info) => {
            result.lsa_domain_info = Some(info);
            info!("[RPC] LSARPC domain info obtained");
        }
        Err(e) => {
            debug!("[RPC] LSARPC enumeration failed: {e}");
        }
    }

    // 2. SRVSVC — share enumeration
    match enumerate_srvsvc(&smb).await {
        Ok(shares) => {
            result.srvsvc_shares = shares;
            info!(
                "[RPC] SRVSVC shares enumerated: {}",
                result.srvsvc_shares.len()
            );
        }
        Err(e) => {
            debug!("[RPC] SRVSVC enumeration failed: {e}");
        }
    }

    // 3. EPMAPPER — endpoint discovery
    match enumerate_epmapper(&smb).await {
        Ok(endpoints) => {
            result.epmapper_endpoints = endpoints;
            info!(
                "[RPC] EPMAPPER endpoints discovered: {}",
                result.epmapper_endpoints.len()
            );
        }
        Err(e) => {
            debug!("[RPC] EPMAPPER enumeration failed: {e}");
        }
    }

    info!("[RPC] Null session enumeration complete on {target}");
    Ok(result)
}

async fn enumerate_lsa(smb: &SmbSession) -> Result<LsaDomainInfo> {
    // Bind to LSARPC
    let bind_req = build_rpc_bind(&LSARPC_UUID, 0, 0);
    let bind_resp = smb.pipe_transact("lsarpc", &bind_req).await?;
    if !is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: "lsarpc".to_string(),
            reason: "Bind rejected".to_string(),
        });
    }

    // OpenPolicy2
    let open_req = build_lsa_open_policy2("");
    let open_resp = smb.pipe_transact("lsarpc", &open_req).await?;
    let handle = extract_handle(&open_resp).ok_or_else(|| OverthroneError::Rpc {
        target: "lsarpc".to_string(),
        reason: "OpenPolicy2 failed".to_string(),
    })?;

    // QueryInformationPolicy (class 5 = PolicyPrimaryDomainInformation)
    let query_req = build_lsa_query_info_policy(&handle, 5);
    let query_resp = smb.pipe_transact("lsarpc", &query_req).await?;
    let domain_info = parse_lsa_domain_info(&query_resp);

    // Close handle
    let close_req = build_lsa_close(&handle);
    let _ = smb.pipe_transact("lsarpc", &close_req).await;

    domain_info.ok_or_else(|| OverthroneError::Rpc {
        target: "lsarpc".to_string(),
        reason: "Failed to parse domain info".to_string(),
    })
}

async fn enumerate_srvsvc(smb: &SmbSession) -> Result<Vec<SrvShare>> {
    // Bind to SRVSVC
    let bind_req = build_rpc_bind(&SRVSVC_UUID, 3, 0);
    let bind_resp = smb.pipe_transact("srvsvc", &bind_req).await?;
    if !is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: "srvsvc".to_string(),
            reason: "Bind rejected".to_string(),
        });
    }

    // NetrShareEnum level 1
    let enum_req = build_srvsvc_share_enum("", 1);
    let enum_resp = smb.pipe_transact("srvsvc", &enum_req).await?;
    let shares = parse_srvsvc_shares(&enum_resp);

    Ok(shares)
}

async fn enumerate_epmapper(smb: &SmbSession) -> Result<Vec<EpEndpoint>> {
    // Bind to EPMAPPER
    let bind_req = build_rpc_bind(&EPMAPPER_UUID, 0, 0);
    let bind_resp = smb.pipe_transact("epmapper", &bind_req).await?;
    if !is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: "epmapper".to_string(),
            reason: "Bind rejected".to_string(),
        });
    }

    // EpmMap
    let map_req = build_epm_map(100);
    let map_resp = smb.pipe_transact("epmapper", &map_req).await?;
    let endpoints = parse_epm_endpoints(&map_resp);

    Ok(endpoints)
}

// ═══════════════════════════════════════════════════════════
//  TCP-based EPM resolution
// ═══════════════════════════════════════════════════════════

/// Write a DCE/RPC PDU with BTF (4-byte LE length prefix) framing over TCP.
async fn btf_write_frame(stream: &mut TcpStream, pdu: &[u8]) -> Result<()> {
    let len = (pdu.len() as u32).to_le_bytes();
    stream.write_all(&len).await.map_err(|e| {
        OverthroneError::custom(format!("BTF write failed: {e}"))
    })?;
    stream.write_all(pdu).await.map_err(|e| {
        OverthroneError::custom(format!("BTF write PDU failed: {e}"))
    })?;
    Ok(())
}

/// Read a DCE/RPC PDU with BTF (4-byte LE length prefix) framing over TCP.
async fn btf_read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        OverthroneError::custom(format!("BTF read length failed: {e}"))
    })?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err(OverthroneError::custom(format!(
            "BTF frame too large: {len} bytes"
        )));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(|e| {
        OverthroneError::custom(format!("BTF read data failed: {e}"))
    })?;
    Ok(buf)
}

/// Build an ept_map (opnum 3) request for a specific interface UUID.
/// Queries the endpoint mapper for TCP binding information.
fn build_ept_map_request_uuid(interface_uuid: &[u8; 16]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);

    // DCE/RPC header (request)
    pkt.push(5);
    pkt.push(0);
    pkt.push(0);
    pkt.push(0x03);
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&1u32.to_le_bytes());

    // Request body
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x03, 0x00]);

    // ept_map inputs
    pkt.extend_from_slice(&[0u8; 16]);
    let tower_len: u32 = 75;
    pkt.extend_from_slice(&tower_len.to_le_bytes());
    pkt.extend_from_slice(&tower_len.to_le_bytes());

    // Floor 1: Interface UUID
    pkt.extend_from_slice(&[0x05, 0x00]);
    pkt.push(0x0D);
    pkt.extend_from_slice(interface_uuid);
    pkt.extend_from_slice(&[0x00, 0x00]);

    // Floor 2: NDR transfer syntax
    pkt.push(0x0D);
    pkt.extend_from_slice(&[
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
        0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
    ]);
    pkt.extend_from_slice(&[0x02, 0x00]);

    // Floor 3: NCACN
    pkt.push(0x09);
    pkt.extend_from_slice(&[0x00, 0x00]);

    // Floor 4: TCP
    pkt.push(0x07);
    pkt.extend_from_slice(&[0x00, 0x00]);

    // Floor 5: IP
    pkt.push(0x09);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    pkt.extend_from_slice(&4u32.to_le_bytes());

    // Fix frag length
    let len = pkt.len() as u16;
    pkt[8] = (len & 0xFF) as u8;
    pkt[9] = (len >> 8) as u8;

    pkt
}

/// Parse ept_map response to extract the TCP port from tower data.
/// Returns the port number, or 0 if not found.
fn parse_ept_map_tcp_port(response: &[u8]) -> u16 {
    if response.len() < 40 {
        return 0;
    }
    for i in 24..response.len().saturating_sub(3) {
        if response[i] == 0x07 && response[i + 1] != 0 && response[i + 2] != 0 {
            let port = u16::from_be_bytes([response[i + 1], response[i + 2]]);
            if (1024..=65535).contains(&port) {
                debug!("EPM TCP: Resolved dynamic port {port}");
                return port;
            }
        }
    }
    0
}

/// Parse ept_map response to extract the IPv4 address from tower data.
/// Returns the address as a string, or None if not found.
fn parse_ept_map_addr(response: &[u8]) -> Option<String> {
    for i in 24..response.len().saturating_sub(7) {
        if response[i] == 0x09 && response[i + 1] == 0x00 {
            let a = response[i + 2];
            let b = response[i + 3];
            let c = response[i + 4];
            let d = response[i + 5];
            if a != 0 || b != 0 || c != 0 || d != 0 {
                return Some(format!("{a}.{b}.{c}.{d}"));
            }
        }
    }
    None
}

/// Resolve an RPC interface UUID to a TCP endpoint by querying the
/// Endpoint Mapper over TCP (port 135).
///
/// Returns `(host, port)` on success.
pub async fn resolve_uuid_via_epm_tcp(
    target: &str,
    interface_uuid: &[u8; 16],
) -> Result<(String, u16)> {
    let addr = format!("{target}:135");
    debug!("EPM TCP: Connecting to {addr}");

    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| OverthroneError::custom(format!("EPM TCP connect to {addr} failed: {e}")))?;

    // Bind to EPM v3.0
    let bind_req = build_rpc_bind(&EPMAPPER_UUID, 3, 0);
    btf_write_frame(&mut stream, &bind_req).await?;

    let bind_resp = btf_read_frame(&mut stream).await?;
    if !is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::custom("EPM TCP bind rejected"));
    }

    // ept_map (opnum 3) for the target interface
    let map_req = build_ept_map_request_uuid(interface_uuid);
    btf_write_frame(&mut stream, &map_req).await?;

    let map_resp = btf_read_frame(&mut stream).await?;
    let port = parse_ept_map_tcp_port(&map_resp);

    if port == 0 {
        return Err(OverthroneError::custom(
            "EPM TCP: no TCP endpoint found for interface".to_string(),
        ));
    }

    let host = parse_ept_map_addr(&map_resp).unwrap_or_else(|| target.to_string());

    debug!("EPM TCP: {target} interface resolved to {host}:{port}");
    Ok((host, port))
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_bind_structure() {
        let bind = build_rpc_bind(&LSARPC_UUID, 0, 0);
        assert_eq!(bind[0], 5); // RPC version major
        assert_eq!(bind[1], 0); // RPC version minor
        assert_eq!(bind[2], 11); // Packet type = Bind
        assert_eq!(bind.len(), 72); // Expected bind size
    }

    #[test]
    fn test_rpc_request_structure() {
        let stub = vec![0u8; 10];
        let req = build_rpc_request(0, &stub);
        assert_eq!(req[0], 5); // RPC version
        assert_eq!(req[2], 0); // Packet type = Request
        assert_eq!(req.len(), 34); // 24 header + 10 stub
    }

    #[test]
    fn test_ndr_string() {
        let encoded = ndr_conformant_string("test");
        assert!(!encoded.is_empty());
        // Should contain UTF-16 encoded "test\0"
        assert!(encoded.windows(2).any(|w| w == [b't', 0]));
    }
}
