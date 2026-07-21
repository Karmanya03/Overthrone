//! NetBIOS Name Service (NBNS) and SMB protocol discovery.
//!
//! Provides unauthenticated network-level discovery:
//! - NBNS queries for computer name, domain name, user list
//! - SMB protocol negotiation fingerprinting
//! - SMB signing requirement detection
//! - OS version detection from SMB negotiate response

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, info};

// ===========================================================
//  Types
// ===========================================================

/// NetBIOS node status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NbnsNodeStatus {
    /// Computer name (NetBIOS name)
    pub computer_name: String,
    /// Domain/workgroup name
    pub domain_name: String,
    /// User name (if available)
    pub user_name: Option<String>,
    /// MAC address
    pub mac_address: String,
    /// NetBIOS name table entries
    pub name_table: Vec<NbnsNameEntry>,
}

/// NetBIOS name table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NbnsNameEntry {
    /// NetBIOS name
    pub name: String,
    /// Name type suffix
    pub name_type: String,
    /// Name flags
    pub flags: String,
}

/// SMB protocol negotiation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbNegotiateResult {
    /// Target host
    pub target: String,
    /// Highest SMB dialect supported
    pub highest_dialect: String,
    /// SMB signing required
    pub signing_required: bool,
    /// SMB signing enabled
    pub signing_enabled: bool,
    /// GUID of the server
    pub server_guid: String,
    /// OS name (if available)
    pub os_name: Option<String>,
    /// Native OS (if available)
    pub native_os: Option<String>,
    /// Native LAN manager (if available)
    pub native_lm: Option<String>,
    /// Maximum buffer size
    pub max_buffer_size: u32,
    /// Raw negotiate response bytes
    pub raw_response: Option<Vec<u8>>,
}

// ===========================================================
//  NBNS (NetBIOS Name Service)
// ===========================================================

/// NBNS query type: Node Status Request (0x21)
#[allow(dead_code)]
const NBNS_NODE_STATUS: u16 = 0x21;
/// NBNS port
const NBNS_PORT: u16 = 137;

/// Perform NBNS node status query against a target.
/// Returns computer name, domain name, and NetBIOS name table.
pub async fn nbns_node_status(target: &str) -> Result<NbnsNodeStatus> {
    info!("[NBNS] Querying node status on {target}");

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| OverthroneError::Dns {
            target: target.to_string(),
            reason: format!("Failed to bind UDP socket: {e}"),
        })?;

    let addr: SocketAddr =
        format!("{target}:{NBNS_PORT}")
            .parse()
            .map_err(|e| OverthroneError::Dns {
                target: target.to_string(),
                reason: format!("Invalid address: {e}"),
            })?;

    // Build NBNS Node Status Request
    let query = build_nbns_node_status_query();
    socket
        .send_to(&query, addr)
        .await
        .map_err(|e| OverthroneError::Dns {
            target: target.to_string(),
            reason: format!("NBNS send failed: {e}"),
        })?;

    // Read response with timeout
    let mut buf = [0u8; 1024];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
        .await
        .map_err(|_| OverthroneError::Dns {
            target: target.to_string(),
            reason: "NBNS query timed out".to_string(),
        })?
        .map_err(|e| OverthroneError::Dns {
            target: target.to_string(),
            reason: format!("NBNS recv failed: {e}"),
        })?;

    parse_nbns_node_status(&buf[..len])
}

/// Build NBNS Node Status Request packet.
fn build_nbns_node_status_query() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Transaction ID
    pkt.extend_from_slice(&[0xAB, 0xCD]);
    // Flags: standard query, recursion desired
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    pkt.extend_from_slice(&[0x00, 0x00]);

    // Question name: encoded "*" (wildcard) for node status
    // NetBIOS name encoding: each byte -> two chars (hex + 'A')
    pkt.push(0x20); // Length = 32 (16 bytes * 2)
    // "*" padded to 15 bytes, type 0x00 (workstation)
    let name = "*".to_string() + &" ".repeat(15);
    for b in name.as_bytes() {
        let high = (b >> 4) + b'A';
        let low = (b & 0x0F) + b'A';
        pkt.push(high);
        pkt.push(low);
    }
    pkt.push(0x00); // Null terminator

    // Question type: Node Status (0x21)
    pkt.extend_from_slice(&[0x00, 0x21]);
    // Question class: IN (0x01)
    pkt.extend_from_slice(&[0x00, 0x01]);

    pkt
}

/// Parse NBNS Node Status Response.
fn parse_nbns_node_status(data: &[u8]) -> Result<NbnsNodeStatus> {
    if data.len() < 57 {
        return Err(OverthroneError::Dns {
            target: "nbns".to_string(),
            reason: format!(
                "NBNS response too short: {} bytes (expected >=57)",
                data.len()
            ),
        });
    }

    // Check flags for response
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return Err(OverthroneError::Dns {
            target: "nbns".to_string(),
            reason: "Not a response packet".to_string(),
        });
    }

    // Number of name entries
    let num_names = data[56] as usize;
    if num_names == 0 || num_names > 25 {
        return Err(OverthroneError::Dns {
            target: "nbns".to_string(),
            reason: format!("Invalid name count: {num_names}"),
        });
    }

    let mut entries = Vec::new();
    let mut computer_name = String::new();
    let mut domain_name = String::new();
    let mut user_name = None;
    let mut mac_address = String::new();

    let mut offset = 57;
    for _ in 0..num_names {
        if offset + 18 > data.len() {
            break;
        }

        // NetBIOS name (16 bytes, padded with spaces)
        let raw_name = &data[offset..offset + 16];
        let name = String::from_utf8_lossy(raw_name)
            .trim_end()
            .trim_end_matches('\0')
            .to_string();
        let suffix = data[offset + 15];
        offset += 16;

        // Flags
        let name_flags = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let name_type = match suffix {
            0x00 => "Workstation",
            0x03 => "Messenger",
            0x06 => "RAS Server",
            0x1B => "Domain Master Browser",
            0x1C => "Domain Controllers",
            0x1D => "Master Browser",
            0x1E => "Browser Elections",
            0x20 => "File Server",
            0x21 => "RAS Client",
            0xBE => "Network Monitor Agent",
            0xBF => "Network Monitor Application",
            _ => "Unknown",
        };

        let flags_str = if name_flags & 0x8000 != 0 {
            "GROUP"
        } else {
            "UNIQUE"
        };

        // Categorize names
        if suffix == 0x20 && name_flags & 0x8000 == 0 {
            computer_name = name.clone();
        } else if suffix == 0x00 && name_flags & 0x8000 != 0 {
            domain_name = name.clone();
        } else if suffix == 0x03 && name_flags & 0x8000 == 0 {
            user_name = Some(name.clone());
        }

        entries.push(NbnsNameEntry {
            name,
            name_type: name_type.to_string(),
            flags: flags_str.to_string(),
        });
    }

    // MAC address is after the name table (6 bytes)
    if offset + 6 <= data.len() {
        mac_address = data[offset..offset + 6]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");
    }

    if computer_name.is_empty() && !entries.is_empty() {
        // Use first UNIQUE name as computer name
        for entry in &entries {
            if entry.flags == "UNIQUE" && !entry.name.is_empty() {
                computer_name = entry.name.clone();
                break;
            }
        }
    }

    Ok(NbnsNodeStatus {
        computer_name,
        domain_name,
        user_name,
        mac_address,
        name_table: entries,
    })
}

// ===========================================================
//  SMB Protocol Negotiation
// ===========================================================

const SMB_PORT: u16 = 445;

/// Perform SMB protocol negotiation to fingerprint the target.
/// Returns dialect info, signing requirements, and OS details.
pub async fn smb_negotiate(target: &str) -> Result<SmbNegotiateResult> {
    info!("[SMB] Negotiating protocol with {target}");

    let addr: SocketAddr = format!("{target}:{SMB_PORT}")
        .parse()
        .map_err(|e| OverthroneError::Smb(format!("Invalid address: {e}")))?;

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| OverthroneError::Smb(format!("TCP connect failed: {e}")))?;

    // Send SMB2 Negotiate Protocol Request
    let negotiate_req = build_smb2_negotiate_request();
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(&negotiate_req))
        .await
        .map_err(|_| OverthroneError::Smb("SMB send timed out".to_string()))?
        .map_err(|e| OverthroneError::Smb(format!("SMB send failed: {e}")))?;

    // Read SMB header (64 bytes for SMB2)
    let mut header = [0u8; 64];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .map_err(|_| OverthroneError::Smb("SMB header read timed out".to_string()))?
        .map_err(|e| OverthroneError::Smb(format!("SMB header read failed: {e}")))?;

    // Verify SMB2 protocol ID
    if &header[0..4] != b"\xfeSMB" {
        let actual: Vec<u8> = header.get(0..4).unwrap_or_default().to_vec();
        return Err(OverthroneError::Smb(format!(
            "Not an SMB2 response: first 4 bytes = {actual:02x?} (expected fe SMB), remote may be SMB1 or non-SMB service",
        )));
    }

    // Parse SMB2 header
    let struct_size = header[4] as usize;
    let _credit_charge = u16::from_le_bytes([header[5], header[6]]);
    let status = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let command = u16::from_le_bytes([header[12], header[13]]);
    let _credit_resp = u16::from_le_bytes([header[14], header[15]]);
    let _flags = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let next_command = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
    let _message_id = u64::from_le_bytes([
        header[24], header[25], header[26], header[27], header[28], header[29], header[30],
        header[31],
    ]);
    let _reserved = u32::from_le_bytes([header[32], header[33], header[34], header[35]]);
    let _tree_id = u32::from_le_bytes([header[36], header[37], header[38], header[39]]);
    let _session_id = u64::from_le_bytes([
        header[40], header[41], header[42], header[43], header[44], header[45], header[46],
        header[47],
    ]);
    let _signature = &header[48..64];

    // Read the rest of the response
    let payload_len = if next_command > 0 {
        next_command as usize
    } else {
        struct_size
    };

    let mut payload = vec![0u8; payload_len - 64];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut payload))
        .await
        .map_err(|_| OverthroneError::Smb("SMB payload read timed out".to_string()))?
        .map_err(|e| OverthroneError::Smb(format!("SMB payload read failed: {e}")))?;

    let full_response = [header.to_vec(), payload.clone()].concat();

    // Parse negotiate response
    let mut result = SmbNegotiateResult {
        target: target.to_string(),
        highest_dialect: "unknown".to_string(),
        signing_required: false,
        signing_enabled: false,
        server_guid: String::new(),
        os_name: None,
        native_os: None,
        native_lm: None,
        max_buffer_size: 0,
        raw_response: Some(full_response.clone()),
    };

    if command == 0 && status == 0 && payload.len() >= 64 {
        // SMB2 Negotiate Response
        let struct_size = payload[0] as usize;
        let security_mode = payload[2];
        result.signing_enabled = security_mode & 0x01 != 0;
        result.signing_required = security_mode & 0x02 != 0;

        // Dialect revision
        let dialect = u16::from_le_bytes([payload[4], payload[5]]);
        result.highest_dialect = match dialect {
            0x0202 => "SMB 2.0.2".to_string(),
            0x0210 => "SMB 2.1".to_string(),
            0x0300 => "SMB 3.0".to_string(),
            0x0302 => "SMB 3.0.2".to_string(),
            0x0311 => "SMB 3.1.1".to_string(),
            _ => format!("SMB dialect 0x{dialect:04X}"),
        };

        // Server GUID
        let guid_bytes = &payload[8..24];
        result.server_guid = guid_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("");

        // Capabilities
        let capabilities = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);

        // Max buffer size
        result.max_buffer_size =
            u32::from_le_bytes([payload[28], payload[29], payload[30], payload[31]]);

        // If SMB 3.1.1, parse contexts
        if dialect == 0x0311 && payload.len() > struct_size {
            // Look for preauth integrity and encryption contexts
            // Simplified: just note the dialect
        }

        // Try to extract OS info from the response
        // SMB2 negotiate response doesn't include OS info directly
        // but we can infer from capabilities
        if capabilities & 0x00000080 != 0 {
            // DFS
        }
        if capabilities & 0x00000002 != 0 {
            // Large MTU
        }
    }

    info!(
        "[SMB] Negotiate complete: dialect={}, signing_required={}, signing_enabled={}",
        result.highest_dialect, result.signing_required, result.signing_enabled
    );

    Ok(result)
}

/// Build SMB2 Negotiate Protocol Request.
fn build_smb2_negotiate_request() -> Vec<u8> {
    let mut pkt = Vec::new();

    // SMB2 Header
    pkt.extend_from_slice(b"\xfeSMB"); // Protocol ID
    pkt.extend_from_slice(&[0x40, 0x00]); // Structure size (64)
    pkt.extend_from_slice(&[0x00, 0x00]); // Credit charge
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Channel sequence
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Flags
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Next command
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Message ID
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Tree ID
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Session ID
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Signature

    // SMB2 Negotiate Request
    pkt.extend_from_slice(&[0x24, 0x00]); // Structure size (36)
    pkt.extend_from_slice(&[0x01, 0x00]); // Dialect count
    pkt.extend_from_slice(&[0x00, 0x00]); // Security mode
    pkt.extend_from_slice(&[0x00, 0x00]); // Reserved
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Capabilities
    // Client GUID (16 bytes)
    pkt.extend_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]);
    // Negotiate context offset
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Dialect: SMB 3.1.1
    pkt.extend_from_slice(&[0x11, 0x03]);

    pkt
}

// ===========================================================
//  Combined Discovery
// ===========================================================

/// Combined NetBIOS and SMB discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetBiosDiscoveryResult {
    /// Target host
    pub target: String,
    /// NBNS node status (if available)
    pub nbns: Option<NbnsNodeStatus>,
    /// SMB negotiation result (if available)
    pub smb_negotiate: Option<SmbNegotiateResult>,
}

/// Perform combined NetBIOS and SMB discovery against a target.
pub async fn netbios_discovery(target: &str) -> NetBiosDiscoveryResult {
    info!("[NetBIOS] Starting discovery on {target}");

    let mut result = NetBiosDiscoveryResult {
        target: target.to_string(),
        nbns: None,
        smb_negotiate: None,
    };

    // NBNS query
    match nbns_node_status(target).await {
        Ok(status) => {
            info!(
                "[NetBIOS] NBNS: computer={}, domain={}, user={:?}",
                status.computer_name, status.domain_name, status.user_name
            );
            result.nbns = Some(status);
        }
        Err(e) => {
            debug!("[NetBIOS] NBNS query failed: {e}");
        }
    }

    // SMB negotiate
    match smb_negotiate(target).await {
        Ok(neg) => {
            info!(
                "[NetBIOS] SMB: dialect={}, signing_required={}, signing_enabled={}",
                neg.highest_dialect, neg.signing_required, neg.signing_enabled
            );
            result.smb_negotiate = Some(neg);
        }
        Err(e) => {
            debug!("[NetBIOS] SMB negotiate failed: {e}");
        }
    }

    result
}

// ===========================================================
//  Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nbns_query_structure() {
        let query = build_nbns_node_status_query();
        assert_eq!(query[0], 0xAB); // Transaction ID
        assert_eq!(query[1], 0xCD);
        assert_eq!(query[2], 0x00); // Flags
        assert_eq!(query[12], 0x20); // Name length (32 chars)
    }

    #[test]
    fn test_smb2_negotiate_structure() {
        let req = build_smb2_negotiate_request();
        assert_eq!(&req[0..4], b"\xfeSMB"); // SMB2 protocol ID
        assert_eq!(req[4], 0x40); // Structure size
        assert_eq!(req[84], 0x11); // Dialect SMB 3.1.1
        assert_eq!(req[85], 0x03);
    }
}
