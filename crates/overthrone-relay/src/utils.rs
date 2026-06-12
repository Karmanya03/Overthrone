//! Utility functions for NTLM relay and responder
//!
//! Provides helper functions for NTLM calculations,
//! challenge generation, and response validation using
//! the full NTLMv2 implementation from overthrone-core.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::{NtlmChallenge, NtlmResponse, RelayError, Result};
use overthrone_core::proto::ntlm;
use tokio::net::TcpStream;
use tokio_socks::tcp::socks5::Socks5Stream;

/// Format an IP address and port into a `host:port` string
/// suitable for `TcpStream::connect` or `TcpListener::bind`.
///
/// Correctly brackets IPv6 addresses (`[::1]:445`) while
/// leaving IPv4 and hostnames plain (`192.168.1.1:445`).
pub fn format_addr(ip: &str, port: u16) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{ip}]:{port}"),
        _ => format!("{ip}:{port}"),
    }
}

/// Connect to a target address, optionally via SOCKS5 proxy.
/// When `socks5` is `Some`, routes through the SOCKS5 proxy at `host:port`.
/// Otherwise connects directly via TCP.
pub async fn socks5_connect(
    target: SocketAddr,
    timeout: Duration,
    socks5: Option<&str>,
) -> std::result::Result<TcpStream, RelayError> {
    match socks5 {
        Some(proxy) => {
            let proxy_addr: SocketAddr = proxy.parse().map_err(|e| {
                RelayError::Config(format!("Invalid SOCKS5 proxy '{}': {}", proxy, e))
            })?;
            let socks5_stream =
                tokio::time::timeout(timeout, Socks5Stream::connect(proxy_addr, target))
                    .await
                    .map_err(|_| {
                        RelayError::Connection(format!(
                            "Timeout connecting to {} via SOCKS5 proxy {}",
                            target, proxy
                        ))
                    })?
                    .map_err(|e| {
                        RelayError::Connection(format!(
                            "SOCKS5 connect to {} via {}: {}",
                            target, proxy, e
                        ))
                    })?;
            Ok(socks5_stream.into_inner())
        }
        None => tokio::time::timeout(timeout, TcpStream::connect(target))
            .await
            .map_err(|_| RelayError::Connection(format!("Timeout connecting to {}", target)))?
            .map_err(|e| RelayError::Connection(format!("Connect to {}: {}", target, e))),
    }
}

/// Synchronous SOCKS5-aware TCP connect for sync contexts (std threads).
/// Uses manual SOCKS5 handshake over `std::net::TcpStream`.
pub fn socks5_connect_sync(
    target: SocketAddr,
    timeout: Duration,
    socks5: Option<&str>,
) -> std::result::Result<std::net::TcpStream, RelayError> {
    match socks5 {
        Some(proxy) => {
            let proxy_addr: SocketAddr = proxy.parse().map_err(|e| {
                RelayError::Config(format!("Invalid SOCKS5 proxy '{}': {}", proxy, e))
            })?;
            let mut s = std::net::TcpStream::connect_timeout(&proxy_addr, timeout)
                .map_err(|e| RelayError::Connection(format!("SOCKS5 proxy connect: {e}")))?;
            s.set_read_timeout(Some(timeout)).ok();
            s.set_write_timeout(Some(timeout)).ok();

            use std::io::{Read, Write};

            // SOCKS5 handshake: greet
            s.write_all(&[0x05, 0x01, 0x00])
                .map_err(|e| RelayError::Connection(format!("SOCKS5 greet: {e}")))?;
            let mut resp = [0u8; 2];
            s.read_exact(&mut resp)
                .map_err(|e| RelayError::Connection(format!("SOCKS5 greet response: {e}")))?;
            if resp != [0x05, 0x00] {
                return Err(RelayError::Connection(format!(
                    "SOCKS5 server rejected greeting: {:02x?}",
                    resp
                )));
            }

            // SOCKS5 connect request
            let addr_bytes = match target {
                SocketAddr::V4(v4) => {
                    let mut b = Vec::with_capacity(10);
                    b.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
                    b.extend_from_slice(&v4.ip().octets());
                    b.extend_from_slice(&v4.port().to_be_bytes());
                    b
                }
                SocketAddr::V6(v6) => {
                    let mut b = Vec::with_capacity(22);
                    b.extend_from_slice(&[0x05, 0x01, 0x00, 0x04]);
                    b.extend_from_slice(&v6.ip().octets());
                    b.extend_from_slice(&v6.port().to_be_bytes());
                    b
                }
            };
            s.write_all(&addr_bytes)
                .map_err(|e| RelayError::Connection(format!("SOCKS5 connect: {e}")))?;

            let mut conn_resp = [0u8; 4];
            s.read_exact(&mut conn_resp)
                .map_err(|e| RelayError::Connection(format!("SOCKS5 connect response: {e}")))?;
            if conn_resp[1] != 0x00 {
                return Err(RelayError::Connection(format!(
                    "SOCKS5 connect failed: status={:02x}",
                    conn_resp[1]
                )));
            }
            // Read remaining response (bind address + port)
            let bind_len = match conn_resp[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut len = [0u8; 1];
                    s.read_exact(&mut len).ok();
                    len[0] as usize
                }
                _ => return Err(RelayError::Connection("Unknown SOCKS5 address type".into())),
            };
            let mut _bind_extra = vec![0u8; bind_len + 2];
            let _ = s.read_exact(&mut _bind_extra);

            Ok(s)
        }
        None => std::net::TcpStream::connect_timeout(&target, timeout)
            .map_err(|e| RelayError::Connection(format!("Connect to {}: {}", target, e))),
    }
}

/// Calculate NTLMv2 response for a given challenge.
/// This is used for offline cracking validation — NOT for relay
/// (relay forwards the victim's response directly).
pub fn calculate_ntlmv2_response(
    username: &str,
    domain: &str,
    password: &str,
    challenge: &NtlmChallenge,
) -> Result<NtlmResponse> {
    // Compute the NT hash, then NTLMv2 hash
    let nt_hash = ntlm::nt_hash(password);
    let v2_hash = ntlm::ntlmv2_hash(&nt_hash, username, domain);

    // Generate random client challenge
    let client_challenge: [u8; 8] = rand::random();

    // Build a client blob with current timestamp
    let timestamp = ntlm::windows_filetime_now();
    let client_blob = ntlm::build_ntlmv2_client_blob(timestamp, &client_challenge, &[]);

    // Compute NTLMv2 response
    let server_challenge: [u8; 8] = challenge.data[..8].try_into().unwrap_or([0u8; 8]);
    let nt_response = ntlm::ntlmv2_response(&v2_hash, &server_challenge, &client_blob);

    // Compute LMv2 response
    let lm_response = ntlm::lmv2_response(&v2_hash, &server_challenge, &client_challenge);

    Ok(NtlmResponse {
        username: username.to_string(),
        domain: domain.to_string(),
        lm_response,
        nt_response,
    })
}

/// Generate random 8-byte NTLM server challenge
pub fn generate_challenge() -> NtlmChallenge {
    let challenge_data: [u8; 8] = rand::random();

    NtlmChallenge {
        data: challenge_data.to_vec(),
        target_name: "OVERTHRONE".to_string(),
    }
}

/// Validate an NTLMv2 response against a known password
pub fn validate_ntlm_response(
    response: &NtlmResponse,
    challenge: &NtlmChallenge,
    expected_password: &str,
) -> Result<bool> {
    // Compute expected NTLMv2 hash
    let nt_hash = ntlm::nt_hash(expected_password);
    let v2_hash = ntlm::ntlmv2_hash(&nt_hash, &response.username, &response.domain);

    // The NTLMv2 response = NTProofStr(16) + ClientBlob(variable)
    if response.nt_response.len() < 16 {
        return Ok(false);
    }

    let nt_proof_str = &response.nt_response[..16];
    let client_blob = &response.nt_response[16..];

    // Recompute NTProofStr: HMAC-MD5(v2_hash, challenge + client_blob)
    let server_challenge: [u8; 8] = challenge.data[..8].try_into().unwrap_or([0u8; 8]);
    let expected_response = ntlm::ntlmv2_response(&v2_hash, &server_challenge, client_blob);
    let expected_proof = &expected_response[..16];

    // Constant-time comparison would be better, but for a red-team tool this is fine
    Ok(nt_proof_str == expected_proof)
}

/// Parse NTLM message type from raw bytes
pub fn parse_ntlm_message_type(data: &[u8]) -> Option<u8> {
    if data.len() < 12 {
        return None;
    }

    if &data[0..8] != b"NTLMSSP\x00" {
        return None;
    }

    // Message type is a u32 at offset 8, but we return only the low byte
    // since types are 1, 2, 3
    Some(data[8])
}

/// Extract domain from NTLM target info AV_PAIR list
pub fn extract_domain_from_target_info(target_info: &[u8]) -> Option<String> {
    // AV_PAIR: AvId(u16) + AvLen(u16) + Value(AvLen bytes)
    // MsvAvNbDomainName = 0x0002
    let mut pos = 0;
    while pos + 4 <= target_info.len() {
        let av_id = u16::from_le_bytes([target_info[pos], target_info[pos + 1]]);
        let av_len = u16::from_le_bytes([target_info[pos + 2], target_info[pos + 3]]) as usize;
        pos += 4;

        if av_id == 0x0000 {
            break; // MsvAvEOL
        }

        if pos + av_len > target_info.len() {
            break;
        }

        if av_id == 0x0002 {
            // MsvAvNbDomainName — UTF-16LE
            let domain_chars: Vec<u16> = target_info[pos..pos + av_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return Some(String::from_utf16_lossy(&domain_chars));
        }

        pos += av_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_addr_ipv4() {
        assert_eq!(format_addr("192.168.1.1", 445), "192.168.1.1:445");
    }

    #[test]
    fn test_format_addr_ipv6() {
        assert_eq!(format_addr("::1", 389), "[::1]:389");
        assert_eq!(format_addr("fe80::1", 80), "[fe80::1]:80");
    }

    #[test]
    fn test_format_addr_unspecified() {
        assert_eq!(format_addr("0.0.0.0", 445), "0.0.0.0:445");
        assert_eq!(format_addr("::", 80), "[::]:80");
    }

    #[test]
    fn test_format_addr_hostname() {
        // Hostnames are passed through as-is
        let result = format_addr("dc01.corp.local", 445);
        assert_eq!(result, "dc01.corp.local:445");
    }

    #[test]
    fn test_format_addr_loopback() {
        assert_eq!(format_addr("127.0.0.1", 8080), "127.0.0.1:8080");
        assert_eq!(format_addr("::1", 443), "[::1]:443");
    }

    const TEST_USER: &str = "testuser";
    const TEST_DOMAIN: &str = "TEST";
    const TEST_PASSWORD: &str = "NtlmV2TestPwd!";

    #[test]
    fn test_generate_challenge() {
        let challenge = generate_challenge();
        assert_eq!(challenge.data.len(), 8);
        assert_eq!(challenge.target_name, "OVERTHRONE");

        // Two challenges should be different (random)
        let challenge2 = generate_challenge();
        assert_ne!(challenge.data, challenge2.data);
    }

    #[test]
    fn test_parse_ntlm_message_type_valid() {
        let mut data = b"NTLMSSP\0".to_vec();
        data.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(parse_ntlm_message_type(&data), Some(0x01));
    }

    #[test]
    fn test_parse_ntlm_message_type_invalid() {
        let data = b"INVALID\0\x01\x00\x00\x00";
        assert_eq!(parse_ntlm_message_type(data), None);
    }

    #[test]
    fn test_parse_ntlm_message_type_too_short() {
        let data = b"NTLM";
        assert_eq!(parse_ntlm_message_type(data), None);
    }

    #[test]
    fn test_extract_domain_from_target_info() {
        // Build a minimal AV_PAIR list:
        // MsvAvNbDomainName(0x0002) + len=8 + "TEST" in UTF-16LE
        // MsvAvEOL(0x0000) + len=0
        let mut info = Vec::new();
        info.extend_from_slice(&0x0002u16.to_le_bytes()); // AvId = NbDomainName
        info.extend_from_slice(&8u16.to_le_bytes()); // AvLen = 8 bytes
        for c in "TEST".encode_utf16() {
            info.extend_from_slice(&c.to_le_bytes());
        }
        info.extend_from_slice(&0x0000u16.to_le_bytes()); // AvId = EOL
        info.extend_from_slice(&0u16.to_le_bytes()); // AvLen = 0

        assert_eq!(
            extract_domain_from_target_info(&info),
            Some("TEST".to_string())
        );
    }

    #[test]
    fn test_extract_domain_empty_info() {
        // Just an EOL pair
        let info = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(extract_domain_from_target_info(&info), None);
    }

    #[test]
    fn test_calculate_ntlmv2_response_format() {
        let challenge = NtlmChallenge {
            data: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            target_name: "TEST".to_string(),
        };

        let response =
            calculate_ntlmv2_response(TEST_USER, TEST_DOMAIN, TEST_PASSWORD, &challenge).unwrap();
        assert_eq!(response.username, TEST_USER);
        assert_eq!(response.domain, TEST_DOMAIN);
        // NTLMv2 response = NTProofStr(16) + ClientBlob(28+)
        assert!(response.nt_response.len() >= 44);
        // LMv2 response is always 24 bytes
        assert_eq!(response.lm_response.len(), 24);
    }

    #[test]
    fn test_validate_ntlm_response_correct_password() {
        let challenge = NtlmChallenge {
            data: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
            target_name: "CORP".to_string(),
        };

        let response =
            calculate_ntlmv2_response(TEST_USER, TEST_DOMAIN, TEST_PASSWORD, &challenge).unwrap();
        let valid = validate_ntlm_response(&response, &challenge, TEST_PASSWORD).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_validate_ntlm_response_wrong_password() {
        let challenge = NtlmChallenge {
            data: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
            target_name: "CORP".to_string(),
        };

        let response =
            calculate_ntlmv2_response(TEST_USER, TEST_DOMAIN, TEST_PASSWORD, &challenge).unwrap();
        let valid = validate_ntlm_response(&response, &challenge, "WrongPwd!").unwrap();
        assert!(!valid);
    }
}
