//! Pure-Rust SMB2/3 client — replaces pavao (C/libsmbclient) for cross-platform support.
//!
//! Implements the minimum viable subset of MS-SMB2 needed by Overthrone:
//!   • Negotiate (SMB 2.1 / 3.0.2)
//!   • Session Setup with NTLMSSP (NTLMv2)
//!   • Tree Connect / Disconnect
//!   • Create, Read, Write, Close (files & named pipes)
//!   • IOCTL (FSCTL_PIPE_TRANSCEIVE for DCE/RPC)
//!   • Query Directory (for list_directory)
//!
//! References:
//!   MS-SMB2: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/>
//!   MS-NLMP: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>

use crate::error::{OverthroneError, Result};
use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use md4::{Digest as Md4Digest, Md4};
use md5::Md5;
use rand::Rng;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, trace};

type HmacMd5 = Hmac<Md5>;

// ═══════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
const SMB2_HEADER_SIZE: usize = 64;

// SMB2 Commands
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

// SMB2 Dialects
const SMB2_DIALECT_210: u16 = 0x0210; // SMB 2.1
const SMB2_DIALECT_300: u16 = 0x0300; // SMB 3.0
const SMB2_DIALECT_302: u16 = 0x0302; // SMB 3.0.2

// SMB2 Flags
#[allow(dead_code)] // Protocol reference constants
const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

// NTLMSSP
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NTLMSSP_NEGOTIATE: u32 = 1;
const NTLMSSP_CHALLENGE: u32 = 2;
const NTLMSSP_AUTH: u32 = 3;

// Negotiate flags
const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;

// File access masks
#[allow(dead_code)] // Protocol reference constants kept for completeness
const FILE_READ_DATA: u32 = 0x0000_0001;
#[allow(dead_code)]
const FILE_WRITE_DATA: u32 = 0x0000_0002;
#[allow(dead_code)]
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const SYNCHRONIZE: u32 = 0x0010_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
#[allow(dead_code)]
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const DELETE_ACCESS: u32 = 0x0001_0000;

// File attributes & options
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

// Create dispositions
const FILE_OPEN: u32 = 0x0000_0001;
#[allow(dead_code)]
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;
#[allow(dead_code)]
const FILE_SUPERSEDE: u32 = 0x0000_0000;

// IOCTL
const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

// Query directory
const FILE_DIRECTORY_INFORMATION: u8 = 1;
#[allow(dead_code)]
const FILE_ID_BOTH_DIR_INFORMATION: u8 = 37;

// SPNEGO OIDs
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const NTLMSSP_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];
// Kerberos OID: 1.2.840.113554.1.2.2
const KERBEROS_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

// Status codes
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;

// ═══════════════════════════════════════════════════════════
//  SMB2 Connection — TCP Transport
// ═══════════════════════════════════════════════════════════

/// A low-level SMB2 connection over TCP.
pub struct Smb2Connection {
    stream: Mutex<TcpStream>,
    message_id: AtomicU64,
    session_id: Mutex<u64>,
    tree_id: Mutex<u32>,
    /// NTLMSSP session base key (16 bytes) — needed for DCSync and signing
    session_key: Mutex<Option<Vec<u8>>>,
    /// Whether the server requires packet signing
    sign_required: std::sync::atomic::AtomicBool,
    /// Negotiated SMB dialect (e.g. 0x0210 = SMB 2.1, 0x0300 = SMB 3.0, 0x0302 = SMB 3.0.2)
    dialect: AtomicU16,
    /// Negotiated max transaction size
    #[allow(dead_code)] // Populated during SMB2 negotiation
    max_transact_size: u32,
    /// Negotiated max read size
    max_read_size: u32,
    /// Negotiated max write size
    max_write_size: u32,
}

impl Smb2Connection {
    // ───────────────── Connection ─────────────────

    /// Open a raw TCP connection to the target's SMB port (445).
    pub async fn connect(target: &str, port: u16) -> Result<Self> {
        let addr = format!("{target}:{port}");
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| OverthroneError::Timeout(10))?
        .map_err(|e| OverthroneError::Smb(format!("SMB2 TCP connect {addr}: {e}")))?;

        stream
            .set_nodelay(true)
            .map_err(|e| OverthroneError::Smb(format!("set_nodelay: {e}")))?;

        Ok(Self {
            stream: Mutex::new(stream),
            message_id: AtomicU64::new(0),
            session_id: Mutex::new(0),
            tree_id: Mutex::new(0),
            session_key: Mutex::new(None),
            sign_required: std::sync::atomic::AtomicBool::new(false),
            dialect: AtomicU16::new(0),
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
        })
    }

    // ───────────────── Transport ─────────────────

    /// Send an SMB2 message (prepends NetBIOS session header).
    async fn send(&self, data: &[u8]) -> Result<()> {
        let mut stream = self.stream.lock().await;
        let len = data.len() as u32;
        // NetBIOS session service header: 4 bytes big-endian length
        let header = len.to_be_bytes();
        stream
            .write_all(&header)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB2 send header: {e}")))?;
        stream
            .write_all(data)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB2 send data: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB2 flush: {e}")))?;
        Ok(())
    }

    /// Receive an SMB2 response (reads NetBIOS header, then payload).
    async fn recv(&self) -> Result<Vec<u8>> {
        let mut stream = self.stream.lock().await;
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_exact(&mut len_buf),
        )
        .await
        .map_err(|_| OverthroneError::Timeout(30))?
        .map_err(|e| OverthroneError::Smb(format!("SMB2 recv header: {e}")))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(OverthroneError::Smb(format!(
                "SMB2 response too large: {len} bytes"
            )));
        }

        let mut buf = vec![0u8; len];
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_exact(&mut buf),
        )
        .await
        .map_err(|_| OverthroneError::Timeout(30))?
        .map_err(|e| OverthroneError::Smb(format!("SMB2 recv body: {e}")))?;

        Ok(buf)
    }

    /// Get the next message ID.
    fn next_message_id(&self) -> u64 {
        self.message_id.fetch_add(1, Ordering::Relaxed)
    }

    // ───────────────── SMB2 Header Builder ─────────────────

    /// Build an SMB2 header (64 bytes).
    async fn build_header(&self, command: u16, credit_charge: u16) -> Vec<u8> {
        let session_id = *self.session_id.lock().await;
        let tree_id = *self.tree_id.lock().await;
        let msg_id = self.next_message_id();

        let mut hdr = vec![0u8; SMB2_HEADER_SIZE];
        hdr[0..4].copy_from_slice(SMB2_MAGIC);
        // StructureSize = 64
        hdr[4..6].copy_from_slice(&64u16.to_le_bytes());
        // CreditCharge
        hdr[6..8].copy_from_slice(&credit_charge.to_le_bytes());
        // Status = 0 (request)
        // hdr[8..12] = 0
        // Command
        hdr[12..14].copy_from_slice(&command.to_le_bytes());
        // CreditRequest = 31
        hdr[14..16].copy_from_slice(&31u16.to_le_bytes());
        // Flags = 0 (client to server)
        // hdr[16..20] = 0
        // NextCommand = 0
        // hdr[20..24] = 0
        // MessageId
        hdr[24..32].copy_from_slice(&msg_id.to_le_bytes());
        // Reserved (for async) / ProcessId
        // hdr[32..36] = 0
        // TreeId
        hdr[36..40].copy_from_slice(&tree_id.to_le_bytes());
        // SessionId
        hdr[40..48].copy_from_slice(&session_id.to_le_bytes());
        // Signature (16 bytes) = 0 for unsigned
        // hdr[48..64] = 0

        hdr
    }

    /// Sign an SMB2/3 packet (MS-SMB2 §3.1.4.1).
    ///
    /// SMB 2.x uses HMAC-SHA256(session_key, packet)[0:16].
    /// SMB 3.x+ derives a signing key via SP800-108 KDF and uses AES-128-CMAC.
    fn sign_packet(pkt: &mut [u8], session_key: &[u8], dialect: u16) {
        // Set SMB2_FLAGS_SIGNED (bit 3) in the Flags field (bytes 16..20)
        let flags = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        let flags = flags | SMB2_FLAGS_SIGNED;
        pkt[16..20].copy_from_slice(&flags.to_le_bytes());

        // Zero the signature field before computing
        pkt[48..64].fill(0);

        if dialect >= SMB2_DIALECT_300 {
            // SMB 3.x: derive SigningKey = SP800-108(session_key, "SMBSigningKey\0", "SmbSign\0")
            let signing_key = sp800_108_counter_kdf(
                session_key,
                b"SMBSigningKey\x00",
                b"SmbSign\x00",
            );
            let sig = aes_cmac_16(&signing_key, pkt);
            pkt[48..64].copy_from_slice(&sig);
        } else {
            // SMB 2.x: HMAC-SHA256(session_key, packet)[0:16]
            let mut mac = HmacSha256::new_from_slice(session_key)
                .expect("HMAC-SHA256 accepts any key size");
            mac.update(pkt);
            let result = mac.finalize().into_bytes();
            pkt[48..64].copy_from_slice(&result[..16]);
        }
    }

    /// Send a packet, signing it first if signing is required and a session key is available.
    async fn send_signed(&self, pkt: &mut [u8]) -> Result<()> {
        if self
            .sign_required
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(ref key) = *self.session_key.lock().await
        {
            let dialect = self.dialect.load(Ordering::Relaxed);
            Self::sign_packet(pkt, key, dialect);
        }
        self.send(pkt).await
    }

    // ───────────────── Negotiate ─────────────────

    /// SMB2 Negotiate — establishes dialect (2.1 / 3.0.2).
    pub async fn negotiate(&self) -> Result<()> {
        debug!("SMB2: Negotiate");

        let hdr = self.build_header(SMB2_NEGOTIATE, 0).await;

        // Negotiate request body
        let mut body = Vec::with_capacity(64);
        // StructureSize = 36
        body.extend_from_slice(&36u16.to_le_bytes());
        // DialectCount = 3
        body.extend_from_slice(&3u16.to_le_bytes());
        // SecurityMode = Signing Enabled (0x01)
        body.extend_from_slice(&0x01u16.to_le_bytes());
        // Reserved
        body.extend_from_slice(&0u16.to_le_bytes());
        // Capabilities = 0 (no DFS, no leasing, etc.)
        body.extend_from_slice(&0u32.to_le_bytes());
        // ClientGuid (16 bytes random)
        let mut guid = [0u8; 16];
        rand::thread_rng().fill(&mut guid);
        body.extend_from_slice(&guid);
        // ClientStartTime = 0
        body.extend_from_slice(&0u64.to_le_bytes());
        // Dialects: 2.1, 3.0, 3.0.2
        body.extend_from_slice(&SMB2_DIALECT_210.to_le_bytes());
        body.extend_from_slice(&SMB2_DIALECT_300.to_le_bytes());
        body.extend_from_slice(&SMB2_DIALECT_302.to_le_bytes());

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);

        self.send(&pkt).await?;
        let resp = self.recv().await?;

        // Validate response
        if resp.len() < SMB2_HEADER_SIZE + 65 {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Negotiate response too short: {} bytes",
                resp.len()
            )));
        }

        // Check status
        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Negotiate failed: 0x{status:08X}"
            )));
        }

        // Parse negotiate response (starts at offset 64)
        let body = &resp[SMB2_HEADER_SIZE..];
        let dialect = u16::from_le_bytes([body[4], body[5]]);
        debug!("SMB2: Negotiated dialect 0x{:04X}", dialect);
        // Store dialect for use in signing key derivation
        self.dialect.store(dialect, Ordering::Relaxed);

        // SecurityMode (offset 2): bit 0 = signing enabled, bit 1 = signing required
        let server_security_mode = u16::from_le_bytes([body[2], body[3]]);
        if server_security_mode & 0x02 != 0 {
            debug!("SMB2: Server REQUIRES signing");
            self.sign_required
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // MaxTransactSize (offset 28)
        let max_transact = u32::from_le_bytes([body[28], body[29], body[30], body[31]]);
        let max_read = u32::from_le_bytes([body[32], body[33], body[34], body[35]]);
        let max_write = u32::from_le_bytes([body[36], body[37], body[38], body[39]]);
        debug!("SMB2: MaxTransact={max_transact}, MaxRead={max_read}, MaxWrite={max_write}");

        // Store server capabilities (we don't mutate self's sizes since they're not
        // behind Mutex — we use safe defaults set during construction)

        Ok(())
    }

    // ───────────────── Session Setup (NTLMSSP) ─────────────────

    /// Authenticate via NTLMSSP (NTLMv2) inside SPNEGO.
    ///
    /// Returns the 16-byte session base key on success.
    pub async fn session_setup(
        &self,
        domain: &str,
        username: &str,
        password: &str,
    ) -> Result<Vec<u8>> {
        debug!("SMB2: Session setup for {domain}\\{username}");

        // ── Step 1: Send NTLMSSP Negotiate (Type 1) ──
        let type1 = build_ntlmssp_negotiate();
        let spnego_init = wrap_spnego_init(&type1);

        let hdr = self.build_header(SMB2_SESSION_SETUP, 0).await;
        let mut body = Vec::new();
        // StructureSize = 25
        body.extend_from_slice(&25u16.to_le_bytes());
        // Flags = 0
        body.push(0);
        // SecurityMode = Signing Enabled (0x01)
        body.push(0x01);
        // Capabilities = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // Channel = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // SecurityBufferOffset (fixed at header + 24 bytes of body = 88)
        let sec_offset = (SMB2_HEADER_SIZE + 24) as u16;
        body.extend_from_slice(&sec_offset.to_le_bytes());
        // SecurityBufferLength
        body.extend_from_slice(&(spnego_init.len() as u16).to_le_bytes());
        // PreviousSessionId = 0
        body.extend_from_slice(&0u64.to_le_bytes());
        // Pad to offset 24
        while body.len() < 24 {
            body.push(0);
        }
        // Security buffer (SPNEGO token)
        body.extend_from_slice(&spnego_init);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send(&pkt).await?;
        let resp = self.recv().await?;

        if resp.len() < SMB2_HEADER_SIZE + 9 {
            return Err(OverthroneError::Smb(
                "SMB2 Session Setup Type1 response too short".to_string(),
            ));
        }

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Session Setup Type1 unexpected status: 0x{status:08X}"
            )));
        }

        // Store session ID from response
        let session_id = u64::from_le_bytes([
            resp[40], resp[41], resp[42], resp[43], resp[44], resp[45], resp[46], resp[47],
        ]);
        *self.session_id.lock().await = session_id;
        debug!("SMB2: Got session ID 0x{session_id:016X}");

        // ── Step 2: Parse NTLMSSP Challenge (Type 2) from SPNEGO response ──
        let resp_body = &resp[SMB2_HEADER_SIZE..];
        let sec_buf_offset =
            u16::from_le_bytes([resp_body[4], resp_body[5]]) as usize - SMB2_HEADER_SIZE;
        let sec_buf_len = u16::from_le_bytes([resp_body[6], resp_body[7]]) as usize;

        if sec_buf_offset + sec_buf_len > resp_body.len() {
            return Err(OverthroneError::Smb(
                "SMB2 Session Setup Type2 security buffer overflow".to_string(),
            ));
        }

        let sec_buf = &resp_body[sec_buf_offset..sec_buf_offset + sec_buf_len];
        let type2 = extract_ntlmssp_from_spnego(sec_buf)?;
        let challenge = parse_ntlmssp_challenge(&type2)?;

        // ── Step 3: Build NTLMSSP Authenticate (Type 3) ──
        let (type3, session_key) =
            build_ntlmssp_authenticate(domain, username, password, &challenge)?;
        let spnego_resp = wrap_spnego_response(&type3);

        // Send authentication
        let hdr = self.build_header(SMB2_SESSION_SETUP, 0).await;
        let mut body = Vec::new();
        body.extend_from_slice(&25u16.to_le_bytes());
        body.push(0);
        body.push(0x01);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let sec_offset = (SMB2_HEADER_SIZE + 24) as u16;
        body.extend_from_slice(&sec_offset.to_le_bytes());
        body.extend_from_slice(&(spnego_resp.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        while body.len() < 24 {
            body.push(0);
        }
        body.extend_from_slice(&spnego_resp);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send(&pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Auth(format!(
                "SMB2 NTLMSSP auth failed for {domain}\\{username}: 0x{status:08X}"
            )));
        }

        debug!("SMB2: Authenticated as {domain}\\{username}");

        // Store session key
        *self.session_key.lock().await = Some(session_key.clone());

        Ok(session_key)
    }

    /// Authenticate using pass-the-hash (raw NT hash, 32 hex chars).
    pub async fn session_setup_hash(
        &self,
        domain: &str,
        username: &str,
        nt_hash_hex: &str,
    ) -> Result<Vec<u8>> {
        debug!("SMB2: Session setup PtH for {domain}\\{username}");

        let nt_hash = hex::decode(nt_hash_hex)
            .map_err(|e| OverthroneError::Smb(format!("Invalid NT hash hex: {e}")))?;
        if nt_hash.len() != 16 {
            return Err(OverthroneError::Smb(format!(
                "NT hash must be 16 bytes, got {}",
                nt_hash.len()
            )));
        }

        // ── Step 1: Negotiate Type 1 ──
        let type1 = build_ntlmssp_negotiate();
        let spnego_init = wrap_spnego_init(&type1);

        let hdr = self.build_header(SMB2_SESSION_SETUP, 0).await;
        let mut body = Vec::new();
        body.extend_from_slice(&25u16.to_le_bytes());
        body.push(0);
        body.push(0x01);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let sec_offset = (SMB2_HEADER_SIZE + 24) as u16;
        body.extend_from_slice(&sec_offset.to_le_bytes());
        body.extend_from_slice(&(spnego_init.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        while body.len() < 24 {
            body.push(0);
        }
        body.extend_from_slice(&spnego_init);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send(&pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(OverthroneError::Smb(format!(
                "SMB2 PtH Session Setup Type1: 0x{status:08X}"
            )));
        }

        let session_id = u64::from_le_bytes([
            resp[40], resp[41], resp[42], resp[43], resp[44], resp[45], resp[46], resp[47],
        ]);
        *self.session_id.lock().await = session_id;

        // ── Step 2: Parse challenge ──
        let resp_body = &resp[SMB2_HEADER_SIZE..];
        let sec_buf_offset =
            u16::from_le_bytes([resp_body[4], resp_body[5]]) as usize - SMB2_HEADER_SIZE;
        let sec_buf_len = u16::from_le_bytes([resp_body[6], resp_body[7]]) as usize;
        let sec_buf = &resp_body[sec_buf_offset..sec_buf_offset + sec_buf_len];
        let type2 = extract_ntlmssp_from_spnego(sec_buf)?;
        let challenge = parse_ntlmssp_challenge(&type2)?;

        // ── Step 3: Build Type 3 with raw NT hash (no password needed) ──
        let (type3, session_key) =
            build_ntlmssp_authenticate_hash(domain, username, &nt_hash, &challenge)?;
        let spnego_resp = wrap_spnego_response(&type3);

        let hdr = self.build_header(SMB2_SESSION_SETUP, 0).await;
        let mut body = Vec::new();
        body.extend_from_slice(&25u16.to_le_bytes());
        body.push(0);
        body.push(0x01);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let sec_offset = (SMB2_HEADER_SIZE + 24) as u16;
        body.extend_from_slice(&sec_offset.to_le_bytes());
        body.extend_from_slice(&(spnego_resp.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        while body.len() < 24 {
            body.push(0);
        }
        body.extend_from_slice(&spnego_resp);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send(&pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Auth(format!(
                "SMB2 PtH auth failed for {domain}\\{username}: 0x{status:08X}"
            )));
        }

        *self.session_key.lock().await = Some(session_key.clone());
        debug!("SMB2: PtH authenticated as {domain}\\{username}");
        Ok(session_key)
    }

    /// Authenticate using a Kerberos AP-REQ (SPNEGO wrapped).
    /// `ap_req_bytes` is the DER-encoded AP-REQ from kerberos::build_ap_req_bytes.
    /// `session_key` is the Kerberos session key from the service ticket.
    pub async fn session_setup_kerberos(
        &self,
        ap_req_bytes: &[u8],
        session_key: &[u8],
    ) -> Result<Vec<u8>> {
        debug!("SMB2: Kerberos session setup");

        let spnego_init = wrap_spnego_kerberos(ap_req_bytes);

        let hdr = self.build_header(SMB2_SESSION_SETUP, 0).await;
        let mut body = Vec::new();
        body.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
        body.push(0); // Flags
        body.push(0x01); // SecurityMode = Signing Enabled
        body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        body.extend_from_slice(&0u32.to_le_bytes()); // Channel
        let sec_offset = (SMB2_HEADER_SIZE + 24) as u16;
        body.extend_from_slice(&sec_offset.to_le_bytes());
        body.extend_from_slice(&(spnego_init.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
        while body.len() < 24 {
            body.push(0);
        }
        body.extend_from_slice(&spnego_init);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send(&pkt).await?;
        let resp = self.recv().await?;

        if resp.len() < SMB2_HEADER_SIZE {
            return Err(OverthroneError::Smb(
                "SMB2 Kerberos Session Setup response too short".to_string(),
            ));
        }

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS && status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(OverthroneError::Auth(format!(
                "SMB2 Kerberos auth failed: 0x{status:08X}"
            )));
        }

        // Store session ID
        let session_id = u64::from_le_bytes([
            resp[40], resp[41], resp[42], resp[43], resp[44], resp[45], resp[46], resp[47],
        ]);
        *self.session_id.lock().await = session_id;
        debug!("SMB2: Kerberos session ID 0x{session_id:016X}");

        // Use the Kerberos session key as the SMB session key
        let key = session_key.to_vec();
        *self.session_key.lock().await = Some(key.clone());

        Ok(key)
    }

    // ───────────────── Tree Connect ─────────────────

    /// Connect to a share (e.g. `\\target\IPC$`).
    pub async fn tree_connect(&self, share_path: &str) -> Result<u32> {
        debug!("SMB2: Tree connect to {share_path}");

        let hdr = self.build_header(SMB2_TREE_CONNECT, 0).await;
        let path_utf16: Vec<u8> = share_path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut body = Vec::new();
        // StructureSize = 9
        body.extend_from_slice(&9u16.to_le_bytes());
        // Reserved/Flags
        body.extend_from_slice(&0u16.to_le_bytes());
        // PathOffset (header + 8 bytes of body = 72)
        let path_offset = (SMB2_HEADER_SIZE + 8) as u16;
        body.extend_from_slice(&path_offset.to_le_bytes());
        // PathLength
        body.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
        // Path
        body.extend_from_slice(&path_utf16);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Tree connect to {share_path} failed: 0x{status:08X}"
            )));
        }

        let tree_id = u32::from_le_bytes([resp[36], resp[37], resp[38], resp[39]]);
        *self.tree_id.lock().await = tree_id;
        debug!("SMB2: Tree ID 0x{tree_id:08X} for {share_path}");
        Ok(tree_id)
    }

    /// Disconnect from the current tree.
    pub async fn tree_disconnect(&self) -> Result<()> {
        let hdr = self.build_header(SMB2_TREE_DISCONNECT, 0).await;
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let _resp = self.recv().await?;
        *self.tree_id.lock().await = 0;
        Ok(())
    }

    // ───────────────── Create (Open) ─────────────────

    /// Open a file or named pipe. Returns (file_id_persistent, file_id_volatile).
    pub async fn create(
        &self,
        path: &str,
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> Result<[u8; 32]> {
        trace!("SMB2: Create '{path}'");

        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let hdr = self.build_header(SMB2_CREATE, 0).await;
        let mut body = Vec::new();
        // StructureSize = 57
        body.extend_from_slice(&57u16.to_le_bytes());
        // SecurityFlags = 0
        body.push(0);
        // RequestedOplockLevel = 0 (none)
        body.push(0);
        // ImpersonationLevel = Impersonation (2)
        body.extend_from_slice(&2u32.to_le_bytes());
        // SmbCreateFlags (8 bytes) = 0
        body.extend_from_slice(&0u64.to_le_bytes());
        // Reserved = 0
        body.extend_from_slice(&0u64.to_le_bytes());
        // DesiredAccess
        body.extend_from_slice(&desired_access.to_le_bytes());
        // FileAttributes
        body.extend_from_slice(&file_attributes.to_le_bytes());
        // ShareAccess
        body.extend_from_slice(&share_access.to_le_bytes());
        // CreateDisposition
        body.extend_from_slice(&create_disposition.to_le_bytes());
        // CreateOptions
        body.extend_from_slice(&create_options.to_le_bytes());
        // NameOffset (header + 56 bytes of body = 120)
        let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
        body.extend_from_slice(&name_offset.to_le_bytes());
        // NameLength
        body.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
        // CreateContextsOffset = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // CreateContextsLength = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // Pad body to NameOffset
        while body.len() < 56 {
            body.push(0);
        }
        // File name
        body.extend_from_slice(&path_utf16);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Create '{path}' failed: 0x{status:08X}"
            )));
        }

        // File ID is at response body offset 64 (persistent) + 72 (volatile) = 16 bytes each
        // Response body starts at SMB2_HEADER_SIZE
        let rb = &resp[SMB2_HEADER_SIZE..];
        // FileId: Persistent (8 bytes at offset 64) + Volatile (8 bytes at offset 72)
        // In the Create response body: offset 64 from start of response body
        if rb.len() < 80 {
            return Err(OverthroneError::Smb(
                "SMB2 Create response too short for FileId".to_string(),
            ));
        }

        let mut file_id = [0u8; 32];
        // SMB2 CREATE response: FileId starts at body offset 64
        // But StructureSize(2) + OplockLevel(1) + Flags(1) + CreateAction(4) +
        // CreationTime(8) + LastAccessTime(8) + LastWriteTime(8) + ChangeTime(8) +
        // AllocationSize(8) + EndofFile(8) + FileAttributes(4) + Reserved2(4) = 64
        // Then FileId(16) + CreateContextsOffset(4) + CreateContextsLength(4)
        file_id[..16].copy_from_slice(&rb[64..80]);

        trace!("SMB2: Opened '{path}' => FileId {:02x?}", &file_id[..16]);
        Ok(file_id)
    }

    /// Open a named pipe for read/write (e.g. "srvsvc", "samr", "lsarpc").
    pub async fn open_pipe(&self, pipe_name: &str) -> Result<[u8; 32]> {
        self.create(
            pipe_name,
            FILE_READ_DATA | FILE_WRITE_DATA,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            0,
        )
        .await
    }

    /// Open a file for reading.
    pub async fn open_file_read(&self, path: &str) -> Result<[u8; 32]> {
        self.create(
            path,
            GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        )
        .await
    }

    /// Open a file for writing (create/overwrite).
    pub async fn open_file_write(&self, path: &str) -> Result<[u8; 32]> {
        self.create(
            path,
            GENERIC_WRITE | GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE,
        )
        .await
    }

    /// Open a directory for listing.
    pub async fn open_directory(&self, path: &str) -> Result<[u8; 32]> {
        let p = if path.is_empty() { "" } else { path };
        self.create(
            p,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
        )
        .await
    }

    // ───────────────── Close ─────────────────

    /// Close a file or pipe handle.
    pub async fn close(&self, file_id: &[u8; 32]) -> Result<()> {
        let hdr = self.build_header(SMB2_CLOSE, 0).await;
        let mut body = Vec::new();
        // StructureSize = 24
        body.extend_from_slice(&24u16.to_le_bytes());
        // Flags = 0
        body.extend_from_slice(&0u16.to_le_bytes());
        // Reserved = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // FileId (16 bytes)
        body.extend_from_slice(&file_id[..16]);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let _resp = self.recv().await?;
        Ok(())
    }

    // ───────────────── Read ─────────────────

    /// Read data from an open file/pipe. Returns bytes read.
    pub async fn read(&self, file_id: &[u8; 32], offset: u64, length: u32) -> Result<Vec<u8>> {
        let hdr = self.build_header(SMB2_READ, 0).await;
        let mut body = Vec::new();
        // StructureSize = 49
        body.extend_from_slice(&49u16.to_le_bytes());
        // Padding = 0x50
        body.push(0x50);
        // Flags (SMB 3.x) = 0
        body.push(0);
        // Length
        body.extend_from_slice(&length.to_le_bytes());
        // Offset
        body.extend_from_slice(&offset.to_le_bytes());
        // FileId (16 bytes)
        body.extend_from_slice(&file_id[..16]);
        // MinimumCount = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // Channel = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // RemainingBytes = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // ReadChannelInfoOffset = 0
        body.extend_from_slice(&0u16.to_le_bytes());
        // ReadChannelInfoLength = 0
        body.extend_from_slice(&0u16.to_le_bytes());
        // Buffer (1 byte minimum)
        body.push(0);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Read failed: 0x{status:08X}"
            )));
        }

        let rb = &resp[SMB2_HEADER_SIZE..];
        let data_offset = rb[2] as usize - SMB2_HEADER_SIZE;
        let data_length = u32::from_le_bytes([rb[4], rb[5], rb[6], rb[7]]) as usize;

        if data_offset + data_length > rb.len() {
            return Err(OverthroneError::Smb(
                "SMB2 Read response data overflow".to_string(),
            ));
        }

        Ok(rb[data_offset..data_offset + data_length].to_vec())
    }

    /// Read all data from a file (multi-chunk).
    pub async fn read_all(&self, file_id: &[u8; 32]) -> Result<Vec<u8>> {
        let chunk = self.max_read_size.min(65536);
        let mut result = Vec::new();
        let mut offset = 0u64;

        loop {
            match self.read(file_id, offset, chunk).await {
                Ok(data) => {
                    if data.is_empty() {
                        break;
                    }
                    offset += data.len() as u64;
                    result.extend_from_slice(&data);
                    if data.len() < chunk as usize {
                        break; // last chunk
                    }
                }
                Err(e) => {
                    // STATUS_END_OF_FILE is normal
                    if result.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        Ok(result)
    }

    // ───────────────── Write ─────────────────

    /// Write data to an open file/pipe.
    pub async fn write(&self, file_id: &[u8; 32], offset: u64, data: &[u8]) -> Result<u32> {
        let hdr = self.build_header(SMB2_WRITE, 0).await;
        let mut body = Vec::new();
        // StructureSize = 49
        body.extend_from_slice(&49u16.to_le_bytes());
        // DataOffset (header + 48 bytes body = 112)
        let data_offset = (SMB2_HEADER_SIZE + 48) as u16;
        body.extend_from_slice(&data_offset.to_le_bytes());
        // Length
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        // Offset
        body.extend_from_slice(&offset.to_le_bytes());
        // FileId (16 bytes)
        body.extend_from_slice(&file_id[..16]);
        // Channel = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // RemainingBytes = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // WriteChannelInfoOffset = 0
        body.extend_from_slice(&0u16.to_le_bytes());
        // WriteChannelInfoLength = 0
        body.extend_from_slice(&0u16.to_le_bytes());
        // Flags = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // Pad to data offset
        while body.len() < 48 {
            body.push(0);
        }
        // Data
        body.extend_from_slice(data);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Write failed: 0x{status:08X}"
            )));
        }

        let rb = &resp[SMB2_HEADER_SIZE..];
        let count = u32::from_le_bytes([rb[2], rb[3], rb[4], rb[5]]);
        Ok(count)
    }

    /// Write all data (multi-chunk if needed).
    pub async fn write_all(&self, file_id: &[u8; 32], data: &[u8]) -> Result<()> {
        let chunk = self.max_write_size.min(65536) as usize;
        let mut offset = 0usize;

        while offset < data.len() {
            let end = (offset + chunk).min(data.len());
            let written = self
                .write(file_id, offset as u64, &data[offset..end])
                .await?;
            offset += written as usize;
        }

        Ok(())
    }

    // ───────────────── IOCTL (Named Pipe Transact) ─────────────────

    /// FSCTL_PIPE_TRANSCEIVE — send DCE/RPC request, receive response.
    /// This is the critical operation for WMI, SAMR, DRSUAPI, etc.
    pub async fn ioctl_pipe_transceive(&self, file_id: &[u8; 32], input: &[u8]) -> Result<Vec<u8>> {
        let hdr = self.build_header(SMB2_IOCTL, 0).await;
        let mut body = Vec::new();
        // StructureSize = 57
        body.extend_from_slice(&57u16.to_le_bytes());
        // Reserved = 0
        body.extend_from_slice(&0u16.to_le_bytes());
        // CtlCode = FSCTL_PIPE_TRANSCEIVE
        body.extend_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes());
        // FileId (16 bytes)
        body.extend_from_slice(&file_id[..16]);
        // InputOffset (header + 56 bytes body = 120)
        let input_offset = (SMB2_HEADER_SIZE + 56) as u32;
        body.extend_from_slice(&input_offset.to_le_bytes());
        // InputCount
        body.extend_from_slice(&(input.len() as u32).to_le_bytes());
        // MaxInputResponse = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // OutputOffset = 0 (filled by server)
        body.extend_from_slice(&0u32.to_le_bytes());
        // OutputCount = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // MaxOutputResponse — 1 MiB budget so DCSync / large RPC replies are not truncated
        body.extend_from_slice(&1_048_576u32.to_le_bytes());
        // Flags = SMB2_0_IOCTL_IS_FSCTL (1)
        body.extend_from_slice(&1u32.to_le_bytes());
        // Reserved2 = 0
        body.extend_from_slice(&0u32.to_le_bytes());
        // Pad to input offset
        while body.len() < 56 {
            body.push(0);
        }
        // Input data
        body.extend_from_slice(input);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let resp = self.recv().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Smb(format!(
                "SMB2 IOCTL failed: 0x{status:08X}"
            )));
        }

        let rb = &resp[SMB2_HEADER_SIZE..];
        // OutputOffset (at body offset 32)
        let out_offset =
            u32::from_le_bytes([rb[32], rb[33], rb[34], rb[35]]) as usize - SMB2_HEADER_SIZE;
        // OutputCount (at body offset 36)
        let out_count = u32::from_le_bytes([rb[36], rb[37], rb[38], rb[39]]) as usize;

        if out_count == 0 {
            return Ok(Vec::new());
        }
        if out_offset + out_count > rb.len() {
            return Err(OverthroneError::Smb(
                "SMB2 IOCTL output overflow".to_string(),
            ));
        }

        Ok(rb[out_offset..out_offset + out_count].to_vec())
    }

    // ───────────────── Query Directory ─────────────────

    /// List directory entries. Returns `(name, is_directory, size)` tuples.
    pub async fn query_directory(&self, dir_id: &[u8; 32]) -> Result<Vec<(String, bool, u64)>> {
        let mut all_entries = Vec::new();
        let mut first = true;

        loop {
            let hdr = self.build_header(SMB2_QUERY_DIRECTORY, 0).await;
            let mut body = Vec::new();
            // StructureSize = 33
            body.extend_from_slice(&33u16.to_le_bytes());
            // FileInformationClass = FileDirectoryInformation (1)
            body.push(FILE_DIRECTORY_INFORMATION);
            // Flags: SMB2_RESTART_SCANS(1) on first call, SMB2_CONTINUE_SCANS(0) after
            body.push(if first { 0x01 } else { 0x00 });
            // FileIndex = 0
            body.extend_from_slice(&0u32.to_le_bytes());
            // FileId (16 bytes)
            body.extend_from_slice(&dir_id[..16]);
            // Search pattern "*" — offset and length
            let pattern: Vec<u8> = "*".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            let pattern_offset = (SMB2_HEADER_SIZE + 32) as u16;
            body.extend_from_slice(&pattern_offset.to_le_bytes());
            body.extend_from_slice(&(pattern.len() as u16).to_le_bytes());
            // OutputBufferLength
            body.extend_from_slice(&65536u32.to_le_bytes());
            // Pad to 32
            while body.len() < 32 {
                body.push(0);
            }
            // Search pattern
            body.extend_from_slice(&pattern);

            let mut pkt = hdr;
            pkt.extend_from_slice(&body);
            self.send_signed(&mut pkt).await?;
            let resp = self.recv().await?;

            let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
            if status == STATUS_NO_MORE_FILES {
                break;
            }
            if status != STATUS_SUCCESS {
                return Err(OverthroneError::Smb(format!(
                    "SMB2 QueryDirectory failed: 0x{status:08X}"
                )));
            }

            let rb = &resp[SMB2_HEADER_SIZE..];
            let out_offset = rb[2] as usize - SMB2_HEADER_SIZE;
            let out_len = u32::from_le_bytes([rb[4], rb[5], rb[6], rb[7]]) as usize;

            if out_offset + out_len > rb.len() {
                break;
            }

            let data = &rb[out_offset..out_offset + out_len];
            parse_file_directory_info(data, &mut all_entries);

            first = false;
        }

        Ok(all_entries)
    }

    // ───────────────── Delete ─────────────────

    /// Delete a file by opening with DELETE disposition and closing.
    pub async fn delete_file(&self, path: &str) -> Result<()> {
        let file_id = self
            .create(
                path,
                DELETE_ACCESS | SYNCHRONIZE,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            )
            .await?;

        // Set disposition info via SET_INFO
        // For simplicity, we use CREATE with FILE_DISPOSITION_DELETE flag
        // Actually in SMB2, delete = Create with DELETE_ON_CLOSE option
        // Let's re-create with FILE_DELETE_ON_CLOSE
        self.close(&file_id).await?;

        // Re-open with DELETE_ON_CLOSE
        let file_id = self
            .create(
                path,
                DELETE_ACCESS | SYNCHRONIZE,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | 0x0000_1000, // FILE_DELETE_ON_CLOSE
            )
            .await?;
        self.close(&file_id).await?;
        Ok(())
    }

    /// Get the session key (for DCSync/crypto operations).
    pub async fn get_session_key(&self) -> Option<Vec<u8>> {
        self.session_key.lock().await.clone()
    }

    /// Logoff and cleanly close the session.
    pub async fn logoff(&self) -> Result<()> {
        let hdr = self.build_header(SMB2_LOGOFF, 0).await;
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let _resp = self.recv().await?;
        *self.session_id.lock().await = 0;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
//  NTLMSSP Implementation (NTLMv2)
// ═══════════════════════════════════════════════════════════

/// Parsed NTLMSSP Type 2 (Challenge) message.
struct NtlmChallenge {
    server_challenge: [u8; 8],
    target_info: Vec<u8>,
    negotiate_flags: u32,
}

/// Build NTLMSSP Type 1 (Negotiate) message.
fn build_ntlmssp_negotiate() -> Vec<u8> {
    let flags = NTLMSSP_NEGOTIATE_56
        | NTLMSSP_NEGOTIATE_KEY_EXCH
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_SEAL
        | NTLMSSP_NEGOTIATE_SIGN
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_UNICODE;

    let mut msg = Vec::with_capacity(40);
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&NTLMSSP_NEGOTIATE.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    // DomainNameFields (Len, MaxLen, Offset) = 0
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    // WorkstationFields = 0
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg
}

/// Parse NTLMSSP Type 2 (Challenge) message.
fn parse_ntlmssp_challenge(data: &[u8]) -> Result<NtlmChallenge> {
    if data.len() < 32 {
        return Err(OverthroneError::Smb("NTLMSSP Type 2 too short".to_string()));
    }

    // Verify signature
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err(OverthroneError::Smb(
            "Invalid NTLMSSP signature in Type 2".to_string(),
        ));
    }

    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != NTLMSSP_CHALLENGE {
        return Err(OverthroneError::Smb(format!(
            "Expected NTLMSSP Type 2, got {msg_type}"
        )));
    }

    let negotiate_flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // TargetInfo: Len at offset 40, Offset at offset 44
    let target_info = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let ti_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
        if ti_offset + ti_len <= data.len() {
            data[ti_offset..ti_offset + ti_len].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(NtlmChallenge {
        server_challenge,
        target_info,
        negotiate_flags,
    })
}

/// Build NTLMSSP Type 3 (Authenticate) from password.
/// Returns (type3_message, session_key).
fn build_ntlmssp_authenticate(
    domain: &str,
    username: &str,
    password: &str,
    challenge: &NtlmChallenge,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Compute NT hash = MD4(UTF-16LE(password))
    let password_utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let nt_hash = {
        let mut md4 = Md4::new();
        md4.update(&password_utf16);
        md4.finalize().to_vec()
    };

    build_ntlmssp_authenticate_hash(domain, username, &nt_hash, challenge)
}

/// Build NTLMSSP Type 3 from raw NT hash (for pass-the-hash).
fn build_ntlmssp_authenticate_hash(
    domain: &str,
    username: &str,
    nt_hash: &[u8],
    challenge: &NtlmChallenge,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // ── NTLMv2 computation ──
    // Step 1: ResponseKeyNT = HMAC_MD5(NT_Hash, UPPER(username) + domain)
    let user_domain: Vec<u8> = username
        .to_uppercase()
        .encode_utf16()
        .chain(domain.encode_utf16())
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let response_key = hmac_md5(nt_hash, &user_domain)?;

    // Step 2: Build NTLMv2 client challenge blob
    let client_challenge: [u8; 8] = rand::thread_rng().r#gen();
    let timestamp = filetime_now();
    let blob = build_ntlmv2_blob(&client_challenge, &timestamp, &challenge.target_info);

    // Step 3: NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + Blob)
    let mut proof_input = Vec::with_capacity(8 + blob.len());
    proof_input.extend_from_slice(&challenge.server_challenge);
    proof_input.extend_from_slice(&blob);
    let nt_proof_str = hmac_md5(&response_key, &proof_input)?;

    // Step 4: NtChallengeResponse = NTProofStr + Blob
    let mut nt_response = Vec::with_capacity(nt_proof_str.len() + blob.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&blob);

    // Step 5: SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    let session_base_key = hmac_md5(&response_key, &nt_proof_str)?;

    // Step 6: Build Type 3 message
    let flags = challenge.negotiate_flags;

    let domain_utf16: Vec<u8> = domain
        .to_uppercase()
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let user_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let workstation_utf16: Vec<u8> = "OVERTHRONE"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // LM response (24 bytes of zeros for NTLMv2)
    let lm_response = vec![0u8; 24];

    // Encrypted random session key (key exchange)
    let exported_session_key: Vec<u8> = if flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
        let random_key: [u8; 16] = rand::thread_rng().r#gen();
        random_key.to_vec()
    } else {
        session_base_key.clone()
    };

    let encrypted_session_key: Vec<u8> = if flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
        // RC4(SessionBaseKey, ExportedSessionKey)
        rc4_encrypt(&session_base_key, &exported_session_key)
    } else {
        Vec::new()
    };

    // Calculate offsets (header=88 bytes for authenticate)
    let header_len = 88u32;
    let lm_offset = header_len;
    let nt_offset = lm_offset + lm_response.len() as u32;
    let domain_offset = nt_offset + nt_response.len() as u32;
    let user_offset = domain_offset + domain_utf16.len() as u32;
    let ws_offset = user_offset + user_utf16.len() as u32;
    let enc_key_offset = ws_offset + workstation_utf16.len() as u32;

    let mut msg = Vec::with_capacity(256);
    // Signature
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    // MessageType = 3
    msg.extend_from_slice(&NTLMSSP_AUTH.to_le_bytes());
    // LmChallengeResponseFields
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&lm_offset.to_le_bytes());
    // NtChallengeResponseFields
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&nt_offset.to_le_bytes());
    // DomainNameFields
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());
    // UserNameFields
    msg.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&user_offset.to_le_bytes());
    // WorkstationFields
    msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&ws_offset.to_le_bytes());
    // EncryptedRandomSessionKeyFields
    msg.extend_from_slice(&(encrypted_session_key.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(encrypted_session_key.len() as u16).to_le_bytes());
    msg.extend_from_slice(&enc_key_offset.to_le_bytes());
    // NegotiateFlags
    msg.extend_from_slice(&flags.to_le_bytes());
    // MIC (16 bytes of zeros — we don't compute MIC for simplicity)
    msg.extend_from_slice(&[0u8; 16]);

    // Payload
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&user_utf16);
    msg.extend_from_slice(&workstation_utf16);
    msg.extend_from_slice(&encrypted_session_key);

    Ok((msg, exported_session_key))
}

/// Build NTLMv2 client challenge blob (AvPairs, timestamp, etc.)
fn build_ntlmv2_blob(
    client_challenge: &[u8; 8],
    timestamp: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    let mut blob = Vec::with_capacity(32 + target_info.len());
    // RespType = 1
    blob.push(0x01);
    // HiRespType = 1
    blob.push(0x01);
    // Reserved1 = 0 (2 bytes)
    blob.extend_from_slice(&0u16.to_le_bytes());
    // Reserved2 = 0 (4 bytes)
    blob.extend_from_slice(&0u32.to_le_bytes());
    // TimeStamp (8 bytes, Windows FILETIME)
    blob.extend_from_slice(timestamp);
    // ChallengeFromClient (8 bytes)
    blob.extend_from_slice(client_challenge);
    // Reserved3 = 0 (4 bytes)
    blob.extend_from_slice(&0u32.to_le_bytes());
    // AvPairs (target info from server)
    blob.extend_from_slice(target_info);
    // Padding (4 bytes)
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob
}

/// Get current time as Windows FILETIME (100-ns intervals since 1601-01-01).
fn filetime_now() -> [u8; 8] {
    // Unix epoch = 1970-01-01, FILETIME epoch = 1601-01-01
    // Difference = 11644473600 seconds
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ft = (now.as_secs() + 11_644_473_600) * 10_000_000 + now.subsec_nanos() as u64 / 100;
    ft.to_le_bytes()
}

// ═══════════════════════════════════════════════════════════
//  SPNEGO Wrappers (minimal ASN.1)
// ═══════════════════════════════════════════════════════════

/// Wrap an NTLMSSP token in a SPNEGO NegTokenInit.
fn wrap_spnego_init(ntlmssp: &[u8]) -> Vec<u8> {
    // Build inner mechTypes sequence [NTLMSSP OID]
    let mech_types = asn1_sequence(NTLMSSP_OID);
    // mechToken [2] OCTET STRING
    let mech_token = asn1_context_tag(2, &asn1_octet_string(ntlmssp));
    // NegTokenInit sequence
    let neg_token_init_inner =
        asn1_sequence(&[asn1_context_tag(0, &mech_types), mech_token].concat());
    // Wrap in [0] context for SPNEGO
    let neg_token_init = asn1_context_tag(0, &neg_token_init_inner);
    // Application [0] IMPLICIT (SPNEGO OID + NegTokenInit)
    let spnego = [SPNEGO_OID, &neg_token_init].concat();
    asn1_application_tag(0, &spnego)
}

/// Wrap an NTLMSSP token in a SPNEGO NegTokenResp (responseToken).
fn wrap_spnego_response(ntlmssp: &[u8]) -> Vec<u8> {
    // NegTokenResp: responseToken [2] OCTET STRING
    let resp_token = asn1_context_tag(2, &asn1_octet_string(ntlmssp));
    let neg_token_resp = asn1_sequence(&resp_token);
    asn1_context_tag(1, &neg_token_resp)
}

/// Wrap a Kerberos AP-REQ token in a SPNEGO NegTokenInit.
fn wrap_spnego_kerberos(ap_req: &[u8]) -> Vec<u8> {
    let mech_types = asn1_sequence(KERBEROS_OID);
    let mech_token = asn1_context_tag(2, &asn1_octet_string(ap_req));
    let neg_token_init_inner =
        asn1_sequence(&[asn1_context_tag(0, &mech_types), mech_token].concat());
    let neg_token_init = asn1_context_tag(0, &neg_token_init_inner);
    let spnego = [SPNEGO_OID, &neg_token_init].concat();
    asn1_application_tag(0, &spnego)
}

/// Extract the NTLMSSP token from a SPNEGO response.
fn extract_ntlmssp_from_spnego(data: &[u8]) -> Result<Vec<u8>> {
    // Walk the ASN.1 looking for the NTLMSSP signature
    if let Some(pos) = find_subsequence(data, NTLMSSP_SIGNATURE) {
        // Find the end of this NTLMSSP message
        // Scan forward for the message boundary
        Ok(data[pos..].to_vec())
    } else {
        Err(OverthroneError::Smb(
            "No NTLMSSP token found in SPNEGO response".to_string(),
        ))
    }
}

// ═══════════════════════════════════════════════════════════
//  ASN.1 DER Helpers (minimal, no external dependency)
// ═══════════════════════════════════════════════════════════

fn asn1_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn asn1_sequence(data: &[u8]) -> Vec<u8> {
    let mut r = vec![0x30];
    r.extend_from_slice(&asn1_length(data.len()));
    r.extend_from_slice(data);
    r
}

fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut r = vec![0x04];
    r.extend_from_slice(&asn1_length(data.len()));
    r.extend_from_slice(data);
    r
}

fn asn1_context_tag(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut r = vec![0xA0 | tag];
    r.extend_from_slice(&asn1_length(data.len()));
    r.extend_from_slice(data);
    r
}

fn asn1_application_tag(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut r = vec![0x60 | tag];
    r.extend_from_slice(&asn1_length(data.len()));
    r.extend_from_slice(data);
    r
}

// ═══════════════════════════════════════════════════════════
//  Crypto Helpers — KDF + AES-CMAC
// ═══════════════════════════════════════════════════════════

/// NIST SP800-108 Counter Mode KDF using HMAC-SHA256.
///
/// Derives a 16-byte key from `key_in`, `label` (null-terminated), and
/// `context` (null-terminated).  Used to produce SMB 3.x signing and
/// encryption keys from the exported session key.
///
/// Input to one HMAC iteration:
///   `\x00\x00\x00\x01` || label || `\x00` || context || `\x00\x00\x00\x80`
fn sp800_108_counter_kdf(key_in: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    // counter = 1 (single 128-bit block is enough)
    let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
    input.extend_from_slice(&1u32.to_be_bytes()); // i = 1
    input.extend_from_slice(label); // already null-terminated by caller
    input.push(0x00); // separator
    input.extend_from_slice(context); // already null-terminated by caller
    input.extend_from_slice(&128u32.to_be_bytes()); // L = 128 bits

    let mut mac =
        HmacSha256::new_from_slice(key_in).expect("HMAC-SHA256 accepts any key size");
    mac.update(&input);
    mac.finalize().into_bytes()[..16].to_vec()
}

/// AES-128-CMAC over `data` using `key` (should be 16 bytes).  Returns 16-byte tag.
fn aes_cmac_16(key: &[u8], data: &[u8]) -> [u8; 16] {
    // Ensure exactly 16 bytes — zero-pad or truncate if necessary.
    // In practice the session-derived key is always 16 bytes; the fallback
    // path is a safety net only.
    let mut key16 = [0u8; 16];
    let n = key.len().min(16);
    key16[..n].copy_from_slice(&key[..n]);

    type AesCmac = Cmac<Aes128>;
    let mut mac =
        AesCmac::new_from_slice(&key16).expect("CMAC accepts 16-byte key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

// ═══════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════

fn hmac_md5(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        HmacMd5::new_from_slice(key).map_err(|e| OverthroneError::custom(format!("HMAC: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// RC4 encrypt/decrypt (simple key-schedule implementation).
fn rc4_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut i: u8 = 0;
    let mut j: u8 = 0;
    let mut result = Vec::with_capacity(data.len());
    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        result.push(byte ^ k);
    }
    result
}

/// Find a subsequence within a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse FILE_DIRECTORY_INFORMATION entries from a QueryDirectory response buffer.
fn parse_file_directory_info(data: &[u8], results: &mut Vec<(String, bool, u64)>) {
    let mut offset = 0;

    loop {
        if offset + 64 > data.len() {
            break;
        }

        let next_entry = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let file_attributes = u32::from_le_bytes([
            data[offset + 56],
            data[offset + 57],
            data[offset + 58],
            data[offset + 59],
        ]);
        let file_name_len = u32::from_le_bytes([
            data[offset + 60],
            data[offset + 61],
            data[offset + 62],
            data[offset + 63],
        ]) as usize;
        let end_of_file = u64::from_le_bytes([
            data[offset + 40],
            data[offset + 41],
            data[offset + 42],
            data[offset + 43],
            data[offset + 44],
            data[offset + 45],
            data[offset + 46],
            data[offset + 47],
        ]);

        let name_start = offset + 64;
        let name_end = name_start + file_name_len;
        if name_end > data.len() {
            break;
        }

        // Decode UTF-16LE filename
        let name_bytes = &data[name_start..name_end];
        let mut utf16 = Vec::with_capacity(file_name_len / 2);
        for chunk in name_bytes.chunks_exact(2) {
            utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        let name = String::from_utf16_lossy(&utf16);

        let is_dir = file_attributes & 0x10 != 0; // FILE_ATTRIBUTE_DIRECTORY

        if name != "." && name != ".." {
            results.push((name, is_dir, end_of_file));
        }

        if next_entry == 0 {
            break;
        }
        offset += next_entry as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlmssp_negotiate_builds() {
        let type1 = build_ntlmssp_negotiate();
        assert_eq!(&type1[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(
            u32::from_le_bytes([type1[8], type1[9], type1[10], type1[11]]),
            NTLMSSP_NEGOTIATE
        );
    }

    #[test]
    fn test_filetime_is_reasonable() {
        let ft = filetime_now();
        let val = u64::from_le_bytes(ft);
        // Should be after year 2024 (approximately 133_500_000_000_000_000)
        assert!(val > 133_000_000_000_000_000);
    }

    #[test]
    fn test_spnego_wrapping() {
        let type1 = build_ntlmssp_negotiate();
        let wrapped = wrap_spnego_init(&type1);
        // Should start with APPLICATION [0] tag
        assert_eq!(wrapped[0], 0x60);
        // Should contain the NTLMSSP signature somewhere
        assert!(find_subsequence(&wrapped, NTLMSSP_SIGNATURE).is_some());
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"testkey123456";
        let plaintext = b"Hello, SMB2 world!";
        let encrypted = rc4_encrypt(key, plaintext);
        let decrypted = rc4_encrypt(key, &encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hmac_md5_nonempty() {
        let result = hmac_md5(b"key", b"data").unwrap();
        assert_eq!(result.len(), 16);
        assert_ne!(result, vec![0u8; 16]);
    }

    #[test]
    fn test_ntlmv2_blob_structure() {
        let client_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let timestamp = filetime_now();
        let target_info = vec![0x02, 0x00, 0x08, 0x00]; // fake AvPair
        let blob = build_ntlmv2_blob(&client_challenge, &timestamp, &target_info);
        // RespType + HiRespType = 0x01, 0x01
        assert_eq!(blob[0], 0x01);
        assert_eq!(blob[1], 0x01);
        // Client challenge at offset 16
        assert_eq!(&blob[16..24], &client_challenge);
    }
}
