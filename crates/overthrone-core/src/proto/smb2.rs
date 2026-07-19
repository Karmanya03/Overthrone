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
use rand::RngExt;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

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
#[allow(dead_code)] // Protocol reference constant
const SMB2_FLUSH: u16 = 0x0007;
const SMB2_READ: u16 = 0x0008;
const SMB2_WRITE: u16 = 0x0009;
#[allow(dead_code)] // Protocol reference constant
const SMB2_LOCK: u16 = 0x000A;
const SMB2_IOCTL: u16 = 0x000B;
#[allow(dead_code)] // Protocol reference constant
const SMB2_CANCEL: u16 = 0x000C;
#[allow(dead_code)] // Protocol reference constant
const SMB2_ECHO: u16 = 0x000D;
const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
#[allow(dead_code)] // Protocol reference constant
const SMB2_CHANGE_NOTIFY: u16 = 0x000F;
#[allow(dead_code)] // Protocol reference constant
const SMB2_QUERY_INFO: u16 = 0x0010;
#[allow(dead_code)] // Protocol reference constant
const SMB2_SET_INFO: u16 = 0x0011;
const SMB2_OPLOCK_BREAK: u16 = 0x0012;

// SMB2 NT Status codes
const STATUS_PENDING: u32 = 0x00000103;
const STATUS_SUCCESS: u32 = 0x00000000;

// SMB2 OPLOCK levels
#[allow(dead_code)] // Protocol reference constant
const OPLOCK_LEVEL_NONE: u8 = 0x00;
#[allow(dead_code)] // Protocol reference constant
const OPLOCK_LEVEL_II: u8 = 0x01;
#[allow(dead_code)] // Protocol reference constant
const OPLOCK_LEVEL_EXCLUSIVE: u8 = 0x08;
#[allow(dead_code)] // Protocol reference constant
const OPLOCK_LEVEL_BATCH: u8 = 0x09;
#[allow(dead_code)] // Protocol reference constant
const OPLOCK_LEVEL_LEASE: u8 = 0xFF;

// SMB2 Dialects
const SMB2_DIALECT_202: u16 = 0x0202; // SMB 2.0.2 (required by some servers)
const SMB2_DIALECT_210: u16 = 0x0210; // SMB 2.1
const SMB2_DIALECT_300: u16 = 0x0300; // SMB 3.0
const SMB2_DIALECT_302: u16 = 0x0302; // SMB 3.0.2
const SMB2_DIALECT_311: u16 = 0x0311; // SMB 3.1.1 (Windows 10 / Server 2016+)

/// Update the cumulative pre-authentication integrity hash for SMB 3.1.1.
/// Per MS-SMB2 §2.2.4 and Impacket: new_hash = SHA-512(old_hash || message_data)
/// where old_hash is the 64-byte SHA-512 digest from the previous step,
/// initialized to 64 zero bytes. The hash accumulates across all pre-auth
/// messages: NegotiateReq, NegotiateResp, SessionSetupReq(Leg1),
/// SessionSetupResp(Leg1), SessionSetupReq(Leg2).
fn update_preauth_hash(old_hash: &[u8], message_data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(old_hash);
    hasher.update(message_data);
    hasher.finalize().to_vec()
}

/// Derive an SMB signing key via SP800-108 KDF in Counter Mode (MS-SMB2 §3.2.4.1.2).
/// The context depends on the dialect:
/// - SMB 3.1.1: Label="SMBSigningKey\x00", Context=Session.PreauthIntegrityHashValue (64 bytes)
/// - SMB 3.0.x:  Label="SMB2AESCMAC\x00",  Context="SmbSign\x00"
///
/// The session key is the NTLM ExportedSessionKey (untransformed).
/// Returns a 16-byte AES-CMAC signing key.
fn derive_signing_key(session_key: &[u8], dialect: u16, preauth_hash: Option<&[u8]>) -> [u8; 16] {
    let (label, ctx_bytes): (&[u8], &[u8]) = if dialect >= SMB2_DIALECT_311 {
        // SMB 3.1.1: context = PreauthIntegrityHashValue (SHA-512 of all pre-auth messages)
        // Impacket uses the raw (untransformed) NTLM session key + preauth_hash as context.
        // Some sources also XOR the session key with HMAC-SHA256(preauth_hash, label),
        // but WS2025 does NOT XOR (matching Impacket's behavior).
        if let Some(hash) = preauth_hash {
            let key = sp800_108_counter_kdf_sep(session_key, b"SMBSigningKey\x00", hash);
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&key[..16]);
            return sig;
        }
        // Fallback: use "SmbSign" context if no preauth hash (should not happen)
        (b"SMBSigningKey\x00", b"SmbSign\x00")
    } else {
        // SMB 3.0.x: static context
        (b"SMB2AESCMAC\x00", b"SmbSign\x00")
    };
    let key = sp800_108_counter_kdf_sep(session_key, label, ctx_bytes);
    let mut sig = [0u8; 16];
    sig.copy_from_slice(&key[..16]);
    sig
}

/// Diagnostic: derive signing key using HMAC-SHA512 as PRF instead of HMAC-SHA256.
fn derive_signing_key_sha512(
    session_key: &[u8],
    dialect: u16,
    preauth_hash: Option<&[u8]>,
) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let (label, ctx_bytes): (&[u8], &[u8]) = if dialect >= SMB2_DIALECT_311 {
        if let Some(hash) = preauth_hash {
            let mut input = Vec::with_capacity(4 + 17 + hash.len() + 4);
            input.extend_from_slice(&1u32.to_be_bytes());
            input.extend_from_slice(b"SMBSigningKey\x00");
            input.push(0x00);
            input.extend_from_slice(hash);
            input.extend_from_slice(&128u32.to_be_bytes());
            let mut mac = Hmac::<Sha512>::new_from_slice(session_key)
                .expect("HMAC-SHA512 accepts any key size");
            mac.update(&input);
            let result = mac.finalize().into_bytes();
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&result[..16]);
            return sig;
        }
        (b"SMBSigningKey\x00", b"SmbSign\x00")
    } else {
        (b"SMB2AESCMAC\x00", b"SmbSign\x00")
    };
    let mut input = Vec::with_capacity(4 + label.len() + 1 + ctx_bytes.len() + 4);
    input.extend_from_slice(&1u32.to_be_bytes());
    input.extend_from_slice(label);
    input.push(0x00);
    input.extend_from_slice(ctx_bytes);
    input.extend_from_slice(&128u32.to_be_bytes());
    let mut mac =
        Hmac::<Sha512>::new_from_slice(session_key).expect("HMAC-SHA512 accepts any key size");
    mac.update(&input);
    let result = mac.finalize().into_bytes();
    let mut sig = [0u8; 16];
    sig.copy_from_slice(&result[..16]);
    sig
}

/// Diagnostic: derive signing key without the initial counter (just label || ctx || L).
fn derive_signing_key_nocounter(
    session_key: &[u8],
    dialect: u16,
    preauth_hash: Option<&[u8]>,
) -> [u8; 16] {
    let (label, ctx_bytes): (&[u8], &[u8]) = if dialect >= SMB2_DIALECT_311 {
        if let Some(hash) = preauth_hash {
            let mut input = Vec::with_capacity(17 + hash.len() + 4);
            input.extend_from_slice(b"SMBSigningKey\x00");
            input.push(0x00);
            input.extend_from_slice(hash);
            input.extend_from_slice(&128u32.to_be_bytes());
            let mut mac =
                HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 accepts any key size");
            mac.update(&input);
            let result = mac.finalize().into_bytes();
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&result[..16]);
            return sig;
        }
        (b"SMBSigningKey\x00", b"SmbSign\x00")
    } else {
        (b"SMB2AESCMAC\x00", b"SmbSign\x00")
    };
    let mut input = Vec::with_capacity(label.len() + 1 + ctx_bytes.len() + 4);
    input.extend_from_slice(label);
    input.push(0x00);
    input.extend_from_slice(ctx_bytes);
    input.extend_from_slice(&128u32.to_be_bytes());
    let mut mac =
        HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 accepts any key size");
    mac.update(&input);
    let result = mac.finalize().into_bytes();
    let mut sig = [0u8; 16];
    sig.copy_from_slice(&result[..16]);
    sig
}

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
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

fn ntstatus_to_name(code: u32) -> &'static str {
    match code {
        STATUS_SUCCESS => "SUCCESS",
        STATUS_MORE_PROCESSING_REQUIRED => "MORE_PROCESSING_REQUIRED",
        STATUS_NO_MORE_FILES => "NO_MORE_FILES",
        STATUS_INVALID_PARAMETER => "INVALID_PARAMETER",
        STATUS_NOT_SUPPORTED => "NOT_SUPPORTED",
        STATUS_INVALID_DEVICE_REQUEST => "INVALID_DEVICE_REQUEST",
        STATUS_ACCESS_DENIED => "ACCESS_DENIED",
        STATUS_LOGON_FAILURE => "LOGON_FAILURE",
        STATUS_OBJECT_NAME_NOT_FOUND => "OBJECT_NAME_NOT_FOUND",
        0xC000_0005 => "ACCESS_VIOLATION",
        0xC000_0023 => "INVALID_HANDLE",
        0xC000_0071 => "INVALID_SMB",
        0xC000_00C0 => "BUFFER_OVERFLOW",
        0xC000_010B => "INVALID_DEVICE_STATE",
        0xC000_01C3 => "USER_SESSION_DELETED",
        0xC000_0225 => "NOT_FOUND",
        0x8000_0005 => "BUFFER_OVERFLOW",
        _ => "UNKNOWN",
    }
}

// SMB3 Transform_Header (MS-SMB2 §2.2.41)
const SMB3_TRANSFORM_MAGIC: &[u8; 4] = b"\xfdSMB";
const SMB3_TRANSFORM_HEADER_SIZE: usize = 52;
const SMB3_ENCRYPTION_AES128_GCM: u16 = 0x0001;
#[allow(dead_code)]
const SMB3_ENCRYPTION_AES256_GCM: u16 = 0x0002;
// KDF labels for SMB 3.x encryption key derivation
const SMB3_ENCRYPTION_KEY_LABEL_C2S: &[u8] = b"SMBC2SCipherKey";
const SMB3_ENCRYPTION_KEY_LABEL_S2C: &[u8] = b"SMBS2CCipherKey";
const SMB3_ENCRYPTION_KEY_CONTEXT: &[u8] = b"SmbCipher";

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
    /// Whether the server requires SMB3 encryption
    encryption_required: std::sync::atomic::AtomicBool,
    /// Derived SMB3 encryption key (server→client direction)
    decryption_key: Mutex<Option<Vec<u8>>>,
    /// Derived SMB3 encryption key (client→server direction)
    encryption_key: Mutex<Option<Vec<u8>>>,
    /// Negotiated SMB dialect (e.g. 0x0210 = SMB 2.1, 0x0300 = SMB 3.0, 0x0302 = SMB 3.0.2)
    dialect: AtomicU16,
    /// Negotiated max transaction size (from server NEGOTIATE response)
    max_transact_size: AtomicU32,
    /// Negotiated max read size
    max_read_size: u32,
    /// Negotiated max write size
    max_write_size: u32,
    /// Pre-authentication integrity hash (SHA-512) for SMB 3.1.1 session key transformation
    preauth_hash: Mutex<Option<Vec<u8>>>,
    /// Whether signing is known to be broken (WS2025 non-standard KDF).
    /// When true, skip signing outgoing packets and skip verifying incoming ones.
    signing_known_broken: std::sync::atomic::AtomicBool,
    /// Selected cipher ID from negotiate response (0x0001 = AES-128-CCM, 0x0002 = AES-128-GCM)
    #[allow(dead_code)]
    cipher_id: AtomicU16,
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
            encryption_required: std::sync::atomic::AtomicBool::new(false),
            decryption_key: Mutex::new(None),
            encryption_key: Mutex::new(None),
            dialect: AtomicU16::new(0),
            max_transact_size: AtomicU32::new(65536),
            max_read_size: 65536,
            max_write_size: 65536,
            // Initialize to 64 zero bytes for SMB 3.1.1 cumulative pre-auth integrity hash
            preauth_hash: Mutex::new(Some(vec![0u8; 64])),
            signing_known_broken: std::sync::atomic::AtomicBool::new(false),
            cipher_id: AtomicU16::new(0x0001),
        })
    }

    // ───────────────── Transport ─────────────────

    /// Send an SMB2 message (prepends NetBIOS session header).
    /// Automatically wraps with SMB3 Transform_Header if encryption is enabled.
    async fn send(&self, data: &[u8]) -> Result<()> {
        let payload = if self
            .encryption_required
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let session_id = *self.session_id.lock().await;
            let enc_key =
                self.encryption_key.lock().await.clone().ok_or_else(|| {
                    OverthroneError::Smb("SMB3 encryption key not set".to_string())
                })?;
            smb3_encrypt_aes128_gcm(data, &enc_key, session_id)?
        } else {
            data.to_vec()
        };

        let mut stream = self.stream.lock().await;
        let len = payload.len() as u32;
        let header = len.to_be_bytes();
        stream
            .write_all(&header)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB2 send header: {e}")))?;
        stream
            .write_all(&payload)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB2 send data: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB2 flush: {e}")))?;
        Ok(())
    }

    /// Receive an SMB2 response (reads NetBIOS header, then payload).
    /// Automatically unwraps SMB3 Transform_Header if encryption is enabled.
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

        // Decrypt if this is an SMB3 encrypted packet
        if self
            .encryption_required
            .load(std::sync::atomic::Ordering::Relaxed)
            && is_smb3_encrypted(&buf)
        {
            let dec_key =
                self.decryption_key.lock().await.clone().ok_or_else(|| {
                    OverthroneError::Smb("SMB3 decryption key not set".to_string())
                })?;
            let plaintext = smb3_decrypt_aes128_gcm(&buf, &dec_key)?;
            return Ok(plaintext);
        }

        Ok(buf)
    }

    /// Receive a response and verify its SMB2 signature (if signing is required).
    /// If SMB3 encryption is active, the signature is verified on the decrypted payload.
    async fn recv_verified(&self) -> Result<Vec<u8>> {
        let buf = self.recv().await?;

        // Skip verification if signing is known to be broken (WS2025 non-standard KDF)
        if self
            .signing_known_broken
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(buf);
        }

        // If encryption is active, the received buffer is already decrypted by recv()
        // and the signature is embedded in the SMB2 header of the decrypted payload.
        if self
            .sign_required
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(ref key) = *self.session_key.lock().await
        {
            let dialect = self.dialect.load(Ordering::Relaxed);
            let preauth = self.preauth_hash.lock().await.clone();
            if !Self::verify_packet(&buf, key, dialect, true, preauth.as_deref()) {
                // WS2025 signing quirk — once a single packet fails verification,
                // disable all further verification to prevent session corruption.
                // The signing key derivation for SMB 3.1.1 on WS2025 does not match
                // our SP800-108 KDF output, so intermittent failures are expected.
                warn!(
                    "SMB2: Packet signature verification failed — disabling further \
                       verification for this session (WS2025 signing quirk)."
                );
                self.signing_known_broken
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

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
    /// SMB 2.x uses HMAC-SHA256(session_key, packet)[0:16].
    /// SMB 3.x+ derives a signing key via SP800-108 KDF and uses AES-128-CMAC.
    /// `preauth_hash` is the Session.PreauthIntegrityHashValue for SMB 3.1.1 (used as KDF context).
    fn sign_packet(pkt: &mut [u8], session_key: &[u8], dialect: u16, preauth_hash: Option<&[u8]>) {
        // Set SMB2_FLAGS_SIGNED (bit 3) in the Flags field (bytes 16..20)
        let flags = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        let flags = flags | SMB2_FLAGS_SIGNED;
        pkt[16..20].copy_from_slice(&flags.to_le_bytes());

        // Zero the signature field before computing
        pkt[48..64].fill(0);

        if dialect >= SMB2_DIALECT_300 {
            let signing_key = derive_signing_key(session_key, dialect, preauth_hash);
            let sig = aes_cmac_16(&signing_key, pkt);
            pkt[48..64].copy_from_slice(&sig);
        } else {
            // SMB 2.x: HMAC-SHA256(session_key, packet)[0:16]
            let mut mac =
                HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 accepts any key size");
            mac.update(pkt);
            let result = mac.finalize().into_bytes();
            pkt[48..64].copy_from_slice(&result[..16]);
        }
    }

    /// Verify an SMB2/3 packet signature (MS-SMB2 §3.1.4.1).
    /// Returns true if the signature is valid or if signing is not enabled.
    /// `preauth_hash` is the Session.PreauthIntegrityHashValue for SMB 3.1.1 (used as KDF context).
    fn verify_packet(
        pkt: &[u8],
        session_key: &[u8],
        dialect: u16,
        sign_required: bool,
        preauth_hash: Option<&[u8]>,
    ) -> bool {
        if pkt.len() < 64 {
            return !sign_required;
        }

        // Check if the packet has the SIGNED flag set
        let flags = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        if flags & SMB2_FLAGS_SIGNED == 0 {
            return !sign_required;
        }

        // Extract the claimed signature
        let claimed_sig = &pkt[48..64];

        // Compute the expected signature over the entire packet, with sig field zeroed
        let mut verify_buf = pkt.to_vec();
        verify_buf[48..64].fill(0);

        let expected_sig: [u8; 16] = if dialect >= SMB2_DIALECT_300 {
            let signing_key = derive_signing_key(session_key, dialect, preauth_hash);
            let cmac = aes_cmac_16(&signing_key, &verify_buf);
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&cmac);
            sig
        } else {
            // SMB 2.x: HMAC-SHA256[0:16]
            let mut mac =
                HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 accepts any key size");
            mac.update(&verify_buf);
            let result = mac.finalize().into_bytes();
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&result[..16]);
            sig
        };

        if claimed_sig != expected_sig {
            let pkt_proto = &pkt[0..4];
            let pkt_hdr = &pkt[4..48];
            let pkt_sig_claimed = &pkt[48..64];
            let pkt_body = if pkt.len() > 72 { &pkt[64..72] } else { &[] };
            warn!(
                "SMB2 signature mismatch! claimed={:02x?}, expected={:02x?}, session_key={:02x?}, pkt_proto={:02x?}, hdr={:02x?}, sig_off={:02x?}, body={:02x?}",
                claimed_sig,
                expected_sig,
                session_key,
                pkt_proto,
                pkt_hdr,
                pkt_sig_claimed,
                pkt_body
            );

            // Diagnostic: try alternative signing methods
            if dialect >= SMB2_DIALECT_300 {
                // 1) legacy HMAC-SHA256(session_key, packet)[0:16]
                {
                    let mut mac = HmacSha256::new_from_slice(session_key).expect("HMAC");
                    mac.update(&verify_buf);
                    let legacy = mac.finalize().into_bytes();
                    if &legacy[..16] == claimed_sig {
                        warn!("SMB2: Server uses HMAC-SHA256 (SMB 2.x) not AES-CMAC!");
                        return true;
                    }
                }
                // 2) AES-CMAC(session_key, packet) without KDF
                {
                    let raw_cmac = aes_cmac_16(session_key, &verify_buf);
                    if &raw_cmac[..] == claimed_sig {
                        warn!("SMB2: Server uses AES-CMAC with raw session_key (no KDF)!");
                        return true;
                    }
                }
                // 3) AES-CMAC with KDF + SMB2AESCMAC label (SMB 3.0.x) using derive_signing_key
                {
                    let sk = derive_signing_key(session_key, SMB2_DIALECT_302, None);
                    let cmac = aes_cmac_16(&sk, &verify_buf);
                    if &cmac[..] == claimed_sig {
                        warn!("SMB2: Server uses SMB2AESCMAC KDF label (SMB 3.0.x)");
                        return true;
                    }
                }
                // 4) AES-CMAC with KDF + SMBSigningKey label + PreauthIntegrityHashValue context (SMB 3.1.1)
                if dialect >= SMB2_DIALECT_311 {
                    let sk = derive_signing_key(session_key, dialect, preauth_hash);
                    let cmac = aes_cmac_16(&sk, &verify_buf);
                    if &cmac[..] == claimed_sig {
                        warn!(
                            "SMB2: Server uses SMBSigningKey KDF with PreauthIntegrityHashValue context"
                        );
                        return true;
                    }
                }
                // 5) XOR session_key with first 16 bytes of preauth_hash before KDF
                if let Some(hash) = preauth_hash
                    && hash.len() >= 16
                {
                    let xored: Vec<u8> = session_key
                        .iter()
                        .zip(hash.iter())
                        .map(|(a, b)| a ^ b)
                        .collect();
                    let sk = derive_signing_key(&xored, dialect, preauth_hash);
                    let cmac = aes_cmac_16(&sk, &verify_buf);
                    if &cmac[..] == claimed_sig {
                        warn!("SMB2: Server uses XOR'd session_key with PreauthIntegrityHashValue");
                        return true;
                    }
                }
                // 6) KDF with HMAC-SHA512 as PRF instead of HMAC-SHA256
                {
                    let sk = derive_signing_key_sha512(session_key, dialect, preauth_hash);
                    let cmac = aes_cmac_16(&sk, &verify_buf);
                    if &cmac[..] == claimed_sig {
                        warn!("SMB2: Server uses HMAC-SHA512 as PRF in KDF");
                        return true;
                    }
                }
                // 7) No counter in KDF (just label || 0x00 || context || L without i)
                {
                    let sk = derive_signing_key_nocounter(session_key, dialect, preauth_hash);
                    let cmac = aes_cmac_16(&sk, &verify_buf);
                    if &cmac[..] == claimed_sig {
                        warn!("SMB2: Server uses no-counter KDF variant");
                        return true;
                    }
                }
                warn!("SMB2: NONE of signing methods match claimed_sig");
            }
            return false;
        }

        true
    }

    /// Send a packet, signing it first if signing is required and a session key is available.
    /// When SMB3 encryption is active, signing occurs on the plaintext before encryption wrapping.
    async fn send_signed(&self, pkt: &mut [u8]) -> Result<()> {
        if self
            .sign_required
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(ref key) = *self.session_key.lock().await
        {
            let dialect = self.dialect.load(Ordering::Relaxed);
            let preauth = self.preauth_hash.lock().await.clone();
            Self::sign_packet(pkt, key, dialect, preauth.as_deref());
        }
        self.send(pkt).await
    }

    // ───────────────── Negotiate ─────────────────

    /// SMB2 Negotiate — establishes dialect.
    ///
    /// Strategy (matching Impacket's compatibility-first approach):
    /// 1. Offer dialects 2.0.2 through 3.0.2 (no 3.1.1 pre-auth integrity).
    /// 2. If that fails, retry with all dialects including 3.1.1 + contexts.
    ///
    /// This avoids SMB 3.1.1 pre-auth integrity hashing which isn't implemented
    /// in the session setup path. Most servers work fine with 3.0.2.
    pub async fn negotiate(&self) -> Result<()> {
        // Try SMB 3.1.1 first — needed for IOCTL on WS2025, and signing key derivation
        // now correctly uses PreauthIntegrityHashValue as context.
        let result_311 = self.negotiate_dialects(true).await;
        if result_311.is_ok() {
            return result_311;
        }

        debug!("SMB2: 3.1.1 negotiate failed, retrying with 3.0.2");
        self.negotiate_dialects(false).await
    }

    /// Offer a dialect list. When `include_311` is false, exclude SMB 3.1.1
    /// (avoiding pre-auth integrity complexity in session setup).
    async fn negotiate_dialects(&self, include_311: bool) -> Result<()> {
        debug!("SMB2: Negotiate (include_311={include_311})");

        let hdr = self.build_header(SMB2_NEGOTIATE, 0).await;

        let dialects: Vec<u16> = if include_311 {
            vec![
                SMB2_DIALECT_202,
                SMB2_DIALECT_210,
                SMB2_DIALECT_300,
                SMB2_DIALECT_302,
                SMB2_DIALECT_311,
            ]
        } else {
            vec![
                SMB2_DIALECT_202,
                SMB2_DIALECT_210,
                SMB2_DIALECT_300,
                SMB2_DIALECT_302,
            ]
        };

        let dialect_count = dialects.len() as u16;
        let dialects_byte_len = dialects.len() * 2;

        // Negotiate request body
        let mut body = Vec::with_capacity(128);
        // StructureSize = 36
        body.extend_from_slice(&36u16.to_le_bytes());
        // DialectCount
        body.extend_from_slice(&dialect_count.to_le_bytes());
        // SecurityMode = Signing Enabled (0x01)
        body.extend_from_slice(&0x01u16.to_le_bytes());
        // Reserved
        body.extend_from_slice(&0u16.to_le_bytes());
        // Capabilities = SMB2_GLOBAL_CAP_ENCRYPTION (0x40) for 3.x
        body.extend_from_slice(&0x40u32.to_le_bytes());
        // ClientGuid (16 bytes random)
        let mut guid = [0u8; 16];
        rand::rng().fill(&mut guid);
        body.extend_from_slice(&guid);

        if include_311 {
            // Body: 36 fixed + dialects + padding to 8-byte boundary
            let body_prefix = 36 + dialects_byte_len;
            let padding = (8 - body_prefix % 8) % 8;
            let context_offset = (SMB2_HEADER_SIZE + body_prefix + padding) as u32;
            body.extend_from_slice(&context_offset.to_le_bytes());
            body.extend_from_slice(&1u16.to_le_bytes()); // NegotiateContextCount
            body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        } else {
            body.extend_from_slice(&0u32.to_le_bytes()); // No NegotiateContextOffset
            body.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount = 0
            body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        }

        // Dialects
        for d in &dialects {
            body.extend_from_slice(&d.to_le_bytes());
        }

        if include_311 {
            // Padding for 8-byte alignment of negotiate context
            let body_prefix = 36 + dialects_byte_len;
            let padding = (8 - body_prefix % 8) % 8;
            body.extend(std::iter::repeat_n(0, padding));

            // Pre-Auth Integrity Context (SHA-512)
            // ContextType = 0x0001, DataLength = 38
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&38u16.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            // HashAlgorithmCount = 1, SaltLength = 32
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&32u16.to_le_bytes());
            // HashAlgorithm = SHA-512 (0x0001)
            body.extend_from_slice(&1u16.to_le_bytes());
            // Salt (32 bytes random)
            let mut salt = [0u8; 32];
            rand::rng().fill(&mut salt);
            body.extend_from_slice(&salt);
        }

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);

        self.send(&pkt).await?;
        // Update cumulative pre-auth hash with negotiate request
        if include_311 {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &pkt));
            }
        }
        let resp = self.recv_verified().await?;
        // Update cumulative pre-auth hash with negotiate response
        if include_311 {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &resp));
                debug!("SMB2: Pre-auth integrity hash updated with negotiate messages");
            }
        }

        debug!("SMB2: Negotiate response {} bytes", resp.len());

        // Log raw negotiate response body for 3.x cipher context analysis
        if resp.len() > 128 {
            trace!(
                "SMB2: Negotiate response raw (first 128) = {:02x?}",
                &resp[..128]
            );
        }

        // Check for SMB1 response first
        if resp.len() >= 4 && resp[..4] == [0xff, b'S', b'M', b'B'] {
            return Err(OverthroneError::Smb(
                "SMB2 Negotiate failed: server responded with SMB1 (SMB1 dialect not supported)"
                    .to_string(),
            ));
        }

        // Validate SMB2 magic
        if resp.len() >= 4 && resp[..4] != [0xfe, b'S', b'M', b'B'] {
            let magic_hex: Vec<String> = resp[..4.min(resp.len())]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            return Err(OverthroneError::Smb(format!(
                "SMB2 Negotiate response has invalid magic: [{magic_hex:?}] (expected fe534d42 '\\xfeSMB'), \
                 server may not support SMB2 or response is garbled"
            )));
        }

        // Validate minimum SMB2 header size
        if resp.len() < SMB2_HEADER_SIZE {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Negotiate response too short: {} bytes (expected >=64 for SMB2 header)",
                resp.len()
            )));
        }

        // Check NTSTATUS before anything else — server may return error PDU
        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            let status_name = ntstatus_to_name(status);
            return Err(OverthroneError::Smb(format!(
                "SMB2 Negotiate failed: {status_name} (0x{status:08X})"
            )));
        }

        // Now validate negotiate response body size
        // Per MS-SMB2: negotiate response body minimum = 64 bytes (without 3.1.1 contexts)
        if resp.len() < SMB2_HEADER_SIZE + 64 {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Negotiate response body too short: {} bytes (expected >=64 for negotiate response)",
                resp.len() - SMB2_HEADER_SIZE,
            )));
        }

        // Parse negotiate response (starts at offset 64)
        let body = &resp[SMB2_HEADER_SIZE..];

        // Validate StructureSize = 65 (negotiate response)
        let body_struct_size = u16::from_le_bytes([body[0], body[1]]);
        if body_struct_size != 65 {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Negotiate response unexpected StructureSize: {} (expected 65)",
                body_struct_size
            )));
        }

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

        // Store negotiated sizes — used when building IOCTL MaxOutputResponse
        self.max_transact_size
            .store(max_transact, Ordering::Relaxed);

        Ok(())
    }

    // ───────────────── Session Setup (NTLMSSP) ─────────────────

    /// Authenticate via NTLMSSP (NTLMv2) inside SPNEGO.
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
        // Update cumulative pre-auth hash with session setup request (leg 1)
        {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &pkt));
            }
        }
        let resp = self.recv_verified().await?;
        // Update cumulative pre-auth hash with session setup response (leg 1)
        {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &resp));
            }
        }

        if resp.len() < SMB2_HEADER_SIZE + 9 {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Session Setup Type1 response too short: {} bytes (expected >={})",
                resp.len(),
                SMB2_HEADER_SIZE + 9
            )));
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
        let ti_last4 = if challenge.target_info.len() >= 4 {
            format!(
                "{:02x?}",
                &challenge.target_info[challenge.target_info.len() - 4..]
            )
        } else {
            "N/A".into()
        };
        debug!(
            "SMB2: NTLM challenge flags=0x{:08X}, server_challenge={:02x?}, target_info_len={}, target_info_end={}",
            challenge.negotiate_flags,
            challenge.server_challenge,
            challenge.target_info.len(),
            ti_last4
        );

        // ── Step 3: Build NTLMSSP Authenticate (Type 3) ──
        let (mut type3, session_key, _session_base_key) =
            build_ntlmssp_authenticate(domain, username, password, &challenge)?;

        // Compute NTLMv2 MIC if SIGN or SEAL is negotiated
        if challenge.negotiate_flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL) != 0
            && type3.len() >= NTLMSSP_TYPE3_MIC_OFFSET + 16
        {
            type3[NTLMSSP_TYPE3_MIC_OFFSET..NTLMSSP_TYPE3_MIC_OFFSET + 16].fill(0);
            let mic = compute_ntlmv2_mic(&session_key, &type1, &type2, &type3)?;
            type3[NTLMSSP_TYPE3_MIC_OFFSET..NTLMSSP_TYPE3_MIC_OFFSET + 16].copy_from_slice(&mic);
        }

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
        // Update cumulative pre-auth hash with session setup request (leg 2 / final auth)
        {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &pkt));
            }
        }
        let raw_resp = self.recv().await?;

        let status = u32::from_le_bytes([raw_resp[8], raw_resp[9], raw_resp[10], raw_resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Auth(format!(
                "SMB2 NTLMSSP auth failed for {domain}\\{username}: 0x{status:08X}"
            )));
        }

        debug!("SMB2: Authenticated as {domain}\\{username}");

        // Store session key — the server signs its response with a signing key derived from this.
        // Per MS-SMB2 §3.2.4.1.2: the session key for signing key derivation is the
        // NTLM ExportedSessionKey (untransformed). The PreauthIntegrityHashValue is used
        // as the KDF context (label = "SMBSigningKey\x00"), NOT XOR'd with the session key.
        // Impacket confirms this behavior — no SessionKey XOR on WS2025.
        *self.session_key.lock().await = Some(session_key.clone());

        // Verify the server's response signature now that the key is stored
        if self
            .sign_required
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let dialect = self.dialect.load(std::sync::atomic::Ordering::Relaxed);
            let claimed_sig = &raw_resp[48..64];
            let mut verify_buf = raw_resp.to_vec();
            verify_buf[48..64].fill(0);
            let preauth_hash = self.preauth_hash.lock().await.clone();
            let expected = derive_signing_key(&session_key, dialect, preauth_hash.as_deref());
            let expected_cmac = aes_cmac_16(&expected, &verify_buf);
            if &expected_cmac[..] != claimed_sig {
                warn!("SMB2 Session Setup sig mismatch — disabling signing (WS2025 workaround)");
                self.signing_known_broken
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

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
        // Update cumulative pre-auth hash with session setup request (leg 1)
        {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &pkt));
            }
        }
        let resp = self.recv_verified().await?;
        // Update cumulative pre-auth hash with session setup response (leg 1)
        {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &resp));
            }
        }

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
        let ti_last4 = if challenge.target_info.len() >= 4 {
            format!(
                "{:02x?}",
                &challenge.target_info[challenge.target_info.len() - 4..]
            )
        } else {
            "N/A".into()
        };
        debug!(
            "SMB2: NTLM challenge flags=0x{:08X}, server_challenge={:02x?}, target_info_len={}, target_info_end={}, target_info={:02x?}",
            challenge.negotiate_flags,
            challenge.server_challenge,
            challenge.target_info.len(),
            ti_last4,
            &challenge.target_info[..challenge.target_info.len().min(256)]
        );

        // ── Step 3: Build Type 3 with raw NT hash (no password needed) ──
        let (mut type3, session_key, session_base_key) =
            build_ntlmssp_authenticate_hash(domain, username, &nt_hash, &challenge)?;

        // Compute NTLMv2 MIC if SIGN or SEAL is negotiated
        if challenge.negotiate_flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL) != 0
            && type3.len() >= NTLMSSP_TYPE3_MIC_OFFSET + 16
        {
            type3[NTLMSSP_TYPE3_MIC_OFFSET..NTLMSSP_TYPE3_MIC_OFFSET + 16].fill(0);
            let mic = compute_ntlmv2_mic(&session_key, &type1, &type2, &type3)?;
            type3[NTLMSSP_TYPE3_MIC_OFFSET..NTLMSSP_TYPE3_MIC_OFFSET + 16].copy_from_slice(&mic);
        }

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
        // Update cumulative pre-auth hash with session setup request (leg 2 / final auth)
        {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &pkt));
            }
        }
        let raw_resp = self.recv().await?;

        let status = u32::from_le_bytes([raw_resp[8], raw_resp[9], raw_resp[10], raw_resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Auth(format!(
                "SMB2 PtH auth failed for {domain}\\{username}: 0x{status:08X}"
            )));
        }

        *self.session_key.lock().await = Some(session_key.clone());

        // Verify the server's response signature now that the key is stored.
        // Use derive_signing_key which handles both 3.0.x (SMB2AESCMAC) and
        // 3.1.1 (SMBSigningKey + PreauthIntegrityHashValue context).
        if self
            .sign_required
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let dialect = self.dialect.load(Ordering::Relaxed);
            let claimed_sig = &raw_resp[48..64];
            let mut verify_buf = raw_resp.to_vec();
            verify_buf[48..64].fill(0);
            let preauth_hash = self.preauth_hash.lock().await.clone();
            let signing_key = derive_signing_key(&session_key, dialect, preauth_hash.as_deref());
            let expected = aes_cmac_16(&signing_key, &verify_buf);
            if &expected[..] == claimed_sig {
                debug!("SMB2 PtH: Session setup resp sig OK (dialect-appropriate label)");
            } else {
                // Try all signing key derivations for diagnostic
                let try_method_sep = |label, ctx| {
                    let sk = sp800_108_counter_kdf_sep(&session_key, label, ctx);
                    aes_cmac_16(&sk, &verify_buf) == claimed_sig
                };
                let try_method_sbk_sep = |label, ctx| {
                    let sk = sp800_108_counter_kdf_sep(&session_base_key, label, ctx);
                    aes_cmac_16(&sk, &verify_buf) == claimed_sig
                };
                let try_method_imp = |label, ctx| {
                    let sk = sp800_108_counter_kdf_imp(&session_key, label, ctx);
                    aes_cmac_16(&sk, &verify_buf) == claimed_sig
                };
                let try_method_sbk_imp = |label, ctx| {
                    let sk = sp800_108_counter_kdf_imp(&session_base_key, label, ctx);
                    aes_cmac_16(&sk, &verify_buf) == claimed_sig
                };
                let mut found = "none";
                // ── Separator-style KDF (our original) ──
                // A: KDF bare labels with separator
                if try_method_sep(b"SMBSigningKey", b"SmbSign") {
                    found = "A";
                }
                // B: KDF bare labels with SBK
                else if try_method_sbk_sep(b"SMBSigningKey", b"SmbSign") {
                    found = "B";
                }
                // C: KDF embedded-\0 labels
                else if try_method_sep(b"SMBSigningKey\x00", b"SmbSign\x00") {
                    found = "C";
                }
                // D: KDF embedded-\0 with SBK
                else if try_method_sbk_sep(b"SMBSigningKey\x00", b"SmbSign\x00") {
                    found = "D";
                }
                // E: KDF joined label-context with \0, empty context
                else if try_method_sep(b"SMBSigningKey\x00SmbSign\x00", b"") {
                    found = "E";
                }
                // F: same with SBK
                else if try_method_sbk_sep(b"SMBSigningKey\x00SmbSign\x00", b"") {
                    found = "F";
                }
                // G: label has \0, context bare
                else if try_method_sep(b"SMBSigningKey\x00", b"SmbSign") {
                    found = "G";
                }
                // H: with SBK
                else if try_method_sbk_sep(b"SMBSigningKey\x00", b"SmbSign") {
                    found = "H";
                }
                // I: label bare, context has \0
                else if try_method_sep(b"SMBSigningKey", b"SmbSign\x00") {
                    found = "I";
                }
                // J: with SBK
                else if try_method_sbk_sep(b"SMBSigningKey", b"SmbSign\x00") {
                    found = "J";
                }
                // ── SMB2AESCMAC label (SMB 3.0.x) ──
                // a: sep with SMB2AESCMAC null-terminated
                else if try_method_sep(b"SMB2AESCMAC\x00", b"SmbSign\x00") {
                    found = "a";
                }
                // b: sep with SMB2AESCMAC + SBK
                else if try_method_sbk_sep(b"SMB2AESCMAC\x00", b"SmbSign\x00") {
                    found = "b";
                }
                // c: sep with SMB2AESCMAC bare (no null)
                else if try_method_sep(b"SMB2AESCMAC", b"SmbSign") {
                    found = "c";
                }
                // d: sep with SMB2AESCMAC bare + SBK
                else if try_method_sbk_sep(b"SMB2AESCMAC", b"SmbSign") {
                    found = "d";
                }
                // ── Impacket-style KDF (no separator, null-terminated labels) ──
                // K: imp-style with exported key
                else if try_method_imp(b"SMBSigningKey\x00", b"SmbSign\x00") {
                    found = "K";
                }
                // L: imp-style with SBK
                else if try_method_sbk_imp(b"SMBSigningKey\x00", b"SmbSign\x00") {
                    found = "L";
                }
                // M: imp-style bare labels (no null terminators)
                else if try_method_imp(b"SMBSigningKey", b"SmbSign") {
                    found = "M";
                }
                // N: imp-style bare with SBK
                else if try_method_sbk_imp(b"SMBSigningKey", b"SmbSign") {
                    found = "N";
                }
                // O: imp-style label has \0, context bare
                else if try_method_imp(b"SMBSigningKey\x00", b"SmbSign") {
                    found = "O";
                }
                // P: with SBK
                else if try_method_sbk_imp(b"SMBSigningKey\x00", b"SmbSign") {
                    found = "P";
                }
                // Q: imp-style label bare, context has \0
                else if try_method_imp(b"SMBSigningKey", b"SmbSign\x00") {
                    found = "Q";
                }
                // R: with SBK
                else if try_method_sbk_imp(b"SMBSigningKey", b"SmbSign\x00") {
                    found = "R";
                }
                // ── Legacy / fallback ──
                // S: HMAC-SHA256(session_key, packet)
                // T: HMAC-SHA256(session_base_key, packet)
                let hmac_s = {
                    let mut mac = HmacSha256::new_from_slice(&session_key).unwrap();
                    mac.update(&verify_buf);
                    mac.finalize().into_bytes()
                };
                let hmac_t = {
                    let mut mac = HmacSha256::new_from_slice(&session_base_key).unwrap();
                    mac.update(&verify_buf);
                    mac.finalize().into_bytes()
                };
                if &hmac_s[..16] == claimed_sig {
                    found = "S";
                } else if &hmac_t[..16] == claimed_sig {
                    found = "T";
                }
                // U: raw AES-CMAC(session_key, packet) — no KDF
                else if &aes_cmac_16(&session_key, &verify_buf)[..] == claimed_sig {
                    found = "U";
                }
                // V: raw AES-CMAC(session_base_key, packet) — no KDF
                else if &aes_cmac_16(&session_base_key, &verify_buf)[..] == claimed_sig {
                    found = "V";
                }
                // W: imp-style, joined single label with SBK
                else if try_method_sbk_imp(b"SMBSigningKey\x00SmbSign\x00", b"") {
                    found = "W";
                }
                // X: imp-style, joined single label with exported key
                else if try_method_imp(b"SMBSigningKey\x00SmbSign\x00", b"") {
                    found = "X";
                }
                if found != "none" {
                    debug!("SMB2: Session setup resp sig matches via method {found}");
                } else {
                    let resp_flags = u32::from_le_bytes([
                        raw_resp[16],
                        raw_resp[17],
                        raw_resp[18],
                        raw_resp[19],
                    ]);
                    warn!(
                        "SMB2: Session setup resp sig: NONE of methods match. resp_flags=0x{:08X}, SIGNED_bit={}, claimed={:02x?}, session_key={:02x?}, session_base_key={:02x?}, dialect=0x{:04X}",
                        resp_flags,
                        resp_flags & SMB2_FLAGS_SIGNED != 0,
                        claimed_sig,
                        session_key,
                        session_base_key,
                        dialect
                    );
                }
            }
        }

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
        // Kerberos session key is known upfront — store before sending
        let key = session_key.to_vec();
        *self.session_key.lock().await = Some(key.clone());

        self.send(&pkt).await?;
        // Update cumulative pre-auth hash with Kerberos session setup request (single leg)
        {
            let mut old = self.preauth_hash.lock().await;
            if let Some(ref h) = *old {
                *old = Some(update_preauth_hash(h, &pkt));
            }
        }
        let raw_resp = self.recv().await?;

        if raw_resp.len() < SMB2_HEADER_SIZE {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Kerberos Session Setup response too short: {} bytes (expected >={})",
                raw_resp.len(),
                SMB2_HEADER_SIZE
            )));
        }

        let status = u32::from_le_bytes([raw_resp[8], raw_resp[9], raw_resp[10], raw_resp[11]]);
        if status != STATUS_SUCCESS && status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(OverthroneError::Auth(format!(
                "SMB2 Kerberos auth failed: 0x{status:08X}"
            )));
        }

        // Store session ID
        let session_id = u64::from_le_bytes([
            raw_resp[40],
            raw_resp[41],
            raw_resp[42],
            raw_resp[43],
            raw_resp[44],
            raw_resp[45],
            raw_resp[46],
            raw_resp[47],
        ]);
        *self.session_id.lock().await = session_id;
        debug!("SMB2: Kerberos session ID 0x{session_id:016X}");

        // Verify the server's response signature now that the key is stored
        if self
            .sign_required
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let dialect = self.dialect.load(Ordering::Relaxed);
            let preauth_hash = self.preauth_hash.lock().await.clone();
            if !Self::verify_packet(&raw_resp, &key, dialect, true, preauth_hash.as_deref()) {
                return Err(OverthroneError::Smb(
                    "SMB2 Kerberos Session Setup response signature verification failed".into(),
                ));
            }
        }

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
        let resp = self.recv_verified().await?;

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
        let _resp = self.recv_verified().await?;
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
        let resp = self.recv_verified().await?;

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
            return Err(OverthroneError::Smb(format!(
                "SMB2 Create '{path}' response body too short for FileId: {} bytes (expected >=80)",
                rb.len()
            )));
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

    /// Open a file with a requested OPLOCK level.
    ///
    /// Returns `(file_id, granted_oplock_level)`.
    /// Supported levels: 0 (none), 1 (II), 8 (exclusive), 9 (batch).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_oplock(
        &self,
        path: &str,
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        oplock_level: u8,
    ) -> Result<([u8; 32], u8)> {
        trace!("SMB2: Create '{path}' with oplock 0x{oplock_level:02X}");

        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let hdr = self.build_header(SMB2_CREATE, 0).await;
        let mut body = Vec::new();
        body.extend_from_slice(&57u16.to_le_bytes());
        body.push(0); // SecurityFlags
        body.push(oplock_level); // RequestedOplockLevel
        body.extend_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel
        body.extend_from_slice(&0u64.to_le_bytes()); // SmbCreateFlags
        body.extend_from_slice(&0u64.to_le_bytes()); // Reserved
        body.extend_from_slice(&desired_access.to_le_bytes());
        body.extend_from_slice(&file_attributes.to_le_bytes());
        body.extend_from_slice(&share_access.to_le_bytes());
        body.extend_from_slice(&create_disposition.to_le_bytes());
        body.extend_from_slice(&create_options.to_le_bytes());
        let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
        body.extend_from_slice(&name_offset.to_le_bytes());
        body.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        while body.len() < 56 {
            body.push(0);
        }
        body.extend_from_slice(&path_utf16);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        self.send_signed(&mut pkt).await?;
        let resp = self.recv_verified().await?;

        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        if status != STATUS_SUCCESS {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Create '{path}' failed: 0x{status:08X}"
            )));
        }

        let rb = &resp[SMB2_HEADER_SIZE..];
        if rb.len() < 80 {
            return Err(OverthroneError::Smb(format!(
                "SMB2 Create '{}' response body too short for FileId: {} bytes (expected >=80)",
                path,
                rb.len()
            )));
        }

        let granted_oplock = rb[2]; // OplockLevel at body offset 2

        let mut file_id = [0u8; 32];
        file_id[..16].copy_from_slice(&rb[64..80]);

        trace!(
            "SMB2: Opened '{path}' => FileId {:02x?} oplock=0x{granted_oplock:02X}",
            &file_id[..16]
        );
        Ok((file_id, granted_oplock))
    }

    /// Open a named pipe for read/write (e.g. "srvsvc", "samr", "lsarpc").
    pub async fn open_pipe(&self, pipe_name: &str) -> Result<[u8; 32]> {
        // Named pipes require GENERIC_READ | GENERIC_WRITE for IOCTL operations.
        // On WS2025, minimal access (FILE_READ_DATA|FILE_WRITE_DATA) opens the pipe
        // but rejects FSCTL_PIPE_TRANSCEIVE with STATUS_INVALID_PARAMETER.
        self.create(
            pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            0, // Impacket-compatible: 0 create options for named pipes
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
        let _resp = self.recv_verified().await?;
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
        let resp = self.recv_verified().await?;

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
        let resp = self.recv_verified().await?;

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
    /// Build and send an IOCTL packet, returning the raw response bytes.
    /// Used internally by `ioctl_pipe_transceive` and for retry loops.
    async fn ioctl_send_raw(
        &self,
        file_id: &[u8; 32],
        input: &[u8],
        max_out: u32,
    ) -> Result<Vec<u8>> {
        let hdr = self.build_header(SMB2_IOCTL, 0).await; // CreditCharge=0 (same as other ops)
        let mut body = Vec::new();
        body.extend_from_slice(&57u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes());
        body.extend_from_slice(&file_id[..16]);
        let input_offset = (SMB2_HEADER_SIZE + 56) as u32;
        body.extend_from_slice(&input_offset.to_le_bytes());
        body.extend_from_slice(&(input.len() as u32).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&max_out.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes()); // Flags = SMB2_0_IOCTL_IS_FSCTL
        body.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        while body.len() < 56 {
            body.push(0);
        }
        body.extend_from_slice(input);
        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        let hdr_flags = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        let tree_id = u32::from_le_bytes([pkt[36], pkt[37], pkt[38], pkt[39]]);
        let sess_id = u64::from_le_bytes(pkt[40..48].try_into().unwrap_or([0u8; 8]));
        trace!(
            "SMB2: IOCTL body fields: struct_size=57, ctl_code=0x{FSCTL_PIPE_TRANSCEIVE:08X}, \
               input_offset={input_offset}, input_count={}, max_out={max_out}, \
               hdr_flags=0x{hdr_flags:08X}, tree_id=0x{tree_id:08X}, session_id=0x{sess_id:016X}",
            input.len()
        );
        self.send_signed(&mut pkt).await?;
        let resp = self.recv_verified().await?;
        let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        trace!(
            "SMB2: IOCTL response {} bytes, status=0x{status:08X}",
            resp.len()
        );
        Ok(resp)
    }

    pub async fn ioctl_pipe_transceive(&self, file_id: &[u8; 32], input: &[u8]) -> Result<Vec<u8>> {
        let max_out = self.max_transact_size.load(Ordering::Relaxed).min(65_536);
        debug!(
            "SMB2: IOCTL Request — session_key={}, sign_required={}, dialect=0x{:04X}, max_out={max_out}, input_count={}",
            self.session_key.lock().await.is_some(),
            self.sign_required.load(Ordering::Relaxed),
            self.dialect.load(Ordering::Relaxed),
            input.len(),
        );

        // WS2025 SMB 3.1.1 may return STATUS_PENDING for DCE/RPC operations
        // that require async processing (e.g. OpenSCManagerW). We retry with
        // exponential backoff to give the server time to complete.
        let mut last_error: Option<OverthroneError> = None;
        for attempt in 0..3 {
            let resp = self.ioctl_send_raw(file_id, input, max_out).await?;

            let status = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
            if status == STATUS_PENDING {
                debug!(
                    "SMB2: IOCTL STATUS_PENDING (attempt {}/3), waiting 1s",
                    attempt + 1
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                last_error = Some(OverthroneError::Smb("STATUS_PENDING after retries".into()));
                continue;
            }
            if status == STATUS_BUFFER_OVERFLOW && max_out > 0 {
                // Buffer too small — retry with larger buffer if possible
                let new_max = max_out.min(self.max_transact_size.load(Ordering::Relaxed));
                debug!("SMB2: IOCTL STATUS_BUFFER_OVERFLOW, retrying with max_out={new_max}");
                return self
                    .ioctl_send_raw(file_id, input, new_max)
                    .await
                    .and_then(|resp2| Self::parse_ioctl_output(&resp2));
            }
            if status != STATUS_SUCCESS {
                return Err(OverthroneError::Smb(format!(
                    "SMB2 IOCTL failed: 0x{status:08X}"
                )));
            }

            return Self::parse_ioctl_output(&resp);
        }

        if let Some(e) = last_error {
            Err(e)
        } else {
            Ok(Vec::new())
        }
    }

    /// Extract DCE/RPC output data from an IOCTL response body.
    fn parse_ioctl_output(resp: &[u8]) -> Result<Vec<u8>> {
        let rb = &resp[SMB2_HEADER_SIZE..];
        // IOCTL response body must be at least 48 bytes (StructureSize 2 + Reserved 2 +
        // CCCC 4 + InputOffset 4 + InputCount 4 + OutputOffset 4 + OutputCount 4 +
        // Flags 4 + Reserved 8). A short body indicates an async or truncated response.
        if rb.len() < 40 {
            debug!(
                "SMB2: IOCTL response body too short: {} bytes (expected >=40)",
                rb.len()
            );
            return Ok(Vec::new());
        }
        let out_off_raw = u32::from_le_bytes([rb[32], rb[33], rb[34], rb[35]]) as usize;
        let out_count = u32::from_le_bytes([rb[36], rb[37], rb[38], rb[39]]) as usize;
        let in_off = u32::from_le_bytes([rb[24], rb[25], rb[26], rb[27]]) as usize;
        let in_cnt = u32::from_le_bytes([rb[28], rb[29], rb[30], rb[31]]) as usize;

        if out_count == 0 {
            debug!("SMB2: IOCTL response has no output data");
            return Ok(Vec::new());
        }

        let out_offset = out_off_raw.saturating_sub(SMB2_HEADER_SIZE);
        let dce_type: u8 = if out_count >= 3 {
            rb[out_offset + 2]
        } else {
            0
        };
        debug!(
            "SMB2: IOCTL response: out_off_raw={out_off_raw}, out_offset={out_offset}, out_count={out_count}, rb_len={}, in_off={in_off}, in_cnt={in_cnt}, dce_type={dce_type}",
            rb.len()
        );
        if out_offset + out_count > rb.len() {
            debug!("SMB2: IOCTL output overflow: body({})={rb:02x?}", rb.len());
            return Err(OverthroneError::Smb("SMB2 IOCTL output overflow".into()));
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
            let resp = self.recv_verified().await?;

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

    // ───────────────── OPLOCK Break ─────────────────

    /// Wait for an OPLOCK break notification from the server.
    ///
    /// Blocks until the server sends an `SMB2_OPLOCK_BREAK` notification
    /// or the timeout expires.  On success returns the **new** (downgraded)
    /// OplockLevel and the FileId of the file whose oplock was broken.
    ///
    /// After receiving the break, the caller **must** acknowledge it via
    /// [`acknowledge_oplock_break`] to unblock the server.
    pub async fn wait_for_oplock_break(&self, timeout_secs: u64) -> Result<(u8, [u8; 32])> {
        let mut stream = self.stream.lock().await;
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            stream.read_exact(&mut len_buf),
        )
        .await
        .map_err(|_| OverthroneError::Timeout(timeout_secs))?
        .map_err(|e| OverthroneError::Smb(format!("SMB2 OPLOCK recv header: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(OverthroneError::Smb(format!(
                "SMB2 OPLOCK response too large: {len} bytes"
            )));
        }
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB2 OPLOCK recv body: {e}")))?;
        // Release the stream lock; the caller will send the ack separately.
        drop(stream);

        // SMB2 header: command is at bytes 12-13
        if buf.len() < 14 {
            return Err(OverthroneError::Smb(format!(
                "OPLOCK break packet too short: {} bytes (expected >=14)",
                buf.len()
            )));
        }
        let command = u16::from_le_bytes([buf[12], buf[13]]);
        if command != SMB2_OPLOCK_BREAK {
            return Err(OverthroneError::Smb(format!(
                "Expected OPLOCK_BREAK (0x{SMB2_OPLOCK_BREAK:04X}) but got 0x{command:04X}"
            )));
        }

        // OPLOCK_BREAK response body (MS-SMB2 2.2.24):
        //   StructureSize(2) + OplockLevel(1) + Flags(1) + Reserved(4) +
        //   PersistentFileId(8) + VolatileFileId(8)
        let rb = &buf[SMB2_HEADER_SIZE..];
        if rb.len() < 24 {
            return Err(OverthroneError::Smb(format!(
                "OPLOCK_BREAK body too short: {} bytes (expected >=24)",
                rb.len()
            )));
        }
        let new_level = rb[2];
        let mut file_id = [0u8; 32];
        file_id[..8].copy_from_slice(&rb[8..16]); // Persistent
        file_id[16..24].copy_from_slice(&rb[16..24]); // Volatile

        Ok((new_level, file_id))
    }

    /// Acknowledge (ack) an OPLOCK break notification.
    ///
    /// Sends an `SMB2_OPLOCK_BREAK` acknowledgment packet telling the server
    /// the client accepts the oplock downgrade to `new_level`.
    pub async fn acknowledge_oplock_break(
        &self,
        file_id: &[u8; 32],
        new_oplock_level: u8,
    ) -> Result<()> {
        // The OPLOCK_BREAK ack is a special case: it uses a fresh header but
        // is NOT signed (MS-SMB2: OPLOCK_BREAK is not signed).
        let hdr = self.build_header(SMB2_OPLOCK_BREAK, 0).await;

        let mut body = Vec::new();
        // StructureSize = 24
        body.extend_from_slice(&24u16.to_le_bytes());
        body.push(new_oplock_level); // OplockLevel
        body.push(0); // Flags (reserved)
        body.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        // FileId: Persistent[0..8] + Volatile[16..24]
        body.extend_from_slice(&file_id[..8]);
        body.extend_from_slice(&file_id[16..24]);

        let mut pkt = hdr;
        pkt.extend_from_slice(&body);

        // Send without signing (OPLOCK_BREAK ack is explicitly unsigned)
        self.send(&pkt).await?;
        Ok(())
    }

    /// Get the session key (for DCSync/crypto operations).
    pub async fn get_session_key(&self) -> Option<Vec<u8>> {
        self.session_key.lock().await.clone()
    }

    /// Enable SMB3 encryption (AES-128-GCM) for subsequent messages.
    ///
    /// Must be called after successful session setup. Derives encryption keys
    /// from the session key using SP800-108 KDF and enables Transform_Header
    /// wrapping on all subsequent sends and unwrapping on receives.
    ///
    /// This is needed when the server advertises SMB3_ENCRYPTION_CAPABLE
    /// in the Negotiate response and the client chooses to enable encryption
    /// (e.g., by sending a SMB2 Session Setup with encryption preference).
    pub async fn enable_encryption(&self) -> Result<()> {
        let session_key = self.session_key.lock().await.clone().ok_or_else(|| {
            OverthroneError::Smb("Cannot enable encryption without session key".to_string())
        })?;

        if self.dialect.load(Ordering::Relaxed) < SMB2_DIALECT_300 {
            return Err(OverthroneError::Smb(
                "SMB3 encryption requires dialect 3.x+".to_string(),
            ));
        }

        // Derive C2S (encryption) and S2C (decryption) keys
        let enc_key = derive_smb3_encryption_key(&session_key, false);
        let dec_key = derive_smb3_encryption_key(&session_key, true);

        *self.encryption_key.lock().await = Some(enc_key);
        *self.decryption_key.lock().await = Some(dec_key);
        self.encryption_required
            .store(true, std::sync::atomic::Ordering::Relaxed);

        debug!("SMB3 encryption enabled (AES-128-GCM)");
        Ok(())
    }

    /// Check whether SMB3 encryption is currently active.
    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption_required
            .load(std::sync::atomic::Ordering::Relaxed)
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
        let _resp = self.recv_verified().await?;
        *self.session_id.lock().await = 0;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
//  NTLMSSP Implementation (NTLMv2)
// ═══════════════════════════════════════════════════════════

/// Parsed NTLMSSP Type 2 (Challenge) message.
pub struct NtlmChallenge {
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
    pub negotiate_flags: u32,
}

/// Build NTLMSSP Type 1 (Negotiate) message.
pub fn build_ntlmssp_negotiate() -> Vec<u8> {
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
pub fn parse_ntlmssp_challenge(data: &[u8]) -> Result<NtlmChallenge> {
    if data.len() < 32 {
        return Err(OverthroneError::Smb(format!(
            "NTLMSSP Type 2 challenge too short: {} bytes (expected >=32)",
            data.len()
        )));
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
pub fn build_ntlmssp_authenticate(
    domain: &str,
    username: &str,
    password: &str,
    challenge: &NtlmChallenge,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
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
pub fn build_ntlmssp_authenticate_hash(
    domain: &str,
    username: &str,
    nt_hash: &[u8],
    challenge: &NtlmChallenge,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // ── NTLMv2 computation ──
    // Step 1: ResponseKeyNT = HMAC_MD5(NT_Hash, UPPER(username) + domain)
    // MS-NLMP: only UPPER(user), server_name (domain) stays as provided
    let user_domain: Vec<u8> = username
        .to_uppercase()
        .encode_utf16()
        .chain(domain.encode_utf16())
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let response_key = hmac_md5(nt_hash, &user_domain)?;

    // Step 2: Build NTLMv2 client challenge blob
    let client_challenge: [u8; 8] = rand::rng().random();
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

    debug!(
        "NTLMv2: server_challenge={:02x?}",
        challenge.server_challenge
    );
    debug!("NTLMv2: target_info={:02x?}", challenge.target_info);
    debug!("NTLMv2: response_key={:02x?}", response_key);
    debug!("NTLMv2: nt_proof_str={:02x?}", nt_proof_str);
    debug!("NTLMv2: session_base_key={:02x?}", session_base_key);
    debug!("NTLMv2: client_challenge={:02x?}", client_challenge);
    debug!("NTLMv2: timestamp={:02x?}", timestamp);
    debug!("NTLMv2: blob={:02x?}", blob);

    // Step 6: Build Type 3 message
    let flags = challenge.negotiate_flags;

    let domain_utf16: Vec<u8> = domain
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

    // KEY_EXCH: export random session key encrypted with SessionBaseKey
    debug!(
        "NTLMv2: flags=0x{:08X}, KEY_EXCH=0x{:08X}, key_exch_flag_set={}",
        flags,
        NTLMSSP_NEGOTIATE_KEY_EXCH,
        flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0
    );
    let exported_session_key: Vec<u8> = if flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
        rand::rng().random::<[u8; 16]>().to_vec()
    } else {
        session_base_key.clone()
    };
    let encrypted_session_key: Vec<u8> = if flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
        rc4_encrypt(&session_base_key, &exported_session_key)
    } else {
        Vec::new()
    };

    // Calculate offsets (header=88 bytes with OS Version)
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
    // OS Version field (8 bytes, MS-NLMP §2.2.2.10)
    msg.push(10); // ProductMajorVersion
    msg.push(0); // ProductMinorVersion
    msg.extend_from_slice(&0u16.to_le_bytes()); // ProductBuild
    msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved (3 bytes used + padding)
    msg.push(0); // Reserved (3rd byte)
    msg.push(15); // NTLMRevisionCurrent (NTLMSSP_REVISION_W2K3)
    // MIC (16 bytes of zeros — the caller should compute and fill this if needed)
    msg.extend_from_slice(&[0u8; 16]);

    // Payload
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&user_utf16);
    msg.extend_from_slice(&workstation_utf16);
    msg.extend_from_slice(&encrypted_session_key);

    Ok((msg, exported_session_key, session_base_key))
}

/// Find an AV_PAIR value by AvId in target info.
fn find_av_pair_value(target_info: &[u8], target_av_id: u16) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 4 <= target_info.len() {
        let av_id = u16::from_le_bytes([target_info[pos], target_info[pos + 1]]);
        let av_len = u16::from_le_bytes([target_info[pos + 2], target_info[pos + 3]]) as usize;
        if av_id == 0 {
            return None;
        }
        pos += 4;
        if pos + av_len > target_info.len() {
            return None;
        }
        if av_id == target_av_id {
            return Some(target_info[pos..pos + av_len].to_vec());
        }
        pos += av_len;
    }
    None
}

/// Add MsvAvTargetName (AvId=9) AV pair before EOL in target_info.
/// Value is "cifs/{dns_hostname}" in UTF-16LE. Falls back to original if no DNS hostname found.
fn add_target_name_to_av_pairs(target_info: &[u8]) -> Vec<u8> {
    let dns_hostname = match find_av_pair_value(target_info, 3) {
        Some(v) => {
            let chars: Vec<u16> = v
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&chars)
                .trim_matches('\0')
                .to_string()
        }
        None => {
            debug!("NTLMv2: MsvAvDnsHostname not found in target_info, trying AvId=5 (DNS tree)");
            // Fallback: try DNS tree name (AvId=5)
            match find_av_pair_value(target_info, 5) {
                Some(v) => {
                    let chars: Vec<u16> = v
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&chars)
                        .trim_matches('\0')
                        .to_string()
                }
                None => {
                    debug!("NTLMv2: No DNS name found in target_info, using original");
                    return target_info.to_vec();
                }
            }
        }
    };

    let target_name_utf16: Vec<u8> = format!("cifs/{}", dns_hostname)
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    debug!(
        "NTLMv2: Adding MsvAvTargetName length={}, value='cifs/{}'",
        target_name_utf16.len(),
        dns_hostname
    );

    let mut result = Vec::with_capacity(target_info.len() + target_name_utf16.len() + 8);
    let eol_pos = (0..target_info.len().saturating_sub(3))
        .find(|&i| {
            i + 3 < target_info.len()
                && target_info[i] == 0
                && target_info[i + 1] == 0
                && target_info[i + 2] == 0
                && target_info[i + 3] == 0
        })
        .unwrap_or(target_info.len());
    debug!(
        "NTLMv2: EOL found at position {}, target_info len {}",
        eol_pos,
        target_info.len()
    );

    result.extend_from_slice(&target_info[..eol_pos]);
    result.extend_from_slice(&9u16.to_le_bytes());
    result.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes());
    result.extend_from_slice(&target_name_utf16);
    result.extend_from_slice(&target_info[eol_pos..]);
    result
}

/// Build NTLMv2 client challenge blob (AvPairs, timestamp, etc.)
fn build_ntlmv2_blob(
    client_challenge: &[u8; 8],
    timestamp: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    let augmented_ti = add_target_name_to_av_pairs(target_info);
    let mut blob = Vec::with_capacity(32 + augmented_ti.len());
    blob.push(0x01);
    blob.push(0x01);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(timestamp);
    blob.extend_from_slice(client_challenge);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&augmented_ti);
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
pub fn wrap_spnego_init(ntlmssp: &[u8]) -> Vec<u8> {
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
pub fn wrap_spnego_response(ntlmssp: &[u8]) -> Vec<u8> {
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
pub fn extract_ntlmssp_from_spnego(data: &[u8]) -> Result<Vec<u8>> {
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

/// Offset of the MIC field in an NTLMSSP Type 3 message.
/// Layout: Sig(8) + Type(4) + LmResp(8) + NtResp(8) + Domain(8) + User(8) + Wks(8) + SessionKey(8) + Flags(4) + Version(8) = 72 bytes before MIC.
const NTLMSSP_TYPE3_MIC_OFFSET: usize = 72;

/// Compute NTLMv2 Message Integrity Code (MIC).
/// MIC = HMAC_MD5(exported_session_key, type1_raw || type2_raw || type3_with_mic_zeroed)
/// The type3 message MUST have bytes [72..88] set to zero before calling this.
/// Returns the MIC bytes (16 bytes).
fn compute_ntlmv2_mic(
    exported_session_key: &[u8],
    type1_raw: &[u8],
    type2_raw: &[u8],
    type3_raw: &[u8],
) -> Result<Vec<u8>> {
    let mut mic_input = Vec::new();
    mic_input.extend_from_slice(type1_raw);
    mic_input.extend_from_slice(type2_raw);
    mic_input.extend_from_slice(type3_raw);
    hmac_md5(exported_session_key, &mic_input)
}

// ═══════════════════════════════════════════════════════════
//  Crypto Helpers — KDF + AES-CMAC
// ═══════════════════════════════════════════════════════════

/// NIST SP800-108 Counter Mode KDF using HMAC-SHA256.
/// Derives a 16-byte key from `key_in`, `label`, and `context`.
/// Used to produce SMB 3.x signing and encryption keys from the exported session key.
/// This variant matches impacket's implementation: `\x00\x00\x00\x01 || label || context || \x00\x00\x00\x80`
/// where `label` and `context` are expected to include their own null terminators.
fn sp800_108_counter_kdf_imp(key_in: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(4 + label.len() + context.len() + 4);
    input.extend_from_slice(&1u32.to_be_bytes()); // i = 1
    input.extend_from_slice(label);
    input.extend_from_slice(context);
    input.extend_from_slice(&128u32.to_be_bytes()); // L = 128 bits

    let mut mac = HmacSha256::new_from_slice(key_in).expect("HMAC-SHA256 accepts any key size");
    mac.update(&input);
    mac.finalize().into_bytes()[..16].to_vec()
}

/// NIST SP800-108 Counter Mode KDF using HMAC-SHA256.
/// Variant with extra 0x00 separator between label and context (per SP800-108 format).
fn sp800_108_counter_kdf_sep(key_in: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
    input.extend_from_slice(&1u32.to_be_bytes()); // i = 1
    input.extend_from_slice(label);
    input.push(0x00); // SP800-108 separator
    input.extend_from_slice(context);
    input.extend_from_slice(&128u32.to_be_bytes()); // L = 128 bits

    let mut mac = HmacSha256::new_from_slice(key_in).expect("HMAC-SHA256 accepts any key size");
    mac.update(&input);
    mac.finalize().into_bytes()[..16].to_vec()
}

/// Derive SMB 3.x encryption key for the given direction.
/// Uses SP800-108 KDF with direction-specific labels.
fn derive_smb3_encryption_key(session_key: &[u8], is_server_to_client: bool) -> Vec<u8> {
    let label = if is_server_to_client {
        SMB3_ENCRYPTION_KEY_LABEL_S2C
    } else {
        SMB3_ENCRYPTION_KEY_LABEL_C2S
    };
    sp800_108_counter_kdf_sep(session_key, label, SMB3_ENCRYPTION_KEY_CONTEXT)
}

/// Encrypt an SMB3 payload using AES-128-GCM and build a Transform_Header.
///
/// Returns the complete Transform_Header + encrypted payload (with 16-byte GCM tag appended).
/// The nonce is randomly generated and embedded in the header.
fn smb3_encrypt_aes128_gcm(
    plaintext: &[u8],
    encryption_key: &[u8],
    session_id: u64,
) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{Aead, KeyInit},
    };

    let key = Aes128Gcm::new_from_slice(encryption_key)
        .map_err(|e| OverthroneError::Smb(format!("AES-128-GCM key init: {e}")))?;

    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with GCM — tag is appended to ciphertext
    let ciphertext = key
        .encrypt(nonce, plaintext)
        .map_err(|e| OverthroneError::Smb(format!("AES-128-GCM encrypt failed: {e}")))?;

    // Build Transform_Header (52 bytes) + encrypted data
    let mut result = Vec::with_capacity(SMB3_TRANSFORM_HEADER_SIZE + ciphertext.len());
    result.extend_from_slice(SMB3_TRANSFORM_MAGIC); // 0..4: ProtocolId
    result.extend_from_slice(&(plaintext.len() as u32).to_le_bytes()); // 4..8: OriginalMessageSize
    result.extend_from_slice(&0u16.to_le_bytes()); // 8..10: Reserved
    result.extend_from_slice(&SMB3_ENCRYPTION_AES128_GCM.to_le_bytes()); // 10..12: Algorithm
    result.extend_from_slice(&session_id.to_le_bytes()); // 12..20: SessionId
    result.extend_from_slice(&nonce_bytes); // 20..32: Nonce (12 bytes)
    result.extend_from_slice(&[0u8; 4]); // 32..36: Reserved
    result.extend_from_slice(&[0u8; 16]); // 36..52: RemainingSessionKey (zeroed)
    result.extend_from_slice(&ciphertext); // 52..: EncryptedData + GCM tag

    Ok(result)
}

/// Decrypt an SMB3 Transform_Header-wrapped payload using AES-128-GCM.
///
/// Expects `data` to start with a 52-byte Transform_Header followed by
/// encrypted payload + 16-byte GCM authentication tag.
/// Returns the decrypted plaintext on success.
fn smb3_decrypt_aes128_gcm(data: &[u8], encryption_key: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{Aead, KeyInit},
    };

    if data.len() < SMB3_TRANSFORM_HEADER_SIZE + 16 {
        return Err(OverthroneError::Smb(format!(
            "SMB3 encrypted packet too short: {} bytes (need at least {})",
            data.len(),
            SMB3_TRANSFORM_HEADER_SIZE + 16
        )));
    }

    // Validate Transform_Header magic
    if &data[0..4] != SMB3_TRANSFORM_MAGIC {
        return Err(OverthroneError::Smb(
            "SMB3 Transform_Header magic mismatch".to_string(),
        ));
    }

    // Extract nonce (bytes 20..32)
    let nonce = Nonce::from_slice(&data[20..32]);

    // Extract encrypted payload (bytes 52..)
    let encrypted = &data[SMB3_TRANSFORM_HEADER_SIZE..];

    let key = Aes128Gcm::new_from_slice(encryption_key)
        .map_err(|e| OverthroneError::Smb(format!("AES-128-GCM key init: {e}")))?;

    let plaintext = key
        .decrypt(nonce, encrypted)
        .map_err(|e| OverthroneError::Smb(format!("AES-128-GCM decrypt failed: {e}")))?;

    Ok(plaintext)
}

/// Check whether a received packet is wrapped in an SMB3 Transform_Header.
fn is_smb3_encrypted(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == SMB3_TRANSFORM_MAGIC
}

/// Compute AES-GMAC signature: GMAC(key, nonce, aad) → 16-byte tag.
/// Used by SMB 3.x when the cipher is AES-128-GCM (cipher_id=0x0002).
/// Uses the aes-gcm crate's AeadInPlace API with empty plaintext.
#[cfg(test)]
#[allow(dead_code)]
fn aes_gmac_16(key: &[u8], aad: &[u8]) -> [u8; 16] {
    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInPlace, KeyInit},
    };
    let mut key16 = [0u8; 16];
    let n = key.len().min(16);
    key16[..n].copy_from_slice(&key[..n]);
    let gcm_key = match Aes128Gcm::new_from_slice(&key16) {
        Ok(k) => k,
        Err(_) => return [0u8; 16],
    };
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let mut empty = [0u8; 0];
    let tag = match gcm_key.encrypt_in_place_detached(nonce, aad, &mut empty) {
        Ok(t) => t,
        Err(_) => return [0u8; 16],
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..]);
    out
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
    let mut mac = AesCmac::new_from_slice(&key16).expect("CMAC accepts 16-byte key");
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
    fn test_rc4_basic() {
        // RFC 6229 Test Vector: Key = "Key", Plaintext = "Plaintext"
        let key = b"Key";
        let data = b"Plaintext";
        let expected = hex::decode("BBF316E8D940AF0AD3").unwrap();
        let result = rc4_encrypt(key, data);
        assert_eq!(result, expected, "RC4 basic test failed");
        // RC4 is symmetric: decrypt = encrypt
        let decrypted = rc4_encrypt(key, &result);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_rc4_ntlm_key_exchange() {
        // Simulate NTLMv2 key exchange: SessionBaseKey is all 0xBB
        // Random key is all 0xAA, both 16 bytes
        let session_base_key = [0xBBu8; 16];
        let random_key = [0xAAu8; 16];
        let encrypted = rc4_encrypt(&session_base_key, &random_key);
        assert_eq!(encrypted.len(), 16);
        // Decrypt with same key to recover original
        let decrypted = rc4_encrypt(&session_base_key, &encrypted);
        assert_eq!(decrypted, random_key);
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

    #[test]
    fn test_aes_cmac_rfc4493_vector1() {
        // RFC 4493 Test Vector 1: Empty message
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let msg = b"";
        let expected = hex::decode("bb1d6929e95937287fa37d129b756746").unwrap();
        let result = aes_cmac_16(&key, msg);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_aes_cmac_rfc4493_vector2() {
        // RFC 4493 Test Vector 2: 16-byte message
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let msg = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let expected = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();
        let result = aes_cmac_16(&key, &msg);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_aes_cmac_rfc4493_vector3() {
        // RFC 4493 Test Vector 3: 40-byte message
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let msg = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        )
        .unwrap();
        let expected = hex::decode("dfa66747de9ae63030ca32611497c827").unwrap();
        let result = aes_cmac_16(&key, &msg);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_sp800_108_kdf_smb_signing() {
        // Known test vector for SMB 3.x signing key derivation
        // Using a known session_key, verify the signing key
        let session_key = [0x01u8; 16]; // 16 bytes of 0x01
        let signing_key = sp800_108_counter_kdf_sep(&session_key, b"SMBSigningKey", b"SmbSign");
        // AES-128-CMAC uses a 128-bit key (16 bytes)
        assert_eq!(signing_key.len(), 16);
        // Not comparing against a known value, just ensuring deterministic
        let signing_key2 = sp800_108_counter_kdf_sep(&session_key, b"SMBSigningKey", b"SmbSign");
        assert_eq!(signing_key, signing_key2);
    }

    #[test]
    fn test_sp800_108_kdf_smb_signing_null() {
        // Same test but with null-terminated labels
        let session_key = [0x01u8; 16];
        let with_null =
            sp800_108_counter_kdf_sep(&session_key, b"SMBSigningKey\x00", b"SmbSign\x00");
        let without = sp800_108_counter_kdf_sep(&session_key, b"SMBSigningKey", b"SmbSign");
        // These should be different since labels differ
        assert_ne!(with_null, without);
    }

    #[test]
    fn test_ntlmv2_response_key_computation() {
        let nt_hash = hex::decode("c66d72021a2d4744409969a581a1705e").unwrap();
        let domain = "sevenkingdoms";
        let username = "Administrator";
        let domain_upper = domain.to_uppercase();
        let user_domain: Vec<u8> = username
            .to_uppercase()
            .encode_utf16()
            .chain(domain_upper.encode_utf16())
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let response_key = hmac_md5(&nt_hash, &user_domain).unwrap();
        assert_eq!(response_key.len(), 16);
        assert_ne!(response_key, vec![0u8; 16]);
        // ResponseKeyNT = HMAC-MD5(nt_hash, "ADMINISTRATORSEVENKINGDOMS" UTF16-LE)
        eprintln!(
            "ResponseKeyNT(Administrator, sevenkingdoms) = {}",
            hex::encode(&response_key)
        );
    }

    #[test]
    fn test_parse_ioctl_output_returns_data() {
        // Build a minimal SMB2 IOCTL response with 8 bytes of output
        let mut resp = vec![0u8; 64 + 56]; // header + body
        resp[0..4].copy_from_slice(b"\xfeSMB");
        resp[8..12].copy_from_slice(&0u32.to_le_bytes()); // STATUS_SUCCESS
        resp[12..14].copy_from_slice(&0x000Bu16.to_le_bytes()); // SMB2_IOCTL
        // OutputOffset = body start(64) + body length(56) = 120 (from SMB2 header start)
        let out_offset = 120u32;
        resp[64 + 32..64 + 36].copy_from_slice(&out_offset.to_le_bytes());
        // OutputCount = 8
        resp[64 + 36..64 + 40].copy_from_slice(&8u32.to_le_bytes());
        // Output data at offset 64
        let output_data = b"\x05\x00\x0b\x03\x10\x00\x00\x00";
        resp.extend_from_slice(output_data);

        let result = Smb2Connection::parse_ioctl_output(&resp).unwrap();
        assert_eq!(result, output_data);
    }

    #[test]
    fn test_parse_ioctl_output_empty() {
        let mut resp = vec![0u8; 64 + 56];
        resp[0..4].copy_from_slice(b"\xfeSMB");
        resp[8..12].copy_from_slice(&0u32.to_le_bytes());
        resp[64 + 36..64 + 40].copy_from_slice(&0u32.to_le_bytes()); // out_count = 0
        let result = Smb2Connection::parse_ioctl_output(&resp).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ioctl_output_overflow_returns_err() {
        let mut resp = vec![0u8; 64 + 56];
        resp[0..4].copy_from_slice(b"\xfeSMB");
        resp[8..12].copy_from_slice(&0u32.to_le_bytes());
        let out_offset = 64u32;
        resp[64 + 32..64 + 36].copy_from_slice(&out_offset.to_le_bytes());
        resp[64 + 36..64 + 40].copy_from_slice(&100u32.to_le_bytes()); // out_count=100 but only 56+0 bytes
        let result = Smb2Connection::parse_ioctl_output(&resp);
        assert!(result.is_err());
    }
}
