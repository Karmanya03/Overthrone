//! NTLM hash computation and authentication helpers.
//!
//! Implements NT hash (MD4), NTLMv2 hash (HMAC-MD5), NTLMv2 challenge-response,
//! and Pass-the-Hash support for Active Directory authentication.
//!
//! Reference: [MS-NLMP] — Microsoft NT LAN Manager Authentication Protocol

use crate::error::{OverthroneError, Result};
use digest::Digest;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

// ═══════════════════════════════════════════════════════════
// NT Hash — MD4(UTF-16LE(password))
// ═══════════════════════════════════════════════════════════

/// Compute the NT hash of a password: MD4(UTF-16LE(password))
///
/// This is the primary credential hash stored in the SAM database
/// and Active Directory. It is "password equivalent" — knowing this
/// hash is sufficient to authenticate without the plaintext password.
pub fn nt_hash(password: &str) -> Vec<u8> {
    let utf16le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16le);
    hasher.finalize().to_vec()
}

/// Compute NT hash and return as lowercase hex string
pub fn nt_hash_hex(password: &str) -> String {
    hex::encode(nt_hash(password))
}

// ═══════════════════════════════════════════════════════════
// NTLMv2 Hash — HMAC-MD5(NT_HASH, UPPER(user) + UPPER(domain))
// ═══════════════════════════════════════════════════════════

/// Compute the NTLMv2 hash (also called the "NTLMv2 OWF").
///
/// Formula: HMAC-MD5(NT_HASH, UTF-16LE(UPPER(username) + UPPER(domain)))
///
/// This is used as the key for computing NTLMv2 challenge responses
/// and session keys. Reference: [MS-NLMP] Section 3.3.2
pub fn ntlmv2_hash(nt_hash: &[u8], username: &str, domain: &str) -> Vec<u8> {
    let identity = format!(
        "{}{}",
        username.to_uppercase(),
        domain.to_uppercase()
    );
    let identity_utf16: Vec<u8> = identity
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut mac = HmacMd5::new_from_slice(nt_hash)
        .expect("HMAC-MD5 accepts any key length");
    mac.update(&identity_utf16);
    mac.finalize().into_bytes().to_vec()
}

/// Convenience: compute NTLMv2 hash directly from a plaintext password.
pub fn ntlmv2_hash_from_password(password: &str, username: &str, domain: &str) -> Vec<u8> {
    let nt = nt_hash(password);
    ntlmv2_hash(&nt, username, domain)
}

// ═══════════════════════════════════════════════════════════
// NTLMv2 Response — for challenge-response authentication
// ═══════════════════════════════════════════════════════════

/// Compute the NTLMv2 response for a given server challenge.
///
/// Formula: HMAC-MD5(NTLMv2_HASH, server_challenge + client_blob)
///          concatenated with the client_blob.
///
/// The `client_blob` (NTLMv2_CLIENT_CHALLENGE) contains a timestamp,
/// client nonce, and target info from the server's CHALLENGE_MESSAGE.
/// Reference: [MS-NLMP] Section 3.3.2
pub fn ntlmv2_response(
    ntlmv2_hash: &[u8],
    server_challenge: &[u8; 8],
    client_blob: &[u8],
) -> Vec<u8> {
    // NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge + ClientBlob)
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash)
        .expect("HMAC-MD5 accepts any key length");
    mac.update(server_challenge);
    mac.update(client_blob);
    let nt_proof_str = mac.finalize().into_bytes();

    // Response = NTProofStr (16 bytes) + ClientBlob
    let mut response = nt_proof_str.to_vec();
    response.extend_from_slice(client_blob);
    response
}

/// Build a minimal NTLMv2 client blob (NTLMv2_CLIENT_CHALLENGE).
///
/// Layout (28+ bytes):
///   - RespType:    u8  = 0x01
///   - HiRespType:  u8  = 0x01
///   - Reserved1:   u16 = 0
///   - Reserved2:   u32 = 0
///   - TimeStamp:   u64 (Windows FILETIME, 100ns ticks since 1601-01-01)
///   - ClientChallenge: 8 bytes (random)
///   - Reserved3:   u32 = 0
///   - AvPairs:     target_info bytes from CHALLENGE_MESSAGE
///
/// Reference: [MS-NLMP] Section 2.2.2.7
pub fn build_ntlmv2_client_blob(
    timestamp: u64,
    client_challenge: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    let mut blob = Vec::with_capacity(28 + target_info.len());

    blob.push(0x01);                             // RespType
    blob.push(0x01);                             // HiRespType
    blob.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    blob.extend_from_slice(&timestamp.to_le_bytes()); // TimeStamp
    blob.extend_from_slice(client_challenge);    // ChallengeFromClient
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    blob.extend_from_slice(target_info);         // AvPairs

    blob
}

/// Get the current time as a Windows FILETIME (100ns ticks since 1601-01-01).
///
/// The offset between Unix epoch (1970) and Windows epoch (1601) is
/// 116444736000000000 ticks (100ns units).
pub fn windows_filetime_now() -> u64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Convert nanoseconds to 100-nanosecond intervals and add epoch offset
    (unix_nanos / 100) + EPOCH_DIFF
}

// ═══════════════════════════════════════════════════════════
// NTLMv2 Session Key
// ═══════════════════════════════════════════════════════════

/// Compute the NTLMv2 session base key.
///
/// Formula: HMAC-MD5(NTLMv2_HASH, NTProofStr)
///
/// The NTProofStr is the first 16 bytes of the NTLMv2 response.
/// This session key is used for signing and sealing messages.
/// Reference: [MS-NLMP] Section 3.3.2
pub fn ntlmv2_session_base_key(ntlmv2_hash: &[u8], nt_proof_str: &[u8]) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash)
        .expect("HMAC-MD5 accepts any key length");
    mac.update(nt_proof_str);
    mac.finalize().into_bytes().to_vec()
}

// ═══════════════════════════════════════════════════════════
// LMv2 Response (companion to NTLMv2)
// ═══════════════════════════════════════════════════════════

/// Compute the LMv2 response.
///
/// Formula: HMAC-MD5(NTLMv2_HASH, server_challenge + client_challenge)
///          concatenated with client_challenge.
///
/// Reference: [MS-NLMP] Section 3.3.2
pub fn lmv2_response(
    ntlmv2_hash: &[u8],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash)
        .expect("HMAC-MD5 accepts any key length");
    mac.update(server_challenge);
    mac.update(client_challenge);
    let proof = mac.finalize().into_bytes();

    // Response = proof (16 bytes) + client_challenge (8 bytes) = 24 bytes
    let mut response = proof.to_vec();
    response.extend_from_slice(client_challenge);
    response
}

// ═══════════════════════════════════════════════════════════
// Hash Parsing & Utilities
// ═══════════════════════════════════════════════════════════

/// Parse an NTLM hash string in `LMHASH:NTHASH` or bare `NTHASH` format.
///
/// Returns the 16-byte NT hash. Accepts secretsdump/hashdump output format.
pub fn parse_ntlm_hash(hash_str: &str) -> Result<Vec<u8>> {
    let nt_part = if hash_str.contains(':') {
        // Format: LMHASH:NTHASH — take the NT part
        hash_str
            .split(':')
            .nth(1)
            .ok_or_else(|| OverthroneError::InvalidHash(hash_str.to_string()))?
    } else {
        hash_str
    };

    // Validate: must be 32 hex chars (16 bytes)
    if nt_part.len() != 32 {
        return Err(OverthroneError::InvalidHash(format!(
            "Expected 32 hex chars, got {}",
            nt_part.len()
        )));
    }

    hex::decode(nt_part).map_err(|e| {
        OverthroneError::InvalidHash(format!("Invalid hex: {e}"))
    })
}

/// Parse a full secretsdump-style hash line:
/// `username:rid:lm_hash:nt_hash:::`
///
/// Returns (username, rid, nt_hash_bytes)
pub fn parse_secretsdump_line(line: &str) -> Result<(String, u32, Vec<u8>)> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 4 {
        return Err(OverthroneError::InvalidHash(format!(
            "Expected secretsdump format 'user:rid:lm:nt', got: {line}"
        )));
    }

    let username = parts[0].to_string();
    let rid: u32 = parts[1].parse().map_err(|_| {
        OverthroneError::InvalidHash(format!("Invalid RID '{}' in: {line}", parts[1]))
    })?;
    let nt_hash = hex::decode(parts[3]).map_err(|e| {
        OverthroneError::InvalidHash(format!("Invalid NT hash hex: {e}"))
    })?;

    if nt_hash.len() != 16 {
        return Err(OverthroneError::InvalidHash(format!(
            "NT hash must be 16 bytes, got {}",
            nt_hash.len()
        )));
    }

    Ok((username, rid, nt_hash))
}

/// Constant for the "empty" LM hash (password blank or LM hashing disabled).
///
/// This appears in virtually all modern Windows environments since
/// LM hashes are disabled by default on Vista+.
pub fn lm_hash_empty() -> Vec<u8> {
    hex::decode("aad3b435b51404eeaad3b435b51404ee").unwrap()
}

/// Check if an NT hash represents an empty/blank password.
pub fn is_empty_nt_hash(hash: &[u8]) -> bool {
    // NT hash of "" = 31d6cfe0d16ae931b73c59d7e0c089c0
    let empty_nt = hex::decode("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
    hash == empty_nt.as_slice()
}

/// Check if an LM hash is the "disabled/empty" sentinel value.
pub fn is_empty_lm_hash(hash: &[u8]) -> bool {
    let empty_lm = hex::decode("aad3b435b51404eeaad3b435b51404ee").unwrap();
    hash == empty_lm.as_slice()
}

// ═══════════════════════════════════════════════════════════
// NTLM Message Building (for authentication)
// ═══════════════════════════════════════════════════════════

/// NTLM signature bytes
const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\x00";

/// NTLM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmMessageType {
    Negotiate = 1,
    Challenge = 2,
    Authenticate = 3,
}

/// Parsed NTLM Challenge message
#[derive(Debug, Clone)]
pub struct NtlmChallengeMessage {
    pub message_type: NtlmMessageType,
    pub target_name: Option<String>,
    pub challenge: [u8; 8],
    pub target_info: Option<Vec<u8>>,
    pub flags: u32,
}

/// Build NTLM Type 1 (Negotiate) message
///
/// This message is sent from client to server to initiate NTLM authentication.
pub fn build_negotiate_message(domain: &str) -> Vec<u8> {
    let mut msg = Vec::new();

    // Signature
    msg.extend_from_slice(NTLM_SIGNATURE);

    // Message type (Type 1 = Negotiate)
    msg.extend_from_slice(&1u32.to_le_bytes());

    // NTLM negotiate flags
    // NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_OEM | NTLMSSP_REQUEST_TARGET |
    // NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    let flags: u32 = 0x00000202 | 0x00020000 | 0x00000010 | 0x00000200 | 0x00008000 | 0x00080000;
    msg.extend_from_slice(&flags.to_le_bytes());

    // Domain name (optional, we'll include if provided)
    if !domain.is_empty() {
        let domain_utf16: Vec<u8> = domain.to_uppercase()
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        
        // Domain length and offset
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes()); // Max length
        msg.extend_from_slice(&32u32.to_le_bytes()); // Offset after header
        
        // Workstation (empty)
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&32u32.to_le_bytes());
        
        // Payload
        msg.extend_from_slice(&domain_utf16);
    } else {
        // Empty domain and workstation
        msg.extend_from_slice(&0u16.to_le_bytes()); // Domain length
        msg.extend_from_slice(&0u16.to_le_bytes()); // Domain max
        msg.extend_from_slice(&0u32.to_le_bytes()); // Domain offset
        msg.extend_from_slice(&0u16.to_le_bytes()); // Workstation length
        msg.extend_from_slice(&0u16.to_le_bytes()); // Workstation max
        msg.extend_from_slice(&0u32.to_le_bytes()); // Workstation offset
    }

    // Version (Windows 7.1 = 6.1 = 0x0601)
    msg.extend_from_slice(&[0x06, 0x01, 0xB1, 0x1D, 0x00, 0x00, 0x00, 0x0F]);

    msg
}

/// Parse NTLM Type 2 (Challenge) message from server
pub fn parse_challenge_message(data: &[u8]) -> Result<NtlmChallengeMessage> {
    if data.len() < 48 {
        return Err(OverthroneError::Ntlm("Challenge message too short".to_string()));
    }

    // Verify signature
    if &data[0..8] != NTLM_SIGNATURE {
        return Err(OverthroneError::Ntlm("Invalid NTLM signature".to_string()));
    }

    // Check message type
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != 2 {
        return Err(OverthroneError::Ntlm(format!("Expected Type 2 message, got {}", msg_type)));
    }

    // Extract target name
    let target_len = u16::from_le_bytes([data[12], data[13]]) as usize;
    let target_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    
    let target_name = if target_len > 0 && target_offset + target_len <= data.len() {
        Some(String::from_utf16_lossy(
            &data[target_offset..target_offset + target_len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>()
        ))
    } else {
        None
    };

    // Extract challenge (8 bytes at offset 24)
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&data[24..32]);

    // Extract flags
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    // Extract target info if present
    let target_info = if data.len() >= 48 {
        let info_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let info_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
        
        if info_len > 0 && info_offset + info_len <= data.len() {
            Some(data[info_offset..info_offset + info_len].to_vec())
        } else {
            None
        }
    } else {
        None
    };

    Ok(NtlmChallengeMessage {
        message_type: NtlmMessageType::Challenge,
        target_name,
        challenge,
        target_info,
        flags,
    })
}

/// Compute NTOWFv1 (same as NT hash)
pub fn ntowfv1(password: &str) -> Vec<u8> {
    nt_hash(password)
}

/// Build NTLM Type 3 (Authenticate) message
///
/// This message contains the proof of identity using the NTLMv2 response.
pub fn build_authenticate_message(
    domain: &str,
    username: &str,
    nt_hash: &[u8],
    server_challenge: &[u8; 8],
    target_info: Option<&[u8]>,
    _password: Option<&str>,
) -> Vec<u8> {
    let mut msg = Vec::new();

    // Compute NTLMv2 hash
    let ntlmv2_h = ntlmv2_hash(nt_hash, username, domain);

    // Generate random client challenge
    let client_challenge: [u8; 8] = rand::random();

    // Build client blob
    let timestamp = windows_filetime_now();
    let target_info_bytes = target_info.unwrap_or(&[]);
    let client_blob = build_ntlmv2_client_blob(timestamp, &client_challenge, target_info_bytes);

    // Compute NTLMv2 response
    let nt_response = ntlmv2_response(&ntlmv2_h, server_challenge, &client_blob);

    // Compute LMv2 response
    let lm_response = lmv2_response(&ntlmv2_h, server_challenge, &client_challenge);

    // Convert domain and username to UTF-16LE
    let domain_utf16: Vec<u8> = domain.to_uppercase()
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    
    let username_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    
    let workstation_utf16: Vec<u8> = "WORKSTATION"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Calculate offsets
    let header_size = 64u32; // Base header
    let domain_offset = header_size;
    let username_offset = domain_offset + domain_utf16.len() as u32;
    let workstation_offset = username_offset + username_utf16.len() as u32;
    let lm_offset = workstation_offset + workstation_utf16.len() as u32;
    let nt_offset = lm_offset + lm_response.len() as u32;

    // Build message
    // Signature
    msg.extend_from_slice(NTLM_SIGNATURE);

    // Message type (Type 3 = Authenticate)
    msg.extend_from_slice(&3u32.to_le_bytes());

    // LM response
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&lm_offset.to_le_bytes());

    // NT response
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&nt_offset.to_le_bytes());

    // Domain
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // Username
    msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&username_offset.to_le_bytes());

    // Workstation
    msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&workstation_offset.to_le_bytes());

    // Session key (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());

    // Flags
    let flags: u32 = 0x00000202 | 0x00020000 | 0x00000010 | 0x00000200 | 0x00008000 | 0x00080000 | 0x00002000;
    msg.extend_from_slice(&flags.to_le_bytes());

    // Version
    msg.extend_from_slice(&[0x06, 0x01, 0xB1, 0x1D, 0x00, 0x00, 0x00, 0x0F]);

    // Payload
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&username_utf16);
    msg.extend_from_slice(&workstation_utf16);
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);

    msg
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── NT Hash ──────────────────────────────────────────

    #[test]
    fn test_nt_hash_known_value() {
        // Canonical NT hash for "password"
        // Reference: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.nthash.html
        let hash = nt_hash_hex("password");
        assert_eq!(hash, "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn test_nt_hash_empty() {
        // Known NT hash for empty string — universal "blank password" indicator
        let hash = nt_hash_hex("");
        assert_eq!(hash, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_nt_hash_case_sensitive() {
        // NT hashes are case-sensitive: "password" ≠ "Password"
        let lower = nt_hash_hex("password");
        let upper = nt_hash_hex("Password");
        assert_ne!(lower, upper);
        assert_eq!(lower, "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn test_nt_hash_unicode() {
        // Verify UTF-16LE encoding handles multi-byte characters
        let hash = nt_hash("Übér");
        assert_eq!(hash.len(), 16);
    }

    // ── NTLMv2 Hash ─────────────────────────────────────

    #[test]
    fn test_ntlmv2_hash_deterministic() {
        let nt = nt_hash("password");
        let v2a = ntlmv2_hash(&nt, "admin", "CORP.LOCAL");
        let v2b = ntlmv2_hash(&nt, "admin", "CORP.LOCAL");
        assert_eq!(v2a, v2b);
        assert_eq!(v2a.len(), 16);
    }

    #[test]
    fn test_ntlmv2_hash_user_case_insensitive() {
        // Username and domain are uppercased internally
        let nt = nt_hash("password");
        let v2a = ntlmv2_hash(&nt, "Admin", "corp.local");
        let v2b = ntlmv2_hash(&nt, "ADMIN", "CORP.LOCAL");
        assert_eq!(v2a, v2b);
    }

    #[test]
    fn test_ntlmv2_from_password_convenience() {
        let nt = nt_hash("test123");
        let expected = ntlmv2_hash(&nt, "jsmith", "CONTOSO.COM");
        let actual = ntlmv2_hash_from_password("test123", "jsmith", "CONTOSO.COM");
        assert_eq!(expected, actual);
    }

    // ── NTLMv2 Response ─────────────────────────────────

    #[test]
    fn test_ntlmv2_response_format() {
        let nt = nt_hash("password");
        let v2 = ntlmv2_hash(&nt, "user", "DOMAIN");
        let server_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let client_challenge = [0xAA; 8];
        let blob = build_ntlmv2_client_blob(
            windows_filetime_now(),
            &client_challenge,
            &[],
        );
        let response = ntlmv2_response(&v2, &server_challenge, &blob);
        // Response = NTProofStr (16 bytes) + blob
        assert_eq!(response.len(), 16 + blob.len());
    }

    #[test]
    fn test_lmv2_response_length() {
        let nt = nt_hash("password");
        let v2 = ntlmv2_hash(&nt, "user", "DOMAIN");
        let sc = [0x11; 8];
        let cc = [0x22; 8];
        let resp = lmv2_response(&v2, &sc, &cc);
        // LMv2 response is always 24 bytes (16 proof + 8 client challenge)
        assert_eq!(resp.len(), 24);
    }

    // ── Session Key ─────────────────────────────────────

    #[test]
    fn test_session_base_key_length() {
        let nt = nt_hash("password");
        let v2 = ntlmv2_hash(&nt, "user", "DOMAIN");
        let fake_proof = [0xAA; 16];
        let key = ntlmv2_session_base_key(&v2, &fake_proof);
        assert_eq!(key.len(), 16);
    }

    // ── Client Blob ─────────────────────────────────────

    #[test]
    fn test_client_blob_structure() {
        let cc = [0xFF; 8];
        let target_info = b"\x02\x00\x0C\x00D\x00O\x00M\x00A\x00I\x00N";
        let blob = build_ntlmv2_client_blob(0x01D7_1B02_4C00_0000, &cc, target_info);

        assert_eq!(blob[0], 0x01); // RespType
        assert_eq!(blob[1], 0x01); // HiRespType
        // Bytes 2-3: Reserved1 (0)
        assert_eq!(&blob[2..4], &[0, 0]);
        // Bytes 4-7: Reserved2 (0)
        assert_eq!(&blob[4..8], &[0, 0, 0, 0]);
        // Bytes 8-15: Timestamp
        assert_eq!(blob.len(), 28 + target_info.len());
        // Bytes 16-23: ClientChallenge
        assert_eq!(&blob[16..24], &[0xFF; 8]);
    }

    // ── Filetime ────────────────────────────────────────

    #[test]
    fn test_windows_filetime_reasonable() {
        let ft = windows_filetime_now();
        // Should be well past the year 2020 in FILETIME ticks
        // 2020-01-01 ≈ 132224352000000000
        assert!(ft > 132_224_352_000_000_000);
    }

    // ── Hash Parsing ────────────────────────────────────

    #[test]
    fn test_parse_ntlm_hash_full() {
        let result = parse_ntlm_hash(
            "aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_parse_ntlm_hash_nt_only() {
        let result = parse_ntlm_hash("8846f7eaee8fb117ad06bdd830b7586c");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), nt_hash("password"));
    }

    #[test]
    fn test_parse_ntlm_hash_invalid() {
        let result = parse_ntlm_hash("not_a_valid_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ntlm_hash_wrong_length() {
        let result = parse_ntlm_hash("aabbccdd");
        assert!(result.is_err());
    }

    // ── Secretsdump Parsing ─────────────────────────────

    #[test]
    fn test_parse_secretsdump_line() {
        let line =
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::";
        let (user, rid, hash) = parse_secretsdump_line(line).unwrap();
        assert_eq!(user, "Administrator");
        assert_eq!(rid, 500);
        assert_eq!(hash, nt_hash("password"));
    }

    #[test]
    fn test_parse_secretsdump_invalid() {
        assert!(parse_secretsdump_line("garbage").is_err());
    }

    // ── Empty Hash Checks ───────────────────────────────

    #[test]
    fn test_is_empty_nt_hash() {
        let empty = nt_hash("");
        assert!(is_empty_nt_hash(&empty));
        assert!(!is_empty_nt_hash(&nt_hash("password")));
    }

    #[test]
    fn test_is_empty_lm_hash() {
        let empty = lm_hash_empty();
        assert!(is_empty_lm_hash(&empty));
        assert!(!is_empty_lm_hash(&[0u8; 16]));
    }
}
