//! HMAC utilities for ticket validation and protocol authentication.
//!
//! Centralised HMAC helpers used across Kerberos ticket forging (PAC checksums),
//! NTLMSSP session key derivation, and domain credential validation.

use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

/// HMAC-MD5: keyed hash used for RC4-HMAC PAC checksums and NTLMSSP session keys.
///
/// Returns a 16-byte MAC.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// HMAC-MD5 with multiple data segments (avoids concatenation allocation).
pub fn hmac_md5_multi(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA1: full 20-byte keyed hash.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA1-96-AES256: truncated 12-byte HMAC used for AES PAC checksums (etype 17/18).
///
/// Per RFC 3962 / MS-PAC §2.8, the PAC checksum for AES etypes is
/// `HMAC-SHA1-96-AES256` (checksum type 16) — the first 12 bytes of HMAC-SHA1.
///
/// The `key` should be the Kerberos session key (32 bytes for AES-256, 16 for AES-128).
pub fn hmac_sha1_96_aes(key: &[u8], data: &[u8]) -> [u8; 12] {
    let full = hmac_sha1(key, data);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// HMAC-SHA1 with multiple data segments.
pub fn hmac_sha1_multi(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// Verify an HMAC-MD5 tag. Returns `true` if the `expected` matches.
pub fn hmac_md5_verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let computed = hmac_md5(key, data);
    // Constant-time comparison when lengths match
    if expected.len() != 16 {
        return false;
    }
    constant_time_eq(&computed, expected)
}

/// Verify an HMAC-SHA1-96 tag. Returns `true` if the first 12 bytes match.
pub fn hmac_sha1_96_verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let computed = hmac_sha1_96_aes(key, data);
    if expected.len() < 12 {
        return false;
    }
    constant_time_eq(&computed, &expected[..12])
}

/// Derive an NTLMSSP session base key: `HMAC-MD5(NT_hash, NTProofStr)`.
///
/// This is the NTLMv2 Session Base Key used in SMB signing and session key derivation.
pub fn ntlmssp_session_base_key(nt_hash: &[u8], nt_proof_str: &[u8]) -> [u8; 16] {
    hmac_md5(nt_hash, nt_proof_str)
}

/// Compute the NTLMv2 response: `HMAC-MD5(NTOWFv2, ServerChallenge || blob)`.
///
/// `nt_owf_v2` = `HMAC-MD5(NTHash, UPPERCASE(username) || domain)` (all UTF-16LE).
pub fn ntlmv2_response(nt_owf_v2: &[u8], server_challenge: &[u8], blob: &[u8]) -> [u8; 16] {
    hmac_md5_multi(nt_owf_v2, &[server_challenge, blob])
}

/// Compute NTOWFv2: `HMAC-MD5(NTHash, UPPER(user) || domain)`, all UTF-16LE.
pub fn nt_owf_v2(nt_hash: &[u8; 16], username: &str, domain: &str) -> [u8; 16] {
    let user_upper: Vec<u8> = username
        .to_uppercase()
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let domain_utf16: Vec<u8> = domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    hmac_md5_multi(nt_hash, &[&user_upper, &domain_utf16])
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_md5_basic() {
        // RFC 2104 test vector (key = 0x0b * 16, data = "Hi There")
        let key = [0x0bu8; 16];
        let data = b"Hi There";
        let result = hmac_md5(&key, data);
        assert_eq!(hex::encode(result), "9294727a3638bb1c13f48ef8158bfc9d");
    }

    #[test]
    fn test_hmac_md5_multi() {
        let key = b"secret";
        let a = b"hello ";
        let b_data = b"world";
        let combined = hmac_md5(key, b"hello world");
        let multi = hmac_md5_multi(key, &[a, b_data]);
        assert_eq!(combined, multi);
    }

    #[test]
    fn test_hmac_sha1_basic() {
        // RFC 2202 test case 1 (key = 0x0b * 20, data = "Hi There")
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha1(&key, data);
        assert_eq!(
            hex::encode(result),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn test_hmac_sha1_96_truncation() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let full = hmac_sha1(&key, data);
        let truncated = hmac_sha1_96_aes(&key, data);
        assert_eq!(&full[..12], &truncated);
        assert_eq!(truncated.len(), 12);
    }

    #[test]
    fn test_hmac_md5_verify() {
        let key = b"key";
        let data = b"data";
        let mac = hmac_md5(key, data);
        assert!(hmac_md5_verify(key, data, &mac));
        let mut bad = mac;
        bad[0] ^= 0xff;
        assert!(!hmac_md5_verify(key, data, &bad));
    }

    #[test]
    fn test_hmac_sha1_96_verify() {
        let key = b"key";
        let data = b"data";
        let mac = hmac_sha1_96_aes(key, data);
        assert!(hmac_sha1_96_verify(key, data, &mac));
        let mut bad = mac;
        bad[0] ^= 0xff;
        assert!(!hmac_sha1_96_verify(key, data, &bad));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    #[test]
    fn test_nt_owf_v2() {
        // Verify it produces 16 bytes and is deterministic
        let nt_hash = [0xaau8; 16];
        let result1 = nt_owf_v2(&nt_hash, "Administrator", "CONTOSO.COM");
        let result2 = nt_owf_v2(&nt_hash, "Administrator", "CONTOSO.COM");
        assert_eq!(result1, result2);
        // Case-insensitive for username
        let result3 = nt_owf_v2(&nt_hash, "administrator", "CONTOSO.COM");
        assert_eq!(result1, result3);
    }
}
