//! MD4 hash for NTLM password hashing.
//!
//! Centralised NTLM hash computation used throughout the codebase.
//! The NTLM hash is `MD4(UTF-16LE(password))`.

use md4::{Digest, Md4};

/// Compute the NTLM hash of a password string.
///
/// NTLM hash = `MD4(UTF-16LE(password))`.
///
/// # Example
/// ```
/// let hash = overthrone_core::crypto::md4::ntlm_hash("Password123");
/// assert_eq!(hex::encode(hash), "58a478135a93ac3bf058a5ea0e8fdb71");
/// ```
pub fn ntlm_hash(password: &str) -> [u8; 16] {
    let utf16le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    ntlm_hash_from_bytes(&utf16le)
}

/// Compute the NTLM hash from raw UTF-16LE bytes.
///
/// Use this when you already have the password in UTF-16LE encoding.
pub fn ntlm_hash_from_bytes(utf16le: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(utf16le);
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the NTLM hash and return it as a lowercase hex string.
pub fn ntlm_hash_hex(password: &str) -> String {
    hex::encode(ntlm_hash(password))
}

/// Compute the NTLM hash from a password and compare with an expected hash.
///
/// Both NT hash bytes and hex strings are accepted for comparison.
pub fn ntlm_verify(password: &str, expected_hash: &[u8; 16]) -> bool {
    ntlm_hash(password) == *expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_hash_empty() {
        // Well-known: NTLM("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        let hash = ntlm_hash("");
        assert_eq!(hex::encode(hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_ntlm_hash_password123() {
        let hash = ntlm_hash("Password123");
        assert_eq!(hex::encode(hash), "58a478135a93ac3bf058a5ea0e8fdb71");
    }

    #[test]
    fn test_ntlm_hash_password() {
        // NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
        let hash = ntlm_hash("password");
        assert_eq!(hex::encode(hash), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn test_ntlm_hash_from_bytes() {
        let utf16: Vec<u8> = "test"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let hash = ntlm_hash_from_bytes(&utf16);
        assert_eq!(hash, ntlm_hash("test"));
    }

    #[test]
    fn test_ntlm_verify() {
        let hash = ntlm_hash("Password123");
        assert!(ntlm_verify("Password123", &hash));
        assert!(!ntlm_verify("Wrong", &hash));
    }

    #[test]
    fn test_ntlm_hash_hex() {
        assert_eq!(
            ntlm_hash_hex("password"),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
    }
}
