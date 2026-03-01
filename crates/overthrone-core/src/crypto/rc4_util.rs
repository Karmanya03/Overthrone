//! RC4 encryption for Kerberos etype 23 and SAM hash decryption.
//!
//! Provides RC4 stream cipher operations used in:
//! - Kerberos RC4-HMAC (etype 23) encryption/decryption
//! - Pre-Vista SAM hash decryption
//! - Pre-Vista LSA secret key derivation
//! - NTLMSSP session key encryption

use anyhow::{Result, bail};

use super::hmac_util;

/// Raw RC4 encrypt/decrypt (symmetric — same operation for both).
///
/// RC4 is a stream cipher, so encryption and decryption are identical.
/// Uses a pure-Rust implementation to avoid generic key-size constraints
/// from the `rc4` crate.
pub fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    // RC4 key scheduling algorithm (KSA)
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // RC4 pseudo-random generation algorithm (PRGA)
    let mut output = data.to_vec();
    let mut i: u8 = 0;
    j = 0;
    for byte in output.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *byte ^= k;
    }
    output
}

// ═══════════════════════════════════════════════════════════
// Kerberos RC4-HMAC (etype 23)
// ═══════════════════════════════════════════════════════════

/// Encrypt data using Kerberos RC4-HMAC (etype 23).
///
/// Per RFC 4757:
/// 1. K1 = HMAC-MD5(key, usage_number_le32)
/// 2. Generate random 8-byte confounder
/// 3. K3 = HMAC-MD5(K1, confounder || plaintext)  [this is the checksum]
/// 4. K2 = HMAC-MD5(K1, K3)  [this is the encryption key]
/// 5. RC4(K2, confounder || plaintext)
/// 6. Output = checksum (16) || encrypted(confounder (8) || plaintext)
pub fn rc4_hmac_encrypt(key: &[u8], data: &[u8], key_usage: i32) -> Vec<u8> {
    let usage_bytes = key_usage.to_le_bytes();

    // K1 = HMAC-MD5(key, usage)
    let k1 = hmac_util::hmac_md5(key, &usage_bytes);

    // Generate 8-byte confounder
    let confounder: [u8; 8] = rand::random();

    // plaintext_with_confounder = confounder || data
    let mut plain_conf = Vec::with_capacity(8 + data.len());
    plain_conf.extend_from_slice(&confounder);
    plain_conf.extend_from_slice(data);

    // K3 (checksum) = HMAC-MD5(K1, confounder || plaintext)
    let k3 = hmac_util::hmac_md5(&k1, &plain_conf);

    // K2 (encryption key) = HMAC-MD5(K1, K3)
    let k2 = hmac_util::hmac_md5(&k1, &k3);

    // Encrypt confounder || plaintext with RC4(K2)
    let encrypted = rc4_crypt(&k2, &plain_conf);

    // Output: checksum (16) || encrypted data
    let mut output = Vec::with_capacity(16 + encrypted.len());
    output.extend_from_slice(&k3);
    output.extend_from_slice(&encrypted);
    output
}

/// Decrypt data encrypted with Kerberos RC4-HMAC (etype 23).
///
/// Input format: checksum (16) || encrypted(confounder (8) || plaintext)
pub fn rc4_hmac_decrypt(key: &[u8], data: &[u8], key_usage: i32) -> Result<Vec<u8>> {
    if data.len() < 24 {
        bail!("RC4-HMAC ciphertext too short (need >= 24 bytes, got {})", data.len());
    }

    let usage_bytes = key_usage.to_le_bytes();

    // Split: checksum (16) || encrypted_data
    let checksum = &data[..16];
    let encrypted = &data[16..];

    // K1 = HMAC-MD5(key, usage)
    let k1 = hmac_util::hmac_md5(key, &usage_bytes);

    // K2 = HMAC-MD5(K1, checksum)
    let k2 = hmac_util::hmac_md5(&k1, checksum);

    // Decrypt to get confounder || plaintext
    let decrypted = rc4_crypt(&k2, encrypted);

    // Verify checksum: K3 = HMAC-MD5(K1, decrypted_confounder_plaintext)
    let k3 = hmac_util::hmac_md5(&k1, &decrypted);
    if !hmac_util::hmac_md5_verify(&k1, &decrypted, checksum) {
        // Recompute for a better check — compare k3 vs checksum directly
        if k3 != <[u8; 16]>::try_from(checksum).unwrap_or([0; 16]) {
            bail!("RC4-HMAC checksum verification failed");
        }
    }

    // Strip 8-byte confounder, return plaintext
    if decrypted.len() < 8 {
        bail!("RC4-HMAC decrypted data too short");
    }
    Ok(decrypted[8..].to_vec())
}

// ═══════════════════════════════════════════════════════════
// SAM Hash Decryption (pre-Vista, RC4-based)
// ═══════════════════════════════════════════════════════════

/// Well-known constants for SAM hash decryption (from MS-SAMR).
const SAM_LMPASSWORD: &[u8] = b"LMPASSWORD\x00";
const SAM_NTPASSWORD: &[u8] = b"NTPASSWORD\x00";

/// Decrypt a SAM hash (pre-Vista format, RC4-based).
///
/// Algorithm (per Impacket/MS-SAMR):
/// 1. `rc4_key = MD5(hashed_boot_key || RID_le32 || constant)`
///    where constant is `"LMPASSWORD\0"` for LM or `"NTPASSWORD\0"` for NT.
/// 2. `obfuscated_hash = RC4(rc4_key, encrypted_hash)`
/// 3. `final_hash = DES_decrypt_two_blocks(RID, obfuscated_hash)`
pub fn decrypt_sam_hash_rc4(
    rid: u32,
    hashed_boot_key: &[u8],
    encrypted_hash: &[u8],
    is_nt: bool,
) -> Result<[u8; 16]> {
    use md5::{Md5, Digest};

    if encrypted_hash.len() < 16 {
        bail!("Encrypted SAM hash too short (need >= 16, got {})", encrypted_hash.len());
    }

    let constant = if is_nt { SAM_NTPASSWORD } else { SAM_LMPASSWORD };

    // Step 1: Derive RC4 key = MD5(hashed_boot_key || RID_le || constant)
    let mut md5 = Md5::new();
    md5.update(hashed_boot_key);
    md5.update(&rid.to_le_bytes());
    md5.update(constant);
    let rc4_key = md5.finalize();

    // Step 2: RC4 decrypt
    let obfuscated = rc4_crypt(&rc4_key, &encrypted_hash[..16]);

    // Step 3: DES two-block decrypt using RID-derived keys
    des_decrypt_hash(rid, &obfuscated)
}

/// Decrypt a SAM hash block using DES with RID-derived keys.
///
/// The 16-byte hash is split into two 8-byte blocks, each decrypted with a
/// 7-byte DES key derived from the RID.
pub(crate) fn des_decrypt_hash(rid: u32, data: &[u8]) -> Result<[u8; 16]> {
    use des::cipher::{BlockDecrypt, KeyInit as DesKeyInit};
    use des::Des;

    if data.len() < 16 {
        bail!("DES input too short");
    }

    let (key1, key2) = rid_to_des_keys(rid);

    let cipher1 = Des::new(&key1.into());
    let cipher2 = Des::new(&key2.into());

    let mut block1 = des::cipher::generic_array::GenericArray::clone_from_slice(&data[..8]);
    let mut block2 = des::cipher::generic_array::GenericArray::clone_from_slice(&data[8..16]);

    cipher1.decrypt_block(&mut block1);
    cipher2.decrypt_block(&mut block2);

    let mut result = [0u8; 16];
    result[..8].copy_from_slice(&block1);
    result[8..].copy_from_slice(&block2);
    Ok(result)
}

/// Convert a RID to two 8-byte DES keys.
///
/// Per MS-SAMR, the RID is expanded into two 7-byte strings which are then
/// spread into 8-byte DES keys with parity bits.
fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let r = rid.to_le_bytes();
    let s1 = [r[0], r[1], r[2], r[3], r[0], r[1], r[2]];
    let s2 = [r[3], r[0], r[1], r[2], r[3], r[0], r[1]];
    (str_to_des_key(&s1), str_to_des_key(&s2))
}

/// Spread 7 bytes into an 8-byte DES key with parity bits.
fn str_to_des_key(s: &[u8; 7]) -> [u8; 8] {
    [
        (s[0] >> 1),
        ((s[0] & 0x01) << 6) | (s[1] >> 2),
        ((s[1] & 0x03) << 5) | (s[2] >> 3),
        ((s[2] & 0x07) << 4) | (s[3] >> 4),
        ((s[3] & 0x0f) << 3) | (s[4] >> 5),
        ((s[4] & 0x1f) << 2) | (s[5] >> 6),
        ((s[5] & 0x3f) << 1) | (s[6] >> 7),
        (s[6] & 0x7f) << 1,
    ]
}

// ═══════════════════════════════════════════════════════════
// Pre-Vista LSA Secret Key Derivation
// ═══════════════════════════════════════════════════════════

/// Derive the pre-Vista LSA secret encryption key.
///
/// Per Impacket `_decryptSecret`:
/// ```text
/// key = boot_key
/// for _ in 0..1000:
///     md5 = MD5()
///     md5.update(key)
///     md5.update(secret[60..76])  // 16-byte "salt" from the secret blob
///     key = md5.finalize()
/// decrypted = RC4(key, secret[12..60])
/// ```
pub fn decrypt_lsa_key_pre_vista(
    boot_key: &[u8],
    secret_blob: &[u8],
) -> Result<Vec<u8>> {
    use md5::{Md5, Digest};

    if secret_blob.len() < 76 {
        bail!("LSA secret blob too short for pre-Vista decryption");
    }

    let salt = &secret_blob[60..76];
    let encrypted = &secret_blob[12..60];

    // Iterated MD5 key derivation (1000 rounds)
    let mut key = boot_key.to_vec();
    for _ in 0..1000 {
        let mut md5 = Md5::new();
        md5.update(&key);
        md5.update(salt);
        key = md5.finalize().to_vec();
    }

    // RC4 decrypt
    Ok(rc4_crypt(&key, encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_crypt_roundtrip() {
        let key = b"test_key";
        let plaintext = b"Hello, World!";
        let encrypted = rc4_crypt(key, plaintext);
        let decrypted = rc4_crypt(key, &encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rc4_crypt_known_vector() {
        // RC4 known test vector: key="Key", plaintext="Plaintext"
        let key = b"Key";
        let plaintext = b"Plaintext";
        let encrypted = rc4_crypt(key, plaintext);
        assert_eq!(hex::encode(&encrypted), "bbf316e8d940af0ad3");
    }

    #[test]
    fn test_rc4_hmac_encrypt_decrypt_roundtrip() {
        let key = [0xaau8; 16]; // 16-byte NTLM-like key
        let plaintext = b"This is a test message for RC4-HMAC encryption";
        let key_usage = 7; // Kerberos key usage for AP-REQ authenticator

        let encrypted = rc4_hmac_encrypt(&key, plaintext, key_usage);
        assert!(encrypted.len() > plaintext.len()); // Should be larger (confounder + checksum)

        let decrypted = rc4_hmac_decrypt(&key, &encrypted, key_usage).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rc4_hmac_decrypt_wrong_key() {
        let key = [0xaau8; 16];
        let wrong_key = [0xbbu8; 16];
        let plaintext = b"secret data";

        let encrypted = rc4_hmac_encrypt(&key, plaintext, 7);
        let result = rc4_hmac_decrypt(&wrong_key, &encrypted, 7);
        assert!(result.is_err());
    }

    #[test]
    fn test_rc4_hmac_decrypt_too_short() {
        let result = rc4_hmac_decrypt(&[0u8; 16], &[0u8; 10], 7);
        assert!(result.is_err());
    }

    #[test]
    fn test_str_to_des_key() {
        let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let key = str_to_des_key(&input);
        assert_eq!(key.len(), 8);
        // Verify parity-like bit spreading
        assert_eq!(key[0], 0x01 >> 1);
    }

    #[test]
    fn test_rid_to_des_keys() {
        let (k1, k2) = rid_to_des_keys(500);
        assert_eq!(k1.len(), 8);
        assert_eq!(k2.len(), 8);
        // Different RIDs should produce different keys
        let (k3, k4) = rid_to_des_keys(501);
        assert_ne!(k1, k3);
        assert_ne!(k2, k4);
    }

    #[test]
    fn test_des_decrypt_hash_too_short() {
        let result = des_decrypt_hash(500, &[0u8; 8]);
        assert!(result.is_err());
    }
}
