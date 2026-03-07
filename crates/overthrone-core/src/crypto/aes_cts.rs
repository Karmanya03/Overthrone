//! AES-CTS-HMAC-SHA1 for Kerberos etype 17 (AES-128) and 18 (AES-256).
//!
//! Implements AES in CBC mode with CipherText Stealing (CTS) as specified in
//! RFC 3962 for Kerberos, plus AES-CBC and AES-CFB helpers for SAM/LSA
//! decryption (Vista+).
//!
//! # Kerberos AES-CTS
//! CTS modifies standard CBC so the ciphertext is the same length as the
//! plaintext (no padding). The last two ciphertext blocks are swapped.
//!
//! # SAM/LSA decryption (Vista+)
//! Uses AES-128-CBC (SAM hashes) and AES-256-CBC (LSA secrets) with standard
//! PKCS7 or zero-padded blocks.

use aes::Aes128;
use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use anyhow::{Result, bail};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

const AES_BLOCK_SIZE: usize = 16;

// ═══════════════════════════════════════════════════════════
// Kerberos Key Derivation (RFC 3962)
// ═══════════════════════════════════════════════════════════

/// Derive an AES-256 key from a password and salt per RFC 3962.
///
/// `key = PBKDF2-HMAC-SHA1(password, salt, 4096, 32)` for etype 18.
pub fn derive_key_aes256(password: &str, salt: &str) -> [u8; 32] {
    use sha1::Sha1;
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), 4096, &mut key);
    key
}

/// Derive an AES-128 key from a password and salt per RFC 3962.
///
/// `key = PBKDF2-HMAC-SHA1(password, salt, 4096, 16)` for etype 17.
pub fn derive_key_aes128(password: &str, salt: &str) -> [u8; 16] {
    use sha1::Sha1;
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), 4096, &mut key);
    key
}

// ═══════════════════════════════════════════════════════════
// AES-CTS (CipherText Stealing) — RFC 3962
// ═══════════════════════════════════════════════════════════

/// Encrypt with AES-256-CTS (CipherText Stealing).
///
/// For data shorter than one block, standard CBC is used.
/// For data exactly one block, standard ECB is used.
/// For longer data, CBC with the last two ciphertext blocks swapped.
pub fn aes256_cts_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("AES-256 key must be 32 bytes, got {}", key.len());
    }
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }
    let original_len = plaintext.len();
    let padded_len = original_len.div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    let mut padded = vec![0u8; padded_len];
    padded[..original_len].copy_from_slice(plaintext);
    let iv = [0u8; AES_BLOCK_SIZE];
    let enc = Aes256CbcEnc::new(key.into(), &iv.into());
    let ct = enc.encrypt_padded_vec_mut::<NoPadding>(&padded);
    Ok(cts_swap_and_truncate(ct, original_len))
}

/// Decrypt with AES-256-CTS (CipherText Stealing).
///
/// Handles three cases:
/// - Single block (≤16 bytes): ECB decrypt
/// - Block-aligned (multiple of 16): swap last two blocks, CBC decrypt
/// - Non-aligned: recover stolen ciphertext bytes via ECB, then CBC decrypt
pub fn aes256_cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("AES-256 key must be 32 bytes, got {}", key.len());
    }
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    cts_decrypt_impl(
        ciphertext,
        |k, iv, data| {
            let dec = Aes256CbcDec::new(k.into(), iv.into());
            dec.decrypt_padded_vec_mut::<NoPadding>(data)
                .map_err(|e| anyhow::anyhow!("AES-256-CTS decrypt: {e}"))
        },
        key,
    )
}

/// Encrypt with AES-128-CTS (CipherText Stealing).
pub fn aes128_cts_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 {
        bail!("AES-128 key must be 16 bytes, got {}", key.len());
    }
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }
    let original_len = plaintext.len();
    let padded_len = original_len.div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    let mut padded = vec![0u8; padded_len];
    padded[..original_len].copy_from_slice(plaintext);
    let iv = [0u8; AES_BLOCK_SIZE];
    let enc = Aes128CbcEnc::new(key.into(), &iv.into());
    let ct = enc.encrypt_padded_vec_mut::<NoPadding>(&padded);
    Ok(cts_swap_and_truncate(ct, original_len))
}

/// Decrypt with AES-128-CTS (CipherText Stealing).
///
/// Same algorithm as AES-256-CTS but with 128-bit key.
pub fn aes128_cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 {
        bail!("AES-128 key must be 16 bytes, got {}", key.len());
    }
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    cts_decrypt_impl(
        ciphertext,
        |k, iv, data| {
            let dec = Aes128CbcDec::new(k.into(), iv.into());
            dec.decrypt_padded_vec_mut::<NoPadding>(data)
                .map_err(|e| anyhow::anyhow!("AES-128-CTS decrypt: {e}"))
        },
        key,
    )
}

/// After CBC encryption, swap the last two ciphertext blocks and truncate.
fn cts_swap_and_truncate(mut ct: Vec<u8>, original_len: usize) -> Vec<u8> {
    let num_blocks = ct.len() / AES_BLOCK_SIZE;
    if num_blocks >= 2 {
        let swap_start = (num_blocks - 2) * AES_BLOCK_SIZE;
        let mid = swap_start + AES_BLOCK_SIZE;
        let (first_part, second_part) = ct.split_at_mut(mid);
        let penultimate = &mut first_part[swap_start..];
        let mut temp = [0u8; AES_BLOCK_SIZE];
        temp.copy_from_slice(penultimate);
        penultimate.copy_from_slice(&second_part[..AES_BLOCK_SIZE]);
        second_part[..AES_BLOCK_SIZE].copy_from_slice(&temp);
    }
    ct.truncate(original_len);
    ct
}

/// Core CTS decryption implementation using a provided CBC decrypt closure.
///
/// The CTS encrypt format for non-block-aligned data is:
///   `C_1 .. C_{n-2}, C_n (full), C_{n-1}[0..remainder]`
///
/// Decryption recovers the stolen bytes by ECB-decrypting the last full block
/// (using CBC with IV=0 on a single block, which is equivalent to ECB), then
/// reconstructing the full penultimate block from the partial ciphertext bytes
/// plus the stolen intermediate bytes.
fn cts_decrypt_impl<F>(ciphertext: &[u8], cbc_decrypt: F, key: &[u8]) -> Result<Vec<u8>>
where
    F: Fn(&[u8], &[u8; AES_BLOCK_SIZE], &[u8]) -> Result<Vec<u8>>,
{
    let ct_len = ciphertext.len();
    let iv = [0u8; AES_BLOCK_SIZE];

    // Single block (≤16 bytes): ECB = CBC with IV=0 on one padded block
    if ct_len <= AES_BLOCK_SIZE {
        let mut padded = [0u8; AES_BLOCK_SIZE];
        padded[..ct_len].copy_from_slice(ciphertext);
        let pt = cbc_decrypt(key, &iv, &padded)?;
        return Ok(pt[..ct_len].to_vec());
    }

    let remainder = ct_len % AES_BLOCK_SIZE;

    if remainder == 0 {
        // Block-aligned: swap last two blocks back, then CBC decrypt
        let mut data = ciphertext.to_vec();
        let n = data.len() / AES_BLOCK_SIZE;
        if n >= 2 {
            let swap_start = (n - 2) * AES_BLOCK_SIZE;
            let mid = swap_start + AES_BLOCK_SIZE;
            let (left, right) = data.split_at_mut(mid);
            let penultimate = &mut left[swap_start..];
            let mut temp = [0u8; AES_BLOCK_SIZE];
            temp.copy_from_slice(penultimate);
            penultimate.copy_from_slice(&right[..AES_BLOCK_SIZE]);
            right[..AES_BLOCK_SIZE].copy_from_slice(&temp);
        }
        return cbc_decrypt(key, &iv, &data);
    }

    // ── Non-block-aligned CTS decryption ──
    //
    // Input layout: [C_1..C_{n-2}] [C_n (16 bytes)] [C_{n-1} partial (remainder bytes)]
    //
    // Step 1: ECB-decrypt C_n to get intermediate I
    //         I = D_K(C_n) = (P_n || 0^pad) XOR C_{n-1}
    //
    // Step 2: Recover full C_{n-1}:
    //         C_{n-1}[0..r]  = partial (from input)
    //         C_{n-1}[r..16] = I[r..16]  (the "stolen" bytes)
    //
    // Step 3: P_n = I[0..r] XOR C_{n-1}[0..r]
    //
    // Step 4: CBC decrypt [C_1..C_{n-2}, C_{n-1}] → P_1..P_{n-1}
    //
    // Step 5: Result = P_1..P_{n-1} || P_n

    let n_full = ct_len / AES_BLOCK_SIZE;
    let last_full_start = (n_full - 1) * AES_BLOCK_SIZE;
    let last_full_block = &ciphertext[last_full_start..last_full_start + AES_BLOCK_SIZE];
    let partial_block = &ciphertext[last_full_start + AES_BLOCK_SIZE..];

    // Step 1: ECB decrypt = CBC with IV=0 on a single block
    let intermediate = cbc_decrypt(key, &iv, last_full_block)?;

    // Step 2: Reconstruct full penultimate block
    let mut c_penultimate = vec![0u8; AES_BLOCK_SIZE];
    c_penultimate[..remainder].copy_from_slice(partial_block);
    c_penultimate[remainder..].copy_from_slice(&intermediate[remainder..]);

    // Step 3: Recover partial last plaintext block
    let mut p_last = vec![0u8; remainder];
    for i in 0..remainder {
        p_last[i] = intermediate[i] ^ c_penultimate[i];
    }

    // Step 4: CBC decrypt leading blocks + reconstructed penultimate block
    let mut cbc_data = Vec::with_capacity(n_full * AES_BLOCK_SIZE);
    if last_full_start > 0 {
        cbc_data.extend_from_slice(&ciphertext[..last_full_start]);
    }
    cbc_data.extend_from_slice(&c_penultimate);

    let leading_pt = cbc_decrypt(key, &iv, &cbc_data)?;

    // Step 5: Combine
    let mut result = leading_pt;
    result.extend_from_slice(&p_last);
    Ok(result)
}

// ═══════════════════════════════════════════════════════════
// Standard AES-CBC (for SAM/LSA decryption)
// ═══════════════════════════════════════════════════════════

/// Decrypt with AES-128-CBC (Vista+ SAM hash decryption).
///
/// Input must be a multiple of 16 bytes. IV is provided separately.
pub fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 {
        bail!("AES-128 key must be 16 bytes");
    }
    if iv.len() != 16 {
        bail!("AES-128-CBC IV must be 16 bytes");
    }
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK_SIZE != 0 {
        bail!("AES-128-CBC ciphertext must be a non-empty multiple of 16 bytes");
    }
    let dec = Aes128CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-128-CBC decrypt: {e}"))
}

/// Encrypt with AES-128-CBC.
pub fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 {
        bail!("AES-128 key must be 16 bytes");
    }
    if iv.len() != 16 {
        bail!("AES-128-CBC IV must be 16 bytes");
    }
    let enc = Aes128CbcEnc::new(key.into(), iv.into());
    Ok(enc.encrypt_padded_vec_mut::<NoPadding>(plaintext))
}

/// Decrypt with AES-256-CBC (Vista+ LSA secret decryption).
pub fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("AES-256 key must be 32 bytes");
    }
    if iv.len() != 16 {
        bail!("AES-256-CBC IV must be 16 bytes");
    }
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK_SIZE != 0 {
        bail!("AES-256-CBC ciphertext must be a non-empty multiple of 16 bytes");
    }
    let dec = Aes256CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-256-CBC decrypt: {e}"))
}

/// Encrypt with AES-256-CBC.
pub fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("AES-256 key must be 32 bytes");
    }
    if iv.len() != 16 {
        bail!("AES-256-CBC IV must be 16 bytes");
    }
    let enc = Aes256CbcEnc::new(key.into(), iv.into());
    Ok(enc.encrypt_padded_vec_mut::<NoPadding>(plaintext))
}

// ═══════════════════════════════════════════════════════════
// Vista+ SAM Hash Decryption (AES-based)
// ═══════════════════════════════════════════════════════════

/// Decrypt a Vista+ SAM hash (AES-128-CBC + DES two-block).
///
/// Algorithm:
/// 1. AES-128-CBC decrypt with provided IV.
/// 2. DES two-block decrypt using RID-derived keys.
pub fn decrypt_sam_hash_aes(
    rid: u32,
    hashed_boot_key: &[u8],
    encrypted_hash: &[u8],
    iv: &[u8],
) -> Result<[u8; 16]> {
    if hashed_boot_key.len() < 16 {
        bail!("Hashed boot key too short");
    }

    // Step 1: AES-128-CBC decrypt
    // Pad ciphertext to block size if needed
    let mut ct = encrypted_hash.to_vec();
    if ct.len() % AES_BLOCK_SIZE != 0 {
        ct.resize(ct.len().div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE, 0);
    }
    let decrypted = aes128_cbc_decrypt(&hashed_boot_key[..16], iv, &ct)?;

    if decrypted.len() < 16 {
        bail!("AES-decrypted SAM hash too short");
    }

    // Step 2: DES two-block final decrypt
    super::rc4_util::des_decrypt_hash(rid, &decrypted[..16])
}

// ═══════════════════════════════════════════════════════════
// Vista+ LSA Secret Decryption (AES-256-CBC)
// ═══════════════════════════════════════════════════════════

/// Decrypt a Vista+ LSA secret using AES-256-CBC.
///
/// The encrypted blob has the IV prepended (first 16 bytes), then AES-256-CBC
/// encrypted data follows. The encryption key is the LSA encryption key from
/// the policy store.
///
/// The decryption is done in 16-byte-at-a-time blocks with the same IV reused
/// for each block (per Impacket's LSA implementation).
pub fn decrypt_lsa_secret_vista(encryption_key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 32 {
        bail!("LSA secret too short (need IV + at least one block)");
    }

    let iv = &encrypted_data[..16];
    let data = &encrypted_data[16..];

    // Decrypt in 16-byte blocks, each with the same IV (per MS implementation)
    let key = if encryption_key.len() >= 32 {
        &encryption_key[..32]
    } else {
        // Pad key to 32 bytes if shorter
        let mut padded = vec![0u8; 32];
        padded[..encryption_key.len()].copy_from_slice(encryption_key);
        return decrypt_lsa_blocks(&padded, iv, data);
    };

    let result = decrypt_lsa_blocks(key, iv, data)?;
    Ok(result)
}

/// Decrypt LSA blocks 16 bytes at a time with reused IV.
fn decrypt_lsa_blocks(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        if chunk.len() == 16 {
            let dec = aes256_cbc_decrypt(key, iv, chunk)?;
            result.extend_from_slice(&dec);
        } else {
            // Last partial block — pad and decrypt
            let mut padded = [0u8; 16];
            padded[..chunk.len()].copy_from_slice(chunk);
            let dec = aes256_cbc_decrypt(key, iv, &padded)?;
            result.extend_from_slice(&dec[..chunk.len()]);
        }
    }
    Ok(result)
}

/// Decrypt the Vista+ LSA encryption key list (policy secret EK list).
///
/// Structure of `LSAPR_CR_CIPHER_VALUE` (simplified):
/// - Bytes 0..3:  version (must be 3)
/// - Bytes 16..32: IV
/// - Bytes 32..: AES-256-CBC encrypted key material
///
/// The boot key is SHA-256 hashed to derive the AES-256 key.
pub fn decrypt_lsa_key_vista(boot_key: &[u8], ek_list: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    if ek_list.len() < 48 {
        bail!("EK list too short for Vista+ decryption");
    }

    // Derive the AES key from boot key via SHA-256
    let mut hasher = Sha256::new();
    hasher.update(boot_key);
    let aes_key = hasher.finalize();

    let iv = &ek_list[16..32];
    let encrypted = &ek_list[32..];

    // Decrypt in 16-byte blocks with reused IV
    decrypt_lsa_blocks(&aes_key, iv, encrypted)
}

/// Decrypt a Vista+ cached domain credential entry.
///
/// Uses AES-128-CBC with the NL$KEY and an all-zeros IV.
pub fn decrypt_cached_credential(nl_key: &[u8], encrypted_entry: &[u8]) -> Result<Vec<u8>> {
    if nl_key.len() < 16 {
        bail!("NL$KEY too short");
    }
    let iv = [0u8; 16];
    let key = &nl_key[..16];

    // Pad to block boundary
    let mut ct = encrypted_entry.to_vec();
    if ct.len() % 16 != 0 {
        ct.resize(ct.len().div_ceil(16) * 16, 0);
    }

    aes128_cbc_decrypt(key, &iv, &ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_aes256() {
        let key = derive_key_aes256("password", "CONTOSO.COMadministrator");
        assert_eq!(key.len(), 32);
        // Key derivation is deterministic
        let key2 = derive_key_aes256("password", "CONTOSO.COMadministrator");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_derive_key_aes128() {
        let key = derive_key_aes128("password", "CONTOSO.COMadministrator");
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = [0xaa; 16];
        let iv = [0xbb; 16];
        let plaintext = [0x42; 32]; // 2 blocks
        let ct = aes128_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let pt = aes128_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = [0xaa; 32];
        let iv = [0xbb; 16];
        let plaintext = [0x42; 48]; // 3 blocks
        let ct = aes256_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let pt = aes256_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes256_cts_roundtrip_exact_blocks() {
        let key = [0xcc; 32];
        let plaintext = [0x55; 32]; // Exactly 2 blocks
        let ct = aes256_cts_encrypt(&key, &plaintext).unwrap();
        let pt = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn test_aes256_cts_roundtrip_non_aligned() {
        let key = [0xcc; 32];
        let plaintext = [0x55; 25]; // Not aligned to block boundary
        let ct = aes256_cts_encrypt(&key, &plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len()); // CTS preserves length
        let pt = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn test_aes128_cts_roundtrip() {
        let key = [0xdd; 16];
        let plaintext = b"This is a Kerberos ticket test!!extra";
        let ct = aes128_cts_encrypt(&key, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len());
        let pt = aes128_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn test_aes_cts_single_block() {
        let key = [0xee; 32];
        let plaintext = [0x42; 16]; // Exactly one block
        let ct = aes256_cts_encrypt(&key, &plaintext).unwrap();
        let pt = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn test_aes_cts_empty() {
        let key = [0xff; 32];
        let ct = aes256_cts_encrypt(&key, &[]).unwrap();
        assert!(ct.is_empty());
    }

    #[test]
    fn test_cached_credential_decrypt() {
        let key = [0xaa; 16];
        // Encrypt some test data first
        let iv = [0u8; 16];
        let plaintext = [0x42; 32];
        let ct = aes128_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let pt = decrypt_cached_credential(&key, &ct).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn test_aes128_cbc_bad_key_length() {
        let result = aes128_cbc_decrypt(&[0u8; 15], &[0u8; 16], &[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes256_cbc_bad_key_length() {
        let result = aes256_cbc_decrypt(&[0u8; 16], &[0u8; 16], &[0u8; 16]);
        assert!(result.is_err());
    }
}
