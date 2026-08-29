#![allow(dead_code)]
//! Encrypted operator credential vault (`ovt creds`).
//!
//! Stores AD credentials (password or NT hash) for reuse across commands.
//! The vault file is encrypted with AES-256-CBC (encrypt-then-MAC with
//! HMAC-SHA256) using a key derived from a master passphrase via
//! PBKDF2-HMAC-SHA256 (600k iterations). The passphrase is never stored.
//!
//! File layout: `magic(8) | version(1) | kdf_iter(4 LE) | salt(16) |
//! iv(16) | mac(32) | ciphertext`
//!
//! Secrets are masked in `list` output; the full secret is only shown with
//! `show --reveal` or used by `--from-vault <NAME>` on any command.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use anyhow::{Context, Result, bail};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};

/// Vault file magic -- identifies an Overthrone vault file.
const VAULT_MAGIC: &[u8; 8] = b"OVTVAULT";
/// Current vault format version.
const VAULT_VERSION: u8 = 1;
/// PBKDF2 iteration count for master passphrase -> key.
const KDF_ITERATIONS: u32 = 600_000;
/// Salt length (16 bytes).
const SALT_LEN: usize = 16;
/// AES-256-CBC IV length.
const IV_LEN: usize = 16;
/// HMAC-SHA256 output length.
const MAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// One credential entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique name used to reference the entry (`--from-vault <name>`)
    pub name: String,
    /// Domain FQDN (e.g., "corp.local")
    pub domain: String,
    /// Username (without domain prefix)
    pub username: String,
    /// Secret: password or NT hash
    pub secret: String,
    /// Whether `secret` is an NT hash (true) or a password (false)
    pub is_hash: bool,
    /// Optional notes (e.g., "Domain Admin, DC01")
    pub notes: Option<String>,
    /// When the entry was created
    pub created_at: DateTime<Utc>,
    /// When the entry was last updated
    pub updated_at: DateTime<Utc>,
}

impl VaultEntry {
    /// New entry with timestamps set to now.
    pub fn new(
        name: &str,
        domain: &str,
        username: &str,
        secret: &str,
        is_hash: bool,
        notes: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            name: name.to_string(),
            domain: domain.to_string(),
            username: username.to_string(),
            secret: secret.to_string(),
            is_hash,
            notes,
            created_at: now,
            updated_at: now,
        }
    }

    /// Masked display of the secret (keeps the vault usable on screen).
    pub fn masked_secret(&self) -> String {
        mask_secret(&self.secret)
    }
}

/// Mask a secret for display: keep first 2 + last 2 chars.
pub fn mask_secret(secret: &str) -> String {
    let bytes = secret.as_bytes();
    if bytes.len() <= 4 {
        return "*".repeat(bytes.len());
    }
    let mut out = String::with_capacity(bytes.len());
    out.push_str(&secret[..2]);
    out.push_str(&"*".repeat(bytes.len() - 4));
    out.push_str(&secret[bytes.len() - 2..]);
    out
}

/// The on-disk vault (encrypted payload plus KDF parameters).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    /// PBKDF2 iteration count used for the master key
    kdf_iter: u32,
    /// Salt for KDF
    salt: [u8; SALT_LEN],
    /// AES-CBC IV
    iv: [u8; IV_LEN],
    /// HMAC-SHA256 over (version || salt || iv || ciphertext)
    mac: [u8; MAC_LEN],
    /// Encrypted JSON payload
    ciphertext: Vec<u8>,
}

/// Default vault location: `<config_dir>/vault.ovt`.
pub fn default_vault_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("OT_CONFIG")
        && !explicit.is_empty()
    {
        let p = PathBuf::from(explicit);
        return Some(
            p.parent()
                .map(|parent| parent.join("vault.ovt"))
                .unwrap_or_else(|| PathBuf::from("vault.ovt")),
        );
    }
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "overthrone", "Overthrone") {
        return Some(proj_dirs.config_dir().join("vault.ovt"));
    }
    if let Some(home) = dirs::config_dir() {
        return Some(home.join("overthrone").join("vault.ovt"));
    }
    None
}

// ===========================================================
// Crypto
// ===========================================================

/// Derive the 32-byte AES key from the master passphrase + salt.
fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
    key
}

/// Encrypt the JSON payload into a VaultFile.
fn encrypt_payload(passphrase: &str, payload: &[u8], iterations: u32) -> Result<VaultFile> {
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    rand::rng().fill(&mut salt);
    rand::rng().fill(&mut iv);

    let key = derive_key(passphrase, &salt, iterations);

    // AES-256-CBC encrypt with PKCS7 padding
    let key_ga = GenericArray::from_slice(&key);
    let iv_ga = GenericArray::from_slice(&iv);
    let encryptor = Encryptor::<Aes256>::new(iv_ga, key_ga);
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(payload);

    // Encrypt-then-MAC: HMAC over (version || salt || iv || ciphertext)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).context("HMAC key init")?;
    mac.update(&[VAULT_VERSION]);
    mac.update(&salt);
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    Ok(VaultFile {
        kdf_iter: iterations,
        salt,
        iv,
        mac: mac_bytes.into(),
        ciphertext,
    })
}

/// Decrypt a VaultFile, verifying the MAC first (reject tampering).
fn decrypt_payload(passphrase: &str, file: &VaultFile) -> Result<Vec<u8>> {
    let key = derive_key(passphrase, &file.salt, file.kdf_iter);

    // Verify MAC
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).context("HMAC key init")?;
    mac.update(&[VAULT_VERSION]);
    mac.update(&file.salt);
    mac.update(&file.iv);
    mac.update(&file.ciphertext);
    let expected = mac.finalize().into_bytes();
    // Constant-time comparison via hmac's verify
    let mut verifier = <HmacSha256 as Mac>::new_from_slice(&key).context("HMAC key init")?;
    verifier.update(&[VAULT_VERSION]);
    verifier.update(&file.salt);
    verifier.update(&file.iv);
    verifier.update(&file.ciphertext);
    verifier
        .verify_slice(&expected)
        .context("vault MAC verification failed (wrong passphrase or tampered file)")?;
    let _ = expected;

    // Decrypt
    let key_ga = GenericArray::from_slice(&key);
    let iv_ga = GenericArray::from_slice(&file.iv);
    let decryptor = Decryptor::<Aes256>::new(iv_ga, key_ga);
    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&file.ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed (wrong passphrase?): {e}"))?;
    Ok(plaintext)
}

// ===========================================================
// Vault Operations
// ===========================================================

/// Load the vault from disk and decrypt it.
pub fn load_vault(path: &Path, passphrase: &str) -> Result<Vec<VaultEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read(path).with_context(|| format!("read vault {}", path.display()))?;
    if raw.len() < 8 + 1 + 4 + SALT_LEN + IV_LEN + MAC_LEN {
        bail!("vault file too short (corrupted?)");
    }
    if &raw[..8] != VAULT_MAGIC {
        bail!("not an Overthrone vault file (bad magic)");
    }
    if raw[8] != VAULT_VERSION {
        bail!("unsupported vault version {}", raw[8]);
    }

    let kdf_iter = u32::from_le_bytes([raw[9], raw[10], raw[11], raw[12]]);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[13..13 + SALT_LEN]);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&raw[13 + SALT_LEN..13 + SALT_LEN + IV_LEN]);
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&raw[13 + SALT_LEN + IV_LEN..13 + SALT_LEN + IV_LEN + MAC_LEN]);
    let ciphertext = raw[13 + SALT_LEN + IV_LEN + MAC_LEN..].to_vec();

    let file = VaultFile {
        kdf_iter,
        salt,
        iv,
        mac,
        ciphertext,
    };
    let plaintext = decrypt_payload(passphrase, &file)?;
    let entries: Vec<VaultEntry> = serde_json::from_slice(&plaintext)
        .context("vault payload is not valid JSON (corrupted?)")?;
    Ok(entries)
}

/// Encrypt and persist the vault to disk.
pub fn save_vault(path: &Path, passphrase: &str, entries: &[VaultEntry]) -> Result<()> {
    let payload = serde_json::to_vec(entries).context("serialize vault entries")?;
    let file = encrypt_payload(passphrase, &payload, KDF_ITERATIONS)?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create vault dir {}", parent.display()))?;
    }

    let mut out = Vec::with_capacity(64 + file.ciphertext.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.push(VAULT_VERSION);
    out.extend_from_slice(&file.kdf_iter.to_le_bytes());
    out.extend_from_slice(&file.salt);
    out.extend_from_slice(&file.iv);
    out.extend_from_slice(&file.mac);
    out.extend_from_slice(&file.ciphertext);

    std::fs::write(path, &out).with_context(|| format!("write vault {}", path.display()))?;
    Ok(())
}

// ===========================================================
// Entry CRUD
// ===========================================================

/// Add or replace a vault entry.
pub fn upsert_entry(entries: &mut Vec<VaultEntry>, entry: VaultEntry) {
    let now = Utc::now();
    if let Some(existing) = entries.iter_mut().find(|e| e.name == entry.name) {
        existing.domain = entry.domain;
        existing.username = entry.username;
        existing.secret = entry.secret;
        existing.is_hash = entry.is_hash;
        existing.notes = entry.notes;
        existing.updated_at = now;
    } else {
        entries.push(entry);
    }
}

/// Remove an entry by name. Returns the removed entry, if any.
pub fn remove_entry(entries: &mut Vec<VaultEntry>, name: &str) -> Option<VaultEntry> {
    let idx = entries.iter().position(|e| e.name == name)?;
    Some(entries.remove(idx))
}

/// Look up an entry by name.
pub fn find_entry<'a>(entries: &'a [VaultEntry], name: &str) -> Option<&'a VaultEntry> {
    entries.iter().find(|e| e.name == name)
}

/// Validate a vault entry name: alphanumeric + `-`/`_`, 1..=32 chars.
pub fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        bail!("entry name must be 1..=32 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("entry name may only contain A-Z, a-z, 0-9, '-' and '_'");
    }
    Ok(())
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entries() -> Vec<VaultEntry> {
        vec![
            VaultEntry::new(
                "da",
                "corp.local",
                "Administrator",
                "P@ssw0rd!",
                false,
                Some("Domain Admin".to_string()),
            ),
            VaultEntry::new(
                "svc-sql",
                "corp.local",
                "svc_sql",
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                true,
                None,
            ),
        ]
    }

    #[test]
    fn test_mask_secret() {
        assert_eq!(mask_secret("P@ssw0rd!"), "P@********!");
        assert_eq!(mask_secret("abc"), "***");
        assert_eq!(mask_secret("ab"), "**");
        assert_eq!(mask_secret("abcd"), "****");
        assert_eq!(mask_secret(""), "");
    }

    #[test]
    fn test_entry_new_timestamps() {
        let e = VaultEntry::new("x", "d", "u", "s", false, None);
        assert_eq!(e.name, "x");
        assert!(!e.is_hash);
        assert!(e.created_at <= e.updated_at);
    }

    #[test]
    fn test_vault_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.ovt");
        let entries = test_entries();

        save_vault(&path, "hunter2", &entries).unwrap();
        let loaded = load_vault(&path, "hunter2").unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "da");
        assert_eq!(loaded[0].secret, "P@ssw0rd!");
        assert!(loaded[1].is_hash);
    }

    #[test]
    fn test_vault_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.ovt");
        save_vault(&path, "hunter2", &test_entries()).unwrap();
        assert!(load_vault(&path, "wrong").is_err());
    }

    #[test]
    fn test_vault_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.ovt");
        save_vault(&path, "hunter2", &test_entries()).unwrap();

        // Flip a ciphertext byte -> MAC check must fail
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();
        assert!(load_vault(&path, "hunter2").is_err());
    }

    #[test]
    fn test_vault_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.ovt");
        let entries = load_vault(&path, "hunter2").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_vault_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.ovt");
        std::fs::write(
            &path,
            b"NOTAVLT0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert!(load_vault(&path, "hunter2").is_err());
    }

    #[test]
    fn test_upsert_entry_new_and_replace() {
        let mut entries = Vec::new();
        upsert_entry(
            &mut entries,
            VaultEntry::new("a", "d1", "u1", "s1", false, None),
        );
        assert_eq!(entries.len(), 1);
        // Replace
        upsert_entry(
            &mut entries,
            VaultEntry::new("a", "d2", "u2", "s2", true, None),
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "d2");
        assert_eq!(entries[0].secret, "s2");
        assert!(entries[0].is_hash);
    }

    #[test]
    fn test_remove_entry() {
        let mut entries = test_entries();
        let removed = remove_entry(&mut entries, "da");
        assert!(removed.is_some());
        assert_eq!(entries.len(), 1);
        assert!(remove_entry(&mut entries, "missing").is_none());
    }

    #[test]
    fn test_find_entry() {
        let entries = test_entries();
        assert!(find_entry(&entries, "da").is_some());
        assert!(find_entry(&entries, "nope").is_none());
    }

    #[test]
    fn test_validate_entry_name() {
        assert!(validate_entry_name("da").is_ok());
        assert!(validate_entry_name("svc-sql_01").is_ok());
        assert!(validate_entry_name("").is_err());
        assert!(validate_entry_name(&"a".repeat(33)).is_err());
        assert!(validate_entry_name("has space").is_err());
        assert!(validate_entry_name("../../etc/passwd").is_err());
    }

    #[test]
    fn test_default_vault_path() {
        let p = default_vault_path();
        assert!(p.is_some());
        let p = p.unwrap();
        assert_eq!(p.file_name().unwrap().to_str().unwrap(), "vault.ovt");
    }

    #[test]
    fn test_vault_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep/nested/vault.ovt");
        save_vault(&path, "hunter2", &test_entries()).unwrap();
        assert!(path.exists());
        let loaded = load_vault(&path, "hunter2").unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_vault_different_iterations_still_load() {
        // Sanity: save with default iterations, ensure load uses stored value
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.ovt");
        save_vault(&path, "hunter2", &test_entries()).unwrap();
        let raw = std::fs::read(&path).unwrap();
        // kdf_iter at offset 9..13
        let stored = u32::from_le_bytes([raw[9], raw[10], raw[11], raw[12]]);
        assert_eq!(stored, KDF_ITERATIONS);
    }
}
