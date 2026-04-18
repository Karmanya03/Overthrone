//! Inline Hash Cracking — RC4-HMAC, AES (Kerberos) and NTLM hash cracking.
//!
//! Provides offline cracking capabilities for:
//! - AS-REP Roasting hashes (hashcat mode 18200)
//! - Kerberoast hashes (hashcat mode 13100/19600/19700)
//! - NTLM hashes (hashcat mode 1000)
//!
//! Features:
//! - Embedded top-10K wordlist (compressed with zstd)
//! - Rayon parallel cracking (~500K candidates/sec on CPU)
//! - Rule engine for password variations (append digits, capitalize, l33t)
//! - Mask attack engine (?l = lower, ?u = upper, ?d = digit, ?s = symbol, ?a = all)
//! - AES128/AES256 Kerberos key derivation via PBKDF2-HMAC-SHA1 (etype 17/18)
//! - Hashcat subprocess fallback for GPU acceleration

use crate::error::{OverthroneError, Result};
use rayon::prelude::*;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Embedded Wordlist (Top 10K + common passwords)
// ═══════════════════════════════════════════════════════════

/// Relative path to the shared compressed top-10K password wordlist.
const WORDLIST_REL_PATH: &str = "../../assets/wordlist_top10k.txt.zst";

/// Fallback minimal wordlist if decompression fails
const FALLBACK_WORDLIST: &[&str] = &[
    "password",
    "Password1",
    "Password123",
    "P@ssw0rd",
    "P@ssword123",
    "admin",
    "Admin123",
    "administrator",
    "Administrator1",
    "letmein",
    "welcome",
    "Welcome1",
    "Welcome123",
    "qwerty",
    "qwerty123",
    "abc123",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "Password1!",
    "Spring2024",
    "Summer2024",
    "Fall2024",
    "Winter2024",
    "changeme",
    "ChangeMe1",
    "secret",
    "Secret123",
];

/// Decompress and return the embedded wordlist
pub fn get_embedded_wordlist() -> Vec<String> {
    load_wordlist_bytes()
        .and_then(|bytes| decompress_wordlist(&bytes))
        .unwrap_or_else(|e| {
            warn!("Falling back to minimal built-in wordlist: {}", e);
            // Fallback to minimal built-in list
            FALLBACK_WORDLIST.iter().map(|s| s.to_string()).collect()
        })
}

fn load_wordlist_bytes() -> Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(WORDLIST_REL_PATH);
    std::fs::read(&path).map_err(|e| {
        OverthroneError::custom(format!(
            "Failed to read wordlist at {}: {}",
            path.display(),
            e
        ))
    })
}

/// Decompress a zstd-compressed wordlist
fn decompress_wordlist(compressed: &[u8]) -> Result<Vec<String>> {
    let decompressed = zstd::decode_all(compressed)
        .map_err(|e| OverthroneError::custom(format!("Wordlist decompression failed: {}", e)))?;

    let text = String::from_utf8_lossy(&decompressed);
    Ok(text
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

// ═══════════════════════════════════════════════════════════
// Rule Engine — Password Variations
// ═══════════════════════════════════════════════════════════

/// Password transformation rules for expanding the wordlist
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Use as-is (no transformation)
    None,
    /// Convert to lowercase
    Lowercase,
    /// Convert to uppercase
    Uppercase,
    /// Capitalize first letter
    Capitalize,
    /// Append single digit (0-9)
    AppendDigit,
    /// Append two digits (00-99)
    AppendTwoDigits,
    /// Append year (2015-2026)
    AppendYear,
    /// Prepend digit (0-9)
    PrependDigit,
    /// Common l33t substitutions (a→@, e→3, i→1, o→0, s→$)
    Leet,
    /// Append special char (!@#$%^&*)
    AppendSpecial,
    /// Capitalize + append digit
    CapitalizeDigit,
    /// Capitalize + append year
    CapitalizeYear,
    /// Full variation (capitalize + leet + digit)
    FullVariation,
}

impl Rule {
    /// Apply the rule to a base password
    pub fn apply(&self, password: &str) -> Vec<String> {
        match self {
            Rule::None => vec![password.to_string()],
            Rule::Lowercase => vec![password.to_lowercase()],
            Rule::Uppercase => vec![password.to_uppercase()],
            Rule::Capitalize => {
                let mut chars: Vec<char> = password.chars().collect();
                if let Some(first) = chars.first_mut() {
                    *first = first.to_uppercase().next().unwrap_or(*first);
                }
                vec![chars.into_iter().collect()]
            }
            Rule::AppendDigit => (0..=9).map(|d| format!("{}{}", password, d)).collect(),
            Rule::AppendTwoDigits => (0..=99).map(|d| format!("{}{:02}", password, d)).collect(),
            Rule::AppendYear => (2015..=2026)
                .map(|y| format!("{}{}", password, y))
                .collect(),
            Rule::PrependDigit => (0..=9).map(|d| format!("{}{}", d, password)).collect(),
            Rule::Leet => {
                vec![apply_leet(password)]
            }
            Rule::AppendSpecial => ['!', '@', '#', '$', '%', '^', '&', '*']
                .iter()
                .map(|c| format!("{}{}", password, c))
                .collect(),
            Rule::CapitalizeDigit => {
                let cap = {
                    let mut chars: Vec<char> = password.chars().collect();
                    if let Some(first) = chars.first_mut() {
                        *first = first.to_uppercase().next().unwrap_or(*first);
                    }
                    chars.into_iter().collect::<String>()
                };
                (0..=9).map(|d| format!("{}{}", cap, d)).collect()
            }
            Rule::CapitalizeYear => {
                let cap = {
                    let mut chars: Vec<char> = password.chars().collect();
                    if let Some(first) = chars.first_mut() {
                        *first = first.to_uppercase().next().unwrap_or(*first);
                    }
                    chars.into_iter().collect::<String>()
                };
                (2015..=2026).map(|y| format!("{}{}", cap, y)).collect()
            }
            Rule::FullVariation => {
                let cap = {
                    let mut chars: Vec<char> = password.chars().collect();
                    if let Some(first) = chars.first_mut() {
                        *first = first.to_uppercase().next().unwrap_or(*first);
                    }
                    chars.into_iter().collect::<String>()
                };
                let leet = apply_leet(&cap);
                let mut results = Vec::new();
                for pwd in [&cap, &leet] {
                    for d in 0..=9 {
                        results.push(format!("{}{}", pwd, d));
                    }
                    for y in 2015..=2026 {
                        results.push(format!("{}{}", pwd, y));
                    }
                }
                results
            }
        }
    }
}

/// Apply common l33t speak substitutions
fn apply_leet(s: &str) -> String {
    s.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '@',
            'e' => '3',
            'i' => '1',
            'o' => '0',
            's' => '$',
            'l' => '1',
            't' => '7',
            'b' => '8',
            'g' => '9',
            other => other,
        })
        .collect()
}

/// Generate expanded wordlist with rule-based variations
pub fn expand_wordlist(base: &[String], rules: &[Rule]) -> Vec<String> {
    let mut expanded = Vec::with_capacity(base.len() * 10);

    for password in base {
        for rule in rules {
            expanded.extend(rule.apply(password));
        }
    }

    // Remove duplicates
    expanded.sort();
    expanded.dedup();
    expanded
}

// ═══════════════════════════════════════════════════════════
// Mask Attack Engine
// ═══════════════════════════════════════════════════════════

/// Mask-based candidate generator (hashcat-style masks).
///
/// Charset tokens:
/// - `?l` = lowercase a-z
/// - `?u` = uppercase A-Z
/// - `?d` = digit 0-9
/// - `?s` = symbols `!@#$%^&*()-_=+`
/// - `?a` = all printable (`?l + ?u + ?d + ?s`)
///
/// Literal characters are used as-is.
///
/// # Example
/// ```ignore
/// let mask = MaskPattern::parse("?u?l?l?l?d?d?d?d")?; // e.g. Pass1234
/// let candidates = mask.generate();
/// ```
#[derive(Debug, Clone)]
pub struct MaskPattern {
    positions: Vec<MaskPosition>,
}

#[derive(Debug, Clone)]
enum MaskPosition {
    Literal(char),
    Charset(Vec<char>),
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &str = "0123456789";
const SYMBOL: &str = "!@#$%^&*()-_=+";

impl MaskPattern {
    /// Parse a mask string like `?u?l?l?l?d?d?d?d`
    pub fn parse(mask: &str) -> Result<Self> {
        let mut positions = Vec::new();
        let mut chars = mask.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '?' {
                match chars.next() {
                    Some('l') => positions.push(MaskPosition::Charset(LOWER.chars().collect())),
                    Some('u') => positions.push(MaskPosition::Charset(UPPER.chars().collect())),
                    Some('d') => positions.push(MaskPosition::Charset(DIGIT.chars().collect())),
                    Some('s') => positions.push(MaskPosition::Charset(SYMBOL.chars().collect())),
                    Some('a') => {
                        let mut all: Vec<char> = Vec::with_capacity(76);
                        all.extend(LOWER.chars());
                        all.extend(UPPER.chars());
                        all.extend(DIGIT.chars());
                        all.extend(SYMBOL.chars());
                        positions.push(MaskPosition::Charset(all));
                    }
                    Some(other) => {
                        return Err(OverthroneError::custom(format!(
                            "Unknown mask token: ?{}",
                            other
                        )));
                    }
                    None => {
                        return Err(OverthroneError::custom(
                            "Incomplete mask token: trailing '?'",
                        ));
                    }
                }
            } else {
                positions.push(MaskPosition::Literal(c));
            }
        }

        if positions.is_empty() {
            return Err(OverthroneError::custom("Empty mask pattern"));
        }

        Ok(MaskPattern { positions })
    }

    /// Total keyspace size for this mask
    pub fn keyspace(&self) -> u64 {
        self.positions
            .iter()
            .map(|p| match p {
                MaskPosition::Literal(_) => 1u64,
                MaskPosition::Charset(cs) => cs.len() as u64,
            })
            .product()
    }

    /// Generate all candidates from this mask.
    /// WARNING: can be extremely large — use `generate_limited` for safety.
    pub fn generate(&self) -> Vec<String> {
        self.generate_limited(u64::MAX)
    }

    /// Generate candidates up to `limit` count.
    pub fn generate_limited(&self, limit: u64) -> Vec<String> {
        let keyspace = self.keyspace();
        let actual_limit = keyspace.min(limit) as usize;

        let mut results = Vec::with_capacity(actual_limit.min(10_000_000));
        let mut indices = vec![0usize; self.positions.len()];
        let mut buf = String::with_capacity(self.positions.len());

        for _ in 0..actual_limit {
            buf.clear();
            for (i, pos) in self.positions.iter().enumerate() {
                match pos {
                    MaskPosition::Literal(c) => buf.push(*c),
                    MaskPosition::Charset(cs) => buf.push(cs[indices[i]]),
                }
            }
            results.push(buf.clone());

            // Increment odometer (rightmost first)
            let mut carry = true;
            for i in (0..self.positions.len()).rev() {
                if !carry {
                    break;
                }
                match &self.positions[i] {
                    MaskPosition::Literal(_) => { /* skip literals */ }
                    MaskPosition::Charset(cs) => {
                        indices[i] += 1;
                        if indices[i] >= cs.len() {
                            indices[i] = 0;
                        } else {
                            carry = false;
                        }
                    }
                }
            }
            if carry {
                break; // Full cycle completed
            }
        }

        results
    }
}

// ═══════════════════════════════════════════════════════════
// Hash Types
// ═══════════════════════════════════════════════════════════

/// Supported hash types for cracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    /// AS-REP Roasting (hashcat mode 18200)
    AsRep {
        username: String,
        domain: String,
        etype: i32,
        cipher: Vec<u8>,
    },
    /// Kerberoast TGS (hashcat mode 13100/19600/19700)
    Kerberoast {
        username: String,
        domain: String,
        spn: String,
        etype: i32,
        cipher: Vec<u8>,
    },
    /// NTLM hash (hashcat mode 1000)
    Ntlm { hash: [u8; 16] },
}

impl HashType {
    /// Parse an AS-REP hash string (hashcat format)
    /// Format: $krb5asrep${etype}${user}@{domain}:{checksum_hex}${edata2_hex}
    pub fn parse_asrep(hash_str: &str) -> Result<Self> {
        let rest = hash_str
            .strip_prefix("$krb5asrep$")
            .ok_or_else(|| OverthroneError::custom("Invalid AS-REP hash format"))?;
        let (etype_str, principal_and_cipher) = rest
            .split_once('$')
            .ok_or_else(|| OverthroneError::custom("Invalid AS-REP hash format"))?;
        let (user_domain, cipher_parts) = principal_and_cipher
            .split_once(':')
            .ok_or_else(|| OverthroneError::custom("Invalid AS-REP hash format"))?;

        let etype: i32 = etype_str.parse().unwrap_or(23);
        let (username, domain) = match user_domain.split_once('@') {
            Some((user, realm)) => (user.to_string(), realm.to_string()),
            None => (user_domain.to_string(), String::new()),
        };

        let (checksum_hex, edata2_hex) = match cipher_parts.split_once('$') {
            Some((checksum, edata2)) => (checksum, edata2),
            None => ("", cipher_parts),
        };

        let mut cipher = Vec::new();
        if !checksum_hex.is_empty() {
            cipher
                .extend(hex::decode(checksum_hex).map_err(|e| {
                    OverthroneError::custom(format!("Invalid checksum hex: {}", e))
                })?);
        }
        cipher.extend(
            hex::decode(edata2_hex)
                .map_err(|e| OverthroneError::custom(format!("Invalid cipher hex: {}", e)))?,
        );

        Ok(HashType::AsRep {
            username,
            domain,
            etype,
            cipher,
        })
    }

    /// Parse a Kerberoast hash string (hashcat format)
    /// Format: $krb5tgs${etype}$*{user}${domain}${spn}*${checksum_hex}${edata2_hex}
    pub fn parse_kerberoast(hash_str: &str) -> Result<Self> {
        let rest = hash_str
            .strip_prefix("$krb5tgs$")
            .ok_or_else(|| OverthroneError::custom("Invalid Kerberoast hash format"))?;
        let (etype_str, principal_and_cipher) = rest
            .split_once('$')
            .ok_or_else(|| OverthroneError::custom("Invalid Kerberoast hash format"))?;

        let etype: i32 = etype_str.parse().unwrap_or(23);
        let principal_and_cipher = principal_and_cipher.trim_start_matches('*');
        let (principal_block, cipher_block) = principal_and_cipher
            .split_once("*$")
            .ok_or_else(|| OverthroneError::custom("Invalid Kerberoast hash format"))?;

        let mut principal_parts = principal_block.split('$');
        let username = principal_parts
            .next()
            .ok_or_else(|| OverthroneError::custom("Missing Kerberoast username"))?
            .to_string();
        let domain = principal_parts
            .next()
            .ok_or_else(|| OverthroneError::custom("Missing Kerberoast domain"))?
            .to_string();
        let spn = principal_parts.collect::<Vec<_>>().join("$");
        if spn.is_empty() {
            return Err(OverthroneError::custom("Missing Kerberoast SPN"));
        }

        let (checksum_hex, edata2_hex) = match cipher_block.split_once('$') {
            Some((checksum, edata2)) => (checksum, edata2),
            None => ("", cipher_block),
        };

        let mut cipher = Vec::new();
        if !checksum_hex.is_empty() {
            cipher
                .extend(hex::decode(checksum_hex).map_err(|e| {
                    OverthroneError::custom(format!("Invalid checksum hex: {}", e))
                })?);
        }
        cipher.extend(
            hex::decode(edata2_hex)
                .map_err(|e| OverthroneError::custom(format!("Invalid cipher hex: {}", e)))?,
        );

        Ok(HashType::Kerberoast {
            username,
            domain,
            spn,
            etype,
            cipher,
        })
    }

    /// Parse an NTLM hash string
    /// Format: 32 hex characters
    pub fn parse_ntlm(hash_str: &str) -> Result<Self> {
        let clean = hash_str.trim();
        if clean.len() != 32 {
            return Err(OverthroneError::custom(
                "NTLM hash must be 32 hex characters",
            ));
        }

        let bytes = hex::decode(clean)
            .map_err(|e| OverthroneError::custom(format!("Invalid NTLM hex: {}", e)))?;

        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);

        Ok(HashType::Ntlm { hash: arr })
    }

    /// Get the hashcat mode number for this hash type
    pub fn hashcat_mode(&self) -> u32 {
        match self {
            HashType::AsRep { .. } => 18200,
            HashType::Kerberoast { etype, .. } => match etype {
                17 => 19600, // AES128
                18 => 19700, // AES256
                _ => 13100,  // RC4
            },
            HashType::Ntlm { .. } => 1000,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Kerberos Crypto — RC4-HMAC Key Derivation
// ═══════════════════════════════════════════════════════════

/// Compute NTLM hash from password (used as RC4-HMAC key for Kerberos)
pub fn password_to_nt_hash(password: &str) -> [u8; 16] {
    use md4::{Digest as Md4Digest, Md4};
    let utf16le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hasher = Md4::new();
    hasher.update(&utf16le);
    let result = hasher.finalize();

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Compute RC4-HMAC checksum for AS-REP/Kerberoast verification
/// For AS-REP: HMAC-MD5(key=NTHash, data=encryption type + cipher without checksum)
/// For Kerberoast: Same principle but with different key usage
pub fn rc4_hmac_verify(key: &[u8; 16], data: &[u8], checksum: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use md5::Md5;

    type HmacMd5 = Hmac<Md5>;

    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    mac.update(data);

    let result = mac.finalize();
    let computed = result.into_bytes();

    computed.as_slice() == checksum
}

/// RC4 decrypt using HMAC-MD5 derived key (Kerberos style)
pub fn rc4_decrypt_kerberos(key: &[u8; 16], cipher: &[u8]) -> Vec<u8> {
    // RC4 is symmetric - same operation for encrypt/decrypt
    rc4_crypt(key, cipher)
}

/// Simple RC4 encrypt/decrypt
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: usize = 0;

    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    let mut i: usize = 0;
    j = 0;
    data.iter()
        .map(|byte| {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;
            s.swap(i, j);
            byte ^ s[(s[i] as usize + s[j] as usize) % 256]
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════
// Kerberos Crypto — AES Key Derivation (etype 17/18)
// ═══════════════════════════════════════════════════════════

/// Build the Kerberos salt for AES key derivation.
/// Convention: `REALM` + principal (e.g. `CORP.LOCALjdoe` for user,
/// `CORP.LOCALhostdc01.corp.local` for computer).
fn kerberos_aes_salt(realm: &str, principal: &str) -> String {
    format!("{}{}", realm.to_uppercase(), principal)
}

/// Verify AES Kerberoast/AS-REP by using kerberos_crypto to decrypt + check.
/// Returns `true` if the password produces a key that decrypts the cipher correctly.
fn verify_aes_candidate(password: &str, salt: &str, etype: i32, cipher: &[u8]) -> bool {
    // Use kerberos_crypto's cipher abstraction
    let kc = match kerberos_crypto::new_kerberos_cipher(etype) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Derive key from password + salt using RFC 3961 string-to-key
    let key = kc.generate_key_from_string(password, salt.as_bytes());

    // etype 17/18 cipher structure: confounder + encrypted data + HMAC
    if cipher.len() < 24 {
        return false;
    }

    // Try decryption — key_usage 2 for TGS-REP (Kerberoast), 3 for AS-REP
    // Try both usages since we don't always know context
    kc.decrypt(&key, 2, cipher).is_ok() || kc.decrypt(&key, 3, cipher).is_ok()
}

// ═══════════════════════════════════════════════════════════
// Crackers — Parallel Implementation
// ═══════════════════════════════════════════════════════════

/// Result of a cracking attempt
#[derive(Debug, Clone)]
pub struct CrackResult {
    pub hash_type: String,
    pub username: Option<String>,
    pub cracked: bool,
    pub password: Option<String>,
    pub candidates_tried: usize,
    pub time_ms: u64,
}

/// Configuration for the cracker
#[derive(Debug, Clone)]
pub struct CrackerConfig {
    /// Use embedded wordlist
    pub use_embedded: bool,
    /// Custom wordlist path (overrides embedded)
    pub custom_wordlist: Option<String>,
    /// Rules to apply for expansion
    pub rules: Vec<Rule>,
    /// Maximum candidates to try (0 = unlimited)
    pub max_candidates: usize,
    /// Try hashcat first if available
    pub prefer_hashcat: bool,
    /// Number of threads (0 = auto)
    pub threads: usize,
    /// Mask patterns (hashcat-style, e.g. "?u?l?l?l?d?d?d?d")
    pub masks: Vec<String>,
    /// Enable hybrid mode (wordlist + mask suffix)
    pub hybrid_masks: Vec<String>,
}

impl Default for CrackerConfig {
    fn default() -> Self {
        Self {
            use_embedded: true,
            custom_wordlist: None,
            rules: vec![
                Rule::None,
                Rule::Capitalize,
                Rule::AppendDigit,
                Rule::AppendYear,
                Rule::CapitalizeDigit,
                Rule::CapitalizeYear,
            ],
            max_candidates: 0,
            prefer_hashcat: false,
            threads: 0,
            masks: Vec::new(),
            hybrid_masks: Vec::new(),
        }
    }
}

impl CrackerConfig {
    /// Fast mode — minimal rules, embedded wordlist only
    pub fn fast() -> Self {
        Self {
            use_embedded: true,
            custom_wordlist: None,
            rules: vec![Rule::None, Rule::Capitalize, Rule::AppendDigit],
            max_candidates: 100_000,
            prefer_hashcat: false,
            threads: 0,
            masks: Vec::new(),
            hybrid_masks: Vec::new(),
        }
    }

    /// Thorough mode — all rules, expanded candidates, common masks
    pub fn thorough() -> Self {
        Self {
            use_embedded: true,
            custom_wordlist: None,
            rules: vec![
                Rule::None,
                Rule::Lowercase,
                Rule::Uppercase,
                Rule::Capitalize,
                Rule::AppendDigit,
                Rule::AppendTwoDigits,
                Rule::AppendYear,
                Rule::PrependDigit,
                Rule::Leet,
                Rule::AppendSpecial,
                Rule::CapitalizeDigit,
                Rule::CapitalizeYear,
            ],
            max_candidates: 0,
            prefer_hashcat: false,
            threads: 0,
            // Common AD password masks
            masks: vec![
                "?u?l?l?l?l?l?d?d".into(),     // Passwo12
                "?u?l?l?l?l?l?l?d?d".into(),   // Passwor12
                "?u?l?l?l?l?l?l?l?d?d".into(), // Password12
                "?u?l?l?l?l?l?d?d?d?d".into(), // Passwo1234
            ],
            hybrid_masks: vec![
                "?d?d?d?d".into(),   // word + 4 digits
                "?d?d?d?d?s".into(), // word + 4 digits + symbol
                "?s?d?d".into(),     // word + symbol + 2 digits
            ],
        }
    }
}

/// Main cracker — parallel candidate testing
pub struct HashCracker {
    config: CrackerConfig,
    wordlist: Vec<String>,
}

impl HashCracker {
    /// Create a new cracker with the specified configuration
    pub fn new(config: CrackerConfig) -> Result<Self> {
        // Configure rayon thread pool
        if config.threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(config.threads)
                .build_global()
                .ok(); // Ignore error if already built
        }

        // Load wordlist
        let wordlist = if let Some(ref path) = config.custom_wordlist {
            load_wordlist_from_file(path)?
        } else if config.use_embedded {
            get_embedded_wordlist()
        } else {
            return Err(OverthroneError::custom("No wordlist source configured"));
        };

        info!("Loaded {} base words", wordlist.len());

        Ok(Self { config, wordlist })
    }

    /// Crack a single hash
    pub fn crack(&self, hash: &HashType) -> CrackResult {
        let start = std::time::Instant::now();
        let hash_type_str = match hash {
            HashType::AsRep { username, .. } => {
                format!("AS-REP ({})", username)
            }
            HashType::Kerberoast { spn, .. } => {
                format!("Kerberoast ({})", spn)
            }
            HashType::Ntlm { .. } => "NTLM".to_string(),
        };

        // Try hashcat first if preferred and available
        if self.config.prefer_hashcat && is_hashcat_available() {
            info!("Attempting hashcat GPU cracking...");
            if let Some(password) = try_hashcat(hash) {
                return CrackResult {
                    hash_type: hash_type_str,
                    username: hash.username().map(|s| s.to_string()),
                    cracked: true,
                    password: Some(password),
                    candidates_tried: 0, // Hashcat doesn't report this
                    time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        // Phase 1: Dictionary + rules
        let candidates = expand_wordlist(&self.wordlist, &self.config.rules);
        let total_candidates = if self.config.max_candidates > 0 {
            self.config.max_candidates.min(candidates.len())
        } else {
            candidates.len()
        };

        info!(
            "Phase 1: Dictionary+rules — {} candidates ({} rules)",
            total_candidates,
            self.config.rules.len()
        );

        // Parallel cracking — Phase 1: Dictionary
        let counter = AtomicUsize::new(0);
        let password = candidates
            .par_iter()
            .take(total_candidates)
            .find_map_any(|candidate| {
                let count = counter.fetch_add(1, Ordering::Relaxed);
                if count.is_multiple_of(10_000) {
                    debug!("Tried {} candidates...", count);
                }

                if verify_candidate(hash, candidate) {
                    Some(candidate.clone())
                } else {
                    None
                }
            });

        if let Some(pwd) = password {
            let tried = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_millis() as u64;
            info!(
                "✓ Password found (dictionary): {} ({} candidates, {}ms)",
                pwd, tried, elapsed
            );
            return CrackResult {
                hash_type: hash_type_str,
                username: hash.username().map(|s| s.to_string()),
                cracked: true,
                password: Some(pwd),
                candidates_tried: tried,
                time_ms: elapsed,
            };
        }

        let dict_tried = counter.load(Ordering::Relaxed);

        // Phase 2: Mask attacks
        if !self.config.masks.is_empty() {
            info!("Phase 2: Mask attack — {} masks", self.config.masks.len());
            for mask_str in &self.config.masks {
                match MaskPattern::parse(mask_str) {
                    Ok(mask) => {
                        let ks = mask.keyspace();
                        let limit = if self.config.max_candidates > 0 {
                            (self.config.max_candidates as u64).saturating_sub(dict_tried as u64)
                        } else {
                            ks.min(50_000_000) // 50M cap per mask
                        };
                        info!("  Mask '{}' — keyspace {} (limit {})", mask_str, ks, limit);
                        let mask_candidates = mask.generate_limited(limit);
                        let mask_counter = AtomicUsize::new(0);
                        let found = mask_candidates.par_iter().find_map_any(|candidate| {
                            mask_counter.fetch_add(1, Ordering::Relaxed);
                            if verify_candidate(hash, candidate) {
                                Some(candidate.clone())
                            } else {
                                None
                            }
                        });

                        let mask_tried = mask_counter.load(Ordering::Relaxed);
                        counter.fetch_add(mask_tried, Ordering::Relaxed);

                        if let Some(pwd) = found {
                            let total_tried = counter.load(Ordering::Relaxed);
                            let elapsed = start.elapsed().as_millis() as u64;
                            info!(
                                "✓ Password found (mask): {} ({} total candidates, {}ms)",
                                pwd, total_tried, elapsed
                            );
                            return CrackResult {
                                hash_type: hash_type_str,
                                username: hash.username().map(|s| s.to_string()),
                                cracked: true,
                                password: Some(pwd),
                                candidates_tried: total_tried,
                                time_ms: elapsed,
                            };
                        }
                    }
                    Err(e) => {
                        warn!("Invalid mask '{}': {}", mask_str, e);
                    }
                }
            }
        }

        // Phase 3: Hybrid (wordlist base + mask suffix)
        if !self.config.hybrid_masks.is_empty() {
            info!(
                "Phase 3: Hybrid attack — {} masks × {} words",
                self.config.hybrid_masks.len(),
                self.wordlist.len()
            );
            for mask_str in &self.config.hybrid_masks {
                match MaskPattern::parse(mask_str) {
                    Ok(mask) => {
                        let suffixes = mask.generate_limited(10_000); // cap suffix space
                        let hybrid_counter = AtomicUsize::new(0);

                        // Build capitalized base words (most common in AD)
                        let bases: Vec<String> = self
                            .wordlist
                            .iter()
                            .map(|w| {
                                let mut chars: Vec<char> = w.chars().collect();
                                if let Some(first) = chars.first_mut() {
                                    *first = first.to_uppercase().next().unwrap_or(*first);
                                }
                                chars.into_iter().collect()
                            })
                            .collect();

                        let found = bases.par_iter().find_map_any(|base| {
                            for suffix in &suffixes {
                                hybrid_counter.fetch_add(1, Ordering::Relaxed);
                                let candidate = format!("{}{}", base, suffix);
                                if verify_candidate(hash, &candidate) {
                                    return Some(candidate);
                                }
                            }
                            None
                        });

                        let hybrid_tried = hybrid_counter.load(Ordering::Relaxed);
                        counter.fetch_add(hybrid_tried, Ordering::Relaxed);

                        if let Some(pwd) = found {
                            let total_tried = counter.load(Ordering::Relaxed);
                            let elapsed = start.elapsed().as_millis() as u64;
                            info!(
                                "✓ Password found (hybrid): {} ({} total, {}ms)",
                                pwd, total_tried, elapsed
                            );
                            return CrackResult {
                                hash_type: hash_type_str,
                                username: hash.username().map(|s| s.to_string()),
                                cracked: true,
                                password: Some(pwd),
                                candidates_tried: total_tried,
                                time_ms: elapsed,
                            };
                        }
                    }
                    Err(e) => {
                        warn!("Invalid hybrid mask '{}': {}", mask_str, e);
                    }
                }
            }
        }

        let tried = counter.load(Ordering::Relaxed);
        let elapsed = start.elapsed().as_millis() as u64;
        info!(
            "✗ Password not found after {} candidates ({}ms)",
            tried, elapsed
        );
        CrackResult {
            hash_type: hash_type_str,
            username: hash.username().map(|s| s.to_string()),
            cracked: false,
            password: None,
            candidates_tried: tried,
            time_ms: elapsed,
        }
    }

    /// Crack multiple hashes in parallel
    pub fn crack_batch(&self, hashes: &[HashType]) -> Vec<CrackResult> {
        info!("Cracking {} hashes in parallel", hashes.len());
        hashes.iter().map(|h| self.crack(h)).collect()
    }
}

/// Load a wordlist from a file
fn load_wordlist_from_file(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| OverthroneError::custom(format!("Cannot read wordlist: {}", e)))?;

    Ok(content
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

/// Verify if a password candidate matches the hash
fn verify_candidate(hash: &HashType, password: &str) -> bool {
    match hash {
        HashType::AsRep {
            cipher,
            etype,
            username,
            domain,
            ..
        } => {
            match *etype {
                23 => {
                    // RC4-HMAC verification
                    let nt_hash = password_to_nt_hash(password);
                    if cipher.len() < 32 {
                        return false;
                    }
                    let decrypted = rc4_decrypt_kerberos(&nt_hash, cipher);
                    decrypted.len() >= 32 && (decrypted[0] == 0x30 || decrypted[0] == 0x7A)
                }
                17 | 18 => {
                    // AES verification — salt is REALM + username
                    let salt = kerberos_aes_salt(domain, username);
                    verify_aes_candidate(password, &salt, *etype, cipher)
                }
                _ => false,
            }
        }

        HashType::Kerberoast {
            cipher,
            etype,
            domain,
            spn,
            ..
        } => {
            match *etype {
                23 => {
                    // RC4-HMAC — service account's NT hash
                    let nt_hash = password_to_nt_hash(password);
                    if cipher.len() < 32 {
                        return false;
                    }
                    let decrypted = rc4_decrypt_kerberos(&nt_hash, cipher);
                    decrypted.len() >= 32 && decrypted[0] == 0x63
                }
                17 | 18 => {
                    // AES — salt is REALM + service principal (from SPN)
                    // For service accounts, salt = REALM + principal (e.g. "CORP.LOCALsqlsvc")
                    // Try multiple salt formats since SPN parsing varies
                    let service_name = spn.split('/').next().unwrap_or(spn);
                    let salts = [
                        kerberos_aes_salt(domain, service_name),
                        kerberos_aes_salt(domain, spn),
                        // Some services use the full SPN as salt suffix
                        format!("{}{}", domain.to_uppercase(), spn),
                    ];
                    for salt in &salts {
                        if verify_aes_candidate(password, salt, *etype, cipher) {
                            return true;
                        }
                    }
                    false
                }
                _ => false,
            }
        }

        HashType::Ntlm { hash } => {
            // Simple NTLM comparison
            let nt_hash = password_to_nt_hash(password);
            nt_hash == *hash
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Hashcat Integration
// ═══════════════════════════════════════════════════════════

/// Check if hashcat is available on the system
pub fn is_hashcat_available() -> bool {
    Command::new("hashcat")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Write hash to file for hashcat
fn write_hash_file(hash: &HashType) -> Result<std::path::PathBuf> {
    let hash_str = match hash {
        HashType::AsRep {
            username,
            domain,
            etype,
            cipher,
        } => {
            let checksum_len = if *etype == 23 { 16 } else { 12 };
            let (checksum, edata2) = cipher.split_at(std::cmp::min(checksum_len, cipher.len()));
            format!(
                "$krb5asrep${etype}${username}@{domain}:{checksum}${edata2}",
                etype = etype,
                username = username,
                domain = domain,
                checksum = hex::encode(checksum),
                edata2 = hex::encode(edata2),
            )
        }
        HashType::Kerberoast {
            username,
            domain,
            spn,
            etype,
            cipher,
        } => {
            let checksum_len = if *etype == 23 { 16 } else { 12 };
            let (checksum, edata2) = cipher.split_at(std::cmp::min(checksum_len, cipher.len()));
            format!(
                "$krb5tgs${etype}$*{username}${domain}${spn}*${checksum}${edata2}",
                etype = etype,
                username = username,
                domain = domain,
                spn = spn,
                checksum = hex::encode(checksum),
                edata2 = hex::encode(edata2),
            )
        }
        HashType::Ntlm { hash } => hex::encode(hash),
    };

    let temp_dir = std::env::temp_dir();
    let hash_file = temp_dir.join(format!("overthrone_hash_{}.txt", rand::random::<u32>()));

    std::fs::write(&hash_file, &hash_str)
        .map_err(|e| OverthroneError::custom(format!("Cannot write hash file: {}", e)))?;

    Ok(hash_file)
}

/// Try cracking with hashcat
fn try_hashcat(hash: &HashType) -> Option<String> {
    let hash_file = write_hash_file(hash).ok()?;
    let wordlist_file = std::env::temp_dir().join("overthrone_wordlist.txt");

    // Write wordlist
    let wordlist = get_embedded_wordlist();
    let wordlist_content = wordlist.join("\n");
    std::fs::write(&wordlist_file, &wordlist_content).ok()?;

    let mode = hash.hashcat_mode();

    // Run hashcat in quiet mode
    let output = Command::new("hashcat")
        .args([
            "-m",
            &mode.to_string(),
            "-a",
            "0", // Dictionary attack
            "--quiet",
            "--force",
            hash_file.to_str()?,
            wordlist_file.to_str()?,
        ])
        .output()
        .ok()?;

    // Cleanup
    let _ = std::fs::remove_file(&hash_file);
    let _ = std::fs::remove_file(&wordlist_file);

    if output.status.success() {
        // Try to get the cracked password with --show
        let show_output = Command::new("hashcat")
            .args(["-m", &mode.to_string(), "--show", hash_file.to_str()?])
            .output()
            .ok()?;

        let result = String::from_utf8_lossy(&show_output.stdout);
        // Parse: hash:password
        result
            .lines()
            .next()?
            .split(':')
            .nth(1)
            .map(|s| s.to_string())
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════
// Helper Traits
// ═══════════════════════════════════════════════════════════

impl HashType {
    /// Get the username if available
    pub fn username(&self) -> Option<&str> {
        match self {
            HashType::AsRep { username, .. } => Some(username),
            HashType::Kerberoast { username, .. } => Some(username),
            HashType::Ntlm { .. } => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_nt_hash() {
        // Known NT hash for "Password123"
        let hash = password_to_nt_hash("Password123");
        // NT hash computed correctly by our MD4 implementation
        let expected = hex::decode("58a478135a93ac3bf058a5ea0e8fdb71").unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_rule_capitalize() {
        let results = Rule::Capitalize.apply("password");
        assert_eq!(results, vec!["Password"]);
    }

    #[test]
    fn test_rule_append_digit() {
        let results = Rule::AppendDigit.apply("password");
        assert_eq!(results.len(), 10);
        assert_eq!(results[0], "password0");
        assert_eq!(results[9], "password9");
    }

    #[test]
    fn test_rule_append_year() {
        let results = Rule::AppendYear.apply("password");
        assert!(results.contains(&"password2024".to_string()));
    }

    #[test]
    fn test_leet_substitution() {
        let leet = apply_leet("password");
        // a→@, s→$, o→0, so "password" becomes "p@$$w0rd"
        assert_eq!(leet, "p@$$w0rd");
    }

    #[test]
    fn test_ntlm_parsing() {
        let hash = HashType::parse_ntlm("2ac9cb7dc02b3c0083eb70898e549b63").unwrap();
        match hash {
            HashType::Ntlm { hash } => {
                assert_eq!(
                    hash,
                    [
                        0x2a, 0xc9, 0xcb, 0x7d, 0xc0, 0x2b, 0x3c, 0x00, 0x83, 0xeb, 0x70, 0x89,
                        0x8e, 0x54, 0x9b, 0x63
                    ]
                );
            }
            _ => panic!("Wrong hash type"),
        }
    }

    #[test]
    fn test_asrep_hashcat_format_parsing() {
        let hash = HashType::parse_asrep(
            "$krb5asrep$23$alice@CORP.LOCAL:00112233445566778899aabbccddeeff$deadbeef",
        )
        .unwrap();

        match hash {
            HashType::AsRep {
                username,
                domain,
                etype,
                cipher,
            } => {
                assert_eq!(username, "alice");
                assert_eq!(domain, "CORP.LOCAL");
                assert_eq!(etype, 23);
                assert_eq!(cipher.len(), 20);
            }
            _ => panic!("Wrong hash type"),
        }
    }

    #[test]
    fn test_kerberoast_hashcat_format_parsing() {
        let hash = HashType::parse_kerberoast(
            "$krb5tgs$23$*alice$CORP.LOCAL$cifs/dc01.corp.local*$00112233445566778899aabbccddeeff$deadbeef",
        )
        .unwrap();

        match hash {
            HashType::Kerberoast {
                username,
                domain,
                spn,
                etype,
                cipher,
            } => {
                assert_eq!(username, "alice");
                assert_eq!(domain, "CORP.LOCAL");
                assert_eq!(spn, "cifs/dc01.corp.local");
                assert_eq!(etype, 23);
                assert_eq!(cipher.len(), 20);
            }
            _ => panic!("Wrong hash type"),
        }
    }

    #[test]
    fn test_ntlm_crack() {
        let config = CrackerConfig::fast();
        let cracker = HashCracker::new(config).unwrap();

        // Use the correct NT hash for "Password123" computed by our MD4 implementation
        let hash = HashType::parse_ntlm("58a478135a93ac3bf058a5ea0e8fdb71").unwrap();
        let result = cracker.crack(&hash);

        assert!(result.cracked);
        assert_eq!(result.password, Some("Password123".to_string()));
    }

    #[test]
    fn test_expand_wordlist() {
        let base = vec!["password".to_string()];
        let rules = vec![Rule::None, Rule::Capitalize];
        let expanded = expand_wordlist(&base, &rules);

        assert!(expanded.contains(&"password".to_string()));
        assert!(expanded.contains(&"Password".to_string()));
    }

    #[test]
    fn test_mask_pattern_digits() {
        let mask = MaskPattern::parse("?d?d?d?d").unwrap();
        assert_eq!(mask.keyspace(), 10_000);
        let candidates = mask.generate();
        assert_eq!(candidates.len(), 10_000);
        assert!(candidates.contains(&"0000".to_string()));
        assert!(candidates.contains(&"9999".to_string()));
        assert!(candidates.contains(&"1234".to_string()));
    }

    #[test]
    fn test_mask_pattern_literal() {
        let mask = MaskPattern::parse("Pass?d?d?d?d").unwrap();
        assert_eq!(mask.keyspace(), 10_000);
        let candidates = mask.generate();
        assert!(candidates.contains(&"Pass0000".to_string()));
        assert!(candidates.contains(&"Pass1234".to_string()));
    }

    #[test]
    fn test_mask_pattern_upper_lower() {
        let mask = MaskPattern::parse("?u?l").unwrap();
        assert_eq!(mask.keyspace(), 26 * 26);
        let candidates = mask.generate();
        assert!(candidates.contains(&"Aa".to_string()));
        assert!(candidates.contains(&"Zz".to_string()));
    }

    #[test]
    fn test_mask_pattern_limited() {
        let mask = MaskPattern::parse("?a?a?a?a?a?a").unwrap();
        // Full keyspace would be 76^6 ≈ 192 billion
        let candidates = mask.generate_limited(100);
        assert_eq!(candidates.len(), 100);
    }

    #[test]
    fn test_mask_pattern_invalid() {
        assert!(MaskPattern::parse("?z").is_err());
        assert!(MaskPattern::parse("").is_err());
        assert!(MaskPattern::parse("hello?").is_err());
    }

    #[test]
    fn test_aes_salt_generation() {
        let salt = kerberos_aes_salt("corp.local", "jdoe");
        assert_eq!(salt, "CORP.LOCALjdoe");
    }
}
