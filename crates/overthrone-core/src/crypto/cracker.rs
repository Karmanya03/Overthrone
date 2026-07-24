//! Inline Hash Cracking -- RC4-HMAC, AES (Kerberos) and NTLM hash cracking.
//!
//! Provides offline cracking capabilities for:
//! - AS-REP Roasting hashes (hashcat mode 18200)
//! - Kerberoast hashes (hashcat mode 13100/19600/19700)
//! - NTLM hashes (hashcat mode 1000)
//!
//! Features:
//! - Streaming wordlist reading (no OOM on 14M-line wordlists)
//! - Lazy rule engine (password variations applied on-the-fly, no pre-allocation)
//! - Streaming mask attack engine (?l = lower, ?u = upper, ?d = digit, ?s = symbol, ?a = all)
//! - Hybrid attack (wordlist + mask suffix, streaming)
//! - Batch parallel verification with real-time progress/speed
//! - AES128/AES256 Kerberos key derivation via PBKDF2-HMAC-SHA1 (etype 17/18)
//! - Hashcat subprocess fallback for GPU acceleration
//! - Embedded top-10K wordlist (compressed with zstd)

use crate::crypto::rc4_util::rc4_hmac_decrypt;
use crate::error::{OverthroneError, Result};
use rayon::prelude::*;
use std::io::BufRead;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{info, warn};

// ===========================================================
// Embedded Wordlist (Top 10K + common passwords)
// ===========================================================

/// Shared compressed top-10K password wordlist bundled with the crate.
const EMBEDDED_WORDLIST_ZST: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/wordlist_top10k.txt.zst"
));

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

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
    decode_wordlist_bytes("embedded wordlist", EMBEDDED_WORDLIST_ZST).unwrap_or_else(|e| {
        warn!("Falling back to minimal built-in wordlist: {}", e);
        // Fallback to minimal built-in list
        FALLBACK_WORDLIST.iter().map(|s| s.to_string()).collect()
    })
}

fn decode_wordlist_bytes(source: &str, bytes: &[u8]) -> Result<Vec<String>> {
    let payload = if is_zstd_compressed(bytes) {
        zstd::decode_all(bytes).map_err(|e| {
            OverthroneError::custom(format!(
                "Wordlist decompression failed for {}: {}",
                source, e
            ))
        })?
    } else {
        bytes.to_vec()
    };

    let text = String::from_utf8_lossy(&payload);
    Ok(text
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

fn is_zstd_compressed(bytes: &[u8]) -> bool {
    bytes.len() >= ZSTD_MAGIC.len() && bytes[..ZSTD_MAGIC.len()] == ZSTD_MAGIC
}

// ===========================================================
// Rule Engine -- Password Variations
// ===========================================================

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
    /// Common l33t substitutions (a->@, e->3, i->1, o->0, s->$)
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
    /// Apply the rule to a base password (convenience, kept for backward compat)
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
                let cap = capitalize_first(password);
                (0..=9).map(|d| format!("{}{}", cap, d)).collect()
            }
            Rule::CapitalizeYear => {
                let cap = capitalize_first(password);
                (2015..=2026).map(|y| format!("{}{}", cap, y)).collect()
            }
            Rule::FullVariation => {
                let cap = capitalize_first(password);
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

/// Capitalize the first character of a string
fn capitalize_first(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = first.to_uppercase().next().unwrap_or(*first);
    }
    chars.into_iter().collect()
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

/// Generate expanded wordlist with rule-based variations.
/// Kept for backward compatibility -- not used internally by streaming cracker.
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

// ===========================================================
// Streaming Wordlist Sources
// ===========================================================

/// Read lines from a file, one at a time
struct FileWordlistReader {
    reader: std::io::BufReader<std::fs::File>,
    buf: String,
}

impl FileWordlistReader {
    fn open(path: &str) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            OverthroneError::custom(format!("Cannot open wordlist '{}': {}", path, e))
        })?;
        Ok(Self {
            reader: std::io::BufReader::new(file),
            buf: String::with_capacity(128),
        })
    }
}

impl Iterator for FileWordlistReader {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.buf.clear();
            match self.reader.read_line(&mut self.buf) {
                Ok(0) => return None,
                Ok(_) => {
                    let trimmed = self.buf.trim().to_string();
                    if !trimmed.is_empty() {
                        return Some(trimmed);
                    }
                    // Skip empty lines
                }
                Err(_) => return None,
            }
        }
    }
}

/// Generate rule-expanded candidates lazily from a wordlist iterator
struct RuleCandidateIter<I> {
    inner: I,
    rules: Vec<Rule>,
    // State for current word
    current_word: Option<String>,
    rule_idx: usize,
    sub_idx: usize,
    exhausted: bool,
}

impl<I: Iterator<Item = String>> RuleCandidateIter<I> {
    fn new(inner: I, rules: Vec<Rule>) -> Self {
        Self {
            inner,
            rules,
            current_word: None,
            rule_idx: 0,
            sub_idx: 0,
            exhausted: false,
        }
    }
}

impl<I: Iterator<Item = String>> Iterator for RuleCandidateIter<I> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }

        // When no rules, pass words through as-is
        if self.rules.is_empty() {
            if self.exhausted {
                return None;
            }
            let word = self.inner.next();
            if word.is_none() {
                self.exhausted = true;
            }
            return word;
        }

        loop {
            // Get a word if needed
            if self.current_word.is_none() {
                self.current_word = self.inner.next();
                self.rule_idx = 0;
                self.sub_idx = 0;
                if self.current_word.is_none() {
                    self.exhausted = true;
                    return None;
                }
            }

            let word = self.current_word.as_ref().unwrap();

            if self.rule_idx >= self.rules.len() {
                // Move to next word
                self.current_word = None;
                continue;
            }

            let rule = &self.rules[self.rule_idx];

            // Generate the next candidate for this rule
            match rule {
                Rule::None => {
                    self.rule_idx += 1;
                    return Some(word.clone());
                }
                Rule::Lowercase => {
                    self.rule_idx += 1;
                    return Some(word.to_lowercase());
                }
                Rule::Uppercase => {
                    self.rule_idx += 1;
                    return Some(word.to_uppercase());
                }
                Rule::Capitalize => {
                    self.rule_idx += 1;
                    return Some(capitalize_first(word));
                }
                Rule::Leet => {
                    self.rule_idx += 1;
                    return Some(apply_leet(word));
                }
                Rule::AppendDigit => {
                    if self.sub_idx <= 9 {
                        let result = format!("{}{}", word, self.sub_idx);
                        self.sub_idx += 1;
                        return Some(result);
                    }
                    self.sub_idx = 0;
                    self.rule_idx += 1;
                    continue;
                }
                Rule::AppendTwoDigits => {
                    if self.sub_idx <= 99 {
                        let result = format!("{}{:02}", word, self.sub_idx);
                        self.sub_idx += 1;
                        return Some(result);
                    }
                    self.sub_idx = 0;
                    self.rule_idx += 1;
                    continue;
                }
                Rule::AppendYear => {
                    let year = 2015 + self.sub_idx;
                    if year <= 2026 {
                        let result = format!("{}{}", word, year);
                        self.sub_idx += 1;
                        return Some(result);
                    }
                    self.sub_idx = 0;
                    self.rule_idx += 1;
                    continue;
                }
                Rule::PrependDigit => {
                    if self.sub_idx <= 9 {
                        let result = format!("{}{}", self.sub_idx, word);
                        self.sub_idx += 1;
                        return Some(result);
                    }
                    self.sub_idx = 0;
                    self.rule_idx += 1;
                    continue;
                }
                Rule::AppendSpecial => {
                    let specials = ['!', '@', '#', '$', '%', '^', '&', '*'];
                    if self.sub_idx < specials.len() {
                        let result = format!("{}{}", word, specials[self.sub_idx]);
                        self.sub_idx += 1;
                        return Some(result);
                    }
                    self.sub_idx = 0;
                    self.rule_idx += 1;
                    continue;
                }
                Rule::CapitalizeDigit => {
                    if self.sub_idx <= 9 {
                        let cap = capitalize_first(word);
                        let result = format!("{}{}", cap, self.sub_idx);
                        self.sub_idx += 1;
                        return Some(result);
                    }
                    self.sub_idx = 0;
                    self.rule_idx += 1;
                    continue;
                }
                Rule::CapitalizeYear => {
                    let year = 2015 + self.sub_idx;
                    if year <= 2026 {
                        let cap = capitalize_first(word);
                        let result = format!("{}{}", cap, year);
                        self.sub_idx += 1;
                        return Some(result);
                    }
                    self.sub_idx = 0;
                    self.rule_idx += 1;
                    continue;
                }
                Rule::FullVariation => {
                    let total_variants = 2 * (10 + 12);
                    if self.sub_idx >= total_variants {
                        self.sub_idx = 0;
                        self.rule_idx += 1;
                        continue;
                    }
                    let cap = capitalize_first(word);
                    let leet = apply_leet(&cap);
                    let variant = self.sub_idx;
                    self.sub_idx += 1;
                    let is_leet = variant >= (10 + 12);
                    let base = if is_leet { &leet } else { &cap };
                    let local = variant % (10 + 12);
                    if local < 10 {
                        return Some(format!("{}{}", base, local));
                    } else {
                        let year = 2015 + (local - 10);
                        return Some(format!("{}{}", base, year));
                    }
                }
            }
        }
    }
}

// ===========================================================
// Mask Attack Engine
// ===========================================================

/// Mask-based candidate generator (hashcat-style masks).
/// Charset tokens:
/// - `?l` = lowercase a-z
/// - `?u` = uppercase A-Z
/// - `?d` = digit 0-9
/// - `?s` = symbols `!@#$%^&*()-_=+`
/// - `?a` = all printable (`?l + ?u + ?d + ?s`)
///   Literal characters are used as-is.
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

    /// Generate all candidates from this mask (legacy, kept for compat).
    /// WARNING: can be extremely large -- can OOM on large masks.
    /// Prefer `into_iter()` or `iter_limited()` for streaming.
    pub fn generate(&self) -> Vec<String> {
        self.iter_limited(u64::MAX).collect()
    }

    /// Generate candidates up to `limit` count (legacy, kept for compat).
    /// Prefer `iter_limited()` for memory safety.
    pub fn generate_limited(&self, limit: u64) -> Vec<String> {
        self.iter_limited(limit).collect()
    }

    /// Create a streaming iterator with an optional limit
    pub fn iter_limited(&self, limit: u64) -> MaskIter<'_> {
        MaskIter::new(self, limit)
    }
}

/// Streaming mask candidate iterator -- yields one candidate at a time,
/// no pre-allocation of all candidates.
#[derive(Debug, Clone)]
pub struct MaskIter<'a> {
    positions: &'a [MaskPosition],
    indices: Vec<usize>,
    count: u64,
    limit: u64,
    done: bool,
}

impl<'a> MaskIter<'a> {
    fn new(mask: &'a MaskPattern, limit: u64) -> Self {
        Self {
            positions: &mask.positions,
            indices: vec![0usize; mask.positions.len()],
            count: 0,
            limit,
            done: false,
        }
    }
}

impl<'a> Iterator for MaskIter<'a> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.count >= self.limit {
            return None;
        }

        let mut s = String::with_capacity(self.positions.len());
        for (i, pos) in self.positions.iter().enumerate() {
            match pos {
                MaskPosition::Literal(c) => s.push(*c),
                MaskPosition::Charset(cs) => s.push(cs[self.indices[i]]),
            }
        }

        self.count += 1;

        // Increment odometer (rightmost first)
        let mut carry = true;
        for i in (0..self.positions.len()).rev() {
            if !carry {
                break;
            }
            match &self.positions[i] {
                MaskPosition::Literal(_) => { /* skip literals */ }
                MaskPosition::Charset(cs) => {
                    self.indices[i] += 1;
                    if self.indices[i] >= cs.len() {
                        self.indices[i] = 0;
                    } else {
                        carry = false;
                    }
                }
            }
        }
        if carry {
            self.done = true;
        }

        Some(s)
    }
}

/// Hybrid attack iterator: combines wordlist words with mask suffixes,
/// streaming (no pre-allocation).
struct HybridCandidates<I: Iterator<Item = String>> {
    word_iter: I,
    suffixes: Vec<String>,
    current_word: Option<String>,
    suffix_idx: usize,
    exhausted: bool,
}

impl<I: Iterator<Item = String>> HybridCandidates<I> {
    fn new(word_iter: I, suffixes: Vec<String>) -> Self {
        Self {
            word_iter,
            suffixes,
            current_word: None,
            suffix_idx: 0,
            exhausted: false,
        }
    }
}

impl<I: Iterator<Item = String>> Iterator for HybridCandidates<I> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }

        loop {
            if self.current_word.is_none() {
                self.current_word = self.word_iter.next();
                self.suffix_idx = 0;
                if self.current_word.is_none() {
                    self.exhausted = true;
                    return None;
                }
                // Capitalize the word (most common AD pattern)
                self.current_word = Some(capitalize_first(self.current_word.as_ref().unwrap()));
            }

            let word = self.current_word.as_ref().unwrap();

            if self.suffix_idx < self.suffixes.len() {
                let result = format!("{}{}", word, self.suffixes[self.suffix_idx]);
                self.suffix_idx += 1;
                return Some(result);
            }

            // Move to next word
            self.current_word = None;
        }
    }
}

// ===========================================================
// Hash Types
// ===========================================================

/// Supported hash types for cracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    /// AS-REP Roasting (hashcat mode 18200)
    AsRep {
        /// Username for authentication
        username: String,
        /// Domain FQDN
        domain: String,
        /// Encryption type
        etype: i32,
        /// Cipher field
        cipher: Vec<u8>,
    },
    /// Kerberoast TGS (hashcat mode 13100/19600/19700)
    Kerberoast {
        /// Username for authentication
        username: String,
        /// Domain FQDN
        domain: String,
        /// Service Principal Name
        spn: String,
        /// Encryption type
        etype: i32,
        /// Cipher field
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
            .trim()
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
            .trim()
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

    /// Get the username if available
    pub fn username(&self) -> Option<&str> {
        match self {
            HashType::AsRep { username, .. } => Some(username),
            HashType::Kerberoast { username, .. } => Some(username),
            HashType::Ntlm { .. } => None,
        }
    }
}

// ===========================================================
// Kerberos Crypto -- RC4-HMAC Key Derivation
// ===========================================================

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

// ===========================================================
// Kerberos Crypto -- AES Key Derivation (etype 17/18)
// ===========================================================

/// Build the Kerberos salt for AES key derivation.
fn kerberos_aes_salt(realm: &str, principal: &str) -> String {
    format!("{}{}", realm.to_uppercase(), principal)
}

/// Verify AES Kerberoast/AS-REP by using kerberos_crypto to decrypt + check.
/// Returns `true` if the password produces a key that decrypts the cipher correctly.
fn verify_aes_candidate(password: &str, salt: &str, etype: i32, cipher: &[u8]) -> bool {
    let kc = match kerberos_crypto::new_kerberos_cipher(etype) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let key = kc.generate_key_from_string(password, salt.as_bytes());

    if cipher.len() < 24 {
        return false;
    }

    // Try both key usages since we don't always know context
    kc.decrypt(&key, 2, cipher).is_ok() || kc.decrypt(&key, 3, cipher).is_ok()
}

// ===========================================================
// Batch Parallel Verifier
// ===========================================================

const BATCH_SIZE: usize = 10_000;

/// Verify a batch of candidates in parallel.
/// Returns the password if found, None otherwise.
fn verify_batch(
    candidates: &[String],
    hash: &HashType,
    found: &AtomicBool,
    counter: &AtomicUsize,
) -> Option<String> {
    candidates.par_iter().find_map_any(|candidate| {
        if found.load(Ordering::Relaxed) {
            return None;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        if verify_candidate(hash, candidate) {
            found.store(true, Ordering::Relaxed);
            Some(candidate.clone())
        } else {
            None
        }
    })
}

/// Run a streaming candidate generator with batch parallel verification.
/// Reports progress every 2 seconds with speed/H/s.
fn crack_streaming<Gen: Iterator<Item = String>>(
    generator: &mut Gen,
    hash: &HashType,
    counter: &AtomicUsize,
    found: &AtomicBool,
    start: Instant,
    phase_name: &str,
) -> Option<String> {
    let mut last_report = Instant::now();

    loop {
        if found.load(Ordering::Relaxed) {
            return None;
        }

        let batch: Vec<String> = generator.take(BATCH_SIZE).collect();
        if batch.is_empty() {
            return None;
        }

        if let Some(pwd) = verify_batch(&batch, hash, found, counter) {
            return Some(pwd);
        }

        // Progress report every ~2 seconds
        let now = Instant::now();
        if now.duration_since(last_report).as_secs_f64() > 2.0 {
            let count = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                count as f64 / elapsed
            } else {
                0.0
            };
            info!(
                "[{}] Speed: {:.0} H/s, {} candidates, {:.1}s",
                phase_name, speed, count, elapsed
            );
            last_report = now;
        }
    }
}

// ===========================================================
// Crackers -- Parallel Implementation
// ===========================================================

/// Result of a cracking attempt
#[derive(Debug, Clone)]
pub struct CrackResult {
    /// Hash type description
    pub hash_type: String,
    /// Username (if applicable)
    pub username: Option<String>,
    /// Whether the hash was cracked
    pub cracked: bool,
    /// Cracked password (if found)
    pub password: Option<String>,
    /// Number of candidates tried
    pub candidates_tried: usize,
    /// Time taken in milliseconds
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
    /// Smart wordlist from AD enumeration (supersedes embedded/custom)
    pub smart_wordlist: Vec<String>,
    /// Enable LDAP-derived smart wordlist generation
    pub use_smart_wordlist: bool,
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
            smart_wordlist: Vec::new(),
            use_smart_wordlist: false,
        }
    }
}

impl CrackerConfig {
    /// Fast mode -- minimal rules, embedded wordlist only
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
            smart_wordlist: Vec::new(),
            use_smart_wordlist: false,
        }
    }

    /// Thorough mode -- all rules, expanded candidates, common masks
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
            masks: vec![
                "?u?l?l?l?l?l?d?d".into(),
                "?u?l?l?l?l?l?l?d?d".into(),
                "?u?l?l?l?l?l?l?l?d?d".into(),
                "?u?l?l?l?l?l?d?d?d?d".into(),
            ],
            hybrid_masks: vec!["?d?d?d?d".into(), "?d?d?d?d?s".into(), "?s?d?d".into()],
            smart_wordlist: Vec::new(),
            use_smart_wordlist: false,
        }
    }

    /// Smart wordlist mode -- uses LDAP-derived patterns, aggressive rules.
    pub fn smart() -> Self {
        Self {
            use_embedded: true,
            custom_wordlist: None,
            rules: vec![
                Rule::None,
                Rule::Capitalize,
                Rule::CapitalizeDigit,
                Rule::CapitalizeYear,
                Rule::AppendYear,
                Rule::AppendSpecial,
                Rule::FullVariation,
            ],
            max_candidates: 0,
            prefer_hashcat: false,
            threads: 0,
            masks: vec![
                "?u?l?l?l?l?l?d?d".into(),
                "?u?l?l?l?l?l?l?d?d".into(),
                "?u?l?l?l?l?l?l?l?d?d".into(),
            ],
            hybrid_masks: vec!["?d?d?d?d".into(), "?s?d?d".into()],
            smart_wordlist: Vec::new(),
            use_smart_wordlist: true,
        }
    }
}

/// Main cracker -- parallel candidate testing
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
                .ok();
        }

        // Load wordlist -- smart wordlist takes priority
        let wordlist = if config.use_smart_wordlist && !config.smart_wordlist.is_empty() {
            info!(
                "Using smart wordlist with {} AD-derived candidates",
                config.smart_wordlist.len()
            );
            config.smart_wordlist.clone()
        } else if config.use_embedded && config.custom_wordlist.is_none() {
            get_embedded_wordlist()
        } else {
            // Wordlist will be streamed from file during crack(), not pre-loaded
            Vec::new()
        };

        if !wordlist.is_empty() {
            info!("Loaded {} base words", wordlist.len());
        }

        Ok(Self { config, wordlist })
    }

    /// Crack a single hash
    pub fn crack(&self, hash: &HashType) -> CrackResult {
        let start = Instant::now();
        let hash_type_str = match hash {
            HashType::AsRep { username, .. } => format!("AS-REP ({})", username),
            HashType::Kerberoast { spn, .. } => format!("Kerberoast ({})", spn),
            HashType::Ntlm { .. } => "NTLM".to_string(),
        };

        let counter = AtomicUsize::new(0);
        let found = AtomicBool::new(false);

        // Try hashcat first if preferred and available
        if self.config.prefer_hashcat && is_hashcat_available() {
            info!("Attempting hashcat GPU cracking...");
            if let Some(password) = try_hashcat(hash) {
                return CrackResult {
                    hash_type: hash_type_str,
                    username: hash.username().map(|s| s.to_string()),
                    cracked: true,
                    password: Some(password),
                    candidates_tried: 0,
                    time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        // Phase 1: Dictionary + Rules (streaming)
        let mut phase1_gen = self.build_phase1_generator();
        let total_cap = if self.config.max_candidates > 0 {
            self.config.max_candidates
        } else {
            usize::MAX
        };

        info!(
            "Phase 1: Dictionary+rules ({} rules, streaming)",
            self.config.rules.len()
        );

        if let Some(pwd) = crack_streaming_limited(
            &mut phase1_gen,
            hash,
            &counter,
            &found,
            start,
            "Phase 1",
            total_cap,
        ) {
            let tried = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_millis() as u64;
            info!(
                "[+] Password found (dictionary): {} ({} candidates, {}ms)",
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

        // Phase 2: Mask attacks (streaming)
        if !self.config.masks.is_empty() {
            info!("Phase 2: Mask attack -- {} masks", self.config.masks.len());
            for mask_str in &self.config.masks {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                match MaskPattern::parse(mask_str) {
                    Ok(mask) => {
                        let ks = mask.keyspace();
                        let remaining = if self.config.max_candidates > 0 {
                            (self.config.max_candidates as u64).saturating_sub(dict_tried as u64)
                        } else {
                            ks.min(50_000_000)
                        };
                        info!(
                            "  Mask '{}' -- keyspace {} (limit {})",
                            mask_str, ks, remaining
                        );

                        let mut mask_iter = mask.iter_limited(remaining);
                        if let Some(pwd) = crack_streaming(
                            &mut mask_iter,
                            hash,
                            &counter,
                            &found,
                            start,
                            &format!("Mask '{}'", mask_str),
                        ) {
                            let total_tried = counter.load(Ordering::Relaxed);
                            let elapsed = start.elapsed().as_millis() as u64;
                            info!(
                                "[+] Password found (mask): {} ({} total candidates, {}ms)",
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

        // Phase 3: Hybrid (wordlist base + mask suffix, streaming)
        if !self.config.hybrid_masks.is_empty() {
            info!(
                "Phase 3: Hybrid attack -- {} masks (streaming)",
                self.config.hybrid_masks.len()
            );
            for mask_str in &self.config.hybrid_masks {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                match MaskPattern::parse(mask_str) {
                    Ok(mask) => {
                        let suffixes: Vec<String> = mask.iter_limited(10_000).collect();
                        let mut hybrid_iter = self.build_hybrid_generator(suffixes);

                        if let Some(pwd) = crack_streaming(
                            &mut hybrid_iter,
                            hash,
                            &counter,
                            &found,
                            start,
                            &format!("Hybrid '{}'", mask_str),
                        ) {
                            let total_tried = counter.load(Ordering::Relaxed);
                            let elapsed = start.elapsed().as_millis() as u64;
                            info!(
                                "[+] Password found (hybrid): {} ({} total, {}ms)",
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
            "[-] Password not found after {} candidates ({}ms)",
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

    /// Build Phase 1 generator: wordlist + rules (streaming)
    fn build_phase1_generator(&self) -> Box<dyn Iterator<Item = String> + Send> {
        // Determine wordlist source
        let word_iter: Box<dyn Iterator<Item = String> + Send> =
            if self.config.use_smart_wordlist && !self.config.smart_wordlist.is_empty() {
                Box::new(self.config.smart_wordlist.clone().into_iter())
            } else if let Some(ref path) = self.config.custom_wordlist {
                match FileWordlistReader::open(path) {
                    Ok(reader) => Box::new(reader),
                    Err(_) => {
                        warn!(
                            "Cannot open custom wordlist '{}', falling back to embedded",
                            path
                        );
                        Box::new(get_embedded_wordlist().into_iter())
                    }
                }
            } else {
                // Use self.wordlist (pre-loaded embedded or smart)
                Box::new(self.wordlist.clone().into_iter())
            };

        if self.config.rules.is_empty() {
            word_iter
        } else {
            Box::new(RuleCandidateIter::new(word_iter, self.config.rules.clone()))
        }
    }

    /// Build Phase 3 hybrid generator: wordlist + suffixes (streaming)
    fn build_hybrid_generator(
        &self,
        suffixes: Vec<String>,
    ) -> Box<dyn Iterator<Item = String> + Send> {
        let word_iter: Box<dyn Iterator<Item = String> + Send> =
            if self.config.use_smart_wordlist && !self.config.smart_wordlist.is_empty() {
                Box::new(self.config.smart_wordlist.clone().into_iter())
            } else if let Some(ref path) = self.config.custom_wordlist {
                match FileWordlistReader::open(path) {
                    Ok(reader) => Box::new(reader),
                    Err(_) => {
                        warn!(
                            "Cannot open custom wordlist '{}', falling back to embedded",
                            path
                        );
                        Box::new(get_embedded_wordlist().into_iter())
                    }
                }
            } else {
                Box::new(self.wordlist.clone().into_iter())
            };

        Box::new(HybridCandidates::new(word_iter, suffixes))
    }

    /// Crack multiple hashes in parallel
    pub fn crack_batch(&self, hashes: &[HashType]) -> Vec<CrackResult> {
        info!("Cracking {} hashes in parallel", hashes.len());
        hashes.iter().map(|h| self.crack(h)).collect()
    }
}

/// Like crack_streaming but respects a total candidate cap
fn crack_streaming_limited<Gen: Iterator<Item = String>>(
    generator: &mut Gen,
    hash: &HashType,
    counter: &AtomicUsize,
    found: &AtomicBool,
    start: Instant,
    phase_name: &str,
    limit: usize,
) -> Option<String> {
    let mut reported = 0;
    let mut last_report = Instant::now();
    let mut total_processed: usize = 0;

    loop {
        if found.load(Ordering::Relaxed) {
            return None;
        }

        let batch_size = BATCH_SIZE.min(limit.saturating_sub(total_processed));
        if batch_size == 0 {
            return None;
        }

        let batch: Vec<String> = generator.take(batch_size).collect();
        if batch.is_empty() {
            return None;
        }

        total_processed += batch.len();
        if let Some(pwd) = verify_batch(&batch, hash, found, counter) {
            return Some(pwd);
        }

        // Progress report
        let now = Instant::now();
        if now.duration_since(last_report).as_secs_f64() > 2.0 {
            let count = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                count as f64 / elapsed
            } else {
                0.0
            };
            info!(
                "[{}] Speed: {:.0} H/s, {} candidates, {:.1}s",
                phase_name, speed, count, elapsed
            );
            if count > reported + 500_000 {
                reported = count;
            }
            last_report = now;
        }
    }
}

/// Verify if a password candidate matches the hash
pub fn verify_candidate(hash: &HashType, password: &str) -> bool {
    match hash {
        HashType::AsRep {
            cipher,
            etype,
            username,
            domain,
            ..
        } => match *etype {
            23 => {
                let nt_hash = password_to_nt_hash(password);
                if cipher.len() < 24 {
                    return false;
                }
                rc4_hmac_decrypt(&nt_hash, cipher, 3).is_ok()
            }
            17 | 18 => {
                let salt = kerberos_aes_salt(domain, username);
                verify_aes_candidate(password, &salt, *etype, cipher)
            }
            _ => false,
        },

        HashType::Kerberoast {
            cipher,
            etype,
            domain,
            spn,
            ..
        } => match *etype {
            23 => {
                let nt_hash = password_to_nt_hash(password);
                if cipher.len() < 24 {
                    return false;
                }
                rc4_hmac_decrypt(&nt_hash, cipher, 8).is_ok()
            }
            17 | 18 => {
                let service_name = spn.split('/').next().unwrap_or(spn);
                let salts = [
                    kerberos_aes_salt(domain, service_name),
                    kerberos_aes_salt(domain, spn),
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
        },

        HashType::Ntlm { hash } => {
            let nt_hash = password_to_nt_hash(password);
            nt_hash == *hash
        }
    }
}

// ===========================================================
// Hashcat Integration
// ===========================================================

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

    let wordlist = get_embedded_wordlist();
    let wordlist_content = wordlist.join("\n");
    std::fs::write(&wordlist_file, &wordlist_content).ok()?;

    let mode = hash.hashcat_mode();

    let output = Command::new("hashcat")
        .args([
            "-m",
            &mode.to_string(),
            "-a",
            "0",
            "--quiet",
            "--force",
            hash_file.to_str()?,
            wordlist_file.to_str()?,
        ])
        .output()
        .ok()?;

    let _ = std::fs::remove_file(&hash_file);
    let _ = std::fs::remove_file(&wordlist_file);

    if output.status.success() {
        let show_output = Command::new("hashcat")
            .args(["-m", &mode.to_string(), "--show", hash_file.to_str()?])
            .output()
            .ok()?;

        let result = String::from_utf8_lossy(&show_output.stdout);
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

/// Create a `CrackerConfig` pre-populated with SmartWordlist candidates.
pub fn config_from_smart_wordlist(
    smart: &mut crate::crypto::smart_wordlist::SmartWordlist,
) -> CrackerConfig {
    let mut config = CrackerConfig::smart();
    config.smart_wordlist = smart.generate();
    config
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_nt_hash() {
        let hash = password_to_nt_hash("Password123");
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
            "  $krb5asrep$23$alice@CORP.LOCAL:00112233445566778899aabbccddeeff$deadbeef\n",
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
            "\t$krb5tgs$23$*alice$CORP.LOCAL$cifs/dc01.corp.local*$00112233445566778899aabbccddeeff$deadbeef\r\n",
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
        let candidates: Vec<String> = mask.iter_limited(u64::MAX).collect();
        assert_eq!(candidates.len(), 10_000);
        assert!(candidates.contains(&"0000".to_string()));
        assert!(candidates.contains(&"9999".to_string()));
        assert!(candidates.contains(&"1234".to_string()));
    }

    #[test]
    fn test_mask_pattern_literal() {
        let mask = MaskPattern::parse("Pass?d?d?d?d").unwrap();
        assert_eq!(mask.keyspace(), 10_000);
        let candidates: Vec<String> = mask.iter_limited(u64::MAX).collect();
        assert!(candidates.contains(&"Pass0000".to_string()));
        assert!(candidates.contains(&"Pass1234".to_string()));
    }

    #[test]
    fn test_mask_pattern_upper_lower() {
        let mask = MaskPattern::parse("?u?l").unwrap();
        assert_eq!(mask.keyspace(), 26 * 26);
        let candidates: Vec<String> = mask.iter_limited(u64::MAX).collect();
        assert!(candidates.contains(&"Aa".to_string()));
        assert!(candidates.contains(&"Zz".to_string()));
    }

    #[test]
    fn test_mask_pattern_limited() {
        let mask = MaskPattern::parse("?a?a?a?a?a?a").unwrap();
        let candidates: Vec<String> = mask.iter_limited(100).collect();
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

    #[test]
    fn test_smart_wordlist_config_integration() {
        let mut smart = crate::crypto::smart_wordlist::SmartWordlist::new("corp.local");
        smart.add_static_keywords(&["Contoso", "ITDepartment", "SQLServer"]);
        let config = config_from_smart_wordlist(&mut smart);
        assert!(config.use_smart_wordlist);
        assert!(!config.smart_wordlist.is_empty());
        assert!(config.smart_wordlist.iter().any(|w| w.contains("Contoso")));
    }

    #[test]
    fn test_rule_iter_none() {
        let words = vec!["hello".to_string(), "world".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::None]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results, vec!["hello", "world"]);
    }

    #[test]
    fn test_rule_iter_capitalize() {
        let words = vec!["hello".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::Capitalize]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results, vec!["Hello"]);
    }

    #[test]
    fn test_rule_iter_append_digit() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::AppendDigit]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results.len(), 10);
        assert_eq!(results[0], "pass0");
        assert_eq!(results[9], "pass9");
    }

    #[test]
    fn test_rule_iter_multiple_words_multiple_rules() {
        let words = vec!["a".to_string(), "b".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::None, Rule::Capitalize]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results, vec!["a", "A", "b", "B"]);
    }

    #[test]
    fn test_mask_iter_streaming() {
        let mask = MaskPattern::parse("?d?d").unwrap();
        let mut iter = mask.iter_limited(5);
        assert_eq!(iter.next(), Some("00".to_string()));
        assert_eq!(iter.next(), Some("01".to_string()));
        assert_eq!(iter.next(), Some("02".to_string()));
        assert_eq!(iter.next(), Some("03".to_string()));
        assert_eq!(iter.next(), Some("04".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_mask_iter_completes_keyspace() {
        let mask = MaskPattern::parse("?d?d").unwrap();
        let results: Vec<String> = mask.iter_limited(500).collect();
        assert_eq!(results.len(), 100); // keyspace is 100
        assert_eq!(results[0], "00");
        assert_eq!(results[99], "99");
    }

    #[test]
    fn test_hybrid_candidates() {
        let words = vec!["Pass".to_string(), "Word".to_string()];
        let suffixes = vec!["123".to_string(), "!".to_string()];
        let hybrid = HybridCandidates::new(words.into_iter(), suffixes);
        let results: Vec<String> = hybrid.collect();
        assert_eq!(results, vec!["Pass123", "Pass!", "Word123", "Word!"]);
    }

    #[test]
    fn test_hybrid_candidates_empty_suffixes() {
        let words = vec!["test".to_string()];
        let suffixes: Vec<String> = vec![];
        let hybrid = HybridCandidates::new(words.into_iter(), suffixes);
        let results: Vec<String> = hybrid.collect();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_rule_iter_with_append_two_digits() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::AppendTwoDigits]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results.len(), 100);
        assert_eq!(results[0], "pass00");
        assert_eq!(results[99], "pass99");
    }

    #[test]
    fn test_rule_iter_with_lowercase() {
        let words = vec!["HELLO".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::Lowercase]);
        assert_eq!(iter.collect::<Vec<_>>(), vec!["hello"]);
    }

    #[test]
    fn test_rule_iter_with_uppercase() {
        let words = vec!["hello".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::Uppercase]);
        assert_eq!(iter.collect::<Vec<_>>(), vec!["HELLO"]);
    }

    #[test]
    fn test_rule_iter_with_leet() {
        let words = vec!["password".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::Leet]);
        assert_eq!(iter.collect::<Vec<_>>(), vec!["p@$$w0rd"]);
    }

    #[test]
    fn test_rule_iter_with_prepend_digit() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::PrependDigit]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results.len(), 10);
        assert_eq!(results[0], "0pass");
        assert_eq!(results[9], "9pass");
    }

    #[test]
    fn test_rule_iter_with_append_special() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::AppendSpecial]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results.len(), 8);
        assert!(results.contains(&"pass!".to_string()));
        assert!(results.contains(&"pass*".to_string()));
    }

    #[test]
    fn test_rule_iter_with_full_variation() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::FullVariation]);
        let results: Vec<String> = iter.collect();
        // FullVariation: capitalize + leet × (10 digits + 12 years) = 44 outputs
        assert_eq!(results.len(), 44);
        assert!(results.contains(&"Pass0".to_string()));
        assert!(results.contains(&"Pass2015".to_string()));
        assert!(results.contains(&"p@$$0".to_string()));
    }

    #[test]
    fn test_empty_wordlist_produces_nothing() {
        let words: Vec<String> = vec![];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::None, Rule::Capitalize]);
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn test_file_wordlist_reader_nonexistent() {
        assert!(FileWordlistReader::open("C:\\nonexistent\\path\\rockyou.txt").is_err());
    }

    #[test]
    fn test_mask_iter_parallel_collect() {
        let mask = MaskPattern::parse("?d?d?d").unwrap();
        let results: Vec<String> = mask.iter_limited(200).collect();
        assert_eq!(results.len(), 200);
        assert_eq!(results[0], "000");
        assert_eq!(results[199], "199");
    }

    #[test]
    fn test_rule_iter_capitalize_digit() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::CapitalizeDigit]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results.len(), 10);
        assert_eq!(results[0], "Pass0");
        assert_eq!(results[9], "Pass9");
    }

    #[test]
    fn test_rule_iter_capitalize_year() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::CapitalizeYear]);
        let results: Vec<String> = iter.collect();
        // Years 2015-2026 = 12 entries
        assert_eq!(results.len(), 12);
        assert!(results.contains(&"Pass2015".to_string()));
        assert!(results.contains(&"Pass2026".to_string()));
    }

    #[test]
    fn test_rule_iter_append_year() {
        let words = vec!["pass".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![Rule::AppendYear]);
        let results: Vec<String> = iter.collect();
        assert_eq!(results.len(), 12);
        assert!(results.contains(&"pass2015".to_string()));
        assert!(results.contains(&"pass2026".to_string()));
    }

    #[test]
    fn test_crack_ntlm_streaming() {
        let config = CrackerConfig::fast();
        let cracker = HashCracker::new(config).unwrap();
        let hash = HashType::parse_ntlm("58a478135a93ac3bf058a5ea0e8fdb71").unwrap();
        let result = cracker.crack(&hash);
        assert!(result.cracked);
        assert_eq!(result.password, Some("Password123".to_string()));
    }

    #[test]
    fn test_verify_candidate_asrep_rc4() {
        // Construct minimal AS-REP hash for RC4 (etype 23)
        // This won't actually verify since we need a real cipher, but it should not panic
        let hash = HashType::AsRep {
            username: "testuser".to_string(),
            domain: "TEST.LOCAL".to_string(),
            etype: 23,
            cipher: vec![0u8; 32], // 16 checksum + 16+ edata2
        };
        // Should return false (wrong cipher), not panic
        assert!(!verify_candidate(&hash, "wrongpassword"));
    }

    #[test]
    fn test_verify_candidate_short_cipher() {
        let hash = HashType::AsRep {
            username: "testuser".to_string(),
            domain: "TEST.LOCAL".to_string(),
            etype: 23,
            cipher: vec![0u8; 4], // too short
        };
        assert!(!verify_candidate(&hash, "anything"));
    }

    #[test]
    fn test_crack_result_defaults() {
        let result = CrackResult {
            hash_type: "test".to_string(),
            username: None,
            cracked: false,
            password: None,
            candidates_tried: 0,
            time_ms: 0,
        };
        assert!(!result.cracked);
        assert_eq!(result.candidates_tried, 0);
    }

    #[test]
    fn test_config_fast_has_limits() {
        let config = CrackerConfig::fast();
        assert!(config.max_candidates > 0);
        assert!(config.max_candidates <= 100_000);
    }

    #[test]
    fn test_config_thorough_has_masks() {
        let config = CrackerConfig::thorough();
        assert!(!config.masks.is_empty());
        assert!(!config.hybrid_masks.is_empty());
    }

    #[test]
    fn test_rule_iter_with_empty_rules() {
        let words = vec!["hello".to_string(), "world".to_string()];
        let iter = RuleCandidateIter::new(words.into_iter(), vec![]);
        // With no rules, all words pass through as-is
        let results: Vec<String> = iter.collect();
        assert_eq!(results, vec!["hello", "world"]);
    }
}
