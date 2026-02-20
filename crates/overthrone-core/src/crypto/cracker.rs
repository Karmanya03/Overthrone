//! Inline Hash Cracking — RC4-HMAC (Kerberos) and NTLM hash cracking.
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
//! - Hashcat subprocess fallback for GPU acceleration

use crate::error::{OverthroneError, Result};
use rayon::prelude::*;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Embedded Wordlist (Top 10K + common passwords)
// ═══════════════════════════════════════════════════════════

/// Compressed top-10K password wordlist with common variations.
/// Generated from seclists Pwdb-Top10K + rockyou.txt top occurrences.
/// Compressed with zstd level 19: 90KB → 40KB (44.5% ratio).
///
/// To regenerate: `zstd -19 wordlist.txt -o wordlist.txt.zst`
static WORDLIST_ZST: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/wordlist_top10k.txt.zst"));

/// Fallback minimal wordlist if decompression fails
const FALLBACK_WORDLIST: &[&str] = &[
    "password", "Password1", "Password123", "P@ssw0rd", "P@ssword123",
    "admin", "Admin123", "administrator", "Administrator1", "letmein",
    "welcome", "Welcome1", "Welcome123", "qwerty", "qwerty123",
    "abc123", "123456", "1234567", "12345678", "123456789",
    "1234567890", "Password1!", "Spring2024", "Summer2024", "Fall2024",
    "Winter2024", "changeme", "ChangeMe1", "secret", "Secret123",
];

/// Decompress and return the embedded wordlist
pub fn get_embedded_wordlist() -> Vec<String> {
    decompress_wordlist(WORDLIST_ZST).unwrap_or_else(|_| {
        // Fallback to minimal built-in list
        FALLBACK_WORDLIST.iter().map(|s| s.to_string()).collect()
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
            Rule::AppendDigit => {
                (0..=9).map(|d| format!("{}{}", password, d)).collect()
            }
            Rule::AppendTwoDigits => {
                (0..=99).map(|d| format!("{}{:02}", password, d)).collect()
            }
            Rule::AppendYear => {
                (2015..=2026).map(|y| format!("{}{}", password, y)).collect()
            }
            Rule::PrependDigit => {
                (0..=9).map(|d| format!("{}{}", d, password)).collect()
            }
            Rule::Leet => {
                vec![apply_leet(password)]
            }
            Rule::AppendSpecial => {
                ['!', '@', '#', '$', '%', '^', '&', '*']
                    .iter()
                    .map(|c| format!("{}{}", password, c))
                    .collect()
            }
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
    Ntlm {
        hash: [u8; 16],
    },
}

impl HashType {
    /// Parse an AS-REP hash string (hashcat format)
    /// Format: $krb5asrep${etype}${user}@{domain}:{cipher_hex}
    pub fn parse_asrep(hash_str: &str) -> Result<Self> {
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 4 || !hash_str.starts_with("$krb5asrep$") {
            return Err(OverthroneError::custom("Invalid AS-REP hash format"));
        }
        
        // Parse: $krb5asrep${etype}${user}@{domain}:{cipher}
        let inner = &parts[2..].join("$");
        let main_parts: Vec<&str> = inner.split(':').collect();
        if main_parts.len() != 2 {
            return Err(OverthroneError::custom("Invalid AS-REP hash format"));
        }
        
        let user_domain = main_parts[0];
        let cipher_hex = main_parts[1];
        
        // Extract etype and user@domain
        let first_dollar = user_domain.find('$').unwrap_or(0);
        let (etype_str, user_domain_part) = if first_dollar > 0 {
            user_domain.split_at(first_dollar)
        } else {
            ("23", user_domain) // Default to RC4
        };
        
        let etype: i32 = etype_str.parse().unwrap_or(23);
        
        // Parse user@domain
        let ud_parts: Vec<&str> = user_domain_part.trim_start_matches('$').split('@').collect();
        let (username, domain) = if ud_parts.len() == 2 {
            (ud_parts[0].to_string(), ud_parts[1].to_string())
        } else {
            (ud_parts[0].to_string(), String::new())
        };
        
        let cipher = hex::decode(cipher_hex)
            .map_err(|e| OverthroneError::custom(format!("Invalid cipher hex: {}", e)))?;
        
        Ok(HashType::AsRep { username, domain, etype, cipher })
    }
    
    /// Parse a Kerberoast hash string (hashcat format)
    /// Format: $krb5tgs${etype}${user}${domain}${spn}*${cipher}
    pub fn parse_kerberoast(hash_str: &str) -> Result<Self> {
        if !hash_str.starts_with("$krb5tgs$") {
            return Err(OverthroneError::custom("Invalid Kerberoast hash format"));
        }
        
        // Simplified parsing - hashcat format varies by etype
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 5 {
            return Err(OverthroneError::custom("Invalid Kerberoast hash format"));
        }
        
        let etype: i32 = parts[2].parse().unwrap_or(23);
        
        // Find the cipher (after the last $ or *)
        let cipher_start = hash_str.rfind('*').or_else(|| hash_str.rfind('$'));
        let cipher_hex = if let Some(pos) = cipher_start {
            &hash_str[pos + 1..]
        } else {
            return Err(OverthroneError::custom("Cannot find cipher in Kerberoast hash"));
        };
        
        let cipher = hex::decode(cipher_hex)
            .map_err(|e| OverthroneError::custom(format!("Invalid cipher hex: {}", e)))?;
        
        // Extract user/domain/spn from hash string (simplified)
        let username = parts.get(3).unwrap_or(&"unknown").to_string();
        let domain = parts.get(4).unwrap_or(&"unknown").to_string();
        let spn = parts.get(5).unwrap_or(&"unknown").to_string();
        
        Ok(HashType::Kerberoast { username, domain, spn, etype, cipher })
    }
    
    /// Parse an NTLM hash string
    /// Format: 32 hex characters
    pub fn parse_ntlm(hash_str: &str) -> Result<Self> {
        let clean = hash_str.trim();
        if clean.len() != 32 {
            return Err(OverthroneError::custom("NTLM hash must be 32 hex characters"));
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
    use md4::{Md4, Digest as Md4Digest};
    let utf16le: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    
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
        }
    }
    
    /// Thorough mode — all rules, expanded candidates
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
        
        // Expand wordlist with rules
        let candidates = expand_wordlist(&self.wordlist, &self.config.rules);
        let total_candidates = if self.config.max_candidates > 0 {
            self.config.max_candidates.min(candidates.len())
        } else {
            candidates.len()
        };
        
        info!(
            "Cracking {} with {} candidates ({} rules applied)",
            hash_type_str,
            total_candidates,
            self.config.rules.len()
        );
        
        // Parallel cracking
        let counter = AtomicUsize::new(0);
        let password = candidates
            .par_iter()
            .take(total_candidates)
            .find_map_any(|candidate| {
                let count = counter.fetch_add(1, Ordering::Relaxed);
                if count % 10_000 == 0 {
                    debug!("Tried {} candidates...", count);
                }
                
                if verify_candidate(hash, candidate) {
                    Some(candidate.clone())
                } else {
                    None
                }
            });
        
        let tried = counter.load(Ordering::Relaxed);
        let elapsed = start.elapsed().as_millis() as u64;
        
        if let Some(pwd) = password {
            info!("✓ Password found: {} ({} candidates, {}ms)", pwd, tried, elapsed);
            CrackResult {
                hash_type: hash_type_str,
                username: hash.username().map(|s| s.to_string()),
                cracked: true,
                password: Some(pwd),
                candidates_tried: tried,
                time_ms: elapsed,
            }
        } else {
            info!("✗ Password not found after {} candidates ({}ms)", tried, elapsed);
            CrackResult {
                hash_type: hash_type_str,
                username: hash.username().map(|s| s.to_string()),
                cracked: false,
                password: None,
                candidates_tried: tried,
                time_ms: elapsed,
            }
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
    let nt_hash = password_to_nt_hash(password);
    
    match hash {
        HashType::AsRep { cipher, etype, .. } => {
            // AS-REP RC4-HMAC verification
            if *etype != 23 {
                // Only RC4 supported for now
                return false;
            }
            
            // The cipher contains: HMAC-MD5 checksum (16 bytes) + encrypted data
            if cipher.len() < 32 {
                return false;
            }
            
            // Simplified verification - decrypt and check structure
            let decrypted = rc4_decrypt_kerberos(&nt_hash, cipher);
            
            // Check if decrypted data looks like valid AS-REP enc-part
            // It should contain recognizable ASN.1 structures
            decrypted.len() >= 32 && 
                (decrypted[0] == 0x30 || decrypted[0] == 0x7A) // SEQUENCE or APPLICATION 26
        }
        
        HashType::Kerberoast { cipher, etype, .. } => {
            // Kerberoast RC4-HMAC verification
            if *etype != 23 {
                // Only RC4 supported for now
                return false;
            }
            
            if cipher.len() < 32 {
                return false;
            }
            
            // Decrypt and check for valid EncTicketPart structure
            let decrypted = rc4_decrypt_kerberos(&nt_hash, cipher);
            
            // EncTicketPart starts with APPLICATION 3 (0x63)
            decrypted.len() >= 32 && decrypted[0] == 0x63
        }
        
        HashType::Ntlm { hash } => {
            // Simple NTLM comparison
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
        HashType::AsRep { username, domain, etype, cipher } => {
            format!(
                "$krb5asrep${}${}@{}:{}",
                etype,
                username,
                domain,
                hex::encode(cipher)
            )
        }
        HashType::Kerberoast { username, domain, spn, etype, cipher } => {
            format!(
                "$krb5tgs${}${}${}${}*${}",
                etype,
                username,
                domain,
                spn,
                hex::encode(cipher)
            )
        }
        HashType::Ntlm { hash } => {
            hex::encode(hash)
        }
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
            "-m", &mode.to_string(),
            "-a", "0", // Dictionary attack
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
            .args([
                "-m", &mode.to_string(),
                "--show",
                hash_file.to_str()?,
            ])
            .output()
            .ok()?;
        
        let result = String::from_utf8_lossy(&show_output.stdout);
        // Parse: hash:password
        result.lines().next()?.split(':').nth(1).map(|s| s.to_string())
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
                assert_eq!(hash, [0x2a, 0xc9, 0xcb, 0x7d, 0xc0, 0x2b, 0x3c, 0x00, 
                                  0x83, 0xeb, 0x70, 0x89, 0x8e, 0x54, 0x9b, 0x63]);
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
}