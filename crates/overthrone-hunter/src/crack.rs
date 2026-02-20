//! Hash Cracking Integration — Wire the cracker to hunter module.
//!
//! Provides automatic cracking of captured AS-REP and Kerberoast hashes
//! using the inline cracker from overthrone-core.

use crate::asreproast::RoastedAccount;
use crate::kerberoast::RoastedService;
use colored::Colorize;
use overthrone_core::crypto::{
    CrackResult, CrackerConfig, HashCracker, HashType,
};
use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════
// Cracked Credentials
// ═══════════════════════════════════════════════════════════

/// A successfully cracked credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
    pub hash_type: String,
    pub source: CrackSource,
}

/// Source of the cracked hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrackSource {
    AsRepRoast,
    Kerberoast,
    Ntlm,
}

/// Result of batch cracking operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackReport {
    pub total_hashes: usize,
    pub cracked: Vec<CrackedCredential>,
    pub failed: Vec<FailedHash>,
    pub time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedHash {
    pub username: Option<String>,
    pub hash_type: String,
    pub candidates_tried: usize,
}

// ═══════════════════════════════════════════════════════════
// Hash Parsing Utilities
// ═══════════════════════════════════════════════════════════

/// Auto-detect hash type from string format
pub fn detect_hash_type(hash_str: &str) -> Result<HashType> {
    let trimmed = hash_str.trim();
    
    if trimmed.starts_with("$krb5asrep$") {
        HashType::parse_asrep(trimmed)
    } else if trimmed.starts_with("$krb5tgs$") {
        HashType::parse_kerberoast(trimmed)
    } else if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        HashType::parse_ntlm(trimmed)
    } else {
        Err(OverthroneError::custom(
            "Unknown hash format. Expected AS-REP ($krb5asrep$), Kerberoast ($krb5tgs$), or NTLM (32 hex chars)"
        ))
    }
}

/// Extract hash type name for display
fn hash_type_name(hash: &HashType) -> &'static str {
    match hash {
        HashType::AsRep { .. } => "AS-REP",
        HashType::Kerberoast { .. } => "Kerberoast",
        HashType::Ntlm { .. } => "NTLM",
    }
}

// ═══════════════════════════════════════════════════════════
// Cracking Functions
// ═══════════════════════════════════════════════════════════

/// Crack a single hash string with default config
pub fn crack_hash(hash_str: &str) -> Result<CrackResult> {
    let config = CrackerConfig::default();
    crack_hash_with_config(hash_str, &config)
}

/// Crack a single hash string with custom config
pub fn crack_hash_with_config(hash_str: &str, config: &CrackerConfig) -> Result<CrackResult> {
    let hash = detect_hash_type(hash_str)?;
    let cracker = HashCracker::new(config.clone())?;
    Ok(cracker.crack(&hash))
}

/// Crack AS-REP roasted accounts
pub fn crack_asrep_hashes(
    accounts: &[RoastedAccount],
    config: &CrackerConfig,
) -> Result<CrackReport> {
    let start = std::time::Instant::now();
    let cracker = HashCracker::new(config.clone())?;
    
    info!("Cracking {} AS-REP hashes...", accounts.len());
    
    let mut cracked = Vec::new();
    let mut failed = Vec::new();
    
    for account in accounts {
        let hash = HashType::parse_asrep(&account.hash_string)?;
        let result = cracker.crack(&hash);
        
        if result.cracked {
            if let Some(password) = &result.password {
                info!(
                    "  {} {}:{} — {}",
                    "✓".green(),
                    account.username.bold(),
                    password.yellow(),
                    "CRACKED".green().bold()
                );
                cracked.push(CrackedCredential {
                    username: account.username.clone(),
                    domain: account.domain.clone(),
                    password: password.clone(),
                    hash_type: "AS-REP".to_string(),
                    source: CrackSource::AsRepRoast,
                });
            }
        } else {
            warn!(
                "  {} {} — {} candidates tried",
                "✗".red(),
                account.username,
                result.candidates_tried
            );
            failed.push(FailedHash {
                username: Some(account.username.clone()),
                hash_type: "AS-REP".to_string(),
                candidates_tried: result.candidates_tried,
            });
        }
    }
    
    let elapsed = start.elapsed().as_millis() as u64;
    
    info!(
        "AS-REP Cracking: {}/{} cracked in {}ms",
        cracked.len().to_string().green(),
        accounts.len(),
        elapsed
    );
    
    Ok(CrackReport {
        total_hashes: accounts.len(),
        cracked,
        failed,
        time_ms: elapsed,
    })
}

/// Crack Kerberoast hashes
pub fn crack_kerberoast_hashes(
    services: &[RoastedService],
    config: &CrackerConfig,
) -> Result<CrackReport> {
    let start = std::time::Instant::now();
    let cracker = HashCracker::new(config.clone())?;
    
    info!("Cracking {} Kerberoast hashes...", services.len());
    
    let mut cracked = Vec::new();
    let mut failed = Vec::new();
    
    for service in services {
        // Skip AES hashes (not supported by inline cracker yet)
        if service.etype != "RC4" {
            warn!(
                "  {} {} — Skipping {} (only RC4 supported)",
                "→".yellow(),
                service.username,
                service.etype
            );
            continue;
        }
        
        let hash = HashType::parse_kerberoast(&service.hash_string)?;
        let result = cracker.crack(&hash);
        
        if result.cracked {
            if let Some(password) = &result.password {
                info!(
                    "  {} {}:{} — {} [{}]",
                    "✓".green(),
                    service.username.bold(),
                    password.yellow(),
                    "CRACKED".green().bold(),
                    service.spn.dimmed()
                );
                cracked.push(CrackedCredential {
                    username: service.username.clone(),
                    domain: service.domain.clone(),
                    password: password.clone(),
                    hash_type: "Kerberoast".to_string(),
                    source: CrackSource::Kerberoast,
                });
            }
        } else {
            warn!(
                "  {} {} — {} candidates tried",
                "✗".red(),
                service.username,
                result.candidates_tried
            );
            failed.push(FailedHash {
                username: Some(service.username.clone()),
                hash_type: format!("Kerberoast/{}", service.etype),
                candidates_tried: result.candidates_tried,
            });
        }
    }
    
    let elapsed = start.elapsed().as_millis() as u64;
    
    info!(
        "Kerberoast Cracking: {}/{} cracked in {}ms",
        cracked.len().to_string().green(),
        services.len(),
        elapsed
    );
    
    Ok(CrackReport {
        total_hashes: services.len(),
        cracked,
        failed,
        time_ms: elapsed,
    })
}

/// Crack multiple hash strings (auto-detect type)
pub fn crack_hashes(
    hash_strings: &[String],
    config: &CrackerConfig,
) -> Result<CrackReport> {
    let start = std::time::Instant::now();
    let cracker = HashCracker::new(config.clone())?;
    
    info!("Cracking {} hashes (auto-detecting types)...", hash_strings.len());
    
    let mut cracked = Vec::new();
    let mut failed = Vec::new();
    
    for hash_str in hash_strings {
        match detect_hash_type(hash_str) {
            Ok(hash) => {
                let result = cracker.crack(&hash);
                let username = hash.username().map(|s| s.to_string());
                
                if result.cracked {
                    if let Some(password) = &result.password {
                        info!(
                            "  {} {}:{} — {}",
                            "✓".green(),
                            username.as_deref().unwrap_or("unknown").bold(),
                            password.yellow(),
                            hash_type_name(&hash).green()
                        );
                        cracked.push(CrackedCredential {
                            username: username.clone().unwrap_or_else(|| "unknown".to_string()),
                            domain: String::new(),
                            password: password.clone(),
                            hash_type: hash_type_name(&hash).to_string(),
                            source: match hash {
                                HashType::AsRep { .. } => CrackSource::AsRepRoast,
                                HashType::Kerberoast { .. } => CrackSource::Kerberoast,
                                HashType::Ntlm { .. } => CrackSource::Ntlm,
                            },
                        });
                    }
                } else {
                    warn!(
                        "  {} {} — not cracked",
                        "✗".red(),
                        username.as_deref().unwrap_or("unknown")
                    );
                    failed.push(FailedHash {
                        username,
                        hash_type: hash_type_name(&hash).to_string(),
                        candidates_tried: result.candidates_tried,
                    });
                }
            }
            Err(e) => {
                warn!("  {} Invalid hash format: {}", "✗".red(), e);
                failed.push(FailedHash {
                    username: None,
                    hash_type: "invalid".to_string(),
                    candidates_tried: 0,
                });
            }
        }
    }
    
    let elapsed = start.elapsed().as_millis() as u64;
    
    Ok(CrackReport {
        total_hashes: hash_strings.len(),
        cracked,
        failed,
        time_ms: elapsed,
    })
}

// ═══════════════════════════════════════════════════════════
// Report Display
// ═══════════════════════════════════════════════════════════

impl CrackReport {
    /// Pretty-print the crack report
    pub fn print_summary(&self) {
        println!("\n{}", "═══ CRACK REPORT ═══".bold().cyan());
        println!("  Total hashes:  {}", self.total_hashes.to_string().bold());
        println!(
            "  Cracked:       {} ({:.1}%)",
            self.cracked.len().to_string().green().bold(),
            (self.cracked.len() as f64 / self.total_hashes.max(1) as f64) * 100.0
        );
        println!("  Time:          {}ms", self.time_ms);
        
        if !self.cracked.is_empty() {
            println!("\n  {} Cracked Credentials:", "✓".green().bold());
            for cred in &self.cracked {
                println!(
                    "    {}:{} {}",
                    cred.username.bold(),
                    cred.password.yellow(),
                    format!("[{}]", cred.hash_type).dimmed()
                );
            }
        }
        
        println!("{}\n", "═══════════════════".cyan());
    }
    
    /// Export cracked credentials to hashcat format
    pub fn to_cracked_file(&self) -> String {
        self.cracked
            .iter()
            .map(|c| format!("{}:{}", c.username, c.password))
            .collect::<Vec<_>>()
            .join("\n")
    }
}