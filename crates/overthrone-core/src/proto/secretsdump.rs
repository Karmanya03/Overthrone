//! Secrets extraction from Active Directory domain controllers
//!
//! Implements credential extraction techniques equivalent to
//! Impacket's secretsdump.py:
//! - SAM database extraction (local accounts)
//! - LSA secrets extraction (service credentials, cached passwords)
//! - NTDS.dit extraction via DRSUAPI (domain account hashes)
//! - DCC2 cached domain credentials

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Credential types that can be extracted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretType {
    /// SAM database — local account NTLM hashes
    Sam,
    /// LSA secrets — service account credentials, DPAPI keys
    Lsa,
    /// NTDS.dit — all domain account hashes via DRSUAPI
    Ntds,
    /// Domain Cached Credentials v2 (mscash2)
    CachedDomain,
}

/// A single extracted credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSecret {
    pub secret_type: SecretType,
    /// Domain\Username or machine account
    pub account: String,
    /// RID (Relative Identifier) if applicable
    pub rid: Option<u32>,
    /// LM hash (usually empty/disabled on modern systems)
    pub lm_hash: Option<String>,
    /// NTLM hash
    pub nt_hash: Option<String>,
    /// Plaintext password (from LSA secrets or reversible encryption)
    pub plaintext: Option<String>,
    /// Raw secret data for non-password secrets
    pub raw_data: Option<Vec<u8>>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Options controlling what to extract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpOptions {
    /// Extract SAM database hashes
    pub dump_sam: bool,
    /// Extract LSA secrets
    pub dump_lsa: bool,
    /// Extract NTDS.dit via DRSUAPI
    pub dump_ntds: bool,
    /// Extract cached domain credentials
    pub dump_cached: bool,
    /// Target specific user(s) for NTDS extraction
    pub target_users: Vec<String>,
    /// Use VSS (Volume Shadow Copy) method for NTDS
    pub use_vss: bool,
    /// Number of DRSUAPI replication threads
    pub replication_threads: u32,
    /// Include machine accounts in NTDS dump
    pub include_machine_accounts: bool,
    /// Include password history
    pub include_history: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            dump_sam: true,
            dump_lsa: true,
            dump_ntds: true,
            dump_cached: true,
            target_users: Vec::new(),
            use_vss: false,
            replication_threads: 4,
            include_machine_accounts: false,
            include_history: false,
        }
    }
}

/// Result of a secrets extraction operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpResult {
    pub target_host: String,
    pub secrets: Vec<ExtractedSecret>,
    pub sam_count: usize,
    pub lsa_count: usize,
    pub ntds_count: usize,
    pub cached_count: usize,
    pub errors: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
//  SAM Database Extraction
// ═══════════════════════════════════════════════════════════

/// Boot key (SysKey) extracted from the SYSTEM registry hive
#[derive(Debug, Clone)]
pub struct BootKey {
    pub key: [u8; 16],
}

impl BootKey {
    /// Derive the boot key from SYSTEM hive JD/Skew1/GBG/Data class values
    pub fn from_system_hive(jd: &[u8], skew1: &[u8], gbg: &[u8], data: &[u8]) -> Result<Self> {
        if jd.len() < 2 || skew1.len() < 2 || gbg.len() < 2 || data.len() < 2 {
            return Err(anyhow!("Invalid SYSTEM hive class data for boot key derivation"));
        }

        // Scrambled key from registry class names
        let mut scrambled = Vec::with_capacity(16);
        for src in &[jd, skew1, gbg, data] {
            scrambled.extend_from_slice(&src[..std::cmp::min(4, src.len())]);
        }
        scrambled.resize(16, 0);

        // Permutation table to unscramble the boot key
        const PERM: [usize; 16] = [
            0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
            0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7,
        ];

        let mut key = [0u8; 16];
        for (i, &p) in PERM.iter().enumerate() {
            if p < scrambled.len() {
                key[i] = scrambled[p];
            }
        }

        Ok(Self { key })
    }
}

/// Parse a SAM entry into an ExtractedSecret
pub fn parse_sam_hash(account: &str, rid: u32, lm_bytes: &[u8], nt_bytes: &[u8]) -> ExtractedSecret {
    let lm_hash = if lm_bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(hex::encode(lm_bytes))
    };

    let nt_hash = if nt_bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(hex::encode(nt_bytes))
    };

    ExtractedSecret {
        secret_type: SecretType::Sam,
        account: account.to_string(),
        rid: Some(rid),
        lm_hash,
        nt_hash,
        plaintext: None,
        raw_data: None,
        metadata: HashMap::new(),
    }
}

// ═══════════════════════════════════════════════════════════
//  LSA Secrets Extraction
// ═══════════════════════════════════════════════════════════

/// Known LSA secret prefixes and their meanings
pub fn classify_lsa_secret(name: &str) -> &'static str {
    if name.starts_with("_SC_") {
        "Service Account Password"
    } else if name.starts_with("NL$KM") {
        "NL$KM — Cached Credentials Encryption Key"
    } else if name.starts_with("DPAPI") {
        "DPAPI Master Key Backup"
    } else if name.starts_with("$MACHINE.ACC") {
        "Machine Account Password"
    } else if name.starts_with("DefaultPassword") {
        "Auto-Logon Default Password"
    } else if name.starts_with("aspnet_WP_PASSWORD") {
        "ASP.NET Worker Process Password"
    } else {
        "Unknown LSA Secret"
    }
}

// ═══════════════════════════════════════════════════════════
//  NTDS.dit Extraction (via DRSUAPI)
// ═══════════════════════════════════════════════════════════

/// Format an NTDS hash entry in the standard secretsdump format:
/// `domain\user:rid:lm_hash:nt_hash:::`
pub fn format_ntds_hash(domain: &str, secret: &ExtractedSecret) -> String {
    let lm = secret.lm_hash.as_deref().unwrap_or("aad3b435b51404eeaad3b435b51404ee");
    let nt = secret.nt_hash.as_deref().unwrap_or("31d6cfe0d16ae931b73c59d7e0c089c0");
    let rid = secret.rid.unwrap_or(0);

    format!("{}\\{}:{}:{}:{}:::", domain, secret.account, rid, lm, nt)
}

/// Format output compatible with hashcat (-m 1000) and john
pub fn format_for_cracking(secrets: &[ExtractedSecret]) -> Vec<String> {
    secrets
        .iter()
        .filter_map(|s| {
            s.nt_hash.as_ref().map(|nt| {
                format!("{}:{}", s.account, nt)
            })
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════
//  DCC2 / mscash2 Cached Credentials
// ═══════════════════════════════════════════════════════════

/// Format cached domain credential for hashcat (-m 2100)
pub fn format_dcc2_for_cracking(username: &str, dcc2_hash: &[u8]) -> String {
    format!("$DCC2$10240#{}#{}", username, hex::encode(dcc2_hash))
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sam_hash_parse() {
        let lm = [0u8; 16];
        let nt = [0xAA; 16];
        let secret = parse_sam_hash("Administrator", 500, &lm, &nt);

        assert_eq!(secret.account, "Administrator");
        assert_eq!(secret.rid, Some(500));
        assert!(secret.lm_hash.is_none()); // all zeros → disabled
        assert!(secret.nt_hash.is_some());
    }

    #[test]
    fn test_ntds_hash_format() {
        let secret = ExtractedSecret {
            secret_type: SecretType::Ntds,
            account: "jdoe".to_string(),
            rid: Some(1104),
            lm_hash: None,
            nt_hash: Some("fc525c9683e8fe067095ba2ddc971889".to_string()),
            plaintext: None,
            raw_data: None,
            metadata: HashMap::new(),
        };

        let formatted = format_ntds_hash("CORP", &secret);
        assert!(formatted.starts_with("CORP\\jdoe:1104:"));
        assert!(formatted.contains("fc525c9683e8fe067095ba2ddc971889"));
    }

    #[test]
    fn test_lsa_secret_classification() {
        assert_eq!(classify_lsa_secret("_SC_SqlService"), "Service Account Password");
        assert_eq!(classify_lsa_secret("$MACHINE.ACC"), "Machine Account Password");
        assert_eq!(classify_lsa_secret("NL$KM"), "NL$KM — Cached Credentials Encryption Key");
        assert_eq!(classify_lsa_secret("RandomThing"), "Unknown LSA Secret");
    }

    #[test]
    fn test_dcc2_format() {
        let hash = [0xBB; 16];
        let formatted = format_dcc2_for_cracking("admin", &hash);
        assert!(formatted.starts_with("$DCC2$10240#admin#"));
    }

    #[test]
    fn test_dump_options_default() {
        let opts = DumpOptions::default();
        assert!(opts.dump_sam);
        assert!(opts.dump_ntds);
        assert_eq!(opts.replication_threads, 4);
        assert!(!opts.use_vss);
    }

    #[test]
    fn test_cracking_format() {
        let secrets = vec![
            ExtractedSecret {
                secret_type: SecretType::Ntds,
                account: "admin".to_string(),
                rid: Some(500),
                lm_hash: None,
                nt_hash: Some("aabbccdd".to_string()),
                plaintext: None,
                raw_data: None,
                metadata: HashMap::new(),
            },
        ];
        let lines = format_for_cracking(&secrets);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "admin:aabbccdd");
    }
}
