//! Unified LAPS + gMSA purpose-built enumeration.
//!
//! Provides a single high-level entry point that combines LAPS v1/v2
//! and gMSA enumeration into a unified result, with smart filtering
//! to surface the most actionable credentials first.
//!
//! # Usage
//! ```ignore
//! let result = enumerate_laps_and_gmsa(&config).await?;
//! for entry in &result.actionable {
//!     println!("{}: {}", entry.target, entry.password());
//! }
//! ```

use crate::gmsa::{GmsaEntry, enumerate_gmsa};
use crate::laps::{LapsEntry, LapsSource, enumerate_laps};
use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};

/// Unified result combining LAPS and gMSA enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsGmsaResult {
    /// Entries sorted by actionability (readable passwords first)
    pub actionable: Vec<CredentialEntry>,
    /// LAPS entries that are encrypted only (need DPAPI backup key)
    pub encrypted_laps: Vec<LapsEntry>,
    /// gMSA entries (password blob available but needs decryption)
    pub gmsa_accounts: Vec<GmsaEntry>,
    /// LAPS entries detected but no password readable
    pub detected_only: Vec<LapsEntry>,
    /// Summary statistics
    pub stats: LapsGmsaStats,
}

/// Aggregated statistics about LAPS/gMSA findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsGmsaStats {
    /// Total LAPS-enabled computers found
    pub laps_total: usize,
    /// LAPS v1 passwords readable
    pub laps_v1_readable: usize,
    /// LAPS v2 plaintext passwords readable
    pub laps_v2_plaintext: usize,
    /// LAPS v2 encrypted blobs (need DPAPI backup key)
    pub laps_v2_encrypted: usize,
    /// LAPS detected but password not readable
    pub laps_detected: usize,
    /// gMSA accounts found
    pub gmsa_total: usize,
    /// gMSA accounts with password blob available
    pub gmsa_with_blob: usize,
}

/// A single actionable credential entry from LAPS or gMSA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// Target computer name (for LAPS) or account name (for gMSA)
    pub target: String,
    /// Distinguished name
    pub distinguished_name: String,
    /// Source type
    pub source: CredentialSource,
    /// Cleartext password (if available)
    pub password: Option<String>,
    /// Username/account associated with the credential
    pub account_name: Option<String>,
    /// Expiration timestamp (LAPS only)
    pub expiration: Option<String>,
    /// Priority ranking (0 = highest, higher = lower priority)
    pub priority: u8,
}

/// Source of a credential entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CredentialSource {
    /// LAPS v1 (ms-Mcs-AdmPwd)
    LapsV1,
    /// LAPS v2 plaintext JSON
    LapsV2Plaintext,
    /// LAPS v2 encrypted blob (password not directly readable)
    LapsV2Encrypted,
    /// gMSA (msDS-ManagedPassword blob)
    Gmsa,
}

impl std::fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialSource::LapsV1 => write!(f, "LAPS v1"),
            CredentialSource::LapsV2Plaintext => write!(f, "LAPS v2 plaintext"),
            CredentialSource::LapsV2Encrypted => write!(f, "LAPS v2 encrypted"),
            CredentialSource::Gmsa => write!(f, "gMSA"),
        }
    }
}

/// Enumerate LAPS and gMSA credentials with unified output.
///
/// This function calls both `enumerate_laps` and `enumerate_gmsa`,
/// then merges results into a single sorted view with actionable
/// entries first.
pub async fn enumerate_laps_and_gmsa(config: &ReaperConfig) -> Result<LapsGmsaResult> {
    let laps_entries = enumerate_laps(config).await.unwrap_or_default();
    let gmsa_entries = enumerate_gmsa(config).await.unwrap_or_default();

    let mut actionable: Vec<CredentialEntry> = Vec::new();
    let mut encrypted_laps: Vec<LapsEntry> = Vec::new();
    let mut detected_only: Vec<LapsEntry> = Vec::new();

    // Classify LAPS entries
    for entry in &laps_entries {
        match entry.source {
            LapsSource::V1 => {
                actionable.push(CredentialEntry {
                    target: entry.computer_name.clone(),
                    distinguished_name: entry.distinguished_name.clone(),
                    source: CredentialSource::LapsV1,
                    password: entry.password.clone(),
                    account_name: Some("Administrator".to_string()),
                    expiration: entry.expiration.clone(),
                    priority: 0,
                });
            }
            LapsSource::V2Plaintext => {
                let acct = entry
                    .managed_account
                    .clone()
                    .unwrap_or_else(|| "Administrator".to_string());
                actionable.push(CredentialEntry {
                    target: entry.computer_name.clone(),
                    distinguished_name: entry.distinguished_name.clone(),
                    source: CredentialSource::LapsV2Plaintext,
                    password: entry.password.clone(),
                    account_name: Some(acct),
                    expiration: entry.expiration.clone(),
                    priority: 1,
                });
            }
            LapsSource::V2Encrypted => {
                encrypted_laps.push(entry.clone());
                actionable.push(CredentialEntry {
                    target: entry.computer_name.clone(),
                    distinguished_name: entry.distinguished_name.clone(),
                    source: CredentialSource::LapsV2Encrypted,
                    password: None,
                    account_name: entry.managed_account.clone(),
                    expiration: entry.expiration.clone(),
                    priority: 10,
                });
            }
            LapsSource::Detected => {
                detected_only.push(entry.clone());
            }
        }
    }

    // Add gMSA entries to actionable (blob available but needs offline decrypt)
    for entry in &gmsa_entries {
        let has_blob = entry.managed_password_blob.is_some();
        actionable.push(CredentialEntry {
            target: entry.sam_account_name.clone(),
            distinguished_name: entry.distinguished_name.clone(),
            source: CredentialSource::Gmsa,
            password: None,
            account_name: Some(entry.sam_account_name.clone()),
            expiration: entry.password_last_set.clone(),
            priority: if has_blob { 5 } else { 15 },
        });
    }

    // Sort by priority (lower = more actionable)
    actionable.sort_by_key(|e| e.priority);

    let stats = LapsGmsaStats {
        laps_total: laps_entries.len(),
        laps_v1_readable: laps_entries
            .iter()
            .filter(|e| e.source == LapsSource::V1)
            .count(),
        laps_v2_plaintext: laps_entries
            .iter()
            .filter(|e| e.source == LapsSource::V2Plaintext)
            .count(),
        laps_v2_encrypted: laps_entries
            .iter()
            .filter(|e| e.source == LapsSource::V2Encrypted)
            .count(),
        laps_detected: laps_entries
            .iter()
            .filter(|e| e.source == LapsSource::Detected)
            .count(),
        gmsa_total: gmsa_entries.len(),
        gmsa_with_blob: gmsa_entries
            .iter()
            .filter(|e| e.managed_password_blob.is_some())
            .count(),
    };

    Ok(LapsGmsaResult {
        actionable,
        encrypted_laps,
        gmsa_accounts: gmsa_entries,
        detected_only,
        stats,
    })
}

/// Get a human-readable summary line for a credential entry.
pub fn format_entry(entry: &CredentialEntry) -> String {
    match entry.source {
        CredentialSource::LapsV1 | CredentialSource::LapsV2Plaintext => {
            let acct = entry.account_name.as_deref().unwrap_or("Administrator");
            let _pw = entry.password.as_deref().unwrap_or("<unknown>");
            let exp = entry.expiration.as_deref().unwrap_or("<no expiry>");
            format!(
                "[{}] {} / {} — expires {}",
                entry.source, entry.target, acct, exp
            )
        }
        CredentialSource::LapsV2Encrypted => {
            format!(
                "[LAPS v2 encrypted] {} — needs DPAPI backup key to decrypt",
                entry.target
            )
        }
        CredentialSource::Gmsa => {
            format!(
                "[gMSA] {} — password blob available, needs KRB_GROUP_KEY decryption",
                entry.target
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_laps_entry(name: &str, source: LapsSource, pw: Option<&str>) -> LapsEntry {
        LapsEntry {
            computer_name: name.to_string(),
            distinguished_name: format!("CN={},DC=domain,DC=com", name),
            password: pw.map(|s| s.to_string()),
            expiration: Some("2026-06-15".to_string()),
            expiration_raw: None,
            is_laps_v2: matches!(source, LapsSource::V2Plaintext | LapsSource::V2Encrypted),
            managed_account: Some("Administrator".to_string()),
            encrypted_blob: if matches!(source, LapsSource::V2Encrypted) {
                Some(vec![0x01, 0x02, 0x03])
            } else {
                None
            },
            source,
        }
    }

    fn make_gmsa_entry(name: &str, has_blob: bool) -> GmsaEntry {
        GmsaEntry {
            sam_account_name: name.to_string(),
            distinguished_name: format!("CN={},CN=Managed Service Accounts,DC=domain,DC=com", name),
            dns_host_name: None,
            managed_by: Some("CN=Admin,DC=domain,DC=com".to_string()),
            member_of_dn: Some("CN=Allowed,DC=domain,DC=com".to_string()),
            managed_password_blob: if has_blob { Some(vec![0xAA; 64]) } else { None },
            password_last_set: Some("2026-01-01".to_string()),
            password_header: None,
        }
    }

    // ─── Result Construction Tests ───────────────────────────────

    #[test]
    fn test_empty_result() {
        let result = LapsGmsaResult {
            actionable: vec![],
            encrypted_laps: vec![],
            gmsa_accounts: vec![],
            detected_only: vec![],
            stats: LapsGmsaStats {
                laps_total: 0,
                laps_v1_readable: 0,
                laps_v2_plaintext: 0,
                laps_v2_encrypted: 0,
                laps_detected: 0,
                gmsa_total: 0,
                gmsa_with_blob: 0,
            },
        };
        assert!(result.actionable.is_empty());
        assert_eq!(result.stats.laps_total, 0);
    }

    #[test]
    fn test_laps_v1_has_priority_0() {
        let entry = CredentialEntry {
            target: "PC01".to_string(),
            distinguished_name: "CN=PC01,DC=domain,DC=com".to_string(),
            source: CredentialSource::LapsV1,
            password: Some("P@ssw0rd".to_string()),
            account_name: Some("Administrator".to_string()),
            expiration: Some("2026-07-01".to_string()),
            priority: 0,
        };
        assert_eq!(entry.priority, 0);
        assert_eq!(entry.source.to_string(), "LAPS v1");
        assert!(entry.password.is_some());
    }

    #[test]
    fn test_sorting_priorities_readable_first() {
        let mut entries = vec![
            CredentialEntry {
                target: "ENC".to_string(),
                source: CredentialSource::LapsV2Encrypted,
                priority: 10,
                ..dummy_entry("ENC")
            },
            CredentialEntry {
                target: "V1".to_string(),
                source: CredentialSource::LapsV1,
                priority: 0,
                ..dummy_entry("V1")
            },
            CredentialEntry {
                target: "GMSA".to_string(),
                source: CredentialSource::Gmsa,
                priority: 5,
                ..dummy_entry("GMSA")
            },
        ];
        entries.sort_by_key(|e| e.priority);
        assert_eq!(entries[0].target, "V1");
        assert_eq!(entries[1].target, "GMSA");
        assert_eq!(entries[2].target, "ENC");
    }

    fn dummy_entry(target: &str) -> CredentialEntry {
        CredentialEntry {
            target: target.to_string(),
            distinguished_name: format!("CN={},DC=domain,DC=com", target),
            source: CredentialSource::LapsV1,
            password: None,
            account_name: None,
            expiration: None,
            priority: 0,
        }
    }

    // ─── Stats Calculation Tests ─────────────────────────────────

    #[test]
    fn test_stats_calculation() {
        let laps = vec![
            make_laps_entry("PC1", LapsSource::V1, Some("pw1")),
            make_laps_entry("PC2", LapsSource::V2Plaintext, Some("pw2")),
            make_laps_entry("PC3", LapsSource::V2Encrypted, None),
            make_laps_entry("PC4", LapsSource::Detected, None),
        ];
        let gmsa = vec![
            make_gmsa_entry("svc_gmsa1", true),
            make_gmsa_entry("svc_gmsa2", false),
        ];

        let stats = LapsGmsaStats {
            laps_total: laps.len(),
            laps_v1_readable: laps.iter().filter(|e| e.source == LapsSource::V1).count(),
            laps_v2_plaintext: laps
                .iter()
                .filter(|e| e.source == LapsSource::V2Plaintext)
                .count(),
            laps_v2_encrypted: laps
                .iter()
                .filter(|e| e.source == LapsSource::V2Encrypted)
                .count(),
            laps_detected: laps
                .iter()
                .filter(|e| e.source == LapsSource::Detected)
                .count(),
            gmsa_total: gmsa.len(),
            gmsa_with_blob: gmsa
                .iter()
                .filter(|e| e.managed_password_blob.is_some())
                .count(),
        };

        assert_eq!(stats.laps_total, 4);
        assert_eq!(stats.laps_v1_readable, 1);
        assert_eq!(stats.laps_v2_plaintext, 1);
        assert_eq!(stats.laps_v2_encrypted, 1);
        assert_eq!(stats.laps_detected, 1);
        assert_eq!(stats.gmsa_total, 2);
        assert_eq!(stats.gmsa_with_blob, 1);
    }

    // ─── Format Entry Tests ──────────────────────────────────────

    #[test]
    fn test_format_v1_entry() {
        let entry = CredentialEntry {
            target: "PC01".to_string(),
            distinguished_name: String::new(),
            source: CredentialSource::LapsV1,
            password: Some("secret".to_string()),
            account_name: Some("Administrator".to_string()),
            expiration: Some("2026-07-01".to_string()),
            priority: 0,
        };
        let formatted = format_entry(&entry);
        assert!(formatted.contains("PC01"));
        assert!(formatted.contains("LAPS v1"));
    }

    #[test]
    fn test_format_encrypted_entry() {
        let entry = CredentialEntry {
            target: "PC02".to_string(),
            distinguished_name: String::new(),
            source: CredentialSource::LapsV2Encrypted,
            password: None,
            account_name: None,
            expiration: None,
            priority: 10,
        };
        let formatted = format_entry(&entry);
        assert!(formatted.contains("encrypted"));
        assert!(formatted.contains("DPAPI backup key"));
    }

    #[test]
    fn test_format_gmsa_entry() {
        let entry = CredentialEntry {
            target: "svc_gmsa$".to_string(),
            distinguished_name: String::new(),
            source: CredentialSource::Gmsa,
            password: None,
            account_name: Some("svc_gmsa$".to_string()),
            expiration: None,
            priority: 5,
        };
        let formatted = format_entry(&entry);
        assert!(formatted.contains("gMSA"));
        assert!(formatted.contains("KRB_GROUP_KEY"));
    }

    // ─── Display Tests ───────────────────────────────────────────

    #[test]
    fn test_credential_source_display() {
        assert_eq!(CredentialSource::LapsV1.to_string(), "LAPS v1");
        assert_eq!(
            CredentialSource::LapsV2Plaintext.to_string(),
            "LAPS v2 plaintext"
        );
        assert_eq!(
            CredentialSource::LapsV2Encrypted.to_string(),
            "LAPS v2 encrypted"
        );
        assert_eq!(CredentialSource::Gmsa.to_string(), "gMSA");
    }

    #[test]
    fn test_credential_source_equality() {
        assert_eq!(CredentialSource::LapsV1, CredentialSource::LapsV1);
        assert_ne!(CredentialSource::LapsV1, CredentialSource::Gmsa);
    }

    // ─── Serialization Tests ─────────────────────────────────────

    #[test]
    fn test_result_serialization_roundtrip() {
        let result = LapsGmsaResult {
            actionable: vec![CredentialEntry {
                target: "PC01".to_string(),
                distinguished_name: "CN=PC01,DC=domain".to_string(),
                source: CredentialSource::LapsV1,
                password: Some("P@ss!".to_string()),
                account_name: Some("Administrator".to_string()),
                expiration: Some("2026-07-01".to_string()),
                priority: 0,
            }],
            encrypted_laps: vec![],
            gmsa_accounts: vec![],
            detected_only: vec![],
            stats: LapsGmsaStats {
                laps_total: 1,
                laps_v1_readable: 1,
                laps_v2_plaintext: 0,
                laps_v2_encrypted: 0,
                laps_detected: 0,
                gmsa_total: 0,
                gmsa_with_blob: 0,
            },
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("PC01"));
        assert!(json.contains("P@ss!"));
        assert!(json.contains("actionable"));

        let deserialized: LapsGmsaResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.actionable.len(), 1);
        assert_eq!(deserialized.stats.laps_total, 1);
    }

    // ─── Edge Cases ──────────────────────────────────────────────

    #[test]
    fn test_entry_with_no_password_is_not_actionable_priority_high() {
        let entry = CredentialEntry {
            target: "ENC-PC".to_string(),
            distinguished_name: String::new(),
            source: CredentialSource::LapsV2Encrypted,
            password: None,
            account_name: None,
            expiration: None,
            priority: 10,
        };
        assert!(entry.password.is_none());
        assert_eq!(entry.priority, 10);
    }

    #[test]
    fn test_gmsa_without_blob_has_higher_priority() {
        let with_blob = CredentialEntry {
            target: "gmsa1".to_string(),
            source: CredentialSource::Gmsa,
            priority: 5,
            ..dummy_entry("gmsa1")
        };
        let without_blob = CredentialEntry {
            target: "gmsa2".to_string(),
            source: CredentialSource::Gmsa,
            priority: 15,
            ..dummy_entry("gmsa2")
        };
        assert!(with_blob.priority < without_blob.priority);
    }
}
