//! Credential store — thread-safe vault for discovered credentials.
//!
//! All modules that harvest credentials (secretsdump, dcsync, kerberoast,
//! spray, LAPS, etc.) push entries here. The autopwn runner pulls
//! from the store to try newly discovered credentials on other hosts.
//!
//! # Design
//! - `Arc<CredStore>` is shared across all executor threads.
//! - Entries are deduplicated by (domain, username, secret).
//! - Entries are ranked by privilege level so the runner can prefer DA
//!   credentials over regular user credentials.
//! - Persistence: the vault can be serialized to JSON (same as session state).

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// ─── Public Entry Types ───────────────────────────────────────────────────────

/// Privilege tier of a credential (higher = better)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CredPrivilege {
    Unknown = 0,
    LocalAdmin = 1,
    ServiceAccount = 2,
    DomainUser = 3,
    DomainAdmin = 4,
    EnterpriseAdmin = 5,
    DcSync = 6,
}

impl Default for CredPrivilege {
    fn default() -> Self {
        CredPrivilege::Unknown
    }
}

/// The credential secret — either a plaintext password or an NT hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredSecret {
    Password(String),
    NtHash(String),
    /// ntlm hash stored as LM:NT colon form
    NtlmPair { lm: String, nt: String },
    /// Kerberos ticket cache path
    TicketPath(String),
}

impl CredSecret {
    /// Get the NT hash if this is a hash-type secret
    pub fn nt_hash(&self) -> Option<&str> {
        match self {
            CredSecret::NtHash(h) => Some(h),
            CredSecret::NtlmPair { nt, .. } => Some(nt),
            _ => None,
        }
    }

    /// Get plaintext password if available
    pub fn password(&self) -> Option<&str> {
        match self {
            CredSecret::Password(p) => Some(p),
            _ => None,
        }
    }

    /// Returns `true` if this is a hash (no cleartext available)
    pub fn is_hash(&self) -> bool {
        matches!(self, CredSecret::NtHash(_) | CredSecret::NtlmPair { .. })
    }
}

impl std::fmt::Display for CredSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredSecret::Password(p) => write!(f, "{}", p),
            CredSecret::NtHash(h) => write!(f, "{}", h),
            CredSecret::NtlmPair { lm, nt } => write!(f, "{}:{}", lm, nt),
            CredSecret::TicketPath(p) => write!(f, "ticket:{}", p),
        }
    }
}

/// Source that produced this credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredSource {
    Sam,
    Lsa,
    Ntds,
    Dcc2,
    DcSync,
    Kerberoast,
    AsRepRoast,
    GppDecrypt,
    Laps,
    PasswordSpray,
    Manual,
    Other(String),
}

impl std::fmt::Display for CredSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CredSource::Sam => "SAM",
            CredSource::Lsa => "LSA",
            CredSource::Ntds => "NTDS",
            CredSource::Dcc2 => "DCC2",
            CredSource::DcSync => "DCSync",
            CredSource::Kerberoast => "Kerberoast",
            CredSource::AsRepRoast => "AS-REP",
            CredSource::GppDecrypt => "GPP",
            CredSource::Laps => "LAPS",
            CredSource::PasswordSpray => "Spray",
            CredSource::Manual => "Manual",
            CredSource::Other(o) => o,
        };
        write!(f, "{}", s)
    }
}

/// A single credential entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredEntry {
    pub domain: String,
    pub username: String,
    pub secret: CredSecret,
    pub privilege: CredPrivilege,
    pub source: CredSource,
    pub source_host: Option<String>,
    pub cracked: bool,
    /// When this entry was added (Unix timestamp seconds)
    pub added_at: u64,
}

impl CredEntry {
    pub fn new(
        domain: impl Into<String>,
        username: impl Into<String>,
        secret: CredSecret,
        source: CredSource,
    ) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            domain: domain.into(),
            username: username.into(),
            secret,
            privilege: CredPrivilege::Unknown,
            source,
            source_host: None,
            cracked: false,
            added_at: ts,
        }
    }

    /// Unique key for deduplication: domain\username:secret
    fn dedup_key(&self) -> String {
        format!(
            "{}\\{}:{}",
            self.domain.to_lowercase(),
            self.username.to_lowercase(),
            self.secret
        )
    }
}

// ─── CredStore ────────────────────────────────────────────────────────────────

/// Thread-safe credential vault.
///
/// Wrap in `Arc<CredStore>` and share across modules.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CredStore {
    entries: Mutex<Vec<CredEntry>>,
}

impl CredStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in `Arc` for sharing across threads.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Add a credential entry. Deduplicates by (domain, username, secret).
    /// Returns `true` if the entry was new, `false` if already present.
    pub fn insert(&self, entry: CredEntry) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let key = entry.dedup_key();
        if entries.iter().any(|e| e.dedup_key() == key) {
            return false;
        }
        entries.push(entry);
        true
    }

    /// Insert many entries, returning count of NEW entries added.
    pub fn insert_all(&self, new_entries: impl IntoIterator<Item = CredEntry>) -> usize {
        let mut count = 0;
        for e in new_entries {
            if self.insert(e) {
                count += 1;
            }
        }
        count
    }

    /// Find credentials for a specific user in a domain.
    pub fn get(&self, domain: &str, username: &str) -> Vec<CredEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| {
                e.domain.eq_ignore_ascii_case(domain)
                    && e.username.eq_ignore_ascii_case(username)
            })
            .cloned()
            .collect()
    }

    /// Get highest-privilege credentials available for any user.
    pub fn best_creds(&self) -> Option<CredEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.cracked || !e.secret.is_hash())
            .max_by_key(|e| e.privilege.clone())
            .cloned()
    }

    /// Get all domain admin / DA-equivalent credentials.
    pub fn da_creds(&self) -> Vec<CredEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| {
                e.privilege >= CredPrivilege::DomainAdmin
            })
            .cloned()
            .collect()
    }

    /// Get all entries (for reporting / JSON output).
    pub fn all(&self) -> Vec<CredEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Total entry count.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Mark a hash entry as cracked with a plaintext password.
    pub fn mark_cracked(&self, domain: &str, username: &str, plaintext: &str) {
        let mut entries = self.entries.lock().unwrap();
        for entry in entries.iter_mut() {
            if entry.domain.eq_ignore_ascii_case(domain)
                && entry.username.eq_ignore_ascii_case(username)
                && entry.secret.is_hash()
            {
                entry.secret = CredSecret::Password(plaintext.to_string());
                entry.cracked = true;
            }
        }
    }

    /// Update privilege level for all entries matching (domain, username).
    pub fn set_privilege(&self, domain: &str, username: &str, priv_level: CredPrivilege) {
        let mut entries = self.entries.lock().unwrap();
        for entry in entries.iter_mut() {
            if entry.domain.eq_ignore_ascii_case(domain)
                && entry.username.eq_ignore_ascii_case(username)
            {
                if priv_level > entry.privilege {
                    entry.privilege = priv_level.clone();
                }
            }
        }
    }

    /// Export all entries keyed by "DOMAIN\username" for quick lookup.
    pub fn as_map(&self) -> HashMap<String, CredEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .map(|e| {
                let key = format!("{}\\{}", e.domain.to_lowercase(), e.username.to_lowercase());
                (key, e.clone())
            })
            .collect()
    }

    /// Serialize vault to pretty JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let entries = self.entries.lock().unwrap();
        serde_json::to_string_pretty(entries.as_slice())
    }

    /// Save vault to file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = self
            .to_json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load vault from file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read cred store {}: {}", path.display(), e))?;
        let entries: Vec<CredEntry> = serde_json::from_str(&data)
            .map_err(|e| format!("Parse error: {}", e))?;
        Ok(Self {
            entries: Mutex::new(entries),
        })
    }
}

/// Convenience: build a `CredEntry` from a SAM dump result.
pub fn from_sam_credential(
    cred: &crate::proto::secretsdump::SamCredential,
    domain: &str,
) -> CredEntry {
    let secret = match &cred.nt_hash {
        Some(nt) => {
            let lm = cred
                .lm_hash
                .as_deref()
                .unwrap_or("aad3b435b51404eeaad3b435b51404ee")
                .to_string();
            CredSecret::NtlmPair { lm, nt: nt.clone() }
        }
        None => CredSecret::NtHash("31d6cfe0d16ae931b73c59d7e0c089c0".to_string()),
    };
    CredEntry::new(domain, &cred.username, secret, CredSource::Sam)
}

/// Convenience: build a `CredEntry` from an LSA secrets result.
pub fn from_lsa_credential(
    cred: &crate::proto::secretsdump::LsaCredential,
    domain: &str,
) -> CredEntry {
    let secret = if let Some(ref p) = cred.plaintext {
        CredSecret::Password(p.clone())
    } else if let Some(ref h) = cred.nt_hash {
        CredSecret::NtHash(h.clone())
    } else {
        CredSecret::NtHash("31d6cfe0d16ae931b73c59d7e0c089c0".to_string())
    };
    CredEntry::new(domain, &cred.username, secret, CredSource::Lsa)
}
