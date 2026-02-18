use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Master configuration for an Overthrone session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverthroneConfig {
    /// Target domain controller IP or hostname
    pub target: String,
    /// Target domain FQDN (e.g., "corp.local")
    pub domain: String,
    /// Authentication configuration
    pub auth: AuthConfig,
    /// Output format for results
    pub output_format: OutputFormat,
    /// Enable verbose/debug logging
    pub verbose: bool,
    /// Number of concurrent threads for enumeration
    pub threads: usize,
    /// Connection timeout
    pub timeout: Duration,
    /// Stealth options
    pub stealth: StealthConfig,
    /// Output directory for reports and exports
    pub output_dir: PathBuf,
}

/// Authentication methods supported by Overthrone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthConfig {
    /// Plaintext username + password
    Password {
        username: String,
        password: String,
    },
    /// Pass-the-Hash with NTLM hash
    NtlmHash {
        username: String,
        hash: String,
    },
    /// Pass-the-Ticket with .kirbi or .ccache file
    Ticket {
        path: PathBuf,
    },
    /// Certificate-based auth (PKINIT) with PFX file
    Certificate {
        pfx_path: PathBuf,
        password: String,
    },
}

/// Output format for tool results
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub enum OutputFormat {
    #[default]
    Json,
    Table,
    Raw,
    BloodHound,
    Csv,
}

/// Stealth/OPSEC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    /// Random delay between requests (milliseconds)
    pub jitter_ms: u64,
    /// Randomize enumeration order
    pub randomize_order: bool,
    /// Avoid known honeypot indicators
    pub avoid_honeypots: bool,
    /// Max LDAP page size (lower = stealthier)
    pub ldap_page_size: u32,
    /// Delay between LDAP queries
    pub ldap_delay_ms: u64,
}

impl Default for OverthroneConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            domain: String::new(),
            auth: AuthConfig::Password {
                username: String::new(),
                password: String::new(),
            },
            output_format: OutputFormat::Json,
            verbose: false,
            threads: 10,
            timeout: Duration::from_secs(30),
            stealth: StealthConfig::default(),
            output_dir: PathBuf::from("./output"),
        }
    }
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            jitter_ms: 0,
            randomize_order: false,
            avoid_honeypots: true,
            ldap_page_size: 1000,
            ldap_delay_ms: 0,
        }
    }
}

impl OverthroneConfig {
    /// Build the LDAP URL from target config
    pub fn ldap_url(&self) -> String {
        format!("ldap://{}:389", self.target)
    }

    /// Build the LDAPS URL from target config
    pub fn ldaps_url(&self) -> String {
        format!("ldaps://{}:636", self.target)
    }

    /// Get the domain's base DN (e.g., "corp.local" → "DC=corp,DC=local")
    pub fn base_dn(&self) -> String {
        self.domain
            .split('.')
            .map(|part| format!("DC={part}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Get bind credentials as (username@domain, password) if password auth
    pub fn bind_creds(&self) -> Option<(String, String)> {
        match &self.auth {
            AuthConfig::Password { username, password } => {
                let upn = if username.contains('@') || username.contains('\\') {
                    username.clone()
                } else {
                    format!("{username}@{}", self.domain)
                };
                Some((upn, password.clone()))
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Table => write!(f, "table"),
            Self::Raw => write!(f, "raw"),
            Self::BloodHound => write!(f, "bloodhound"),
            Self::Csv => write!(f, "csv"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            "raw" => Ok(Self::Raw),
            "bloodhound" | "bh" => Ok(Self::BloodHound),
            "csv" => Ok(Self::Csv),
            _ => Err(format!("Unknown output format: '{s}'")),
        }
    }
}
