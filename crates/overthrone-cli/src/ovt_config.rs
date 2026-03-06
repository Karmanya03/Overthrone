//! TOML configuration file support for Overthrone.
//!
//! Supports loading a config file from:
//!   1. `--config <path>` CLI flag
//!   2. `OT_CONFIG` environment variable
//!   3. `~/.overthrone/config.toml`  (automatic if present)
//!   4. `./overthrone.toml`          (CWD fallback)
//!
//! # Example config
//! ```toml
//! [targets]
//! dc       = "10.10.10.161"
//! domain   = "htb.local"
//!
//! [credentials]
//! username = "administrator"
//! password = "Password123!"
//! # nt_hash = "aad3b435b51404eeaad3b435b51404ee:..."
//!
//! [wordlists]
//! passwords = "/usr/share/wordlists/rockyou.txt"
//! users     = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
//!
//! [options]
//! ldaps    = false
//! jitter   = 500
//! opsec    = "medium"   # low | medium | high | silent
//! dryrun   = false
//! ```

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverthroneConfig {
    #[serde(default)]
    pub targets: TargetsConfig,

    #[serde(default)]
    pub credentials: CredentialsConfig,

    #[serde(default)]
    pub wordlists: WordlistsConfig,

    #[serde(default)]
    pub options: OptionsConfig,

    #[serde(default)]
    pub exclusions: ExclusionsConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetsConfig {
    /// Primary DC IP or hostname
    pub dc: Option<String>,
    /// AD domain (e.g. corp.local)
    pub domain: Option<String>,
    /// Additional target hosts
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Out-of-scope hosts/subnets
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialsConfig {
    pub username: Option<String>,
    /// Plaintext password (prefer nt_hash for OPSEC)
    pub password: Option<String>,
    /// NT hash (pass-the-hash)
    pub nt_hash: Option<String>,
    /// Path to Kerberos ccache file
    pub ticket: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WordlistsConfig {
    /// Password wordlist for spray/brute
    pub passwords: Option<String>,
    /// Username list
    pub users: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptionsConfig {
    /// Use LDAPS (port 636) instead of plain LDAP
    #[serde(default)]
    pub ldaps: bool,
    /// Jitter in milliseconds between actions
    #[serde(default)]
    pub jitter: u64,
    /// OPSEC profile: "low" | "medium" | "high" | "silent"
    #[serde(default = "default_opsec")]
    pub opsec: String,
    /// Dry-run: plan but don't execute
    #[serde(default)]
    pub dryrun: bool,
    /// Maximum threads / parallelism
    #[serde(default = "default_threads")]
    pub threads: usize,
    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExclusionsConfig {
    /// Users to never attack (e.g. krbtgt, service accounts)
    #[serde(default)]
    pub users: Vec<String>,
    /// Hosts to skip
    #[serde(default)]
    pub hosts: Vec<String>,
}

fn default_opsec() -> String {
    "medium".to_string()
}
fn default_threads() -> usize {
    4
}
fn default_timeout() -> u64 {
    10
}

impl OverthroneConfig {
    /// Load config from the given path or auto-discover.
    pub fn load(path: Option<&str>) -> Result<Self, String> {
        let config_path = match path {
            Some(p) => PathBuf::from(p),
            None => {
                // Check OT_CONFIG env var
                if let Ok(env_path) = std::env::var("OT_CONFIG") {
                    PathBuf::from(env_path)
                } else {
                    // Try ~/.overthrone/config.toml then ./overthrone.toml
                    let home_config = dirs_home().join(".overthrone").join("config.toml");
                    let cwd_config = PathBuf::from("overthrone.toml");
                    if home_config.exists() {
                        home_config
                    } else if cwd_config.exists() {
                        cwd_config
                    } else {
                        // No config file found — return defaults silently
                        return Ok(Self::default());
                    }
                }
            }
        };

        Self::from_file(&config_path)
    }

    /// Parse a TOML config file.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read config {}: {}", path.display(), e))?;

        toml::from_str(&content)
            .map_err(|e| format!("Config parse error in {}: {}", path.display(), e))
    }

    /// Apply CLI overrides: values explicitly passed on the command line
    /// take precedence over config file values.
    #[allow(dead_code)]
    pub fn apply_cli_override(&mut self, key: &str, value: &str) {
        match key {
            "dc"       => self.targets.dc       = Some(value.to_string()),
            "domain"   => self.targets.domain   = Some(value.to_string()),
            "username" => self.credentials.username = Some(value.to_string()),
            "password" => self.credentials.password = Some(value.to_string()),
            "nt_hash"  => self.credentials.nt_hash  = Some(value.to_string()),
            "ticket"   => self.credentials.ticket   = Some(value.to_string()),
            "opsec"    => self.options.opsec     = value.to_string(),
            _ => {}
        }
    }

    /// Write the current config to a TOML file (useful for --init-config).
    #[allow(dead_code)]
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create config dir: {}", e))?;
        }
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| format!("Config serialization error: {}", e))?;
        std::fs::write(path, toml_str)
            .map_err(|e| format!("Cannot write config {}: {}", path.display(), e))
    }
}

fn dirs_home() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| {
                std::env::var("HOMEDRIVE").and_then(|d| {
                    std::env::var("HOMEPATH").map(|p| format!("{}{}", d, p))
                })
            })
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }
}
