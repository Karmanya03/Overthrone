//! Certificate auto-enrollment — CES (WS-Trust) and ICertPassage enrollment.
//!
//! Implements two enrollment paths for ESC9/ESC10 attack patterns:
//!
//! - **EnrolmentWebServiceClient**: HTTP-based CES (Certificate Enrollment Web Services)
//!   using SOAP/XML requests.  WS2025+ CAs commonly disable the legacy `/certsrv`
//!   endpoint but leave CES accessible on `/ADPolicyProvider/CEP/...` and
//!   `/ADPolicyProvider/ CES/...`.
//!
//! - **CertAutoEnroll**: High-level orchestrator that wraps either the RPC-based
//!   [`ICertPassage`](crate::icert_passage) enrollment or the CES HTTP enrollment
//!   based on what the target CA supports.
//!
//! References:
//! - MS-WSTEP: WS-Trust Enrollment Protocol
//! - MS-ICPR: ICertPassage Protocol Specification

use base64::Engine;
use overthrone_core::error::{OverthroneError, Result};
use tracing::{debug, info};

// ═══════════════════════════════════════════════════════════
// EnrolmentWebServiceClient — CES HTTP enrollment
// ═══════════════════════════════════════════════════════════

/// HTTP client for Certificate Enrollment Web Services (CES).
///
/// Communicates with the CA's CES endpoint (`/ADPolicyProvider/...`) via
/// SOAP/XML-based WS-Trust messages.
pub struct EnrolmentWebServiceClient {
    ca_server: String,
    use_ssl: bool,
    http_client: reqwest::Client,
}

impl EnrolmentWebServiceClient {
    /// Create a new CES client for the given CA server.
    pub fn new(ca_server: &str) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(|e| OverthroneError::Connection {
                target: ca_server.to_string(),
                reason: format!("CES HTTP client creation failed: {e}"),
            })?;

        Ok(Self {
            ca_server: ca_server.to_string(),
            use_ssl: true,
            http_client,
        })
    }

    /// Disable SSL (use HTTP instead of HTTPS).
    pub fn disable_ssl(&mut self) {
        self.use_ssl = false;
    }

    /// Build the base URL for CES requests.
    fn base_url(&self) -> String {
        let scheme = if self.use_ssl { "https" } else { "http" };
        format!("{scheme}://{}/ADPolicyProvider/CEP/", self.ca_server)
    }

    /// Retrieve certificate enrollment policy from the CA's CEP endpoint.
    pub async fn get_policy(&self, template: &str) -> Result<String> {
        let url = format!("{}certificate", self.base_url());
        let soap_body = build_soap_policy_request(template);

        let resp = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/soap+xml")
            .body(soap_body)
            .send()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: self.ca_server.clone(),
                reason: format!("CES get_policy request failed: {e}"),
            })?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| OverthroneError::Connection {
            target: self.ca_server.clone(),
            reason: format!("CES get_policy read body failed: {e}"),
        })?;

        if !status.is_success() {
            return Err(OverthroneError::Connection {
                target: self.ca_server.clone(),
                reason: format!("CES get_policy returned HTTP {status}"),
            });
        }

        debug!("[CES] Policy retrieved for template {}", template);
        Ok(body)
    }

    /// Submit a PKCS#10 CSR to the CA via the CES endpoint.
    pub async fn submit_request(&self, csr_pkcs10_der: &[u8], template: &str) -> Result<Vec<u8>> {
        let url = self.base_url().replace("/CEP/", "/CES/");
        let request_soap = build_soap_certificate_request(csr_pkcs10_der, template);

        let resp = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/soap+xml")
            .body(request_soap)
            .send()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: self.ca_server.clone(),
                reason: format!("CES submit_request failed: {e}"),
            })?;

        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: self.ca_server.clone(),
                reason: format!("CES submit_request read body failed: {e}"),
            })?;

        if !status.is_success() {
            return Err(OverthroneError::Connection {
                target: self.ca_server.clone(),
                reason: format!("CES submit_request returned HTTP {status}"),
            });
        }

        // Parse the SOAP response to extract the issued certificate (PKCS#7 DER blob)
        let cert_der = extract_ces_certificate(&body)?;
        info!("[CES] Certificate obtained ({} bytes)", cert_der.len());
        Ok(cert_der)
    }
}

/// Build a minimal SOAP policy request body.
fn build_soap_policy_request(_template: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://www.w3.org/2005/08/addressing"
               xmlns:cep="http://schemas.microsoft.com/windows/pki/2009/A08/cep">
  <soap:Header>
    <wsa:Action>http://schemas.microsoft.com/windows/pki/2009/A08/cep/GetPolicies</wsa:Action>
    <wsa:MessageID>urn:uuid:aabbccdd-0000-0000-0000-000000000001</wsa:MessageID>
    <wsa:To>https://dummy/ADPolicyProvider/CEP/</wsa:To>
  </soap:Header>
  <soap:Body>
    <cep:GetPolicies>
      <cep:filters>
        <cep:filter>
          <cep:template>{_template}</cep:template>
        </cep:filter>
      </cep:filters>
    </cep:GetPolicies>
  </soap:Body>
</soap:Envelope>"#,
    )
}

/// Build a minimal SOAP certificate request body.
fn build_soap_certificate_request(csr: &[u8], template: &str) -> String {
    let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr);
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://www.w3.org/2005/08/addressing"
               xmlns:est="http://schemas.microsoft.com/windows/pki/2009/A08/est">
  <soap:Header>
    <wsa:Action>http://schemas.microsoft.com/windows/pki/2009/A08/est/Request</wsa:Action>
    <wsa:MessageID>urn:uuid:aabbccdd-0000-0000-0000-000000000002</wsa:MessageID>
    <wsa:To>https://dummy/ADPolicyProvider/CES/</wsa:To>
  </soap:Header>
  <soap:Body>
    <est:Request>
      <est:Template>{template}</est:Template>
      <est:BinaryRequest>{csr_b64}</est:BinaryRequest>
    </est:Request>
  </soap:Body>
</soap:Envelope>"#,
    )
}

/// Extract a DER certificate from a CES SOAP response.
fn extract_ces_certificate(resp: &[u8]) -> Result<Vec<u8>> {
    // Scan for DER SEQUENCE start marker (0x30)
    for i in 0..resp.len().saturating_sub(4) {
        if resp[i] == 0x30 {
            let len_byte = resp[i + 1];
            if len_byte < 0x80 {
                let total = 2 + len_byte as usize;
                if i + total <= resp.len() {
                    return Ok(resp[i..i + total].to_vec());
                }
            } else {
                let num_len_bytes = (len_byte & 0x7f) as usize;
                if num_len_bytes > 0 && num_len_bytes <= 4 && i + 2 + num_len_bytes <= resp.len() {
                    let mut der_len = 0usize;
                    for j in 0..num_len_bytes {
                        der_len = (der_len << 8) | resp[i + 2 + j] as usize;
                    }
                    let total = 2 + num_len_bytes + der_len;
                    if i + total <= resp.len() {
                        return Ok(resp[i..i + total].to_vec());
                    }
                }
            }
        }
    }

    Err(OverthroneError::CertificateRequest(
        "Failed to extract certificate from CES response".to_string(),
    ))
}

// ═══════════════════════════════════════════════════════════
// CertAutoEnroll — high-level orchestrator
// ═══════════════════════════════════════════════════════════

/// Which enrollment path to use for automatic certificate enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentPath {
    /// RPC-based ICertPassage enrollment (MS-ICPR).
    Rpc,
    /// HTTP-based CES enrollment (MS-WSTEP).
    Ces,
}

/// High-level orchestrator for ESC9/10 certificate auto-enrollment.
///
/// Supports both RPC (ICertPassage) and CES (HTTP) enrollment paths.
pub struct CertAutoEnroll {
    ca_server: String,
    ca_name: String,
    path: EnrollmentPath,
}

impl CertAutoEnroll {
    /// Create a new auto-enrollment orchestrator.
    pub fn new(ca_server: &str, ca_name: &str, path: EnrollmentPath) -> Self {
        Self {
            ca_server: ca_server.to_string(),
            ca_name: ca_name.to_string(),
            path,
        }
    }

    /// The target CA server address.
    pub fn ca_server(&self) -> &str {
        &self.ca_server
    }

    /// The target CA name.
    pub fn ca_name(&self) -> &str {
        &self.ca_name
    }

    /// The configured enrollment path.
    pub fn enrollment_path(&self) -> EnrollmentPath {
        self.path
    }

    /// Request a certificate via the configured enrollment path.
    ///
    /// # Arguments
    /// * `template` - Certificate template name
    /// * `subject` - Subject string (e.g. "CN=overthrone-esc9")
    /// * `csr_der` - PKCS#10 DER-encoded CSR
    ///
    /// # Returns
    /// Raw DER-encoded X.509 certificate bytes.
    pub async fn request_certificate(
        &self,
        _template: &str,
        _subject: &str,
        _csr_der: &[u8],
    ) -> Result<Vec<u8>> {
        match self.path {
            EnrollmentPath::Ces => {
                info!(
                    "[CertAutoEnroll] CES enrollment: CA={}, template={}",
                    self.ca_server, _template
                );
                let client = EnrolmentWebServiceClient::new(&self.ca_server)?;
                client.submit_request(_csr_der, _template).await
            }
            EnrollmentPath::Rpc => Err(OverthroneError::Adcs(
                "RPC-based auto-enrollment requires an authenticated SMB session; \
                     use RemoteCertService directly"
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_path_default() {
        assert_eq!(EnrollmentPath::Rpc as u8, 0);
        assert_eq!(EnrollmentPath::Ces as u8, 1);
    }

    #[test]
    fn test_cert_auto_enroll_new() {
        let enroll = CertAutoEnroll::new("ca.corp.local", "corp-CA", EnrollmentPath::Ces);
        assert_eq!(enroll.ca_server(), "ca.corp.local");
        assert_eq!(enroll.ca_name(), "corp-CA");
        assert_eq!(enroll.enrollment_path(), EnrollmentPath::Ces);
    }

    #[test]
    fn test_build_soap_request_contains_template() {
        let csr = b"\x30\x82\x03\x21\x02\x01\x00\x30\x0c\x06\x03\x55\x04\x03\x0c\x05\x6f\x76\x74\x65\x73\x74";
        let soap = build_soap_certificate_request(csr, "User");
        assert!(soap.contains("User"));
        assert!(soap.contains("BinaryRequest"));
        assert!(soap.contains("soap:Envelope"));
    }

    #[test]
    fn test_extract_ces_certificate_simple_der() {
        let der = b"\x30\x05\x02\x03\x01\x02\x03";
        let result = extract_ces_certificate(der);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), der);
    }

    #[test]
    fn test_extract_ces_certificate_long_form() {
        // DER with long-form length: 0x30 0x82 0x01 0x00 (256 bytes of content)
        let mut buf = vec![0x30, 0x82, 0x01, 0x00];
        buf.resize(4 + 256, 0xAA);

        let result = extract_ces_certificate(&buf);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 4 + 256);
    }

    #[test]
    fn test_extract_ces_certificate_not_found() {
        let result = extract_ces_certificate(b"<xml>no cert</xml>");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_soap_policy_request() {
        let soap = build_soap_policy_request("Machine");
        assert!(soap.contains("GetPolicies"));
        assert!(soap.contains("Machine"));
    }
}
