//! LDAP Certificate Template Enumeration
//!
//! Queries Active Directory for certificate templates and CA configurations
//! to identify ESC vulnerabilities.

use crate::error::Result;
use crate::proto::ldap::LdapSession;
use ldap3::SearchEntry;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════
// LDAP OIDs and Attribute Names
// ═══════════════════════════════════════════════════════════

/// Certificate Template schema ID GUID
pub const CERTIFICATE_TEMPLATE_GUID: &str = "e5209ca2-3bba-11d2-907b-00c04fd2d15a";

/// PKI Certificate Template object class
pub const PKI_CERT_TEMPLATE_CLASS: &str = "pKICertificateTemplate";

/// Certificate Authority object class  
pub const CERT_AUTHORITY_CLASS: &str = "certificationAuthority";

/// Enrollment Service object class
pub const ENROLLMENT_SERVICE_CLASS: &str = "pKIEnrollmentService";

// Certificate Template Flags
pub const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;
pub const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME: u32 = 0x00010000;
pub const CT_FLAG_SUBJECT_ALT_NAME_REQUIRE_EMAIL: u32 = 0x00000004;
pub const CT_FLAG_SUBJECT_ALT_NAME_REQUIRE_DNS: u32 = 0x40000000;
pub const CT_FLAG_SUBJECT_ALT_NAME_REQUIRE_DIRECTORY_GUID: u32 = 0x00100000;
pub const CT_FLAG_SUBJECT_ALT_NAME_REQUIRE_UPN: u32 = 0x00200000;
pub const CT_FLAG_SUBJECT_ALT_NAME_REQUIRE_SPN: u32 = 0x00400000;
pub const CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN: u32 = 0x00800000;
pub const CT_FLAG_SUBJECT_REQUIRE_EMAIL: u32 = 0x01000000;
pub const CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME: u32 = 0x10000000;
pub const CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH: u32 = 0x80000000;
pub const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;
pub const CT_FLAG_EXPORTABLE_KEY: u32 = 0x00000004;
pub const CT_FLAG_ARCHIVED_KEY: u32 = 0x00000040;
pub const CT_FLAG_STRONG_KEY_PROTECTION: u32 = 0x00000200;

// ═══════════════════════════════════════════════════════════
// Template Types
// ═══════════════════════════════════════════════════════════

/// LDAP Certificate Template with full configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapCertificateTemplate {
    pub name: String,
    pub display_name: String,
    pub oid: String,
    pub flags: u32,
    pub subject_name_flags: u32,
    pub enrollment_flags: u32,
    pub private_key_flags: u32,
    pub schema_version: u32,
    pub validity_period: String,
    pub renewal_period: String,
    pub extended_key_usage: Vec<String>,
    pub application_policies: Vec<String>,
    pub issuance_policies: Vec<String>,
    pub authorized_signatures_required: u32,
    pub security_descriptor: String,
    pub dn: String,
}

impl LdapCertificateTemplate {
    /// Check if template allows enrollee to supply subject
    pub fn allows_enrollee_subject(&self) -> bool {
        (self.subject_name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0
            || (self.subject_name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME) != 0
    }

    /// Check if template requires manager approval
    pub fn requires_manager_approval(&self) -> bool {
        (self.flags & CT_FLAG_PEND_ALL_REQUESTS) != 0
    }

    /// Check if template allows private key export
    pub fn allows_key_export(&self) -> bool {
        (self.private_key_flags & CT_FLAG_EXPORTABLE_KEY) != 0
    }

    /// Check if template has any purpose EKU
    pub fn has_any_purpose(&self) -> bool {
        self.extended_key_usage.iter().any(|eku| {
            eku == "2.5.29.37.0" || // Any Purpose
            eku.to_lowercase().contains("any purpose")
        })
    }

    /// Check if template is an enrollment agent
    pub fn is_enrollment_agent(&self) -> bool {
        self.extended_key_usage.iter().any(|eku| {
            eku == "1.3.6.1.4.1.311.20.2.1" || // Certificate Request Agent
            eku.to_lowercase().contains("request agent")
        })
    }

    /// Determine ESC vulnerability
    pub fn esc_vulnerability(&self) -> Option<u8> {
        // ESC1: Any Purpose + SAN allowed + no manager approval
        if self.has_any_purpose()
            && self.allows_enrollee_subject()
            && !self.requires_manager_approval()
        {
            return Some(1);
        }

        // ESC2: Any Purpose (can be used for any purpose)
        if self.has_any_purpose() && !self.requires_manager_approval() {
            return Some(2);
        }

        // ESC3: Enrollment Agent template
        if self.is_enrollment_agent() {
            return Some(3);
        }

        // ESC4: Weak ACLs (checked separately via security descriptor)
        None
    }
}

// ═══════════════════════════════════════════════════════════
// CA Configuration Types
// ═══════════════════════════════════════════════════════════

/// Certification Authority from LDAP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapCertificationAuthority {
    pub name: String,
    pub dn: String,
    pub ca_certificate: Option<Vec<u8>>,
    pub certificate_templates: Vec<String>,
    pub security_descriptor: String,
    pub enrollment_endpoints: Vec<String>,
}

/// CA Configuration Flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfiguration {
    pub ca_name: String,
    pub dn: String,
    /// EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
    pub allows_san_attribute: bool,
    /// EDITF_REQUESTEXTENSIONLIST flag
    pub allows_extension_list: bool,
    /// Security descriptor
    pub security_descriptor: String,
    /// Vulnerable configurations found
    pub vulnerabilities: Vec<CaVulnerabilityInfo>,
}

/// CA Vulnerability Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaVulnerabilityInfo {
    pub esc_number: u8,
    pub description: String,
    pub severity: String,
    pub remediation: String,
}

// ═══════════════════════════════════════════════════════════
// LDAP Enumeration Client
// ═══════════════════════════════════════════════════════════

/// LDAP enumeration for ADCS
pub struct LdapAdcsEnumerator {
    ldap: LdapSession,
}

impl LdapAdcsEnumerator {
    /// Create a new enumerator with an existing LDAP session
    pub fn new(ldap: LdapSession) -> Self {
        Self { ldap }
    }

    /// Enumerate all certificate templates
    pub async fn enumerate_templates(&mut self) -> Result<Vec<LdapCertificateTemplate>> {
        info!("Enumerating certificate templates via LDAP");

        // Search for all certificate template objects
        let filter = format!("(objectClass={})", PKI_CERT_TEMPLATE_CLASS);
        let config_nc = format!("CN=Configuration,{}", self.ldap.base_dn);

        let entries = self
            .ldap
            .custom_search_with_base(
                &config_nc,
                &filter,
                &[
                    "cn",
                    "displayName",
                    "pKIExtendedKeyUsage",
                    "pKIKeyUsage",
                    "msPKI-Certificate-Name-Flag",
                    "msPKI-Enrollment-Flag",
                    "msPKI-Private-Key-Flag",
                    "msPKI-Template-Schema-Version",
                    "msPKI-Certificate-Application-Policy",
                    "msPKI-Certificate-Policy",
                    "msPKI-Minimal-Key-Size",
                    "msPKI-Supersede-Templates",
                    "msPKI-RA-Signature",
                    "pKIExpirationPeriod",
                    "pKIOverlapPeriod",
                    "nTSecurityDescriptor",
                    "distinguishedName",
                ],
            )
            .await?;

        let mut templates = Vec::new();

        for entry in entries {
            match self.parse_template_entry(&entry) {
                Ok(template) => templates.push(template),
                Err(e) => {
                    warn!("Failed to parse template entry: {}", e);
                }
            }
        }

        info!("Found {} certificate templates", templates.len());
        Ok(templates)
    }

    /// Parse a single template LDAP entry
    fn parse_template_entry(&self, entry: &SearchEntry) -> Result<LdapCertificateTemplate> {
        let name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let display_name = entry
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| name.clone());

        let extended_key_usage = entry
            .attrs
            .get("pKIExtendedKeyUsage")
            .cloned()
            .unwrap_or_default();

        let subject_name_flags = entry
            .attrs
            .get("msPKI-Certificate-Name-Flag")
            .and_then(|v| v.first())
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);

        let enrollment_flags = entry
            .attrs
            .get("msPKI-Enrollment-Flag")
            .and_then(|v| v.first())
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);

        let private_key_flags = entry
            .attrs
            .get("msPKI-Private-Key-Flag")
            .and_then(|v| v.first())
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);

        let schema_version = entry
            .attrs
            .get("msPKI-Template-Schema-Version")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let authorized_signatures_required = entry
            .attrs
            .get("msPKI-RA-Signature")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let application_policies = entry
            .attrs
            .get("msPKI-Certificate-Application-Policy")
            .cloned()
            .unwrap_or_default();

        let issuance_policies = entry
            .attrs
            .get("msPKI-Certificate-Policy")
            .cloned()
            .unwrap_or_default();

        let dn = entry.dn.clone();

        let security_descriptor = entry
            .attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let validity_period = entry
            .attrs
            .get("pKIExpirationPeriod")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "1 year".to_string());

        let renewal_period = entry
            .attrs
            .get("pKIOverlapPeriod")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "6 weeks".to_string());

        // Generate OID if not present
        let oid = entry
            .attrs
            .get("msPKI-Cert-Template-OID")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| format!("1.3.6.1.4.1.311.21.8.{}", name.len()));

        let flags = enrollment_flags;

        Ok(LdapCertificateTemplate {
            name,
            display_name,
            oid,
            flags,
            subject_name_flags,
            enrollment_flags,
            private_key_flags,
            schema_version,
            validity_period,
            renewal_period,
            extended_key_usage,
            application_policies,
            issuance_policies,
            authorized_signatures_required,
            security_descriptor,
            dn,
        })
    }

    /// Enumerate CAs from Configuration partition
    pub async fn enumerate_cas(&mut self) -> Result<Vec<LdapCertificationAuthority>> {
        info!("Enumerating Certification Authorities via LDAP");

        let filter = format!("(objectClass={})", CERT_AUTHORITY_CLASS);
        let config_nc = format!("CN=Configuration,{}", self.ldap.base_dn);

        let entries = self
            .ldap
            .custom_search_with_base(
                &config_nc,
                &filter,
                &[
                    "cn",
                    "cACertificate",
                    "certificateTemplates",
                    "nTSecurityDescriptor",
                    "distinguishedName",
                ],
            )
            .await?;

        let mut cas = Vec::new();

        for entry in entries {
            match self.parse_ca_entry(&entry) {
                Ok(ca) => cas.push(ca),
                Err(e) => {
                    warn!("Failed to parse CA entry: {}", e);
                }
            }
        }

        info!("Found {} CAs", cas.len());
        Ok(cas)
    }

    /// Parse a single CA LDAP entry
    fn parse_ca_entry(&self, entry: &SearchEntry) -> Result<LdapCertificationAuthority> {
        let name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let dn = entry.dn.clone();

        let ca_certificate = entry
            .attrs
            .get("cACertificate")
            .and_then(|v| v.first())
            .map(|s| s.as_bytes().to_vec());

        let certificate_templates = entry
            .attrs
            .get("certificateTemplates")
            .cloned()
            .unwrap_or_default();

        let security_descriptor = entry
            .attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let enrollment_endpoints = entry
            .attrs
            .get("enrollmentEndpoints")
            .cloned()
            .unwrap_or_default();

        Ok(LdapCertificationAuthority {
            name,
            dn,
            ca_certificate,
            certificate_templates,
            security_descriptor,
            enrollment_endpoints,
        })
    }

    /// Get enrollment services (for finding HTTP enrollment endpoints)
    pub async fn enumerate_enrollment_services(&mut self) -> Result<Vec<EnrollmentService>> {
        info!("Enumerating enrollment services via LDAP");

        let filter = format!("(objectClass={})", ENROLLMENT_SERVICE_CLASS);
        let config_nc = format!("CN=Configuration,{}", self.ldap.base_dn);

        let entries = self
            .ldap
            .custom_search_with_base(
                &config_nc,
                &filter,
                &[
                    "cn",
                    "dNSHostName",
                    "certificateTemplates",
                    "nTSecurityDescriptor",
                ],
            )
            .await?;

        let mut services = Vec::new();

        for entry in entries {
            let name = entry
                .attrs
                .get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dns_host_name = entry
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let certificate_templates = entry
                .attrs
                .get("certificateTemplates")
                .cloned()
                .unwrap_or_default();

            let security_descriptor = entry
                .attrs
                .get("nTSecurityDescriptor")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            services.push(EnrollmentService {
                name,
                dns_host_name,
                certificate_templates,
                security_descriptor,
            });
        }

        Ok(services)
    }

    /// Find all vulnerable templates
    pub async fn find_vulnerable_templates(
        &mut self,
    ) -> Result<Vec<(LdapCertificateTemplate, u8)>> {
        let templates = self.enumerate_templates().await?;

        let vulnerable: Vec<_> = templates
            .into_iter()
            .filter_map(|t| t.esc_vulnerability().map(|esc| (t, esc)))
            .collect();

        info!("Found {} vulnerable templates", vulnerable.len());
        Ok(vulnerable)
    }

    /// Check for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
    /// This requires checking CA registry settings or certificate enrollment policy
    pub async fn check_esc6_configuration(&mut self) -> Result<Vec<CaConfiguration>> {
        let cas = self.enumerate_cas().await?;

        let mut configs = Vec::new();

        for ca in cas {
            // Check security descriptor for ESC7 (CA permissions)
            let mut vulnerabilities = Vec::new();

            // Check if "Everyone" or "Authenticated Users" have enrollment rights
            if ca.security_descriptor.contains("S-1-1-0")
                || ca.security_descriptor.contains("S-1-5-11")
            {
                vulnerabilities.push(CaVulnerabilityInfo {
                    esc_number: 7,
                    description:
                        "Weak CA permissions - unprivileged users may have enrollment rights"
                            .to_string(),
                    severity: "High".to_string(),
                    remediation: "Review CA security descriptor and remove unnecessary permissions"
                        .to_string(),
                });
            }

            configs.push(CaConfiguration {
                ca_name: ca.name,
                dn: ca.dn,
                // ESC6 requires checking registry or using certutil - this is a best-effort check
                allows_san_attribute: false, // Would need to check registry
                allows_extension_list: false,
                security_descriptor: ca.security_descriptor,
                vulnerabilities,
            });
        }

        Ok(configs)
    }
}

/// Enrollment Service from LDAP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentService {
    pub name: String,
    pub dns_host_name: String,
    pub certificate_templates: Vec<String>,
    pub security_descriptor: String,
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_flag_checks() {
        let template = LdapCertificateTemplate {
            name: "Test".to_string(),
            display_name: "Test Template".to_string(),
            oid: "1.2.3.4".to_string(),
            flags: 0,
            subject_name_flags: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            enrollment_flags: 0,
            private_key_flags: CT_FLAG_EXPORTABLE_KEY,
            schema_version: 2,
            validity_period: "1 year".to_string(),
            renewal_period: "6 weeks".to_string(),
            extended_key_usage: vec!["2.5.29.37.0".to_string()],
            application_policies: vec![],
            issuance_policies: vec![],
            authorized_signatures_required: 0,
            security_descriptor: String::new(),
            dn: "CN=Test,CN=Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local".to_string(),
        };

        assert!(template.allows_enrollee_subject());
        assert!(template.allows_key_export());
        assert!(template.has_any_purpose());
        assert_eq!(template.esc_vulnerability(), Some(1));
    }

    #[test]
    fn test_safe_template() {
        let template = LdapCertificateTemplate {
            name: "Safe".to_string(),
            display_name: "Safe Template".to_string(),
            oid: "1.2.3.5".to_string(),
            flags: CT_FLAG_PEND_ALL_REQUESTS,
            subject_name_flags: 0,
            enrollment_flags: 0,
            private_key_flags: 0,
            schema_version: 2,
            validity_period: "1 year".to_string(),
            renewal_period: "6 weeks".to_string(),
            extended_key_usage: vec!["1.3.6.1.5.5.7.3.2".to_string()], // Client Auth
            application_policies: vec![],
            issuance_policies: vec![],
            authorized_signatures_required: 0,
            security_descriptor: String::new(),
            dn: "CN=Safe,CN=Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local".to_string(),
        };

        assert!(!template.allows_enrollee_subject());
        assert!(template.requires_manager_approval());
        assert!(!template.has_any_purpose());
        assert_eq!(template.esc_vulnerability(), None);
    }
}
