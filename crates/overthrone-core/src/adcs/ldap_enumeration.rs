//! LDAP Certificate Template Enumeration
//!
//! Queries Active Directory for certificate templates and CA configurations
//! to identify ESC vulnerabilities and CA-side ESC16 hooks.

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
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub display_name: String,
    /// Stable unique identifier.
    pub oid: String,
    /// flags field
    pub flags: u32,
    /// Object or account name.
    pub subject_name_flags: u32,
    /// enrollment flags field
    pub enrollment_flags: u32,
    /// Key data
    pub private_key_flags: u32,
    /// schema version field
    pub schema_version: u32,
    /// Stable unique identifier.
    pub validity_period: String,
    /// renewal period field
    pub renewal_period: String,
    /// Key data
    pub extended_key_usage: Vec<String>,
    /// application policies field
    pub application_policies: Vec<String>,
    /// issuance policies field
    pub issuance_policies: Vec<String>,
    /// authorized signatures required field
    pub authorized_signatures_required: u32,
    /// security descriptor field
    pub security_descriptor: String,
    /// dn field
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
        // ESC15: Schema V1 template with enrollee-supplied subject on an unpatched CA
        if self.schema_version == 1
            && self.allows_enrollee_subject()
            && !self.requires_manager_approval()
        {
            return Some(15);
        }

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
    /// Object or account name.
    pub name: String,
    /// dn field
    pub dn: String,
    /// ca certificate field
    pub ca_certificate: Option<Vec<u8>>,
    /// certificate templates field
    pub certificate_templates: Vec<String>,
    /// security descriptor field
    pub security_descriptor: String,
    /// enrollment endpoints field
    pub enrollment_endpoints: Vec<String>,
    /// disabled extensions field
    #[serde(default)]
    pub disabled_extensions: Vec<String>,
}

impl LdapCertificationAuthority {
    /// Return true when the CA disables the NTDS security extension.
    pub fn is_security_extension_disabled(&self) -> bool {
        self.disabled_extensions
            .iter()
            .any(|extension| extension == "1.3.6.1.4.1.311.25.2")
    }
}

/// CA Configuration Flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfiguration {
    /// Object or account name.
    pub ca_name: String,
    /// dn field
    pub dn: String,
    /// EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
    pub allows_san_attribute: bool,
    /// EDITF_REQUESTEXTENSIONLIST flag
    pub allows_extension_list: bool,
    /// Disabled certificate extensions (ESC16 hook)
    #[serde(default)]
    pub disabled_extensions: Vec<String>,
    /// Security descriptor
    pub security_descriptor: String,
    /// Vulnerable configurations found
    pub vulnerabilities: Vec<CaVulnerabilityInfo>,
}

impl CaConfiguration {
    /// Return true when the CA disables the NTDS security extension.
    pub fn is_security_extension_disabled(&self) -> bool {
        self.disabled_extensions
            .iter()
            .any(|extension| extension == "1.3.6.1.4.1.311.25.2")
    }
}

/// CA Vulnerability Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaVulnerabilityInfo {
    /// esc number field
    pub esc_number: u8,
    /// description field
    pub description: String,
    /// severity field
    pub severity: String,
    /// remediation field
    pub remediation: String,
}

impl CaVulnerabilityInfo {
    /// Runs this module operation.
    pub fn new(esc_number: u8, description: &str, severity: &str, remediation: &str) -> Self {
        Self {
            esc_number,
            description: description.to_string(),
            severity: severity.to_string(),
            remediation: remediation.to_string(),
        }
    }
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
                    "disabled_extensions",
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

        let disabled_extensions = entry
            .attrs
            .get("disabled_extensions")
            .cloned()
            .unwrap_or_default();

        Ok(LdapCertificationAuthority {
            name,
            dn,
            ca_certificate,
            certificate_templates,
            security_descriptor,
            enrollment_endpoints,
            disabled_extensions,
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

    /// Check for CA-side ESC6 / ESC16 configuration.
    /// ESC6 still requires registry checks; ESC16 can be inferred from LDAP if exposed.
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
                vulnerabilities.push(CaVulnerabilityInfo::new(
                    7,
                    "Weak CA permissions - unprivileged users may have enrollment rights",
                    "High",
                    "Review CA security descriptor and remove unnecessary permissions",
                ));
            }

            if ca.is_security_extension_disabled() {
                vulnerabilities.push(CaVulnerabilityInfo::new(
                    16,
                    "CA security extension is disabled - issued certificates omit the NTDS security extension",
                    "High",
                    "Re-enable the NTDS security extension and remove 1.3.6.1.4.1.311.25.2 from the disabled extension list",
                ));
            }

            configs.push(CaConfiguration {
                ca_name: ca.name,
                dn: ca.dn,
                // ESC6 requires checking registry or using certutil - this is a best-effort check
                allows_san_attribute: false, // Would need to check registry
                allows_extension_list: false,
                disabled_extensions: ca.disabled_extensions,
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
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub dns_host_name: String,
    /// certificate templates field
    pub certificate_templates: Vec<String>,
    /// security descriptor field
    pub security_descriptor: String,
}

/// Result of a write-access check on an ADCS object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsWriteAccess {
    /// Whether the trustee has write access.
    pub can_write: bool,
    /// Type of access granted (GenericAll, WriteProperty, WriteDacl, etc.).
    pub access_type: String,
    /// Specific rights granted.
    pub granted_rights: Vec<String>,
    /// DN of the checked object.
    pub object_dn: String,
    /// Trustee SID that was checked.
    pub trustee_sid: String,
}

impl LdapAdcsEnumerator {
    /// Check whether a given trustee SID has write access to a template or CA object.
    /// Used for ESC5 (PKI object ACL abuse) and ESC7 (CA permission abuse).
    pub async fn check_write_access(
        &mut self,
        object_dn: &str,
        trustee_sid: &str,
    ) -> Result<AdcsWriteAccess> {
        info!(
            "Checking write access for trustee {} on object {}",
            trustee_sid, object_dn
        );

        let entries = self
            .ldap
            .custom_search_with_base(
                object_dn,
                "(objectClass=*)",
                &["nTSecurityDescriptor", "distinguishedName", "objectClass"],
            )
            .await?;

        let entry = entries.first().ok_or_else(|| {
            crate::error::OverthroneError::Adcs(format!("Object not found: {}", object_dn))
        })?;

        let sd = entry
            .attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let object_class = entry.attrs.get("objectClass").cloned().unwrap_or_default();

        let is_template = object_class.iter().any(|c| c == PKI_CERT_TEMPLATE_CLASS);
        let is_ca = object_class
            .iter()
            .any(|c| c == CERT_AUTHORITY_CLASS || c == ENROLLMENT_SERVICE_CLASS);

        let (can_write, access_type, granted_rights) =
            Self::parse_sd_for_write_access(&sd, trustee_sid, is_template, is_ca);

        let result = AdcsWriteAccess {
            can_write,
            access_type,
            granted_rights,
            object_dn: entry.dn.clone(),
            trustee_sid: trustee_sid.to_string(),
        };

        info!(
            "Write access check: can_write={}, access_type={}",
            result.can_write, result.access_type
        );

        Ok(result)
    }

    /// Parse a security descriptor string for write access by a trustee SID.
    fn parse_sd_for_write_access(
        sd: &str,
        trustee_sid: &str,
        is_template: bool,
        is_ca: bool,
    ) -> (bool, String, Vec<String>) {
        let mut can_write = false;
        let mut access_type = String::new();
        let mut granted_rights = Vec::new();

        // Check for GenericAll (full control)
        if sd.contains(trustee_sid) {
            // Look for ACE entries containing the trustee SID
            for part in sd.split('(') {
                if !part.contains(trustee_sid) {
                    continue;
                }

                // Extract rights mask (hex value after the semicolals before the SID)
                if let Some(rights_start) = part.find(';') {
                    let remainder = &part[rights_start..];
                    let parts: Vec<&str> = remainder.split(';').collect();
                    if parts.len() >= 3
                        && let Ok(rights) =
                            u32::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                    {
                        // 0xF01FF = GenericAll
                        if rights & 0xF01FF == 0xF01FF || rights == 0x1F01FF {
                            can_write = true;
                            access_type = "GenericAll".to_string();
                            granted_rights.push("Full Control".to_string());
                            break;
                        }
                        // 0x20 = WriteProperty
                        if rights & 0x20 != 0 {
                            can_write = true;
                            if access_type.is_empty() {
                                access_type = "WriteProperty".to_string();
                            }
                            if is_template {
                                granted_rights.push("Write template attributes".to_string());
                            }
                            if is_ca {
                                granted_rights.push("Write CA configuration".to_string());
                            }
                        }
                        // 0x40000 = WriteDacl
                        if rights & 0x40000 != 0 {
                            can_write = true;
                            if access_type.is_empty() {
                                access_type = "WriteDacl".to_string();
                            }
                            granted_rights.push("Modify permissions".to_string());
                        }
                        // 0x8 = WriteOwner
                        if rights & 0x8 != 0 {
                            can_write = true;
                            if access_type.is_empty() {
                                access_type = "WriteOwner".to_string();
                            }
                            granted_rights.push("Take ownership".to_string());
                        }
                    }
                }
            }
        }

        // Fallback: check for well-known SIDs
        if !can_write {
            let well_known_write_sids = [
                "S-1-5-11",     // Authenticated Users
                "S-1-1-0",      // Everyone
                "S-1-5-32-544", // Administrators
                "S-1-5-32-548", // Account Operators
            ];
            for wk_sid in &well_known_write_sids {
                if trustee_sid == *wk_sid && sd.contains(wk_sid) {
                    can_write = true;
                    access_type = format!("WellKnownSID ({})", wk_sid);
                    granted_rights.push("Inherited write access".to_string());
                    break;
                }
            }
        }

        if access_type.is_empty() && !can_write {
            access_type = "NoAccess".to_string();
        }

        (can_write, access_type, granted_rights)
    }
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

    #[test]
    fn test_schema_v1_template_reports_esc15() {
        let template = LdapCertificateTemplate {
            name: "Legacy".to_string(),
            display_name: "Legacy Template".to_string(),
            oid: "1.2.3.6".to_string(),
            flags: 0,
            subject_name_flags: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            enrollment_flags: 0,
            private_key_flags: 0,
            schema_version: 1,
            validity_period: "1 year".to_string(),
            renewal_period: "6 weeks".to_string(),
            extended_key_usage: vec!["1.3.6.1.5.5.7.3.2".to_string()],
            application_policies: vec![],
            issuance_policies: vec![],
            authorized_signatures_required: 0,
            security_descriptor: String::new(),
            dn: "CN=Legacy,CN=Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local".to_string(),
        };

        assert!(template.allows_enrollee_subject());
        assert!(!template.requires_manager_approval());
        assert_eq!(template.esc_vulnerability(), Some(15));
    }

    #[test]
    fn test_ca_configuration_is_security_extension_disabled_flag() {
        let config = CaConfiguration {
            ca_name: "TestCA".to_string(),
            dn: "CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local".to_string(),
            allows_san_attribute: false,
            allows_extension_list: false,
            disabled_extensions: vec!["1.3.6.1.4.1.311.25.2".to_string()],
            security_descriptor: String::new(),
            vulnerabilities: vec![],
        };

        assert!(config.is_security_extension_disabled());
    }
}
