//! Hostile Domain Controller Detection
//!
//! Performs multi-layer verification of a Domain Controller to detect
//! rogue/malicious DCs that may be intercepting or manipulating traffic.
//!
//! Detection strategies:
//! 1. **LDAP rootDSE probe** - Anonymous LDAP query to verify DC responds
//! 2. **Domain name match** - Cross-check rootDSE domain against configured domain
//! 3. **DNS SRV consistency** - Verify DC is registered in AD DNS
//! 4. **Hostname resolution** - Check dnsHostName resolves to dc_host IP
//! 5. **Kerberos port check** - Verify KDC is listening on port 88

use colored::Colorize;
use overthrone_core::proto::dns::DnsResolver;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// Which check was performed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DcCheckKind {
    /// Anonymous LDAP rootDSE query
    LdapRootDse,
    /// Domain name match between config and rootDSE
    DomainNameMatch,
    /// DNS SRV lookup for domain controllers
    DnsSrvConsistency,
    /// dnsHostName resolution vs configured dc_host
    HostnameResolution,
    /// Kerberos port 88 TCP connectivity
    KerberosPort,
}

/// Severity of a single check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckSeverity {
    /// Check passed
    Pass,
    /// Suspicious but not definitive
    Warning,
    /// Likely hostile
    Fail,
}

/// Result of a single DC verification check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcCheckResult {
    /// Which check was performed
    pub kind: DcCheckKind,
    /// Did it pass?
    pub severity: CheckSeverity,
    /// Human-readable message
    pub message: String,
}

/// Overall DC verification summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcVerificationSummary {
    /// Individual check results
    pub checks: Vec<DcCheckResult>,
    /// Configured dc_host
    pub configured_dc_host: String,
    /// dnsHostName reported by rootDSE (if available)
    pub reported_hostname: Option<String>,
    /// dnsDomainName reported by rootDSE (if available)
    pub reported_domain: Option<String>,
    /// Domain controllers discovered via DNS SRV
    pub dns_domain_controllers: Vec<(String, Vec<String>)>,
    /// Whether the overall assessment is suspicious
    pub hostile_suspicion: bool,
    /// Human-readable summary
    pub summary: String,
}

/// Configuration for DC verification
#[derive(Debug, Clone)]
pub struct DcVerifyConfig {
    /// Enable DC verification (default: true)
    pub enabled: bool,
    /// Whether to skip DNS-dependent checks (e.g., when no DNS is available)
    pub skip_dns: bool,
    /// Timeout per check in seconds
    pub check_timeout_secs: u64,
    /// Whether verification failure should prevent execution (strict mode)
    pub strict: bool,
}

impl Default for DcVerifyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            skip_dns: false,
            check_timeout_secs: 10,
            strict: false,
        }
    }
}

/// Run all DC verification checks against the target domain controller.
///
/// Returns a `DcVerificationSummary` with the results of each check.
/// Logs warnings for any suspicious findings but does not abort — the
/// caller decides whether to continue based on `strict` mode.
pub async fn verify_dc(
    dc_host: &str,
    domain: &str,
    config: &DcVerifyConfig,
) -> DcVerificationSummary {
    let configured_dc_host = dc_host.to_string();
    let mut checks = Vec::new();
    let mut reported_hostname: Option<String> = None;
    let mut reported_domain: Option<String> = None;
    let mut dns_domain_controllers = Vec::new();
    let mut hostile_suspicion = false;

    let timeout_dur = Duration::from_secs(config.check_timeout_secs);

    // ── Check 1: LDAP rootDSE probe ──
    info!("DC verification: checking rootDSE on {dc_host}");
    match tokio::time::timeout(
        timeout_dur,
        overthrone_core::proto::ldap::probe_rootdse_raw(dc_host, false),
    )
    .await
    {
        Ok(Ok(rootdse)) => {
            checks.push(DcCheckResult {
                kind: DcCheckKind::LdapRootDse,
                severity: CheckSeverity::Pass,
                message: format!(
                    "LDAP rootDSE responded (server: {})",
                    rootdse.server_name.as_deref().unwrap_or("unknown")
                ),
            });
            reported_hostname = rootdse.dns_host_name.clone();
            reported_domain = rootdse.dns_domain_name.clone();

            info!(
                "DC rootDSE: hostname={:?}, domain={:?}",
                rootdse.dns_host_name, rootdse.dns_domain_name
            );

            // ── Check 2: Domain name match ──
            if let Some(ref dns_domain) = rootdse.dns_domain_name {
                let config_domain_lower = domain.to_lowercase();
                let reported_domain_lower = dns_domain.to_lowercase();
                if reported_domain_lower == config_domain_lower {
                    checks.push(DcCheckResult {
                        kind: DcCheckKind::DomainNameMatch,
                        severity: CheckSeverity::Pass,
                        message: format!("Domain name matches: {dns_domain}"),
                    });
                } else {
                    hostile_suspicion = true;
                    let msg = format!(
                        "Domain MISMATCH: configured domain is '{domain}' but DC reports '{dns_domain}'"
                    );
                    warn!("{}", msg);
                    checks.push(DcCheckResult {
                        kind: DcCheckKind::DomainNameMatch,
                        severity: CheckSeverity::Fail,
                        message: msg,
                    });
                }
            } else {
                checks.push(DcCheckResult {
                    kind: DcCheckKind::DomainNameMatch,
                    severity: CheckSeverity::Warning,
                    message: "DC did not report a dnsDomainName in rootDSE".to_string(),
                });
            }

            // ── Check 4: Hostname resolution consistency ──
            if let Some(ref hostname) = rootdse.dns_host_name {
                match tokio::net::lookup_host(format!("{hostname}:0")).await {
                    Ok(addrs) => {
                        let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                        let matches_dc = ips.iter().any(|ip| ip == dc_host);
                        if matches_dc {
                            checks.push(DcCheckResult {
                                kind: DcCheckKind::HostnameResolution,
                                severity: CheckSeverity::Pass,
                                message: format!("dnsHostName {hostname} resolves to {dc_host}"),
                            });
                        } else {
                            let msg = format!(
                                "dnsHostName '{hostname}' resolves to IPs {ips:?}, none match configured dc_host '{dc_host}'"
                            );
                            warn!("{}", msg);
                            checks.push(DcCheckResult {
                                kind: DcCheckKind::HostnameResolution,
                                severity: CheckSeverity::Warning,
                                message: msg,
                            });
                        }
                    }
                    Err(e) => {
                        checks.push(DcCheckResult {
                            kind: DcCheckKind::HostnameResolution,
                            severity: CheckSeverity::Warning,
                            message: format!("dnsHostName '{hostname}' failed to resolve: {e}"),
                        });
                    }
                }
            } else {
                checks.push(DcCheckResult {
                    kind: DcCheckKind::HostnameResolution,
                    severity: CheckSeverity::Warning,
                    message: "DC did not report a dnsHostName in rootDSE".to_string(),
                });
            }
        }
        Ok(Err(e)) => {
            let msg = format!("LDAP rootDSE probe failed: {e}");
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind: DcCheckKind::LdapRootDse,
                severity: CheckSeverity::Fail,
                message: msg,
            });
            hostile_suspicion = true;
        }
        Err(_) => {
            let msg = format!(
                "LDAP rootDSE probe timed out after {}s",
                config.check_timeout_secs
            );
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind: DcCheckKind::LdapRootDse,
                severity: CheckSeverity::Fail,
                message: msg,
            });
            hostile_suspicion = true;
        }
    }

    // ── Check 3: DNS SRV consistency ──
    if !config.skip_dns {
        info!("DC verification: checking DNS SRV records for {domain}");
        match DnsResolver::system() {
            Ok(resolver) => {
                match tokio::time::timeout(
                    timeout_dur,
                    resolver.discover_domain_controllers(domain),
                )
                .await
                {
                    Ok(Ok(dcs)) => {
                        dns_domain_controllers = dcs.clone();
                        let dc_host_lower = dc_host.to_lowercase();
                        let found = dcs.iter().any(|(hostname, ips): &(String, Vec<String>)| {
                            hostname.to_lowercase() == dc_host_lower
                                || ips.iter().any(|ip| ip == &dc_host_lower || ip == dc_host)
                        });
                        if found {
                            checks.push(DcCheckResult {
                                kind: DcCheckKind::DnsSrvConsistency,
                                severity: CheckSeverity::Pass,
                                message: format!(
                                    "DC {} found in DNS SRV records ({} DCs total)",
                                    dc_host,
                                    dcs.len()
                                ),
                            });
                        } else {
                            let known: Vec<String> = dcs
                                .iter()
                                .map(|(h, _): &(String, Vec<String>)| h.clone())
                                .collect();
                            let msg = format!(
                                "DC '{}' NOT found in DNS SRV records for {domain}. Known DCs: {known:?}",
                                dc_host,
                            );
                            warn!("{}", msg);
                            checks.push(DcCheckResult {
                                kind: DcCheckKind::DnsSrvConsistency,
                                severity: CheckSeverity::Warning,
                                message: msg,
                            });
                        }
                    }
                    Ok(Err(e)) => {
                        checks.push(DcCheckResult {
                            kind: DcCheckKind::DnsSrvConsistency,
                            severity: CheckSeverity::Warning,
                            message: format!("DNS SRV lookup failed: {e}"),
                        });
                    }
                    Err(_) => {
                        checks.push(DcCheckResult {
                            kind: DcCheckKind::DnsSrvConsistency,
                            severity: CheckSeverity::Warning,
                            message: format!(
                                "DNS SRV lookup timed out after {}s",
                                config.check_timeout_secs
                            ),
                        });
                    }
                }
            }
            Err(e) => {
                checks.push(DcCheckResult {
                    kind: DcCheckKind::DnsSrvConsistency,
                    severity: CheckSeverity::Warning,
                    message: format!("DNS resolver initialization failed: {e}"),
                });
            }
        }
    } else {
        checks.push(DcCheckResult {
            kind: DcCheckKind::DnsSrvConsistency,
            severity: CheckSeverity::Pass,
            message: "DNS checks skipped (skip_dns=true)".to_string(),
        });
    }

    // ── Check 5: Kerberos port check ──
    info!("DC verification: checking Kerberos port 88 on {dc_host}");
    match tokio::time::timeout(
        timeout_dur,
        tokio::net::TcpStream::connect(format!("{dc_host}:88")),
    )
    .await
    {
        Ok(Ok(_)) => {
            checks.push(DcCheckResult {
                kind: DcCheckKind::KerberosPort,
                severity: CheckSeverity::Pass,
                message: "Kerberos port 88 is open".to_string(),
            });
        }
        Ok(Err(e)) => {
            let msg = format!("Kerberos port 88 connection failed: {e}");
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind: DcCheckKind::KerberosPort,
                severity: CheckSeverity::Fail,
                message: msg,
            });
            hostile_suspicion = true;
        }
        Err(_) => {
            let msg = format!(
                "Kerberos port 88 timed out after {}s",
                config.check_timeout_secs
            );
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind: DcCheckKind::KerberosPort,
                severity: CheckSeverity::Fail,
                message: msg,
            });
            hostile_suspicion = true;
        }
    }

    // ── Compile summary ──
    let failed_count = checks
        .iter()
        .filter(|c| matches!(c.severity, CheckSeverity::Fail))
        .count();
    let warn_count = checks
        .iter()
        .filter(|c| matches!(c.severity, CheckSeverity::Warning))
        .count();
    let total = checks.len();

    let summary = if hostile_suspicion {
        format!(
            "HOSTILE DC DETECTED: {failed_count}/{total} checks failed, {warn_count} warnings — \
             this DC may be rogue or misconfigured"
        )
    } else if warn_count > 0 {
        format!(
            "DC verification passed with {warn_count} warnings ({failed_count}/{total} failures)"
        )
    } else {
        format!("DC verification passed all {total} checks")
    };

    info!("DC verification complete: {summary}");

    DcVerificationSummary {
        checks,
        configured_dc_host,
        reported_hostname,
        reported_domain,
        dns_domain_controllers,
        hostile_suspicion,
        summary,
    }
}

impl DcVerificationSummary {
    /// Returns true if any critical check failed (suggesting a hostile DC)
    pub fn is_hostile(&self) -> bool {
        self.hostile_suspicion
    }

    /// Prints a colored summary to stdout for the CLI user
    pub fn print_summary(&self) {
        println!("\n  {} DC Verification Report", "═══".bold().cyan());
        for check in &self.checks {
            let (icon, severity_label) = match check.severity {
                CheckSeverity::Pass => ("✓".green().bold(), "PASS"),
                CheckSeverity::Warning => ("!".yellow().bold(), "WARN"),
                CheckSeverity::Fail => ("✗".red().bold(), "FAIL"),
            };
            println!("  {} [{}] {}", icon, severity_label.bold(), check.message);
        }
        if self.is_hostile() {
            println!(
                "  {} {}",
                "!!!".red().bold(),
                "HOSTILE DC DETECTED — proceed with extreme caution"
                    .red()
                    .bold()
            );
        }
        println!("  {}\n", "═══".bold().cyan());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_dc_unreachable_host_fails() {
        let result = verify_dc(
            "198.51.100.1",
            "test.example.com",
            &DcVerifyConfig {
                enabled: true,
                skip_dns: true,
                check_timeout_secs: 2,
                strict: false,
            },
        )
        .await;

        assert!(
            result.is_hostile(),
            "unreachable DC should be flagged as hostile"
        );
        assert!(!result.checks.is_empty(), "should have at least one check");

        let rootdse_failed = result.checks.iter().any(|c| {
            c.kind == DcCheckKind::LdapRootDse && matches!(c.severity, CheckSeverity::Fail)
        });
        let kerb_failed = result.checks.iter().any(|c| {
            c.kind == DcCheckKind::KerberosPort && matches!(c.severity, CheckSeverity::Fail)
        });
        assert!(
            rootdse_failed,
            "rootDSE check should fail for unreachable host"
        );
        assert!(
            kerb_failed,
            "Kerberos check should fail for unreachable host"
        );
    }

    #[tokio::test]
    async fn test_dns_skip_avoids_dns_checks() {
        let result = verify_dc(
            "198.51.100.1",
            "test.example.com",
            &DcVerifyConfig {
                enabled: true,
                skip_dns: true,
                check_timeout_secs: 2,
                strict: false,
            },
        )
        .await;

        let dns_check = result
            .checks
            .iter()
            .find(|c| c.kind == DcCheckKind::DnsSrvConsistency);
        assert!(dns_check.is_some(), "DNS check should be present");
        assert!(
            matches!(dns_check.unwrap().severity, CheckSeverity::Pass),
            "DNS check should pass (skipped)"
        );
        assert_eq!(
            dns_check.unwrap().message,
            "DNS checks skipped (skip_dns=true)"
        );
    }

    #[test]
    fn test_default_config() {
        let config = DcVerifyConfig::default();
        assert!(config.enabled);
        assert!(!config.skip_dns);
        assert_eq!(config.check_timeout_secs, 10);
        assert!(!config.strict);
    }

    #[test]
    fn test_print_summary_does_not_panic() {
        let result = DcVerificationSummary {
            checks: vec![
                DcCheckResult {
                    kind: DcCheckKind::LdapRootDse,
                    severity: CheckSeverity::Pass,
                    message: "Passed".to_string(),
                },
                DcCheckResult {
                    kind: DcCheckKind::DomainNameMatch,
                    severity: CheckSeverity::Fail,
                    message: "Mismatch".to_string(),
                },
            ],
            configured_dc_host: "10.0.0.1".to_string(),
            reported_hostname: Some("dc01.example.com".to_string()),
            reported_domain: Some("example.com".to_string()),
            dns_domain_controllers: vec![],
            hostile_suspicion: true,
            summary: "Test summary".to_string(),
        };
        result.print_summary();
    }

    #[test]
    fn test_verify_dc_config_default() {
        let config = DcVerifyConfig::default();
        assert!(config.enabled);
        assert_eq!(config.check_timeout_secs, 10);
    }
}
