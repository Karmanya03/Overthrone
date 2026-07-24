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
//! 6. **NTLM challenge** - Verify SMB port 445 returns NTLMSSP challenge
//! 7. **EPM port check** - Verify RPC Endpoint Mapper on port 135
//! 8. **LDAP port check** - Verify LDAP port 389
//! 9. **Cross-DC consistency** - Compare rootDSE across multiple DCs

use colored::Colorize;
use overthrone_core::proto::dns::DnsResolver;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    /// SMB port 445 NTLM challenge
    NtlmChallenge,
    /// RPC Endpoint Mapper on port 135
    EpmPort,
    /// LDAP port 389
    LdapPort,
    /// Cross-DC consistency check
    CrossDcConsistency,
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
    /// Target domain
    pub domain: String,
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
    /// Enable NTLM challenge check (default: true)
    pub check_ntlm: bool,
    /// Enable EPM port check (default: true)
    pub check_epm: bool,
    /// Enable LDAP port check (default: true)
    pub check_ldap_port: bool,
    /// Enable cross-DC consistency check (default: true)
    pub check_cross_dc: bool,
}

impl Default for DcVerifyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            skip_dns: false,
            check_timeout_secs: 10,
            strict: false,
            check_ntlm: true,
            check_epm: true,
            check_ldap_port: true,
            check_cross_dc: true,
        }
    }
}

/// Run all DC verification checks against the target domain controller.
///
/// Returns a `DcVerificationSummary` with the results of each check.
/// Logs warnings for any suspicious findings but does not abort -- the
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

    // -- Check 1: LDAP rootDSE probe --
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

            // -- Check 2: Domain name match --
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

            // -- Check 4: Hostname resolution consistency --
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

    // -- Check 3: DNS SRV consistency --
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

                        // -- Check 9: Cross-DC consistency (if multiple DCs found) --
                        if config.check_cross_dc
                            && dcs.len() > 1
                            && checks.iter().any(|c| {
                                c.kind == DcCheckKind::LdapRootDse
                                    && matches!(c.severity, CheckSeverity::Pass)
                            })
                        {
                            let cross_result =
                                check_cross_dc_consistency(&dcs, dc_host, domain, &timeout_dur)
                                    .await;
                            if let Some(result) = cross_result {
                                if matches!(result.severity, CheckSeverity::Fail) {
                                    hostile_suspicion = true;
                                }
                                checks.push(result);
                            }
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

    // -- Check 5: Kerberos port check --
    info!("DC verification: checking Kerberos port 88 on {dc_host}");
    check_port(
        dc_host,
        88,
        DcCheckKind::KerberosPort,
        "Kerberos",
        &timeout_dur,
        &mut checks,
        &mut hostile_suspicion,
    )
    .await;

    // -- Check 6: NTLM challenge via SMB port 445 --
    if config.check_ntlm {
        info!("DC verification: checking SMB NTLM challenge on {dc_host}");
        check_ntlm_challenge(dc_host, &timeout_dur, &mut checks, &mut hostile_suspicion).await;
    } else {
        checks.push(DcCheckResult {
            kind: DcCheckKind::NtlmChallenge,
            severity: CheckSeverity::Pass,
            message: "NTLM challenge check skipped".to_string(),
        });
    }

    // -- Check 7: EPM port 135 --
    if config.check_epm {
        info!("DC verification: checking EPM port 135 on {dc_host}");
        check_port(
            dc_host,
            135,
            DcCheckKind::EpmPort,
            "RPC Endpoint Mapper",
            &timeout_dur,
            &mut checks,
            &mut hostile_suspicion,
        )
        .await;
    } else {
        checks.push(DcCheckResult {
            kind: DcCheckKind::EpmPort,
            severity: CheckSeverity::Pass,
            message: "EPM port check skipped".to_string(),
        });
    }

    // -- Check 8: LDAP port 389 --
    if config.check_ldap_port {
        info!("DC verification: checking LDAP port 389 on {dc_host}");
        check_port(
            dc_host,
            389,
            DcCheckKind::LdapPort,
            "LDAP",
            &timeout_dur,
            &mut checks,
            &mut hostile_suspicion,
        )
        .await;
    } else {
        checks.push(DcCheckResult {
            kind: DcCheckKind::LdapPort,
            severity: CheckSeverity::Pass,
            message: "LDAP port check skipped".to_string(),
        });
    }

    // -- Compile summary --
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
            "HOSTILE DC DETECTED: {failed_count}/{total} checks failed, {warn_count} warnings -- \
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
        domain: domain.to_string(),
    }
}

/// Check if a TCP port is open on the target host
async fn check_port(
    host: &str,
    port: u16,
    kind: DcCheckKind,
    service_name: &str,
    timeout_dur: &Duration,
    checks: &mut Vec<DcCheckResult>,
    hostile_suspicion: &mut bool,
) {
    match tokio::time::timeout(
        *timeout_dur,
        tokio::net::TcpStream::connect(format!("{host}:{port}")),
    )
    .await
    {
        Ok(Ok(_)) => {
            checks.push(DcCheckResult {
                kind,
                severity: CheckSeverity::Pass,
                message: format!("{service_name} port {port} is open"),
            });
        }
        Ok(Err(e)) => {
            let msg = format!("{service_name} port {port} connection failed: {e}");
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind,
                severity: CheckSeverity::Fail,
                message: msg,
            });
            *hostile_suspicion = true;
        }
        Err(_) => {
            let msg = format!(
                "{service_name} port {port} timed out after {}s",
                timeout_dur.as_secs()
            );
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind,
                severity: CheckSeverity::Fail,
                message: msg,
            });
            *hostile_suspicion = true;
        }
    }
}

/// Check the SMB NTLM challenge on port 445.
/// A real DC will respond with an NTLMSSP challenge in the SMB negotiate response.
async fn check_ntlm_challenge(
    host: &str,
    timeout_dur: &Duration,
    checks: &mut Vec<DcCheckResult>,
    hostile_suspicion: &mut bool,
) {
    match tokio::time::timeout(*timeout_dur, check_ntlm_challenge_inner(host)).await {
        Ok(Ok(msg)) => {
            checks.push(DcCheckResult {
                kind: DcCheckKind::NtlmChallenge,
                severity: CheckSeverity::Pass,
                message: msg,
            });
        }
        Ok(Err(msg)) => {
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind: DcCheckKind::NtlmChallenge,
                severity: CheckSeverity::Warning,
                message: msg,
            });
        }
        Err(_) => {
            let msg = format!(
                "SMB NTLM challenge check timed out after {}s",
                timeout_dur.as_secs()
            );
            warn!("{}", msg);
            checks.push(DcCheckResult {
                kind: DcCheckKind::NtlmChallenge,
                severity: CheckSeverity::Fail,
                message: msg,
            });
            *hostile_suspicion = true;
        }
    }
}

/// Inner implementation of NTLM challenge check.
/// Sends an SMBv2 negotiate request and checks for NTLMSSP in the response.
async fn check_ntlm_challenge_inner(host: &str) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(format!("{host}:445"))
        .await
        .map_err(|e| format!("SMB connect failed: {e}"))?;

    // SMBv2 negotiate request (simplified, minimal)
    // NetBIOS session request first
    let netbios_session = vec![0x00u8; 4]; // NetBIOS session request with 0 length
    stream
        .write_all(&netbios_session)
        .await
        .map_err(|e| format!("NetBIOS session send failed: {e}"))?;

    // Read NetBIOS session response (4 bytes)
    let mut netbios_resp = [0u8; 4];
    stream
        .read_exact(&mut netbios_resp)
        .await
        .map_err(|e| format!("NetBIOS session response failed: {e}"))?;

    if netbios_resp[0] != 0x00 {
        return Err(format!(
            "NetBIOS session rejected: type={}",
            netbios_resp[0]
        ));
    }

    // SMB2 negotiate request
    // Protocol: SMBv2, Dialect revision: 0x0202 (SMB 2.0.2)
    let mut smb_nego = Vec::new();
    smb_nego.extend_from_slice(b"\xfeSMB"); // Protocol ID
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // StructureSize
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    smb_nego.extend_from_slice(&0u32.to_le_bytes()); // Status
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // Command: Negotiate (0x0000)
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // Credits requested
    smb_nego.extend_from_slice(&0u32.to_le_bytes()); // Flags
    smb_nego.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    smb_nego.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    smb_nego.push(0u8); // Reserved
    smb_nego.push(0u8); // Reserved
    smb_nego.push(0u8); // Reserved
    smb_nego.push(0u8); // Reserved
    smb_nego.extend_from_slice(&0u32.to_le_bytes()); // TreeId (0)
    smb_nego.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // StructureSize (36)
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // DialectCount
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // SecurityMode
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    smb_nego.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    let client_guid = [0u8; 16]; // ClientGuid (16 bytes, zero is fine for probe)
    smb_nego.extend_from_slice(&client_guid);
    smb_nego.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    smb_nego.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    // Dialects: SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
    let dialects = [0x0202u16, 0x0210, 0x0300, 0x0302, 0x0311];
    for d in &dialects {
        smb_nego.extend_from_slice(&d.to_le_bytes());
    }

    // Prepend NetBIOS transport header with length
    let mut pdu = Vec::new();
    pdu.extend_from_slice(&(smb_nego.len() as u32).to_be_bytes()); // NetBIOS length (big endian)
    pdu.push(0x00); // NetBIOS session message type
    pdu.extend_from_slice(&smb_nego);

    stream
        .write_all(&pdu)
        .await
        .map_err(|e| format!("SMB negotiate send failed: {e}"))?;

    // Read SMB negotiate response
    let mut nb_header = [0u8; 4];
    stream
        .read_exact(&mut nb_header)
        .await
        .map_err(|e| format!("SMB negotiate read header failed: {e}"))?;

    let resp_len = u32::from_be_bytes(nb_header) as usize;
    if !(4..=65536).contains(&resp_len) {
        return Err(format!("SMB negotiate response length invalid: {resp_len}"));
    }

    let mut resp = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| format!("SMB negotiate read body failed: {e}"))?;

    // Check for SMB protocol ID
    if resp.len() < 4 || &resp[0..4] != b"\xfeSMB" {
        return Err("SMB negotiate response missing protocol ID".to_string());
    }

    // Extract security blob offset and length from SMB2 header
    // SMB2 header is 64 bytes. Negotiate response has:
    // offset 0-3: protocol (already checked)
    // offset 4-5: structure size
    // offset 6-7: credit charge
    // offset 8-11: status (NTSTATUS)
    // offset 12-13: command
    // offset 14-15: credit granted
    // offset 16-19: flags
    // offset 20-23: next command
    // offset 24-31: message id
    // offset 32-35: reserved
    // offset 36-39: tree id
    // offset 40-47: session id
    // offset 48-49: structure size (negotiate response = 65)
    // offset 50-51: security mode
    // offset 52-53: dialect revision
    // offset 54-55: negotiate context count (3.1.1)
    // offset 56-63: server guid
    // offset 64-67: capabilities
    // offset 68-71: max transact size
    // offset 72-75: max read size
    // offset 76-79: max write size
    // offset 80-87: system time (filetime)
    // offset 88-91: server start time
    // offset 92-93: security buffer offset
    // offset 94-95: security buffer length
    // offset 96+: negotiate contexts (for 3.1.1)

    // Parse the negotiate response
    if resp.len() < 64 {
        return Err(format!(
            "SMB negotiate response too short: {} bytes",
            resp.len()
        ));
    }

    // Look for NTLMSSP signature in the response
    let ntlmssp_sig = b"NTLMSSP";
    if let Some(pos) = resp.windows(7).position(|w| w == ntlmssp_sig) {
        let challenge_len = resp.len() - pos;
        Ok(format!(
            "SMB NTLM challenge received (offset={pos}, blob_size={challenge_len})"
        ))
    } else {
        Err("SMB negotiate response does not contain NTLMSSP challenge".to_string())
    }
}

/// Check cross-DC consistency by probing rootDSE on other DCs found via DNS
async fn check_cross_dc_consistency(
    dcs: &[(String, Vec<String>)],
    primary_dc_host: &str,
    domain: &str,
    timeout_dur: &Duration,
) -> Option<DcCheckResult> {
    // Find the IP of the primary DC for comparison
    let primary_dc_lower = primary_dc_host.to_lowercase();
    let primary_domain_lower = domain.to_lowercase();

    // Try up to 2 other DCs
    let other_dcs: Vec<&str> = dcs
        .iter()
        .filter(|(hostname, _)| {
            let h = hostname.to_lowercase();
            h != primary_dc_lower
        })
        .take(2)
        .map(|(hostname, ips)| {
            // Try hostname first, then first IP
            ip_from_dc_entry(hostname, ips)
        })
        .collect();

    if other_dcs.is_empty() {
        return Some(DcCheckResult {
            kind: DcCheckKind::CrossDcConsistency,
            severity: CheckSeverity::Pass,
            message: "No other DCs available for cross-check".to_string(),
        });
    }

    let mut matched = 0;
    let mut failed = 0;
    let mut domains_seen: Vec<String> = Vec::new();

    for other_dc in &other_dcs {
        match tokio::time::timeout(
            *timeout_dur,
            overthrone_core::proto::ldap::probe_rootdse_raw(other_dc, false),
        )
        .await
        {
            Ok(Ok(rootdse)) => {
                let other_domain = rootdse.dns_domain_name.as_deref().unwrap_or("unknown");
                domains_seen.push(format!("{other_dc}:{other_domain}"));
                if rootdse.dns_domain_name.as_deref().map(|d| d.to_lowercase())
                    == Some(primary_domain_lower.clone())
                {
                    matched += 1;
                } else {
                    warn!(
                        "Cross-DC domain mismatch: {} reports domain '{other_domain}' (expected '{domain}')",
                        other_dc
                    );
                    failed += 1;
                }
            }
            Ok(Err(e)) => {
                warn!("Cross-DC probe failed for {other_dc}: {e}");
                failed += 1;
            }
            Err(_) => {
                warn!("Cross-DC probe timed out for {other_dc}");
                failed += 1;
            }
        }
    }

    let total_checked = other_dcs.len();
    let result = if failed > 0 {
        DcCheckResult {
            kind: DcCheckKind::CrossDcConsistency,
            severity: CheckSeverity::Warning,
            message: format!(
                "Cross-DC: {matched}/{total_checked} secondary DCs match domain. Domains seen: {}",
                domains_seen.join(", ")
            ),
        }
    } else {
        DcCheckResult {
            kind: DcCheckKind::CrossDcConsistency,
            severity: CheckSeverity::Pass,
            message: format!(
                "Cross-DC consistent: {matched}/{total_checked} secondary DCs match domain"
            ),
        }
    };

    Some(result)
}

/// Extract an IP string from a DNS SRV entry (hostname or first IP)
fn ip_from_dc_entry<'a>(hostname: &'a str, ips: &'a [String]) -> &'a str {
    if !ips.is_empty() { &ips[0] } else { hostname }
}

impl DcVerificationSummary {
    /// Returns true if any critical check failed (suggesting a hostile DC)
    pub fn is_hostile(&self) -> bool {
        self.hostile_suspicion
    }

    /// Returns the number of failed checks
    pub fn failed_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| matches!(c.severity, CheckSeverity::Fail))
            .count()
    }

    /// Returns the number of warning checks
    pub fn warn_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| matches!(c.severity, CheckSeverity::Warning))
            .count()
    }

    /// Prints a colored summary to stdout for the CLI user
    pub fn print_summary(&self) {
        println!("\n  {} DC Verification Report", "===".bold().cyan());
        for check in &self.checks {
            let (icon, severity_label) = match check.severity {
                CheckSeverity::Pass => ("[+]".green().bold(), "PASS"),
                CheckSeverity::Warning => ("!".yellow().bold(), "WARN"),
                CheckSeverity::Fail => ("[-]".red().bold(), "FAIL"),
            };
            println!("  {} [{}] {}", icon, severity_label.bold(), check.message);
        }
        if self.is_hostile() {
            println!(
                "  {} {}",
                "!!!".red().bold(),
                "HOSTILE DC DETECTED -- proceed with extreme caution"
                    .red()
                    .bold()
            );
        }
        println!("  {}\n", "===".bold().cyan());
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
                check_ntlm: false,
                check_epm: false,
                check_ldap_port: false,
                check_cross_dc: false,
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
                check_ntlm: false,
                check_epm: false,
                check_ldap_port: false,
                check_cross_dc: false,
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
        assert!(config.check_ntlm);
        assert!(config.check_epm);
        assert!(config.check_ldap_port);
        assert!(config.check_cross_dc);
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
            domain: "example.com".to_string(),
        };
        result.print_summary();
    }

    #[test]
    fn test_verify_dc_config_default() {
        let config = DcVerifyConfig::default();
        assert!(config.enabled);
        assert_eq!(config.check_timeout_secs, 10);
    }

    #[test]
    fn test_check_kind_display_variants() {
        // Verify all check kinds exist and are distinct
        let kinds = vec![
            DcCheckKind::LdapRootDse,
            DcCheckKind::DomainNameMatch,
            DcCheckKind::DnsSrvConsistency,
            DcCheckKind::HostnameResolution,
            DcCheckKind::KerberosPort,
            DcCheckKind::NtlmChallenge,
            DcCheckKind::EpmPort,
            DcCheckKind::LdapPort,
            DcCheckKind::CrossDcConsistency,
        ];
        assert_eq!(kinds.len(), 9);
        // Ensure no duplicates
        let mut seen = std::collections::HashSet::new();
        for kind in &kinds {
            assert!(seen.insert(kind), "duplicate check kind found");
        }
    }

    #[test]
    fn test_dc_verification_summary_counts() {
        let result = DcVerificationSummary {
            checks: vec![
                DcCheckResult {
                    kind: DcCheckKind::LdapRootDse,
                    severity: CheckSeverity::Pass,
                    message: "ok".to_string(),
                },
                DcCheckResult {
                    kind: DcCheckKind::KerberosPort,
                    severity: CheckSeverity::Fail,
                    message: "fail".to_string(),
                },
                DcCheckResult {
                    kind: DcCheckKind::EpmPort,
                    severity: CheckSeverity::Warning,
                    message: "warn".to_string(),
                },
            ],
            configured_dc_host: "10.0.0.1".to_string(),
            reported_hostname: None,
            reported_domain: None,
            dns_domain_controllers: vec![],
            hostile_suspicion: true,
            summary: "Test".to_string(),
            domain: "example.com".to_string(),
        };
        assert_eq!(result.failed_count(), 1);
        assert_eq!(result.warn_count(), 1);
        assert!(result.is_hostile());
    }

    #[test]
    fn test_ip_from_dc_entry_prefers_ip() {
        let hostname = "dc01.example.com";
        let ips = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        assert_eq!(ip_from_dc_entry(hostname, &ips), "10.0.0.1");
    }

    #[test]
    fn test_ip_from_dc_entry_falls_back_to_hostname() {
        let hostname = "dc01.example.com";
        let ips: Vec<String> = vec![];
        assert_eq!(ip_from_dc_entry(hostname, &ips), "dc01.example.com");
    }

    #[test]
    fn test_ntlm_challenge_inner_no_connect_fails_gracefully() {
        // This tests the inner function returns Err on a non-existent host
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(check_ntlm_challenge_inner("198.51.100.1"));
        assert!(
            result.is_err(),
            "NTLM challenge should fail on unreachable host"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("SMB connect failed") || err.contains("timed out"),
            "Error should mention connection failure: {err}"
        );
    }
}
