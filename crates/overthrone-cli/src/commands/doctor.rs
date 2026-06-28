//! Environment diagnostics command — `ovt doctor`
//!
//! Checks your environment for required dependencies, network connectivity,
//! and platform-specific features. Provides a protocol-level status summary
//! that tells you which Overthrone modules will work against the target DC.

use crate::banner;
use chrono::{NaiveDateTime, Utc};
use colored::Colorize;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Result of a single diagnostic check
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub hint: Option<String>,
}

/// Run all environment diagnostics.
/// If `dc` is provided, also runs full DC connectivity checks with a capability summary.
pub async fn run(checks: Option<Vec<String>>, dc: Option<&str>) -> i32 {
    banner::print_module_banner("DOCTOR");

    println!(
        "  {} Running environment diagnostics...\n",
        "▸".bright_black()
    );

    let all_checks = vec![
        check_platform(),
        check_kerberos_config(),
        check_winrm_adapter(),
    ];

    let mut results: Vec<CheckResult> = if let Some(specific) = checks {
        all_checks
            .into_iter()
            .filter(|c| {
                specific
                    .iter()
                    .any(|s| c.name.to_lowercase().contains(&s.to_lowercase()))
            })
            .collect()
    } else {
        all_checks
    };

    let mut passed = 0usize;
    let mut failed = 0usize;

    // Print local environment checks
    for result in &results {
        let status = if result.passed {
            passed += 1;
            "✓".green().bold()
        } else {
            failed += 1;
            "✗".red().bold()
        };
        println!("  {} {}: {}", status, result.name, result.message);
        if let Some(ref hint) = result.hint {
            println!("    {} {}", "→".yellow(), hint.yellow().dimmed());
        }
    }

    // DC connectivity checks (if target provided)
    if let Some(dc_host) = dc {
        println!();
        println!(
            "  {} Checking DC: {}\n",
            "▸".bright_black(),
            dc_host.cyan().bold()
        );

        let dc_results = check_dc_connectivity(dc_host).await;

        for result in &dc_results {
            let status = if result.passed {
                passed += 1;
                "✓".green().bold()
            } else {
                failed += 1;
                "✗".red().bold()
            };
            println!("  {} {}", status, result.message);
            if let Some(ref hint) = result.hint {
                println!("    {} {}", "→".yellow(), hint.yellow().dimmed());
            }
        }

        // Capability summary
        println!();
        println!("  {} Capability Summary", "▸".bright_black().bold());
        print_capability_summary(&dc_results);
        results.extend(dc_results);
    }

    // Summary
    println!();
    println!(
        "  {} {} passed, {} failed",
        if failed == 0 {
            "✓".green()
        } else {
            "!".yellow()
        },
        passed.to_string().cyan(),
        failed.to_string().red()
    );

    if failed > 0 {
        println!(
            "  {} Some checks failed. Read the hints above, or consult the docs.",
            "!".yellow()
        );
    } else {
        println!("  {} All systems go. Go overthrow something.", "✓".green());
    }

    if failed > 0 { 1 } else { 0 }
}

/// Print a capability summary table showing which Overthrone modules are available
/// based on DC protocol check results.
fn print_capability_summary(results: &[CheckResult]) {
    // Match port checks by suffix (names are like "10.0.0.1:389") and protocol checks by exact name
    let port_open = |port: u16| -> bool {
        let suffix = format!(":{port}");
        results
            .iter()
            .any(|r| r.name.ends_with(&suffix) && r.passed)
    };
    let check_pass = |name: &str| -> bool { results.iter().any(|r| r.name == name && r.passed) };

    let rdap = port_open(389);
    let _ldaps = port_open(636);
    let smb = port_open(445);
    let kerberos = port_open(88) && check_pass("kdc_probe");
    let winrm = port_open(5985) || port_open(5986);
    let rpc = port_open(135);
    let dns_ok = check_pass("dns_resolution");
    let skew_ok = check_pass("clock_skew");

    // Define all Overthrone capabilities with their protocol requirements
    let capabilities: Vec<(&str, &str, bool, &str)> = vec![
        (
            "Enumeration",
            "LDAP on 389",
            rdap,
            "ovt enum, ovt ldap search",
        ),
        (
            "Shadow Credentials",
            "LDAP + Kerberos",
            rdap && kerberos,
            "ovt shadow-cred add",
        ),
        (
            "DCSync",
            "RPC on 135 + Kerberos",
            rpc && kerberos,
            "ovt kerberos dcsync",
        ),
        (
            "Kerberoasting",
            "Kerberos on 88",
            kerberos && skew_ok,
            "ovt kerberos roast",
        ),
        (
            "AS-REP Roasting",
            "Kerberos on 88",
            kerberos && skew_ok,
            "ovt kerberos asreproast",
        ),
        (
            "TGT/TGS",
            "Kerberos on 88",
            kerberos && skew_ok,
            "ovt kerberos get-tgt, get-tgs",
        ),
        ("SMB Exec", "SMB on 445", smb, "ovt smb exec"),
        ("SMB Spider", "SMB on 445", smb, "ovt smb spider"),
        ("WinRM Exec", "WinRM 5985/6", winrm, "ovt winrm exec"),
        (
            "NTLM Relay",
            "SMB + LDAP on 389",
            smb && rdap,
            "ovt ntlm relay",
        ),
        (
            "NTLM Capture",
            "SMB + LDAP on 389",
            smb && rdap,
            "ovt ntlm capture",
        ),
        (
            "Spoofing",
            "DNS + WPAD + SMB",
            dns_ok && smb,
            "ovt ntlm capture --wpad",
        ),
        (
            "Forge Tickets",
            "N/A (local)",
            true,
            "ovt forge golden/silver/diamond/skeleton",
        ),
        ("ADCS Relay", "SMB on 445", smb, "ovt ntlm relay --adcs"),
        (
            "BloodHound",
            "LDAP on 389",
            rdap,
            "ovt bh analyze --source ldap",
        ),
    ];

    println!(
        "  {:25} {:15}  {:20}  {}",
        "module".cyan(),
        "proto".cyan(),
        "ready".cyan(),
        "commands".cyan()
    );
    println!("  {}", "─".repeat(95).dimmed());

    for (module, proto, ready, cmds) in &capabilities {
        let status = if *ready {
            "✓".green().bold()
        } else {
            "✗".red().bold()
        };
        println!(
            "  {:25} {:15}  {} {:17}  {}",
            module,
            proto,
            status,
            if *ready { "ready" } else { "blocked" },
            cmds.dimmed(),
        );
    }

    println!();
    println!(
        "  {} Legend: ✓ = available, ✗ = blocked by failed prerequisite",
        "ℹ".bright_black()
    );

    // If clock skew is bad, warn about Kerberos globally
    if !skew_ok {
        println!(
            "  {} WARNING: Clock skew >5 min — ALL Kerberos operations will fail. Sync your clock first.",
            "!".yellow().bold()
        );
    }
}

/// Check platform and available features
fn check_platform() -> CheckResult {
    let (platform, features) = if cfg!(windows) {
        (
            "Windows",
            vec!["SMB2/3 (native Rust)", "WinRM (native)", "NTLM (SSPI)"],
        )
    } else if cfg!(target_os = "linux") {
        (
            "Linux",
            vec![
                "SMB2/3 (native Rust)",
                "WinRM (WS-Man)",
                "NTLM (native Rust/ntlmclient)",
            ],
        )
    } else if cfg!(target_os = "macos") {
        (
            "macOS",
            vec![
                "SMB2/3 (native Rust)",
                "WinRM (WS-Man)",
                "NTLM (native Rust/ntlmclient)",
            ],
        )
    } else {
        ("Unknown", vec![])
    };

    CheckResult {
        name: "Platform".to_string(),
        passed: true,
        message: format!("{} — {}", platform, features.join(", ")),
        hint: None,
    }
}

/// Check for Kerberos configuration
fn check_kerberos_config() -> CheckResult {
    let has_config = ["/etc/krb5.conf", "/etc/krb5/krb5.conf"]
        .iter()
        .any(|path| std::fs::metadata(path).is_ok())
        || std::env::var("KRB5_CONFIG").is_ok();

    let hint = if cfg!(windows) || has_config {
        None
    } else {
        Some("Set KRB5_CONFIG or add /etc/krb5.conf if you want kerberos-native tools to auto-discover realm defaults".to_string())
    };

    CheckResult {
        name: "kerberos".to_string(),
        passed: true,
        message: if cfg!(windows) {
            "Native Kerberos via SSPI; external tools not required".to_string()
        } else if has_config {
            "Native Kerberos stack ready".to_string()
        } else {
            "Native Kerberos stack ready; krb5.conf optional for some paths".to_string()
        },
        hint,
    }
}

/// Check for WinRM adapter availability
fn check_winrm_adapter() -> CheckResult {
    CheckResult {
        name: "winrm".to_string(),
        passed: true,
        message: if cfg!(windows) {
            "Native WinRM/WS-Man path available".to_string()
        } else {
            "Native WS-Man path available; no external winrm adapters required".to_string()
        },
        hint: None,
    }
}

/// Run connectivity checks against a specific DC
pub async fn check_dc_connectivity(dc: &str) -> Vec<CheckResult> {
    let ports = [
        (389, "LDAP"),
        (636, "LDAPS"),
        (445, "SMB"),
        (5985, "WinRM HTTP"),
        (5986, "WinRM HTTPS"),
        (88, "Kerberos"),
        (135, "RPC Endpoint Mapper"),
        (139, "NetBIOS SMB"),
    ];

    let mut results = Vec::new();

    for (port, name) in &ports {
        let addr = format!("{}:{}", dc, port);
        let socket_addr = match addr.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(_) => {
                results.push(CheckResult {
                    name: format!("{}:{}", dc, port),
                    passed: false,
                    message: format!("{} — invalid address", name),
                    hint: None,
                });
                continue;
            }
        };
        let result = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3));

        let passed = result.is_ok();
        let message = if passed {
            "open".to_string()
        } else {
            "closed/filtered".to_string()
        };

        results.push(CheckResult {
            name: format!("{}:{}", dc, port),
            passed,
            message: format!("{} — {}", name, message),
            hint: if !passed {
                Some(format!(
                    "Port {} appears to be filtered or the service is down",
                    port
                ))
            } else {
                None
            },
        });
    }

    // Clock skew check via LDAP RootDSE
    results.push(check_clock_skew(dc).await);

    // LDAP channel binding enforcement check
    results.push(check_ldap_channel_binding(dc).await);

    // NTLM authentication policy check
    results.push(check_ntlm_policy(dc).await);

    // SMB protocol negotiation check
    results.push(check_smb_negotiate(dc).await);

    // DNS resolution check
    results.push(check_dns_resolution(dc).await);

    // Kerberos protocol-level probe
    results.push(check_kdc_probe(dc).await);

    // WinRM protocol-level probe
    results.push(check_winrm_probe(dc).await);

    // RPC Endpoint Mapper probe
    results.push(check_epm_probe(dc).await);

    results
}

/// Check clock skew between local system and a DC via LDAP RootDSE `currentTime`.
/// Kerberos tolerates up to 5 minutes of clock difference.
async fn check_clock_skew(dc_ip: &str) -> CheckResult {
    let url = format!("ldap://{}:389", dc_ip);
    let ldap_result = ldap3::LdapConnAsync::new(&url).await;
    let (conn, mut ldap) = match ldap_result {
        Ok(pair) => pair,
        Err(e) => {
            return CheckResult {
                name: "clock_skew".to_string(),
                passed: false,
                message: format!("LDAP connect failed: {e}"),
                hint: Some("Ensure port 389 is reachable on the DC".to_string()),
            };
        }
    };
    // Drive the connection in the background
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            tracing::debug!("LDAP connection driver error: {e}");
        }
    });

    // Anonymous bind
    if let Err(e) = ldap.simple_bind("", "").await {
        return CheckResult {
            name: "clock_skew".to_string(),
            passed: false,
            message: format!("LDAP anonymous bind failed: {e}"),
            hint: Some("DC may not allow anonymous LDAP binds".to_string()),
        };
    }

    // Query RootDSE for currentTime
    let search = ldap
        .search(
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["currentTime"],
        )
        .await;
    let _ = ldap.unbind().await;

    let (entries, _) = match search {
        Ok(result) => match result.success() {
            Ok(r) => r,
            Err(e) => {
                return CheckResult {
                    name: "clock_skew".to_string(),
                    passed: false,
                    message: format!("LDAP search failed: {e}"),
                    hint: None,
                };
            }
        },
        Err(e) => {
            return CheckResult {
                name: "clock_skew".to_string(),
                passed: false,
                message: format!("LDAP search error: {e}"),
                hint: None,
            };
        }
    };

    // Parse currentTime (GeneralizedTime: YYYYMMDDHHmmSS.0Z)
    let dc_time_str = entries.first().and_then(|e| {
        let se = ldap3::SearchEntry::construct(e.clone());
        se.attrs.get("currentTime").and_then(|v| v.first().cloned())
    });

    let dc_time_str = match dc_time_str {
        Some(s) => s,
        None => {
            return CheckResult {
                name: "clock_skew".to_string(),
                passed: false,
                message: "DC did not return currentTime attribute".to_string(),
                hint: None,
            };
        }
    };

    // Parse "20250101120000.0Z" format
    let trimmed = dc_time_str
        .trim_end_matches('Z')
        .split('.')
        .next()
        .unwrap_or(&dc_time_str);
    let dc_time = match NaiveDateTime::parse_from_str(trimmed, "%Y%m%d%H%M%S") {
        Ok(t) => t.and_utc(),
        Err(e) => {
            return CheckResult {
                name: "clock_skew".to_string(),
                passed: false,
                message: format!("Failed to parse DC time '{dc_time_str}': {e}"),
                hint: None,
            };
        }
    };

    let local_time = Utc::now();
    let skew = (dc_time - local_time).num_seconds().unsigned_abs();
    let skew_mins = skew / 60;
    let skew_secs = skew % 60;

    if skew > 300 {
        // > 5 minutes — Kerberos will reject
        CheckResult {
            name: "clock_skew".to_string(),
            passed: false,
            message: format!("CRITICAL: {skew_mins}m {skew_secs}s skew (Kerberos max: 5m)"),
            hint: Some(
                "Sync your clock: sudo ntpdate <dc_ip> or timedatectl set-ntp true".to_string(),
            ),
        }
    } else if skew > 240 {
        // > 4 minutes — warning
        CheckResult {
            name: "clock_skew".to_string(),
            passed: true,
            message: format!("WARNING: {skew_mins}m {skew_secs}s skew (close to 5m limit)"),
            hint: Some("Consider syncing your clock to avoid Kerberos failures".to_string()),
        }
    } else {
        CheckResult {
            name: "clock_skew".to_string(),
            passed: true,
            message: format!("{skew_mins}m {skew_secs}s skew (within Kerberos tolerance)"),
            hint: None,
        }
    }
}

/// Check LDAP channel binding enforcement policy on a DC.
/// Queries RootDSE for supportedCapabilities and domain functionality level
/// to determine if channel binding is likely enforced.
///
/// Windows Server 2025 (functionality level 7+) defaults to "Required" for
/// LDAP channel binding. Older servers default to "When supported" (Negotiate).
async fn check_ldap_channel_binding(dc_ip: &str) -> CheckResult {
    let url = format!("ldap://{}:389", dc_ip);
    let ldap_result = ldap3::LdapConnAsync::new(&url).await;
    let (conn, mut ldap) = match ldap_result {
        Ok(pair) => pair,
        Err(e) => {
            return CheckResult {
                name: "ldap_channel_binding".to_string(),
                passed: false,
                message: format!("LDAP connect failed: {e}"),
                hint: Some("Ensure port 389 is reachable on the DC".to_string()),
            };
        }
    };
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            tracing::debug!("LDAP connection driver error: {e}");
        }
    });

    if let Err(e) = ldap.simple_bind("", "").await {
        return CheckResult {
            name: "ldap_channel_binding".to_string(),
            passed: false,
            message: format!("LDAP anonymous bind failed: {e}"),
            hint: Some("DC may not allow anonymous LDAP binds".to_string()),
        };
    }

    let search = ldap
        .search(
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec![
                "supportedCapabilities",
                "supportedExtension",
                "domainFunctionality",
                "forestFunctionality",
                "domainControllerFunctionality",
            ],
        )
        .await;
    let _ = ldap.unbind().await;

    let (entries, _) = match search {
        Ok(result) => match result.success() {
            Ok(r) => r,
            Err(e) => {
                return CheckResult {
                    name: "ldap_channel_binding".to_string(),
                    passed: false,
                    message: format!("RootDSE search failed: {e}"),
                    hint: None,
                };
            }
        },
        Err(e) => {
            return CheckResult {
                name: "ldap_channel_binding".to_string(),
                passed: false,
                message: format!("RootDSE search error: {e}"),
                hint: None,
            };
        }
    };

    let entry = match entries.first() {
        Some(e) => ldap3::SearchEntry::construct(e.clone()),
        None => {
            return CheckResult {
                name: "ldap_channel_binding".to_string(),
                passed: false,
                message: "Empty RootDSE response".to_string(),
                hint: None,
            };
        }
    };

    // Check domain functionality level
    let dc_functionality = entry
        .attrs
        .get("domainControllerFunctionality")
        .and_then(|v| v.first())
        .map(|s| s.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);

    // Check for policy hints OID (1.2.840.113556.1.4.2237)
    let has_policy_hints = entry
        .attrs
        .get("supportedExtension")
        .map(|exts| exts.iter().any(|e| e.contains("1.2.840.113556.1.4.2237")))
        .unwrap_or(false);

    // Check for LDAP signing policy OID (1.2.840.113556.1.4.1791)
    let _has_signing_policy = entry
        .attrs
        .get("supportedExtension")
        .map(|exts| exts.iter().any(|e| e.contains("1.2.840.113556.1.4.1791")))
        .unwrap_or(false);

    // Determine channel binding enforcement level
    // Functionality levels: 0=2000, 1=2003, 2=2008, 3=2008R2, 4=2012, 5=2012R2, 6=2016, 7=2025
    let cb_status = if dc_functionality >= 7 {
        // WS 2025: defaults to "Required" for channel binding
        "Required"
    } else if dc_functionality >= 6 {
        // WS 2016/2019/2022: defaults to "When supported" (Negotiate)
        "Negotiate"
    } else {
        // Older: typically "Never" or "When supported"
        "Negotiate (likely)"
    };

    let os_label = match dc_functionality {
        0 => "Windows 2000",
        1 => "Windows 2003",
        2 => "Windows 2008",
        3 => "Windows 2008 R2",
        4 => "Windows 2012",
        5 => "Windows 2012 R2",
        6 => "Windows 2016/2019/2022",
        7 => "Windows Server 2025",
        _ => "Unknown",
    };

    if cb_status == "Required" {
        CheckResult {
            name: "ldap_channel_binding".to_string(),
            passed: false,
            message: format!("CB={cb_status} on {os_label} (level {dc_functionality}) — relay to LDAPS will fail"),
            hint: Some("Channel binding is REQUIRED. NTLM relay to LDAPS is cryptographically impossible. Use pure Kerberos paths (Kerberoast, ASREPRoast, DCSync) instead.".to_string()),
        }
    } else {
        CheckResult {
            name: "ldap_channel_binding".to_string(),
            passed: true,
            message: format!(
                "CB={cb_status} on {os_label} (level {dc_functionality}) — relay bypass should work"
            ),
            hint: if has_policy_hints {
                Some("Server supports policy hints OID. Our relay strips MsvAvChannelBindings AV_PAIRs to bypass CBT in Negotiate mode.".to_string())
            } else {
                None
            },
        }
    }
}

/// Check NTLM authentication policy on a DC.
/// Queries RootDSE for domain functionality level and security-relevant
/// attributes to assess NTLM relay viability.
///
/// Note: NTLM blocking is a domain policy (GPO) that cannot be reliably
/// detected remotely. This check provides guidance based on the DC's
/// functionality level and known defaults.
async fn check_ntlm_policy(dc_ip: &str) -> CheckResult {
    let url = format!("ldap://{}:389", dc_ip);
    let ldap_result = ldap3::LdapConnAsync::new(&url).await;
    let (conn, mut ldap) = match ldap_result {
        Ok(pair) => pair,
        Err(e) => {
            return CheckResult {
                name: "ntlm_policy".to_string(),
                passed: false,
                message: format!("LDAP connect failed: {e}"),
                hint: Some("Ensure port 389 is reachable on the DC".to_string()),
            };
        }
    };
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            tracing::debug!("LDAP connection driver error: {e}");
        }
    });

    if let Err(e) = ldap.simple_bind("", "").await {
        return CheckResult {
            name: "ntlm_policy".to_string(),
            passed: false,
            message: format!("LDAP anonymous bind failed: {e}"),
            hint: Some("DC may not allow anonymous LDAP binds".to_string()),
        };
    }

    let search = ldap
        .search(
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec![
                "domainFunctionality",
                "forestFunctionality",
                "domainControllerFunctionality",
                "supportedSASLMechanisms",
            ],
        )
        .await;
    let _ = ldap.unbind().await;

    let (entries, _) = match search {
        Ok(result) => match result.success() {
            Ok(r) => r,
            Err(e) => {
                return CheckResult {
                    name: "ntlm_policy".to_string(),
                    passed: false,
                    message: format!("RootDSE search failed: {e}"),
                    hint: None,
                };
            }
        },
        Err(e) => {
            return CheckResult {
                name: "ntlm_policy".to_string(),
                passed: false,
                message: format!("RootDSE search error: {e}"),
                hint: None,
            };
        }
    };

    let entry = match entries.first() {
        Some(e) => ldap3::SearchEntry::construct(e.clone()),
        None => {
            return CheckResult {
                name: "ntlm_policy".to_string(),
                passed: false,
                message: "Empty RootDSE response".to_string(),
                hint: None,
            };
        }
    };

    let dc_functionality = entry
        .attrs
        .get("domainControllerFunctionality")
        .and_then(|v| v.first())
        .map(|s| s.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);

    let sasl_mechs = entry
        .attrs
        .get("supportedSASLMechanisms")
        .map(|v| v.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>())
        .unwrap_or_default();

    let has_gssapi = sasl_mechs.iter().any(|m| m.contains("gssapi"));
    let has_ntlm = sasl_mechs
        .iter()
        .any(|m| m.contains("ntlm") || m.contains("gss-spnego"));

    let os_label = match dc_functionality {
        7 => "Windows Server 2025",
        6 => "Windows 2016/2019/2022",
        5 => "Windows 2012 R2",
        4 => "Windows 2012",
        _ => "Older",
    };

    if dc_functionality >= 7 && !has_ntlm {
        // WS 2025 without NTLM in SASL mechanisms = likely NTLM blocked
        CheckResult {
            name: "ntlm_policy".to_string(),
            passed: false,
            message: format!("NTLM likely BLOCKED on {os_label} (no NTLM in SASL mechanisms)"),
            hint: Some("NTLM relay will not work. Pure Kerberos paths (Kerberoast, ASREPRoast, DCSync via RPC, LDAP with GSSAPI) still function.".to_string()),
        }
    } else if has_gssapi {
        CheckResult {
            name: "ntlm_policy".to_string(),
            passed: true,
            message: format!("GSSAPI available on {os_label} — Kerberos auth works; NTLM status depends on domain policy"),
            hint: Some("If NTLM is blocked by GPO, use Kerberos-based tools (kerberoast, asreproast, dcsync). NTLM relay requires NTLM to be accepted by the target.".to_string()),
        }
    } else {
        CheckResult {
            name: "ntlm_policy".to_string(),
            passed: true,
            message: format!("NTLM appears available on {os_label}"),
            hint: None,
        }
    }
}

/// Perform SMB protocol negotiation against the target DC.
/// Tests SMB2 transport and reports highest dialect and signing configuration.
async fn check_smb_negotiate(dc: &str) -> CheckResult {
    match overthrone_core::proto::netbios::smb_negotiate(dc).await {
        Ok(result) => {
            let mut details = vec![format!("dialect: {}", result.highest_dialect)];
            if result.signing_required {
                details.push("signing: REQUIRED".to_string());
            } else if result.signing_enabled {
                details.push("signing: enabled (not required)".to_string());
            } else {
                details.push("signing: disabled".to_string());
            }
            if let Some(ref os) = result.native_os {
                details.push(format!("OS: {os}"));
            }
            CheckResult {
                name: "smb_negotiate".to_string(),
                passed: true,
                message: details.join(", "),
                hint: if result.signing_required {
                    Some("SMB signing is required. NTLM relay to SMB will fail. Use Kerberos-based relay instead.".to_string())
                } else {
                    None
                },
            }
        }
        Err(e) => CheckResult {
            name: "smb_negotiate".to_string(),
            passed: false,
            message: format!("SMB2 negotiate failed: {e}"),
            hint: Some("Ensure port 445 is open and the target is running SMB2+".to_string()),
        },
    }
}

/// Check DNS resolution for the target DC.
/// Tests forward resolution and LDAP/Kerberos SRV record availability.
async fn check_dns_resolution(dc: &str) -> CheckResult {
    // Forward resolution
    let forward_ok = match format!("{dc}:0").to_socket_addrs() {
        Ok(mut addrs) => addrs.any(|a| a.is_ipv4() || a.is_ipv6()),
        Err(_) => false,
    };

    // Try SRV lookups via system DNS
    let srv_results = match overthrone_core::proto::dns::DnsResolver::system() {
        Ok(resolver) => {
            let ldap_srv = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                resolver.lookup_srv("_ldap._tcp"),
            )
            .await;

            let kerb_srv = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                resolver.lookup_srv("_kerberos._tcp"),
            )
            .await;

            match (ldap_srv, kerb_srv) {
                (Ok(Ok(ldap)), Ok(Ok(kerb))) => {
                    let l = ldap.len();
                    let k = kerb.len();
                    Some(format!(
                        "LDAP SRV: {l} record(s), Kerberos SRV: {k} record(s)"
                    ))
                }
                _ => None,
            }
        }
        Err(_) => None,
    };

    let message = if forward_ok {
        let mut msg = "forward resolution OK".to_string();
        if let Some(srv) = &srv_results {
            msg.push_str(&format!(", {srv}"));
        }
        msg
    } else {
        "forward resolution FAILED".to_string()
    };

    CheckResult {
        name: "dns_resolution".to_string(),
        passed: forward_ok,
        message,
        hint: if !forward_ok {
            Some("DC hostname does not resolve. Check DNS configuration or use --dc with an IP address.".to_string())
        } else if srv_results.is_none() {
            Some("SRV records not resolvable via system DNS. Kerberos DNS discovery may not work without proper DNS configuration.".to_string())
        } else {
            None
        },
    }
}

/// Send a minimal Kerberos AS-REQ to the target DC to verify the KDC is alive
/// and processing requests at the protocol level.
async fn check_kdc_probe(dc: &str) -> CheckResult {
    match overthrone_core::proto::kerberos::probe_kdc(dc).await {
        Ok(status) => {
            let passed = !status.contains("unreachable");
            let hint = if !passed {
                Some("Ensure port 88 (TCP/UDP) is accessible and the KDC service is running on the target DC".to_string())
            } else if status.contains("PREAUTH_REQUIRED") {
                None // This is the normal/healthy response
            } else if status.contains("no pre-auth required") {
                Some("The KDC does not require pre-authentication for this user. Consider checking for AS-REP roasting targets.".to_string())
            } else {
                None
            };
            CheckResult {
                name: "kdc_probe".to_string(),
                passed,
                message: format!("Kerberos KDC: {status}"),
                hint,
            }
        }
        Err(e) => CheckResult {
            name: "kdc_probe".to_string(),
            passed: false,
            message: format!("Kerberos probe failed: {e}"),
            hint: Some("The KDC request could not be completed. Check network connectivity and KDC health.".to_string()),
        },
    }
}

/// Probe the WinRM HTTP listener on the target.
/// Sends a minimal HTTP GET to port 5985 and checks for an HTTP response
/// with WWW-Authenticate header (proves WinRM is alive).
async fn check_winrm_probe(dc: &str) -> CheckResult {
    match overthrone_core::exec::winrm::probe_winrm(dc).await {
        Ok(status) => {
            let passed = !status.contains("unreachable") && !status.contains("timeout");
            let hint = if !passed {
                Some(
                    "Ensure port 5985 is open and the WinRM service is running on the target"
                        .to_string(),
                )
            } else {
                None
            };
            CheckResult {
                name: "winrm_probe".to_string(),
                passed,
                message: status,
                hint,
            }
        }
        Err(e) => CheckResult {
            name: "winrm_probe".to_string(),
            passed: false,
            message: format!("WinRM probe failed: {e}"),
            hint: Some(
                "The WinRM request could not be completed. Check WinRM configuration.".to_string(),
            ),
        },
    }
}

/// Probe the RPC Endpoint Mapper on the target.
/// Connects to port 135, performs a DCE/RPC bind to EPMAPPER_UUID.
async fn check_epm_probe(dc: &str) -> CheckResult {
    match overthrone_core::proto::epm::probe_epm(dc).await {
        Ok(status) => {
            let passed = !status.contains("unreachable")
                && !status.contains("timeout")
                && status.contains("accepted");
            let hint = if !passed {
                Some(
                    "Ensure port 135 is open and the RPC Endpoint Mapper service is running"
                        .to_string(),
                )
            } else {
                None
            };
            CheckResult {
                name: "epm_probe".to_string(),
                passed,
                message: status,
                hint,
            }
        }
        Err(e) => CheckResult {
            name: "epm_probe".to_string(),
            passed: false,
            message: format!("EPM probe failed: {e}"),
            hint: Some("The RPC EPM request could not be completed.".to_string()),
        },
    }
}
