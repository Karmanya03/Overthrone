//! Environment diagnostics command — `ovt doctor`
//!
//! Checks your environment for required dependencies, network connectivity,
//! and platform-specific features. Because knowing is half the battle.
//! (The other half is actually hacking things, but we can't help you there.)

use crate::banner;
use chrono::{NaiveDateTime, Utc};
use colored::Colorize;
use std::net::TcpStream;

use std::time::Duration;

/// Result of a single diagnostic check
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub hint: Option<String>,
}

/// Run all environment diagnostics
pub async fn run(checks: Option<Vec<String>>) -> i32 {
    banner::print_module_banner("DOCTOR");

    println!(
        "  {} Running environment diagnostics...\n",
        "▸".bright_black()
    );

    let all_checks = vec![
        check_platform(),
        check_kerberos_config(),
        check_winrm_adapter(),
        check_network_ports(),
    ];

    let results: Vec<CheckResult> = if let Some(specific) = checks {
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

    // Print results
    let mut passed = 0usize;
    let mut failed = 0usize;

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

/// Check network connectivity to common AD ports
fn check_network_ports() -> CheckResult {
    // Default ports to check (localhost for now, user should specify DC)
    let ports = [
        (389, "LDAP"),
        (636, "LDAPS"),
        (445, "SMB"),
        (5985, "WinRM HTTP"),
        (5986, "WinRM HTTPS"),
        (88, "Kerberos"),
    ];

    let mut available = Vec::new();
    let mut unavailable = Vec::new();

    for (port, name) in &ports {
        // We check if we can bind to the port locally (not ideal, but safe)
        // For actual DC connectivity, user should test with actual target
        if let Ok(addr) = format!("127.0.0.1:{}", port).parse::<std::net::SocketAddr>() {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                available.push(*name);
            } else {
                unavailable.push(*name);
            }
        } else {
            tracing::warn!("Failed to parse address for port {}", port);
            unavailable.push(*name);
        }
    }

    // This check always passes since we're not actually testing a DC
    CheckResult {
        name: "network".to_string(),
        passed: true,
        message: "ports checked (use --dc to test specific DC)".to_string(),
        hint: Some("Run 'ovt doctor --dc 10.10.10.1' to test actual DC connectivity".to_string()),
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
