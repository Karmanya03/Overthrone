//! Environment diagnostics command — `ovt doctor`
//!
//! Checks your environment for required dependencies, network connectivity,
//! and platform-specific features. Because knowing is half the battle.
//! (The other half is actually hacking things, but we can't help you there.)

use crate::banner;
use colored::Colorize;
use std::process::Command;
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
        check_smbclient(),
        check_libsmbclient(),
        check_kerberos_config(),
        check_winrm_adapter(),
        check_network_ports(),
    ];

    let results: Vec<CheckResult> = if let Some(specific) = checks {
        all_checks
            .into_iter()
            .filter(|c| specific.iter().any(|s| c.name.to_lowercase().contains(&s.to_lowercase())))
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

        println!(
            "  {} {:<20} {}",
            status,
            result.name.white(),
            result.message.dimmed()
        );

        if let Some(ref hint) = result.hint {
            println!("    {} {}", "→".yellow(), hint.yellow().dimmed());
        }
    }

    // Summary
    println!();
    println!(
        "  {} {} passed, {} failed",
        if failed == 0 { "✓".green() } else { "!".yellow() },
        passed.to_string().cyan(),
        failed.to_string().red()
    );

    if failed > 0 {
        println!(
            "  {} Some checks failed. Read the hints above, or consult the docs.",
          "!".yellow()
        );
    } else {
        println!(
            "  {} All systems go. Go overthrow something.",
            "✓".green()
        );
    }

    if failed > 0 { 1 } else { 0 }
}

/// Check platform and available features
fn check_platform() -> CheckResult {
    let (platform, features) = if cfg!(windows) {
        (
            "Windows",
            vec!["SMB (native)", "WinRM (native)", "NTLM (SSPI)"],
        )
    } else if cfg!(target_os = "linux") {
        (
            "Linux",
            vec!["SMB (pavao/libsmbclient)", "WinRM (WS-Man)", "NTLM (ntlmclient)"],
        )
    } else if cfg!(target_os = "macos") {
        (
            "macOS",
            vec!["SMB (pavao/libsmbclient)", "WinRM (WS-Man)", "NTLM (ntlmclient)"],
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

/// Check if smbclient CLI is available
fn check_smbclient() -> CheckResult {
    #[cfg(windows)]
    {
        CheckResult {
            name: "smbclient".to_string(),
            passed: true,
            message: "Not needed on Windows (native SMB)".to_string(),
            hint: None,
        }
    }

    #[cfg(not(windows))]
    {
        let result = Command::new("smbclient")
            .arg("--version")
            .output();

        match result {
            Ok(output) if output.status.success() => {
                let version = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or("installed")
                    .trim()
                    .to_string();
                CheckResult {
                    name: "smbclient".to_string(),
                    passed: true,
                    message: version,
                    hint: None,
                }
            }
            Ok(_) => CheckResult {
                name: "smbclient".to_string(),
                passed: false,
                message: "found but not executable".to_string(),
                hint: Some("apt install smbclient (Debian/Ubuntu) or brew install samba (macOS)".to_string()),
            },
            Err(_) => CheckResult {
                name: "smbclient".to_string(),
                passed: false,
                message: "not found".to_string(),
                hint: Some("apt install smbclient (Debian/Ubuntu) or brew install samba (macOS)".to_string()),
            },
        }
    }
}

/// Check if libsmbclient library is available
fn check_libsmbclient() -> CheckResult {
    #[cfg(windows)]
    {
        CheckResult {
            name: "libsmbclient".to_string(),
            passed: true,
            message: "Not needed on Windows (native SMB)".to_string(),
            hint: None,
        }
    }

    #[cfg(not(windows))]
    {
        // Try to find libsmbclient via ldconfig or pkg-config
        let ldconfig = Command::new("sh")
            .arg("-c")
            .arg("ldconfig -p 2>/dev/null | grep -i libsmbclient || pkg-config --exists libsmbclient 2>/dev/null && echo found")
            .output();

        let found = ldconfig
            .map(|o| !o.stdout.is_empty() && String::from_utf8_lossy(&o.stdout).contains("found"))
            .unwrap_or(false);

        // Alternative: check for the library file directly
        let alt_check = std::fs::metadata("/usr/lib/x86_64-linux-gnu/libsmbclient.so")
            .or_else(|_| std::fs::metadata("/usr/lib/libsmbclient.so"))
            .or_else(|_| std::fs::metadata("/usr/local/lib/libsmbclient.so"))
            .or_else(|_| std::fs::metadata("/opt/homebrew/lib/libsmbclient.dylib"))
            .is_ok();

        if found || alt_check {
            CheckResult {
                name: "libsmbclient".to_string(),
                passed: true,
                message: "library available".to_string(),
                hint: None,
            }
        } else {
            CheckResult {
                name: "libsmbclient".to_string(),
                passed: false,
                message: "not found".to_string(),
                hint: Some("apt install libsmbclient-dev (Debian/Ubuntu) or brew install samba (macOS)".to_string()),
            }
        }
    }
}

/// Check for Kerberos configuration
fn check_kerberos_config() -> CheckResult {
    #[cfg(windows)]
    {
        // Windows has built-in Kerberos via SSPI
        CheckResult {
            name: "kerberos".to_string(),
            passed: true,
            message: "Native Windows Kerberos (SSPI)".to_string(),
            hint: None,
        }
    }

    #[cfg(not(windows))]
    {
        let config_paths = [
            "/etc/krb5.conf",
            "/etc/krb5/krb5.conf",
            &format!("{}/.krb5.conf", std::env::var("HOME").unwrap_or_default()),
        ];

        for path in &config_paths {
            if std::fs::metadata(path).is_ok() {
                return CheckResult {
                    name: "kerberos".to_string(),
                    passed: true,
                    message: format!("config found at {}", path),
                    hint: None,
                };
            }
        }

        // Check for MIT Kerberos binary
        let kinit = Command::new("kinit").arg("--version").output();
        if kinit.map(|o| o.status.success()).unwrap_or(false) {
            return CheckResult {
                name: "kerberos".to_string(),
                passed: true,
                message: "kinit available, but no krb5.conf found".to_string(),
                hint: Some("Create /etc/krb5.conf for your domain".to_string()),
            };
        }

        CheckResult {
            name: "kerberos".to_string(),
            passed: false,
            message: "no krb5.conf found".to_string(),
            hint: Some("apt install krb5-user (Debian/Ubuntu) or brew install krb5 (macOS)".to_string()),
        }
    }
}

/// Check for WinRM adapter availability
fn check_winrm_adapter() -> CheckResult {
    let mut adapters = Vec::new();

    // Native support
    #[cfg(windows)]
    adapters.push("native Win32 API");

    #[cfg(not(windows))]
    adapters.push("native WS-Man (ntlmclient)");

    // Check for winrs
    if Command::new("winrs").arg("-?").output().is_ok() {
        adapters.push("winrs");
    }

    // Check for evil-winrm (Ruby gem)
    if Command::new("evil-winrm").arg("--version").output().is_ok() {
        adapters.push("evil-winrm");
    }

    // Check for pywinrm
    if Command::new("python3")
        .args(["-c", "import winrm"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        adapters.push("pywinrm");
    }

    if adapters.is_empty() {
        CheckResult {
            name: "winrm".to_string(),
            passed: false,
            message: "no adapters found".to_string(),
            hint: Some("Install evil-winrm (gem install evil-winrm) or pywinrm".to_string()),
        }
    } else {
        CheckResult {
            name: "winrm".to_string(),
            passed: true,
            message: adapters.join(", "),
            hint: None,
        }
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
        let addr = format!("127.0.0.1:{}", port);
        if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(100)).is_ok() {
            available.push(*name);
        } else {
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
        let result = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            Duration::from_secs(3),
        );

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
                Some(format!("Port {} appears to be filtered or the service is down", port))
            } else {
                None
            },
        });
    }

    results
}