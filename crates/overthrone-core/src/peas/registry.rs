use super::{PeasFinding, PeasResult, PeasSeverity};
use std::collections::HashMap;

fn run_reg_query(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("reg")
        .args(["query"].iter().chain(args.iter()))
        .output()
        .map_err(|e| format!("Failed to query registry: {}", e))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("Registry query error: {}", stderr))
    }
}

fn run_powershell(script: &str) -> Result<String, String> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("PowerShell error: {}", stderr))
    }
}

pub async fn enumerate() -> PeasResult {
    let mut findings = Vec::new();

    if cfg!(target_os = "windows") {
        // AlwaysInstallElevated
        match run_reg_query(&[
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "/v",
            "EnableLUA",
        ]) {
            Ok(output) => {
                let always_install = output.contains("0x1");
                let mut data = HashMap::new();
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "AlwaysInstallElevated (UAC Policy)".into(),
                    description: format!(
                        "AlwaysInstallElevated is {}",
                        if always_install {
                            "ENABLED (vulnerable)"
                        } else {
                            "disabled"
                        }
                    ),
                    severity: if always_install {
                        PeasSeverity::High
                    } else {
                        PeasSeverity::Info
                    },
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "AlwaysInstallElevated".into(),
                    description: "Failed to check AlwaysInstallElevated".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Sticky Keys (sethc.exe debugger)
        match run_reg_query(&[
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
            "/v",
            "Debugger",
        ]) {
            Ok(output) => {
                let description = format!("Sticky Keys image hijack detected:\n{}", output);
                let mut data = HashMap::new();
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "Sticky Keys Backdoor (sethc.exe)".into(),
                    description,
                    severity: PeasSeverity::Medium,
                    data,
                });
            }
            Err(_) => {
                let mut data = HashMap::new();
                data.insert("status".into(), "not_configured".into());
                findings.push(PeasFinding {
                    name: "Sticky Keys Backdoor (sethc.exe)".into(),
                    description: "No sethc.exe Debugger override found (default)".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // HKCU AutoRun
        match run_reg_query(&[r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]) {
            Ok(output) => {
                let entries: Vec<String> = output
                    .lines()
                    .filter(|l| l.contains("REG_"))
                    .map(String::from)
                    .collect();
                let entry_count = entries.len();
                let mut data = HashMap::new();
                data.insert("entry_count".into(), entry_count.to_string());
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "HKCU AutoRun Programs".into(),
                    description: format!("Found {} auto-run entr(ies) in HKCU", entry_count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "HKCU AutoRun Programs".into(),
                    description: "Failed to query HKCU auto-run entries (may not exist)".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // HKLM AutoRun
        match run_reg_query(&[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]) {
            Ok(output) => {
                let entries: Vec<String> = output
                    .lines()
                    .filter(|l| l.contains("REG_"))
                    .map(String::from)
                    .collect();
                let entry_count = entries.len();
                let mut data = HashMap::new();
                data.insert("entry_count".into(), entry_count.to_string());
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "HKLM AutoRun Programs".into(),
                    description: format!("Found {} auto-run entr(ies) in HKLM", entry_count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "HKLM AutoRun Programs".into(),
                    description: "Failed to query HKLM auto-run entries".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // LSA security packages / WDigest
        match run_powershell(
            "Get-ItemProperty -Path 'HKLM:SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue | Select-Object UseLogonCredential",
        ) {
            Ok(output) => {
                let wdigest = output.contains("1");
                let mut data = HashMap::new();
                data.insert("wdigest_enabled".into(), wdigest.to_string());
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "WDigest Credential Caching".into(),
                    description: format!(
                        "WDigest UseLogonCredential is {}",
                        if wdigest {
                            "ENABLED (cleartext cached)"
                        } else {
                            "not set / disabled"
                        }
                    ),
                    severity: if wdigest {
                        PeasSeverity::High
                    } else {
                        PeasSeverity::Info
                    },
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "WDigest Credential Caching".into(),
                    description: "Failed to check WDigest (key may not exist)".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }
    } else {
        let mut data = HashMap::new();
        data.insert("platform".into(), std::env::consts::OS.to_string());
        findings.push(PeasFinding {
            name: "Platform".into(),
            description: "Registry checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Registry".into(),
        findings,
    }
}
