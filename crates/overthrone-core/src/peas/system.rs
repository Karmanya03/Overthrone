use super::{PeasFinding, PeasResult, PeasSeverity};
use std::collections::HashMap;

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

fn run_reg_query(key: &str, value: &str) -> Result<String, String> {
    let output = std::process::Command::new("reg")
        .args(["query", key, "/v", value])
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

pub async fn enumerate() -> PeasResult {
    let mut findings = Vec::new();

    if cfg!(target_os = "windows") {
        // OS Version
        match run_powershell(
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | Format-List",
        ) {
            Ok(info) => {
                let mut data = HashMap::new();
                for line in info.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        data.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
                findings.push(PeasFinding {
                    name: "OS Version".into(),
                    description: "Operating system version and architecture".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "OS Version".into(),
                    description: "Failed to query OS version".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Hotfixes
        match run_powershell(
            "Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID,InstalledOn,Description | Format-List",
        ) {
            Ok(info) => {
                let count = info.lines().filter(|l| l.contains("HotFixID")).count();
                let mut data = HashMap::new();
                data.insert("hotfix_count".into(), count.to_string());
                data.insert("details".into(), info);
                findings.push(PeasFinding {
                    name: "Installed Hotfixes".into(),
                    description: format!("Found {} hotfix(es) installed", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Installed Hotfixes".into(),
                    description: "Failed to query hotfixes".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // UAC Status
        match run_reg_query(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        ) {
            Ok(output) => {
                let enabled = output.contains("0x1");
                let mut data = HashMap::new();
                data.insert("raw".into(), output);
                data.insert("enabled".into(), enabled.to_string());
                findings.push(PeasFinding {
                    name: "UAC Status".into(),
                    description: format!("UAC is {}", if enabled { "enabled" } else { "disabled" }),
                    severity: if enabled {
                        PeasSeverity::Info
                    } else {
                        PeasSeverity::Medium
                    },
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "UAC Status".into(),
                    description: "Failed to check UAC status".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Domain Join
        match run_powershell("(Get-CimInstance Win32_ComputerSystem).PartOfDomain") {
            Ok(info) => {
                let is_domain_joined = info.trim().eq_ignore_ascii_case("true");
                let mut data = HashMap::new();
                data.insert("part_of_domain".into(), is_domain_joined.to_string());
                findings.push(PeasFinding {
                    name: "Domain Join Status".into(),
                    description: format!(
                        "Machine is {} a domain",
                        if is_domain_joined {
                            "part of"
                        } else {
                            "NOT part of"
                        }
                    ),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Domain Join Status".into(),
                    description: "Failed to query domain join status".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Architecture
        match run_powershell("(Get-CimInstance Win32_OperatingSystem).OSArchitecture") {
            Ok(info) => {
                let mut data = HashMap::new();
                data.insert("architecture".into(), info.trim().to_string());
                findings.push(PeasFinding {
                    name: "System Architecture".into(),
                    description: format!("Architecture: {}", info.trim()),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "System Architecture".into(),
                    description: "Failed to query architecture".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }
    } else {
        let mut data = HashMap::new();
        data.insert("os".into(), std::env::consts::OS.to_string());
        findings.push(PeasFinding {
            name: "Platform".into(),
            description: "System information checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "System Information".into(),
        findings,
    }
}
