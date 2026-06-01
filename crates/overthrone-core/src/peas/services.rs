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

fn check_unquoted_path(path: &str) -> bool {
    if path.starts_with('"') {
        return false;
    }
    path.contains(' ')
}

pub async fn enumerate() -> PeasResult {
    let mut findings = Vec::new();

    if cfg!(target_os = "windows") {
        // Service listing
        match run_powershell(
            "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartName,PathName | Format-List",
        ) {
            Ok(output) => {
                let running_count = output.lines().filter(|l| l.contains("State : Running")).count();
                let system_count = output.lines().filter(|l| l.contains("StartName : LocalSystem")).count();
                let mut data = HashMap::new();
                data.insert("running_count".into(), running_count.to_string());
                data.insert("system_count".into(), system_count.to_string());
                data.insert("details".into(), output.clone());
                findings.push(PeasFinding {
                    name: "Running Services".into(),
                    description: format!(
                        "{} service(s) running, {} as SYSTEM",
                        running_count, system_count
                    ),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Running Services".into(),
                    description: "Failed to enumerate services".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Unquoted service paths
        match run_powershell(
            "Get-CimInstance Win32_Service | Select-Object Name,PathName,State,StartName | Format-List",
        ) {
            Ok(output) => {
                let mut unquoted: Vec<String> = Vec::new();
                let mut current_name = String::new();
                for line in output.lines() {
                    if let Some(val) = line.strip_prefix("Name : ") {
                        current_name = val.trim().to_string();
                    }
                    if let Some(val) = line.strip_prefix("PathName : ") {
                        let current_path = val.trim().to_string();
                        if check_unquoted_path(&current_path) && !current_name.is_empty() {
                            unquoted.push(format!("{} -> {}", current_name, current_path));
                        }
                    }
                }
                let mut data = HashMap::new();
                data.insert("unquoted_count".into(), unquoted.len().to_string());
                if !unquoted.is_empty() {
                    data.insert("services".into(), unquoted.join("\n"));
                }
                findings.push(PeasFinding {
                    name: "Unquoted Service Paths".into(),
                    description: if unquoted.is_empty() {
                        "No unquoted service paths found".into()
                    } else {
                        format!("Found {} service(s) with unquoted paths", unquoted.len())
                    },
                    severity: if unquoted.is_empty() {
                        PeasSeverity::Info
                    } else {
                        PeasSeverity::High
                    },
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Unquoted Service Paths".into(),
                    description: "Failed to check unquoted service paths".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Services running as SYSTEM
        match run_powershell(
            "Get-CimInstance Win32_Service | Where-Object { $_.StartName -eq 'LocalSystem' -and $_.State -eq 'Running' } | Select-Object Name,DisplayName,PathName | Format-List",
        ) {
            Ok(output) => {
                let count = output.lines().filter(|l| l.contains("Name :")).count();
                let mut data = HashMap::new();
                data.insert("count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Services Running as SYSTEM".into(),
                    description: format!("{} service(s) running as SYSTEM", count),
                    severity: PeasSeverity::Medium,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Services Running as SYSTEM".into(),
                    description: "Failed to enumerate SYSTEM services".into(),
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
            description: "Service enumeration checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Services".into(),
        findings,
    }
}
