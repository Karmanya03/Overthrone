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

fn run_reg_query(key: &str) -> Result<String, String> {
    let output = std::process::Command::new("reg")
        .args(["query", key])
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
        // AutoLogon credentials
        match run_reg_query(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
            Ok(output) => {
                let has_user = output.contains("DefaultUserName");
                let has_pass = output.contains("DefaultPassword");

                if has_pass {
                    let username = output
                        .lines()
                        .find(|l| l.contains("DefaultUserName"))
                        .and_then(|l| l.split("REG_SZ").last())
                        .map(|s| s.trim())
                        .unwrap_or("unknown")
                        .to_string();
                    let password = output
                        .lines()
                        .find(|l| l.contains("DefaultPassword"))
                        .and_then(|l| l.split("REG_SZ").last())
                        .map(|s| s.trim())
                        .unwrap_or("unknown")
                        .to_string();
                    let mut data = HashMap::new();
                    data.insert("raw".into(), output);
                    data.insert("username".into(), username.clone());
                    data.insert("password".into(), password.clone());
                    findings.push(PeasFinding {
                        name: "AutoLogon Credentials".into(),
                        description: format!(
                            "AutoLogon credentials FOUND! User: {}, Password: {}",
                            username, password
                        ),
                        severity: PeasSeverity::Critical,
                        data,
                    });
                } else {
                    let mut data = HashMap::new();
                    data.insert("raw".into(), output);
                    findings.push(PeasFinding {
                        name: "AutoLogon Credentials".into(),
                        description: format!(
                            "No AutoLogon password stored (DefaultUserName: {})",
                            has_user
                        ),
                        severity: PeasSeverity::Info,
                        data,
                    });
                }
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "AutoLogon Credentials".into(),
                    description: "Failed to query Winlogon registry".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // GPP passwords (Group Policy Preferences)
        match run_powershell(
            "Get-ChildItem -Path 'C:\\ProgramData\\Microsoft\\Group Policy\\History' -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-List",
        ) {
            Ok(output) => {
                if output.is_empty() {
                    let mut data = HashMap::new();
                    data.insert("status".into(), "no_gpp_files".into());
                    findings.push(PeasFinding {
                        name: "GPP Passwords".into(),
                        description: "No Group Policy History files found".into(),
                        severity: PeasSeverity::Info,
                        data,
                    });
                } else {
                    let mut data = HashMap::new();
                    data.insert("details".into(), output);
                    findings.push(PeasFinding {
                        name: "GPP Passwords".into(),
                        description: "Group Policy History files found (may contain cpassword)"
                            .into(),
                        severity: PeasSeverity::High,
                        data,
                    });
                }
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "GPP Passwords".into(),
                    description: "Failed to check GPP files".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // SAM backup
        match run_powershell("Test-Path 'C:\\Windows\\repair\\SAM'") {
            Ok(output) => {
                let exists = output.trim().eq_ignore_ascii_case("true");
                let mut data = HashMap::new();
                data.insert("sam_backup_exists".into(), exists.to_string());

                let sam_paths = [
                    "C:\\Windows\\repair\\SAM",
                    "C:\\Windows\\System32\\config\\SAM",
                ];
                for path in &sam_paths {
                    if let Ok(p) = run_powershell(&format!("Test-Path '{}'", path)) {
                        data.insert(format!("exists:{}", path), p.trim().to_string());
                    }
                }

                findings.push(PeasFinding {
                    name: "SAM Backup Detection".into(),
                    description: if exists {
                        "SAM backup file found at C:\\Windows\\repair\\SAM".into()
                    } else {
                        "No SAM backup found at C:\\Windows\\repair\\SAM".into()
                    },
                    severity: if exists {
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
                    name: "SAM Backup Detection".into(),
                    description: "Failed to check for SAM backup".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Additional: check for unattended install files
        match run_powershell(
            "Get-ChildItem -Path 'C:\\Windows\\Panther' -Filter 'Unattend*' -ErrorAction SilentlyContinue | Select-Object FullName | Format-List",
        ) {
            Ok(output) => {
                if output.is_empty() {
                    let mut data = HashMap::new();
                    data.insert("status".into(), "no_unattend".into());
                    findings.push(PeasFinding {
                        name: "Unattended Install Files".into(),
                        description: "No unattended install files found".into(),
                        severity: PeasSeverity::Info,
                        data,
                    });
                } else {
                    let mut data = HashMap::new();
                    data.insert("details".into(), output);
                    findings.push(PeasFinding {
                        name: "Unattended Install Files".into(),
                        description: "Unattended install files found (may contain credentials)"
                            .into(),
                        severity: PeasSeverity::High,
                        data,
                    });
                }
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Unattended Install Files".into(),
                    description: "Failed to check unattended install files".into(),
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
            description: "Credential checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Credentials & Secrets".into(),
        findings,
    }
}
