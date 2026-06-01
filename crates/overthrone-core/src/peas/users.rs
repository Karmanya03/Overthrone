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

fn run_cmd(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("cmd")
        .args(["/C"].into_iter().chain(args.iter().copied()))
        .output()
        .map_err(|e| format!("Failed to execute cmd: {}", e))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("cmd error: {}", stderr))
    }
}

pub async fn enumerate() -> PeasResult {
    let mut findings = Vec::new();

    if cfg!(target_os = "windows") {
        // whoami /all
        match run_cmd(&["whoami", "/all"]) {
            Ok(output) => {
                let is_admin = output.contains("S-1-16-12288");
                let mut data = HashMap::new();
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "Current User Details".into(),
                    description: format!(
                        "Current user token: {}",
                        if is_admin { "Administrator" } else { "Standard User" }
                    ),
                    severity: if is_admin { PeasSeverity::High } else { PeasSeverity::Info },
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Current User Details".into(),
                    description: "Failed to get current user details".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Local administrators
        match run_cmd(&["net", "localgroup", "Administrators"]) {
            Ok(output) => {
                let members: Vec<&str> = output
                    .lines()
                    .skip_while(|l| !l.contains("---"))
                    .skip(1)
                    .take_while(|l| !l.trim().is_empty())
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .collect();
                let count = members.len();
                let mut data = HashMap::new();
                data.insert("member_count".into(), count.to_string());
                data.insert("members".into(), members.join(", "));
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "Local Administrators".into(),
                    description: format!("Found {} local administrator(s)", count),
                    severity: if count > 0 { PeasSeverity::Medium } else { PeasSeverity::Info },
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Local Administrators".into(),
                    description: "Failed to enumerate local administrators".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // All local users
        match run_powershell(
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon,Description | Format-List",
        ) {
            Ok(output) => {
                let count = output.lines().filter(|l| l.contains("Name :")).count();
                let mut data = HashMap::new();
                data.insert("user_count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Local Users".into(),
                    description: format!("Found {} local user(s)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Local Users".into(),
                    description: "Failed to enumerate local users".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Domain admin detection
        match run_powershell(
            "If ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { try { $group = Get-ADGroup -Identity 'Domain Admins' -ErrorAction Stop; Get-ADGroupMember -Identity $group | Select-Object Name,SamAccountName | Format-List } catch { 'Domain Admins group query failed or no AD module' } } else { 'Not domain-joined' }",
        ) {
            Ok(output) => {
                let count = output.lines().filter(|l| l.contains("Name :")).count();
                let mut data = HashMap::new();
                data.insert("domain_admin_count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Domain Admins".into(),
                    description: if count > 0 {
                        format!("Found {} domain admin(s)", count)
                    } else {
                        "No domain admins enumerated".into()
                    },
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Domain Admins".into(),
                    description: "Failed to enumerate domain admins".into(),
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
            description: "User enumeration checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Users & Groups".into(),
        findings,
    }
}
