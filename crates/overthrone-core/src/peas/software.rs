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

pub async fn enumerate() -> PeasResult {
    let mut findings = Vec::new();

    if cfg!(target_os = "windows") {
        // Installed software from HKLM
        match run_powershell(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object { $_.DisplayName } | Format-List",
        ) {
            Ok(output) => {
                let count = output.lines().filter(|l| l.contains("DisplayName :")).count();
                let mut data = HashMap::new();
                data.insert("installed_count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Installed Software (HKLM)".into(),
                    description: format!("Found {} installed application(s)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Installed Software (HKLM)".into(),
                    description: "Failed to enumerate installed software".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // 64-bit software from HKLM (WOW6432Node)
        if let Ok(output) = run_powershell(
            "Get-ItemProperty HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object { $_.DisplayName } | Format-List",
        )
            && !output.is_empty() {
                let count = output.lines().filter(|l| l.contains("DisplayName :")).count();
                let mut data = HashMap::new();
                data.insert("installed_count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Installed Software (WOW6432Node)".into(),
                    description: format!("Found {} 32-bit application(s)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }

        // HKCU installed software
        if let Ok(output) = run_powershell(
            "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object { $_.DisplayName } | Format-List",
        )
            && !output.is_empty() {
                let count = output.lines().filter(|l| l.contains("DisplayName :")).count();
                let mut data = HashMap::new();
                data.insert("installed_count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Installed Software (HKCU)".into(),
                    description: format!("Found {} user-installed application(s)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }

        // Antivirus / Security product detection
        match run_powershell(
            "Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object DisplayName,ProductState | Format-List",
        ) {
            Ok(output) => {
                if output.is_empty() {
                    let mut data = HashMap::new();
                    data.insert("status".into(), "no_av_detected".into());
                    findings.push(PeasFinding {
                        name: "Antivirus Products".into(),
                        description: "No antivirus products detected via WMI".into(),
                        severity: PeasSeverity::Info,
                        data,
                    });
                } else {
                    let count = output.lines().filter(|l| l.contains("DisplayName :")).count();
                    let mut data = HashMap::new();
                    data.insert("av_count".into(), count.to_string());
                    data.insert("details".into(), output);
                    findings.push(PeasFinding {
                        name: "Antivirus Products".into(),
                        description: format!("Found {} AV/security product(s)", count),
                        severity: PeasSeverity::Info,
                        data,
                    });
                }
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Antivirus Products".into(),
                    description: "Failed to detect AV products (SecurityCenter2 may not exist)".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Windows Defender status
        match run_powershell(
            "Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled | Format-List",
        ) {
            Ok(output) => {
                let mut data = HashMap::new();
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Windows Defender Status".into(),
                    description: "Windows Defender/Microsoft Defender status".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Windows Defender Status".into(),
                    description: "Failed to get Defender status".into(),
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
            description: "Software enumeration checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Software & Patches".into(),
        findings,
    }
}
