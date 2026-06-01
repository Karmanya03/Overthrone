use super::{PeasFinding, PeasResult, PeasSeverity};
use std::collections::HashMap;

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
        // Network shares
        match run_cmd(&["net", "share"]) {
            Ok(output) => {
                let share_lines: Vec<&str> = output
                    .lines()
                    .skip(2)
                    .take_while(|l| !l.trim().is_empty())
                    .collect();
                let count = share_lines.len();
                let mut data = HashMap::new();
                data.insert("share_count".into(), count.to_string());
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "Network Shares".into(),
                    description: format!("Found {} network share(s)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Network Shares".into(),
                    description: "Failed to enumerate network shares".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Listening ports via netstat
        match run_cmd(&["netstat", "-ano"]) {
            Ok(output) => {
                let listening: Vec<&str> = output
                    .lines()
                    .filter(|l| l.contains("LISTENING"))
                    .collect();
                let count = listening.len();
                let mut data = HashMap::new();
                data.insert("listening_count".into(), count.to_string());
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "Listening Ports".into(),
                    description: format!("Found {} listening port(s)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Listening Ports".into(),
                    description: "Failed to enumerate listening ports".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Network interfaces via PowerShell
        match run_powershell(
            "Get-NetIPAddress | Select-Object IPAddress,InterfaceAlias,AddressFamily | Format-List",
        ) {
            Ok(output) => {
                let count = output.lines().filter(|l| l.contains("IPAddress :")).count();
                let mut data = HashMap::new();
                data.insert("interface_count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Network Interfaces".into(),
                    description: format!("Found {} IP address(es) configured", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Network Interfaces".into(),
                    description: "Failed to enumerate network interfaces".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // DNS configuration
        match run_powershell(
            "Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | Format-List",
        ) {
            Ok(output) => {
                let mut data = HashMap::new();
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "DNS Servers".into(),
                    description: "DNS client server address configuration".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "DNS Servers".into(),
                    description: "Failed to enumerate DNS configuration".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // ARP table
        match run_cmd(&["arp", "-a"]) {
            Ok(output) => {
                let entries: Vec<&str> = output
                    .lines()
                    .filter(|l| l.contains("dynamic") || l.contains("static"))
                    .collect();
                let count = entries.len();
                let mut data = HashMap::new();
                data.insert("arp_entries".into(), count.to_string());
                data.insert("raw".into(), output);
                findings.push(PeasFinding {
                    name: "ARP Table".into(),
                    description: format!("Found {} ARP entr(ies)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "ARP Table".into(),
                    description: "Failed to enumerate ARP table".into(),
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
            description: "Network enumeration checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Network Information".into(),
        findings,
    }
}
