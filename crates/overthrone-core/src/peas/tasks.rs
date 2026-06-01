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
        // Get all scheduled tasks
        match run_powershell(
            "Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author,Description,Date | Format-List",
        ) {
            Ok(output) => {
                let task_count = output.lines().filter(|l| l.contains("TaskName :")).count();
                let mut data = HashMap::new();
                data.insert("task_count".into(), task_count.to_string());
                data.insert("details".into(), output.clone());
                findings.push(PeasFinding {
                    name: "Scheduled Tasks Overview".into(),
                    description: format!("Found {} scheduled task(s)", task_count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Scheduled Tasks Overview".into(),
                    description: "Failed to enumerate scheduled tasks".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Group by author
        match run_powershell(
            "Get-ScheduledTask | Group-Object -Property Author | Select-Object Name,Count | Format-List",
        ) {
            Ok(output) => {
                let mut data = HashMap::new();
                data.insert("author_groups".into(), output);
                findings.push(PeasFinding {
                    name: "Tasks Grouped by Author".into(),
                    description: "Scheduled tasks grouped by author".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Tasks Grouped by Author".into(),
                    description: "Failed to group tasks by author".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Group by state
        match run_powershell(
            "Get-ScheduledTask | Group-Object -Property State | Select-Object Name,Count | Format-List",
        ) {
            Ok(output) => {
                let mut data = HashMap::new();
                data.insert("state_groups".into(), output);
                findings.push(PeasFinding {
                    name: "Tasks Grouped by State".into(),
                    description: "Scheduled tasks grouped by state (Ready/Running/Disabled)".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Tasks Grouped by State".into(),
                    description: "Failed to group tasks by state".into(),
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
            description: "Scheduled task enumeration is Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Scheduled Tasks".into(),
        findings,
    }
}
