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

/// High-value privilege that enables privilege escalation
fn is_dangerous_privilege(name: &str) -> Option<PeasSeverity> {
    match name {
        "SeBackupPrivilege" => Some(PeasSeverity::Critical),
        "SeRestorePrivilege" => Some(PeasSeverity::Critical),
        "SeTakeOwnershipPrivilege" => Some(PeasSeverity::Critical),
        "SeDebugPrivilege" => Some(PeasSeverity::Critical),
        "SeImpersonatePrivilege" => Some(PeasSeverity::High),
        "SeAssignPrimaryTokenPrivilege" => Some(PeasSeverity::High),
        "SeLoadDriverPrivilege" => Some(PeasSeverity::High),
        "SeTcbPrivilege" => Some(PeasSeverity::Critical),
        "SeCreateTokenPrivilege" => Some(PeasSeverity::Critical),
        _ => None,
    }
}

pub async fn enumerate() -> PeasResult {
    let mut findings = Vec::new();

    if cfg!(target_os = "windows") {
        // Get all privileges via whoami
        match run_cmd(&["whoami", "/priv"]) {
            Ok(output) => {
                let mut data = HashMap::new();
                data.insert("raw".into(), output.clone());

                let mut dangerous_found: Vec<String> = Vec::new();

                for line in output.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let priv_name = parts[0].trim();
                        let enabled = parts.get(1).unwrap_or(&"").trim();
                        if !priv_name.is_empty() && enabled.eq_ignore_ascii_case("Enabled")
                            && let Some(severity) = is_dangerous_privilege(priv_name) {
                                dangerous_found.push(priv_name.to_string());
                                let mut priv_data = HashMap::new();
                                priv_data.insert("privilege".into(), priv_name.to_string());
                                priv_data.insert("state".into(), "Enabled".into());
                                findings.push(PeasFinding {
                                    name: format!("Dangerous Privilege: {}", priv_name),
                                    description: format!(
                                        "{} is ENABLED - privilege escalation risk",
                                        priv_name
                                    ),
                                    severity,
                                    data: priv_data,
                                });
                            }
                    }
                }

                if dangerous_found.is_empty() {
                    findings.push(PeasFinding {
                        name: "Token Privileges".into(),
                        description: "No dangerous privileges enabled in current token".into(),
                        severity: PeasSeverity::Info,
                        data,
                    });
                }
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Token Privileges".into(),
                    description: "Failed to query token privileges".into(),
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
            description: "Token privilege checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Access Tokens".into(),
        findings,
    }
}
