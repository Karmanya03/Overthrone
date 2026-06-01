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
        // All environment variables
        match run_powershell("Get-ChildItem Env: | Format-List") {
            Ok(output) => {
                let count = output.lines().filter(|l| l.contains(":")).count();
                let mut data = HashMap::new();
                data.insert("variable_count".into(), count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Environment Variables".into(),
                    description: format!("Found {} environment variable(s)", count),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Environment Variables".into(),
                    description: "Failed to enumerate environment variables".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // PATH variable analysis
        match run_powershell(
            "Get-ChildItem Env: | Where-Object { $_.Name -eq 'PATH' } | Select-Object Value | Format-List",
        ) {
            Ok(output) => {
                let mut data = HashMap::new();
                data.insert("raw".into(), output.clone());

                let path_val = output
                    .lines()
                    .find(|l| l.contains("Value :"))
                    .map(|l| l.split(':').next_back().unwrap_or("").trim())
                    .unwrap_or("");

                let dirs: Vec<&str> = path_val.split(';').filter(|d| !d.is_empty()).collect();
                data.insert("directory_count".into(), dirs.len().to_string());

                findings.push(PeasFinding {
                    name: "PATH Variable".into(),
                    description: format!("PATH contains {} director(ies)", dirs.len()),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "PATH Variable".into(),
                    description: "Failed to read PATH variable".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Check PATH for world-writable directories
        match run_powershell(
            r#"
$writable = @()
$env:Path -split ';' | ForEach-Object {
    $dir = $_.Trim()
    if (Test-Path $dir -ErrorAction SilentlyContinue) {
        try {
            $acl = Get-Acl -Path $dir -ErrorAction SilentlyContinue
            $access = $acl.Access | Where-Object {
                $_.IdentityReference -match 'Everyone|BUILTIN\\Users' -and
                $_.FileSystemRights -match 'Write|Modify|FullControl'
            }
            if ($access) {
                $writable += $dir
            }
        } catch {}
    }
}
if ($writable.Count -gt 0) { $writable -join "`n" } else { "None" }
"#,
        ) {
            Ok(output) => {
                let trimmed = output.trim();
                let has_writable = !trimmed.eq_ignore_ascii_case("None") && !trimmed.is_empty();
                let writable_dirs: Vec<String> = output.lines().filter(|l| l.contains(":\\")).map(String::from).collect();
                let writable_count = writable_dirs.len();
                let mut data = HashMap::new();
                data.insert("writable_count".into(), writable_count.to_string());
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Writable PATH Directories".into(),
                    description: if has_writable {
                        format!(
                            "Found {} world-writable director(ies) in PATH (dll hijacking risk)",
                            writable_count
                        )
                    } else {
                        "No world-writable directories found in PATH".into()
                    },
                    severity: if has_writable {
                        PeasSeverity::Medium
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
                    name: "Writable PATH Directories".into(),
                    description: "Failed to check writable PATH directories".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
        }

        // Sensitive variables
        match run_powershell(
            "Get-ChildItem Env: | Where-Object { $_.Name -match 'USERNAME|USERDOMAIN|COMPUTERNAME|SESSIONNAME|LOGONSERVER|HOMEPATH|HOMEDRIVE|USERPROFILE' } | Format-List",
        ) {
            Ok(output) => {
                let mut data = HashMap::new();
                data.insert("details".into(), output);
                findings.push(PeasFinding {
                    name: "Sensitive Environment Variables".into(),
                    description: "Environment variables revealing user/domain context".into(),
                    severity: PeasSeverity::Info,
                    data,
                });
            }
            Err(e) => {
                let mut data = HashMap::new();
                data.insert("error".into(), e);
                findings.push(PeasFinding {
                    name: "Sensitive Environment Variables".into(),
                    description: "Failed to query sensitive environment variables".into(),
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
            description: "Environment variable checks are Windows-only".into(),
            severity: PeasSeverity::Info,
            data,
        });
    }

    PeasResult {
        category: "Environment Variables".into(),
        findings,
    }
}
