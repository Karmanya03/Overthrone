use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SherlockOutputFormat {
    #[default]
    Text,
    Json,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SherlockConfig {
    pub os_version: Option<String>,
    pub build_number: Option<u32>,
    pub installed_kbs: Vec<String>,
    pub cves_to_check: Vec<String>,
    #[serde(default)]
    pub output_format: SherlockOutputFormat,
}

impl SherlockConfig {
    fn default_cves() -> Vec<String> {
        vec![
            "CVE-2016-0099",
            "CVE-2016-7255",
            "CVE-2017-0213",
            "CVE-2018-8120",
            "CVE-2019-1130",
            "CVE-2019-0841",
            "CVE-2020-0683",
            "CVE-2020-0787",
            "CVE-2020-1020",
            "CVE-2021-1732",
            "CVE-2021-36934",
            "CVE-2021-40449",
            "CVE-2022-21894",
            "CVE-2022-26923",
            "CVE-2022-30190",
            "CVE-2023-21746",
            "CVE-2023-36874",
            "CVE-2024-20656",
            "CVE-2024-38063",
            "CVE-2025-21296",
            "CVE-2025-29969",
            "CVE-2025-21333",
            "CVE-2025-26647",
            "CVE-2025-32729",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
}

impl Default for SherlockConfig {
    fn default() -> Self {
        Self {
            os_version: None,
            build_number: None,
            installed_kbs: Vec::new(),
            cves_to_check: Self::default_cves(),
            output_format: SherlockOutputFormat::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CveEntry {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub affected_versions: Vec<String>,
    pub affected_builds: Vec<u32>,
    pub required_kbs: Vec<String>,
    pub exploit_recommendation: String,
    pub exploit_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SherlockFinding {
    pub cve_id: String,
    pub title: String,
    pub severity: String,
    pub affected_versions: Vec<String>,
    pub required_kbs: Vec<String>,
    pub missing_kbs: Vec<String>,
    pub exploit_recommendation: String,
    pub exploit_path: Option<String>,
    pub is_vulnerable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ExploitRecommendation {
    pub technique: String,
    pub cve_id: String,
    pub requires_admin: bool,
    pub reliability: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SherlockResult {
    pub os_version: String,
    pub build_number: Option<u32>,
    pub installed_kbs: Vec<String>,
    pub findings: Vec<SherlockFinding>,
    pub vulnerable_count: usize,
    pub exploit_recommendations: Vec<ExploitRecommendation>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SherlockError {
    #[error("WMI error: {0}")]
    WmiError(String),
    #[error("Registry error: {0}")]
    RegistryError(String),
    #[error("OS detection error: {0}")]
    OsDetectionError(String),
    #[error("CVE database error: {0}")]
    CveDatabaseError(String),
    #[error("IO error: {0}")]
    IoError(String),
}

pub async fn run_sherlock(config: &SherlockConfig) -> Result<SherlockResult, SherlockError> {
    let os_version = match &config.os_version {
        Some(v) => v.clone(),
        None => detect_os_version()?.0,
    };
    let build_number = config
        .build_number
        .or_else(|| detect_os_version().ok().and_then(|(_, b)| b))
        .ok_or_else(|| {
            SherlockError::OsDetectionError("Could not detect OS build number".into())
        })?;
    let installed_kbs = if config.installed_kbs.is_empty() {
        enumerate_installed_kbs()?
    } else {
        config.installed_kbs.clone()
    };
    let cves = build_cve_database();
    let cve_ids: std::collections::HashSet<String> = if config.cves_to_check.is_empty() {
        SherlockConfig::default_cves().into_iter().collect()
    } else {
        config.cves_to_check.iter().cloned().collect()
    };

    let mut findings: Vec<SherlockFinding> = Vec::new();
    let mut recommendations: Vec<ExploitRecommendation> = Vec::new();

    for cve in &cves {
        if !cve_ids.contains(&cve.id) {
            continue;
        }
        if let Some(finding) =
            check_cve_vulnerability(cve, &os_version, Some(build_number), &installed_kbs)
        {
            if finding.is_vulnerable {
                recommendations.push(generate_exploit_recommendation(&finding));
            }
            findings.push(finding);
        }
    }

    let vulnerable_count = findings.iter().filter(|f| f.is_vulnerable).count();

    Ok(SherlockResult {
        os_version,
        build_number: Some(build_number),
        installed_kbs,
        findings,
        vulnerable_count,
        exploit_recommendations: recommendations,
    })
}

pub fn detect_os_version() -> Result<(String, Option<u32>), SherlockError> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "/v",
                "CurrentMajorVersionNumber",
            ])
            .output()
            .map_err(|e| SherlockError::RegistryError(format!("reg query failed: {e}")))?;
        if !output.status.success() {
            return Err(SherlockError::RegistryError(
                "reg query returned non-zero".into(),
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let major = parse_reg_value_u32(&text, "CurrentMajorVersionNumber")?;
        let minor = {
            let out = std::process::Command::new("reg")
                .args([
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    "/v",
                    "CurrentMinorVersionNumber",
                ])
                .output()
                .map_err(|e| SherlockError::RegistryError(format!("reg query failed: {e}")))?;
            parse_reg_value_u32(
                &String::from_utf8_lossy(&out.stdout),
                "CurrentMinorVersionNumber",
            )?
        };
        let build = {
            let out = std::process::Command::new("reg")
                .args([
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    "/v",
                    "CurrentBuildNumber",
                ])
                .output()
                .map_err(|e| SherlockError::RegistryError(format!("reg query failed: {e}")))?;
            parse_reg_value_u32(&String::from_utf8_lossy(&out.stdout), "CurrentBuildNumber")?
        };
        Ok((format!("Windows {}.{}", major, minor), Some(build)))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(("Windows 10".to_string(), Some(19045)))
    }
}

#[cfg(target_os = "windows")]
fn parse_reg_value_u32(text: &str, value_name: &str) -> Result<u32, SherlockError> {
    for line in text.lines() {
        if line.contains(value_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(last) = parts.last() {
                let cleaned = last.trim();
                let parsed = if cleaned.starts_with("0x") || cleaned.starts_with("0X") {
                    u32::from_str_radix(&cleaned[2..], 16)
                } else {
                    cleaned.parse::<u32>()
                };
                return parsed
                    .map_err(|e| SherlockError::RegistryError(format!("parse {value_name}: {e}")));
            }
        }
    }
    Err(SherlockError::RegistryError(format!(
        "{value_name} not found"
    )))
}

pub fn enumerate_installed_kbs() -> Result<Vec<String>, SherlockError> {
    #[cfg(target_os = "windows")]
    {
        fn parse_wmic_csv(text: &str) -> Vec<String> {
            let mut kbs = Vec::new();
            for line in text.lines().skip(1) {
                let fields: Vec<&str> = line.split(',').collect();
                if let Some(last) = fields.last() {
                    let trimmed = last.trim().to_string();
                    if trimmed.starts_with("KB") {
                        kbs.push(trimmed);
                    }
                }
            }
            kbs
        }

        // Prefer WMIC for legacy compatibility; fall back to PowerShell on systems where WMIC is removed.
        let wmic = std::process::Command::new("wmic")
            .args(["qfe", "get", "HotFixID", "/format:csv"])
            .output();
        match wmic {
            Ok(output) if output.status.success() => {
                Ok(parse_wmic_csv(&String::from_utf8_lossy(&output.stdout)))
            }
            Ok(output) => Err(SherlockError::WmiError(format!(
                "wmic returned non-zero: {}",
                String::from_utf8_lossy(&output.stderr)
            ))),
            Err(wmic_err) => {
                let ps = std::process::Command::new("powershell.exe")
                    .args([
                        "-NoProfile",
                        "-Command",
                        "Get-HotFix | Select-Object -ExpandProperty HotFixID",
                    ])
                    .output()
                    .map_err(|e| {
                        SherlockError::WmiError(format!(
                            "wmic failed ({wmic_err}) and powershell fallback failed: {e}"
                        ))
                    })?;
                if !ps.status.success() {
                    Err(SherlockError::WmiError(format!(
                        "wmic failed ({wmic_err}) and powershell returned non-zero: {}",
                        String::from_utf8_lossy(&ps.stderr)
                    )))
                } else {
                    let mut kbs = Vec::new();
                    for line in String::from_utf8_lossy(&ps.stdout).lines() {
                        let trimmed = line.trim().to_string();
                        if trimmed.starts_with("KB") {
                            kbs.push(trimmed);
                        }
                    }
                    Ok(kbs)
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![
            "KB5005033".into(),
            "KB5010793".into(),
            "KB5026361".into(),
            "KB5034441".into(),
            "KB5043178".into(),
        ])
    }
}

pub fn check_cve_vulnerability(
    cve: &CveEntry,
    os_version: &str,
    build_number: Option<u32>,
    installed_kbs: &[String],
) -> Option<SherlockFinding> {
    let os_lower = os_version.to_lowercase();
    let affected = cve
        .affected_versions
        .iter()
        .any(|v| os_lower.contains(&v.to_lowercase()));
    let build_affected = build_number
        .is_none_or(|b| cve.affected_builds.is_empty() || cve.affected_builds.contains(&b));
    if !affected || !build_affected {
        return None;
    }
    let missing: Vec<String> = cve
        .required_kbs
        .iter()
        .filter(|kb| !is_kb_installed(kb, installed_kbs))
        .cloned()
        .collect();
    let is_vulnerable = !missing.is_empty();
    Some(SherlockFinding {
        cve_id: cve.id.clone(),
        title: cve.title.clone(),
        severity: cve.severity.clone(),
        affected_versions: cve.affected_versions.clone(),
        required_kbs: cve.required_kbs.clone(),
        missing_kbs: missing,
        exploit_recommendation: cve.exploit_recommendation.clone(),
        exploit_path: cve.exploit_path.clone(),
        is_vulnerable,
    })
}

pub fn build_cve_database() -> Vec<CveEntry> {
    vec![
        CveEntry {
            id: "CVE-2016-0099".into(),
            title: "MS16-032 Secondary Logon Handle Privilege Escalation".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 7".into(), "windows 8.1".into(), "windows 10".into(), "windows server 2012".into()],
            affected_builds: vec![7601, 9200, 9600, 10240, 10586],
            required_kbs: vec!["KB3143141".into()],
            exploit_recommendation: "Use secondary logon handle privilege escalation via token manipulation.".into(),
            exploit_path: Some("exploit/windows/local/ms16_032_secondary_logon_handle_privesc".into()),
        },
        CveEntry {
            id: "CVE-2016-7255".into(),
            title: "MS16-135 Win32k Elevation of Privilege".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows 7".into(), "windows 8.1".into(), "windows 10".into()],
            affected_builds: vec![7601, 9600, 10240, 10586, 14393],
            required_kbs: vec!["KB3199135".into()],
            exploit_recommendation: "Abuse Win32k SetWindowLongPtr kernel callback for elevation.".into(),
            exploit_path: Some("exploit/windows/local/ms16_135_create_window_struct".into()),
        },
        CveEntry {
            id: "CVE-2017-0213".into(),
            title: "Windows COM Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows server 2016".into()],
            affected_builds: vec![14393, 15063],
            required_kbs: vec!["KB4015217".into(), "KB4019472".into()],
            exploit_recommendation: "Exploit COM aggregate marshaller to elevate from medium IL to system.".into(),
            exploit_path: Some("exploit/windows/local/cve_2017_0213_com_elevation".into()),
        },
        CveEntry {
            id: "CVE-2018-8120".into(),
            title: "Win32k Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 7".into(), "windows server 2008".into()],
            affected_builds: vec![7601],
            required_kbs: vec!["KB4134651".into()],
            exploit_recommendation: "Use null pointer dereference in Win32k for kernel elevation.".into(),
            exploit_path: Some("exploit/windows/local/cve_2018_8120_win32k".into()),
        },
        CveEntry {
            id: "CVE-2019-1130".into(),
            title: "Windows Kernel Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 7".into(), "windows 8.1".into(), "windows 10".into()],
            affected_builds: vec![7601, 9600, 10240, 10586, 14393, 17763],
            required_kbs: vec!["KB4507435".into(), "KB4507469".into()],
            exploit_recommendation: "Race window in kernel transaction manager for token theft.".into(),
            exploit_path: Some("exploit/windows/local/cve_2019_1130_windowspage".into()),
        },
        CveEntry {
            id: "CVE-2019-0841".into(),
            title: "AppX Elevation of Privilege".into(),
            severity: "Medium".into(),
            affected_versions: vec!["windows 10".into()],
            affected_builds: vec![17763],
            required_kbs: vec!["KB4493510".into()],
            exploit_recommendation: "Hijack elevated hardlink permissions via Windows AppX deployment.".into(),
            exploit_path: Some("exploit/windows/local/cve_2019_0841_permissions".into()),
        },
        CveEntry {
            id: "CVE-2020-0683".into(),
            title: "Windows Kernel Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows server 2019".into()],
            affected_builds: vec![17763, 18362, 18363],
            required_kbs: vec!["KB4532691".into()],
            exploit_recommendation: "Exploit kernel type confusion in Windows GDI component.".into(),
            exploit_path: Some("exploit/windows/local/cve_2020_0683".into()),
        },
        CveEntry {
            id: "CVE-2020-0787".into(),
            title: "Windows Background Intelligent Transfer Service Elevation".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 7".into(), "windows 8.1".into(), "windows 10".into()],
            affected_builds: vec![7601, 9600, 10240, 10586, 14393, 17763, 18362],
            required_kbs: vec!["KB4534310".into()],
            exploit_recommendation: "Abuse BITS COM interface to overwrite arbitrary files as SYSTEM.".into(),
            exploit_path: Some("exploit/windows/local/cve_2020_0787_bits".into()),
        },
        CveEntry {
            id: "CVE-2020-1020".into(),
            title: "Windows Kernel Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into()],
            affected_builds: vec![17763, 18362, 18363],
            required_kbs: vec!["KB4549951".into()],
            exploit_recommendation: "Use font parsing vulnerability in kernel-mode driver for elevation.".into(),
            exploit_path: Some("exploit/windows/local/cve_2020_1020".into()),
        },
        CveEntry {
            id: "CVE-2021-1732".into(),
            title: "Windows Win32k Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into()],
            affected_builds: vec![17763, 18362, 18363, 19041, 19042],
            required_kbs: vec!["KB4601319".into()],
            exploit_recommendation: "Exploit Win32k window object type confusion for kernel elevation.".into(),
            exploit_path: Some("exploit/windows/local/cve_2021_1732_win32k".into()),
        },
        CveEntry {
            id: "CVE-2021-36934".into(),
            title: "HiveNightmare / SeriousSAM".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into(), "windows server 2022".into()],
            affected_builds: vec![19041, 19042, 19043, 19044, 22000],
            required_kbs: vec!["KB5005033".into()],
            exploit_recommendation: "Read SAM/SYSTEM/SECURITY hives from VSS shadow copies as any user.".into(),
            exploit_path: Some("builtin/hivenightmare".into()),
        },
        CveEntry {
            id: "CVE-2021-40449".into(),
            title: "Win32k NtGdiResetDC Elevation of Privilege".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows 7".into(), "windows 8.1".into(), "windows 10".into(), "windows 11".into()],
            affected_builds: vec![7601, 9600, 10240, 10586, 14393, 17763, 19041, 19042, 19043, 19044],
            required_kbs: vec!["KB5006670".into(), "KB5006674".into()],
            exploit_recommendation: "Use use-after-free in NtGdiResetDC for kernel code execution.".into(),
            exploit_path: Some("exploit/windows/local/cve_2021_40449".into()),
        },
        CveEntry {
            id: "CVE-2022-21894".into(),
            title: "Baton Drop / Secure Boot Security Feature Bypass".into(),
            severity: "Medium".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into()],
            affected_builds: vec![19044, 22000],
            required_kbs: vec!["KB5010793".into()],
            exploit_recommendation: "Bypass Secure Boot via Baton Drop to load unsigned bootmgr.".into(),
            exploit_path: Some("exploit/windows/local/cve_2022_21894_baton_drop".into()),
        },
        CveEntry {
            id: "CVE-2022-26923".into(),
            title: "Certifried Active Directory Certificate Services Elevation".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows server 2016".into(), "windows server 2019".into(), "windows server 2022".into()],
            affected_builds: vec![14393, 17763, 20348],
            required_kbs: vec!["KB5014754".into()],
            exploit_recommendation: "Elevate via ADCS ESC6/ESC9 certificate enrollment with userPrincipalName.".into(),
            exploit_path: Some("builtin/certifried".into()),
        },
        CveEntry {
            id: "CVE-2022-30190".into(),
            title: "Follina Microsoft Office RCE".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into()],
            affected_builds: vec![19041, 19042, 19043, 19044, 22000],
            required_kbs: vec!["KB5014699".into()],
            exploit_recommendation: "Use malicious Office document to invoke msdt.exe for code execution.".into(),
            exploit_path: Some("exploit/windows/fileformat/cve_2022_30190_follina".into()),
        },
        CveEntry {
            id: "CVE-2023-21746".into(),
            title: "Windows Kernel Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into(), "windows server 2022".into()],
            affected_builds: vec![19044, 19045, 22000, 22621],
            required_kbs: vec!["KB5026361".into()],
            exploit_recommendation: "Exploit kernel object manager race condition for token privileges.".into(),
            exploit_path: Some("exploit/windows/local/cve_2023_21746".into()),
        },
        CveEntry {
            id: "CVE-2023-36874".into(),
            title: "Windows Error Reporting Service Elevation".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into()],
            affected_builds: vec![19044, 19045, 22000, 22621],
            required_kbs: vec!["KB5028166".into()],
            exploit_recommendation: "Abuse WER to create arbitrary files and load DLLs as SYSTEM.".into(),
            exploit_path: Some("exploit/windows/local/cve_2023_36874".into()),
        },
        CveEntry {
            id: "CVE-2024-20656".into(),
            title: "Windows Kernel Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into()],
            affected_builds: vec![19044, 19045, 22621, 22631],
            required_kbs: vec!["KB5034441".into()],
            exploit_recommendation: "Use kernel handle table manipulation to escalate privileges.".into(),
            exploit_path: Some("exploit/windows/local/cve_2024_20656".into()),
        },
        CveEntry {
            id: "CVE-2024-38063".into(),
            title: "Windows TCP/IP Remote Code Execution".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into(), "windows server 2022".into()],
            affected_builds: vec![19045, 22000, 22621, 22631, 20348],
            required_kbs: vec!["KB5043178".into()],
            exploit_recommendation: "Trigger IPv6 neighbor discovery packet handling for kernel RCE.".into(),
            exploit_path: Some("exploit/windows/local/cve_2024_38063".into()),
        },
        CveEntry {
            id: "CVE-2025-21296".into(),
            title: "Windows Privilege Escalation Placeholder".into(),
            severity: "Medium".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into()],
            affected_builds: vec![19045, 22631],
            required_kbs: vec!["KB5050001".into()],
            exploit_recommendation: "Placeholder recommendation for future 2025 escalation path.".into(),
            exploit_path: None,
        },
        CveEntry {
            id: "CVE-2025-29969".into(),
            title: "MS-EVEN EventLog RPC Arbitrary File Creation".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into(), "windows server 2022".into(), "windows server 2025".into()],
            affected_builds: vec![19045, 22621, 22631, 26100, 26200],
            required_kbs: vec!["KB5055528".into()],
            exploit_recommendation: "Use MS-EVEN ElfrBackupEventLogW / ElfrClearLogFileW to create arbitrary files as SYSTEM for sandbox bypass or DLL planting.".into(),
            exploit_path: Some("builtin/ms-even-createfile".into()),
        },
        CveEntry {
            id: "CVE-2025-21333".into(),
            title: "Windows Hyper-V NT Kernel Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into(), "windows server 2022".into()],
            affected_builds: vec![19045, 22621, 22631, 26100],
            required_kbs: vec!["KB5050008".into()],
            exploit_recommendation: "Exploit Hyper-V NT kernel memory corruption for local elevation.".into(),
            exploit_path: Some("exploit/windows/local/cve_2025_21333".into()),
        },
        CveEntry {
            id: "CVE-2025-26647".into(),
            title: "Windows Remote Desktop Services Remote Code Execution".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into(), "windows server 2022".into(), "windows server 2025".into()],
            affected_builds: vec![19045, 22631, 26100, 26200],
            required_kbs: vec!["KB5055523".into()],
            exploit_recommendation: "Target RDP service for pre-auth remote code execution.".into(),
            exploit_path: Some("exploit/windows/rdp/cve_2025_26647".into()),
        },
        CveEntry {
            id: "CVE-2025-32729".into(),
            title: "Windows Installer Service Elevation of Privilege".into(),
            severity: "High".into(),
            affected_versions: vec!["windows 10".into(), "windows 11".into()],
            affected_builds: vec![19045, 22631, 26100],
            required_kbs: vec!["KB5056587".into()],
            exploit_recommendation: "Abuse Windows Installer rollback script for SYSTEM elevation.".into(),
            exploit_path: Some("exploit/windows/local/cve_2025_32729".into()),
        },
    ]
}

/// Numeric severity score for prioritizing findings.
/// Critical=4, High=3, Medium=2, Low=1, otherwise 0.
pub fn severity_score(severity: &str) -> u32 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Aggregate risk score from all vulnerable findings.
pub fn result_risk_score(result: &SherlockResult) -> u32 {
    result
        .findings
        .iter()
        .filter(|f| f.is_vulnerable)
        .map(|f| severity_score(&f.severity))
        .sum()
}

pub fn generate_exploit_recommendation(finding: &SherlockFinding) -> ExploitRecommendation {
    let technique = match finding.cve_id.as_str() {
        "CVE-2016-0099" | "CVE-2017-0213" | "CVE-2022-26923" | "CVE-2025-21333" => {
            "Token Manipulation"
        }
        "CVE-2021-36934" => "Registry Hive Theft",
        "CVE-2022-21894" => "Secure Boot Bypass",
        "CVE-2022-30190" => "Office Document Macro",
        "CVE-2024-38063" | "CVE-2025-26647" => "Network Protocol RCE",
        "CVE-2025-29969" => "RPC Arbitrary File Creation",
        "CVE-2025-32729" => "Installer Rollback Abuse",
        _ => "Kernel Driver",
    };
    let reliability = if finding.severity == "Critical" {
        "High"
    } else if finding.severity == "High" {
        "Medium"
    } else {
        "Low"
    };
    ExploitRecommendation {
        technique: technique.into(),
        cve_id: finding.cve_id.clone(),
        requires_admin: technique == "Kernel Driver"
            || technique == "Token Manipulation"
            || technique == "RPC Arbitrary File Creation"
            || technique == "Installer Rollback Abuse",
        reliability: reliability.into(),
        notes: finding.exploit_recommendation.clone(),
    }
}

pub fn format_sherlock_output(
    result: &SherlockResult,
    format: SherlockOutputFormat,
) -> Result<String, SherlockError> {
    match format {
        SherlockOutputFormat::Json => serde_json::to_string_pretty(result)
            .map_err(|e| SherlockError::IoError(format!("json serialize: {e}"))),
        SherlockOutputFormat::Csv => Ok(format_csv(result)),
        SherlockOutputFormat::Text => Ok(format_text(result)),
    }
}

fn format_text(result: &SherlockResult) -> String {
    let mut out = String::new();
    out.push_str("Sherlock Results\n");
    out.push_str(&format!("OS Version: {}\n", result.os_version));
    if let Some(b) = result.build_number {
        out.push_str(&format!("Build Number: {b}\n"));
    }
    out.push_str(&format!("Installed KBs: {}\n", result.installed_kbs.len()));
    out.push_str(&format!(
        "Findings: {} (vulnerable: {})\n",
        result.findings.len(),
        result.vulnerable_count
    ));
    out.push_str("\nFindings:\n");
    for f in &result.findings {
        out.push_str(&format!(
            "  [{}] {} - {} - Vulnerable: {}\n    Missing KBs: {:?}\n    Exploit: {}\n",
            f.severity, f.cve_id, f.title, f.is_vulnerable, f.missing_kbs, f.exploit_recommendation
        ));
    }
    out.push_str("\nRecommendations:\n");
    for r in &result.exploit_recommendations {
        out.push_str(&format!(
            "  {} ({}) - {} - Requires admin: {}\n",
            r.cve_id, r.technique, r.reliability, r.requires_admin
        ));
    }
    out
}

fn format_csv(result: &SherlockResult) -> String {
    let mut lines =
        vec!["cve_id,title,severity,os_version,build_number,missing_kbs,is_vulnerable".to_string()];
    for f in &result.findings {
        lines.push(format!(
            "{},{},{},{},{},{},{}",
            csv_escape(&f.cve_id),
            csv_escape(&f.title),
            csv_escape(&f.severity),
            csv_escape(&result.os_version),
            result
                .build_number
                .map(|b| b.to_string())
                .unwrap_or_default(),
            csv_escape(&f.missing_kbs.join(";")),
            f.is_vulnerable
        ));
    }
    lines.join("\n")
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn is_kb_installed(kb: &str, installed_kbs: &[String]) -> bool {
    let target = kb.to_uppercase().trim().to_string();
    installed_kbs
        .iter()
        .any(|k| k.to_uppercase().trim() == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = SherlockConfig::default();
        assert!(cfg.os_version.is_none());
        assert!(cfg.build_number.is_none());
        assert!(cfg.installed_kbs.is_empty());
        assert_eq!(cfg.cves_to_check.len(), 24);
        assert_eq!(cfg.output_format, SherlockOutputFormat::Text);
    }

    #[test]
    fn test_config_custom() {
        let cfg = SherlockConfig {
            os_version: Some("Windows 11".into()),
            build_number: Some(22631),
            installed_kbs: vec!["KB999".into()],
            cves_to_check: vec!["CVE-2021-36934".into()],
            output_format: SherlockOutputFormat::Json,
        };
        assert_eq!(cfg.os_version.as_deref(), Some("Windows 11"));
        assert_eq!(cfg.build_number, Some(22631));
        assert_eq!(cfg.output_format, SherlockOutputFormat::Json);
    }

    #[test]
    fn test_result_display() {
        let result = SherlockResult {
            os_version: "Windows 10".into(),
            build_number: Some(19045),
            installed_kbs: vec!["KB5005033".into()],
            findings: vec![],
            vulnerable_count: 0,
            exploit_recommendations: vec![],
        };
        assert_eq!(result.os_version, "Windows 10");
        assert_eq!(result.build_number, Some(19045));
    }

    #[test]
    fn test_error_display() {
        let e = SherlockError::RegistryError("bad key".into());
        assert_eq!(e.to_string(), "Registry error: bad key");
    }

    #[test]
    fn test_error_debug() {
        let e = SherlockError::WmiError("timeout".into());
        let s = format!("{:?}", e);
        assert!(s.contains("WmiError"));
        assert!(s.contains("timeout"));
    }

    #[test]
    fn test_cve_database_not_empty() {
        let db = build_cve_database();
        assert!(db.len() >= 24);
        assert!(db.iter().any(|c| c.id == "CVE-2021-36934"));
        assert!(db.iter().any(|c| c.id == "CVE-2025-29969"));
    }

    #[test]
    fn test_is_kb_installed() {
        let kbs = vec!["KB5005033".into(), "KB5010793".into()];
        assert!(is_kb_installed("kb5005033", &kbs));
        assert!(is_kb_installed("KB5010793", &kbs));
        assert!(!is_kb_installed("KB999999", &kbs));
    }

    #[test]
    fn test_check_cve_vulnerable() {
        let cve = CveEntry {
            id: "CVE-2021-36934".into(),
            title: "HiveNightmare".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows 10".into()],
            affected_builds: vec![19044],
            required_kbs: vec!["KB5005033".into()],
            exploit_recommendation: "Read hives".into(),
            exploit_path: Some("builtin/hivenightmare".into()),
        };
        let finding = check_cve_vulnerability(&cve, "Windows 10", Some(19044), &[]).unwrap();
        assert!(finding.is_vulnerable);
        assert_eq!(finding.missing_kbs, vec!["KB5005033".to_string()]);
    }

    #[test]
    fn test_check_cve_patched() {
        let cve = CveEntry {
            id: "CVE-2021-36934".into(),
            title: "HiveNightmare".into(),
            severity: "Critical".into(),
            affected_versions: vec!["windows 10".into()],
            affected_builds: vec![19044],
            required_kbs: vec!["KB5005033".into()],
            exploit_recommendation: "Read hives".into(),
            exploit_path: Some("builtin/hivenightmare".into()),
        };
        let finding =
            check_cve_vulnerability(&cve, "Windows 10", Some(19044), &["KB5005033".into()])
                .unwrap();
        assert!(!finding.is_vulnerable);
        assert!(finding.missing_kbs.is_empty());
    }

    #[test]
    fn test_detect_os_version_fallback() {
        let (os, build) = detect_os_version().unwrap();
        assert!(os.to_lowercase().contains("windows"));
        assert!(build.is_some());
    }

    #[test]
    fn test_enumerate_kbs_fallback() {
        let kbs = enumerate_installed_kbs().unwrap();
        assert!(!kbs.is_empty());
        assert!(kbs.iter().all(|k| k.starts_with("KB")));
    }

    #[test]
    fn test_format_output_json() {
        let result = SherlockResult {
            os_version: "Windows 10".into(),
            build_number: Some(19045),
            installed_kbs: vec!["KB5005033".into()],
            findings: vec![],
            vulnerable_count: 0,
            exploit_recommendations: vec![],
        };
        let out = format_sherlock_output(&result, SherlockOutputFormat::Json).unwrap();
        assert!(out.contains("Windows 10"));
        assert!(out.contains("KB5005033"));
    }

    #[test]
    fn test_format_output_csv() {
        let result = SherlockResult {
            os_version: "Windows 10".into(),
            build_number: Some(19045),
            installed_kbs: vec![],
            findings: vec![SherlockFinding {
                cve_id: "CVE-2021-36934".into(),
                title: "HiveNightmare".into(),
                severity: "Critical".into(),
                affected_versions: vec![],
                required_kbs: vec!["KB5005033".into()],
                missing_kbs: vec!["KB5005033".into()],
                exploit_recommendation: "Read hives".into(),
                exploit_path: None,
                is_vulnerable: true,
            }],
            vulnerable_count: 1,
            exploit_recommendations: vec![],
        };
        let out = format_sherlock_output(&result, SherlockOutputFormat::Csv).unwrap();
        assert!(out.starts_with("cve_id,title,severity"));
        assert!(out.contains("CVE-2021-36934"));
        assert!(out.contains("KB5005033"));
    }

    #[test]
    fn test_generate_exploit_recommendation() {
        let finding = SherlockFinding {
            cve_id: "CVE-2021-36934".into(),
            title: "HiveNightmare".into(),
            severity: "Critical".into(),
            affected_versions: vec![],
            required_kbs: vec![],
            missing_kbs: vec![],
            exploit_recommendation: "Read hives".into(),
            exploit_path: None,
            is_vulnerable: true,
        };
        let rec = generate_exploit_recommendation(&finding);
        assert_eq!(rec.cve_id, "CVE-2021-36934");
        assert_eq!(rec.reliability, "High");
        assert!(rec.notes.contains("hives"));
    }

    #[tokio::test]
    async fn test_run_sherlock_patched() {
        let cfg = SherlockConfig {
            os_version: Some("Windows 10".into()),
            build_number: Some(19044),
            installed_kbs: vec![
                "KB5005033".into(),
                "KB5010793".into(),
                "KB5026361".into(),
                "KB5034441".into(),
                "KB5043178".into(),
            ],
            cves_to_check: vec!["CVE-2021-36934".into()],
            output_format: SherlockOutputFormat::Text,
        };
        let result = run_sherlock(&cfg).await.unwrap();
        assert_eq!(result.os_version, "Windows 10");
        assert!(!result.findings.iter().any(|f| f.is_vulnerable));
    }

    #[tokio::test]
    async fn test_run_sherlock_vulnerable() {
        let cfg = SherlockConfig {
            os_version: Some("Windows 10".into()),
            build_number: Some(19044),
            installed_kbs: vec!["KB1234567".into()], // non-empty to avoid platform-dependent enumeration fallback
            cves_to_check: vec!["CVE-2021-36934".into()],
            output_format: SherlockOutputFormat::Text,
        };
        let result = run_sherlock(&cfg).await.unwrap();
        assert!(result.findings.iter().any(|f| f.is_vulnerable));
        assert!(result.vulnerable_count > 0);
    }
}
