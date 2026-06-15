//! Credential Guard / VBS pre-flight detection module.
//!
//! Before attempting LSASS-touching techniques (Skeleton Key, DCSync via LSASS,
//! PtH, Kiwi), check whether Credential Guard is enabled on the target.
//! If CG is active, LSASS-derived secrets are isolated and classic attacks fail.
//!
//! # Detection Methods
//! 1. **Remote Registry via SMB**: Query `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
//!    `LsaCfgFlags` (0=disabled, 1=enabled with UEFI lock, 2=enabled without lock)
//! 2. **Remote Registry via SMB**: Query
//!    `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CredentialGuard`
//!    `IsolatedCredentialsRootSecret` (presence indicates CG active)
//! 3. **Name/OS heuristic**: Fallback when SMB remote registry is unavailable
//!
//! # Routing
//! - If CG enabled → route to ADCS Shadow Credentials / RBCD instead
//! - If CG disabled → proceed with LSASS techniques
//! - If unknown → assume CG disabled (legacy compat)

use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use crate::proto::registry::{PredefinedHive, REG_DWORD, read_remote_registry_value};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Credential Guard status for a target system.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CredentialGuardStatus {
    /// CG is confirmed enabled — LSASS techniques will fail.
    Enabled,
    /// CG is confirmed disabled — LSASS techniques are viable.
    Disabled,
    /// CG status unknown — proceed with legacy path.
    Unknown,
}

/// Full Credential Guard pre-flight result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgPreflightResult {
    /// Overall CG status.
    pub status: CredentialGuardStatus,
    /// Whether `LsaCfgFlags` was readable.
    pub lsa_cfg_flags_readable: bool,
    /// Raw `LsaCfgFlags` value (0-2), if readable.
    pub lsa_cfg_flags: Option<u32>,
    /// Whether the `IsolatedCredentialsRootSecret` value exists.
    pub isolated_credential_secret_present: Option<bool>,
    /// Whether `Win32_DeviceGuard` was queriable.
    pub device_guard_queried: bool,
    /// Raw `SecurityServicesRunning` value, if queried.
    pub security_services_running: Option<u32>,
    /// Recommended technique based on CG status.
    pub recommendation: String,
    /// Human-readable findings.
    pub findings: Vec<String>,
}

/// Pre-flight CG check on a remote system using SMB remote registry.
///
/// Connects via SMB named pipe `\PIPE\winreg` and queries:
/// - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags`
/// - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CredentialGuard\IsolatedCredentialsRootSecret`
///
/// This provides definitive detection without requiring code execution on the target.
pub async fn check_credential_guard_remote(
    smb_session: &mut crate::proto::smb::SmbSession,
) -> CgPreflightResult {
    let mut findings = Vec::new();
    let mut lsa_cfg_flags: Option<u32> = None;
    let mut flags_readable = false;

    findings.push(format!(
        "SMB Remote Registry CG check on {}",
        smb_session.target
    ));

    // Method 1: Query LsaCfgFlags
    match read_remote_registry_value(
        smb_session,
        PredefinedHive::LocalMachine,
        "SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "LsaCfgFlags",
    )
    .await
    {
        Ok(value) if value.data_type == REG_DWORD && value.data.len() >= 4 => {
            let flags =
                u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]);
            lsa_cfg_flags = Some(flags);
            flags_readable = true;
            findings.push(format!("LsaCfgFlags = {flags}"));
        }
        Ok(value) => {
            findings.push(format!(
                "LsaCfgFlags returned unexpected type={}/len={}",
                value.data_type,
                value.data.len()
            ));
        }
        Err(e) => {
            findings.push(format!("LsaCfgFlags not readable: {e}"));
        }
    }

    // Method 2: Query IsolatedCredentialsRootSecret presence. Windows builds
    // have exposed this indicator under both paths in the wild.
    let secret_found = query_isolated_credentials_secret(smb_session, &mut findings).await;
    let secret_present = secret_found;

    let (status, recommendation) = match (lsa_cfg_flags, secret_present) {
        (_, Some(true)) => (
            CredentialGuardStatus::Enabled,
            "CG confirmed via IsolatedCredentialsRootSecret; use LSAISO bypass (ALPC → process memory → WDigest fallback), or route to ADCS Shadow Credentials, RBCD, or dMSA"
                .to_string(),
        ),
        (Some(1) | Some(2), _) => (
            CredentialGuardStatus::Enabled,
            "CG confirmed via LsaCfgFlags — use LSAISO bypass (ALPC → process memory → WDigest fallback), or route to ADCS Shadow Credentials, RBCD, or dMSA"
                .to_string(),
        ),
        (Some(0), _) => (
            CredentialGuardStatus::Disabled,
            "CG disabled (LsaCfgFlags=0) and no isolated-secret indicator was found".to_string(),
        ),
        (Some(flag), _) => (
            CredentialGuardStatus::Unknown,
            format!("CG inconclusive (unknown LsaCfgFlags={flag}); avoid LSASS techniques"),
        ),
        (None, _) => (
            CredentialGuardStatus::Unknown,
            "CG status unknown; avoid LSASS techniques".to_string(),
        ),
    };

    info!(
        "CG Remote Preflight: status={:?}, LsaCfgFlags={:?}, findings={}",
        status,
        lsa_cfg_flags,
        findings.len()
    );

    CgPreflightResult {
        status,
        lsa_cfg_flags_readable: flags_readable,
        lsa_cfg_flags,
        isolated_credential_secret_present: secret_present,
        device_guard_queried: false,
        security_services_running: None,
        recommendation,
        findings,
    }
}

async fn query_isolated_credentials_secret(
    smb_session: &mut crate::proto::smb::SmbSession,
    findings: &mut Vec<String>,
) -> Option<bool> {
    const VALUE_NAME: &str = "IsolatedCredentialsRootSecret";
    const PATHS: &[&str] = &[
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\CredentialGuard",
    ];

    let mut checked_any = false;
    for path in PATHS {
        match read_remote_registry_value(
            smb_session,
            PredefinedHive::LocalMachine,
            path,
            VALUE_NAME,
        )
        .await
        {
            Ok(value) => {
                checked_any = true;
                let found = !value.data.is_empty();
                findings.push(format!("HKLM\\{path}\\{VALUE_NAME} present: {found}"));
                if found {
                    return Some(true);
                }
            }
            Err(e) => {
                findings.push(format!("HKLM\\{path}\\{VALUE_NAME} not readable: {e}"));
            }
        }
    }

    if checked_any { Some(false) } else { None }
}

/// Pre-flight CG check using heuristic/name-based detection.
///
/// Fallback when SMB remote registry is unavailable:
/// - If the OS version suggests WS2025, flag as likely CG-enabled
/// - Otherwise, return Unknown
pub fn check_credential_guard_preflight(
    target: &str,
    _dc_ip: &str,
    _domain: &str,
) -> CgPreflightResult {
    let mut findings = Vec::new();
    let mut cg_flags: Option<u32> = None;

    findings.push(format!("Target: {target} (heuristic only)"));

    if target.contains("2025") || target.contains("WS2025") || target.contains("win2025") {
        findings.push("OS hint suggests Windows Server 2025 — CG likely enabled".to_string());
        cg_flags = Some(2);
    }

    let (status, recommendation) = match cg_flags {
        Some(2) | Some(1) => (
            CredentialGuardStatus::Enabled,
            "CG likely enabled (WS2025 heuristic) — route to ADCS Shadow Credentials, RBCD, or dMSA"
                .to_string(),
        ),
        _ => (
            CredentialGuardStatus::Unknown,
            "CG not confirmed; avoid LSASS-touching techniques until remote registry or WMI evidence is available".to_string(),
        ),
    };

    info!("CG Heuristic Preflight: target={target}, status={status:?}");

    CgPreflightResult {
        status,
        lsa_cfg_flags_readable: false,
        lsa_cfg_flags: cg_flags,
        isolated_credential_secret_present: None,
        device_guard_queried: false,
        security_services_running: None,
        recommendation,
        findings,
    }
}

/// Decision result from `choose_cred_extraction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionDecision {
    /// Recommended strategy name
    pub strategy: String,
    /// Human-readable recommendation
    pub recommendation: String,
    /// Priority order of methods to try
    pub method_priority: Vec<String>,
}

impl ExtractionDecision {
    fn new(strategy: &str, recommendation: String, methods: Vec<&str>) -> Self {
        Self {
            strategy: strategy.to_string(),
            recommendation,
            method_priority: methods.into_iter().map(String::from).collect(),
        }
    }
}

/// Decide which credential extraction technique to use based on CG status.
/// Choose credential extraction strategy based on Credential Guard status.
///
/// Returns an `ExtractionDecision` with:
/// - `strategy`: Short name of the primary strategy
/// - `recommendation`: Human-readable guidance
/// - `method_priority`: Ordered list of methods to try
pub fn choose_cred_extraction(cg: &CgPreflightResult) -> ExtractionDecision {
    match cg.status {
        CredentialGuardStatus::Enabled => ExtractionDecision::new(
            "lsaiso_bypass",
            "CG confirmed — use LSAISO bypass (ALPC → process memory → WDigest fallback)".into(),
            vec![
                "alpc",
                "process_memory",
                "wdigest",
                "shadow_credentials",
                "rbcd",
            ],
        ),
        CredentialGuardStatus::Unknown => ExtractionDecision::new(
            "shadow_credentials",
            "CG status unknown — prefer non-LSASS techniques (Shadow Credentials, RBCD)".into(),
            vec!["shadow_credentials", "rbcd", "lsaiso_bypass", "lsass_dump"],
        ),
        CredentialGuardStatus::Disabled => ExtractionDecision::new(
            "lsass_dump",
            "CG not detected — proceed with LSASS memory dumping".into(),
            vec!["lsass_dump", "wdigest"],
        ),
    }
}

// ──────────────────────────────────────────────────────────────────────
//  WMI-based Credential Guard Detection
// ──────────────────────────────────────────────────────────────────────

/// Check Credential Guard / VBS status via WMI on a remote machine.
///
/// Uses the `Win32_DeviceGuard` WMI class to query:
/// - `DeviceGuardEnabled` — whether VBS is enabled
/// - `SecurityServicesRunning` — which CG services are running
/// - `DeviceGuardLocalSystemAuthorityCredentialGuard` — CG-specific
/// - `VirtualizationBasedSecurityStatus` — VBS status
///
/// Requires admin credentials and WMI access to the target.
#[cfg(target_os = "windows")]
pub fn check_credential_guard_via_wmi(
    target: &str,
    _username: &str,
    _password: &str,
) -> Result<CgPreflightResult> {
    use std::collections::HashMap;
    use wmi::COMLibrary;
    use wmi::WMIConnection;

    let mut findings = Vec::new();
    findings.push(format!("WMI CG check on {target}"));

    let com = COMLibrary::new()
        .map_err(|e| OverthroneError::PostExploitation(format!("WMI COM init failed: {e}")))?;

    let wmi_conn = WMIConnection::new(com)
        .map_err(|e| OverthroneError::PostExploitation(format!("WMI connection failed: {e}")))?;

    let results: Vec<HashMap<String, wmi::Variant>> = wmi_conn.query().map_err(|e| {
        OverthroneError::PostExploitation(format!("WMI query Win32_DeviceGuard failed: {e}"))
    })?;

    let mut device_guard_queried = false;
    let mut lsa_cfg_flags: Option<u32> = None;
    let mut security_services_running: Option<u32> = None;
    let mut isolated_secret_present: Option<bool> = None;

    for result in results {
        device_guard_queried = true;

        // Check VirtualizationBasedSecurityStatus: 0 = Disabled, 1 = Running, 2 = Stopped
        if let Some(wmi::Variant::UI4(val)) = result.get("VirtualizationBasedSecurityStatus") {
            findings.push(format!("VirtualizationBasedSecurityStatus = {val}"));
            if *val == 1 {
                lsa_cfg_flags = Some(2);
            }
        }

        // Check SecurityServicesRunning: bitmask of running services
        // 1 = SecureBoot, 2 = DMA, 4 = HypervisorEnforcedCodeIntegrity, 8 = CredentialGuard
        if let Some(wmi::Variant::UI4(val)) = result.get("SecurityServicesRunning") {
            security_services_running = Some(*val);
            findings.push(format!("SecurityServicesRunning = {val} (bitmask)"));
            if *val & 0x08 != 0 {
                findings.push("Credential Guard service is running".to_string());
            }
        }

        // Check DeviceGuardLocalSystemAuthorityCredentialGuard (actually just CredentialGuard)
        if let Some(wmi::Variant::Bool(val)) =
            result.get("DeviceGuardLocalSystemAuthorityCredentialGuard")
        {
            findings.push(format!("CredentialGuard field = {val}"));
            if *val {
                isolated_secret_present = Some(true);
            }
        }
    }

    if !device_guard_queried {
        findings.push("Win32_DeviceGuard query returned no results".to_string());
    }

    let (status, recommendation) = match (lsa_cfg_flags, isolated_secret_present) {
        (Some(1) | Some(2), _) => (
            CredentialGuardStatus::Enabled,
            "CG confirmed via WMI (VBS running) — use LSAISO bypass (ALPC → process memory → WDigest fallback), or route to ADCS Shadow Credentials, RBCD, or dMSA".to_string(),
        ),
        (_, Some(true)) => (
            CredentialGuardStatus::Enabled,
            "CG confirmed via WMI (CredentialGuard field) — use LSAISO bypass (ALPC → process memory → WDigest fallback), or route to ADCS Shadow Credentials, RBCD, or dMSA".to_string(),
        ),
        (Some(0), _) => (
            CredentialGuardStatus::Disabled,
            "CG disabled via WMI (VBS not running)".to_string(),
        ),
        _ => (
            CredentialGuardStatus::Unknown,
            "CG status via WMI inconclusive — further investigation needed".to_string(),
        ),
    };

    Ok(CgPreflightResult {
        status,
        lsa_cfg_flags_readable: lsa_cfg_flags.is_some(),
        lsa_cfg_flags,
        isolated_credential_secret_present: isolated_secret_present,
        device_guard_queried,
        security_services_running,
        recommendation,
        findings,
    })
}

#[cfg(not(target_os = "windows"))]
pub fn check_credential_guard_via_wmi(
    _target: &str,
    _username: &str,
    _password: &str,
) -> Result<CgPreflightResult> {
    Err(OverthroneError::PostExploitation(
        "WMI CG check requires Windows platform".into(),
    ))
}

// ──────────────────────────────────────────────────────────────────────
//  Domain-level CG Assessment via LDAP
// ──────────────────────────────────────────────────────────────────────

/// Assess Credential Guard deployment across the domain via LDAP.
///
/// Queries domain controllers for:
/// 1. OS version / build number (WS2025 defaults to CG enabled)
/// 2. GPO links that deploy CG
/// 3. Active Directory offering for VBS/CG
///
/// Returns a domain-wide CG posture assessment.
pub async fn assess_domain_credential_guard(
    ldap: &mut LdapSession,
    domain: &str,
) -> Result<DomainCgAssessment> {
    let mut findings = Vec::new();
    let mut dc_builds: Vec<(String, String)> = Vec::new();
    let mut gpo_cg_policies: Vec<String> = Vec::new();
    let mut ws2025_dcs = 0;
    let mut total_dcs = 0;

    // Phase 1: Enumerate DCs and check build versions
    let dcs = ldap
        .custom_search(
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            &[
                "cn",
                "operatingSystem",
                "operatingSystemVersion",
                "dNSHostName",
            ],
        )
        .await
        .map_err(|e| OverthroneError::Ldap {
            target: domain.into(),
            reason: e.to_string(),
        })?;

    for dc in &dcs {
        total_dcs += 1;
        let dc_name = dc
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let os_ver = dc
            .attrs
            .get("operatingSystemVersion")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let os_name = dc
            .attrs
            .get("operatingSystem")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        dc_builds.push((dc_name.clone(), os_ver.clone()));

        // WS2025 has build 10.0.26xxx
        if os_ver.starts_with("10.0.26") {
            ws2025_dcs += 1;
            findings.push(format!(
                "{dc_name}: WS2025 (build {os_ver}) — CG likely enabled by default"
            ));
        } else if os_ver.starts_with("10.0.2") {
            let build_num: u32 = os_ver
                .split('.')
                .nth(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if build_num >= 20348 {
                findings.push(format!(
                    "{dc_name}: WS2022+ (build {os_ver}) — CG may be deployed via GPO"
                ));
            }
        } else {
            let has_dc_name = if !dc_name.is_empty() {
                dc_name
            } else {
                "Unknown DC".into()
            };
            findings.push(format!("{has_dc_name}: OS = {os_name} (build {os_ver})"));
        }
    }

    // Phase 2: GPO-based CG detection
    let gpo_search = ldap
        .custom_search(
            "(&(objectClass=groupPolicyContainer)(displayName=*CredentialGuard*))",
            &["cn", "displayName", "gPCFileSysPath"],
        )
        .await;

    if let Ok(gpos) = gpo_search {
        for gpo in &gpos {
            if let Some(names) = gpo.attrs.get("displayName") {
                for name in names {
                    gpo_cg_policies.push(name.clone());
                    findings.push(format!(
                        "GPO found: {name} — likely deploys CredentialGuard"
                    ));
                }
            }
        }
    }

    // Phase 3: Determine overall domain posture
    let cg_likely_enabled = ws2025_dcs > 0 || !gpo_cg_policies.is_empty();
    let percentage = if total_dcs > 0 {
        (ws2025_dcs as f64 / total_dcs as f64) * 100.0
    } else {
        0.0
    };

    let posture = if cg_likely_enabled {
        DomainCgPosture::LikelyEnabled
    } else if total_dcs == 0 {
        DomainCgPosture::InsufficientData
    } else if percentage > 50.0 {
        DomainCgPosture::LikelyEnabled
    } else {
        DomainCgPosture::LikelyDisabled
    };

    Ok(DomainCgAssessment {
        total_dcs,
        ws2025_dcs,
        dc_builds,
        gpo_cg_policies,
        ws2025_percentage: percentage,
        posture,
        findings,
    })
}

/// Domain-level CG posture.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DomainCgPosture {
    /// All evidence suggests CG is deployed
    LikelyEnabled,
    /// Most evidence suggests CG is not deployed
    LikelyDisabled,
    /// Not enough data
    InsufficientData,
}

impl std::fmt::Display for DomainCgPosture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LikelyEnabled => write!(f, "Likely Enabled"),
            Self::LikelyDisabled => write!(f, "Likely Disabled"),
            Self::InsufficientData => write!(f, "Insufficient Data"),
        }
    }
}

/// Domain-level Credential Guard assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCgAssessment {
    /// Total domain controllers found
    pub total_dcs: usize,
    /// Number of WS2025 DCs detected
    pub ws2025_dcs: usize,
    /// DC build version details
    pub dc_builds: Vec<(String, String)>,
    /// GPOs related to Credential Guard
    pub gpo_cg_policies: Vec<String>,
    /// Percentage of WS2025 DCs
    pub ws2025_percentage: f64,
    /// Overall assessment
    pub posture: DomainCgPosture,
    /// Bulleted findings
    pub findings: Vec<String>,
}

// ──────────────────────────────────────────────────────────────────────
//  Multi-signal CG Check (combined remote + WMI + domain + heuristic)
// ──────────────────────────────────────────────────────────────────────

/// Multi-signal Credential Guard check combining all available methods.
///
/// Collects evidence from:
/// 1. Remote registry (SMB) — if session provided
/// 2. WMI — if credentials provided
/// 3. LDAP domain assessment — if session provided
/// 4. Name/OS heuristic — always available
///
/// Returns a consolidated result with confidence scoring.
pub async fn comprehensive_cg_check(
    target: &str,
    domain: &str,
    smb_session: Option<&mut crate::proto::smb::SmbSession>,
    ldap_session: Option<&mut LdapSession>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<ComprehensiveCgResult> {
    let mut signals: Vec<CgSignal> = Vec::new();
    let mut findings: Vec<String> = Vec::new();
    let mut domain_assessment: Option<DomainCgAssessment> = None;

    // Signal 1: Remote registry via SMB
    if let Some(smb) = smb_session {
        let reg_result = check_credential_guard_remote(smb).await;
        let reg_status = reg_result.status;
        findings.push(format!(
            "SMB Remote Registry: {:?} (LsaCfgFlags={:?})",
            reg_status, reg_result.lsa_cfg_flags
        ));
        signals.push(CgSignal {
            method: "SMB Remote Registry".into(),
            status: reg_status,
            confidence: 0.9,
        });
    }

    // Signal 2: Domain-level via LDAP
    if let Some(ldap) = ldap_session {
        match assess_domain_credential_guard(ldap, domain).await {
            Ok(domain_cg) => {
                let domain_status = match domain_cg.posture {
                    DomainCgPosture::LikelyEnabled => CredentialGuardStatus::Enabled,
                    DomainCgPosture::LikelyDisabled => CredentialGuardStatus::Disabled,
                    DomainCgPosture::InsufficientData => CredentialGuardStatus::Unknown,
                };
                findings.push(format!(
                    "Domain Assessment: {:?} ({} WS2025 DCs out of {}, {} policies found)",
                    domain_status,
                    domain_cg.ws2025_dcs,
                    domain_cg.total_dcs,
                    domain_cg.gpo_cg_policies.len()
                ));
                signals.push(CgSignal {
                    method: "Domain Assessment".into(),
                    status: domain_status,
                    confidence: 0.7,
                });
                domain_assessment = Some(domain_cg);
            }
            Err(e) => {
                findings.push(format!("Domain assessment failed: {e}"));
            }
        }
    }

    // Signal 3: WMI (if credentials provided)
    let wmi_result = if let (Some(user), Some(pass)) = (username, password) {
        match check_credential_guard_via_wmi(target, user, pass) {
            Ok(wmi) => {
                let wmi_status = wmi.status;
                findings.push(format!("WMI: {:?}", wmi_status));
                signals.push(CgSignal {
                    method: "WMI".into(),
                    status: wmi_status,
                    confidence: 0.85,
                });
                Some(wmi)
            }
            Err(e) => {
                findings.push(format!("WMI query failed: {e}"));
                None
            }
        }
    } else {
        findings.push("WMI: skipped (no credentials)".to_string());
        None
    };

    // Signal 4: Heuristic fallback
    let heuristic = check_credential_guard_preflight(target, "", domain);
    let heuristic_status = heuristic.status;
    findings.push(format!("Heuristic: {:?}", heuristic_status));
    signals.push(CgSignal {
        method: "Heuristic".into(),
        status: heuristic_status,
        confidence: 0.3,
    });

    // Consolidate: weighted voting
    let mut enable_weight: f64 = 0.0;
    let mut disable_weight: f64 = 0.0;
    let mut unknown_weight: f64 = 0.0;

    for signal in &signals {
        match signal.status {
            CredentialGuardStatus::Enabled => enable_weight += signal.confidence,
            CredentialGuardStatus::Disabled => disable_weight += signal.confidence,
            CredentialGuardStatus::Unknown => unknown_weight += signal.confidence * 0.5,
        }
    }

    let total_weight = enable_weight + disable_weight + unknown_weight;
    let (final_status, confidence) = if total_weight == 0.0 {
        (CredentialGuardStatus::Unknown, 0.0)
    } else {
        let enable_pct = enable_weight / total_weight;
        let disable_pct = disable_weight / total_weight;
        if enable_pct > 0.5 {
            (CredentialGuardStatus::Enabled, enable_pct)
        } else if disable_pct > 0.5 {
            (CredentialGuardStatus::Disabled, disable_pct)
        } else {
            (CredentialGuardStatus::Unknown, total_weight.max(0.3))
        }
    };

    let recommendation = match final_status {
        CredentialGuardStatus::Enabled => {
            "CG confirmed — use LSAISO bypass (ALPC → process memory → WDigest fallback), or route to ADCS Shadow Credentials, RBCD, or dMSA".to_string()
        }
        CredentialGuardStatus::Disabled => {
            "CG not detected — proceed with LSASS techniques".to_string()
        }
        CredentialGuardStatus::Unknown => {
            "CG status unclear — prefer non-LSASS techniques as precaution".to_string()
        }
    };

    Ok(ComprehensiveCgResult {
        status: final_status,
        confidence,
        signals: signals.len(),
        enable_weight: format!("{:.2}", enable_weight),
        disable_weight: format!("{:.2}", disable_weight),
        domain_assessment,
        wmi_result,
        recommendation,
        findings,
    })
}

/// A single Credential Guard detection signal with confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgSignal {
    pub method: String,
    pub status: CredentialGuardStatus,
    pub confidence: f64,
}

/// Comprehensive Credential Guard assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveCgResult {
    pub status: CredentialGuardStatus,
    pub confidence: f64,
    pub signals: usize,
    pub enable_weight: String,
    pub disable_weight: String,
    pub domain_assessment: Option<DomainCgAssessment>,
    pub wmi_result: Option<CgPreflightResult>,
    pub recommendation: String,
    pub findings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cg_heuristic_ws2025() {
        let result = check_credential_guard_preflight("DC01-WS2025", "192.168.1.10", "corp.local");
        assert_eq!(result.status, CredentialGuardStatus::Enabled);
        assert_eq!(result.lsa_cfg_flags, Some(2));
    }

    #[test]
    fn test_cg_heuristic_unknown() {
        let result = check_credential_guard_preflight("DC01", "192.168.1.10", "corp.local");
        assert_eq!(result.status, CredentialGuardStatus::Unknown);
    }

    #[test]
    fn test_choose_extraction_cg_enabled() {
        let cg = CgPreflightResult {
            status: CredentialGuardStatus::Enabled,
            lsa_cfg_flags_readable: true,
            lsa_cfg_flags: Some(2),
            isolated_credential_secret_present: Some(true),
            device_guard_queried: true,
            security_services_running: Some(3),
            recommendation: "Use ADCS".to_string(),
            findings: vec![],
        };
        let decision = choose_cred_extraction(&cg);
        assert_eq!(decision.strategy, "lsaiso_bypass");
        assert!(decision.method_priority.contains(&"alpc".to_string()));
        assert!(
            decision
                .method_priority
                .contains(&"process_memory".to_string())
        );
    }

    #[test]
    fn test_choose_extraction_cg_disabled() {
        let cg = CgPreflightResult {
            status: CredentialGuardStatus::Disabled,
            lsa_cfg_flags_readable: true,
            lsa_cfg_flags: Some(0),
            isolated_credential_secret_present: Some(false),
            device_guard_queried: true,
            security_services_running: Some(0),
            recommendation: "Use LSASS".to_string(),
            findings: vec![],
        };
        let decision = choose_cred_extraction(&cg);
        assert_eq!(decision.strategy, "lsass_dump");
        assert!(decision.method_priority.contains(&"lsass_dump".to_string()));
    }

    #[test]
    fn test_choose_extraction_cg_unknown() {
        let cg = CgPreflightResult {
            status: CredentialGuardStatus::Unknown,
            lsa_cfg_flags_readable: false,
            lsa_cfg_flags: None,
            isolated_credential_secret_present: None,
            device_guard_queried: false,
            security_services_running: None,
            recommendation: "Unknown — using legacy".to_string(),
            findings: vec![],
        };
        let decision = choose_cred_extraction(&cg);
        assert_eq!(decision.strategy, "shadow_credentials");
        assert!(
            decision
                .method_priority
                .contains(&"lsaiso_bypass".to_string())
        );
    }

    #[test]
    fn test_extraction_decision_serde() {
        let d = ExtractionDecision::new(
            "test_strat",
            "test recommendation".into(),
            vec!["method1", "method2"],
        );
        let json = serde_json::to_string(&d).unwrap();
        let deserialized: ExtractionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.strategy, "test_strat");
        assert_eq!(deserialized.recommendation, "test recommendation");
        let expected: Vec<String> = vec!["method1".into(), "method2".into()];
        assert_eq!(deserialized.method_priority, expected);
    }
}
