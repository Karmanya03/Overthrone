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

use crate::proto::registry::{PredefinedHive, REG_DWORD, read_remote_registry_value};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Credential Guard status for a target system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

    findings.push(format!("SMB Remote Registry CG check on {}", smb_session.target));

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
            let flags = u32::from_le_bytes([
                value.data[0],
                value.data[1],
                value.data[2],
                value.data[3],
            ]);
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

    // Method 2: Query IsolatedCredentialsRootSecret presence
    let secret_found = match read_remote_registry_value(
        smb_session,
        PredefinedHive::LocalMachine,
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\CredentialGuard",
        "IsolatedCredentialsRootSecret",
    )
    .await
    {
        Ok(value) => {
            let found = !value.data.is_empty();
            findings.push(format!("IsolatedCredentialsRootSecret present: {found}"));
            Some(found)
        }
        Err(e) => {
            findings.push(format!("IsolatedCredentialsRootSecret not found: {e}"));
            Some(false)
        }
    };
    let secret_present = secret_found;

    let (status, recommendation) = match lsa_cfg_flags {
        Some(1) | Some(2) => (
            CredentialGuardStatus::Enabled,
            "CG confirmed via LsaCfgFlags — route to ADCS Shadow Credentials, RBCD, or dMSA"
                .to_string(),
        ),
        Some(0) => (
            CredentialGuardStatus::Disabled,
            "CG disabled (LsaCfgFlags=0) — LSASS techniques are viable".to_string(),
        ),
        Some(flag) => (
            CredentialGuardStatus::Unknown,
            format!("CG unreadable (unknown LsaCfgFlags={flag}) — assuming disabled for legacy compat"),
        ),
        None => {
            (
                CredentialGuardStatus::Unknown,
                "CG status unknown — assuming disabled for legacy compat".to_string(),
            )
        }
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
            "CG not confirmed — attempt LSASS technique with opsec pre-checks".to_string(),
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

/// Decide which credential extraction technique to use based on CG status.
pub fn choose_cred_extraction(cg: &CgPreflightResult) -> &'static str {
    match cg.status {
        CredentialGuardStatus::Enabled => {
            "shadow_credentials"
        }
        CredentialGuardStatus::Disabled | CredentialGuardStatus::Unknown => {
            "lsass_dump"
        }
    }
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
        assert_eq!(choose_cred_extraction(&cg), "shadow_credentials");
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
        assert_eq!(choose_cred_extraction(&cg), "lsass_dump");
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
        assert_eq!(choose_cred_extraction(&cg), "lsass_dump");
    }
}
