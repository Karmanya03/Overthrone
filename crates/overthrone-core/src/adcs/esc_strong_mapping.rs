//! WS2025 Strong Certificate Mapping Enforcement detection.
//!
//! KB5014754 introduced `StrongCertificateBindingEnforcement` for the KDC.
//! WS2025 fresh installs default to **2 (Enforced)**, which breaks ESC9 and
//! ESC10 Variant A. Upgrades from WS2022 preserve the prior setting (usually 1).
//!
//! This module provides:
//! - LDAP-based DC build detection (WS2025 vs WS2022 vs older)
//! - Registry query commands for manual verification
//! - Programmatic enforcement state assessment

use crate::proto::registry::{PredefinedHive, REG_DWORD, read_remote_registry_value};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// The three states of `StrongCertificateBindingEnforcement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StrongBindingState {
    /// Value 0 -- Disabled (legacy). Weak mapping accepted. VULNERABLE.
    Disabled,
    /// Value 1 -- Compatibility / Audit. Logs warnings but still accepts. VULNERABLE.
    Compatibility,
    /// Value 2 -- Enforced. Rejects weak mapping. SAFE (blocks ESC9, ESC10A).
    Enforced,
    /// Could not determine the state.
    Unknown,
}

impl StrongBindingState {
    /// Whether this state allows weak certificate mapping (ESC9/ESC10A).
    pub fn allows_weak_mapping(&self) -> bool {
        matches!(self, Self::Disabled | Self::Compatibility)
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Disabled => "Disabled (0) -- legacy weak mapping: VULNERABLE",
            Self::Compatibility => "Compatibility (1) -- audit mode: VULNERABLE",
            Self::Enforced => "Enforced (2) -- strong binding: SAFE (blocks ESC9/ESC10A)",
            Self::Unknown => "Unknown -- cannot determine enforcement state",
        }
    }
}

/// Result of a strong mapping enforcement assessment on a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrongMappingAssessment {
    /// Detected state on the primary DC
    pub binding_state: StrongBindingState,
    /// Whether any detected DC is WS2025 (fresh install defaults to Enforced)
    pub ws2025_dc_present: bool,
    /// Domain controller build versions found
    pub dc_builds: Vec<String>,
    /// Whether enforcement could be definitively determined
    pub determined: bool,
    /// Operational recommendations
    pub recommendations: Vec<String>,
}

/// Detect WS2025 from a DC's `operatingSystem` LDAP attribute.
/// WS2025 build prefix: 10.0.26xxx
pub fn is_ws2025_build(os: Option<&str>, version: Option<&str>) -> bool {
    os.is_some_and(|v| v.contains("2025"))
        || version.is_some_and(|v| {
            v.starts_with("10.0 (26100")
                || v.starts_with("10.0.26100")
                || v.trim().starts_with("26100")
        })
}

/// Infer likely `StrongCertificateBindingEnforcement` from DC build info alone.
/// This is used when remote registry access is unavailable.
///
/// - WS2025 fresh install -> Enforced (2)
/// - WS2025 upgrade -> Compatibility (1) -- cannot distinguish from build alone
/// - WS2022 and earlier -> Disabled/Compat (0 or 1) -- depends on admin changes
pub fn infer_binding_state_from_build(is_ws2025: bool) -> StrongBindingState {
    if is_ws2025 {
        // Fresh install defaults to 2, but upgrades preserve prior value.
        // We report "Unknown" and let registry confirmation decide.
        StrongBindingState::Unknown
    } else {
        // Pre-WS2025: default is 0 or not set
        StrongBindingState::Unknown
    }
}

/// Generate a registry query command to check
/// `StrongCertificateBindingEnforcement` on a remote DC.
pub fn reg_query_command(dc: &str) -> String {
    format!(
        "reg query \"\\\\{dc}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\" \
         /v StrongCertificateBindingEnforcement 2>nul\n\
         # Output: 0x0 = Disabled (VULNERABLE), 0x1 = Compat (VULNERABLE), \
         0x2 = Enforced (safe)"
    )
}

/// Generate a PowerShell command to check via WinRM.
pub fn winrm_check_command(dc: &str) -> String {
    format!(
        "Invoke-Command -ComputerName {dc} -ScriptBlock {{\n\
         $v = Get-ItemPropertyValue -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc' \
         -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue;\n\
         if ($v -eq $null) {{ 'Not set (default=0) -- VULNERABLE' }}\
         elseif ($v -eq 0) {{ 'Disabled (0) -- VULNERABLE' }}\
         elseif ($v -eq 1) {{ 'Compatibility (1) -- VULNERABLE' }}\
         elseif ($v -eq 2) {{ 'Enforced (2) -- SAFE' }}\
         else {{ 'Unknown value: ' + $v }}\
         }}"
    )
}

/// Generate commands for checking `CertificateMappingMethods` UPN match bit (ESC10B).
pub fn cert_mapping_methods_command(dc: &str) -> String {
    format!(
        "reg query \"\\\\{dc}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\" \
         /v CertificateMappingMethods 2>nul\n\
         # Output bit 0x4 = UPN match enabled (VULNERABLE to ESC10B)"
    )
}

/// Collect `operatingSystem` values from all domain controllers via LDAP.
/// Returns a list of OS strings (e.g. "Windows Server 2025 Standard").
pub async fn collect_dc_builds(ldap: &mut crate::proto::ldap::LdapSession) -> Vec<String> {
    use ldap3::SearchEntry;

    let filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
    match ldap
        .custom_search(filter, &["operatingSystem", "dnshostname"])
        .await
    {
        Ok(results) => results
            .into_iter()
            .filter_map(|entry: SearchEntry| {
                entry
                    .attrs
                    .get("operatingSystem")
                    .and_then(|vals| vals.first().cloned())
                    .or_else(|| {
                        entry
                            .attrs
                            .get("dnshostname")
                            .and_then(|vals| vals.first().cloned())
                    })
            })
            .collect(),
        Err(e) => {
            info!("collect_dc_builds: LDAP search failed: {e}");
            Vec::new()
        }
    }
}

/// Read `StrongCertificateBindingEnforcement` from a remote DC via SMB `\\pipe\winreg`.
///
/// Requires an authenticated SMB session to the DC with `SYSTEM\CurrentControlSet\Services\Kdc`
/// read access. Returns `None` if the value is not set (defaults to 0/pre-WS2025) or on error.
pub async fn read_strong_mapping_via_smb(
    smb: &mut crate::proto::smb::SmbSession,
) -> Option<StrongBindingState> {
    const KDC_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Kdc";
    const VALUE_NAME: &str = "StrongCertificateBindingEnforcement";

    match read_remote_registry_value(smb, PredefinedHive::LocalMachine, KDC_REG_PATH, VALUE_NAME)
        .await
    {
        Ok(val) if val.data_type == REG_DWORD => {
            if val.data.len() >= 4 {
                let dw = u32::from_le_bytes(val.data[..4].try_into().unwrap_or([0; 4]));
                match dw {
                    0 => {
                        info!("SMB registry: StrongCertificateBindingEnforcement=0 (Disabled)");
                        Some(StrongBindingState::Disabled)
                    }
                    1 => {
                        info!(
                            "SMB registry: StrongCertificateBindingEnforcement=1 (Compatibility)"
                        );
                        Some(StrongBindingState::Compatibility)
                    }
                    2 => {
                        info!("SMB registry: StrongCertificateBindingEnforcement=2 (Enforced)");
                        Some(StrongBindingState::Enforced)
                    }
                    other => {
                        warn!(
                            "SMB registry: StrongCertificateBindingEnforcement={other} (unknown)"
                        );
                        Some(StrongBindingState::Unknown)
                    }
                }
            } else {
                warn!(
                    "SMB registry: StrongCertificateBindingEnforcement value too short ({})",
                    val.data.len()
                );
                None
            }
        }
        Ok(_) => {
            info!("SMB registry: StrongCertificateBindingEnforcement returned non-DWORD type");
            None
        }
        Err(e) => {
            warn!("SMB registry read failed (falling back to build inference): {e}");
            None
        }
    }
}

/// Read `CertificateMappingMethods` from a remote DC via SMB `\\pipe\winreg`.
/// Bit 0x4 (UPN match) enables ESC10 Variant B.
pub async fn read_cert_mapping_methods_via_smb(
    smb: &mut crate::proto::smb::SmbSession,
) -> Option<u32> {
    const KDC_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Kdc";
    const VALUE_NAME: &str = "CertificateMappingMethods";

    match read_remote_registry_value(smb, PredefinedHive::LocalMachine, KDC_REG_PATH, VALUE_NAME)
        .await
    {
        Ok(val) if val.data_type == REG_DWORD => {
            if val.data.len() >= 4 {
                let dw = u32::from_le_bytes(val.data[..4].try_into().unwrap_or([0; 4]));
                info!("SMB registry: CertificateMappingMethods=0x{dw:08x}");
                Some(dw)
            } else {
                warn!("SMB registry: CertificateMappingMethods value too short");
                None
            }
        }
        Ok(_) => {
            warn!("SMB registry: CertificateMappingMethods returned non-DWORD type");
            None
        }
        Err(e) if e.to_string().contains("not found") || e.to_string().contains("Value '") => {
            info!(
                "SMB registry: CertificateMappingMethods not set (defaults to 7 = SID+UPN+Issuer)"
            );
            Some(7)
        }
        Err(e) => {
            warn!("SMB registry read for CertificateMappingMethods failed: {e}");
            None
        }
    }
}

/// Build a full assessment summary for strong mapping enforcement.
pub fn assess_strong_mapping(
    dc_builds: Vec<String>,
    ws2025_dc_present: bool,
    binding_state: StrongBindingState,
) -> StrongMappingAssessment {
    let mut recommendations = Vec::new();

    match binding_state {
        StrongBindingState::Disabled | StrongBindingState::Unknown if ws2025_dc_present => {
            recommendations.push(
                "WS2025 DC detected but binding state is not Enforced -- check if this is \
                 an upgrade (preserving old settings) or whether enforcement was explicitly disabled"
                    .to_string(),
            );
        }
        StrongBindingState::Enforced => {
            recommendations.push(
                "StrongCertificateBindingEnforcement=2 -- ESC9 and ESC10 Variant A are BLOCKED. \
                 Consider ESC8 (NTLM relay to CA) or Shadow Credentials as alternatives"
                    .to_string(),
            );
        }
        StrongBindingState::Compatibility => {
            recommendations.push(
                "Compatibility mode (1) -- ESC9 and ESC10A work but generate KDC warning \
                 events (Event ID 45). Ensure operational security considers audit log coverage"
                    .to_string(),
            );
        }
        StrongBindingState::Disabled => {
            recommendations.push(
                "Strong binding is disabled (0) -- ESC9 and ESC10A are fully exploitable. \
                 No audit events are generated by the KDC"
                    .to_string(),
            );
        }
        _ => {}
    }

    if !ws2025_dc_present {
        recommendations.push(
            "No WS2025 DCs detected -- pre-WS2025 defaults apply. Verify \
             StrongCertificateBindingEnforcement via registry to confirm"
                .to_string(),
        );
    }

    StrongMappingAssessment {
        binding_state,
        ws2025_dc_present,
        dc_builds,
        determined: !matches!(binding_state, StrongBindingState::Unknown),
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ws2025_build_positive() {
        assert!(is_ws2025_build(Some("Windows Server 2025"), None));
        assert!(is_ws2025_build(None, Some("10.0 (26100) Standard Edition")));
        assert!(is_ws2025_build(None, Some("10.0.26100.1")));
        assert!(is_ws2025_build(None, Some("26100.1")));
    }

    #[test]
    fn test_is_ws2025_build_negative() {
        assert!(!is_ws2025_build(Some("Windows Server 2022"), None));
        assert!(!is_ws2025_build(None, Some("10.0 (20348)")));
        assert!(!is_ws2025_build(
            Some("Windows Server 2019"),
            Some("10.0 (17763)")
        ));
    }

    #[test]
    fn test_binding_state_descriptions() {
        assert!(
            StrongBindingState::Disabled
                .description()
                .contains("VULNERABLE")
        );
        assert!(
            StrongBindingState::Compatibility
                .description()
                .contains("VULNERABLE")
        );
        assert!(StrongBindingState::Enforced.description().contains("SAFE"));
    }

    #[test]
    fn test_allows_weak_mapping() {
        assert!(StrongBindingState::Disabled.allows_weak_mapping());
        assert!(StrongBindingState::Compatibility.allows_weak_mapping());
        assert!(!StrongBindingState::Enforced.allows_weak_mapping());
        assert!(!StrongBindingState::Unknown.allows_weak_mapping());
    }

    #[test]
    fn test_reg_query_command() {
        let cmd = reg_query_command("dc01.corp.local");
        assert!(cmd.contains("dc01.corp.local"));
        assert!(cmd.contains("StrongCertificateBindingEnforcement"));
    }

    #[test]
    fn test_cert_mapping_methods_command() {
        let cmd = cert_mapping_methods_command("192.168.1.10");
        assert!(cmd.contains("192.168.1.10"));
        assert!(cmd.contains("CertificateMappingMethods"));
    }

    #[test]
    fn test_assessment_recommendations_enforced() {
        let assessment = assess_strong_mapping(
            vec!["10.0.26100.1".to_string()],
            true,
            StrongBindingState::Enforced,
        );
        assert!(
            assessment
                .recommendations
                .iter()
                .any(|r| r.contains("BLOCKED"))
        );
    }

    #[test]
    fn test_assessment_recommendations_no_ws2025() {
        let assessment = assess_strong_mapping(
            vec!["10.0.20348.1".to_string()],
            false,
            StrongBindingState::Unknown,
        );
        assert!(
            assessment
                .recommendations
                .iter()
                .any(|r| r.contains("No WS2025"))
        );
    }
}
