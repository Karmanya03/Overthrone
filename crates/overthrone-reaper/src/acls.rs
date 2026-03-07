//! Dangerous ACL enumeration — GenericAll, WriteDACL, WriteOwner, etc.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DangerousRight {
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    ForceChangePassword,
    AddMembers,
    ReadLapsPassword,
    ReadGmsaPassword,
    DcSync,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclFinding {
    pub principal: String,
    pub principal_sid: Option<String>,
    pub target: String,
    pub target_dn: String,
    pub right: DangerousRight,
    pub is_inherited: bool,
}

/// ACE access mask bits that map to dangerous rights.
const GENERIC_ALL: u32 = 0x10000000;
const GENERIC_WRITE: u32 = 0x40000000;
const WRITE_DACL: u32 = 0x00040000;
const WRITE_OWNER: u32 = 0x00080000;
const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x00000020;
const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x00000100;
/// ADS_RIGHT_DS_CREATE_CHILD — SDDL abbreviation "CC" (0x1, not to be confused with CR=0x100)
const ADS_RIGHT_DS_CREATE_CHILD: u32 = 0x00000001;

/// Well-known GUIDs for extended rights / properties.
const GUID_USER_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
const GUID_REPLICATING_DIRECTORY_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
const GUID_REPLICATING_DIRECTORY_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
const GUID_MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
const GUID_MS_MCS_ADMPWD: &str = "faa13209-962c-4e55-8cfe-1b99ae3f1169";

pub async fn enumerate_dangerous_acls(config: &ReaperConfig) -> Result<Vec<AclFinding>> {
    info!("[acls] Querying {} for dangerous ACLs", config.dc_ip);

    let mut conn = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    )
    .await?;

    // Pull all objects with nTSecurityDescriptor — we parse the SDDL string representation
    // ldap3 returns binary attributes as base64; nTSecurityDescriptor comes back as a string
    // when the DC honours the "LDAP_SERVER_SD_FLAGS_OID" control (not available in ldap3 v0.11
    // without a raw extension).  We fall back to querying the textual `msDS-Approx-Immed-Subordinates`
    // and ACL-related attributes that ARE returned as strings.
    //
    // Strategy: look for the specific AD permissions that matter for attack paths.
    // We query each high-value object class separately with targeted filters.

    let mut findings: Vec<AclFinding> = Vec::new();

    // ── 1. Objects with WriteDACL / GenericAll on high-value groups ──────────────
    let hv_filters = [
        "(&(objectCategory=group)(|(sAMAccountName=Domain Admins)(sAMAccountName=Enterprise Admins)(sAMAccountName=Schema Admins)(sAMAccountName=Administrators)))",
        "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
        "(objectClass=domainDNS)",
    ];

    let sd_attrs = &[
        "distinguishedName",
        "sAMAccountName",
        "nTSecurityDescriptor",
    ];

    for filter in &hv_filters {
        match conn.custom_search(filter, sd_attrs).await {
            Ok(entries) => {
                for entry in &entries {
                    let target_dn = entry.dn.clone();
                    let target_name = entry
                        .attrs
                        .get("sAMAccountName")
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_else(|| target_dn.clone());

                    // nTSecurityDescriptor is returned as a base64 blob or SDDL string.
                    // We parse the SDDL representation when available.
                    if let Some(sddl_vals) = entry.attrs.get("nTSecurityDescriptor") {
                        for sddl in sddl_vals {
                            for finding in parse_sddl_acl(sddl, &target_name, &target_dn) {
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("[acls] SD query failed for filter {}: {}", filter, e),
        }
    }

    // ── 2. Users with msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) ───────────
    match conn
        .custom_search(
            "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            &[
                "distinguishedName",
                "sAMAccountName",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        )
        .await
    {
        Ok(entries) => {
            for entry in &entries {
                let target_dn = entry.dn.clone();
                let target_name = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| target_dn.clone());

                // The attribute value encodes the security descriptor of which principal
                // is allowed to perform RBCD — mark the computer itself as a finding.
                findings.push(AclFinding {
                    principal: "(encoded in msDS-AllowedToActOnBehalfOfOtherIdentity)".into(),
                    principal_sid: None,
                    target: target_name,
                    target_dn,
                    right: DangerousRight::Custom(
                        "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)".into(),
                    ),
                    is_inherited: false,
                });
            }
        }
        Err(e) => warn!("[acls] RBCD query failed: {}", e),
    }

    // ── 3. Objects with msDS-AllowedToDelegateTo ─────────────────────────────────
    match conn
        .custom_search(
            "(msDS-AllowedToDelegateTo=*)",
            &[
                "distinguishedName",
                "sAMAccountName",
                "msDS-AllowedToDelegateTo",
            ],
        )
        .await
    {
        Ok(entries) => {
            for entry in &entries {
                let target_dn = entry.dn.clone();
                let principal = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| target_dn.clone());

                let targets = entry
                    .attrs
                    .get("msDS-AllowedToDelegateTo")
                    .cloned()
                    .unwrap_or_default();

                for spn in &targets {
                    findings.push(AclFinding {
                        principal: principal.clone(),
                        principal_sid: None,
                        target: spn.clone(),
                        target_dn: target_dn.clone(),
                        right: DangerousRight::Custom(format!("Constrained delegation → {}", spn)),
                        is_inherited: false,
                    });
                }
            }
        }
        Err(e) => warn!("[acls] Delegation query failed: {}", e),
    }

    let _ = conn.disconnect().await;

    info!("[acls] Found {} dangerous ACL findings", findings.len());
    Ok(findings)
}

/// Parse an SDDL string and extract ACEs that map to dangerous rights.
/// SDDL ACE format: (ace_type;ace_flags;rights;object_guid;inherit_object_guid;trustee)
fn parse_sddl_acl(sddl: &str, target: &str, target_dn: &str) -> Vec<AclFinding> {
    let mut findings = Vec::new();

    // Find the DACL section: D:(...)
    let dacl_start = match sddl.find("D:") {
        Some(i) => i + 2,
        None => return findings,
    };
    let dacl_str = &sddl[dacl_start..];

    // Extract individual ACEs between parentheses
    let mut depth = 0usize;
    let mut ace_start = 0usize;
    let mut in_ace = false;

    for (i, ch) in dacl_str.char_indices() {
        match ch {
            '(' => {
                if depth == 0 {
                    ace_start = i + 1;
                    in_ace = true;
                }
                depth += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && in_ace {
                    let ace = &dacl_str[ace_start..i];
                    if let Some(f) = parse_sddl_ace(ace, target, target_dn) {
                        findings.push(f);
                    }
                    in_ace = false;
                }
            }
            _ => {}
        }
    }

    findings
}

/// Parse a single SDDL ACE string into an AclFinding if it represents a dangerous right.
fn parse_sddl_ace(ace: &str, target: &str, target_dn: &str) -> Option<AclFinding> {
    let parts: Vec<&str> = ace.splitn(6, ';').collect();
    if parts.len() < 6 {
        return None;
    }

    let ace_type = parts[0];
    let ace_flags = parts[1];
    let rights_str = parts[2];
    let object_guid = parts[3].to_lowercase();
    // parts[4] = inherit object guid (unused here)
    let trustee = parts[5];

    // Only care about Allow ACEs
    if ace_type != "A" {
        return None;
    }

    // Skip well-known system trustees
    if matches!(
        trustee,
        "BA" | "SY" | "PS" | "AU" | "WD" | "DA" | "EA" | "SA"
    ) {
        return None;
    }

    let is_inherited = ace_flags.contains('I');

    // Attempt to parse hex rights mask
    let rights_mask: u32 = if rights_str.starts_with("0x") || rights_str.starts_with("0X") {
        u32::from_str_radix(&rights_str[2..], 16).unwrap_or(0)
    } else {
        // Could be abbreviated like "GA", "GW", "SDWDWO" etc.
        sddl_abbrev_to_mask(rights_str)
    };

    // Determine which dangerous right applies
    let right = if rights_mask & GENERIC_ALL != 0 || rights_str.contains("GA") {
        DangerousRight::GenericAll
    } else if rights_mask & WRITE_DACL != 0 || rights_str.contains("WD") {
        DangerousRight::WriteDacl
    } else if rights_mask & WRITE_OWNER != 0 || rights_str.contains("WO") {
        DangerousRight::WriteOwner
    } else if rights_mask & GENERIC_WRITE != 0 || rights_str.contains("GW") {
        DangerousRight::GenericWrite
    } else if rights_mask & ADS_RIGHT_DS_CONTROL_ACCESS != 0 {
        // Extended right — check the object GUID
        match object_guid.as_str() {
            g if g == GUID_USER_FORCE_CHANGE_PASSWORD => DangerousRight::ForceChangePassword,
            g if g == GUID_REPLICATING_DIRECTORY_CHANGES
                || g == GUID_REPLICATING_DIRECTORY_CHANGES_ALL =>
            {
                DangerousRight::DcSync
            }
            _ => return None,
        }
    } else if rights_mask & ADS_RIGHT_DS_WRITE_PROP != 0 {
        // Write property — check the property set GUID
        match object_guid.as_str() {
            g if g == GUID_MEMBER => DangerousRight::AddMembers,
            g if g.contains(GUID_MS_MCS_ADMPWD) => DangerousRight::ReadLapsPassword,
            _ => return None,
        }
    } else {
        return None;
    };

    Some(AclFinding {
        principal: trustee.to_string(),
        principal_sid: Some(trustee.to_string()),
        target: target.to_string(),
        target_dn: target_dn.to_string(),
        right,
        is_inherited,
    })
}

/// Convert common SDDL abbreviated rights strings to a bitmask.
fn sddl_abbrev_to_mask(s: &str) -> u32 {
    let mut mask = 0u32;
    let mut i = 0;
    let bytes = s.as_bytes();
    while i + 1 < bytes.len() {
        let abbrev = &s[i..i + 2];
        match abbrev {
            "GA" => mask |= GENERIC_ALL,
            "GW" => mask |= GENERIC_WRITE,
            "GR" => mask |= 0x80000000,
            "GX" => mask |= 0x20000000,
            "WD" => mask |= WRITE_DACL,
            "WO" => mask |= WRITE_OWNER,
            "SD" => mask |= 0x00010000,
            "RC" => mask |= 0x00020000,
            "CC" => mask |= ADS_RIGHT_DS_CREATE_CHILD,
            "DC" => mask |= ADS_RIGHT_DS_WRITE_PROP,
            "SW" => mask |= 0x00000080,
            _ => {}
        }
        i += 2;
    }
    mask
}
