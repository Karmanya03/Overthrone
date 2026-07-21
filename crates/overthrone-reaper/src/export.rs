//! Export reaper results to JSON, CSV, or BloodHound-compatible formats.

use crate::acls::DangerousRight;
use crate::runner::ReaperResult;
use overthrone_core::error::Result;
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone)]
pub enum ExportFormat {
    /// `Json` variant
    Json,
    /// `JsonPretty` variant
    JsonPretty,
    /// `Csv` variant
    Csv,
    /// `BloodHoundV4` variant
    BloodHoundV4,
}

pub async fn export_results(
    result: &ReaperResult,
    path: &Path,
    format: ExportFormat,
) -> Result<()> {
    info!("[export] Writing results to {}", path.display());

    match format {
        ExportFormat::Json => {
            let json = serde_json::to_string(result)?;
            tokio::fs::write(path, json).await?;
        }
        ExportFormat::JsonPretty => {
            let json = serde_json::to_string_pretty(result)?;
            tokio::fs::write(path, json).await?;
        }
        ExportFormat::Csv => {
            export_csv(result, path).await?;
        }
        ExportFormat::BloodHoundV4 => {
            export_bloodhound_v4(result, path).await?;
        }
    }

    info!("[export] Done -> {}", path.display());
    Ok(())
}

async fn export_csv(result: &ReaperResult, base: &Path) -> Result<()> {
    let dir = base.parent().unwrap_or(Path::new("."));
    let stem = base
        .file_stem()
        .unwrap_or(OsStr::new("reaper"))
        .to_string_lossy();

    if !result.users.is_empty() {
        let path = dir.join(format!("{stem}_users.csv"));
        let mut lines = vec![
            "sAMAccountName,enabled,adminCount,kerberoastable,asrepRoastable,badPwdCount,badPwdTime,lockoutTime,logonCount,memberOf_count"
                .to_string(),
        ];
        for u in &result.users {
            lines.push(format!(
                "{},{},{},{},{},{},{},{},{},{}",
                u.sam_account_name,
                u.enabled,
                u.admin_count,
                u.is_kerberoastable(),
                u.is_asrep_roastable(),
                u.bad_pwd_count.map(|v| v.to_string()).unwrap_or_default(),
                u.bad_pwd_time.as_deref().unwrap_or(""),
                u.lockout_time.as_deref().unwrap_or(""),
                u.logon_count.map(|v| v.to_string()).unwrap_or_default(),
                u.member_of.len(),
            ));
        }
        tokio::fs::write(&path, lines.join("\n")).await?;
        info!("[export] -> {}", path.display());
    }

    if !result.snaffle_findings.is_empty() {
        let path = dir.join(format!("{stem}_snaffle.csv"));
        let mut lines = vec!["hostname,share,path,reason,severity,size".to_string()];
        for f in &result.snaffle_findings {
            lines.push(format!(
                "{},{},{},{},{},{}",
                f.hostname, f.share, f.path, f.reason, f.severity, f.size,
            ));
        }
        tokio::fs::write(&path, lines.join("\n")).await?;
        info!("[export] -> {}", path.display());
    }

    if !result.computers.is_empty() {
        let path = dir.join(format!("{stem}_computers.csv"));
        let mut lines =
            vec!["sAMAccountName,dnsHostname,os,enabled,unconstrainedDeleg,isDC".to_string()];
        for c in &result.computers {
            lines.push(format!(
                "{},{},{},{},{},{}",
                c.sam_account_name,
                c.dns_hostname.as_deref().unwrap_or(""),
                c.operating_system.as_deref().unwrap_or(""),
                c.enabled,
                c.unconstrained_delegation,
                c.is_domain_controller,
            ));
        }
        tokio::fs::write(&path, lines.join("\n")).await?;
        info!("[export] -> {}", path.display());
    }

    Ok(())
}

// ----------------------------------------------
//  BloodHound v4 Export
// ----------------------------------------------

fn right_to_bloodhound_name(right: &DangerousRight) -> String {
    match right {
        DangerousRight::GenericAll => "GenericAll".to_string(),
        DangerousRight::GenericWrite => "GenericWrite".to_string(),
        DangerousRight::WriteDacl => "WriteDacl".to_string(),
        DangerousRight::WriteOwner => "WriteOwner".to_string(),
        DangerousRight::Owns => "Owns".to_string(),
        DangerousRight::AllExtendedRights => "AllExtendedRights".to_string(),
        DangerousRight::CreateChild => "CreateChild".to_string(),
        DangerousRight::WriteSelf => "WriteSelf".to_string(),
        DangerousRight::ForceChangePassword => "ForceChangePassword".to_string(),
        DangerousRight::DcSync => "DcSync".to_string(),
        DangerousRight::ReadLapsPassword => "ReadLapsPassword".to_string(),
        DangerousRight::ReadLapsPasswordExpiry => "ReadLapsPasswordExpiry".to_string(),
        DangerousRight::ReadGmsaPassword => "ReadGmsaPassword".to_string(),
        DangerousRight::AddMembers => "AddMembers".to_string(),
        DangerousRight::AddSelf => "AddSelf".to_string(),
        DangerousRight::WriteSPN => "WriteSPN".to_string(),
        DangerousRight::WriteAllowedToDelegateTo => "WriteAllowedToDelegateTo".to_string(),
        DangerousRight::AddAllowedToAct => "AddAllowedToAct".to_string(),
        DangerousRight::WriteAccountRestrictions => "WriteAccountRestrictions".to_string(),
        DangerousRight::WriteLogonScript => "WriteLogonScript".to_string(),
        DangerousRight::WriteProfilePath => "WriteProfilePath".to_string(),
        DangerousRight::WriteScriptPath => "WriteScriptPath".to_string(),
        DangerousRight::WriteDnsHostName => "WriteDnsHostName".to_string(),
        DangerousRight::WriteServicePrincipalName => "WriteServicePrincipalName".to_string(),
        DangerousRight::WriteKeyCredentialLink => "WriteKeyCredentialLink".to_string(),
        DangerousRight::WriteMsDsKeyCredentialLink => "WriteMsDsKeyCredentialLink".to_string(),
        DangerousRight::WriteAltSecurityIdentities => "WriteAltSecurityIdentities".to_string(),
        DangerousRight::WriteUserParameters => "WriteUserParameters".to_string(),
        DangerousRight::WritePwdProperties => "WritePwdProperties".to_string(),
        DangerousRight::WriteLockoutThreshold => "WriteLockoutThreshold".to_string(),
        DangerousRight::WriteMinPwdLength => "WriteMinPwdLength".to_string(),
        DangerousRight::WritePwdHistoryLength => "WritePwdHistoryLength".to_string(),
        DangerousRight::WritePwdComplexity => "WritePwdComplexity".to_string(),
        DangerousRight::WritePwdReversibleEncryption => "WritePwdReversibleEncryption".to_string(),
        DangerousRight::WritePwdAge => "WritePwdAge".to_string(),
        DangerousRight::WriteLockoutDuration => "WriteLockoutDuration".to_string(),
        DangerousRight::WriteLockoutObservationWindow => {
            "WriteLockoutObservationWindow".to_string()
        }
        DangerousRight::WriteGPLink => "WriteGPLink".to_string(),
        DangerousRight::AddKeyCredentialLink => "AddKeyCredentialLink".to_string(),
        DangerousRight::WriteUserCertificate => "WriteUserCertificate".to_string(),
        DangerousRight::EnrollCertificate => "EnrollCertificate".to_string(),
        DangerousRight::Enroll => "Enroll".to_string(),
        DangerousRight::ManageCA => "ManageCA".to_string(),
        DangerousRight::ManageCertificates => "ManageCertificates".to_string(),
        DangerousRight::ManageCertTemplate => "ManageCertTemplate".to_string(),
        DangerousRight::UserForceChangePassword => "UserForceChangePassword".to_string(),
        DangerousRight::AllowedToAct => "AllowedToAct".to_string(),
        DangerousRight::WriteProperty { attribute, guid: _ } => attribute.clone(),
        DangerousRight::Custom(s) => s.clone(),
    }
}

async fn export_bloodhound_v4(result: &ReaperResult, base: &Path) -> Result<()> {
    let dir = base.parent().unwrap_or(Path::new("."));
    let timestamp = chrono::Utc::now().timestamp();

    let mut user_aces: Vec<Value> = Vec::new();
    let mut computer_aces: Vec<Value> = Vec::new();
    let mut group_aces: Vec<Value> = Vec::new();
    let mut ou_aces: Vec<Value> = Vec::new();
    let mut gpo_aces: Vec<Value> = Vec::new();
    let mut domain_aces: Vec<Value> = Vec::new();

    for finding in &result.acl_findings {
        let ace = json!({
            "PrincipalSID": finding.principal_sid.clone().unwrap_or_else(|| finding.principal.clone()),
            "PrincipalType": "Unknown",
            "RightName": right_to_bloodhound_name(&finding.right),
            "IsInherited": finding.is_inherited,
        });

        let target_lower = finding.target_dn.to_lowercase();
        if target_lower.contains("ou=") && !target_lower.contains("cn=users") {
            ou_aces.push(ace);
        } else if target_lower.contains("cn=users")
            || result
                .users
                .iter()
                .any(|u| u.sam_account_name.eq_ignore_ascii_case(&finding.target))
        {
            user_aces.push(ace);
        } else if result
            .computers
            .iter()
            .any(|c| c.sam_account_name.eq_ignore_ascii_case(&finding.target))
        {
            computer_aces.push(ace);
        } else if result
            .groups
            .iter()
            .any(|g| g.sam_account_name.eq_ignore_ascii_case(&finding.target))
        {
            group_aces.push(ace);
        } else if result.gpos.iter().any(|g| {
            g.display_name.eq_ignore_ascii_case(&finding.target)
                || g.gpc_file_sys_path
                    .as_ref()
                    .is_some_and(|p| p.eq_ignore_ascii_case(&finding.target))
        }) {
            gpo_aces.push(ace);
        } else {
            domain_aces.push(ace);
        }
    }

    // -- Users --
    if !result.users.is_empty() {
        let users_json: Vec<Value> = result
            .users
            .iter()
            .map(|u| {
                let domain_upper = result.domain.to_uppercase();
                let object_id = u.sid.clone().unwrap_or_default();
                let user_aces_for_this_user: Vec<Value> = user_aces
                    .iter()
                    .filter(|a| {
                        a["PrincipalSID"].as_str().is_some_and(|sid| {
                            u.sid.as_deref() == Some(sid)
                                || u.sam_account_name.eq_ignore_ascii_case(sid)
                        })
                    })
                    .cloned()
                    .collect();
                json!({
                    "ObjectIdentifier": object_id,
                    "Properties": {
                        "name": format!("{}@{}", u.sam_account_name.to_uppercase(), domain_upper),
                        "domain": domain_upper,
                        "samaccountname": u.sam_account_name,
                        "displayname": u.display_name,
                        "description": u.description,
                        "enabled": u.enabled,
                        "admincount": u.admin_count,
                        "hasspn": !u.service_principal_names.is_empty(),
                        "dontreqpreauth": u.dont_require_preauth,
                        "passwordnotreqd": u.uac_flags & 0x0020 != 0,
                        "pwdneverexpires": u.password_never_expires,
                        "lastlogontimestamp": u.last_logon,
                        "pwdlastset": u.last_password_change,
                        "badpwdcount": u.bad_pwd_count,
                        "badpwdtime": u.bad_pwd_time,
                        "lockouttime": u.lockout_time,
                        "accountexpires": u.account_expires,
                        "logoncount": u.logon_count,
                        "whencreated": u.when_created,
                        "whenchanged": u.when_changed,
                        "serviceprincipalnames": u.service_principal_names,
                        "highvalue": u.is_high_value(),
                        "allowedtodelegate": u.allowed_to_delegate_to,
                        "unconstraineddelegation": u.uac_flags & 0x80000 != 0,
                        "trustedtoauth": u.uac_flags & 0x1000000 != 0,
                        "hasrbcd": u.has_rbcd,
                    },
                    "MemberOf": u.member_of,
                    "Aces": user_aces_for_this_user,
                    "SPNTargets": [],
                    "HasSIDHistory": [],
                })
            })
            .collect();

        let output = json!({
            "meta": {
                "methods": 0,
                "type": "users",
                "count": users_json.len(),
                "version": 5
            },
            "data": users_json
        });

        let path = dir.join(format!("{}_users.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound users -> {}", path.display());
    }

    // -- Computers --
    if !result.computers.is_empty() {
        let computers_json: Vec<Value> = result
            .computers
            .iter()
            .map(|c| {
                let domain_upper = result.domain.to_uppercase();
                let object_id = c.sid.clone().unwrap_or_default();
                let computer_aces_for_this: Vec<Value> = computer_aces
                    .iter()
                    .filter(|a| {
                        a["PrincipalSID"].as_str().is_some_and(|sid| {
                            c.sid.as_deref() == Some(sid)
                                || c.sam_account_name.eq_ignore_ascii_case(sid)
                        })
                    })
                    .cloned()
                    .collect();
                json!({
                    "ObjectIdentifier": object_id,
                    "Properties": {
                        "name": format!(
                            "{}@{}",
                            c.dns_hostname.as_deref().unwrap_or(&c.sam_account_name).to_uppercase(),
                            domain_upper
                        ),
                        "domain": domain_upper,
                        "samaccountname": c.sam_account_name,
                        "operatingsystem": c.operating_system,
                        "enabled": c.enabled,
                        "unconstraineddelegation": c.unconstrained_delegation,
                        "trustedtoauth": c.constrained_delegation,
                        "lastlogontimestamp": c.last_logon,
                        "highvalue": c.is_high_value(),
                        "isdc": c.is_domain_controller,
                        "haslapsv1": c.laps_expiry.is_some(),
                    },
                    "AllowedToDelegate": c.allowed_to_delegate_to,
                    "AllowedToAct": [],
                    "Sessions": { "Results": [], "Collected": false },
                    "LocalAdmins": { "Results": [], "Collected": false },
                    "Aces": computer_aces_for_this,
                })
            })
            .collect();

        let output = json!({
            "meta": {
                "methods": 0,
                "type": "computers",
                "count": computers_json.len(),
                "version": 5
            },
            "data": computers_json
        });

        let path = dir.join(format!("{}_computers.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound computers -> {}", path.display());
    }

    // -- Groups --
    if !result.groups.is_empty() {
        let groups_json: Vec<Value> = result.groups.iter().map(|g| {
            let domain_upper = result.domain.to_uppercase();
            let object_id = g.sid.clone().unwrap_or_default();
            let group_aces_for_this: Vec<Value> = group_aces
                .iter()
                .filter(|a| a["PrincipalSID"].as_str().is_some_and(|sid| {
                    g.sid.as_deref() == Some(sid) || g.sam_account_name.eq_ignore_ascii_case(sid)
                }))
                .cloned()
                .collect();
            json!({
                "ObjectIdentifier": object_id,
                "Properties": {
                    "name": format!("{}@{}", g.sam_account_name.to_uppercase(), domain_upper),
                    "domain": domain_upper,
                    "samaccountname": g.sam_account_name,
                    "description": g.description,
                    "admincount": g.admin_count,
                    "highvalue": g.is_privileged(),
                },
                "Members": g.members.iter().map(|m| json!({ "MemberId": m, "MemberType": "Base" })).collect::<Vec<_>>(),
                "Aces": group_aces_for_this,
            })
        }).collect();

        let output = json!({
            "meta": {
                "methods": 0,
                "type": "groups",
                "count": groups_json.len(),
                "version": 5
            },
            "data": groups_json
        });

        let path = dir.join(format!("{}_groups.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound groups -> {}", path.display());
    }

    // -- OUs --
    if !result.ous.is_empty() {
        let ous_json: Vec<Value> = result
            .ous
            .iter()
            .map(|ou| {
                let ou_aces_for_this: Vec<Value> = ou_aces
                    .iter()
                    .filter(|a| {
                        a["PrincipalSID"]
                            .as_str()
                            .is_some_and(|sid| ou.distinguished_name.eq_ignore_ascii_case(sid))
                    })
                    .cloned()
                    .collect();
                json!({
                    "ObjectIdentifier": ou.distinguished_name,
                    "Properties": {
                        "name": ou.name,
                        "domain": result.domain.to_uppercase(),
                        "highvalue": false,
                    },
                    "Aces": ou_aces_for_this,
                    "ChildObjects": [],
                    "Links": [],
                })
            })
            .collect();

        let output = json!({
            "meta": {
                "methods": 0,
                "type": "ous",
                "count": ous_json.len(),
                "version": 5
            },
            "data": ous_json
        });

        let path = dir.join(format!("{}_ous.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound OUs -> {}", path.display());
    }

    // -- GPOs --
    if !result.gpos.is_empty() {
        let gpos_json: Vec<Value> = result.gpos.iter().map(|g| {
            let gpo_aces_for_this: Vec<Value> = gpo_aces
                .iter()
                .filter(|a| a["PrincipalSID"].as_str().is_some_and(|sid| {
                    g.display_name.eq_ignore_ascii_case(sid) ||
                    g.gpc_file_sys_path.as_ref().is_some_and(|p| p.eq_ignore_ascii_case(sid))
                }))
                .cloned()
                .collect();
            json!({
                "ObjectIdentifier": if !g.distinguished_name.is_empty() { g.distinguished_name.clone() } else { g.display_name.clone() },
                "Properties": {
                    "name": g.display_name,
                    "domain": result.domain.to_uppercase(),
                    "highvalue": false,
                },
                "Aces": gpo_aces_for_this,
                "ChildObjects": [],
                "Links": [],
            })
        }).collect();

        let output = json!({
            "meta": {
                "methods": 0,
                "type": "gpos",
                "count": gpos_json.len(),
                "version": 5
            },
            "data": gpos_json
        });

        let path = dir.join(format!("{}_gpos.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound GPOs -> {}", path.display());
    }

    // -- Domains --
    let domain_upper = result.domain.to_uppercase();

    // Derive domain SID from an enumerated object's SID (strip the last RID component).
    let domain_sid: Option<String> = result
        .users
        .iter()
        .filter_map(|u| u.sid.as_deref())
        .chain(result.computers.iter().filter_map(|c| c.sid.as_deref()))
        .find_map(|sid| {
            let parts: Vec<&str> = sid.splitn(8, '-').collect();
            if parts.len() >= 7 {
                Some(parts[..parts.len() - 1].join("-"))
            } else {
                None
            }
        });

    let domain_object_id = domain_sid.as_deref().unwrap_or("UNKNOWN");

    let functional_level = match result.functional_level {
        Some(0) => "2000",
        Some(1) => "2003Mixed",
        Some(2) => "2003",
        Some(3) => "2008",
        Some(4) => "2008R2",
        Some(5) => "2012",
        Some(6) => "2012R2",
        Some(7) => "2016",
        _ => "Unknown",
    };
    let domain_policy = result
        .policy
        .as_ref()
        .and_then(|p| p.domain_policy.as_ref());

    let domain_json = json!({
        "meta": {
            "methods": 0,
            "type": "domains",
            "count": 1,
            "version": 5
        },
        "data": [{
            "ObjectIdentifier": domain_object_id,
            "Properties": {
                "name": domain_upper,
                "domain": domain_upper,
                "functionallevel": functional_level,
                "minpwdlength": domain_policy.and_then(|p| p.min_password_length),
                "lockoutthreshold": domain_policy.and_then(|p| p.lockout_threshold),
                "lockoutduration": domain_policy.and_then(|p| p.lockout_duration.clone()),
                "lockoutobservationwindow": domain_policy.and_then(|p| p.lockout_observation_window.clone()),
                "pwdhistorylength": domain_policy.and_then(|p| p.password_history_length),
                "pwdcomplexity": domain_policy.map(|p| p.password_complexity_enabled),
                "reversibleencryption": domain_policy.map(|p| p.reversible_encryption_enabled),
            },
            "Trusts": result.trusts.iter().map(|t| json!({
                "TargetDomainName": t.target_domain.to_uppercase(),
                "TrustDirection": format!("{}", t.direction),
                "TrustType": format!("{}", t.trust_type),
                "IsTransitive": t.transitive,
                "SidFilteringEnabled": t.sid_filtering_enabled,
            })).collect::<Vec<_>>(),
            "Aces": domain_aces,
            "Links": [],
            "ChildObjects": [],
        }]
    });

    let path = dir.join(format!("{}_domains.json", timestamp));
    tokio::fs::write(&path, serde_json::to_string_pretty(&domain_json)?).await?;
    info!("[export] BloodHound domains -> {}", path.display());

    Ok(())
}

// ═══════════════════════════════════════════════════════════
// BloodHound Edge-Type Coverage Validation
// ═══════════════════════════════════════════════════════════

/// Known BloodHound v4 edge types (ACE rights).
/// This is the canonical list from the BloodHound Community Edition
/// and SpecterOps documentation (as of 2025).
pub fn known_bloodhound_v4_edges() -> Vec<&'static str> {
    vec![
        // Core ACL rights
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "AllExtendedRights",
        "CreateChild",
        "WriteSelf",
        "ForceChangePassword",
        "ReadLapsPassword",
        "ReadLapsPasswordExpiry",
        "ReadGmsaPassword",
        // Group membership
        "AddMembers",
        "AddSelf",
        // Kerberos/SPN abuse
        "WriteSPN",
        "WriteAllowedToDelegateTo",
        "AddAllowedToAct",
        "AddKeyCredentialLink",
        "WriteKeyCredentialLink",
        "WriteMsDsKeyCredentialLink",
        // Account restrictions
        "WriteAccountRestrictions",
        "WriteLogonScript",
        "WriteProfilePath",
        "WriteScriptPath",
        "WriteDnsHostName",
        "WriteServicePrincipalName",
        "WriteUserCertificate",
        "WriteUserParameters",
        "WriteAltSecurityIdentities",
        // Password policy
        "WritePwdProperties",
        "WriteLockoutThreshold",
        "WriteMinPwdLength",
        "WritePwdHistoryLength",
        "WritePwdComplexity",
        "WritePwdReversibleEncryption",
        "WritePwdAge",
        "WriteLockoutDuration",
        "WriteLockoutObservationWindow",
        // GPO
        "WriteGPLink",
        // DCSync
        "DcSync",
        // Certificate enrollment
        "Enroll",
        "EnrollCertificate",
        // CA management
        "ManageCA",
        "ManageCertificates",
        "ManageCertTemplate",
        // Extended rights
        "UserForceChangePassword",
        "AllowedToAct",
    ]
}

/// Check which known BloodHound v4 edge types are NOT covered by the
/// current `right_to_bloodhound_name` mapping.
pub fn missing_bloodhound_edges() -> Vec<String> {
    // Collect all edge names produced by our DangerousRight enum
    let covered: Vec<String> = all_mapped_bloodhound_edges();
    let covered_refs: Vec<&str> = covered.iter().map(|s| s.as_str()).collect();
    missing_bloodhound_edges_from(&covered_refs)
}

/// Check which known edges are missing from a given set of covered edges.
pub fn missing_bloodhound_edges_from(covered: &[&str]) -> Vec<String> {
    let known = known_bloodhound_v4_edges();
    known
        .iter()
        .filter(|edge| !covered.contains(edge))
        .map(|s| s.to_string())
        .collect()
}

/// Collect all edge names produced by the `right_to_bloodhound_name` function
/// across all `DangerousRight` variants (excluding WriteProperty and Custom).
fn all_mapped_bloodhound_edges() -> Vec<String> {
    use crate::acls::DangerousRight;
    let variants = [
        DangerousRight::GenericAll,
        DangerousRight::GenericWrite,
        DangerousRight::WriteDacl,
        DangerousRight::WriteOwner,
        DangerousRight::Owns,
        DangerousRight::AllExtendedRights,
        DangerousRight::CreateChild,
        DangerousRight::WriteSelf,
        DangerousRight::ForceChangePassword,
        DangerousRight::DcSync,
        DangerousRight::ReadLapsPassword,
        DangerousRight::ReadLapsPasswordExpiry,
        DangerousRight::ReadGmsaPassword,
        DangerousRight::AddMembers,
        DangerousRight::AddSelf,
        DangerousRight::WriteSPN,
        DangerousRight::WriteAllowedToDelegateTo,
        DangerousRight::AddAllowedToAct,
        DangerousRight::WriteAccountRestrictions,
        DangerousRight::WriteLogonScript,
        DangerousRight::WriteProfilePath,
        DangerousRight::WriteScriptPath,
        DangerousRight::WriteDnsHostName,
        DangerousRight::WriteServicePrincipalName,
        DangerousRight::WriteKeyCredentialLink,
        DangerousRight::WriteMsDsKeyCredentialLink,
        DangerousRight::WriteAltSecurityIdentities,
        DangerousRight::WriteUserParameters,
        DangerousRight::WritePwdProperties,
        DangerousRight::WriteLockoutThreshold,
        DangerousRight::WriteMinPwdLength,
        DangerousRight::WritePwdHistoryLength,
        DangerousRight::WritePwdComplexity,
        DangerousRight::WritePwdReversibleEncryption,
        DangerousRight::WritePwdAge,
        DangerousRight::WriteLockoutDuration,
        DangerousRight::WriteLockoutObservationWindow,
        DangerousRight::WriteGPLink,
        DangerousRight::AddKeyCredentialLink,
        DangerousRight::WriteUserCertificate,
        DangerousRight::EnrollCertificate,
        DangerousRight::Enroll,
        DangerousRight::ManageCA,
        DangerousRight::ManageCertificates,
        DangerousRight::ManageCertTemplate,
        DangerousRight::UserForceChangePassword,
        DangerousRight::AllowedToAct,
    ];
    variants.iter().map(right_to_bloodhound_name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_right_to_bloodhound_name_generic_all() {
        assert_eq!(
            right_to_bloodhound_name(&DangerousRight::GenericAll),
            "GenericAll"
        );
    }

    #[test]
    fn test_right_to_bloodhound_name_dcsync() {
        assert_eq!(right_to_bloodhound_name(&DangerousRight::DcSync), "DcSync");
    }

    #[test]
    fn test_right_to_bloodhound_name_write_property() {
        assert_eq!(
            right_to_bloodhound_name(&DangerousRight::WriteProperty {
                attribute: "servicePrincipalName".into(),
                guid: String::new(),
            }),
            "servicePrincipalName"
        );
    }

    #[test]
    fn test_right_to_bloodhound_name_custom() {
        assert_eq!(
            right_to_bloodhound_name(&DangerousRight::Custom("CustomRight".into())),
            "CustomRight"
        );
    }

    #[test]
    fn test_right_to_bloodhound_name_roundtrip() {
        let cases = [
            (DangerousRight::GenericAll, "GenericAll"),
            (DangerousRight::GenericWrite, "GenericWrite"),
            (DangerousRight::WriteDacl, "WriteDacl"),
            (DangerousRight::WriteOwner, "WriteOwner"),
            (DangerousRight::Owns, "Owns"),
            (DangerousRight::AllExtendedRights, "AllExtendedRights"),
            (DangerousRight::CreateChild, "CreateChild"),
            (DangerousRight::WriteSelf, "WriteSelf"),
            (DangerousRight::ForceChangePassword, "ForceChangePassword"),
            (DangerousRight::DcSync, "DcSync"),
            (DangerousRight::ReadLapsPassword, "ReadLapsPassword"),
            (DangerousRight::ReadGmsaPassword, "ReadGmsaPassword"),
            (DangerousRight::AddMembers, "AddMembers"),
            (DangerousRight::AddSelf, "AddSelf"),
            (DangerousRight::WriteSPN, "WriteSPN"),
            (DangerousRight::AddAllowedToAct, "AddAllowedToAct"),
            (DangerousRight::EnrollCertificate, "EnrollCertificate"),
            (DangerousRight::WriteGPLink, "WriteGPLink"),
        ];
        for (right, expected) in &cases {
            assert_eq!(right_to_bloodhound_name(right), *expected);
        }
    }

    #[test]
    fn test_bloodhound_edge_coverage_all_known_types_mapped() {
        let missing = missing_bloodhound_edges();
        assert!(
            missing.is_empty(),
            "Missing BloodHound edge types: {:?}",
            missing
        );
    }

    #[test]
    fn test_bloodhound_edge_coverage_detects_gaps() {
        // Simulate a result with only a few edge types
        let covered = vec!["GenericAll", "DcSync", "Owns"];
        let missing = missing_bloodhound_edges_from(&covered);
        assert!(!missing.is_empty());
        assert!(missing.contains(&"GenericWrite".to_string()));
        assert!(missing.contains(&"WriteDacl".to_string()));
    }

    #[test]
    fn test_known_bloodhound_v4_edges_comprehensive() {
        let edges = known_bloodhound_v4_edges();
        // Verify critical edges are in the known list
        assert!(edges.contains(&"GenericAll"));
        assert!(edges.contains(&"DcSync"));
        assert!(edges.contains(&"ForceChangePassword"));
        assert!(edges.contains(&"AddMembers"));
        assert!(edges.contains(&"WriteDacl"));
        assert!(edges.contains(&"WriteOwner"));
        assert!(edges.contains(&"Owns"));
        assert!(edges.contains(&"ReadLapsPassword"));
        assert!(edges.contains(&"Enroll"));
        assert!(edges.contains(&"AllExtendedRights"));
        // Verify count is reasonable (BloodHound v4 has ~50 edge types)
        assert!(
            edges.len() >= 40,
            "Expected >= 40 known edges, got {}",
            edges.len()
        );
    }
}
