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
    /// Standalone offline HTML report (users / groups / computers / trusts)
    Html,
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
        ExportFormat::Html => {
            export_html(result, path).await?;
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
//  HTML report export
// ----------------------------------------------

/// Escape text for HTML output.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render one `<table>` with escape-safe cells.
fn html_table(title: &str, headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "<h2>{}</h2>\n<table>\n<thead>\n<tr>",
        html_escape(title)
    ));
    for h in headers {
        out.push_str(&format!("<th>{}</th>", html_escape(h)));
    }
    out.push_str("</tr>\n</thead>\n<tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for cell in row {
            out.push_str(&format!("<td>{}</td>", html_escape(cell)));
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table>\n");
    out
}

/// Build the whole report page: summary tables for users, groups,
/// computers, and trusts plus section counts for everything skipped.
async fn export_html(result: &ReaperResult, base: &Path) -> Result<()> {
    let dir = base.parent().unwrap_or(Path::new("."));
    let stem = base
        .file_stem()
        .unwrap_or(OsStr::new("reaper"))
        .to_string_lossy();
    let path = dir.join(format!("{stem}_report.html"));

    let mut body = String::new();

    // Count helpers keep the summary compact.
    let user_rows: Vec<Vec<String>> = result
        .users
        .iter()
        .map(|u| {
            vec![
                u.sam_account_name.clone(),
                u.enabled.to_string(),
                u.admin_count.to_string(),
                u.is_kerberoastable().to_string(),
                u.is_asrep_roastable().to_string(),
                u.user_principal_name.clone().unwrap_or_default(),
            ]
        })
        .collect();

    let group_rows: Vec<Vec<String>> = result
        .groups
        .iter()
        .map(|g| {
            vec![
                g.sam_account_name.clone(),
                match g.group_type {
                    crate::groups::GroupKind::Global => "Global".to_string(),
                    crate::groups::GroupKind::DomainLocal => "Domain Local".to_string(),
                    crate::groups::GroupKind::Universal => "Universal".to_string(),
                    crate::groups::GroupKind::BuiltIn => "BuiltIn".to_string(),
                    crate::groups::GroupKind::Unknown(_) => "Unknown".to_string(),
                },
                g.members.len().to_string(),
                g.admin_count.to_string(),
                g.sid.clone().unwrap_or_default(),
            ]
        })
        .collect();

    let computer_rows: Vec<Vec<String>> = result
        .computers
        .iter()
        .map(|c| {
            vec![
                c.sam_account_name.clone(),
                c.dns_hostname.clone().unwrap_or_default(),
                c.operating_system.clone().unwrap_or_default(),
                c.enabled.to_string(),
                c.unconstrained_delegation.to_string(),
                c.is_domain_controller.to_string(),
            ]
        })
        .collect();

    let trust_rows: Vec<Vec<String>> = result
        .trusts
        .iter()
        .map(|t| {
            vec![
                t.target_domain.clone(),
                t.direction.to_string(),
                t.trust_type.to_string(),
                t.transitive.to_string(),
                t.sid_filtering_enabled.to_string(),
                t.tgt_delegation_enabled.to_string(),
            ]
        })
        .collect();

    body.push_str(&format!(
        "<h1>Overthrone REAPER report -- {}</h1>\n<p>Base DN: {} | functional level: {}</p>\n\
         <p>Objects: {} users, {} groups, {} computers, {} trusts | ACL findings: {} | LAPS: {} | \
         gMSA: {} | SPNs: {} | delegations: {} | snaffle findings: {}</p>\n",
        html_escape(&result.domain),
        html_escape(&result.base_dn),
        result
            .functional_level
            .map(|l| l.to_string())
            .unwrap_or_else(|| "unknown".into()),
        result.users.len(),
        result.groups.len(),
        result.computers.len(),
        result.trusts.len(),
        result.acl_findings.len(),
        result.laps_entries.len(),
        result.gmsa_entries.len(),
        result.spn_accounts.len(),
        result.delegations.len(),
        result.snaffle_findings.len(),
    ));

    if !user_rows.is_empty() {
        body.push_str(&html_table(
            "Users",
            &[
                "sAMAccountName",
                "enabled",
                "adminCount",
                "kerberoastable",
                "as-REP roastable",
                "UPN",
            ],
            &user_rows,
        ));
    }
    if !group_rows.is_empty() {
        body.push_str(&html_table(
            "Groups",
            &["sAMAccountName", "type", "members", "adminCount", "SID"],
            &group_rows,
        ));
    }
    if !computer_rows.is_empty() {
        body.push_str(&html_table(
            "Computers",
            &[
                "sAMAccountName",
                "dnsHostname",
                "os",
                "enabled",
                "unconstr. deleg",
                "DC",
            ],
            &computer_rows,
        ));
    }
    if !trust_rows.is_empty() {
        body.push_str(&html_table(
            "Trusts",
            &[
                "target domain",
                "direction",
                "type",
                "transitive",
                "SID filtering",
                "TGT delegation",
            ],
            &trust_rows,
        ));
    }

    let html = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Overthrone REAPER -- {}</title>\n\
         <style>\nbody{{font-family:Consolas,monospace;margin:2em;background:#111;color:#ccc}}\n\
         table{{border-collapse:collapse;margin-bottom:2em;font-size:0.9em}}\n\
         th,td{{border:1px solid #444;padding:4px 10px;text-align:left}}\n\
         th{{background:#262626;color:#e6e6e6}}\n\
         tr:nth-child(even){{background:#1a1a1a}}\nh1{{color:#f33}}h2{{color:#7cc}}\n\
         </style>\n</head>\n<body>\n{body}</body>\n</html>\n",
        html_escape(&result.domain),
    );

    tokio::fs::write(&path, html).await?;
    info!("[export] HTML report -> {}", path.display());
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

// ===========================================================
// BloodHound Edge-Type Coverage Validation
// ===========================================================

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

    // -------------------------------------------------------
    //  HTML report export
    // -------------------------------------------------------

    #[test]
    fn test_html_escape_special_chars() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("say \"hi\""), "say &quot;hi&quot;");
        assert_eq!(html_escape("plain cn=Users"), "plain cn=Users");
    }

    #[test]
    fn test_html_table_renders_headers_rows_and_escapes() {
        let table = html_table(
            "Users",
            &["sAMAccountName", "enabled"],
            &[vec!["<b>evil</b>".to_string(), "true".to_string()]],
        );
        assert!(table.contains("<h2>Users</h2>"), "title");
        assert!(table.contains("<th>sAMAccountName</th>"), "header");
        assert!(table.contains("<th>enabled</th>"), "header");
        assert!(
            table.contains("<td>&lt;b&gt;evil&lt;/b&gt;</td>"),
            "cell escaped: {table}"
        );
        assert!(!table.contains("<b>evil</b>"), "no raw angle brackets");
    }

    #[test]
    fn test_html_table_empty_rows() {
        let table = html_table("Empty", &["h1"], &[]);
        assert!(table.contains("<h2>Empty</h2>"));
        assert!(table.contains("<th>h1</th>"));
        assert!(!table.contains("<td>"));
    }

    /// Synthetic result covering one entry of each rendered table plus a
    /// hostile name that must come out escaped.
    fn sample_result() -> ReaperResult {
        use crate::computers::ComputerEntry;
        use crate::groups::{GroupEntry, GroupKind};
        use crate::trusts::{TrustDirection, TrustEntry, TrustType};
        use crate::users::UserEntry;

        ReaperResult {
            domain: "corp.local".into(),
            base_dn: "DC=corp,DC=local".into(),
            functional_level: Some(7),
            users: vec![UserEntry {
                sam_account_name: "svc.sql<i>inject</i>".into(),
                enabled: true,
                admin_count: true,
                ..Default::default()
            }],
            groups: vec![GroupEntry {
                sam_account_name: "Domain Admins".into(),
                group_type: GroupKind::BuiltIn,
                admin_count: true,
                sid: Some("S-1-5-32-544".into()),
                ..Default::default()
            }],
            computers: vec![ComputerEntry {
                sam_account_name: "DC01$".into(),
                is_domain_controller: true,
                unconstrained_delegation: true,
                ..Default::default()
            }],
            trusts: vec![TrustEntry {
                target_domain: "forest.corp.local".into(),
                direction: TrustDirection::Bidirectional,
                trust_type: TrustType::Forest,
                ..Default::default()
            }],
            ..sample_result_shell()
        }
    }

    fn sample_result_shell() -> ReaperResult {
        ReaperResult {
            domain: String::new(),
            base_dn: String::new(),
            functional_level: None,
            users: Vec::new(),
            groups: Vec::new(),
            computers: Vec::new(),
            ous: Vec::new(),
            gpos: Vec::new(),
            trusts: Vec::new(),
            policy: None,
            spn_accounts: Vec::new(),
            delegations: Vec::new(),
            acl_findings: Vec::new(),
            laps_entries: Vec::new(),
            gmsa_entries: Vec::new(),
            snaffle_findings: Vec::new(),
            powerview_results: None,
            mssql_instances: Vec::new(),
            adcs_templates: Vec::new(),
        }
    }

    #[test]
    fn test_export_html_roundtrip() {
        use tokio_test::block_on;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("engagement");
        block_on(export_results(&sample_result(), &base, ExportFormat::Html)).unwrap();

        let report = dir.path().join("engagement_report.html");
        assert!(report.exists(), "html report written next to the base stem");
        let html = std::fs::read_to_string(&report).unwrap();
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<h1>Overthrone REAPER report -- corp.local</h1>"));
        assert!(html.contains("Base DN: DC=corp,DC=local"));
        assert!(html.contains("<h2>Users</h2>"));
        assert!(html.contains("<h2>Groups</h2>"));
        assert!(html.contains("<h2>Computers</h2>"));
        assert!(html.contains("<h2>Trusts</h2>"));
        assert!(
            html.contains("svc.sql&lt;i&gt;inject&lt;/i&gt;"),
            "hostile name escaped"
        );
        assert!(!html.contains("svc.sql<i>inject</i>"), "never raw html");
        assert!(html.contains("Domain Admins"));
        assert!(html.contains("S-1-5-32-544"));
        assert!(html.contains("forest.corp.local"));
        assert!(html.contains("Bidirectional"));
    }

    #[test]
    fn test_export_html_empty_result_has_no_tables() {
        use tokio_test::block_on;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("empty");
        block_on(export_results(
            &sample_result_shell(),
            &base,
            ExportFormat::Html,
        ))
        .unwrap();

        let html = std::fs::read_to_string(dir.path().join("empty_report.html")).unwrap();
        assert!(html.contains("Objects: 0 users, 0 groups, 0 computers, 0 trusts"));
        assert!(!html.contains("<h2>"));
    }

    #[test]
    fn test_export_html_does_not_overlap_stem_exports() {
        use tokio_test::block_on;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("out");
        block_on(export_results(
            &sample_result_shell(),
            &base,
            ExportFormat::Html,
        ))
        .unwrap();
        block_on(export_results(
            &sample_result_shell(),
            &base,
            ExportFormat::JsonPretty,
        ))
        .unwrap();

        assert!(dir.path().join("out_report.html").exists());
        assert!(dir.path().join("out").exists());
        // json export must not have been diverted to the html name
        assert!(
            std::fs::read_to_string(dir.path().join("out"))
                .unwrap()
                .starts_with('{')
        );
    }
}
