//! Export reaper results to JSON, CSV, or BloodHound-compatible formats.

use crate::runner::ReaperResult;
use overthrone_core::error::Result;
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    JsonPretty,
    Csv,
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

    info!("[export] Done → {}", path.display());
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
            "sAMAccountName,enabled,adminCount,kerberoastable,asrepRoastable,memberOf_count"
                .to_string(),
        ];
        for u in &result.users {
            lines.push(format!(
                "{},{},{},{},{},{}",
                u.sam_account_name,
                u.enabled,
                u.admin_count,
                u.is_kerberoastable(),
                u.is_asrep_roastable(),
                u.member_of.len(),
            ));
        }
        tokio::fs::write(&path, lines.join("\n")).await?;
        info!("[export] → {}", path.display());
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
        info!("[export] → {}", path.display());
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  BloodHound v4 Export
// ═══════════════════════════════════════════════════════════

async fn export_bloodhound_v4(result: &ReaperResult, base: &Path) -> Result<()> {
    let dir = base.parent().unwrap_or(Path::new("."));
    let timestamp = chrono::Utc::now().timestamp();

    // ── Users ──
    if !result.users.is_empty() {
        let users_json: Vec<Value> = result
            .users
            .iter()
            .map(|u| {
                let domain_upper = result.domain.to_uppercase();
                let object_id = u.sid.clone().unwrap_or_default();
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
                        "serviceprincipalnames": u.service_principal_names,
                        "highvalue": u.is_high_value(),
                    },
                    "MemberOf": u.member_of,
                    "Aces": [],
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
                "version": 4
            },
            "data": users_json
        });

        let path = dir.join(format!("{}_users.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound users → {}", path.display());
    }

    // ── Computers ──
    if !result.computers.is_empty() {
        let computers_json: Vec<Value> = result
            .computers
            .iter()
            .map(|c| {
                let domain_upper = result.domain.to_uppercase();
                let object_id = c.sid.clone().unwrap_or_default();
                json!({
                    "ObjectIdentifier": object_id,
                    "Properties": {
                        "name": format!("{}@{}",
                            c.dns_hostname.as_deref().unwrap_or(&c.sam_account_name).to_uppercase(),
                            domain_upper
                        ),
                        "domain": domain_upper,
                        "samaccountname": c.sam_account_name,
                        "operatingsystem": c.operating_system,
                        "enabled": c.enabled,
                        "unconstraineddelegation": c.unconstrained_delegation,
                        "lastlogontimestamp": c.last_logon,
                        "highvalue": c.is_high_value(),
                        "isDC": c.is_domain_controller,
                    },
                    "AllowedToDelegate": c.allowed_to_delegate_to,
                    "AllowedToAct": [],
                    "Sessions": { "Results": [], "Collected": false },
                    "LocalAdmins": { "Results": [], "Collected": false },
                    "Aces": [],
                })
            })
            .collect();

        let output = json!({
            "meta": {
                "methods": 0,
                "type": "computers",
                "count": computers_json.len(),
                "version": 4
            },
            "data": computers_json
        });

        let path = dir.join(format!("{}_computers.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound computers → {}", path.display());
    }

    // ── Groups ──
    if !result.groups.is_empty() {
        let groups_json: Vec<Value> = result.groups.iter().map(|g| {
            let domain_upper = result.domain.to_uppercase();
            let object_id = g.sid.clone().unwrap_or_default();
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
                "Aces": [],
            })
        }).collect();

        let output = json!({
            "meta": {
                "methods": 0,
                "type": "groups",
                "count": groups_json.len(),
                "version": 4
            },
            "data": groups_json
        });

        let path = dir.join(format!("{}_groups.json", timestamp));
        tokio::fs::write(&path, serde_json::to_string_pretty(&output)?).await?;
        info!("[export] BloodHound groups → {}", path.display());
    }

    // ── Domains ──
    let domain_upper = result.domain.to_uppercase();

    // Derive domain SID from an enumerated object's SID (strip the last RID component).
    // A Windows SID has the form S-1-5-21-<sub1>-<sub2>-<sub3>-<RID>.
    // The domain SID is everything except the last component.
    // If no object SID is available, omit the ObjectIdentifier rather than emitting
    // a syntactically invalid fake SID.
    let domain_sid: Option<String> = result
        .users
        .iter()
        .filter_map(|u| u.sid.as_deref())
        .chain(result.computers.iter().filter_map(|c| c.sid.as_deref()))
        .find_map(|sid| {
            let parts: Vec<&str> = sid.splitn(8, '-').collect();
            // SID: S-1-5-21-<A>-<B>-<C>-<RID> → 8 components; domain = first 7
            if parts.len() >= 7 {
                Some(parts[..parts.len() - 1].join("-"))
            } else {
                None
            }
        });

    let domain_object_id = domain_sid.as_deref().unwrap_or("UNKNOWN");

    let domain_json = json!({
        "meta": {
            "methods": 0,
            "type": "domains",
            "count": 1,
            "version": 4
        },
        "data": [{
            "ObjectIdentifier": domain_object_id,
            "Properties": {
                "name": domain_upper,
                "domain": domain_upper,
                "functionallevel": "Unknown",
            },
            "Trusts": result.trusts.iter().map(|t| json!({
                "TargetDomainName": t.target_domain.to_uppercase(),
                "TrustDirection": format!("{}", t.direction),
                "TrustType": format!("{}", t.trust_type),
                "IsTransitive": t.transitive,
                "SidFilteringEnabled": t.sid_filtering_enabled,
            })).collect::<Vec<_>>(),
            "Aces": [],
            "Links": [],
            "ChildObjects": [],
        }]
    });

    let path = dir.join(format!("{}_domains.json", timestamp));
    tokio::fs::write(&path, serde_json::to_string_pretty(&domain_json)?).await?;
    info!("[export] BloodHound domains → {}", path.display());

    Ok(())
}
