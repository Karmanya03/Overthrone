use crate::session::{EngagementSession, Finding, Severity};
use anyhow::{Context, Result};
use rust_xlsxwriter::*;
use std::collections::BTreeMap;
use std::path::Path;

const HEADER_BG: u32 = 0x4472C4;
const ALT_ROW_BG: u32 = 0xD9E2F3;

fn header_format() -> Format {
    Format::new()
        .set_bold()
        .set_background_color(Color::RGB(HEADER_BG))
        .set_font_color(Color::White)
        .set_border(FormatBorder::Thin)
}

fn alt_format() -> Format {
    Format::new()
        .set_background_color(Color::RGB(ALT_ROW_BG))
        .set_border(FormatBorder::Thin)
}

fn base_format() -> Format {
    Format::new().set_border(FormatBorder::Thin)
}

fn severity_format(severity: &Severity) -> Format {
    let (bg, fc) = match severity {
        Severity::Critical => (0xC0392B, 0xFFFFFF),
        Severity::High => (0xE67E22, 0xFFFFFF),
        Severity::Medium => (0xF1C40F, 0x000000),
        Severity::Low => (0x3498DB, 0xFFFFFF),
        Severity::Informational => (0x95A5A6, 0xFFFFFF),
    };
    Format::new()
        .set_background_color(Color::RGB(bg))
        .set_font_color(Color::RGB(fc))
        .set_border(FormatBorder::Thin)
}

fn write_headers(worksheet: &mut Worksheet, headers: &[&str], header_fmt: &Format) -> Result<()> {
    for (col, h) in headers.iter().enumerate() {
        worksheet.write_with_format(0, col as u16, *h, header_fmt)?;
    }
    Ok(())
}

fn row_fmt(row: u32) -> Format {
    if (row & 1) == 0 {
        base_format()
    } else {
        alt_format()
    }
}

pub fn generate_xlsx_report(session: &EngagementSession, output_path: &Path) -> Result<()> {
    let mut workbook = Workbook::new();
    let hdr = header_format();

    // -- Sheet 1: Summary --
    {
        let ws = workbook.add_worksheet();
        ws.set_name("Summary")?;
        ws.set_tab_color(Color::RGB(HEADER_BG));
        ws.write_with_format(0, 0, "Summary", &hdr)?;
        ws.set_column_width(0, 30)?;
        ws.set_column_width(1, 50)?;

        let data = build_summary_data(session);
        for (i, (k, v)) in data.iter().enumerate() {
            let row = (i + 1) as u32;
            let fmt = row_fmt(row);
            ws.write_with_format(row, 0, k.as_str(), &fmt)?;
            ws.write_with_format(row, 1, v.as_str(), &fmt)?;
        }
    }

    // -- Sheet 2: Findings --
    {
        let ws = workbook.add_worksheet();
        ws.set_name("Findings")?;
        ws.set_tab_color(Color::RGB(0xC0392B));
        let headers = &[
            "ID",
            "Title",
            "Severity",
            "CVSS",
            "Category",
            "Affected Assets",
            "Description",
            "Impact",
            "Remediation",
            "Status",
        ];
        write_headers(ws, headers, &hdr)?;
        ws.autofilter(0, 0, session.findings.len() as u32, 9)?;
        ws.set_column_width(0, 14)?;
        ws.set_column_width(1, 45)?;
        ws.set_column_width(2, 10)?;
        ws.set_column_width(3, 6)?;
        ws.set_column_width(4, 20)?;
        ws.set_column_width(5, 30)?;
        ws.set_column_width(6, 40)?;
        ws.set_column_width(7, 30)?;
        ws.set_column_width(8, 40)?;
        ws.set_column_width(9, 14)?;

        for (i, finding) in session.findings.iter().enumerate() {
            let row = (i + 1) as u32;
            let sfmt = severity_format(&finding.severity);
            let bfmt = row_fmt(row);

            ws.write_with_format(row, 0, &finding.id, &bfmt)?;
            ws.write_with_format(row, 1, &finding.title, &bfmt)?;
            ws.write_with_format(row, 2, finding.severity.to_string(), &sfmt)?;
            ws.write_with_format(row, 3, finding.cvss_score as f64, &bfmt)?;
            ws.write_with_format(row, 4, finding.category.to_string(), &bfmt)?;
            ws.write_with_format(row, 5, finding.affected_assets.join("; "), &bfmt)?;
            ws.write_with_format(row, 6, &finding.description, &bfmt)?;
            ws.write_with_format(row, 7, &finding.business_impact, &bfmt)?;
            let m: Vec<&str> = finding
                .mitigations
                .iter()
                .map(|m| m.title.as_str())
                .collect();
            ws.write_with_format(row, 8, m.join("; "), &bfmt)?;
            ws.write_with_format(row, 9, "Open", &bfmt)?;
        }
    }

    // -- Sheets 3-8 (require engagement_state) --
    if let Some(ref state) = session.engagement_state {
        let domain = state.domain.as_deref().unwrap_or("");

        // Sheet 3: Users
        {
            let ws = workbook.add_worksheet();
            ws.set_name("Users")?;
            ws.set_tab_color(Color::RGB(0x27AE60));
            let headers = &[
                "Username",
                "Domain",
                "Enabled",
                "Admin Count",
                "SPNs",
                "AS-REP Roastable",
                "Kerberoastable",
                "Description",
            ];
            write_headers(ws, headers, &hdr)?;
            ws.autofilter(0, 0, state.users.len() as u32, 7)?;
            ws.set_column_width(0, 20)?;
            ws.set_column_width(1, 20)?;
            ws.set_column_width(2, 8)?;
            ws.set_column_width(3, 10)?;
            ws.set_column_width(4, 30)?;
            ws.set_column_width(5, 12)?;
            ws.set_column_width(6, 12)?;
            ws.set_column_width(7, 30)?;

            let asrep_set: std::collections::HashSet<&str> =
                state.asrep_roastable.iter().map(|s| s.as_str()).collect();
            let kerb_set: std::collections::HashSet<&str> =
                state.kerberoastable.iter().map(|s| s.as_str()).collect();

            for (i, user) in state.users.iter().enumerate() {
                let row = (i + 1) as u32;
                let fmt = row_fmt(row);
                ws.write_with_format(row, 0, &user.sam_account_name, &fmt)?;
                ws.write_with_format(row, 1, domain, &fmt)?;
                ws.write_with_format(row, 2, if user.enabled { "Yes" } else { "No" }, &fmt)?;
                ws.write_with_format(row, 3, if user.admin_count { "Yes" } else { "No" }, &fmt)?;
                let spns = state
                    .spn_map
                    .get(&user.sam_account_name)
                    .cloned()
                    .unwrap_or_default();
                ws.write_with_format(row, 4, spns.join("; "), &fmt)?;
                ws.write_with_format(
                    row,
                    5,
                    if asrep_set.contains(user.sam_account_name.as_str()) {
                        "Yes"
                    } else {
                        "No"
                    },
                    &fmt,
                )?;
                ws.write_with_format(
                    row,
                    6,
                    if kerb_set.contains(user.sam_account_name.as_str()) {
                        "Yes"
                    } else {
                        "No"
                    },
                    &fmt,
                )?;
                ws.write_with_format(row, 7, user.description.as_deref().unwrap_or(""), &fmt)?;
            }
        }

        // Sheet 4: Computers
        {
            let ws = workbook.add_worksheet();
            ws.set_name("Computers")?;
            ws.set_tab_color(Color::RGB(0x2980B9));
            let headers = &[
                "Name",
                "Domain",
                "OS",
                "Unconstrained Delegation",
                "LAPS",
                "Description",
            ];
            write_headers(ws, headers, &hdr)?;
            ws.autofilter(0, 0, state.computers.len() as u32, 5)?;
            ws.set_column_width(0, 20)?;
            ws.set_column_width(1, 20)?;
            ws.set_column_width(2, 25)?;
            ws.set_column_width(3, 18)?;
            ws.set_column_width(4, 10)?;
            ws.set_column_width(5, 30)?;

            let laps_names: std::collections::HashSet<&str> = state
                .laps
                .iter()
                .map(|l| l.computer_name.as_str())
                .collect();

            for (i, comp) in state.computers.iter().enumerate() {
                let row = (i + 1) as u32;
                let fmt = row_fmt(row);
                ws.write_with_format(row, 0, &comp.sam_account_name, &fmt)?;
                ws.write_with_format(row, 1, domain, &fmt)?;
                ws.write_with_format(
                    row,
                    2,
                    comp.operating_system.as_deref().unwrap_or("Unknown"),
                    &fmt,
                )?;
                ws.write_with_format(
                    row,
                    3,
                    if comp.unconstrained_delegation {
                        "Yes"
                    } else {
                        "No"
                    },
                    &fmt,
                )?;
                ws.write_with_format(
                    row,
                    4,
                    if laps_names.contains(comp.sam_account_name.as_str()) {
                        "Yes"
                    } else {
                        "No"
                    },
                    &fmt,
                )?;
                ws.write_with_format(row, 5, "", &fmt)?;
            }
        }

        // Sheet 5: Groups
        {
            let ws = workbook.add_worksheet();
            ws.set_name("Groups")?;
            ws.set_tab_color(Color::RGB(0x8E44AD));
            let headers = &[
                "Name",
                "Domain",
                "Group Type",
                "Members Count",
                "Privileged",
                "Admin Count",
                "Description",
            ];
            write_headers(ws, headers, &hdr)?;

            let mut sorted: Vec<(&String, &Vec<String>)> = state.groups.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            ws.autofilter(0, 0, sorted.len() as u32, 6)?;
            ws.set_column_width(0, 25)?;
            ws.set_column_width(1, 20)?;
            ws.set_column_width(2, 15)?;
            ws.set_column_width(3, 12)?;
            ws.set_column_width(4, 10)?;
            ws.set_column_width(5, 10)?;
            ws.set_column_width(6, 30)?;

            let privileged_keywords = [
                "admin",
                "domain admins",
                "enterprise admins",
                "schema admins",
                "backup operators",
                "server operators",
                "account operators",
                "print operators",
            ];

            for (i, (name, members)) in sorted.iter().enumerate() {
                let row = (i + 1) as u32;
                let fmt = row_fmt(row);
                let name_lower = name.to_lowercase();
                let is_priv = privileged_keywords.iter().any(|k| name_lower.contains(k));
                ws.write_with_format(row, 0, name.as_str(), &fmt)?;
                ws.write_with_format(row, 1, domain, &fmt)?;
                ws.write_with_format(
                    row,
                    2,
                    if is_priv { "Security" } else { "Distribution" },
                    &fmt,
                )?;
                ws.write_with_format(row, 3, members.len() as f64, &fmt)?;
                ws.write_with_format(row, 4, if is_priv { "Yes" } else { "No" }, &fmt)?;
                ws.write_with_format(row, 5, "", &fmt)?;
                ws.write_with_format(row, 6, "", &fmt)?;
            }
            if sorted.is_empty() {
                ws.write_with_format(1, 0, "No groups discovered", &base_format())?;
            }
        }

        // Sheet 6: Trusts
        {
            let ws = workbook.add_worksheet();
            ws.set_name("Trusts")?;
            ws.set_tab_color(Color::RGB(0xE67E22));
            let headers = &[
                "Source Domain",
                "Target Domain",
                "Direction",
                "Type",
                "Transitive",
                "SID Filtering",
            ];
            write_headers(ws, headers, &hdr)?;
            ws.autofilter(0, 0, state.trusts.len().max(1) as u32, 5)?;
            ws.set_column_width(0, 25)?;
            ws.set_column_width(1, 25)?;
            ws.set_column_width(2, 15)?;
            ws.set_column_width(3, 15)?;
            ws.set_column_width(4, 12)?;
            ws.set_column_width(5, 12)?;

            for (i, trust_str) in state.trusts.iter().enumerate() {
                let row = (i + 1) as u32;
                let fmt = row_fmt(row);
                let parts: Vec<&str> = trust_str.splitn(2, '\\').collect();
                let target = if parts.len() > 1 {
                    parts[1]
                } else {
                    trust_str.as_str()
                };
                ws.write_with_format(row, 0, domain, &fmt)?;
                ws.write_with_format(row, 1, target, &fmt)?;
                ws.write_with_format(row, 2, "Bidirectional", &fmt)?;
                ws.write_with_format(row, 3, "External", &fmt)?;
                ws.write_with_format(row, 4, "Yes", &fmt)?;
                ws.write_with_format(row, 5, "Enabled", &fmt)?;
            }
            if state.trusts.is_empty() {
                ws.write_with_format(1, 0, "No trusts discovered", &base_format())?;
            }
        }

        // Sheet 7: Kerberos
        {
            let ws = workbook.add_worksheet();
            ws.set_name("Kerberos")?;
            ws.set_tab_color(Color::RGB(0xF39C12));
            let headers = &["Username", "Domain", "Issue Type", "Service", "Hash"];
            write_headers(ws, headers, &hdr)?;

            struct KerbRow {
                user: String,
                domain: String,
                issue: String,
                service: String,
                hash: String,
            }

            let mut rows: Vec<KerbRow> = Vec::new();
            for user in &state.kerberoastable {
                let issue = if state.asrep_roastable.contains(user) {
                    "Both".into()
                } else {
                    "Kerberoastable".into()
                };
                let spns = state.spn_map.get(user).cloned().unwrap_or_default();
                rows.push(KerbRow {
                    user: user.clone(),
                    domain: domain.to_string(),
                    issue,
                    service: spns.join("; "),
                    hash: String::new(),
                });
            }
            for user in &state.asrep_roastable {
                if !state.kerberoastable.contains(user) {
                    rows.push(KerbRow {
                        user: user.clone(),
                        domain: domain.to_string(),
                        issue: "AS-REP".into(),
                        service: String::new(),
                        hash: String::new(),
                    });
                }
            }

            ws.autofilter(0, 0, rows.len().max(1) as u32, 4)?;
            ws.set_column_width(0, 20)?;
            ws.set_column_width(1, 20)?;
            ws.set_column_width(2, 16)?;
            ws.set_column_width(3, 40)?;
            ws.set_column_width(4, 50)?;

            for (i, r) in rows.iter().enumerate() {
                let row = (i + 1) as u32;
                let fmt = row_fmt(row);
                ws.write_with_format(row, 0, &r.user, &fmt)?;
                ws.write_with_format(row, 1, &r.domain, &fmt)?;
                ws.write_with_format(row, 2, &r.issue, &fmt)?;
                ws.write_with_format(row, 3, &r.service, &fmt)?;
                ws.write_with_format(row, 4, &r.hash, &fmt)?;
            }
            if rows.is_empty() {
                ws.write_with_format(1, 0, "No kerberos issues discovered", &base_format())?;
            }
        }

        // Sheet 8: Delegation
        {
            let ws = workbook.add_worksheet();
            ws.set_name("Delegation")?;
            ws.set_tab_color(Color::RGB(0xE74C3C));
            let headers = &["Account", "Domain", "Delegation Type", "Allowed Principals"];
            write_headers(ws, headers, &hdr)?;

            struct DelRow {
                account: String,
                domain: String,
                del_type: String,
                principals: String,
            }

            let mut d: Vec<DelRow> = Vec::new();
            for comp in &state.unconstrained_delegation {
                d.push(DelRow {
                    account: comp.clone(),
                    domain: domain.to_string(),
                    del_type: "Unconstrained".into(),
                    principals: String::new(),
                });
            }
            for info in &state.constrained_delegation {
                d.push(DelRow {
                    account: info.account.clone(),
                    domain: domain.to_string(),
                    del_type: format!("Constrained ({})", info.delegation_type),
                    principals: info.targets.join("; "),
                });
            }
            for target in &state.rbcd_targets {
                d.push(DelRow {
                    account: target.clone(),
                    domain: domain.to_string(),
                    del_type: "RBCD".into(),
                    principals: String::new(),
                });
            }

            ws.autofilter(0, 0, d.len().max(1) as u32, 3)?;
            ws.set_column_width(0, 25)?;
            ws.set_column_width(1, 20)?;
            ws.set_column_width(2, 20)?;
            ws.set_column_width(3, 40)?;

            for (i, r) in d.iter().enumerate() {
                let row = (i + 1) as u32;
                let fmt = row_fmt(row);
                ws.write_with_format(row, 0, &r.account, &fmt)?;
                ws.write_with_format(row, 1, &r.domain, &fmt)?;
                ws.write_with_format(row, 2, &r.del_type, &fmt)?;
                ws.write_with_format(row, 3, &r.principals, &fmt)?;
            }
            if d.is_empty() {
                ws.write_with_format(1, 0, "No delegation issues discovered", &base_format())?;
            }
        }
    }

    // -- Sheet 9: Remediation --
    {
        let ws = workbook.add_worksheet();
        ws.set_name("Remediation")?;
        ws.set_tab_color(Color::RGB(0x2ECC71));
        let headers = &[
            "Priority",
            "Finding Title",
            "Category",
            "Effort",
            "Implementation",
            "Description",
        ];
        write_headers(ws, headers, &hdr)?;

        let mut all_mits: Vec<(&Finding, &crate::mitigations::Mitigation)> = Vec::new();
        for finding in &session.findings {
            for mitigation in &finding.mitigations {
                all_mits.push((finding, mitigation));
            }
        }
        all_mits.sort_by_key(|(_, m)| m.priority);

        ws.autofilter(0, 0, all_mits.len().max(1) as u32, 5)?;
        ws.set_column_width(0, 18)?;
        ws.set_column_width(1, 45)?;
        ws.set_column_width(2, 20)?;
        ws.set_column_width(3, 10)?;
        ws.set_column_width(4, 40)?;
        ws.set_column_width(5, 40)?;

        for (i, (finding, mitigation)) in all_mits.iter().enumerate() {
            let row = (i + 1) as u32;
            let fmt = row_fmt(row);
            ws.write_with_format(row, 0, mitigation.priority.to_string(), &fmt)?;
            ws.write_with_format(row, 1, &finding.title, &fmt)?;
            ws.write_with_format(row, 2, mitigation.category.to_string(), &fmt)?;
            ws.write_with_format(row, 3, mitigation.effort.to_string(), &fmt)?;
            ws.write_with_format(row, 4, &mitigation.title, &fmt)?;
            ws.write_with_format(row, 5, &mitigation.description, &fmt)?;
        }
        if all_mits.is_empty() {
            ws.write_with_format(1, 0, "No mitigations available", &base_format())?;
        }
    }

    // -- Sheet 10: MITRE ATT&CK --
    {
        let ws = workbook.add_worksheet();
        ws.set_name("MITRE ATT&CK")?;
        ws.set_tab_color(Color::RGB(0x8E44AD));
        let headers = &["Tactic", "Technique ID", "Technique Name", "Finding Count"];
        write_headers(ws, headers, &hdr)?;

        let mut tech_counts: BTreeMap<String, (String, String, usize)> = BTreeMap::new();
        for finding in &session.findings {
            for mitre in &finding.mitre {
                let entry = tech_counts
                    .entry(mitre.technique_id.clone())
                    .or_insert_with(|| (mitre.tactic.clone(), mitre.technique_name.clone(), 0));
                entry.2 += 1;
            }
        }
        let rows: Vec<(&String, &String, &String, usize)> = tech_counts
            .iter()
            .map(|(id, (tactic, name, count))| (id, tactic, name, *count))
            .collect();

        ws.autofilter(0, 0, rows.len().max(1) as u32, 3)?;
        ws.set_column_width(0, 25)?;
        ws.set_column_width(1, 15)?;
        ws.set_column_width(2, 40)?;
        ws.set_column_width(3, 14)?;

        for (i, (tech_id, tactic, name, count)) in rows.iter().enumerate() {
            let row = (i + 1) as u32;
            let fmt = row_fmt(row);
            ws.write_with_format(row, 0, *tactic, &fmt)?;
            ws.write_with_format(row, 1, *tech_id, &fmt)?;
            ws.write_with_format(row, 2, *name, &fmt)?;
            ws.write_with_format(row, 3, *count as f64, &fmt)?;
        }
        if rows.is_empty() {
            ws.write_with_format(1, 0, "No MITRE ATT&CK mappings available", &base_format())?;
        }
    }

    workbook
        .save(output_path)
        .with_context(|| format!("Failed to save XLSX report to {}", output_path.display()))?;

    Ok(())
}

fn build_summary_data(session: &EngagementSession) -> Vec<(String, String)> {
    let counts = session.severity_counts();
    let total = session.findings.len();
    let critical = counts.get(&Severity::Critical).copied().unwrap_or(0);
    let high = counts.get(&Severity::High).copied().unwrap_or(0);
    let medium = counts.get(&Severity::Medium).copied().unwrap_or(0);
    let low = counts.get(&Severity::Low).copied().unwrap_or(0);
    let info = counts.get(&Severity::Informational).copied().unwrap_or(0);

    let mut data = Vec::new();
    data.push((
        "Overall Risk Score".into(),
        session.overall_risk().to_string(),
    ));
    data.push(("Total Findings".into(), total.to_string()));
    data.push(("  Critical".into(), critical.to_string()));
    data.push(("  High".into(), high.to_string()));
    data.push(("  Medium".into(), medium.to_string()));
    data.push(("  Low".into(), low.to_string()));
    data.push(("  Informational".into(), info.to_string()));
    data.push((
        "Assessment Date".into(),
        chrono::Utc::now().format("%Y-%m-%d").to_string(),
    ));
    data.push(("Client Name".into(), session.client_name.clone()));
    data.push((
        "Assessor".into(),
        format!("{} ({})", session.assessor_name, session.assessor_company),
    ));
    data.push(("Domain(s)".into(), session.scope.domains.join(", ")));
    data.push(("IP Range(s)".into(), session.scope.ip_ranges.join(", ")));
    data.push((
        "Domain Admin Achieved".into(),
        if session.domain_admin_achieved {
            "Yes".into()
        } else {
            "No".into()
        },
    ));
    data.push((
        "Users Enumerated".into(),
        session.total_users_enumerated.to_string(),
    ));
    data.push((
        "Computers Enumerated".into(),
        session.total_computers_enumerated.to_string(),
    ));
    data.push((
        "Credentials Compromised".into(),
        session.total_credentials_compromised.to_string(),
    ));
    data.push(("Admin Hosts".into(), session.total_admin_hosts.to_string()));
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::*;
    use chrono::Utc;

    fn mock_session() -> EngagementSession {
        let mut session = EngagementSession::new(
            "Test AD Assessment",
            "TestCorp",
            "TestOp",
            "Overthrone Labs",
        );
        session.engagement_type = EngagementType::AdAssessment;
        session.scope = EngagementScope {
            domains: vec!["test.local".to_string()],
            ip_ranges: vec!["10.0.0.0/24".to_string()],
            excluded_hosts: vec![],
            rules_of_engagement: vec!["Authorized testing".to_string()],
            objectives: vec!["Find path to DA".to_string()],
        };

        session.findings.push(Finding {
            id: "OT-TEST-001".to_string(),
            title: "Test Kerberoast Finding".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            cvss_vector: None,
            category: FindingCategory::KerberosAbuse,
            description: "Test description".to_string(),
            affected_assets: vec!["svc_sql@test.local".to_string()],
            proof_of_concept: vec!["Step 1".to_string()],
            evidence: vec![],
            mitre: crate::mapper::map_technique("kerberoast"),
            mitigations: crate::mitigations::get_mitigations("kerberoast"),
            business_impact: "Test impact".to_string(),
            references: vec![],
            discovered_at: Utc::now(),
        });

        session.findings.push(Finding {
            id: "OT-TEST-002".to_string(),
            title: "Test AS-REP Finding".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.1,
            cvss_vector: None,
            category: FindingCategory::KerberosAbuse,
            description: "AS-REP test".to_string(),
            affected_assets: vec!["user1@test.local".to_string()],
            proof_of_concept: vec![],
            evidence: vec![],
            mitre: crate::mapper::map_technique("asrep_roast"),
            mitigations: crate::mitigations::get_mitigations("asrep_roast"),
            business_impact: "High impact".to_string(),
            references: vec![],
            discovered_at: Utc::now(),
        });

        session.domain_admin_achieved = true;
        session.total_users_enumerated = 10;
        session.total_computers_enumerated = 5;
        session.total_credentials_compromised = 3;
        session.total_admin_hosts = 2;

        let mut state = overthrone_pilot::goals::EngagementState::default();
        state.domain = Some("test.local".to_string());
        state.users = vec![
            overthrone_pilot::goals::DiscoveredUser {
                sam_account_name: "jdoe".into(),
                distinguished_name: "CN=John Doe,CN=Users,DC=test,DC=local".into(),
                admin_count: false,
                has_spn: false,
                dont_req_preauth: false,
                enabled: true,
                description: Some("Regular user".into()),
                user_principal_name: Some("jdoe@test.local".into()),
                ..Default::default()
            },
            overthrone_pilot::goals::DiscoveredUser {
                sam_account_name: "svc_sql".into(),
                distinguished_name: "CN=svc_sql,CN=Users,DC=test,DC=local".into(),
                admin_count: true,
                has_spn: true,
                dont_req_preauth: false,
                enabled: true,
                description: Some("SQL service account".into()),
                user_principal_name: Some("svc_sql@test.local".into()),
                ..Default::default()
            },
            overthrone_pilot::goals::DiscoveredUser {
                sam_account_name: "asrep_user".into(),
                distinguished_name: "CN=asrep_user,CN=Users,DC=test,DC=local".into(),
                admin_count: false,
                has_spn: false,
                dont_req_preauth: true,
                enabled: true,
                description: None,
                user_principal_name: None,
                ..Default::default()
            },
        ];
        state.computers = vec![
            overthrone_pilot::goals::DiscoveredComputer {
                sam_account_name: "DC01$".into(),
                dns_hostname: Some("dc01.test.local".into()),
                operating_system: Some("Windows Server 2022".into()),
                unconstrained_delegation: false,
                is_dc: true,
            },
            overthrone_pilot::goals::DiscoveredComputer {
                sam_account_name: "SRV01$".into(),
                dns_hostname: Some("srv01.test.local".into()),
                operating_system: Some("Windows Server 2019".into()),
                unconstrained_delegation: true,
                is_dc: false,
            },
        ];
        let mut groups = std::collections::HashMap::new();
        groups.insert("Domain Admins".into(), vec!["jdoe".into()]);
        groups.insert("Domain Users".into(), vec!["jdoe".into(), "svc_sql".into()]);
        state.groups = groups;
        state.trusts = vec!["TEST.LOCAL\\child.test.local".into()];
        state.kerberoastable = vec!["svc_sql".into()];
        state.asrep_roastable = vec!["asrep_user".into()];
        let mut spn_map = std::collections::HashMap::new();
        spn_map.insert(
            "svc_sql".into(),
            vec!["MSSQLSvc/sql.test.local:1433".into()],
        );
        state.spn_map = spn_map;
        state.unconstrained_delegation = vec!["SRV01$".into()];
        state.constrained_delegation = vec![overthrone_pilot::goals::DelegationInfo {
            account: "SRV02$".into(),
            delegation_type: "Constrained".into(),
            targets: vec!["cifs/dc01.test.local".into()],
            protocol_transition: false,
        }];
        state.rbcd_targets = vec!["SRV03$".into()];
        state.laps = vec![overthrone_pilot::goals::LapsInfo {
            computer_name: "DC01$".into(),
            dns_name: Some("dc01.test.local".into()),
            username: "DC01$".into(),
            password: Some("TempPass123".into()),
            expiration: Some("2025-12-31".into()),
            source: "test.local".into(),
            readable: true,
        }];
        session.engagement_state = Some(state);
        session
    }

    fn tmp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ot_scribe_test_{}.xlsx",
            Utc::now().timestamp_subsec_nanos()
        ))
    }

    #[test]
    fn test_generate_xlsx_report_creates_file() {
        let session = mock_session();
        let p = tmp_path();
        generate_xlsx_report(&session, &p).unwrap();
        assert!(p.exists());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_generate_xlsx_report_empty_session() {
        let session = EngagementSession::new("Empty", "Client", "Op", "Co");
        let p = tmp_path();
        generate_xlsx_report(&session, &p).unwrap();
        assert!(p.exists());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_generate_xlsx_report_with_findings() {
        let session = mock_session();
        let p = tmp_path();
        generate_xlsx_report(&session, &p).unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        assert!(meta.len() > 3000, "file too small: {} bytes", meta.len());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_generate_xlsx_report_no_state() {
        let mut session = mock_session();
        session.engagement_state = None;
        let p = tmp_path();
        generate_xlsx_report(&session, &p).unwrap();
        assert!(p.exists());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_generate_xlsx_report_no_findings() {
        let mut session = mock_session();
        session.findings.clear();
        let p = tmp_path();
        generate_xlsx_report(&session, &p).unwrap();
        assert!(p.exists());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_build_summary_data_contains_risk() {
        let data = build_summary_data(&mock_session());
        assert!(data.iter().any(|(k, _)| k == "Overall Risk Score"));
        assert!(data.iter().any(|(k, _)| k == "Total Findings"));
        assert!(data.iter().any(|(k, _)| k == "Client Name"));
    }

    #[test]
    fn test_build_summary_data_counts() {
        let data = build_summary_data(&mock_session());
        let total = data
            .iter()
            .find(|(k, _)| k == "Total Findings")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(total, "2");
    }

    #[test]
    fn test_generate_xlsx_report_users_computers_present() {
        let session = mock_session();
        let p = tmp_path();
        generate_xlsx_report(&session, &p).unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        assert!(
            meta.len() > 4000,
            "file with users+computers should be > 4 KB, got {} bytes",
            meta.len()
        );
        let _ = std::fs::remove_file(&p);
    }
}
