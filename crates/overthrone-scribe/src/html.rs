//! HTML report renderer — produces a standalone HTML report with embedded CSS.
//! Suitable for in-browser review by SOC teams and management.

use crate::session::{EngagementSession, Severity};
use chrono::Utc;

/// Render an engagement session as a standalone HTML document
pub fn render(session: &EngagementSession) -> String {
    let mut html = String::with_capacity(32 * 1024);

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!(
        "<title>{} — Penetration Test Report</title>\n",
        escape_html(&session.title)
    ));
    html.push_str(STYLESHEET);
    html.push_str("</head>\n<body>\n");

    // ── Header ──
    html.push_str("<header>\n");
    html.push_str("<h1>Penetration Test Report</h1>\n");
    html.push_str(&format!(
        "<p class=\"subtitle\">{}</p>\n",
        escape_html(&session.title)
    ));
    html.push_str(&format!(
        "<p class=\"meta\">Classification: <strong>{}</strong> | Version: {}</p>\n",
        escape_html(&session.classification),
        escape_html(&session.version)
    ));
    html.push_str("</header>\n");

    // ── Executive Summary ──
    html.push_str("<section id=\"summary\">\n");
    html.push_str("<h2>Executive Summary</h2>\n");
    html.push_str("<table class=\"info-table\">\n");
    html.push_str(&format!(
        "<tr><td>Client</td><td>{}</td></tr>\n",
        escape_html(&session.client_name)
    ));
    html.push_str(&format!(
        "<tr><td>Assessor</td><td>{} ({})</td></tr>\n",
        escape_html(&session.assessor_name),
        escape_html(&session.assessor_company)
    ));
    html.push_str(&format!(
        "<tr><td>Engagement Type</td><td>{}</td></tr>\n",
        escape_html(&session.engagement_type.to_string())
    ));
    html.push_str(&format!(
        "<tr><td>Started</td><td>{}</td></tr>\n",
        session.started_at.format("%Y-%m-%d %H:%M UTC")
    ));
    if let Some(finished) = session.finished_at {
        html.push_str(&format!(
            "<tr><td>Finished</td><td>{}</td></tr>\n",
            finished.format("%Y-%m-%d %H:%M UTC")
        ));
    }
    html.push_str(&format!(
        "<tr><td>Overall Risk</td><td><span class=\"severity severity-{}\">{}</span></td></tr>\n",
        session.overall_risk().to_string().to_lowercase(),
        session.overall_risk()
    ));
    html.push_str(&format!(
        "<tr><td>Domain Admin Achieved</td><td>{}</td></tr>\n",
        if session.domain_admin_achieved {
            "<strong class=\"da-yes\">YES</strong>"
        } else {
            "No"
        }
    ));
    html.push_str("</table>\n");

    // ── Operator Attribution ──
    if let Some(ref op) = session.operator {
        html.push_str("<h3>Operator Attribution</h3>\n");
        html.push_str("<table class=\"info-table\">\n");
        html.push_str(&format!(
            "<tr><td>Operator</td><td>{}</td></tr>\n",
            escape_html(&op.operator_name)
        ));
        if let Some(ref team) = op.team {
            html.push_str(&format!(
                "<tr><td>Team</td><td>{}</td></tr>\n",
                escape_html(team)
            ));
        }
        if let Some(ref ip) = op.source_ip {
            html.push_str(&format!(
                "<tr><td>Source IP</td><td>{}</td></tr>\n",
                escape_html(ip)
            ));
        }
        if let Some(ref role) = op.role {
            html.push_str(&format!(
                "<tr><td>Role</td><td>{}</td></tr>\n",
                escape_html(role)
            ));
        }
        if let Some(ref email) = op.contact_email {
            html.push_str(&format!(
                "<tr><td>Contact</td><td>{}</td></tr>\n",
                escape_html(email)
            ));
        }
        if !op.certifications.is_empty() {
            html.push_str(&format!(
                "<tr><td>Certifications</td><td>{}</td></tr>\n",
                op.certifications
                    .iter()
                    .map(|c| escape_html(c))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        html.push_str("</table>\n");
    }
    html.push_str("</section>\n");

    // ── Stats ──
    html.push_str("<section id=\"stats\">\n");
    html.push_str("<h2>Key Metrics</h2>\n");
    html.push_str("<div class=\"stats-grid\">\n");
    html.push_str(&stat_card("Users Enumerated", session.total_users_enumerated));
    html.push_str(&stat_card("Computers Enumerated", session.total_computers_enumerated));
    html.push_str(&stat_card(
        "Credentials Compromised",
        session.total_credentials_compromised,
    ));
    html.push_str(&stat_card("Admin Hosts", session.total_admin_hosts));
    html.push_str(&stat_card("Total Findings", session.findings.len()));
    html.push_str("</div>\n");

    // Severity breakdown
    let counts = session.severity_counts();
    html.push_str("<h3>Findings by Severity</h3>\n");
    html.push_str("<div class=\"severity-grid\">\n");
    for sev in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Informational,
    ] {
        let count = counts.get(sev).copied().unwrap_or(0);
        html.push_str(&format!(
            "<div class=\"sev-card sev-{}\"><span class=\"count\">{}</span><span class=\"label\">{}</span></div>\n",
            sev.to_string().to_lowercase(),
            count,
            sev.label()
        ));
    }
    html.push_str("</div>\n");
    html.push_str("</section>\n");

    // ── Timeline ──
    let timeline = session.timeline_by_day();
    if !timeline.is_empty() {
        html.push_str("<section id=\"timeline\">\n");
        html.push_str("<h2>Timeline</h2>\n");
        html.push_str("<div class=\"timeline\">\n");
        for day in &timeline {
            html.push_str(&format!(
                "<div class=\"timeline-day\"><span class=\"date\">{}</span><span class=\"count\">{} finding{}</span></div>\n",
                escape_html(&day.date),
                day.count,
                if day.count == 1 { "" } else { "s" }
            ));
            for title in &day.findings {
                html.push_str(&format!(
                    "<div class=\"timeline-entry\">{}</div>\n",
                    escape_html(title)
                ));
            }
        }
        html.push_str("</div>\n");
        html.push_str("</section>\n");
    }

    // ── Scope ──
    html.push_str("<section id=\"scope\">\n");
    html.push_str("<h2>Scope</h2>\n");
    if !session.scope.domains.is_empty() {
        html.push_str("<h3>Domains</h3>\n<ul>\n");
        for d in &session.scope.domains {
            html.push_str(&format!("<li>{}</li>\n", escape_html(d)));
        }
        html.push_str("</ul>\n");
    }
    if !session.scope.ip_ranges.is_empty() {
        html.push_str("<h3>IP Ranges</h3>\n<ul>\n");
        for r in &session.scope.ip_ranges {
            html.push_str(&format!("<li>{}</li>\n", escape_html(r)));
        }
        html.push_str("</ul>\n");
    }
    if !session.scope.objectives.is_empty() {
        html.push_str("<h3>Objectives</h3>\n<ul>\n");
        for o in &session.scope.objectives {
            html.push_str(&format!("<li>{}</li>\n", escape_html(o)));
        }
        html.push_str("</ul>\n");
    }
    html.push_str("</section>\n");

    // ── Findings ──
    html.push_str("<section id=\"findings\">\n");
    html.push_str("<h2>Findings</h2>\n");
    if session.findings.is_empty() {
        html.push_str("<p class=\"no-findings\">No findings recorded.</p>\n");
    } else {
        for (i, finding) in session.findings.iter().enumerate() {
            html.push_str(&format!(
                "<article class=\"finding\" id=\"finding-{}\">\n",
                i
            ));
            html.push_str(&format!(
                "<h3><span class=\"finding-id\">{}</span> {}</h3>\n",
                escape_html(&finding.id),
                escape_html(&finding.title)
            ));
            html.push_str(&format!(
                "<div class=\"finding-meta\"><span class=\"severity severity-{}\">{}</span> \
                 <span class=\"cvss\">CVSS: {:.1}</span> \
                 <span class=\"category\">{}</span></div>\n",
                finding.severity.to_string().to_lowercase(),
                finding.severity.label(),
                finding.cvss_score,
                escape_html(&finding.category.to_string())
            ));

            // Description
            html.push_str(&format!(
                "<div class=\"description\"><h4>Description</h4><p>{}</p></div>\n",
                escape_html(&finding.description)
            ));

            // Affected assets
            if !finding.affected_assets.is_empty() {
                html.push_str("<div class=\"assets\"><h4>Affected Assets</h4><ul>\n");
                for a in &finding.affected_assets {
                    html.push_str(&format!("<li>{}</li>\n", escape_html(a)));
                }
                html.push_str("</ul></div>\n");
            }

            // Proof of concept
            if !finding.proof_of_concept.is_empty() {
                html.push_str("<div class=\"poc\"><h4>Proof of Concept</h4><ol>\n");
                for step in &finding.proof_of_concept {
                    html.push_str(&format!("<li>{}</li>\n", escape_html(step)));
                }
                html.push_str("</ol></div>\n");
            }

            // Evidence
            if !finding.evidence.is_empty() {
                html.push_str("<div class=\"evidence\"><h4>Evidence</h4>\n");
                for ev in &finding.evidence {
                    html.push_str(&format!(
                        "<div class=\"evidence-item\">\n<p class=\"ev-label\">{} <span class=\"ev-type\">({:?})</span></p>\n",
                        escape_html(&ev.label),
                        ev.content_type
                    ));
                    html.push_str(&format!(
                        "<pre class=\"ev-content\">{}</pre>\n",
                        escape_html(&ev.content)
                    ));
                    if let Some(ref hash) = ev.sha256_hash {
                        html.push_str(&format!(
                            "<p class=\"ev-hash\">SHA-256: <code>{}</code></p>\n",
                            escape_html(hash)
                        ));
                    }
                    html.push_str("</div>\n");
                }
                html.push_str("</div>\n");
            }

            // Business impact
            if !finding.business_impact.is_empty() {
                html.push_str(&format!(
                    "<div class=\"impact\"><h4>Business Impact</h4><p>{}</p></div>\n",
                    escape_html(&finding.business_impact)
                ));
            }

            // MITRE ATT&CK
            if !finding.mitre.is_empty() {
                html.push_str("<div class=\"mitre\"><h4>MITRE ATT&CK</h4><ul>\n");
                for m in &finding.mitre {
                    html.push_str(&format!(
                        "<li>{} — {}</li>\n",
                        escape_html(&m.technique_id),
                        escape_html(&m.technique_name)
                    ));
                }
                html.push_str("</ul></div>\n");
            }

            // Mitigations
            if !finding.mitigations.is_empty() {
                html.push_str("<div class=\"mitigations\"><h4>Recommendations</h4><ul>\n");
                for m in &finding.mitigations {
                    html.push_str(&format!(
                        "<li><strong>{}</strong>: {}</li>\n",
                        escape_html(&m.title),
                        escape_html(&m.description)
                    ));
                }
                html.push_str("</ul></div>\n");
            }

            // References
            if !finding.references.is_empty() {
                html.push_str("<div class=\"references\"><h4>References</h4><ul>\n");
                for r in &finding.references {
                    html.push_str(&format!(
                        "<li><a href=\"{}\" target=\"_blank\" rel=\"noopener\">{}</a></li>\n",
                        escape_html(r),
                        escape_html(r)
                    ));
                }
                html.push_str("</ul></div>\n");
            }

            html.push_str("</article>\n");
        }
    }
    html.push_str("</section>\n");

    // ── Footer ──
    html.push_str("<footer>\n");
    html.push_str(&format!(
        "<p>Generated by Overthrone Scribe on {}</p>\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
    html.push_str(&format!(
        "<p>Classification: {} | Session ID: {}</p>\n",
        escape_html(&session.classification),
        escape_html(&session.id)
    ));
    html.push_str("</footer>\n");

    html.push_str("</body>\n</html>\n");
    html
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn stat_card(label: &str, value: usize) -> String {
    format!(
        "<div class=\"stat-card\"><span class=\"value\">{}</span><span class=\"label\">{}</span></div>\n",
        value,
        escape_html(label)
    )
}

const STYLESHEET: &str = r#"<style>
:root {
    --critical: #8e44ad; --high: #e74c3c; --medium: #f39c12;
    --low: #2ecc71; --info: #3498db;
    --bg: #f8f9fa; --card: #fff; --text: #2c3e50; --border: #dee2e6;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       color: var(--text); background: var(--bg); line-height: 1.6; max-width: 1100px;
       margin: 0 auto; padding: 2rem; }
header { text-align: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 3px solid var(--text); }
h1 { font-size: 2rem; } h2 { font-size: 1.5rem; margin: 1.5rem 0 0.75rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
h3 { font-size: 1.1rem; margin: 1rem 0 0.5rem; } h4 { font-size: 0.95rem; margin: 0.75rem 0 0.25rem; color: #555; }
.subtitle { font-size: 1.2rem; color: #555; } .meta { font-size: 0.9rem; color: #777; }
section { margin-bottom: 2rem; }
.info-table { width: 100%; border-collapse: collapse; }
.info-table td { padding: 0.5rem 1rem; border-bottom: 1px solid var(--border); }
.info-table td:first-child { font-weight: 600; width: 200px; background: #f1f3f5; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1rem 0; }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
.stat-card .value { display: block; font-size: 2rem; font-weight: 700; color: var(--text); }
.stat-card .label { font-size: 0.85rem; color: #777; }
.severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.5rem; margin: 1rem 0; }
.sev-card { text-align: center; padding: 0.75rem; border-radius: 6px; color: #fff; }
.sev-card .count { display: block; font-size: 1.5rem; font-weight: 700; }
.sev-card .label { font-size: 0.75rem; text-transform: uppercase; }
.sev-critical { background: var(--critical); } .sev-high { background: var(--high); }
.sev-medium { background: var(--medium); } .sev-low { background: var(--low); }
.sev-informational { background: var(--info); }
.severity { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; color: #fff; font-size: 0.8rem; font-weight: 600; }
.severity-critical { background: var(--critical); } .severity-high { background: var(--high); }
.severity-medium { background: var(--medium); } .severity-low { background: var(--low); }
.severity-informational { background: var(--info); }
.da-yes { color: var(--critical); }
.timeline { border-left: 3px solid var(--border); padding-left: 1.5rem; margin: 1rem 0; }
.timeline-day { font-weight: 700; margin-top: 1rem; }
.timeline-day .date { margin-right: 0.5rem; }
.timeline-day .count { font-weight: 400; color: #777; font-size: 0.85rem; }
.timeline-entry { padding: 0.25rem 0; color: #555; }
.finding { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
.finding-id { color: #777; font-size: 0.85rem; font-weight: 400; }
.finding-meta { display: flex; gap: 0.75rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; }
.cvss { font-size: 0.85rem; color: #555; } .category { font-size: 0.85rem; color: #777; }
.evidence-item { background: #f8f9fa; border: 1px solid var(--border); border-radius: 4px; padding: 0.75rem; margin-bottom: 0.5rem; }
.ev-label { font-weight: 600; } .ev-type { font-weight: 400; color: #777; font-size: 0.85rem; }
.ev-content { background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: 4px; overflow-x: auto;
              font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85rem; white-space: pre-wrap; }
.ev-hash { font-size: 0.8rem; color: #777; } .ev-hash code { background: #e9ecef; padding: 0.1rem 0.3rem; border-radius: 2px; }
ul, ol { padding-left: 1.5rem; margin: 0.5rem 0; } li { margin: 0.25rem 0; }
.references a { color: var(--info); } .no-findings { color: #777; font-style: italic; }
footer { text-align: center; padding-top: 2rem; border-top: 1px solid var(--border); color: #777; font-size: 0.85rem; }
</style>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::*;

    fn minimal_session() -> EngagementSession {
        EngagementSession::new("Test Report", "TestClient", "Tester", "TestCo")
    }

    #[test]
    fn test_render_empty_session() {
        let session = minimal_session();
        let html = render(&session);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test Report"));
        assert!(html.contains("TestClient"));
        assert!(html.contains("No findings recorded"));
    }

    #[test]
    fn test_render_with_finding() {
        let mut session = minimal_session();
        session.findings.push(Finding {
            id: "OT-001".into(),
            title: "Test Finding".into(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
            category: FindingCategory::KerberosAbuse,
            description: "A critical finding".into(),
            affected_assets: vec!["dc01.corp.local".into()],
            proof_of_concept: vec!["Step 1".into(), "Step 2".into()],
            evidence: vec![EvidenceItem::new(
                "Test evidence",
                "some output",
                EvidenceType::CommandOutput,
            )],
            mitre: vec![],
            mitigations: vec![],
            business_impact: "High impact".into(),
            references: vec!["https://example.com".into()],
            discovered_at: chrono::Utc::now(),
        });
        let html = render(&session);
        assert!(html.contains("OT-001"));
        assert!(html.contains("Test Finding"));
        assert!(html.contains("severity-critical"));
        assert!(html.contains("dc01.corp.local"));
        assert!(html.contains("SHA-256:"));
    }

    #[test]
    fn test_render_with_operator() {
        let session = minimal_session().with_operator(OperatorMetadata {
            operator_name: "Alice".into(),
            team: Some("Red Team".into()),
            source_ip: Some("10.0.0.5".into()),
            role: Some("Lead Assessor".into()),
            contact_email: Some("alice@example.com".into()),
            certifications: vec!["OSCP".into(), "CRTP".into()],
        });
        let html = render(&session);
        assert!(html.contains("Alice"));
        assert!(html.contains("Red Team"));
        assert!(html.contains("10.0.0.5"));
        assert!(html.contains("OSCP"));
    }

    #[test]
    fn test_render_timeline() {
        let mut session = minimal_session();
        session.findings.push(Finding {
            id: "F1".into(),
            title: "Finding Day 1".into(),
            severity: Severity::High,
            cvss_score: 7.0,
            cvss_vector: None,
            category: FindingCategory::Other("Test".into()),
            description: "".into(),
            affected_assets: vec![],
            proof_of_concept: vec![],
            evidence: vec![],
            mitre: vec![],
            mitigations: vec![],
            business_impact: "".into(),
            references: vec![],
            discovered_at: chrono::Utc::now(),
        });
        let html = render(&session);
        assert!(html.contains("Timeline"));
        assert!(html.contains("Finding Day 1"));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }

    #[test]
    fn test_evidence_hash_in_html() {
        let ev = EvidenceItem::new("test", "hello world", EvidenceType::CommandOutput);
        assert!(ev.sha256_hash.is_some());
        assert!(ev.verify_integrity());
        let hash = ev.sha256_hash.as_ref().unwrap();
        // SHA-256 of "hello world" is well-known
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }
}
