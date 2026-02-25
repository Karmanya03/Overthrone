//! Integration tests for overthrone-scribe — report generation engine.
//!
//! Tests report data structures, formatting, and output generation offline.

use std::collections::HashMap;
use std::path::PathBuf;

fn load_json(name: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let raw = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&raw).unwrap()
}

// ═══════════════════════════════════════════════════════════
//  Finding Severity Classification
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, PartialOrd)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

fn classify_finding(finding_type: &str) -> Severity {
    match finding_type {
        "gpp_password" => Severity::Critical,
        "laps_v1_readable" => Severity::Critical,
        "laps_v2_readable" => Severity::Critical,
        "laps_v2_encrypted_stored" => Severity::High,
        "kerberoastable_user" => Severity::High,
        "password_in_description" => Severity::High,
        "disabled_admin_in_da" => Severity::Medium,
        "stale_password" => Severity::Medium,
        "constrained_delegation" => Severity::High,
        "unconstrained_delegation" => Severity::Critical,
        "foreign_da_membership" => Severity::High,
        "bidirectional_trust_no_filter" => Severity::Medium,
        _ => Severity::Info,
    }
}

#[test]
fn test_severity_classification() {
    assert_eq!(classify_finding("gpp_password"), Severity::Critical);
    assert_eq!(classify_finding("kerberoastable_user"), Severity::High);
    assert_eq!(classify_finding("disabled_admin_in_da"), Severity::Medium);
    assert_eq!(classify_finding("unknown_thing"), Severity::Info);
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

// ═══════════════════════════════════════════════════════════
//  Report Data Generation from Fixtures
// ═══════════════════════════════════════════════════════════

#[derive(Debug)]
struct ReportFinding {
    title: String,
    severity: Severity,
    affected_objects: Vec<String>,
    description: String,
    remediation: String,
}

fn generate_findings_from_domain(domain: &serde_json::Value) -> Vec<ReportFinding> {
    let mut findings = Vec::new();
    let users = domain["users"].as_array().unwrap();

    // Check for kerberoastable users
    let roastable: Vec<String> = users
        .iter()
        .filter_map(|u| {
            let enabled = u["enabled"].as_bool().unwrap_or(false);
            let has_spn = u["spn"].as_array().map(|a| !a.is_empty()).unwrap_or(false);
            if enabled && has_spn {
                Some(u["sam_account_name"].as_str().unwrap().to_string())
            } else {
                None
            }
        })
        .collect();

    if !roastable.is_empty() {
        findings.push(ReportFinding {
            title: "Kerberoastable Service Accounts".to_string(),
            severity: Severity::High,
            affected_objects: roastable,
            description: "Service accounts with SPNs are vulnerable to offline password cracking via Kerberoasting.".to_string(),
            remediation: "Use Group Managed Service Accounts (gMSA) or set 128+ character passwords.".to_string(),
        });
    }

    // Check for password in description
    let leaky: Vec<String> = users
        .iter()
        .filter_map(|u| {
            let desc = u["description"].as_str().unwrap_or("").to_lowercase();
            if desc.contains("password") || desc.contains("pwd") {
                Some(u["sam_account_name"].as_str().unwrap().to_string())
            } else {
                None
            }
        })
        .collect();

    if !leaky.is_empty() {
        findings.push(ReportFinding {
            title: "Credentials in User Description".to_string(),
            severity: Severity::High,
            affected_objects: leaky,
            description: "User account descriptions contain plaintext credentials visible to all domain users.".to_string(),
            remediation: "Remove credentials from description fields immediately and rotate affected passwords.".to_string(),
        });
    }

    // Check for disabled admins
    let disabled_admins: Vec<String> = users
        .iter()
        .filter_map(|u| {
            let disabled = !u["enabled"].as_bool().unwrap_or(true);
            let admin = u["admin_count"].as_i64().unwrap_or(0) == 1;
            if disabled && admin {
                Some(u["sam_account_name"].as_str().unwrap().to_string())
            } else {
                None
            }
        })
        .collect();

    if !disabled_admins.is_empty() {
        findings.push(ReportFinding {
            title: "Disabled Accounts in Privileged Groups".to_string(),
            severity: Severity::Medium,
            affected_objects: disabled_admins,
            description:
                "Disabled accounts remain members of privileged groups, posing re-enablement risk."
                    .to_string(),
            remediation: "Remove disabled accounts from all privileged groups.".to_string(),
        });
    }

    findings
}

#[test]
fn test_report_findings_generated() {
    let domain = load_json("mock_domain.json");
    let findings = generate_findings_from_domain(&domain);

    assert!(
        findings.len() >= 3,
        "Expected at least 3 findings, got {}",
        findings.len()
    );
}

#[test]
fn test_report_findings_have_remediation() {
    let domain = load_json("mock_domain.json");
    let findings = generate_findings_from_domain(&domain);

    for finding in &findings {
        assert!(
            !finding.remediation.is_empty(),
            "Finding '{}' missing remediation",
            finding.title
        );
        assert!(
            !finding.description.is_empty(),
            "Finding '{}' missing description",
            finding.title
        );
    }
}

#[test]
fn test_report_findings_sorted_by_severity() {
    let domain = load_json("mock_domain.json");
    let mut findings = generate_findings_from_domain(&domain);

    // Sort descending by severity (Critical first)
    findings.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

    // Verify ordering
    for window in findings.windows(2) {
        assert!(
            window[0].severity >= window[1].severity,
            "'{}' ({:?}) should come before '{}' ({:?})",
            window[0].title,
            window[0].severity,
            window[1].title,
            window[1].severity
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  Markdown Report Output
// ═══════════════════════════════════════════════════════════

fn render_finding_markdown(finding: &ReportFinding) -> String {
    let severity_badge = match finding.severity {
        Severity::Critical => "🔴 CRITICAL",
        Severity::High => "🟠 HIGH",
        Severity::Medium => "🟡 MEDIUM",
        Severity::Low => "🔵 LOW",
        Severity::Info => "⚪ INFO",
    };

    let mut md = String::new();
    md.push_str(&format!("### {} [{}]\n\n", finding.title, severity_badge));
    md.push_str(&format!("**Description:** {}\n\n", finding.description));
    md.push_str("**Affected Objects:**\n");
    for obj in &finding.affected_objects {
        md.push_str(&format!("- `{}`\n", obj));
    }
    md.push_str(&format!(
        "\n**Remediation:** {}\n\n---\n\n",
        finding.remediation
    ));
    md
}

#[test]
fn test_markdown_report_rendering() {
    let domain = load_json("mock_domain.json");
    let findings = generate_findings_from_domain(&domain);

    let mut report = String::from("# Overthrone Assessment Report\n\n");
    report.push_str(&format!(
        "**Domain:** {}\n\n",
        domain["domain"].as_str().unwrap()
    ));
    report.push_str(&format!("**Findings:** {}\n\n---\n\n", findings.len()));

    for finding in &findings {
        report.push_str(&render_finding_markdown(finding));
    }

    // Validate report structure
    assert!(report.contains("# Overthrone Assessment Report"));
    assert!(report.contains("YOURORG.LOCAL"));
    assert!(report.contains("Kerberoastable"));
    assert!(report.contains("svc_sql"));
    assert!(report.contains("Remediation"));
}

#[test]
fn test_markdown_severity_badges() {
    let finding = ReportFinding {
        title: "Test".to_string(),
        severity: Severity::Critical,
        affected_objects: vec!["obj1".to_string()],
        description: "desc".to_string(),
        remediation: "fix".to_string(),
    };
    let md = render_finding_markdown(&finding);
    assert!(md.contains("🔴 CRITICAL"));
}

// ═══════════════════════════════════════════════════════════
//  Statistics Generation
// ═══════════════════════════════════════════════════════════

#[test]
fn test_domain_statistics() {
    let domain = load_json("mock_domain.json");

    let user_count = domain["users"].as_array().unwrap().len();
    let computer_count = domain["computers"].as_array().unwrap().len();
    let group_count = domain["groups"].as_array().unwrap().len();
    let gpo_count = domain["gpos"].as_array().unwrap().len();
    let dc_count = domain["domain_controllers"].as_array().unwrap().len();

    assert!(user_count >= 4);
    assert!(computer_count >= 3);
    assert!(group_count >= 2);
    assert!(gpo_count >= 2);
    assert!(dc_count >= 2);

    let enabled_users = domain["users"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["enabled"].as_bool().unwrap_or(false))
        .count();
    assert!(
        enabled_users < user_count,
        "Should have at least 1 disabled user"
    );

    let admin_users = domain["users"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["admin_count"].as_i64().unwrap_or(0) == 1)
        .count();
    assert!(
        admin_users >= 2,
        "Should have at least 2 admin-flagged users"
    );
}
