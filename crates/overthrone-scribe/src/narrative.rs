//! Narrative generator — Produces human-readable prose for findings,
//! executive summaries, and attack chain descriptions.

use crate::session::{EngagementSession, Finding, Severity};

/// Generate an executive summary paragraph for the engagement
pub fn executive_summary(session: &EngagementSession) -> String {
    let counts = session.severity_counts();
    let critical = counts.get(&Severity::Critical).copied().unwrap_or(0);
    let high = counts.get(&Severity::High).copied().unwrap_or(0);
    let medium = counts.get(&Severity::Medium).copied().unwrap_or(0);
    let low = counts.get(&Severity::Low).copied().unwrap_or(0);
    let info = counts.get(&Severity::Informational).copied().unwrap_or(0);
    let total = session.findings.len();

    let risk = session.overall_risk();
    let domain = session
        .scope
        .domains
        .first()
        .cloned()
        .unwrap_or_else(|| "the target".to_string());

    let mut parts = Vec::new();

    parts.push(format!(
        "{} performed an {} for {} during the period {} to {}.",
        session.assessor_company,
        session.engagement_type,
        session.client_name,
        session.started_at.format("%B %d, %Y"),
        session
            .finished_at
            .map(|d| d.format("%B %d, %Y").to_string())
            .unwrap_or_else(|| "present".to_string())
    ));

    parts.push(format!(
        "The assessment targeted the **{}** Active Directory domain. \
         A total of **{} finding(s)** were identified: \
         {} Critical, {} High, {} Medium, {} Low, and {} Informational.",
        domain, total, critical, high, medium, low, info
    ));

    parts.push(format!(
        "The overall risk rating for the environment is **{}**.",
        risk
    ));

    if session.domain_admin_achieved {
        parts.push(format!(
            "**Domain Admin privileges were achieved during the assessment**, \
             demonstrating that a motivated attacker with low-privilege access \
             could fully compromise the {} domain. Immediate remediation \
             of critical findings is strongly recommended.",
            domain
        ));
    } else {
        parts.push(
            "Domain Admin was not achieved during the assessment window; however, \
             the identified findings still represent significant risk if left unaddressed."
                .to_string(),
        );
    }

    if session.total_credentials_compromised > 0 {
        parts.push(format!(
            "A total of **{} credential(s)** were compromised through various \
             attack techniques, and administrative access was obtained on **{} host(s)**.",
            session.total_credentials_compromised, session.total_admin_hosts
        ));
    }

    parts.join("\n\n")
}

/// Generate scope description
pub fn scope_description(session: &EngagementSession) -> String {
    let scope = &session.scope;
    let mut parts = Vec::new();

    if !scope.domains.is_empty() {
        parts.push(format!(
            "**Target Domains:** {}",
            scope.domains.join(", ")
        ));
    }
    if !scope.ip_ranges.is_empty() {
        parts.push(format!(
            "**IP Ranges:** {}",
            scope.ip_ranges.join(", ")
        ));
    }
    if !scope.excluded_hosts.is_empty() {
        parts.push(format!(
            "**Excluded Hosts:** {}",
            scope.excluded_hosts.join(", ")
        ));
    }
    if !scope.objectives.is_empty() {
        parts.push("**Objectives:**".to_string());
        for obj in &scope.objectives {
            parts.push(format!("- {}", obj));
        }
    }
    if !scope.rules_of_engagement.is_empty() {
        parts.push("\n**Rules of Engagement:**".to_string());
        for rule in &scope.rules_of_engagement {
            parts.push(format!("- {}", rule));
        }
    }

    parts.join("\n")
}

/// Generate a narrative for a single finding
pub fn finding_narrative(finding: &Finding) -> String {
    let mut parts = Vec::new();

    parts.push(finding.description.clone());

    if !finding.affected_assets.is_empty() {
        let asset_count = finding.affected_assets.len();
        if asset_count <= 5 {
            parts.push(format!(
                "The following asset(s) are affected: {}.",
                finding.affected_assets.join(", ")
            ));
        } else {
            parts.push(format!(
                "{} asset(s) are affected, including: {} (and {} more).",
                asset_count,
                finding.affected_assets[..3].join(", "),
                asset_count - 3
            ));
        }
    }

    if !finding.business_impact.is_empty() {
        parts.push(format!(
            "**Business Impact:** {}",
            finding.business_impact
        ));
    }

    parts.join("\n\n")
}

/// Generate a high-level attack chain narrative from the action log
pub fn attack_chain_narrative(session: &EngagementSession) -> String {
    let state = match &session.engagement_state {
        Some(s) => s,
        None => return "No attack chain data available.".to_string(),
    };

    if state.action_log.is_empty() {
        return "No actions were logged during the engagement.".to_string();
    }

    let mut parts = Vec::new();
    parts.push("The following attack chain was executed during the automated assessment:\n".to_string());

    let mut current_stage = String::new();
    let mut step_num = 1;

    for entry in &state.action_log {
        if entry.stage != current_stage {
            current_stage = entry.stage.clone();
            parts.push(format!("\n**Phase: {}**\n", current_stage));
        }

        let status = if entry.success { "✓" } else { "✗" };
        let detail_short = if entry.detail.len() > 100 {
            format!("{}…", &entry.detail[..97])
        } else {
            entry.detail.clone()
        };

        parts.push(format!(
            "{}. [{}] {} — {} — {}",
            step_num,
            entry.timestamp.format("%H:%M:%S"),
            status,
            entry.action,
            detail_short
        ));
        step_num += 1;
    }

    let succeeded = state.action_log.iter().filter(|a| a.success).count();
    let failed = state.action_log.len() - succeeded;
    parts.push(format!(
        "\n**Summary:** {} total actions, {} succeeded, {} failed.",
        state.action_log.len(),
        succeeded,
        failed
    ));

    parts.join("\n")
}

/// Generate methodology description
pub fn methodology_description() -> String {
    r#"The assessment followed a structured methodology consisting of the following phases:

1. **Reconnaissance & Enumeration** — LDAP queries were used to enumerate domain users, computers, groups, Group Policy Objects, trust relationships, and service accounts. No exploitation was performed during this phase.

2. **Kerberos Attacks** — Kerberoasting and AS-REP Roasting were used to extract password hashes for offline cracking. Delegation configurations (constrained, unconstrained, RBCD) were identified and evaluated.

3. **Credential Attacks** — Obtained hashes were cracked using offline techniques. Password spraying was performed where authorized, adhering to lockout thresholds.

4. **Lateral Movement** — Compromised credentials were used to move laterally through the environment using SMB, WMI, and WinRM. Admin access was verified on discovered hosts.

5. **Privilege Escalation** — Attack paths to Domain Admin were identified and exploited through delegation abuse, credential reuse, and local privilege escalation.

6. **Credential Dumping** — On compromised hosts, SAM databases, LSA secrets, and (where applicable) NTDS.dit were extracted to identify additional credentials.

All activities were performed using the **Overthrone** framework, a Rust-based Active Directory assessment toolkit."#.to_string()
}
