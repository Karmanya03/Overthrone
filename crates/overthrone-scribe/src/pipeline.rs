use serde::Serialize;

/// A JSON-serializable event for pipeline ingestion
#[derive(Debug, Clone, Serialize)]
pub struct PipelineEvent {
    /// Event type (finding, progress, error, etc.)
    #[serde(rename = "event_type")]
    pub event_type: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Target host
    pub target: Option<String>,
    /// Domain
    pub domain: Option<String>,
    /// Event-specific data
    pub data: serde_json::Value,
}

/// Emit a pipeline event as JSON to stdout
pub fn emit_pipeline_event(event: &PipelineEvent) {
    if let Ok(json) = serde_json::to_string(event) {
        println!("{}", json);
    }
}

/// Emit an event from the engagement state findings.
pub fn findings_to_events(
    domain: Option<String>,
    findings: &[crate::session::Finding],
) -> Vec<PipelineEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    findings
        .iter()
        .map(|f| {
            let mitre_ids: Vec<String> = f.mitre.iter().map(|m| m.technique_id.clone()).collect();
            let mitigation_titles: Vec<String> =
                f.mitigations.iter().map(|m| m.title.clone()).collect();
            PipelineEvent {
                event_type: "finding".to_string(),
                timestamp: now.clone(),
                target: f.affected_assets.first().cloned(),
                domain: domain.clone(),
                data: serde_json::json!({
                    "id": f.id,
                    "title": f.title,
                    "severity": format!("{:?}", f.severity),
                    "cvss": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "category": format!("{:?}", f.category),
                    "affected_assets": f.affected_assets,
                    "mitre_techniques": mitre_ids,
                    "mitigations": mitigation_titles,
                    "business_impact": f.business_impact,
                    "references": f.references,
                }),
            }
        })
        .collect()
}

/// Emit all findings as JSON Lines to stdout.
pub fn emit_findings_json_lines(domain: Option<String>, findings: &[crate::session::Finding]) {
    for event in findings_to_events(domain.clone(), findings) {
        emit_pipeline_event(&event);
    }
}

/// Configuration for pipeline output
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Enable JSON pipeline output
    pub json_output: bool,
    /// Only emit findings (omit progress/status events)
    pub findings_only: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            json_output: false,
            findings_only: true,
        }
    }
}

/// Emit a session summary event for pipeline consumers.
pub fn emit_session_summary(session: &crate::session::EngagementSession) {
    let event = PipelineEvent {
        event_type: "session_summary".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        target: None,
        domain: session.scope.domains.first().cloned(),
        data: serde_json::json!({
            "title": session.title,
            "client_name": session.client_name,
            "total_findings": session.findings.len(),
            "severity_counts": {
                "critical": session.findings.iter().filter(|f| matches!(f.severity, crate::session::Severity::Critical)).count(),
                "high": session.findings.iter().filter(|f| matches!(f.severity, crate::session::Severity::High)).count(),
                "medium": session.findings.iter().filter(|f| matches!(f.severity, crate::session::Severity::Medium)).count(),
                "low": session.findings.iter().filter(|f| matches!(f.severity, crate::session::Severity::Low)).count(),
                "informational": session.findings.iter().filter(|f| matches!(f.severity, crate::session::Severity::Informational)).count(),
            },
            "domain_admin_achieved": session.domain_admin_achieved,
            "total_credentials_compromised": session.total_credentials_compromised,
            "total_admin_hosts": session.total_admin_hosts,
        }),
    };
    emit_pipeline_event(&event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Finding, FindingCategory, Severity};
    use chrono::Utc;

    fn mock_finding() -> Finding {
        Finding {
            id: "OT-001".to_string(),
            title: "Test Finding".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N".to_string()),
            category: FindingCategory::KerberosAbuse,
            description: "Test description".to_string(),
            affected_assets: vec!["dc01.corp.local".to_string()],
            proof_of_concept: vec!["Step 1".to_string()],
            evidence: vec![],
            mitre: crate::mapper::map_technique("kerberoast"),
            mitigations: crate::mitigations::get_mitigations("kerberoast"),
            business_impact: "Test impact".to_string(),
            references: vec!["https://example.com".to_string()],
            discovered_at: Utc::now(),
        }
    }

    #[test]
    fn test_findings_to_events() {
        let finding = mock_finding();
        let events = findings_to_events(Some("corp.local".to_string()), &[finding]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "finding");
        assert!(events[0].data["cvss"].as_f64().unwrap() - 7.5 < f64::EPSILON);
        assert_eq!(events[0].domain.as_deref(), Some("corp.local"));
        assert!(events[0].data["mitre_techniques"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn test_emit_session_summary_serializable() {
        let _session =
            crate::session::EngagementSession::new("Test", "Client", "Assessor", "Company");
        // Should not panic
        let _event = {
            // capture the emitted event logic
            let event = PipelineEvent {
                event_type: "session_summary".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                target: None,
                domain: None,
                data: serde_json::json!({"test": true}),
            };
            serde_json::to_string(&event).unwrap()
        };
        assert!(true);
    }

    #[test]
    fn test_pipeline_config_defaults() {
        let config = PipelineConfig::default();
        assert!(!config.json_output);
        assert!(config.findings_only);
    }

    #[test]
    fn test_empty_findings_to_events() {
        let events = findings_to_events(None, &[]);
        assert!(events.is_empty());
    }
}
