//! Engagement session — Holds all metadata, scope, findings, and raw
//! data needed to produce a report. Acts as the single input struct
//! that the report renderers consume.

use crate::mapper::MitreMapping;
use crate::mitigations::Mitigation;
use chrono::{DateTime, Utc};
use overthrone_pilot::goals::EngagementState;
use overthrone_pilot::runner::AutoPwnResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════
// Severity
// ═══════════════════════════════════════════════════════════

/// Finding severity aligned with CVSS v3.1 qualitative ratings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// CVSS score range lower bound
    pub fn cvss_min(&self) -> f32 {
        match self {
            Self::Informational => 0.0,
            Self::Low => 0.1,
            Self::Medium => 4.0,
            Self::High => 7.0,
            Self::Critical => 9.0,
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Informational => "#3498db",
            Self::Low => "#2ecc71",
            Self::Medium => "#f39c12",
            Self::High => "#e74c3c",
            Self::Critical => "#8e44ad",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Informational => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ═══════════════════════════════════════════════════════════
// Finding
// ═══════════════════════════════════════════════════════════

/// A single security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique ID
    pub id: String,
    /// Short title
    pub title: String,
    /// Severity
    pub severity: Severity,
    /// CVSS v3.1 score (0.0–10.0)
    pub cvss_score: f32,
    /// CVSS vector string
    pub cvss_vector: Option<String>,
    /// Finding category
    pub category: FindingCategory,
    /// Detailed description of what was found
    pub description: String,
    /// Affected assets (hostnames, users, services)
    pub affected_assets: Vec<String>,
    /// Step-by-step proof of exploitation
    pub proof_of_concept: Vec<String>,
    /// Raw evidence (command output, hashes, etc.)
    pub evidence: Vec<EvidenceItem>,
    /// MITRE ATT&CK mapping
    pub mitre: Vec<MitreMapping>,
    /// Recommended mitigations
    pub mitigations: Vec<Mitigation>,
    /// Business impact description
    pub business_impact: String,
    /// References (URLs, CVEs)
    pub references: Vec<String>,
    /// When this finding was discovered
    pub discovered_at: DateTime<Utc>,
}

/// Finding categories
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    WeakAuthentication,
    KerberosAbuse,
    PrivilegeEscalation,
    LateralMovement,
    CredentialExposure,
    Misconfiguration,
    InsufficientLogging,
    DelegationAbuse,
    WeakEncryption,
    DefaultCredentials,
    PasswordPolicy,
    Other(String),
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakAuthentication => write!(f, "Weak Authentication"),
            Self::KerberosAbuse => write!(f, "Kerberos Abuse"),
            Self::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            Self::LateralMovement => write!(f, "Lateral Movement"),
            Self::CredentialExposure => write!(f, "Credential Exposure"),
            Self::Misconfiguration => write!(f, "Misconfiguration"),
            Self::InsufficientLogging => write!(f, "Insufficient Logging"),
            Self::DelegationAbuse => write!(f, "Delegation Abuse"),
            Self::WeakEncryption => write!(f, "Weak Encryption"),
            Self::DefaultCredentials => write!(f, "Default Credentials"),
            Self::PasswordPolicy => write!(f, "Password Policy"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Evidence item attached to a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub label: String,
    pub content: String,
    pub content_type: EvidenceType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    CommandOutput,
    Hash,
    Credential,
    LogEntry,
    Screenshot,
    Configuration,
    NetworkCapture,
}

// ═══════════════════════════════════════════════════════════
// Engagement Session
// ═══════════════════════════════════════════════════════════

/// Complete engagement session — the single source of truth for report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementSession {
    // ── Metadata ──
    pub id: String,
    pub title: String,
    pub client_name: String,
    pub assessor_name: String,
    pub assessor_company: String,
    pub engagement_type: EngagementType,
    pub classification: String,
    pub version: String,

    // ── Timeline ──
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,

    // ── Scope ──
    pub scope: EngagementScope,

    // ── Findings ──
    pub findings: Vec<Finding>,

    // ── Raw data from pilot ──
    pub engagement_state: Option<EngagementState>,
    pub autopwn_result: Option<AutoPwnResult>,

    // ── Summary stats ──
    pub domain_admin_achieved: bool,
    pub total_users_enumerated: usize,
    pub total_computers_enumerated: usize,
    pub total_credentials_compromised: usize,
    pub total_admin_hosts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngagementType {
    InternalPentest,
    ExternalPentest,
    RedTeam,
    PurpleTeam,
    AdAssessment,
    Custom(String),
}

impl std::fmt::Display for EngagementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalPentest => write!(f, "Internal Penetration Test"),
            Self::ExternalPentest => write!(f, "External Penetration Test"),
            Self::RedTeam => write!(f, "Red Team Assessment"),
            Self::PurpleTeam => write!(f, "Purple Team Exercise"),
            Self::AdAssessment => write!(f, "Active Directory Security Assessment"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementScope {
    pub domains: Vec<String>,
    pub ip_ranges: Vec<String>,
    pub excluded_hosts: Vec<String>,
    pub rules_of_engagement: Vec<String>,
    pub objectives: Vec<String>,
}

impl EngagementSession {
    /// Create a new session from an AutoPwnResult
    pub fn from_autopwn(
        result: &AutoPwnResult,
        client_name: &str,
        assessor_name: &str,
        assessor_company: &str,
    ) -> Self {
        let state = &result.state;
        let domain = state
            .domain
            .clone()
            .unwrap_or_else(|| "UNKNOWN".to_string());

        let mut session = Self {
            id: Uuid::new_v4().to_string(),
            title: format!("Active Directory Assessment — {}", domain),
            client_name: client_name.to_string(),
            assessor_name: assessor_name.to_string(),
            assessor_company: assessor_company.to_string(),
            engagement_type: EngagementType::AdAssessment,
            classification: "CONFIDENTIAL".to_string(),
            version: "1.0".to_string(),

            started_at: result.started_at,
            finished_at: Some(result.finished_at),

            scope: EngagementScope {
                domains: vec![domain.clone()],
                ip_ranges: state.dc_ip.iter().cloned().collect(),
                excluded_hosts: vec![],
                rules_of_engagement: vec![
                    "Testing authorized during maintenance window".to_string(),
                    "No denial-of-service attacks".to_string(),
                    "Credential dumping permitted on compromised hosts".to_string(),
                ],
                objectives: vec![
                    "Assess Active Directory security posture".to_string(),
                    "Identify attack paths to Domain Admin".to_string(),
                    "Evaluate detection and response capabilities".to_string(),
                ],
            },

            findings: Vec::new(),
            engagement_state: Some(state.clone()),
            autopwn_result: Some(result.clone()),

            domain_admin_achieved: result.domain_admin_achieved,
            total_users_enumerated: state.users.len(),
            total_computers_enumerated: state.computers.len(),
            total_credentials_compromised: state.credentials.len(),
            total_admin_hosts: state.admin_hosts.len(),
        };

        // Auto-generate findings from state
        session.auto_generate_findings();
        session
    }

    /// Create an empty session for manual report building
    pub fn new(
        title: &str,
        client_name: &str,
        assessor_name: &str,
        assessor_company: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title: title.to_string(),
            client_name: client_name.to_string(),
            assessor_name: assessor_name.to_string(),
            assessor_company: assessor_company.to_string(),
            engagement_type: EngagementType::AdAssessment,
            classification: "CONFIDENTIAL".to_string(),
            version: "1.0".to_string(),

            started_at: Utc::now(),
            finished_at: None,

            scope: EngagementScope {
                domains: vec![],
                ip_ranges: vec![],
                excluded_hosts: vec![],
                rules_of_engagement: vec![],
                objectives: vec![],
            },

            findings: Vec::new(),
            engagement_state: None,
            autopwn_result: None,

            domain_admin_achieved: false,
            total_users_enumerated: 0,
            total_computers_enumerated: 0,
            total_credentials_compromised: 0,
            total_admin_hosts: 0,
        }
    }

    /// Auto-generate findings from engagement state
    fn auto_generate_findings(&mut self) {
        let state = match &self.engagement_state {
            Some(s) => s.clone(),
            None => return,
        };
        let domain = state.domain.clone().unwrap_or_default();

        // ── Kerberoastable accounts ──
        if !state.kerberoastable.is_empty() {
            self.findings.push(Finding {
                id: format!("OT-{}-001", self.id.split('-').next().unwrap_or("F")),
                title: "Kerberoastable Service Accounts Detected".to_string(),
                severity: Severity::High,
                cvss_score: 7.5,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N".to_string()),
                category: FindingCategory::KerberosAbuse,
                description: format!(
                    "{} user account(s) with Service Principal Names (SPNs) were identified. \
                     These accounts are vulnerable to Kerberoasting — an attacker with any \
                     valid domain credential can request TGS tickets and crack them offline \
                     to recover plaintext passwords.",
                    state.kerberoastable.len()
                ),
                affected_assets: state.kerberoastable.clone(),
                proof_of_concept: vec![
                    "Authenticated to the domain with low-privilege credentials".to_string(),
                    "Requested TGS tickets for all SPN-enabled accounts".to_string(),
                    "Extracted encrypted ticket data in hashcat-compatible format".to_string(),
                    "Cracked service account passwords offline using hashcat".to_string(),
                ],
                evidence: vec![EvidenceItem {
                    label: "Kerberoastable accounts".to_string(),
                    content: state.kerberoastable.join("\n"),
                    content_type: EvidenceType::CommandOutput,
                }],
                mitre: crate::mapper::map_technique("kerberoast"),
                mitigations: crate::mitigations::get_mitigations("kerberoast"),
                business_impact: "Compromised service accounts often have elevated privileges \
                    and access to critical business systems. Kerberoasting requires only \
                    low-privilege access and is difficult to detect."
                    .to_string(),
                references: vec![
                    "https://attack.mitre.org/techniques/T1558/003/".to_string(),
                    "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting".to_string(),
                ],
                discovered_at: Utc::now(),
            });
        }

        // ── AS-REP Roastable accounts ──
        if !state.asrep_roastable.is_empty() {
            self.findings.push(Finding {
                id: format!("OT-{}-002", self.id.split('-').next().unwrap_or("F")),
                title: "AS-REP Roastable Accounts (No Pre-Authentication)".to_string(),
                severity: Severity::High,
                cvss_score: 7.5,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                category: FindingCategory::KerberosAbuse,
                description: format!(
                    "{} account(s) have Kerberos pre-authentication disabled \
                     (DONT_REQ_PREAUTH). An attacker can request an AS-REP for these \
                     accounts without any credentials and crack the encrypted \
                     portion offline.",
                    state.asrep_roastable.len()
                ),
                affected_assets: state.asrep_roastable.clone(),
                proof_of_concept: vec![
                    "Identified accounts with DONT_REQ_PREAUTH flag via LDAP".to_string(),
                    "Sent AS-REQ without pre-authentication data".to_string(),
                    "Captured AS-REP with encrypted timestamp (hashcat mode 18200)".to_string(),
                ],
                evidence: vec![EvidenceItem {
                    label: "AS-REP roastable accounts".to_string(),
                    content: state.asrep_roastable.join("\n"),
                    content_type: EvidenceType::CommandOutput,
                }],
                mitre: crate::mapper::map_technique("asrep_roast"),
                mitigations: crate::mitigations::get_mitigations("asrep_roast"),
                business_impact: "These accounts can be attacked without any authentication, \
                    representing a zero-credential attack path."
                    .to_string(),
                references: vec!["https://attack.mitre.org/techniques/T1558/004/".to_string()],
                discovered_at: Utc::now(),
            });
        }

        // ── Compromised credentials ──
        if !state.credentials.is_empty() {
            let admin_creds: Vec<_> = state
                .credentials
                .values()
                .filter(|c| c.is_admin)
                .map(|c| c.username.clone())
                .collect();
            let normal_creds: Vec<_> = state
                .credentials
                .values()
                .filter(|c| !c.is_admin)
                .map(|c| c.username.clone())
                .collect();

            self.findings.push(Finding {
                id: format!("OT-{}-003", self.id.split('-').next().unwrap_or("F")),
                title: "Compromised Domain Credentials".to_string(),
                severity: if !admin_creds.is_empty() {
                    Severity::Critical
                } else {
                    Severity::High
                },
                cvss_score: if !admin_creds.is_empty() { 9.8 } else { 7.5 },
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H".to_string()),
                category: FindingCategory::CredentialExposure,
                description: format!(
                    "{} credential(s) were compromised during the assessment \
                     ({} with administrative privileges). These were obtained through \
                     Kerberos attacks, credential dumping, or password spraying.",
                    state.credentials.len(),
                    admin_creds.len()
                ),
                affected_assets: admin_creds
                    .iter()
                    .chain(normal_creds.iter())
                    .cloned()
                    .collect(),
                proof_of_concept: vec![
                    "Obtained credentials through various attack techniques".to_string(),
                    "Verified credential validity via authentication".to_string(),
                ],
                evidence: state
                    .credentials
                    .values()
                    .map(|c| EvidenceItem {
                        label: format!("{} ({})", c.username, c.source),
                        content: format!(
                            "User: {}\\{}, Type: {:?}, Admin: {}",
                            domain, c.username, c.secret_type, c.is_admin
                        ),
                        content_type: EvidenceType::Credential,
                    })
                    .collect(),
                mitre: crate::mapper::map_technique("credential_access"),
                mitigations: crate::mitigations::get_mitigations("credential_exposure"),
                business_impact: "Compromised administrative credentials grant full control \
                    over domain-joined systems and sensitive data."
                    .to_string(),
                references: vec!["https://attack.mitre.org/tactics/TA0006/".to_string()],
                discovered_at: Utc::now(),
            });
        }

        // ── Unconstrained delegation ──
        if !state.unconstrained_delegation.is_empty() {
            self.findings.push(Finding {
                id: format!("OT-{}-004", self.id.split('-').next().unwrap_or("F")),
                title: "Unconstrained Delegation Enabled on Non-DC Hosts".to_string(),
                severity: Severity::Critical,
                cvss_score: 9.1,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N".to_string()),
                category: FindingCategory::DelegationAbuse,
                description: format!(
                    "{} non-DC computer(s) have unconstrained delegation enabled. \
                     An attacker who compromises these hosts can capture TGTs from \
                     any user who authenticates to them — including domain admins \
                     via coercion attacks (e.g., PetitPotam, PrinterBug).",
                    state.unconstrained_delegation.len()
                ),
                affected_assets: state.unconstrained_delegation.clone(),
                proof_of_concept: vec![
                    "Identified unconstrained delegation via LDAP (UAC flag 0x80000)".to_string(),
                    "Coerced DC authentication to delegation host".to_string(),
                    "Captured DC machine account TGT".to_string(),
                    "Used captured TGT for DCSync replication".to_string(),
                ],
                evidence: vec![EvidenceItem {
                    label: "Unconstrained delegation hosts".to_string(),
                    content: state.unconstrained_delegation.join("\n"),
                    content_type: EvidenceType::CommandOutput,
                }],
                mitre: crate::mapper::map_technique("unconstrained_delegation"),
                mitigations: crate::mitigations::get_mitigations("unconstrained_delegation"),
                business_impact: "Complete domain compromise possible through TGT capture \
                    and replay."
                    .to_string(),
                references: vec!["https://attack.mitre.org/techniques/T1550/003/".to_string()],
                discovered_at: Utc::now(),
            });
        }

        // ── Admin access on hosts ──
        if !state.admin_hosts.is_empty() {
            self.findings.push(Finding {
                id: format!("OT-{}-005", self.id.split('-').next().unwrap_or("F")),
                title: "Local Administrator Access on Domain Hosts".to_string(),
                severity: Severity::High,
                cvss_score: 8.1,
                cvss_vector: None,
                category: FindingCategory::LateralMovement,
                description: format!(
                    "Local administrator access was obtained on {} host(s), enabling \
                     remote command execution, credential dumping, and lateral movement.",
                    state.admin_hosts.len()
                ),
                affected_assets: state.admin_hosts.iter().cloned().collect(),
                proof_of_concept: vec![
                    "Authenticated via SMB with compromised credentials".to_string(),
                    "Confirmed admin share (C$/ADMIN$) write access".to_string(),
                    "Executed remote commands via service creation".to_string(),
                ],
                evidence: vec![],
                mitre: crate::mapper::map_technique("lateral_movement"),
                mitigations: crate::mitigations::get_mitigations("admin_access"),
                business_impact: "Lateral movement enables attackers to pivot across \
                    the network, dumping credentials and escalating privileges."
                    .to_string(),
                references: vec!["https://attack.mitre.org/tactics/TA0008/".to_string()],
                discovered_at: Utc::now(),
            });
        }

        // ── Domain Admin achieved ──
        if state.has_domain_admin {
            self.findings.push(Finding {
                id: format!("OT-{}-006", self.id.split('-').next().unwrap_or("F")),
                title: "Full Domain Compromise — Domain Admin Achieved".to_string(),
                severity: Severity::Critical,
                cvss_score: 10.0,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H".to_string()),
                category: FindingCategory::PrivilegeEscalation,
                description: format!(
                    "Domain Admin privileges were achieved during the assessment \
                     (user: {}). This represents a complete compromise of the \
                     Active Directory environment, granting full control over all \
                     domain-joined systems, user accounts, and Group Policy.",
                    state.da_user.as_deref().unwrap_or("unknown")
                ),
                affected_assets: vec![domain.clone()],
                proof_of_concept: vec![
                    "Compromised initial credentials via Kerberos attacks".to_string(),
                    "Escalated through lateral movement / delegation abuse".to_string(),
                    "Achieved Domain Admin membership or equivalent".to_string(),
                ],
                evidence: vec![],
                mitre: crate::mapper::map_technique("domain_admin"),
                mitigations: crate::mitigations::get_mitigations("domain_compromise"),
                business_impact: "Complete domain compromise. An attacker can read all \
                    emails, access all file shares, deploy ransomware domain-wide, \
                    create persistent backdoors, and exfiltrate any data."
                    .to_string(),
                references: vec!["https://attack.mitre.org/techniques/T1078/002/".to_string()],
                discovered_at: Utc::now(),
            });
        }

        // Sort findings by severity (Critical first)
        self.findings.sort_by_key(|b| std::cmp::Reverse(b.severity));
    }

    /// Severity breakdown for summary
    pub fn severity_counts(&self) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        for f in &self.findings {
            *counts.entry(f.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Overall risk rating based on findings
    pub fn overall_risk(&self) -> Severity {
        if self
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
        {
            Severity::Critical
        } else if self.findings.iter().any(|f| f.severity == Severity::High) {
            Severity::High
        } else if self.findings.iter().any(|f| f.severity == Severity::Medium) {
            Severity::Medium
        } else if self.findings.iter().any(|f| f.severity == Severity::Low) {
            Severity::Low
        } else {
            Severity::Informational
        }
    }
}
