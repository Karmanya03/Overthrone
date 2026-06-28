use serde::{Deserialize, Serialize};

use crate::{
    acls::AclFinding, adcs::CertTemplate, delegations::DelegationEntry, runner::ReaperResult,
    snaffler::SnaffleFinding, trusts::TrustEntry, users::UserEntry,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    pub fn numeric(&self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    pub fn cvss_score(&self) -> f32 {
        match self {
            Self::Critical => 9.5,
            Self::High => 7.5,
            Self::Medium => 5.0,
            Self::Low => 2.5,
            Self::Info => 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskCategory {
    PasswordPolicy,
    KerberosDelegation,
    KerberosPreAuth,
    Kerberoasting,
    AdcsVulnerability,
    AclAbuse,
    TrustRelationship,
    LapsDeployment,
    DomainHealth,
    SnafflerExposure,
}

impl RiskCategory {
    pub fn label(&self) -> &str {
        match self {
            Self::PasswordPolicy => "Password Policy",
            Self::KerberosDelegation => "Kerberos Delegation",
            Self::KerberosPreAuth => "Kerberos Pre-Authentication",
            Self::Kerberoasting => "Kerberoasting Risk",
            Self::AdcsVulnerability => "ADCS Vulnerabilities",
            Self::AclAbuse => "ACL Abuse Paths",
            Self::TrustRelationship => "Trust Relationships",
            Self::LapsDeployment => "LAPS Deployment",
            Self::DomainHealth => "Domain Health",
            Self::SnafflerExposure => "Sensitive Data Exposure",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub category: RiskCategory,
    pub title: String,
    pub severity: RiskLevel,
    pub score_impact: f32,
    pub description: String,
    pub recommendation: String,
    pub affected_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub category: RiskCategory,
    pub label: String,
    pub score: f32,
    pub max_score: f32,
    pub finding_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentResult {
    pub domain: String,
    pub overall_health_score: f32,
    pub overall_health_label: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub category_scores: Vec<CategoryScore>,
    pub findings: Vec<RiskFinding>,
}

fn clamp(v: f32, min: f32, max: f32) -> f32 {
    if v < min {
        min
    } else if v > max {
        max
    } else {
        v
    }
}

fn score_to_label(score: f32) -> String {
    match score as u8 {
        90..=100 => "Excellent".to_string(),
        75..=89 => "Good".to_string(),
        60..=74 => "Fair".to_string(),
        40..=59 => "Poor".to_string(),
        _ => "Critical".to_string(),
    }
}

pub fn assess_reaper_result(result: &ReaperResult) -> RiskAssessmentResult {
    let mut findings: Vec<RiskFinding> = Vec::new();
    let mut critical = 0usize;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    // ── Password Policy ──
    if let Some(ref policy) = result.policy
        && let Some(ref dp) = policy.domain_policy
    {
        let mut score_impact = 0.0f32;
        let mut issues = Vec::new();

        if let Some(len) = dp.min_password_length {
            if len < 8 {
                issues.push(format!(
                    "Minimum password length is {} (recommended: 14+)",
                    len
                ));
                score_impact += 25.0;
            } else if len < 14 {
                issues.push(format!(
                    "Minimum password length is {} (recommended: 14+)",
                    len
                ));
                score_impact += 10.0;
            }
        }
        if dp.lockout_threshold.unwrap_or(0) == 0 || dp.lockout_threshold.unwrap_or(999) > 10 {
            issues.push("Account lockout threshold is missing or too high".to_string());
            score_impact += 15.0;
        }
        if dp.max_password_age.as_deref().unwrap_or("") == "0"
            || dp.max_password_age.as_deref().unwrap_or("") == "-9223372036854775808"
        {
            issues.push("Domain passwords never expire".to_string());
            score_impact += 20.0;
        }

        if !issues.is_empty() {
            let severity = if score_impact >= 25.0 {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            };
            let level = severity.numeric();
            match level {
                5 => critical += 1,
                4 => high += 1,
                3 => medium += 1,
                2 => low += 1,
                _ => info += 1,
            };
            findings.push(RiskFinding {
                    category: RiskCategory::PasswordPolicy,
                    title: "Weak Domain Password Policy".to_string(),
                    severity,
                    score_impact,
                    description: issues.join("; "),
                    recommendation: "Set minimum password length to 14+, enforce lockout after 5 attempts, and set a reasonable max password age (90 days or less).".to_string(),
                    affected_count: issues.len(),
                });
        }
    }

    // ── Kerberos Pre-Auth (AS-REP roastable) ──
    let asrep_users: Vec<&UserEntry> = result
        .users
        .iter()
        .filter(|u| u.enabled && (u.uac_flags & crate::users::UAC_DONT_REQ_PREAUTH) != 0)
        .collect();
    if !asrep_users.is_empty() {
        let count = asrep_users.len();
        high += 1;
        findings.push(RiskFinding {
            category: RiskCategory::KerberosPreAuth,
            title: "AS-REP Roastable Accounts".to_string(),
            severity: RiskLevel::High,
            score_impact: 12.5,
            description: format!("{} enabled user(s) have DONT_REQ_PREAUTH set, allowing offline AS-REP roasting", count),
            recommendation: "Enable Kerberos pre-authentication for all accounts. Identify and fix the accounts listed above.".to_string(),
            affected_count: count,
        });
    }

    // ── Kerberoasting (SPN accounts) ──
    let kerberoastable = result.spn_accounts.len();
    if kerberoastable > 0 {
        let severity = if kerberoastable > 50 {
            RiskLevel::High
        } else if kerberoastable > 10 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };
        let level = severity.numeric();
        match level {
            5 => critical += 1,
            4 => high += 1,
            3 => medium += 1,
            2 => low += 1,
            _ => info += 1,
        };
        findings.push(RiskFinding {
            category: RiskCategory::Kerberoasting,
            title: "Kerberoastable Service Accounts".to_string(),
            severity,
            score_impact: clamp(kerberoastable as f32 * 0.4, 2.0, 15.0),
            description: format!("{} service accounts with SPNs registered (potential Kerberoast targets)", kerberoastable),
            recommendation: "Use Group Managed Service Accounts (gMSA) instead of user accounts for services. Set long, random passwords for required service accounts.".to_string(),
            affected_count: kerberoastable,
        });
    }

    // ── Kerberos Delegation ──
    let unconstrained: Vec<&DelegationEntry> = result
        .delegations
        .iter()
        .filter(|d| {
            matches!(
                d.delegation_type,
                crate::delegations::DelegationType::Unconstrained
            )
        })
        .collect();
    if !unconstrained.is_empty() {
        critical += 1;
        findings.push(RiskFinding {
            category: RiskCategory::KerberosDelegation,
            title: "Unconstrained Kerberos Delegation".to_string(),
            severity: RiskLevel::Critical,
            score_impact: 20.0,
            description: format!("{} computer(s) have unconstrained delegation enabled, allowing TGT theft from connecting users", unconstrained.len()),
            recommendation: "Replace unconstrained delegation with constrained or resource-based delegation. Audit which accounts connect to these systems.".to_string(),
            affected_count: unconstrained.len(),
        });
    }

    let constrained_risky: Vec<&DelegationEntry> = result
        .delegations
        .iter()
        .filter(|d| {
            matches!(
                d.delegation_type,
                crate::delegations::DelegationType::ConstrainedWithProtocolTransition
            )
        })
        .collect();
    if !constrained_risky.is_empty() {
        medium += 1;
        findings.push(RiskFinding {
            category: RiskCategory::KerberosDelegation,
            title: "Constrained Delegation with Protocol Transition".to_string(),
            severity: RiskLevel::Medium,
            score_impact: 8.0,
            description: format!("{} account(s) have constrained delegation with protocol transition (S4U2Self), allowing impersonation of any user", constrained_risky.len()),
            recommendation: "Use resource-based delegation instead of protocol transition. Audit delegation configurations regularly.".to_string(),
            affected_count: constrained_risky.len(),
        });
    }

    // ── ADCS Vulnerabilities ──
    let vuln_templates: Vec<&CertTemplate> = result
        .adcs_templates
        .iter()
        .filter(|t| !t.vulnerabilities.is_empty())
        .collect();
    if !vuln_templates.is_empty() {
        let total_vulns: usize = vuln_templates.iter().map(|t| t.vulnerabilities.len()).sum();
        let esc_count: usize = vuln_templates
            .iter()
            .flat_map(|t| t.vulnerabilities.iter())
            .filter(|v| v.starts_with("ESC"))
            .count();
        let severity = if esc_count > 0 {
            RiskLevel::Critical
        } else {
            RiskLevel::High
        };
        let level = severity.numeric();
        match level {
            5 => critical += 1,
            4 => high += 1,
            3 => medium += 1,
            2 => low += 1,
            _ => info += 1,
        };
        findings.push(RiskFinding {
            category: RiskCategory::AdcsVulnerability,
            title: "Vulnerable ADCS Certificate Templates".to_string(),
            severity,
            score_impact: clamp(esc_count as f32 * 10.0, 10.0, 30.0),
            description: format!("{} vulnerable template(s) found with {} total issues ({} ESC-level)", vuln_templates.len(), total_vulns, esc_count),
            recommendation: "Disable or harden vulnerable certificate templates. Remove enrollment rights for low-privileged users. Enable manager approval.".to_string(),
            affected_count: vuln_templates.len(),
        });
    }

    // ── ACL Abuse ──
    let dangerous_acls: Vec<&AclFinding> = result
        .acl_findings
        .iter()
        .filter(|a| a.severity <= 2)
        .collect();
    if !dangerous_acls.is_empty() {
        let severity = if dangerous_acls.len() > 10 {
            RiskLevel::Critical
        } else if dangerous_acls.len() > 3 {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
        let level = severity.numeric();
        match level {
            5 => critical += 1,
            4 => high += 1,
            3 => medium += 1,
            2 => low += 1,
            _ => info += 1,
        };
        findings.push(RiskFinding {
            category: RiskCategory::AclAbuse,
            title: "Dangerous ACL Configurations".to_string(),
            severity,
            score_impact: clamp(dangerous_acls.len() as f32 * 2.0, 5.0, 25.0),
            description: format!("{} high-severity ACL abuse paths found (GenericAll/WriteDACL/WriteOwner/AllExtendedRights)", dangerous_acls.len()),
            recommendation: "Review and remove excessive ACL entries. Apply the principle of least privilege. Audit ACL changes regularly.".to_string(),
            affected_count: dangerous_acls.len(),
        });
    }

    // ── Trust Relationships ──
    let external_trusts: Vec<&TrustEntry> = result
        .trusts
        .iter()
        .filter(|t| {
            matches!(t.trust_type, crate::trusts::TrustType::External)
                || matches!(t.trust_type, crate::trusts::TrustType::Forest)
        })
        .collect();
    if !external_trusts.is_empty() {
        let no_sid_filtering = external_trusts
            .iter()
            .filter(|t| !t.sid_filtering_enabled)
            .count();
        let mut issues = Vec::new();
        let mut score_impact = 0.0f32;

        issues.push(format!(
            "{} external/forest trust(s) configured",
            external_trusts.len()
        ));
        if no_sid_filtering > 0 {
            issues.push(format!(
                "{} trust(s) without SID filtering",
                no_sid_filtering
            ));
            score_impact += 15.0;
        }

        let severity = if no_sid_filtering > 0 {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
        let level = severity.numeric();
        match level {
            5 => critical += 1,
            4 => high += 1,
            3 => medium += 1,
            2 => low += 1,
            _ => info += 1,
        };
        findings.push(RiskFinding {
            category: RiskCategory::TrustRelationship,
            title: "External Trust Relationships".to_string(),
            severity,
            score_impact: clamp(score_impact + external_trusts.len() as f32 * 2.0, 3.0, 20.0),
            description: issues.join("; "),
            recommendation: "Enable SID filtering on all external and forest trusts. Regularly review trust relationships and remove unused ones.".to_string(),
            affected_count: external_trusts.len(),
        });
    }

    // ── LAPS Deployment ──
    let laps_count = result.laps_entries.len();
    let computer_count = result.computers.len();
    if computer_count > 0 {
        let coverage = laps_count as f32 / computer_count as f32;
        if coverage < 0.5 {
            high += 1;
            findings.push(RiskFinding {
                category: RiskCategory::LapsDeployment,
                title: "Insufficient LAPS Deployment".to_string(),
                severity: RiskLevel::High,
                score_impact: 15.0,
                description: format!("LAPS is deployed on only {}/{} computers ({:.0}%)", laps_count, computer_count, coverage * 100.0),
                recommendation: "Deploy LAPS (or Windows LAPS) to all domain-joined computers. Ensure passwords are rotated regularly and access is audited.".to_string(),
                affected_count: computer_count - laps_count,
            });
        } else if coverage < 0.9 {
            medium += 1;
            findings.push(RiskFinding {
                category: RiskCategory::LapsDeployment,
                title: "Partial LAPS Deployment".to_string(),
                severity: RiskLevel::Medium,
                score_impact: 5.0,
                description: format!("LAPS is deployed on {}/{} computers ({:.0}%)", laps_count, computer_count, coverage * 100.0),
                recommendation: "Extend LAPS deployment to cover all computers, especially servers.".to_string(),
                affected_count: computer_count - laps_count,
            });
        } else {
            info += 1;
            findings.push(RiskFinding {
                category: RiskCategory::LapsDeployment,
                title: "Good LAPS Deployment".to_string(),
                severity: RiskLevel::Info,
                score_impact: -2.0,
                description: format!(
                    "LAPS is deployed on {}/{} computers ({:.0}%)",
                    laps_count,
                    computer_count,
                    coverage * 100.0
                ),
                recommendation:
                    "Continue maintaining LAPS coverage and monitor for expired passwords."
                        .to_string(),
                affected_count: 0,
            });
        }
    }

    // ── Domain Functional Level ──
    if let Some(level) = result.functional_level {
        if level < 6 {
            high += 1;
            findings.push(RiskFinding {
                category: RiskCategory::DomainHealth,
                title: "Low Domain Functional Level".to_string(),
                severity: RiskLevel::High,
                score_impact: 10.0,
                description: format!("Domain functional level is {} (recommended: 6 = Server 2012 R2+ or higher for modern security features)", level),
                recommendation: "Raise domain functional level to at least Windows Server 2012 R2 (level 6) to enable modern security features like Kerberos armoring and compound authentication.".to_string(),
                affected_count: 0,
            });
        } else {
            info += 1;
            findings.push(RiskFinding {
                category: RiskCategory::DomainHealth,
                title: "Domain Functional Level".to_string(),
                severity: RiskLevel::Info,
                score_impact: 0.0,
                description: format!("Domain functional level is {} (adequate)", level),
                recommendation: "No action required.".to_string(),
                affected_count: 0,
            });
        }
    }

    // ── Snaffler Exposure ──
    if !result.snaffle_findings.is_empty() {
        let high_value: Vec<&SnaffleFinding> = result
            .snaffle_findings
            .iter()
            .filter(|s| s.severity <= 2)
            .collect();
        let severity = if !high_value.is_empty() {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
        let level = severity.numeric();
        match level {
            5 => critical += 1,
            4 => high += 1,
            3 => medium += 1,
            2 => low += 1,
            _ => info += 1,
        };
        findings.push(RiskFinding {
            category: RiskCategory::SnafflerExposure,
            title: "Sensitive Data on File Shares".to_string(),
            severity,
            score_impact: clamp(high_value.len() as f32 * 3.0, 3.0, 20.0),
            description: format!("{} sensitive files found on readable SMB shares ({} high-value)", result.snaffle_findings.len(), high_value.len()),
            recommendation: "Audit and secure file shares. Remove sensitive data from accessible shares. Implement Data Loss Prevention (DLP) solutions.".to_string(),
            affected_count: result.snaffle_findings.len(),
        });
    }

    // ── Compute category scores ──
    let categories = RiskCategory::all();
    let mut cat_scores: Vec<CategoryScore> = Vec::with_capacity(categories.len());
    for cat in &categories {
        let cat_findings: Vec<&RiskFinding> = findings
            .iter()
            .filter(|f| f.category.label() == cat.label())
            .collect();
        let total_impact: f32 = cat_findings
            .iter()
            .map(|f| {
                if f.score_impact > 0.0 {
                    f.score_impact
                } else {
                    0.0
                }
            })
            .sum();
        cat_scores.push(CategoryScore {
            category: cat.clone(),
            label: cat.label().to_string(),
            score: clamp(100.0 - total_impact, 0.0, 100.0),
            max_score: 100.0,
            finding_count: cat_findings.len(),
        });
    }

    // ── Compute overall score ──
    let total_impact: f32 = findings
        .iter()
        .map(|f| {
            if f.score_impact > 0.0 {
                f.score_impact
            } else {
                0.0
            }
        })
        .sum();
    let positive_boost: f32 = findings
        .iter()
        .map(|f| {
            if f.score_impact < 0.0 {
                -f.score_impact
            } else {
                0.0
            }
        })
        .sum();
    let overall = clamp(100.0 - total_impact + positive_boost, 0.0, 100.0);

    RiskAssessmentResult {
        domain: result.domain.clone(),
        overall_health_score: overall,
        overall_health_label: score_to_label(overall),
        total_findings: findings.len(),
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        info_count: info,
        category_scores: cat_scores,
        findings,
    }
}

impl RiskCategory {
    fn all() -> Vec<RiskCategory> {
        vec![
            RiskCategory::PasswordPolicy,
            RiskCategory::KerberosDelegation,
            RiskCategory::KerberosPreAuth,
            RiskCategory::Kerberoasting,
            RiskCategory::AdcsVulnerability,
            RiskCategory::AclAbuse,
            RiskCategory::TrustRelationship,
            RiskCategory::LapsDeployment,
            RiskCategory::DomainHealth,
            RiskCategory::SnafflerExposure,
        ]
    }
}
