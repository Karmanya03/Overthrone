//! ACL reasoning for kerberoast/AS-REP targets.
//!
//! This module analyzes Active Directory ACLs to determine WHY a user/computer
//! is worth roasting, going beyond simple SPN enumeration to provide attack
//! path context and risk scoring.
//!
//! Features:
//! - Identifies high-privilege accounts (DA, EA, Schema Admins, etc.)
//! - Detects delegation relationships (constrained/unconstrained/RBCD)
//! - Finds lateral movement paths (GenericAll, ForceChangePassword, etc.)
//! - Scores targets by attack value (critical/high/medium/low)
//! - Provides actionable intelligence ("roast this to gain X")
//!
//! NOTE: Full graph-based ACL analysis requires LDAP query integration.
//! Current implementation provides risk scoring based on account properties
//! and known high-value indicators.

use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

// ═══════════════════════════════════════════════════════════
// Result Structures
// ═══════════════════════════════════════════════════════════

/// ACL reasoning result for a roast target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclReasoningResult {
    /// Analyzed targets with reasoning
    pub targets: Vec<TargetAnalysis>,
    /// Summary statistics
    pub summary: ReasoningSummary,
}

/// Analysis of a single roast target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAnalysis {
    /// Account name (sAMAccountName)
    pub account_name: String,
    /// Account type (User/Computer/Service)
    pub account_type: String,
    /// SPNs (for kerberoast) or preauth status (for AS-REP)
    pub identifiers: Vec<String>,
    /// Why this target is worth roasting
    pub reasons: Vec<AttackReason>,
    /// Attack value score
    pub risk_level: RiskLevel,
    /// Potential attack paths unlocked
    pub attack_paths: Vec<AttackPath>,
    /// Group memberships that elevate value
    pub high_value_groups: Vec<String>,
    /// Delegation relationships
    pub delegation_rights: DelegationInfo,
}

/// Why this target is worth attacking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackReason {
    /// Category of the reason
    pub category: String,
    /// Detailed explanation
    pub description: String,
    /// Impact if compromised
    pub impact: String,
}

/// Attack path unlocked by compromising this target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    /// Path description
    pub path: String,
    /// Edge types traversed
    pub edges: Vec<String>,
    /// Target node (what you gain access to)
    pub target: String,
    /// Estimated difficulty (1-10)
    pub difficulty: u8,
}

/// Delegation rights held by or over this target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationInfo {
    /// Has unconstrained delegation
    pub unconstrained_delegation: bool,
    /// Has constrained delegation (and to what SPNs)
    pub constrained_delegation_to: Vec<String>,
    /// RBCD: can act on behalf of others to this target
    pub rbcd_vulnerable: bool,
    /// RBCD: this target can delegate to others
    pub rbcd_delegator: bool,
}

/// Risk level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Domain Admin equivalent, immediate DA path
    Critical,
    /// High-privilege account, short path to DA
    High,
    /// Medium-privilege, useful for lateral movement
    Medium,
    /// Low-privilege, minimal strategic value
    Low,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
        }
    }
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningSummary {
    /// Total targets analyzed
    pub total_targets: usize,
    /// Count by risk level
    pub critical_count: usize,
    /// Count by risk level
    pub high_count: usize,
    /// Count by risk level
    pub medium_count: usize,
    /// Count by risk level
    pub low_count: usize,
    /// Top 3 highest-value targets
    pub top_targets: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
// High-Value Indicators
// ═══════════════════════════════════════════════════════════

/// Keywords that indicate high-value accounts
const HIGH_VALUE_KEYWORDS: &[&str] = &[
    "admin", "da", "ea", "domain admin", "enterprise admin",
    "schema admin", "key admin", "dnsadmin", "backup",
    "restore", "service", "sql", "exchange", "sccm",
];

// ═══════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════

/// Analyze ACLs and attack paths for kerberoast/AS-REP targets
///
/// This function analyzes roast targets based on:
/// 1. Account naming patterns (admin, DA, EA, etc.)
/// 2. SPN analysis (service accounts, SQL, Exchange, etc.)
/// 3. Known high-value indicators
/// 4. Delegation relationships (when available from LDAP)
///
/// NOTE: Full graph-based ACL analysis requires LDAP integration.
/// Current implementation uses heuristic analysis.
pub async fn analyze_roast_targets(
    hunt_config: &HuntConfig,
    target_accounts: &[String],
    spn_map: &std::collections::HashMap<String, Vec<String>>,
) -> Result<AclReasoningResult> {
    info!(
        "{}",
        "═══ ACL REASONING ANALYSIS ═══".bold().bright_cyan()
    );
    info!("Analyzing {} targets for attack value...", target_accounts.len());

    let mut targets = Vec::new();
    let mut summary = ReasoningSummary {
        total_targets: target_accounts.len(),
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        top_targets: Vec::new(),
    };

    for account in target_accounts {
        info!("  Analyzing: {}", account);

        let analysis = analyze_single_target(
            account,
            spn_map.get(account).cloned().unwrap_or_default(),
            &hunt_config.domain,
        );

        // Update summary counts
        match analysis.risk_level {
            RiskLevel::Critical => summary.critical_count += 1,
            RiskLevel::High => summary.high_count += 1,
            RiskLevel::Medium => summary.medium_count += 1,
            RiskLevel::Low => summary.low_count += 1,
        }

        // Track top targets (critical/high priority)
        if analysis.risk_level == RiskLevel::Critical
            || analysis.risk_level == RiskLevel::High
        {
            summary.top_targets.push(account.clone());
        }

        targets.push(analysis);
    }

    // Sort targets by risk level (critical first)
    targets.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

    info!(
        "Analysis complete: {} critical, {} high, {} medium, {} low",
        summary.critical_count,
        summary.high_count,
        summary.medium_count,
        summary.low_count
    );

    Ok(AclReasoningResult {
        targets,
        summary,
    })
}

// ═══════════════════════════════════════════════════════════
// Single Target Analysis
// ═══════════════════════════════════════════════════════════

fn analyze_single_target(
    account_name: &str,
    spns: Vec<String>,
    domain: &str,
) -> TargetAnalysis {
    let mut reasons = Vec::new();
    let mut attack_paths = Vec::new();
    let mut high_value_groups = Vec::new();
    let delegation_info = DelegationInfo {
        unconstrained_delegation: false,
        constrained_delegation_to: Vec::new(),
        rbcd_vulnerable: false,
        rbcd_delegator: false,
    };

    // Determine account type
    let account_type = if account_name.ends_with('$') {
        "Computer".to_string()
    } else {
        "User".to_string()
    };

    // Analyze account name for high-value indicators
    analyze_account_name(account_name, &mut reasons, &mut high_value_groups);

    // Analyze SPNs for service value
    analyze_spns(&spns, &mut reasons, &mut attack_paths);

    // Calculate risk level
    let risk_level = calculate_risk_level(&reasons, &attack_paths, &high_value_groups);

    TargetAnalysis {
        account_name: account_name.to_string(),
        account_type,
        identifiers: if spns.is_empty() {
            vec![format!("{}@{}", account_name, domain)]
        } else {
            spns.clone()
        },
        reasons,
        risk_level,
        attack_paths,
        high_value_groups,
        delegation_rights: delegation_info,
    }
}

// ═══════════════════════════════════════════════════════════
// Analysis Helpers
// ═══════════════════════════════════════════════════════════

fn analyze_account_name(
    account_name: &str,
    reasons: &mut Vec<AttackReason>,
    high_value_groups: &mut Vec<String>,
) {
    let name_lower = account_name.to_lowercase();

    // Check for admin keywords
    for keyword in HIGH_VALUE_KEYWORDS {
        if name_lower.contains(keyword) {
            reasons.push(AttackReason {
                category: "Account Name".to_string(),
                description: format!("Account name contains high-value keyword: '{}'", keyword),
                impact: "Likely privileged account - high value for credential theft".to_string(),
            });

            if keyword.contains("admin") {
                high_value_groups.push(format!("Potential Admin Group (based on name '{}')", account_name));
            }
            break; // Only count once
        }
    }

    // Check for service account patterns
    if account_name.starts_with("svc_") || account_name.starts_with("service_") {
        reasons.push(AttackReason {
            category: "Service Account".to_string(),
            description: "Follows service account naming pattern (svc_ or service_)".to_string(),
            impact: "Service accounts often have elevated privileges and weak passwords".to_string(),
        });
    }

    // Check for backup/restore accounts
    if name_lower.contains("backup") || name_lower.contains("restore") {
        reasons.push(AttackReason {
            category: "Backup Account".to_string(),
            description: "Account name suggests backup/restore privileges".to_string(),
            impact: "Backup operators can access domain controller backups with NTDS.dit".to_string(),
        });
    }
}

fn analyze_spns(
    spns: &[String],
    reasons: &mut Vec<AttackReason>,
    attack_paths: &mut Vec<AttackPath>,
) {
    for spn in spns {
        let spn_lower = spn.to_lowercase();

        // SQL Server SPNs
        if spn_lower.contains("mssqlsvc") {
            reasons.push(AttackReason {
                category: "SPN Analysis".to_string(),
                description: format!("SQL Server SPN: {}", spn),
                impact: "SQL service accounts often have db_owner or sysadmin rights".to_string(),
            });
            attack_paths.push(AttackPath {
                path: format!("SQL SPN → {} → Database access", spn),
                edges: vec!["Kerberoast".to_string(), "SQL Access".to_string()],
                target: "SQL Server".to_string(),
                difficulty: 3,
            });
        }

        // HTTP/WEB SPNs
        if spn_lower.starts_with("http/") || spn_lower.starts_with("www/") {
            reasons.push(AttackReason {
                category: "SPN Analysis".to_string(),
                description: format!("Web service SPN: {}", spn),
                impact: "Web services may have application pool or IIS privileges".to_string(),
            });
        }

        // HOST SPNs (often indicate computer accounts with local admin)
        if spn_lower.starts_with("host/") {
            reasons.push(AttackReason {
                category: "SPN Analysis".to_string(),
                description: format!("HOST SPN: {}", spn),
                impact: "HOST SPN often indicates computer account with local admin rights".to_string(),
            });
        }

        // Exchange SPNs
        if spn_lower.contains("exchange") || spn_lower.starts_with("exchange") {
            reasons.push(AttackReason {
                category: "SPN Analysis".to_string(),
                description: format!("Exchange SPN: {}", spn),
                impact: "Exchange servers often have high privileges and sensitive data".to_string(),
            });
            attack_paths.push(AttackPath {
                path: format!("Exchange SPN → {} → Email access", spn),
                edges: vec!["Kerberoast".to_string(), "Exchange Access".to_string()],
                target: "Exchange Server".to_string(),
                difficulty: 4,
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Risk Calculation
// ═══════════════════════════════════════════════════════════

fn calculate_risk_level(
    reasons: &[AttackReason],
    attack_paths: &[AttackPath],
    high_value_groups: &[String],
) -> RiskLevel {
    // Critical: Explicit admin/DA/EA indicators
    if high_value_groups.iter().any(|g| {
        g.contains("Domain Admin") || g.contains("Enterprise Admin") || g.contains("Schema Admin")
    }) {
        return RiskLevel::Critical;
    }

    if reasons.iter().any(|r| {
        r.description.contains("Domain Admin") || 
        r.description.contains("Enterprise Admin") ||
        r.description.contains("Schema Admin")
    }) {
        return RiskLevel::Critical;
    }

    // High: Multiple attack paths OR service accounts with SQL/Exchange
    if attack_paths.len() >= 2 {
        return RiskLevel::High;
    }

    if reasons.iter().any(|r| {
        r.category.contains("SPN") && (
            r.description.contains("SQL") || 
            r.description.contains("Exchange") ||
            r.description.contains("HOST")
        )
    }) {
        return RiskLevel::High;
    }

    if reasons.iter().any(|r| {
        r.category.contains("Backup") || r.category.contains("Service Account")
    }) {
        return RiskLevel::High;
    }

    // Medium: Any named-based admin indicators OR single attack path
    if reasons.iter().any(|r| r.category.contains("Account Name") && r.description.contains("admin")) {
        return RiskLevel::Medium;
    }

    if !attack_paths.is_empty() {
        return RiskLevel::Medium;
    }

    // Low: No special indicators
    RiskLevel::Low
}
