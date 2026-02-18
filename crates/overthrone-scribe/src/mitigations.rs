//! Mitigation recommendations — Maps finding types to specific,
//! actionable remediation steps with priority and effort estimates.

use serde::{Deserialize, Serialize};

/// A single mitigation recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mitigation {
    pub title: String,
    pub description: String,
    pub priority: MitigationPriority,
    pub effort: ImplementationEffort,
    pub category: MitigationCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MitigationPriority {
    Immediate,
    ShortTerm,
    MediumTerm,
    LongTerm,
}

impl std::fmt::Display for MitigationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Immediate => write!(f, "Immediate (0–48 hours)"),
            Self::ShortTerm => write!(f, "Short-Term (1–2 weeks)"),
            Self::MediumTerm => write!(f, "Medium-Term (1–3 months)"),
            Self::LongTerm => write!(f, "Long-Term (3–12 months)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImplementationEffort {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for ImplementationEffort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitigationCategory {
    Configuration,
    Policy,
    Architecture,
    Monitoring,
    PatchManagement,
    AccessControl,
    CredentialHygiene,
}

impl std::fmt::Display for MitigationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration => write!(f, "Configuration"),
            Self::Policy => write!(f, "Policy"),
            Self::Architecture => write!(f, "Architecture"),
            Self::Monitoring => write!(f, "Monitoring"),
            Self::PatchManagement => write!(f, "Patch Management"),
            Self::AccessControl => write!(f, "Access Control"),
            Self::CredentialHygiene => write!(f, "Credential Hygiene"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Mitigation Database
// ═══════════════════════════════════════════════════════════

/// Get mitigations for a specific finding type
pub fn get_mitigations(finding_type: &str) -> Vec<Mitigation> {
    match finding_type {
        "kerberoast" => vec![
            Mitigation {
                title: "Use Group Managed Service Accounts (gMSA)".to_string(),
                description: "Replace regular service accounts with gMSAs. These use \
                    120-character randomly generated passwords that rotate automatically \
                    every 30 days, making offline cracking infeasible."
                    .to_string(),
                priority: MitigationPriority::ShortTerm,
                effort: ImplementationEffort::Medium,
                category: MitigationCategory::CredentialHygiene,
            },
            Mitigation {
                title: "Enforce AES-256 encryption for service accounts".to_string(),
                description: "Set msDS-SupportedEncryptionTypes to 0x18 (AES128+AES256) \
                    on service accounts and disable RC4 (etype 23). AES tickets are \
                    significantly harder to crack."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::Configuration,
            },
            Mitigation {
                title: "Use 25+ character passwords for service accounts".to_string(),
                description: "If gMSAs are not feasible, ensure all SPN-enabled accounts \
                    use passwords of 25+ characters with high complexity."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::CredentialHygiene,
            },
            Mitigation {
                title: "Monitor for anomalous TGS requests".to_string(),
                description: "Alert on Event ID 4769 when a single user requests TGS \
                    tickets for many different SPNs in a short time, or when RC4 \
                    encryption is requested for AES-capable accounts."
                    .to_string(),
                priority: MitigationPriority::ShortTerm,
                effort: ImplementationEffort::Medium,
                category: MitigationCategory::Monitoring,
            },
        ],

        "asrep_roast" => vec![
            Mitigation {
                title: "Enable Kerberos pre-authentication for all accounts".to_string(),
                description: "Remove the DONT_REQ_PREAUTH flag from all user accounts. \
                    Audit with: Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::Configuration,
            },
            Mitigation {
                title: "Monitor for AS-REQ without pre-auth".to_string(),
                description: "Alert on Kerberos Event ID 4768 where pre-authentication \
                    type is 0 (none). This indicates potential AS-REP roasting."
                    .to_string(),
                priority: MitigationPriority::ShortTerm,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::Monitoring,
            },
        ],

        "credential_exposure" => vec![
            Mitigation {
                title: "Implement LAPS for local admin passwords".to_string(),
                description: "Deploy Microsoft LAPS (Local Administrator Password Solution) \
                    to randomize local admin passwords on all domain-joined machines, \
                    preventing credential reuse across hosts."
                    .to_string(),
                priority: MitigationPriority::ShortTerm,
                effort: ImplementationEffort::Medium,
                category: MitigationCategory::CredentialHygiene,
            },
            Mitigation {
                title: "Enable Credential Guard on Windows 10/11+".to_string(),
                description: "Windows Defender Credential Guard uses virtualization-based \
                    security to isolate LSASS, preventing NTLM hash and Kerberos \
                    ticket extraction from memory."
                    .to_string(),
                priority: MitigationPriority::MediumTerm,
                effort: ImplementationEffort::Medium,
                category: MitigationCategory::Configuration,
            },
            Mitigation {
                title: "Implement tiered administration model".to_string(),
                description: "Separate admin accounts into tiers (T0: domain, T1: servers, \
                    T2: workstations) with strict boundaries. DA credentials should \
                    never touch non-T0 systems."
                    .to_string(),
                priority: MitigationPriority::MediumTerm,
                effort: ImplementationEffort::High,
                category: MitigationCategory::Architecture,
            },
        ],

        "unconstrained_delegation" => vec![
            Mitigation {
                title: "Remove unconstrained delegation from all non-DC hosts".to_string(),
                description: "Disable the TRUSTED_FOR_DELEGATION flag on all computer \
                    accounts except domain controllers. Use constrained delegation \
                    or RBCD instead."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::Configuration,
            },
            Mitigation {
                title: "Add sensitive accounts to 'Protected Users' group".to_string(),
                description: "Members of the Protected Users group cannot be delegated. \
                    Add all privileged accounts (DA, EA, service accounts) to this group."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::AccessControl,
            },
            Mitigation {
                title: "Set 'Account is sensitive and cannot be delegated'".to_string(),
                description: "Flag all high-privilege accounts with the NOT_DELEGATED \
                    attribute to prevent their TGTs from being forwarded."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::Configuration,
            },
        ],

        "admin_access" => vec![
            Mitigation {
                title: "Restrict local admin group membership".to_string(),
                description: "Use Group Policy to control local Administrators group \
                    membership. Remove domain users from local admin groups on servers \
                    and workstations."
                    .to_string(),
                priority: MitigationPriority::ShortTerm,
                effort: ImplementationEffort::Medium,
                category: MitigationCategory::AccessControl,
            },
            Mitigation {
                title: "Disable SMBv1 and restrict admin shares".to_string(),
                description: "Disable SMBv1 protocol via Group Policy. Consider disabling \
                    default admin shares (C$, ADMIN$) on non-server systems."
                    .to_string(),
                priority: MitigationPriority::ShortTerm,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::Configuration,
            },
        ],

        "domain_compromise" => vec![
            Mitigation {
                title: "Reset krbtgt password TWICE".to_string(),
                description: "Immediately reset the krbtgt account password twice (with \
                    12+ hours between resets) to invalidate any golden tickets. This \
                    is the most critical immediate action after domain compromise."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Low,
                category: MitigationCategory::CredentialHygiene,
            },
            Mitigation {
                title: "Reset all privileged account passwords".to_string(),
                description: "Reset passwords for all Domain Admin, Enterprise Admin, \
                    and service accounts. Rotate all machine account passwords."
                    .to_string(),
                priority: MitigationPriority::Immediate,
                effort: ImplementationEffort::Medium,
                category: MitigationCategory::CredentialHygiene,
            },
            Mitigation {
                title: "Implement Privileged Access Workstations (PAW)".to_string(),
                description: "Deploy hardened admin workstations for all Tier 0 operations. \
                    Prevent privileged credentials from being exposed to less-secure \
                    endpoints."
                    .to_string(),
                priority: MitigationPriority::MediumTerm,
                effort: ImplementationEffort::High,
                category: MitigationCategory::Architecture,
            },
            Mitigation {
                title: "Enable Advanced Audit Policies".to_string(),
                description: "Configure advanced auditing for: Directory Service Access, \
                    Kerberos operations, logon events, process creation with command \
                    line logging, and PowerShell script block logging."
                    .to_string(),
                priority: MitigationPriority::ShortTerm,
                effort: ImplementationEffort::Medium,
                category: MitigationCategory::Monitoring,
            },
        ],

        _ => vec![],
    }
}

/// Get all unique mitigations across all finding types, deduplicated by title
pub fn aggregate_mitigations(finding_types: &[&str]) -> Vec<Mitigation> {
    let mut all: Vec<Mitigation> = finding_types
        .iter()
        .flat_map(|ft| get_mitigations(ft))
        .collect();

    all.sort_by(|a, b| a.priority.cmp(&b.priority));
    all.dedup_by(|a, b| a.title == b.title);
    all
}
