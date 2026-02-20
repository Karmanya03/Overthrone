//! Attack goals — Define what the pilot is trying to achieve.
//!
//! Goals are high-level objectives like "become Domain Admin" or
//! "dump NTDS.dit". Each goal has success criteria that can be
//! evaluated against the current engagement state.

use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Goal Definitions
// ═══════════════════════════════════════════════════════════

/// A high-level attack objective
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackGoal {
    /// Achieve membership/token for a target group (default: "Domain Admins")
    DomainAdmin {
        target_group: String,
    },
    /// Obtain credentials for a specific user
    CompromiseUser {
        target_user: String,
    },
    /// Gain admin access to a specific host
    CompromiseHost {
        target_host: String,
    },
    /// Extract domain credential database (NTDS.dit)
    DumpNtds {
        target_dc: Option<String>,
    },
    /// Establish persistent access via golden/silver ticket
    Persistence {
        method: PersistenceMethod,
    },
    /// Full domain enumeration only (no exploitation)
    ReconOnly,
    /// Custom goal with freeform success criteria
    Custom {
        description: String,
        success_check: String,
    },
}

impl AttackGoal {
    /// Human-readable description of the goal
    pub fn describe(&self) -> String {
        match self {
            Self::DomainAdmin { target_group } => {
                format!("Achieve {} privileges", target_group)
            }
            Self::CompromiseUser { target_user } => {
                format!("Compromise user: {}", target_user)
            }
            Self::CompromiseHost { target_host } => {
                format!("Gain admin on: {}", target_host)
            }
            Self::DumpNtds { target_dc } => {
                let dc = target_dc.as_deref().unwrap_or("any DC");
                format!("Dump NTDS.dit from {}", dc)
            }
            Self::Persistence { method } => {
                format!("Establish persistence via {:?}", method)
            }
            Self::ReconOnly => "Full domain reconnaissance".to_string(),
            Self::Custom { description, .. } => description.clone(),
        }
    }

    /// Check if this goal requires DA-level access at some point
    pub fn requires_da(&self) -> bool {
        matches!(
            self,
            Self::DomainAdmin { .. }
                | Self::DumpNtds { .. }
                | Self::Persistence {
                    method: PersistenceMethod::GoldenTicket
                }
        )
    }

    /// Minimum stage needed before this goal can be evaluated
    pub fn minimum_stage(&self) -> super::runner::Stage {
        match self {
            Self::ReconOnly => super::runner::Stage::Enumerate,
            Self::DomainAdmin { .. } => super::runner::Stage::Escalate,
            Self::CompromiseUser { .. } => super::runner::Stage::Attack,
            Self::CompromiseHost { .. } => super::runner::Stage::Lateral,
            Self::DumpNtds { .. } => super::runner::Stage::Loot,
            Self::Persistence { .. } => super::runner::Stage::Loot,
            Self::Custom { .. } => super::runner::Stage::Attack,
        }
    }
}

impl std::fmt::Display for AttackGoal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.describe())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistenceMethod {
    GoldenTicket,
    SilverTicket,
    Skeleton,
    DCShadow,
    AdminSDHolder,
}

// ═══════════════════════════════════════════════════════════
// Goal Status / Evaluation
// ═══════════════════════════════════════════════════════════

/// Current status of a goal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalStatus {
    /// Not yet attempted
    Pending,
    /// Currently being worked on
    InProgress,
    /// Goal achieved
    Achieved,
    /// Goal failed, but alternative paths may exist
    Blocked { reason: String },
    /// Goal definitively failed — no remaining paths
    Failed { reason: String },
    /// Skipped (dry-run or dependency not met)
    Skipped,
}

impl GoalStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Achieved | Self::Failed { .. } | Self::Skipped)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Achieved)
    }
}

impl std::fmt::Display for GoalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "{}", "PENDING".dimmed()),
            Self::InProgress => write!(f, "{}", "IN PROGRESS".yellow()),
            Self::Achieved => write!(f, "{}", "ACHIEVED".green().bold()),
            Self::Blocked { reason } => write!(f, "{} ({})", "BLOCKED".yellow(), reason),
            Self::Failed { reason } => write!(f, "{} ({})", "FAILED".red(), reason),
            Self::Skipped => write!(f, "{}", "SKIPPED".dimmed()),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Engagement State — everything we know so far
// ═══════════════════════════════════════════════════════════

/// Accumulated knowledge from the engagement — updated after each step
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngagementState {
    /// Domain info
    pub domain: Option<String>,
    pub dc_ip: Option<String>,
    pub dc_hostname: Option<String>,

    /// Discovered users
    pub users: Vec<DiscoveredUser>,
    /// Discovered computers
    pub computers: Vec<DiscoveredComputer>,
    /// Discovered groups and memberships
    pub groups: HashMap<String, Vec<String>>,

    /// Compromised credentials (username → secret)
    pub credentials: HashMap<String, CompromisedCred>,
    /// Hosts with confirmed admin access
    pub admin_hosts: HashSet<String>,

    /// Kerberoastable accounts (SPN users)
    pub kerberoastable: Vec<String>,
    /// AS-REP roastable accounts
    pub asrep_roastable: Vec<String>,
    /// Cracked hashes (username → plaintext)
    pub cracked: HashMap<String, String>,

    /// Delegation findings
    pub constrained_delegation: Vec<DelegationInfo>,
    pub unconstrained_delegation: Vec<String>,
    pub rbcd_targets: Vec<String>,

    /// Whether we currently hold DA-equivalent privileges
    pub has_domain_admin: bool,
    /// The user we achieved DA with (if any)
    pub da_user: Option<String>,

    /// Collected loot (NTDS dump, SAM, LSA secrets, etc.)
    pub loot: Vec<LootItem>,
    /// All actions taken (for audit trail)
    pub action_log: Vec<ActionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredUser {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub admin_count: bool,
    pub has_spn: bool,
    pub dont_req_preauth: bool,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredComputer {
    pub sam_account_name: String,
    pub dns_hostname: Option<String>,
    pub operating_system: Option<String>,
    pub unconstrained_delegation: bool,
    pub is_dc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompromisedCred {
    pub username: String,
    pub secret: String,
    pub secret_type: SecretType,
    pub source: String,
    pub is_admin: bool,
    pub admin_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    Password,
    NtHash,
    AesKey,
    Ticket,
    Dcc2,
}

// ─── Display impl for SecretType (fixes E0277 in autopwn.rs) ───
impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::NtHash => write!(f, "nthash"),
            Self::AesKey => write!(f, "aeskey"),
            Self::Ticket => write!(f, "ticket"),
            Self::Dcc2 => write!(f, "dcc2"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationInfo {
    pub account: String,
    pub delegation_type: String,
    pub targets: Vec<String>,
    pub protocol_transition: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LootItem {
    pub loot_type: String,
    pub source: String,
    pub path: Option<String>,
    pub entries: usize,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogEntry {
    pub timestamp: DateTime<Utc>,
    pub stage: String,
    pub action: String,
    pub target: String,
    pub success: bool,
    pub detail: String,
}

/// Summary statistics for engagement state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateStats {
    pub total_users: usize,
    pub total_computers: usize,
    pub total_groups: usize,
    pub credentials_obtained: usize,
    pub admin_hosts: usize,
    pub kerberoastable: usize,
    pub asrep_roastable: usize,
    pub cracked_passwords: usize,
    pub domain_admin: bool,
    pub da_user: Option<String>,
    pub actions_logged: usize,
    pub loot_items: usize,
}

impl std::fmt::Display for StateStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Users: {} | Computers: {} | Groups: {}", 
            self.total_users, self.total_computers, self.total_groups)?;
        writeln!(f, "Credentials: {} | Admin Hosts: {}", 
            self.credentials_obtained, self.admin_hosts)?;
        writeln!(f, "Kerberoast: {} | AS-REP: {} | Cracked: {}", 
            self.kerberoastable, self.asrep_roastable, self.cracked_passwords)?;
        writeln!(f, "Domain Admin: {} ({})", 
            if self.domain_admin { "YES" } else { "NO" },
            self.da_user.as_deref().unwrap_or("N/A"))?;
        writeln!(f, "Actions: {} | Loot: {}", 
            self.actions_logged, self.loot_items)
    }
}

impl EngagementState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Save state to a JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load state from a JSON file
    pub fn load_from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(state)
    }

    /// Auto-save to default location (engagement_state.json)
    pub fn auto_save(&self) {
        let path = std::path::Path::new("engagement_state.json");
        if let Err(e) = self.save_to_file(path) {
            warn!("Failed to auto-save state: {}", e);
        } else {
            debug!("State auto-saved to engagement_state.json");
        }
    }

    /// Merge credentials from another state (useful for checkpoint loading)
    pub fn merge_credentials(&mut self, other: &Self) {
        for (user, cred) in &other.credentials {
            if !self.credentials.contains_key(user) {
                self.credentials.insert(user.clone(), cred.clone());
            }
        }
        for host in &other.admin_hosts {
            self.admin_hosts.insert(host.clone());
        }
        if other.has_domain_admin && !self.has_domain_admin {
            self.has_domain_admin = true;
            self.da_user = other.da_user.clone();
        }
    }

    /// Get statistics summary for reporting
    pub fn stats_summary(&self) -> StateStats {
        StateStats {
            total_users: self.users.len(),
            total_computers: self.computers.len(),
            total_groups: self.groups.len(),
            credentials_obtained: self.credentials.len(),
            admin_hosts: self.admin_hosts.len(),
            kerberoastable: self.kerberoastable.len(),
            asrep_roastable: self.asrep_roastable.len(),
            cracked_passwords: self.cracked.len(),
            domain_admin: self.has_domain_admin,
            da_user: self.da_user.clone(),
            actions_logged: self.action_log.len(),
            loot_items: self.loot.len(),
        }
    }

    /// Log an action to the audit trail
    pub fn log_action(
        &mut self,
        stage: &str,
        action: &str,
        target: &str,
        success: bool,
        detail: &str,
    ) {
        self.action_log.push(ActionLogEntry {
            timestamp: Utc::now(),
            stage: stage.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            success,
            detail: detail.to_string(),
        });
    }

    /// Add a compromised credential
    pub fn add_credential(&mut self, cred: CompromisedCred) {
        info!(
            " {} New credential: {}:{} ({})",
            "🔑".green(),
            cred.username.bold(),
            if cred.secret_type == SecretType::Password {
                "***"
            } else {
                &cred.secret[..8.min(cred.secret.len())]
            },
            cred.secret_type.to_string().dimmed()
        );
        self.credentials.insert(cred.username.clone(), cred);
    }

    /// Check if we have any admin-level credentials
    pub fn has_any_admin(&self) -> bool {
        self.credentials.values().any(|c| c.is_admin)
    }

    /// Get the best credential we currently hold (prefer admin, then DA)
    pub fn best_credential(&self) -> Option<&CompromisedCred> {
        // Prefer DA creds
        if let Some(cred) = self.credentials.values().find(|c| {
            c.is_admin
                && self
                    .groups
                    .get("Domain Admins")
                    .map(|members| members.contains(&c.username))
                    .unwrap_or(false)
        }) {
            return Some(cred);
        }
        // Then any admin cred
        if let Some(cred) = self.credentials.values().find(|c| c.is_admin) {
            return Some(cred);
        }
        // Then any cred at all
        self.credentials.values().next()
    }

    /// Check if goal is achieved based on current state
    pub fn evaluate_goal(&self, goal: &AttackGoal) -> GoalStatus {
        match goal {
            AttackGoal::DomainAdmin { target_group: _ } => {
                if self.has_domain_admin {
                    GoalStatus::Achieved
                } else if self.credentials.is_empty() {
                    GoalStatus::Pending
                } else {
                    GoalStatus::InProgress
                }
            }
            AttackGoal::CompromiseUser { target_user } => {
                if self.credentials.contains_key(target_user) {
                    GoalStatus::Achieved
                } else {
                    GoalStatus::InProgress
                }
            }
            AttackGoal::CompromiseHost { target_host } => {
                if self.admin_hosts.contains(target_host) {
                    GoalStatus::Achieved
                } else {
                    GoalStatus::InProgress
                }
            }
            AttackGoal::DumpNtds { .. } => {
                if self.loot.iter().any(|l| l.loot_type == "NTDS") {
                    GoalStatus::Achieved
                } else {
                    GoalStatus::InProgress
                }
            }
            AttackGoal::ReconOnly => {
                if !self.users.is_empty() && !self.computers.is_empty() {
                    GoalStatus::Achieved
                } else {
                    GoalStatus::InProgress
                }
            }
            AttackGoal::Persistence { .. } => GoalStatus::InProgress,
            AttackGoal::Custom { .. } => GoalStatus::InProgress,
        }
    }

    /// Pretty-print current state summary
    pub fn print_summary(&self) {
        println!("\n{}", "═══ ENGAGEMENT STATE ═══".bold().cyan());
        println!(
            "  Domain:      {}",
            self.domain.as_deref().unwrap_or("unknown")
        );
        println!("  Users:       {}", self.users.len());
        println!("  Computers:   {}", self.computers.len());
        println!("  Credentials: {}", self.credentials.len().to_string().green());
        println!("  Admin hosts: {}", self.admin_hosts.len().to_string().yellow());
        println!(
            "  Kerberoast:  {} | AS-REP: {}",
            self.kerberoastable.len(),
            self.asrep_roastable.len()
        );
        println!(
            "  Domain Admin: {}",
            if self.has_domain_admin {
                format!("YES ({})", self.da_user.as_deref().unwrap_or("?"))
                    .green()
                    .bold()
                    .to_string()
            } else {
                "NO".red().to_string()
            }
        );
        println!("  Actions:     {}", self.action_log.len());
        println!("{}\n", "════════════════════════".cyan());
    }
}
