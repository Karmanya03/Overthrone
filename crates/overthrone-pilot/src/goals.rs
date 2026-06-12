//! Attack goals — Define what the pilot is trying to achieve.
//!
//! Goals are high-level objectives like "become Domain Admin" or
//! "dump NTDS.dit". Each goal has success criteria that can be
//! evaluated against the current engagement state.

use crate::dc_verify::DcVerificationSummary;
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
#[allow(missing_docs)]
pub enum AttackGoal {
    /// Achieve membership/token for a target group (default: "Domain Admins")
    DomainAdmin { target_group: String },
    /// Obtain credentials for a specific user
    CompromiseUser { target_user: String },
    /// Gain admin access to a specific host
    CompromiseHost { target_host: String },
    /// Extract domain credential database (NTDS.dit)
    DumpNtds { target_dc: Option<String> },
    /// Establish persistent access via golden/silver ticket
    Persistence { method: PersistenceMethod },
    /// Full domain enumeration only (no exploitation)
    ReconOnly,
    /// Custom goal with freeform success criteria
    Custom {
        description: String,
        success_check: String,
    },
}

fn non_zero_windows_time(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed != "0" && trimmed != "never"
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
    /// `GoldenTicket` variant
    GoldenTicket,
    /// `SilverTicket` variant
    SilverTicket,
    /// `Skeleton` variant
    Skeleton,
    /// `DCShadow` variant
    DCShadow,
    /// `AdminSDHolder` variant
    AdminSDHolder,
}

// ═══════════════════════════════════════════════════════════
// Goal Status / Evaluation
// ═══════════════════════════════════════════════════════════

/// Current status of a goal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
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
    /// Domain controller IP address
    pub dc_ip: Option<String>,
    /// Object or account name.
    pub dc_hostname: Option<String>,

    /// Discovered users
    pub users: Vec<DiscoveredUser>,
    /// Discovered computers
    pub computers: Vec<DiscoveredComputer>,
    /// Discovered groups and memberships
    pub groups: HashMap<String, Vec<String>>,

    /// Compromised credentials (username -> secret)
    pub credentials: HashMap<String, CompromisedCred>,
    /// Hosts with confirmed admin access
    pub admin_hosts: HashSet<String>,

    /// Kerberoastable accounts (SPN users)
    pub kerberoastable: Vec<String>,
    /// SPN map: sam_account_name -> list of SPNs (for kerberoast)
    pub spn_map: HashMap<String, Vec<String>>,
    /// AS-REP roastable accounts
    pub asrep_roastable: Vec<String>,
    /// Cracked hashes (username -> plaintext)
    pub cracked: HashMap<String, String>,
    /// Captured but not-yet-cracked hashes (hashcat-format strings)
    pub roast_hashes: Vec<String>,

    /// Domain trusts
    pub trusts: Vec<String>,
    /// Discovered GPOs
    pub gpos: Vec<String>,
    /// Parsed GPO details useful for planning and reporting
    #[serde(default)]
    pub gpo_details: Vec<GpoInfo>,
    /// Domain password/lockout policy
    #[serde(default)]
    pub password_policy: Option<PasswordPolicyInfo>,
    /// LAPS passwords readable by the current credential
    #[serde(default)]
    pub laps: Vec<LapsInfo>,

    /// Delegation findings
    pub constrained_delegation: Vec<DelegationInfo>,
    /// unconstrained delegation field
    pub unconstrained_delegation: Vec<String>,
    /// rbcd targets field
    pub rbcd_targets: Vec<String>,

    /// Whether we currently hold DA-equivalent privileges
    pub has_domain_admin: bool,
    /// The user we achieved DA with (if any)
    pub da_user: Option<String>,

    /// Collected loot (NTDS dump, SAM, LSA secrets, etc.)
    pub loot: Vec<LootItem>,
    /// All actions taken (for audit trail)
    pub action_log: Vec<ActionLogEntry>,
    /// DC verification results (hostile DC detection)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dc_verification: Option<DcVerificationSummary>,
}
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveredUser {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Item count
    pub admin_count: bool,
    /// Service Principal Name
    pub has_spn: bool,
    /// dont req preauth field
    pub dont_req_preauth: bool,
    /// enabled field
    pub enabled: bool,
    /// description field
    pub description: Option<String>,
    /// Item count
    #[serde(default)]
    pub bad_pwd_count: Option<u32>,
    /// bad pwd time field
    #[serde(default)]
    pub bad_pwd_time: Option<String>,
    /// lockout time field
    #[serde(default)]
    pub lockout_time: Option<String>,
    /// Item count
    #[serde(default)]
    pub logon_count: Option<u32>,
    /// pwd last set field
    #[serde(default)]
    pub pwd_last_set: Option<String>,
    /// last logon timestamp field
    #[serde(default)]
    pub last_logon_timestamp: Option<String>,
    /// Object or account name.
    #[serde(default)]
    pub user_principal_name: Option<String>,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredComputer {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub dns_hostname: Option<String>,
    /// operating system field
    pub operating_system: Option<String>,
    /// unconstrained delegation field
    pub unconstrained_delegation: bool,
    /// is dc field
    pub is_dc: bool,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompromisedCred {
    /// Username for authentication
    pub username: String,
    /// Secret value
    pub secret: String,
    /// Classification for this object.
    pub secret_type: SecretType,
    /// Source domain FQDN
    pub source: String,
    /// is admin field
    pub is_admin: bool,
    /// admin on field
    pub admin_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    /// `Password` variant
    Password,
    /// `NtHash` variant
    NtHash,
    /// `AesKey` variant
    AesKey,
    /// `Ticket` variant
    Ticket,
    /// `Dcc2` variant
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
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationInfo {
    /// Item count
    pub account: String,
    /// Classification for this object.
    pub delegation_type: String,
    /// targets field
    pub targets: Vec<String>,
    /// Network protocol variant
    pub protocol_transition: bool,
}
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasswordPolicyInfo {
    /// Password for authentication
    pub min_password_length: Option<u32>,
    /// lockout threshold field
    pub lockout_threshold: Option<u32>,
    /// lockout duration field
    pub lockout_duration: Option<String>,
    /// lockout observation window field
    pub lockout_observation_window: Option<String>,
    /// Password for authentication
    pub max_password_age: Option<String>,
    /// Password for authentication
    pub min_password_age: Option<String>,
    /// Password for authentication
    pub password_history_length: Option<u32>,
    /// Password for authentication
    pub password_complexity_enabled: bool,
    /// reversible encryption enabled field
    pub reversible_encryption_enabled: bool,
    /// Item count
    pub fine_grained_policy_count: usize,
}
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpoInfo {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub distinguished_name: Option<String>,
    /// Filesystem path.
    pub sysvol_path: Option<String>,
    /// flags field
    pub flags: Option<u32>,
    /// version field
    pub version: Option<u32>,
    /// when changed field
    pub when_changed: Option<String>,
    /// user settings disabled field
    pub user_settings_disabled: bool,
    /// computer settings disabled field
    pub computer_settings_disabled: bool,
}
/// Structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LapsInfo {
    /// Object or account name.
    pub computer_name: String,
    /// Object or account name.
    pub dns_name: Option<String>,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: Option<String>,
    /// expiration field
    pub expiration: Option<String>,
    /// Source domain FQDN
    pub source: String,
    /// readable field
    pub readable: bool,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LootItem {
    /// Classification for this object.
    pub loot_type: String,
    /// Source domain FQDN
    pub source: String,
    /// Filesystem path.
    pub path: Option<String>,
    /// entries field
    pub entries: usize,
    /// collected at field
    pub collected_at: DateTime<Utc>,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogEntry {
    /// timestamp field
    pub timestamp: DateTime<Utc>,
    /// stage field
    pub stage: String,
    /// action field
    pub action: String,
    /// Target domain FQDN
    pub target: String,
    /// success field
    pub success: bool,
    /// detail field
    pub detail: String,
}

/// Summary statistics for engagement state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateStats {
    /// Total count
    pub total_users: usize,
    /// Total count
    pub total_computers: usize,
    /// Total count
    pub total_groups: usize,
    /// credentials obtained field
    pub credentials_obtained: usize,
    /// admin hosts field
    pub admin_hosts: usize,
    /// kerberoastable field
    pub kerberoastable: usize,
    /// asrep roastable field
    pub asrep_roastable: usize,
    /// Password for authentication
    pub cracked_passwords: usize,
    /// Domain FQDN
    pub domain_admin: bool,
    /// da user field
    pub da_user: Option<String>,
    /// actions logged field
    pub actions_logged: usize,
    /// loot items field
    pub loot_items: usize,
    /// locked or near lockout field
    pub locked_or_near_lockout: usize,
    /// readable laps field
    pub readable_laps: usize,
    /// delegation findings field
    pub delegation_findings: usize,
    /// Password for authentication
    pub password_policy_known: bool,
}

impl std::fmt::Display for StateStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Users: {} | Computers: {} | Groups: {}",
            self.total_users, self.total_computers, self.total_groups
        )?;
        writeln!(
            f,
            "Credentials: {} | Admin Hosts: {}",
            self.credentials_obtained, self.admin_hosts
        )?;
        writeln!(
            f,
            "Kerberoast: {} | AS-REP: {} | Cracked: {}",
            self.kerberoastable, self.asrep_roastable, self.cracked_passwords
        )?;
        writeln!(
            f,
            "Domain Admin: {} ({})",
            if self.domain_admin { "YES" } else { "NO" },
            self.da_user.as_deref().unwrap_or("N/A")
        )?;
        writeln!(
            f,
            "Actions: {} | Loot: {}",
            self.actions_logged, self.loot_items
        )?;
        writeln!(
            f,
            "Policy: {} | LAPS: {} | Delegation findings: {} | Lockout-risk users: {}",
            if self.password_policy_known {
                "known"
            } else {
                "unknown"
            },
            self.readable_laps,
            self.delegation_findings,
            self.locked_or_near_lockout
        )
    }
}

impl DiscoveredUser {
    pub fn is_locked_out(&self) -> bool {
        self.lockout_time
            .as_deref()
            .map(non_zero_windows_time)
            .unwrap_or(false)
    }

    pub fn is_near_lockout(&self, threshold: Option<u32>) -> bool {
        match (self.bad_pwd_count, threshold) {
            (Some(count), Some(threshold)) if threshold > 0 => count + 1 >= threshold,
            _ => false,
        }
    }

    pub fn can_be_sprayed(&self, threshold: Option<u32>) -> bool {
        self.enabled && !self.is_locked_out() && !self.is_near_lockout(threshold)
    }
}

impl EngagementState {
    /// Runs this module operation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Save state to a JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load state from a JSON file
    pub fn load_from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&json).map_err(std::io::Error::other)?;
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
            locked_or_near_lockout: self.users_near_lockout(),
            readable_laps: self.readable_laps_count(),
            delegation_findings: self.delegation_count(),
            password_policy_known: self.password_policy.is_some(),
        }
    }

    pub fn lockout_threshold(&self) -> Option<u32> {
        self.password_policy
            .as_ref()
            .and_then(|policy| policy.lockout_threshold)
            .filter(|threshold| *threshold > 0)
    }

    pub fn users_near_lockout(&self) -> usize {
        let threshold = self.lockout_threshold();
        self.users
            .iter()
            .filter(|user| user.is_locked_out() || user.is_near_lockout(threshold))
            .count()
    }

    pub fn safe_spray_candidates(&self) -> Vec<String> {
        let threshold = self.lockout_threshold();
        self.users
            .iter()
            .filter(|user| user.can_be_sprayed(threshold))
            .map(|user| user.sam_account_name.clone())
            .collect()
    }

    pub fn spray_guard_allows_attempts(&self) -> bool {
        matches!(self.lockout_threshold(), Some(threshold) if threshold > 1)
            && !self.safe_spray_candidates().is_empty()
    }

    pub fn spray_risk_summary(&self) -> String {
        let threshold = self.lockout_threshold();
        let safe = self
            .users
            .iter()
            .filter(|user| user.can_be_sprayed(threshold))
            .count();
        let risky = self.users.len().saturating_sub(safe);
        match threshold {
            Some(threshold) => {
                format!("{safe} safe users, {risky} skipped near/at lockout, threshold={threshold}")
            }
            None => "spray disabled until password/lockout policy is known".to_string(),
        }
    }

    pub fn readable_laps_count(&self) -> usize {
        self.laps.iter().filter(|entry| entry.readable).count()
    }

    pub fn delegation_count(&self) -> usize {
        self.constrained_delegation.len()
            + self.unconstrained_delegation.len()
            + self.rbcd_targets.len()
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
            "ðŸ”‘".green(),
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
            AttackGoal::Persistence { method } => {
                let target_loot = match method {
                    PersistenceMethod::GoldenTicket => "GoldenTicket",
                    PersistenceMethod::SilverTicket => "SilverTicket",
                    PersistenceMethod::Skeleton => "Skeleton",
                    PersistenceMethod::DCShadow => "DCShadow",
                    PersistenceMethod::AdminSDHolder => "AdminSDHolder",
                };
                if self.loot.iter().any(|l| l.loot_type == target_loot) {
                    GoalStatus::Achieved
                } else if self.has_domain_admin || !self.credentials.is_empty() {
                    GoalStatus::InProgress
                } else {
                    GoalStatus::Pending
                }
            }
            AttackGoal::Custom { .. } => {
                // Custom goals: achieved if we have any credentials and admin hosts
                if !self.credentials.is_empty() && !self.admin_hosts.is_empty() {
                    GoalStatus::Achieved
                } else if !self.credentials.is_empty() || !self.users.is_empty() {
                    GoalStatus::InProgress
                } else {
                    GoalStatus::Pending
                }
            }
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
        println!(
            "  Credentials: {}",
            self.credentials.len().to_string().green()
        );
        println!(
            "  Admin hosts: {}",
            self.admin_hosts.len().to_string().yellow()
        );
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
        println!(
            "  Policy:      {} | LAPS: {} | Delegation: {}",
            if self.password_policy.is_some() {
                "known"
            } else {
                "unknown"
            },
            self.readable_laps_count(),
            self.delegation_count()
        );
        println!(
            "  Spray Guard: {}",
            self.spray_risk_summary().bright_black()
        );
        println!("{}\n", "════════════════════════".cyan());
    }
}
