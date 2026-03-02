//! Attack planner — Build ordered attack plans from the current
//! engagement state toward a goal using a scoring/priority system.
//!
//! The planner evaluates what's known, what's been tried, and what
//! attack paths remain viable — then produces an ordered plan.

use crate::goals::{AttackGoal, EngagementState, GoalStatus};
use crate::playbook::PlaybookId;
use crate::runner::Stage;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Plan Types
// ═══════════════════════════════════════════════════════════

/// An ordered sequence of attack steps to reach the goal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlan {
    pub goal: String,
    pub steps: Vec<PlanStep>,
    pub estimated_noise: NoiseLevel,
    pub requires_interaction: bool,
}

/// A single step in the attack plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    /// Unique step identifier
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Which stage this step belongs to
    pub stage: Stage,
    /// The specific action to execute
    pub action: PlannedAction,
    /// Priority score (higher = try first)
    pub priority: i32,
    /// Estimated noise level
    pub noise: NoiseLevel,
    /// Steps that must complete before this one
    pub depends_on: Vec<String>,
    /// Has this step been executed?
    pub executed: bool,
    /// Result of execution (if executed)
    pub result: Option<StepResult>,
    /// Number of times this step has been retried
    pub retries: u32,
    /// Maximum retries before giving up
    pub max_retries: u32,
}

/// Specific action the executor should perform
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannedAction {
    // ── Recon ──
    EnumerateUsers,
    EnumerateComputers,
    EnumerateGroups,
    EnumerateTrusts,
    EnumerateGpos,
    EnumerateShares { target: String },
    CheckAdminAccess { targets: Vec<String> },

    // ── Kerberos Attacks ──
    AsRepRoast { users: Vec<String> },
    Kerberoast { spns: Vec<String> },
    ConstrainedDelegation { account: String, target_spn: String, impersonate: String },
    UnconstrainedDelegation { target_host: String },
    RbcdAttack { controlled: String, target: String },

    // ── Credential Attacks ──
    PasswordSpray { users: Vec<String>, password: String },
    CrackHashes { hashes: Vec<String> },

    // ── Lateral Movement ──
    ExecCommand { target: String, command: String, method: String },
    PsExec { target: String, command: String },
    SmbExec { target: String, command: String },
    WmiExec { target: String, command: String },
    WinRmExec { target: String, command: String },

    // ── Credential Dumping ──
    DumpSam { target: String },
    DumpLsa { target: String },
    DumpNtds { target: String },
    DumpDcc2 { target: String },
    DcsSync { target_user: Option<String> },

    // ── Coercion ──
    Coerce { target: String, listener: String },

    // ── ADCS ──
    AdcsEnumerate,
    AdcsEsc1 { template: String, ca: String, target_upn: String },
    AdcsEsc4 { template: String },
    AdcsEsc6 { template: String, ca: String, target_upn: String },

    // ── Persistence ──
    ForgeGoldenTicket { krbtgt_hash: String },
    ForgeSilverTicket { service_hash: String, spn: String },

    // ── Playbook ──
    RunPlaybook { playbook_id: PlaybookId },

    // ── Utility ──
    Sleep { seconds: u64 },
    Checkpoint { message: String },
}

/// Result of executing a step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub success: bool,
    pub output: String,
    pub new_credentials: usize,
    pub new_admin_hosts: usize,
}

/// Estimated noise/detection risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NoiseLevel {
    /// Passive / read-only LDAP queries
    Silent,
    /// Normal authentication, benign-looking traffic
    Low,
    /// Service creation, WMI, potentially logged actions
    Medium,
    /// Password spraying, mass scanning, obvious attack patterns
    High,
    /// NTDS dump, DC replication, golden ticket — very loud
    Critical,
}

impl std::fmt::Display for NoiseLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Silent => write!(f, "{}", "SILENT".dimmed()),
            Self::Low => write!(f, "{}", "LOW".green()),
            Self::Medium => write!(f, "{}", "MEDIUM".yellow()),
            Self::High => write!(f, "{}", "HIGH".red()),
            Self::Critical => write!(f, "{}", "CRITICAL".red().bold()),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Planner
// ═══════════════════════════════════════════════════════════

/// The attack planner — builds plans from state + goal
pub struct Planner {
    stealth: bool,
    max_noise: NoiseLevel,
    /// Maximum total steps before bail-out
    max_steps: usize,
}

impl Planner {
    pub fn new(stealth: bool) -> Self {
        Self {
            stealth,
            max_noise: if stealth {
                NoiseLevel::Medium
            } else {
                NoiseLevel::Critical
            },
            max_steps: 60,
        }
    }

    /// Build an attack plan for the given goal based on current state
    pub fn plan(
        &self,
        goal: &AttackGoal,
        state: &EngagementState,
        failed_actions: &[String],
    ) -> AttackPlan {
        info!(
            "{} Planning attack: {}",
            "PLAN".bold().blue(),
            goal.describe().bold()
        );

        let mut steps = Vec::new();
        let mut step_counter = 0u32;
        let mut next_id = || {
            step_counter += 1;
            format!("step_{:03}", step_counter)
        };

        // ── Phase 1: Recon (always needed if state is empty) ──
        if state.users.is_empty() {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate domain users".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateUsers,
                priority: 100,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 2,
            });
        }

        if state.computers.is_empty() {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate domain computers".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateComputers,
                priority: 99,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 2,
            });
        }

        if state.groups.is_empty() {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate groups & memberships".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateGroups,
                priority: 98,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 2,
            });
        }

        // If goal is recon-only, stop here
        if matches!(goal, AttackGoal::ReconOnly) {
            return self.finalize_plan(goal, steps);
        }

        // ── Phase 2: Kerberos Attacks (low noise, high reward) ──
        let recon_dep = steps
            .first()
            .map(|s| s.id.clone())
            .unwrap_or_default();

        if state.kerberoastable.is_empty() && !failed_actions.contains(&"kerberoast".to_string()) {
            let kerb_id = next_id();
            steps.push(PlanStep {
                id: kerb_id.clone(),
                description: "Kerberoast — extract TGS hashes for offline cracking".to_string(),
                stage: Stage::Attack,
                action: PlannedAction::Kerberoast { spns: vec![] },
                priority: 90,
                noise: NoiseLevel::Low,
                depends_on: if recon_dep.is_empty() {
                    vec![]
                } else {
                    vec![recon_dep.clone()]
                },
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
            });
        }

        if state.asrep_roastable.is_empty()
            && !failed_actions.contains(&"asreproast".to_string())
        {
            steps.push(PlanStep {
                id: next_id(),
                description: "AS-REP Roast — extract hashes for no-preauth accounts".to_string(),
                stage: Stage::Attack,
                action: PlannedAction::AsRepRoast { users: vec![] },
                priority: 88,
                noise: NoiseLevel::Low,
                depends_on: if recon_dep.is_empty() {
                    vec![]
                } else {
                    vec![recon_dep.clone()]
                },
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
            });
        }

        // ── Phase 2.5: ADCS Certificate Abuse ──
        if !failed_actions.contains(&"adcs_enum".to_string()) {
            let adcs_enum_id = next_id();
            steps.push(PlanStep {
                id: adcs_enum_id.clone(),
                description: "ADCS — enumerate certificate templates & CAs".to_string(),
                stage: Stage::Attack,
                action: PlannedAction::AdcsEnumerate,
                priority: 87,
                noise: NoiseLevel::Silent,
                depends_on: if recon_dep.is_empty() {
                    vec![]
                } else {
                    vec![recon_dep.clone()]
                },
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
            });

            // ESC1 — enrollee supplies SAN (most common ADCS vuln)
            if !failed_actions.contains(&"adcs_esc1".to_string()) {
                steps.push(PlanStep {
                    id: next_id(),
                    description:
                        "ADCS ESC1 — request cert with arbitrary SAN for impersonation"
                            .to_string(),
                    stage: Stage::Attack,
                    action: PlannedAction::AdcsEsc1 {
                        template: String::new(),
                        ca: String::new(),
                        target_upn: String::new(),
                    },
                    priority: 86,
                    noise: NoiseLevel::Low,
                    depends_on: vec![adcs_enum_id.clone()],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                });
            }

            // ESC4 — writable template → make it ESC1-vulnerable
            if !failed_actions.contains(&"adcs_esc4".to_string()) {
                steps.push(PlanStep {
                    id: next_id(),
                    description:
                        "ADCS ESC4 — modify writable template then exploit as ESC1"
                            .to_string(),
                    stage: Stage::Attack,
                    action: PlannedAction::AdcsEsc4 {
                        template: String::new(),
                    },
                    priority: 84,
                    noise: NoiseLevel::Medium,
                    depends_on: vec![adcs_enum_id.clone()],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                });
            }

            // ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
            if !failed_actions.contains(&"adcs_esc6".to_string()) {
                steps.push(PlanStep {
                    id: next_id(),
                    description:
                        "ADCS ESC6 — abuse EDITF_ATTRIBUTESUBJECTALTNAME2 for SAN injection"
                            .to_string(),
                    stage: Stage::Attack,
                    action: PlannedAction::AdcsEsc6 {
                        template: String::new(),
                        ca: String::new(),
                        target_upn: String::new(),
                    },
                    priority: 83,
                    noise: NoiseLevel::Low,
                    depends_on: vec![adcs_enum_id],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                });
            }
        }

        // ── Phase 3: Delegation Abuse ──
        if !failed_actions.contains(&"constrained_delegation".to_string()) {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate & abuse constrained delegation".to_string(),
                stage: Stage::Attack,
                action: PlannedAction::ConstrainedDelegation {
                    account: String::new(),
                    target_spn: String::new(),
                    impersonate: "Administrator".to_string(),
                },
                priority: 85,
                noise: NoiseLevel::Low,
                depends_on: if recon_dep.is_empty() {
                    vec![]
                } else {
                    vec![recon_dep.clone()]
                },
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
            });
        }

        // ── Phase 4: Admin Access Check ──
        if !state.computers.is_empty() && state.admin_hosts.is_empty() {
            let targets: Vec<String> = state
                .computers
                .iter()
                .filter_map(|c| c.dns_hostname.clone())
                .collect();
            if !targets.is_empty() {
                steps.push(PlanStep {
                    id: next_id(),
                    description: format!("Check admin access on {} hosts", targets.len()),
                    stage: Stage::Lateral,
                    action: PlannedAction::CheckAdminAccess { targets },
                    priority: 80,
                    noise: NoiseLevel::Medium,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                });
            }
        }

        // ── Phase 4.5: RBCD Attack (if we have a controlled computer & write access) ──
        if !state.rbcd_targets.is_empty()
            && !failed_actions.contains(&"rbcd".to_string())
        {
            for target in &state.rbcd_targets {
                // Use the first discovered computer we control (or our own machine account)
                let controlled = state
                    .credentials
                    .values()
                    .find(|c| c.username.ends_with('$'))
                    .map(|c| c.username.clone())
                    .unwrap_or_default();
                if !controlled.is_empty() {
                    steps.push(PlanStep {
                        id: next_id(),
                        description: format!("RBCD: {} → {}", controlled, target),
                        stage: Stage::Attack,
                        action: PlannedAction::RbcdAttack {
                            controlled: controlled.clone(),
                            target: target.clone(),
                        },
                        priority: 78,
                        noise: NoiseLevel::Medium,
                        depends_on: vec![],
                        executed: false,
                        result: None,
                        retries: 0,
                        max_retries: 1,
                    });
                }
            }
        }

        // ── Phase 5: Lateral Movement (if we have admin creds) ──
        if state.has_any_admin() && !state.admin_hosts.is_empty() {
            // Try to reach a DC
            if let Some(dc) = state.computers.iter().find(|c| c.is_dc) {
                let dc_target = dc
                    .dns_hostname
                    .clone()
                    .unwrap_or_else(|| dc.sam_account_name.trim_end_matches('$').to_string());

                if !self.stealth || self.max_noise >= NoiseLevel::Medium {
                    steps.push(PlanStep {
                        id: next_id(),
                        description: format!("Exec on DC: {}", dc_target),
                        stage: Stage::Lateral,
                        action: PlannedAction::SmbExec {
                            target: dc_target.clone(),
                            command: "whoami".to_string(),
                        },
                        priority: 75,
                        noise: NoiseLevel::Medium,
                        depends_on: vec![],
                        executed: false,
                        result: None,
                        retries: 0,
                        max_retries: 2,
                    });
                }
            }
        }

        // ── Phase 6: Credential Dumping (escalation path) ──
        if goal.requires_da() && !state.has_domain_admin {
            // If we have admin on any host, try dumping SAM/LSA for more creds
            for host in &state.admin_hosts {
                if !failed_actions.contains(&format!("dump_lsa_{}", host)) {
                    steps.push(PlanStep {
                        id: next_id(),
                        description: format!("Dump LSA secrets from {}", host),
                        stage: Stage::Escalate,
                        action: PlannedAction::DumpLsa {
                            target: host.clone(),
                        },
                        priority: 70,
                        noise: NoiseLevel::High,
                        depends_on: vec![],
                        executed: false,
                        result: None,
                        retries: 0,
                        max_retries: 1,
                    });
                }
                if !failed_actions.contains(&format!("dump_sam_{}", host)) {
                    steps.push(PlanStep {
                        id: next_id(),
                        description: format!("Dump SAM from {}", host),
                        stage: Stage::Escalate,
                        action: PlannedAction::DumpSam {
                            target: host.clone(),
                        },
                        priority: 69,
                        noise: NoiseLevel::High,
                        depends_on: vec![],
                        executed: false,
                        result: None,
                        retries: 0,
                        max_retries: 1,
                    });
                }
            }
        }

        // ── Phase 6.5: Credential Reuse — re-check admin with new creds ──
        // If we obtained credentials from dumps/cracking, try them against
        // all known computers to expand access before going for DCSync.
        if !state.credentials.is_empty() && !state.has_domain_admin {
            let unchecked: Vec<String> = state
                .computers
                .iter()
                .filter_map(|c| c.dns_hostname.clone())
                .filter(|h| !state.admin_hosts.contains(h))
                .collect();
            if !unchecked.is_empty() && unchecked.len() <= 50 {
                steps.push(PlanStep {
                    id: next_id(),
                    description: format!(
                        "Credential reuse — re-check {} hosts with dumped creds",
                        unchecked.len()
                    ),
                    stage: Stage::Lateral,
                    action: PlannedAction::CheckAdminAccess {
                        targets: unchecked,
                    },
                    priority: 65,
                    noise: NoiseLevel::Medium,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                });
            }
        }

        // ── Phase 7: DCSync / NTDS Dump (final goal) ──
        if state.has_domain_admin
            && matches!(goal, AttackGoal::DumpNtds { .. } | AttackGoal::DomainAdmin { .. }) {
                let _dc_target = state
                    .dc_hostname
                    .clone()
                    .or_else(|| state.dc_ip.clone())
                    .unwrap_or_else(|| "DC".to_string());

                steps.push(PlanStep {
                    id: next_id(),
                    description: "DCSync — replicate credentials".to_string(),
                    stage: Stage::Loot,
                    action: PlannedAction::DcsSync { target_user: None },
                    priority: 60,
                    noise: NoiseLevel::Critical,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                });
            }

        // ── Phase 8: Coercion (if other paths blocked) ──
        if !state.has_domain_admin
            && !state.unconstrained_delegation.is_empty()
            && !failed_actions.contains(&"coerce".to_string())
            && self.max_noise >= NoiseLevel::Medium
        {
            steps.push(PlanStep {
                id: next_id(),
                description: "Coerce DC authentication to unconstrained delegation host".to_string(),
                stage: Stage::Attack,
                action: PlannedAction::Coerce {
                    target: state.dc_ip.clone().unwrap_or_default(),
                    listener: state
                        .unconstrained_delegation
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                },
                priority: 50,
                noise: NoiseLevel::Medium,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
            });
        }

        self.finalize_plan(goal, steps)
    }

    /// Sort steps by priority, filter by noise, enforce step cap, and return the plan
    fn finalize_plan(&self, goal: &AttackGoal, mut steps: Vec<PlanStep>) -> AttackPlan {
        // Filter out steps above noise threshold
        if self.stealth {
            steps.retain(|s| s.noise <= self.max_noise);
        }

        // Sort by stage order first, then priority within stage
        steps.sort_by(|a, b| {
            let stage_cmp = (a.stage as u8).cmp(&(b.stage as u8));
            if stage_cmp == std::cmp::Ordering::Equal {
                b.priority.cmp(&a.priority)
            } else {
                stage_cmp
            }
        });

        // Enforce maximum step cap to prevent runaway plans
        if steps.len() > self.max_steps {
            warn!(
                "Plan has {} steps, truncating to {} (bail-out)",
                steps.len(),
                self.max_steps
            );
            steps.truncate(self.max_steps);
        }

        let max_noise = steps
            .iter()
            .map(|s| s.noise)
            .max()
            .unwrap_or(NoiseLevel::Silent);

        let plan = AttackPlan {
            goal: goal.describe(),
            steps,
            estimated_noise: max_noise,
            requires_interaction: false,
        };

        self.print_plan(&plan);
        plan
    }

    /// Pretty-print the plan
    fn print_plan(&self, plan: &AttackPlan) {
        println!("\n{}", "═══ ATTACK PLAN ═══".bold().blue());
        println!("  Goal:  {}", plan.goal.bold());
        println!("  Steps: {}", plan.steps.len());
        println!("  Noise: {}", plan.estimated_noise);
        println!();

        for (i, step) in plan.steps.iter().enumerate() {
            let stage_color = match step.stage {
                Stage::Enumerate => step.stage.to_string().dimmed(),
                Stage::Attack => step.stage.to_string().yellow(),
                Stage::Escalate => step.stage.to_string().red(),
                Stage::Lateral => step.stage.to_string().magenta(),
                Stage::Loot => step.stage.to_string().red().bold(),
                Stage::Cleanup => step.stage.to_string().green(),
            };
            println!(
                "  {:>2}. [{}] {} (noise: {}, prio: {})",
                i + 1,
                stage_color,
                step.description,
                step.noise,
                step.priority
            );
        }
        println!("{}\n", "═══════════════════".blue());
    }
}
