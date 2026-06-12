//! Attack planner — Build ordered attack plans from the current
//! engagement state toward a goal using a scoring/priority system.
//!
//! The planner evaluates what's known, what's been tried, and what
//! attack paths remain viable — then produces an ordered plan.

use crate::goals::{AttackGoal, EngagementState};
use crate::playbook::PlaybookId;
use crate::runner::Stage;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════
// Plan Types
// ═══════════════════════════════════════════════════════════

/// An ordered sequence of attack steps to reach the goal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlan {
    /// goal field
    pub goal: String,
    /// steps field
    pub steps: Vec<PlanStep>,
    /// estimated noise field
    pub estimated_noise: NoiseLevel,
    /// requires interaction field
    pub requires_interaction: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_planner() -> Planner {
        Planner::new(false, None)
    }

    fn stealth_planner() -> Planner {
        Planner::new(true, Some("users.txt".into()))
    }

    fn empty_state() -> EngagementState {
        EngagementState::new()
    }

    // ── Basic plan generation ──

    #[test]
    fn user_enum_uses_embedded_fallback_when_no_userlist_is_provided() {
        let planner = empty_planner();
        let state = empty_state();
        let plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], false);

        match &plan.steps[0].action {
            PlannedAction::UserEnum { wordlist } => assert!(wordlist.is_empty()),
            other => panic!("expected UserEnum step, got {:?}", other),
        }
    }

    #[test]
    fn user_enum_uses_explicit_userlist_when_provided() {
        let planner = Planner::new(false, Some("custom-users.txt".to_string()));
        let state = empty_state();
        let plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], false);

        match &plan.steps[0].action {
            PlannedAction::UserEnum { wordlist } => {
                assert_eq!(wordlist, "custom-users.txt")
            }
            other => panic!("expected UserEnum step, got {:?}", other),
        }
    }

    #[test]
    fn stealth_plan_includes_stealth_probes_when_ldap_available() {
        let planner = stealth_planner();
        let state = empty_state();
        let plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], true);

        let actions: Vec<&PlannedAction> = plan.steps.iter().map(|s| &s.action).collect();
        assert!(
            actions.contains(&&PlannedAction::StealthLdapProbe),
            "Stealth plan should include StealthLdapProbe when LDAP is available"
        );
        assert!(
            actions.contains(&&PlannedAction::StealthDelegationProbe),
            "Stealth plan should include StealthDelegationProbe when LDAP is available"
        );
    }

    #[test]
    fn stealth_plan_falls_back_to_user_enum_when_ldap_unavailable() {
        let planner = stealth_planner();
        let state = empty_state();
        let plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], false);

        // Without LDAP, first step should be UserEnum, not stealth probes
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| matches!(s.action, PlannedAction::StealthLdapProbe)),
            "Without LDAP, stealth probes should not be in plan"
        );
    }

    #[test]
    fn plan_excludes_failed_actions() {
        let planner = empty_planner();
        let state = empty_state();
        let plan = planner.plan(
            &AttackGoal::ReconOnly,
            &state,
            &["user_enum".to_string()],
            false,
        );

        // UserEnum should not appear in the plan
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| matches!(s.action, PlannedAction::UserEnum { .. })),
            "Plan should exclude failed actions"
        );
    }

    #[test]
    fn domain_admin_goal_produces_different_plan_than_recon() {
        let planner = empty_planner();
        let state = empty_state();

        let recon_plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], false);
        let da_plan = planner.plan(
            &AttackGoal::DomainAdmin {
                target_group: "Domain Admins".into(),
            },
            &state,
            &[],
            false,
        );

        // DA plan should have more steps (it includes exploitation, not just recon)
        assert!(
            da_plan.steps.len() >= recon_plan.steps.len(),
            "DA plan ({} steps) should have >= Recon plan ({} steps)",
            da_plan.steps.len(),
            recon_plan.steps.len()
        );
    }

    #[test]
    fn plan_has_no_duplicate_step_ids() {
        let planner = empty_planner();
        let state = empty_state();
        let plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], false);

        let mut ids: Vec<&str> = plan.steps.iter().map(|s| s.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), plan.steps.len(), "Step IDs should be unique");
    }

    #[test]
    fn plan_has_no_negative_priority() {
        let planner = empty_planner();
        let state = empty_state();
        let plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], false);

        for step in &plan.steps {
            assert!(
                step.priority >= 0,
                "Step {} has negative priority {}",
                step.id,
                step.priority
            );
        }
    }

    #[test]
    fn plan_sorted_by_priority_descending() {
        let planner = empty_planner();
        let state = empty_state();
        let plan = planner.plan(&AttackGoal::ReconOnly, &state, &[], false);

        for window in plan.steps.windows(2) {
            assert!(
                window[0].priority >= window[1].priority,
                "Steps not sorted by priority: {} (prio={}) > {} (prio={})",
                window[0].id,
                window[0].priority,
                window[1].id,
                window[1].priority
            );
        }
    }

    // ── Goal descriptions ──

    #[test]
    fn goal_describe_returns_readable_string() {
        let g = AttackGoal::DomainAdmin {
            target_group: "Domain Admins".into(),
        };
        assert!(g.describe().contains("Domain Admins"));

        let g = AttackGoal::ReconOnly;
        assert!(g.describe().contains("reconnaissance"));

        let g = AttackGoal::DumpNtds { target_dc: None };
        assert!(g.describe().contains("NTDS"));

        let g = AttackGoal::Custom {
            description: "test goal".into(),
            success_check: "".into(),
        };
        assert_eq!(g.describe(), "test goal");
    }

    #[test]
    fn goal_requires_da_is_correct() {
        assert!(
            AttackGoal::DomainAdmin {
                target_group: "DA".into()
            }
            .requires_da()
        );
        assert!(AttackGoal::DumpNtds { target_dc: None }.requires_da());
        assert!(!AttackGoal::ReconOnly.requires_da());
        assert!(
            !AttackGoal::CompromiseUser {
                target_user: "u".into()
            }
            .requires_da()
        );
    }
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
    /// If true, this step can be reversed via `compensate_step`
    pub reversible: bool,
    /// Optional compensation action to undo this step
    pub compensation: Option<CompensationAction>,
    /// Whether this step can run concurrently with other parallel-safe steps
    /// in the same stage (no shared state or side effects).
    #[serde(default)]
    pub parallel_safe: bool,
}

/// Describes how to undo/reverse a completed step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompensationAction {
    /// Remove the RBCD SD entry from the target computer
    RbcdCleanup { controlled: String, target: String },
    /// Restore an ADCS certificate template that was modified
    RestoreTemplate { template: String },
    /// Delete a temporary file or service created on the target
    CleanupService {
        target: String,
        service_name: String,
    },
    /// Generic rollback: a human-readable description for manual reversal
    Manual { instruction: String },
}

/// Specific action the executor should perform
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannedAction {
    // ── Recon ──
    /// `EnumerateUsers` variant
    EnumerateUsers,
    /// `EnumerateComputers` variant
    EnumerateComputers,
    /// `EnumerateGroups` variant
    EnumerateGroups,
    /// `EnumerateTrusts` variant
    EnumerateTrusts,
    /// `EnumerateGpos` variant
    EnumerateGpos,
    /// `EnumeratePasswordPolicy` variant
    EnumeratePasswordPolicy,
    /// `EnumerateDelegations` variant
    EnumerateDelegations,
    /// `EnumerateLaps` variant
    EnumerateLaps,
    /// `` variant
    EnumerateShares {
        /// Target domain FQDN
        target: String,
    },
    /// `` variant
    CheckAdminAccess {
        /// targets field
        targets: Vec<String>,
    },
    /// `` variant
    UserEnum {
        /// wordlist field
        wordlist: String,
    },
    /// `` variant
    RidCycle {
        /// Stable unique identifier.
        start_rid: u32,
        /// Stable unique identifier.
        end_rid: u32,
    },
    /// `StealthLdapProbe` variant
    StealthLdapProbe,
    /// `StealthDelegationProbe` variant
    StealthDelegationProbe,

    // ── Kerberos Attacks ──
    /// `` variant
    AsRepRoast {
        /// users field
        users: Vec<String>,
    },
    /// `` variant
    Kerberoast {
        /// Service Principal Name
        spns: Vec<String>,
    },
    /// `` variant
    ConstrainedDelegation {
        /// Item count
        account: String,
        /// Service Principal Name
        target_spn: String,
        /// impersonate field
        impersonate: String,
    },
    /// `` variant
    UnconstrainedDelegation {
        /// Target host address
        target_host: String,
    },
    /// `` variant
    RbcdAttack {
        /// controlled field
        controlled: String,
        /// Target domain FQDN
        target: String,
    },

    // ── Credential Attacks ──
    /// `` variant
    PasswordSpray {
        /// users field
        users: Vec<String>,
        /// Password for authentication
        password: String,
    },
    /// `` variant
    CrackHashes {
        /// Hash value
        hashes: Vec<String>,
    },

    // ── Lateral Movement ──
    /// `` variant
    ExecCommand {
        /// Target domain FQDN
        target: String,
        /// command field
        command: String,
        /// Execution method that produced this output.
        method: String,
    },
    /// `` variant
    PsExec {
        /// Target domain FQDN
        target: String,
        /// command field
        command: String,
    },
    /// `` variant
    SmbExec {
        /// Target domain FQDN
        target: String,
        /// command field
        command: String,
    },
    /// `` variant
    WmiExec {
        /// Target domain FQDN
        target: String,
        /// command field
        command: String,
    },
    /// `` variant
    WinRmExec {
        /// Target domain FQDN
        target: String,
        /// command field
        command: String,
    },

    // ── Credential Dumping ──
    /// `` variant
    DumpSam {
        /// Target domain FQDN
        target: String,
    },
    /// `` variant
    DumpLsa {
        /// Target domain FQDN
        target: String,
    },
    /// `` variant
    DumpNtds {
        /// Target domain FQDN
        target: String,
    },
    /// `` variant
    DumpDcc2 {
        /// Target domain FQDN
        target: String,
    },
    /// `` variant
    DcsSync {
        /// target user field
        target_user: Option<String>,
    },

    // ── Coercion ──
    /// `` variant
    Coerce {
        /// Target domain FQDN
        target: String,
        /// listener field
        listener: String,
    },

    // ── ADCS ──
    /// `AdcsEnumerate` variant
    AdcsEnumerate,
    /// `` variant
    AdcsEsc1 {
        /// template field
        template: String,
        /// ca field
        ca: String,
        /// target upn field
        target_upn: String,
    },
    /// `` variant
    AdcsEsc2 {
        /// template field
        template: String,
        /// ca field
        ca: String,
    },
    /// `` variant
    AdcsEsc3 {
        /// agent template field
        agent_template: String,
        /// target template field
        target_template: String,
        /// ca field
        ca: String,
        /// target upn field
        target_upn: String,
    },
    /// `` variant
    AdcsEsc4 {
        /// template field
        template: String,
    },
    /// `` variant
    AdcsEsc5 {
        /// ca field
        ca: String,
    },
    /// `` variant
    AdcsEsc6 {
        /// template field
        template: String,
        /// ca field
        ca: String,
        /// target upn field
        target_upn: String,
    },
    /// `` variant
    AdcsEsc7 {
        /// ca field
        ca: String,
    },
    /// `` variant
    AdcsEsc8 {
        /// ca field
        ca: String,
        /// template field
        template: String,
        /// target upn field
        target_upn: String,
    },
    /// `` variant
    AdcsEsc9 {
        /// template field
        template: String,
        /// ca field
        ca: String,
        /// victim field
        victim: String,
        /// target upn field
        target_upn: String,
    },
    /// `` variant
    AdcsEsc10 {
        /// template field
        template: String,
        /// ca field
        ca: String,
        /// victim field
        victim: String,
        /// target upn field
        target_upn: String,
        /// variant field
        variant: String,
    },
    /// `` variant
    AdcsEsc11 {
        /// ca field
        ca: String,
        /// template field
        template: String,
        /// target upn field
        target_upn: String,
    },
    /// `` variant
    AdcsEsc12 {
        /// ca host field
        ca_host: String,
        /// Object or account name.
        ca_name: String,
    },
    /// `` variant
    AdcsEsc13 {
        /// template field
        template: String,
        /// ca field
        ca: String,
        /// target upn field
        target_upn: String,
    },
    /// `AdcsEsc14` variant
    AdcsEsc14,
    /// `` variant
    AdcsEsc15 {
        /// template field
        template: String,
        /// ca field
        ca: String,
        /// target upn field
        target_upn: String,
    },
    /// `` variant
    AdcsEsc16 {
        /// template field
        template: String,
        /// ca field
        ca: String,
        /// victim field
        victim: String,
        /// target upn field
        target_upn: String,
    },

    // ── Persistence ──
    /// `` variant
    ForgeGoldenTicket {
        /// Hash value
        krbtgt_hash: String,
    },
    /// `` variant
    ForgeSilverTicket {
        /// Hash value
        service_hash: String,
        /// Service Principal Name
        spn: String,
    },
    /// Skeleton key deployment on DC
    DeploySkeletonKey {
        /// Target domain controller
        target_dc: String,
        /// Master password
        master_password: String,
    },

    // ── Playbook ──
    /// `` variant
    RunPlaybook {
        /// Stable unique identifier.
        playbook_id: PlaybookId,
    },

    // ── Utility ──
    /// `` variant
    Sleep {
        /// seconds field
        seconds: u64,
    },
    /// `` variant
    Checkpoint {
        /// message field
        message: String,
    },
}

impl PlannedAction {
    pub fn key(&self) -> &'static str {
        match self {
            Self::EnumerateUsers => "enumerate_users",
            Self::EnumerateComputers => "enumerate_computers",
            Self::EnumerateGroups => "enumerate_groups",
            Self::EnumerateTrusts => "enumerate_trusts",
            Self::EnumerateGpos => "enumerate_gpos",
            Self::EnumeratePasswordPolicy => "enumerate_password_policy",
            Self::EnumerateDelegations => "enumerate_delegations",
            Self::EnumerateLaps => "enumerate_laps",
            Self::EnumerateShares { .. } => "enumerate_shares",
            Self::CheckAdminAccess { .. } => "check_admin_access",
            Self::UserEnum { .. } => "user_enum",
            Self::RidCycle { .. } => "rid_cycle",
            Self::StealthLdapProbe => "stealth_ldap_probe",
            Self::StealthDelegationProbe => "stealth_delegation_probe",
            Self::AsRepRoast { .. } => "asreproast",
            Self::Kerberoast { .. } => "kerberoast",
            Self::ConstrainedDelegation { .. } => "constrained_delegation",
            Self::UnconstrainedDelegation { .. } => "unconstrained_delegation",
            Self::RbcdAttack { .. } => "rbcd",
            Self::PasswordSpray { .. } => "password_spray",
            Self::CrackHashes { .. } => "crack_hashes",
            Self::ExecCommand { .. } => "exec_command",
            Self::PsExec { .. } => "psexec",
            Self::SmbExec { .. } => "smbexec",
            Self::WmiExec { .. } => "wmiexec",
            Self::WinRmExec { .. } => "winrmexec",
            Self::DumpSam { .. } => "dump_sam",
            Self::DumpLsa { .. } => "dump_lsa",
            Self::DumpNtds { .. } => "dump_ntds",
            Self::DumpDcc2 { .. } => "dump_dcc2",
            Self::DcsSync { .. } => "dcsync",
            Self::Coerce { .. } => "coerce",
            Self::AdcsEnumerate => "adcs_enum",
            Self::AdcsEsc1 { .. } => "adcs_esc1",
            Self::AdcsEsc2 { .. } => "adcs_esc2",
            Self::AdcsEsc3 { .. } => "adcs_esc3",
            Self::AdcsEsc4 { .. } => "adcs_esc4",
            Self::AdcsEsc5 { .. } => "adcs_esc5",
            Self::AdcsEsc6 { .. } => "adcs_esc6",
            Self::AdcsEsc7 { .. } => "adcs_esc7",
            Self::AdcsEsc8 { .. } => "adcs_esc8",
            Self::AdcsEsc9 { .. } => "adcs_esc9",
            Self::AdcsEsc10 { .. } => "adcs_esc10",
            Self::AdcsEsc11 { .. } => "adcs_esc11",
            Self::AdcsEsc12 { .. } => "adcs_esc12",
            Self::AdcsEsc13 { .. } => "adcs_esc13",
            Self::AdcsEsc14 => "adcs_esc14",
            Self::AdcsEsc15 { .. } => "adcs_esc15",
            Self::AdcsEsc16 { .. } => "adcs_esc16",
            Self::ForgeGoldenTicket { .. } => "forge_golden_ticket",
            Self::ForgeSilverTicket { .. } => "forge_silver_ticket",
            Self::DeploySkeletonKey { .. } => "deploy_skeleton_key",
            Self::RunPlaybook { .. } => "run_playbook",
            Self::Sleep { .. } => "sleep",
            Self::Checkpoint { .. } => "checkpoint",
        }
    }

    pub fn ovt_command_hints(&self) -> Vec<String> {
        match self {
            Self::EnumerateUsers => vec![
                "ovt enum users -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt powerview users -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumerateComputers => vec![
                "ovt enum computers -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt powerview computers -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumerateGroups => vec![
                "ovt enum groups -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt powerview groups -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumerateTrusts => vec![
                "ovt enum trusts -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt powerview trusts -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt move trusts -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumerateGpos => vec![
                "ovt enum gpos -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt gpo enum -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumeratePasswordPolicy => vec![
                "ovt enum policy -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt powerview policy -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumerateDelegations => vec![
                "ovt enum delegations -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt powerview delegations -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumerateLaps => vec![
                "ovt enum laps -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt laps -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::EnumerateShares { target } => vec![
                format!("ovt smb shares --target {target} -d <domain> -u <user> -p <pass>"),
                "ovt snaffler -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::CheckAdminAccess { targets } => vec![format!(
                "ovt smb admin --targets {} -d <domain> -u <user> -p <pass>",
                targets.join(",")
            )],
            Self::UserEnum { wordlist } => vec![format!(
                "ovt kerberos user-enum -H <dc> -d <domain> --userlist {wordlist}"
            )],
            Self::RidCycle { start_rid, end_rid } => vec![format!(
                "ovt rid -H <dc> -d <domain> --start-rid {start_rid} --end-rid {end_rid}"
            )],
            Self::StealthLdapProbe => {
                vec![
                    "ovt enum anonymous -H <dc>".to_string(),
                    "ovt enum pre -H <dc>".to_string(),
                ]
            }
            Self::StealthDelegationProbe => {
                vec!["ovt enum delegations -H <dc> -d <domain> -u <user> -p <pass>".to_string()]
            }
            Self::AsRepRoast { .. } => vec![
                "ovt enum asrep -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt kerberos asrep-roast -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::Kerberoast { .. } => vec![
                "ovt enum spns -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt kerberos roast -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
            ],
            Self::ConstrainedDelegation {
                account,
                target_spn,
                impersonate,
            } => vec![
                "ovt enum delegations -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                "ovt move escalation -H <dc> -d <domain> -u <user> -p <pass>".to_string(),
                format!(
                    "planned constrained delegation: account={account}, spn={target_spn}, impersonate={impersonate}"
                ),
            ],
            Self::UnconstrainedDelegation { target_host } => vec![format!(
                "ovt enum delegations -H <dc> -d <domain> -u <user> -p <pass>; validate unconstrained host {target_host}"
            )],
            Self::RbcdAttack { controlled, target } => vec![format!(
                "ovt enum delegations -H <dc> -d <domain> -u <user> -p <pass>; validate RBCD controlled={controlled} target={target}"
            )],
            Self::PasswordSpray { .. } => {
                vec!["ovt spray -U users.txt --password <password> -H <dc> -d <domain>".to_string()]
            }
            Self::CrackHashes { .. } => {
                vec!["ovt crack --file hashes.txt --mode default".to_string()]
            }
            Self::ExecCommand {
                target,
                command,
                method,
            } => vec![format!(
                "ovt exec --method {method} --target {target} --command \"{}\" -d <domain> -u <user> -p <pass>",
                command.replace('"', "\\\"")
            )],
            Self::PsExec { target, command } => vec![format!(
                "ovt exec --method psexec --target {target} --command \"{}\" -d <domain> -u <user> -p <pass>",
                command.replace('"', "\\\"")
            )],
            Self::SmbExec { target, command } => vec![format!(
                "ovt exec --method smbexec --target {target} --command \"{}\" -d <domain> -u <user> -p <pass>",
                command.replace('"', "\\\"")
            )],
            Self::WmiExec { target, command } => vec![format!(
                "ovt exec --method wmiexec --target {target} --command \"{}\" -d <domain> -u <user> -p <pass>",
                command.replace('"', "\\\"")
            )],
            Self::WinRmExec { target, command } => vec![format!(
                "ovt exec --method winrm --target {target} --command \"{}\" -d <domain> -u <user> -p <pass>",
                command.replace('"', "\\\"")
            )],
            Self::DumpSam { target } => vec![format!(
                "ovt dump --target {target} sam -d <domain> -u <user> -p <pass>"
            )],
            Self::DumpLsa { target } => vec![format!(
                "ovt dump --target {target} lsa -d <domain> -u <user> -p <pass>"
            )],
            Self::DumpNtds { target } => vec![format!(
                "ovt dump --target {target} ntds -d <domain> -u <user> -p <pass>"
            )],
            Self::DumpDcc2 { target } => vec![format!(
                "ovt dump --target {target} dcc2 -d <domain> -u <user> -p <pass>"
            )],
            Self::DcsSync { target_user } => vec![format!(
                "ovt dump --target {} ntds -d <domain> -u <user> -p <pass>",
                target_user.as_deref().unwrap_or("<dc>")
            )],
            Self::Coerce { target, listener } => vec![format!(
                "ovt ntlm relay --targets {listener}:445 --command \"whoami\"; coerce target {target}"
            )],
            Self::AdcsEnumerate => {
                vec!["ovt adcs enum -H <dc> -d <domain> -u <user> -p <pass>".to_string()]
            }
            Self::AdcsEsc1 {
                template,
                ca,
                target_upn,
            } => vec![format!(
                "ovt adcs esc1 --template {template} --ca {ca} --target-user {target_upn} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc2 { template, ca } => vec![format!(
                "ovt adcs esc2 --template {template} --ca {ca} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc3 {
                agent_template,
                target_template,
                ca,
                target_upn,
            } => vec![format!(
                "ovt adcs esc3 --agent-template {agent_template} --target-template {target_template} --ca {ca} --target-user {target_upn} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc4 { template } => vec![format!(
                "ovt adcs esc4 --template {template} --ca <ca> -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc5 { ca } => vec![format!(
                "ovt adcs esc5 --ca {ca} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc6 {
                template,
                ca,
                target_upn,
            } => vec![format!(
                "ovt adcs esc6 --ca {ca} --target-user {target_upn} -H <dc> -d <domain> -u <user> -p <pass>; template hint: {template}"
            )],
            Self::AdcsEsc7 { ca } => vec![format!(
                "ovt adcs esc7 --ca {ca} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc8 {
                ca,
                template,
                target_upn,
            } => vec![format!(
                "ovt adcs esc8 --url {ca} --target-user {target_upn} -H <dc> -d <domain> -u <user> -p <pass>; template hint: {template}"
            )],
            Self::AdcsEsc9 {
                template,
                ca,
                victim,
                target_upn,
            } => vec![format!(
                "ovt adcs esc9 --template {template} --ca {ca} --victim {victim} --target-upn {target_upn} --original-upn <victim-original-upn> -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc10 {
                template,
                ca,
                victim,
                target_upn,
                variant,
            } => vec![format!(
                "ovt adcs esc10 --template {template} --ca {ca} --target-upn {target_upn} --variant {variant} --victim {victim} --original-upn <victim-original-upn> -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc11 {
                ca,
                template,
                target_upn,
            } => vec![format!(
                "ovt adcs esc11 --ca-host {ca} --ca-name <ca-name> --template {template} -H <dc> -d <domain> -u <user> -p <pass>; target hint: {target_upn}"
            )],
            Self::AdcsEsc12 { ca_host, ca_name } => vec![format!(
                "ovt adcs esc12 --ca-host {ca_host} --ca-name {ca_name} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc13 {
                template,
                ca,
                target_upn,
            } => vec![format!(
                "ovt adcs esc13 --template {template} --ca {ca} --policy-oid <oid> --linked-group-dn <group-dn> --subject {target_upn} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::AdcsEsc14 => vec!["ovt adcs esc14".to_string()],
            Self::AdcsEsc15 {
                template,
                ca,
                target_upn,
            } => vec![format!(
                "ovt adcs esc15 --ca {ca} --template {template} --target-user {}",
                target_upn.split('@').next().unwrap_or(target_upn)
            )],
            Self::AdcsEsc16 {
                template,
                ca,
                victim,
                target_upn,
            } => vec![format!(
                "ovt adcs esc16 --ca {ca} --template {template} --target-upn {target_upn} --victim {victim} --original-upn <victim-original-upn> --ldap-url ldap://<dc>"
            )],
            Self::ForgeGoldenTicket { .. } => vec![
                "ovt forge golden --domain-sid <sid> --krbtgt-hash <hash> --user Administrator"
                    .to_string(),
            ],
            Self::ForgeSilverTicket { spn, .. } => vec![format!(
                "ovt forge silver --domain-sid <sid> --spn {spn} --service-hash <hash>"
            )],
            Self::DeploySkeletonKey {
                target_dc,
                master_password,
            } => vec![
                format!("ovt postex skeleton-key --dc {target_dc} --password {master_password}"),
                format!("ovt postex skeleton-key --dc {target_dc} --method reflective-dll"),
            ],
            Self::RunPlaybook { playbook_id } => vec![format!(
                "ovt auto-pwn --playbook {playbook_id:?} -H <dc> -d <domain> -u <user> -p <pass>"
            )],
            Self::Sleep { seconds } => vec![format!("sleep {seconds}")],
            Self::Checkpoint { message } => vec![format!("checkpoint: {message}")],
        }
    }
}

impl PlanStep {
    pub fn action_key(&self) -> &'static str {
        self.action.key()
    }

    /// Create a new plan step with sensible defaults.
    /// `parallel_safe` defaults to `false`; set it explicitly for read-only recon steps.
    pub fn new(
        id: String,
        description: String,
        stage: Stage,
        action: PlannedAction,
        priority: i32,
        noise: NoiseLevel,
        max_retries: u32,
    ) -> Self {
        Self {
            id,
            description,
            stage,
            action,
            priority,
            noise,
            depends_on: vec![],
            executed: false,
            result: None,
            retries: 0,
            max_retries,
            reversible: false,
            compensation: None,
            parallel_safe: false,
        }
    }

    /// Mark this step as safe for concurrent execution.
    pub fn with_parallel_safe(mut self) -> Self {
        self.parallel_safe = true;
        self
    }
}

/// Result of executing a step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// success field
    pub success: bool,
    /// output field
    pub output: String,
    /// new credentials field
    pub new_credentials: usize,
    /// new admin_hosts field
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
// OPSEC-Aware Cost/Benefit Profile
// ═══════════════════════════════════════════════════════════

/// OPSEC profile for cost/benefit analysis of noisy operations.
/// Determines whether a noisy step is worth the risk based on
/// the current engagement context and potential reward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecProfile {
    /// Maximum noise level allowed (budget)
    pub max_noise: NoiseLevel,
    /// Whether to allow "worth it" overrides (high-value steps can exceed budget)
    pub allow_value_overrides: bool,
    /// Noise multiplier for password spraying / mass operations
    pub spray_penalty: f64,
    /// Noise reduction for steps that use credentials (less suspicious)
    pub authenticated_bonus: f64,
    /// Value threshold: steps with priority >= this can override noise budget
    pub value_override_threshold: i32,
}

impl Default for OpsecProfile {
    fn default() -> Self {
        Self {
            max_noise: NoiseLevel::Medium,
            allow_value_overrides: true,
            spray_penalty: 2.0,
            authenticated_bonus: 1.0,
            value_override_threshold: 90,
        }
    }
}

impl OpsecProfile {
    /// Create a stealth profile (low noise, no overrides).
    pub fn stealth() -> Self {
        Self {
            max_noise: NoiseLevel::Low,
            allow_value_overrides: false,
            spray_penalty: 3.0,
            authenticated_bonus: 1.5,
            value_override_threshold: 100,
        }
    }

    /// Create an aggressive profile (high noise OK, value overrides enabled).
    pub fn aggressive() -> Self {
        Self {
            max_noise: NoiseLevel::Critical,
            allow_value_overrides: true,
            spray_penalty: 0.5,
            authenticated_bonus: 0.5,
            value_override_threshold: 50,
        }
    }

    /// Evaluate whether a step should be executed based on cost/benefit.
    /// Returns `true` if the step should proceed, `false` if it should be skipped.
    pub fn should_execute(
        &self,
        step_noise: NoiseLevel,
        step_priority: i32,
        has_credentials: bool,
    ) -> OpsecDecision {
        let effective_noise = if has_credentials {
            // Authenticated operations are less suspicious
            self.reduce_noise(step_noise)
        } else {
            step_noise
        };

        if effective_noise <= self.max_noise {
            return OpsecDecision::Allow {
                reason: format!("noise {} within budget {}", effective_noise, self.max_noise),
            };
        }

        // Check if high-value override applies
        if self.allow_value_overrides && step_priority >= self.value_override_threshold {
            return OpsecDecision::AllowOverride {
                reason: format!(
                    "noise {} exceeds budget {} but priority {} >= threshold {}",
                    effective_noise, self.max_noise, step_priority, self.value_override_threshold
                ),
            };
        }

        OpsecDecision::Deny {
            reason: format!(
                "noise {} exceeds budget {} (priority {} < threshold {})",
                effective_noise, self.max_noise, step_priority, self.value_override_threshold
            ),
        }
    }

    /// Reduce noise level by one step (for authenticated operations).
    fn reduce_noise(&self, noise: NoiseLevel) -> NoiseLevel {
        match noise {
            NoiseLevel::Critical => NoiseLevel::High,
            NoiseLevel::High => NoiseLevel::Medium,
            NoiseLevel::Medium => NoiseLevel::Low,
            NoiseLevel::Low => NoiseLevel::Silent,
            NoiseLevel::Silent => NoiseLevel::Silent,
        }
    }
}

/// Result of an OPSEC cost/benefit evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpsecDecision {
    /// Step is within noise budget
    Allow { reason: String },
    /// Step exceeds budget but high-value override applies
    AllowOverride { reason: String },
    /// Step exceeds budget and no override
    Deny { reason: String },
}

impl OpsecDecision {
    /// Whether the step should be executed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. } | Self::AllowOverride { .. })
    }
}

// ═══════════════════════════════════════════════════════════
// Multi-DC Targeting
// ═══════════════════════════════════════════════════════════

/// Configuration for targeting multiple domain controllers.
/// Allows the planner to distribute operations across DCs
/// for resilience and load distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDcConfig {
    /// Whether multi-DC targeting is enabled
    pub enabled: bool,
    /// List of DC IPs to target (in priority order)
    pub dc_hosts: Vec<String>,
    /// Current active DC index (for round-robin or failover)
    pub active_index: usize,
    /// Whether to failover to next DC on connection failure
    pub auto_failover: bool,
    /// Whether to distribute different operations across DCs
    pub distribute_operations: bool,
}

impl Default for MultiDcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dc_hosts: vec![],
            active_index: 0,
            auto_failover: true,
            distribute_operations: false,
        }
    }
}

impl MultiDcConfig {
    /// Create a multi-DC config from a list of DC IPs.
    pub fn new(dc_hosts: Vec<String>) -> Self {
        Self {
            enabled: dc_hosts.len() > 1,
            dc_hosts,
            active_index: 0,
            auto_failover: true,
            distribute_operations: false,
        }
    }

    /// Get the current active DC host.
    pub fn active_host(&self) -> Option<&str> {
        self.dc_hosts.get(self.active_index).map(|s| s.as_str())
    }

    /// Get the next DC host for round-robin distribution.
    pub fn next_host(&mut self) -> Option<&str> {
        if self.dc_hosts.is_empty() {
            return None;
        }
        self.active_index = (self.active_index + 1) % self.dc_hosts.len();
        self.dc_hosts.get(self.active_index).map(|s| s.as_str())
    }

    /// Failover to the next DC (called on connection failure).
    pub fn failover(&mut self) -> Option<&str> {
        if self.dc_hosts.len() <= 1 {
            return None;
        }
        self.active_index = (self.active_index + 1) % self.dc_hosts.len();
        warn!("Multi-DC failover to {}", self.dc_hosts[self.active_index]);
        self.dc_hosts.get(self.active_index).map(|s| s.as_str())
    }

    /// Number of configured DC hosts.
    pub fn len(&self) -> usize {
        self.dc_hosts.len()
    }

    /// Whether no DC hosts are configured.
    pub fn is_empty(&self) -> bool {
        self.dc_hosts.is_empty()
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
    userlist: Option<String>,
}

impl Planner {
    /// Runs this module operation.
    pub fn new(stealth: bool, userlist: Option<String>) -> Self {
        Self {
            stealth,
            max_noise: if stealth {
                NoiseLevel::Medium
            } else {
                NoiseLevel::Critical
            },
            max_steps: 60,
            userlist,
        }
    }

    /// Build an attack plan for the given goal based on current state
    pub fn plan(
        &self,
        goal: &AttackGoal,
        state: &EngagementState,
        failed_actions: &[String],
        ldap_available: bool,
    ) -> AttackPlan {
        info!(
            "{} Planning attack: {} (LDAP: {})",
            "PLAN".bold().blue(),
            goal.describe().bold(),
            if ldap_available {
                "OK".green()
            } else {
                "OFF".red()
            }
        );

        let mut steps = Vec::new();
        let mut step_counter = 0u32;
        let mut next_id = || {
            step_counter += 1;
            format!("step_{:03}", step_counter)
        };

        let failed = |key: &str| failed_actions.iter().any(|action| action == key);

        if ldap_available && self.stealth {
            if !failed("stealth_ldap_probe") {
                steps.push(PlanStep {
                    id: next_id(),
                    description:
                        "Stealth LDAP baseline probe (RootDSE, domain flags, tiny tier-zero sample)"
                            .to_string(),
                    stage: Stage::Enumerate,
                    action: PlannedAction::StealthLdapProbe,
                    priority: 110,
                    noise: NoiseLevel::Silent,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                    reversible: false,
                    compensation: None,
                    parallel_safe: true,
                });
            }
            if !failed("stealth_delegation_probe") {
                steps.push(PlanStep {
                    id: next_id(),
                    description:
                        "Stealth delegation probe (targeted UAC and delegation attributes)"
                            .to_string(),
                    stage: Stage::Enumerate,
                    action: PlannedAction::StealthDelegationProbe,
                    priority: 109,
                    noise: NoiseLevel::Silent,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                    reversible: false,
                    compensation: None,
                    parallel_safe: true,
                });
            }
        }

        // ── Phase 1: Recon (always needed if state is empty) ──
        if state.users.is_empty() {
            if ldap_available {
                if failed("enumerate_users") {
                    warn!("Skipping user enumeration (previously failed)");
                } else {
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
                        reversible: false,
                        compensation: None,
                        parallel_safe: true,
                    });
                }
            } else {
                // LDAP unavailable — use Kerberos user enumeration as primary recon
                if !failed("user_enum") {
                    steps.push(PlanStep {
                        id: next_id(),
                        description: "Kerberos User Enumeration".to_string(),
                        stage: Stage::Enumerate,
                        action: PlannedAction::UserEnum {
                            wordlist: self.userlist.clone().unwrap_or_default(),
                        },
                        priority: 105, // Higher priority as it's our only way to get users
                        noise: NoiseLevel::Low,
                        depends_on: vec![],
                        executed: false,
                        result: None,
                        retries: 0,
                        max_retries: 1,
                        reversible: false,
                        compensation: None,
                        parallel_safe: false,
                    });
                }

                // Also try RID cycling if we have SMB
                if !failed("rid_cycle") {
                    steps.push(PlanStep {
                        id: next_id(),
                        description: "RID Cycling via SAMR (SMB fallback)".to_string(),
                        stage: Stage::Enumerate,
                        action: PlannedAction::RidCycle {
                            start_rid: 500,
                            end_rid: 2000,
                        },
                        priority: 104,
                        noise: NoiseLevel::Low,
                        depends_on: vec![],
                        executed: false,
                        result: None,
                        retries: 0,
                        max_retries: 1,
                        reversible: false,
                        compensation: None,
                        parallel_safe: false,
                    });
                }
            }
        }

        if ldap_available && state.computers.is_empty() && !failed("enumerate_computers") {
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
                reversible: false,
                compensation: None,
                parallel_safe: true,
            });
        }

        if ldap_available && state.groups.is_empty() && !failed("enumerate_groups") {
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
                reversible: false,
                compensation: None,
                parallel_safe: true,
            });
        }

        // ── Phase 1b: Extended Recon (trusts, GPOs, shares) ──
        // These give the planner and Q-learner richer state for decision-making.

        if ldap_available && state.password_policy.is_none() && !failed("enumerate_password_policy")
        {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate password and lockout policy".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumeratePasswordPolicy,
                priority: 101,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
                reversible: false,
                compensation: None,
                parallel_safe: true,
            });
        }

        if ldap_available && state.trusts.is_empty() && !failed("enumerate_trusts") {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate domain trusts & trust relationships".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateTrusts,
                priority: 97,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
                reversible: false,
                compensation: None,
                parallel_safe: true,
            });
        }

        if ldap_available && state.gpos.is_empty() && !failed("enumerate_gpos") {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate GPOs & linked policies".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateGpos,
                priority: 96,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
                reversible: false,
                compensation: None,
                parallel_safe: true,
            });
        }

        if ldap_available && state.delegation_count() == 0 && !failed("enumerate_delegations") {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate Kerberos delegation and RBCD settings".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateDelegations,
                priority: 94,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
                reversible: false,
                compensation: None,
                parallel_safe: true,
            });
        }

        if ldap_available && state.laps.is_empty() && !failed("enumerate_laps") {
            steps.push(PlanStep {
                id: next_id(),
                description: "Enumerate readable LAPS passwords".to_string(),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateLaps,
                priority: 93,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
                reversible: false,
                compensation: None,
                parallel_safe: true,
            });
        }

        // Enumerate shares on the DC for GPP passwords, SYSVOL scripts, etc.
        if let Some(ref dc_ip) = state.dc_ip
            && !failed("enumerate_shares")
        {
            steps.push(PlanStep {
                id: next_id(),
                description: format!("Enumerate SMB shares on DC ({})", dc_ip),
                stage: Stage::Enumerate,
                action: PlannedAction::EnumerateShares {
                    target: dc_ip.clone(),
                },
                priority: 95,
                noise: NoiseLevel::Low,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
                reversible: false,
                compensation: None,
                parallel_safe: false,
            });
        }

        // If goal is recon-only, stop here
        if matches!(goal, AttackGoal::ReconOnly) {
            return self.finalize_plan(goal, steps);
        }

        // ── Phase 2: Kerberos Attacks (low noise, high reward) ──
        let recon_dep = steps.first().map(|s| s.id.clone()).unwrap_or_default();

        if !failed("kerberoast")
            && state.roast_hashes.is_empty()
            && (state.users.is_empty() || !state.kerberoastable.is_empty())
        {
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
                reversible: false,
                compensation: None,
                parallel_safe: false,
            });
        }

        if !failed("asreproast")
            && state.roast_hashes.is_empty()
            && (state.users.is_empty() || !state.asrep_roastable.is_empty())
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
                reversible: false,
                compensation: None,
                parallel_safe: false,
            });
        }

        // ── Phase 2.1: Inline Hash Cracking (if we have captured roast hashes) ──
        if !state.roast_hashes.is_empty() && !failed("crack_hashes") {
            let hashes: Vec<String> = state.roast_hashes.clone();
            steps.push(PlanStep {
                id: next_id(),
                description: format!(
                    "Crack {} captured hashes (inline wordlist + rules)",
                    hashes.len()
                ),
                stage: Stage::Attack,
                action: PlannedAction::CrackHashes { hashes },
                priority: 89,
                noise: NoiseLevel::Silent,
                depends_on: vec![],
                executed: false,
                result: None,
                retries: 0,
                max_retries: 1,
                reversible: false,
                compensation: None,
                parallel_safe: false,
            });
        }

        // ── Phase 2.2: Password Spray (if we have a user list but few creds) ──
        if !state.users.is_empty()
            && state.credentials.len() <= 1
            && !failed("password_spray")
            && state.spray_guard_allows_attempts()
            && !self.stealth
        // spraying is noisy, skip in stealth mode
        {
            let users = state.safe_spray_candidates();
            if !users.is_empty() {
                steps.push(PlanStep {
                    id: next_id(),
                    description: format!(
                        "Password spray {} lockout-safe users ({})",
                        users.len(),
                        state.spray_risk_summary()
                    ),
                    stage: Stage::Attack,
                    action: PlannedAction::PasswordSpray {
                        users,
                        password: String::new(), // executor will pick seasonal passwords
                    },
                    priority: 82,
                    noise: NoiseLevel::High,
                    depends_on: if recon_dep.is_empty() {
                        vec![]
                    } else {
                        vec![recon_dep.clone()]
                    },
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }
        }

        // ── Phase 2.5: ADCS Certificate Abuse ──
        if ldap_available && !failed("adcs_enum") {
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
                reversible: false,
                compensation: None,
                parallel_safe: false,
            });

            // ESC1 — enrollee supplies SAN (most common ADCS vuln)
            if !failed("adcs_esc1") {
                steps.push(PlanStep {
                    id: next_id(),
                    description: "ADCS ESC1 — request cert with arbitrary SAN for impersonation"
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
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }

            // ESC4 — writable template → make it ESC1-vulnerable
            if !failed("adcs_esc4") {
                steps.push(PlanStep {
                    id: next_id(),
                    description: "ADCS ESC4 — modify writable template then exploit as ESC1"
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
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }

            // ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
            if !failed("adcs_esc6") {
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
                    depends_on: vec![adcs_enum_id.clone()],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }

            let additional_adcs = vec![
                (
                    "adcs_esc2",
                    "ADCS ESC2 - abuse Any Purpose or weak EKU certificate template",
                    PlannedAction::AdcsEsc2 {
                        template: String::new(),
                        ca: String::new(),
                    },
                    82,
                    NoiseLevel::Low,
                ),
                (
                    "adcs_esc3",
                    "ADCS ESC3 - enrollment-agent abuse for certificate impersonation",
                    PlannedAction::AdcsEsc3 {
                        agent_template: String::new(),
                        target_template: String::new(),
                        ca: String::new(),
                        target_upn: String::new(),
                    },
                    81,
                    NoiseLevel::Low,
                ),
                (
                    "adcs_esc5",
                    "ADCS ESC5 - CA object or PKI container control path",
                    PlannedAction::AdcsEsc5 { ca: String::new() },
                    80,
                    NoiseLevel::Medium,
                ),
                (
                    "adcs_esc7",
                    "ADCS ESC7 - ManageCA or ManageCertificates abuse path",
                    PlannedAction::AdcsEsc7 { ca: String::new() },
                    79,
                    NoiseLevel::Medium,
                ),
                (
                    "adcs_esc8",
                    "ADCS ESC8 - NTLM relay to web enrollment endpoints",
                    PlannedAction::AdcsEsc8 {
                        ca: String::new(),
                        template: String::new(),
                        target_upn: String::new(),
                    },
                    78,
                    NoiseLevel::Medium,
                ),
                (
                    "adcs_esc9",
                    "ADCS ESC9 - NoSecurityExtension mapping abuse",
                    PlannedAction::AdcsEsc9 {
                        template: String::new(),
                        ca: String::new(),
                        victim: String::new(),
                        target_upn: String::new(),
                    },
                    77,
                    NoiseLevel::Low,
                ),
                (
                    "adcs_esc10",
                    "ADCS ESC10 - weak certificate mapping abuse",
                    PlannedAction::AdcsEsc10 {
                        template: String::new(),
                        ca: String::new(),
                        victim: String::new(),
                        target_upn: String::new(),
                        variant: String::new(),
                    },
                    76,
                    NoiseLevel::Low,
                ),
                (
                    "adcs_esc11",
                    "ADCS ESC11 - IF_ENFORCEENCRYPTICERTREQUEST relay path",
                    PlannedAction::AdcsEsc11 {
                        ca: String::new(),
                        template: String::new(),
                        target_upn: String::new(),
                    },
                    75,
                    NoiseLevel::Medium,
                ),
                (
                    "adcs_esc12",
                    "ADCS ESC12 - vulnerable CA certificate or key material path",
                    PlannedAction::AdcsEsc12 {
                        ca_host: String::new(),
                        ca_name: String::new(),
                    },
                    74,
                    NoiseLevel::Medium,
                ),
                (
                    "adcs_esc13",
                    "ADCS ESC13 - issuance policy OID group link abuse",
                    PlannedAction::AdcsEsc13 {
                        template: String::new(),
                        ca: String::new(),
                        target_upn: String::new(),
                    },
                    73,
                    NoiseLevel::Low,
                ),
                (
                    "adcs_esc14",
                    "ADCS ESC14 - certificate mapping / altSecurityIdentities guidance",
                    PlannedAction::AdcsEsc14,
                    72,
                    NoiseLevel::Silent,
                ),
                (
                    "adcs_esc15",
                    "ADCS ESC15 - schema v1 enrollee-supplied subject abuse",
                    PlannedAction::AdcsEsc15 {
                        template: String::new(),
                        ca: String::new(),
                        target_upn: String::new(),
                    },
                    71,
                    NoiseLevel::Low,
                ),
                (
                    "adcs_esc16",
                    "ADCS ESC16 - CA security extension disablement path",
                    PlannedAction::AdcsEsc16 {
                        template: String::new(),
                        ca: String::new(),
                        victim: String::new(),
                        target_upn: String::new(),
                    },
                    70,
                    NoiseLevel::Low,
                ),
            ];

            for (key, description, action, priority, noise) in additional_adcs {
                if failed(key) {
                    continue;
                }
                steps.push(PlanStep {
                    id: next_id(),
                    description: description.to_string(),
                    stage: Stage::Attack,
                    action,
                    priority,
                    noise,
                    depends_on: vec![adcs_enum_id.clone()],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }
        }

        // ── Phase 3: Delegation Abuse ──
        if !failed("constrained_delegation") {
            for delegation in &state.constrained_delegation {
                let target_spn = delegation.targets.first().cloned().unwrap_or_default();
                if delegation.account.is_empty() || target_spn.is_empty() {
                    continue;
                }
                steps.push(PlanStep {
                    id: next_id(),
                    description: format!(
                        "Abuse constrained delegation: {} -> {}",
                        delegation.account, target_spn
                    ),
                    stage: Stage::Attack,
                    action: PlannedAction::ConstrainedDelegation {
                        account: delegation.account.clone(),
                        target_spn,
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
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }
        }

        if !failed("unconstrained_delegation") {
            for target_host in &state.unconstrained_delegation {
                steps.push(PlanStep {
                    id: next_id(),
                    description: format!(
                        "Prepare unconstrained delegation capture on {target_host}"
                    ),
                    stage: Stage::Attack,
                    action: PlannedAction::UnconstrainedDelegation {
                        target_host: target_host.clone(),
                    },
                    priority: 84,
                    noise: NoiseLevel::Low,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }
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
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }
        }

        // ── Phase 4.5: RBCD Attack (if we have a controlled computer & write access) ──
        if !state.rbcd_targets.is_empty() && !failed("rbcd") {
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
                        reversible: false,
                        compensation: None,
                        parallel_safe: false,
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
                        reversible: false,
                        compensation: None,
                        parallel_safe: false,
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
                        reversible: false,
                        compensation: None,
                        parallel_safe: false,
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
                        reversible: false,
                        compensation: None,
                        parallel_safe: false,
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
                    action: PlannedAction::CheckAdminAccess { targets: unchecked },
                    priority: 65,
                    noise: NoiseLevel::Medium,
                    depends_on: vec![],
                    executed: false,
                    result: None,
                    retries: 0,
                    max_retries: 1,
                    reversible: false,
                    compensation: None,
                    parallel_safe: false,
                });
            }
        }

        // ── Phase 7: DCSync / NTDS Dump (final goal) ──
        if state.has_domain_admin
            && matches!(
                goal,
                AttackGoal::DumpNtds { .. } | AttackGoal::DomainAdmin { .. }
            )
        {
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
                reversible: false,
                compensation: None,
                parallel_safe: false,
            });
        }

        // ── Phase 8: Coercion (if other paths blocked) ──
        if !state.has_domain_admin
            && !state.unconstrained_delegation.is_empty()
            && !failed("coerce")
            && self.max_noise >= NoiseLevel::Medium
        {
            steps.push(PlanStep {
                id: next_id(),
                description: "Coerce DC authentication to unconstrained delegation host"
                    .to_string(),
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
                reversible: false,
                compensation: None,
                parallel_safe: false,
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
