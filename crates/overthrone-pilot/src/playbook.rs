//! Predefined attack playbooks — curated sequences for common AD attack paths.
//!
//! Each playbook is a named template that generates plan steps.
//! Think of them as "recipes" — the planner can invoke a playbook
//! when it detects the right conditions.

use crate::planner::{NoiseLevel, PlanStep, PlannedAction};
use crate::runner::Stage;
use serde::{Deserialize, Serialize};
use tracing::info;

// ═══════════════════════════════════════════════════════════
// Playbook Identifiers
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlaybookId {
    /// Full recon: users, computers, groups, trusts, GPOs, shares
    FullRecon,
    /// Kerberoast + AS-REP roast + crack
    RoastAndCrack,
    /// Constrained delegation → S4U → impersonate admin
    DelegationAbuse,
    /// RBCD → S4U → service ticket as admin
    RbcdChain,
    /// Coerce DC → relay → compromise DC
    CoerceAndRelay,
    /// PSExec/SMBExec to target → dump creds → pivot
    LateralPivot,
    /// DCSync once DA is achieved
    DcSyncDump,
    /// Golden ticket persistence
    GoldenTicketPersist,
    /// Full automated chain: recon → roast → lateral → DA → loot
    FullAutoPwn,
}

impl std::fmt::Display for PlaybookId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullRecon => write!(f, "Full Recon"),
            Self::RoastAndCrack => write!(f, "Roast & Crack"),
            Self::DelegationAbuse => write!(f, "Delegation Abuse"),
            Self::RbcdChain => write!(f, "RBCD Chain"),
            Self::CoerceAndRelay => write!(f, "Coerce & Relay"),
            Self::LateralPivot => write!(f, "Lateral Pivot"),
            Self::DcSyncDump => write!(f, "DCSync Dump"),
            Self::GoldenTicketPersist => write!(f, "Golden Ticket"),
            Self::FullAutoPwn => write!(f, "Full AutoPwn"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Playbook Definition
// ═══════════════════════════════════════════════════════════

/// A playbook is a named, described collection of plan steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: PlaybookId,
    pub name: String,
    pub description: String,
    pub noise_level: NoiseLevel,
    pub steps: Vec<PlanStep>,
    pub tags: Vec<String>,
}

impl Playbook {
    /// Generate the playbook steps with sequential IDs
    pub fn generate(id: PlaybookId) -> Self {
        match id {
            PlaybookId::FullRecon => Self::full_recon(),
            PlaybookId::RoastAndCrack => Self::roast_and_crack(),
            PlaybookId::DelegationAbuse => Self::delegation_abuse(),
            PlaybookId::RbcdChain => Self::rbcd_chain(),
            PlaybookId::CoerceAndRelay => Self::coerce_and_relay(),
            PlaybookId::LateralPivot => Self::lateral_pivot(),
            PlaybookId::DcSyncDump => Self::dcsync_dump(),
            PlaybookId::GoldenTicketPersist => Self::golden_ticket_persist(),
            PlaybookId::FullAutoPwn => Self::full_autopwn(),
        }
    }

    /// List all available playbooks with descriptions
    pub fn list_all() -> Vec<(PlaybookId, &'static str, NoiseLevel)> {
        vec![
            (PlaybookId::FullRecon, "Comprehensive domain enumeration", NoiseLevel::Silent),
            (PlaybookId::RoastAndCrack, "Kerberoast + AS-REP Roast + offline cracking", NoiseLevel::Low),
            (PlaybookId::DelegationAbuse, "S4U chain via constrained delegation", NoiseLevel::Low),
            (PlaybookId::RbcdChain, "RBCD write → S4U → impersonate", NoiseLevel::Medium),
            (PlaybookId::CoerceAndRelay, "Auth coercion → NTLM relay", NoiseLevel::Medium),
            (PlaybookId::LateralPivot, "Exec on host → dump creds → move", NoiseLevel::High),
            (PlaybookId::DcSyncDump, "DCSync replication of all credentials", NoiseLevel::Critical),
            (PlaybookId::GoldenTicketPersist, "Forge golden ticket from krbtgt hash", NoiseLevel::Critical),
            (PlaybookId::FullAutoPwn, "Full chain: recon → escalate → DA → loot", NoiseLevel::Critical),
        ]
    }

    // ═══════════════════════════════════════════════════════
    // Playbook Builders
    // ═══════════════════════════════════════════════════════

    fn make_step(
        id: &str,
        desc: &str,
        stage: Stage,
        action: PlannedAction,
        priority: i32,
        noise: NoiseLevel,
        deps: Vec<String>,
    ) -> PlanStep {
        PlanStep {
            id: id.to_string(),
            description: desc.to_string(),
            stage,
            action,
            priority,
            noise,
            depends_on: deps,
            executed: false,
            result: None,
            retries: 0,
            max_retries: 2,
        }
    }

    fn full_recon() -> Self {
        let steps = vec![
            Self::make_step("recon_1", "Enumerate all users", Stage::Enumerate, PlannedAction::EnumerateUsers, 100, NoiseLevel::Silent, vec![]),
            Self::make_step("recon_2", "Enumerate all computers", Stage::Enumerate, PlannedAction::EnumerateComputers, 99, NoiseLevel::Silent, vec![]),
            Self::make_step("recon_3", "Enumerate groups & memberships", Stage::Enumerate, PlannedAction::EnumerateGroups, 98, NoiseLevel::Silent, vec![]),
            Self::make_step("recon_4", "Enumerate domain trusts", Stage::Enumerate, PlannedAction::EnumerateTrusts, 97, NoiseLevel::Silent, vec![]),
            Self::make_step("recon_5", "Enumerate GPOs", Stage::Enumerate, PlannedAction::EnumerateGpos, 96, NoiseLevel::Silent, vec![]),
        ];
        Self {
            id: PlaybookId::FullRecon,
            name: "Full Reconnaissance".to_string(),
            description: "Comprehensive LDAP enumeration of all domain objects".to_string(),
            noise_level: NoiseLevel::Silent,
            steps,
            tags: vec!["recon".to_string(), "ldap".to_string(), "safe".to_string()],
        }
    }

    fn roast_and_crack() -> Self {
        let steps = vec![
            Self::make_step("roast_1", "Kerberoast all SPN accounts", Stage::Attack, PlannedAction::Kerberoast { spns: vec![] }, 90, NoiseLevel::Low, vec![]),
            Self::make_step("roast_2", "AS-REP Roast no-preauth accounts", Stage::Attack, PlannedAction::AsRepRoast { users: vec![] }, 88, NoiseLevel::Low, vec![]),
            Self::make_step("roast_3", "Crack obtained hashes", Stage::Attack, PlannedAction::CrackHashes { hashes: vec![] }, 85, NoiseLevel::Silent, vec!["roast_1".to_string(), "roast_2".to_string()]),
        ];
        Self {
            id: PlaybookId::RoastAndCrack,
            name: "Roast & Crack".to_string(),
            description: "Extract and crack Kerberos hashes for offline password recovery".to_string(),
            noise_level: NoiseLevel::Low,
            steps,
            tags: vec!["kerberos".to_string(), "cracking".to_string()],
        }
    }

    fn delegation_abuse() -> Self {
        let steps = vec![
            Self::make_step("deleg_1", "Enumerate constrained delegation accounts", Stage::Enumerate, PlannedAction::EnumerateUsers, 90, NoiseLevel::Silent, vec![]),
            Self::make_step("deleg_2", "S4U2Self → S4U2Proxy impersonation chain", Stage::Attack, PlannedAction::ConstrainedDelegation { account: String::new(), target_spn: String::new(), impersonate: "Administrator".to_string() }, 85, NoiseLevel::Low, vec!["deleg_1".to_string()]),
            Self::make_step("deleg_3", "Verify admin access with impersonated ticket", Stage::Lateral, PlannedAction::CheckAdminAccess { targets: vec![] }, 80, NoiseLevel::Medium, vec!["deleg_2".to_string()]),
        ];
        Self {
            id: PlaybookId::DelegationAbuse,
            name: "Delegation Abuse".to_string(),
            description: "Exploit constrained delegation for privilege escalation via S4U".to_string(),
            noise_level: NoiseLevel::Low,
            steps,
            tags: vec!["kerberos".to_string(), "delegation".to_string(), "s4u".to_string()],
        }
    }

    fn rbcd_chain() -> Self {
        let steps = vec![
            Self::make_step("rbcd_1", "Identify RBCD-writable targets", Stage::Enumerate, PlannedAction::EnumerateComputers, 90, NoiseLevel::Silent, vec![]),
            Self::make_step("rbcd_2", "Write RBCD attribute + S4U chain", Stage::Attack, PlannedAction::RbcdAttack { controlled: String::new(), target: String::new() }, 85, NoiseLevel::Medium, vec!["rbcd_1".to_string()]),
            Self::make_step("rbcd_3", "Access target with impersonated ticket", Stage::Lateral, PlannedAction::CheckAdminAccess { targets: vec![] }, 80, NoiseLevel::Medium, vec!["rbcd_2".to_string()]),
        ];
        Self {
            id: PlaybookId::RbcdChain,
            name: "RBCD Chain".to_string(),
            description: "Resource-Based Constrained Delegation attack chain".to_string(),
            noise_level: NoiseLevel::Medium,
            steps,
            tags: vec!["rbcd".to_string(), "delegation".to_string()],
        }
    }

    fn coerce_and_relay() -> Self {
        let steps = vec![
            Self::make_step("coerce_1", "Identify unconstrained delegation hosts", Stage::Enumerate, PlannedAction::EnumerateComputers, 90, NoiseLevel::Silent, vec![]),
            Self::make_step("coerce_2", "Coerce DC authentication", Stage::Attack, PlannedAction::Coerce { target: String::new(), listener: String::new() }, 80, NoiseLevel::Medium, vec!["coerce_1".to_string()]),
            Self::make_step("coerce_3", "Checkpoint: verify captured TGT", Stage::Attack, PlannedAction::Checkpoint { message: "Verify TGT captured from coercion".to_string() }, 75, NoiseLevel::Silent, vec!["coerce_2".to_string()]),
        ];
        Self {
            id: PlaybookId::CoerceAndRelay,
            name: "Coerce & Relay".to_string(),
            description: "Coerce DC authentication and capture/relay credentials".to_string(),
            noise_level: NoiseLevel::Medium,
            steps,
            tags: vec!["coercion".to_string(), "relay".to_string()],
        }
    }

    fn lateral_pivot() -> Self {
        let steps = vec![
            Self::make_step("lat_1", "Execute on target host via SMBExec", Stage::Lateral, PlannedAction::SmbExec { target: String::new(), command: "whoami /all".to_string() }, 85, NoiseLevel::Medium, vec![]),
            Self::make_step("lat_2", "Dump LSA secrets", Stage::Escalate, PlannedAction::DumpLsa { target: String::new() }, 80, NoiseLevel::High, vec!["lat_1".to_string()]),
            Self::make_step("lat_3", "Dump SAM database", Stage::Escalate, PlannedAction::DumpSam { target: String::new() }, 78, NoiseLevel::High, vec!["lat_1".to_string()]),
            Self::make_step("lat_4", "Check admin with new creds", Stage::Lateral, PlannedAction::CheckAdminAccess { targets: vec![] }, 70, NoiseLevel::Medium, vec!["lat_2".to_string()]),
        ];
        Self {
            id: PlaybookId::LateralPivot,
            name: "Lateral Pivot".to_string(),
            description: "Exec on host, dump credentials, and pivot to new targets".to_string(),
            noise_level: NoiseLevel::High,
            steps,
            tags: vec!["lateral".to_string(), "exec".to_string(), "dumping".to_string()],
        }
    }

    fn dcsync_dump() -> Self {
        let steps = vec![
            Self::make_step("dc_1", "DCSync — replicate all domain credentials", Stage::Loot, PlannedAction::DcsSync { target_user: None }, 100, NoiseLevel::Critical, vec![]),
        ];
        Self {
            id: PlaybookId::DcSyncDump,
            name: "DCSync".to_string(),
            description: "Replicate domain credentials via Directory Replication Service".to_string(),
            noise_level: NoiseLevel::Critical,
            steps,
            tags: vec!["dcsync".to_string(), "ntds".to_string(), "da_required".to_string()],
        }
    }

    fn golden_ticket_persist() -> Self {
        let steps = vec![
            Self::make_step("gt_1", "DCSync krbtgt hash", Stage::Loot, PlannedAction::DcsSync { target_user: Some("krbtgt".to_string()) }, 100, NoiseLevel::Critical, vec![]),
            Self::make_step("gt_2", "Forge golden ticket", Stage::Loot, PlannedAction::ForgeGoldenTicket { krbtgt_hash: String::new() }, 95, NoiseLevel::Silent, vec!["gt_1".to_string()]),
        ];
        Self {
            id: PlaybookId::GoldenTicketPersist,
            name: "Golden Ticket".to_string(),
            description: "Forge a golden ticket for persistent domain access".to_string(),
            noise_level: NoiseLevel::Critical,
            steps,
            tags: vec!["persistence".to_string(), "golden_ticket".to_string()],
        }
    }

    fn full_autopwn() -> Self {
        // Composite: chain multiple playbooks
        let mut steps = Vec::new();
        let recon = Self::full_recon();
        let roast = Self::roast_and_crack();
        let deleg = Self::delegation_abuse();
        let pivot = Self::lateral_pivot();
        let dump = Self::dcsync_dump();

        steps.extend(recon.steps);
        steps.extend(roast.steps);
        steps.extend(deleg.steps);
        steps.extend(pivot.steps);
        steps.extend(dump.steps);

        // Re-number steps to avoid ID collisions
        for (i, step) in steps.iter_mut().enumerate() {
            step.id = format!("auto_{:03}", i + 1);
            // Clear deps since we're executing sequentially with adaptive re-planning
            step.depends_on.clear();
        }

        Self {
            id: PlaybookId::FullAutoPwn,
            name: "Full AutoPwn".to_string(),
            description: "Automated full chain: recon → roast → delegate → lateral → DA → loot".to_string(),
            noise_level: NoiseLevel::Critical,
            steps,
            tags: vec!["autopwn".to_string(), "full_chain".to_string()],
        }
    }
}
