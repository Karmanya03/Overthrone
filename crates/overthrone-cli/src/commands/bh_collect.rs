//! BloodHound-compatible LDAP collection (SharpHound-equivalent).
//!
//! Queries AD via LDAP and produces JSON files consumable by BloodHound CE / SharpHound.

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

// ============================================================
//  BloodHound-compatible JSON structures
// ============================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct BhDomain {
    #[serde(rename = "ObjectType")]
    pub object_type: String,
    #[serde(rename = "Properties")]
    pub properties: serde_json::Value,
    #[serde(rename = "Members")]
    pub members: Vec<BhReference>,
    #[serde(rename = "Aces")]
    pub aces: Vec<BhAce>,
    #[serde(rename = "ChildObjects")]
    pub child_objects: Vec<serde_json::Value>,
    #[serde(rename = "Trusts")]
    pub trusts: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct BhUser {
    #[serde(rename = "ObjectType")]
    pub object_type: String,
    #[serde(rename = "Properties")]
    pub properties: serde_json::Value,
    #[serde(rename = "MembersOf")]
    pub members_of: Vec<BhReference>,
    #[serde(rename = "Aces")]
    pub aces: Vec<BhAce>,
    #[serde(rename = "Sessions")]
    pub sessions: Vec<serde_json::Value>,
    #[serde(rename = "RemoteDesktopRights")]
    pub rdp_rights: Vec<serde_json::Value>,
    #[serde(rename = "AllowDelegRightsTo")]
    pub allow_deleg: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct BhComputer {
    #[serde(rename = "ObjectType")]
    pub object_type: String,
    #[serde(rename = "Properties")]
    pub properties: serde_json::Value,
    #[serde(rename = "MembersOf")]
    pub members_of: Vec<BhReference>,
    #[serde(rename = "Aces")]
    pub aces: Vec<BhAce>,
    #[serde(rename = "Sessions")]
    pub sessions: Vec<serde_json::Value>,
    #[serde(rename = "PrivilegedSessions")]
    pub priv_sessions: Vec<serde_json::Value>,
    #[serde(rename = "RegistrySessions")]
    pub reg_sessions: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct BhGroup {
    #[serde(rename = "ObjectType")]
    pub object_type: String,
    #[serde(rename = "Properties")]
    pub properties: serde_json::Value,
    #[serde(rename = "Members")]
    pub members: Vec<BhReference>,
    #[serde(rename = "Aces")]
    pub aces: Vec<BhAce>,
    #[serde(rename = "ChildObjects")]
    pub child_objects: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BhReference {
    #[serde(rename = "ObjectIdentifier")]
    pub object_id: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BhAce {
    #[serde(rename = "PrincipalSID")]
    pub principal_sid: String,
    #[serde(rename = "PrincipalType")]
    pub principal_type: String,
    #[serde(rename = "RightName")]
    pub right_name: String,
    #[serde(rename = "IsInherited")]
    pub is_inherited: bool,
    #[serde(rename = "AceType")]
    pub ace_type: String,
}

// ============================================================
//  Collector
// ============================================================

pub struct BhCollector<'a> {
    conn: &'a mut LdapSession,
    #[allow(dead_code)]
    output_dir: String,
    #[allow(dead_code)]
    domain_sid: String,
    domain_name: String,
}

impl<'a> BhCollector<'a> {
    pub fn new(
        conn: &'a mut LdapSession,
        output_dir: &str,
        domain_sid: &str,
        domain_name: &str,
    ) -> Self {
        Self {
            conn,
            output_dir: output_dir.to_string(),
            domain_sid: domain_sid.to_string(),
            domain_name: domain_name.to_string(),
        }
    }

    /// Run all collectors and write JSON files to `output_dir`.
    #[allow(dead_code)]
    pub async fn collect_all(&mut self) -> Result<()> {
        let output_dir = self.output_dir.clone();
        let dir = Path::new(&output_dir);
        std::fs::create_dir_all(dir).map_err(|e| {
            overthrone_core::error::OverthroneError::Ldap {
                target: output_dir.clone(),
                reason: format!("Failed to create output directory: {e}"),
            }
        })?;

        info!("Starting BloodHound collection -> {output_dir}");

        let users = self.collect_users().await?;
        info!("Collected {} users", users.len());
        let computers = self.collect_computers().await?;
        info!("Collected {} computers", computers.len());
        let groups = self.collect_groups().await?;
        info!("Collected {} groups", groups.len());
        let domains = self.collect_domains().await?;
        info!("Collected {} domains", domains.len());
        let gpos = self.collect_gpos().await?;
        info!("Collected {} GPOs", gpos.len());
        let ous = self.collect_ous().await?;
        info!("Collected {} OUs", ous.len());

        write_json(dir, "users.json", &users)?;
        write_json(dir, "computers.json", &computers)?;
        write_json(dir, "groups.json", &groups)?;
        write_json(dir, "domains.json", &domains)?;
        write_json(dir, "gpos.json", &gpos)?;
        write_json(dir, "ous.json", &ous)?;

        info!("BloodHound collection complete -> {output_dir}");
        Ok(())
    }

    // ----------------------------------------------------------
    //  Users
    // ----------------------------------------------------------

    pub async fn collect_users(&mut self) -> Result<Vec<BhUser>> {
        let attrs = &[
            "sAMAccountName",
            "objectSid",
            "userAccountControl",
            "memberOf",
            "servicePrincipalName",
            "msDS-AllowedToDelegateTo",
            "adminCount",
            "description",
            "pwdLastSet",
            "lastLogon",
            "displayName",
            "title",
            "department",
            "mail",
            "homeDirectory",
            "scriptPath",
            "profilePath",
            "member",
            "distinguishedName",
        ];

        let entries = self
            .conn
            .custom_search("(&(objectClass=user)(objectCategory=person))", attrs)
            .await?;

        // Fetch ACLs for all user objects
        let acls = self
            .conn
            .enumerate_acls("(&(objectClass=user)(objectCategory=person))")
            .await
            .unwrap_or_default();

        // Index ACLs by DN for fast lookup
        let mut acl_map: HashMap<String, Vec<overthrone_core::proto::ldap::AceEntry>> =
            HashMap::new();
        for dacl in &acls {
            acl_map.insert(dacl.object_dn.clone(), dacl.aces.clone());
        }

        let mut users = Vec::with_capacity(entries.len());
        for entry in &entries {
            let sam = get_attr(entry, "sAMAccountName").unwrap_or_default();
            let dn = entry.dn.clone();
            let sid = sid_from_entry(entry);
            let uac = get_attr_u32(entry, "userAccountControl");
            let enabled = uac & 0x2 == 0;
            let spns = get_attr_list(entry, "servicePrincipalName");
            let member_of = dn_to_object_refs(get_attr_list(entry, "memberOf"));
            let deleg_to = get_attr_list(entry, "msDS-AllowedToDelegateTo");

            let mut properties = serde_json::json!({
                "name": sam.to_uppercase(),
                "domain": self.domain_name,
                "sid": sid,
                "enabled": enabled,
                "admincount": get_attr_bool(entry, "adminCount"),
                "description": get_attr(entry, "description"),
                "displayname": get_attr(entry, "displayName"),
                "title": get_attr(entry, "title"),
                "department": get_attr(entry, "department"),
                "email": get_attr(entry, "mail"),
                "homedirectory": get_attr(entry, "homeDirectory"),
                "scriptpath": get_attr(entry, "scriptPath"),
                "profilepath": get_attr(entry, "profilePath"),
                "pwdlastset": get_attr(entry, "pwdLastSet").and_then(|v| v.parse::<i64>().ok()),
                "lastlogon": get_attr(entry, "lastLogon").and_then(|v| v.parse::<i64>().ok()),
                "dontreqpreauth": uac & 0x400000 != 0,
                "passwordnotreqd": uac & 0x20 != 0,
                "hasspn": !spns.is_empty(),
                "unconstraineddelegation": uac & 0x80000 != 0,
                "trustedtoauth": uac & 0x800000 != 0,
                "敏感用户": false,
            });

            // Merge Kerberos-specific properties into the Value
            if let serde_json::Value::Object(ref mut map) = properties {
                map.insert(
                    "serviceprincipalnames".to_string(),
                    serde_json::to_value(&spns).unwrap_or_default(),
                );
                map.insert(
                    "allowedtodelegate".to_string(),
                    serde_json::to_value(&deleg_to).unwrap_or_default(),
                );
            }

            let aces = acl_map
                .get(&dn)
                .map(|aces| aces.iter().map(bh_ace_from_entry).collect())
                .unwrap_or_default();

            users.push(BhUser {
                object_type: "User".to_string(),
                properties,
                members_of: member_of,
                aces,
                sessions: Vec::new(),
                rdp_rights: Vec::new(),
                allow_deleg: deleg_to
                    .into_iter()
                    .map(|s| serde_json::json!({"ObjectIdentifier": s, "ObjectType": "User"}))
                    .collect(),
            });
        }

        Ok(users)
    }

    // ----------------------------------------------------------
    //  Computers
    // ----------------------------------------------------------

    pub async fn collect_computers(&mut self) -> Result<Vec<BhComputer>> {
        let attrs = &[
            "sAMAccountName",
            "objectSid",
            "operatingSystem",
            "operatingSystemVersion",
            "dNSHostName",
            "servicePrincipalName",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "adminCount",
            "memberOf",
            "userAccountControl",
            "distinguishedName",
            "lastLogon",
        ];

        let entries = self
            .conn
            .custom_search("(objectClass=computer)", attrs)
            .await?;

        let acls = self
            .conn
            .enumerate_acls("(objectClass=computer)")
            .await
            .unwrap_or_default();

        let mut acl_map: HashMap<String, Vec<overthrone_core::proto::ldap::AceEntry>> =
            HashMap::new();
        for dacl in &acls {
            acl_map.insert(dacl.object_dn.clone(), dacl.aces.clone());
        }

        let mut computers = Vec::with_capacity(entries.len());
        for entry in &entries {
            let sam = get_attr(entry, "sAMAccountName").unwrap_or_default();
            let dn = entry.dn.clone();
            let sid = sid_from_entry(entry);
            let uac = get_attr_u32(entry, "userAccountControl");
            let enabled = uac & 0x2 == 0;
            let spns = get_attr_list(entry, "servicePrincipalName");
            let member_of = dn_to_object_refs(get_attr_list(entry, "memberOf"));
            let deleg_to = get_attr_list(entry, "msDS-AllowedToDelegateTo");
            let os = get_attr(entry, "operatingSystem").unwrap_or_default();
            let os_version = get_attr(entry, "operatingSystemVersion").unwrap_or_default();
            let dns = get_attr(entry, "dNSHostName").unwrap_or_default();

            let properties = serde_json::json!({
                "name": sam.trim_end_matches('$').to_uppercase(),
                "domain": self.domain_name,
                "sid": sid,
                "enabled": enabled,
                "operatingsystem": os,
                "operatingsystemversion": os_version,
                "dnshostname": dns,
                "admincount": get_attr_bool(entry, "adminCount"),
                "unconstraineddelegation": uac & 0x80000 != 0,
                "trustedtoauth": uac & 0x800000 != 0,
                "lastlogon": get_attr(entry, "lastLogon").and_then(|v| v.parse::<i64>().ok()),
                "allowpsremote": uac & 0x40000 != 0,
                "serviceprincipalnames": spns,
                "allowedtodelegate": deleg_to,
            });

            let aces = acl_map
                .get(&dn)
                .map(|aces| aces.iter().map(bh_ace_from_entry).collect())
                .unwrap_or_default();

            computers.push(BhComputer {
                object_type: "Computer".to_string(),
                properties,
                members_of: member_of,
                aces,
                sessions: Vec::new(),
                priv_sessions: Vec::new(),
                reg_sessions: Vec::new(),
            });
        }

        Ok(computers)
    }

    // ----------------------------------------------------------
    //  Groups
    // ----------------------------------------------------------

    pub async fn collect_groups(&mut self) -> Result<Vec<BhGroup>> {
        let attrs = &[
            "sAMAccountName",
            "objectSid",
            "member",
            "adminCount",
            "description",
            "distinguishedName",
            "memberOf",
        ];

        let entries = self
            .conn
            .custom_search("(objectClass=group)", attrs)
            .await?;

        let acls = self
            .conn
            .enumerate_acls("(objectClass=group)")
            .await
            .unwrap_or_default();

        let mut acl_map: HashMap<String, Vec<overthrone_core::proto::ldap::AceEntry>> =
            HashMap::new();
        for dacl in &acls {
            acl_map.insert(dacl.object_dn.clone(), dacl.aces.clone());
        }

        let mut groups = Vec::with_capacity(entries.len());
        for entry in &entries {
            let sam = get_attr(entry, "sAMAccountName").unwrap_or_default();
            let dn = entry.dn.clone();
            let sid = sid_from_entry(entry);
            let members = dn_to_object_refs(get_attr_list(entry, "member"));
            let admin_count = get_attr_bool(entry, "adminCount");

            let properties = serde_json::json!({
                "name": sam.to_uppercase(),
                "domain": self.domain_name,
                "sid": sid,
                "admincount": admin_count,
                "description": get_attr(entry, "description"),
                "dn": dn,
            });

            let aces = acl_map
                .get(&dn)
                .map(|aces| aces.iter().map(bh_ace_from_entry).collect())
                .unwrap_or_default();

            groups.push(BhGroup {
                object_type: "Group".to_string(),
                properties,
                members,
                aces,
                child_objects: Vec::new(),
            });
        }

        Ok(groups)
    }

    // ----------------------------------------------------------
    //  Domains
    // ----------------------------------------------------------

    pub async fn collect_domains(&mut self) -> Result<Vec<BhDomain>> {
        let attrs = &[
            "objectSid",
            "domainFunctionality",
            "netBIOSName",
            "dnsRoot",
            "distinguishedName",
            "description",
        ];

        let entries = self
            .conn
            .custom_search("(objectClass=domain)", attrs)
            .await?;

        let acls = self
            .conn
            .enumerate_acls("(objectClass=domain)")
            .await
            .unwrap_or_default();

        let mut acl_map: HashMap<String, Vec<overthrone_core::proto::ldap::AceEntry>> =
            HashMap::new();
        for dacl in &acls {
            acl_map.insert(dacl.object_dn.clone(), dacl.aces.clone());
        }

        let mut domains = Vec::with_capacity(entries.len());
        for entry in &entries {
            let dn = entry.dn.clone();
            let sid = sid_from_entry(entry);
            let netbios = get_attr(entry, "netBIOSName").unwrap_or_default();
            let dns_root = get_attr(entry, "dnsRoot").unwrap_or_default();
            let func_level = get_attr_u32(entry, "domainFunctionality");

            let properties = serde_json::json!({
                "name": self.domain_name.to_uppercase(),
                "domain": self.domain_name,
                "sid": sid,
                "netbiosname": netbios,
                "dnsroot": dns_root,
                "functionalitylevel": func_level,
                "description": get_attr(entry, "description"),
                "dn": dn,
            });

            let aces = acl_map
                .get(&dn)
                .map(|aces| aces.iter().map(bh_ace_from_entry).collect())
                .unwrap_or_default();

            domains.push(BhDomain {
                object_type: "Domain".to_string(),
                properties,
                members: Vec::new(),
                aces,
                child_objects: Vec::new(),
                trusts: Vec::new(),
            });
        }

        Ok(domains)
    }

    // ----------------------------------------------------------
    //  GPOs
    // ----------------------------------------------------------

    pub async fn collect_gpos(&mut self) -> Result<Vec<serde_json::Value>> {
        let attrs = &[
            "displayName",
            "cn",
            "gPCFileSysPath",
            "distinguishedName",
            "whenChanged",
            "flags",
            "gPCFunctionalityVersion",
        ];

        let entries = self
            .conn
            .custom_search("(objectClass=groupPolicyContainer)", attrs)
            .await?;

        let mut gpos = Vec::with_capacity(entries.len());
        for entry in &entries {
            let display_name = get_attr(entry, "displayName").unwrap_or_default();
            let cn = get_attr(entry, "cn").unwrap_or_default();
            let gpc_path = get_attr(entry, "gPCFileSysPath").unwrap_or_default();
            let flags = get_attr_u32(entry, "flags");
            let func_ver = get_attr_u32(entry, "gPCFunctionalityVersion");

            gpos.push(serde_json::json!({
                "ObjectType": "GPO",
                "Properties": {
                    "name": display_name,
                    "domain": self.domain_name,
                    "guid": cn,
                    "gpcpath": gpc_path,
                    "flags": flags,
                    "functionalityversion": func_ver,
                    "whenchanged": get_attr(entry, "whenChanged"),
                    "dn": entry.dn,
                },
                "Aces": [],
                "ChildObjects": [],
            }));
        }

        Ok(gpos)
    }

    // ----------------------------------------------------------
    //  OUs
    // ----------------------------------------------------------

    pub async fn collect_ous(&mut self) -> Result<Vec<serde_json::Value>> {
        let attrs = &[
            "distinguishedName",
            "name",
            "description",
            "managedBy",
            "nTSecurityDescriptor",
        ];

        let entries = self
            .conn
            .custom_search("(objectClass=organizationalUnit)", attrs)
            .await?;

        let acls = self
            .conn
            .enumerate_acls("(objectClass=organizationalUnit)")
            .await
            .unwrap_or_default();

        let mut acl_map: HashMap<String, Vec<overthrone_core::proto::ldap::AceEntry>> =
            HashMap::new();
        for dacl in &acls {
            acl_map.insert(dacl.object_dn.clone(), dacl.aces.clone());
        }

        let mut ous = Vec::with_capacity(entries.len());
        for entry in &entries {
            let dn = entry.dn.clone();
            let name = get_attr(entry, "name").unwrap_or_default();

            let aces: Vec<BhAce> = acl_map
                .get(&dn)
                .map(|aces| aces.iter().map(bh_ace_from_entry).collect())
                .unwrap_or_default();

            ous.push(serde_json::json!({
                "ObjectType": "OU",
                "Properties": {
                    "name": name,
                    "domain": self.domain_name,
                    "description": get_attr(entry, "description"),
                    "managedby": get_attr(entry, "managedBy"),
                    "dn": dn,
                },
                "Aces": aces,
                "ChildObjects": [],
                "Links": [],
            }));
        }

        Ok(ous)
    }
}

// ============================================================
//  Helpers
// ============================================================

#[allow(dead_code)]
fn write_json<T: Serialize>(dir: &Path, filename: &str, data: &T) -> Result<()> {
    let path = dir.join(filename);
    let wrapper = serde_json::json!({ "data": data });
    let json = serde_json::to_string_pretty(&wrapper).map_err(|e| {
        overthrone_core::error::OverthroneError::Ldap {
            target: filename.to_string(),
            reason: format!("JSON serialization failed: {e}"),
        }
    })?;
    std::fs::write(&path, json).map_err(|e| overthrone_core::error::OverthroneError::Ldap {
        target: path.display().to_string(),
        reason: format!("Write failed: {e}"),
    })?;
    info!("Wrote {}", path.display());
    Ok(())
}

/// Get the first string value of a named attribute from a `SearchEntry`.
fn get_attr(entry: &ldap3::SearchEntry, attr: &str) -> Option<String> {
    entry.attrs.get(attr).and_then(|v| v.first()).cloned()
}

/// Get all string values of a named attribute.
fn get_attr_list(entry: &ldap3::SearchEntry, attr: &str) -> Vec<String> {
    entry.attrs.get(attr).cloned().unwrap_or_default()
}

/// Parse a u32 attribute, defaulting to 0.
fn get_attr_u32(entry: &ldap3::SearchEntry, attr: &str) -> u32 {
    get_attr(entry, attr)
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Parse a boolean attribute (AD stores 1/0 or TRUE/FALSE).
fn get_attr_bool(entry: &ldap3::SearchEntry, attr: &str) -> bool {
    matches!(
        get_attr(entry, attr).as_deref(),
        Some("1") | Some("TRUE") | Some("true")
    )
}

/// Extract the SID string from `objectSid` binary attribute in a SearchEntry.
fn sid_from_entry(entry: &ldap3::SearchEntry) -> String {
    entry
        .bin_attrs
        .get("objectSid")
        .and_then(|v| v.first())
        .map(|bytes| sid_bytes_to_string(bytes))
        .unwrap_or_default()
}

/// Convert binary SID bytes (MS-DTYP 2.4.2.2) to S-1-5-... string form.
pub fn sid_bytes_to_string(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return String::new();
    }
    let revision = bytes[0];
    let sub_count = bytes[1] as usize;
    // Authority is bytes[2..8], big-endian u48
    let authority = u64::from_be_bytes({
        let mut buf = [0u8; 8];
        buf[2..8].copy_from_slice(&bytes[2..8]);
        buf
    });

    let mut sid = format!("S-{revision}-{authority}");
    for i in 0..sub_count {
        let start = 8 + i * 4;
        if start + 4 > bytes.len() {
            break;
        }
        let sub = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        sid.push('-');
        sid.push_str(&sub.to_string());
    }
    sid
}

/// Convert a list of DNs (from `memberOf` / `member`) to `BhReference` objects.
fn dn_to_object_refs(dns: Vec<String>) -> Vec<BhReference> {
    dns.into_iter()
        .map(|dn| {
            let (object_type, name) = dn_type_and_name(&dn);
            BhReference {
                object_id: name,
                object_type,
            }
        })
        .collect()
}

/// Guess the object type and extract a name from a DN.
/// e.g. `CN=Domain Admins,CN=Users,DC=corp,DC=local` -> ("Group", "DOMAIN ADMINS@CORP.LOCAL")
fn dn_type_and_name(dn: &str) -> (String, String) {
    // Extract the CN= or OU= component
    let first_rdn = dn.split(',').next().unwrap_or(dn);
    let name = if let Some(cn) = first_rdn.strip_prefix("CN=") {
        cn.to_string()
    } else if let Some(ou) = first_rdn.strip_prefix("OU=") {
        ou.to_string()
    } else {
        first_rdn.to_string()
    };

    // Guess type from DN pattern
    let lower = dn.to_lowercase();
    let object_type =
        if lower.contains("cn=users") || lower.contains("cn=foreignsecurityprincipals") {
            // Member is typically a user if its DN is under CN=Users
            "User"
        } else if lower.contains("cn=computers") {
            "Computer"
        } else if lower.starts_with("cn=") {
            // Default: if it starts with CN=, it's likely a User or Group
            "User"
        } else if lower.starts_with("ou=") {
            "OU"
        } else {
            "Base"
        };

    (object_type.to_string(), name.to_uppercase())
}

/// Map a core `AceEntry` to a BloodHound `BhAce`.
fn bh_ace_from_entry(ace: &overthrone_core::proto::ldap::AceEntry) -> BhAce {
    let right_name = ace_to_right_name(ace);
    let ace_type = match ace.ace_type {
        overthrone_core::proto::ldap::AceType::AccessAllowed => "Allow".to_string(),
        overthrone_core::proto::ldap::AceType::AccessDenied => "Deny".to_string(),
        overthrone_core::proto::ldap::AceType::AccessAllowedObject => "Allow".to_string(),
        overthrone_core::proto::ldap::AceType::AccessDeniedObject => "Deny".to_string(),
        overthrone_core::proto::ldap::AceType::Unknown(_) => "Allow".to_string(),
    };

    // Determine principal type from SID prefix
    let principal_type = if ace.trustee_sid.ends_with("-512")
        || ace.trustee_sid.ends_with("-518")
        || ace.trustee_sid.ends_with("-519")
        || ace.trustee_sid.ends_with("-520")
    {
        "Group"
    } else if ace.trustee_sid.ends_with("-516") {
        "Computer"
    } else {
        "User"
    };

    BhAce {
        principal_sid: ace.trustee_sid.clone(),
        principal_type: principal_type.to_string(),
        right_name,
        is_inherited: ace.ace_flags & 0x10 != 0, // CONTAINER_INHERIT_ACE
        ace_type,
    }
}

/// Map an ACE access mask + object type GUID to a BloodHound right name string.
fn ace_to_right_name(ace: &overthrone_core::proto::ldap::AceEntry) -> String {
    // Check well-known extended right GUIDs first (object-specific ACEs)
    if let Some(ref obj_type) = ace.object_type {
        let guid_lower = obj_type.to_lowercase();
        return match guid_lower.as_str() {
            // User-Force-Change-Password
            "00299570-246d-11d0-a768-00aa006e0529" => "ForceChangePassword".to_string(),
            // DS-Replication-Get-Changes
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" => "GetChanges".to_string(),
            // DS-Replication-Get-Changes-All
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" => "GetChangesAll".to_string(),
            // DS-Replication-Get-Changes-In-Filtered-Set
            "89e95b76-444d-4c62-991a-0facbeda640c" => "GetChangesInFilteredSet".to_string(),
            // Self-Membership / Write-Member
            "bf9679c0-0de6-11d0-a285-00aa003049e2" => {
                if ace.access_mask & 0x04 != 0 {
                    "AddMember".to_string()
                } else {
                    "AddSelf".to_string()
                }
            }
            // User-Account-Restrictions (Write)
            "bf9679c4-0de6-11d0-a285-00aa003049e2" => "WriteAccountRestrictions".to_string(),
            // SPN write
            "f3a647f4-5a21-11d0-a763-00aa006e0529" => "WriteSPN".to_string(),
            // Generic-Write / validated-SPN equivalent
            _ => {
                // Fall through to mask-based check
                mask_to_right_name(ace)
            }
        };
    }

    mask_to_right_name(ace)
}

/// Map raw access mask bits to BloodHound right names.
fn mask_to_right_name(ace: &overthrone_core::proto::ldap::AceEntry) -> String {
    let mask = ace.access_mask;

    // GenericAll: 0x10000000 or full control mask 0x001F01FF
    if mask & 0x10000000 != 0 || mask == 0x001F01FF {
        return "GenericAll".to_string();
    }
    // GenericWrite: 0x40000000
    if mask & 0x40000000 != 0 {
        return "GenericWrite".to_string();
    }
    // WriteDacl: 0x00040000
    if mask & 0x00040000 != 0 {
        return "WriteDacl".to_string();
    }
    // WriteOwner: 0x00080000
    if mask & 0x00080000 != 0 {
        return "WriteOwner".to_string();
    }
    // AllExtendedRights: 0x00000100 (ADS_RIGHT_DS_CONTROL_ACCESS)
    if mask & 0x00000100 != 0 && mask & 0x001F01FF == mask {
        return "AllExtendedRights".to_string();
    }
    // ReadLapsPassword: specific GUID-based, but also check for generic read+control
    if mask & 0x001200A9 == mask {
        return "ReadLapsPassword".to_string();
    }
    // Owns: specific SID match (owner), not mask-based
    // WriteProperty / Self: AddSelf
    if mask & 0x00000020 != 0 && mask & 0x00000004 != 0 {
        return "AddSelf".to_string();
    }
    // Default: describe the mask as an integer
    format!("Mask_{mask:#010x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_bytes_to_string_roundtrip() {
        // S-1-5-21-... typical domain SID
        let bytes: Vec<u8> = vec![
            0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x44, 0x3B,
            0x7F, 0x8C, 0x2F, 0xA1, 0xD0, 0x01, 0xF4, 0x35, 0x2D, 0x94, 0x50, 0xF3, 0x37, 0x04,
        ];
        let sid = sid_bytes_to_string(&bytes);
        assert!(sid.starts_with("S-1-5-21-"));
    }

    #[test]
    fn sid_bytes_too_short_returns_empty() {
        assert_eq!(sid_bytes_to_string(&[0x01, 0x02]), "");
    }

    #[test]
    fn bh_ace_from_entry_generic_all() {
        let ace = overthrone_core::proto::ldap::AceEntry {
            ace_type: overthrone_core::proto::ldap::AceType::AccessAllowed,
            ace_flags: 0,
            access_mask: 0x10000000,
            trustee_sid: "S-1-5-21-1234-5678-9012-3456-512".to_string(),
            object_type: None,
            inherited_object_type: None,
        };
        let bh = bh_ace_from_entry(&ace);
        assert_eq!(bh.right_name, "GenericAll");
        assert_eq!(bh.principal_type, "Group");
        assert_eq!(bh.ace_type, "Allow");
    }

    #[test]
    fn bh_ace_from_entry_write_dacl() {
        let ace = overthrone_core::proto::ldap::AceEntry {
            ace_type: overthrone_core::proto::ldap::AceType::AccessAllowed,
            ace_flags: 0,
            access_mask: 0x00040000,
            trustee_sid: "S-1-5-21-1234-5678-9012-3456-1001".to_string(),
            object_type: None,
            inherited_object_type: None,
        };
        let bh = bh_ace_from_entry(&ace);
        assert_eq!(bh.right_name, "WriteDacl");
        assert_eq!(bh.principal_type, "User");
    }

    #[test]
    fn bh_ace_from_entry_force_change_password() {
        let ace = overthrone_core::proto::ldap::AceEntry {
            ace_type: overthrone_core::proto::ldap::AceType::AccessAllowedObject,
            ace_flags: 0,
            access_mask: 0x00000100,
            trustee_sid: "S-1-5-21-1234-5678-9012-3456-512".to_string(),
            object_type: Some("00299570-246d-11d0-a768-00aa006e0529".to_string()),
            inherited_object_type: None,
        };
        let bh = bh_ace_from_entry(&ace);
        assert_eq!(bh.right_name, "ForceChangePassword");
    }

    #[test]
    fn bh_ace_from_entry_inherited_flag() {
        let ace = overthrone_core::proto::ldap::AceEntry {
            ace_type: overthrone_core::proto::ldap::AceType::AccessAllowed,
            ace_flags: 0x10, // CONTAINER_INHERIT
            access_mask: 0x40000000,
            trustee_sid: "S-1-5-18".to_string(),
            object_type: None,
            inherited_object_type: None,
        };
        let bh = bh_ace_from_entry(&ace);
        assert!(bh.is_inherited);
        assert_eq!(bh.right_name, "GenericWrite");
    }

    #[test]
    fn mask_to_right_name_variants() {
        let make_ace = |mask: u32| overthrone_core::proto::ldap::AceEntry {
            ace_type: overthrone_core::proto::ldap::AceType::AccessAllowed,
            ace_flags: 0,
            access_mask: mask,
            trustee_sid: "S-1-5-18".to_string(),
            object_type: None,
            inherited_object_type: None,
        };
        assert_eq!(mask_to_right_name(&make_ace(0x001F01FF)), "GenericAll");
        assert_eq!(mask_to_right_name(&make_ace(0x40000000)), "GenericWrite");
        assert_eq!(mask_to_right_name(&make_ace(0x00080000)), "WriteOwner");
    }

    #[test]
    fn get_attr_u32_missing_defaults_to_zero() {
        let entry = ldap3::SearchEntry {
            dn: "CN=test".to_string(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::new(),
        };
        assert_eq!(get_attr_u32(&entry, "nonexistent"), 0);
    }

    #[test]
    fn get_attr_bool_true_values() {
        let entry = ldap3::SearchEntry {
            dn: "CN=test".to_string(),
            attrs: HashMap::from([("adminCount".to_string(), vec!["1".to_string()])]),
            bin_attrs: HashMap::new(),
        };
        assert!(get_attr_bool(&entry, "adminCount"));
    }

    #[test]
    fn get_attr_bool_false_values() {
        let entry = ldap3::SearchEntry {
            dn: "CN=test".to_string(),
            attrs: HashMap::from([("adminCount".to_string(), vec!["0".to_string()])]),
            bin_attrs: HashMap::new(),
        };
        assert!(!get_attr_bool(&entry, "adminCount"));
    }

    #[test]
    fn dn_to_object_refs_extracts_names() {
        let refs = dn_to_object_refs(vec![
            "CN=Domain Admins,CN=Users,DC=corp,DC=local".to_string(),
            "CN=DC01,OU=Servers,DC=corp,DC=local".to_string(),
        ]);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].object_id, "DOMAIN ADMINS");
        assert_eq!(refs[1].object_id, "DC01");
    }

    #[test]
    fn bh_domain_default() {
        let d = BhDomain::default();
        assert!(d.members.is_empty());
        assert!(d.aces.is_empty());
    }

    #[test]
    fn bh_reference_clone() {
        let r = BhReference {
            object_id: "S-1-5-21-1234".to_string(),
            object_type: "User".to_string(),
        };
        let r2 = r.clone();
        assert_eq!(r.object_id, r2.object_id);
    }

    #[test]
    fn bh_json_wrapper_format() {
        let users: Vec<BhUser> = vec![];
        let wrapper = serde_json::json!({ "data": users });
        let json = serde_json::to_string(&wrapper).unwrap();
        assert!(json.contains("\"data\""));
        assert!(json.contains("[]"));
    }

    #[test]
    fn ace_to_right_name_write_spn() {
        let ace = overthrone_core::proto::ldap::AceEntry {
            ace_type: overthrone_core::proto::ldap::AceType::AccessAllowedObject,
            ace_flags: 0,
            access_mask: 0x00000020, // WRITE_PROP
            trustee_sid: "S-1-5-21-1234-5678-9012-3456-1001".to_string(),
            object_type: Some("f3a647f4-5a21-11d0-a763-00aa006e0529".to_string()),
            inherited_object_type: None,
        };
        let bh = bh_ace_from_entry(&ace);
        assert_eq!(bh.right_name, "WriteSPN");
    }
}
