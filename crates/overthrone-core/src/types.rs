//! Shared type definitions used across all Overthrone crates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════
//  Domain
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub netbios_name: String,
    /// Security Identifier
    pub sid: String,
    /// dn field
    pub dn: String,
    /// Active Directory functional level.
    pub functional_level: FunctionalLevel,
    /// Domain FQDN
    pub domain_controllers: Vec<Computer>,
    /// Object or account name.
    pub forest_name: String,
    /// Domain FQDN
    pub child_domains: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionalLevel {
    /// `Windows2000` variant
    Windows2000,
    /// `Windows2003` variant
    Windows2003,
    /// `Windows2008` variant
    Windows2008,
    /// `Windows2008R2` variant
    Windows2008R2,
    /// `Windows2012` variant
    Windows2012,
    /// `Windows2012R2` variant
    Windows2012R2,
    /// `Windows2016` variant
    Windows2016,
    /// `Unknown` variant
    Unknown(String),
}

impl From<&str> for FunctionalLevel {
    fn from(val: &str) -> Self {
        match val {
            "0" => Self::Windows2000,
            "2" => Self::Windows2003,
            "3" => Self::Windows2008,
            "4" => Self::Windows2008R2,
            "5" => Self::Windows2012,
            "6" => Self::Windows2012R2,
            "7" => Self::Windows2016,
            other => Self::Unknown(other.to_string()),
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  User
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub display_name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Security Identifier
    pub sid: String,
    /// upn field
    pub upn: String,
    /// enabled field
    pub enabled: bool,
    /// Item count
    pub admin_count: bool,
    /// sensitive field
    pub sensitive: bool,
    /// Service Principal Name
    pub spn: Vec<String>,
    /// dont req preauth field
    pub dont_req_preauth: bool,
    /// Password for authentication
    pub password_not_required: bool,
    /// Password for authentication
    pub password_never_expires: bool,
    /// Password for authentication
    pub password_last_set: Option<DateTime<Utc>>,
    /// last logon field
    pub last_logon: Option<DateTime<Utc>>,
    /// Item count
    pub logon_count: u32,
    /// member of field
    pub member_of: Vec<String>,
    /// description field
    pub description: String,
    /// email field
    pub email: String,
    /// Item count
    pub user_account_control: u32,
}

impl User {
    /// Check if user is Kerberoastable (has SPN and is enabled)
    pub fn is_kerberoastable(&self) -> bool {
        self.enabled && !self.spn.is_empty()
    }

    /// Check if user is AS-REP Roastable
    pub fn is_asrep_roastable(&self) -> bool {
        self.enabled && self.dont_req_preauth
    }

    /// Check if this is likely a service account
    pub fn is_service_account(&self) -> bool {
        let name = self.sam_account_name.to_lowercase();
        name.starts_with("svc")
            || name.starts_with("srv")
            || name.contains("service")
            || !self.spn.is_empty()
    }

    /// Check if user is a Domain Admin (basic check via memberOf)
    pub fn is_domain_admin(&self) -> bool {
        self.member_of
            .iter()
            .any(|g| g.to_uppercase().contains("CN=DOMAIN ADMINS"))
    }
}

impl Default for User {
    fn default() -> Self {
        Self {
            sam_account_name: String::new(),
            display_name: String::new(),
            distinguished_name: String::new(),
            sid: String::new(),
            upn: String::new(),
            enabled: true,
            admin_count: false,
            sensitive: false,
            spn: Vec::new(),
            dont_req_preauth: false,
            password_not_required: false,
            password_never_expires: false,
            password_last_set: None,
            last_logon: None,
            logon_count: 0,
            member_of: Vec::new(),
            description: String::new(),
            email: String::new(),
            user_account_control: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Computer
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Computer {
    /// Object or account name.
    pub sam_account_name: String,
    /// Object or account name.
    pub dns_hostname: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Target host address
    pub os: String,
    /// os version field
    pub os_version: String,
    /// Security Identifier
    pub sid: String,
    /// enabled field
    pub enabled: bool,
    /// is dc field
    pub is_dc: bool,
    /// unconstrained delegation field
    pub unconstrained_delegation: bool,
    /// constrained delegation field
    pub constrained_delegation: Vec<String>,
    /// rbcd principals field
    pub rbcd_principals: Vec<String>,
    /// laps enabled field
    pub laps_enabled: bool,
    /// laps expiry field
    pub laps_expiry: Option<DateTime<Utc>>,
    /// last logon field
    pub last_logon: Option<DateTime<Utc>>,
    /// Item count
    pub user_account_control: u32,
    /// Service Principal Name
    pub spn: Vec<String>,
}

impl Computer {
    /// Check if this is a Windows Server
    pub fn is_server(&self) -> bool {
        self.os.to_lowercase().contains("server")
    }

    /// Check if OS is obsolete (< Server 2016 / < Win 10)
    pub fn is_obsolete_os(&self) -> bool {
        let os_lower = self.os.to_lowercase();
        os_lower.contains("2003")
            || os_lower.contains("2008")
            || os_lower.contains("windows 7")
            || os_lower.contains("windows xp")
            || os_lower.contains("2000")
    }

    /// Check if this computer has any delegation configured
    pub fn has_delegation(&self) -> bool {
        self.unconstrained_delegation
            || !self.constrained_delegation.is_empty()
            || !self.rbcd_principals.is_empty()
    }
}

impl Default for Computer {
    fn default() -> Self {
        Self {
            sam_account_name: String::new(),
            dns_hostname: String::new(),
            distinguished_name: String::new(),
            os: String::new(),
            os_version: String::new(),
            sid: String::new(),
            enabled: true,
            is_dc: false,
            unconstrained_delegation: false,
            constrained_delegation: Vec::new(),
            rbcd_principals: Vec::new(),
            laps_enabled: false,
            laps_expiry: None,
            last_logon: None,
            user_account_control: 0,
            spn: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Group
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Security Identifier
    pub sid: String,
    /// description field
    pub description: String,
    /// members field
    pub members: Vec<String>,
    /// member of field
    pub member_of: Vec<String>,
    /// Item count
    pub admin_count: bool,
    /// Classification for this object.
    pub group_type: GroupType,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GroupType {
    /// `DomainLocal` variant
    DomainLocal,
    /// `Global` variant
    Global,
    /// `Universal` variant
    Universal,
    /// `BuiltIn` variant
    BuiltIn,
    /// `Unknown` variant
    Unknown,
}

impl Group {
    /// Known high-value groups in AD
    pub fn is_high_value(&self) -> bool {
        let name_upper = self.name.to_uppercase();
        matches!(
            name_upper.as_str(),
            "DOMAIN ADMINS"
                | "ENTERPRISE ADMINS"
                | "ADMINISTRATORS"
                | "SCHEMA ADMINS"
                | "ACCOUNT OPERATORS"
                | "BACKUP OPERATORS"
                | "SERVER OPERATORS"
                | "DNSADMINS"
                | "DOMAIN CONTROLLERS"
                | "GROUP POLICY CREATOR OWNERS"
                | "KEY ADMINS"
                | "ENTERPRISE KEY ADMINS"
                | "CERT PUBLISHERS"
        )
    }
}

// ═══════════════════════════════════════════════════════════
//  Trust
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trust {
    /// Source domain FQDN
    pub source_domain: String,
    /// Target domain FQDN
    pub target_domain: String,
    /// Classification for this object.
    pub trust_type: TrustType,
    /// trust direction field
    pub trust_direction: TrustDirection,
    /// Security Identifier
    pub sid_filtering: bool,
    /// tgt delegation field
    pub tgt_delegation: bool,
    /// transitive field
    pub transitive: bool,
    /// forest transitive field
    pub forest_transitive: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustType {
    /// `ParentChild` variant
    ParentChild,
    /// `External` variant
    External,
    /// `Forest` variant
    Forest,
    /// `Realm` variant
    Realm,
    /// `Unknown` variant
    Unknown(u32),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustDirection {
    /// `Inbound` variant
    Inbound,
    /// `Outbound` variant
    Outbound,
    /// `Bidirectional` variant
    Bidirectional,
    /// `Unknown` variant
    Unknown,
}

impl Trust {
    /// Check if trust can be abused for lateral movement
    pub fn is_exploitable(&self) -> bool {
        !self.sid_filtering || self.trust_type == TrustType::ParentChild || self.tgt_delegation
    }
}

// ═══════════════════════════════════════════════════════════
//  ACL / ACE
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    /// target dn field
    pub target_dn: String,
    /// Security Identifier
    pub target_sid: String,
    /// principal dn field
    pub principal_dn: String,
    /// Security Identifier
    pub principal_sid: String,
    /// right field
    pub right: AclRight,
    /// inherited field
    pub inherited: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AclRight {
    /// `GenericAll` variant
    GenericAll,
    /// `GenericWrite` variant
    GenericWrite,
    /// `WriteDacl` variant
    WriteDacl,
    /// `WriteOwner` variant
    WriteOwner,
    /// `ForceChangePassword` variant
    ForceChangePassword,
    /// `AddMember` variant
    AddMember,
    /// `AllExtendedRights` variant
    AllExtendedRights,
    /// `ReadLaps` variant
    ReadLaps,
    /// `ReadGmsa` variant
    ReadGmsa,
    /// `WriteSPN` variant
    WriteSPN,
    /// `WriteAccountRestrictions` variant
    WriteAccountRestrictions,
    /// `Owns` variant
    Owns,
    /// `DcSync` variant
    DcSync,
    /// `AddSelf` variant
    AddSelf,
    /// `Other` variant
    Other(String),
}

impl AclRight {
    /// Check if this ACL right is directly exploitable
    pub fn is_exploitable(&self) -> bool {
        matches!(
            self,
            Self::GenericAll
                | Self::GenericWrite
                | Self::WriteDacl
                | Self::WriteOwner
                | Self::ForceChangePassword
                | Self::AllExtendedRights
                | Self::WriteSPN
                | Self::WriteAccountRestrictions
                | Self::DcSync
                | Self::AddMember
        )
    }
}

// ═══════════════════════════════════════════════════════════
//  GPO
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gpo {
    /// Object or account name.
    pub display_name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// Stable unique identifier.
    pub gpo_id: String,
    /// Filesystem path.
    pub gpc_path: String,
    /// linked ous field
    pub linked_ous: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
//  OU (Organizational Unit)
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationalUnit {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// description field
    pub description: String,
    /// linked gpos field
    pub linked_gpos: Vec<String>,
    /// Item count
    pub child_count: u32,
}

// ═══════════════════════════════════════════════════════════
//  Certificate Template (ADCS)
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub display_name: String,
    /// Stable unique identifier.
    pub oid: String,
    /// schema version field
    pub schema_version: u32,
    /// enrollee supplies subject field
    pub enrollee_supplies_subject: bool,
    /// client auth field
    pub client_auth: bool,
    /// enrollment agent field
    pub enrollment_agent: bool,
    /// any purpose field
    pub any_purpose: bool,
    /// requires manager approval field
    pub requires_manager_approval: bool,
    /// authorized signatures field
    pub authorized_signatures: u32,
    /// enrollment permissions field
    pub enrollment_permissions: Vec<String>,
    /// vulnerable esc field
    pub vulnerable_esc: Vec<EscVulnerability>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EscVulnerability {
    /// `ESC1` variant
    ESC1,
    /// `ESC2` variant
    ESC2,
    /// `ESC3` variant
    ESC3,
    /// `ESC4` variant
    ESC4,
    /// `ESC5` variant
    ESC5,
    /// `ESC6` variant
    ESC6,
    /// `ESC7` variant
    ESC7,
    /// `ESC8` variant
    ESC8,
    /// `ESC9` variant
    ESC9,
    /// `ESC10` variant
    ESC10,
    /// `ESC11` variant
    ESC11,
    /// `ESC12` variant
    ESC12,
    /// `ESC13` variant
    ESC13,
    /// `ESC14` variant
    ESC14,
    /// `ESC15` variant
    ESC15,
    /// `ESC16` variant
    ESC16,
}

impl std::fmt::Display for EscVulnerability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ESC1 => write!(f, "ESC1 - Enrollee supplies subject + Client Auth"),
            Self::ESC2 => write!(f, "ESC2 - Any Purpose EKU"),
            Self::ESC3 => write!(f, "ESC3 - Enrollment Agent template"),
            Self::ESC4 => write!(f, "ESC4 - Vulnerable template ACLs"),
            Self::ESC5 => write!(f, "ESC5 - Vulnerable PKI object ACLs"),
            Self::ESC6 => write!(f, "ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 flag"),
            Self::ESC7 => write!(f, "ESC7 - Vulnerable CA ACLs"),
            Self::ESC8 => write!(f, "ESC8 - NTLM relay to HTTP enrollment"),
            Self::ESC9 => write!(
                f,
                "ESC9 - No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)"
            ),
            Self::ESC10 => write!(f, "ESC10 - Weak Certificate Mapping"),
            Self::ESC11 => write!(f, "ESC11 - NTLM relay to ICPR"),
            Self::ESC12 => write!(f, "ESC12 - CA private key exfiltration"),
            Self::ESC13 => write!(f, "ESC13 - Issuance Policy OID linked to group"),
            Self::ESC14 => write!(f, "ESC14 - Certificate mapping / altSecurityIdentities"),
            Self::ESC15 => write!(f, "ESC15 - Schema V1 enrollee-supplied subject"),
            Self::ESC16 => write!(f, "ESC16 - CA security extension disabled"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  UserAccountControl bit flags
// ═══════════════════════════════════════════════════════════

/// User Account Control (UAC) bit flag constants.
pub mod uac {
    pub const ACCOUNT_DISABLED: u32 = 0x0002;
    pub const HOMEDIR_REQUIRED: u32 = 0x0008;
    pub const LOCKOUT: u32 = 0x0010;
    pub const PASSWD_NOTREQD: u32 = 0x0020;
    pub const PASSWD_CANT_CHANGE: u32 = 0x0040;
    pub const ENCRYPTED_TEXT_PWD_ALLOWED: u32 = 0x0080;
    pub const NORMAL_ACCOUNT: u32 = 0x0200;
    pub const INTERDOMAIN_TRUST_ACCOUNT: u32 = 0x0800;
    pub const WORKSTATION_TRUST_ACCOUNT: u32 = 0x1000;
    pub const SERVER_TRUST_ACCOUNT: u32 = 0x2000;
    pub const DONT_EXPIRE_PASSWORD: u32 = 0x10000;
    pub const SMARTCARD_REQUIRED: u32 = 0x40000;
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x80000;
    pub const NOT_DELEGATED: u32 = 0x100000;
    pub const USE_DES_KEY_ONLY: u32 = 0x200000;
    pub const DONT_REQ_PREAUTH: u32 = 0x400000;
    pub const PASSWORD_EXPIRED: u32 = 0x800000;
    pub const TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x1000000;
    pub const PARTIAL_SECRETS_ACCOUNT: u32 = 0x4000000;

    /// Parse UAC flags into a human-readable list
    pub fn parse_flags(uac: u32) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if uac & ACCOUNT_DISABLED != 0 {
            flags.push("DISABLED");
        }
        if uac & PASSWD_NOTREQD != 0 {
            flags.push("PASSWD_NOTREQD");
        }
        if uac & NORMAL_ACCOUNT != 0 {
            flags.push("NORMAL_ACCOUNT");
        }
        if uac & DONT_EXPIRE_PASSWORD != 0 {
            flags.push("DONT_EXPIRE_PASSWORD");
        }
        if uac & TRUSTED_FOR_DELEGATION != 0 {
            flags.push("TRUSTED_FOR_DELEGATION");
        }
        if uac & NOT_DELEGATED != 0 {
            flags.push("NOT_DELEGATED");
        }
        if uac & DONT_REQ_PREAUTH != 0 {
            flags.push("DONT_REQ_PREAUTH");
        }
        if uac & TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
            flags.push("TRUSTED_TO_AUTH_FOR_DELEGATION");
        }
        if uac & SERVER_TRUST_ACCOUNT != 0 {
            flags.push("SERVER_TRUST_ACCOUNT");
        }
        if uac & WORKSTATION_TRUST_ACCOUNT != 0 {
            flags.push("WORKSTATION_TRUST_ACCOUNT");
        }
        flags
    }

    /// Check if account is enabled
    pub fn is_enabled(uac: u32) -> bool {
        uac & ACCOUNT_DISABLED == 0
    }
}

// ═══════════════════════════════════════════════════════════
//  Enumeration Session (holds all collected data)
// ═══════════════════════════════════════════════════════════
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnumerationData {
    /// Domain FQDN
    pub domain: Option<DomainInfo>,
    /// users field
    pub users: Vec<User>,
    /// computers field
    pub computers: Vec<Computer>,
    /// groups field
    pub groups: Vec<Group>,
    /// trusts field
    pub trusts: Vec<Trust>,
    /// gpos field
    pub gpos: Vec<Gpo>,
    /// ous field
    pub ous: Vec<OrganizationalUnit>,
    /// acls field
    pub acls: Vec<AclEntry>,
    /// cert templates field
    pub cert_templates: Vec<CertTemplate>,
    /// Raw byte data
    pub metadata: EnumMetadata,
}
/// Data structure used by this module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnumMetadata {
    /// started at field
    pub started_at: Option<DateTime<Utc>>,
    /// finished at field
    pub finished_at: Option<DateTime<Utc>>,
    /// Target domain FQDN
    pub target_domain: String,
    /// collector version field
    pub collector_version: String,
}

impl EnumerationData {
    /// Runs this module operation.
    pub fn new() -> Self {
        Self {
            metadata: EnumMetadata {
                collector_version: env!("CARGO_PKG_VERSION").to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Summary statistics
    pub fn summary(&self) -> HashMap<&str, usize> {
        let mut map = HashMap::new();
        map.insert("users", self.users.len());
        map.insert("computers", self.computers.len());
        map.insert("groups", self.groups.len());
        map.insert("trusts", self.trusts.len());
        map.insert("gpos", self.gpos.len());
        map.insert("ous", self.ous.len());
        map.insert("acls", self.acls.len());
        map.insert("cert_templates", self.cert_templates.len());
        map.insert(
            "kerberoastable",
            self.users.iter().filter(|u| u.is_kerberoastable()).count(),
        );
        map.insert(
            "asrep_roastable",
            self.users.iter().filter(|u| u.is_asrep_roastable()).count(),
        );
        map
    }
}

// ═══════════════════════════════════════════════════════════
//  Sid
// ═══════════════════════════════════════════════════════════

/// Windows Security Identifier (SID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sid {
    /// revision field
    pub revision: u8,
    /// authority field
    pub authority: [u8; 6],
    /// sub authorities field
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Runs this module operation.
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 4 || parts[0] != "S" {
            return None;
        }
        let revision: u8 = parts[1].parse().ok()?;
        let auth_val: u64 = parts[2].parse().ok()?;
        let mut authority = [0u8; 6];
        authority[0] = ((auth_val >> 40) & 0xFF) as u8;
        authority[1] = ((auth_val >> 32) & 0xFF) as u8;
        authority[2] = ((auth_val >> 24) & 0xFF) as u8;
        authority[3] = ((auth_val >> 16) & 0xFF) as u8;
        authority[4] = ((auth_val >> 8) & 0xFF) as u8;
        authority[5] = (auth_val & 0xFF) as u8;
        let sub_authorities: Option<Vec<u32>> = parts[3..].iter().map(|p| p.parse().ok()).collect();
        Some(Self {
            revision,
            authority,
            sub_authorities: sub_authorities?,
        })
    }
    /// Runs this module operation.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let revision = bytes[0];
        let count = bytes[1] as usize;
        let mut authority = [0u8; 6];
        authority.copy_from_slice(&bytes[2..8]);
        if bytes.len() < 8 + count * 4 {
            return None;
        }
        let mut sub_authorities = Vec::with_capacity(count);
        for i in 0..count {
            let o = 8 + i * 4;
            sub_authorities.push(u32::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
            ]));
        }
        Some(Self {
            revision,
            authority,
            sub_authorities,
        })
    }
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }
    pub fn domain_sid(&self) -> Self {
        let mut sub = self.sub_authorities.clone();
        sub.pop();
        Self {
            revision: self.revision,
            authority: self.authority,
            sub_authorities: sub,
        }
    }
    pub fn is_well_known(&self) -> bool {
        self.rid().map(|r| r < 1000).unwrap_or(false)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.sub_authorities.len() * 4);
        buf.push(self.revision);
        buf.push(self.sub_authorities.len() as u8);
        buf.extend_from_slice(&self.authority);
        for sa in &self.sub_authorities {
            buf.extend_from_slice(&sa.to_le_bytes());
        }
        buf
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth_val: u64 = ((self.authority[0] as u64) << 40)
            | ((self.authority[1] as u64) << 32)
            | ((self.authority[2] as u64) << 24)
            | ((self.authority[3] as u64) << 16)
            | ((self.authority[4] as u64) << 8)
            | (self.authority[5] as u64);
        write!(f, "S-{}-{}", self.revision, auth_val)?;
        for sa in &self.sub_authorities {
            write!(f, "-{}", sa)?;
        }
        Ok(())
    }
}
