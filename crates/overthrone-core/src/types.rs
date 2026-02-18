use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════
//  Domain
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub name: String,
    pub netbios_name: String,
    pub sid: String,
    pub dn: String,
    pub functional_level: FunctionalLevel,
    pub domain_controllers: Vec<Computer>,
    pub forest_name: String,
    pub child_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionalLevel {
    Windows2000,
    Windows2003,
    Windows2008,
    Windows2008R2,
    Windows2012,
    Windows2012R2,
    Windows2016,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub sam_account_name: String,
    pub display_name: String,
    pub distinguished_name: String,
    pub sid: String,
    pub upn: String,
    pub enabled: bool,
    pub admin_count: bool,
    pub sensitive: bool,
    pub spn: Vec<String>,
    pub dont_req_preauth: bool,
    pub password_not_required: bool,
    pub password_never_expires: bool,
    pub password_last_set: Option<DateTime<Utc>>,
    pub last_logon: Option<DateTime<Utc>>,
    pub logon_count: u32,
    pub member_of: Vec<String>,
    pub description: String,
    pub email: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Computer {
    pub sam_account_name: String,
    pub dns_hostname: String,
    pub distinguished_name: String,
    pub os: String,
    pub os_version: String,
    pub sid: String,
    pub enabled: bool,
    pub is_dc: bool,
    pub unconstrained_delegation: bool,
    pub constrained_delegation: Vec<String>,
    pub rbcd_principals: Vec<String>,
    pub laps_enabled: bool,
    pub laps_expiry: Option<DateTime<Utc>>,
    pub last_logon: Option<DateTime<Utc>>,
    pub user_account_control: u32,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub distinguished_name: String,
    pub sid: String,
    pub description: String,
    pub members: Vec<String>,
    pub member_of: Vec<String>,
    pub admin_count: bool,
    pub group_type: GroupType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GroupType {
    DomainLocal,
    Global,
    Universal,
    BuiltIn,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trust {
    pub source_domain: String,
    pub target_domain: String,
    pub trust_type: TrustType,
    pub trust_direction: TrustDirection,
    pub sid_filtering: bool,
    pub tgt_delegation: bool,
    pub transitive: bool,
    pub forest_transitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustType {
    ParentChild,
    External,
    Forest,
    Realm,
    Unknown(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustDirection {
    Inbound,
    Outbound,
    Bidirectional,
    Unknown,
}

impl Trust {
    /// Check if trust can be abused for lateral movement
    pub fn is_exploitable(&self) -> bool {
        !self.sid_filtering
            || self.trust_type == TrustType::ParentChild
            || self.tgt_delegation
    }
}

// ═══════════════════════════════════════════════════════════
//  ACL / ACE
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub target_dn: String,
    pub target_sid: String,
    pub principal_dn: String,
    pub principal_sid: String,
    pub right: AclRight,
    pub inherited: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AclRight {
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    ForceChangePassword,
    AddMember,
    AllExtendedRights,
    ReadLaps,
    ReadGmsa,
    WriteSPN,
    WriteAccountRestrictions,
    Owns,
    DcSync,
    AddSelf,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gpo {
    pub display_name: String,
    pub distinguished_name: String,
    pub gpo_id: String,
    pub gpc_path: String,
    pub linked_ous: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
//  OU (Organizational Unit)
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationalUnit {
    pub name: String,
    pub distinguished_name: String,
    pub description: String,
    pub linked_gpos: Vec<String>,
    pub child_count: u32,
}

// ═══════════════════════════════════════════════════════════
//  Certificate Template (ADCS)
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    pub name: String,
    pub display_name: String,
    pub oid: String,
    pub schema_version: u32,
    pub enrollee_supplies_subject: bool,
    pub client_auth: bool,
    pub enrollment_agent: bool,
    pub any_purpose: bool,
    pub requires_manager_approval: bool,
    pub authorized_signatures: u32,
    pub enrollment_permissions: Vec<String>,
    pub vulnerable_esc: Vec<EscVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EscVulnerability {
    ESC1,
    ESC2,
    ESC3,
    ESC4,
    ESC5,
    ESC6,
    ESC7,
    ESC8,
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
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  UserAccountControl bit flags
// ═══════════════════════════════════════════════════════════

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
        if uac & ACCOUNT_DISABLED != 0 { flags.push("DISABLED"); }
        if uac & PASSWD_NOTREQD != 0 { flags.push("PASSWD_NOTREQD"); }
        if uac & NORMAL_ACCOUNT != 0 { flags.push("NORMAL_ACCOUNT"); }
        if uac & DONT_EXPIRE_PASSWORD != 0 { flags.push("DONT_EXPIRE_PASSWORD"); }
        if uac & TRUSTED_FOR_DELEGATION != 0 { flags.push("TRUSTED_FOR_DELEGATION"); }
        if uac & NOT_DELEGATED != 0 { flags.push("NOT_DELEGATED"); }
        if uac & DONT_REQ_PREAUTH != 0 { flags.push("DONT_REQ_PREAUTH"); }
        if uac & TRUSTED_TO_AUTH_FOR_DELEGATION != 0 { flags.push("TRUSTED_TO_AUTH_FOR_DELEGATION"); }
        if uac & SERVER_TRUST_ACCOUNT != 0 { flags.push("SERVER_TRUST_ACCOUNT"); }
        if uac & WORKSTATION_TRUST_ACCOUNT != 0 { flags.push("WORKSTATION_TRUST_ACCOUNT"); }
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnumerationData {
    pub domain: Option<DomainInfo>,
    pub users: Vec<User>,
    pub computers: Vec<Computer>,
    pub groups: Vec<Group>,
    pub trusts: Vec<Trust>,
    pub gpos: Vec<Gpo>,
    pub ous: Vec<OrganizationalUnit>,
    pub acls: Vec<AclEntry>,
    pub cert_templates: Vec<CertTemplate>,
    pub metadata: EnumMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnumMetadata {
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub target_domain: String,
    pub collector_version: String,
}

impl EnumerationData {
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
        map.insert("kerberoastable", self.users.iter().filter(|u| u.is_kerberoastable()).count());
        map.insert("asrep_roastable", self.users.iter().filter(|u| u.is_asrep_roastable()).count());
        map
    }
}
