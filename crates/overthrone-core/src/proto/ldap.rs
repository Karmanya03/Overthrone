//! LDAP enumeration for Active Directory reconnaissance.
//!
//! Provides async LDAP operations for enumerating users, groups, computers,
//! SPNs (Kerberoastable accounts), AS-REP Roastable accounts, trusts, and ACLs.
//!
//! Uses the `ldap3` crate (v0.11) with async Tokio support.

use crate::error::{OverthroneError, Result};
use base64::Engine as _;
use ldap3::controls::RawControl;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, drive};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════

/// Default LDAP port (plaintext)
pub const LDAP_PORT: u16 = 389;
/// Default LDAPS port (TLS)
pub const LDAPS_PORT: u16 = 636;

/// UserAccountControl flag: account is disabled
pub const UAC_ACCOUNT_DISABLE: u32 = 0x0002;
/// UserAccountControl flag: pre-auth not required (AS-REP Roastable)
pub const UAC_DONT_REQ_PREAUTH: u32 = 0x400000;
/// UserAccountControl flag: trusted for delegation
pub const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x80000;
/// UserAccountControl flag: trusted to auth for delegation (constrained)
pub const UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x1000000;
/// UserAccountControl flag: password never expires
pub const UAC_DONT_EXPIRE_PASSWORD: u32 = 0x10000;
/// UserAccountControl flag: normal user account
pub const UAC_NORMAL_ACCOUNT: u32 = 0x0200;
/// UserAccountControl flag: workstation trust account (computer)
pub const UAC_WORKSTATION_TRUST: u32 = 0x1000;
/// UserAccountControl flag: server trust account (DC)
pub const UAC_SERVER_TRUST: u32 = 0x2000;

/// Common user attributes for enumeration
const USER_ATTRS: &[&str] = &[
    "sAMAccountName",
    "distinguishedName",
    "userPrincipalName",
    "userAccountControl",
    "memberOf",
    "servicePrincipalName",
    "adminCount",
    "pwdLastSet",
    "lastLogonTimestamp",
    "description",
    "objectSid",
    "msDS-AllowedToDelegateTo",
];

/// Common computer attributes for enumeration
const COMPUTER_ATTRS: &[&str] = &[
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "servicePrincipalName",
    "msDS-AllowedToDelegateTo",
    "lastLogonTimestamp",
    "objectSid",
];

/// Common group attributes for enumeration
const GROUP_ATTRS: &[&str] = &[
    "sAMAccountName",
    "distinguishedName",
    "member",
    "memberOf",
    "description",
    "adminCount",
    "objectSid",
    "groupType",
];

/// Trust attributes for domain trust enumeration
const TRUST_ATTRS: &[&str] = &[
    "trustPartner",
    "trustDirection",
    "trustType",
    "trustAttributes",
    "flatName",
    "securityIdentifier",
];

/// OID for Simple Paged Results Control (RFC 2696)
const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";

/// OID for SD_FLAGS control (request specific security descriptor parts)
const SD_FLAGS_OID: &str = "1.2.840.113556.1.4.801";

/// SD_FLAGS value to request the DACL (4) + Owner (1) = 5
const SD_FLAGS_DACL_OWNER: u32 = 0x05;

/// GPO attributes for Group Policy enumeration
const GPO_ATTRS: &[&str] = &[
    "displayName",
    "cn",
    "gPCFileSysPath",
    "distinguishedName",
    "whenChanged",
    "flags",
    "gPCFunctionalityVersion",
];

/// Security descriptor attributes for ACL enumeration
const ACL_ATTRS: &[&str] = &[
    "distinguishedName",
    "sAMAccountName",
    "nTSecurityDescriptor",
    "objectClass",
];

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// Type of LDAP bind that was used to authenticate
#[derive(Debug, Clone, PartialEq)]
pub enum BindType {
    /// Authenticated with provided credentials
    Authenticated,
    /// Anonymous simple bind (empty DN and password)
    Anonymous,
}

impl std::fmt::Display for BindType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticated => write!(f, "authenticated"),
            Self::Anonymous => write!(f, "anonymous"),
        }
    }
}

/// Represents an authenticated LDAP session to a Domain Controller
pub struct LdapSession {
    ldap: ldap3::Ldap,
    pub base_dn: String,
    pub domain: String,
    pub dc_ip: String,
    /// How the session was authenticated
    pub bind_type: BindType,
}

/// Parsed AD user object
#[derive(Debug, Clone)]
pub struct AdUser {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub user_principal_name: Option<String>,
    pub user_account_control: u32,
    pub member_of: Vec<String>,
    pub service_principal_names: Vec<String>,
    pub admin_count: bool,
    pub pwd_last_set: Option<String>,
    pub last_logon: Option<String>,
    pub description: Option<String>,
    pub allowed_to_delegate_to: Vec<String>,
    pub enabled: bool,
    pub dont_req_preauth: bool,
    pub trusted_for_delegation: bool,
    pub constrained_delegation: bool,
}

/// Parsed AD computer object
#[derive(Debug, Clone)]
pub struct AdComputer {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub dns_hostname: Option<String>,
    pub operating_system: Option<String>,
    pub os_version: Option<String>,
    pub user_account_control: u32,
    pub service_principal_names: Vec<String>,
    pub allowed_to_delegate_to: Vec<String>,
    pub last_logon: Option<String>,
    pub unconstrained_delegation: bool,
    pub constrained_delegation: bool,
}

/// Parsed AD group object
#[derive(Debug, Clone)]
pub struct AdGroup {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub members: Vec<String>,
    pub member_of: Vec<String>,
    pub description: Option<String>,
    pub admin_count: bool,
    pub group_type: i32,
}

/// Parsed AD domain trust
#[derive(Debug, Clone)]
pub struct AdTrust {
    pub trust_partner: String,
    pub trust_direction: TrustDirection,
    pub trust_type: TrustType,
    pub trust_attributes: u32,
    pub flat_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustDirection {
    Disabled,
    Inbound,
    Outbound,
    Bidirectional,
    Unknown(u32),
}

impl TrustDirection {
    fn from_raw(val: u32) -> Self {
        match val {
            0 => Self::Disabled,
            1 => Self::Inbound,
            2 => Self::Outbound,
            3 => Self::Bidirectional,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for TrustDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "Disabled"),
            Self::Inbound => write!(f, "Inbound"),
            Self::Outbound => write!(f, "Outbound"),
            Self::Bidirectional => write!(f, "Bidirectional"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustType {
    Downlevel,
    Uplevel,
    Mit,
    Dce,
    Unknown(u32),
}

impl TrustType {
    fn from_raw(val: u32) -> Self {
        match val {
            1 => Self::Downlevel,
            2 => Self::Uplevel,
            3 => Self::Mit,
            4 => Self::Dce,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for TrustType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Downlevel => write!(f, "Downlevel (Windows NT)"),
            Self::Uplevel => write!(f, "Uplevel (Windows 2000+)"),
            Self::Mit => write!(f, "MIT (non-Windows Kerberos)"),
            Self::Dce => write!(f, "DCE"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// Summary of domain enumeration results
#[derive(Debug, Clone)]
pub struct DomainEnumeration {
    pub domain: String,
    pub base_dn: String,
    pub users: Vec<AdUser>,
    pub computers: Vec<AdComputer>,
    pub groups: Vec<AdGroup>,
    pub trusts: Vec<AdTrust>,
    pub kerberoastable: Vec<AdUser>,
    pub asrep_roastable: Vec<AdUser>,
    pub unconstrained_delegation: Vec<AdComputer>,
    pub constrained_delegation_users: Vec<AdUser>,
    pub constrained_delegation_computers: Vec<AdComputer>,
    pub domain_admins: Vec<String>,
    pub spn_map: HashMap<String, Vec<String>>,
    pub gpos: Vec<GpoInfo>,
    pub acl_entries: Vec<DaclInfo>,
}

// ─────────────────────────────────────────────────────
//  ACL / DACL Types
// ─────────────────────────────────────────────────────

/// ACE type from an Active Directory DACL
#[derive(Debug, Clone, PartialEq)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    AccessAllowedObject,
    AccessDeniedObject,
    Unknown(u8),
}

impl AceType {
    fn from_raw(val: u8) -> Self {
        match val {
            0x00 => Self::AccessAllowed,
            0x01 => Self::AccessDenied,
            0x05 => Self::AccessAllowedObject,
            0x06 => Self::AccessDeniedObject,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for AceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessAllowed => write!(f, "ACCESS_ALLOWED"),
            Self::AccessDenied => write!(f, "ACCESS_DENIED"),
            Self::AccessAllowedObject => write!(f, "ACCESS_ALLOWED_OBJECT"),
            Self::AccessDeniedObject => write!(f, "ACCESS_DENIED_OBJECT"),
            Self::Unknown(v) => write!(f, "UNKNOWN(0x{v:02x})"),
        }
    }
}

/// A parsed Access Control Entry from an AD object's DACL
#[derive(Debug, Clone)]
pub struct AceEntry {
    pub ace_type: AceType,
    pub ace_flags: u8,
    pub access_mask: u32,
    pub trustee_sid: String,
    /// Object type GUID (for object-specific ACEs)
    pub object_type: Option<String>,
    /// Inherited object type GUID
    pub inherited_object_type: Option<String>,
}

impl AceEntry {
    /// Check if this ACE grants GenericAll
    pub fn is_generic_all(&self) -> bool {
        self.access_mask & 0x10000000 != 0 || self.access_mask == 0x000F01FF
    }

    /// Check if this ACE grants WriteDacl
    pub fn is_write_dacl(&self) -> bool {
        self.access_mask & 0x00040000 != 0
    }

    /// Check if this ACE grants WriteOwner
    pub fn is_write_owner(&self) -> bool {
        self.access_mask & 0x00080000 != 0
    }

    /// Check if this ACE grants GenericWrite
    pub fn is_generic_write(&self) -> bool {
        self.access_mask & 0x40000000 != 0
    }

    /// Check if this ACE grants extended right (DS-Control-Access)
    pub fn is_extended_right(&self) -> bool {
        self.access_mask & 0x00000100 != 0
    }

    /// Check if this ACE grants WriteProperty
    pub fn is_write_prop(&self) -> bool {
        self.access_mask & 0x00000020 != 0
    }
}

/// DACL information for an AD object
#[derive(Debug, Clone)]
pub struct DaclInfo {
    pub object_dn: String,
    pub owner_sid: String,
    pub aces: Vec<AceEntry>,
}

/// Group Policy Object information
#[derive(Debug, Clone)]
pub struct GpoInfo {
    pub display_name: String,
    pub cn: String,
    pub gpc_file_sys_path: String,
    pub distinguished_name: String,
    pub when_changed: Option<String>,
    pub flags: u32,
}

/// Well-known AD control access right GUIDs
pub mod ad_rights {
    /// User-Force-Change-Password
    pub const FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
    /// DS-Replication-Get-Changes
    pub const REPL_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    /// DS-Replication-Get-Changes-All
    pub const REPL_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    /// DS-Replication-Get-Changes-In-Filtered-Set
    pub const REPL_GET_CHANGES_FILTERED: &str = "89e95b76-444d-4c62-991a-0facbeda640c";
    /// Write-Member (add/remove group members)
    pub const WRITE_MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
    /// Self-Membership (add self to group)
    pub const SELF_MEMBERSHIP: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
}

/// Trust attribute flags (MS-ADTS section 6.1.6.7.9)
pub mod trust_flags {
    pub const NON_TRANSITIVE: u32 = 0x00000001;
    pub const UPLEVEL_ONLY: u32 = 0x00000002;
    pub const QUARANTINED_DOMAIN: u32 = 0x00000004;
    pub const FOREST_TRANSITIVE: u32 = 0x00000008;
    pub const CROSS_ORGANIZATION: u32 = 0x00000010;
    pub const WITHIN_FOREST: u32 = 0x00000020;
    pub const TREAT_AS_EXTERNAL: u32 = 0x00000040;
    pub const USES_RC4_ENCRYPTION: u32 = 0x00000080;
    pub const USES_AES_KEYS: u32 = 0x00000100;
    pub const PIM_TRUST: u32 = 0x00000400;

    /// Parse trust attributes into human-readable flags
    pub fn describe(attrs: u32) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if attrs & NON_TRANSITIVE != 0 {
            flags.push("NON_TRANSITIVE");
        }
        if attrs & UPLEVEL_ONLY != 0 {
            flags.push("UPLEVEL_ONLY");
        }
        if attrs & QUARANTINED_DOMAIN != 0 {
            flags.push("QUARANTINED");
        }
        if attrs & FOREST_TRANSITIVE != 0 {
            flags.push("FOREST_TRANSITIVE");
        }
        if attrs & CROSS_ORGANIZATION != 0 {
            flags.push("CROSS_ORG");
        }
        if attrs & WITHIN_FOREST != 0 {
            flags.push("WITHIN_FOREST");
        }
        if attrs & TREAT_AS_EXTERNAL != 0 {
            flags.push("TREAT_AS_EXTERNAL");
        }
        if attrs & USES_RC4_ENCRYPTION != 0 {
            flags.push("RC4");
        }
        if attrs & USES_AES_KEYS != 0 {
            flags.push("AES");
        }
        if attrs & PIM_TRUST != 0 {
            flags.push("PIM");
        }
        if flags.is_empty() {
            flags.push("NONE");
        }
        flags
    }
}

// ═══════════════════════════════════════════════════════════
//  Connection & Authentication
// ═══════════════════════════════════════════════════════════

impl LdapSession {
    /// Connect and bind to an LDAP server using simple authentication.
    /// `domain` should be like "corp.local", `username` like "admin" or "CORP\\admin".
    pub async fn connect(
        dc_ip: &str,
        domain: &str,
        username: &str,
        password: &str,
        use_tls: bool,
    ) -> Result<Self> {
        let port = if use_tls { LDAPS_PORT } else { LDAP_PORT };
        let scheme = if use_tls { "ldaps" } else { "ldap" };
        let url = format!("{scheme}://{dc_ip}:{port}");

        info!("Connecting to LDAP: {url}");

        let settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10));

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: url.clone(),
                reason: format!("Connection failed: {e}"),
            })?;

        drive!(conn);

        // Build bind DN: DOMAIN\user or user@domain
        let bind_dn = if username.contains('\\') || username.contains('@') {
            username.to_string()
        } else {
            format!("{domain}\\{username}")
        };

        info!("LDAP bind as: {bind_dn}");

        let result =
            ldap.simple_bind(&bind_dn, password)
                .await
                .map_err(|e| OverthroneError::Ldap {
                    target: dc_ip.to_string(),
                    reason: format!("Bind failed: {e}"),
                })?;

        let bind_type = if result.rc != 0 {
            let auth_err = format!(
                "Bind rejected (rc={}): {}",
                result.rc,
                ldap_rc_to_string(result.rc)
            );
            warn!("LDAP authenticated bind failed: {auth_err}");
            warn!("Attempting anonymous bind fallback...");

            // Try anonymous bind: empty DN and empty password
            let anon_result =
                ldap.simple_bind("", "")
                    .await
                    .map_err(|e| OverthroneError::Ldap {
                        target: dc_ip.to_string(),
                        reason: format!("Anonymous bind failed: {e}"),
                    })?;

            if anon_result.rc != 0 {
                // Both authenticated and anonymous binds failed
                return Err(OverthroneError::Ldap {
                    target: dc_ip.to_string(),
                    reason: format!(
                        "All bind attempts failed. Authenticated: {}. Anonymous: rc={} {}",
                        auth_err,
                        anon_result.rc,
                        ldap_rc_to_string(anon_result.rc)
                    ),
                });
            }

            warn!("LDAP anonymous bind succeeded — results may be limited");
            BindType::Anonymous
        } else {
            BindType::Authenticated
        };

        let base_dn = domain_to_base_dn(domain);
        info!("LDAP bind successful ({}). Base DN: {base_dn}", bind_type);

        Ok(LdapSession {
            ldap,
            base_dn,
            domain: domain.to_string(),
            dc_ip: dc_ip.to_string(),
            bind_type,
        })
    }

    /// Unbind and close the LDAP session
    pub async fn disconnect(&mut self) -> Result<()> {
        self.ldap
            .unbind()
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: self.dc_ip.clone(),
                reason: format!("Unbind failed: {e}"),
            })?;
        info!("LDAP session closed");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Raw Modify Helpers (RBCD support)
    // ═══════════════════════════════════════════════════════

    /// Replace an attribute value on a DN (raw LDAP modify-replace).
    /// Used by RBCD to write msDS-AllowedToActOnBehalfOfOtherIdentity.
    pub async fn modify_replace(&mut self, dn: &str, attr: &str, value: &[u8]) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;
        debug!("LDAP modify-replace: dn={dn}, attr={attr}");

        // Convert value to base64 string for LDAP
        let value_str = base64::engine::general_purpose::STANDARD.encode(value);
        let mut values = HashSet::new();
        values.insert(value_str);
        let mods = vec![Mod::Replace(attr.to_string(), values)];

        let result = self
            .ldap
            .modify(dn, mods)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!("Modify-replace failed: {e}"),
            })?;

        if result.rc != 0 {
            return Err(OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!(
                    "Modify-replace rejected (rc={}): {}",
                    result.rc,
                    ldap_rc_to_string(result.rc)
                ),
            });
        }

        debug!("LDAP modify-replace successful on {dn}");
        Ok(())
    }

    /// Delete an attribute from a DN (raw LDAP modify-delete).
    /// Used by RBCD cleanup to remove msDS-AllowedToActOnBehalfOfOtherIdentity.
    pub async fn modify_delete(&mut self, dn: &str, attr: &str) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;
        debug!("LDAP modify-delete: dn={dn}, attr={attr}");

        let values = HashSet::new();
        let mods = vec![Mod::Delete(attr.to_string(), values)];

        let result = self
            .ldap
            .modify(dn, mods)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!("Modify-delete failed: {e}"),
            })?;

        if result.rc != 0 {
            return Err(OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!(
                    "Modify-delete rejected (rc={}): {}",
                    result.rc,
                    ldap_rc_to_string(result.rc)
                ),
            });
        }

        debug!("LDAP modify-delete successful on {dn}");
        Ok(())
    }

    /// Add values to an attribute on a DN (raw LDAP modify-add).
    /// Used by Shadow Credentials to write msDS-KeyCredentialLink.
    pub async fn modify_add(&mut self, dn: &str, attr: &str, values: &[String]) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;
        debug!(
            "LDAP modify-add: dn={dn}, attr={attr}, {} values",
            values.len()
        );

        let value_set: HashSet<String> = values.iter().cloned().collect();
        let mods = vec![Mod::Add(attr.to_string(), value_set)];

        let result = self
            .ldap
            .modify(dn, mods)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!("Modify-add failed: {e}"),
            })?;

        if result.rc != 0 {
            return Err(OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!(
                    "Modify-add rejected (rc={}): {}",
                    result.rc,
                    ldap_rc_to_string(result.rc)
                ),
            });
        }

        debug!("LDAP modify-add successful on {dn}");
        Ok(())
    }

    /// Remove specific values from an attribute on a DN (raw LDAP modify-delete-values).
    /// Used by Shadow Credentials cleanup to remove specific key credentials.
    pub async fn modify_delete_values(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[String],
    ) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;
        debug!(
            "LDAP modify-delete-values: dn={dn}, attr={attr}, {} values",
            values.len()
        );

        let value_set: HashSet<String> = values.iter().cloned().collect();
        let mods = vec![Mod::Delete(attr.to_string(), value_set)];

        let result = self
            .ldap
            .modify(dn, mods)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!("Modify-delete-values failed: {e}"),
            })?;

        if result.rc != 0 {
            return Err(OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!(
                    "Modify-delete-values rejected (rc={}): {}",
                    result.rc,
                    ldap_rc_to_string(result.rc)
                ),
            });
        }

        debug!("LDAP modify-delete-values successful on {dn}");
        Ok(())
    }

    /// Modify an LDAP attribute with typed operation and string values.
    ///
    /// Used by ADCS ESC4 and other modules that need proper LDAP writes
    /// with multiple string values and a selectable operation type.
    pub async fn modify_attribute(
        &mut self,
        dn: &str,
        attribute: &str,
        op: crate::adcs::esc4::ModifyOp,
        values: &[&str],
    ) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;
        debug!(
            "LDAP modify-attribute: dn={dn}, attr={attribute}, op={:?}, {} values",
            op,
            values.len()
        );

        let value_set: HashSet<String> = values.iter().map(|v| v.to_string()).collect();

        let mods = vec![match op {
            crate::adcs::esc4::ModifyOp::Replace => Mod::Replace(attribute.to_string(), value_set),
            crate::adcs::esc4::ModifyOp::Add => Mod::Add(attribute.to_string(), value_set),
            crate::adcs::esc4::ModifyOp::Delete => Mod::Delete(attribute.to_string(), value_set),
        }];

        let result = self
            .ldap
            .modify(dn, mods)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!("Modify-attribute failed: {e}"),
            })?;

        if result.rc != 0 {
            return Err(OverthroneError::Ldap {
                target: dn.to_string(),
                reason: format!(
                    "Modify-attribute rejected (rc={}): {}",
                    result.rc,
                    ldap_rc_to_string(result.rc)
                ),
            });
        }

        debug!("LDAP modify-attribute successful on {dn}");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    //  Raw Search Helper
    // ═══════════════════════════════════════════════════════

    /// Perform an LDAP search with automatic paging (RFC 2696).
    ///
    /// Uses the Simple Paged Results Control to iterate through all results
    /// in chunks of 1000, avoiding the server's default size limit.
    async fn search_entries(
        &mut self,
        base: &str,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>> {
        debug!("LDAP search: base={base}, filter={filter}");

        const PAGE_SIZE: i32 = 1000;
        let mut all_entries = Vec::new();
        let mut cookie: Vec<u8> = Vec::new();

        loop {
            let ctrl = build_paged_results_control(PAGE_SIZE, &cookie);

            let (rs, res) = self
                .ldap
                .with_controls(vec![ctrl])
                .search(base, Scope::Subtree, filter, attrs)
                .await
                .map_err(|e| OverthroneError::Ldap {
                    target: base.to_string(),
                    reason: format!("Search failed: {e}"),
                })?
                .success()
                .map_err(|e| OverthroneError::Ldap {
                    target: base.to_string(),
                    reason: format!("Search error: {e}"),
                })?;

            let page_count = rs.len();
            all_entries.extend(rs.into_iter().map(SearchEntry::construct));

            // Extract paged results cookie from response controls
            cookie = extract_paged_cookie(&res.ctrls);

            if cookie.is_empty() || page_count == 0 {
                break;
            }

            debug!(
                "LDAP paged search: {} entries so far, continuing...",
                all_entries.len()
            );
        }

        debug!("LDAP search returned {} entries", all_entries.len());
        Ok(all_entries)
    }

    // ═══════════════════════════════════════════════════════
    //  User Enumeration
    // ═══════════════════════════════════════════════════════

    /// Enumerate all user accounts in the domain
    pub async fn enumerate_users(&mut self) -> Result<Vec<AdUser>> {
        info!("Enumerating domain users...");
        let filter = "(&(objectCategory=person)(objectClass=user))";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, USER_ATTRS)
            .await?;
        let users: Vec<AdUser> = entries.iter().map(parse_ad_user).collect();

        info!("Found {} user accounts", users.len());
        Ok(users)
    }

    /// Find users that are AS-REP Roastable (DONT_REQUIRE_PREAUTH set)
    pub async fn find_asrep_roastable(&mut self) -> Result<Vec<AdUser>> {
        info!("Searching for AS-REP Roastable users...");
        let filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, USER_ATTRS)
            .await?;
        let users: Vec<AdUser> = entries.iter().map(parse_ad_user).collect();

        info!("Found {} AS-REP Roastable users", users.len());
        for u in &users {
            info!("  → {}", u.sam_account_name);
        }
        Ok(users)
    }

    /// Find users with SPNs set (Kerberoastable)
    pub async fn find_kerberoastable(&mut self) -> Result<Vec<AdUser>> {
        info!("Searching for Kerberoastable users...");
        let filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, USER_ATTRS)
            .await?;
        let users: Vec<AdUser> = entries.iter().map(parse_ad_user).collect();

        info!("Found {} Kerberoastable users", users.len());
        for u in &users {
            info!(
                "  → {} (SPNs: {:?})",
                u.sam_account_name, u.service_principal_names
            );
        }
        Ok(users)
    }

    /// Find users with admin privileges (adminCount=1)
    pub async fn find_admin_users(&mut self) -> Result<Vec<AdUser>> {
        info!("Searching for privileged users (adminCount=1)...");
        let filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1))";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, USER_ATTRS)
            .await?;
        let users: Vec<AdUser> = entries.iter().map(parse_ad_user).collect();

        info!("Found {} admin users", users.len());
        Ok(users)
    }

    /// Find users trusted for constrained delegation
    pub async fn find_constrained_delegation_users(&mut self) -> Result<Vec<AdUser>> {
        info!("Searching for users with constrained delegation...");
        let filter = "(&(objectCategory=person)(objectClass=user)(msDS-AllowedToDelegateTo=*))";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, USER_ATTRS)
            .await?;
        let users: Vec<AdUser> = entries.iter().map(parse_ad_user).collect();

        info!("Found {} users with constrained delegation", users.len());
        for u in &users {
            info!(
                "  → {} delegates to: {:?}",
                u.sam_account_name, u.allowed_to_delegate_to
            );
        }
        Ok(users)
    }

    // ═══════════════════════════════════════════════════════
    //  Computer Enumeration
    // ═══════════════════════════════════════════════════════

    /// Enumerate all computer accounts in the domain
    pub async fn enumerate_computers(&mut self) -> Result<Vec<AdComputer>> {
        info!("Enumerating domain computers...");
        let filter = "(objectCategory=computer)";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, COMPUTER_ATTRS)
            .await?;
        let computers: Vec<AdComputer> = entries.iter().map(parse_ad_computer).collect();

        info!("Found {} computer accounts", computers.len());
        Ok(computers)
    }

    /// Find computers with unconstrained delegation
    pub async fn find_unconstrained_delegation(&mut self) -> Result<Vec<AdComputer>> {
        info!("Searching for unconstrained delegation computers...");
        let filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, COMPUTER_ATTRS)
            .await?;
        let computers: Vec<AdComputer> = entries.iter().map(parse_ad_computer).collect();

        info!(
            "Found {} unconstrained delegation computers",
            computers.len()
        );
        for c in &computers {
            info!(
                "  → {} ({})",
                c.sam_account_name,
                c.dns_hostname.as_deref().unwrap_or("?")
            );
        }
        Ok(computers)
    }

    /// Find computers with constrained delegation
    pub async fn find_constrained_delegation_computers(&mut self) -> Result<Vec<AdComputer>> {
        info!("Searching for constrained delegation computers...");
        let filter = "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, COMPUTER_ATTRS)
            .await?;
        let computers: Vec<AdComputer> = entries.iter().map(parse_ad_computer).collect();

        info!("Found {} constrained delegation computers", computers.len());
        for c in &computers {
            info!(
                "  → {} delegates to: {:?}",
                c.sam_account_name, c.allowed_to_delegate_to
            );
        }
        Ok(computers)
    }

    // ═══════════════════════════════════════════════════════
    //  Group Enumeration
    // ═══════════════════════════════════════════════════════

    /// Enumerate all groups in the domain
    pub async fn enumerate_groups(&mut self) -> Result<Vec<AdGroup>> {
        info!("Enumerating domain groups...");
        let filter = "(objectCategory=group)";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, GROUP_ATTRS)
            .await?;
        let groups: Vec<AdGroup> = entries.iter().map(parse_ad_group).collect();

        info!("Found {} groups", groups.len());
        Ok(groups)
    }

    /// Get members of a specific group by its sAMAccountName
    pub async fn get_group_members(&mut self, group_name: &str) -> Result<Vec<String>> {
        info!("Resolving members of group: {group_name}");
        let filter = format!(
            "(&(objectCategory=group)(sAMAccountName={}))",
            ldap3::ldap_escape(group_name)
        );

        let entries = self
            .search_entries(&self.base_dn.clone(), &filter, GROUP_ATTRS)
            .await?;

        if let Some(entry) = entries.first() {
            let members = get_attr_values(entry, "member");
            info!("Group '{group_name}' has {} direct members", members.len());
            Ok(members)
        } else {
            warn!("Group '{group_name}' not found");
            Ok(Vec::new())
        }
    }

    /// Recursively resolve all members of a group (follows nested groups)
    pub async fn get_group_members_recursive(&mut self, group_dn: &str) -> Result<Vec<String>> {
        info!("Recursive member resolution for: {group_dn}");
        // LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
        let filter = format!(
            "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={}))",
            ldap3::ldap_escape(group_dn)
        );

        let entries = self
            .search_entries(
                &self.base_dn.clone(),
                &filter,
                &["sAMAccountName", "distinguishedName"],
            )
            .await?;

        let members: Vec<String> = entries
            .iter()
            .filter_map(|e| get_first_attr(e, "sAMAccountName"))
            .collect();

        info!("Recursive resolution found {} members", members.len());
        Ok(members)
    }

    /// Get Domain Admins group members
    pub async fn get_domain_admins(&mut self) -> Result<Vec<String>> {
        info!("Resolving Domain Admins...");

        let filter = "(&(objectCategory=group)(sAMAccountName=Domain Admins))";
        let entries = self
            .search_entries(&self.base_dn.clone(), filter, &["distinguishedName"])
            .await?;

        if let Some(entry) = entries.first() {
            let dn = &entry.dn;
            let admins = self.get_group_members_recursive(dn).await?;
            info!("Domain Admins: {} members", admins.len());
            for a in &admins {
                info!("  → {a}");
            }
            Ok(admins)
        } else {
            warn!("Domain Admins group not found");
            Ok(Vec::new())
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Trust Enumeration
    // ═══════════════════════════════════════════════════════

    /// Enumerate domain trusts with detailed attribute parsing
    pub async fn enumerate_trusts(&mut self) -> Result<Vec<AdTrust>> {
        info!("Enumerating domain trusts...");
        let filter = "(objectClass=trustedDomain)";
        let trust_base = format!("CN=System,{}", self.base_dn);

        let entries = self
            .search_entries(&trust_base, filter, TRUST_ATTRS)
            .await?;

        let trusts: Vec<AdTrust> = entries.iter().map(parse_ad_trust).collect();

        info!("Found {} domain trusts", trusts.len());
        for t in &trusts {
            let attr_flags = trust_flags::describe(t.trust_attributes);
            info!(
                "  → {} ({}, {}, attrs=[{}])",
                t.trust_partner,
                t.trust_direction,
                t.trust_type,
                attr_flags.join(", ")
            );
        }
        Ok(trusts)
    }

    // ═══════════════════════════════════════════════════════
    //  SPN Map Builder
    // ═══════════════════════════════════════════════════════

    /// Build a map of SPN → account(s) for all users and computers with SPNs.
    ///
    /// Returns `HashMap<String, Vec<String>>` where key is the SPN
    /// (e.g., "MSSQLSvc/db01.corp.local:1433") and value is the list
    /// of accounts that have that SPN registered.
    pub async fn build_spn_map(&mut self) -> Result<HashMap<String, Vec<String>>> {
        info!("Building SPN map...");
        let mut spn_map: HashMap<String, Vec<String>> = HashMap::new();

        // Users with SPNs
        let user_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))";
        let user_entries = self
            .search_entries(
                &self.base_dn.clone(),
                user_filter,
                &["sAMAccountName", "servicePrincipalName"],
            )
            .await?;

        for entry in &user_entries {
            let account = get_first_attr(entry, "sAMAccountName").unwrap_or_default();
            for spn in get_attr_values(entry, "servicePrincipalName") {
                spn_map.entry(spn).or_default().push(account.clone());
            }
        }

        // Computers with SPNs
        let comp_filter = "(&(objectCategory=computer)(servicePrincipalName=*))";
        let comp_entries = self
            .search_entries(
                &self.base_dn.clone(),
                comp_filter,
                &["sAMAccountName", "servicePrincipalName"],
            )
            .await?;

        for entry in &comp_entries {
            let account = get_first_attr(entry, "sAMAccountName").unwrap_or_default();
            for spn in get_attr_values(entry, "servicePrincipalName") {
                spn_map.entry(spn).or_default().push(account.clone());
            }
        }

        info!(
            "SPN map: {} unique SPNs across {} user + {} computer accounts",
            spn_map.len(),
            user_entries.len(),
            comp_entries.len()
        );
        Ok(spn_map)
    }

    // ═══════════════════════════════════════════════════════
    //  GPO Enumeration
    // ═══════════════════════════════════════════════════════

    /// Enumerate all Group Policy Objects in the domain.
    ///
    /// Returns GPO display names, CNs (GUIDs), SYSVOL paths, and flags.
    pub async fn enumerate_gpos(&mut self) -> Result<Vec<GpoInfo>> {
        info!("Enumerating Group Policy Objects...");
        let filter = "(objectClass=groupPolicyContainer)";

        let entries = self
            .search_entries(&self.base_dn.clone(), filter, GPO_ATTRS)
            .await?;

        let mut gpos = Vec::new();
        for entry in &entries {
            let display_name =
                get_first_attr(entry, "displayName").unwrap_or_else(|| "(unnamed)".to_string());
            let cn = get_first_attr(entry, "cn").unwrap_or_default();
            let gpc_path = get_first_attr(entry, "gPCFileSysPath").unwrap_or_default();
            let when_changed = get_first_attr(entry, "whenChanged");
            let flags = get_attr_u32(entry, "flags");

            info!("  → {} [{}] → {}", display_name, cn, gpc_path);

            gpos.push(GpoInfo {
                display_name,
                cn,
                gpc_file_sys_path: gpc_path,
                distinguished_name: entry.dn.clone(),
                when_changed,
                flags,
            });
        }

        info!("Found {} GPOs", gpos.len());
        Ok(gpos)
    }

    // ═══════════════════════════════════════════════════════
    //  ACL / DACL Enumeration
    // ═══════════════════════════════════════════════════════

    /// Enumerate DACLs for high-value objects (users, groups, computers, OUs).
    ///
    /// Uses the SD_FLAGS control to request only DACL + Owner from the
    /// `nTSecurityDescriptor` attribute, then parses the binary
    /// NT Security Descriptor into structured ACE entries.
    pub async fn enumerate_acls(&mut self, filter: &str) -> Result<Vec<DaclInfo>> {
        info!("Enumerating ACLs with filter: {filter}");

        // Build SD_FLAGS control to request DACL + Owner
        let sd_ctrl = build_sd_flags_control(SD_FLAGS_DACL_OWNER);

        let (rs, _res) = self
            .ldap
            .with_controls(vec![sd_ctrl])
            .search(&self.base_dn.clone(), Scope::Subtree, filter, ACL_ATTRS)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: self.base_dn.clone(),
                reason: format!("ACL search failed: {e}"),
            })?
            .success()
            .map_err(|e| OverthroneError::Ldap {
                target: self.base_dn.clone(),
                reason: format!("ACL search error: {e}"),
            })?;

        let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();

        let mut results = Vec::new();
        for entry in &entries {
            // nTSecurityDescriptor is a binary attribute
            if let Some(sd_bytes) = entry
                .bin_attrs
                .get("nTSecurityDescriptor")
                .and_then(|v| v.first())
            {
                match parse_security_descriptor(sd_bytes) {
                    Ok(dacl) => {
                        results.push(DaclInfo {
                            object_dn: entry.dn.clone(),
                            owner_sid: dacl.0,
                            aces: dacl.1,
                        });
                    }
                    Err(e) => {
                        debug!("Failed to parse SD for {}: {e}", entry.dn);
                    }
                }
            }
        }

        info!(
            "Parsed DACLs for {} objects ({} total ACEs)",
            results.len(),
            results.iter().map(|d| d.aces.len()).sum::<usize>()
        );
        Ok(results)
    }

    /// Find objects where a specific SID has dangerous permissions.
    ///
    /// Searches for DACLs containing ACEs that grant the given SID
    /// GenericAll, WriteDacl, WriteOwner, GenericWrite, or DCSync rights.
    pub async fn find_abusable_acls(&mut self, trustee_sid: &str) -> Result<Vec<DaclInfo>> {
        let all_acls = self
            .enumerate_acls(
                "(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)(objectClass=domain))"
            )
            .await?;

        let mut abusable = Vec::new();
        for dacl in all_acls {
            let dangerous_aces: Vec<AceEntry> = dacl
                .aces
                .iter()
                .filter(|ace| {
                    ace.trustee_sid == trustee_sid
                        && matches!(
                            ace.ace_type,
                            AceType::AccessAllowed | AceType::AccessAllowedObject
                        )
                        && (ace.is_generic_all()
                            || ace.is_write_dacl()
                            || ace.is_write_owner()
                            || ace.is_generic_write()
                            || ace.is_extended_right()
                            || ace.is_write_prop())
                })
                .cloned()
                .collect();

            if !dangerous_aces.is_empty() {
                abusable.push(DaclInfo {
                    object_dn: dacl.object_dn,
                    owner_sid: dacl.owner_sid,
                    aces: dangerous_aces,
                });
            }
        }

        info!(
            "Found {} objects with abusable ACLs for SID {}",
            abusable.len(),
            trustee_sid
        );
        Ok(abusable)
    }

    // ═══════════════════════════════════════════════════════
    //  Custom Queries
    // ═══════════════════════════════════════════════════════

    /// Execute a raw LDAP search with a custom filter and attributes
    pub async fn custom_search(
        &mut self,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>> {
        self.search_entries(&self.base_dn.clone(), filter, attrs)
            .await
    }

    /// Execute a raw LDAP search with a custom base DN
    pub async fn custom_search_with_base(
        &mut self,
        base_dn: &str,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>> {
        self.search_entries(base_dn, filter, attrs).await
    }

    // ═══════════════════════════════════════════════════════
    //  Full Domain Enumeration
    // ═══════════════════════════════════════════════════════

    /// Perform comprehensive domain enumeration in one shot.
    /// Calls all enumeration functions and returns a consolidated report.
    pub async fn full_enumeration(&mut self) -> Result<DomainEnumeration> {
        info!("═══ Starting full domain enumeration ═══");

        let users = self.enumerate_users().await?;
        let computers = self.enumerate_computers().await?;
        let groups = self.enumerate_groups().await?;
        let trusts = self.enumerate_trusts().await?;
        let kerberoastable = self.find_kerberoastable().await?;
        let asrep_roastable = self.find_asrep_roastable().await?;
        let unconstrained_delegation = self.find_unconstrained_delegation().await?;
        let constrained_delegation_users = self.find_constrained_delegation_users().await?;
        let constrained_delegation_computers = self.find_constrained_delegation_computers().await?;
        let domain_admins = self.get_domain_admins().await?;
        let spn_map = self.build_spn_map().await.unwrap_or_default();
        let gpos = self.enumerate_gpos().await.unwrap_or_default();
        // ACL enumeration is expensive; best-effort for high-value objects
        let acl_entries = self
            .enumerate_acls("(|(adminCount=1)(objectClass=domain))")
            .await
            .unwrap_or_default();

        let result = DomainEnumeration {
            domain: self.domain.clone(),
            base_dn: self.base_dn.clone(),
            users,
            computers,
            groups,
            trusts,
            kerberoastable,
            asrep_roastable,
            unconstrained_delegation,
            constrained_delegation_users,
            constrained_delegation_computers,
            domain_admins,
            spn_map,
            gpos,
            acl_entries,
        };

        info!("═══ Domain enumeration complete ═══");
        info!("  Users:                  {}", result.users.len());
        info!("  Computers:              {}", result.computers.len());
        info!("  Groups:                 {}", result.groups.len());
        info!("  Trusts:                 {}", result.trusts.len());
        info!("  Kerberoastable:         {}", result.kerberoastable.len());
        info!("  AS-REP Roastable:       {}", result.asrep_roastable.len());
        info!(
            "  Unconstrained Deleg:    {}",
            result.unconstrained_delegation.len()
        );
        info!(
            "  Constrained Deleg Users:{}",
            result.constrained_delegation_users.len()
        );
        info!(
            "  Constrained Deleg PCs:  {}",
            result.constrained_delegation_computers.len()
        );
        info!("  Domain Admins:          {}", result.domain_admins.len());
        info!("  SPN entries:            {}", result.spn_map.len());
        info!("  GPOs:                   {}", result.gpos.len());
        info!("  ACL objects:            {}", result.acl_entries.len());

        Ok(result)
    }

    // ═══════════════════════════════════════════════════════
    //  LAPS Password Reading
    // ═══════════════════════════════════════════════════════

    /// Read LAPS (Local Administrator Password Solution) passwords from AD.
    ///
    /// Queries computer objects for:
    /// - `ms-Mcs-AdmPwd` (LAPS v1)
    /// - `ms-Mcs-AdmPwdExpirationTime` (LAPS v1 expiry)
    /// - `msLAPS-Password` (Windows LAPS / LAPS v2)
    ///
    /// Returns only computers where the password is readable.
    pub async fn read_laps_passwords(
        &mut self,
        computer_filter: Option<&str>,
    ) -> Result<Vec<LapsResult>> {
        info!("Querying LAPS passwords...");

        let filter = match computer_filter {
            Some(name) => format!(
                "(&(objectClass=computer)(sAMAccountName={}$))",
                name.trim_end_matches('$')
            ),
            None => "(objectClass=computer)".to_string(),
        };

        let attrs = &[
            "sAMAccountName",
            "dNSHostName",
            "ms-Mcs-AdmPwd",
            "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-Password",
        ];

        let entries = self
            .search_entries(&self.base_dn.clone(), &filter, attrs)
            .await?;
        let mut results = Vec::new();

        for entry in &entries {
            let computer_name = get_first_attr(entry, "sAMAccountName").unwrap_or_default();
            let dns_name = get_first_attr(entry, "dNSHostName").unwrap_or_default();

            // LAPS v1
            let laps_v1 = get_first_attr(entry, "ms-Mcs-AdmPwd");
            let laps_v1_expiry = get_first_attr(entry, "ms-Mcs-AdmPwdExpirationTime");

            // Windows LAPS / LAPS v2
            let laps_v2 = get_first_attr(entry, "msLAPS-Password");

            if laps_v1.is_some() || laps_v2.is_some() {
                results.push(LapsResult {
                    computer_name,
                    dns_name,
                    password: laps_v1.clone(),
                    expiration: laps_v1_expiry,
                    laps_v2_password: laps_v2,
                });
            }
        }

        info!("LAPS: {} computers with readable passwords", results.len());
        Ok(results)
    }
}

/// LAPS password query result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LapsResult {
    pub computer_name: String,
    pub dns_name: String,
    /// LAPS v1 password (ms-Mcs-AdmPwd)
    pub password: Option<String>,
    /// LAPS v1 expiration time
    pub expiration: Option<String>,
    /// Windows LAPS / LAPS v2 password (JSON blob)
    pub laps_v2_password: Option<String>,
}

// ═══════════════════════════════════════════════════════════
//  Parsing Helpers
// ═══════════════════════════════════════════════════════════

/// Convert "corp.local" to "DC=corp,DC=local"
fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Get the first value of a named attribute from a SearchEntry
fn get_first_attr(entry: &SearchEntry, attr: &str) -> Option<String> {
    entry.attrs.get(attr).and_then(|vals| vals.first()).cloned()
}

/// Get all values of a named attribute from a SearchEntry
fn get_attr_values(entry: &SearchEntry, attr: &str) -> Vec<String> {
    entry.attrs.get(attr).cloned().unwrap_or_default()
}

/// Parse a numeric attribute, returning 0 if absent or unparseable
fn get_attr_u32(entry: &SearchEntry, attr: &str) -> u32 {
    get_first_attr(entry, attr)
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Parse a numeric attribute as i32
fn get_attr_i32(entry: &SearchEntry, attr: &str) -> i32 {
    get_first_attr(entry, attr)
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0)
}

/// Parse a SearchEntry into an AdUser
fn parse_ad_user(entry: &SearchEntry) -> AdUser {
    let uac = get_attr_u32(entry, "userAccountControl");
    AdUser {
        sam_account_name: get_first_attr(entry, "sAMAccountName").unwrap_or_default(),
        distinguished_name: entry.dn.clone(),
        user_principal_name: get_first_attr(entry, "userPrincipalName"),
        user_account_control: uac,
        member_of: get_attr_values(entry, "memberOf"),
        service_principal_names: get_attr_values(entry, "servicePrincipalName"),
        admin_count: get_first_attr(entry, "adminCount")
            .map(|v| v == "1")
            .unwrap_or(false),
        pwd_last_set: get_first_attr(entry, "pwdLastSet"),
        last_logon: get_first_attr(entry, "lastLogonTimestamp"),
        description: get_first_attr(entry, "description"),
        allowed_to_delegate_to: get_attr_values(entry, "msDS-AllowedToDelegateTo"),
        enabled: (uac & UAC_ACCOUNT_DISABLE) == 0,
        dont_req_preauth: (uac & UAC_DONT_REQ_PREAUTH) != 0,
        trusted_for_delegation: (uac & UAC_TRUSTED_FOR_DELEGATION) != 0,
        constrained_delegation: (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0,
    }
}

/// Parse a SearchEntry into an AdComputer
fn parse_ad_computer(entry: &SearchEntry) -> AdComputer {
    let uac = get_attr_u32(entry, "userAccountControl");
    AdComputer {
        sam_account_name: get_first_attr(entry, "sAMAccountName").unwrap_or_default(),
        distinguished_name: entry.dn.clone(),
        dns_hostname: get_first_attr(entry, "dNSHostName"),
        operating_system: get_first_attr(entry, "operatingSystem"),
        os_version: get_first_attr(entry, "operatingSystemVersion"),
        user_account_control: uac,
        service_principal_names: get_attr_values(entry, "servicePrincipalName"),
        allowed_to_delegate_to: get_attr_values(entry, "msDS-AllowedToDelegateTo"),
        last_logon: get_first_attr(entry, "lastLogonTimestamp"),
        unconstrained_delegation: (uac & UAC_TRUSTED_FOR_DELEGATION) != 0,
        constrained_delegation: (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0,
    }
}

/// Parse a SearchEntry into an AdGroup
fn parse_ad_group(entry: &SearchEntry) -> AdGroup {
    AdGroup {
        sam_account_name: get_first_attr(entry, "sAMAccountName").unwrap_or_default(),
        distinguished_name: entry.dn.clone(),
        members: get_attr_values(entry, "member"),
        member_of: get_attr_values(entry, "memberOf"),
        description: get_first_attr(entry, "description"),
        admin_count: get_first_attr(entry, "adminCount")
            .map(|v| v == "1")
            .unwrap_or(false),
        group_type: get_attr_i32(entry, "groupType"),
    }
}

/// Parse a SearchEntry into an AdTrust
fn parse_ad_trust(entry: &SearchEntry) -> AdTrust {
    AdTrust {
        trust_partner: get_first_attr(entry, "trustPartner").unwrap_or_default(),
        trust_direction: TrustDirection::from_raw(get_attr_u32(entry, "trustDirection")),
        trust_type: TrustType::from_raw(get_attr_u32(entry, "trustType")),
        trust_attributes: get_attr_u32(entry, "trustAttributes"),
        flat_name: get_first_attr(entry, "flatName"),
    }
}

/// Map common LDAP result codes to readable strings
fn ldap_rc_to_string(rc: u32) -> &'static str {
    match rc {
        0 => "Success",
        1 => "Operations error",
        2 => "Protocol error",
        3 => "Time limit exceeded",
        4 => "Size limit exceeded",
        7 => "Auth method not supported",
        8 => "Strong auth required",
        32 => "No such object",
        34 => "Invalid DN syntax",
        48 => "Inappropriate authentication",
        49 => "Invalid credentials",
        50 => "Insufficient access rights",
        51 => "Busy",
        52 => "Unavailable",
        53 => "Unwilling to perform",
        65 => "Object class violation",
        68 => "Entry already exists",
        _ => "Unknown error",
    }
}

// ═══════════════════════════════════════════════════════════
//  Paged Results Control (RFC 2696) — BER encoding/decoding
// ═══════════════════════════════════════════════════════════

/// Build a BER-encoded Simple Paged Results Control for LDAP requests.
///
/// The control value is a BER `SEQUENCE { INTEGER size, OCTET STRING cookie }`.
fn build_paged_results_control(page_size: i32, cookie: &[u8]) -> RawControl {
    let mut inner = Vec::new();
    ber_write_integer(&mut inner, page_size as i64);
    ber_write_octet_string(&mut inner, cookie);

    let mut val = Vec::new();
    val.push(0x30); // SEQUENCE tag
    ber_write_length(&mut val, inner.len());
    val.extend(inner);

    RawControl {
        ctype: PAGED_RESULTS_OID.to_string(),
        crit: true,
        val: Some(val),
    }
}

/// Build SD_FLAGS control to specify which SD parts to return.
fn build_sd_flags_control(flags: u32) -> RawControl {
    // Value is a BER SEQUENCE { INTEGER flags }
    let mut inner = Vec::new();
    ber_write_integer(&mut inner, flags as i64);

    let mut val = Vec::new();
    val.push(0x30);
    ber_write_length(&mut val, inner.len());
    val.extend(inner);

    RawControl {
        ctype: SD_FLAGS_OID.to_string(),
        crit: true,
        val: Some(val),
    }
}

/// Extract the paged results cookie from LDAP response controls.
///
/// Iterates through response controls looking for the Paged Results OID,
/// then parses the BER-encoded value to extract the cookie.
fn extract_paged_cookie(ctrls: &[ldap3::controls::Control]) -> Vec<u8> {
    for ctrl in ctrls {
        // Control is a tuple struct wrapping Option<ControlType>
        // Check if it's a PagedResults variant (typed parse may lack cookie access)
        if let Some(ldap3::controls::ControlType::PagedResults) = ctrl.0 {
            // The parsed control identifies the type but doesn't expose the
            // cookie struct directly. Fall through to raw parsing below.
        }
    }

    // Fallback: parse from raw bytes if available
    // ldap3 Control also preserves the raw form
    // Attempt to reconstruct cookie from the control's BER data
    for ctrl in ctrls {
        // ldap3 0.12 Control may have a raw() method or we can try downcast
        // Since we cannot easily extract the cookie via the typed API,
        // we use the raw control approach
        let raw_bytes = extract_raw_paged_control_bytes(ctrl);
        if !raw_bytes.is_empty() {
            return raw_bytes;
        }
    }

    Vec::new()
}

/// Try to extract paged results cookie bytes from a Control.
///
/// The ldap3 Control struct wraps ControlType. For PagedResults, we
/// need the cookie that the server returned. ldap3 0.12 parses it
/// into ControlType::PagedResults but accessing the inner PagedResults
/// struct requires matching the variant.
fn extract_raw_paged_control_bytes(ctrl: &ldap3::controls::Control) -> Vec<u8> {
    // In ldap3 0.12, Control(pub Option<ControlType>) where
    // ControlType::PagedResults wraps the PagedResults struct.
    // Try the typed API first.
    if let Some(ref ct) = ctrl.0 {
        // ControlType might have a method or we can match exhaustively
        // Using debug format to extract cookie when typed matching is complex
        let debug_str = format!("{ct:?}");
        if debug_str.contains("PagedResults") {
            // Parse cookie from debug representation as fallback
            // Format: PagedResults(PagedResults { size: N, cookie: [...] })
            if let Some(start) = debug_str.find("cookie: [") {
                let remaining = &debug_str[start + 9..];
                if let Some(end) = remaining.find(']') {
                    let byte_str = &remaining[..end];
                    if byte_str.is_empty() {
                        return Vec::new();
                    }
                    let bytes: Vec<u8> = byte_str
                        .split(", ")
                        .filter_map(|s| s.trim().parse::<u8>().ok())
                        .collect();
                    return bytes;
                }
            }
        }
    }
    Vec::new()
}

/// BER-encode an INTEGER value and append to buf
fn ber_write_integer(buf: &mut Vec<u8>, val: i64) {
    buf.push(0x02); // INTEGER tag

    let mut content = Vec::new();
    if val == 0 {
        content.push(0);
    } else if val > 0 {
        let mut v = val;
        while v > 0 {
            content.push((v & 0xFF) as u8);
            v >>= 8;
        }
        // Add leading zero if high bit is set (two's complement positive)
        if content.last().unwrap_or(&0) & 0x80 != 0 {
            content.push(0);
        }
        content.reverse();
    } else {
        // Negative (shouldn't occur for page sizes)
        content.push(0);
    }

    ber_write_length(buf, content.len());
    buf.extend(content);
}

/// BER-encode an OCTET STRING and append to buf
fn ber_write_octet_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(0x04); // OCTET STRING tag
    ber_write_length(buf, data.len());
    buf.extend(data);
}

/// BER-encode a length value and append to buf
fn ber_write_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

// ═══════════════════════════════════════════════════════════
//  NT Security Descriptor Parsing
// ═══════════════════════════════════════════════════════════

/// Parse a binary NT Security Descriptor (SECURITY_DESCRIPTOR_RELATIVE format).
///
/// Returns `(owner_sid, Vec<AceEntry>)` containing the DACL entries.
fn parse_security_descriptor(data: &[u8]) -> std::result::Result<(String, Vec<AceEntry>), String> {
    // SECURITY_DESCRIPTOR_RELATIVE layout:
    //   0: Revision (u8) — must be 1
    //   1: Sbz1 (u8)
    //   2-3: Control (u16 LE) — SE_DACL_PRESENT = 0x0004
    //   4-7: OffsetOwner (u32 LE)
    //   8-11: OffsetGroup (u32 LE)
    //  12-15: OffsetSacl (u32 LE)
    //  16-19: OffsetDacl (u32 LE)
    if data.len() < 20 {
        return Err("SD too short".to_string());
    }

    let _revision = data[0];
    let control = u16::from_le_bytes([data[2], data[3]]);
    let offset_owner = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let offset_dacl = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

    // Parse owner SID
    let owner_sid = if offset_owner > 0 && offset_owner < data.len() {
        parse_sid(&data[offset_owner..])
    } else {
        "S-1-0-0".to_string()
    };

    // Check SE_DACL_PRESENT
    if control & 0x0004 == 0 || offset_dacl == 0 || offset_dacl >= data.len() {
        return Ok((owner_sid, Vec::new()));
    }

    // Parse ACL header
    let acl = &data[offset_dacl..];
    if acl.len() < 8 {
        return Err("ACL too short".to_string());
    }

    let _acl_revision = acl[0];
    let _acl_size = u16::from_le_bytes([acl[2], acl[3]]);
    let ace_count = u16::from_le_bytes([acl[4], acl[5]]) as usize;

    let mut aces = Vec::new();
    let mut offset = 8; // Start after ACL header

    for _ in 0..ace_count {
        if offset + 4 > acl.len() {
            break;
        }

        let ace_type_raw = acl[offset];
        let ace_flags = acl[offset + 1];
        let ace_size = u16::from_le_bytes([acl[offset + 2], acl[offset + 3]]) as usize;

        if ace_size < 4 || offset + ace_size > acl.len() {
            break;
        }

        let ace_data = &acl[offset..offset + ace_size];
        let ace_type = AceType::from_raw(ace_type_raw);

        match ace_type_raw {
            // ACCESS_ALLOWED_ACE (0x00) / ACCESS_DENIED_ACE (0x01)
            0x00 | 0x01 => {
                if ace_data.len() >= 8 {
                    let mask =
                        u32::from_le_bytes([ace_data[4], ace_data[5], ace_data[6], ace_data[7]]);
                    let sid = if ace_data.len() > 8 {
                        parse_sid(&ace_data[8..])
                    } else {
                        "S-1-0-0".to_string()
                    };

                    aces.push(AceEntry {
                        ace_type,
                        ace_flags,
                        access_mask: mask,
                        trustee_sid: sid,
                        object_type: None,
                        inherited_object_type: None,
                    });
                }
            }
            // ACCESS_ALLOWED_OBJECT_ACE (0x05) / ACCESS_DENIED_OBJECT_ACE (0x06)
            0x05 | 0x06 => {
                if ace_data.len() >= 12 {
                    let mask =
                        u32::from_le_bytes([ace_data[4], ace_data[5], ace_data[6], ace_data[7]]);
                    let obj_flags =
                        u32::from_le_bytes([ace_data[8], ace_data[9], ace_data[10], ace_data[11]]);

                    let mut pos = 12;
                    let object_type = if obj_flags & 0x01 != 0 && pos + 16 <= ace_data.len() {
                        let guid = format_guid(&ace_data[pos..pos + 16]);
                        pos += 16;
                        Some(guid)
                    } else {
                        None
                    };

                    let inherited = if obj_flags & 0x02 != 0 && pos + 16 <= ace_data.len() {
                        let guid = format_guid(&ace_data[pos..pos + 16]);
                        pos += 16;
                        Some(guid)
                    } else {
                        None
                    };

                    let sid = if pos < ace_data.len() {
                        parse_sid(&ace_data[pos..])
                    } else {
                        "S-1-0-0".to_string()
                    };

                    aces.push(AceEntry {
                        ace_type,
                        ace_flags,
                        access_mask: mask,
                        trustee_sid: sid,
                        object_type,
                        inherited_object_type: inherited,
                    });
                }
            }
            _ => {
                // Skip unrecognized ACE types
            }
        }

        offset += ace_size;
    }

    Ok((owner_sid, aces))
}

/// Parse a SID from raw bytes to string format (S-1-5-21-...)
fn parse_sid(data: &[u8]) -> String {
    if data.len() < 8 {
        return "S-1-0-0".to_string();
    }
    let revision = data[0];
    let sub_count = data[1] as usize;
    let authority =
        u64::from_be_bytes([0, 0, data[2], data[3], data[4], data[5], data[6], data[7]]);
    let mut sid = format!("S-{revision}-{authority}");
    for i in 0..sub_count {
        let off = 8 + (i * 4);
        if off + 4 > data.len() {
            break;
        }
        let sub = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        sid.push_str(&format!("-{sub}"));
    }
    sid
}

/// Format a 16-byte GUID as a string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
///
/// Uses the mixed-endian format that Windows GUIDs use:
/// - bytes 0-3: little-endian u32
/// - bytes 4-5: little-endian u16
/// - bytes 6-7: little-endian u16
/// - bytes 8-15: big-endian (raw order)
fn format_guid(data: &[u8]) -> String {
    if data.len() < 16 {
        return "00000000-0000-0000-0000-000000000000".to_string();
    }
    let d1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let d2 = u16::from_le_bytes([data[4], data[5]]);
    let d3 = u16::from_le_bytes([data[6], data[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]
    )
}
