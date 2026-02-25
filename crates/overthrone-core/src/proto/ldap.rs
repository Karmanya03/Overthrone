//! LDAP enumeration for Active Directory reconnaissance.
//!
//! Provides async LDAP operations for enumerating users, groups, computers,
//! SPNs (Kerberoastable accounts), AS-REP Roastable accounts, trusts, and ACLs.
//!
//! Uses the `ldap3` crate (v0.11) with async Tokio support.

use crate::error::{OverthroneError, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, drive};
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
#[allow(dead_code)]
pub const UAC_DONT_EXPIRE_PASSWORD: u32 = 0x10000;
/// UserAccountControl flag: normal user account
#[allow(dead_code)]
pub const UAC_NORMAL_ACCOUNT: u32 = 0x0200;
/// UserAccountControl flag: workstation trust account (computer)
#[allow(dead_code)]
pub const UAC_WORKSTATION_TRUST: u32 = 0x1000;
/// UserAccountControl flag: server trust account (DC)
#[allow(dead_code)]
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

    /// Perform an LDAP search and return parsed SearchEntry results
    async fn search_entries(
        &mut self,
        base: &str,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>> {
        debug!("LDAP search: base={base}, filter={filter}");

        let (rs, _res) = self
            .ldap
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

        let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();

        debug!("LDAP search returned {} entries", entries.len());
        Ok(entries)
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

    /// Enumerate domain trusts
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
            info!(
                "  → {} ({}, {})",
                t.trust_partner, t.trust_direction, t.trust_type
            );
        }
        Ok(trusts)
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
