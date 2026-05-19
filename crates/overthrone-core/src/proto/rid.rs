//! RID cycling / brute-force for unauthenticated user enumeration.
//!
//! Enumerates domain users and groups by cycling through Relative
//! Identifiers (RIDs) via MS-SAMR over the IPC$ named pipe.
//!
//! Works with:
//! - Null sessions (no credentials)
//! - Low-privilege authenticated sessions
//!
//! Windows/Linux/macOS: Uses native LDAP/SID lookups when possible.
//! Legacy RPC tooling is no longer required for the common path.
//!
//! This is the #1 unauthenticated enumeration technique for AD.

use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Type of account discovered via RID cycling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RidAccountType {
    /// `User` variant
    User,
    /// `Computer` variant
    Computer,
    /// `Group` variant
    Group,
    /// `Alias` variant
    Alias, // local/domain alias (built-in groups)
    /// `WellKnown` variant
    WellKnown, // well-known SIDs
    /// `DeletedAccount` variant
    DeletedAccount,
    /// `Unknown` variant
    Unknown(String),
}

impl std::fmt::Display for RidAccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Computer => write!(f, "computer"),
            Self::Group => write!(f, "group"),
            Self::Alias => write!(f, "alias"),
            Self::WellKnown => write!(f, "well-known"),
            Self::DeletedAccount => write!(f, "deleted"),
            Self::Unknown(s) => write!(f, "{s}"),
        }
    }
}

/// A single RID lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RidResult {
    /// Stable unique identifier.
    pub rid: u32,
    /// Object or account name.
    pub name: String,
    /// Classification for this object.
    pub account_type: RidAccountType,
    /// Security Identifier
    pub sid: String,
}

/// Configuration for RID cycling
#[derive(Debug, Clone)]
pub struct RidCycleConfig {
    /// Target domain FQDN
    pub target: String,
    /// Domain FQDN
    pub domain: String,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
    /// null session field
    pub null_session: bool,
    /// Stable unique identifier.
    pub start_rid: u32,
    /// Stable unique identifier.
    pub end_rid: u32,
    /// Size in bytes
    pub batch_size: u32,
}

/// Quick availability check for RID cycling tooling.
pub fn tooling_available() -> bool {
    true
}

impl Default for RidCycleConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            domain: String::new(),
            username: String::new(),
            password: String::new(),
            null_session: false,
            start_rid: 500,
            end_rid: 10500,
            batch_size: 50,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Core Function
// ═══════════════════════════════════════════════════════════

/// Perform RID cycling enumeration against a domain controller.
/// Connects via IPC$ / MS-SAMR and queries SamrLookupIdsInDomain
/// for each RID in the specified range.
pub async fn rid_cycle(config: &RidCycleConfig) -> Result<Vec<RidResult>> {
    info!(
        "RID cycling {} → RID range {}-{} (batch size: {})",
        config.target, config.start_rid, config.end_rid, config.batch_size
    );

    // First, get the domain SID
    let domain_sid = get_domain_sid(config).await?;
    info!("Domain SID: {domain_sid}");

    let mut results = Vec::new();

    // Cycle through RIDs in batches
    let mut current = config.start_rid;
    while current <= config.end_rid {
        let batch_end = (current + config.batch_size - 1).min(config.end_rid);
        let rids: Vec<u32> = (current..=batch_end).collect();

        debug!("Querying RIDs {current}-{batch_end}...");

        match lookup_rids(config, &domain_sid, &rids).await {
            Ok(batch_results) => {
                for r in batch_results {
                    debug!("  RID {}: {} ({})", r.rid, r.name, r.account_type);
                    results.push(r);
                }
            }
            Err(e) => {
                warn!("Batch {current}-{batch_end} failed: {e}");
                // Fall back to one-by-one for this batch
                for rid in rids {
                    match lookup_rids(config, &domain_sid, &[rid]).await {
                        Ok(batch) => results.extend(batch),
                        Err(_) => continue,
                    }
                }
            }
        }

        current = batch_end + 1;
    }

    info!(
        "RID cycling complete: {} accounts discovered",
        results.len()
    );
    Ok(results)
}

// ═══════════════════════════════════════════════════════════
//  Platform-Specific Implementations
// ═══════════════════════════════════════════════════════════

/// Get the domain SID via rpcclient/net command
async fn get_domain_sid(config: &RidCycleConfig) -> Result<String> {
    let mut ldap = connect_for_rid(config).await?;
    let base_dn = ldap.base_dn.clone();
    let results = ldap
        .custom_search_with_base(&base_dn, "(objectClass=domainDNS)", &["objectSid"])
        .await
        .map_err(|e| OverthroneError::Ldap {
            target: config.target.clone(),
            reason: format!("Failed to query domain SID: {e}"),
        })?;

    for entry in results {
        if let Some(sid_bytes) = entry.bin_attrs.get("objectSid").and_then(|v| v.first()) {
            return Ok(sid_bytes_to_string(sid_bytes));
        }
    }

    Err(OverthroneError::Ldap {
        target: config.target.clone(),
        reason: "Could not extract domain SID from LDAP".to_string(),
    })
}

/// Lookup a batch of RIDs and return resolved names
async fn lookup_rids(
    config: &RidCycleConfig,
    domain_sid: &str,
    rids: &[u32],
) -> Result<Vec<RidResult>> {
    let mut results = Vec::new();
    let mut ldap = connect_for_rid(config).await?;
    let base_dn = ldap.base_dn.clone();
    let domain_sid_bytes = sid_string_to_bytes(domain_sid);

    // Native LDAP lookups for each SID.
    for &rid in rids {
        let full_sid = sid_string_with_rid(&domain_sid_bytes, rid);
        let sid_filter = ldap_filter_bytes(&full_sid);
        let filter = format!(
            "(&(objectSid={sid_filter})(|(objectClass=user)(objectClass=group)(objectClass=computer)))"
        );

        let entries = ldap
            .custom_search_with_base(
                &base_dn,
                &filter,
                &[
                    "sAMAccountName",
                    "cn",
                    "objectClass",
                    "userAccountControl",
                    "groupType",
                    "objectSid",
                ],
            )
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: config.target.clone(),
                reason: format!("LDAP RID lookup failed for {rid}: {e}"),
            })?;

        for entry in entries {
            let name = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .or_else(|| entry.attrs.get("cn").and_then(|v| v.first()).cloned())
                .unwrap_or_else(|| format!("RID-{rid}"));

            let object_classes = entry
                .attrs
                .get("objectClass")
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<_>>();
            let is_computer = object_classes.iter().any(|c| c == "computer")
                || name.ends_with('$')
                || entry.attrs.contains_key("userAccountControl")
                    && entry
                        .attrs
                        .get("userAccountControl")
                        .and_then(|v| v.first())
                        .and_then(|v| v.parse::<u32>().ok())
                        .is_some_and(|uac| uac & 0x1000 != 0);
            let is_group = object_classes.iter().any(|c| c == "group")
                || entry.attrs.contains_key("groupType");

            let account_type = if is_computer {
                RidAccountType::Computer
            } else if is_group {
                RidAccountType::Group
            } else {
                RidAccountType::User
            };

            results.push(RidResult {
                rid,
                name,
                account_type,
                sid: sid_bytes_to_string(&full_sid),
            });
        }
    }

    Ok(results)
}

/// Parse the rpcclient account type number to our enum
#[cfg(test)]
fn parse_account_type(type_str: &str) -> RidAccountType {
    match type_str.trim() {
        "1" => RidAccountType::User,
        "2" => RidAccountType::Group,
        "3" => RidAccountType::Alias,
        "4" => RidAccountType::Alias, // domain local alias
        "5" => RidAccountType::WellKnown,
        "6" => RidAccountType::DeletedAccount,
        "8" => RidAccountType::Unknown("unknown-8".into()),
        "SidTypeUser" => RidAccountType::User,
        "SidTypeGroup" | "SidTypeDomain" => RidAccountType::Group,
        "SidTypeAlias" | "SidTypeWellKnownGroup" => RidAccountType::Alias,
        "SidTypeDeletedAccount" => RidAccountType::DeletedAccount,
        other => RidAccountType::Unknown(other.to_string()),
    }
}

async fn connect_for_rid(config: &RidCycleConfig) -> Result<LdapSession> {
    if config.null_session || config.username.is_empty() {
        LdapSession::connect_anonymous(&config.target, &config.domain, false).await
    } else {
        LdapSession::connect(
            &config.target,
            &config.domain,
            &config.username,
            &config.password,
            false,
        )
        .await
    }
}

fn sid_string_to_bytes(sid_str: &str) -> Vec<u8> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    assert!(
        parts.len() >= 4 && parts[0] == "S",
        "invalid SID: {sid_str}"
    );
    let revision: u8 = parts[1].parse().unwrap_or(1);
    let authority: u64 = parts[2].parse().unwrap_or(5);
    let sub_authorities: Vec<u32> = parts[3..].iter().filter_map(|s| s.parse().ok()).collect();

    let mut sid = Vec::new();
    sid.push(revision);
    sid.push(sub_authorities.len() as u8);
    sid.extend_from_slice(&authority.to_be_bytes()[2..8]);
    for sub in sub_authorities {
        sid.extend_from_slice(&sub.to_le_bytes());
    }
    sid
}

fn sid_string_with_rid(domain_sid: &[u8], rid: u32) -> Vec<u8> {
    let mut sid = domain_sid.to_vec();
    if sid.len() < 8 {
        return sid;
    }
    sid[1] = sid[1].saturating_add(1);
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

fn sid_bytes_to_string(data: &[u8]) -> String {
    if data.len() < 8 {
        return String::from("S-0-0");
    }

    let revision = data[0];
    let sub_auth_count = data[1] as usize;
    let authority =
        u64::from_be_bytes([0, 0, data[2], data[3], data[4], data[5], data[6], data[7]]);

    let mut sid = format!("S-{}-{}", revision, authority);
    for i in 0..sub_auth_count {
        let offset = 8 + i * 4;
        if offset + 4 > data.len() {
            break;
        }
        let sub_auth = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        sid.push_str(&format!("-{}", sub_auth));
    }
    sid
}

fn ldap_filter_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{:02x}", b)).collect()
}

// ═══════════════════════════════════════════════════════════
//  rpcclient / net rpc launcher
// ═══════════════════════════════════════════════════════════

/// Parse an rpcclient lookupsids output line into a RidResult.
/// The output line format from `rpcclient lookupsids <sid>` is:
///   S-1-5-21-<domain>-<rid> DOMAIN\\Name (type_code)
/// This function extracts the name and type from a line matching the
/// expected `sid_prefix` (the full SID string, including the RID).
#[cfg(test)]
fn parse_lookupsids_line(output: &str, _expected_rid: u32, sid_prefix: &str) -> Option<RidResult> {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Split on whitespace: first token is the SID, rest is name + type
        let (sid_part, rest) = line.split_once(' ')?;
        if sid_part != sid_prefix {
            continue;
        }
        // rest = 'DOMAIN\Name (type)' — the name may contain spaces
        // Find the last '(' to extract the type code
        let paren_open = rest.rfind(" (")?;
        let type_str = rest[paren_open + 2..].trim_end_matches(')').trim();
        let account_type = parse_account_type(type_str);

        // Everything before ' (' is the qualified name (DOMAIN\Name)
        let qualified_name = rest[..paren_open].trim();
        // Extract just the account name after the backslash
        let name = qualified_name
            .split('\\')
            .next_back()
            .unwrap_or(qualified_name)
            .to_string();

        // Parse the RID from the SID
        let rid = sid_prefix
            .rsplit('-')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        return Some(RidResult {
            rid,
            name,
            account_type,
            sid: sid_prefix.to_string(),
        });
    }
    None
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lookupsids_user() {
        let output = "S-1-5-21-1234567890-1234567890-1234567890-500 CORP\\Administrator (1)\n";
        let sid = "S-1-5-21-1234567890-1234567890-1234567890-500";
        let result = parse_lookupsids_line(output, 500, sid).unwrap();
        assert_eq!(result.rid, 500);
        assert_eq!(result.name, "Administrator");
        assert_eq!(result.account_type, RidAccountType::User);
    }

    #[test]
    fn test_parse_lookupsids_group() {
        let output = "S-1-5-21-1234567890-1234567890-1234567890-512 CORP\\Domain Admins (2)\n";
        let sid = "S-1-5-21-1234567890-1234567890-1234567890-512";
        let result = parse_lookupsids_line(output, 512, sid).unwrap();
        assert_eq!(result.rid, 512);
        assert_eq!(result.name, "Domain Admins");
        assert_eq!(result.account_type, RidAccountType::Group);
    }

    #[test]
    fn test_parse_account_types() {
        assert_eq!(parse_account_type("1"), RidAccountType::User);
        assert_eq!(parse_account_type("2"), RidAccountType::Group);
        assert_eq!(parse_account_type("3"), RidAccountType::Alias);
        assert_eq!(parse_account_type("SidTypeUser"), RidAccountType::User);
    }

    #[test]
    fn test_default_config() {
        let config = RidCycleConfig::default();
        assert_eq!(config.start_rid, 500);
        assert_eq!(config.end_rid, 10500);
        assert_eq!(config.batch_size, 50);
    }
}
