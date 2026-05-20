//! RID cycling / brute-force for unauthenticated user enumeration.
//!
//! Enumerates domain users and groups by cycling through Relative
//! Identifiers (RIDs) via MS-SAMR over the IPC$ named pipe.
//!
//! Works with:
//! - Null sessions (no credentials) — SAMR via SMB IPC$
//! - Low-privilege authenticated sessions
//!
//! Primary method: MS-SAMR RPC over SMB named pipe (works unauthenticated).
//! Fallback: LDAP SID lookup (requires authentication).
//!
//! This is the #1 unauthenticated enumeration technique for AD.

use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use crate::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Type of account discovered via RID cycling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RidAccountType {
    User,
    Computer,
    Group,
    Alias,
    WellKnown,
    DeletedAccount,
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
    pub rid: u32,
    pub name: String,
    pub account_type: RidAccountType,
    pub sid: String,
}

/// Configuration for RID cycling
#[derive(Debug, Clone)]
pub struct RidCycleConfig {
    pub target: String,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub null_session: bool,
    pub start_rid: u32,
    pub end_rid: u32,
    pub batch_size: u32,
}

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
//  Core Function — SAMR Primary, LDAP Fallback
// ═══════════════════════════════════════════════════════════

pub async fn rid_cycle(config: &RidCycleConfig) -> Result<Vec<RidResult>> {
    info!(
        "RID cycling {} → RID range {}-{} (batch size: {})",
        config.target, config.start_rid, config.end_rid, config.batch_size
    );

    match rid_cycle_samr(config).await {
        Ok(results) => {
            info!(
                "RID cycling via SAMR complete: {} accounts discovered",
                results.len()
            );
            return Ok(results);
        }
        Err(e) => {
            warn!("SAMR RID cycling failed: {e}");
            info!("Falling back to LDAP SID lookup method");
        }
    }

    rid_cycle_ldap(config).await
}

// ═══════════════════════════════════════════════════════════
//  SAMR-based RID Cycling (Primary Method)
// ═══════════════════════════════════════════════════════════

async fn rid_cycle_samr(config: &RidCycleConfig) -> Result<Vec<RidResult>> {
    info!("[SAMR] Connecting to {} for RID cycling", config.target);

    let smb = if config.null_session || config.username.is_empty() {
        match SmbSession::connect(&config.target, "", "", "").await {
            Ok(s) => s,
            Err(_) => SmbSession::connect(&config.target, ".", "guest", "")
                .await
                .map_err(|e| OverthroneError::Smb(format!("SMB null session failed: {e}")))?,
        }
    } else {
        let domain = if config.domain.is_empty() {
            "."
        } else {
            &config.domain
        };
        SmbSession::connect(&config.target, domain, &config.username, &config.password)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB auth failed: {e}")))?
    };

    use crate::proto::smb::{
        build_samr_bind, build_samr_connect, build_samr_enumerate_domains, build_samr_lookup_ids,
        build_samr_open_domain_by_sid, parse_samr_enumerate_domains, parse_samr_lookup_ids,
    };

    let bind_resp = smb.pipe_transact("samr", &build_samr_bind()).await?;
    if !is_rpc_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Smb("SAMR RPC bind failed".to_string()));
    }

    let connect_resp = smb.pipe_transact("samr", &build_samr_connect()).await?;
    let server_handle = extract_rpc_handle(&connect_resp)
        .ok_or_else(|| OverthroneError::Smb("SamrConnect failed".to_string()))?;

    let enum_resp = smb
        .pipe_transact("samr", &build_samr_enumerate_domains(&server_handle))
        .await?;
    let domains = parse_samr_enumerate_domains(&enum_resp);
    let primary_domain = domains
        .first()
        .cloned()
        .unwrap_or_else(|| "Domain".to_string());
    info!("[SAMR] Primary domain: {primary_domain}");

    let domain_sid_bytes = extract_domain_sid_from_samr(&enum_resp)
        .unwrap_or_else(|| vec![1, 4, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0]);

    let mut results = Vec::new();
    let mut current_rid = config.start_rid;

    while current_rid <= config.end_rid {
        let batch_end = (current_rid + config.batch_size - 1).min(config.end_rid);
        let rids: Vec<u32> = (current_rid..=batch_end).collect();

        debug!("[SAMR] Querying RIDs {current_rid}-{batch_end}...");

        let open_domain_req = build_samr_open_domain_by_sid(&server_handle, &domain_sid_bytes);
        let domain_resp = match smb.pipe_transact("samr", &open_domain_req).await {
            Ok(r) => r,
            Err(e) => {
                warn!("[SAMR] OpenDomain failed: {e}");
                break;
            }
        };

        let domain_handle = match extract_rpc_handle(&domain_resp) {
            Some(h) => h,
            None => {
                warn!("[SAMR] No domain handle returned");
                break;
            }
        };

        let lookup_req = build_samr_lookup_ids(&domain_handle, &rids);
        match smb.pipe_transact("samr", &lookup_req).await {
            Ok(resp) => {
                let parsed = parse_samr_lookup_ids(&resp, &rids);
                for (rid, name, acct_type) in parsed {
                    if !name.is_empty() {
                        let account_type = samr_type_to_rid_type(acct_type);
                        let full_sid = sid_bytes_with_rid(&domain_sid_bytes, rid);
                        debug!("  RID {rid}: {name} ({account_type})");
                        results.push(RidResult {
                            rid,
                            name,
                            account_type,
                            sid: sid_to_string(&full_sid),
                        });
                    }
                }
            }
            Err(e) => {
                warn!("[SAMR] LookupIds failed for batch {current_rid}-{batch_end}: {e}");
            }
        }

        current_rid = batch_end + 1;
    }

    info!(
        "[SAMR] RID cycling complete: {} accounts discovered",
        results.len()
    );
    Ok(results)
}

// ═══════════════════════════════════════════════════════════
//  LDAP-based RID Cycling (Fallback)
// ═══════════════════════════════════════════════════════════

async fn rid_cycle_ldap(config: &RidCycleConfig) -> Result<Vec<RidResult>> {
    info!("[LDAP] RID cycling via LDAP SID lookup");

    let domain_sid = get_domain_sid_ldap(config).await?;
    info!("[LDAP] Domain SID: {domain_sid}");

    let mut results = Vec::new();
    let mut current = config.start_rid;
    let domain_sid_bytes = sid_string_to_bytes(&domain_sid);

    while current <= config.end_rid {
        let batch_end = (current + config.batch_size - 1).min(config.end_rid);
        let rids: Vec<u32> = (current..=batch_end).collect();

        debug!("[LDAP] Querying RIDs {current}-{batch_end}...");

        for rid in rids {
            let full_sid = sid_string_with_rid(&domain_sid_bytes, rid);
            let sid_filter = ldap_filter_bytes(&full_sid);
            let filter = format!(
                "(&(objectSid={sid_filter})(|(objectClass=user)(objectClass=group)(objectClass=computer)))"
            );

            let mut ldap = match connect_for_rid(config).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let base_dn = ldap.base_dn.clone();

            match ldap
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
            {
                Ok(entries) => {
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
                Err(e) => {
                    debug!("[LDAP] RID {rid} lookup failed: {e}");
                }
            }
        }

        current = batch_end + 1;
    }

    info!(
        "[LDAP] RID cycling complete: {} accounts discovered",
        results.len()
    );
    Ok(results)
}

async fn get_domain_sid_ldap(config: &RidCycleConfig) -> Result<String> {
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

// ═══════════════════════════════════════════════════════════
//  SAMR Response Helpers
// ═══════════════════════════════════════════════════════════

fn is_rpc_bind_accepted(resp: &[u8]) -> bool {
    resp.len() > 30 && resp[28] == 0 && resp[29] == 0
}

fn extract_rpc_handle(resp: &[u8]) -> Option<[u8; 20]> {
    if resp.len() < 48 {
        return None;
    }
    let mut handle = [0u8; 20];
    handle.copy_from_slice(&resp[28..48]);
    if handle.iter().all(|&b| b == 0) {
        return None;
    }
    Some(handle)
}

fn extract_domain_sid_from_samr(resp: &[u8]) -> Option<Vec<u8>> {
    if resp.len() < 40 {
        return None;
    }
    for i in 24..resp.len().saturating_sub(12) {
        if resp[i] == 1 && resp[i + 1] > 0 && resp[i + 1] < 16 {
            let authority = u64::from_be_bytes([
                0,
                0,
                resp[i + 2],
                resp[i + 3],
                resp[i + 4],
                resp[i + 5],
                resp[i + 6],
                resp[i + 7],
            ]);
            if authority == 5 {
                let count = resp[i + 1] as usize;
                let total_len = 8 + count * 4;
                if i + total_len <= resp.len() {
                    return Some(resp[i..i + total_len].to_vec());
                }
            }
        }
    }
    None
}

fn samr_type_to_rid_type(type_code: u32) -> RidAccountType {
    match type_code {
        1 => RidAccountType::User,
        2 => RidAccountType::Group,
        3 | 4 => RidAccountType::Alias,
        5 => RidAccountType::WellKnown,
        6 => RidAccountType::DeletedAccount,
        _ => RidAccountType::Unknown(format!("type-{type_code}")),
    }
}

fn sid_bytes_with_rid(domain_sid: &[u8], rid: u32) -> Vec<u8> {
    let mut sid = domain_sid.to_vec();
    if sid.len() < 8 {
        return sid;
    }
    sid[1] = sid[1].saturating_add(1);
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

fn sid_to_string(data: &[u8]) -> String {
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

// ═══════════════════════════════════════════════════════════
//  SID Helpers (for LDAP fallback)
// ═══════════════════════════════════════════════════════════

fn sid_string_to_bytes(sid_str: &str) -> Vec<u8> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 4 || parts[0] != "S" {
        return Vec::new();
    }
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
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RidCycleConfig::default();
        assert_eq!(config.start_rid, 500);
        assert_eq!(config.end_rid, 10500);
        assert_eq!(config.batch_size, 50);
    }

    #[test]
    fn test_samr_type_mapping() {
        assert_eq!(samr_type_to_rid_type(1), RidAccountType::User);
        assert_eq!(samr_type_to_rid_type(2), RidAccountType::Group);
        assert_eq!(samr_type_to_rid_type(3), RidAccountType::Alias);
        assert_eq!(samr_type_to_rid_type(5), RidAccountType::WellKnown);
    }
}
