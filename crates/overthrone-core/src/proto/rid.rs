//! RID cycling / brute-force for unauthenticated user enumeration.
//!
//! Enumerates domain users and groups by cycling through Relative
//! Identifiers (RIDs) via MS-SAMR over the IPC$ named pipe.
//!
//! Works with:
//! - Null sessions (no credentials)
//! - Low-privilege authenticated sessions
//!
//! Windows:  Uses `net rpc` or direct SMB named pipe when available
//! Linux/macOS: Uses `rpcclient` (from samba-common-bin)
//!
//! This is the #1 unauthenticated enumeration technique for AD.

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Type of account discovered via RID cycling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RidAccountType {
    User,
    Group,
    Alias,     // local/domain alias (built-in groups)
    WellKnown, // well-known SIDs
    DeletedAccount,
    Unknown(String),
}

impl std::fmt::Display for RidAccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
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
///
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
    let output = run_rpcclient(config, "lsaquery").await?;

    // Parse: "Domain Name: CORP\nDomain Sid: S-1-5-21-..."
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Domain Sid:") || line.starts_with("Domain SID:") {
            let sid = line
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .ok_or_else(|| OverthroneError::Rpc {
                    target: config.target.clone(),
                    reason: "Failed to parse domain SID from lsaquery output".to_string(),
                })?;
            if sid.starts_with("S-1-5-21-") {
                return Ok(sid);
            }
        }
    }

    Err(OverthroneError::Rpc {
        target: config.target.clone(),
        reason: format!(
            "Could not extract domain SID from lsaquery response: {}",
            output.lines().take(5).collect::<Vec<_>>().join(" | ")
        ),
    })
}

/// Lookup a batch of RIDs and return resolved names
async fn lookup_rids(
    config: &RidCycleConfig,
    domain_sid: &str,
    rids: &[u32],
) -> Result<Vec<RidResult>> {
    let mut results = Vec::new();

    // Use lookupsids for each SID (rpcclient supports this)
    for &rid in rids {
        let full_sid = format!("{domain_sid}-{rid}");
        let cmd = format!("lookupsids {full_sid}");

        match run_rpcclient(config, &cmd).await {
            Ok(output) => {
                // Parse: "S-1-5-21-...-500 CORP\Administrator (1)"
                // Format: <SID> <DOMAIN>\<name> (<type>)
                if let Some(result) = parse_lookupsids_line(&output, rid, &full_sid) {
                    // Skip entries that resolve to "(unknown)" or are clearly invalid
                    if result.name != "(unknown)" && !result.name.is_empty() {
                        results.push(result);
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Ok(results)
}

/// Parse a lookupsids response line into a RidResult
fn parse_lookupsids_line(output: &str, rid: u32, sid: &str) -> Option<RidResult> {
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with(sid) && !line.starts_with("S-1-5-21-") {
            continue;
        }

        // Format: "S-1-5-21-...-500 CORP\Administrator (1)"
        let after_sid = line.strip_prefix(sid)?.trim();

        // Extract the name and type
        let (name_part, type_part) = if let Some(paren_start) = after_sid.rfind('(') {
            let name = after_sid[..paren_start].trim();
            let typ = after_sid[paren_start..].trim_matches(|c| c == '(' || c == ')');
            (name, typ)
        } else {
            (after_sid, "")
        };

        // Name may be "DOMAIN\username" — extract just the username
        let name = if let Some((_domain, user)) = name_part.split_once('\\') {
            user.to_string()
        } else {
            name_part.to_string()
        };

        let account_type = parse_account_type(type_part);

        return Some(RidResult {
            rid,
            name,
            account_type,
            sid: sid.to_string(),
        });
    }
    None
}

/// Parse the rpcclient account type number to our enum
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

// ═══════════════════════════════════════════════════════════
//  rpcclient / net rpc launcher
// ═══════════════════════════════════════════════════════════

/// Run an rpcclient command and return stdout
async fn run_rpcclient(config: &RidCycleConfig, rpc_cmd: &str) -> Result<String> {
    let target = &config.target;
    let rpc_cmd = rpc_cmd.to_string();
    let config = config.clone();

    tokio::task::spawn_blocking(move || run_rpcclient_sync(&config, &rpc_cmd))
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: target.clone(),
            reason: format!("task join: {e}"),
        })?
}

/// Synchronous rpcclient execution
fn run_rpcclient_sync(config: &RidCycleConfig, rpc_cmd: &str) -> Result<String> {
    // Try rpcclient first (Linux/macOS), then net rpc (Windows/Linux)
    if let Ok(output) = try_rpcclient(config, rpc_cmd) {
        return Ok(output);
    }

    // Fallback: net rpc on Windows
    #[cfg(windows)]
    if let Ok(output) = try_net_rpc(config, rpc_cmd) {
        return Ok(output);
    }

    Err(OverthroneError::Rpc {
        target: config.target.clone(),
        reason: "Neither 'rpcclient' nor 'net rpc' is available. \
                 Install samba-common-bin (Linux) or samba-client (macOS) \
                 to enable RID cycling."
            .to_string(),
    })
}

/// Try running via rpcclient (Samba)
fn try_rpcclient(config: &RidCycleConfig, rpc_cmd: &str) -> Result<String> {
    let mut cmd = Command::new("rpcclient");

    if config.null_session {
        cmd.arg("-U").arg("").arg("-N");
    } else if !config.username.is_empty() {
        let user_spec = if config.domain.is_empty() {
            config.username.clone()
        } else {
            format!("{}\\{}", config.domain, config.username)
        };
        cmd.arg("-U")
            .arg(format!("{}%{}", user_spec, config.password));
    } else {
        cmd.arg("-U").arg("").arg("-N");
    }

    cmd.arg(&config.target);
    cmd.arg("-c").arg(rpc_cmd);

    debug!("rpcclient -c '{}' {}", rpc_cmd, config.target);

    let output = cmd.output().map_err(|e| OverthroneError::Rpc {
        target: config.target.clone(),
        reason: format!("rpcclient exec failed: {e}"),
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OverthroneError::Rpc {
            target: config.target.clone(),
            reason: format!("rpcclient error: {}", stderr.trim()),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Windows fallback: use `net rpc` for basic RPC operations
#[cfg(windows)]
fn try_net_rpc(config: &RidCycleConfig, rpc_cmd: &str) -> Result<String> {
    // Map rpcclient commands to net rpc equivalents
    let server_arg = format!("/S:{}", config.target);
    let (net_cmd, net_args): (&str, Vec<&str>) = if rpc_cmd == "lsaquery" {
        // net rpc info gives domain SID
        ("net", vec!["rpc", "info", &server_arg])
    } else {
        return Err(OverthroneError::Rpc {
            target: config.target.clone(),
            reason: format!("net rpc fallback not implemented for: {rpc_cmd}"),
        });
    };

    let mut cmd = Command::new(net_cmd);
    for arg in &net_args {
        cmd.arg(arg);
    }

    if !config.null_session && !config.username.is_empty() {
        cmd.arg(format!("/U:{}\\{}", config.domain, config.username));
        cmd.arg(format!("/P:{}", config.password));
    }

    let output = cmd.output().map_err(|e| OverthroneError::Rpc {
        target: config.target.clone(),
        reason: format!("net rpc exec failed: {e}"),
    })?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
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
