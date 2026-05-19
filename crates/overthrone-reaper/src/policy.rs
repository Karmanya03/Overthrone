//! Domain password policy and fine-grained password settings enumeration.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

const DOMAIN_PASSWORD_COMPLEX: i64 = 0x1;
const DOMAIN_PASSWORD_STORE_CLEARTEXT: i64 = 0x10;
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Domain FQDN
    pub domain_policy: Option<DomainPasswordPolicy>,
    /// fine grained field
    pub fine_grained: Vec<FineGrainedPasswordPolicy>,
}

impl PolicyResult {
    pub fn entry_count(&self) -> usize {
        usize::from(self.domain_policy.is_some()) + self.fine_grained.len()
    }
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPasswordPolicy {
    /// Password for authentication
    pub min_password_length: Option<u32>,
    /// lockout threshold field
    pub lockout_threshold: Option<u32>,
    /// lockout duration field
    pub lockout_duration: Option<String>,
    /// lockout observation window field
    pub lockout_observation_window: Option<String>,
    /// Password for authentication
    pub max_password_age: Option<String>,
    /// Password for authentication
    pub min_password_age: Option<String>,
    /// Password for authentication
    pub password_history_length: Option<u32>,
    /// Password for authentication
    pub password_complexity_enabled: bool,
    /// reversible encryption enabled field
    pub reversible_encryption_enabled: bool,
    /// raw field
    pub raw: HashMap<String, Vec<String>>,
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FineGrainedPasswordPolicy {
    /// Object or account name.
    pub name: String,
    /// Object or account name.
    pub distinguished_name: String,
    /// precedence field
    pub precedence: Option<u32>,
    /// Password for authentication
    pub min_password_length: Option<u32>,
    /// lockout threshold field
    pub lockout_threshold: Option<u32>,
    /// lockout duration field
    pub lockout_duration: Option<String>,
    /// lockout observation window field
    pub lockout_observation_window: Option<String>,
    /// Password for authentication
    pub max_password_age: Option<String>,
    /// Password for authentication
    pub min_password_age: Option<String>,
    /// Password for authentication
    pub password_history_length: Option<u32>,
    /// Password for authentication
    pub password_complexity_enabled: Option<bool>,
    /// reversible encryption enabled field
    pub reversible_encryption_enabled: Option<bool>,
    /// applies to field
    pub applies_to: Vec<String>,
}

pub async fn enumerate_policies(config: &ReaperConfig) -> Result<PolicyResult> {
    info!(
        "[policy] Querying {} for domain password policy",
        config.dc_ip
    );

    let mut conn = crate::runner::ldap_connect(config).await?;

    let domain_attrs = &[
        "minPwdLength",
        "lockoutThreshold",
        "lockoutDuration",
        "lockOutObservationWindow",
        "maxPwdAge",
        "minPwdAge",
        "pwdHistoryLength",
        "pwdProperties",
    ];
    let domain_entries = conn
        .custom_search_with_base(&config.base_dn, "(objectClass=domainDNS)", domain_attrs)
        .await?;
    let domain_policy = domain_entries
        .first()
        .map(|entry| parse_domain_policy(&entry.attrs));

    let pso_attrs = &[
        "cn",
        "distinguishedName",
        "msDS-PasswordSettingsPrecedence",
        "msDS-MinimumPasswordLength",
        "msDS-LockoutThreshold",
        "msDS-LockoutDuration",
        "msDS-LockoutObservationWindow",
        "msDS-MaximumPasswordAge",
        "msDS-MinimumPasswordAge",
        "msDS-PasswordHistoryLength",
        "msDS-PasswordComplexityEnabled",
        "msDS-PasswordReversibleEncryptionEnabled",
        "msDS-PSOAppliesTo",
    ];
    let fine_grained = match conn
        .custom_search("(objectClass=msDS-PasswordSettings)", pso_attrs)
        .await
    {
        Ok(entries) => entries
            .iter()
            .map(|entry| parse_fine_grained_policy(&entry.dn, &entry.attrs))
            .collect(),
        Err(e) => {
            warn!("[policy] Fine-grained password policy query failed: {e}");
            Vec::new()
        }
    };

    let _ = conn.disconnect().await;

    info!(
        "[policy] Found {} domain policy and {} fine-grained policies",
        usize::from(domain_policy.is_some()),
        fine_grained.len()
    );

    Ok(PolicyResult {
        domain_policy,
        fine_grained,
    })
}

fn parse_domain_policy(attrs: &HashMap<String, Vec<String>>) -> DomainPasswordPolicy {
    let pwd_properties = first_i64(attrs, "pwdProperties").unwrap_or(0);
    DomainPasswordPolicy {
        min_password_length: first_u32(attrs, "minPwdLength"),
        lockout_threshold: first_u32(attrs, "lockoutThreshold"),
        lockout_duration: first_interval(attrs, "lockoutDuration"),
        lockout_observation_window: first_interval(attrs, "lockOutObservationWindow"),
        max_password_age: first_interval(attrs, "maxPwdAge"),
        min_password_age: first_interval(attrs, "minPwdAge"),
        password_history_length: first_u32(attrs, "pwdHistoryLength"),
        password_complexity_enabled: pwd_properties & DOMAIN_PASSWORD_COMPLEX != 0,
        reversible_encryption_enabled: pwd_properties & DOMAIN_PASSWORD_STORE_CLEARTEXT != 0,
        raw: attrs.clone(),
    }
}

fn parse_fine_grained_policy(
    dn: &str,
    attrs: &HashMap<String, Vec<String>>,
) -> FineGrainedPasswordPolicy {
    FineGrainedPasswordPolicy {
        name: first(attrs, "cn").unwrap_or_else(|| dn.to_string()),
        distinguished_name: first(attrs, "distinguishedName").unwrap_or_else(|| dn.to_string()),
        precedence: first_u32(attrs, "msDS-PasswordSettingsPrecedence"),
        min_password_length: first_u32(attrs, "msDS-MinimumPasswordLength"),
        lockout_threshold: first_u32(attrs, "msDS-LockoutThreshold"),
        lockout_duration: first_interval(attrs, "msDS-LockoutDuration"),
        lockout_observation_window: first_interval(attrs, "msDS-LockoutObservationWindow"),
        max_password_age: first_interval(attrs, "msDS-MaximumPasswordAge"),
        min_password_age: first_interval(attrs, "msDS-MinimumPasswordAge"),
        password_history_length: first_u32(attrs, "msDS-PasswordHistoryLength"),
        password_complexity_enabled: first_bool(attrs, "msDS-PasswordComplexityEnabled"),
        reversible_encryption_enabled: first_bool(
            attrs,
            "msDS-PasswordReversibleEncryptionEnabled",
        ),
        applies_to: attrs.get("msDS-PSOAppliesTo").cloned().unwrap_or_default(),
    }
}

fn first(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|v| v.first().cloned())
}

fn first_u32(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<u32> {
    first(attrs, key).and_then(|v| v.parse().ok())
}

fn first_i64(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<i64> {
    first(attrs, key).and_then(|v| v.parse().ok())
}

fn first_bool(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<bool> {
    first(attrs, key).and_then(|v| parse_bool(&v))
}

fn first_interval(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    first(attrs, key).and_then(|v| windows_interval_to_string(&v))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn windows_interval_to_string(raw: &str) -> Option<String> {
    let ticks = raw.parse::<i64>().ok()?;
    if ticks == 0 {
        return Some("0m".to_string());
    }
    if ticks == i64::MIN {
        return Some("never".to_string());
    }

    let total_seconds = ticks.unsigned_abs() / 10_000_000;
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;

    Some(if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    })
}

#[cfg(test)]
mod tests {
    use super::windows_interval_to_string;

    #[test]
    fn formats_windows_intervals() {
        assert_eq!(
            windows_interval_to_string("-18000000000"),
            Some("30m".to_string())
        );
        assert_eq!(
            windows_interval_to_string("-864000000000"),
            Some("1d 0h".to_string())
        );
    }
}
