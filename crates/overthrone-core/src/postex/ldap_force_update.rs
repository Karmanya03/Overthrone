use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ForceUpdateConfig {
    pub target_dn: String,
    pub attribute: ForceUpdateAttr,
    pub value: String,
    pub dry_run: bool,
}

impl Default for ForceUpdateConfig {
    fn default() -> Self {
        Self {
            target_dn: String::new(),
            attribute: ForceUpdateAttr::LogonTimeSyncInterval,
            value: String::new(),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ForceUpdateResult {
    pub target_dn: String,
    pub attribute: String,
    pub value: String,
    pub force_update_set: bool,
    pub success: bool,
    pub message: String,
}

impl fmt::Display for ForceUpdateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] forceUpdate on {}: {}={} (set={}) -- {}",
            if self.success { "OK" } else { "FAIL" },
            self.target_dn,
            self.attribute,
            self.value,
            self.force_update_set,
            self.message
        )
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ForceUpdateAttr {
    #[default]
    LogonTimeSyncInterval,
    SecondaryKrbTgtNumber,
    Custom(String),
}

impl fmt::Display for ForceUpdateAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogonTimeSyncInterval => write!(f, "msDS-LogonTimeSyncInterval"),
            Self::SecondaryKrbTgtNumber => write!(f, "msDS-SecondaryKrbTgtNumber"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl FromStr for ForceUpdateAttr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace(['-', '_'], "") {
            x if x == "logontimesyncinterval" || x == "msdslogontimesyncinterval" => {
                Ok(Self::LogonTimeSyncInterval)
            }
            x if x == "secondarykrbtgtnumber" || x == "msdssecondarykrbtgtnumber" => {
                Ok(Self::SecondaryKrbTgtNumber)
            }
            _ => Ok(Self::Custom(s.to_string())),
        }
    }
}

#[derive(Debug, Error)]
pub enum ForceUpdateError {
    #[error("LDAP operation failed on '{target}': {reason}")]
    LdapError { target: String, reason: String },
    #[error("Not authorized: {0}")]
    NotAuthorized(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

fn attr_name(attr: &ForceUpdateAttr) -> &str {
    match attr {
        ForceUpdateAttr::LogonTimeSyncInterval => "msDS-LogonTimeSyncInterval",
        ForceUpdateAttr::SecondaryKrbTgtNumber => "msDS-SecondaryKrbTgtNumber",
        ForceUpdateAttr::Custom(s) => s.as_str(),
    }
}

fn build_modify(attr: &str, value: &str) -> Vec<ldap3::Mod<Vec<u8>>> {
    let mut vals: HashSet<Vec<u8>> = HashSet::new();
    vals.insert(value.as_bytes().to_vec());
    let mut fv: HashSet<Vec<u8>> = HashSet::new();
    fv.insert(b"1".to_vec());
    vec![
        ldap3::Mod::Replace(attr.as_bytes().to_vec(), vals),
        ldap3::Mod::Replace(b"forceUpdate".to_vec(), fv),
    ]
}

pub async fn apply_force_update(
    ldap: &mut ldap3::Ldap,
    config: &ForceUpdateConfig,
) -> Result<ForceUpdateResult, ForceUpdateError> {
    let attr = attr_name(&config.attribute);
    if config.dry_run {
        return Ok(ForceUpdateResult {
            target_dn: config.target_dn.clone(),
            attribute: attr.to_string(),
            value: config.value.clone(),
            force_update_set: true,
            success: true,
            message: format!(
                "[dry-run] would set forceUpdate=1 and set {attr}={}",
                config.value
            ),
        });
    }
    let mods = build_modify(attr, &config.value);
    ldap.modify(&config.target_dn, mods)
        .await
        .map_err(|e| ForceUpdateError::LdapError {
            target: config.target_dn.clone(),
            reason: e.to_string(),
        })?;
    Ok(ForceUpdateResult {
        target_dn: config.target_dn.clone(),
        attribute: attr.to_string(),
        value: config.value.clone(),
        force_update_set: true,
        success: true,
        message: format!("forceUpdate=1 and {attr}={} applied", config.value),
    })
}

pub async fn remove_force_update(
    ldap: &mut ldap3::Ldap,
    config: &ForceUpdateConfig,
) -> Result<ForceUpdateResult, ForceUpdateError> {
    let attr = attr_name(&config.attribute);
    let mut vals: HashSet<Vec<u8>> = HashSet::new();
    vals.insert(config.value.as_bytes().to_vec());
    let mods = vec![
        ldap3::Mod::Replace(attr.as_bytes().to_vec(), vals),
        ldap3::Mod::Delete(b"forceUpdate".to_vec(), HashSet::new()),
    ];
    ldap.modify(&config.target_dn, mods)
        .await
        .map_err(|e| ForceUpdateError::LdapError {
            target: config.target_dn.clone(),
            reason: e.to_string(),
        })?;
    Ok(ForceUpdateResult {
        target_dn: config.target_dn.clone(),
        attribute: attr.to_string(),
        value: config.value.clone(),
        force_update_set: false,
        success: true,
        message: "forceUpdate flag removed".to_string(),
    })
}

pub async fn check_force_update(
    ldap: &mut ldap3::Ldap,
    target_dn: &str,
) -> Result<Option<ForceUpdateResult>, ForceUpdateError> {
    use ldap3::{Scope, SearchEntry};
    let sr = ldap
        .search(
            target_dn,
            Scope::Base,
            "(objectClass=*)",
            vec![
                "forceUpdate",
                "msDS-LogonTimeSyncInterval",
                "msDS-SecondaryKrbTgtNumber",
            ],
        )
        .await
        .map_err(|e| ForceUpdateError::LdapError {
            target: target_dn.to_string(),
            reason: e.to_string(),
        })?;
    let (rs, _) = sr.success().map_err(|e| ForceUpdateError::LdapError {
        target: target_dn.to_string(),
        reason: e.to_string(),
    })?;
    let entry = match rs.into_iter().next() {
        Some(e) => SearchEntry::construct(e),
        None => return Ok(None),
    };
    if !entry.attrs.contains_key("forceUpdate") {
        return Ok(None);
    }
    let val = entry
        .attrs
        .get("forceUpdate")
        .and_then(|v| v.first().cloned())
        .unwrap_or_default();
    let found = if entry.attrs.contains_key("msDS-LogonTimeSyncInterval") {
        "msDS-LogonTimeSyncInterval"
    } else if entry.attrs.contains_key("msDS-SecondaryKrbTgtNumber") {
        "msDS-SecondaryKrbTgtNumber"
    } else {
        "unknown"
    };
    let attr_val = entry
        .attrs
        .get(found)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default();
    Ok(Some(ForceUpdateResult {
        target_dn: target_dn.to_string(),
        attribute: found.to_string(),
        value: attr_val,
        force_update_set: true,
        success: true,
        message: format!("forceUpdate={val}"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let c = ForceUpdateConfig::default();
        assert!(c.target_dn.is_empty() && c.value.is_empty() && !c.dry_run);
        assert_eq!(c.attribute, ForceUpdateAttr::LogonTimeSyncInterval);
    }

    #[test]
    fn test_config_custom() {
        let c = ForceUpdateConfig {
            target_dn: "DC=corp,DC=local".into(),
            attribute: ForceUpdateAttr::SecondaryKrbTgtNumber,
            value: "31337".into(),
            dry_run: true,
        };
        assert_eq!(c.target_dn, "DC=corp,DC=local");
        assert!(c.dry_run);
    }

    #[test]
    fn test_result_display() {
        let ok = ForceUpdateResult {
            target_dn: "DC=corp,DC=local".into(),
            attribute: "msDS-LogonTimeSyncInterval".into(),
            value: "1800".into(),
            force_update_set: true,
            success: true,
            message: "applied".into(),
        };
        assert!(ok.to_string().contains("[OK]") && ok.to_string().contains("1800"));
        let fail = ForceUpdateResult {
            target_dn: "DC=corp,DC=local".into(),
            attribute: "x".into(),
            value: "".into(),
            force_update_set: false,
            success: false,
            message: "failed".into(),
        };
        assert!(fail.to_string().contains("[FAIL]"));
    }

    #[test]
    fn test_attr_display() {
        assert_eq!(
            ForceUpdateAttr::LogonTimeSyncInterval.to_string(),
            "msDS-LogonTimeSyncInterval"
        );
        assert_eq!(
            ForceUpdateAttr::SecondaryKrbTgtNumber.to_string(),
            "msDS-SecondaryKrbTgtNumber"
        );
        assert_eq!(ForceUpdateAttr::Custom("foo".into()).to_string(), "foo");
    }

    #[test]
    fn test_attr_from_str() {
        assert_eq!(
            "msDS-LogonTimeSyncInterval"
                .parse::<ForceUpdateAttr>()
                .unwrap(),
            ForceUpdateAttr::LogonTimeSyncInterval
        );
        assert_eq!(
            "logontimesyncinterval".parse::<ForceUpdateAttr>().unwrap(),
            ForceUpdateAttr::LogonTimeSyncInterval
        );
        assert_eq!(
            "msDS-SecondaryKrbTgtNumber"
                .parse::<ForceUpdateAttr>()
                .unwrap(),
            ForceUpdateAttr::SecondaryKrbTgtNumber
        );
        assert_eq!(
            "customAttr".parse::<ForceUpdateAttr>().unwrap(),
            ForceUpdateAttr::Custom("customAttr".into())
        );
    }

    #[test]
    fn test_error_display() {
        let e = ForceUpdateError::LdapError {
            target: "DC=corp,DC=local".into(),
            reason: "down".into(),
        };
        assert!(e.to_string().contains("LDAP") && e.to_string().contains("down"));
        assert!(
            ForceUpdateError::NotAuthorized("no".into())
                .to_string()
                .contains("Not authorized")
        );
        assert!(
            ForceUpdateError::ConfigError("bad".into())
                .to_string()
                .contains("Configuration error")
        );
    }

    #[test]
    fn test_dry_run() {
        let c = ForceUpdateConfig {
            target_dn: "DC=x".into(),
            ..Default::default()
        };
        assert!(!c.dry_run);
        let c2 = ForceUpdateConfig { dry_run: true, ..c };
        assert!(c2.dry_run);
    }

    #[test]
    fn test_build_modify() {
        let m = build_modify("msDS-LogonTimeSyncInterval", "3600");
        assert_eq!(m.len(), 2);
    }
}
