//! Domain computer enumeration via LDAP.

use crate::runner::ReaperConfig;
use crate::users::{UAC_DISABLED, UAC_TRUSTED_FOR_DELEGATION, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION};
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputerEntry {
    pub sam_account_name: String,
    pub dns_hostname: Option<String>,
    pub distinguished_name: String,
    pub operating_system: Option<String>,
    pub os_version: Option<String>,
    pub enabled: bool,
    pub uac_flags: u32,
    pub unconstrained_delegation: bool,
    pub constrained_delegation: bool,
    pub allowed_to_delegate_to: Vec<String>,
    pub service_principal_names: Vec<String>,
    pub last_logon: Option<String>,
    pub sid: Option<String>,
    pub is_domain_controller: bool,
    /// LAPS v1 password expiration (ms-Mcs-AdmPwdExpirationTime as Windows FILETIME string).
    pub laps_expiry: Option<String>,
}

impl ComputerEntry {
    pub fn is_high_value(&self) -> bool {
        self.is_domain_controller
            || self.unconstrained_delegation
            || self
                .operating_system
                .as_deref()
                .map(|os| os.contains("Server"))
                .unwrap_or(false)
    }

    pub fn is_legacy_os(&self) -> bool {
        self.operating_system
            .as_deref()
            .map(|os| {
                os.contains("2008")
                    || os.contains("2003")
                    || os.contains("XP")
                    || os.contains("7")
                    || os.contains("Vista")
            })
            .unwrap_or(false)
    }
}

pub fn computer_filter() -> String {
    "(objectCategory=computer)".to_string()
}

pub fn computer_attributes() -> Vec<String> {
    [
        "sAMAccountName",
        "dNSHostName",
        "distinguishedName",
        "operatingSystem",
        "operatingSystemVersion",
        "userAccountControl",
        "msDS-AllowedToDelegateTo",
        "servicePrincipalName",
        "lastLogonTimestamp",
        "objectSid",
        "ms-Mcs-AdmPwdExpirationTime",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub async fn enumerate_computers(config: &ReaperConfig) -> Result<Vec<ComputerEntry>> {
    info!("[computers] Querying {} for domain computers", config.dc_ip);

    let mut conn = overthrone_core::proto::ldap::LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    )
    .await?;

    let filter = computer_filter();
    let attr_list = computer_attributes();
    let attrs: Vec<&str> = attr_list.iter().map(|s| s.as_str()).collect();

    let entries = match conn.custom_search(&filter, &attrs).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("[computers] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();
    for entry in &entries {
        results.push(parse_computer_entry(&entry.attrs));
    }

    let _ = conn.disconnect().await;
    info!("[computers] Found {} domain computers", results.len());
    Ok(results)
}

pub fn parse_computer_entry(attrs: &HashMap<String, Vec<String>>) -> ComputerEntry {
    let uac: u32 = first_val(attrs, "userAccountControl")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let enabled = uac & UAC_DISABLED == 0;
    let unconstrained = uac & UAC_TRUSTED_FOR_DELEGATION != 0;
    let constrained = uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION != 0;
    let delegate_to = attrs
        .get("msDS-AllowedToDelegateTo")
        .cloned()
        .unwrap_or_default();
    let spns = attrs
        .get("servicePrincipalName")
        .cloned()
        .unwrap_or_default();
<<<<<<< HEAD
    // Domain Controllers have UAC flag SERVER_TRUST (0x2000).
    // Checking SPN prefixes is unreliable (member servers can have LDAP SPNs too).
    let is_dc = uac & 0x2000 != 0;
=======
    // Use UAC SERVER_TRUST_ACCOUNT bit (0x2000) for reliable DC detection.
    // SPN-based heuristics (e.g. starts_with("ldap/")) are unreliable because
    // non-DC servers can also have LDAP SPNs registered.
    const UAC_SERVER_TRUST_ACCOUNT: u32 = 0x00002000;
    let is_dc = uac & UAC_SERVER_TRUST_ACCOUNT != 0;
>>>>>>> origin/main

    ComputerEntry {
        sam_account_name: first_val(attrs, "sAMAccountName").unwrap_or_default(),
        dns_hostname: first_val(attrs, "dNSHostName"),
        distinguished_name: first_val(attrs, "distinguishedName").unwrap_or_default(),
        operating_system: first_val(attrs, "operatingSystem"),
        os_version: first_val(attrs, "operatingSystemVersion"),
        enabled,
        uac_flags: uac,
        unconstrained_delegation: unconstrained,
        constrained_delegation: constrained,
        allowed_to_delegate_to: delegate_to,
        service_principal_names: spns,
        last_logon: first_val(attrs, "lastLogonTimestamp"),
        sid: first_val(attrs, "objectSid"),
        is_domain_controller: is_dc,
        laps_expiry: first_val(attrs, "ms-Mcs-AdmPwdExpirationTime"),
    }
}

fn first_val(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|v| v.first().cloned())
}
