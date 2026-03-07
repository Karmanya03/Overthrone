//! Domain trust enumeration.

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustDirection {
    Inbound,
    Outbound,
    Bidirectional,
    Unknown(u32),
}

impl std::fmt::Display for TrustDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inbound => write!(f, "Inbound"),
            Self::Outbound => write!(f, "Outbound"),
            Self::Bidirectional => write!(f, "Bidirectional"),
            Self::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustType {
    ParentChild,
    External,
    Forest,
    CrossLink,
    Unknown(u32),
}

impl std::fmt::Display for TrustType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentChild => write!(f, "ParentChild"),
            Self::External => write!(f, "External"),
            Self::Forest => write!(f, "Forest"),
            Self::CrossLink => write!(f, "CrossLink"),
            Self::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub target_domain: String,
    pub direction: TrustDirection,
    pub trust_type: TrustType,
    pub transitive: bool,
    pub sid_filtering_enabled: bool,
    pub tgt_delegation_enabled: bool,
}

pub fn trust_filter() -> String {
    "(objectClass=trustedDomain)".to_string()
}

// trustAttributes bit flags
const TRUST_ATTR_NON_TRANSITIVE: u32 = 0x00000001;
const TRUST_ATTR_QUARANTINED_DOMAIN: u32 = 0x00000004; // SID filtering
const TRUST_ATTR_FOREST_TRANSITIVE: u32 = 0x00000008;
const TRUST_ATTR_CROSS_ORG: u32 = 0x00000010;
const TRUST_ATTR_WITHIN_FOREST: u32 = 0x00000020;
const TRUST_ATTR_TGT_DELEGATION: u32 = 0x00000200;

pub async fn enumerate_trusts(config: &ReaperConfig) -> Result<Vec<TrustEntry>> {
    info!("[trusts] Querying {} for domain trusts", config.dc_ip);

    let mut conn = crate::runner::ldap_connect(config).await?;

    // Trusts live under CN=System,<base_dn>
    let base_dn = ReaperConfig::base_dn_from_domain(&config.domain);
    let trust_base = format!("CN=System,{}", base_dn);
    let filter = trust_filter();
    let attrs = &[
        "trustPartner",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "flatName",
        "securityIdentifier",
    ];

    let entries = match conn
        .custom_search_with_base(&trust_base, &filter, attrs)
        .await
    {
        Ok(e) => e,
        Err(e) => {
            warn!("[trusts] LDAP search failed: {}", e);
            let _ = conn.disconnect().await;
            return Err(e);
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let target_domain = entry
            .attrs
            .get("trustPartner")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.clone());

        let raw_dir: u32 = entry
            .attrs
            .get("trustDirection")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let direction = match raw_dir {
            1 => TrustDirection::Inbound,
            2 => TrustDirection::Outbound,
            3 => TrustDirection::Bidirectional,
            other => TrustDirection::Unknown(other),
        };

        let raw_type: u32 = entry
            .attrs
            .get("trustType")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let trust_attrs: u32 = entry
            .attrs
            .get("trustAttributes")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Derive TrustType from trustType + trustAttributes
        let trust_type = if trust_attrs & TRUST_ATTR_WITHIN_FOREST != 0 {
            TrustType::ParentChild
        } else if trust_attrs & TRUST_ATTR_FOREST_TRANSITIVE != 0 {
            TrustType::Forest
        } else if trust_attrs & TRUST_ATTR_CROSS_ORG != 0 {
            TrustType::CrossLink
        } else {
            match raw_type {
                1 => TrustType::External, // Downlevel / External
                2 => TrustType::External, // Uplevel / Active Directory
                3 => TrustType::External, // MIT (non-Windows Kerberos)
                other => TrustType::Unknown(other),
            }
        };

        let transitive = trust_attrs & TRUST_ATTR_NON_TRANSITIVE == 0;
        let sid_filtering_enabled = trust_attrs & TRUST_ATTR_QUARANTINED_DOMAIN != 0;
        let tgt_delegation_enabled = trust_attrs & TRUST_ATTR_TGT_DELEGATION != 0;

        info!(
            "[trusts]  {} ({}, {}, transitive={}, sid-filter={})",
            target_domain, direction, trust_type, transitive, sid_filtering_enabled
        );

        results.push(TrustEntry {
            target_domain,
            direction,
            trust_type,
            transitive,
            sid_filtering_enabled,
            tgt_delegation_enabled,
        });
    }

    let _ = conn.disconnect().await;

    info!("[trusts] Found {} domain trusts", results.len());
    Ok(results)
}
