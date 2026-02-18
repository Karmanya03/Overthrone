//! AD Certificate Services (ADCS) template enumeration.
//! Identifies vulnerable certificate templates (ESC1-ESC8).

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    pub name: String,
    pub display_name: Option<String>,
    pub distinguished_name: String,
    pub schema_version: u32,
    pub oid: Option<String>,
    pub enroll_permissions: Vec<String>,
    pub enrollee_supplies_subject: bool,
    pub extended_key_usage: Vec<String>,
    pub requires_manager_approval: bool,
    pub authorized_signatures_required: u32,
    pub vulnerabilities: Vec<String>,
}

impl CertTemplate {
    /// ESC1: Client auth + enrollee supplies subject + no approval + no authorized signatures
    pub fn check_esc1(&self) -> bool {
        self.enrollee_supplies_subject
            && !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && (self.extended_key_usage.is_empty()
                || self.extended_key_usage.iter().any(|eku| {
                    eku == "1.3.6.1.5.5.7.3.2"        // Client Authentication
                    || eku == "1.3.6.1.4.1.311.20.2.2" // Smart Card Logon
                    || eku == "2.5.29.37.0"             // Any Purpose
                }))
    }

    /// ESC2: Any purpose EKU or empty EKU with no restrictions
    pub fn check_esc2(&self) -> bool {
        !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && (self.extended_key_usage.is_empty()
                || self.extended_key_usage.contains(&"2.5.29.37.0".to_string()))
    }

    pub fn analyze(&mut self) {
        if self.check_esc1() {
            self.vulnerabilities.push("ESC1: Enrollee supplies subject + client auth".into());
        }
        if self.check_esc2() {
            self.vulnerabilities.push("ESC2: Any purpose / no EKU restriction".into());
        }
    }
}

pub fn adcs_base_dn(domain_base_dn: &str) -> String {
    format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{domain_base_dn}")
}

pub fn adcs_filter() -> String {
    "(objectClass=pKICertificateTemplate)".to_string()
}

pub fn adcs_attributes() -> Vec<String> {
    [
        "cn", "displayName", "distinguishedName", "msPKI-Cert-Template-OID",
        "revision", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
        "msPKI-Template-Schema-Version", "nTSecurityDescriptor",
    ].iter().map(|s| s.to_string()).collect()
}

/// msPKI-Certificate-Name-Flag: bit 1 = ENROLLEE_SUPPLIES_SUBJECT
const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;
/// msPKI-Enrollment-Flag: bit 4 = PEND_ALL_REQUESTS (manager approval)
const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;

pub async fn enumerate_adcs(config: &ReaperConfig) -> Result<Vec<CertTemplate>> {
    info!("[adcs] Querying {} for ADCS certificate templates", config.dc_ip);

    let mut conn = LdapSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
        false,
    ).await?;

    let base_dn = ReaperConfig::base_dn_from_domain(&config.domain);
    let adcs_dn = adcs_base_dn(&base_dn);
    let filter  = adcs_filter();
    let attr_refs: Vec<&str> = [
        "cn", "displayName", "distinguishedName", "msPKI-Cert-Template-OID",
        "revision", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
        "msPKI-Template-Schema-Version", "nTSecurityDescriptor",
    ].to_vec();

    let entries = match conn.custom_search_with_base(&adcs_dn, &filter, &attr_refs).await {
        Ok(e) => e,
        Err(e) => {
            // ADCS may not be deployed — not an error, just no templates
            warn!("[adcs] Certificate template query failed (ADCS may not be deployed): {}", e);
            let _ = conn.disconnect().await;
            return Ok(Vec::new());
        }
    };

    let mut results = Vec::new();

    for entry in &entries {
        let name = entry.attrs
            .get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.clone());

        let display_name = entry.attrs
            .get("displayName")
            .and_then(|v| v.first())
            .cloned();

        let schema_version: u32 = entry.attrs
            .get("msPKI-Template-Schema-Version")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let oid = entry.attrs
            .get("msPKI-Cert-Template-OID")
            .and_then(|v| v.first())
            .cloned();

        let extended_key_usage: Vec<String> = entry.attrs
            .get("pKIExtendedKeyUsage")
            .cloned()
            .unwrap_or_default();

        let name_flag: u32 = entry.attrs
            .get("msPKI-Certificate-Name-Flag")
            .and_then(|v| v.first())
            .and_then(|s| {
                if s.starts_with('-') {
                    // Stored as signed int in AD
                    s.parse::<i64>().ok().map(|v| v as u32)
                } else {
                    s.parse::<u32>().ok()
                }
            })
            .unwrap_or(0);

        let enroll_flag: u32 = entry.attrs
            .get("msPKI-Enrollment-Flag")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let ra_sigs: u32 = entry.attrs
            .get("msPKI-RA-Signature")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let enrollee_supplies_subject = name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT != 0;
        let requires_manager_approval = enroll_flag & CT_FLAG_PEND_ALL_REQUESTS != 0;

        // Enroll permissions from nTSecurityDescriptor are complex to parse fully;
        // we surface them as a raw list — vulnerability logic doesn't depend on them.
        let enroll_permissions: Vec<String> = entry.attrs
            .get("nTSecurityDescriptor")
            .map(|v| v.clone())
            .unwrap_or_default();

        let mut template = CertTemplate {
            name: name.clone(),
            display_name,
            distinguished_name: entry.dn.clone(),
            schema_version,
            oid,
            enroll_permissions,
            enrollee_supplies_subject,
            extended_key_usage,
            requires_manager_approval,
            authorized_signatures_required: ra_sigs,
            vulnerabilities: Vec::new(),
        };

        template.analyze();

        if !template.vulnerabilities.is_empty() {
            info!("[adcs]  {} → {:?}", name, template.vulnerabilities);
        } else {
            info!("[adcs]  {} (no obvious vulnerabilities)", name);
        }

        results.push(template);
    }

    let _ = conn.disconnect().await;

    let vuln_count = results.iter().filter(|t| !t.vulnerabilities.is_empty()).count();
    info!("[adcs] Found {} templates ({} potentially vulnerable)",
        results.len(), vuln_count);
    Ok(results)
}
