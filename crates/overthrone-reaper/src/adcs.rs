//! AD Certificate Services (ADCS) template enumeration.
//! Identifies vulnerable certificate templates (ESC1-ESC8).

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::info;

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
    pub fn check_esc1(&self) -> bool {
        self.enrollee_supplies_subject
            && !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && (self.extended_key_usage.is_empty()
                || self.extended_key_usage.iter().any(|eku| {
                    eku == "1.3.6.1.5.5.7.3.2"
                    || eku == "1.3.6.1.4.1.311.20.2.2"
                    || eku == "2.5.29.37.0"
                }))
    }

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

pub async fn enumerate_adcs(config: &ReaperConfig) -> Result<Vec<CertTemplate>> {
    info!("[adcs] Querying {} for ADCS certificate templates", config.dc_ip);
    Err(OverthroneError::NotImplemented { module: "reaper::adcs".into() })
}
