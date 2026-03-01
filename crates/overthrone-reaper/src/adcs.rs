//! AD Certificate Services (ADCS) template enumeration.
//! Identifies vulnerable certificate templates (ESC1-ESC8).

use overthrone_core::error::Result;
use overthrone_core::proto::ldap::LdapSession;
use crate::runner::ReaperConfig;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Well-known OIDs
// ═══════════════════════════════════════════════════════════

/// Client Authentication EKU
const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
/// Smart Card Logon EKU
const OID_SMART_CARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
/// Certificate Request Agent (Enrollment Agent) EKU
const OID_CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";
/// Any Purpose EKU
const OID_ANY_PURPOSE: &str = "2.5.29.37.0";
/// SubCA (Subordinate Certification Authority) — no EKU or explicit SubCA
const OID_SUBCA: &str = "1.3.6.1.5.5.7.3.9";

// ═══════════════════════════════════════════════════════════
//  Well-known SIDs (low-privilege)
// ═══════════════════════════════════════════════════════════

/// Authenticated Users
const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
/// Everyone
const SID_EVERYONE: &str = "S-1-1-0";
/// Domain Users (relative; actual SID is domain-specific)
const SID_DOMAIN_USERS_SUFFIX: &str = "-513";
/// Builtin\Users
const SID_BUILTIN_USERS: &str = "S-1-5-32-545";

// ═══════════════════════════════════════════════════════════
//  SDDL rights abbreviations used in ACEs
// ═══════════════════════════════════════════════════════════

/// Dangerous SDDL rights that allow template modification
const DANGEROUS_SDDL_RIGHTS: &[&str] = &[
    "GA", // Generic All
    "WD", // Write DACL
    "WO", // Write Owner
    "WP", // Write Property
    "CC", // Create Child
    "DC", // Delete Child
];

// ═══════════════════════════════════════════════════════════
//  Flag constants
// ═══════════════════════════════════════════════════════════

/// msPKI-Certificate-Name-Flag: bit 0 = ENROLLEE_SUPPLIES_SUBJECT
const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;
/// msPKI-Enrollment-Flag: bit 1 = PEND_ALL_REQUESTS (manager approval)
const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;

// ═══════════════════════════════════════════════════════════
//  CertTemplate
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    pub name: String,
    pub display_name: Option<String>,
    pub distinguished_name: String,
    pub schema_version: u32,
    pub oid: Option<String>,
    /// Raw nTSecurityDescriptor strings (SDDL or base64-encoded binary).
    pub enroll_permissions: Vec<String>,
    pub enrollee_supplies_subject: bool,
    pub extended_key_usage: Vec<String>,
    pub requires_manager_approval: bool,
    pub authorized_signatures_required: u32,
    pub vulnerabilities: Vec<String>,
}

impl CertTemplate {
    // ──────────────────────────────────── ESC1 ─────────────────
    /// ESC1: Enrollee supplies subject + client-auth EKU + no approval/sigs.
    pub fn check_esc1(&self) -> bool {
        self.enrollee_supplies_subject
            && !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && self.has_authentication_eku()
    }

    // ──────────────────────────────────── ESC2 ─────────────────
    /// ESC2: Any Purpose EKU or empty EKU with no restrictions.
    pub fn check_esc2(&self) -> bool {
        !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && (self.extended_key_usage.is_empty()
                || self.extended_key_usage.contains(&OID_ANY_PURPOSE.to_string()))
    }

    // ──────────────────────────────────── ESC3 ─────────────────
    /// ESC3: Template grants Certificate Request Agent (enrollment agent) EKU
    /// with no approval and no authorized signature requirement. An attacker
    /// can request an enrollment agent certificate, then use it to request
    /// certs on behalf of other users.
    pub fn check_esc3(&self) -> bool {
        !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && self
                .extended_key_usage
                .contains(&OID_CERT_REQUEST_AGENT.to_string())
    }

    // ──────────────────────────────────── ESC4 ─────────────────
    /// ESC4: Overly-permissive ACLs on the template itself. A low-privilege
    /// principal (Authenticated Users, Everyone, Domain Users, Builtin\Users)
    /// has WriteDacl/WriteOwner/WriteProperty/GenericAll on the template
    /// object, allowing the template to be modified into an ESC1-vulnerable
    /// configuration.
    pub fn check_esc4(&self) -> bool {
        let aces = parse_sddl_aces(&self.enroll_permissions);
        for ace in &aces {
            if is_low_privilege_sid(&ace.trustee_sid) && ace.has_dangerous_right() {
                return true;
            }
        }
        false
    }

    // ──────────────────────────────────── ESC5 ─────────────────
    /// ESC5: Vulnerable PKI object ACLs (CA server, RootCA container,
    /// NTAuthCertificates, Enrollment Services). At the template level we
    /// flag templates where low-privilege principals have WriteProperty or
    /// GenericAll on the template *and* the template is published to a CA
    /// (indicated by non-empty enroll_permissions).
    ///
    /// Full ESC5 detection requires CA-level enumeration beyond templates.
    pub fn check_esc5(&self) -> bool {
        // Heuristic: if a low-priv principal has GenericAll, the broader
        // PKI ACL is likely permissive (ESC5 pattern).
        let aces = parse_sddl_aces(&self.enroll_permissions);
        for ace in &aces {
            if is_low_privilege_sid(&ace.trustee_sid)
                && (ace.rights.contains(&"GA".to_string())
                    || ace.rights.contains(&"WO".to_string()))
            {
                return true;
            }
        }
        false
    }

    // ──────────────────────────────────── ESC6 ─────────────────
    /// ESC6: Template-level indicator for EDITF_ATTRIBUTESUBJECTALTNAME2.
    ///
    /// At the template level: the template does NOT let the enrollee supply
    /// the subject, but it has a client-auth EKU and no approval — meaning
    /// that if the CA has the EDITF flag, any user can inject a SAN via
    /// request attributes.
    ///
    /// Confirmed exploitation requires checking the CA config separately.
    pub fn check_esc6(&self) -> bool {
        !self.enrollee_supplies_subject
            && !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && self.has_authentication_eku()
    }

    // ──────────────────────────────────── ESC7 ─────────────────
    /// ESC7: Template associated with ManageCA-level enrollment. If a low-
    /// privilege user can manage the CA (ManageCA right on the CA object),
    /// they can enable SubCA templates and issue certificates.
    ///
    /// At the template level: flag SubCA-capable or wildcard templates
    /// (empty EKU) since they are the targets of an ESC7 attack after the
    /// attacker gains ManageCA rights.
    pub fn check_esc7(&self) -> bool {
        // SubCA template indicator: no EKU restrictions + anyone can enroll
        // OID_ANY_PURPOSE also qualifies since it grants unrestricted usage
        let is_subca_template = self.extended_key_usage.is_empty()
            || self.extended_key_usage.contains(&OID_SUBCA.to_string())
            || self.extended_key_usage.contains(&OID_ANY_PURPOSE.to_string());

        let low_priv_enroll = {
            let aces = parse_sddl_aces(&self.enroll_permissions);
            aces.iter()
                .any(|a| is_low_privilege_sid(&a.trustee_sid))
        };

        is_subca_template && low_priv_enroll
    }

    // ──────────────────────────────────── ESC8 ─────────────────
    /// ESC8: HTTP-based enrollment (AD CS Web Enrollment / CES). Templates
    /// that allow enrollment with client-auth EKU and no manager approval
    /// are exploitable via NTLM relay to the web enrollment endpoint.
    ///
    /// Full ESC8 detection requires confirming the CA has an HTTP endpoint;
    /// at the template level we flag templates that *would be* vulnerable.
    pub fn check_esc8(&self) -> bool {
        !self.requires_manager_approval
            && self.authorized_signatures_required == 0
            && self.has_authentication_eku()
    }

    // ─────────────────── helpers ───────────────────────────────

    /// Does this template have an EKU that grants authentication?
    fn has_authentication_eku(&self) -> bool {
        self.extended_key_usage.is_empty()
            || self.extended_key_usage.iter().any(|eku| {
                eku == OID_CLIENT_AUTH
                    || eku == OID_SMART_CARD_LOGON
                    || eku == OID_ANY_PURPOSE
            })
    }

    /// Run all ESC checks and populate `vulnerabilities`.
    pub fn analyze(&mut self) {
        if self.check_esc1() {
            self.vulnerabilities
                .push("ESC1: Enrollee supplies subject + client auth".into());
        }
        if self.check_esc2() {
            self.vulnerabilities
                .push("ESC2: Any purpose / no EKU restriction".into());
        }
        if self.check_esc3() {
            self.vulnerabilities
                .push("ESC3: Certificate Request Agent EKU (enrollment agent)".into());
        }
        if self.check_esc4() {
            self.vulnerabilities
                .push("ESC4: Low-privilege principal has dangerous ACL on template".into());
        }
        if self.check_esc5() {
            self.vulnerabilities
                .push("ESC5: Overly permissive PKI object ACLs (GenericAll/WriteOwner)".into());
        }
        if self.check_esc6() {
            self.vulnerabilities
                .push("ESC6: Potential EDITF_ATTRIBUTESUBJECTALTNAME2 (client auth, no SAN flag)".into());
        }
        if self.check_esc7() {
            self.vulnerabilities
                .push("ESC7: SubCA/any-EKU template enrollable by low-priv (ManageCA target)".into());
        }
        if self.check_esc8() {
            self.vulnerabilities
                .push("ESC8: HTTP enrollment eligible (client auth, no approval)".into());
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Lightweight SDDL / ACE parsing
// ═══════════════════════════════════════════════════════════

/// Parsed Access Control Entry from an SDDL string.
#[derive(Debug, Clone)]
struct SddlAce {
    /// ACE type: "A" (Allow), "D" (Deny), "OA" (Object Allow), etc.
    ace_type: String,
    /// Rights abbreviations: "GA", "WP", "WD", "WO", etc.
    rights: Vec<String>,
    /// Trustee SID (e.g. "S-1-5-11", "AU", "WD")
    trustee_sid: String,
}

impl SddlAce {
    /// Does this ACE grant any of the dangerous rights?
    fn has_dangerous_right(&self) -> bool {
        self.rights
            .iter()
            .any(|r| DANGEROUS_SDDL_RIGHTS.contains(&r.as_str()))
    }
}

/// Parse SDDL ACE entries from the raw nTSecurityDescriptor strings.
///
/// nTSecurityDescriptor may be returned as:
/// 1. SDDL string: `O:SYG:SYD:(A;;RPWPCCDCLCSWRCWDWO;;;AU)(A;;GA;;;BA)...`
/// 2. Base64-encoded binary SD (not parsed here — we'd need full SD binary decoder)
/// 3. Raw hex bytes
///
/// We handle case (1) for template-level ESC4/5/7 checks.
fn parse_sddl_aces(raw_entries: &[String]) -> Vec<SddlAce> {
    let mut aces = Vec::new();

    for entry in raw_entries {
        // Look for ACE strings in parentheses: (type;flags;rights;object;inherit;trustee)
        let mut pos = 0;
        let bytes = entry.as_bytes();

        while pos < bytes.len() {
            if bytes[pos] == b'(' {
                if let Some(end) = entry[pos..].find(')') {
                    let ace_str = &entry[pos + 1..pos + end];
                    if let Some(ace) = parse_single_ace(ace_str) {
                        aces.push(ace);
                    }
                    pos += end + 1;
                } else {
                    break;
                }
            } else {
                pos += 1;
            }
        }
    }

    aces
}

/// Parse a single ACE: `type;flags;rights;object_guid;inherit_guid;trustee_sid`
fn parse_single_ace(ace_str: &str) -> Option<SddlAce> {
    let parts: Vec<&str> = ace_str.split(';').collect();
    if parts.len() < 6 {
        return None;
    }

    let ace_type = parts[0].to_string();
    let rights_str = parts[2];
    let trustee_sid = parts[5].to_string();

    // Parse compound rights string (each right is 2 chars)
    let rights = parse_rights_string(rights_str);

    Some(SddlAce {
        ace_type,
        rights,
        trustee_sid,
    })
}

/// Break a rights string like "RPWPCCDCLCSWRCWDWO" into 2-char tokens.
fn parse_rights_string(s: &str) -> Vec<String> {
    let mut rights = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if i + 1 < chars.len() {
            rights.push(format!("{}{}", chars[i], chars[i + 1]));
            i += 2;
        } else {
            // Odd trailing character — include it
            rights.push(chars[i].to_string());
            i += 1;
        }
    }

    rights
}

/// Is the given SID / SDDL alias a low-privilege principal?
fn is_low_privilege_sid(sid: &str) -> bool {
    // SDDL aliases
    match sid {
        "AU" => return true, // Authenticated Users
        "WD" => return true, // Everyone (World)
        "BU" => return true, // Builtin\Users
        "DU" => return true, // Domain Users
        "IU" => return true, // Interactive Users
        "NU" => return true, // Network Users
        _ => {}
    }

    // Full SID form
    if sid == SID_AUTHENTICATED_USERS
        || sid == SID_EVERYONE
        || sid == SID_BUILTIN_USERS
        || sid.ends_with(SID_DOMAIN_USERS_SUFFIX)
    {
        return true;
    }

    false
}

// ═══════════════════════════════════════════════════════════
//  DN / filter helpers
// ═══════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════
//  Enumeration
// ═══════════════════════════════════════════════════════════

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

        let enroll_permissions: Vec<String> = entry.attrs
            .get("nTSecurityDescriptor")
            .cloned()
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
            debug!("[adcs]  {} (no obvious vulnerabilities)", name);
        }

        results.push(template);
    }

    let _ = conn.disconnect().await;

    let vuln_count = results.iter().filter(|t| !t.vulnerabilities.is_empty()).count();
    info!("[adcs] Found {} templates ({} potentially vulnerable)",
        results.len(), vuln_count);
    Ok(results)
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_template(
        name: &str,
        enrollee_supplies_subject: bool,
        requires_approval: bool,
        ra_sigs: u32,
        ekus: &[&str],
        permissions: &[&str],
    ) -> CertTemplate {
        CertTemplate {
            name: name.to_string(),
            display_name: None,
            distinguished_name: format!("CN={},CN=Certificate Templates", name),
            schema_version: 2,
            oid: None,
            enroll_permissions: permissions.iter().map(|s| s.to_string()).collect(),
            enrollee_supplies_subject,
            extended_key_usage: ekus.iter().map(|s| s.to_string()).collect(),
            requires_manager_approval: requires_approval,
            authorized_signatures_required: ra_sigs,
            vulnerabilities: Vec::new(),
        }
    }

    #[test]
    fn test_esc1_vulnerable() {
        let t = make_template("VulnESC1", true, false, 0, &[OID_CLIENT_AUTH], &[]);
        assert!(t.check_esc1());
    }

    #[test]
    fn test_esc1_safe_approval_required() {
        let t = make_template("SafeESC1", true, true, 0, &[OID_CLIENT_AUTH], &[]);
        assert!(!t.check_esc1());
    }

    #[test]
    fn test_esc2_vulnerable_any_purpose() {
        let t = make_template("VulnESC2", false, false, 0, &[OID_ANY_PURPOSE], &[]);
        assert!(t.check_esc2());
    }

    #[test]
    fn test_esc2_vulnerable_no_eku() {
        let t = make_template("VulnESC2b", false, false, 0, &[], &[]);
        assert!(t.check_esc2());
    }

    #[test]
    fn test_esc3_enrollment_agent() {
        let t = make_template("VulnESC3", false, false, 0, &[OID_CERT_REQUEST_AGENT], &[]);
        assert!(t.check_esc3());
    }

    #[test]
    fn test_esc3_not_vulnerable_wrong_eku() {
        let t = make_template("SafeESC3", false, false, 0, &[OID_CLIENT_AUTH], &[]);
        assert!(!t.check_esc3());
    }

    #[test]
    fn test_esc4_vulnerable_acl() {
        // SDDL with Authenticated Users having GenericAll
        let perms = ["(A;;GA;;;AU)"];
        let t = make_template("VulnESC4", false, false, 0, &[OID_CLIENT_AUTH], &perms);
        assert!(t.check_esc4());
    }

    #[test]
    fn test_esc4_safe_admin_only() {
        // Only Domain Admins have GenericAll
        let perms = ["(A;;GA;;;DA)"];
        let t = make_template("SafeESC4", false, false, 0, &[OID_CLIENT_AUTH], &perms);
        assert!(!t.check_esc4());
    }

    #[test]
    fn test_esc5_generic_all_everyone() {
        let perms = ["(A;;GA;;;WD)"];
        let t = make_template("VulnESC5", false, false, 0, &[], &perms);
        assert!(t.check_esc5());
    }

    #[test]
    fn test_esc6_potential() {
        // No enrollee-supplies-subject BUT has client auth and no approval
        let t = make_template("PotentialESC6", false, false, 0, &[OID_CLIENT_AUTH], &[]);
        assert!(t.check_esc6());
    }

    #[test]
    fn test_esc6_not_when_subject_supplied() {
        // enrollee_supplies_subject=true → ESC1, not ESC6
        let t = make_template("ESC1not6", true, false, 0, &[OID_CLIENT_AUTH], &[]);
        assert!(!t.check_esc6());
    }

    #[test]
    fn test_esc7_subca_template() {
        let perms = ["(A;;GA;;;AU)"];
        let t = make_template("VulnESC7", false, false, 0, &[], &perms);
        assert!(t.check_esc7());
    }

    #[test]
    fn test_esc8_http_enrollable() {
        let t = make_template("VulnESC8", false, false, 0, &[OID_CLIENT_AUTH], &[]);
        assert!(t.check_esc8());
    }

    #[test]
    fn test_esc8_not_when_approval_needed() {
        let t = make_template("SafeESC8", false, true, 0, &[OID_CLIENT_AUTH], &[]);
        assert!(!t.check_esc8());
    }

    #[test]
    fn test_analyze_populates_all_vulns() {
        let perms = ["(A;;GA;;;AU)"];
        let mut t = make_template(
            "MegaVuln", true, false, 0, &[OID_ANY_PURPOSE], &perms
        );
        t.analyze();
        // Should flag ESC1, ESC2, ESC4, ESC5, ESC7, ESC8 at minimum
        assert!(t.vulnerabilities.len() >= 4, "Expected multiple vulns, got: {:?}", t.vulnerabilities);
    }

    #[test]
    fn test_parse_sddl_aces_basic() {
        let raw = vec!["O:SYG:SYD:(A;;RPWP;;;AU)(A;;GA;;;BA)".to_string()];
        let aces = parse_sddl_aces(&raw);
        assert_eq!(aces.len(), 2);
        assert_eq!(aces[0].ace_type, "A");
        assert_eq!(aces[0].trustee_sid, "AU");
        assert_eq!(aces[1].trustee_sid, "BA");
        assert!(aces[1].has_dangerous_right()); // GA
    }

    #[test]
    fn test_parse_rights_string() {
        let rights = parse_rights_string("RPWPCCDCLCSWRCWDWO");
        assert_eq!(rights, vec!["RP","WP","CC","DC","LC","SW","RC","WD","WO"]);
    }

    #[test]
    fn test_is_low_privilege_sid() {
        assert!(is_low_privilege_sid("AU"));
        assert!(is_low_privilege_sid("WD"));
        assert!(is_low_privilege_sid("S-1-5-11"));
        assert!(is_low_privilege_sid("S-1-5-21-1234567890-1234567890-1234567890-513"));
        assert!(!is_low_privilege_sid("DA"));
        assert!(!is_low_privilege_sid("BA"));
    }
}
