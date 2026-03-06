//! Integration tests for ADCS ESC1-ESC8 certificate template vulnerability checks.
//!
//! These tests run entirely offline — no live DC or ADCS required.
//! They validate the full ESC detection pipeline against synthetic templates.

use overthrone_reaper::adcs::CertTemplate;

// ═══════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════

/// Well-known OIDs used in tests.
const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const OID_SMART_CARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
const OID_CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";
const OID_ANY_PURPOSE: &str = "2.5.29.37.0";
const OID_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

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
        display_name: Some(name.to_string()),
        distinguished_name: format!(
            "CN={},CN=Certificate Templates,CN=Public Key Services,CN=Services,\
             CN=Configuration,DC=yourorg,DC=local",
            name
        ),
        schema_version: 2,
        oid: Some("1.3.6.1.4.1.311.21.8.0".to_string()),
        enroll_permissions: permissions.iter().map(|s| s.to_string()).collect(),
        enrollee_supplies_subject,
        extended_key_usage: ekus.iter().map(|s| s.to_string()).collect(),
        requires_manager_approval: requires_approval,
        authorized_signatures_required: ra_sigs,
        vulnerabilities: Vec::new(),
    }
}

// ═══════════════════════════════════════════════════════════
//  ESC1 — Enrollee Supplies Subject + Client Auth
// ═══════════════════════════════════════════════════════════

#[test]
fn esc1_classic_vulnerable() {
    let mut t = make_template("WebServer-SAN", true, false, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(
        has_esc(&t, "ESC1"),
        "Expected ESC1: {:?}",
        t.vulnerabilities
    );
}

#[test]
fn esc1_smartcard_eku_also_triggers() {
    let mut t = make_template(
        "SmartCard-SAN",
        true,
        false,
        0,
        &[OID_SMART_CARD_LOGON],
        &[],
    );
    t.analyze();
    assert!(has_esc(&t, "ESC1"));
}

#[test]
fn esc1_blocked_by_manager_approval() {
    let mut t = make_template("Approved-SAN", true, true, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(!has_esc(&t, "ESC1"));
}

#[test]
fn esc1_blocked_by_ra_signature() {
    let mut t = make_template("Signed-SAN", true, false, 1, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(!has_esc(&t, "ESC1"));
}

#[test]
fn esc1_blocked_by_server_auth_only() {
    let mut t = make_template("Server-Only", true, false, 0, &[OID_SERVER_AUTH], &[]);
    t.analyze();
    assert!(
        !has_esc(&t, "ESC1"),
        "Server-auth only should not trigger ESC1"
    );
}

// ═══════════════════════════════════════════════════════════
//  ESC2 — Any Purpose / No EKU
// ═══════════════════════════════════════════════════════════

#[test]
fn esc2_any_purpose_eku() {
    let mut t = make_template("AnyPurpose", false, false, 0, &[OID_ANY_PURPOSE], &[]);
    t.analyze();
    assert!(has_esc(&t, "ESC2"));
}

#[test]
fn esc2_empty_eku() {
    let mut t = make_template("NoEKU", false, false, 0, &[], &[]);
    t.analyze();
    assert!(has_esc(&t, "ESC2"), "Empty EKU = any purpose → ESC2");
}

#[test]
fn esc2_safe_with_specific_eku() {
    let mut t = make_template("ClientAuth-Only", false, false, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(!has_esc(&t, "ESC2"), "Specific EKU should not trigger ESC2");
}

// ═══════════════════════════════════════════════════════════
//  ESC3 — Certificate Request Agent
// ═══════════════════════════════════════════════════════════

#[test]
fn esc3_enrollment_agent_eku() {
    let mut t = make_template(
        "EnrollmentAgent",
        false,
        false,
        0,
        &[OID_CERT_REQUEST_AGENT],
        &[],
    );
    t.analyze();
    assert!(has_esc(&t, "ESC3"));
}

#[test]
fn esc3_safe_wrong_eku() {
    let mut t = make_template("ClientAuth", false, false, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(
        !has_esc(&t, "ESC3"),
        "Client auth alone should not trigger ESC3"
    );
}

#[test]
fn esc3_safe_with_approval() {
    let mut t = make_template(
        "EnrollmentAgent-Approved",
        false,
        true,
        0,
        &[OID_CERT_REQUEST_AGENT],
        &[],
    );
    t.analyze();
    assert!(!has_esc(&t, "ESC3"), "Approval blocks ESC3");
}

#[test]
fn esc3_safe_with_signature_requirement() {
    let mut t = make_template(
        "EnrollmentAgent-Signed",
        false,
        false,
        2,
        &[OID_CERT_REQUEST_AGENT],
        &[],
    );
    t.analyze();
    assert!(!has_esc(&t, "ESC3"), "RA signatures block ESC3");
}

// ═══════════════════════════════════════════════════════════
//  ESC4 — Overly Permissive Template ACLs
// ═══════════════════════════════════════════════════════════

#[test]
fn esc4_authenticated_users_write_property() {
    let perms = &["O:SYG:SYD:(A;;RPWP;;;AU)"];
    let mut t = make_template(
        "WritableTemplate",
        false,
        false,
        0,
        &[OID_CLIENT_AUTH],
        perms,
    );
    t.analyze();
    assert!(has_esc(&t, "ESC4"), "AU with WP → ESC4");
}

#[test]
fn esc4_everyone_generic_all() {
    let perms = &["(A;;GA;;;WD)"];
    let mut t = make_template("PublicTemplate", false, false, 0, &[OID_CLIENT_AUTH], perms);
    t.analyze();
    assert!(has_esc(&t, "ESC4"), "Everyone/GA → ESC4");
}

#[test]
fn esc4_domain_users_write_dacl() {
    let perms = &["(A;;RPWDRC;;;DU)"];
    let mut t = make_template("DU-WriteDacl", false, false, 0, &[OID_CLIENT_AUTH], perms);
    t.analyze();
    assert!(has_esc(&t, "ESC4"), "DU with WD → ESC4");
}

#[test]
fn esc4_safe_admin_only() {
    let perms = &["O:SYG:SYD:(A;;GA;;;DA)(A;;RPRC;;;AU)"];
    let mut t = make_template("AdminOnly", false, false, 0, &[OID_CLIENT_AUTH], perms);
    t.analyze();
    assert!(!has_esc(&t, "ESC4"), "Only DA has write → safe");
}

// ═══════════════════════════════════════════════════════════
//  ESC5 — Overly Permissive PKI Object ACLs
// ═══════════════════════════════════════════════════════════

#[test]
fn esc5_everyone_generic_all() {
    let perms = &["(A;;GA;;;WD)"];
    let mut t = make_template("PKI-Open", false, false, 0, &[], perms);
    t.analyze();
    assert!(has_esc(&t, "ESC5"));
}

#[test]
fn esc5_auth_users_write_owner() {
    let perms = &["(A;;RPWORC;;;AU)"];
    let mut t = make_template("AU-WriteOwner", false, false, 0, &[], perms);
    t.analyze();
    assert!(has_esc(&t, "ESC5"), "AU with WO → ESC5");
}

#[test]
fn esc5_safe_read_only() {
    let perms = &["(A;;RPRC;;;AU)"];
    let mut t = make_template("ReadOnly", false, false, 0, &[], perms);
    t.analyze();
    assert!(!has_esc(&t, "ESC5"), "ReadProp+ReadControl only → safe");
}

// ═══════════════════════════════════════════════════════════
//  ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Indicator
// ═══════════════════════════════════════════════════════════

#[test]
fn esc6_potential_indicator() {
    let mut t = make_template(
        "StandardUser",
        false, // enrollee does NOT supply subject
        false, // no approval
        0,     // no sigs
        &[OID_CLIENT_AUTH],
        &[],
    );
    t.analyze();
    assert!(
        has_esc(&t, "ESC6"),
        "No SAN flag + client auth + no approval → potential ESC6"
    );
}

#[test]
fn esc6_not_when_enrollee_supplies_subject() {
    // If enrollee_supplies_subject, that's ESC1, not ESC6
    let mut t = make_template("SAN-Enabled", true, false, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(
        !has_esc(&t, "ESC6"),
        "enrollee_supplies_subject → ESC1 not ESC6"
    );
}

#[test]
fn esc6_blocked_by_approval() {
    let mut t = make_template("Approved-User", false, true, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(!has_esc(&t, "ESC6"));
}

// ═══════════════════════════════════════════════════════════
//  ESC7 — SubCA / ManageCA Abuse
// ═══════════════════════════════════════════════════════════

#[test]
fn esc7_empty_eku_low_priv_enrollment() {
    let perms = &["(A;;GA;;;AU)"];
    let mut t = make_template("SubCA-Template", false, false, 0, &[], perms);
    t.analyze();
    assert!(
        has_esc(&t, "ESC7"),
        "Empty EKU + low-priv enrollment → ESC7"
    );
}

#[test]
fn esc7_safe_no_low_priv_enrollment() {
    let perms = &["(A;;GA;;;DA)"];
    let mut t = make_template("SubCA-Admin", false, false, 0, &[], perms);
    t.analyze();
    assert!(!has_esc(&t, "ESC7"), "Only DA can enroll → no ESC7");
}

// ═══════════════════════════════════════════════════════════
//  ESC8 — HTTP Enrollment / NTLM Relay
// ═══════════════════════════════════════════════════════════

#[test]
fn esc8_client_auth_no_approval() {
    let mut t = make_template("HTTPEnroll", false, false, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(has_esc(&t, "ESC8"));
}

#[test]
fn esc8_blocked_by_approval() {
    let mut t = make_template("HTTPEnroll-Safe", false, true, 0, &[OID_CLIENT_AUTH], &[]);
    t.analyze();
    assert!(!has_esc(&t, "ESC8"));
}

#[test]
fn esc8_blocked_by_no_client_eku() {
    let mut t = make_template("ServerOnly-HTTP", false, false, 0, &[OID_SERVER_AUTH], &[]);
    t.analyze();
    assert!(!has_esc(&t, "ESC8"), "Server auth only → no ESC8");
}

// ═══════════════════════════════════════════════════════════
//  Combined / Scenario Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn mega_vulnerable_template_flags_many_escs() {
    let perms = &["O:SYG:SYD:(A;;GA;;;AU)"];
    let mut t = make_template(
        "MegaVulnerable",
        true, // supplies subject → ESC1
        false,
        0,
        &[OID_ANY_PURPOSE], // any purpose → ESC2
        perms,              // AU:GA → ESC4, ESC5, ESC7
    );
    t.analyze();
    let esc_nums: Vec<&str> = t
        .vulnerabilities
        .iter()
        .filter_map(|v| v.split(':').next())
        .collect();
    assert!(
        esc_nums.contains(&"ESC1"),
        "Missing ESC1: {:?}",
        t.vulnerabilities
    );
    assert!(
        esc_nums.contains(&"ESC2"),
        "Missing ESC2: {:?}",
        t.vulnerabilities
    );
    assert!(
        esc_nums.contains(&"ESC4"),
        "Missing ESC4: {:?}",
        t.vulnerabilities
    );
    assert!(
        esc_nums.contains(&"ESC5"),
        "Missing ESC5: {:?}",
        t.vulnerabilities
    );
    assert!(
        esc_nums.contains(&"ESC7"),
        "Missing ESC7: {:?}",
        t.vulnerabilities
    );
    assert!(
        t.vulnerabilities.len() >= 5,
        "Expected 5+ vulns, got {}",
        t.vulnerabilities.len()
    );
}

#[test]
fn hardened_template_has_zero_vulns() {
    let perms = &["O:SYG:SYD:(A;;GA;;;DA)(A;;RPRC;;;AU)"];
    let mut t = make_template(
        "Hardened-ServerAuth",
        false,              // CA builds subject from AD
        true,               // requires manager approval
        1,                  // requires authorized signature
        &[OID_SERVER_AUTH], // server auth only
        perms,              // only DA has write
    );
    t.analyze();
    assert!(
        t.vulnerabilities.is_empty(),
        "Hardened template should have zero vulns: {:?}",
        t.vulnerabilities
    );
}

#[test]
fn complex_sddl_with_multiple_aces() {
    let perms =
        &["O:SYG:SYD:PAI(A;;RPRC;;;AU)(A;;RPWPCCDCLCSWRCWDWO;;;DU)(A;;GA;;;BA)(A;;GA;;;SY)"];
    // Domain Users (DU) has WP+CC+DC+WD+WO → dangerous
    let mut t = make_template("MultiACE", false, false, 0, &[OID_CLIENT_AUTH], perms);
    t.analyze();
    assert!(
        has_esc(&t, "ESC4"),
        "DU with WP+WD+WO → ESC4: {:?}",
        t.vulnerabilities
    );
}

#[test]
fn builtin_users_sid_triggers_esc4() {
    let perms = &["(A;;RPWP;;;BU)"]; // BU = Builtin\Users
    let mut t = make_template("BU-Writable", false, false, 0, &[OID_CLIENT_AUTH], perms);
    t.analyze();
    assert!(has_esc(&t, "ESC4"), "Builtin Users (BU) with WP → ESC4");
}

#[test]
fn full_sid_format_authenticated_users() {
    // Use full SID instead of SDDL alias
    let perms = &["(A;;GA;;;S-1-5-11)"];
    let mut t = make_template("FullSID-AU", false, false, 0, &[], perms);
    t.analyze();
    assert!(
        has_esc(&t, "ESC4"),
        "S-1-5-11 (Authenticated Users) with GA → ESC4"
    );
}

#[test]
fn full_sid_domain_users_suffix() {
    // Domain Users SID ends in -513
    let perms = &["(A;;GA;;;S-1-5-21-1234567890-1234567890-1234567890-513)"];
    let mut t = make_template("FullSID-DU", false, false, 0, &[], perms);
    t.analyze();
    assert!(
        has_esc(&t, "ESC4"),
        "Domain Users SID (-513) with GA → ESC4"
    );
}

// ═══════════════════════════════════════════════════════════
//  Helper
// ═══════════════════════════════════════════════════════════

fn has_esc(t: &CertTemplate, esc: &str) -> bool {
    t.vulnerabilities.iter().any(|v| v.contains(esc))
}
