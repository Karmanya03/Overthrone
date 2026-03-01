//! Integration tests for overthrone-reaper — LDAP enumeration engine.
//!
//! These tests run entirely offline using fixture data.
//! No live DC/LDAP connection required.

use std::collections::HashMap;
use std::path::PathBuf;

// ═══════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn load_fixture(name: &str) -> String {
    let path = fixtures_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read fixture '{}': {}", path.display(), e))
}

fn load_json(name: &str) -> serde_json::Value {
    let raw = load_fixture(name);
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Cannot parse fixture '{}': {}", name, e))
}

/// Build an attribute map from the fixture JSON "attrs" object.
fn attrs_from_json(val: &serde_json::Value) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    if let Some(obj) = val.as_object() {
        for (key, values) in obj {
            let vec: Vec<String> = values
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !vec.is_empty() {
                map.insert(key.clone(), vec);
            }
        }
    }
    map
}

// ═══════════════════════════════════════════════════════════
//  Mock Domain Fixture Validation
// ═══════════════════════════════════════════════════════════

#[test]
fn test_mock_domain_loads() {
    let domain = load_json("mock_domain.json");
    assert_eq!(domain["domain"].as_str().unwrap(), "YOURORG.LOCAL");
    assert!(
        domain["domain_sid"]
            .as_str()
            .unwrap()
            .starts_with("S-1-5-21-")
    );
}

#[test]
fn test_mock_domain_has_users() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();
    assert!(users.len() >= 4, "Expected at least 4 test users");

    // Verify admin user
    let admin = users
        .iter()
        .find(|u| u["sam_account_name"] == "administrator")
        .unwrap();
    assert_eq!(admin["admin_count"], 1);
    assert_eq!(admin["enabled"], true);
}

#[test]
fn test_mock_domain_has_kerberoastable_user() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();
    let spn_users: Vec<_> = users
        .iter()
        .filter(|u| {
            u["spn"].as_array().map(|a| !a.is_empty()).unwrap_or(false) && u["enabled"] == true
        })
        .collect();
    assert!(
        !spn_users.is_empty(),
        "Expected at least 1 kerberoastable user"
    );
    assert_eq!(spn_users[0]["sam_account_name"], "svc_sql");
}

#[test]
fn test_mock_domain_has_stale_admin() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();
    let stale = users
        .iter()
        .find(|u| u["enabled"] == false && u["admin_count"] == 1);
    assert!(
        stale.is_some(),
        "Expected a disabled user still in DA group"
    );
}

#[test]
fn test_mock_domain_has_description_password() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();
    let leaky = users.iter().find(|u| {
        u["description"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("password")
    });
    assert!(
        leaky.is_some(),
        "Expected a user with password in description field"
    );
}

#[test]
fn test_mock_domain_computers() {
    let domain = load_json("mock_domain.json");
    let computers = domain["computers"].as_array().unwrap();
    assert!(computers.len() >= 3);

    let ws01 = computers
        .iter()
        .find(|c| c["sam_account_name"] == "WS01$")
        .unwrap();
    assert!(
        ws01["laps_v1"].as_str().is_some(),
        "WS01 should have LAPS v1 password"
    );
}

#[test]
fn test_mock_domain_gpos() {
    let domain = load_json("mock_domain.json");
    let gpos = domain["gpos"].as_array().unwrap();
    assert!(gpos.len() >= 2);

    // Every GPO should have a GUID
    for gpo in gpos {
        let guid = gpo["guid"].as_str().unwrap();
        assert!(
            guid.starts_with('{') && guid.ends_with('}'),
            "GPO GUID malformed: {}",
            guid
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  LAPS Parsing Tests (from fixture data)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_laps_v1_from_fixture() {
    let data = load_json("laps_v2_response.json");
    let entries = data["entries"].as_array().unwrap();

    let ws01 = entries
        .iter()
        .find(|e| e["attrs"]["sAMAccountName"][0].as_str() == Some("WS01$"))
        .unwrap();

    let attrs = attrs_from_json(&ws01["attrs"]);
    let entry = overthrone_reaper::laps::parse_laps_entry(&attrs);

    assert_eq!(entry.computer_name, "WS01$");
    assert_eq!(entry.password.as_deref(), Some("xK9mL2pQ7rW3"));
    assert!(!entry.is_laps_v2);
    assert!(entry.managed_account.is_none());
    assert!(entry.encrypted_blob.is_none());
    assert!(
        entry.expiration.is_some(),
        "Expiration should be converted from FILETIME"
    );
}

#[test]
fn test_laps_v2_plaintext_from_fixture() {
    let data = load_json("laps_v2_response.json");
    let entries = data["entries"].as_array().unwrap();

    let srv01 = entries
        .iter()
        .find(|e| e["attrs"]["sAMAccountName"][0].as_str() == Some("SRV01$"))
        .unwrap();

    let attrs = attrs_from_json(&srv01["attrs"]);
    let entry = overthrone_reaper::laps::parse_laps_entry(&attrs);

    assert_eq!(entry.computer_name, "SRV01$");
    assert_eq!(entry.password.as_deref(), Some("R@nd0mP@ss99!"));
    assert!(entry.is_laps_v2);
    assert_eq!(entry.managed_account.as_deref(), Some("Administrator"));
}

#[test]
fn test_laps_v2_custom_account_from_fixture() {
    let data = load_json("laps_v2_response.json");
    let entries = data["entries"].as_array().unwrap();

    let srv02 = entries
        .iter()
        .find(|e| e["attrs"]["sAMAccountName"][0].as_str() == Some("SRV02$"))
        .unwrap();

    let attrs = attrs_from_json(&srv02["attrs"]);
    let entry = overthrone_reaper::laps::parse_laps_entry(&attrs);

    assert_eq!(entry.managed_account.as_deref(), Some("LocalMgmt"));
    assert_eq!(entry.password.as_deref(), Some("Zx!9kW#mP2"));
}

#[test]
fn test_laps_v2_encrypted_from_fixture() {
    let data = load_json("laps_v2_response.json");
    let entries = data["entries"].as_array().unwrap();

    let dc01 = entries
        .iter()
        .find(|e| e["attrs"]["sAMAccountName"][0].as_str() == Some("DC01$"))
        .unwrap();

    let attrs = attrs_from_json(&dc01["attrs"]);
    let entry = overthrone_reaper::laps::parse_laps_entry(&attrs);

    assert_eq!(entry.computer_name, "DC01$");
    assert!(
        entry.password.is_none(),
        "Encrypted LAPS should not have plaintext password"
    );
    assert!(entry.is_laps_v2);
    assert!(
        entry.encrypted_blob.is_some(),
        "Should store encrypted blob for later decryption"
    );
}

#[test]
fn test_laps_no_attrs_skipped() {
    // Entry with no LAPS attributes at all — parse_laps_entry should return Detected
    let mut attrs = HashMap::new();
    attrs.insert("sAMAccountName".to_string(), vec!["WS99$".to_string()]);
    attrs.insert(
        "distinguishedName".to_string(),
        vec!["CN=WS99,OU=Workstations,DC=yourorg,DC=local".to_string()],
    );

    let entry = overthrone_reaper::laps::parse_laps_entry(&attrs);
    assert!(entry.password.is_none());
    assert!(!entry.is_laps_v2);
    assert!(entry.encrypted_blob.is_none());
}

// ═══════════════════════════════════════════════════════════
//  Trust Fixture Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_trusts_fixture_loads() {
    let data = load_json("mock_trusts.json");
    let trusts = data["trusts"].as_array().unwrap();
    assert!(trusts.len() >= 2);
}

#[test]
fn test_trust_bidirectional_forest() {
    let data = load_json("mock_trusts.json");
    let trusts = data["trusts"].as_array().unwrap();
    let forest_trust = trusts.iter().find(|t| t["trust_type"] == "Forest").unwrap();
    assert_eq!(forest_trust["trusted_domain"], "PARTNER.COM");
    assert_eq!(forest_trust["trust_direction"], "Bidirectional");
    assert_eq!(forest_trust["sid_filtering"], true);
}

#[test]
fn test_trust_foreign_membership() {
    let data = load_json("mock_trusts.json");
    let foreign = data["foreign_memberships"].as_array().unwrap();
    assert!(!foreign.is_empty());
    assert!(
        foreign[0]["foreign_member_sid"]
            .as_str()
            .unwrap()
            .starts_with("S-1-5-21-")
    );
}

// ═══════════════════════════════════════════════════════════
//  LDAP Response Fixture Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_ldap_response_delegation() {
    let data = load_json("mock_ldap_response.json");
    let deleg = data["delegation_results"].as_array().unwrap();
    assert!(!deleg.is_empty());

    let ws01 = &deleg[0];
    let allowed_to = ws01["attrs"]["msDS-AllowedToDelegateTo"][0]
        .as_str()
        .unwrap();
    assert!(
        allowed_to.contains("cifs/"),
        "Expected constrained delegation to cifs SPN"
    );
}

// ═══════════════════════════════════════════════════════════
//  ADCS Certificate Template ESC Checks (offline)
// ═══════════════════════════════════════════════════════════

use overthrone_reaper::adcs::CertTemplate;

fn make_cert_template(
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
        distinguished_name: format!("CN={},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=yourorg,DC=local", name),
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

#[test]
fn test_adcs_esc1_vulnerable_template() {
    let mut t = make_cert_template(
        "WebServer-ESC1",
        true,   // enrollee supplies subject
        false,  // no manager approval
        0,      // no signatures required
        &["1.3.6.1.5.5.7.3.2"], // Client Authentication
        &[],
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC1")),
        "Should be flagged ESC1: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc1_safe_with_approval() {
    let mut t = make_cert_template(
        "ManagedUser",
        true,
        true,   // requires manager approval → blocks ESC1
        0,
        &["1.3.6.1.5.5.7.3.2"],
        &[],
    );
    t.analyze();
    assert!(!t.vulnerabilities.iter().any(|v| v.contains("ESC1")),
        "Should NOT be ESC1 when approval required: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc2_any_purpose() {
    let mut t = make_cert_template(
        "AnyPurpose",
        false,
        false,
        0,
        &["2.5.29.37.0"], // Any Purpose EKU
        &[],
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC2")),
        "Should be flagged ESC2: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc2_no_eku() {
    let mut t = make_cert_template("NoEKU", false, false, 0, &[], &[]);
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC2")),
        "Empty EKU = any purpose → ESC2: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc3_enrollment_agent() {
    let mut t = make_cert_template(
        "EnrollmentAgent",
        false,
        false,
        0,
        &["1.3.6.1.4.1.311.20.2.1"], // Certificate Request Agent
        &[],
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC3")),
        "Should be flagged ESC3: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc3_safe_requires_signatures() {
    let mut t = make_cert_template(
        "EnrollmentAgent-Safe",
        false,
        false,
        1,    // requires 1 authorized signature
        &["1.3.6.1.4.1.311.20.2.1"],
        &[],
    );
    t.analyze();
    assert!(!t.vulnerabilities.iter().any(|v| v.contains("ESC3")),
        "Should NOT be ESC3 when signatures required: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc4_writable_by_auth_users() {
    let mut t = make_cert_template(
        "Writable-ESC4",
        false,
        false,
        0,
        &["1.3.6.1.5.5.7.3.2"],
        &["O:SYG:SYD:(A;;RPWP;;;AU)(A;;GA;;;SY)"], // AU = Authenticated Users with WriteProperty
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC4")),
        "Should be ESC4 when AU has WriteProperty: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc4_safe_admin_only() {
    let mut t = make_cert_template(
        "AdminOnly-ESC4",
        false,
        false,
        0,
        &["1.3.6.1.5.5.7.3.2"],
        &["O:SYG:SYD:(A;;GA;;;DA)(A;;RPRC;;;AU)"], // DA has GenericAll, AU has ReadProp+ReadControl
    );
    t.analyze();
    assert!(!t.vulnerabilities.iter().any(|v| v.contains("ESC4")),
        "Should NOT be ESC4 when only DA has GenericAll: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc5_generic_all_everyone() {
    let mut t = make_cert_template(
        "OpenACL-ESC5",
        false,
        false,
        0,
        &[],
        &["O:SYG:SYD:(A;;GA;;;WD)"], // WD = Everyone with GenericAll
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC5")),
        "Should be ESC5 with Everyone:GenericAll: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc6_indicator() {
    // Template that would be vulnerable if CA has EDITF_ATTRIBUTESUBJECTALTNAME2
    let mut t = make_cert_template(
        "StandardUser-ESC6",
        false,  // enrollee does NOT supply subject (that would be ESC1)
        false,
        0,
        &["1.3.6.1.5.5.7.3.2"], // Client Authentication
        &[],
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC6")),
        "Should be potential ESC6 indicator: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc7_subca_template() {
    let mut t = make_cert_template(
        "SubCA-ESC7",
        false,
        false,
        0,
        &[],  // empty EKU = SubCA-capable
        &["O:SYG:SYD:(A;;GA;;;AU)"], // low-priv can enroll
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC7")),
        "Should be ESC7 SubCA enrollable by low-priv: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc8_http_enrollment() {
    let mut t = make_cert_template(
        "HttpEnroll-ESC8",
        false,
        false,
        0,
        &["1.3.6.1.5.5.7.3.2"], // Client Authentication
        &[],
    );
    t.analyze();
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC8")),
        "Should be potential ESC8: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_esc8_safe_with_approval() {
    let mut t = make_cert_template(
        "ApprovalRequired",
        false,
        true,  // requires approval
        0,
        &["1.3.6.1.5.5.7.3.2"],
        &[],
    );
    t.analyze();
    assert!(!t.vulnerabilities.iter().any(|v| v.contains("ESC8")),
        "Should NOT be ESC8 with approval: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_mega_vulnerable_template() {
    let mut t = make_cert_template(
        "MegaVulnerable",
        true,   // supplies subject
        false,  // no approval
        0,      // no sigs
        &["2.5.29.37.0"], // Any Purpose
        &["O:SYG:SYD:(A;;GA;;;AU)"], // AU has GenericAll
    );
    t.analyze();
    // Should have at minimum: ESC1, ESC2, ESC4, ESC5, ESC7
    assert!(t.vulnerabilities.len() >= 5,
        "MegaVulnerable should trigger many ESC checks, got {}: {:?}",
        t.vulnerabilities.len(), t.vulnerabilities);
}

#[test]
fn test_adcs_hardened_template_no_vulns() {
    let mut t = make_cert_template(
        "Hardened-Server-Auth",
        false,  // CA builds subject from AD
        true,   // requires manager approval
        1,      // requires authorized signature
        &["1.3.6.1.5.5.7.3.1"], // Server Authentication only (not client auth)
        &["O:SYG:SYD:(A;;GA;;;DA)(A;;RPRC;;;AU)"], // Only DA has write
    );
    t.analyze();
    assert!(t.vulnerabilities.is_empty(),
        "Hardened template should have zero vulns: {:?}", t.vulnerabilities);
}

#[test]
fn test_adcs_sddl_parsing_multiple_aces() {
    let mut t = make_cert_template(
        "MultiACE",
        false, false, 0,
        &["1.3.6.1.5.5.7.3.2"],
        &["O:SYG:SYD:(A;;RPRC;;;AU)(A;;RPWP;;;DU)(A;;GA;;;BA)(D;;WD;;;WD)"],
        // AU: ReadProp+ReadControl (safe)
        // DU: ReadProp+WriteProp (dangerous for Domain Users → ESC4)
        // BA: GenericAll (admin, safe)
        // WD: Everyone denied WriteDacl (deny ACE, but our parser doesn't distinguish)
    );
    t.analyze();
    // Domain Users with WriteProperty → ESC4
    assert!(t.vulnerabilities.iter().any(|v| v.contains("ESC4")),
        "DU with WP should trigger ESC4: {:?}", t.vulnerabilities);
}
