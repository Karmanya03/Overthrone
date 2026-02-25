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
