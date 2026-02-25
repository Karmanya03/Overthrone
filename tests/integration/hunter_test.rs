//! Integration tests for credential hunting — GPP decryption, LAPS parsing,
//! description scraping, and Kerberoastable user detection.
//!
//! All tests run offline using fixture data.

use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
}

fn load_fixture(name: &str) -> String {
    let path = fixtures_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read fixture '{}': {}", path.display(), e))
}

fn load_json(name: &str) -> serde_json::Value {
    let raw = load_fixture(name);
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Parse '{}': {}", name, e))
}

// ═══════════════════════════════════════════════════════════
//  GPP Password Decryption
// ═══════════════════════════════════════════════════════════

#[test]
fn test_gpp_groups_xml_has_credentials() {
    let xml = load_fixture("gpp_groups.xml");
    let creds = overthrone_core::crypto::gpp::parse_gpp_xml(&xml, "test/Groups.xml");
    assert!(
        creds.len() >= 2,
        "Expected at least 2 credentials from Groups.xml, got {}",
        creds.len()
    );
}

#[test]
fn test_gpp_groups_xml_usernames() {
    let xml = load_fixture("gpp_groups.xml");
    let creds = overthrone_core::crypto::gpp::parse_gpp_xml(&xml, "test");
    let names: Vec<&str> = creds.iter().map(|c| c.username.as_str()).collect();
    assert!(names.contains(&"LocalAdmin"), "Missing LocalAdmin from GPP");
    assert!(names.contains(&"svc_deploy"), "Missing svc_deploy from GPP");
}

#[test]
fn test_gpp_groups_xml_passwords_decrypted() {
    let xml = load_fixture("gpp_groups.xml");
    let creds = overthrone_core::crypto::gpp::parse_gpp_xml(&xml, "test");
    for cred in &creds {
        assert!(
            !cred.password.is_empty(),
            "Decrypted password should not be empty for user '{}'",
            cred.username
        );
        // Decrypted passwords should NOT look like base64 (no trailing =)
        assert!(
            !cred.password.ends_with('='),
            "Password for '{}' looks like it's still base64-encoded: {}",
            cred.username,
            cred.password
        );
    }
}

#[test]
fn test_gpp_groups_xml_changed_dates() {
    let xml = load_fixture("gpp_groups.xml");
    let creds = overthrone_core::crypto::gpp::parse_gpp_xml(&xml, "test");
    for cred in &creds {
        assert!(
            !cred.changed.is_empty(),
            "Changed date should be populated for '{}'",
            cred.username
        );
    }
}

#[test]
fn test_gpp_services_xml_has_credentials() {
    let xml = load_fixture("gpp_services.xml");
    let creds = overthrone_core::crypto::gpp::parse_gpp_xml(&xml, "test/Services.xml");
    assert!(
        !creds.is_empty(),
        "Services.xml should contain at least 1 credential"
    );
    // Service accounts often use DOMAIN\user format
    let svc = &creds[0];
    assert!(
        svc.username.contains("svc_app") || svc.username.contains("YOURORG"),
        "Expected service account username, got: {}",
        svc.username
    );
}

#[test]
fn test_gpp_empty_xml_no_credentials() {
    let xml = load_fixture("gpp_empty.xml");
    let creds = overthrone_core::crypto::gpp::parse_gpp_xml(&xml, "test/empty.xml");
    // Empty cpassword="" should produce no valid credentials
    assert!(
        creds.is_empty(),
        "Empty cpassword should yield 0 credentials, got {}",
        creds.len()
    );
}

#[test]
fn test_gpp_decrypt_known_vector() {
    // Microsoft's well-known AES key: 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
    // This is the MS14-025 disclosed key, hardcoded in all Windows installations.
    let known_cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw";
    let result = overthrone_core::crypto::gpp::decrypt_gpp_password(known_cpassword);
    assert!(result.is_ok(), "Decryption failed: {:?}", result.err());
    let plaintext = result.unwrap();
    assert!(!plaintext.is_empty(), "Decrypted password is empty");
    // Should be valid UTF-8 text, not garbage
    assert!(
        plaintext.chars().all(|c| !c.is_control() || c == '\0'),
        "Decrypted password contains unexpected control characters"
    );
}

#[test]
fn test_gpp_decrypt_empty_cpassword() {
    let result = overthrone_core::crypto::gpp::decrypt_gpp_password("");
    // Should either return empty or error — not panic
    match result {
        Ok(s) => assert!(s.is_empty(), "Empty cpassword should decrypt to empty string"),
        Err(_) => {} // Also acceptable
    }
}

#[test]
fn test_gpp_decrypt_garbage_input() {
    let result = overthrone_core::crypto::gpp::decrypt_gpp_password("not-valid-base64!!!");
    // Should return an error, not panic
    assert!(result.is_err(), "Garbage input should fail gracefully");
}

// ═══════════════════════════════════════════════════════════
//  Description Scraping (password in description field)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_description_password_detection() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();

    let password_patterns = [
        "password:", "password=", "pwd:", "pwd=", "pass:", "p/w:",
        "credentials:", "cred:",
    ];

    let mut found = Vec::new();
    for user in users {
        let desc = user["description"].as_str().unwrap_or("");
        let desc_lower = desc.to_lowercase();
        for pattern in &password_patterns {
            if desc_lower.contains(pattern) {
                found.push((
                    user["sam_account_name"].as_str().unwrap().to_string(),
                    desc.to_string(),
                ));
                break;
            }
        }
    }

    assert!(
        !found.is_empty(),
        "Expected at least 1 user with password in description"
    );
    assert_eq!(found[0].0, "svc_backup");
}

// ═══════════════════════════════════════════════════════════
//  Kerberoastable User Detection
// ═══════════════════════════════════════════════════════════

#[test]
fn test_kerberoastable_detection() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();

    let roastable: Vec<_> = users.iter().filter(|u| {
        let enabled = u["enabled"].as_bool().unwrap_or(false);
        let has_spn = u["spn"].as_array().map(|a| !a.is_empty()).unwrap_or(false);
        let sam = u["sam_account_name"].as_str().unwrap_or("");
        enabled && has_spn && sam != "krbtgt"
    }).collect();

    assert_eq!(roastable.len(), 1);
    assert_eq!(roastable[0]["sam_account_name"], "svc_sql");
}

#[test]
fn test_kerberoastable_spn_format() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();
    let svc_sql = users.iter().find(|u| u["sam_account_name"] == "svc_sql").unwrap();
    let spns = svc_sql["spn"].as_array().unwrap();

    assert!(spns.len() >= 2, "svc_sql should have multiple SPNs");
    assert!(
        spns.iter().any(|s| s.as_str().unwrap().starts_with("MSSQLSvc/")),
        "Expected MSSQLSvc SPN"
    );
    // At least one SPN should have a port
    assert!(
        spns.iter().any(|s| s.as_str().unwrap().contains(":1433")),
        "Expected SPN with port 1433"
    );
}

// ═══════════════════════════════════════════════════════════
//  Stale / Dangerous Account Detection
// ═══════════════════════════════════════════════════════════

#[test]
fn test_disabled_admin_detection() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();

    let dangerous: Vec<_> = users.iter().filter(|u| {
        let disabled = !u["enabled"].as_bool().unwrap_or(true);
        let is_admin = u["admin_count"].as_i64().unwrap_or(0) == 1;
        disabled && is_admin
    }).collect();

    assert!(!dangerous.is_empty(), "Should detect disabled accounts still in privileged groups");
    assert_eq!(dangerous[0]["sam_account_name"], "old_admin");
}

#[test]
fn test_old_password_detection() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();

    // Password older than 365 days (very rough check using FILETIME)
    // 133400000000000000 ≈ mid-2024, 131000000000000000 ≈ 2015
    let threshold: i64 = 133000000000000000; // ~2023

    let stale: Vec<_> = users.iter().filter(|u| {
        let pwd_set = u["pwd_last_set"].as_str().unwrap_or("0").parse::<i64>().unwrap_or(0);
        pwd_set > 0 && pwd_set < threshold && u["enabled"].as_bool().unwrap_or(false)
    }).collect();

    assert!(
        !stale.is_empty(),
        "Should detect accounts with very old passwords"
    );
}
