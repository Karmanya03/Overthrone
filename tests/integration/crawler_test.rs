//! Integration tests for SMB/network crawler functionality.
//!
//! All tests are offline and use fixture data. Tests that require
//! a live SMB connection are gated behind `#[ignore]` and the
//! `OVERTHRONE_TEST_DC` environment variable.

use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn load_json(name: &str) -> serde_json::Value {
    let raw = std::fs::read_to_string(fixtures_dir().join(name)).unwrap();
    serde_json::from_str(&raw).unwrap()
}

// ═══════════════════════════════════════════════════════════
//  SMB Type Validation
// ═══════════════════════════════════════════════════════════

#[test]
fn test_smb_session_types_exist() {
    // Verify the SMB types compile and are usable from external crate
    let info = overthrone_core::proto::smb::RemoteFileInfo {
        name: "test.txt".to_string(),
        path: "share\\test.txt".to_string(),
        is_directory: false,
        size: 1024,
    };
    assert_eq!(info.name, "test.txt");
    assert!(!info.is_directory);
}

#[test]
fn test_share_access_result_types() {
    let result = overthrone_core::proto::smb::ShareAccessResult {
        share_name: "SYSVOL".to_string(),
        readable: true,
        writable: false,
        is_admin_share: false,
    };
    assert!(result.readable);
    assert!(!result.writable);
    assert!(!result.is_admin_share);
}

#[test]
fn test_admin_check_result_types() {
    let result = overthrone_core::proto::smb::AdminCheckResult {
        target: "10.10.10.1".to_string(),
        has_admin: true,
        accessible_shares: vec!["C$".to_string(), "ADMIN$".to_string(), "IPC$".to_string()],
    };
    assert!(result.has_admin);
    assert_eq!(result.accessible_shares.len(), 3);
}

#[test]
fn test_admin_shares_constant() {
    assert!(overthrone_core::proto::smb::ADMIN_SHARES.contains(&"C$"));
    assert!(overthrone_core::proto::smb::ADMIN_SHARES.contains(&"ADMIN$"));
    assert!(overthrone_core::proto::smb::ADMIN_SHARES.contains(&"IPC$"));
}

// ═══════════════════════════════════════════════════════════
//  SYSVOL Path Construction
// ═══════════════════════════════════════════════════════════

#[test]
fn test_sysvol_gpo_path_construction() {
    let domain = load_json("mock_domain.json");
    let gpos = domain["gpos"].as_array().unwrap();

    for gpo in gpos {
        let guid = gpo["guid"].as_str().unwrap();
        let domain_name = domain["domain"].as_str().unwrap();

        // Construct the SYSVOL path as gpp_fetch would
        let sysvol_base = format!("{}\\Policies\\{}\\Machine\\Preferences", domain_name, guid);

        assert!(sysvol_base.contains(guid), "Path should contain GPO GUID");
        assert!(
            sysvol_base.contains("Policies"),
            "Path should contain Policies"
        );
        assert!(
            sysvol_base.ends_with("Preferences"),
            "Path should end with Preferences"
        );
    }
}

#[test]
fn test_sysvol_xml_target_paths() {
    // Verify all 6 GPP XML paths are well-formed
    let xml_files = [
        "Groups\\Groups.xml",
        "Services\\Services.xml",
        "ScheduledTasks\\ScheduledTasks.xml",
        "DataSources\\DataSources.xml",
        "Printers\\Printers.xml",
        "Drives\\Drives.xml",
    ];

    for path in &xml_files {
        assert!(path.ends_with(".xml"));
        assert!(
            path.contains('\\'),
            "Should use backslash separators for SMB"
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  DC Target Discovery (from fixtures)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_dc_targets_from_fixture() {
    let domain = load_json("mock_domain.json");
    let dcs = domain["domain_controllers"].as_array().unwrap();

    assert!(dcs.len() >= 2, "Expected at least 2 DCs in fixture");

    for dc in dcs {
        let ip = dc["ip"].as_str().unwrap();
        let hostname = dc["hostname"].as_str().unwrap();
        // IPs should be valid
        assert!(ip.split('.').count() == 4, "Invalid IP: {}", ip);
        // Hostnames should be FQDNs
        assert!(
            hostname.contains('.'),
            "DC hostname should be FQDN: {}",
            hostname
        );
    }
}

#[test]
fn test_dc_roles_populated() {
    let domain = load_json("mock_domain.json");
    let dcs = domain["domain_controllers"].as_array().unwrap();

    // At least one DC should hold FSMO roles
    let has_roles = dcs.iter().any(|dc| {
        dc["roles"]
            .as_array()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    });
    assert!(has_roles, "At least one DC should have FSMO roles assigned");
}

// ═══════════════════════════════════════════════════════════
//  Live SMB Tests (gated — requires real DC)
// ═══════════════════════════════════════════════════════════

/// Run with: OVERTHRONE_TEST_DC=10.10.10.1 OVERTHRONE_TEST_DOMAIN=yourorg.local \
///           OVERTHRONE_TEST_USER=testuser OVERTHRONE_TEST_PASS=testpass \
///           cargo test -- --ignored test_live_
#[test]
#[ignore = "Requires live DC — set OVERTHRONE_TEST_DC env var"]
fn test_live_sysvol_readable() {
    let dc = std::env::var("OVERTHRONE_TEST_DC").expect("Set OVERTHRONE_TEST_DC");
    let domain = std::env::var("OVERTHRONE_TEST_DOMAIN").expect("Set OVERTHRONE_TEST_DOMAIN");
    let user = std::env::var("OVERTHRONE_TEST_USER").expect("Set OVERTHRONE_TEST_USER");
    let pass = std::env::var("OVERTHRONE_TEST_PASS").expect("Set OVERTHRONE_TEST_PASS");

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let smb = overthrone_core::proto::smb::SmbSession::connect(&dc, &domain, &user, &pass)
            .await
            .expect("SMB connect failed");
        let readable = smb.check_share_read("SYSVOL").await;
        assert!(readable, "SYSVOL should be readable with domain creds");
    });
}

#[test]
#[ignore = "Requires live DC — set OVERTHRONE_TEST_DC env var"]
fn test_live_sysvol_list_policies() {
    let dc = std::env::var("OVERTHRONE_TEST_DC").unwrap();
    let domain = std::env::var("OVERTHRONE_TEST_DOMAIN").unwrap();
    let user = std::env::var("OVERTHRONE_TEST_USER").unwrap();
    let pass = std::env::var("OVERTHRONE_TEST_PASS").unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let smb = overthrone_core::proto::smb::SmbSession::connect(&dc, &domain, &user, &pass)
            .await
            .unwrap();
        let policies_path = format!("{}\\Policies", domain);
        let entries = smb.list_directory("SYSVOL", &policies_path).await.unwrap();
        let gpo_dirs: Vec<_> = entries
            .iter()
            .filter(|e| e.is_directory && e.name.starts_with('{'))
            .collect();
        assert!(!gpo_dirs.is_empty(), "Should find at least 1 GPO in SYSVOL");
    });
}
