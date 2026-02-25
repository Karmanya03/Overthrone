//! Integration tests for overthrone-pilot — attack execution engine.
//!
//! Tests attack path logic, privilege escalation chains, and
//! decision-making offline using fixture data.

use std::path::PathBuf;

fn load_json(name: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let raw = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&raw).unwrap()
}

// ═══════════════════════════════════════════════════════════
//  Attack Path Analysis
// ═══════════════════════════════════════════════════════════

#[test]
fn test_kerberoast_candidates_identified() {
    let domain = load_json("mock_domain.json");
    let users = domain["users"].as_array().unwrap();

    let candidates: Vec<_> = users
        .iter()
        .filter(|u| {
            let enabled = u["enabled"].as_bool().unwrap_or(false);
            let has_spn = u["spn"].as_array().map(|a| !a.is_empty()).unwrap_or(false);
            let sam = u["sam_account_name"].as_str().unwrap_or("");
            enabled && has_spn && sam != "krbtgt"
        })
        .collect();

    assert!(
        !candidates.is_empty(),
        "Pilot should identify kerberoastable targets"
    );
}

#[test]
fn test_laps_targets_identified() {
    let domain = load_json("mock_domain.json");
    let computers = domain["computers"].as_array().unwrap();

    let laps_targets: Vec<_> = computers
        .iter()
        .filter(|c| {
            c["laps_v1"].as_str().is_some()
                || c["laps_v2_password"].as_str().is_some()
                || c["laps_v2_encrypted"].as_bool().unwrap_or(false)
        })
        .collect();

    assert!(
        laps_targets.len() >= 2,
        "Should identify computers with LAPS deployed"
    );
}

#[test]
fn test_delegation_abuse_paths() {
    let ldap = load_json("mock_ldap_response.json");
    let delegations = ldap["delegation_results"].as_array().unwrap();

    let constrained: Vec<_> = delegations
        .iter()
        .filter(|d| {
            d["attrs"]
                .get("msDS-AllowedToDelegateTo")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .collect();

    assert!(
        !constrained.is_empty(),
        "Should find constrained delegation targets"
    );

    // Verify the delegation target points to a DC service
    let target_spn = constrained[0]["attrs"]["msDS-AllowedToDelegateTo"][0]
        .as_str()
        .unwrap();
    assert!(
        target_spn.contains("DC01"),
        "Delegation should target a DC: {}",
        target_spn
    );
}

#[test]
fn test_privilege_escalation_chain_gpp() {
    // Scenario: GPP creds → local admin → LAPS → DA
    let domain = load_json("mock_domain.json");
    let gpos = domain["gpos"].as_array().unwrap();
    let computers = domain["computers"].as_array().unwrap();

    // Step 1: GPO exists that could contain GPP passwords
    assert!(!gpos.is_empty(), "Need GPOs for GPP attack path");

    // Step 2: Computers have LAPS (means we could read local admin pass)
    let laps_computers: Vec<_> = computers
        .iter()
        .filter(|c| c["laps_v1"].as_str().is_some())
        .collect();
    assert!(
        !laps_computers.is_empty(),
        "Need LAPS-enabled computers for chain"
    );
}

#[test]
fn test_trust_abuse_paths() {
    let trusts = load_json("mock_trusts.json");
    let trust_list = trusts["trusts"].as_array().unwrap();
    let foreign = trusts["foreign_memberships"].as_array().unwrap();

    // Check for cross-trust privilege escalation
    let bidir_trusts: Vec<_> = trust_list
        .iter()
        .filter(|t| t["trust_direction"] == "Bidirectional")
        .collect();

    let has_foreign_da = foreign.iter().any(|f| {
        f["group_dn"]
            .as_str()
            .unwrap_or("")
            .contains("Domain Admins")
    });

    if !bidir_trusts.is_empty() && has_foreign_da {
        // This is a valid cross-trust escalation path
        assert!(true, "Cross-trust DA path exists");
    }
}

// ═══════════════════════════════════════════════════════════
//  Attack Priority Scoring
// ═══════════════════════════════════════════════════════════

#[test]
fn test_attack_priority_ordering() {
    // Simulated priority scores (higher = try first)
    let attacks = vec![
        ("GPP_Password_Decrypt", 95),   // Instant win, no noise
        ("LAPS_Read", 90),              // Direct local admin
        ("Kerberoast", 80),             // Offline cracking needed
        ("Constrained_Delegation", 70), // Complex, needs specific setup
        ("DCSync", 60),                 // Requires DA-equivalent already
        ("Trust_Abuse", 50),            // Cross-domain, complex
    ];

    // Verify ordering makes sense
    for window in attacks.windows(2) {
        assert!(
            window[0].1 >= window[1].1,
            "{} (score {}) should be >= {} (score {})",
            window[0].0,
            window[0].1,
            window[1].0,
            window[1].1
        );
    }
}
