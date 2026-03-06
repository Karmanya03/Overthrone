//! Live DC Integration Tests for overthrone-core
//!
//! Run against a real Active Directory (e.g. GOAD):
//!
//!   $env:OT_DC_HOST = "192.168.56.10"
//!   $env:OT_DOMAIN = "north.sevenkingdoms.local"
//!   $env:OT_USERNAME = "brandon.stark"
//!   $env:OT_PASSWORD = "iseedeadpeople"
//!   cargo test -p overthrone-core --test live_dc -- --ignored

struct DcConfig {
    host: String,
    domain: String,
    username: String,
    password: String,
}

impl DcConfig {
    fn require() -> Self {
        Self {
            host: std::env::var("OT_DC_HOST").expect("Set OT_DC_HOST env var"),
            domain: std::env::var("OT_DOMAIN").expect("Set OT_DOMAIN env var"),
            username: std::env::var("OT_USERNAME").expect("Set OT_USERNAME env var"),
            password: std::env::var("OT_PASSWORD").expect("Set OT_PASSWORD env var"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  LDAP
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live DC"]
async fn ldap_connect_and_bind() {
    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host,
        &cfg.domain,
        &cfg.username,
        &cfg.password,
        false,
    )
    .await
    .expect("LDAP connect failed");

    println!("Bind type: {}", session.bind_type);
    let _ = session.disconnect().await;
}

#[tokio::test]
#[ignore = "requires live DC"]
async fn ldap_full_enumeration() {
    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host,
        &cfg.domain,
        &cfg.username,
        &cfg.password,
        false,
    )
    .await
    .expect("LDAP connect failed");

    let data = session
        .full_enumeration()
        .await
        .expect("Enumeration failed");
    let _ = session.disconnect().await;

    println!(
        "Users: {}, Computers: {}, Groups: {}, Trusts: {}",
        data.users.len(),
        data.computers.len(),
        data.groups.len(),
        data.trusts.len()
    );

    assert!(!data.users.is_empty(), "No users found");
    assert!(!data.groups.is_empty(), "No groups found");
}

// ═══════════════════════════════════════════════════════════
//  Attack Graph from Live Data
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live DC"]
async fn graph_build_from_live_dc() {
    use overthrone_core::graph::AttackGraph;

    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host,
        &cfg.domain,
        &cfg.username,
        &cfg.password,
        false,
    )
    .await
    .expect("LDAP connect failed");

    let data = session
        .full_enumeration()
        .await
        .expect("Enumeration failed");
    let _ = session.disconnect().await;

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&data);

    let stats = graph.stats();
    println!("{:?}", stats);

    assert!(stats.total_nodes > 0);
    assert!(stats.total_edges > 0);
    assert!(stats.users > 0);

    // Export and reload roundtrip
    let json = graph.export_json().expect("export failed");
    let tmp = std::env::temp_dir().join("overthrone_live_test_graph.json");
    std::fs::write(&tmp, &json).unwrap();

    let reloaded = AttackGraph::from_json_file(tmp.to_str().unwrap()).unwrap();
    assert_eq!(graph.node_count(), reloaded.node_count());
    assert_eq!(graph.edge_count(), reloaded.edge_count());

    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
#[ignore = "requires live DC"]
async fn graph_paths_to_da_live() {
    use overthrone_core::graph::AttackGraph;

    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host,
        &cfg.domain,
        &cfg.username,
        &cfg.password,
        false,
    )
    .await
    .expect("LDAP connect failed");

    let data = session
        .full_enumeration()
        .await
        .expect("Enumeration failed");
    let _ = session.disconnect().await;

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&data);

    let user = format!(
        "{}@{}",
        cfg.username.to_uppercase(),
        cfg.domain.to_uppercase()
    );
    let paths = graph.paths_to_da(&user, &cfg.domain);
    println!("Paths to DA from {}: found {} path(s)", user, paths.len());
    for (i, p) in paths.iter().enumerate() {
        println!("  Path #{}: {}", i + 1, p);
    }
}

#[tokio::test]
#[ignore = "requires live DC"]
async fn graph_high_value_targets_live() {
    use overthrone_core::graph::AttackGraph;

    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host,
        &cfg.domain,
        &cfg.username,
        &cfg.password,
        false,
    )
    .await
    .expect("LDAP connect failed");

    let data = session
        .full_enumeration()
        .await
        .expect("Enumeration failed");
    let _ = session.disconnect().await;

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&data);

    let hvt = graph.high_value_targets(10);
    println!("High-value targets:");
    for (name, ntype, inbound) in &hvt {
        println!("  {} ({:?}) — {} inbound edges", name, ntype, inbound);
    }
    assert!(!hvt.is_empty(), "No high-value targets found");
}

// ═══════════════════════════════════════════════════════════
//  BloodHound Export
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live DC"]
async fn graph_bloodhound_export_live() {
    use overthrone_core::graph::AttackGraph;

    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host,
        &cfg.domain,
        &cfg.username,
        &cfg.password,
        false,
    )
    .await
    .expect("LDAP connect failed");

    let data = session
        .full_enumeration()
        .await
        .expect("Enumeration failed");
    let _ = session.disconnect().await;

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&data);

    let bh_json = graph.export_bloodhound().expect("BloodHound export failed");
    assert!(!bh_json.is_empty());

    // Should be valid JSON containing expected keys
    let parsed: serde_json::Value =
        serde_json::from_str(&bh_json).expect("BloodHound output is not valid JSON");
    assert!(
        parsed.get("nodes").is_some() || parsed.get("data").is_some(),
        "BloodHound JSON missing expected structure"
    );

    println!("BloodHound export: {} bytes", bh_json.len());
}
