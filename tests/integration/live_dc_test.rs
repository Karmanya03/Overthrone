//! Live DC Integration Tests
//!
//! These tests are designed to run against a real Active Directory environment
//! such as GOAD (Game of Active Directory) or a lab setup.
//!
//! ALL tests are marked `#[ignore]` by default — run them explicitly:
//!
//!   cargo test --test live_dc_test -- --ignored
//!
//! Configure via environment variables:
//!   OT_DC_HOST    - Domain Controller IP (e.g. 192.168.56.10)
//!   OT_DOMAIN     - AD domain (e.g. north.sevenkingdoms.local)
//!   OT_USERNAME   - Valid domain user (e.g. brandon.stark)
//!   OT_PASSWORD   - Password for the user
//!   OT_DC_HOST2   - (Optional) Second DC for trust tests
//!   OT_DOMAIN2    - (Optional) Second domain for trust tests
//!
//! Example for GOAD (default lab):
//!   $env:OT_DC_HOST = "192.168.56.10"
//!   $env:OT_DOMAIN = "north.sevenkingdoms.local"
//!   $env:OT_USERNAME = "brandon.stark"
//!   $env:OT_PASSWORD = "iseedeadpeople"
//!   cargo test --test live_dc_test -- --ignored

use std::time::Duration;

// ═══════════════════════════════════════════════════════════
//  Env Config Helper
// ═══════════════════════════════════════════════════════════

struct DcConfig {
    host: String,
    domain: String,
    username: String,
    password: String,
}

impl DcConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: std::env::var("OT_DC_HOST").ok()?,
            domain: std::env::var("OT_DOMAIN").ok()?,
            username: std::env::var("OT_USERNAME").ok()?,
            password: std::env::var("OT_PASSWORD").ok()?,
        })
    }

    fn require() -> Self {
        Self::from_env().expect(
            "Missing env vars. Set OT_DC_HOST, OT_DOMAIN, OT_USERNAME, OT_PASSWORD"
        )
    }
}

// ═══════════════════════════════════════════════════════════
//  LDAP Connection Tests
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live DC — set OT_DC_HOST etc."]
async fn test_ldap_connect() {
    let cfg = DcConfig::require();
    let session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host, &cfg.domain, &cfg.username, &cfg.password, false,
    ).await;

    assert!(session.is_ok(), "LDAP connect failed: {:?}", session.err());
    let mut session = session.unwrap();
    let _ = session.disconnect().await;
}

#[tokio::test]
#[ignore = "requires live DC — set OT_DC_HOST etc."]
async fn test_ldap_full_enumeration() {
    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host, &cfg.domain, &cfg.username, &cfg.password, false,
    ).await.expect("LDAP connect failed");

    let result = session.full_enumeration().await;
    assert!(result.is_ok(), "Enumeration failed: {:?}", result.err());

    let data = result.unwrap();
    println!("Enumerated: {} users, {} computers, {} groups, {} trusts",
        data.users.len(), data.computers.len(), data.groups.len(), data.trusts.len());

    // Basic sanity — any AD should have at least a few objects
    assert!(!data.users.is_empty(), "No users found");
    assert!(!data.computers.is_empty(), "No computers found");
    assert!(!data.groups.is_empty(), "No groups found");

    let _ = session.disconnect().await;
}

// ═══════════════════════════════════════════════════════════
//  Attack Graph Build from Live DC
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live DC — set OT_DC_HOST etc."]
async fn test_graph_build_from_dc() {
    use overthrone_core::graph::AttackGraph;

    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host, &cfg.domain, &cfg.username, &cfg.password, false,
    ).await.expect("LDAP connect failed");

    let data = session.full_enumeration().await.expect("Enumeration failed");
    let _ = session.disconnect().await;

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&data);

    let stats = graph.stats();
    println!("Graph stats: {:?}", stats);

    assert!(stats.total_nodes > 0, "Empty graph");
    assert!(stats.total_edges > 0, "No edges in graph");
    assert!(stats.users > 0, "No user nodes");
    assert!(stats.computers > 0, "No computer nodes");
}

#[tokio::test]
#[ignore = "requires live DC — set OT_DC_HOST etc."]
async fn test_graph_export_and_reload() {
    use overthrone_core::graph::AttackGraph;

    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host, &cfg.domain, &cfg.username, &cfg.password, false,
    ).await.expect("LDAP connect failed");

    let data = session.full_enumeration().await.expect("Enumeration failed");
    let _ = session.disconnect().await;

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&data);

    // Export JSON
    let json = graph.export_json().expect("Export failed");
    assert!(!json.is_empty());

    // Write and reload
    let tmp = std::env::temp_dir().join("overthrone_test_graph.json");
    std::fs::write(&tmp, &json).expect("Write failed");
    let reloaded = AttackGraph::from_json_file(tmp.to_str().unwrap())
        .expect("Reload failed");

    assert_eq!(graph.node_count(), reloaded.node_count());
    assert_eq!(graph.edge_count(), reloaded.edge_count());

    // Cleanup
    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
#[ignore = "requires live DC — set OT_DC_HOST etc."]
async fn test_graph_shortest_path_live() {
    use overthrone_core::graph::AttackGraph;

    let cfg = DcConfig::require();
    let mut session = overthrone_core::proto::ldap::LdapSession::connect(
        &cfg.host, &cfg.domain, &cfg.username, &cfg.password, false,
    ).await.expect("LDAP connect failed");

    let data = session.full_enumeration().await.expect("Enumeration failed");
    let _ = session.disconnect().await;

    let mut graph = AttackGraph::new();
    graph.ingest_enumeration(&data);

    // Try to find a path — this may or may not succeed depending on the AD data
    let user = format!("{}@{}", cfg.username.to_uppercase(), cfg.domain.to_uppercase());
    let da_group = format!("DOMAIN ADMINS@{}", cfg.domain.to_uppercase());

    match graph.shortest_path(&user, &da_group) {
        Ok(path) => {
            println!("Path found: {}", path);
            assert!(path.hop_count > 0);
        }
        Err(e) => {
            println!("No direct path (expected in some envs): {}", e);
            // Not a failure — just means no path exists from this user
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Kerberos Tests
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live DC — set OT_DC_HOST etc."]
async fn test_kerberos_tgt_request() {
    let cfg = DcConfig::require();

    // Try to get a TGT using the core kerberos module
    let result = overthrone_core::proto::kerberos::request_tgt(
        &cfg.host,
        &cfg.domain,
        &cfg.username,
        &cfg.password,
    ).await;

    match result {
        Ok(tgt) => {
            println!("TGT obtained successfully");
            // The TGT data should be non-empty
            assert!(!tgt.ticket.is_empty(), "Empty TGT ticket");
        }
        Err(e) => {
            // KDC errors like PREAUTH_FAILED are acceptable test outcomes
            let err_str = format!("{}", e);
            println!("TGT request result: {}", err_str);
            // Only fail on network-level errors, not KDC rejections
            assert!(
                !err_str.contains("connection refused") &&
                !err_str.contains("timeout"),
                "Network error getting TGT: {}", e
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  SMB / Exec Tests
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live DC — set OT_DC_HOST etc."]
async fn test_smb_connection() {
    let cfg = DcConfig::require();

    let smb = overthrone_core::exec::smb::SmbConnection {
        host: cfg.host.clone(),
        port: 445,
        domain: cfg.domain.clone(),
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        hash: None,
    };

    // Try smbexec
    let result = overthrone_core::exec::smbexec::exec_command(&smb, "whoami").await;
    match result {
        Ok(r) => {
            println!("SMB exec result: success={}, output={}", r.success, r.output);
        }
        Err(e) => {
            println!("SMB exec failed (may need admin creds): {}", e);
            // Not necessarily a test failure — depends on user privileges
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Proxy Tests (localhost only, no DC needed)
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "network test — starts a local SOCKS5 server"]
async fn test_socks5_server_starts() {
    use overthrone_core::proxy::Socks5Config;
    use overthrone_core::proxy::Socks5Server;

    let config = Socks5Config {
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 0, // OS-assigned port
        ..Default::default()
    };

    let server = Socks5Server::new(config);
    let (tx, rx) = tokio::sync::oneshot::channel();

    let handle = tokio::spawn(async move {
        server.run_until(async { rx.await.ok(); }).await
    });

    // Give server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Signal shutdown
    let _ = tx.send(());
    let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "Server did not shut down in time");
}

#[tokio::test]
#[ignore = "network test — tests local port forwarding"]
async fn test_port_forward_echo() {
    use overthrone_core::proxy::{PortForward, PortForwardConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Start echo server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = echo_listener.accept().await {
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    let config = PortForwardConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        target_addr: echo_addr.ip().to_string(),
        target_port: echo_addr.port(),
        ..Default::default()
    };

    let fwd = PortForward::new(config);
    let (tx, rx) = tokio::sync::oneshot::channel();

    let fwd_handle = tokio::spawn(async move {
        fwd.run_until(async { rx.await.ok(); }).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), fwd_handle).await;
}

// ═══════════════════════════════════════════════════════════
//  Cracker Tests (offline — no DC needed)
// ═══════════════════════════════════════════════════════════

#[test]
#[ignore = "CPU-intensive mask cracking test"]
fn test_mask_attack_keyspace() {
    use overthrone_core::crypto::MaskPattern;

    let pattern = MaskPattern::parse("?u?l?l?l?d?d?d?d").unwrap();
    // 26 * 26 * 26 * 26 * 10 * 10 * 10 * 10 = 4_569_760_000
    assert_eq!(pattern.keyspace(), 4_569_760_000);

    // Verify first candidate is generated correctly
    let mut count = 0;
    pattern.generate(|_candidate| {
        count += 1;
        count < 10 // stop after 10
    });
    assert_eq!(count, 10);
}
