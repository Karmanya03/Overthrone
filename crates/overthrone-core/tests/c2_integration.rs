//! C2 Integration Tests
//!
//! These tests validate the C2 module's types, serialization, and offline logic
//! WITHOUT requiring a live C2 teamserver. For live tests, see tests/integration/.

use overthrone_core::c2::*;
use std::collections::HashMap;
use std::time::Duration;

// ═══════════════════════════════════════════════════════════
// Config & Type Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_c2_framework_display() {
    assert_eq!(C2Framework::CobaltStrike.to_string(), "Cobalt Strike");
    assert_eq!(C2Framework::Sliver.to_string(), "Sliver");
    assert_eq!(C2Framework::Havoc.to_string(), "Havoc");
    assert_eq!(C2Framework::Custom("Empire".into()).to_string(), "Empire");
}

#[test]
fn test_c2_config_serialize_roundtrip() {
    let config = C2Config {
        framework: C2Framework::Sliver,
        host: "10.0.0.1".into(),
        port: 31337,
        auth: C2Auth::Token {
            token: "SECRET123".into(),
        },
        tls: true,
        tls_skip_verify: false,
        timeout: Duration::from_secs(30),
        auto_reconnect: true,
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: C2Config = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.framework, C2Framework::Sliver);
    assert_eq!(deserialized.host, "10.0.0.1");
    assert_eq!(deserialized.port, 31337);
    assert!(deserialized.tls);
    assert!(deserialized.auto_reconnect);
}

#[test]
fn test_c2_config_cobalt_strike() {
    let config = C2Config {
        framework: C2Framework::CobaltStrike,
        host: "teamserver.corp.local".into(),
        port: 50050,
        auth: C2Auth::Password {
            password: "aggressor_pass".into(),
        },
        tls: true,
        tls_skip_verify: true,
        timeout: Duration::from_secs(10),
        auto_reconnect: false,
    };

    let json = serde_json::to_string_pretty(&config).unwrap();
    assert!(json.contains("CobaltStrike"));
    assert!(json.contains("50050"));
}

#[test]
fn test_c2_config_mtls_auth() {
    let config = C2Config {
        framework: C2Framework::Sliver,
        host: "192.168.1.100".into(),
        port: 31337,
        auth: C2Auth::MtlsCert {
            cert_path: "/opt/sliver/operator-cert.pem".into(),
            key_path: "/opt/sliver/operator-key.pem".into(),
            ca_path: "/opt/sliver/ca-cert.pem".into(),
        },
        tls: true,
        tls_skip_verify: false,
        timeout: Duration::from_secs(60),
        auto_reconnect: true,
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: C2Config = serde_json::from_str(&json).unwrap();
    match deserialized.auth {
        C2Auth::MtlsCert {
            cert_path,
            key_path,
            ca_path,
        } => {
            assert!(cert_path.contains("operator-cert"));
            assert!(key_path.contains("operator-key"));
            assert!(ca_path.contains("ca-cert"));
        }
        _ => panic!("Expected MtlsCert auth"),
    }
}

// ═══════════════════════════════════════════════════════════
// Session Type Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_c2_session_serialize() {
    let session = C2Session {
        id: "abc-123-def".into(),
        hostname: "WS01".into(),
        ip: "10.0.0.50".into(),
        username: "jdoe".into(),
        domain: "CORP".into(),
        process: "explorer.exe".into(),
        pid: 4242,
        arch: "x64".into(),
        os: "Windows 10 Enterprise".into(),
        elevated: false,
        session_type: SessionType::Beacon,
        last_seen: "2025-01-15T10:30:00Z".into(),
        sleep_interval: Some(Duration::from_secs(60)),
        metadata: HashMap::new(),
    };

    let json = serde_json::to_string(&session).unwrap();
    let deserialized: C2Session = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.hostname, "WS01");
    assert_eq!(deserialized.pid, 4242);
    assert_eq!(deserialized.session_type, SessionType::Beacon);
    assert!(!deserialized.elevated);
}

#[test]
fn test_session_type_variants() {
    let types = [
        SessionType::Beacon,
        SessionType::Session,
        SessionType::SliverBeacon,
        SessionType::Demon,
        SessionType::Interactive,
    ];

    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let deserialized: SessionType = serde_json::from_str(&json).unwrap();
        assert_eq!(&deserialized, t);
    }
}

// ═══════════════════════════════════════════════════════════
// Task & Implant Request Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_c2_task_result_serialize() {
    let result = C2TaskResult {
        task_id: "task-001".into(),
        success: true,
        output: "NT AUTHORITY\\SYSTEM\n".into(),
        error: String::new(),
        raw_data: None,
        duration: Duration::from_millis(250),
    };

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: C2TaskResult = serde_json::from_str(&json).unwrap();
    assert!(deserialized.success);
    assert!(deserialized.output.contains("SYSTEM"));
}

#[test]
fn test_implant_request_serialize() {
    let request = ImplantRequest {
        target: "10.0.0.10".into(),
        implant_type: ImplantType::SliverImplant,
        listener: "https-listener".into(),
        delivery_method: DeliveryMethod::OverthroneExec,
        arch: "x64".into(),
        staged: false,
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: ImplantRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.target, "10.0.0.10");
    assert!(!deserialized.staged);
}

#[test]
fn test_c2_listener_serialize() {
    let listener = C2Listener {
        name: "https-pivot".into(),
        listener_type: "HTTPS".into(),
        host: "0.0.0.0".into(),
        port: 443,
        active: true,
    };

    let json = serde_json::to_string(&listener).unwrap();
    assert!(json.contains("https-pivot"));
    assert!(json.contains("443"));
}

// ═══════════════════════════════════════════════════════════
// Delivery Method Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_delivery_methods_serialize() {
    let methods = [
        DeliveryMethod::OverthroneExec,
        DeliveryMethod::SmbDrop,
        DeliveryMethod::WinRM,
        DeliveryMethod::ScheduledTask,
        DeliveryMethod::Dcom,
        DeliveryMethod::FrameworkNative,
    ];

    for method in &methods {
        let json = serde_json::to_string(method).unwrap();
        let deserialized: DeliveryMethod = serde_json::from_str(&json).unwrap();
        // Verify roundtrip (compare JSON since DeliveryMethod may not impl PartialEq)
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, json2);
    }
}

// ═══════════════════════════════════════════════════════════
// C2Manager Offline Tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_c2_manager_creation() {
    let manager = C2Manager::new();
    // Manager starts with no channels
    assert_eq!(manager.status().len(), 0);
    assert!(manager.default_channel().is_err());
}

#[test]
fn test_c2_framework_equality() {
    assert_eq!(C2Framework::Sliver, C2Framework::Sliver);
    assert_ne!(C2Framework::Sliver, C2Framework::Havoc);
    assert_eq!(
        C2Framework::Custom("MyC2".into()),
        C2Framework::Custom("MyC2".into())
    );
}
