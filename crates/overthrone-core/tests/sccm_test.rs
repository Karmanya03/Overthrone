//! Unit tests for SCCM module types and display implementations.
//!
//! Tests CollectionType parsing, SccmTechnique display, and SccmAbuseResult
//! field access.  All tests are offline.

use overthrone_core::sccm::{CollectionType, SccmAbuseResult, SccmTechnique, NaaCredential};

// ═══════════════════════════════════════════════════════════
//  CollectionType::from_u32
// ═══════════════════════════════════════════════════════════

#[test]
fn test_collection_type_1_is_user() {
    assert_eq!(CollectionType::from_u32(1), CollectionType::User);
}

#[test]
fn test_collection_type_2_is_device() {
    assert_eq!(CollectionType::from_u32(2), CollectionType::Device);
}

#[test]
fn test_collection_type_unknown_wraps_value() {
    assert_eq!(CollectionType::from_u32(0), CollectionType::Unknown(0));
    assert_eq!(CollectionType::from_u32(99), CollectionType::Unknown(99));
    assert_eq!(CollectionType::from_u32(255), CollectionType::Unknown(255));
}

// ═══════════════════════════════════════════════════════════
//  CollectionType Display
// ═══════════════════════════════════════════════════════════

#[test]
fn test_collection_type_user_display() {
    assert_eq!(CollectionType::User.to_string(), "User");
}

#[test]
fn test_collection_type_device_display() {
    assert_eq!(CollectionType::Device.to_string(), "Device");
}

#[test]
fn test_collection_type_unknown_display_includes_value() {
    let s = CollectionType::Unknown(42).to_string();
    assert!(
        s.contains("42"),
        "Unknown display must include the discriminant value; got: {s}"
    );
}

// ═══════════════════════════════════════════════════════════
//  SccmTechnique Display
// ═══════════════════════════════════════════════════════════

#[test]
fn test_sccm_technique_client_push_display_is_non_empty() {
    let s = SccmTechnique::ClientPushCoercion.to_string();
    assert!(!s.is_empty());
    // Should mention "Push" or "Coercion" to be descriptive
    assert!(
        s.contains("Push") || s.contains("Coercion"),
        "ClientPushCoercion display should mention 'Push' or 'Coercion', got: {s}"
    );
}

#[test]
fn test_sccm_technique_naa_display_mentions_credential() {
    let s = SccmTechnique::NaaCredentialExtraction.to_string();
    assert!(
        s.contains("NAA") || s.contains("Credential"),
        "NaaCredentialExtraction display should mention 'NAA' or 'Credential', got: {s}"
    );
}

#[test]
fn test_sccm_technique_admin_service_display() {
    let s = SccmTechnique::AdminServiceHarvest.to_string();
    assert!(!s.is_empty());
}

#[test]
fn test_sccm_technique_app_deployment_includes_collection_id() {
    let t = SccmTechnique::ApplicationDeployment {
        collection_id: "SMS00001".to_string(),
    };
    let s = t.to_string();
    assert!(
        s.contains("SMS00001"),
        "ApplicationDeployment display must include the collection ID, got: {s}"
    );
}

// ═══════════════════════════════════════════════════════════
//  SccmAbuseResult struct
// ═══════════════════════════════════════════════════════════

#[test]
fn test_sccm_abuse_result_success_fields() {
    let result = SccmAbuseResult {
        technique: SccmTechnique::ClientPushCoercion,
        success: true,
        affected_targets: vec!["10.0.0.5".to_string(), "10.0.0.6".to_string()],
        credentials: vec![],
        command_output: Some("Install triggered".to_string()),
        notes: vec!["Relay listener required on attacker host".to_string()],
    };

    assert!(result.success);
    assert_eq!(result.affected_targets.len(), 2);
    assert!(result.credentials.is_empty());
    assert_eq!(
        result.command_output.as_deref(),
        Some("Install triggered")
    );
    assert_eq!(result.notes[0], "Relay listener required on attacker host");
}

#[test]
fn test_sccm_abuse_result_failure_fields() {
    let result = SccmAbuseResult {
        technique: SccmTechnique::NaaCredentialExtraction,
        success: false,
        affected_targets: vec![],
        credentials: vec![],
        command_output: None,
        notes: vec!["SCCM site not reachable".to_string()],
    };

    assert!(!result.success);
    assert!(result.affected_targets.is_empty());
    assert!(result.command_output.is_none());
}

#[test]
fn test_sccm_abuse_result_with_credentials() {
    let cred = NaaCredential {
        username: "svc_sccm".to_string(),
        password_blob: "S3cr3tP@ss".to_string(),
        domain: "corp.local".to_string(),
    };
    let result = SccmAbuseResult {
        technique: SccmTechnique::NaaCredentialExtraction,
        success: true,
        affected_targets: vec!["SCCM-SERVER".to_string()],
        credentials: vec![cred],
        command_output: None,
        notes: vec![],
    };

    assert_eq!(result.credentials.len(), 1);
    assert_eq!(result.credentials[0].username, "svc_sccm");
    assert_eq!(result.credentials[0].domain, "corp.local");
}
