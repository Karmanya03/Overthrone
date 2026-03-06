//! Integration tests for the plugin system (types, manifest, registry).
//!
//! These tests validate offline functionality: struct creation,
//! serialization, type variants.

use overthrone_core::plugin::{
    PluginCapability, PluginCommand, PluginManifest, PluginRegistry, PluginType,
};

// ═══════════════════════════════════════════════════════════
//  PluginManifest
// ═══════════════════════════════════════════════════════════

#[test]
fn manifest_creation_and_fields() {
    let manifest = PluginManifest {
        id: "com.test.sample".to_string(),
        name: "test-plugin".to_string(),
        version: "1.0.0".to_string(),
        author: "TestAuthor".to_string(),
        description: "A test plugin".to_string(),
        min_overthrone_version: Some("0.1.0".to_string()),
        plugin_type: PluginType::Wasm,
        capabilities: vec![PluginCapability::Execution],
        commands: vec![],
        needs_network: false,
        needs_admin: false,
    };
    assert_eq!(manifest.id, "com.test.sample");
    assert_eq!(manifest.name, "test-plugin");
    assert_eq!(manifest.version, "1.0.0");
    assert_eq!(manifest.author, "TestAuthor");
    assert!(matches!(manifest.plugin_type, PluginType::Wasm));
    assert_eq!(manifest.capabilities.len(), 1);
}

#[test]
fn manifest_serialization_roundtrip() {
    let manifest = PluginManifest {
        id: "com.test.roundtrip".to_string(),
        name: "roundtrip-plugin".to_string(),
        version: "2.0.0".to_string(),
        author: "Author".to_string(),
        description: "Roundtrip test".to_string(),
        min_overthrone_version: None,
        plugin_type: PluginType::Native,
        capabilities: vec![PluginCapability::Execution, PluginCapability::Attack],
        commands: vec![],
        needs_network: true,
        needs_admin: false,
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, "com.test.roundtrip");
    assert_eq!(deserialized.name, "roundtrip-plugin");
    assert_eq!(deserialized.version, "2.0.0");
    assert!(matches!(deserialized.plugin_type, PluginType::Native));
    assert_eq!(deserialized.capabilities.len(), 2);
    assert!(deserialized.needs_network);
    assert!(!deserialized.needs_admin);
}

// ═══════════════════════════════════════════════════════════
//  PluginRegistry
// ═══════════════════════════════════════════════════════════

#[test]
fn registry_creation_empty() {
    let registry = PluginRegistry::new();
    assert_eq!(registry.list().len(), 0);
    assert_eq!(registry.commands().len(), 0);
}

// ═══════════════════════════════════════════════════════════
//  PluginType Enum
// ═══════════════════════════════════════════════════════════

#[test]
fn plugin_type_variants() {
    let wasm = PluginType::Wasm;
    let native = PluginType::Native;
    let builtin = PluginType::Builtin;
    let script = PluginType::Script;

    assert!(matches!(wasm, PluginType::Wasm));
    assert!(matches!(native, PluginType::Native));
    assert!(matches!(builtin, PluginType::Builtin));
    assert!(matches!(script, PluginType::Script));

    // Ensure they are distinct
    assert_ne!(wasm, native);
    assert_ne!(native, builtin);
}

// ═══════════════════════════════════════════════════════════
//  PluginCapability Enum
// ═══════════════════════════════════════════════════════════

#[test]
fn plugin_capability_variants_exist() {
    let caps = [
        PluginCapability::Execution,
        PluginCapability::Enumeration,
        PluginCapability::Attack,
        PluginCapability::GraphMutation,
        PluginCapability::OutputFormat,
        PluginCapability::EventHandler,
        PluginCapability::C2Integration,
    ];
    assert_eq!(caps.len(), 7);
}

#[test]
fn plugin_capability_equality() {
    assert_eq!(PluginCapability::Attack, PluginCapability::Attack);
    assert_ne!(PluginCapability::Attack, PluginCapability::Execution);
}

// ═══════════════════════════════════════════════════════════
//  PluginCommand
// ═══════════════════════════════════════════════════════════

#[test]
fn plugin_command_creation() {
    let cmd = PluginCommand {
        name: "custom-kerberoast".to_string(),
        description: "Custom Kerberoast implementation".to_string(),
        usage: "custom-kerberoast <target>".to_string(),
        args: vec![],
    };
    assert_eq!(cmd.name, "custom-kerberoast");
    assert!(cmd.args.is_empty());
}

#[test]
fn plugin_command_serialization() {
    let cmd = PluginCommand {
        name: "recon-scan".to_string(),
        description: "Network reconnaissance".to_string(),
        usage: "recon-scan --target <ip>".to_string(),
        args: vec![],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("recon-scan"));
    let rt: PluginCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.name, cmd.name);
}
