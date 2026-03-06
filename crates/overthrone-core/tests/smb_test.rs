//! Unit tests for the SMB protocol data structures.
//!
//! All tests are offline — only struct construction and field access are tested.
//! No live SMB connections are made.

use overthrone_core::proto::smb::{AdminCheckResult, RemoteFileInfo, ShareAccessResult};

// ═══════════════════════════════════════════════════════════
//  RemoteFileInfo
// ═══════════════════════════════════════════════════════════

#[test]
fn test_remote_file_info_file_construction() {
    let info = RemoteFileInfo {
        name: "passwords.txt".to_string(),
        path: r"\\server\share\passwords.txt".to_string(),
        is_directory: false,
        size: 1024,
    };
    assert_eq!(info.name, "passwords.txt");
    assert_eq!(info.path, r"\\server\share\passwords.txt");
    assert!(!info.is_directory);
    assert_eq!(info.size, 1024);
}

#[test]
fn test_remote_file_info_directory_construction() {
    let info = RemoteFileInfo {
        name: "Users".to_string(),
        path: r"\\dc01\c$\Users".to_string(),
        is_directory: true,
        size: 0,
    };
    assert!(info.is_directory);
    assert_eq!(info.name, "Users");
    assert_eq!(info.size, 0);
}

#[test]
fn test_remote_file_info_large_size() {
    let info = RemoteFileInfo {
        name: "ntds.dit".to_string(),
        path: r"\\dc01\c$\Windows\NTDS\ntds.dit".to_string(),
        is_directory: false,
        size: u64::MAX,
    };
    assert_eq!(info.size, u64::MAX);
    assert!(!info.is_directory);
}

#[test]
fn test_remote_file_info_empty_name() {
    let info = RemoteFileInfo {
        name: String::new(),
        path: String::new(),
        is_directory: false,
        size: 0,
    };
    assert!(info.name.is_empty());
    assert!(info.path.is_empty());
}

// ═══════════════════════════════════════════════════════════
//  ShareAccessResult
// ═══════════════════════════════════════════════════════════

#[test]
fn test_share_access_readable_only() {
    let result = ShareAccessResult {
        share_name: "SYSVOL".to_string(),
        readable: true,
        writable: false,
        is_admin_share: false,
    };
    assert_eq!(result.share_name, "SYSVOL");
    assert!(result.readable);
    assert!(!result.writable);
    assert!(!result.is_admin_share);
}

#[test]
fn test_share_access_read_write() {
    let result = ShareAccessResult {
        share_name: "share".to_string(),
        readable: true,
        writable: true,
        is_admin_share: false,
    };
    assert!(result.readable);
    assert!(result.writable);
}

#[test]
fn test_share_access_admin_share() {
    let result = ShareAccessResult {
        share_name: "C$".to_string(),
        readable: true,
        writable: true,
        is_admin_share: true,
    };
    assert!(result.is_admin_share);
    assert_eq!(result.share_name, "C$");
}

#[test]
fn test_share_access_no_access() {
    let result = ShareAccessResult {
        share_name: "ADMIN$".to_string(),
        readable: false,
        writable: false,
        is_admin_share: true,
    };
    assert!(!result.readable);
    assert!(!result.writable);
    assert!(result.is_admin_share);
}

#[test]
fn test_share_access_ipc_share() {
    let result = ShareAccessResult {
        share_name: "IPC$".to_string(),
        readable: true,
        writable: false,
        is_admin_share: false,
    };
    assert_eq!(result.share_name, "IPC$");
    assert!(!result.is_admin_share);
}

// ═══════════════════════════════════════════════════════════
//  AdminCheckResult
// ═══════════════════════════════════════════════════════════

#[test]
fn test_admin_check_result_is_admin_with_shares() {
    let result = AdminCheckResult {
        target: "192.168.1.10".to_string(),
        has_admin: true,
        accessible_shares: vec!["C$".to_string(), "ADMIN$".to_string()],
    };
    assert_eq!(result.target, "192.168.1.10");
    assert!(result.has_admin);
    assert_eq!(result.accessible_shares.len(), 2);
    assert!(result.accessible_shares.contains(&"C$".to_string()));
    assert!(result.accessible_shares.contains(&"ADMIN$".to_string()));
}

#[test]
fn test_admin_check_result_not_admin_no_shares() {
    let result = AdminCheckResult {
        target: "10.0.0.5".to_string(),
        has_admin: false,
        accessible_shares: vec![],
    };
    assert_eq!(result.target, "10.0.0.5");
    assert!(!result.has_admin);
    assert!(result.accessible_shares.is_empty());
}

#[test]
fn test_admin_check_result_target_is_hostname() {
    let result = AdminCheckResult {
        target: "WORKSTATION01".to_string(),
        has_admin: true,
        accessible_shares: vec!["C$".to_string()],
    };
    assert_eq!(result.target, "WORKSTATION01");
    assert!(result.has_admin);
}

#[test]
fn test_admin_check_result_shares_contains_specific_share() {
    let shares = vec![
        "SYSVOL".to_string(),
        "NETLOGON".to_string(),
        "C$".to_string(),
    ];
    let result = AdminCheckResult {
        target: "dc01.corp.local".to_string(),
        has_admin: true,
        accessible_shares: shares,
    };
    assert!(result.accessible_shares.contains(&"SYSVOL".to_string()));
    assert!(result.accessible_shares.contains(&"NETLOGON".to_string()));
    assert_eq!(result.accessible_shares.len(), 3);
}

#[test]
fn test_admin_check_result_clone() {
    let original = AdminCheckResult {
        target: "10.0.0.1".to_string(),
        has_admin: true,
        accessible_shares: vec!["C$".to_string()],
    };
    let cloned = original.clone();
    assert_eq!(original.target, cloned.target);
    assert_eq!(original.has_admin, cloned.has_admin);
    assert_eq!(original.accessible_shares, cloned.accessible_shares);
}
