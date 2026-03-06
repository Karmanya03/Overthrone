//! Unit tests for Kerberos protocol utilities and constants.
//!
//! Tests offline-verifiable behaviour only: username/realm normalisation,
//! encryption-type constants, etype ID round-trips, and error-code mapping.
//! No KDC connection is required.

use overthrone_core::proto::kerberos::{
    ETYPE_AES128_CTS, ETYPE_AES256_CTS, ETYPE_RC4_HMAC, EncType, krb_error_to_string,
    normalize_realm, normalize_username,
};

// ═══════════════════════════════════════════════════════════
//  normalize_username
// ═══════════════════════════════════════════════════════════

#[test]
fn test_normalize_username_plain_unchanged() {
    assert_eq!(normalize_username("alice"), "alice");
}

#[test]
fn test_normalize_username_strips_downlevel_domain_prefix() {
    // "CORP\alice" → "alice"
    assert_eq!(normalize_username("CORP\\alice"), "alice");
}

#[test]
fn test_normalize_username_strips_upn_domain_suffix() {
    // "alice@corp.local" → "alice"
    assert_eq!(normalize_username("alice@corp.local"), "alice");
}

#[test]
fn test_normalize_username_prefers_downlevel_over_upn() {
    // If both separators: take the backslash path first
    assert_eq!(
        normalize_username("CORP\\alice@corp.local"),
        "alice@corp.local"
    );
}

// ═══════════════════════════════════════════════════════════
//  normalize_realm
// ═══════════════════════════════════════════════════════════

#[test]
fn test_normalize_realm_uppercases_lowercase() {
    assert_eq!(normalize_realm("corp.local"), "CORP.LOCAL");
}

#[test]
fn test_normalize_realm_already_uppercase_unchanged() {
    assert_eq!(normalize_realm("CORP.LOCAL"), "CORP.LOCAL");
}

#[test]
fn test_normalize_realm_mixed_case() {
    assert_eq!(normalize_realm("Corp.Local"), "CORP.LOCAL");
}

// ═══════════════════════════════════════════════════════════
//  Encryption-type constants (RFC 4120 / MS-KILE)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_etype_rc4_hmac_is_23() {
    assert_eq!(ETYPE_RC4_HMAC, 23, "RC4-HMAC etype must be 23 per RFC 4757");
}

#[test]
fn test_etype_aes128_is_17() {
    assert_eq!(
        ETYPE_AES128_CTS, 17,
        "AES128-CTS etype must be 17 per RFC 3962"
    );
}

#[test]
fn test_etype_aes256_is_18() {
    assert_eq!(
        ETYPE_AES256_CTS, 18,
        "AES256-CTS etype must be 18 per RFC 3962"
    );
}

// ═══════════════════════════════════════════════════════════
//  EncType::to_etype_id / from_etype_id
// ═══════════════════════════════════════════════════════════

#[test]
fn test_enctype_to_etype_id_rc4() {
    assert_eq!(EncType::Rc4Hmac.to_etype_id(), ETYPE_RC4_HMAC);
}

#[test]
fn test_enctype_to_etype_id_aes128() {
    assert_eq!(EncType::Aes128CtsHmacSha1.to_etype_id(), ETYPE_AES128_CTS);
}

#[test]
fn test_enctype_to_etype_id_aes256() {
    assert_eq!(EncType::Aes256CtsHmacSha1.to_etype_id(), ETYPE_AES256_CTS);
}

#[test]
fn test_enctype_from_etype_id_rc4() {
    assert_eq!(EncType::from_etype_id(23), Some(EncType::Rc4Hmac));
}

#[test]
fn test_enctype_from_etype_id_aes128() {
    assert_eq!(EncType::from_etype_id(17), Some(EncType::Aes128CtsHmacSha1));
}

#[test]
fn test_enctype_from_etype_id_aes256() {
    assert_eq!(EncType::from_etype_id(18), Some(EncType::Aes256CtsHmacSha1));
}

#[test]
fn test_enctype_from_etype_id_unknown_returns_none() {
    assert_eq!(EncType::from_etype_id(99), None);
    assert_eq!(EncType::from_etype_id(0), None);
    assert_eq!(EncType::from_etype_id(-1), None);
}

#[test]
fn test_enctype_to_from_roundtrip() {
    for etype in [
        EncType::Rc4Hmac,
        EncType::Aes128CtsHmacSha1,
        EncType::Aes256CtsHmacSha1,
    ] {
        let id = etype.to_etype_id();
        let recovered = EncType::from_etype_id(id);
        assert_eq!(
            recovered,
            Some(etype),
            "Round-trip failed for etype id {id}"
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  krb_error_to_string
// ═══════════════════════════════════════════════════════════

#[test]
fn test_krb_err_string_is_non_empty() {
    // Every defined code should produce a non-empty string
    for code in [0, 6, 7, 12, 14, 17, 18, 24, 25, 31, 37, 41, 68] {
        let s = krb_error_to_string(code);
        assert!(
            !s.is_empty(),
            "krb_error_to_string({code}) must not be empty"
        );
    }
}

#[test]
fn test_krb_err_6_mentions_principal() {
    // Code 6 = KDC_ERR_C_PRINCIPAL_UNKNOWN
    let s = krb_error_to_string(6);
    let s_lower = s.to_lowercase();
    assert!(
        s_lower.contains("principal") || s_lower.contains("unknown"),
        "Error 6 should mention PRINCIPAL or UNKNOWN, got: {s}"
    );
}

#[test]
fn test_krb_err_unknown_code_does_not_panic() {
    // Should return a fallback string, not panic
    let s = krb_error_to_string(9999);
    assert!(!s.is_empty());
}
