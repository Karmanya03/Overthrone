//! Unit tests for NTLM protocol implementation.
//!
//! Tests NTLM message construction, hash parsing, and sentinel detection
//! using RFC-defined known test vectors.  All tests are offline.

use overthrone_core::proto::ntlm::{
    build_authenticate_message, build_negotiate_message, is_empty_lm_hash, is_empty_nt_hash,
    nt_hash, parse_ntlm_hash, parse_secretsdump_line,
};

// ═══════════════════════════════════════════════════════════
//  Negotiate Message (Type 1)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_negotiate_message_starts_with_ntlmssp_signature() {
    let msg = build_negotiate_message("CORP");
    assert_eq!(
        &msg[0..8],
        b"NTLMSSP\x00",
        "NTLM signature must be the 8-byte NTLMSSP\\0 magic"
    );
}

#[test]
fn test_negotiate_message_type_is_1() {
    let msg = build_negotiate_message("CORP");
    let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    assert_eq!(msg_type, 1, "Negotiate message must carry message type 1");
}

#[test]
fn test_negotiate_message_minimum_length() {
    let msg = build_negotiate_message("DOMAIN");
    assert!(
        msg.len() >= 32,
        "Negotiate message must be at least 32 bytes, got {}",
        msg.len()
    );
}

// ═══════════════════════════════════════════════════════════
//  Authenticate Message (Type 3)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_authenticate_message_starts_with_ntlmssp_signature() {
    let key = nt_hash("password");
    let challenge = [0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04u8];
    let msg = build_authenticate_message("CORP", "admin", &key, &challenge, None, None);
    assert_eq!(&msg[0..8], b"NTLMSSP\x00");
}

#[test]
fn test_authenticate_message_type_is_3() {
    let key = nt_hash("password");
    let challenge = [0u8; 8];
    let msg = build_authenticate_message("CORP", "admin", &key, &challenge, None, None);
    let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    assert_eq!(msg_type, 3, "Authenticate message must carry message type 3");
}

#[test]
fn test_authenticate_message_min_length() {
    let key = nt_hash("password");
    let challenge = [0u8; 8];
    let msg = build_authenticate_message("CORP", "admin", &key, &challenge, None, None);
    // Header (64 bytes) + at minimum some payload bytes
    assert!(
        msg.len() >= 64,
        "Authenticate message must be at least 64 bytes, got {}",
        msg.len()
    );
}

// ═══════════════════════════════════════════════════════════
//  parse_secretsdump_line
// ═══════════════════════════════════════════════════════════

#[test]
fn test_parse_secretsdump_administrator_known_hash() {
    // "password" NT hash = 8846f7eaee8fb117ad06bdd830b7586c
    let (user, rid, hash) = parse_secretsdump_line(
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
    )
    .unwrap();
    assert_eq!(user, "Administrator");
    assert_eq!(rid, 500);
    assert_eq!(
        hex::encode(&hash),
        "8846f7eaee8fb117ad06bdd830b7586c",
        "NT hash extracted from secretsdump line must match known vector"
    );
}

#[test]
fn test_parse_secretsdump_empty_password_hash() {
    // empty-password NT hash = 31d6cfe0d16ae931b73c59d7e0c089c0
    let (user, rid, hash) = parse_secretsdump_line(
        "svc_deploy:1105:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    )
    .unwrap();
    assert_eq!(user, "svc_deploy");
    assert_eq!(rid, 1105);
    assert_eq!(
        hex::encode(&hash),
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "Empty-password NT hash must be the known constant"
    );
}

#[test]
fn test_parse_secretsdump_extracts_nt_not_lm() {
    // LM hash occupies field 2; NT hash occupies field 3.
    // Result must be the NT hash (field 3), not the LM placeholder.
    let (_, _, hash) = parse_secretsdump_line(
        "user:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    )
    .unwrap();
    assert_ne!(
        hex::encode(&hash),
        "aad3b435b51404eeaad3b435b51404ee",
        "Result should be NT hash, not LM placeholder"
    );
    assert_eq!(hex::encode(&hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
}

#[test]
fn test_parse_secretsdump_too_few_fields_returns_err() {
    assert!(parse_secretsdump_line("only:two").is_err());
    assert!(parse_secretsdump_line("").is_err());
}

#[test]
fn test_parse_secretsdump_invalid_hash_hex_returns_err() {
    // NT field contains non-hex chars
    assert!(parse_secretsdump_line("user:500:lmhash:NOTAHEX32CHARSHEXSTRING!!!!:::").is_err());
}

// ═══════════════════════════════════════════════════════════
//  parse_ntlm_hash
// ═══════════════════════════════════════════════════════════

#[test]
fn test_parse_ntlm_hash_colon_separated() {
    // Format: LM:NT — must return NT part only
    let h = parse_ntlm_hash(
        "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
    )
    .unwrap();
    assert_eq!(
        hex::encode(&h),
        "8846f7eaee8fb117ad06bdd830b7586c",
        "Colon-separated hash must return the NT (second) component"
    );
}

#[test]
fn test_parse_ntlm_hash_bare_32_hex_chars() {
    let h = parse_ntlm_hash("8846f7eaee8fb117ad06bdd830b7586c").unwrap();
    assert_eq!(h.len(), 16, "32 hex chars decode to 16 bytes");
}

#[test]
fn test_parse_ntlm_hash_empty_hash_constant() {
    let h = parse_ntlm_hash("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
    assert_eq!(h.len(), 16);
}

#[test]
fn test_parse_ntlm_hash_invalid_returns_err() {
    assert!(parse_ntlm_hash("not-a-hash").is_err());
    assert!(parse_ntlm_hash("tooshort").is_err());
    // Too long (33 hex chars) without colon
    assert!(parse_ntlm_hash("8846f7eaee8fb117ad06bdd830b7586c0").is_err());
}

// ═══════════════════════════════════════════════════════════
//  is_empty_nt_hash / is_empty_lm_hash
// ═══════════════════════════════════════════════════════════

#[test]
fn test_is_empty_nt_hash_detects_blank_password() {
    // NT hash of "" = 31d6cfe0d16ae931b73c59d7e0c089c0
    let empty = hex::decode("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
    assert!(
        is_empty_nt_hash(&empty),
        "is_empty_nt_hash must recognise the know blank-password constant"
    );
}

#[test]
fn test_is_empty_nt_hash_rejects_real_password() {
    let nonempty = nt_hash("password");
    assert!(
        !is_empty_nt_hash(&nonempty),
        "NT hash of 'password' must NOT be considered empty"
    );
}

#[test]
fn test_is_empty_lm_hash_detects_disabled_sentinel() {
    // LM disabled sentinel = aad3b435b51404eeaad3b435b51404ee
    let empty_lm = hex::decode("aad3b435b51404eeaad3b435b51404ee").unwrap();
    assert!(is_empty_lm_hash(&empty_lm));
}

#[test]
fn test_is_empty_lm_hash_rejects_non_sentinel() {
    let non_sentinel = hex::decode("8846f7eaee8fb117ad06bdd830b7586c").unwrap();
    assert!(!is_empty_lm_hash(&non_sentinel));
}
