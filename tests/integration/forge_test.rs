//! Integration tests for overthrone-forge — Kerberos ticket operations.
//!
//! Tests ticket structures, SPN parsing, and crypto primitives offline.

// ═══════════════════════════════════════════════════════════
//  Kerberos Ticket Type Validation
// ═══════════════════════════════════════════════════════════

#[test]
fn test_kerberos_ticket_creation() {
    let ticket = overthrone_core::proto::smb::KerberosTicket::new(
        vec![0x30, 0x82, 0x01, 0x00], // dummy ASN.1
        vec![0u8; 32],                // dummy session key
        18,                           // AES256
        true,                         // is TGT
        None,                         // no SPN for TGT
    );
    assert!(ticket.is_tgt);
    assert!(ticket.spn.is_none());
    assert_eq!(ticket.session_key.len(), 32);
}

#[test]
fn test_kerberos_ticket_tgs() {
    let ticket = overthrone_core::proto::smb::KerberosTicket::new(
        vec![0x30, 0x82, 0x02, 0x00],
        vec![0u8; 16],
        23,
        false,
        Some("cifs/DC01.yourorg.local".to_string()),
    );
    assert!(!ticket.is_tgt);
    assert_eq!(ticket.spn.as_deref(), Some("cifs/DC01.yourorg.local"));
}

// ═══════════════════════════════════════════════════════════
//  SPN Parsing
// ═══════════════════════════════════════════════════════════

#[test]
fn test_spn_parsing() {
    let spns = [
        (
            "MSSQLSvc/SQL01.yourorg.local:1433",
            "MSSQLSvc",
            "SQL01.yourorg.local",
            Some(1433u16),
        ),
        (
            "HTTP/web01.yourorg.local",
            "HTTP",
            "web01.yourorg.local",
            None,
        ),
        (
            "cifs/DC01.yourorg.local",
            "cifs",
            "DC01.yourorg.local",
            None,
        ),
        (
            "ldap/DC01.yourorg.local:636",
            "ldap",
            "DC01.yourorg.local",
            Some(636),
        ),
    ];

    for (spn, expected_svc, expected_host, expected_port) in &spns {
        let parts: Vec<&str> = spn.splitn(2, '/').collect();
        assert_eq!(
            parts.len(),
            2,
            "SPN should have service/host format: {}",
            spn
        );
        assert_eq!(parts[0], *expected_svc);

        let host_parts: Vec<&str> = parts[1].splitn(2, ':').collect();
        assert_eq!(host_parts[0], *expected_host);

        let port = host_parts.get(1).and_then(|p| p.parse::<u16>().ok());
        assert_eq!(port, *expected_port, "Port mismatch for SPN: {}", spn);
    }
}

// ═══════════════════════════════════════════════════════════
//  GPP Crypto (AES-256-CBC with known MS key)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_gpp_decrypt_function_exists_and_works() {
    // The well-known GPP key should be baked into the binary
    let test_cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw";
    let result = overthrone_core::crypto::gpp::decrypt_gpp_password(test_cpassword);
    assert!(
        result.is_ok(),
        "GPP decryption should succeed for valid input"
    );
}

#[test]
fn test_gpp_decrypt_wrong_padding_handled() {
    // GPP base64 uses non-standard padding; test with an odd-length string
    let odd_cpassword = "abc"; // Too short to be valid AES block
    let result = overthrone_core::crypto::gpp::decrypt_gpp_password(odd_cpassword);
    // Should fail gracefully, not panic
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════
//  NTLM Hash Format Validation
// ═══════════════════════════════════════════════════════════

#[test]
fn test_ntlm_hash_format() {
    // NTLM hashes are 32-character hex strings (16 bytes = MD4 output)
    let sample_hashes = [
        "aad3b435b51404eeaad3b435b51404ee", // LM empty
        "31d6cfe0d16ae931b73c59d7e0c089c0", // NT empty
        "a4f49c406510bdcab6824ee7c30fd852", // random
    ];

    for hash in &sample_hashes {
        assert_eq!(hash.len(), 32, "NTLM hash should be 32 hex chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should be valid hex: {}",
            hash
        );
    }
}
