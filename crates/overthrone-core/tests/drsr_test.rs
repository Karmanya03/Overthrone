//! Unit tests for the MS-DRSR parser.
//!
//! All tests are offline.  No actual DC connection is needed; the parser
//! returns an error for syntactically invalid input, which is what we test.

use overthrone_core::proto::drsr::parse_get_nc_changes_reply;

// ─────────────────────────────────────────────────────────
//  Empty / undersized input
// ─────────────────────────────────────────────────────────

#[test]
fn test_parse_empty_slice_returns_err() {
    let result = parse_get_nc_changes_reply(&[], &[0u8; 16]);
    assert!(result.is_err(), "Empty slice must return Err");
}

#[test]
fn test_parse_one_byte_returns_err() {
    let result = parse_get_nc_changes_reply(&[0x01], &[0u8; 16]);
    assert!(result.is_err(), "Single-byte slice must return Err");
}

#[test]
fn test_parse_less_than_28_bytes_returns_err() {
    // Parser requires at least 28 bytes (24 PDU header + 4 dwOutVersion)
    let short = vec![0u8; 27];
    let result = parse_get_nc_changes_reply(&short, &[0u8; 16]);
    assert!(result.is_err(), "Slice shorter than 28 bytes must return Err");
}

#[test]
fn test_parse_exactly_28_bytes_no_panic() {
    // 28 bytes passes the initial length check but will still fail deep parsing.
    // We just verify there's no panic.
    let buf = vec![0u8; 28];
    let _ = parse_get_nc_changes_reply(&buf, &[0u8; 16]);
    // test passes if we reach here (no panic)
}

// ─────────────────────────────────────────────────────────
//  Session key edge cases
// ─────────────────────────────────────────────────────────

#[test]
fn test_parse_zero_session_key_no_panic() {
    // An all-zeros session key should not cause a panic even with a minimal stub.
    let buf = vec![0u8; 28];
    let _ = parse_get_nc_changes_reply(&buf, &[0u8; 16]);
}

#[test]
fn test_parse_empty_session_key_no_panic() {
    let buf = vec![0u8; 28];
    let _ = parse_get_nc_changes_reply(&buf, &[]);
}

// ─────────────────────────────────────────────────────────
//  Wrong version values
// ─────────────────────────────────────────────────────────

#[test]
fn test_parse_with_version_99_no_panic() {
    // Build a 32-byte buffer with dwOutVersion = 99 (little-endian at bytes 24..28).
    let mut buf = vec![0u8; 100];
    buf[24] = 99; // out_version = 99 (little-endian)
    // Parser should fall through to v6 parse and fail gracefully, not panic.
    let _ = parse_get_nc_changes_reply(&buf, &[0u8; 16]);
}
