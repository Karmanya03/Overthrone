//! Unit tests for TDS (Tabular Data Stream) message framing and SQL type helpers.
//!
//! Covers message construction, serialisation, round-trip parsing, and the
//! SQL type classification helpers.  All tests are offline.

use overthrone_core::mssql::tds::{
    fixed_type_length, is_fixed_length_type, is_u16_length_type, sql_type_name, sql_types,
    TdsMessage, TdsMessageType,
};

// ═══════════════════════════════════════════════════════════
//  TdsMessage construction
// ═══════════════════════════════════════════════════════════

#[test]
fn test_new_message_has_correct_type_byte() {
    let msg = TdsMessage::new(TdsMessageType::SqlBatch, vec![]);
    assert_eq!(msg.msg_type, TdsMessageType::SqlBatch as u8);
}

#[test]
fn test_new_prelogin_type_byte() {
    let msg = TdsMessage::new(TdsMessageType::Tds7PreLogin, vec![]);
    assert_eq!(msg.msg_type, TdsMessageType::Tds7PreLogin as u8);
}

// ═══════════════════════════════════════════════════════════
//  TdsMessage::to_bytes
// ═══════════════════════════════════════════════════════════

#[test]
fn test_to_bytes_header_size_is_8_bytes_when_empty_payload() {
    let msg = TdsMessage::new(TdsMessageType::SqlBatch, vec![]);
    let bytes = msg.to_bytes();
    // TDS header: type(1)+status(1)+length(2)+spid(2)+packet_id(1)+window(1) = 8 bytes
    assert_eq!(bytes.len(), 8);
}

#[test]
fn test_to_bytes_first_byte_is_msg_type() {
    let msg = TdsMessage::new(TdsMessageType::SqlBatch, b"SELECT 1".to_vec());
    let bytes = msg.to_bytes();
    assert_eq!(bytes[0], TdsMessageType::SqlBatch as u8);
}

#[test]
fn test_to_bytes_length_field_is_big_endian_total_length() {
    let payload = b"SELECT 1 FROM sys.objects".to_vec();
    let msg = TdsMessage::new(TdsMessageType::SqlBatch, payload);
    let bytes = msg.to_bytes();
    let length_field = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    assert_eq!(
        length_field,
        bytes.len(),
        "TDS length field must equal the total serialised length"
    );
}

#[test]
fn test_to_bytes_includes_payload() {
    let payload = b"HELLO".to_vec();
    let msg = TdsMessage::new(TdsMessageType::SqlBatch, payload.clone());
    let bytes = msg.to_bytes();
    // Payload starts at offset 8
    assert_eq!(&bytes[8..], payload.as_slice());
}

// ═══════════════════════════════════════════════════════════
//  TdsMessage::from_bytes
// ═══════════════════════════════════════════════════════════

#[test]
fn test_from_bytes_roundtrip_sql_batch() {
    let payload = b"SELECT TOP 1 name FROM sys.tables".to_vec();
    let original = TdsMessage::new(TdsMessageType::SqlBatch, payload.clone());
    let bytes = original.to_bytes();
    let parsed = TdsMessage::from_bytes(&bytes).expect("round-trip parse must succeed");
    assert_eq!(parsed.msg_type, TdsMessageType::SqlBatch as u8);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn test_from_bytes_roundtrip_empty_payload() {
    let original = TdsMessage::new(TdsMessageType::Tds7PreLogin, vec![]);
    let bytes = original.to_bytes();
    let parsed = TdsMessage::from_bytes(&bytes).expect("empty payload roundtrip must succeed");
    assert_eq!(parsed.payload, Vec::<u8>::new());
}

#[test]
fn test_from_bytes_returns_none_on_truncated_header() {
    // Need at least 8 bytes for the header
    for len in 0..8 {
        let short = vec![0u8; len];
        assert!(
            TdsMessage::from_bytes(&short).is_none(),
            "from_bytes should return None for {len}-byte input"
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  sql_type_name
// ═══════════════════════════════════════════════════════════

#[test]
fn test_sql_type_name_int() {
    assert_eq!(sql_type_name(sql_types::INT), "int");
}

#[test]
fn test_sql_type_name_nvarchar() {
    assert_eq!(sql_type_name(sql_types::NVARCHAR), "nvarchar");
}

#[test]
fn test_sql_type_name_varchar() {
    assert_eq!(sql_type_name(sql_types::VARCHAR), "varchar");
}

#[test]
fn test_sql_type_name_tinyint() {
    assert_eq!(sql_type_name(sql_types::TINYINT), "tinyint");
}

#[test]
fn test_sql_type_name_bigint() {
    assert_eq!(sql_type_name(sql_types::BIGINT), "bigint");
}

#[test]
fn test_sql_type_name_bit() {
    assert_eq!(sql_type_name(sql_types::BIT), "bit");
}

#[test]
fn test_sql_type_name_xml() {
    assert_eq!(sql_type_name(sql_types::XML), "xml");
}

#[test]
fn test_sql_type_name_unknown_returns_unknown() {
    // 0xFF is not a defined TDS type
    assert_eq!(sql_type_name(0xFF), "unknown");
}

// ═══════════════════════════════════════════════════════════
//  Type classification helpers
// ═══════════════════════════════════════════════════════════

#[test]
fn test_is_u16_length_type_nvarchar() {
    assert!(is_u16_length_type(sql_types::NVARCHAR));
}

#[test]
fn test_is_u16_length_type_varchar() {
    assert!(is_u16_length_type(sql_types::VARCHAR));
}

#[test]
fn test_is_u16_length_type_varbinary() {
    assert!(is_u16_length_type(sql_types::VARBINARY));
}

#[test]
fn test_is_u16_length_type_rejects_tinyint() {
    assert!(!is_u16_length_type(sql_types::TINYINT));
}

#[test]
fn test_is_fixed_length_type_tinyint() {
    assert!(is_fixed_length_type(sql_types::TINYINT));
}

#[test]
fn test_is_fixed_length_type_smallint() {
    assert!(is_fixed_length_type(sql_types::SMALLINT));
}

#[test]
fn test_is_fixed_length_type_rejects_nvarchar() {
    assert!(!is_fixed_length_type(sql_types::NVARCHAR));
}

#[test]
fn test_fixed_type_length_tinyint_is_1() {
    assert_eq!(fixed_type_length(sql_types::TINYINT), Some(1));
}

#[test]
fn test_fixed_type_length_bit_is_1() {
    assert_eq!(fixed_type_length(sql_types::BIT), Some(1));
}

#[test]
fn test_fixed_type_length_smallint_is_2() {
    assert_eq!(fixed_type_length(sql_types::SMALLINT), Some(2));
}

#[test]
fn test_fixed_type_length_nvarchar_is_none() {
    assert_eq!(fixed_type_length(sql_types::NVARCHAR), None);
}

#[test]
fn test_fixed_type_length_int_is_none() {
    // INT (0x26 = INTN) is variable-length (nullable int)
    assert_eq!(fixed_type_length(sql_types::INT), None);
}
