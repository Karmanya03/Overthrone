//! TDS (Tabular Data Stream) Protocol Implementation
//!
//! Low-level TDS message building and parsing for SQL Server communication.

use serde::{Deserialize, Serialize};

/// TDS message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TdsMessageType {
    /// SQL Batch (0x01)
    SqlBatch = 0x01,
    /// Pre-TDS7 Login (old)
    PreTds7Login = 0x02,
    /// RPC (Remote Procedure Call)
    Rpc = 0x03,
    /// Tabular Result
    TabularResult = 0x04,
    /// Attention signal
    Attention = 0x06,
    /// Bulk Load Data
    BulkLoad = 0x07,
    /// Federated Authentication Token
    FedAuthToken = 0x08,
    /// Transaction Manager Request
    TransMgrReq = 0x0E,
    /// TDS7 Pre-Login
    Tds7PreLogin = 0x12,
    /// TDS7 Login
    Tds7Login = 0x10,
}

/// TDS token types (in responses)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdsTokenType {
    /// Column metadata (0x81)
    ColMetadata = 0x81,
    /// Tabular result (0x04)
    TabularResult = 0x04,
    /// Row data (0xD1)
    Row = 0xD1,
    /// NBC (Null-bit compressed) Row (0xD2)
    NbcRow = 0xD2,
    /// Return status (0x79)
    ReturnStatus = 0x79,
    /// Done (0xFD)
    Done = 0xFD,
    /// Done in procedure / Return value (0xAC)
    /// Note: DoneInProc and ReturnValue share the same token value
    DoneInProc = 0xAC,
    /// Done procedure (0xFE)
    DoneProc = 0xFE,
    /// Environment change (0xE3)
    EnvChange = 0xE3,
    /// Login acknowledgement (0xAD)
    LoginAck = 0xAD,
    /// Info message (0xAB)
    Info = 0xAB,
    /// Error message (0xAA)
    Error = 0xAA,
    /// Session state (0xAE)
    SessionState = 0xAE,
    /// Order by (0xA9)
    Order = 0xA9,
}

/// TDS column data type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdsColumnData {
    /// Column name
    pub name: String,
    /// Data type ID
    pub type_id: u8,
    /// Data type name
    pub type_name: String,
    /// Maximum length (if applicable)
    pub max_length: Option<u32>,
    /// Precision (for numeric types)
    pub precision: Option<u8>,
    /// Scale (for numeric types)
    pub scale: Option<u8>,
    /// Is nullable
    pub nullable: bool,
    /// Is identity column
    pub is_identity: bool,
}

/// TDS message structure
#[derive(Debug, Clone)]
pub struct TdsMessage {
    /// Message type
    pub msg_type: u8,
    /// Status byte
    pub status: u8,
    /// Packet ID (incrementing)
    pub packet_id: u8,
    /// SPID (session process ID)
    pub spid: u16,
    /// Payload data
    pub payload: Vec<u8>,
}

impl TdsMessage {
    /// Create a new TDS message
    pub fn new(msg_type: TdsMessageType, payload: Vec<u8>) -> Self {
        Self {
            msg_type: msg_type as u8,
            status: 0x01, // EOM (End of Message)
            packet_id: 0,
            spid: 0,
            payload,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = 8 + self.payload.len();
        let mut buf = Vec::with_capacity(total_len);

        buf.push(self.msg_type);
        buf.push(self.status);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push((self.spid >> 8) as u8);
        buf.push((self.spid & 0xFF) as u8);
        buf.push(self.packet_id);
        buf.push(0x00); // Window
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let msg_type = data[0];
        let status = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let spid = u16::from_be_bytes([data[4], data[5]]);
        let packet_id = data[6];

        if data.len() < length {
            return None;
        }

        Some(Self {
            msg_type,
            status,
            packet_id,
            spid,
            payload: data[8..length].to_vec(),
        })
    }
}

/// SQL Server data type constants
pub mod sql_types {
    /// SQL_NULL_TYPE
    pub const SQL_NULL: u8 = 0x1F;
    /// IMAGE
    pub const IMAGE: u8 = 0x22;
    /// TEXT
    pub const TEXT: u8 = 0x24;
    /// INT (INTN - nullable integer)
    pub const INT: u8 = 0x26;
    /// DATETIME2
    pub const DATETIME2: u8 = 0x27;
    /// DATE
    pub const DATE: u8 = 0x28;
    /// DATETIMEOFFSET
    pub const DATETIMEOFFSET: u8 = 0x29;
    /// TIME
    pub const TIME: u8 = 0x2A;
    /// INTN (fixed int, tinyint-sized)
    pub const INTN: u8 = 0x30;
    /// BIT
    pub const BIT: u8 = 0x32;
    /// SMALLINT
    pub const SMALLINT: u8 = 0x34;
    /// TINYINT
    pub const TINYINT: u8 = 0x38;
    /// SMALLDATETIME
    pub const SMALLDATETIME: u8 = 0x3A;
    /// FLOAT
    pub const FLOAT: u8 = 0x3C;
    /// REAL
    pub const REAL: u8 = 0x3E;
    /// MONEY
    pub const MONEY: u8 = 0x3C;
    /// UNIQUEIDENTIFIER
    pub const UNIQUEIDENTIFIER: u8 = 0x68;
    /// INTN_2 (nullable integer variant)
    pub const INTN_2: u8 = 0x6A;
    /// DECIMAL
    pub const DECIMAL: u8 = 0x6C;
    /// NUMERIC
    pub const NUMERIC: u8 = 0x6E;
    /// BIGINT (BIGINTN)
    pub const BIGINT: u8 = 0x7F;
    /// SMALLMONEY
    pub const SMALLMONEY: u8 = 0x7A;
    /// CHAR
    pub const CHAR: u8 = 0xA1;
    /// VARBINARY
    pub const VARBINARY: u8 = 0xA5;
    /// BINARY
    pub const BINARY: u8 = 0xAD;
    /// VARCHAR
    pub const VARCHAR: u8 = 0xA7;
    /// NVARCHAR
    pub const NVARCHAR: u8 = 0xE7;
    /// NCHAR
    pub const NCHAR: u8 = 0xEF;
    /// NTEXT
    pub const NTEXT: u8 = 0x63;
    /// XML
    pub const XML: u8 = 0xF1;
    /// SQL_VARIANT
    pub const SQL_VARIANT: u8 = 0x98;
}

/// Get the name for a SQL type ID
pub fn sql_type_name(type_id: u8) -> &'static str {
    use sql_types::*;
    match type_id {
        SQL_NULL => "null",
        INT => "int",
        INTN => "intn",
        INTN_2 => "intn",
        BIT => "bit",
        SMALLINT => "smallint",
        TINYINT => "tinyint",
        SMALLDATETIME => "smalldatetime",
        BIGINT => "bigint",
        FLOAT => "float",
        REAL => "real",
        UNIQUEIDENTIFIER => "uniqueidentifier",
        DECIMAL => "decimal",
        NUMERIC => "numeric",
        SMALLMONEY => "smallmoney",
        VARBINARY => "varbinary",
        BINARY => "binary",
        VARCHAR => "varchar",
        CHAR => "char",
        NVARCHAR => "nvarchar",
        NCHAR => "nchar",
        TEXT => "text",
        NTEXT => "ntext",
        IMAGE => "image",
        XML => "xml",
        DATETIME2 => "datetime2",
        DATE => "date",
        TIME => "time",
        DATETIMEOFFSET => "datetimeoffset",
        SQL_VARIANT => "sql_variant",
        _ => "unknown",
    }
}

/// Check if a type uses variable-length u16 prefix
pub fn is_u16_length_type(type_id: u8) -> bool {
    use sql_types::*;
    matches!(
        type_id,
        NVARCHAR | NCHAR | VARCHAR | CHAR | VARBINARY | BINARY
    )
}

/// Check if a type is a fixed-length type
pub fn is_fixed_length_type(type_id: u8) -> bool {
    use sql_types::*;
    matches!(type_id, TINYINT | SMALLINT | BIT | SMALLDATETIME)
}

/// Get fixed length for fixed-length types
pub fn fixed_type_length(type_id: u8) -> Option<usize> {
    use sql_types::*;
    match type_id {
        TINYINT | BIT => Some(1),
        SMALLINT => Some(2),
        SMALLDATETIME => Some(4),
        _ => None,
    }
}

/// Environment change types
pub mod env_change_types {
    pub const DATABASE: u8 = 1;
    pub const LANGUAGE: u8 = 2;
    pub const PACKET_SIZE: u8 = 3;
    pub const SORT_ORDER: u8 = 4;
    pub const UNICODE_SORT_ORDER: u8 = 5;
    pub const LCID: u8 = 6;
    pub const COLLATION: u8 = 7;
    pub const BEGIN_TXN: u8 = 8;
    pub const COMMIT_TXN: u8 = 9;
    pub const ROLLBACK_TXN: u8 = 10;
    pub const ENLIST_DTC: u8 = 11;
    pub const DEFECT_DTC: u8 = 12;
    pub const REALIGNED_DTC: u8 = 13;
    pub const PROMOTE_DTC: u8 = 14;
    pub const TXN_ENDED: u8 = 15;
    pub const RESET_COMPLETE: u8 = 16;
    pub const USER_INFO: u8 = 17;
    pub const SST_TXN_STATE: u8 = 18;
    pub const SST_TXN_ENDED: u8 = 19;
    pub const SST_TXN_RECOVERY_ENDED: u8 = 20;
    pub const ROUTING_CHANGE: u8 = 21;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tds_message_roundtrip() {
        let msg = TdsMessage::new(TdsMessageType::SqlBatch, vec![0x01, 0x02, 0x03]);
        let bytes = msg.to_bytes();
        let parsed = TdsMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.msg_type, 0x01);
        assert_eq!(parsed.payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_sql_type_names() {
        assert_eq!(sql_type_name(sql_types::INT), "int");
        assert_eq!(sql_type_name(sql_types::NVARCHAR), "nvarchar");
        assert_eq!(sql_type_name(sql_types::DATETIME2), "datetime2");
    }

    #[test]
    fn test_u16_length_types() {
        assert!(is_u16_length_type(sql_types::NVARCHAR));
        assert!(is_u16_length_type(sql_types::VARCHAR));
        assert!(!is_u16_length_type(sql_types::TINYINT));
    }

    #[test]
    fn test_fixed_length_types() {
        assert_eq!(fixed_type_length(sql_types::TINYINT), Some(1));
        assert_eq!(fixed_type_length(sql_types::SMALLINT), Some(2));
        assert_eq!(fixed_type_length(sql_types::NVARCHAR), None);
    }
}
