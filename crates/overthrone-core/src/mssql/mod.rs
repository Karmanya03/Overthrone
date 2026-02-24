//! MSSQL (Microsoft SQL Server) protocol client.
//!
//! Implements the TDS (Tabular Data Stream) protocol for direct
//! communication with Microsoft SQL Server instances.
//!
//! Features:
//! - TDS 7.4 protocol (SQL Server 2012+)
//! - NTLM and SQL authentication
//! - Query execution with result parsing
//! - xp_cmdshell enable/execute
//! - Linked server enumeration and execution

pub mod tds;
pub mod auth;

use crate::error::{OverthroneError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};

// Re-export main types
pub use tds::{TdsMessage, TdsMessageType, TdsColumnData};
pub use auth::MssqlAuth;

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// MSSQL connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlConfig {
    /// Server hostname or IP
    pub server: String,
    /// TCP port (default 1433)
    pub port: u16,
    /// Database name (default "master")
    pub database: String,
    /// Username for SQL auth (if None, uses Windows/NTLM)
    pub username: Option<String>,
    /// Password for SQL auth
    pub password: Option<String>,
    /// Domain for NTLM auth
    pub domain: Option<String>,
    /// Trust server certificate
    pub trust_cert: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Enable encryption
    pub encrypt: bool,
}

impl Default for MssqlConfig {
    fn default() -> Self {
        Self {
            server: "localhost".to_string(),
            port: 1433,
            database: "master".to_string(),
            username: None,
            password: None,
            domain: None,
            trust_cert: true,
            timeout_secs: 30,
            encrypt: false,
        }
    }
}

impl MssqlConfig {
    /// Create config for a server with default settings
    pub fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
            ..Default::default()
        }
    }

    /// Set credentials for SQL authentication
    pub fn with_sql_auth(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    /// Set credentials for Windows/NTLM authentication
    pub fn with_ntlm_auth(mut self, domain: &str, username: &str, password: &str) -> Self {
        self.domain = Some(domain.to_string());
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    /// Set the target database
    pub fn with_database(mut self, database: &str) -> Self {
        self.database = database.to_string();
        self
    }
}

/// Query result from MSSQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlQueryResult {
    /// Column names
    pub columns: Vec<String>,
    /// Column types (SQL type names)
    pub column_types: Vec<String>,
    /// Result rows (each row is Vec<Option<String>> for nullable columns)
    pub rows: Vec<Vec<Option<String>>>,
    /// Number of rows affected (for INSERT/UPDATE/DELETE)
    pub rows_affected: u64,
    /// Any output parameters from stored procedure
    pub output_params: Vec<(String, Option<String>)>,
    /// Return status from stored procedure
    pub return_status: Option<i32>,
}

impl MssqlQueryResult {
    /// Check if the result has any rows
    pub fn has_rows(&self) -> bool {
        !self.rows.is_empty()
    }

    /// Get a specific column value from a row
    pub fn get(&self, row: usize, col: usize) -> Option<&Option<String>> {
        self.rows.get(row)?.get(col)
    }

    /// Get a column value by name from a row
    pub fn get_by_name(&self, row: usize, col_name: &str) -> Option<&Option<String>> {
        let col_idx = self.columns.iter().position(|c| c == col_name)?;
        self.get(row, col_idx)
    }
}

/// Linked server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedServer {
    /// Linked server name
    pub name: String,
    /// Data source (connection string or server name)
    pub data_source: String,
    /// OLE DB provider name
    pub provider: String,
    /// Product name
    pub product: Option<String>,
    /// Catalog/database
    pub catalog: Option<String>,
    /// Whether RPC is enabled
    pub rpc_out_enabled: bool,
    /// Whether data access is enabled
    pub data_access_enabled: bool,
}

/// SQL Server version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlServerVersion {
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Build number
    pub build: u32,
    /// Full version string
    pub version_string: String,
    /// Edition (e.g., "Enterprise Edition")
    pub edition: String,
    /// Server name
    pub server_name: String,
}

// ═══════════════════════════════════════════════════════════
//  MSSQL Client
// ═══════════════════════════════════════════════════════════

/// MSSQL database client with TDS protocol support
pub struct MssqlClient {
    stream: Option<TcpStream>,
    config: MssqlConfig,
    connected: bool,
    logged_in: bool,
    server_version: Option<SqlServerVersion>,
    /// Packet ID for TDS messages (increments with each packet)
    packet_id: u8,
    /// SPID (Session Process ID) assigned by server
    spid: u16,
}

impl MssqlClient {
    /// Create a new MSSQL client (unconnected)
    pub fn new(config: MssqlConfig) -> Self {
        Self {
            stream: None,
            config,
            connected: false,
            logged_in: false,
            server_version: None,
            packet_id: 0,
            spid: 0,
        }
    }

    /// Connect to the MSSQL server
    pub async fn connect(config: MssqlConfig) -> Result<Self> {
        let addr = format!("{}:{}", config.server, config.port);
        debug!("Connecting to MSSQL at {}", addr);

        let timeout = Duration::from_secs(config.timeout_secs);
        let stream = tokio::time::timeout(
            timeout,
            TcpStream::connect(&addr)
        )
        .await
        .map_err(|_| OverthroneError::Connection {
            target: addr.clone(),
            reason: "Connection timeout".to_string(),
        })?
        .map_err(|e| OverthroneError::Connection {
            target: addr.clone(),
            reason: format!("Failed to connect: {}", e),
        })?;

        let mut client = Self {
            stream: Some(stream),
            config,
            connected: true,
            logged_in: false,
            server_version: None,
            packet_id: 0,
            spid: 0,
        };

        // Perform TDS handshake
        client.perform_handshake().await?;

        Ok(client)
    }

    /// Perform full TDS handshake (PreLogin + Login)
    async fn perform_handshake(&mut self) -> Result<()> {
        // Step 1: Send PreLogin message
        let prelogin = self.build_prelogin();
        self.send_tds_message(&prelogin).await?;

        // Step 2: Receive PreLogin response
        let prelogin_response = self.receive_tds_message().await?;
        self.parse_prelogin_response(&prelogin_response)?;

        // Step 3: Send Login message
        let login = self.build_login_message().await?;
        self.send_tds_message(&login).await?;

        // Step 4: Receive Login response
        let login_response = self.receive_tds_message().await?;
        self.parse_login_response(&login_response)?;

        self.logged_in = true;
        info!("Successfully logged into MSSQL server");
        Ok(())
    }

    /// Build PreLogin TDS message
    fn build_prelogin(&self) -> Vec<u8> {
        let mut msg = Vec::new();

        // TDS Header (type 18 = PreLogin)
        msg.push(0x12); // Type = MT_PRELOGIN
        msg.push(0x01); // Status = 0x01 (EOM - End of Message)
        msg.extend_from_slice(&(512u16).to_be_bytes()); // Length (placeholder)
        msg.push(self.packet_id.wrapping_add(1)); // SPID high byte
        msg.push(0x00); // SPID low byte
        msg.push(0x00); // Packet ID
        msg.push(0x00); // Window

        // PreLogin payload - Option token format
        let mut payload = Vec::new();

        // VERSION token (0x00)
        // SQL Server 2019 = 15.0.0.0 = 0x0F000000
        payload.push(0x00); // Token type = VERSION
        payload.extend_from_slice(&(6u16).to_be_bytes()); // Offset to data
        payload.extend_from_slice(&(4u16).to_be_bytes()); // Data length
        // Version: major.minor.build.build2
        payload.extend_from_slice(&[0x0F, 0x00, 0x00, 0x00]); // Version 15.0

        // ENCRYPTION token (0x01)
        payload.push(0x01); // Token type = ENCRYPTION
        payload.extend_from_slice(&(10u16).to_be_bytes()); // Offset
        payload.extend_from_slice(&(1u16).to_be_bytes()); // Length
        payload.push(0x02); // ENCRYPT_OFF (encryption not required, but supported)

        // INSTOPT token (0x02) - Instance name
        payload.push(0x02); // Token type = INSTOPT
        payload.extend_from_slice(&(11u16).to_be_bytes()); // Offset
        payload.extend_from_slice(&(1u16).to_be_bytes()); // Length
        payload.push(0x00); // Instance name terminator

        // THREADID token (0x03)
        payload.push(0x03);
        payload.extend_from_slice(&(12u16).to_be_bytes());
        payload.extend_from_slice(&(4u16).to_be_bytes());
        payload.extend_from_slice(&0x00000000u32.to_be_bytes()); // Thread ID

        // MARS token (0x04) - Multiple Active Result Sets
        payload.push(0x04);
        payload.extend_from_slice(&(16u16).to_be_bytes());
        payload.extend_from_slice(&(1u16).to_be_bytes());
        payload.push(0x00); // MARS disabled

        // TERMINATOR
        payload.push(0xFF);

        // Update length in header
        let total_len = 8 + payload.len();
        msg[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        msg.extend_from_slice(&payload);

        msg
    }

    /// Parse PreLogin response
    fn parse_prelogin_response(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(OverthroneError::Protocol {
                protocol: "TDS".to_string(),
                reason: "PreLogin response too short".to_string(),
            });
        }

        // Check message type
        if data[0] != 0x04 {
            // MT_PRELOGIN_RESPONSE
            warn!("Unexpected PreLogin response type: 0x{:02X}", data[0]);
        }

        debug!("Received PreLogin response");
        Ok(())
    }

    /// Build Login7 TDS message
    async fn build_login_message(&mut self) -> Result<Vec<u8>> {
        let mut msg = Vec::new();

        // Build login payload first
        let mut payload = Vec::new();

        // Login7 header (extended)
        payload.extend_from_slice(&0x00000100u32.to_le_bytes()); // Length (placeholder, will update)
        payload.extend_from_slice(&0x01000100u32.to_le_bytes()); // TDS version 7.4
        payload.extend_from_slice(&0x00000000u32.to_le_bytes()); // Packet size requested (0 = default)
        payload.extend_from_slice(&0x00000000u32.to_le_bytes()); // ClientProgVer (placeholder)
        payload.extend_from_slice(&0x00000000u32.to_le_bytes()); // ClientPID
        payload.extend_from_slice(&0x00000000u32.to_le_bytes()); // ConnectionID
        payload.push(0xE0); // OptionFlags1: USE_DB_ON, INIT_DB_FATAL, SET_LANG_ON
        payload.push(0x03); // OptionFlags2: ODBC_ON, USER_NORMAL
        payload.push(0x00); // TypeFlags
        payload.push(0x00); // OptionFlags3
        payload.extend_from_slice(&(0u32).to_le_bytes()); // ClientTimeZone
        payload.extend_from_slice(&(0u32).to_le_bytes()); // ClientLCID

        // Variable length data offsets and lengths
        // We'll build the data section and track offsets
        let header_size = 32; // Fixed header before offsets
        let offset_base = 86; // After header and 8 offset fields (32 + 8*8 = 96, minus some)

        let mut data_section = Vec::new();
        let mut current_offset = 0u16;

        // Helper to add a variable-length field
        let mut add_field = |value: &str| -> (u16, u16) {
            let len = value.len() as u16;
            let start = current_offset;
            // Store as UTF-16LE
            for c in value.encode_utf16() {
                data_section.extend_from_slice(&c.to_le_bytes());
            }
            current_offset += len * 2;
            (start, len * 2) // Offset and byte length
        };

        // Collect field data
        let hostname = "overthrone";
        let username = self.config.username.as_deref().unwrap_or("");
        let password = self.config.password.as_deref().unwrap_or("");
        let app_name = "Overthrone AD Toolkit";
        let server_name = &self.config.server;
        let database = &self.config.database;
        let language = "us_english";
        let auth_db = ""; // Auth database

        let hostname_field = add_field(hostname);
        let username_field = add_field(username);
        let password_field = add_field(password);
        let app_name_field = add_field(app_name);
        let server_name_field = add_field(server_name);
        let language_field = add_field(language);
        let database_field = add_field(database);
        let auth_db_field = add_field(auth_db);

        // Build offset fields (8 fields * 4 bytes each = 32 bytes)
        let mut offset_section = Vec::new();

        // HostName
        offset_section.extend_from_slice(&hostname_field.0.to_le_bytes());
        offset_section.extend_from_slice(&hostname_field.1.to_le_bytes());
        // UserName
        offset_section.extend_from_slice(&username_field.0.to_le_bytes());
        offset_section.extend_from_slice(&username_field.1.to_le_bytes());
        // Password
        offset_section.extend_from_slice(&password_field.0.to_le_bytes());
        offset_section.extend_from_slice(&password_field.1.to_le_bytes());
        // AppName
        offset_section.extend_from_slice(&app_name_field.0.to_le_bytes());
        offset_section.extend_from_slice(&app_name_field.1.to_le_bytes());
        // ServerName
        offset_section.extend_from_slice(&server_name_field.0.to_le_bytes());
        offset_section.extend_from_slice(&server_name_field.1.to_le_bytes());
        // Language
        offset_section.extend_from_slice(&language_field.0.to_le_bytes());
        offset_section.extend_from_slice(&language_field.1.to_le_bytes());
        // Database
        offset_section.extend_from_slice(&database_field.0.to_le_bytes());
        offset_section.extend_from_slice(&database_field.1.to_le_bytes());
        // AuthDB (ClientID)
        offset_section.extend_from_slice(&auth_db_field.0.to_le_bytes());
        offset_section.extend_from_slice(&auth_db_field.1.to_le_bytes());

        // Update payload length
        let total_len = payload.len() + offset_section.len() + data_section.len();
        payload[0..4].copy_from_slice(&(total_len as u32).to_le_bytes());

        // Assemble final payload
        payload.extend_from_slice(&offset_section);
        payload.extend_from_slice(&data_section);

        // Wrap in TDS packet
        // Type 0x10 = Login7
        msg.push(0x10);
        msg.push(0x01); // Status = EOM
        let packet_len = (8 + payload.len()) as u16;
        msg.extend_from_slice(&packet_len.to_be_bytes());
        msg.push(0x00); // SPID
        msg.push(0x00);
        msg.push(self.packet_id);
        self.packet_id = self.packet_id.wrapping_add(1);
        msg.push(0x00); // Window
        msg.extend_from_slice(&payload);

        Ok(msg)
    }

    /// Parse Login response
    fn parse_login_response(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(OverthroneError::Protocol {
                protocol: "TDS".to_string(),
                reason: "Login response too short".to_string(),
            });
        }

        // Parse TDS response tokens
        let mut pos = 8; // After header

        while pos < data.len() {
            let token = data[pos];
            pos += 1;

            match token {
                0xAD => {
                    // ENVCHANGE token
                    debug!("Received ENVCHANGE token");
                    pos = self.parse_envchange_token(&data[pos..])?;
                    pos += 8;
                }
                0xAE => {
                    // SESSIONSTATE token
                    debug!("Received SESSIONSTATE token");
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2 + len;
                }
                0xE3 => {
                    // RETURNSTATUS token
                    debug!("Received RETURNSTATUS token");
                    pos += 4;
                }
                0xAB => {
                    // LOGINACK token
                    debug!("Received LOGINACK token");
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    // Parse version from LOGINACK
                    if pos + 4 + len > data.len() {
                        break;
                    }
                    // Skip length, interface, version, server name
                    pos += 2 + len;
                }
                0xFD => {
                    // DONE token (end of response)
                    debug!("Received DONE token - login complete");
                    break;
                }
                0x00 | 0xFF => {
                    // End of message or padding
                    break;
                }
                _ => {
                    // Unknown token - try to skip
                    debug!("Unknown token 0x{:02X} at position {}", token, pos - 1);
                    break;
                }
            }
        }

        self.logged_in = true;
        Ok(())
    }

    /// Parse ENVCHANGE token
    fn parse_envchange_token(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 2 {
            return Ok(0);
        }

        let total_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if total_len == 0 || data.len() < total_len + 2 {
            return Ok(0);
        }

        // Parse environment change type
        if total_len > 2 {
            let change_type = data[2];
            match change_type {
                1 => debug!("ENVCHANGE: Database changed"),
                2 => debug!("ENVCHANGE: Language changed"),
                3 => debug!("ENVCHANGE: Packet size changed"),
                4 => debug!("ENVCHANGE: Sort order changed"),
                5 => debug!("ENVCHANGE: Unicode sort order changed"),
                6 => debug!("ENVCHANGE: LCID changed"),
                7 => debug!("ENVCHANGE: Collation changed"),
                _ => debug!("ENVCHANGE: Type {}", change_type),
            }
        }

        Ok(total_len)
    }

    /// Send a TDS message
    async fn send_tds_message(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.stream.as_mut().ok_or_else(|| OverthroneError::Connection {
            target: self.config.server.clone(),
            reason: "Not connected".to_string(),
        })?;
        
        stream.write_all(data).await.map_err(|e| {
            OverthroneError::Connection {
                target: self.config.server.clone(),
                reason: format!("Failed to send TDS message: {}", e),
            }
        })?;
        stream.flush().await?;
        debug!("Sent {} bytes", data.len());
        Ok(())
    }

    /// Receive a TDS message
    async fn receive_tds_message(&mut self) -> Result<Vec<u8>> {
        let stream = self.stream.as_mut().ok_or_else(|| OverthroneError::Connection {
            target: self.config.server.clone(),
            reason: "Not connected".to_string(),
        })?;
        
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).await.map_err(|e| {
            OverthroneError::Connection {
                target: self.config.server.clone(),
                reason: format!("Failed to read TDS header: {}", e),
            }
        })?;

        let msg_type = header[0];
        let status = header[1];
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;

        let mut buffer = Vec::with_capacity(length);
        buffer.extend_from_slice(&header);

        // Read remaining bytes
        let remaining = length - 8;
        if remaining > 0 {
            buffer.resize(length, 0);
            stream.read_exact(&mut buffer[8..]).await.map_err(|e| {
                OverthroneError::Connection {
                    target: self.config.server.clone(),
                    reason: format!("Failed to read TDS payload: {}", e),
                }
            })?;
        }

        debug!(
            "Received TDS message: type=0x{:02X}, status=0x{:02X}, len={}",
            msg_type, status, length
        );

        Ok(buffer)
    }

    /// Execute a SQL query
    pub async fn query(&mut self, sql: &str) -> Result<MssqlQueryResult> {
        if !self.logged_in {
            return Err(OverthroneError::Auth("Not logged in".to_string()));
        }

        debug!("Executing query: {}", sql);

        // Send SQL Batch message
        let batch = self.build_sql_batch(sql);
        self.send_tds_message(&batch).await?;

        // Receive response
        let response = self.receive_tds_message().await?;
        self.parse_query_response(&response)
    }

    /// Build SQL Batch TDS message
    fn build_sql_batch(&mut self, sql: &str) -> Vec<u8> {
        let mut msg = Vec::new();

        // Convert SQL to UTF-16LE
        let sql_utf16: Vec<u8> = sql.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let total_len = 8 + 4 + sql_utf16.len(); // Header + all header + SQL

        // TDS Header
        msg.push(0x01); // Type = SQL Batch
        msg.push(0x01); // Status = EOM
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(0x00); // SPID
        msg.push(0x00);
        msg.push(self.packet_id);
        self.packet_id = self.packet_id.wrapping_add(1);
        msg.push(0x00); // Window

        // ALL_HEADERS (required for SQL Batch)
        // Total length
        msg.extend_from_slice(&(4u32 + 4u32).to_le_bytes());
        // Transaction descriptor header
        msg.extend_from_slice(&4u32.to_le_bytes()); // Header length
        msg.extend_from_slice(&0x0000000000000000u64.to_le_bytes()); // Transaction descriptor
        msg.extend_from_slice(&1u32.to_le_bytes()); // Outstanding request count

        // SQL text (UTF-16LE)
        msg.extend_from_slice(&sql_utf16);

        msg
    }

    /// Parse query response
    fn parse_query_response(&mut self, data: &[u8]) -> Result<MssqlQueryResult> {
        let mut result = MssqlQueryResult {
            columns: Vec::new(),
            column_types: Vec::new(),
            rows: Vec::new(),
            rows_affected: 0,
            output_params: Vec::new(),
            return_status: None,
        };

        if data.len() < 8 {
            return Ok(result);
        }

        let mut pos = 8; // After header

        while pos < data.len() {
            if pos >= data.len() {
                break;
            }

            let token = data[pos];
            pos += 1;

            match token {
                0x81 => {
                    // COLMETADATA - Column metadata
                    let (new_pos, columns, types) = self.parse_colmetadata(&data[pos..])?;
                    pos += new_pos;
                    result.columns = columns;
                    result.column_types = types;
                }
                0xD1 => {
                    // ROW - Row data
                    let (new_pos, row) = self.parse_row(&data[pos..], &result.columns.len())?;
                    pos += new_pos;
                    result.rows.push(row);
                }
                0xD2 => {
                    // NBCROW - Null-bit compressed row
                    let (new_pos, row) = self.parse_nbcrow(&data[pos..], &result.columns.len())?;
                    pos += new_pos;
                    result.rows.push(row);
                }
                0xFD | 0xFE => {
                    // DONE/DONEPROC
                    if data.len() >= pos + 3 {
                        let done_status = u16::from_le_bytes([data[pos], data[pos + 1]]);
                        let rows_affected = u64::from_le_bytes({
                            let mut arr = [0u8; 8];
                            arr[..4].copy_from_slice(&data[pos + 2..pos + 6]);
                            arr
                        });
                        result.rows_affected = rows_affected;
                    }
                    break;
                }
                0x79 => {
                    // RETURNSTATUS
                    if pos + 4 <= data.len() {
                        result.return_status = Some(i32::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                        ]));
                        pos += 4;
                    }
                }
                0xAC => {
                    // DONEINPROC
                    pos += 6;
                }
                0xA5 => {
                    // ORDER
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2 + len;
                }
                0xFD => break,
                0x00 => break,
                _ => {
                    // Unknown token - try to continue
                    debug!("Unknown response token: 0x{:02X}", token);
                    break;
                }
            }
        }

        Ok(result)
    }

    /// Parse COLMETADATA token
    fn parse_colmetadata(&self, data: &[u8]) -> Result<(usize, Vec<String>, Vec<String>)> {
        if data.len() < 2 {
            return Ok((0, Vec::new(), Vec::new()));
        }

        let column_count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut pos = 2;

        let mut columns = Vec::with_capacity(column_count);
        let mut types = Vec::with_capacity(column_count);

        for _ in 0..column_count {
            if pos + 6 > data.len() {
                break;
            }

            // UserType (4 bytes) and Flags (2 bytes)
            pos += 6;

            // TYPE_INFO
            if pos >= data.len() {
                break;
            }

            let type_id = data[pos];
            pos += 1;

            let type_name = match type_id {
                0x26 => "int",
                0x30 => "intn",
                0x32 => "bit",
                0x34 => "smallint",
                0x38 => "tinyint",
                0x3A => "bigint",
                0x3C => "float",
                0x3E => "real",
                0x68 => "uniqueidentifier",
                0x6A => "intn",
                0x6C => "decimal",
                0x6E => "numeric",
                0x7A => "money",
                0x7E => "smallmoney",
                0xA5 => "varbinary",
                0xA7 => "binary",
                0xAF => "varchar",
                0xE7 => "nvarchar",
                0xE1 => "nchar",
                0xEF => "nchar",
                0xA1 => "char",
                0x24 => "text",
                0x98 => "sql_variant",
                0x22 => "image",
                0xF1 => "datetime",
                0x27 => "datetime2",
                0x29 => "datetimeoffset",
                0x2A => "time",
                _ => "unknown",
            };
            types.push(type_name.to_string());

            // Parse type-specific data (length, precision, scale)
            match type_id {
                0x26 | 0x32 | 0x34 | 0x38 | 0x3A => {
                    // Fixed-length types - no additional data
                }
                0x30 | 0x6A => {
                    // intn - length byte
                    pos += 1;
                }
                0x3C | 0x3E => {
                    // float - length byte
                    pos += 1;
                }
                0x6C | 0x6E => {
                    // decimal/numeric - length + precision + scale
                    pos += 1; // length
                    pos += 1; // precision
                    pos += 1; // scale
                }
                0xA5 | 0xA7 => {
                    // varbinary/binary - length (2 bytes)
                    pos += 2;
                }
                0xAF | 0xA1 => {
                    // varchar/char - length (2 bytes) + collation
                    pos += 2;
                    pos += 5; // collation info
                }
                0xE7 | 0xE1 | 0xEF => {
                    // nvarchar/nchar - length (2 bytes) + collation
                    pos += 2;
                    pos += 5; // collation info
                }
                0x24 | 0x22 => {
                    // text/image - pointer
                    pos += 16;
                }
                0xF1 => {
                    // datetime - length
                    pos += 1;
                }
                0x27 | 0x29 | 0x2A => {
                    // datetime2/datetimeoffset/time - scale
                    pos += 1;
                }
                _ => {
                    // Unknown - try to continue
                }
            }

            // Column name (US_VARCHAR: length + UTF-16 string)
            if pos + 2 > data.len() {
                break;
            }
            let name_len = u8::from_le_bytes([data[pos]]) as usize;
            pos += 1;

            if pos + name_len * 2 > data.len() {
                break;
            }

            let name_bytes: Vec<u8> = data[pos..pos + name_len * 2].to_vec();
            let name: String = name_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .map(|c| char::from_u32(c as u32).unwrap_or('?'))
                .collect();
            columns.push(name);
            pos += name_len * 2;
        }

        Ok((pos, columns, types))
    }

    /// Parse ROW token
    fn parse_row(&self, data: &[u8], col_count: &usize) -> Result<(usize, Vec<Option<String>>)> {
        let mut pos = 0;
        let mut row = Vec::with_capacity(*col_count);

        for _ in 0..*col_count {
            if pos >= data.len() {
                row.push(None);
                continue;
            }

            // Text pointer and timestamp for text/image types
            // For simple types, just read the length byte

            let len = data[pos] as i8;
            pos += 1;

            if len < 0 {
                // NULL
                row.push(None);
            } else if len == 0 {
                // Empty string
                row.push(Some(String::new()));
            } else {
                // Read data
                let data_len = len as usize;
                if pos + data_len > data.len() {
                    row.push(None);
                    continue;
                }

                // Convert from storage type (may be UTF-16 or binary)
                let value = if data_len == 4 && col_count <= &4 {
                    // Could be int - interpret as number
                    let num = i32::from_le_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]);
                    Some(num.to_string())
                } else if data_len.is_multiple_of(2) {
                    // Assume UTF-16LE
                    let s: String = data[pos..pos + data_len]
                        .chunks(2)
                        .filter_map(|c| {
                            if c.len() == 2 {
                                Some(char::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32)?)
                            } else {
                                None
                            }
                        })
                        .collect();
                    Some(s)
                } else {
                    // Binary - convert to hex
                    Some(data[pos..pos + data_len].iter().map(|b| format!("{:02X}", b)).collect())
                };

                row.push(value);
                pos += data_len;
            }
        }

        Ok((pos, row))
    }

    /// Parse NBCROW (Null-bit compressed row)
    fn parse_nbcrow(&self, data: &[u8], col_count: &usize) -> Result<(usize, Vec<Option<String>>)> {
        let mut pos = 0;

        // Null bitmap
        let bitmap_bytes = col_count.div_ceil(8);
        if pos + bitmap_bytes > data.len() {
            return Ok((pos, vec![None; *col_count]));
        }

        let null_bitmap = &data[pos..pos + bitmap_bytes];
        pos += bitmap_bytes;

        let mut row = Vec::with_capacity(*col_count);

        for i in 0..*col_count {
            let is_null = (null_bitmap[i / 8] & (1 << (i % 8))) != 0;

            if is_null {
                row.push(None);
            } else if pos < data.len() {
                // Read length-prefixed data
                let len = data[pos] as usize;
                pos += 1;

                if len == 0 {
                    row.push(Some(String::new()));
                } else if pos + len <= data.len() {
                    // Try UTF-16LE conversion
                    let value: String = data[pos..pos + len]
                        .chunks(2)
                        .filter_map(|c| {
                            if c.len() == 2 {
                                Some(char::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32)?)
                            } else {
                                None
                            }
                        })
                        .collect();
                    row.push(Some(value));
                    pos += len;
                } else {
                    row.push(None);
                }
            } else {
                row.push(None);
            }
        }

        Ok((pos, row))
    }

    /// Execute a SQL statement (returns rows affected)
    pub async fn execute(&mut self, sql: &str) -> Result<u64> {
        let result = self.query(sql).await?;
        Ok(result.rows_affected)
    }

    /// Enable xp_cmdshell
    pub async fn enable_xp_cmdshell(&mut self) -> Result<()> {
        debug!("Enabling xp_cmdshell");

        // Step 1: Enable advanced options
        self.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
            .await?;

        // Step 2: Enable xp_cmdshell
        self.execute("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
            .await?;

        info!("xp_cmdshell enabled successfully");
        Ok(())
    }

    /// Disable xp_cmdshell
    pub async fn disable_xp_cmdshell(&mut self) -> Result<()> {
        debug!("Disabling xp_cmdshell");

        self.execute("EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;")
            .await?;
        self.execute("EXEC sp_configure 'show advanced options', 0; RECONFIGURE;")
            .await?;

        info!("xp_cmdshell disabled");
        Ok(())
    }

    /// Execute command via xp_cmdshell
    pub async fn execute_xp_cmdshell(&mut self, command: &str) -> Result<String> {
        debug!("Executing command via xp_cmdshell: {}", command);

        // Escape single quotes
        let escaped = command.replace("'", "''");
        let sql = format!("EXEC xp_cmdshell '{}';", escaped);

        let result = self.query(&sql).await?;

        // Combine output lines
        let output: String = result
            .rows
            .iter()
            .filter_map(|row| row.first().and_then(|v| v.as_ref()))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        Ok(output)
    }

    /// Check if xp_cmdshell is enabled
    pub async fn check_xp_cmdshell(&mut self) -> Result<bool> {
        let result = self
            .query("SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';")
            .await?;

        if let Some(row) = result.rows.first()
            && let Some(Some(value)) = row.first() {
                return Ok(value == "1");
            }

        Ok(false)
    }

    /// Get SQL Server version
    pub async fn get_version(&mut self) -> Result<SqlServerVersion> {
        let result = self.query("SELECT @@VERSION;").await?;

        if let Some(row) = result.rows.first()
            && let Some(Some(version_str)) = row.first() {
                return Ok(SqlServerVersion {
                    major: 0,
                    minor: 0,
                    build: 0,
                    version_string: version_str.clone(),
                    edition: "Unknown".to_string(),
                    server_name: self.config.server.clone(),
                });
            }

        Err(OverthroneError::Protocol {
            protocol: "TDS".to_string(),
            reason: "Failed to get server version".to_string(),
        })
    }

    /// Enumerate linked servers
    pub async fn enumerate_linked_servers(&mut self) -> Result<Vec<LinkedServer>> {
        let result = self
            .query(
                "SELECT name, product, provider, data_source, catalog, 
                        is_rpc_out_enabled, is_data_access_enabled 
                 FROM sys.servers WHERE is_linked = 1;",
            )
            .await?;

        let mut servers = Vec::new();

        for row in &result.rows {
            if row.len() >= 7 {
                servers.push(LinkedServer {
                    name: row[0].clone().unwrap_or_default(),
                    product: row[1].clone(),
                    provider: row[2].clone().unwrap_or_default(),
                    data_source: row[3].clone().unwrap_or_default(),
                    catalog: row[4].clone(),
                    rpc_out_enabled: row[5].as_ref().map(|v| v == "1").unwrap_or(false),
                    data_access_enabled: row[6].as_ref().map(|v| v == "1").unwrap_or(false),
                });
            }
        }

        Ok(servers)
    }

    /// Execute query on linked server
    pub async fn execute_on_linked_server(
        &mut self,
        server: &str,
        query: &str,
    ) -> Result<MssqlQueryResult> {
        let escaped_query = query.replace("'", "''");
        let sql = format!("SELECT * FROM OPENQUERY([{}], '{}');", server, escaped_query);

        self.query(&sql).await
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<()> {
        if self.connected {
            // Send logout message (type 0x02 with special payload)
            let logout = vec![0x02, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
            let _ = self.send_tds_message(&logout).await;
            self.connected = false;
            self.logged_in = false;
        }
        Ok(())
    }
}

impl Drop for MssqlClient {
    fn drop(&mut self) {
        // Attempt to close connection on drop
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mssql_config_default() {
        let config = MssqlConfig::default();
        assert_eq!(config.port, 1433);
        assert_eq!(config.database, "master");
        assert!(config.trust_cert);
    }

    #[test]
    fn test_mssql_config_builder() {
        let config = MssqlConfig::new("192.168.1.10")
            .with_sql_auth("sa", "password123")
            .with_database("testdb");

        assert_eq!(config.server, "192.168.1.10");
        assert_eq!(config.username, Some("sa".to_string()));
        assert_eq!(config.database, "testdb");
    }

    #[test]
    fn test_query_result() {
        let result = MssqlQueryResult {
            columns: vec!["id".to_string(), "name".to_string()],
            column_types: vec!["int".to_string(), "nvarchar".to_string()],
            rows: vec![
                vec![Some("1".to_string()), Some("Alice".to_string())],
                vec![Some("2".to_string()), Some("Bob".to_string())],
            ],
            rows_affected: 0,
            output_params: Vec::new(),
            return_status: None,
        };

        assert!(result.has_rows());
        assert_eq!(result.get(0, 0), Some(&Some("1".to_string())));
        assert_eq!(result.get_by_name(1, "name"), Some(&Some("Bob".to_string())));
    }

    #[test]
    fn test_build_prelogin() {
        let config = MssqlConfig::new("localhost");
        let client = MssqlClient::new(config);
        let prelogin = client.build_prelogin();

        // Check it's a valid TDS message
        assert!(prelogin.len() > 8);
        assert_eq!(prelogin[0], 0x12); // PreLogin type
    }
}