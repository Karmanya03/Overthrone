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

pub mod auth;
pub mod mssql_links;
pub mod tds;
use crate::error::{OverthroneError, Result};
use auth::obfuscate_password;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

// Re-export main types
pub use auth::MssqlAuth;
pub use mssql_links::{LinkCrawlResult, LinkCrawler, LinkCrawlerConfig, LinkNode};
pub use tds::{TdsColumnData, TdsMessage, TdsMessageType, sql_types};
// ═══════════════════════════════════════════════════════════
// Public Types
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
// MSSQL Client
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
    /// Column metadata cached from last COLMETADATA token
    current_col_types: Vec<u8>,
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
            current_col_types: Vec::new(),
        }
    }

    /// Connect to the MSSQL server
    pub async fn connect(config: MssqlConfig) -> Result<Self> {
        let addr = format!("{}:{}", config.server, config.port);
        debug!("Connecting to MSSQL at {}", addr);

        let timeout = Duration::from_secs(config.timeout_secs);
        let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
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
            current_col_types: Vec::new(),
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
        let login = self.build_login_message()?;
        self.send_tds_message(&login).await?;

        // Step 4: Receive Login response
        let login_response = self.receive_tds_message().await?;
        self.parse_login_response(&login_response)?;

        self.logged_in = true;
        info!("Successfully logged into MSSQL server");
        Ok(())
    }

    // ───────────────────────────────────────────────────────
    // PreLogin
    // ───────────────────────────────────────────────────────

    /// Build PreLogin TDS message (MS-TDS 2.2.6.5)
    ///
    /// Token format: [type:1][offset:2][length:2] per token, terminated by 0xFF.
    /// Offsets are relative to the start of the payload (byte 0 of the first token).
    fn build_prelogin(&mut self) -> Vec<u8> {
        // Token definitions: (type_byte, data)
        let version_data: [u8; 6] = [0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00]; // 15.0.2000.0
        let encryption_data: [u8; 1] = [0x02]; // ENCRYPT_NOT_SUP
        let instopt_data: [u8; 1] = [0x00]; // Default instance
        let threadid_data: [u8; 4] = [0x00; 4]; // Thread ID = 0
        let mars_data: [u8; 1] = [0x00]; // MARS disabled

        let tokens: &[(&[u8], u8)] = &[
            (&version_data, 0x00),
            (&encryption_data, 0x01),
            (&instopt_data, 0x02),
            (&threadid_data, 0x03),
            (&mars_data, 0x04),
        ];

        // Token headers: 5 tokens * 5 bytes each + 1 byte terminator = 26 bytes
        let token_headers_size = tokens.len() * 5 + 1;
        let mut data_offset = token_headers_size as u16;

        let mut payload = Vec::new();

        // Write token headers
        for (data, token_type) in tokens {
            payload.push(*token_type);
            payload.extend_from_slice(&data_offset.to_be_bytes());
            payload.extend_from_slice(&(data.len() as u16).to_be_bytes());
            data_offset += data.len() as u16;
        }

        // Terminator
        payload.push(0xFF);

        // Write token data in order
        for (data, _) in tokens {
            payload.extend_from_slice(data);
        }

        // TDS packet header (8 bytes)
        let total_len = 8 + payload.len();
        let mut msg = Vec::with_capacity(total_len);
        msg.push(0x12); // Type: PreLogin
        msg.push(0x01); // Status: EOM
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(0x00); // SPID high (0 for client)
        msg.push(0x00); // SPID low
        msg.push(self.packet_id); // PacketID
        self.packet_id = self.packet_id.wrapping_add(1);
        msg.push(0x00); // Window

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

        // Response type should be 0x04 (Tabular Result)
        if data[0] != 0x04 {
            warn!("Unexpected PreLogin response type: 0x{:02X}", data[0]);
        }

        debug!("Received PreLogin response ({} bytes)", data.len());
        Ok(())
    }

    // ───────────────────────────────────────────────────────
    // Login7
    // ───────────────────────────────────────────────────────

    /// Build Login7 TDS message (MS-TDS 2.2.6.4)
    ///
    /// The Login7 message consists of:
    ///   - Fixed-length header (94 bytes: 36 bytes fixed + 13 offset/length pairs * 4 bytes + 6 bytes extension)
    ///   - Variable-length data section (UTF-16LE encoded strings)
    ///
    /// Offset/length pairs use character counts (not byte counts) for the length field,
    /// and byte offsets from the start of the Login7 payload for the offset field.
    fn build_login_message(&mut self) -> Result<Vec<u8>> {
        // ── Collect field values ──
        let hostname = "OVERTHRONE";
        let username = self.config.username.as_deref().unwrap_or("");
        let password = self.config.password.as_deref().unwrap_or("");
        let app_name = "Overthrone AD Toolkit";
        let server_name = &self.config.server;
        let database = &self.config.database;
        let language = "us_english";

        // ── Encode all strings to UTF-16LE ──
        let hostname_utf16 = str_to_utf16le(hostname);
        let username_utf16 = str_to_utf16le(username);
        let password_utf16 = obfuscate_password(password); // TDS-obfuscated password
        let app_name_utf16 = str_to_utf16le(app_name);
        let server_name_utf16 = str_to_utf16le(server_name);
        let database_utf16 = str_to_utf16le(database);
        let language_utf16 = str_to_utf16le(language);

        // Client ID (MAC address, 6 bytes — we use zeros)
        let client_id: [u8; 6] = [0x00; 6];

        // ── Calculate the fixed header size ──
        // Login7 fixed header layout (per MS-TDS spec):
        //   Bytes 0-3:   Length (u32 LE)
        //   Bytes 4-7:   TDSVersion
        //   Bytes 8-11:  PacketSize
        //   Bytes 12-15: ClientProgVer
        //   Bytes 16-19: ClientPID
        //   Bytes 20-23: ConnectionID
        //   Byte  24:    OptionFlags1
        //   Byte  25:    OptionFlags2
        //   Byte  26:    TypeFlags
        //   Byte  27:    OptionFlags3
        //   Bytes 28-31: ClientTimZone
        //   Bytes 32-35: ClientLCID
        //   Then 13 offset/length pairs (4 bytes each) = 52 bytes
        //   Then 6 bytes for ClientID (MAC)
        // Total fixed header = 36 + 52 + 6 = 94 bytes
        let fixed_header_len: u16 = 94;

        // ── Build variable data section and compute offsets ──
        let mut var_data = Vec::new();
        let mut var_offset = fixed_header_len;

        // Macro-like helper: returns (offset, char_count) and appends data
        let mut push_field = |data: &[u8], char_count: u16| -> (u16, u16) {
            let offset = var_offset;
            var_data.extend_from_slice(data);
            var_offset += data.len() as u16;
            (offset, char_count)
        };

        // Field order per MS-TDS spec (13 pairs):
        // 0: HostName
        let f_hostname = push_field(&hostname_utf16, hostname.len() as u16);
        // 1: UserName
        let f_username = push_field(&username_utf16, username.len() as u16);
        // 2: Password
        let f_password = push_field(&password_utf16, password.len() as u16);
        // 3: AppName
        let f_app_name = push_field(&app_name_utf16, app_name.len() as u16);
        // 4: ServerName
        let f_server = push_field(&server_name_utf16, server_name.len() as u16);
        // 5: Unused (Extension — 0,0)
        let f_unused = (0u16, 0u16);
        // 6: CltIntName (client interface library name)
        let clt_int = "ODBC";
        let clt_int_utf16 = str_to_utf16le(clt_int);
        let f_clt_int = push_field(&clt_int_utf16, clt_int.len() as u16);
        // 7: Language
        let f_language = push_field(&language_utf16, language.len() as u16);
        // 8: Database
        let f_database = push_field(&database_utf16, database.len() as u16);
        // 9-12: ClientID, SSPI, AtchDBFile, ChangePassword are handled separately

        // ── Assemble fixed header ──
        let total_payload_len = fixed_header_len as u32 + var_data.len() as u32;

        let mut payload = Vec::with_capacity(total_payload_len as usize);

        // Bytes 0-3: Length
        payload.extend_from_slice(&total_payload_len.to_le_bytes());
        // Bytes 4-7: TDS Version 7.4 (SQL Server 2012+)
        payload.extend_from_slice(&[0x04, 0x00, 0x00, 0x74]); // 0x74000004
        // Bytes 8-11: PacketSize (default 4096)
        payload.extend_from_slice(&4096u32.to_le_bytes());
        // Bytes 12-15: ClientProgVer
        payload.extend_from_slice(&0x00000007u32.to_le_bytes());
        // Bytes 16-19: ClientPID
        payload.extend_from_slice(&(std::process::id()).to_le_bytes());
        // Bytes 20-23: ConnectionID
        payload.extend_from_slice(&0u32.to_le_bytes());
        // Byte 24: OptionFlags1 (USE_DB_ON | INIT_DB_FATAL | SET_LANG_ON)
        payload.push(0xE0);
        // Byte 25: OptionFlags2 (ODBC_ON | USER_NORMAL)
        payload.push(0x03);
        // Byte 26: TypeFlags
        payload.push(0x00);
        // Byte 27: OptionFlags3
        payload.push(0x00);
        // Bytes 28-31: ClientTimZone
        payload.extend_from_slice(&0i32.to_le_bytes());
        // Bytes 32-35: ClientLCID
        payload.extend_from_slice(&0x00000409u32.to_le_bytes()); // English (US)

        // ── 13 Offset/Length pairs (each 2+2 = 4 bytes) ──
        // 0: HostName
        payload.extend_from_slice(&f_hostname.0.to_le_bytes());
        payload.extend_from_slice(&f_hostname.1.to_le_bytes());
        // 1: UserName
        payload.extend_from_slice(&f_username.0.to_le_bytes());
        payload.extend_from_slice(&f_username.1.to_le_bytes());
        // 2: Password
        payload.extend_from_slice(&f_password.0.to_le_bytes());
        payload.extend_from_slice(&f_password.1.to_le_bytes());
        // 3: AppName
        payload.extend_from_slice(&f_app_name.0.to_le_bytes());
        payload.extend_from_slice(&f_app_name.1.to_le_bytes());
        // 4: ServerName
        payload.extend_from_slice(&f_server.0.to_le_bytes());
        payload.extend_from_slice(&f_server.1.to_le_bytes());
        // 5: Extension (unused)
        payload.extend_from_slice(&f_unused.0.to_le_bytes());
        payload.extend_from_slice(&f_unused.1.to_le_bytes());
        // 6: CltIntName
        payload.extend_from_slice(&f_clt_int.0.to_le_bytes());
        payload.extend_from_slice(&f_clt_int.1.to_le_bytes());
        // 7: Language
        payload.extend_from_slice(&f_language.0.to_le_bytes());
        payload.extend_from_slice(&f_language.1.to_le_bytes());
        // 8: Database
        payload.extend_from_slice(&f_database.0.to_le_bytes());
        payload.extend_from_slice(&f_database.1.to_le_bytes());
        // 9: ClientID (6 bytes inline, not offset/length)
        payload.extend_from_slice(&client_id);
        // 10: SSPI (offset, length) — not used for SQL auth
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        // 11: AtchDBFile (offset, length)
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        // 12: ChangePassword (offset, length)
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        // SSPI Long (4 bytes)
        payload.extend_from_slice(&0u32.to_le_bytes());

        // Sanity check: fixed header should be exactly 94 bytes
        debug_assert_eq!(
            payload.len(),
            fixed_header_len as usize,
            "Login7 fixed header size mismatch: got {} expected {}",
            payload.len(),
            fixed_header_len
        );

        // ── Append variable data ──
        payload.extend_from_slice(&var_data);

        // ── Wrap in TDS packet ──
        let mut msg = Vec::new();
        msg.push(0x10); // Type: Login7
        msg.push(0x01); // Status: EOM
        let packet_len = (8 + payload.len()) as u16;
        msg.extend_from_slice(&packet_len.to_be_bytes());
        msg.push(0x00); // SPID high
        msg.push(0x00); // SPID low
        msg.push(self.packet_id);
        self.packet_id = self.packet_id.wrapping_add(1);
        msg.push(0x00); // Window

        msg.extend_from_slice(&payload);
        Ok(msg)
    }

    // ───────────────────────────────────────────────────────
    // Login Response Parsing
    // ───────────────────────────────────────────────────────

    /// Parse Login7 response tokens (MS-TDS 2.2.7)
    fn parse_login_response(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(OverthroneError::Protocol {
                protocol: "TDS".to_string(),
                reason: "Login response too short".to_string(),
            });
        }

        let mut pos = 8; // Skip TDS header

        while pos < data.len() {
            let token = data[pos];
            pos += 1;

            match token {
                // ── ENVCHANGE (0xE3) ──
                0xE3 => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    if len > 2 && pos + 2 < data.len() {
                        let change_type = data[pos + 2];
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
                    pos += 2 + len;
                }

                // ── LOGINACK (0xAD) ──
                0xAD => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    debug!("Received LOGINACK — authentication successful");
                    self.logged_in = true;
                    pos += 2 + len;
                }

                // ── INFO (0xAB) ──
                0xAB => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    debug!("Received INFO token");
                    pos += 2 + len;
                }

                // ── ERROR (0xAA) ──
                0xAA => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;

                    // Try to extract the error message
                    let err_msg = if pos + 2 + len <= data.len() && len >= 10 {
                        // Error token: number(4) + state(1) + class(1) + msglen(2) + msg(UTF-16)
                        let msg_len_offset = pos + 2 + 6; // skip number, state, class
                        if msg_len_offset + 2 <= data.len() {
                            let msg_chars = u16::from_le_bytes([
                                data[msg_len_offset],
                                data[msg_len_offset + 1],
                            ]) as usize;
                            let msg_start = msg_len_offset + 2;
                            let msg_bytes = msg_chars * 2;
                            if msg_start + msg_bytes <= data.len() {
                                utf16le_to_string(&data[msg_start..msg_start + msg_bytes])
                            } else {
                                "SQL Server login error".to_string()
                            }
                        } else {
                            "SQL Server login error".to_string()
                        }
                    } else {
                        "SQL Server login error".to_string()
                    };

                    warn!("SQL Server ERROR: {}", err_msg);
                    pos += 2 + len;
                    return Err(OverthroneError::Auth(err_msg));
                }

                // ── DONE (0xFD) ──
                0xFD => {
                    debug!("DONE token — login sequence complete");
                    break;
                }

                // ── Unknown token — skip by length ──
                _ => {
                    if pos + 2 <= data.len() {
                        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                        debug!("Skipping unknown token 0x{:02X} ({} bytes)", token, len);
                        pos += 2 + len;
                    } else {
                        break;
                    }
                }
            }
        }

        if !self.logged_in {
            return Err(OverthroneError::Auth(
                "Login failed: no LOGINACK received".to_string(),
            ));
        }

        Ok(())
    }

    // ───────────────────────────────────────────────────────
    // Send / Receive
    // ───────────────────────────────────────────────────────

    /// Send a raw TDS message
    async fn send_tds_message(&mut self, data: &[u8]) -> Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| OverthroneError::Connection {
                target: self.config.server.clone(),
                reason: "Not connected".to_string(),
            })?;

        stream
            .write_all(data)
            .await
            .map_err(|e| OverthroneError::Connection {
                target: self.config.server.clone(),
                reason: format!("Failed to send TDS message: {}", e),
            })?;

        stream
            .flush()
            .await
            .map_err(|e| OverthroneError::Connection {
                target: self.config.server.clone(),
                reason: format!("Failed to flush: {}", e),
            })?;

        debug!("Sent {} bytes", data.len());
        Ok(())
    }

    /// Receive a complete TDS message, reassembling multiple packets until EOM.
    ///
    /// TDS messages can span multiple TCP packets. Each packet has an 8-byte
    /// header where byte[1] (status) bit 0x01 indicates End-Of-Message.
    /// We must loop until we see EOM.
    async fn receive_tds_message(&mut self) -> Result<Vec<u8>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| OverthroneError::Connection {
                target: self.config.server.clone(),
                reason: "Not connected".to_string(),
            })?;

        let mut full_payload = Vec::new();
        let mut first_header = [0u8; 8];
        let mut is_first = true;

        loop {
            // Read 8-byte TDS packet header
            let mut header = [0u8; 8];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|e| OverthroneError::Connection {
                    target: self.config.server.clone(),
                    reason: format!("Failed to read TDS header: {}", e),
                })?;

            if is_first {
                first_header = header;
                is_first = false;
            }

            let status = header[1];
            let length = u16::from_be_bytes([header[2], header[3]]) as usize;
            let remaining = length.saturating_sub(8);

            // Read packet payload
            if remaining > 0 {
                let mut buf = vec![0u8; remaining];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| OverthroneError::Connection {
                        target: self.config.server.clone(),
                        reason: format!("Failed to read TDS payload: {}", e),
                    })?;
                full_payload.extend_from_slice(&buf);
            }

            // EOM = status bit 0x01 set
            if (status & 0x01) != 0 {
                break;
            }
        }

        // Reassemble: first packet header + combined payload
        let total = 8 + full_payload.len();
        first_header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        let mut result = Vec::with_capacity(total);
        result.extend_from_slice(&first_header);
        result.extend_from_slice(&full_payload);

        debug!(
            "Received TDS: type=0x{:02X}, total_len={}",
            first_header[0], total
        );
        Ok(result)
    }

    // ───────────────────────────────────────────────────────
    // SQL Batch
    // ───────────────────────────────────────────────────────

    /// Execute a SQL query and return parsed results
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

    /// Build SQL Batch TDS message (MS-TDS 2.2.6.7)
    ///
    /// Format: TDS Header(8) + ALL_HEADERS(22) + SQL_TEXT(UTF-16LE)
    fn build_sql_batch(&mut self, sql: &str) -> Vec<u8> {
        // Convert SQL to UTF-16LE
        let sql_utf16: Vec<u8> = sql.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        // ALL_HEADERS section (MS-TDS 2.2.6.6):
        //   TotalLength(4) + [HeaderLength(4) + HeaderType(2) + TxnDescriptor(8) + Outstanding(4)]
        //   = 4 + 18 = 22 bytes
        let all_headers_size: usize = 22;
        let total_len = 8 + all_headers_size + sql_utf16.len();

        let mut msg = Vec::with_capacity(total_len);

        // TDS Header
        msg.push(0x01); // Type: SQL Batch
        msg.push(0x01); // Status: EOM
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(0x00); // SPID high
        msg.push(0x00); // SPID low
        msg.push(self.packet_id);
        self.packet_id = self.packet_id.wrapping_add(1);
        msg.push(0x00); // Window

        // ALL_HEADERS
        let header_data_len: u32 = 4 + 2 + 8 + 4; // = 18
        let total_headers_len: u32 = 4 + header_data_len; // = 22
        msg.extend_from_slice(&total_headers_len.to_le_bytes()); // TotalLength
        msg.extend_from_slice(&header_data_len.to_le_bytes()); // HeaderLength
        msg.extend_from_slice(&0x0002u16.to_le_bytes()); // HeaderType: Transaction descriptor
        msg.extend_from_slice(&0u64.to_le_bytes()); // TransactionDescriptor (no active txn)
        msg.extend_from_slice(&1u32.to_le_bytes()); // OutstandingRequestCount

        // SQL text (UTF-16LE)
        msg.extend_from_slice(&sql_utf16);

        msg
    }

    // ───────────────────────────────────────────────────────
    // Response Parsing
    // ───────────────────────────────────────────────────────

    /// Parse query response tokens
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

        let mut pos = 8; // After TDS header

        while pos < data.len() {
            let token = data[pos];
            pos += 1;

            match token {
                // COLMETADATA (0x81)
                0x81 => {
                    let (new_pos, columns, types, col_type_ids) =
                        self.parse_colmetadata(&data[pos..])?;
                    pos += new_pos;
                    result.columns = columns;
                    result.column_types = types;
                    self.current_col_types = col_type_ids;
                }

                // ROW (0xD1)
                0xD1 => {
                    let (new_pos, row) = self.parse_row(&data[pos..], &result.columns.len())?;
                    pos += new_pos;
                    result.rows.push(row);
                }

                // NBCROW (0xD2)
                0xD2 => {
                    let (new_pos, row) = self.parse_nbcrow(&data[pos..], &result.columns.len())?;
                    pos += new_pos;
                    result.rows.push(row);
                }

                // DONE (0xFD) / DONEPROC (0xFE)
                0xFD | 0xFE => {
                    if pos + 8 <= data.len() {
                        let _done_status = u16::from_le_bytes([data[pos], data[pos + 1]]);
                        let _cur_cmd = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
                        // DoneRowCount is 8 bytes in TDS 7.2+
                        let rows_affected = u64::from_le_bytes([
                            data[pos + 4],
                            data[pos + 5],
                            data[pos + 6],
                            data[pos + 7],
                            if pos + 8 < data.len() {
                                data[pos + 8]
                            } else {
                                0
                            },
                            if pos + 9 < data.len() {
                                data[pos + 9]
                            } else {
                                0
                            },
                            if pos + 10 < data.len() {
                                data[pos + 10]
                            } else {
                                0
                            },
                            if pos + 11 < data.len() {
                                data[pos + 11]
                            } else {
                                0
                            },
                        ]);
                        result.rows_affected = rows_affected;
                    }
                    break;
                }

                // DONEINPROC (0xFF)
                0xFF => {
                    // Skip: status(2) + curcmd(2) + rowcount(8) = 12 bytes
                    if pos + 12 <= data.len() {
                        pos += 12;
                    } else {
                        break;
                    }
                }

                // RETURNSTATUS (0x79)
                0x79 => {
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

                // ORDER (0xA9)
                0xA9 => {
                    if pos + 2 <= data.len() {
                        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                        pos += 2 + len;
                    } else {
                        break;
                    }
                }

                // INFO (0xAB) / ERROR (0xAA)
                0xAA | 0xAB => {
                    if pos + 2 <= data.len() {
                        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                        if token == 0xAA {
                            warn!("SQL Server ERROR token in query response");
                        }
                        pos += 2 + len;
                    } else {
                        break;
                    }
                }

                // ENVCHANGE (0xE3)
                0xE3 => {
                    if pos + 2 <= data.len() {
                        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                        pos += 2 + len;
                    } else {
                        break;
                    }
                }

                // Padding/end
                0x00 => break,

                // Unknown — bail
                _ => {
                    debug!("Unknown response token: 0x{:02X} at pos {}", token, pos - 1);
                    // Try to skip if length-prefixed
                    if pos + 2 <= data.len() {
                        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                        if len < 65535 && pos + 2 + len <= data.len() {
                            pos += 2 + len;
                            continue;
                        }
                    }
                    break;
                }
            }
        }

        Ok(result)
    }

    /// Parse COLMETADATA token (MS-TDS 2.2.7.4)
    ///
    /// Returns (bytes_consumed, column_names, type_names, type_ids)
    fn parse_colmetadata(&self, data: &[u8]) -> Result<(usize, Vec<String>, Vec<String>, Vec<u8>)> {
        if data.len() < 2 {
            return Ok((0, Vec::new(), Vec::new(), Vec::new()));
        }

        let column_count = u16::from_le_bytes([data[0], data[1]]) as usize;

        // 0xFFFF means no metadata
        if column_count == 0xFFFF {
            return Ok((2, Vec::new(), Vec::new(), Vec::new()));
        }

        let mut pos = 2;
        let mut columns = Vec::with_capacity(column_count);
        let mut types = Vec::with_capacity(column_count);
        let mut type_ids = Vec::with_capacity(column_count);

        for _ in 0..column_count {
            if pos + 6 > data.len() {
                break;
            }

            // UserType (4 bytes) + Flags (2 bytes)
            pos += 6;

            if pos >= data.len() {
                break;
            }

            // TYPE_INFO
            let type_id = data[pos];
            pos += 1;
            type_ids.push(type_id);

            let type_name = match type_id {
                // Fixed-length types
                0x1F => "null",
                0x30 => "tinyint",
                0x32 => "bit",
                0x34 => "smallint",
                0x38 => "int",
                0x3A => "smalldatetime",
                0x3B => "real",
                0x3C => "money",
                0x3D => "datetime",
                0x3E => "float",
                0x7A => "smallmoney",
                0x7F => "bigint",
                // Variable-length types
                0x24 => "uniqueidentifier",
                0x26 => "intn",
                0x68 => "bitn",
                0x6A => "decimaln",
                0x6C => "numericn",
                0x6D => "floatn",
                0x6E => "moneyn",
                0x6F => "datetimn",
                0x28 => "date",
                0x29 => "time",
                0x2A => "datetime2",
                0x2B => "datetimeoffset",
                0xA5 => "varbinary",
                0xA7 => "varchar",
                0xAD => "binary",
                0xAF => "char",
                0xE7 => "nvarchar",
                0xEF => "nchar",
                // Long types
                0x22 => "image",
                0x23 => "text",
                0x63 => "ntext",
                0x62 => "sql_variant",
                0xF1 => "xml",
                _ => "unknown",
            };
            types.push(type_name.to_string());

            // Parse type-specific metadata (length, precision, scale, collation)
            match type_id {
                // Fixed-length: no additional bytes
                0x1F | 0x30 | 0x32 | 0x34 | 0x38 | 0x3A | 0x3B | 0x3C | 0x3D | 0x3E | 0x7A
                | 0x7F => {}

                // 1-byte length prefix (intn, bitn, floatn, moneyn, datetimn)
                0x24 | 0x26 | 0x68 | 0x6D | 0x6E | 0x6F => {
                    if pos < data.len() {
                        pos += 1;
                    } // maxlen
                }

                // decimaln / numericn: length + precision + scale
                0x6A | 0x6C => {
                    if pos + 3 <= data.len() {
                        pos += 3;
                    }
                }

                // date: no extra (fixed 3 bytes)
                0x28 => {}

                // time, datetime2, datetimeoffset: 1-byte scale
                0x29..=0x2B => {
                    if pos < data.len() {
                        pos += 1;
                    }
                }

                // varbinary, binary: 2-byte maxlen
                0xA5 | 0xAD => {
                    if pos + 2 <= data.len() {
                        pos += 2;
                    }
                }

                // varchar, char: 2-byte maxlen + 5-byte collation
                0xA7 | 0xAF => {
                    if pos + 7 <= data.len() {
                        pos += 7;
                    }
                }

                // nvarchar, nchar: 2-byte maxlen + 5-byte collation
                0xE7 | 0xEF => {
                    if pos + 7 <= data.len() {
                        pos += 7;
                    }
                }

                // text, ntext, image: 4-byte maxlen + (table name etc.)
                0x22 | 0x23 | 0x63 => {
                    if pos + 4 <= data.len() {
                        pos += 4;
                    } // text_ptr_len
                    // Skip collation for text/ntext
                    if (type_id == 0x23 || type_id == 0x63)
                        && pos + 5 <= data.len() {
                            pos += 5;
                        }
                    // Table name: numParts(1) then for each: len(2) + UTF16
                    if pos < data.len() {
                        let num_parts = data[pos] as usize;
                        pos += 1;
                        for _ in 0..num_parts {
                            if pos + 2 > data.len() {
                                break;
                            }
                            let part_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                            pos += 2 + part_len * 2;
                        }
                    }
                }

                // sql_variant: 4-byte maxlen
                0x62 => {
                    if pos + 4 <= data.len() {
                        pos += 4;
                    }
                }

                // xml: 1 byte schema info
                0xF1 => {
                    if pos < data.len() {
                        let schema_present = data[pos];
                        pos += 1;
                        if schema_present != 0 {
                            // Skip schema: dbname + owning_schema + xml_schema_collection
                            for _ in 0..3 {
                                if pos + 2 > data.len() {
                                    break;
                                }
                                let slen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                                pos += 2 + slen * 2;
                            }
                        }
                    }
                }

                // Unknown type — skip 1 byte and hope for the best
                _ => {
                    if pos < data.len() {
                        pos += 1;
                    }
                }
            }

            // Column name: B_VARCHAR (1-byte length in chars, then UTF-16LE)
            if pos >= data.len() {
                break;
            }
            let name_chars = data[pos] as usize;
            pos += 1;
            let name_bytes = name_chars * 2;
            if pos + name_bytes > data.len() {
                break;
            }

            let name = utf16le_to_string(&data[pos..pos + name_bytes]);
            columns.push(name);
            pos += name_bytes;
        }

        Ok((pos, columns, types, type_ids))
    }

    /// Parse ROW token data (MS-TDS 2.2.7.17)
    ///
    /// Each column value is length-prefixed according to its type:
    /// - Fixed-length types: inline (1/2/4/8 bytes based on type)
    /// - Variable-length (bytelen): 1 byte length, 0xFF = NULL
    /// - Variable-length (ushortlen): 2 byte length, 0xFFFF = NULL
    /// - NVARCHAR/VARCHAR(MAX): 8 bytes, 0xFFFFFFFFFFFFFFFF = NULL (PLP)
    fn parse_row(&self, data: &[u8], col_count: &usize) -> Result<(usize, Vec<Option<String>>)> {
        let mut pos = 0;
        let mut row = Vec::with_capacity(*col_count);

        for col_idx in 0..*col_count {
            if pos >= data.len() {
                row.push(None);
                continue;
            }

            let type_id = self.current_col_types.get(col_idx).copied().unwrap_or(0);

            match type_id {
                // ── Fixed-length types (no length prefix) ──
                0x30 => {
                    // tinyint: 1 byte
                    if pos < data.len() {
                        row.push(Some(data[pos].to_string()));
                        pos += 1;
                    } else {
                        row.push(None);
                    }
                }
                0x32 => {
                    // bit: 1 byte
                    if pos < data.len() {
                        row.push(Some(if data[pos] != 0 { "1" } else { "0" }.to_string()));
                        pos += 1;
                    } else {
                        row.push(None);
                    }
                }
                0x34 => {
                    // smallint: 2 bytes
                    if pos + 2 <= data.len() {
                        let v = i16::from_le_bytes([data[pos], data[pos + 1]]);
                        row.push(Some(v.to_string()));
                        pos += 2;
                    } else {
                        row.push(None);
                    }
                }
                0x38 => {
                    // int: 4 bytes
                    if pos + 4 <= data.len() {
                        let v = i32::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                        ]);
                        row.push(Some(v.to_string()));
                        pos += 4;
                    } else {
                        row.push(None);
                    }
                }
                0x7F => {
                    // bigint: 8 bytes
                    if pos + 8 <= data.len() {
                        let v = i64::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                            data[pos + 4],
                            data[pos + 5],
                            data[pos + 6],
                            data[pos + 7],
                        ]);
                        row.push(Some(v.to_string()));
                        pos += 8;
                    } else {
                        row.push(None);
                    }
                }
                0x3E => {
                    // float: 8 bytes
                    if pos + 8 <= data.len() {
                        let v = f64::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                            data[pos + 4],
                            data[pos + 5],
                            data[pos + 6],
                            data[pos + 7],
                        ]);
                        row.push(Some(v.to_string()));
                        pos += 8;
                    } else {
                        row.push(None);
                    }
                }
                0x3B => {
                    // real: 4 bytes
                    if pos + 4 <= data.len() {
                        let v = f32::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                        ]);
                        row.push(Some(v.to_string()));
                        pos += 4;
                    } else {
                        row.push(None);
                    }
                }

                // ── Byte-length nullable types (INTN, BITN, FLTN, MONEYN, DATETIMN) ──
                0x26 | 0x68 | 0x6D | 0x6E | 0x6F => {
                    if pos >= data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = data[pos] as usize;
                    pos += 1;
                    if len == 0 {
                        row.push(None); // NULL
                    } else if pos + len <= data.len() {
                        let value = parse_fixed_numeric(&data[pos..pos + len], type_id);
                        row.push(Some(value));
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }

                // ── DECIMALN / NUMERICN (byte-length: length + sign + value) ──
                0x6A | 0x6C => {
                    if pos >= data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = data[pos] as usize;
                    pos += 1;
                    if len == 0 {
                        row.push(None);
                    } else if pos + len <= data.len() {
                        // For simplicity, render as hex; a full impl would parse sign + integer
                        let hex: String = data[pos..pos + len]
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect();
                        row.push(Some(hex));
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }

                // ── GUID (0x24): byte-length-prefix, 16 bytes or 0 (NULL) ──
                0x24 => {
                    if pos >= data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = data[pos] as usize;
                    pos += 1;
                    if len == 0 {
                        row.push(None);
                    } else if len == 16 && pos + 16 <= data.len() {
                        // Format as standard GUID
                        let g = &data[pos..pos + 16];
                        let guid = format!(
                            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                            g[3],
                            g[2],
                            g[1],
                            g[0],
                            g[5],
                            g[4],
                            g[7],
                            g[6],
                            g[8],
                            g[9],
                            g[10],
                            g[11],
                            g[12],
                            g[13],
                            g[14],
                            g[15]
                        );
                        row.push(Some(guid));
                        pos += 16;
                    } else {
                        pos += len;
                        row.push(None);
                    }
                }

                // ── NVARCHAR / NCHAR (ushort-length prefix, UTF-16LE) ──
                0xE7 | 0xEF => {
                    if pos + 2 > data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if len == 0xFFFF {
                        row.push(None); // NULL
                    } else if pos + len <= data.len() {
                        let s = utf16le_to_string(&data[pos..pos + len]);
                        row.push(Some(s));
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }

                // ── VARCHAR / CHAR (ushort-length prefix, single-byte encoding) ──
                0xA7 | 0xAF => {
                    if pos + 2 > data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if len == 0xFFFF {
                        row.push(None);
                    } else if pos + len <= data.len() {
                        let s = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
                        row.push(Some(s));
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }

                // ── VARBINARY / BINARY (ushort-length prefix) ──
                0xA5 | 0xAD => {
                    if pos + 2 > data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if len == 0xFFFF {
                        row.push(None);
                    } else if pos + len <= data.len() {
                        let hex: String = data[pos..pos + len]
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect();
                        row.push(Some(format!("0x{}", hex)));
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }

                // ── DATE (0x28): 1 byte len, 3 bytes data ──
                0x28 => {
                    if pos >= data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = data[pos] as usize;
                    pos += 1;
                    if len == 0 {
                        row.push(None);
                    } else if pos + len <= data.len() {
                        let hex: String = data[pos..pos + len]
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect();
                        row.push(Some(hex));
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }

                // ── TIME / DATETIME2 / DATETIMEOFFSET: byte-length prefix ──
                0x29..=0x2B => {
                    if pos >= data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = data[pos] as usize;
                    pos += 1;
                    if len == 0 {
                        row.push(None);
                    } else if pos + len <= data.len() {
                        let hex: String = data[pos..pos + len]
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect();
                        row.push(Some(hex));
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }

                // ── Fallback: try byte-length prefix ──
                _ => {
                    if pos >= data.len() {
                        row.push(None);
                        continue;
                    }
                    let len = data[pos] as usize;
                    pos += 1;
                    if len == 0xFF {
                        row.push(None); // NULL for byte-length types
                    } else if len == 0 {
                        row.push(Some(String::new()));
                    } else if pos + len <= data.len() {
                        // Heuristic: if even length and all looks like UTF-16, decode
                        if len % 2 == 0 {
                            let s = utf16le_to_string(&data[pos..pos + len]);
                            row.push(Some(s));
                        } else {
                            let hex: String = data[pos..pos + len]
                                .iter()
                                .map(|b| format!("{:02X}", b))
                                .collect();
                            row.push(Some(hex));
                        }
                        pos += len;
                    } else {
                        row.push(None);
                    }
                }
            }
        }

        Ok((pos, row))
    }

    /// Parse NBCROW (Null-Bit Compressed Row) token (MS-TDS 2.2.7.13)
    fn parse_nbcrow(&self, data: &[u8], col_count: &usize) -> Result<(usize, Vec<Option<String>>)> {
        let mut pos = 0;

        // Null bitmap: ceil(col_count / 8) bytes
        let bitmap_bytes = (*col_count).div_ceil(8);
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
                let type_id = self.current_col_types.get(i).copied().unwrap_or(0);

                // Use the same logic as parse_row for non-null values
                match type_id {
                    // NVARCHAR/NCHAR: ushort prefix
                    0xE7 | 0xEF => {
                        if pos + 2 <= data.len() {
                            let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                            pos += 2;
                            if len != 0xFFFF && pos + len <= data.len() {
                                row.push(Some(utf16le_to_string(&data[pos..pos + len])));
                                pos += len;
                            } else {
                                row.push(None);
                            }
                        } else {
                            row.push(None);
                        }
                    }

                    // VARCHAR/CHAR: ushort prefix
                    0xA7 | 0xAF => {
                        if pos + 2 <= data.len() {
                            let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                            pos += 2;
                            if len != 0xFFFF && pos + len <= data.len() {
                                row.push(Some(
                                    String::from_utf8_lossy(&data[pos..pos + len]).to_string(),
                                ));
                                pos += len;
                            } else {
                                row.push(None);
                            }
                        } else {
                            row.push(None);
                        }
                    }

                    // Byte-length types
                    _ => {
                        let len = data[pos] as usize;
                        pos += 1;
                        if len == 0 {
                            row.push(Some(String::new()));
                        } else if pos + len <= data.len() {
                            if len % 2 == 0 {
                                row.push(Some(utf16le_to_string(&data[pos..pos + len])));
                            } else {
                                let hex: String = data[pos..pos + len]
                                    .iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect();
                                row.push(Some(hex));
                            }
                            pos += len;
                        } else {
                            row.push(None);
                        }
                    }
                }
            } else {
                row.push(None);
            }
        }

        Ok((pos, row))
    }

    // ───────────────────────────────────────────────────────
    // High-level Operations
    // ───────────────────────────────────────────────────────

    /// Execute a SQL statement (returns rows affected)
    pub async fn execute(&mut self, sql: &str) -> Result<u64> {
        let result = self.query(sql).await?;
        Ok(result.rows_affected)
    }

    /// Enable xp_cmdshell
    pub async fn enable_xp_cmdshell(&mut self) -> Result<()> {
        debug!("Enabling xp_cmdshell");
        self.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
            .await?;
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
        let escaped = command.replace('\'', "''");
        let sql = format!("EXEC xp_cmdshell '{}';", escaped);
        let result = self.query(&sql).await?;

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
                "SELECT name, product, provider, data_source, catalog, \
                 is_rpc_out_enabled, is_data_access_enabled \
                 FROM sys.servers WHERE is_linked = 1;",
            )
            .await?;

        let mut servers = Vec::new();
        for row in &result.rows {
            if row.len() >= 7 {
                servers.push(LinkedServer {
                    name: row[0].clone().unwrap_or_default(),
                    product: row[1].clone(),
                    data_source: row[3].clone().unwrap_or_default(),
                    provider: row[2].clone().unwrap_or_default(),
                    catalog: row[4].clone(),
                    rpc_out_enabled: row[5].as_ref().map(|v| v == "1").unwrap_or(false),
                    data_access_enabled: row[6].as_ref().map(|v| v == "1").unwrap_or(false),
                });
            }
        }

        Ok(servers)
    }

    /// Execute query on linked server via OPENQUERY
    pub async fn execute_on_linked_server(
        &mut self,
        server: &str,
        query: &str,
    ) -> Result<MssqlQueryResult> {
        let escaped_query = query.replace('\'', "''");
        let sql = format!(
            "SELECT * FROM OPENQUERY([{}], '{}');",
            server, escaped_query
        );
        self.query(&sql).await
    }

    /// Close the connection gracefully
    pub async fn close(&mut self) -> Result<()> {
        if self.connected {
            // Send Attention message (type 0x06) to signal disconnect
            let logout = vec![0x06, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
            let _ = self.send_tds_message(&logout).await;
            self.connected = false;
            self.logged_in = false;
        }
        Ok(())
    }
}

impl Drop for MssqlClient {
    fn drop(&mut self) {
        // Best-effort close; can't do async in Drop
    }
}

// ═══════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════

/// Encode a &str to UTF-16LE bytes
fn str_to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Decode UTF-16LE bytes to a String
fn utf16le_to_string(data: &[u8]) -> String {
    data.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<u16>>().to_vec()
        .as_slice()
        .iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('\u{FFFD}'))
        .collect()
}

/// Parse a fixed-length numeric value from raw bytes
fn parse_fixed_numeric(data: &[u8], _type_hint: u8) -> String {
    match data.len() {
        1 => (data[0] as i8).to_string(),
        2 => i16::from_le_bytes([data[0], data[1]]).to_string(),
        4 => i32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        8 => i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
        _ => {
            // Fallback: hex
            data.iter().map(|b| format!("{:02X}", b)).collect()
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Tests
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
        assert_eq!(
            result.get_by_name(1, "name"),
            Some(&Some("Bob".to_string()))
        );
    }

    #[test]
    fn test_build_prelogin_structure() {
        let config = MssqlConfig::new("127.0.0.1");
        let mut client = MssqlClient::new(config);
        let prelogin = client.build_prelogin();

        // TDS header checks
        assert_eq!(prelogin[0], 0x12, "Type should be PreLogin");
        assert_eq!(prelogin[1], 0x01, "Status should be EOM");

        let len = u16::from_be_bytes([prelogin[2], prelogin[3]]) as usize;
        assert_eq!(
            len,
            prelogin.len(),
            "Length field should match actual length"
        );

        // First token should be VERSION (0x00)
        assert_eq!(prelogin[8], 0x00, "First token should be VERSION");
    }

    #[test]
    fn test_build_sql_batch_all_headers() {
        let config = MssqlConfig::new("127.0.0.1");
        let mut client = MssqlClient::new(config);
        client.logged_in = true;
        let batch = client.build_sql_batch("SELECT 1");

        // TDS header
        assert_eq!(batch[0], 0x01, "Type should be SQL Batch");
        assert_eq!(batch[1], 0x01, "Status should be EOM");

        // ALL_HEADERS: total length should be 22
        let total_headers = u32::from_le_bytes([batch[8], batch[9], batch[10], batch[11]]);
        assert_eq!(total_headers, 22, "ALL_HEADERS total should be 22");

        // Header type should be 0x0002 (transaction descriptor)
        let header_type = u16::from_le_bytes([batch[16], batch[17]]);
        assert_eq!(header_type, 0x0002, "Header type should be txn descriptor");
    }

    #[test]
    fn test_str_to_utf16le() {
        let result = str_to_utf16le("AB");
        assert_eq!(result, vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn test_utf16le_to_string() {
        let data = vec![0x41, 0x00, 0x42, 0x00];
        assert_eq!(utf16le_to_string(&data), "AB");
    }
}
