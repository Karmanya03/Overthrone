use std::collections::HashMap;
use std::time::Duration;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::mssql::{MssqlClient, MssqlConfig, MssqlQueryResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct MssqlEnumerator {
    target: String,
    port: u16,
    client: Option<MssqlClient>,
    connected: bool,
}

impl MssqlEnumerator {
    pub fn new(target: &str, port: u16) -> Self {
        Self {
            target: target.to_string(),
            port,
            client: None,
            connected: false,
        }
    }

    pub async fn probe(&mut self) -> Result<HashMap<String, String>> {
        let addr = format!("{}:{}", self.target, self.port);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
            .await
            .map_err(|_| OverthroneError::Connection {
                target: addr.clone(),
                reason: "Connection timeout during probe".to_string(),
            })?
            .map_err(|e| OverthroneError::Connection {
                target: addr.clone(),
                reason: format!("Probe connect failed: {e}"),
            })?;

        let prelogin = build_prelogin_probe();
        stream.write_all(&prelogin).await.map_err(|e| OverthroneError::Connection {
            target: addr.clone(),
            reason: format!("Failed to send prelogin: {e}"),
        })?;

        let mut header = [0u8; 8];
        stream.read_exact(&mut header).await.map_err(|e| OverthroneError::Connection {
            target: addr.clone(),
            reason: format!("Failed to read prelogin response header: {e}"),
        })?;

        let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut payload = vec![0u8; payload_len.saturating_sub(8)];
        stream.read_exact(&mut payload).await.ok();
        let _ = stream.shutdown().await;

        let mut info = HashMap::new();
        info.insert("server".to_string(), self.target.clone());
        info.insert("port".to_string(), self.port.to_string());
        info.insert("tds_type".to_string(), format!("0x{:02X}", header[0]));

        if payload_len >= 8 {
            let mut pos = 0;
            while pos + 5 < payload.len() {
                let token = payload[pos];
                if token == 0xFF { break; }
                let offset = u16::from_be_bytes([payload[pos + 1], payload[pos + 2]]) as usize;
                let length = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
                pos += 5;
                if offset + length <= payload.len() {
                    let data = &payload[offset..offset + length];
                    match token {
                        0x00 => {
                            if length >= 6 {
                                let major = data[0];
                                let minor = data[1];
                                let build = u16::from_be_bytes([data[2], data[3]]);
                                let ver = format!("{}.{}.{}", major, minor, build);
                                info.insert("version".to_string(), ver);
                                let subbuild = u16::from_be_bytes([data[4], data[5]]);
                                info.insert("sub_build".to_string(), subbuild.to_string());
                            }
                        }
                        0x01 => {
                            if length >= 1 {
                                let enc = data[0];
                                info.insert("encryption".to_string(), match enc {
                                    0 => "Not Supported".to_string(),
                                    1 => "Supported".to_string(),
                                    2 => "Required".to_string(),
                                    _ => format!("Unknown({})", enc),
                                });
                            }
                        }
                        0x02 => {
                            if length > 0 {
                                let inst = String::from_utf16_lossy(
                                    &data.chunks_exact(2)
                                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                        .collect::<Vec<_>>()
                                );
                                info.insert("instance_name".to_string(), inst.trim_matches('\0').to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        info!("[MSSQL] Probe complete for {}", self.target);
        Ok(info)
    }

    pub async fn connect_sql_auth(&mut self, username: &str, password: &str) -> Result<()> {
        let mut config = MssqlConfig::new(&self.target);
        config.port = self.port;
        config = config.with_sql_auth(username, password);
        let client = MssqlClient::connect(config).await?;
        self.client = Some(client);
        self.connected = true;
        info!("[MSSQL] Connected as {} to {}", username, self.target);
        Ok(())
    }

    pub async fn query(&mut self, sql: &str) -> Result<Vec<HashMap<String, Option<String>>>> {
        let client = self.client()?;
        let result = client.query(sql).await?;
        Ok(result_set_to_maps(&result))
    }

    pub fn disconnect(&mut self) {
        self.client = None;
        self.connected = false;
        info!("[MSSQL] Disconnected");
    }

    pub async fn run_interactive(&mut self) -> Result<()> {
        println!("MSSQL Enumerator interactive shell for {}:{}", self.target, self.port);
        println!("Commands: probe, connect <user> <pass>, query <sql>, quit");
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();
        loop {
            print!("mssql> ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let line = match lines.next_line().await {
                Ok(Some(l)) => l,
                Ok(None) => break,
                Err(_) => break,
            };
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() { continue; }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            match parts[0] {
                "probe" => {
                    match self.probe().await {
                        Ok(info) => {
                            println!("MSSQL Probe results:");
                            let mut keys: Vec<&String> = info.keys().collect();
                            keys.sort();
                            for k in keys {
                                if let Some(v) = info.get(k) {
                                    println!("  {}: {}", k, v);
                                }
                            }
                        }
                        Err(e) => println!("Probe failed: {e}"),
                    }
                }
                "connect" => {
                    if parts.len() < 3 {
                        println!("Usage: connect <username> <password>");
                        continue;
                    }
                    match self.connect_sql_auth(parts[1], parts[2]).await {
                        Ok(()) => println!("Connected to {}:{}", self.target, self.port),
                        Err(e) => println!("Connect failed: {e}"),
                    }
                }
                "query" => {
                    if !self.connected { println!("Not connected. Use 'connect' first."); continue; }
                    if parts.len() < 2 {
                        println!("Usage: query <sql>");
                        continue;
                    }
                    let sql = parts[1..].join(" ");
                    match self.query(&sql).await {
                        Ok(rows) => {
                            println!("Query results ({} rows):", rows.len());
                            if rows.is_empty() {
                                println!("  (empty)");
                            } else {
                                let headers: Vec<&String> = rows[0].keys().collect();
                                println!("  Columns: {}", headers.iter().map(|h| h.as_str()).collect::<Vec<_>>().join(", "));
                                for (i, row) in rows.iter().enumerate() {
                                    let vals: Vec<String> = headers.iter()
                                        .map(|h| row.get(*h).unwrap_or(&None).as_deref().unwrap_or("NULL").to_string())
                                        .collect();
                                    println!("  Row {}: {}", i + 1, vals.join(", "));
                                }
                            }
                        }
                        Err(e) => println!("Query failed: {e}"),
                    }
                }
                "quit" | "exit" => break,
                _ => println!("Unknown command: {}", parts[0]),
            }
        }
        self.disconnect();
        Ok(())
    }

    fn client(&mut self) -> Result<&mut MssqlClient> {
        self.client.as_mut().ok_or_else(|| OverthroneError::Connection {
            target: self.target.clone(),
            reason: format!("MSSQL not connected to {}", self.target),
        })
    }
}

fn result_set_to_maps(result: &MssqlQueryResult) -> Vec<HashMap<String, Option<String>>> {
    let mut rows = Vec::new();
    for row in &result.rows {
        let mut map = HashMap::new();
        for (i, col_name) in result.columns.iter().enumerate() {
            if i < row.len() {
                map.insert(col_name.clone(), row[i].clone());
            }
        }
        rows.push(map);
    }
    rows
}

fn build_prelogin_probe() -> Vec<u8> {
    let version_data: [u8; 6] = [0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00];
    let encryption_data: [u8; 1] = [0x02];
    let instopt_data: [u8; 1] = [0x00];
    let threadid_data: [u8; 4] = [0x00; 4];
    let tokens: &[(&[u8], u8)] = &[
        (&version_data, 0x00),
        (&encryption_data, 0x01),
        (&instopt_data, 0x02),
        (&threadid_data, 0x03),
    ];
    let token_headers_size = tokens.len() * 5 + 1;
    let mut data_offset = token_headers_size as u16;
    let mut payload = Vec::new();
    for (data, token_type) in tokens {
        payload.push(*token_type);
        payload.extend_from_slice(&data_offset.to_be_bytes());
        payload.extend_from_slice(&(data.len() as u16).to_be_bytes());
        data_offset += data.len() as u16;
    }
    payload.push(0xFF);
    for (data, _) in tokens {
        payload.extend_from_slice(data);
    }
    let total_len = 8 + payload.len();
    let mut msg = Vec::with_capacity(total_len);
    msg.push(0x12);
    msg.push(0x01);
    msg.extend_from_slice(&(total_len as u16).to_be_bytes());
    msg.push(0x00);
    msg.push(0x00);
    msg.push(0x01);
    msg.push(0x00);
    msg.extend_from_slice(&payload);
    msg
}


