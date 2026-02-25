//! Cobalt Strike External C2 + Aggressor Script integration
//!
//! Two integration modes:
//! 1. **TeamServer connection** — Connect as operator via the TeamServer's
//!    management port. Uses the Cobalt Strike Aggressor Script engine to
//!    issue commands to beacons.
//! 2. **External C2** — Act as an External C2 channel (RFC: ExternalC2 spec)
//!    for custom transport.
//!
//! This module implements Mode 1 (operator integration).
//! Connection protocol: TCP to teamserver port (default 50050)

use super::{
    C2Auth, C2Channel, C2Config, C2Framework, C2Listener, C2Session, C2TaskResult, ImplantRequest,
    SessionType,
};
use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Cobalt Strike teamserver connection
pub struct CobaltStrikeChannel {
    /// TCP connection to teamserver
    stream: Option<TcpStream>,
    /// Connected state
    connected: bool,
    /// Cached beacon list
    beacons: Vec<CsBeacon>,
    /// Pending task callbacks
    pending_tasks: HashMap<String, tokio::sync::oneshot::Sender<C2TaskResult>>,
    /// Teamserver metadata
    server_info: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsBeacon {
    id: String,
    internal_ip: String,
    external_ip: String,
    user: String,
    computer: String,
    os: String,
    process: String,
    pid: u32,
    arch: String,
    is_admin: bool,
    last: String,
    sleep: u32,
    jitter: u32,
    listener: String,
}

impl CobaltStrikeChannel {
    pub fn new() -> Self {
        Self {
            stream: None,
            connected: false,
            beacons: Vec::new(),
            pending_tasks: HashMap::new(),
            server_info: HashMap::new(),
        }
    }

    /// Send a raw Aggressor command to the teamserver
    async fn send_aggressor(&mut self, command: &str) -> Result<String> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| OverthroneError::C2("Not connected to Cobalt Strike".to_string()))?;

        // CS teamserver protocol: 4-byte length prefix + UTF-8 data
        let data = command.as_bytes();
        let len = (data.len() as u32).to_be_bytes();

        stream
            .write_all(&len)
            .await
            .map_err(|e| OverthroneError::C2(format!("Write error: {}", e)))?;
        stream
            .write_all(data)
            .await
            .map_err(|e| OverthroneError::C2(format!("Write error: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| OverthroneError::C2(format!("Flush error: {}", e)))?;

        // Read response: 4-byte length prefix + data
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| OverthroneError::C2(format!("Read error: {}", e)))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        if resp_len > 10 * 1024 * 1024 {
            return Err(OverthroneError::C2(format!(
                "Response too large: {} bytes",
                resp_len
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| OverthroneError::C2(format!("Read error: {}", e)))?;

        String::from_utf8(resp_buf)
            .map_err(|e| OverthroneError::C2(format!("Invalid UTF-8 response: {}", e)))
    }

    /// Task a beacon with a command and wait for callback
    async fn task_beacon(&mut self, beacon_id: &str, command: &str) -> Result<C2TaskResult> {
        let task_id = format!("ovt-{}", uuid::Uuid::new_v4().as_simple());

        // Aggressor Sleep script equivalent:
        // btask($bid, "command");
        let aggressor_cmd = format!(
            "btask('{}', '{}');",
            beacon_id.replace('\'', "\\'"),
            command.replace('\'', "\\'")
        );

        let response = self.send_aggressor(&aggressor_cmd).await?;

        // Parse the response — CS returns task acknowledgment immediately,
        // actual results come via callback. For synchronous use, we poll.
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(300); // 5 min timeout

        // Poll for result
        loop {
            if start.elapsed() > timeout {
                return Ok(C2TaskResult {
                    task_id: task_id.clone(),
                    success: false,
                    output: String::new(),
                    error: "Timeout waiting for beacon callback".to_string(),
                    raw_data: None,
                    duration: start.elapsed(),
                });
            }

            // Check for output via: bdata($bid)
            let check_cmd = format!("bdata('{}');", beacon_id);
            let check_result = self.send_aggressor(&check_cmd).await?;

            if !check_result.is_empty() && check_result != "null" {
                return Ok(C2TaskResult {
                    task_id,
                    success: true,
                    output: check_result,
                    error: String::new(),
                    raw_data: None,
                    duration: start.elapsed(),
                });
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

#[async_trait]
impl C2Channel for CobaltStrikeChannel {
    fn framework(&self) -> C2Framework {
        C2Framework::CobaltStrike
    }

    async fn connect(&mut self, config: &C2Config) -> Result<()> {
        let addr = format!("{}:{}", config.host, config.port);
        log::info!("[c2:cs] Connecting to Cobalt Strike at {}", addr);

        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| OverthroneError::C2(format!("Connection timeout to {}", addr)))?
            .map_err(|e| OverthroneError::C2(format!("Connection failed to {}: {}", addr, e)))?;

        self.stream = Some(stream);

        // Authenticate
        let password = match &config.auth {
            C2Auth::Password { password } => password.clone(),
            _ => {
                return Err(OverthroneError::C2(
                    "Cobalt Strike requires password authentication".to_string(),
                ));
            }
        };

        // CS teamserver auth: send password hash
        let auth_cmd = format!("auth('{}')", password.replace('\'', "\\'"));
        let auth_result = self.send_aggressor(&auth_cmd).await?;

        if auth_result.contains("error") || auth_result.contains("denied") {
            return Err(OverthroneError::C2(format!(
                "Authentication failed: {}",
                auth_result
            )));
        }

        self.connected = true;
        log::info!("[c2:cs] Authenticated to Cobalt Strike teamserver");

        // Get server info
        let version = self.send_aggressor("version()").await.unwrap_or_default();
        self.server_info.insert("version".to_string(), version);

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
        self.connected = false;
        log::info!("[c2:cs] Disconnected from Cobalt Strike");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        let sessions: Vec<C2Session> = self
            .beacons
            .iter()
            .map(|b| C2Session {
                id: b.id.clone(),
                hostname: b.computer.clone(),
                ip: b.internal_ip.clone(),
                username: b.user.clone(),
                domain: b.user.split('\\').next().unwrap_or("").to_string(),
                process: b.process.clone(),
                pid: b.pid,
                arch: b.arch.clone(),
                os: b.os.clone(),
                elevated: b.is_admin,
                session_type: SessionType::Beacon,
                last_seen: b.last.clone(),
                sleep_interval: Some(Duration::from_secs(b.sleep as u64)),
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("listener".to_string(), b.listener.clone());
                    m.insert("jitter".to_string(), b.jitter.to_string());
                    m
                },
            })
            .collect();

        Ok(sessions)
    }

    async fn get_session(&self, session_id: &str) -> Result<C2Session> {
        self.list_sessions()
            .await?
            .into_iter()
            .find(|s| s.id == session_id)
            .ok_or_else(|| OverthroneError::C2(format!("Beacon {} not found", session_id)))
    }

    async fn exec_command(&self, session_id: &str, command: &str) -> Result<C2TaskResult> {
        // Must use mutable self — clone needed for the sync wrapper
        Err(OverthroneError::C2(
            "Use exec_powershell for Cobalt Strike — shell commands go via bshell()".to_string(),
        ))
    }

    async fn exec_powershell(&self, session_id: &str, script: &str) -> Result<C2TaskResult> {
        Err(OverthroneError::C2(
            "Requires mutable access — use CobaltStrikeChannel directly".to_string(),
        ))
    }

    async fn upload_file(
        &self,
        session_id: &str,
        local_data: &[u8],
        remote_path: &str,
    ) -> Result<C2TaskResult> {
        Err(OverthroneError::C2(
            "Upload requires mutable access".to_string(),
        ))
    }

    async fn download_file(&self, session_id: &str, remote_path: &str) -> Result<C2TaskResult> {
        Err(OverthroneError::C2(
            "Download requires mutable access".to_string(),
        ))
    }

    async fn execute_assembly(
        &self,
        session_id: &str,
        assembly_data: &[u8],
        args: &str,
    ) -> Result<C2TaskResult> {
        Err(OverthroneError::C2(
            "Execute-assembly requires mutable access".to_string(),
        ))
    }

    async fn execute_bof(
        &self,
        session_id: &str,
        bof_data: &[u8],
        args: &[u8],
    ) -> Result<C2TaskResult> {
        // Cobalt Strike supports inline-execute for BOFs
        Err(OverthroneError::C2(
            "BOF execution requires mutable access".to_string(),
        ))
    }

    async fn list_listeners(&self) -> Result<Vec<C2Listener>> {
        Ok(Vec::new())
    }

    async fn server_info(&self) -> Result<HashMap<String, String>> {
        Ok(self.server_info.clone())
    }
}
