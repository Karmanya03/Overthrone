//! C2 Framework Integration
//!
//! Provides a unified interface to interact with external C2 frameworks:
//! - **Cobalt Strike** — External C2 protocol (TCP listener) + Aggressor Script
//! - **Sliver** — gRPC operator API
//! - **Havoc** — Demon agent integration via REST API
//!
//! Overthrone acts as an **operator-side integration**, meaning it:
//! 1. Connects to an existing C2 teamserver as an operator
//! 2. Tasks existing implants to perform AD-specific actions
//! 3. Receives results and feeds them into the attack graph
//! 4. Can request implant deployment on newly compromised targets
//!
//! Overthrone does NOT replace the C2 — it enhances it with AD-specific automation.

pub mod cobalt_strike;
pub mod havoc;
pub mod sliver;

use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ──────────────────────────────────────────────────────────
// C2 Framework abstraction layer
// ──────────────────────────────────────────────────────────

/// Connection configuration for a C2 teamserver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Config {
    /// Which C2 framework
    pub framework: C2Framework,
    /// Teamserver host
    pub host: String,
    /// Teamserver port
    pub port: u16,
    /// Authentication (varies by framework)
    pub auth: C2Auth,
    /// TLS settings
    pub tls: bool,
    /// Skip TLS certificate verification
    pub tls_skip_verify: bool,
    /// Connection timeout
    pub timeout: Duration,
    /// Reconnect on disconnect
    pub auto_reconnect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum C2Framework {
    CobaltStrike,
    Sliver,
    Havoc,
    Custom(String),
}

impl std::fmt::Display for C2Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CobaltStrike => write!(f, "Cobalt Strike"),
            Self::Sliver => write!(f, "Sliver"),
            Self::Havoc => write!(f, "Havoc"),
            Self::Custom(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum C2Auth {
    /// Password-based (Cobalt Strike teamserver)
    Password { password: String },
    /// mTLS certificate (Sliver)
    MtlsCert {
        cert_path: String,
        key_path: String,
        ca_path: String,
    },
    /// Token-based (Havoc, custom)
    Token { token: String },
    /// Sliver operator config file
    SliverConfig { config_path: String },
}

/// Represents a beacon/implant/agent session on the C2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Session {
    /// Session/beacon ID (framework-specific)
    pub id: String,
    /// Hostname of the implanted machine
    pub hostname: String,
    /// IP address
    pub ip: String,
    /// Username running the implant
    pub username: String,
    /// Domain
    pub domain: String,
    /// Process name hosting the implant
    pub process: String,
    /// Process ID
    pub pid: u32,
    /// Architecture (x86/x64)
    pub arch: String,
    /// Operating system
    pub os: String,
    /// Is the session elevated (SYSTEM/admin)?
    pub elevated: bool,
    /// Session type (beacon, session, interactive, etc.)
    pub session_type: SessionType,
    /// Last check-in time
    pub last_seen: String,
    /// Sleep interval (if applicable)
    pub sleep_interval: Option<Duration>,
    /// Framework-specific metadata
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionType {
    /// Cobalt Strike Beacon (async, callback-based)
    Beacon,
    /// Sliver Session (interactive, real-time)
    Session,
    /// Sliver Beacon (async)
    SliverBeacon,
    /// Havoc Demon
    Demon,
    /// Generic interactive session
    Interactive,
}

/// Result from executing a task on an implant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2TaskResult {
    /// Task ID
    pub task_id: String,
    /// Whether the task completed successfully
    pub success: bool,
    /// Command output (stdout)
    pub output: String,
    /// Error output (stderr)
    pub error: String,
    /// Raw bytes (for binary data like downloaded files)
    pub raw_data: Option<Vec<u8>>,
    /// Time taken
    pub duration: Duration,
}

/// Request to deploy an implant on a target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantRequest {
    /// Target hostname or IP
    pub target: String,
    /// Desired implant type
    pub implant_type: ImplantType,
    /// Listener to callback to
    pub listener: String,
    /// Execution method to use for delivery
    pub delivery_method: DeliveryMethod,
    /// Architecture
    pub arch: String,
    /// Whether to use staged or stageless payload
    pub staged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplantType {
    /// Cobalt Strike Beacon
    CsBeacon,
    /// Sliver implant
    SliverImplant,
    /// Havoc Demon
    HavocDemon,
    /// Generic shellcode (provide listener for callback)
    Shellcode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryMethod {
    /// Use Overthrone's exec module (psexec/smbexec/wmi/etc.)
    OverthroneExec,
    /// Upload and run via SMB share
    SmbDrop,
    /// Use WinRM
    WinRM,
    /// Use scheduled task
    ScheduledTask,
    /// Use DCOM
    Dcom,
    /// Framework handles delivery (e.g. CS's jump command)
    FrameworkNative,
}

// ──────────────────────────────────────────────────────────
// C2 Channel trait — unified interface
// ──────────────────────────────────────────────────────────

/// The core C2 integration trait
/// Implement this for each C2 framework
#[async_trait]
pub trait C2Channel: Send + Sync {
    /// Which framework this channel connects to
    fn framework(&self) -> C2Framework;

    /// Connect to the C2 teamserver
    async fn connect(&mut self, config: &C2Config) -> Result<()>;

    /// Disconnect from the teamserver
    async fn disconnect(&mut self) -> Result<()>;

    /// Check if connected
    fn is_connected(&self) -> bool;

    /// List all active sessions/beacons
    async fn list_sessions(&self) -> Result<Vec<C2Session>>;

    /// Get a specific session by ID
    async fn get_session(&self, session_id: &str) -> Result<C2Session>;

    /// Execute a shell command on a session
    async fn exec_command(&self, session_id: &str, command: &str) -> Result<C2TaskResult>;

    /// Execute a PowerShell command on a session
    async fn exec_powershell(&self, session_id: &str, script: &str) -> Result<C2TaskResult>;

    /// Upload a file to the target
    async fn upload_file(
        &self,
        session_id: &str,
        local_data: &[u8],
        remote_path: &str,
    ) -> Result<C2TaskResult>;

    /// Download a file from the target
    async fn download_file(&self, session_id: &str, remote_path: &str) -> Result<C2TaskResult>;

    /// Execute assembly in-memory (Cobalt Strike execute-assembly, Sliver execute-assembly)
    async fn execute_assembly(
        &self,
        _session_id: &str,
        assembly_data: &[u8],
        _args: &str,
    ) -> Result<C2TaskResult>;

    /// Run a BOF (Beacon Object File) — CS-specific but Sliver also supports via COFF loader
    async fn execute_bof(
        &self,
        _session_id: &str,
        _bof_data: &[u8],
        _args: &[u8],
    ) -> Result<C2TaskResult> {
        Err(OverthroneError::C2(format!(
            "{} does not support BOF execution",
            self.framework()
        )))
    }

    /// Inject shellcode into a target process
    async fn shellcode_inject(
        &self,
        _session_id: &str,
        _shellcode: &[u8],
        _target_pid: u32,
    ) -> Result<C2TaskResult> {
        Err(OverthroneError::C2(format!(
            "{} does not support shellcode injection via operator API",
            self.framework()
        )))
    }

    /// Deploy an implant on a new target (lateral movement via C2)
    async fn deploy_implant(&self, _request: &ImplantRequest) -> Result<C2TaskResult> {
        Err(OverthroneError::C2(format!(
            "{} does not support remote implant deployment",
            self.framework()
        )))
    }

    /// List available listeners on the teamserver
    async fn list_listeners(&self) -> Result<Vec<C2Listener>>;

    /// Get framework-specific info (version, operators, etc.)
    async fn server_info(&self) -> Result<HashMap<String, String>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Listener {
    pub name: String,
    pub listener_type: String,
    pub host: String,
    pub port: u16,
    pub active: bool,
}

// ──────────────────────────────────────────────────────────
// C2 Manager — manages connections to multiple C2 frameworks
// ──────────────────────────────────────────────────────────

pub struct C2Manager {
    channels: HashMap<String, Box<dyn C2Channel>>,
    /// Which channel is the default for operations
    default_channel: Option<String>,
}

impl Default for C2Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl C2Manager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            default_channel: None,
        }
    }

    /// Add a C2 channel with a name
    pub fn add_channel(&mut self, name: &str, channel: Box<dyn C2Channel>) {
        if self.channels.is_empty() {
            self.default_channel = Some(name.to_string());
        }
        self.channels.insert(name.to_string(), channel);
    }

    /// Connect a named channel to its teamserver
    pub async fn connect(&mut self, name: &str, config: &C2Config) -> Result<()> {
        let channel = self
            .channels
            .get_mut(name)
            .ok_or_else(|| OverthroneError::C2(format!("C2 channel '{}' not found", name)))?;

        log::info!(
            "[c2] Connecting to {} at {}:{}",
            config.framework,
            config.host,
            config.port
        );
        channel.connect(config).await?;
        log::info!("[c2] Connected to {} teamserver", config.framework);

        Ok(())
    }

    /// Get the default channel
    pub fn default_channel(&self) -> Result<&dyn C2Channel> {
        let name = self
            .default_channel
            .as_ref()
            .ok_or_else(|| OverthroneError::C2("No default C2 channel set".to_string()))?;
        self.channels
            .get(name)
            .map(|c| c.as_ref())
            .ok_or_else(|| OverthroneError::C2(format!("Default C2 channel '{}' not found", name)))
    }

    /// Get a specific channel by name
    pub fn get_channel(&self, name: &str) -> Option<&dyn C2Channel> {
        self.channels.get(name).map(|c| c.as_ref())
    }

    /// Set the default channel
    pub fn set_default(&mut self, name: &str) -> Result<()> {
        if self.channels.contains_key(name) {
            self.default_channel = Some(name.to_string());
            Ok(())
        } else {
            Err(OverthroneError::C2(format!("Channel '{}' not found", name)))
        }
    }

    /// List all channels and their connection status
    pub fn status(&self) -> Vec<(&str, C2Framework, bool)> {
        self.channels
            .iter()
            .map(|(name, ch)| (name.as_str(), ch.framework(), ch.is_connected()))
            .collect()
    }

    /// Find a session across all connected C2 frameworks by hostname
    pub async fn find_session_by_host(&self, hostname: &str) -> Result<(String, C2Session)> {
        for (name, channel) in &self.channels {
            if !channel.is_connected() {
                continue;
            }

            if let Ok(sessions) = channel.list_sessions().await {
                for session in sessions {
                    if session.hostname.eq_ignore_ascii_case(hostname) {
                        return Ok((name.clone(), session));
                    }
                }
            }
        }

        Err(OverthroneError::C2(format!(
            "No session found for hostname '{}' across any C2",
            hostname
        )))
    }

    /// Disconnect all channels
    pub async fn disconnect_all(&mut self) {
        for (name, channel) in &mut self.channels {
            if channel.is_connected()
                && let Err(e) = channel.disconnect().await {
                    log::warn!("[c2] Error disconnecting '{}': {}", name, e);
                }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2_framework_display() {
        assert_eq!(C2Framework::CobaltStrike.to_string(), "Cobalt Strike");
        assert_eq!(C2Framework::Sliver.to_string(), "Sliver");
        assert_eq!(C2Framework::Havoc.to_string(), "Havoc");
    }

    #[test]
    fn test_c2_manager_new() {
        let mgr = C2Manager::new();
        assert!(mgr.channels.is_empty());
        assert!(mgr.default_channel.is_none());
    }

    #[test]
    fn test_c2_config_serde() {
        let config = C2Config {
            framework: C2Framework::Sliver,
            host: "10.10.10.1".to_string(),
            port: 31337,
            auth: C2Auth::Token {
                token: "abc123".to_string(),
            },
            tls: true,
            tls_skip_verify: false,
            timeout: Duration::from_secs(30),
            auto_reconnect: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("Sliver"));
    }
}
