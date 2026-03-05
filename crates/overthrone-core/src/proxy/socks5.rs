//! SOCKS5 proxy server (RFC 1928) for pivoting through compromised networks.
//!
//! Supports:
//! - CONNECT command (TCP tunneling)
//! - Username/password authentication (RFC 1929) — optional
//! - No-auth mode for local use
//! - IPv4, IPv6, and domain name resolution
//!
//! # Usage
//! ```ignore
//! let config = Socks5Config {
//!     listen_addr: "127.0.0.1:1080".into(),
//!     auth: None, // no auth
//! };
//! let server = Socks5Server::new(config);
//! server.run().await?; // blocks, serving connections
//! ```

use crate::error::{OverthroneError, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

// ═══════════════════════════════════════════════════════════
//  SOCKS5 Constants (RFC 1928)
// ═══════════════════════════════════════════════════════════

const SOCKS_VERSION: u8 = 0x05;

// Authentication methods
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

// Commands
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

// Address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

// ═══════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════

/// SOCKS5 server configuration.
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// Address to listen on (e.g. "127.0.0.1:1080")
    pub listen_addr: String,
    /// Optional username/password authentication
    pub auth: Option<Socks5Auth>,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
    /// Maximum concurrent connections (0 = unlimited)
    pub max_connections: usize,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:1080".into(),
            auth: None,
            connect_timeout_secs: 10,
            max_connections: 0,
        }
    }
}

/// Username/password authentication credentials.
#[derive(Debug, Clone)]
pub struct Socks5Auth {
    pub username: String,
    pub password: String,
}

// ═══════════════════════════════════════════════════════════
//  SOCKS5 Server
// ═══════════════════════════════════════════════════════════

/// Async SOCKS5 proxy server.
pub struct Socks5Server {
    config: Socks5Config,
}

impl Socks5Server {
    pub fn new(config: Socks5Config) -> Self {
        Self { config }
    }

    /// Run the SOCKS5 server (blocks until shutdown).
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                OverthroneError::custom(format!(
                    "SOCKS5: Failed to bind {}: {}",
                    self.config.listen_addr, e
                ))
            })?;

        info!("SOCKS5 proxy listening on {}", self.config.listen_addr);

        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        loop {
            let (stream, peer) = listener.accept().await.map_err(|e| {
                OverthroneError::custom(format!("SOCKS5: Accept failed: {}", e))
            })?;

            let current = active.load(std::sync::atomic::Ordering::Relaxed);
            if self.config.max_connections > 0 && current >= self.config.max_connections {
                warn!("SOCKS5: Max connections ({}) reached, rejecting {}", self.config.max_connections, peer);
                drop(stream);
                continue;
            }

            let auth = self.config.auth.clone();
            let timeout = self.config.connect_timeout_secs;
            let active_clone = active.clone();
            active_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, peer, auth.as_ref(), timeout).await {
                    debug!("SOCKS5: Client {} error: {}", peer, e);
                }
                active_clone.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    /// Run the server with a shutdown signal (e.g. ctrl+c).
    pub async fn run_until(
        &self,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                OverthroneError::custom(format!(
                    "SOCKS5: Failed to bind {}: {}",
                    self.config.listen_addr, e
                ))
            })?;

        info!("SOCKS5 proxy listening on {}", self.config.listen_addr);

        tokio::select! {
            _ = async {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            let auth = self.config.auth.clone();
                            let timeout = self.config.connect_timeout_secs;
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, peer, auth.as_ref(), timeout).await {
                                    debug!("SOCKS5: Client {} error: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("SOCKS5: Accept error: {}", e);
                        }
                    }
                }
            } => {}
            _ = shutdown => {
                info!("SOCKS5 proxy shutting down");
            }
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
//  Connection Handler
// ═══════════════════════════════════════════════════════════

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    auth: Option<&Socks5Auth>,
    connect_timeout_secs: u64,
) -> Result<()> {
    debug!("SOCKS5: New connection from {}", peer);

    // ── Step 1: Greeting ──
    let mut buf = [0u8; 258];
    let n = client.read(&mut buf).await.map_err(sock_err)?;
    if n < 2 || buf[0] != SOCKS_VERSION {
        return Err(OverthroneError::custom("SOCKS5: Invalid greeting"));
    }

    let nmethods = buf[1] as usize;
    if n < 2 + nmethods {
        return Err(OverthroneError::custom("SOCKS5: Truncated greeting"));
    }

    let methods = &buf[2..2 + nmethods];

    // ── Step 2: Authentication ──
    if let Some(expected_auth) = auth {
        if !methods.contains(&AUTH_USERNAME_PASSWORD) {
            client.write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPTABLE]).await.map_err(sock_err)?;
            return Err(OverthroneError::custom("SOCKS5: Client does not support username/password auth"));
        }
        client.write_all(&[SOCKS_VERSION, AUTH_USERNAME_PASSWORD]).await.map_err(sock_err)?;

        // Read username/password sub-negotiation (RFC 1929)
        let n = client.read(&mut buf).await.map_err(sock_err)?;
        if n < 2 || buf[0] != 0x01 {
            return Err(OverthroneError::custom("SOCKS5: Invalid auth sub-negotiation"));
        }
        let ulen = buf[1] as usize;
        if n < 2 + ulen + 1 {
            return Err(OverthroneError::custom("SOCKS5: Truncated auth"));
        }
        let username = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
        let plen = buf[2 + ulen] as usize;
        if n < 3 + ulen + plen {
            return Err(OverthroneError::custom("SOCKS5: Truncated auth"));
        }
        let password = String::from_utf8_lossy(&buf[3 + ulen..3 + ulen + plen]).to_string();

        if username != expected_auth.username || password != expected_auth.password {
            client.write_all(&[0x01, 0x01]).await.map_err(sock_err)?; // auth failure
            return Err(OverthroneError::Auth(format!("SOCKS5: Auth failed for user '{}'", username)));
        }
        client.write_all(&[0x01, 0x00]).await.map_err(sock_err)?; // auth success
        debug!("SOCKS5: Authenticated user '{}'", username);
    } else {
        if !methods.contains(&AUTH_NO_AUTH) {
            client.write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPTABLE]).await.map_err(sock_err)?;
            return Err(OverthroneError::custom("SOCKS5: No acceptable auth method"));
        }
        client.write_all(&[SOCKS_VERSION, AUTH_NO_AUTH]).await.map_err(sock_err)?;
    }

    // ── Step 3: Request ──
    let n = client.read(&mut buf).await.map_err(sock_err)?;
    if n < 4 || buf[0] != SOCKS_VERSION {
        return Err(OverthroneError::custom("SOCKS5: Invalid request"));
    }

    let cmd = buf[1];
    // buf[2] is reserved
    let atyp = buf[3];

    // Parse target address (needed by all commands)
    let (target_addr, target_port) = parse_target_address(&buf, n, atyp)?;
    if target_addr.is_empty() && cmd != CMD_UDP_ASSOCIATE {
        send_reply(&mut client, REP_ATYP_NOT_SUPPORTED, &[0; 4], 0).await?;
        return Err(OverthroneError::custom(format!("SOCKS5: Unsupported address type: {:#x}", atyp)));
    }

    match cmd {
        CMD_CONNECT => {
            handle_connect(client, peer, &target_addr, target_port, connect_timeout_secs).await
        }
        CMD_BIND => {
            handle_bind(client, peer, connect_timeout_secs).await
        }
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate(client, peer).await
        }
        _ => {
            send_reply(&mut client, REP_CMD_NOT_SUPPORTED, &[0; 4], 0).await?;
            Err(OverthroneError::custom(format!("SOCKS5: Unsupported command: {:#x}", cmd)))
        }
    }
}

/// Parse the target address from a SOCKS5 request buffer.
fn parse_target_address(buf: &[u8], n: usize, atyp: u8) -> Result<(String, u16)> {
    match atyp {
        ATYP_IPV4 => {
            if n < 10 {
                return Err(OverthroneError::custom("SOCKS5: Truncated IPv4 request"));
            }
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok((ip.to_string(), port))
        }
        ATYP_DOMAIN => {
            let dlen = buf[4] as usize;
            if n < 5 + dlen + 2 {
                return Err(OverthroneError::custom("SOCKS5: Truncated domain request"));
            }
            let domain = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
            let port = u16::from_be_bytes([buf[5 + dlen], buf[6 + dlen]]);
            Ok((domain, port))
        }
        ATYP_IPV6 => {
            if n < 22 {
                return Err(OverthroneError::custom("SOCKS5: Truncated IPv6 request"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok((ip.to_string(), port))
        }
        _ => Ok((String::new(), 0)),
    }
}

/// Handle SOCKS5 CONNECT command — connect to a remote host and relay bidirectionally.
async fn handle_connect(
    mut client: TcpStream,
    peer: SocketAddr,
    target_addr: &str,
    target_port: u16,
    connect_timeout_secs: u64,
) -> Result<()> {
    debug!("SOCKS5: CONNECT {}:{}", target_addr, target_port);

    let target = format!("{}:{}", target_addr, target_port);
    let remote = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_timeout_secs),
        TcpStream::connect(&target),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!("SOCKS5: Connection to {} failed: {}", target, e);
            send_reply(&mut client, REP_HOST_UNREACHABLE, &[0; 4], 0).await?;
            return Err(OverthroneError::custom(format!("SOCKS5: Connect failed: {}", e)));
        }
        Err(_) => {
            warn!("SOCKS5: Connection to {} timed out", target);
            send_reply(&mut client, REP_HOST_UNREACHABLE, &[0; 4], 0).await?;
            return Err(OverthroneError::custom("SOCKS5: Connect timed out"));
        }
    };

    // Get bound address for reply
    let local_addr = remote.local_addr().map_err(sock_err)?;
    let bind_ip = match local_addr {
        SocketAddr::V4(a) => a.ip().octets().to_vec(),
        SocketAddr::V6(a) => a.ip().octets().to_vec(),
    };
    let bind_port = local_addr.port();

    // Send success reply
    send_reply(&mut client, REP_SUCCESS, &bind_ip, bind_port).await?;
    info!("SOCKS5: {} -> {}:{} established", peer, target_addr, target_port);

    // ── Step 5: Bidirectional relay ──
    let (mut client_r, mut client_w) = client.into_split();
    let (mut remote_r, mut remote_w) = remote.into_split();

    let c2r = tokio::io::copy(&mut client_r, &mut remote_w);
    let r2c = tokio::io::copy(&mut remote_r, &mut client_w);

    tokio::select! {
        result = c2r => {
            if let Err(e) = result {
                debug!("SOCKS5: client->remote copy ended: {}", e);
            }
        }
        result = r2c => {
            if let Err(e) = result {
                debug!("SOCKS5: remote->client copy ended: {}", e);
            }
        }
    }

    debug!("SOCKS5: Connection {} closed", peer);
    Ok(())
}

/// Handle SOCKS5 BIND command (RFC 1928 §4).
///
/// Opens a listening TCP socket or uses an ephemeral port. Sends
/// two replies to the client: the first with the listening address/port, and
/// the second when an inbound connection arrives.  Then relays data
/// bidirectionally between the client and the accepted connection.
async fn handle_bind(
    mut client: TcpStream,
    peer: SocketAddr,
    connect_timeout_secs: u64,
) -> Result<()> {
    debug!("SOCKS5: BIND requested from {}", peer);

    // Bind an ephemeral port on all interfaces
    let listener = TcpListener::bind("0.0.0.0:0").await.map_err(|e| {
        OverthroneError::custom(format!("SOCKS5 BIND: failed to bind listener: {}", e))
    })?;
    let listen_addr = listener.local_addr().map_err(sock_err)?;
    let bind_ip = match listen_addr {
        SocketAddr::V4(a) => a.ip().octets().to_vec(),
        SocketAddr::V6(a) => a.ip().octets().to_vec(),
    };

    // First reply: tell the client where we're listening
    send_reply(&mut client, REP_SUCCESS, &bind_ip, listen_addr.port()).await?;
    info!("SOCKS5: BIND listening on {} for {}", listen_addr, peer);

    // Wait for an incoming connection (with timeout)
    let incoming = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_timeout_secs),
        listener.accept(),
    )
    .await
    {
        Ok(Ok((stream, remote_peer))) => {
            debug!("SOCKS5: BIND accepted connection from {}", remote_peer);
            let remote_ip = match remote_peer {
                SocketAddr::V4(a) => a.ip().octets().to_vec(),
                SocketAddr::V6(a) => a.ip().octets().to_vec(),
            };
            // Second reply: tell the client who connected
            send_reply(&mut client, REP_SUCCESS, &remote_ip, remote_peer.port()).await?;
            stream
        }
        Ok(Err(e)) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, &[0; 4], 0).await?;
            return Err(OverthroneError::custom(format!("SOCKS5 BIND: accept failed: {}", e)));
        }
        Err(_) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, &[0; 4], 0).await?;
            return Err(OverthroneError::custom("SOCKS5 BIND: accept timed out"));
        }
    };

    // Bidirectional relay
    let (mut client_r, mut client_w) = client.into_split();
    let (mut remote_r, mut remote_w) = incoming.into_split();

    let c2r = tokio::io::copy(&mut client_r, &mut remote_w);
    let r2c = tokio::io::copy(&mut remote_r, &mut client_w);

    tokio::select! {
        result = c2r => {
            if let Err(e) = result { debug!("SOCKS5 BIND: client->remote ended: {}", e); }
        }
        result = r2c => {
            if let Err(e) = result { debug!("SOCKS5 BIND: remote->client ended: {}", e); }
        }
    }

    debug!("SOCKS5: BIND connection {} closed", peer);
    Ok(())
}

/// Handle SOCKS5 UDP ASSOCIATE command (RFC 1928 §7).
///
/// Opens a UDP socket and replies with its address.  Then relays
/// SOCKS5-encapsulated UDP datagrams between the client and
/// the destination indicated in each datagram header.  The
/// association is terminated when the TCP control connection closes.
async fn handle_udp_associate(
    mut client: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    debug!("SOCKS5: UDP_ASSOCIATE requested from {}", peer);

    // Bind an ephemeral UDP socket
    let udp_sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
        OverthroneError::custom(format!("SOCKS5 UDP: failed to bind socket: {}", e))
    })?;
    let udp_addr = udp_sock.local_addr().map_err(sock_err)?;
    let bind_ip = match udp_addr {
        SocketAddr::V4(a) => a.ip().octets().to_vec(),
        SocketAddr::V6(a) => a.ip().octets().to_vec(),
    };

    // Reply with the UDP relay address
    send_reply(&mut client, REP_SUCCESS, &bind_ip, udp_addr.port()).await?;
    info!("SOCKS5: UDP relay on {} for {}", udp_addr, peer);

    let udp_sock = std::sync::Arc::new(udp_sock);
    let sock_relay = udp_sock.clone();

    // UDP relay loop: read SOCKS5-encapsulated datagrams, forward, and relay back.
    // The association ends when the TCP control connection drops.
    let relay_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut client_addr: Option<SocketAddr> = None;

        loop {
            let (n, src) = match sock_relay.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("SOCKS5 UDP: recv error: {}", e);
                    break;
                }
            };

            if n < 4 {
                continue;
            }

            // Check RSV and FRAG fields (RFC 1928 §7)
            // [RSV:u16=0x0000] [FRAG:u8] [ATYP:u8] [DST.ADDR] [DST.PORT] [DATA]
            // We don't support fragmentation (FRAG != 0 → drop)
            if buf[2] != 0x00 {
                debug!("SOCKS5 UDP: dropping fragmented datagram (frag={})", buf[2]);
                continue;
            }

            let atyp = buf[3];
            let (dest_addr, dest_port, data_offset) = match atyp {
                ATYP_IPV4 => {
                    if n < 10 { continue; }
                    let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                    let port = u16::from_be_bytes([buf[8], buf[9]]);
                    (std::net::IpAddr::V4(ip), port, 10)
                }
                ATYP_IPV6 => {
                    if n < 22 { continue; }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[4..20]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([buf[20], buf[21]]);
                    (std::net::IpAddr::V6(ip), port, 22)
                }
                ATYP_DOMAIN => {
                    let dlen = buf[4] as usize;
                    if n < 5 + dlen + 2 { continue; }
                    let domain = String::from_utf8_lossy(&buf[5..5 + dlen]);
                    let port = u16::from_be_bytes([buf[5 + dlen], buf[6 + dlen]]);
                    // Resolve domain
                    let resolved = match tokio::net::lookup_host(format!("{}:{}", domain, port)).await {
                        Ok(mut addrs) => match addrs.next() {
                            Some(a) => a.ip(),
                            None => continue,
                        },
                        Err(_) => continue,
                    };
                    (resolved, port, 7 + dlen)
                }
                _ => continue,
            };

            let dest = SocketAddr::new(dest_addr, dest_port);

            // If datagram came from the client, forward the payload to the destination.
            // Otherwise it's a response from a remote host — wrap and send back to the client.
            if client_addr.is_none() || client_addr == Some(src) {
                client_addr = Some(src);
                let _ = sock_relay.send_to(&buf[data_offset..n], dest).await;
            } else if let Some(ca) = client_addr {
                // Build SOCKS5 UDP header for the reply
                let mut reply = vec![0x00, 0x00, 0x00]; // RSV + FRAG
                match src.ip() {
                    std::net::IpAddr::V4(ip) => {
                        reply.push(ATYP_IPV4);
                        reply.extend_from_slice(&ip.octets());
                    }
                    std::net::IpAddr::V6(ip) => {
                        reply.push(ATYP_IPV6);
                        reply.extend_from_slice(&ip.octets());
                    }
                }
                reply.extend_from_slice(&src.port().to_be_bytes());
                reply.extend_from_slice(&buf[..n]);
                let _ = sock_relay.send_to(&reply, ca).await;
            }
        }
    });

    // Wait for the TCP control connection to close (client reads 0 bytes)
    let mut tcp_buf = [0u8; 1];
    loop {
        match client.read(&mut tcp_buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {} // discard any TCP data
        }
    }

    relay_task.abort();
    debug!("SOCKS5: UDP association {} ended", peer);
    Ok(())
}

/// Send a SOCKS5 reply to the client.
async fn send_reply(
    client: &mut TcpStream,
    rep: u8,
    bind_addr: &[u8],
    bind_port: u16,
) -> Result<()> {
    let atyp = if bind_addr.len() == 4 {
        ATYP_IPV4
    } else if bind_addr.len() == 16 {
        ATYP_IPV6
    } else {
        ATYP_IPV4
    };

    let mut reply = vec![SOCKS_VERSION, rep, 0x00, atyp];
    if atyp == ATYP_IPV4 && bind_addr.len() < 4 {
        reply.extend_from_slice(&[0u8; 4]);
    } else {
        reply.extend_from_slice(bind_addr);
    }
    reply.extend_from_slice(&bind_port.to_be_bytes());

    client.write_all(&reply).await.map_err(sock_err)?;
    Ok(())
}

fn sock_err(e: std::io::Error) -> OverthroneError {
    OverthroneError::custom(format!("SOCKS5 I/O: {}", e))
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Socks5Config::default();
        assert_eq!(cfg.listen_addr, "127.0.0.1:1080");
        assert!(cfg.auth.is_none());
        assert_eq!(cfg.connect_timeout_secs, 10);
    }

    #[test]
    fn test_config_with_auth() {
        let cfg = Socks5Config {
            listen_addr: "0.0.0.0:9050".into(),
            auth: Some(Socks5Auth {
                username: "user".into(),
                password: "pass".into(),
            }),
            connect_timeout_secs: 30,
            max_connections: 100,
        };
        assert!(cfg.auth.is_some());
        assert_eq!(cfg.auth.as_ref().unwrap().username, "user");
    }

    #[tokio::test]
    async fn test_server_bind() {
        // Test that server can bind to a port
        let cfg = Socks5Config {
            listen_addr: "127.0.0.1:0".into(), // OS picks a free port
            ..Default::default()
        };
        let listener = TcpListener::bind(&cfg.listen_addr).await;
        assert!(listener.is_ok());
    }
}
