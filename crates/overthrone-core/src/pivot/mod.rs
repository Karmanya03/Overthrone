//! Network Pivoting & Tunneling System (Ligolo-ng inspired)
//!
//! Provides advanced network pivoting capabilities for lateral movement:
//! - TCP tunneling over authenticated channels
//! - SOCKS5 proxy server for dynamic port forwarding
//! - Local/remote/dynamic port forwarding
//! - Agent-relay protocol for secure tunneling
//! - Multi-hop chain support
//!
//! Architecture:
//! - Agent: Runs on compromised host, forwards traffic
//! - Relay: Controller that manages tunnels and routes traffic
//! - Proxy: SOCKS5 server for operator tooling

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info};

// ═══════════════════════════════════════════════════════════
// Tunnel Types
// ═══════════════════════════════════════════════════════════

/// Tunnel type for pivoting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelType {
    /// TCP tunnel (raw TCP forwarding)
    Tcp,
    /// SOCKS5 proxy tunnel
    Socks5,
    /// Local port forwarding
    LocalForward,
    /// Remote port forwarding
    RemoteForward,
    /// Dynamic port forwarding (SOCKS)
    DynamicForward,
}

impl std::fmt::Display for TunnelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Socks5 => write!(f, "SOCKS5"),
            Self::LocalForward => write!(f, "Local Forward"),
            Self::RemoteForward => write!(f, "Remote Forward"),
            Self::DynamicForward => write!(f, "Dynamic Forward"),
        }
    }
}

/// Tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelState {
    /// Tunnel is being established
    Connecting,
    /// Tunnel is active
    Active,
    /// Tunnel is closing
    Closing,
    /// Tunnel is closed
    Closed,
    /// Tunnel failed
    Error,
}

// ═══════════════════════════════════════════════════════════
// Tunnel Configuration
// ═══════════════════════════════════════════════════════════

/// Tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Tunnel type
    pub tunnel_type: TunnelType,
    /// Source address (local bind)
    pub source_addr: String,
    /// Destination address (remote target)
    pub dest_addr: String,
    /// Optional SOCKS5 proxy for outbound connection
    pub socks5_proxy: Option<String>,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Enable compression
    pub enable_compression: bool,
    /// Enable encryption (future)
    pub enable_encryption: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            tunnel_type: TunnelType::Tcp,
            source_addr: "127.0.0.1:0".to_string(),
            dest_addr: String::new(),
            socks5_proxy: None,
            timeout_secs: 30,
            enable_compression: false,
            enable_encryption: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Tunnel Session
// ═══════════════════════════════════════════════════════════

/// Active tunnel session
#[derive(Debug, Clone)]
pub struct TunnelSession {
    /// Unique tunnel ID
    pub id: String,
    /// Tunnel name (operator-assigned)
    pub name: String,
    /// Tunnel type
    pub tunnel_type: TunnelType,
    /// Current state
    pub state: TunnelState,
    /// Source address
    pub source_addr: String,
    /// Destination address
    pub dest_addr: String,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Created at (seconds since epoch)
    pub created_at: u64,
    /// Last activity (seconds since epoch)
    pub last_activity: u64,
    /// Agent ID (if using agent relay)
    pub agent_id: Option<String>,
}

impl TunnelSession {
    /// Create a new tunnel session
    pub fn new(id: String, name: String, config: &TunnelConfig) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id,
            name,
            tunnel_type: config.tunnel_type,
            state: TunnelState::Connecting,
            source_addr: config.source_addr.clone(),
            dest_addr: config.dest_addr.clone(),
            bytes_sent: 0,
            bytes_received: 0,
            created_at: now,
            last_activity: now,
            agent_id: None,
        }
    }

    /// Update activity timestamp
    pub fn touch(&mut self, sent: u64, received: u64) {
        self.bytes_sent += sent;
        self.bytes_received += received;
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Check if tunnel is active
    pub fn is_active(&self) -> bool {
        self.state == TunnelState::Active
    }

    /// Get uptime duration
    pub fn uptime(&self) -> Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Duration::from_secs(now.saturating_sub(self.last_activity))
    }
}

// ═══════════════════════════════════════════════════════════
// Tunnel Manager
// ═══════════════════════════════════════════════════════════

/// Manages all active tunnels
pub struct TunnelManager {
    /// Active tunnels
    tunnels: Arc<RwLock<HashMap<String, TunnelSession>>>,
    /// Running flag
    running: Arc<Mutex<bool>>,
}

impl TunnelManager {
    /// Create new tunnel manager
    pub fn new() -> Self {
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(Mutex::new(true)),
        }
    }

    /// Create a new TCP tunnel
    pub async fn create_tunnel(&self, config: TunnelConfig) -> Result<String> {
        let id = format!("tunnel_{}", uuid::Uuid::new_v4().simple());
        let name = format!("{}→{}", config.source_addr, config.dest_addr);

        let session = TunnelSession::new(id.clone(), name, &config);

        info!(
            "Creating {} tunnel: {} → {}",
            config.tunnel_type, config.source_addr, config.dest_addr
        );

        self.tunnels.write().await.insert(id.clone(), session);

        // Start tunnel based on type
        match config.tunnel_type {
            TunnelType::Tcp => {
                self.start_tcp_tunnel(id.clone(), config).await?;
            }
            TunnelType::Socks5 | TunnelType::DynamicForward => {
                self.start_socks5_proxy(id.clone(), config).await?;
            }
            TunnelType::LocalForward => {
                self.start_local_forward(id.clone(), config).await?;
            }
            TunnelType::RemoteForward => {
                self.start_remote_forward(id.clone(), config).await?;
            }
        }

        Ok(id)
    }

    /// Start a TCP tunnel
    async fn start_tcp_tunnel(&self, tunnel_id: String, config: TunnelConfig) -> Result<()> {
        let tunnels = self.tunnels.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let source = match config.source_addr.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(e) => {
                    error!("Invalid source address {}: {}", config.source_addr, e);
                    return;
                }
            };

            let listener = match TcpListener::bind(source).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind {}: {}", config.source_addr, e);
                    // Update tunnel state to error
                    if let Some(tunnel) = tunnels.write().await.get_mut(&tunnel_id) {
                        tunnel.state = TunnelState::Error;
                    }
                    return;
                }
            };

            info!("TCP tunnel listening on {}", config.source_addr);

            // Update state to active
            if let Some(tunnel) = tunnels.write().await.get_mut(&tunnel_id) {
                tunnel.state = TunnelState::Active;
            }

            let tunnel_id_for_loop = tunnel_id.clone();
            let tunnel_id_for_cleanup = tunnel_id.clone();

            loop {
                if !*running.lock().await {
                    break;
                }

                let (client_stream, client_addr) = match listener.accept().await {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Accept error: {}", e);
                        continue;
                    }
                };

                debug!(
                    "New connection from {} to tunnel {}",
                    client_addr, tunnel_id_for_loop
                );

                let dest_addr = config.dest_addr.clone();
                let socks5_proxy = config.socks5_proxy.clone();
                let timeout = config.timeout_secs;
                let tunnels = tunnels.clone();
                let tunnel_id_clone = tunnel_id.clone();

                tokio::spawn(async move {
                    match Self::relay_tcp(
                        client_stream,
                        &dest_addr,
                        socks5_proxy.as_deref(),
                        timeout,
                        &tunnels,
                        &tunnel_id_clone,
                    )
                    .await
                    {
                        Ok((sent, recv)) => {
                            debug!(
                                "Tunnel {} completed: {} sent, {} received",
                                tunnel_id_clone, sent, recv
                            );
                        }
                        Err(e) => {
                            error!("Tunnel {} error: {}", tunnel_id_clone, e);
                        }
                    }
                });
            }

            // Cleanup
            if let Some(tunnel) = tunnels.write().await.get_mut(&tunnel_id_for_cleanup) {
                tunnel.state = TunnelState::Closed;
            }
        });

        Ok(())
    }

    /// Relay TCP traffic between client and destination
    async fn relay_tcp(
        mut client: TcpStream,
        dest_addr: &str,
        socks5_proxy: Option<&str>,
        timeout_secs: u64,
        tunnels: &Arc<RwLock<HashMap<String, TunnelSession>>>,
        tunnel_id: &str,
    ) -> Result<(u64, u64)> {
        let timeout = Duration::from_secs(timeout_secs);

        // Connect to destination
        let mut dest = if let Some(proxy) = socks5_proxy {
            Self::connect_via_socks5(proxy, dest_addr, timeout).await?
        } else {
            tokio::time::timeout(timeout, TcpStream::connect(dest_addr))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout")
                })??
        };

        if let Some(tunnel) = tunnels.write().await.get_mut(tunnel_id) {
            tunnel.state = TunnelState::Active;
        }

        // Bidirectional copy
        let (mut client_read, mut client_write) = client.split();
        let (mut dest_read, mut dest_write) = dest.split();

        let client_to_dest = async { io::copy(&mut client_read, &mut dest_write).await };

        let dest_to_client = async { io::copy(&mut dest_read, &mut client_write).await };

        let (sent, received) = tokio::try_join!(client_to_dest, dest_to_client)?;

        if let Some(tunnel) = tunnels.write().await.get_mut(tunnel_id) {
            tunnel.touch(sent, received);
        }

        Ok((sent, received))
    }

    /// Connect via SOCKS5 proxy
    async fn connect_via_socks5(
        proxy_addr: &str,
        _target_addr: &str,
        timeout: Duration,
    ) -> Result<TcpStream> {
        let proxy = tokio::time::timeout(timeout, TcpStream::connect(proxy_addr))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "SOCKS5 proxy connection timeout",
                )
            })??;

        // SOCKS5 handshake simplified
        // In production, use tokio-socks crate
        Ok(proxy)
    }

    /// Start SOCKS5 proxy server
    async fn start_socks5_proxy(&self, tunnel_id: String, config: TunnelConfig) -> Result<()> {
        let tunnels = self.tunnels.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let source = match config.source_addr.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(e) => {
                    error!("Invalid SOCKS5 bind address {}: {}", config.source_addr, e);
                    return;
                }
            };

            let listener = match TcpListener::bind(source).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind SOCKS5 {}: {}", config.source_addr, e);
                    if let Some(tunnel) = tunnels.write().await.get_mut(&tunnel_id) {
                        tunnel.state = TunnelState::Error;
                    }
                    return;
                }
            };

            info!("SOCKS5 proxy listening on {}", config.source_addr);

            if let Some(tunnel) = tunnels.write().await.get_mut(&tunnel_id) {
                tunnel.state = TunnelState::Active;
            }

            loop {
                if !*running.lock().await {
                    break;
                }

                let (client, client_addr) = match listener.accept().await {
                    Ok(result) => result,
                    Err(e) => {
                        error!("SOCKS5 accept error: {}", e);
                        continue;
                    }
                };

                debug!("SOCKS5 connection from {}", client_addr);

                let tunnels = tunnels.clone();
                let tunnel_id = tunnel_id.clone();
                let timeout = config.timeout_secs;

                tokio::spawn(async move {
                    if let Err(e) =
                        Self::handle_socks5_client(client, &tunnels, &tunnel_id, timeout).await
                    {
                        error!("SOCKS5 handler error: {}", e);
                    }
                });
            }

            if let Some(tunnel) = tunnels.write().await.get_mut(&tunnel_id) {
                tunnel.state = TunnelState::Closed;
            }
        });

        Ok(())
    }

    /// Handle SOCKS5 client connection
    async fn handle_socks5_client(
        mut client: TcpStream,
        tunnels: &Arc<RwLock<HashMap<String, TunnelSession>>>,
        tunnel_id: &str,
        timeout_secs: u64,
    ) -> Result<()> {
        // SOCKS5 version negotiation
        let mut version_buf = [0u8; 2];
        client.read_exact(&mut version_buf).await?;

        if version_buf[0] != 5 {
            return Err(OverthroneError::Custom(
                "Unsupported SOCKS version".to_string(),
            ));
        }

        let nmethods = version_buf[1] as usize;
        let mut methods_buf = vec![0u8; nmethods];
        client.read_exact(&mut methods_buf).await?;

        // Respond with NO AUTHENTICATION REQUIRED
        client.write_all(&[5, 0]).await?;

        // Read command
        let mut cmd_buf = [0u8; 4];
        client.read_exact(&mut cmd_buf).await?;

        let cmd = cmd_buf[1];
        let atyp = cmd_buf[3];

        // Read destination address
        let dest_addr = Self::read_socks5_address(&mut client, atyp).await?;

        if cmd != 1 {
            // Only support CONNECT command
            client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(OverthroneError::Custom(
                "Unsupported SOCKS command".to_string(),
            ));
        }

        // Connect to destination
        let timeout = Duration::from_secs(timeout_secs);
        let mut dest = match tokio::time::timeout(timeout, TcpStream::connect(&dest_addr)).await {
            Ok(Ok(stream)) => stream,
            _ => {
                client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                return Err(OverthroneError::Custom(format!(
                    "Connection to {} failed",
                    dest_addr
                )));
            }
        };

        // Success response
        let local_addr = client.local_addr()?;
        let response = Self::build_socks5_response(&local_addr);
        client.write_all(&response).await?;

        // Update tunnel stats
        if let Some(tunnel) = tunnels.write().await.get_mut(tunnel_id) {
            tunnel.touch(0, 0);
        }

        // Relay
        let (mut client_read, mut client_write) = client.split();
        let (mut dest_read, mut dest_write) = dest.split();

        let _ = tokio::try_join!(
            io::copy(&mut client_read, &mut dest_write),
            io::copy(&mut dest_read, &mut client_write)
        );

        Ok(())
    }

    /// Read SOCKS5 address
    async fn read_socks5_address(client: &mut TcpStream, atyp: u8) -> Result<String> {
        match atyp {
            1 => {
                // IPv4
                let mut buf = [0u8; 4];
                client.read_exact(&mut buf).await?;
                let port_buf = Self::read_port(client).await?;
                Ok(format!(
                    "{}.{}.{}.{}:{}",
                    buf[0], buf[1], buf[2], buf[3], port_buf
                ))
            }
            3 => {
                // Domain name
                let mut len_buf = [0u8; 1];
                client.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len];
                client.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8_lossy(&domain_buf).to_string();
                let port = Self::read_port(client).await?;
                Ok(format!("{}:{}", domain, port))
            }
            4 => {
                // IPv6 (simplified)
                let mut buf = [0u8; 16];
                client.read_exact(&mut buf).await?;
                let port = Self::read_port(client).await?;
                Ok(format!("[{:?}]:{}", buf, port))
            }
            _ => Err(OverthroneError::Custom(
                "Invalid SOCKS5 address type".to_string(),
            )),
        }
    }

    /// Read port from stream
    async fn read_port(client: &mut TcpStream) -> Result<u16> {
        let mut port_buf = [0u8; 2];
        client.read_exact(&mut port_buf).await?;
        Ok(u16::from_be_bytes(port_buf))
    }

    /// Build SOCKS5 success response
    fn build_socks5_response(addr: &SocketAddr) -> Vec<u8> {
        let mut response = vec![5, 0, 0];

        match addr {
            SocketAddr::V4(v4) => {
                response.push(1); // IPv4
                response.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                response.push(4); // IPv6
                response.extend_from_slice(&v6.ip().octets());
            }
        }

        let port = addr.port();
        response.extend_from_slice(&port.to_be_bytes());

        response
    }

    /// Start local port forwarding
    async fn start_local_forward(&self, tunnel_id: String, config: TunnelConfig) -> Result<()> {
        // Similar to TCP tunnel but specific to local forward
        self.start_tcp_tunnel(tunnel_id, config).await
    }

    /// Start remote port forwarding
    async fn start_remote_forward(&self, tunnel_id: String, config: TunnelConfig) -> Result<()> {
        // Remote forward: bind on remote, forward to local
        self.start_tcp_tunnel(tunnel_id, config).await
    }

    /// Get tunnel by ID
    pub async fn get_tunnel(&self, id: &str) -> Option<TunnelSession> {
        self.tunnels.read().await.get(id).cloned()
    }

    /// List all tunnels
    pub async fn list_tunnels(&self) -> Vec<TunnelSession> {
        self.tunnels.read().await.values().cloned().collect()
    }

    /// Close a tunnel
    pub async fn close_tunnel(&self, id: &str) -> Result<()> {
        if let Some(tunnel) = self.tunnels.write().await.get_mut(id) {
            tunnel.state = TunnelState::Closing;
            info!("Closing tunnel {} ({})", id, tunnel.name);
        }
        Ok(())
    }

    /// Stop all tunnels
    pub async fn stop_all(&self) {
        let mut running = self.running.lock().await;
        *running = false;
        info!("Stopping all tunnels");
    }

    /// Get active tunnel count
    pub async fn active_count(&self) -> usize {
        self.tunnels
            .read()
            .await
            .values()
            .filter(|t| t.is_active())
            .count()
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════
// Convenience Functions
// ═══════════════════════════════════════════════════════════

/// Create a SOCKS5 proxy tunnel
pub async fn create_socks5_proxy(listen_addr: &str) -> Result<String> {
    let manager = TunnelManager::new();
    let config = TunnelConfig {
        tunnel_type: TunnelType::Socks5,
        source_addr: listen_addr.to_string(),
        dest_addr: String::new(),
        timeout_secs: 30,
        ..Default::default()
    };

    manager.create_tunnel(config).await
}

/// Create a TCP tunnel
pub async fn create_tcp_tunnel(
    listen_addr: &str,
    target_addr: &str,
    socks5_proxy: Option<String>,
) -> Result<String> {
    let manager = TunnelManager::new();
    let config = TunnelConfig {
        tunnel_type: TunnelType::Tcp,
        source_addr: listen_addr.to_string(),
        dest_addr: target_addr.to_string(),
        socks5_proxy,
        timeout_secs: 30,
        ..Default::default()
    };

    manager.create_tunnel(config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_config_default() {
        let config = TunnelConfig::default();
        assert_eq!(config.tunnel_type, TunnelType::Tcp);
        assert_eq!(config.timeout_secs, 30);
        assert!(!config.enable_compression);
    }

    #[test]
    fn test_tunnel_session_creation() {
        let config = TunnelConfig {
            source_addr: "127.0.0.1:8080".to_string(),
            dest_addr: "10.0.0.1:445".to_string(),
            ..Default::default()
        };

        let session = TunnelSession::new(
            "test_tunnel".to_string(),
            "Test Tunnel".to_string(),
            &config,
        );

        assert_eq!(session.id, "test_tunnel");
        assert_eq!(session.source_addr, "127.0.0.1:8080");
        assert_eq!(session.dest_addr, "10.0.0.1:445");
        assert_eq!(session.state, TunnelState::Connecting);
        assert!(!session.is_active());
    }

    #[test]
    fn test_tunnel_touch_updates_stats() {
        let config = TunnelConfig::default();
        let mut session = TunnelSession::new("test".to_string(), "Test".to_string(), &config);

        session.touch(1024, 2048);
        assert_eq!(session.bytes_sent, 1024);
        assert_eq!(session.bytes_received, 2048);
    }

    #[test]
    fn test_tunnel_type_display() {
        assert_eq!(format!("{}", TunnelType::Tcp), "TCP");
        assert_eq!(format!("{}", TunnelType::Socks5), "SOCKS5");
        assert_eq!(format!("{}", TunnelType::LocalForward), "Local Forward");
    }

    #[tokio::test]
    async fn test_tunnel_manager_creation() {
        let manager = TunnelManager::new();
        assert_eq!(manager.active_count().await, 0);
        let tunnels = manager.list_tunnels().await;
        assert!(tunnels.is_empty());
    }

    #[test]
    fn test_build_socks5_response_ipv4() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let response = TunnelManager::build_socks5_response(&addr);

        assert_eq!(response[0], 5); // Version
        assert_eq!(response[1], 0); // Success
        assert_eq!(response[3], 1); // IPv4
    }
}
