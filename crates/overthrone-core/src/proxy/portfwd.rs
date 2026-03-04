//! TCP port forwarding for lateral movement and pivoting.
//!
//! Supports:
//! - **Local forwarding** (`-L`): Listen locally, forward to remote target
//! - **Remote forwarding** concept (connect to remote, relay back to local)
//!
//! # Usage
//! ```ignore
//! // Forward local port 8445 to DC01:445
//! let fwd = PortForward::new(PortForwardConfig {
//!     listen_addr: "127.0.0.1:8445".into(),
//!     target_addr: "10.0.0.1:445".into(),
//! });
//! fwd.run().await?;
//! ```

use crate::error::{OverthroneError, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

// ═══════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════

/// Port forwarding configuration.
#[derive(Debug, Clone)]
pub struct PortForwardConfig {
    /// Local address to listen on (e.g. "127.0.0.1:8445")
    pub listen_addr: String,
    /// Remote target to forward to (e.g. "10.0.0.1:445")
    pub target_addr: String,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
}

impl Default for PortForwardConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "127.0.0.1:80".into(),
            connect_timeout_secs: 10,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Port Forwarder
// ═══════════════════════════════════════════════════════════

/// TCP port forwarder — listens locally and relays to a remote target.
pub struct PortForward {
    config: PortForwardConfig,
}

impl PortForward {
    pub fn new(config: PortForwardConfig) -> Self {
        Self { config }
    }

    /// Run the port forwarder (blocks until shutdown).
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                OverthroneError::custom(format!(
                    "PortFwd: Failed to bind {}: {}",
                    self.config.listen_addr, e
                ))
            })?;

        info!(
            "Port forward: {} -> {}",
            self.config.listen_addr, self.config.target_addr
        );

        loop {
            let (client, peer) = listener.accept().await.map_err(|e| {
                OverthroneError::custom(format!("PortFwd: Accept failed: {}", e))
            })?;

            let target = self.config.target_addr.clone();
            let timeout = self.config.connect_timeout_secs;

            tokio::spawn(async move {
                if let Err(e) = relay(client, peer, &target, timeout).await {
                    debug!("PortFwd: {} error: {}", peer, e);
                }
            });
        }
    }

    /// Run with a shutdown signal.
    pub async fn run_until(
        &self,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                OverthroneError::custom(format!(
                    "PortFwd: Failed to bind {}: {}",
                    self.config.listen_addr, e
                ))
            })?;

        info!(
            "Port forward: {} -> {}",
            self.config.listen_addr, self.config.target_addr
        );

        tokio::select! {
            _ = async {
                loop {
                    match listener.accept().await {
                        Ok((client, peer)) => {
                            let target = self.config.target_addr.clone();
                            let timeout = self.config.connect_timeout_secs;
                            tokio::spawn(async move {
                                if let Err(e) = relay(client, peer, &target, timeout).await {
                                    debug!("PortFwd: {} error: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("PortFwd: Accept error: {}", e);
                        }
                    }
                }
            } => {}
            _ = shutdown => {
                info!("Port forward shutting down");
            }
        }

        Ok(())
    }
}

/// Relay traffic between client and target.
async fn relay(
    client: TcpStream,
    peer: SocketAddr,
    target_addr: &str,
    timeout_secs: u64,
) -> Result<()> {
    debug!("PortFwd: {} -> {}", peer, target_addr);

    let remote = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        TcpStream::connect(target_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Err(OverthroneError::custom(format!(
                "PortFwd: Connection to {} failed: {}",
                target_addr, e
            )));
        }
        Err(_) => {
            return Err(OverthroneError::custom(format!(
                "PortFwd: Connection to {} timed out",
                target_addr
            )));
        }
    };

    info!("PortFwd: {} <-> {} established", peer, target_addr);

    let (mut client_r, mut client_w) = client.into_split();
    let (mut remote_r, mut remote_w) = remote.into_split();

    let c2r = tokio::io::copy(&mut client_r, &mut remote_w);
    let r2c = tokio::io::copy(&mut remote_r, &mut client_w);

    tokio::select! {
        result = c2r => {
            if let Err(e) = result {
                debug!("PortFwd: client->remote ended: {}", e);
            }
        }
        result = r2c => {
            if let Err(e) = result {
                debug!("PortFwd: remote->client ended: {}", e);
            }
        }
    }

    debug!("PortFwd: {} session ended", peer);
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = PortForwardConfig::default();
        assert_eq!(cfg.listen_addr, "127.0.0.1:8080");
        assert_eq!(cfg.target_addr, "127.0.0.1:80");
        assert_eq!(cfg.connect_timeout_secs, 10);
    }

    #[tokio::test]
    async fn test_port_forward_bind() {
        let cfg = PortForwardConfig {
            listen_addr: "127.0.0.1:0".into(), // OS picks a free port
            target_addr: "127.0.0.1:80".into(),
            connect_timeout_secs: 5,
        };
        let listener = TcpListener::bind(&cfg.listen_addr).await;
        assert!(listener.is_ok());
    }

    #[tokio::test]
    async fn test_port_forward_relay_echo() {
        // Start an echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });

        // Start port forwarder
        let fwd_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fwd_addr = fwd_listener.local_addr().unwrap();
        let target = echo_addr.to_string();

        tokio::spawn(async move {
            if let Ok((client, peer)) = fwd_listener.accept().await {
                let _ = relay(client, peer, &target, 5).await;
            }
        });

        // Connect through the forwarder
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut stream = TcpStream::connect(fwd_addr).await.unwrap();
        stream.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }
}
