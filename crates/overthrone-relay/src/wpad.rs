//! Standalone WPAD (Web Proxy Auto-Discovery) HTTP server.
//!
//! Serves `wpad.dat` PAC files on HTTP port 80, enabling automatic
//! proxy configuration for browsers on the local network.
//! Can be used independently of mitm6 for proxy-aware credential capture.

use crate::{RelayError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

/// Configuration for the WPAD proxy server
#[derive(Debug, Clone)]
pub struct WpadConfig {
    /// IP address to listen on (e.g., "0.0.0.0", "::")
    pub listen_ip: String,
    /// Port to listen on (default: 80)
    pub listen_port: u16,
    /// PAC script content. When None, generates a default proxy script.
    pub pac_script: Option<String>,
    /// Proxy server URL to advertise (e.g., "http://192.168.1.100:8080")
    /// Used in the default-generated PAC script when pac_script is None.
    pub proxy_url: String,
}

impl Default for WpadConfig {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".to_string(),
            listen_port: 80,
            pac_script: None,
            proxy_url: "http://127.0.0.1:8080".to_string(),
        }
    }
}

impl WpadConfig {
    /// Create a new WPAD config with a custom proxy URL
    pub fn new(proxy_url: impl Into<String>) -> Self {
        Self {
            proxy_url: proxy_url.into(),
            ..Default::default()
        }
    }

    /// Create a new WPAD config from a listen interface and proxy URL
    pub fn from_interface(interface: impl Into<String>, proxy_url: impl Into<String>) -> Self {
        Self {
            listen_ip: interface.into(),
            proxy_url: proxy_url.into(),
            ..Default::default()
        }
    }

    /// Set a custom PAC script (overrides auto-generated one)
    pub fn with_pac_script(mut self, script: impl Into<String>) -> Self {
        self.pac_script = Some(script.into());
        self
    }
}

/// Standalone WPAD HTTP server
///
/// Serves a PAC file at `http://<listen_ip>/wpad.dat` that configures
/// browsers to use the specified proxy server for all traffic.
pub struct WpadServer {
    config: WpadConfig,
}

impl WpadServer {
    /// Create a new WPAD server with the given configuration
    pub fn new(config: WpadConfig) -> Self {
        Self { config }
    }

    /// Start the WPAD HTTP server (blocking until shutdown signal)
    pub async fn start(&self) -> Result<()> {
        let addr: SocketAddr = self
            .config
            .listen_ip
            .parse()
            .map_err(|e| RelayError::Socket(format!("Invalid WPAD listen address: {}", e)))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| RelayError::Socket(format!("Failed to bind WPAD HTTP listener: {}", e)))?;

        let pac_content = self
            .config
            .pac_script
            .clone()
            .unwrap_or_else(|| generate_default_pac(&self.config.proxy_url));

        let pac_arc = Arc::new(pac_content);

        info!(
            "WPAD server listening on http://{}:{}/wpad.dat",
            self.config.listen_ip, self.config.listen_port
        );

        loop {
            match listener.accept().await {
                Ok((mut stream, peer)) => {
                    let pac = pac_arc.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_wpad_request(&mut stream, &pac).await {
                            debug!("WPAD request from {} failed: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("WPAD accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Handle a single HTTP request for wpad.dat
async fn handle_wpad_request(stream: &mut tokio::net::TcpStream, pac_content: &str) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| RelayError::Network(format!("Failed to read WPAD request: {}", e)))?;

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);

    let request_line = request.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let (status_line, content_type, body) = match path {
        "/wpad.dat" => (
            "HTTP/1.1 200 OK\r\n",
            "application/x-ns-proxy-autoconfig",
            pac_content,
        ),
        "/" | "/proxy.pac" => (
            "HTTP/1.1 200 OK\r\n",
            "application/x-ns-proxy-autoconfig",
            pac_content,
        ),
        _ => ("HTTP/1.1 404 Not Found\r\n", "text/plain", "Not Found"),
    };

    let response = format!(
        "{status_line}\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    );

    use tokio::io::AsyncWriteExt;
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| RelayError::Network(format!("Failed to write WPAD response: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| RelayError::Network(format!("Failed to flush WPAD response: {}", e)))?;

    Ok(())
}

/// Generate a default PAC script that routes all traffic through the given proxy
fn generate_default_pac(proxy_url: &str) -> String {
    let proxy_host = proxy_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("socks5://")
        .trim_start_matches("socks4://");

    format!(
        r#"function FindProxyForURL(url, host) {{
    if (shExpMatch(host, "*.local") ||
        shExpMatch(host, "*.corp") ||
        isPlainHostName(host)) {{
        return "DIRECT";
    }}
    return "PROXY {proxy_host}";
}}
"#,
        proxy_host = proxy_host
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpad_config_default() {
        let cfg = WpadConfig::default();
        assert_eq!(cfg.listen_ip, "0.0.0.0");
        assert_eq!(cfg.listen_port, 80);
        assert!(cfg.pac_script.is_none());
        assert_eq!(cfg.proxy_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn test_wpad_config_new() {
        let cfg = WpadConfig::new("http://192.168.1.100:3128");
        assert_eq!(cfg.proxy_url, "http://192.168.1.100:3128");
    }

    #[test]
    fn test_wpad_config_from_interface() {
        let cfg = WpadConfig::from_interface("192.168.1.50", "http://10.0.0.1:8080");
        assert_eq!(cfg.listen_ip, "192.168.1.50");
        assert_eq!(cfg.proxy_url, "http://10.0.0.1:8080");
    }

    #[test]
    fn test_wpad_config_with_pac_script() {
        let script = "function FindProxyForURL(url, host) { return \"PROXY 10.0.0.1:8080\"; }";
        let cfg = WpadConfig::default().with_pac_script(script);
        assert_eq!(cfg.pac_script.unwrap(), script);
    }

    #[test]
    fn test_generate_default_pac() {
        let pac = generate_default_pac("http://192.168.1.5:8080");
        assert!(pac.contains("FindProxyForURL"));
        assert!(pac.contains("PROXY 192.168.1.5:8080"));
        assert!(pac.contains("*.local"));
        assert!(pac.contains("DIRECT"));
    }

    #[test]
    fn test_generate_default_pac_strips_protocol() {
        let pac = generate_default_pac("https://proxy.corp:3128");
        assert!(pac.contains("PROXY proxy.corp:3128"));
        assert!(!pac.contains("https://proxy.corp:3128"));
    }

    #[test]
    fn test_generate_default_pac_socks() {
        let pac = generate_default_pac("socks5://10.0.0.1:1080");
        assert!(pac.contains("PROXY 10.0.0.1:1080"));
    }

    #[test]
    fn test_wpad_config_debug() {
        let cfg = WpadConfig::default();
        let debug = format!("{:?}", cfg);
        assert!(debug.contains("WpadConfig"));
        assert!(debug.contains("0.0.0.0"));
    }

    #[test]
    fn test_wpad_config_clone() {
        let cfg = WpadConfig::new("http://10.0.0.1:3128").with_pac_script("custom script");
        let cloned = cfg.clone();
        assert_eq!(cloned.proxy_url, "http://10.0.0.1:3128");
        assert_eq!(cloned.pac_script.as_deref(), Some("custom script"));
    }

    #[test]
    fn test_wpad_request_response_format() {
        let pac = generate_default_pac("http://proxy:8080");
        assert!(pac.contains("PROXY proxy:8080"));
        assert!(pac.contains("shExpMatch"));
        assert!(pac.contains("isPlainHostName"));
    }
}
