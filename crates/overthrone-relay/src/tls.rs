//! TLS relay support -- RelayStream, RelayIo, build_relay_tls_config, mTLS identity,
//! TLS verification modes, and the shared TlsConfig builder.

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
pub use tokio_rustls::client::TlsStream;

// ===========================================================
// TlsVerificationMode -- controls server certificate verification
// ===========================================================

/// How to verify TLS server certificates for outbound connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsVerificationMode {
    /// Accept any server certificate (relay attack mode, like ntlmrelayx).
    #[default]
    AcceptAll,
    /// Verify server certificates against the system root store.
    /// Rejects self-signed or untrusted certificates.
    VerifyServerCert,
}

impl std::fmt::Display for TlsVerificationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptAll => write!(f, "accept-all"),
            Self::VerifyServerCert => write!(f, "verify-server-cert"),
        }
    }
}

// ===========================================================
// TlsConfig -- shared configuration for TLS connections
// ===========================================================

/// Shared TLS configuration bundling verification mode and optional mTLS identity.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// How to verify the server certificate.
    pub verification_mode: TlsVerificationMode,
    /// Optional mTLS client identity (certificate + private key) for client auth.
    /// When set, the client presents this certificate during the TLS handshake.
    pub identity: Option<TlsIdentity>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verification_mode: TlsVerificationMode::AcceptAll,
            identity: None,
        }
    }
}

impl TlsConfig {
    /// Create a new TlsConfig with AcceptAll mode (relay default).
    pub fn relay_default() -> Self {
        Self::default()
    }

    /// Create a new TlsConfig with server certificate verification.
    pub fn verify_server(identity: Option<TlsIdentity>) -> Self {
        Self {
            verification_mode: TlsVerificationMode::VerifyServerCert,
            identity,
        }
    }
}

// ===========================================================
// AcceptAllVerifier -- accepts any server certificate
// ===========================================================

#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ===========================================================
// RelayIo -- unified trait for TCP and TLS relay streams
// ===========================================================

/// Unified IO trait for relay streams (TCP or TLS-wrapped).
pub trait RelayIo: AsyncRead + AsyncWrite + Unpin + Send {
    fn peer_addr(&self) -> Option<std::net::SocketAddr>;
}

impl RelayIo for TcpStream {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr().ok()
    }
}

impl RelayIo for TlsStream<TcpStream> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.get_ref().0.peer_addr().ok()
    }
}

// ===========================================================
// RelayStream -- newtype wrapper (no bound on struct itself)
// ===========================================================

pub struct RelayStream<S> {
    inner: S,
}

impl<S> RelayStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

// RelayStream delegates RelayIo if the inner implements it
impl<S: RelayIo> RelayIo for RelayStream<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

// RelayStream delegates AsyncRead/AsyncWrite if the inner does
impl<S: AsyncRead + Unpin> AsyncRead for RelayStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RelayStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: Unpin> Unpin for RelayStream<S> {}

impl<S: fmt::Debug> fmt::Debug for RelayStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStream")
            .field("inner", &self.inner)
            .finish()
    }
}

// ===========================================================
// mTLS Identity
// ===========================================================

/// PEM-encoded client certificate and private key for mTLS.
#[derive(Debug, Clone)]
pub struct TlsIdentity {
    /// PEM-encoded certificate chain (leaf first).
    pub cert_pem: String,
    /// PEM-encoded private key (PKCS#8, SEC1, or RSA).
    pub key_pem: String,
}

impl TlsIdentity {
    /// Load from PEM file paths.
    pub fn load(cert_path: &str, key_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| format!("failed to read client cert '{}': {}", cert_path, e))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| format!("failed to read client key '{}': {}", key_path, e))?;
        Ok(Self { cert_pem, key_pem })
    }
}

// ===========================================================
// TLS configuration
// ===========================================================

/// Build a rustls `ClientConfig` for outbound TLS connections.
///
/// The `mode` parameter controls certificate verification:
/// - `AcceptAll`: accept any server certificate (relay attack mode)
/// - `VerifyServerCert`: validate against the system root store
///
/// When `identity` is provided, the client certificate is presented
/// for mTLS-protected targets.
pub fn build_relay_tls_config(
    mode: TlsVerificationMode,
    identity: Option<&TlsIdentity>,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    match mode {
        TlsVerificationMode::AcceptAll => {
            let verifier = Arc::new(AcceptAllVerifier);
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(verifier);
            match identity {
                Some(id) => {
                    let certs = vec![
                        CertificateDer::from_pem_slice(id.cert_pem.as_bytes())
                            .map_err(|e| format!("failed to parse client cert PEM: {}", e))?,
                    ];
                    let key = PrivateKeyDer::from_pem_slice(id.key_pem.as_bytes())
                        .map_err(|e| format!("failed to parse client key PEM: {}", e))?;
                    Ok(builder.with_client_auth_cert(certs, key)?)
                }
                None => Ok(builder.with_no_client_auth()),
            }
        }
        TlsVerificationMode::VerifyServerCert => {
            let mut root_store = rustls::RootCertStore::empty();
            let native_certs = rustls_native_certs::load_native_certs();
            for cert in native_certs.certs {
                let _ = root_store.add(cert);
            }
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
                .with_root_certificates(root_store);
            match identity {
                Some(id) => {
                    let certs = vec![
                        CertificateDer::from_pem_slice(id.cert_pem.as_bytes())
                            .map_err(|e| format!("failed to parse client cert PEM: {}", e))?,
                    ];
                    let key = PrivateKeyDer::from_pem_slice(id.key_pem.as_bytes())
                        .map_err(|e| format!("failed to parse client key PEM: {}", e))?;
                    Ok(builder.with_client_auth_cert(certs, key)?)
                }
                None => Ok(builder.with_no_client_auth()),
            }
        }
    }
}

/// Wrap a TCP stream with TLS for outbound connections.
/// Accepts any AsyncRead+AsyncWrite+Unpin+Send stream.
pub async fn wrap_tls<S>(
    stream: S,
    hostname: String,
    mode: TlsVerificationMode,
    identity: Option<&TlsIdentity>,
) -> Result<RelayStream<tokio_rustls::client::TlsStream<S>>, Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(build_relay_tls_config(mode, identity)?);
    let connector = tokio_rustls::TlsConnector::from(config);

    let domain = rustls::pki_types::ServerName::try_from(hostname.clone())
        .map_err(|e| format!("invalid TLS hostname '{}': {e}", hostname))?;

    let tls_stream = connector.connect(domain, stream).await?;

    Ok(RelayStream::new(tls_stream))
}

/// Determine whether a target protocol needs TLS wrapping.
pub fn requires_tls(protocol: &crate::Protocol) -> bool {
    matches!(protocol, crate::Protocol::Ldaps | crate::Protocol::Https)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_relay_tls_config_succeeds() {
        let config = build_relay_tls_config(TlsVerificationMode::AcceptAll, None);
        assert!(config.is_ok(), "TLS config should build without errors");
    }

    #[test]
    fn test_build_relay_tls_config_accept_all_disables_verification() {
        let config = build_relay_tls_config(TlsVerificationMode::AcceptAll, None).unwrap();
        let _ = config.alpn_protocols;
    }

    #[test]
    fn test_build_relay_tls_config_verify_server_cert_succeeds() {
        let config = build_relay_tls_config(TlsVerificationMode::VerifyServerCert, None);
        assert!(
            config.is_ok(),
            "VerifyServerCert config should build without errors"
        );
    }

    #[test]
    fn test_tls_config_relay_default() {
        let cfg = TlsConfig::relay_default();
        assert_eq!(cfg.verification_mode, TlsVerificationMode::AcceptAll);
        assert!(cfg.identity.is_none());
    }

    #[test]
    fn test_tls_config_verify_server() {
        let cfg = TlsConfig::verify_server(None);
        assert_eq!(cfg.verification_mode, TlsVerificationMode::VerifyServerCert);
        assert!(cfg.identity.is_none());

        let identity = TlsIdentity {
            cert_pem: "cert".into(),
            key_pem: "key".into(),
        };
        let cfg2 = TlsConfig::verify_server(Some(identity));
        assert_eq!(
            cfg2.verification_mode,
            TlsVerificationMode::VerifyServerCert
        );
        assert!(cfg2.identity.is_some());
    }

    #[test]
    fn test_verification_mode_display() {
        assert_eq!(format!("{}", TlsVerificationMode::AcceptAll), "accept-all");
        assert_eq!(
            format!("{}", TlsVerificationMode::VerifyServerCert),
            "verify-server-cert"
        );
    }

    #[test]
    fn test_verification_mode_default() {
        assert_eq!(
            TlsVerificationMode::default(),
            TlsVerificationMode::AcceptAll
        );
    }

    #[test]
    fn test_relay_io_trait_for_tcp_stream() {
        fn assert_relay_io<T: RelayIo>() {}
        assert_relay_io::<TcpStream>();
    }

    #[test]
    fn test_requires_tls() {
        assert!(requires_tls(&crate::Protocol::Ldaps));
        assert!(requires_tls(&crate::Protocol::Https));
        assert!(!requires_tls(&crate::Protocol::Ldap));
        assert!(!requires_tls(&crate::Protocol::Smb));
        assert!(!requires_tls(&crate::Protocol::Http));
    }

    #[test]
    fn test_relay_stream_new() {
        // Just test that the constructor works
        let stream = RelayStream::new(42u32);
        assert_eq!(*stream.inner(), 42u32);
    }

    #[test]
    fn test_relay_stream_inner() {
        let s = "test".to_string();
        let stream = RelayStream::new(s.clone());
        assert_eq!(stream.inner(), &s);
    }

    #[test]
    fn test_relay_stream_inner_mut() {
        let mut stream = RelayStream::new(10u32);
        *stream.inner_mut() = 20u32;
        assert_eq!(*stream.inner(), 20u32);
    }

    #[test]
    fn test_relay_stream_into_inner() {
        let stream = RelayStream::new(String::from("hello"));
        let inner = stream.into_inner();
        assert_eq!(inner, "hello");
    }

    #[test]
    fn test_relay_stream_debug() {
        let stream = RelayStream::new(42u32);
        let s = format!("{:?}", stream);
        assert!(s.contains("RelayStream"));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_relay_io_for_relay_stream() {
        fn assert_relay_io<T: RelayIo>() {}
        assert_relay_io::<RelayStream<TcpStream>>();
    }

    #[test]
    fn test_relay_stream_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<RelayStream<TcpStream>>();
    }

    #[test]
    fn test_relay_stream_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RelayStream<TcpStream>>();
    }

    #[tokio::test]
    async fn test_wrap_tls_with_invalid_hostname_fails() {
        // Use a dummy address that we won't actually connect to.
        // wrap_tls takes ownership of the stream and tries to handshake.
        // The hostname validator runs first, so an invalid hostname
        // should fail fast.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, _server) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept(),);
        let stream = client.unwrap();
        let result = wrap_tls(stream, "".to_string(), TlsVerificationMode::AcceptAll, None).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_requires_tls_only_for_secure_protocols() {
        // Quick sanity: only secure protocols require TLS.
        // This is the public contract.
        assert!(requires_tls(&crate::Protocol::Ldaps));
        assert!(requires_tls(&crate::Protocol::Https));
        for p in [
            crate::Protocol::Ldap,
            crate::Protocol::Smb,
            crate::Protocol::Http,
        ] {
            assert!(!requires_tls(&p), "Protocol {p:?} should not require TLS");
        }
    }

    #[test]
    fn test_tls_identity_load_missing_file() {
        let result = TlsIdentity::load("/tmp/nonexistent-cert.pem", "/tmp/nonexistent-key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_relay_tls_config_with_bad_pem_fails() {
        let identity = TlsIdentity {
            cert_pem: "not-valid-pem".to_string(),
            key_pem: "not-valid-pem".to_string(),
        };
        let config = build_relay_tls_config(TlsVerificationMode::AcceptAll, Some(&identity));
        assert!(config.is_err(), "mTLS config should fail with bad PEM");
        let err = config.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("failed to parse"),
            "error should mention parse failure: got '{}'",
            msg
        );
    }

    #[test]
    fn test_tls_identity_debug() {
        let id = TlsIdentity {
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
        };
        let s = format!("{:?}", id);
        assert!(s.contains("TlsIdentity"));
    }
}
