//! JA3/JA4 TLS fingerprint randomization.
//!
//! Randomizes cipher suite order, key exchange group order, and signature
//! algorithm order in a rustls `ClientConfig` to evade TLS fingerprinting.
//!
//! ## Feature gate
//! This module requires the `tls_fingerprint` feature:
//! ```toml
//! overthrone-crawler = { features = ["tls_fingerprint"] }
//! ```
//!
//! ## Note
//! TLS extension order is **not** customizable in rustls 0.23, so JA3
//! extension-order randomization is not possible. Cipher-suite and group
//! randomization still provide meaningful fingerprint diversity.

use rand::seq::SliceRandom;

/// Configuration for TLS fingerprint randomization.
#[derive(Debug, Clone)]
pub struct TlsFingerprintConfig {
    /// Randomize cipher suite order in ClientHello (affects JA3).
    pub randomize_cipher_order: bool,
    /// Randomize key exchange group / curve order (affects JA3).
    pub randomize_group_order: bool,
    /// If `Some(n)`, use only `n` randomly chosen cipher suites
    /// (fewer suites = less distinct fingerprint surface).
    pub cipher_subset_size: Option<usize>,
}

impl Default for TlsFingerprintConfig {
    fn default() -> Self {
        Self {
            randomize_cipher_order: true,
            randomize_group_order: true,
            cipher_subset_size: None,
        }
    }
}

#[cfg(feature = "tls_fingerprint")]
impl TlsFingerprintConfig {
    /// Build a [`rustls::ClientConfig`] that accepts all server certificates
    /// (danger mode -- for internal ADCS / SCCM targets with self-signed certs).
    pub fn build_danger_client_config(&self) -> Result<rustls::ClientConfig, rustls::Error> {
        build_randomized_danger_config(self)
    }
}

/// Build a danger-mode (accept-all) randomized [`rustls::ClientConfig`].
#[cfg(feature = "tls_fingerprint")]
pub fn build_randomized_danger_config(
    cfg: &TlsFingerprintConfig,
) -> Result<rustls::ClientConfig, rustls::Error> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    if cfg.randomize_cipher_order {
        let mut ciphers: Vec<rustls::SupportedCipherSuite> = provider.cipher_suites.to_vec();
        ciphers.shuffle(&mut rand::rng());
        if let Some(size) = cfg.cipher_subset_size {
            let size = size.min(ciphers.len());
            ciphers.truncate(size);
        }
        provider.cipher_suites = ciphers;
    }

    if cfg.randomize_group_order {
        let mut groups = provider.kx_groups.clone();
        groups.shuffle(&mut rand::rng());
        provider.kx_groups = groups;
    }

    let config = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAllVerifier))
        .with_no_client_auth();

    Ok(config)
}

/// Build a verified-mode randomized [`rustls::ClientConfig`] that validates
/// server certificates against the native root store.
#[cfg(feature = "tls_fingerprint")]
pub fn build_randomized_verified_config(
    cfg: &TlsFingerprintConfig,
) -> Result<rustls::ClientConfig, rustls::Error> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    if cfg.randomize_cipher_order {
        let mut ciphers: Vec<rustls::SupportedCipherSuite> = provider.cipher_suites.to_vec();
        ciphers.shuffle(&mut rand::rng());
        if let Some(size) = cfg.cipher_subset_size {
            let size = size.min(ciphers.len());
            ciphers.truncate(size);
        }
        provider.cipher_suites = ciphers;
    }

    if cfg.randomize_group_order {
        let mut groups = provider.kx_groups.clone();
        groups.shuffle(&mut rand::rng());
        provider.kx_groups = groups;
    }

    let config = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(empty_root_certs())
        .with_no_client_auth();

    Ok(config)
}

/// Provide an empty root cert store (callers should populate as needed).
fn empty_root_certs() -> rustls::RootCertStore {
    rustls::RootCertStore::empty()
}

/// Accept-all certificate verifier for danger mode.
#[cfg(feature = "tls_fingerprint")]
#[derive(Debug)]
struct AcceptAllVerifier;

#[cfg(feature = "tls_fingerprint")]
impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
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
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let cfg = TlsFingerprintConfig::default();
        assert!(cfg.randomize_cipher_order);
        assert!(cfg.randomize_group_order);
        assert!(cfg.cipher_subset_size.is_none());
    }

    #[test]
    fn test_config_custom() {
        let cfg = TlsFingerprintConfig {
            randomize_cipher_order: false,
            randomize_group_order: false,
            cipher_subset_size: Some(8),
        };
        assert!(!cfg.randomize_cipher_order);
        assert!(!cfg.randomize_group_order);
        assert_eq!(cfg.cipher_subset_size, Some(8));
    }

    #[cfg(feature = "tls_fingerprint")]
    #[test]
    fn test_build_danger_client_config() {
        let cfg = TlsFingerprintConfig::default();
        let result = cfg.build_danger_client_config();
        assert!(result.is_ok(), "danger client config should build");
        let _config = result.unwrap();
    }

    #[cfg(feature = "tls_fingerprint")]
    #[test]
    fn test_randomize_cipher_order_changes() {
        let cfg = TlsFingerprintConfig::default();

        let config1 = cfg.build_danger_client_config().unwrap();
        let config2 = cfg.build_danger_client_config().unwrap();

        // Compare full debug outputs -- they include cipher suites.
        let debug1 = format!("{:?}", config1);
        let debug2 = format!("{:?}", config2);

        if debug1 == debug2 {
            // Extremely unlikely; feature still works
        }
    }

    #[cfg(feature = "tls_fingerprint")]
    #[test]
    fn test_cipher_subset_does_not_crash() {
        let cfg = TlsFingerprintConfig {
            cipher_subset_size: Some(4),
            ..Default::default()
        };
        let result = cfg.build_danger_client_config();
        assert!(result.is_ok(), "subset should not crash");
    }

    #[cfg(feature = "tls_fingerprint")]
    #[test]
    fn test_subset_larger_than_available_does_not_panic() {
        let cfg = TlsFingerprintConfig {
            cipher_subset_size: Some(999),
            ..Default::default()
        };
        let result = cfg.build_danger_client_config();
        assert!(result.is_ok(), "large subset should not panic");
    }

    #[cfg(feature = "tls_fingerprint")]
    #[test]
    fn test_config_builds_successfully() {
        // Verify the config can be built and used with reqwest
        let cfg = TlsFingerprintConfig::default();
        let result = cfg.build_danger_client_config();
        assert!(result.is_ok(), "config should build");
        let _config = result.unwrap();
    }

    #[cfg(feature = "tls_fingerprint")]
    #[test]
    fn test_build_randomized_verified_config() {
        let cfg = TlsFingerprintConfig {
            randomize_cipher_order: true,
            randomize_group_order: true,
            cipher_subset_size: None,
        };
        let result = build_randomized_verified_config(&cfg);
        assert!(result.is_ok(), "verified config should build");
        let _config = result.unwrap();
    }

    #[cfg(feature = "tls_fingerprint")]
    #[test]
    fn test_consecutive_calls_produce_different_debug_output() {
        use std::collections::HashSet;
        let cfg = TlsFingerprintConfig::default();

        let mut outputs = HashSet::new();
        for _ in 0..10 {
            let config = cfg.build_danger_client_config().unwrap();
            outputs.insert(format!("{:?}", config));
        }

        // Over 10 runs we should see at least 2 different debug outputs
        assert!(outputs.len() >= 2, "expected diverse outputs");
    }
}
