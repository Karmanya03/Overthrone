//! PKCS#12 (PFX) Generation
//!
//! Creates PFX files from certificate + private key for import into Windows certificate store.

use crate::error::{OverthroneError, Result};
use base64::Engine;
use tracing::info;

// ═══════════════════════════════════════════════════════════
// PKCS#12 / PFX Generation
// ═══════════════════════════════════════════════════════════

/// PFX (PKCS#12) container for certificate and private key
pub struct PfxBuilder {
    certificate_der: Vec<u8>,
    private_key_pem: String,
    friendly_name: String,
    password: String,
}

impl PfxBuilder {
    /// Create a new PFX builder
    pub fn new(certificate_der: Vec<u8>, private_key_pem: String) -> Self {
        Self {
            certificate_der,
            private_key_pem,
            friendly_name: "Overthrone Certificate".to_string(),
            password: String::new(),
        }
    }

    /// Set the friendly name for the certificate
    pub fn with_friendly_name(mut self, name: impl Into<String>) -> Self {
        self.friendly_name = name.into();
        self
    }

    /// Set the password for the PFX (empty = no password)
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    /// Build the PFX file
    ///
    /// Returns the DER-encoded PFX file content using proper MAC and encryption.
    pub fn build(self) -> Result<Vec<u8>> {
        info!("Building PFX file");

        let cert = p12_keystore::Certificate::from_der(&self.certificate_der).map_err(|e| {
            OverthroneError::Decryption(format!("Failed to parse certificate: {:?}", e))
        })?;

        // Parse key DER from PEM
        let pem_content = self
            .private_key_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
            .replace("\r", "")
            .replace("\n", "");

        let key_der = base64::engine::general_purpose::STANDARD
            .decode(&pem_content)
            .map_err(|e| {
                OverthroneError::Decryption(format!("Failed to decode private key: {}", e))
            })?;

        // Generate a random local key ID to bind the cert and key together
        let local_key_id = (0..20).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        let key_chain = p12_keystore::PrivateKeyChain::new(key_der, local_key_id, vec![cert]);

        let mut store = p12_keystore::KeyStore::new();
        store.add_entry(
            &self.friendly_name,
            p12_keystore::KeyStoreEntry::PrivateKeyChain(key_chain),
        );

        let pfx_data = store
            .writer(&self.password)
            .write()
            .map_err(|e| OverthroneError::Decryption(format!("Failed to build PFX: {:?}", e)))?;

        Ok(pfx_data)
    }
}

pub fn create_pfx(
    certificate_der: &[u8],
    private_key_pem: &str,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let builder = PfxBuilder::new(certificate_der.to_vec(), private_key_pem.to_string());

    let builder = if let Some(pwd) = password {
        builder.with_password(pwd)
    } else {
        builder
    };

    builder.build()
}

pub fn create_pfx_with_name(
    certificate_der: &[u8],
    private_key_pem: &str,
    friendly_name: &str,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let builder = PfxBuilder::new(certificate_der.to_vec(), private_key_pem.to_string())
        .with_friendly_name(friendly_name);

    let builder = if let Some(pwd) = password {
        builder.with_password(pwd)
    } else {
        builder
    };

    builder.build()
}

pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .collect();

    format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----\n",
        label,
        lines.join("\n"),
        label
    )
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let content = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .replace("\r", "")
        .replace("\n", "");

    base64::engine::general_purpose::STANDARD
        .decode(&content)
        .map_err(|e| OverthroneError::Decryption(format!("PEM decode failed: {}", e)))
}

pub fn certificate_to_pem(der: &[u8]) -> String {
    der_to_pem(der, "CERTIFICATE")
}

pub fn private_key_to_pem(der: &[u8]) -> String {
    der_to_pem(der, "PRIVATE KEY")
}

pub fn pfx_to_base64(pfx_der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(pfx_der)
}
