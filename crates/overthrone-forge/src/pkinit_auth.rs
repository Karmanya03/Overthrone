//! PKINIT authentication for certificate-based TGT acquisition.
//!
//! Provides a bridge between PKINIT (client certificate authentication)
//! and the Kerberos ticket forging pipeline. Instead of requiring a
//! password or NTLM hash, users can supply a PEM-encoded client
//! certificate and private key to obtain a TGT via PKINIT.
//!
//! This TGT can then be used for:
//! - Diamond Ticket forging (legitimate TGT modification)
//! - Sapphire Ticket forging (KDC-issued PAC extraction via S4U2Self)
//! - Bronze Bit (S4U2Proxy bypass)
//! - Any operation needing a TGT without password exposure

use chrono::DateTime;
use kerberos_asn1::Asn1Object;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::TicketGrantingData;
use overthrone_core::proto::pkinit::{PkinitAuthenticator, PkinitConfig};
use std::path::Path;
use tracing::info;

/// PEM-to-DER conversion helper.
fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let mut in_body = false;
    let mut der = Vec::new();
    for line in pem_data.lines() {
        if line.starts_with("-----BEGIN ") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if in_body {
            let line = line.trim();
            let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, line)
                .map_err(|e| {
                    OverthroneError::TicketForge(format!("PEM base64 decode error: {e}"))
                })?;
            der.extend_from_slice(&decoded);
        }
    }
    if der.is_empty() {
        return Err(OverthroneError::TicketForge(
            "Empty or invalid PEM data — expected BEGIN/END markers with base64 content".into(),
        ));
    }
    Ok(der)
}

/// Authenticate to the KDC using PKINIT with a PEM-encoded client certificate and key.
///
/// # Arguments
/// * `dc_ip` - KDC IP or hostname
/// * `domain` - Kerberos realm / AD domain
/// * `username` - User to authenticate as
/// * `cert_path` - Path to PEM-encoded X.509 client certificate
/// * `key_path` - Path to PEM-encoded private key (PKCS#8)
///
/// # Returns
/// A `TicketGrantingData` containing the TGT and session key,
/// ready for use in forge operations (diamond, S4U2Self, etc.).
pub async fn pkinit_authenticate(
    dc_ip: &str,
    domain: &str,
    username: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<TicketGrantingData> {
    if !Path::new(cert_path).exists() {
        return Err(OverthroneError::TicketForge(format!(
            "PKINIT cert file not found: {cert_path}"
        )));
    }
    if !Path::new(key_path).exists() {
        return Err(OverthroneError::TicketForge(format!(
            "PKINIT key file not found: {key_path}"
        )));
    }

    let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| {
        OverthroneError::TicketForge(format!("Failed to read cert file '{cert_path}': {e}"))
    })?;
    let key_pem = std::fs::read_to_string(key_path).map_err(|e| {
        OverthroneError::TicketForge(format!("Failed to read key file '{key_path}': {e}"))
    })?;

    let cert_der = pem_to_der(&cert_pem)?;
    let key_der = pem_to_der(&key_pem)?;

    let realm = domain.to_uppercase();
    let pkinit_config = PkinitConfig {
        certificate: cert_der,
        private_key: key_der,
        realm: realm.clone(),
        username: username.to_string(),
        kdc_host: dc_ip.to_string(),
        check_revocation: false,
        revocation_timeout_secs: 10,
    };

    info!("[pkinit] Authenticating as {username}@{realm} via PKINIT to {dc_ip}");
    let authenticator = PkinitAuthenticator::new(pkinit_config);
    let result = authenticator.authenticate().await?;

    info!(
        "[pkinit] PKINIT auth succeeded: TGT obtained (session key etype: {}, {} bytes)",
        result.session_key_etype,
        result.session_key.len()
    );

    // Parse the raw ticket bytes back into a Ticket struct
    let (_, ticket) = kerberos_asn1::Ticket::parse(&result.tgt)
        .map_err(|e| OverthroneError::TicketForge(format!("Failed to parse PKINIT TGT: {e}")))?;

    Ok(TicketGrantingData {
        ticket,
        session_key: result.session_key,
        session_key_etype: result.session_key_etype,
        client_principal: username.to_string(),
        client_realm: realm,
        end_time: {
            let dt = DateTime::from_timestamp(result.valid_until as i64, 0).unwrap_or_default();
            Some(kerberos_asn1::KerberosTime::from(dt))
        },
    })
}
