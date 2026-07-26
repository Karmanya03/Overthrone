//! Kerberos password change (kpasswd / MS-KPP) implementation.
//! Changes a user's password via the `kadmin/changepw` service on the KDC
//! (default TCP port 464). Built on top of the existing Kerberos TGT/TGS helpers.

use crate::proto::kerberos::{
    TicketGrantingData, build_ap_req, build_encrypted_authenticator, normalize_realm,
    normalize_username, request_service_ticket, request_tgt,
};
use chrono::Utc;
use kerberos_asn1::{Asn1Object, EncKrbPrivPart, EncryptedData, HostAddress, KrbError, KrbPriv};
use kerberos_crypto::new_kerberos_cipher;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub const KPASSWD_PORT: u16 = 464;
const KEY_USAGE_KRB_PRIV_ENC_PART: i32 = 13;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub struct KpasswdConfig {
    pub dc_ip: String,
    pub domain: String,
    pub username: String,
    pub secret: String,
    pub use_hash: bool,
    pub new_password: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub struct KpasswdResult {
    pub success: bool,
    pub message: String,
    pub result_code: i32,
}

impl std::fmt::Display for KpasswdResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "kpasswd {} (code {})",
            if self.success { "success" } else { "failure" },
            self.result_code
        )?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum KpasswdError {
    #[error("TGT request failed: {0}")]
    TgtError(String),
    #[error("TGS request failed: {0}")]
    TgsError(String),
    #[error("AP-REQ build failed: {0}")]
    ApReqError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

impl KpasswdError {
    fn from_kerberos_err(e: crate::error::OverthroneError) -> Self {
        let msg = e.to_string();
        let lower = msg.to_lowercase();
        if lower.contains("unreachable")
            || lower.contains("cannot reach")
            || lower.contains("invalid kdc address")
            || lower.contains("connection failed")
            || lower.contains("connection refused")
            || lower.contains("timeout")
            || lower.contains("network")
        {
            return KpasswdError::NetworkError(msg);
        }
        if lower.contains("request_tgt") {
            return KpasswdError::TgtError(msg);
        }
        if lower.contains("request_service_ticket") || lower.contains("service ticket") {
            return KpasswdError::TgsError(msg);
        }
        KpasswdError::ProtocolError(msg)
    }
}

fn asn1_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}
fn asn1_seq(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30];
    v.extend(asn1_len(data.len()));
    v.extend_from_slice(data);
    v
}
fn asn1_oct(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04];
    v.extend(asn1_len(data.len()));
    v.extend_from_slice(data);
    v
}

fn build_change_payload(new_password: &str) -> Vec<u8> {
    let b = new_password.as_bytes();
    asn1_seq(&[asn1_oct(b).as_slice(), asn1_oct(b).as_slice()].concat())
}
fn build_reset_payload(target_user: &str, new_password: &str) -> Vec<u8> {
    let np = new_password.as_bytes();
    asn1_seq(
        &[
            asn1_oct(target_user.as_bytes()).as_slice(),
            asn1_oct(np).as_slice(),
            asn1_oct(np).as_slice(),
        ]
        .concat(),
    )
}

fn build_krb_priv(ticket: &TicketGrantingData, payload: &[u8]) -> Result<Vec<u8>, KpasswdError> {
    let cipher = new_kerberos_cipher(ticket.session_key_etype)
        .map_err(|e| KpasswdError::ProtocolError(format!("Cipher init: {e}")))?;
    let now = Utc::now();
    let enc_part = EncKrbPrivPart {
        user_data: payload.to_vec(),
        timestamp: Some(now.into()),
        usec: Some((now.timestamp_subsec_micros() as i32).clamp(0, 999_999)),
        seq_number: Some(rand::random::<u32>()),
        s_address: HostAddress {
            addr_type: 0,
            address: vec![127, 0, 0, 1],
        },
        r_address: None,
    };
    let encrypted = cipher.encrypt(
        &ticket.session_key,
        KEY_USAGE_KRB_PRIV_ENC_PART,
        &enc_part.build(),
    );
    Ok(KrbPriv {
        pvno: 5,
        msg_type: 21,
        enc_part: EncryptedData {
            etype: ticket.session_key_etype,
            kvno: None,
            cipher: encrypted,
        },
    }
    .build())
}

async fn send_kpasswd(
    dc_ip: &str,
    port: u16,
    ap_req: &[u8],
    krb_priv: &[u8],
) -> Result<Vec<u8>, KpasswdError> {
    let addr: std::net::SocketAddr = format!("{dc_ip}:{port}")
        .parse()
        .map_err(|e| KpasswdError::NetworkError(format!("Invalid address: {e}")))?;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|e| KpasswdError::NetworkError(format!("Timeout: {e}")))?
        .map_err(|e| KpasswdError::NetworkError(format!("Connect failed: {e}")))?;
    write_frame(&mut stream, ap_req).await?;
    let _ = read_frame(&mut stream).await?;
    write_frame(&mut stream, krb_priv).await?;
    read_frame(&mut stream).await
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), KpasswdError> {
    let mut msg = (data.len() as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(data);
    stream
        .write_all(&msg)
        .await
        .map_err(|e| KpasswdError::NetworkError(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| KpasswdError::NetworkError(e.to_string()))
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, KpasswdError> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .map_err(|e| KpasswdError::NetworkError(format!("Timeout: {e}")))?
        .map_err(|e| KpasswdError::NetworkError(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(KpasswdError::ProtocolError(format!(
            "Response too large: {len}"
        )));
    }
    let mut data = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut data))
        .await
        .map_err(|e| KpasswdError::NetworkError(format!("Timeout: {e}")))?
        .map_err(|e| KpasswdError::NetworkError(e.to_string()))?;
    Ok(data)
}

fn parse_response(response: &[u8], service_key: &[u8], etype: i32) -> KpasswdResult {
    if response.is_empty() {
        return KpasswdResult {
            success: false,
            message: "Empty response".to_string(),
            result_code: -1,
        };
    }
    if response[0] == 0x7e {
        return match KrbError::parse(response) {
            Ok((_, err)) => KpasswdResult {
                success: false,
                message: format!("KRB-ERROR {}", err.error_code),
                result_code: err.error_code,
            },
            Err(_) => KpasswdResult {
                success: false,
                message: "KRB-ERROR parse failed".to_string(),
                result_code: -1,
            },
        };
    }
    if response[0] != 0x75 {
        return KpasswdResult {
            success: false,
            message: "Unrecognized response".to_string(),
            result_code: -1,
        };
    }
    let Ok((_, priv_part)) = KrbPriv::parse(response) else {
        return KpasswdResult {
            success: false,
            message: "KRB-PRIV parse failed".to_string(),
            result_code: -1,
        };
    };
    let Ok(cipher) = new_kerberos_cipher(etype) else {
        return KpasswdResult {
            success: false,
            message: "Cipher init failed".to_string(),
            result_code: -1,
        };
    };
    let Ok(decrypted) = cipher.decrypt(
        service_key,
        KEY_USAGE_KRB_PRIV_ENC_PART,
        &priv_part.enc_part.cipher,
    ) else {
        return KpasswdResult {
            success: false,
            message: "KRB-PRIV decrypt failed".to_string(),
            result_code: -1,
        };
    };
    let Ok((_, enc_part)) = EncKrbPrivPart::parse(&decrypted) else {
        return KpasswdResult {
            success: false,
            message: "EncKrbPrivPart parse failed".to_string(),
            result_code: -1,
        };
    };
    let code = if enc_part.user_data.len() >= 2 {
        i32::from(u16::from_le_bytes([
            enc_part.user_data[0],
            enc_part.user_data[1],
        ]))
    } else {
        -1
    };
    KpasswdResult {
        success: code == 0,
        message: String::from_utf8_lossy(&enc_part.user_data).to_string(),
        result_code: code,
    }
}

async fn run_kpasswd(
    config: &KpasswdConfig,
    target_user: Option<&str>,
) -> Result<KpasswdResult, KpasswdError> {
    let realm = normalize_realm(&config.domain);
    let username = normalize_username(&config.username);
    info!(
        "kpasswd: {} password for {}@{}",
        if target_user.is_some() {
            "resetting"
        } else {
            "changing"
        },
        username,
        realm
    );
    let tgt = request_tgt(
        &config.dc_ip,
        &realm,
        username,
        &config.secret,
        config.use_hash,
    )
    .await
    .map_err(KpasswdError::from_kerberos_err)?;
    let tkt = request_service_ticket(&config.dc_ip, &tgt, "kadmin/changepw")
        .await
        .map_err(KpasswdError::from_kerberos_err)?;
    let ap_req = build_ap_req_for_ticket(&tkt, &realm, username)?;
    let payload = match target_user {
        Some(u) => build_reset_payload(u, &config.new_password),
        None => build_change_payload(&config.new_password),
    };
    let krb_priv = build_krb_priv(&tkt, &payload)?;
    let response = send_kpasswd(&config.dc_ip, config.port, &ap_req, &krb_priv).await?;
    Ok(parse_response(
        &response,
        &tkt.session_key,
        tkt.session_key_etype,
    ))
}

fn build_ap_req_for_ticket(
    ticket: &TicketGrantingData,
    realm: &str,
    username: &str,
) -> Result<Vec<u8>, KpasswdError> {
    let enc_auth = build_encrypted_authenticator(
        realm,
        username,
        &ticket.session_key,
        ticket.session_key_etype,
    )
    .map_err(|e| KpasswdError::ApReqError(e.to_string()))?;
    Ok(build_ap_req(&ticket.ticket, enc_auth).build())
}

pub async fn kpasswd_change_password(
    config: &KpasswdConfig,
) -> Result<KpasswdResult, KpasswdError> {
    run_kpasswd(config, None).await
}
pub async fn kpasswd_reset_password(
    config: &KpasswdConfig,
    target_user: &str,
) -> Result<KpasswdResult, KpasswdError> {
    run_kpasswd(config, Some(target_user)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kpasswd_config_default() {
        let c = KpasswdConfig::default();
        assert!(c.dc_ip.is_empty() && c.username.is_empty() && c.secret.is_empty());
        assert!(!c.use_hash && c.port == 0);
    }

    #[test]
    fn test_kpasswd_config_custom() {
        let c = KpasswdConfig {
            dc_ip: "192.0.2.1".to_string(),
            domain: "sevenkingdoms.local".to_string(),
            username: "jon.snow".to_string(),
            secret: "x".to_string(),
            use_hash: true,
            new_password: "New!".to_string(),
            port: 464,
        };
        assert_eq!(c.port, 464);
        assert!(c.use_hash && c.username == "jon.snow");
    }

    #[test]
    fn test_kpasswd_result_display() {
        let ok = KpasswdResult {
            success: true,
            message: "changed".to_string(),
            result_code: 0,
        };
        assert_eq!(ok.to_string(), "kpasswd success (code 0): changed");
        let fail = KpasswdResult {
            success: false,
            message: String::new(),
            result_code: 1,
        };
        assert_eq!(fail.to_string(), "kpasswd failure (code 1)");
    }

    #[test]
    fn test_kpasswd_error_display() {
        let e = KpasswdError::TgtError("preauth failed".to_string());
        assert_eq!(e.to_string(), "TGT request failed: preauth failed");
        assert!(
            KpasswdError::NetworkError("timeout".to_string())
                .to_string()
                .contains("timeout")
        );
    }

    #[test]
    fn test_kpasswd_error_debug() {
        let s = format!("{:?}", KpasswdError::ProtocolError("bad tag".to_string()));
        assert!(s.contains("ProtocolError") && s.contains("bad tag"));
    }

    #[tokio::test]
    async fn test_kpasswd_change_password_invalid_dc() {
        let cfg = KpasswdConfig {
            dc_ip: "127.0.0.1".to_string(),
            domain: "sevenkingdoms.local".to_string(),
            username: "test".to_string(),
            secret: "test".to_string(),
            use_hash: false,
            new_password: "NewPass!".to_string(),
            port: 464,
        };
        let err = kpasswd_change_password(&cfg).await.unwrap_err();
        assert!(
            matches!(
                err,
                KpasswdError::NetworkError(_) | KpasswdError::TgtError(_)
            ),
            "expected network/TGT error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_kpasswd_reset_password_invalid_dc() {
        let cfg = KpasswdConfig {
            dc_ip: "127.0.0.1".to_string(),
            domain: "sevenkingdoms.local".to_string(),
            username: "admin".to_string(),
            secret: "test".to_string(),
            use_hash: false,
            new_password: "Reset!".to_string(),
            port: 464,
        };
        let err = kpasswd_reset_password(&cfg, "target.user")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                KpasswdError::NetworkError(_) | KpasswdError::TgtError(_)
            ),
            "expected network/TGT error, got {err:?}"
        );
    }

    #[test]
    fn test_build_kpasswd_payload() {
        let p = build_change_payload("NewPass123!");
        assert_eq!(p[0], 0x30);
        let inner = &p[2..];
        assert_eq!(inner[0], 0x04);
        let first_len = inner[1] as usize;
        assert_eq!(&inner[2..2 + first_len], b"NewPass123!");
    }
}
