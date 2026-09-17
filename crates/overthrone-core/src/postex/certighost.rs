//! Certighost — CA chase fallback enrollment via CES (MS-WSTEP) and `/certsrv`.
//!
//! # Why this file was rewriting the wrong protocol
//!
//! CES (the Certificate Enrollment *Web Service*) does not expose a
//! `RequestCertificate` / `GetClientCertificate` operation. It implements
//! **MS-WSTEP**, which is a profile of **WS-Trust**: the client POSTs a
//! *RequestSecurityToken* (RST) inside a SOAP envelope, and the service replies
//! with a *RequestSecurityTokenResponseCollection* (RSTR).
//!
//! The three things that must be right, all of which the earlier revision got
//! wrong:
//!
//! 1. **The action and SOAP body shape.** The action is
//!    `.../enrollment/RST/wstep`, and the body is
//!    `<RequestSecurityToken>` in the WS-Trust 2005/12 namespace carrying
//!    `<TokenType>` (X509v3) and `<RequestType>.../Issue</RequestType>`. The old
//!    code sent `<GetClientCertificate>` under an `IGetCSPCount` action — neither
//!    is a WSTEP operation, so no CES could ever issue anything.
//! 2. **How the template is communicated.** There is no `<template>` element.
//!    The template name goes into the CSR as the Microsoft
//!    `szOID_ENROLL_CERTTYPE` extension (OID 1.3.6.1.4.1.311.20.2) whose value
//!    is a `BMPString`.
//! 3. **Certificate request encoding.** A PKCS#10 CSR is DER, so the
//!    `attributes [0]` field and the SAN `GeneralName [2]` must use *implicit*
//!    tagging (`0xA0`/`0x82`), and the signature must be a real
//!    SHA256withRSA (with the DigestInfo prefix), not a prefix-less raw RSA
//!    signature that every CA rejects.
//!
//! # CES vs NDES
//!
//! CES = MS-WSTEP (SOAP, this module). NDES = SCEP (`/certsrv/mscep/`, a
//! completely different protocol that is **not** implemented here). The
//! `/certsrv` path in this module is legacy form-based web enrollment, which is
//! also not NDES.

use crate::adcs::web_enrollment::WebEnrollmentClient;
use base64::Engine;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;
use thiserror::Error;
use yasna::Tag;
use yasna::models::ObjectIdentifier;

// ===========================================================
//  Protocol Constants
// ===========================================================

/// SOAP 1.2 envelope namespace.
const SOAP_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
/// WS-Addressing 1.0 (August 2004) namespace — what WSTEP uses.
const WSA_NS: &str = "http://www.w3.org/2005/08/addressing";
/// WS-Trust 1.3 namespace used by the RST/RSTR body.
const WST_NS: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
/// WS-Security extensions namespace (`BinarySecurityToken` lives here).
const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
/// WS-Security utility namespace (for `wsu:Id`).
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
/// The MS-WSTEP RST SOAP action.
pub const WSTEP_RST_ACTION: &str =
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep";
/// Token type: an X.509v3 certificate.
const TOKEN_TYPE_X509V3: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
/// Request type for an issuance.
const REQUEST_TYPE_ISSUE: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
/// Value type marking the request payload as PKCS#10.
const VALUE_TYPE_PKCS10: &str =
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10";
/// Base64 binary encoding type.
const ENCODING_BASE64: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";
/// `szOID_ENROLL_CERTTYPE` — the certificate template name extension.
const OID_ENROLL_CERTTYPE: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 20, 2];
/// `id-ce-subjectAltName`.
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
/// `extensionRequest` attribute OID.
const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];

// ===========================================================
//  Types
// ===========================================================

/// Configuration for a Certighost enrollment attempt.
#[derive(Debug, Clone)]
pub struct CertighostConfig {
    /// CA host, used by the `/certsrv` fallback (e.g. `ca.corp.local`).
    pub ca_server: String,
    /// Full CES endpoint, e.g.
    /// `https://ca.corp.local/CORP-CA_CES_Kerberos/service.svc/CES`.
    pub ces_url: String,
    /// Route the request through `proxy_url`.
    pub use_proxy: bool,
    /// Proxy URL (only used when `use_proxy`).
    pub proxy_url: Option<String>,
    /// Certificate template name (goes into the CSR, not the SOAP body).
    pub template: String,
    /// Subject CN for the CSR.
    pub subject: Option<String>,
    /// Optional SAN (dNSName) to place in the CSR.
    pub san: Option<String>,
    /// RSA key size.
    pub key_size: u32,
    /// Plan only; do not send anything.
    pub dry_run: bool,
    /// Domain name for the `/certsrv` NTLM fallback.
    pub domain: String,
    /// Username: used for HTTP Basic against CES, and for NTLM against `/certsrv`.
    pub username: String,
    /// Password for the same two paths.
    pub password: String,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
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
            domain: String::new(),
            username: String::new(),
            password: String::new(),
            timeout_secs: 60,
        }
    }
}

/// An enrollment result.
#[derive(Debug, Clone)]
pub struct CertighostResult {
    /// Issued certificate (DER), when the service returned the X509v3 token.
    pub certificate: Option<Vec<u8>>,
    /// PKCS#8 private key (DER) matching the CSR.
    pub private_key: Option<Vec<u8>>,
    /// The PKCS#7 blob from the top-level `BinarySecurityToken`, when present.
    pub pkcs7: Option<Vec<u8>>,
    /// Issuer description (best-effort).
    pub issuer: String,
    /// Template that was requested.
    pub template: String,
    /// CSR subject.
    pub subject: String,
    /// SHA-1 thumbprint of the certificate (or of the CSR when no cert was issued).
    pub thumbnail: String,
    /// Server-side request id (`RequestID`), for later retrieval.
    pub request_id: Option<String>,
    /// Human-readable status.
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

/// Errors surfaced by this module.
#[derive(Debug, Error)]
pub enum CertighostError {
    /// Transport-level failure (DNS, TLS, connection).
    #[error("HTTP error: {0}")]
    HttpError(String),
    /// The service refused or the exchange was rejected.
    #[error("enrollment error: {0}")]
    EnrollmentError(String),
    /// Key generation or CSR signing failed.
    #[error("key generation error: {0}")]
    KeyGeneration(String),
    /// The response could not be understood.
    #[error("parser error: {0}")]
    ParserError(String),
}

// ===========================================================
//  CSR construction
// ===========================================================

/// Build a PKCS#10 CSR with the Microsoft certificate-template extension.
///
/// `template` is encoded as the `szOID_ENROLL_CERTTYPE` extension value (a
/// `BMPString`), which is how CES/CEP learn which template to use. `san`, when
/// present, is added as a `dNSName` `GeneralName` inside `subjectAltName`.
///
/// Returns `(csr_der, pkcs8_private_key_der)`.
pub fn build_csr(
    subject: &str,
    san: Option<&str>,
    template: &str,
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

    // CertificationRequestInfo
    let cri = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0); // version
            // subject = SEQUENCE OF RDN -> SET OF AttributeTypeAndValue
            w.next().write_sequence(|w| {
                w.next().write_set(|w| {
                    w.next().write_sequence(|w| {
                        w.next()
                            .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3])); // CN
                        w.next().write_utf8_string(subject);
                    });
                });
            });
            // subjectPKInfo
            w.next().write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));
                    w.next().write_null();
                });
                w.next()
                    .write_bitvec_bytes(pk_der.as_bytes(), pk_der.as_bytes().len() * 8);
            });
            // attributes [0] IMPLICIT SET OF Attribute { extensionRequest }
            //
            // IMPLICIT matters: an explicit `[0] { SET { ... } }` is invalid
            // DER for PKCS#10 and CAs will refuse the request.
            w.next().write_tagged_implicit(Tag::context(0), |w| {
                w.write_set(|w| {
                    w.next().write_sequence(|w| {
                        w.next()
                            .write_oid(&ObjectIdentifier::from_slice(OID_EXTENSION_REQUEST));
                        w.next().write_set(|w| {
                            // Extensions ::= SEQUENCE OF Extension
                            w.next().write_sequence(|w| {
                                // szOID_ENROLL_CERTTYPE -> BMPString(template)
                                w.next().write_sequence(|w| {
                                    w.next().write_oid(&ObjectIdentifier::from_slice(
                                        OID_ENROLL_CERTTYPE,
                                    ));
                                    let value =
                                        yasna::construct_der(|w| w.write_bmp_string(template));
                                    w.next().write_bytes(&value);
                                });
                                // subjectAltName (optional)
                                if let Some(san_value) = san {
                                    w.next().write_sequence(|w| {
                                        w.next().write_oid(&ObjectIdentifier::from_slice(
                                            OID_SUBJECT_ALT_NAME,
                                        ));
                                        let value = yasna::construct_der(|w| {
                                            w.write_sequence(|w| {
                                                // GeneralName dNSName [2] IMPLICIT IA5String
                                                w.next()
                                                    .write_tagged_implicit(Tag::context(2), |w| {
                                                        w.write_ia5_string(san_value)
                                                    });
                                            });
                                        });
                                        w.next().write_bytes(&value);
                                    });
                                }
                            });
                        });
                    });
                });
            });
        })
    });

    // sha256WithRSA: the DigestInfo prefix is required. Signing the raw digest
    // without it (Pkcs1v15Sign::new_unprefixed) produces a signature no CA
    // accepts.
    let digest = Sha256::digest(&cri);
    let signature = private_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| CertighostError::KeyGeneration(format!("Signing failed: {e}")))?;

    let csr = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&cri);
            w.next().write_sequence(|w| {
                // sha256WithRSAEncryption
                w.next().write_oid(&ObjectIdentifier::from_slice(&[
                    1, 2, 840, 113549, 1, 1, 11,
                ]));
                w.next().write_null();
            });
            w.next().write_bitvec_bytes(&signature, signature.len() * 8);
        })
    });

    Ok((csr, pkcs8_key.as_bytes().to_vec()))
}

// ===========================================================
//  MS-WSTEP request
// ===========================================================

/// Build the MS-WSTEP `RequestSecurityToken` SOAP envelope.
///
/// `csr_b64` is the base64 of the DER CSR (template already embedded), and
/// `message_id` must be a `urn:uuid:` unique id echoed by the server's
/// `RelatesTo`.
pub fn build_wstep_rst(ces_url: &str, csr_b64: &str, message_id: &str) -> String {
    format!(
        concat!(
            "<s:Envelope xmlns:a=\"{wsa}\" xmlns:s=\"{soap}\">",
            "<s:Header>",
            "<a:Action s:mustUnderstand=\"1\">{action}</a:Action>",
            "<a:MessageID>{message_id}</a:MessageID>",
            "<a:To s:mustUnderstand=\"1\">{url}</a:To>",
            "</s:Header>",
            "<s:Body>",
            "<RequestSecurityToken PreferredLanguage=\"en-US\" xmlns=\"{wst}\">",
            "<TokenType>{token_type}</TokenType>",
            "<RequestType>{request_type}</RequestType>",
            "<BinarySecurityToken ValueType=\"{pkcs10}\" EncodingType=\"{b64}\" ",
            "a:Id=\"\" xmlns:a=\"{wsu}\" xmlns=\"{wsse}\">",
            "{csr}",
            "</BinarySecurityToken>",
            "</RequestSecurityToken>",
            "</s:Body>",
            "</s:Envelope>",
        ),
        wsa = WSA_NS,
        soap = SOAP_NS,
        action = WSTEP_RST_ACTION,
        message_id = message_id,
        url = ces_url,
        wst = WST_NS,
        token_type = TOKEN_TYPE_X509V3,
        request_type = REQUEST_TYPE_ISSUE,
        pkcs10 = VALUE_TYPE_PKCS10,
        b64 = ENCODING_BASE64,
        wsu = WSU_NS,
        wsse = WSSE_NS,
        csr = csr_b64,
    )
}

// ===========================================================
//  Response parsing
// ===========================================================

/// Parsed MS-WSTEP response.
#[derive(Debug, Clone)]
pub struct WstepResponse {
    /// The X.509v3 certificate (DER) from `RequestedSecurityToken`.
    pub certificate: Option<Vec<u8>>,
    /// The PKCS#7 blob from the top-level `BinarySecurityToken`.
    pub pkcs7: Option<Vec<u8>>,
    /// `DispositionMessage` text (contains the CA's status code, e.g. `0x80094004`).
    pub disposition: String,
    /// Server-assigned `RequestID`, used to retrieve a pended request later.
    pub request_id: Option<String>,
}

/// Find all elements with the given local name, returning `(attributes, inner_xml)`.
///
/// Namespace prefixes are handled by comparing only the part after `:`.
fn find_elements(xml: &str, local: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < xml.len() {
        let Some(rel) = xml[cursor..].find('<') else {
            break;
        };
        let start = cursor + rel;
        let rest = &xml[start + 1..];
        if rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('!') {
            cursor = start + 1;
            continue;
        }
        let name_end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        let raw_name = &rest[..name_end];
        let local_name = raw_name.rsplit(':').next().unwrap_or(raw_name);
        let Some(open_end) = rest.find('>') else {
            break;
        };
        let attrs = rest[name_end..open_end].trim().to_string();
        let self_closing = rest[..open_end].ends_with('/');
        let inner_start = start + 1 + open_end + 1;

        if local_name == local && !self_closing {
            for close in [format!("</{raw_name}>"), format!("</{local_name}>")] {
                if let Some(rel_close) = xml[inner_start..].find(&close) {
                    out.push((
                        attrs.clone(),
                        xml[inner_start..inner_start + rel_close].to_string(),
                    ));
                    cursor = inner_start + rel_close + close.len();
                    break;
                }
            }
            if cursor > start {
                continue;
            }
        }
        cursor = start + 1;
    }
    out
}

/// Text content of the first element with the given local name.
fn elem_text(xml: &str, local: &str) -> Option<String> {
    find_elements(xml, local)
        .into_iter()
        .next()
        .map(|(_, inner)| inner.trim().to_string())
}

/// Value of `name="..."` inside an attribute string.
fn attr_value(attrs: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = attrs.find(&needle)? + needle.len();
    let rest = &attrs[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Decode a base64 element body, tolerating the whitespace and XML character
/// references (`&#xD;`) that WCF inserts at line breaks.
fn decode_b64_element(raw: &str) -> Result<Vec<u8>, CertighostError> {
    let cleaned: String = raw
        .replace("&#xD;", "")
        .replace("&#xA;", "")
        .replace("&#13;", "")
        .replace("&#10;", "")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|e| CertighostError::ParserError(format!("base64 decode: {e}")))
}

/// Detect a SOAP fault and return a readable description.
fn detect_soap_fault(body: &str) -> Option<String> {
    if !body.contains("Fault") {
        return None;
    }
    let reason = elem_text(body, "Text").or_else(|| elem_text(body, "faultstring"));
    let code = elem_text(body, "Value").or_else(|| elem_text(body, "faultcode"));
    Some(match (code, reason) {
        (Some(c), Some(r)) => format!("SOAP fault: {c} - {r}"),
        (None, Some(r)) => format!("SOAP fault: {r}"),
        _ => "SOAP fault (unparsed)".to_string(),
    })
}

/// Parse an MS-WSTEP `RequestSecurityTokenResponseCollection`.
///
/// The issued certificate is the `BinarySecurityToken` with
/// `ValueType="...#X509v3"`, which appears inside `RequestedSecurityToken`. The
/// top-level `BinarySecurityToken` carries the same certificate wrapped as
/// PKCS#7 and is kept separately so callers can use either.
pub fn parse_wstep_response(body: &str) -> Result<WstepResponse, CertighostError> {
    if let Some(fault) = detect_soap_fault(body) {
        return Err(CertighostError::EnrollmentError(fault));
    }

    let mut certificate = None;
    let mut pkcs7 = None;
    for (attrs, inner) in find_elements(body, "BinarySecurityToken") {
        let value_type = attr_value(&attrs, "ValueType").unwrap_or_default();
        if value_type.ends_with("#X509v3") {
            if certificate.is_none() {
                certificate = Some(decode_b64_element(&inner)?);
            }
        } else if value_type.ends_with("#PKCS7") && pkcs7.is_none() {
            pkcs7 = Some(decode_b64_element(&inner)?);
        }
    }

    let disposition = elem_text(body, "DispositionMessage").unwrap_or_default();
    let request_id = elem_text(body, "RequestID");

    if certificate.is_none() && pkcs7.is_none() {
        return Err(CertighostError::ParserError(format!(
            "no certificate in MS-WSTEP response (disposition: {})",
            if disposition.is_empty() {
                "<none>"
            } else {
                &disposition
            }
        )));
    }

    Ok(WstepResponse {
        certificate,
        pkcs7,
        disposition,
        request_id,
    })
}

// ===========================================================
//  Enrollment
// ===========================================================

/// SHA-1 hex thumbprint of a DER blob.
fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Effective template name (defaults to `User`).
fn template_of(config: &CertighostConfig) -> &str {
    if config.template.trim().is_empty() {
        "User"
    } else {
        config.template.trim()
    }
}

/// Effective CSR subject (defaults to `certighost`).
fn subject_of(config: &CertighostConfig) -> String {
    config
        .subject
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "certighost".to_string())
}

/// POST an MS-WSTEP RST to the CES endpoint.
///
/// Authentication note: CES is most commonly configured with **Negotiate**
/// (NTLM/Kerberos) transport authentication. This HTTP client cannot perform
/// Negotiate, so:
///
/// * endpoints configured for username/password auth work via HTTP Basic when
///   `username`/`password` are set;
/// * a `401`/`403` is reported explicitly, pointing at [`certighost_auto_enroll`],
///   which falls back to `/certsrv` where NTLM *is* implemented.
pub async fn certighost_enroll(
    config: &CertighostConfig,
) -> Result<CertighostResult, CertighostError> {
    let template = template_of(config).to_string();
    let subject = subject_of(config);

    let (csr_der, priv_key_der) =
        build_csr(&subject, config.san.as_deref(), &template, config.key_size)?;
    let csr_thumb = sha1_hex(&csr_der);

    if config.dry_run {
        return Ok(CertighostResult {
            certificate: None,
            private_key: Some(priv_key_der),
            pkcs7: None,
            issuer: "(dry-run)".into(),
            template,
            subject,
            thumbnail: csr_thumb,
            request_id: None,
            message: format!(
                "[dry-run] Would POST an MS-WSTEP RST ({}...) to {}",
                WSTEP_NS_PREFIX, config.ces_url
            ),
        });
    }

    if config.ces_url.trim().is_empty() {
        return Err(CertighostError::EnrollmentError(
            "ces_url is empty".to_string(),
        ));
    }

    let url = config.ces_url.trim_end_matches('/').to_string();
    let message_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let csr_b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
    let soap = build_wstep_rst(&url, &csr_b64, &message_id);

    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(config.timeout_secs));
    if config.use_proxy
        && let Some(proxy) = config.proxy_url.as_deref()
    {
        builder = builder.proxy(
            reqwest::Proxy::all(proxy)
                .map_err(|e| CertighostError::HttpError(format!("proxy config: {e}")))?,
        );
    }
    let client = builder
        .build()
        .map_err(|e| CertighostError::HttpError(format!("client build: {e}")))?;

    let mut request = client
        .post(&url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/soap+xml; charset=utf-8",
        )
        .header("SOAPAction", format!("\"{WSTEP_RST_ACTION}\""))
        .body(soap);

    if !config.username.trim().is_empty() {
        request = request.basic_auth(config.username.trim(), Some(config.password.as_str()));
    }

    let response = request
        .send()
        .await
        .map_err(|e| CertighostError::HttpError(format!("CES request failed: {e}")))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| CertighostError::ParserError(format!("read CES response: {e}")))?;

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(CertighostError::EnrollmentError(format!(
            "CES returned {status}. This endpoint needs transport authentication this client \
             cannot perform (normally Negotiate/NTLM or Kerberos). Use a Negotiate-capable \
             proxy (use_proxy/proxy_url) or let the /certsrv fallback handle it — that path \
             implements NTLM."
        )));
    }
    if !status.is_success() {
        return Err(CertighostError::EnrollmentError(format!(
            "CES returned {status}: {}",
            body.chars().take(200).collect::<String>()
        )));
    }

    let parsed = parse_wstep_response(&body)?;
    let thumbnail = parsed
        .certificate
        .as_deref()
        .map(sha1_hex)
        .unwrap_or(csr_thumb);

    Ok(CertighostResult {
        certificate: parsed.certificate,
        private_key: Some(priv_key_der),
        pkcs7: parsed.pkcs7,
        issuer: "(from CES)".into(),
        template,
        subject,
        thumbnail,
        request_id: parsed.request_id,
        message: if parsed.disposition.is_empty() {
            "Certificate issued via CES (MS-WSTEP)".to_string()
        } else {
            format!(
                "Certificate issued via CES (MS-WSTEP): {}",
                parsed.disposition
            )
        },
    })
}

/// Legacy `/certsrv` web enrollment fallback (supports NTLM).
async fn certighost_certsrv_fallback(
    config: &CertighostConfig,
) -> Result<CertighostResult, CertighostError> {
    let template = template_of(config).to_string();
    let subject = subject_of(config);
    let (csr_der, priv_key_der) =
        build_csr(&subject, config.san.as_deref(), &template, config.key_size)?;

    let client = WebEnrollmentClient::new(config.ca_server.trim())
        .map_err(|e| CertighostError::HttpError(format!("/certsrv client: {e}")))?;
    let client = if config.username.trim().is_empty() {
        client
    } else {
        client.with_credentials(&config.domain, config.username.trim(), &config.password)
    };

    let response = client
        .submit_request(&csr_der, &template, None)
        .await
        .map_err(|e| {
            CertighostError::EnrollmentError(format!("/certsrv enrollment failed: {e}"))
        })?;

    let thumbnail = response
        .certificate
        .as_deref()
        .map(sha1_hex)
        .unwrap_or_else(|| sha1_hex(&csr_der));

    Ok(CertighostResult {
        certificate: response.certificate,
        private_key: Some(priv_key_der),
        pkcs7: None,
        issuer: "(from /certsrv)".into(),
        template,
        subject,
        thumbnail,
        request_id: response.request_id.map(|id| id.to_string()),
        message: format!("/certsrv enrollment: {}", response.message),
    })
}

/// Try CES (MS-WSTEP) first, then fall back to legacy `/certsrv` enrollment.
///
/// These are genuinely different protocols and different endpoints, so the
/// fallback is not the same request retried — it is the NTLM-capable path used
/// when the CES endpoint demands transport authentication.
pub async fn certighost_auto_enroll(
    config: &CertighostConfig,
) -> Result<CertighostResult, CertighostError> {
    match certighost_enroll(config).await {
        Ok(result) => Ok(result),
        Err(ces_error) => {
            if config.ca_server.trim().is_empty() {
                return Err(CertighostError::EnrollmentError(format!(
                    "CES/MS-WSTEP enrollment failed: {ces_error} (no ca_server configured for \
                     the /certsrv fallback)"
                )));
            }
            certighost_certsrv_fallback(config).await.map_err(|e| {
                CertighostError::EnrollmentError(format!(
                    "CES/MS-WSTEP: {ces_error}; /certsrv: {e}"
                ))
            })
        }
    }
}

/// Prefix used in the dry-run message (keeps the long namespace out of the format string).
const WSTEP_NS_PREFIX: &str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";

#[cfg(test)]
mod tests {
    use super::*;

    /// DER content bytes of `szOID_ENROLL_CERTTYPE` (1.3.6.1.4.1.311.20.2), used
    /// to assert the template extension is actually present on the wire.
    const CERTTYPE_OID_DER: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02];

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Decode a DER length at `bytes[idx]`, returning `(length, header_len)`.
    fn der_length(bytes: &[u8], idx: usize) -> Option<(usize, usize)> {
        let first = *bytes.get(idx)?;
        if first < 0x80 {
            return Some((first as usize, 1));
        }
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *bytes.get(idx + 1 + i)? as usize;
        }
        Some((len, 1 + count))
    }

    /// Slice out the `CertificationRequestInfo` (first field of the CSR).
    fn csr_cri(csr: &[u8]) -> &[u8] {
        let (_, csr_hdr) = der_length(csr, 1).expect("CSR outer length");
        let content = &csr[1 + csr_hdr..];
        let (cri_len, cri_hdr) = der_length(content, 1).expect("CRI length");
        &content[..1 + cri_hdr + cri_len]
    }

    #[test]
    fn test_certighost_config_default() {
        let cfg = CertighostConfig::default();
        assert_eq!(cfg.template, "User");
        assert_eq!(cfg.key_size, 2048);
        assert_eq!(cfg.timeout_secs, 60);
        assert!(!cfg.dry_run && cfg.subject.is_none() && cfg.san.is_none());
        assert!(cfg.username.is_empty() && cfg.password.is_empty());
    }

    #[test]
    fn test_certighost_config_custom() {
        let cfg = CertighostConfig {
            ca_server: "ca.corp.local".into(),
            ces_url: "https://ca.corp.local/CORP-CA_CES_Kerberos/service.svc/CES".into(),
            template: "DomainController".into(),
            subject: Some("DC01.corp.local".into()),
            san: Some("dc01.corp.local".into()),
            key_size: 4096,
            dry_run: true,
            domain: "corp.local".into(),
            username: "jon.snow".into(),
            password: "hunter2".into(),
            timeout_secs: 30,
            ..Default::default()
        };
        assert_eq!(cfg.ca_server, "ca.corp.local");
        assert_eq!(cfg.template, "DomainController");
        assert_eq!(cfg.key_size, 4096);
        assert_eq!(cfg.timeout_secs, 30);
        assert!(cfg.dry_run);
    }

    #[test]
    fn test_certighost_result_display() {
        let r = CertighostResult {
            certificate: None,
            private_key: None,
            pkcs7: None,
            issuer: "CA-CORP-CA".into(),
            template: "User".into(),
            subject: "CN=certighost".into(),
            thumbnail: "aabbccdd".into(),
            request_id: None,
            message: "test".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("CN=certighost") && s.contains("CA-CORP-CA") && s.contains("aabbccdd"));
    }

    #[test]
    fn test_build_csr_returns_valid_asn1() {
        let (csr_der, pk) = build_csr("CN=test.local", Some("test.local"), "User", 2048).unwrap();
        assert!(!csr_der.is_empty() && !pk.is_empty());
        assert_eq!(csr_der[0], 0x30);
        assert_eq!(pk[0], 0x30);
    }

    #[test]
    fn csr_carries_certificate_template_extension() {
        // CES/CEP read the template from the CSR, not from the SOAP body.
        let (csr_der, _) = build_csr("certighost", None, "DomainController", 2048).unwrap();
        assert!(
            find_subslice(&csr_der, CERTTYPE_OID_DER).is_some(),
            "szOID_ENROLL_CERTTYPE missing from CSR"
        );

        // ...and the template name must be a BMPString (UTF-16BE).
        let units: Vec<u8> = "DomainController"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        let mut expected = vec![0x1E, units.len() as u8];
        expected.extend_from_slice(&units);
        assert!(
            find_subslice(&csr_der, &expected).is_some(),
            "template not encoded as BMPString"
        );
    }

    #[test]
    fn csr_uses_implicit_context_tag_for_attributes() {
        // Regression: `attributes [0]` was written explicitly, so the first child
        // of the [0] TLV was a SET tag (0x31) instead of the Attribute SEQUENCE.
        let (csr_der, _) = build_csr("certighost", None, "User", 2048).unwrap();
        let cri = csr_cri(&csr_der);

        // `attributes [0]` is the last field of the CRI, so the correct candidate
        // is the [0] TLV whose content ends exactly at the CRI boundary. That
        // makes the search deterministic even though the RSA modulus (also inside
        // the CRI) contains random bytes.
        let mut candidate = None;
        for idx in 0..cri.len() {
            if cri[idx] != 0xA0 {
                continue;
            }
            let Some((len, hdr)) = der_length(cri, idx + 1) else {
                continue;
            };
            if idx + 1 + hdr + len == cri.len() {
                candidate = Some((idx, hdr));
                break;
            }
        }

        let (idx, hdr) = candidate.expect("attributes [0] TLV not found in CRI");
        assert_eq!(
            cri[idx + 1 + hdr],
            0x30,
            "attributes [0] must be IMPLICIT (first child should be a SEQUENCE)"
        );
    }

    #[test]
    fn csr_san_uses_implicit_general_name_tag() {
        let (csr_der, _) = build_csr("certighost", Some("dc01.corp.local"), "User", 2048).unwrap();
        // GeneralName dNSName [2] IMPLICIT IA5String -> 0x82 <len> "dc01.corp.local"
        let mut expected = vec![0x82, 15u8];
        expected.extend_from_slice(b"dc01.corp.local");
        assert!(
            find_subslice(&csr_der, &expected).is_some(),
            "SAN dNSName must use implicit [2] tagging"
        );
    }

    #[test]
    fn wstep_envelope_is_a_ws_trust_rst() {
        let csr_b64 = "MIIBczCB5wIBADBSMQswCQYDVQQGEwJVUw==";
        let msg = "urn:uuid:1111-2222";
        let url = "https://ca.corp.local/CORP-CA_CES_Kerberos/service.svc/CES";
        let xml = build_wstep_rst(url, csr_b64, msg);

        // Correct action + addressing.
        assert!(xml.contains(&format!(
            "<a:Action s:mustUnderstand=\"1\">{WSTEP_RST_ACTION}</a:Action>"
        )));
        assert!(xml.contains(&format!("<a:To s:mustUnderstand=\"1\">{url}</a:To>")));
        assert!(xml.contains(&format!("<a:MessageID>{msg}</a:MessageID>")));

        // WS-Trust RST body, not a bare RequestCertificate element.
        assert!(xml.contains(&format!(
            "<RequestSecurityToken PreferredLanguage=\"en-US\" xmlns=\"{WST_NS}\">"
        )));
        assert!(xml.contains(&format!("<TokenType>{TOKEN_TYPE_X509V3}</TokenType>")));
        assert!(xml.contains(&format!("<RequestType>{REQUEST_TYPE_ISSUE}</RequestType>")));
        assert!(xml.contains(&format!("ValueType=\"{VALUE_TYPE_PKCS10}\"")));
        assert!(xml.contains(csr_b64));

        // The operations the previous revision invented must be gone.
        assert!(!xml.contains("GetClientCertificate"));
        assert!(!xml.contains("IGetCSPCount"));
        assert!(!xml.contains("GetCSPCount"));
    }

    /// Build a response shaped like a real CES RSTR (structure taken from a
    /// capture of Windows' own enrollment client).
    fn sample_response(x509_b64: &str, pkcs7_b64: &str) -> String {
        format!(
            "<s:Envelope xmlns:s=\"{SOAP_NS}\" xmlns:a=\"{WSA_NS}\"><s:Header>\
<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>\
<a:RelatesTo>urn:uuid:69cea9e1-95d1-4416-a877-d2b5b79fdf6e</a:RelatesTo></s:Header><s:Body>\
<RequestSecurityTokenResponseCollection xmlns=\"{WST_NS}\"><RequestSecurityTokenResponse>\
<TokenType>{TOKEN_TYPE_X509V3}</TokenType>\
<DispositionMessage xml:lang=\"en-US\" xmlns=\"{WSTEP_NS_PREFIX}\">Issued 0x80094004, The Enrollee has no E-Mail name.&#xD;</DispositionMessage>\
<BinarySecurityToken ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7\" EncodingType=\"{ENCODING_BASE64}\" xmlns=\"{WSSE_NS}\">{pkcs7_b64}</BinarySecurityToken>\
<RequestedSecurityToken><BinarySecurityToken ValueType=\"{TOKEN_TYPE_X509V3}\" EncodingType=\"{ENCODING_BASE64}\" xmlns=\"{WSSE_NS}\">{x509_b64}</BinarySecurityToken></RequestedSecurityToken>\
<RequestID xmlns=\"{WSTEP_NS_PREFIX}\">565818</RequestID>\
</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection></s:Body></s:Envelope>"
        )
    }

    #[test]
    fn parse_wstep_response_extracts_x509_and_pkcs7() {
        let cert = vec![0x30u8, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let p7 = vec![0x30u8, 0x82, 0x02, 0x00, 0x01, 0x02];
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        // Simulate WCF's line wrapping, including the &#xD; character references
        // it emits at each break -- those must not corrupt the base64.
        let encoded = b64(&cert);
        let spaced = format!("{}\n&#xD;\n{}", &encoded[..4], &encoded[4..]);
        let body = sample_response(&spaced, &b64(&p7));

        let parsed = parse_wstep_response(&body).expect("should parse");
        assert_eq!(parsed.certificate.as_deref(), Some(cert.as_slice()));
        assert_eq!(parsed.pkcs7.as_deref(), Some(p7.as_slice()));
        assert_eq!(parsed.request_id.as_deref(), Some("565818"));
        assert!(parsed.disposition.contains("0x80094004"));
    }

    #[test]
    fn parse_wstep_response_reports_soap_fault_instead_of_fabricating_a_cert() {
        let body = format!(
            "<s:Envelope xmlns:s=\"{SOAP_NS}\"><s:Body><s:Fault>\
<s:Code><s:Value>s:Sender</s:Value></s:Code>\
<s:Reason><s:Text xml:lang=\"en-US\">The request was refused</s:Text></s:Reason>\
</s:Fault></s:Body></s:Envelope>"
        );
        let err = parse_wstep_response(&body).expect_err("fault must be an error");
        let msg = err.to_string();
        assert!(msg.contains("refused"), "got: {msg}");
    }

    #[test]
    fn parse_wstep_response_errors_when_no_certificate() {
        let body = format!(
            "<s:Envelope xmlns:s=\"{SOAP_NS}\"><s:Body>\
<RequestSecurityTokenResponseCollection xmlns=\"{WST_NS}\"><RequestSecurityTokenResponse>\
<DispositionMessage xmlns=\"{WSTEP_NS_PREFIX}\">Denied 0x800706BA</DispositionMessage>\
<RequestID xmlns=\"{WSTEP_NS_PREFIX}\">42</RequestID>\
</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection></s:Body></s:Envelope>"
        );
        let err = parse_wstep_response(&body).expect_err("no cert must be an error");
        assert!(err.to_string().contains("0x800706BA"));
    }

    #[test]
    fn attr_value_reads_double_quoted_attributes() {
        let attrs = " ValueType=\"#PKCS7\" EncodingType=\"#base64binary\"";
        assert_eq!(attr_value(attrs, "ValueType").as_deref(), Some("#PKCS7"));
        assert_eq!(
            attr_value(attrs, "EncodingType").as_deref(),
            Some("#base64binary")
        );
        assert_eq!(attr_value(attrs, "Missing"), None);
    }

    #[test]
    fn find_elements_handles_prefixed_and_unprefixed_tags() {
        let xml = "<a:Foo>one</a:Foo><Bar>baz</Bar><Foo>two</Foo>";
        let foos = find_elements(xml, "Foo");
        assert_eq!(foos.len(), 2);
        assert_eq!(foos[0].1, "one");
        assert_eq!(foos[1].1, "two");
        assert_eq!(find_elements(xml, "Bar").len(), 1);
        assert!(find_elements(xml, "Nope").is_empty());
    }
}
