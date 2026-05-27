//! Ticket format conversion — `.kirbi` ↔ `.ccache` ↔ Rubeus-style base64.
//!
//! ## Formats
//!
//! | Format | Extension | Description |
//! |--------|-----------|-------------|
//! | KRB-CRED | `.kirbi` | ASN.1 DER-encoded KRB-CRED (Mimikatz/Impacket) |
//! | CCACHE | `.ccache` | MIT Kerberos credential cache file format |
//! | Base64 | `.b64` | Rubeus-compatible base64-encoded KRB-CRED |
//!
//! ## Usage
//!
//! ```ignore
//! use overthrone_forge::convert::TicketFormat;
//!
//! // Read a .kirbi, write as .ccache
//! let kirbi = std::fs::read("ticket.kirbi")?;
//! let ccache = convert::convert_format(&kirbi, TicketFormat::Kirbi, TicketFormat::Ccache)?;
//! std::fs::write("ticket.ccache", ccache)?;
//!
//! // Convert to Rubeus base64
//! let b64 = convert::ticket_to_base64(&kirbi)?;
//! ```

use kerberos_asn1::Asn1Object;
use overthrone_core::error::{OverthroneError, Result};
use tracing::info;

/// Detect the format of a ticket from its raw bytes.
pub fn detect_format(data: &[u8]) -> Result<TicketFormat> {
    // CCACHE starts with magic 0x0504
    if data.len() >= 2 && data[0] == 0x05 && data[1] == 0x04 {
        return Ok(TicketFormat::Ccache);
    }
    // Base64: check if it starts with a base64 character (A-Za-z0-9+/)
    if !data.is_empty() && data.len() < 100_000 {
        let text = std::str::from_utf8(data).unwrap_or("");
        if !text.is_empty()
            && text.trim().len() > 20
            && text.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || b == b'+'
                    || b == b'/'
                    || b == b'='
                    || b == b'\n'
                    || b == b'{'
                    || b == b'}'
                    || b == b' '
                    || b == b'\r'
            })
        {
            // Try to decode as base64 — if it yields valid ASN.1, it's base64
            let clean = text
                .trim()
                .trim_start_matches('{')
                .trim_end_matches('}')
                .trim();
            if base64::Engine::decode(&base64::engine::general_purpose::STANDARD, clean).is_ok() {
                return Ok(TicketFormat::Base64);
            }
        }
    }
    // Default: assume KRB-CRED DER (kirbi)
    Ok(TicketFormat::Kirbi)
}

/// Parse a format string to a TicketFormat.
pub fn parse_format(fmt: &str) -> Result<TicketFormat> {
    match fmt.to_lowercase().as_str() {
        "kirbi" | "krb-cred" | "der" => Ok(TicketFormat::Kirbi),
        "ccache" | "mit" | "cred" => Ok(TicketFormat::Ccache),
        "base64" | "b64" | "rubeus" => Ok(TicketFormat::Base64),
        _ => Err(OverthroneError::TicketForge(format!(
            "Unknown ticket format: '{fmt}'. Supported: kirbi, ccache, base64"
        ))),
    }
}

/// Supported ticket serialisation formats.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TicketFormat {
    /// KRB-CRED DER (`.kirbi`) — default for Overthrone / Mimikatz
    Kirbi,
    /// MIT Credential Cache (`.ccache`)
    Ccache,
    /// Rubeus-style base64-encoded KRB-CRED
    Base64,
}

/// Convert a ticket between serialisation formats.
pub fn convert_format(input: &[u8], from: TicketFormat, to: TicketFormat) -> Result<Vec<u8>> {
    if from == to {
        return Ok(input.to_vec());
    }

    info!("Converting ticket: {from:?} → {to:?}");

    // Decode from source format
    let raw = match from {
        TicketFormat::Kirbi => input.to_vec(),
        TicketFormat::Ccache => ccache_to_kirbi(input)?,
        TicketFormat::Base64 => base64_to_kirbi(input)?,
    };

    // Encode to target format
    match to {
        TicketFormat::Kirbi => Ok(raw),
        TicketFormat::Ccache => kirbi_to_ccache(&raw),
        TicketFormat::Base64 => Ok(kirbi_to_base64(&raw)?.into_bytes()),
    }
}

/// Decode a base64-encoded KRB-CRED to raw DER bytes.
///
/// Supports both Rubeus format (plain base64) and base64 with
/// the `{ ... }` kerbstone wrapper.
pub fn base64_to_kirbi(input: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(input)
        .map_err(|e| OverthroneError::TicketForge(format!("Invalid UTF-8 in base64 input: {e}")))?;

    let clean = text
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim()
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("");

    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, clean.as_bytes())
            .map_err(|e| OverthroneError::TicketForge(format!("Base64 decode failed: {e}")))?;

    Ok(decoded)
}

/// Encode a KRB-CRED to Rubeus-compatible base64.
pub fn kirbi_to_base64(kirbi: &[u8]) -> Result<String> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, kirbi);
    Ok(encoded)
}

/// Convert a KRB-CRED (kirbi) to MIT CCACHE format.
///
/// CCACHE format per MIT Kerberos:
///
/// ```text
/// struct ccache {
///     header: [u8; 4],         // file format version magic
///     headerlen: u16,          // length of header in bytes
///     header: [u8; headerlen], // optional header (usually empty)
///     credentials: [Cred; N]   // one or more credential entries
/// }
/// ```
///
/// Each credential:
/// ```text
/// struct Cred {
///     client: Principal,
///     server: Principal,
///     keyblock: Keyblock,
///     authtime: i32,
///     starttime: i32,
///     endtime: i32,
///     renew_till: i32,
///     is_skey: u8,
///     ticket_flags: u32,
///     ticket: [u8],
///     second_ticket: [u8],
/// }
/// ```
pub fn kirbi_to_ccache(kirbi: &[u8]) -> Result<Vec<u8>> {
    // Parse the KRB-CRED ASN.1 structure to extract ticket info
    let kerb_cred = kerberos_asn1::KrbCred::parse(kirbi)
        .map_err(|e| OverthroneError::TicketForge(format!("Parse KRB-CRED: {e}")))?
        .1;

    let ticket = kerb_cred
        .tickets
        .first()
        .ok_or_else(|| OverthroneError::TicketForge("KRB-CRED has no tickets".into()))?;

    let mut cred_info = None;
    // The enc_part of a .kirbi is unencrypted (etype=0) and contains EncKrbCredPart
    if kerb_cred.enc_part.etype == 0 || kerb_cred.enc_part.etype == 23 {
        let enc_part_bytes = &kerb_cred.enc_part.cipher;
        if let Ok((_, enc_cred)) = kerberos_asn1::EncKrbCredPart::parse(enc_part_bytes) {
            cred_info = enc_cred.ticket_info.first().cloned();
        }
    }

    let ci = cred_info.as_ref();

    // Build CCACHE header (version 0x0504 — little-endian)
    let mut ccache = Vec::new();
    ccache.extend_from_slice(b"\x05\x04"); // file format magic
    ccache.extend_from_slice(&[0x00, 0x01]); // version 1
    ccache.extend_from_slice(&0u16.to_le_bytes()); // header length = 0

    // Encode principal (client)
    let client_realm = ci
        .and_then(|c| c.prealm.as_deref())
        .unwrap_or(&ticket.realm);
    let default_name = vec!["USER".to_string()];
    let client_name = ci
        .and_then(|c| c.pname.as_ref())
        .map(|p| &p.name_string)
        .unwrap_or(&default_name);
    encode_ccache_principal(&mut ccache, client_realm, client_name);

    // Encode principal (server) — the ticket's sname
    let server_realm = &ticket.realm;
    let server_name = &ticket.sname.name_string;
    encode_ccache_principal(&mut ccache, server_realm, server_name);

    // Keyblock
    let keytype = ci.map(|c| c.key.keytype).unwrap_or(ticket.enc_part.etype);
    let keyvalue = ci.map(|c| c.key.keyvalue.clone()).unwrap_or_default();
    ccache.extend_from_slice(&(keytype as u16).to_le_bytes()); // key type (u16)
    ccache.extend_from_slice(&(keyvalue.len() as u16).to_le_bytes()); // key length
    ccache.extend_from_slice(&keyvalue);

    // Times — using timestamps from cred info or defaults
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i32;

    let authtime = ci
        .and_then(|c| c.authtime.as_ref())
        .map(|t| (**t).timestamp() as i32)
        .unwrap_or(now_ts);
    let starttime = ci
        .and_then(|c| c.starttime.as_ref())
        .map(|t| (**t).timestamp() as i32)
        .unwrap_or(authtime);
    let endtime = ci
        .and_then(|c| c.endtime.as_ref())
        .map(|t| (**t).timestamp() as i32)
        .unwrap_or(now_ts + 36000);
    let renew_till = ci
        .and_then(|c| c.renew_till.as_ref())
        .map(|t| (**t).timestamp() as i32)
        .unwrap_or(now_ts + 86400);

    ccache.extend_from_slice(&authtime.to_le_bytes() as &[u8]);
    ccache.extend_from_slice(&starttime.to_le_bytes());
    ccache.extend_from_slice(&endtime.to_le_bytes());
    ccache.extend_from_slice(&renew_till.to_le_bytes());

    // is_skey (u8)
    ccache.push(0);

    // ticket_flags (u32)
    let flags = ci
        .and_then(|c| c.flags.as_ref())
        .map(|f| f.flags)
        .unwrap_or(0x40E00000u32);
    ccache.extend_from_slice(&flags.to_le_bytes());

    // Ticket data length + data
    let ticket_bytes = ticket.build();
    ccache.extend_from_slice(&(ticket_bytes.len() as u32).to_le_bytes());
    ccache.extend_from_slice(&ticket_bytes);

    // Second ticket (none)
    ccache.extend_from_slice(&0u32.to_le_bytes());

    Ok(ccache)
}

/// Convert a CCACHE file back to KRB-CRED DER bytes.
pub fn ccache_to_kirbi(ccache: &[u8]) -> Result<Vec<u8>> {
    if ccache.len() < 8 {
        return Err(OverthroneError::TicketForge("CCACHE file too short".into()));
    }

    if &ccache[..2] != b"\x05\x04" {
        return Err(OverthroneError::TicketForge(
            "Invalid CCACHE magic bytes (expected 0x0504)".into(),
        ));
    }

    // Minimal parse — we need to extract ticket bytes and reconstruct KRB-CRED
    // For now, parse and rebuild using the ASN.1 types
    let header_len = u16::from_le_bytes([ccache[4], ccache[5]]) as usize;
    let pos = 6 + header_len;

    // Skip client and server principals (we re-derive from the ticket itself)
    // This is a simplified reader — extract the ticket data and wrap in KRB-CRED
    let ticket_start = find_ticket_in_ccache(ccache, pos)?;
    let ticket_len = u32::from_le_bytes([
        ccache[ticket_start - 12],
        ccache[ticket_start - 11],
        ccache[ticket_start - 10],
        ccache[ticket_start - 9],
    ]) as usize;

    if ticket_start + ticket_len > ccache.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: ticket data truncated".into(),
        ));
    }

    let ticket_bytes = &ccache[ticket_start..ticket_start + ticket_len];

    // Parse the ticket from its DER encoding
    let (_, ticket) = kerberos_asn1::Ticket::parse(ticket_bytes)
        .map_err(|e| OverthroneError::TicketForge(format!("CCACHE: parse ticket: {e}")))?;

    // Build KRB-CRED
    let kirbi = kerberos_asn1::KrbCred {
        pvno: 5,
        msg_type: 22,
        tickets: vec![ticket],
        enc_part: kerberos_asn1::EncryptedData {
            etype: 0,
            kvno: None,
            cipher: Vec::new(),
        },
    };

    Ok(kirbi.build())
}

/// Encode a Kerberos principal in CCACHE format.
fn encode_ccache_principal(buf: &mut Vec<u8>, realm: &str, components: &[String]) {
    let realm_utf16_count = realm.encode_utf16().count() as u16;
    buf.extend_from_slice(&realm_utf16_count.to_le_bytes());
    // CCACHE stores name components as u16 length + UTF-8 (not UTF-16)
    buf.extend_from_slice(realm.as_bytes());

    let num_components = components.len() as u16;
    buf.extend_from_slice(&num_components.to_le_bytes());

    let name_type: u32 = 1; // NT_PRINCIPAL
    buf.extend_from_slice(&name_type.to_le_bytes());

    for comp in components {
        let comp_len = comp.len() as u16;
        buf.extend_from_slice(&comp_len.to_le_bytes());
        buf.extend_from_slice(comp.as_bytes());
    }
}

/// Find the start of ticket data in a CCACHE file.
/// Walks past client principal, server principal, keyblock, times, and flags.
fn find_ticket_in_ccache(ccache: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;

    // Skip client principal
    pos = skip_ccache_principal(ccache, pos)?;
    // Skip server principal
    pos = skip_ccache_principal(ccache, pos)?;

    // Skip keyblock: keytype(u16) + keylen(u16) + keydata(keylen)
    if pos + 4 > ccache.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: truncated at keyblock".into(),
        ));
    }
    let key_len = u16::from_le_bytes([ccache[pos + 2], ccache[pos + 3]]) as usize;
    pos += 4 + key_len;

    // Skip times: authtime(i32) + starttime(i32) + endtime(i32) + renew_till(i32)
    if pos + 16 > ccache.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: truncated at times".into(),
        ));
    }
    pos += 16;

    // Skip is_skey(u8) + ticket_flags(u32)
    if pos + 5 > ccache.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: truncated at flags".into(),
        ));
    }
    pos += 1 + 4;

    // Now at ticket data length field — return the position of the data
    if pos + 4 > ccache.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: truncated at ticket len".into(),
        ));
    }
    let ticket_len = u32::from_le_bytes([
        ccache[pos],
        ccache[pos + 1],
        ccache[pos + 2],
        ccache[pos + 3],
    ]) as usize;
    pos += 4;

    if pos + ticket_len > ccache.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: ticket data truncated".into(),
        ));
    }

    Ok(pos)
}

/// Skip past a CCACHE-encoded principal, returning the next position.
fn skip_ccache_principal(data: &[u8], pos: usize) -> Result<usize> {
    if pos + 2 > data.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: truncated principal realm length".into(),
        ));
    }
    let realm_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    let mut p = pos + 2 + realm_len;

    if p + 2 > data.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: truncated principal num components".into(),
        ));
    }
    let num_comps = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
    p += 2;

    // Skip name_type (u32)
    if p + 4 > data.len() {
        return Err(OverthroneError::TicketForge(
            "CCACHE: truncated principal name type".into(),
        ));
    }
    p += 4;

    for _ in 0..num_comps {
        if p + 2 > data.len() {
            return Err(OverthroneError::TicketForge(
                "CCACHE: truncated principal component".into(),
            ));
        }
        let comp_len = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
        p += 2 + comp_len;
    }

    Ok(p)
}
