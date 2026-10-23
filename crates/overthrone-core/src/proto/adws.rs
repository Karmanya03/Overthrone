//! Active Directory Web Services (ADWS / MS-ADWSOD, WS-Man + WS-Trust
//! parity with impacket's `adws` client).
//!
//! ADWS is the SOAP/HTTP(S) sibling of LDAP exposed on DC port 9389 via the
//! `ActiveDirectoryWebServices` endpoint. Authentication uses WS-Trust
//! RST/RSTRC with an NTLM BinaryExchange (the same Type1/Type2/Type3 bytes
//! as every other NTLM endpoint), so this module reuses
//! [`crate::proto::ntlm`] primitives.
//!
//! LDAP connectivity is routinely blocked (unsigned-bind enforcement,
//! LDAPS disabled, filter-evading firewalls); ADWS is unaffected by those
//! hardening measures, which makes it a top-tier enumeration channel on
//! hardened DCs.//!
//! Object parsing is encoding-tolerant: both the
//! `<ads:attr name="cn"><ads:value>x</ads:value></ads:attr>` form and
//! bare `<ads:dn>` children are accepted.

use crate::error::{OverthroneError, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn adws_err(reason: impl std::fmt::Display) -> OverthroneError {
    OverthroneError::Protocol {
        protocol: "ADWS".into(),
        reason: reason.to_string(),
    }
}

/// Local name from possibly-prefixed XML name bytes (`ad:value` ->
/// `value`), lowercased for namespace-insensitive matching. Avoids
/// quick-xml version-specific LocalName/QName APIs.
fn xml_local_name(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.rsplit(':').next().unwrap_or("").to_lowercase()
}

/// Decoded + entity-unescaped text of a BytesText event (quick-xml 0.39
/// keeps text escaped; `decode()` alone returns the escaped form).
fn unescape_text(t: &quick_xml::events::BytesText) -> String {
    let raw = t.decode().unwrap_or_default();
    quick_xml::escape::unescape(&raw)
        .unwrap_or_default()
        .to_string()
}

/// SOAP fault reason, if the response carries a Fault element.
fn fault_reason(xml: &str) -> Option<String> {
    if !xml.contains("Fault") {
        return None;
    }
    Some(
        extract_element_text(xml, "Reason")
            .or_else(|| extract_element_text(xml, "faultstring"))
            .unwrap_or_else(|| "WS-Trust fault without reason".into()),
    )
}

/// WS-Man ResourceURI for AD directory objects.
pub const RESOURCE_URI_ADDDIRECTORY: &str =
    "http://schemas.microsoft.com/2008/09/Identity/Enumeration/ADDirectory";
/// WS-Trust issuing action.
pub const ACTION_RST_ISSUE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/RST/Issue";
/// Enumeration actions.
pub const ACTION_ENUMERATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";
pub const ACTION_PULL: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull";
/// LDAP-filter dialect marker for wsen:Filter.
pub const FILTER_DIALECT_LDAP: &str =
    "http://schemas.microsoft.com/2008/09/Identity/Attributes/LDAPFilter";

/// Default max elements per Pull.
pub const PULL_MAX_ELEMENTS: usize = 1000;

const WSS_SEC_HEADER: &str = "<o:Security s:mustUnderstand=\"1\" \
xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"/>";
const WS_MAN_RES_URI_HEADER: &str = concat!(
    "<wsman:ResourceURI s:mustUnderstand=\"1\" ",
    "xmlns:wsman=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\">",
    "http://schemas.microsoft.com/2008/09/Identity/Enumeration/ADDirectory",
    "</wsman:ResourceURI>"
);

// ===========================================================
// SOAP envelope construction
// ===========================================================

/// Build a full SOAP 1.2 envelope for ADWS with the given action/body.
pub fn soap_envelope(
    host: &str,
    action: &str,
    message_id: &str,
    body: &str,
    extra_header: &str,
) -> String {
    let mut env = String::with_capacity(768 + body.len());
    env.push_str("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" ");
    env.push_str("xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" ");
    env.push_str("xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">");
    env.push_str("<s:Header>");
    env.push_str("<a:Action s:mustUnderstand=\"1\">");
    env.push_str(action);
    env.push_str("</a:Action>");
    env.push_str(&format!(
        "<a:MessageID>urn:uuid:{}</a:MessageID>",
        message_id
    ));
    env.push_str(
        "<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>",
    );
    env.push_str(&format!(
        "<a:To s:mustUnderstand=\"1\">http://{}:9389/ActiveDirectoryWebServices</a:To>",
        host
    ));
    env.push_str(extra_header);
    env.push_str("</s:Header><s:Body>");
    env.push_str(body);
    env.push_str("</s:Body></s:Envelope>");
    env
}

/// WS-Trust RequestSecurityToken body for the NTLM BinaryExchange legs.
/// Leg 1 sends the empty element (server replies with its challenge);
/// leg 2 carries the client's Type3 message base64-encoded.
pub fn rst_issue_body(binary_exchange_xml: Option<&str>) -> String {
    let exchange = match binary_exchange_xml {
        Some(inner) => inner.to_string(),
        None => r#"<wst:BinaryExchange ValueType="http://schemas.xmlsoap.org/ws/2004/09/transfer/NTLM" EncodingType="http://schemas.xmlsoap.org/ws/2004/09/transfer/base64"/>"#.to_string(),
    };
    format!(
        "<wst:RequestSecurityToken xmlns:wst=\"http://schemas.xmlsoap.org/ws/2004/09/trust\">\
<wst:TokenType>http://schemas.microsoft.com/ws/2008/06/identity/securitytoken/saml11token</wst:TokenType>\
<wst:RequestType>http://schemas.xmlsoap.org/ws/2004/09/trust/Issue</wst:RequestType>\
{}</wst:RequestSecurityToken>",
        exchange
    )
}

/// `<wst:BinaryExchange>` element carrying a base64 token (leg 2).
pub fn binary_exchange_with_token(token_b64: &str) -> String {
    format!(
        r#"<wst:BinaryExchange ValueType="http://schemas.xmlsoap.org/ws/2004/09/transfer/NTLM" EncodingType="http://schemas.xmlsoap.org/ws/2004/09/transfer/base64">{}</wst:BinaryExchange>"#,
        token_b64
    )
}

/// Build the wsen:Enumerate body for an LDAP-filter enumeration.
pub fn enumerate_body(filter: &str, max_elements: usize) -> String {
    format!(
        r#"<wsen:Enumerate><wsen:Filter Dialect="{}">{}</wsen:Filter><wsen:MaxElements>{}</wsen:MaxElements></wsen:Enumerate>"#,
        FILTER_DIALECT_LDAP,
        xml_escape(filter),
        max_elements
    )
}

/// Build the wsen:Pull body continuing `context`.
pub fn pull_body(context: &str, max_elements: usize) -> String {
    format!(
        r#"<wsen:Pull><wsen:EnumerationContext>{}</wsen:EnumerationContext><wsen:MaxElements>{}</wsen:MaxElements></wsen:Pull>"#,
        xml_escape(context),
        max_elements
    )
}

/// Minimal XML escaping for attribute/text content.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Generate a per-call WS-Addressing MessageID (RFC 4122 v4 shape,
/// std-only entropy: splitmix64 seeded from wall-clock + address entropy).
pub fn new_message_id() -> String {
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        ^ 0x9E3779B97F4A7C15;
    next(&mut x);
    let a = next(&mut x);
    let b = next(&mut x);
    let c = next(&mut x);
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a & 0xFFFF) as u16,
        b & 0xFFF,
        0x8000 | ((c >> 48) as u16 & 0x3FFF),
        c & 0xFFFF_FFFF_FFFF
    )
}

fn next(x: &mut u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

// ===========================================================
// HTTP transport (SOAP 1.2 over POST)
// ===========================================================

/// Build the raw HTTP POST request bytes for a SOAP call.
pub fn build_http_post(host: &str, body: &str) -> Vec<u8> {
    let req = format!(
        "POST /ActiveDirectoryWebServices HTTP/1.1\r\n\
Host: {}:9389\r\n\
Content-Type: application/soap+xml; charset=utf-8\r\n\
User-Agent: Overthrone-ADWS/1.0\r\n\
Content-Length: {}\r\n\
Connection: Keep-Alive\r\n\r\n{}",
        host,
        body.len(),
        body
    );
    req.into_bytes()
}

/// POST the envelope and return the HTTP body (past the header
/// terminator). Honors Content-Length when present, otherwise reads to
/// EOF (Connection: close).
pub fn post_soap<S: Read + Write>(
    stream: &mut S,
    host: &str,
    body: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    // The caller owns stream timeouts (TcpStream::set_read_timeout before
    // wrapping; TLS wrappers forward them to the underlying socket). The
    // `timeout` parameter is retained for interface stability and is used
    // by convenience constructors below.
    let _ = timeout;
    stream
        .write_all(&build_http_post(host, body))
        .map_err(|e| adws_err(format!("ADWS write: {}", e)))?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 16_384];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if response.len() >= 4
                    && find_header_end(&response)
                        .map(|start| {
                            content_length(&response[..start])
                                .map(|cl| response[start..].len() >= cl)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
                {
                    break;
                }
            }
            Err(e) => {
                if response.is_empty() {
                    return Err(adws_err(format!("ADWS read: {}", e)));
                }
                break;
            }
        }
    }
    if response.is_empty() {
        return Err(adws_err("ADWS: empty response"));
    }
    match find_header_end(&response) {
        Some(s) => Ok(response[s..].to_vec()),
        None => Ok(response),
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn content_length(head: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(head);
    text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
}

// ===========================================================
// SOAP response parsing
// ===========================================================

/// Extract the trimmed concatenated text of the first element whose local
/// name matches `local` (namespace-insensitive).
pub fn extract_element_text(xml: &str, local: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let target = local.to_lowercase();
    let mut depth = 0usize;
    let mut text = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = xml_local_name(e.name().as_ref());
                if name == target || depth > 0 {
                    depth += 1;
                }
            }
            Ok(Event::End(e)) => {
                if depth == 0 {
                    continue;
                }
                depth -= 1;
                let name = xml_local_name(e.name().as_ref());
                if depth == 0 && name == target {
                    return Some(text.trim().to_string());
                }
            }
            Ok(Event::Text(t)) => {
                if depth > 0 {
                    text.push_str(&unescape_text(&t));
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    None
}

// ===========================================================
// AD object model
// ===========================================================

/// One directory object from a Pull response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AdObject {
    pub dn: String,
    pub attrs: BTreeMap<String, Vec<String>>,
}

impl AdObject {
    /// First value of an attribute (lookup is case-insensitive, like LDAP).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attrs
            .get(&name.to_lowercase())
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// All values of an attribute.
    pub fn get_all(&self, name: &str) -> Option<&Vec<String>> {
        self.attrs.get(&name.to_lowercase())
    }
}

/// Parse a Pull (or Enumerate) response into objects. Elements matched
/// namespace-insensitively; multi-valued attributes accumulate in order.
pub fn parse_pull_response(xml: &str) -> Vec<AdObject> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut objects = Vec::new();
    let mut current: Option<AdObject> = None;
    let mut current_attr: Option<String> = None;
    let mut text = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = xml_local_name(e.name().as_ref());
                match name.as_str() {
                    "object" => {
                        let mut dn = String::new();
                        for attr in e.attributes() {
                            let a = match attr {
                                Ok(a) => a,
                                Err(_) => continue,
                            };
                            let key = xml_local_name(a.key.as_ref());
                            if key == "distinguishedname" {
                                dn = a
                                    .unescape_value()
                                    .map(|v| v.trim().to_string())
                                    .unwrap_or_default();
                            }
                        }
                        current = Some(AdObject {
                            dn,
                            attrs: BTreeMap::new(),
                        });
                    }
                    "attr" => {
                        let mut attr_name = String::new();
                        for attr in e.attributes() {
                            let a = match attr {
                                Ok(a) => a,
                                Err(_) => continue,
                            };
                            let key = xml_local_name(a.key.as_ref());
                            if key == "name" {
                                attr_name = a
                                    .unescape_value()
                                    .map(|v| v.to_string())
                                    .unwrap_or_default();
                            }
                        }
                        current_attr = Some(attr_name.to_lowercase());
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = xml_local_name(e.name().as_ref());
                match name.as_str() {
                    "value" => {
                        let v = text.trim().to_string();
                        if let (Some(ci), Some(ca)) = (current.as_mut(), current_attr.as_ref()) {
                            ci.attrs.entry(ca.clone()).or_default().push(v);
                        }
                        text.clear();
                    }
                    "dn" => {
                        let take = current.as_ref().map(|ci| ci.dn.is_empty()).unwrap_or(false);
                        if let (Some(ci), true) = (current.as_mut(), take) {
                            ci.dn = text.trim().to_string();
                        }
                        text.clear();
                    }
                    "object" => {
                        if let Some(ci) = current.take() {
                            objects.push(ci);
                        }
                        current_attr = None;
                    }
                    "endofsequence" => {
                        return objects;
                    }
                    _ => {} // non-relevant End: drop stale text
                }
                if !matches!(name.as_str(), "value" | "dn") {
                    text.clear();
                }
            }
            Ok(Event::Empty(e)) => {
                // Self-closing <ads:EndOfSequence/> terminates the feed
                let name = xml_local_name(e.name().as_ref());
                if name == "endofsequence" {
                    return objects;
                }
                let _ = e;
            }
            Ok(Event::Text(t)) => {
                text.push_str(&unescape_text(&t));
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    if let Some(ci) = current.take() {
        objects.push(ci);
    }
    objects
}

// ===========================================================
// Client state machine
// ===========================================================

/// ADWS connection to a domain controller (port 9389, WS-Trust NTLM).
pub struct AdwsClient<S> {
    stream: S,
    host: String,
    pub connected: bool,
}

impl<S: std::fmt::Debug> std::fmt::Debug for AdwsClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdwsClient")
            .field("host", &self.host)
            .field("connected", &self.connected)
            .finish()
    }
}

/// Credentials for NTLM authentication.
#[derive(Debug, Clone, Default)]
pub struct AdwsConfig {
    pub domain: String,
    pub username: String,
    /// NT hash (`LM:NT` format `aad3b435b51404eeaad3b435b51404ee:...`
    /// or bare 32-hex NT part).
    pub nt_hash_hex: String,
    pub timeout_secs: u64,
}

impl<S: Read + Write> AdwsClient<S> {
    /// Drive the WS-Trust RST/RSTRC NTLM dance over an existing stream
    /// (plain TCP or caller-wrapped TLS).
    pub fn connect_with_transport(mut stream: S, host: &str, config: &AdwsConfig) -> Result<Self> {
        let timeout = Duration::from_secs(config.timeout_secs.max(5));

        // Leg 1: empty BinaryExchange -> server's NTLM Type2 token
        let env1 = soap_envelope(
            host,
            ACTION_RST_ISSUE,
            &new_message_id(),
            &rst_issue_body(None),
            WSS_SEC_HEADER,
        );
        let resp1 = post_soap(&mut stream, host, &env1, timeout)?;
        let resp1_text = String::from_utf8_lossy(&resp1).to_string();

        if let Some(reason) = fault_reason(&resp1_text) {
            return Err(adws_err(format!("ADWS auth fault (leg 1): {}", reason)));
        }

        let server_token_b64 = extract_element_text(&resp1_text, "BinaryExchange")
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                adws_err(
                    "ADWS: leg 1 returned no BinaryExchange token (server rejected the context)",
                )
            })?;
        let server_token = B64
            .decode(server_token_b64.as_bytes())
            .map_err(|e| adws_err(format!("ADWS: BinaryExchange not base64: {}", e)))?;

        let nt_hash = crate::proto::ntlm::parse_ntlm_hash(&config.nt_hash_hex)?;
        let challenge = crate::proto::ntlm::parse_challenge_message(&server_token)?;
        let type3 = crate::proto::ntlm::build_authenticate_message(
            &config.domain,
            &config.username,
            &nt_hash,
            &challenge.challenge,
            challenge.target_info.as_deref(),
            None,
        );
        let type3_b64 = B64.encode(&type3);

        // Leg 2: send the AUTHENTICATE message
        let env2 = soap_envelope(
            host,
            ACTION_RST_ISSUE,
            &new_message_id(),
            &rst_issue_body(Some(&binary_exchange_with_token(&type3_b64))),
            WSS_SEC_HEADER,
        );
        let resp2 = post_soap(&mut stream, host, &env2, timeout)?;
        let resp2_text = String::from_utf8_lossy(&resp2).to_string();

        if let Some(reason) = fault_reason(&resp2_text) {
            return Err(adws_err(format!("ADWS auth fault (leg 2): {}", reason)));
        }

        Ok(Self {
            stream,
            host: host.to_string(),
            connected: true,
        })
    }

    /// Enumerate the directory (wsen:Enumerate + wsen:Pull loop).
    pub fn enumerate(&mut self, filter: &str, max_elements: usize) -> Result<Vec<AdObject>> {
        let timeout = Duration::from_secs(60);
        let env = soap_envelope(
            &self.host,
            ACTION_ENUMERATE,
            &new_message_id(),
            &enumerate_body(filter, max_elements),
            WS_MAN_RES_URI_HEADER,
        );
        let resp = post_soap(&mut self.stream, &self.host, &env, timeout)?;
        let text = String::from_utf8_lossy(&resp).to_string();

        let context = extract_element_text(&text, "EnumerationContext")
            .map(|c| c.trim().to_string())
            .ok_or_else(|| {
                adws_err(format!(
                    "ADWS: no EnumerationContext in enumerate response: {}",
                    text.chars().take(160).collect::<String>()
                ))
            })?;

        let mut objects = parse_pull_response(&text);

        if text.contains("EndOfSequence") {
            return Ok(objects);
        }

        loop {
            let env = soap_envelope(
                &self.host,
                ACTION_PULL,
                &new_message_id(),
                &pull_body(&context, max_elements),
                WS_MAN_RES_URI_HEADER,
            );
            let resp = post_soap(&mut self.stream, &self.host, &env, timeout)?;
            let text = String::from_utf8_lossy(&resp).to_string();
            let done = text.contains("EndOfSequence");
            objects.extend(parse_pull_response(&text));
            if done {
                break;
            }
        }

        Ok(objects)
    }

    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Convenience: connect over plain TCP (port 9389).
pub fn connect_tcp(dc: &str, config: &AdwsConfig) -> Result<AdwsClient<TcpStream>> {
    let stream = TcpStream::connect((dc, 9389))
        .map_err(|e| adws_err(format!("ADWS connect {}: {}", dc, e)))?;
    AdwsClient::connect_with_transport(stream, dc, config)
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::JoinHandle;

    #[test]
    fn test_soap_envelope_structure() {
        let env = soap_envelope(
            "dc01.corp.local",
            ACTION_RST_ISSUE,
            "test-uuid",
            &rst_issue_body(None),
            "<o:Security/>",
        );
        assert!(env.contains("soap-envelope"));
        assert!(
            env.contains(
                "<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/RST/Issue</a:Action>"
            ),
            "action header"
        );
        assert!(env.contains("urn:uuid:test-uuid"));
        assert!(env.contains("http://dc01.corp.local:9389/ActiveDirectoryWebServices"));
        assert!(env.contains("<wst:RequestSecurityToken"));
        assert!(env.contains("<o:Security/>"));
        assert!(!env.contains('\\'), "no stray fold backslashes");
    }

    #[test]
    fn test_rst_issue_body_legs() {
        let body = rst_issue_body(None);
        assert!(body.contains("saml11token"));
        assert!(body.contains("Issue"));
        assert!(
            body.contains(
                "<wst:BinaryExchange ValueType=\"http://schemas.xmlsoap.org/ws/2004/09/transfer/NTLM\" EncodingType=\"http://schemas.xmlsoap.org/ws/2004/09/transfer/base64\"/>"
            ),
            "empty leg-1 token"
        );
        let body2 = rst_issue_body(Some(&binary_exchange_with_token("QUJD")));
        assert!(body2.contains("QUJD</wst:BinaryExchange>"));
    }

    #[test]
    fn test_enumerate_and_pull_bodies() {
        let env = enumerate_body("(&(objectClass=user)(sAMAccountName=A&B))", 100);
        assert!(env.contains(&format!("Dialect=\"{}\"", FILTER_DIALECT_LDAP)));
        assert!(env.contains("A&amp;B"));
        assert!(env.contains("<wsen:MaxElements>100</wsen:MaxElements>"));

        let pull = pull_body("s-1-5-abc-uuid", 500);
        assert!(pull.contains("<wsen:EnumerationContext>s-1-5-abc-uuid</wsen:EnumerationContext>"));
        assert!(pull.contains("<wsen:MaxElements>500</wsen:MaxElements>"));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a<b>&\"c\""), "a&lt;b&gt;&amp;&quot;c&quot;");
    }

    #[test]
    fn test_message_id_shape() {
        let id = new_message_id();
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5, "v4 uuid shape: {id}");
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert!(parts[2].starts_with('4'), "version nibble");
    }

    #[test]
    fn test_message_ids_unique_enough() {
        let a = new_message_id();
        let b = new_message_id();
        assert_ne!(a, b);
    }

    #[test]
    fn test_build_http_post() {
        let body = "<s:Envelope/>";
        let req = String::from_utf8(build_http_post("dc01", body)).unwrap();
        assert!(req.starts_with("POST /ActiveDirectoryWebServices HTTP/1.1\r\n"));
        assert!(req.contains("Host: dc01:9389"));
        assert!(req.contains("Content-Type: application/soap+xml"));
        assert!(req.contains(&format!("Content-Length: {}", body.len())));
        assert!(req.ends_with(body));
    }

    #[test]
    fn test_extract_element_text() {
        let xml = "<s:Envelope xmlns:wst=\"http://x\"><s:Body><wst:BinaryExchange EncType=\"x\">QUJD</wst:BinaryExchange></s:Body></s:Envelope>";
        assert_eq!(
            extract_element_text(xml, "BinaryExchange").as_deref(),
            Some("QUJD")
        );
        let xml2 = "<a><nested><EnumerationContext>ctx-1</EnumerationContext></nested></a>";
        assert_eq!(
            extract_element_text(xml2, "EnumerationContext").as_deref(),
            Some("ctx-1")
        );
        assert_eq!(
            extract_element_text("<a><b>nope</b></a>", "BinaryExchange"),
            None
        );
        assert_eq!(
            extract_element_text("malformed <", "EnumerationContext"),
            None
        );
    }

    #[test]
    fn test_parse_pull_response_attr_form() {
        let xml = r#"<wsen:PullResponse
  xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
  xmlns:ads="http://schemas.microsoft.com/2008/09/Identity/Enumeration/ADDirectory">
  <wsen:Items>
    <ads:Object ad:distinguishedName="CN=alice,CN=Users,DC=corp,DC=local" xmlns:ad="http://adns">
      <ads:attr name="sAMAccountName"><ads:value>alice</ads:value></ads:attr>
      <ads:attr name="primaryGroupID"><ads:value>513</ads:value></ads:attr>
      <ads:attr name="memberOf"><ads:value>CN=Admins</ads:value><ads:value>CN=Users</ads:value></ads:attr>
    </ads:Object>
    <ads:Object ad:distinguishedName="CN=bob,CN=Users,DC=corp,DC=local" xmlns:ad="http://adns">
      <ads:attr name="sAMAccountName"><ads:value>bob</ads:value></ads:attr>
    </ads:Object>
  </wsen:Items>
  <wsen:EndOfSequence/>
</wsen:PullResponse>"#;
        let objects = parse_pull_response(xml);
        assert_eq!(objects.len(), 2, "two objects parsed");
        assert_eq!(objects[0].dn, "CN=alice,CN=Users,DC=corp,DC=local");
        assert_eq!(objects[0].get("samaccountname"), Some("alice"));
        assert_eq!(objects[0].get("primarygroupid"), Some("513"));
        let member_of = objects[0].get_all("memberof").unwrap();
        assert_eq!(member_of.len(), 2, "multi-valued: {member_of:?}");
        assert_eq!(member_of[0], "CN=Admins");
        assert_eq!(objects[1].get("samaccountname"), Some("bob"));
    }

    #[test]
    fn test_parse_pull_response_dn_child_form() {
        let xml = r#"<Item>
  <ads:Object xmlns:ads="http://ad1">
    <ads:dn>CN=carol,DC=corp,DC=local</ads:dn>
    <ads:attr name="objectClass"><ads:value>user</ads:value></ads:attr>
  </ads:Object>
</Item>"#;
        let objects = parse_pull_response(xml);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].dn, "CN=carol,DC=corp,DC=local");
        assert_eq!(objects[0].get("objectclass"), Some("user"));
    }

    #[test]
    fn test_parse_pull_response_malformed_no_crash() {
        for junk in [
            "",
            "<not><wellformed",
            "<wsen:PullResponse><a/></wsen:PullResponse>",
            "plain text no xml",
            "<a:Object /><b:value>stray</b:value>",
        ] {
            let _ = parse_pull_response(junk);
        }
    }

    #[test]
    fn test_parse_pull_response_endofsequence_early_exit() {
        let xml = r#"<Response>
  <ads:Object ad:distinguishedName="D1"><ads:attr name="a"><ads:value>1</ads:value></ads:attr></ads:Object>
  <ads:EndOfSequence/>
  <ads:Object ad:distinguishedName="D2"><ads:attr name="a"><ads:value>2</ads:value></ads:attr></ads:Object>
</Response>"#;
        let objects = parse_pull_response(xml);
        assert_eq!(objects.len(), 1, "stop at EndOfSequence");
        assert_eq!(objects[0].dn, "D1");
    }

    #[test]
    fn test_ad_object_getters() {
        let obj = AdObject {
            dn: "CN=x".into(),
            attrs: BTreeMap::from([("samaccountname".to_string(), vec!["x".to_string()])]),
        };
        assert_eq!(obj.get("SAMACCOUNTNAME"), Some("x"));
        assert_eq!(obj.get("missing"), None);
        assert!(obj.get_all("samaccountname").is_some());
        assert!(obj.get_all("missing").is_none());
    }

    #[test]
    fn test_adws_config_default() {
        let cfg = AdwsConfig::default();
        assert!(cfg.domain.is_empty());
        assert!(cfg.username.is_empty());
        assert!(cfg.nt_hash_hex.is_empty());
        assert_eq!(cfg.timeout_secs, 0);
    }

    #[test]
    fn test_roundtrip_serialization() {
        let obj = AdObject {
            dn: "CN=t".into(),
            attrs: BTreeMap::from([("a".to_string(), vec!["1".into(), "2".into()])]),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: AdObject = serde_json::from_str(&json).unwrap();
        assert_eq!(obj, back);
    }

    // -------------------------------------------------------
    // Mock ADWS server: full WS-Trust + enumerate flow
    // -------------------------------------------------------

    /// Minimal but structurally valid NTLM Type2 challenge message
    /// (signature + type + empty target name + challenge + flags +
    /// empty target info), 48 bytes.
    fn mock_ntlm_type2(challenge: [u8; 8]) -> Vec<u8> {
        let mut t2 = Vec::with_capacity(48);
        t2.extend_from_slice(b"NTLMSSP\0");
        t2.extend_from_slice(&2u32.to_le_bytes());
        t2.extend_from_slice(&0u16.to_le_bytes()); // target name len
        t2.extend_from_slice(&0u16.to_le_bytes()); // target name alloc
        t2.extend_from_slice(&32u32.to_le_bytes()); // target name offset
        t2.extend_from_slice(&0x00288205u32.to_le_bytes()); // flags
        t2.extend_from_slice(&challenge);
        t2.extend_from_slice(&[0u8; 8]); // context
        t2.extend_from_slice(&0u16.to_le_bytes()); // target info len
        t2.extend_from_slice(&0u16.to_le_bytes()); // target info alloc
        t2.extend_from_slice(&48u32.to_le_bytes()); // target info offset
        t2
    }

    fn soap_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    #[test]
    fn test_mock_ntlm_type2_parsable() {
        let t2 = mock_ntlm_type2([1, 2, 3, 4, 5, 6, 7, 8]);
        let parsed = crate::proto::ntlm::parse_challenge_message(&t2)
            .expect("synthetic Type2 is structurally valid");
        assert_eq!(parsed.challenge, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(parsed.target_info.is_none());
    }

    const MOCK_T2_CHALLENGE: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02];

    fn mock_enumerate_response(context: &str) -> String {
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><wsen:EnumerateResponse xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:ads="http://schemas.microsoft.com/2008/09/Identity/Enumeration/ADDirectory"><wsen:EnumerationContext>{}</wsen:EnumerationContext><wsen:Items><ads:Object ad:distinguishedName="CN=alice,CN=Users,DC=corp,DC=local" xmlns:ad="http://x"><ads:attr name="sAMAccountName"><ads:value>alice</ads:value></ads:attr></ads:Object><ads:Object ad:distinguishedName="CN=bob,CN=Users,DC=corp,DC=local" xmlns:ad="http://x"><ads:attr name="sAMAccountName"><ads:value>bob</ads:value></ads:attr></ads:Object></wsen:Items><wsen:EndOfSequence/></wsen:EnumerateResponse></s:Body></s:Envelope>"#,
            context
        )
    }

    /// Leg-1 RSTRC body with the base64 of a structurally valid Type2.
    fn mock_rstrc_leg1() -> String {
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><wst:RequestSecurityTokenResponseCollection xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/trust"><wst:RequestSecurityTokenResponse><wst:BinaryExchange xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/trust" ValueType="http://schemas.xmlsoap.org/ws/2004/09/transfer/NTLM" EncodingType="http://schemas.xmlsoap.org/ws/2004/09/transfer/base64">{}</wst:BinaryExchange></wst:RequestSecurityTokenResponse></wst:RequestSecurityTokenResponseCollection></s:Body></s:Envelope>"#,
            B64.encode(mock_ntlm_type2(MOCK_T2_CHALLENGE))
        )
    }

    /// Read one full HTTP request (headers + Content-Length body).
    fn read_request(socket: &mut std::net::TcpStream) -> String {
        let mut acc = Vec::new();
        let mut chunk = [0u8; 16_384];
        loop {
            match socket.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => acc.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
            let text = String::from_utf8_lossy(&acc);
            if let Some(split) = text.find("\r\n\r\n") {
                let cl = text[..split]
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if acc.len() >= split + 4 + cl {
                    break;
                }
            }
            if acc.len() > 256_000 {
                break;
            }
        }
        String::from_utf8_lossy(&acc).to_string()
    }

    /// Serve one full session on a SINGLE keep-alive connection:
    /// leg 1 -> Type2 b64, leg 2 -> ack, enumerate -> single page.
    fn mock_adws_thread(listener: std::net::TcpListener) -> JoinHandle<Result<usize>> {
        std::thread::spawn(move || -> Result<usize> {
            let mut requests_seen = 0usize;
            let (mut socket, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) => return Err(adws_err(format!("accept: {}", e))),
            };
            for _ in 0..3 {
                let req = read_request(&mut socket);
                let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                requests_seen += 1;

                let resp_body = if body.contains("RST/Issue")
                    && body.contains("<wst:BinaryExchange ValueType")
                    && !body.contains("</wst:BinaryExchange>")
                {
                    // Leg 1: empty BinaryExchange element -> Type2 token
                    soap_response(&mock_rstrc_leg1())
                } else if body.contains("RST/Issue") && body.contains("TlRMTVNTUAAD") {
                    // Leg 2: client Type3 (base64 starts NTLMSSP\0 + type 3)
                    let t3 = B64
                        .decode(
                            body.split("base64\">")
                                .nth(1)
                                .unwrap_or("")
                                .split("</wst:BinaryExchange>")
                                .next()
                                .unwrap_or(""),
                        )
                        .map_err(|e| adws_err(format!("bad leg2 token: {e}")))?;
                    assert_eq!(&t3[..8], b"NTLMSSP\0", "leg2 carries NTLM type3");
                    assert_eq!(u32::from_le_bytes(t3[8..12].try_into().unwrap()), 3);
                    soap_response(
                        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><wst:RequestSecurityTokenResponseCollection xmlns:wst=\"http://schemas.xmlsoap.org/ws/2004/09/trust\"/></s:Body></s:Envelope>",
                    )
                } else if body.contains("Enumerate") {
                    soap_response(&mock_enumerate_response("ctx-0123"))
                } else {
                    return Err(adws_err(format!(
                        "unexpected request body: {}",
                        body.chars().take(80).collect::<String>()
                    )));
                };
                socket
                    .write_all(resp_body.as_bytes())
                    .map_err(|e| adws_err(format!("write: {}", e)))?;
            }
            Ok(requests_seen)
        })
    }
    #[test]
    fn test_full_adws_flow_mock() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = mock_adws_thread(listener);

        let config = AdwsConfig {
            domain: "CORP".into(),
            username: "alice".into(),
            nt_hash_hex: "31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            timeout_secs: 10,
        };
        let mut client = AdwsClient::connect_with_transport(
            TcpStream::connect(("127.0.0.1", port)).unwrap(),
            "dc01",
            &config,
        )
        .expect("WS-Trust handshake");
        assert!(client.connected);
        assert_eq!(client.host(), "dc01");

        let objects = client
            .enumerate("(&(objectClass=user))", 100)
            .expect("enumerate");
        assert_eq!(objects.len(), 2, "two users returned: {objects:?}");
        assert_eq!(objects[0].dn, "CN=alice,CN=Users,DC=corp,DC=local");
        assert_eq!(objects[0].get("samaccountname"), Some("alice"));
        assert_eq!(objects[1].get("samaccountname"), Some("bob"));

        let seen = join.join().expect("mock thread").expect("mock ok");
        assert_eq!(seen, 3, "leg1 + leg2 + enumerate");
    }

    // -------------------------------------------------------
    // Failure paths (real client against hostile mock server)
    // -------------------------------------------------------

    #[test]
    fn test_handshake_fails_on_fault_response() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&mut socket);
            socket
                .write_all(
                    soap_response(
                        "<s:Envelope><s:Body><o:Fault xmlns:o=\"x\"><o:Reason>Access Denied</o:Reason></o:Fault></s:Body></s:Envelope>",
                    )
                    .as_bytes(),
                )
                .unwrap();
        });

        let config = AdwsConfig {
            domain: "CORP".into(),
            username: "alice".into(),
            nt_hash_hex: "31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            timeout_secs: 10,
        };
        let err = AdwsClient::connect_with_transport(
            TcpStream::connect(("127.0.0.1", port)).unwrap(),
            "dc01",
            &config,
        )
        .expect_err("fault must fail the handshake");
        let msg = format!("{}", err);
        assert!(msg.contains("fault"), "fault surfaced: {msg}");
        assert!(msg.contains("Access Denied"), "reason surfaced");
        join.join().unwrap();
    }

    #[test]
    fn test_handshake_fails_on_missing_token() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&mut socket);
            socket
                .write_all(
                    soap_response("<s:Envelope><s:Body><empty/></s:Body></s:Envelope>").as_bytes(),
                )
                .unwrap();
        });

        let config = AdwsConfig {
            domain: "CORP".into(),
            username: "alice".into(),
            nt_hash_hex: "31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            timeout_secs: 10,
        };
        let err = AdwsClient::connect_with_transport(
            TcpStream::connect(("127.0.0.1", port)).unwrap(),
            "dc01",
            &config,
        )
        .expect_err("missing BinaryExchange must fail");
        assert!(
            format!("{}", err).contains("no BinaryExchange"),
            "explicit guidance: {err}"
        );
        join.join().unwrap();
    }
}
