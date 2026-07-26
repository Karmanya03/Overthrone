use ldap3::controls::{Control, RawControl};
use ldap3::{Ldap, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use thiserror::Error;

pub const DIRSYNC_OID: &str = "1.2.840.113556.1.4.841";
pub const OBJECT_SECURITY: u32 = 0x1;
pub const DIRSYNC_ANCESTORS_FIRST_ORDER: u32 = 0x0800;
pub const DIRSYNC_GET_CHANGED: u32 = 0x1;
pub const MAX_DIRSYNC_BYTES: u32 = 33_554_432;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirSyncConfig {
    pub base_dn: String,
    pub cookie: Vec<u8>,
    pub page_size: u32,
    pub attributes: Vec<String>,
    pub object_class: Vec<String>,
    pub include_sd: bool,
}

impl Default for DirSyncConfig {
    fn default() -> Self {
        Self {
            base_dn: String::new(),
            cookie: Vec::new(),
            page_size: 5000,
            attributes: vec!["*".into(), "nTSecurityDescriptor".into()],
            object_class: vec!["user".into(), "computer".into(), "group".into()],
            include_sd: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirSyncResult {
    pub entries: Vec<DirSyncEntry>,
    pub cookie: Vec<u8>,
    pub more_data: bool,
    pub total_count: usize,
    pub elapsed_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirSyncEntry {
    pub dn: String,
    pub attributes: HashMap<String, Vec<String>>,
    pub security_descriptor: Option<Vec<u8>>,
    pub object_class: String,
    pub object_guid: Option<String>,
}

#[derive(Error, Debug)]
pub enum DirSyncError {
    #[error("LDAP operation failed: {0}")]
    LdapError(String),
    #[error("DirSync cookie error: {0}")]
    CookieError(String),
    #[error("DirSync replication error: {0}")]
    ReplicationError(String),
    #[error("Not authorized — missing DS-Replication-Get-Changes: {0}")]
    NotAuthorized(String),
}

impl std::fmt::Display for DirSyncEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DN: {}", self.dn)?;
        if let Some(g) = &self.object_guid {
            write!(f, "  GUID: {g}")?;
        }
        write!(f, "  Class: {}", self.object_class)?;
        let sz = self
            .security_descriptor
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(0);
        write!(f, "  SD Size: {sz} bytes")
    }
}

impl std::fmt::Display for DirSyncResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DirSync: {} entries in {:.2}s (more_data: {}, cookie_len: {})",
            self.total_count,
            self.elapsed_seconds,
            self.more_data,
            self.cookie.len(),
        )
    }
}

fn ber_write_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    } else {
        buf.push(0x83);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn ber_write_octet_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(0x04);
    ber_write_length(buf, data.len());
    buf.extend_from_slice(data);
}

fn ber_write_integer(buf: &mut Vec<u8>, value: u32) {
    buf.push(0x02);
    let bytes = value.to_be_bytes();
    let mut idx = 0;
    while idx < 3 && bytes[idx] == 0 {
        idx += 1;
    }
    ber_write_length(buf, 4 - idx);
    buf.extend_from_slice(&bytes[idx..]);
}

fn ber_encode_sequence(contents: &[u8]) -> Vec<u8> {
    let mut r = vec![0x30];
    ber_write_length(&mut r, contents.len());
    r.extend_from_slice(contents);
    r
}

fn parse_ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        return Some((data[0] as usize, 1));
    }
    let n = (data[0] & 0x7F) as usize;
    if n == 0 || n > data.len() - 1 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[1 + i] as usize;
    }
    Some((len, 1 + n))
}

pub fn build_dirsync_control(cookie: &[u8], flags: u32, max_bytes: u32) -> RawControl {
    let mut seq = Vec::new();
    ber_write_octet_string(&mut seq, cookie);
    ber_write_integer(&mut seq, flags);
    ber_write_integer(&mut seq, max_bytes);
    RawControl {
        ctype: DIRSYNC_OID.into(),
        crit: true,
        val: Some(ber_encode_sequence(&seq)),
    }
}

pub fn parse_dirsync_cookie(raw: &[u8]) -> Option<(Vec<u8>, u64)> {
    if raw.is_empty() || raw[0] != 0x30 {
        return None;
    }
    let mut pos = 1;
    if pos >= raw.len() {
        return None;
    }
    if raw[pos] < 0x80 {
        pos += 1;
    } else {
        let n = (raw[pos] & 0x7F) as usize;
        if n == 0 || pos + 1 + n > raw.len() {
            return None;
        }
        pos += 1 + n;
    }
    if pos >= raw.len() || raw[pos] != 0x04 {
        return None;
    }
    pos += 1;
    if pos >= raw.len() {
        return None;
    }
    let (slen, c) = parse_ber_length(&raw[pos..])?;
    pos += c;
    if pos + slen > raw.len() {
        return None;
    }
    let cookie = raw[pos..pos + slen].to_vec();
    pos += slen;
    if pos >= raw.len() || raw[pos] != 0x02 {
        return Some((cookie, 0));
    }
    pos += 1;
    if pos >= raw.len() {
        return Some((cookie, 0));
    }
    let (ilen, c2) = parse_ber_length(&raw[pos..])?;
    pos += c2;
    if pos + ilen > raw.len() {
        return Some((cookie, 0));
    }
    let mut ts = [0u8; 8];
    let start = 8usize.saturating_sub(ilen);
    for (d, s) in ts[start..].iter_mut().zip(&raw[pos..pos + ilen]) {
        *d = *s;
    }
    Some((cookie, u64::from_be_bytes(ts)))
}

pub async fn dirsync_enum(
    ldap: &mut Ldap,
    config: &DirSyncConfig,
) -> Result<DirSyncResult, DirSyncError> {
    let start = Instant::now();
    let flags = if config.include_sd {
        OBJECT_SECURITY
    } else {
        0
    };
    let ctrl = build_dirsync_control(&config.cookie, flags, MAX_DIRSYNC_BYTES);
    let attrs: Vec<&str> = config.attributes.iter().map(|s| s.as_str()).collect();

    let (entries, ldap_result) = ldap
        .with_controls(vec![ctrl])
        .search(
            if config.base_dn.is_empty() {
                ""
            } else {
                &config.base_dn
            },
            Scope::Subtree,
            "(objectClass=*)",
            &attrs,
        )
        .await
        .map_err(|e| DirSyncError::LdapError(format!("Search failed: {e}")))?
        .success()
        .map_err(|e| DirSyncError::LdapError(format!("Search result error: {e}")))?;

    let parsed: Vec<DirSyncEntry> = entries
        .into_iter()
        .map(|e| entry_from_search_entry(SearchEntry::construct(e), config.include_sd))
        .collect();

    let (cookie, more) = extract_dirsync_response(&ldap_result.ctrls);
    Ok(DirSyncResult {
        total_count: parsed.len(),
        entries: parsed,
        cookie,
        more_data: more,
        elapsed_seconds: start.elapsed().as_secs_f64(),
    })
}

pub async fn dirsync_full_sync(
    ldap: &mut Ldap,
    config: &DirSyncConfig,
) -> Result<DirSyncResult, DirSyncError> {
    let start = Instant::now();
    let mut all = Vec::new();
    let mut cookie = config.cookie.clone();
    let mut page = 0u32;

    loop {
        let cfg = DirSyncConfig {
            cookie,
            ..config.clone()
        };
        let r = dirsync_enum(ldap, &cfg).await?;
        all.extend(r.entries);
        cookie = r.cookie;
        page += 1;
        if !r.more_data {
            break;
        }
        if page >= 1000 {
            return Err(DirSyncError::ReplicationError(
                "DirSync exceeded 1000 pages".into(),
            ));
        }
    }

    let total = all.len();
    Ok(DirSyncResult {
        entries: all,
        cookie,
        more_data: false,
        total_count: total,
        elapsed_seconds: start.elapsed().as_secs_f64(),
    })
}

fn entry_from_search_entry(entry: SearchEntry, include_sd: bool) -> DirSyncEntry {
    let oc = entry
        .attrs
        .get("objectClass")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let guid = entry
        .attrs
        .get("objectGUID")
        .and_then(|v| v.first())
        .cloned()
        .or_else(|| entry.bin_attrs.get("objectGUID")?.first().map(hex::encode));
    let sd = if include_sd {
        entry
            .bin_attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
    } else {
        None
    };
    DirSyncEntry {
        dn: entry.dn,
        attributes: entry.attrs,
        security_descriptor: sd,
        object_class: oc,
        object_guid: guid,
    }
}

fn extract_dirsync_response(controls: &[Control]) -> (Vec<u8>, bool) {
    for ctrl in controls {
        let Control(_, raw) = ctrl;
        if raw.ctype == DIRSYNC_OID
            && let Some(ref val) = raw.val
            && let Some((cookie, _)) = parse_dirsync_cookie(val)
        {
            return (cookie, parse_dirsync_more_flag(val));
        }
    }
    (Vec::new(), false)
}

fn parse_dirsync_more_flag(raw: &[u8]) -> bool {
    if raw.len() < 3 || raw[0] != 0x30 {
        return false;
    }
    let mut pos = 1;
    if pos >= raw.len() {
        return false;
    }
    if raw[pos] < 0x80 {
        pos += 1;
    } else {
        let n = (raw[pos] & 0x7F) as usize;
        if n == 0 || pos + 1 + n > raw.len() {
            return false;
        }
        pos += 1 + n;
    }
    if pos >= raw.len() || raw[pos] != 0x04 {
        return false;
    }
    pos += 1;
    if pos >= raw.len() {
        return false;
    }
    let (slen, c) = match parse_ber_length(&raw[pos..]) {
        Some(r) => r,
        None => return false,
    };
    pos += c + slen;
    if pos >= raw.len() || raw[pos] != 0x02 {
        return false;
    }
    pos += 1;
    if pos >= raw.len() {
        return false;
    }
    let (ilen, c2) = match parse_ber_length(&raw[pos..]) {
        Some(r) => r,
        None => return false,
    };
    pos += c2;
    if pos + ilen > raw.len() {
        return false;
    }
    let mut val = 0u32;
    for &b in &raw[pos..pos + ilen] {
        val = (val << 8) | b as u32;
    }
    val & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dirsync_config_default() {
        let c = DirSyncConfig::default();
        assert!(c.base_dn.is_empty());
        assert!(c.cookie.is_empty());
        assert_eq!(c.page_size, 5000);
        assert_eq!(c.attributes, vec!["*", "nTSecurityDescriptor"]);
        assert_eq!(c.object_class, vec!["user", "computer", "group"]);
        assert!(c.include_sd);
    }

    #[test]
    fn test_dirsync_config_custom() {
        let c = DirSyncConfig {
            base_dn: "DC=ad,DC=example,DC=com".into(),
            cookie: vec![1, 2, 3],
            page_size: 1000,
            attributes: vec!["sAMAccountName".into()],
            object_class: vec!["user".into()],
            include_sd: false,
        };
        assert_eq!(c.base_dn, "DC=ad,DC=example,DC=com");
        assert_eq!(c.cookie, vec![1, 2, 3]);
        assert!(!c.include_sd);
    }

    #[test]
    fn test_dirsync_entry_display() {
        let e = DirSyncEntry {
            dn: "CN=test,DC=ad,DC=local".into(),
            attributes: HashMap::new(),
            security_descriptor: Some(vec![0u8; 64]),
            object_class: "user".into(),
            object_guid: Some("abc-123".into()),
        };
        let s = format!("{e}");
        assert!(s.contains("CN=test,DC=ad,DC=local"));
        assert!(s.contains("abc-123"));
        assert!(s.contains("64 bytes"));
    }

    #[test]
    fn test_dirsync_result_display() {
        let r = DirSyncResult {
            entries: vec![],
            cookie: vec![0xAB; 8],
            more_data: true,
            total_count: 150,
            elapsed_seconds: 2.5,
        };
        let s = format!("{r}");
        assert!(s.contains("150"));
        assert!(s.contains("2.50"));
        assert!(s.contains("cookie_len: 8"));
    }

    #[test]
    fn test_build_dirsync_control_oid() {
        let c = build_dirsync_control(&[], OBJECT_SECURITY, MAX_DIRSYNC_BYTES);
        assert_eq!(c.ctype, DIRSYNC_OID);
        assert!(c.crit);
    }

    #[test]
    fn test_build_dirsync_control_empty_cookie() {
        let c = build_dirsync_control(&[], OBJECT_SECURITY, MAX_DIRSYNC_BYTES);
        let v = c.val.unwrap();
        assert!(!v.is_empty());
        assert_eq!(v[0], 0x30);
    }

    #[test]
    fn test_build_dirsync_control_with_cookie() {
        let cookie = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let c = build_dirsync_control(&cookie, OBJECT_SECURITY, MAX_DIRSYNC_BYTES);
        assert!(
            c.val
                .unwrap()
                .windows(4)
                .any(|w| w == [0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn test_parse_dirsync_cookie_empty() {
        assert!(parse_dirsync_cookie(&[]).is_none());
    }

    #[test]
    fn test_parse_dirsync_cookie_invalid() {
        assert!(parse_dirsync_cookie(&[0xFF, 0xFF, 0xFF]).is_none());
    }

    #[test]
    fn test_ber_encoding_roundtrip() {
        let mut seq = Vec::new();
        ber_write_octet_string(&mut seq, b"test-cookie");
        ber_write_integer(&mut seq, OBJECT_SECURITY);
        ber_write_integer(&mut seq, MAX_DIRSYNC_BYTES);
        let enc = ber_encode_sequence(&seq);
        let (cookie, _ts) = parse_dirsync_cookie(&enc).unwrap();
        assert_eq!(cookie, b"test-cookie");
    }

    #[test]
    fn test_ber_encode_integer_various() {
        let mut b = Vec::new();
        ber_write_integer(&mut b, 0);
        assert_eq!(b, vec![0x02, 0x01, 0x00]);
        let mut b = Vec::new();
        ber_write_integer(&mut b, 1);
        assert_eq!(b, vec![0x02, 0x01, 0x01]);
        let mut b = Vec::new();
        ber_write_integer(&mut b, 255);
        // BER minimal encoding: 0xFF fits in 1 byte
        assert_eq!(b, vec![0x02, 0x01, 0xFF]);
        let mut b = Vec::new();
        ber_write_integer(&mut b, 65535);
        // BER minimal encoding: 0xFFFF fits in 2 bytes
        assert_eq!(b, vec![0x02, 0x02, 0xFF, 0xFF]);
    }

    #[test]
    fn test_parse_dirsync_cookie_valid() {
        let mut seq = Vec::new();
        ber_write_octet_string(&mut seq, b"mycookie");
        ber_write_integer(&mut seq, 12345);
        let enc = ber_encode_sequence(&seq);
        let (cookie, ts) = parse_dirsync_cookie(&enc).unwrap();
        assert_eq!(cookie, b"mycookie");
        assert_eq!(ts, 12345);
    }

    #[test]
    fn test_dirsync_error_display() {
        let e = DirSyncError::LdapError("conn refused".into());
        assert_eq!(format!("{e}"), "LDAP operation failed: conn refused");
        let e = DirSyncError::CookieError("parse".into());
        assert_eq!(format!("{e}"), "DirSync cookie error: parse");
        let e = DirSyncError::ReplicationError("timeout".into());
        assert_eq!(format!("{e}"), "DirSync replication error: timeout");
        let e = DirSyncError::NotAuthorized("denied".into());
        assert_eq!(
            format!("{e}"),
            "Not authorized — missing DS-Replication-Get-Changes: denied"
        );
    }

    #[test]
    fn test_parse_dirsync_more_flag_true() {
        let mut seq = Vec::new();
        ber_write_octet_string(&mut seq, b"");
        ber_write_integer(&mut seq, 1);
        assert!(parse_dirsync_more_flag(&ber_encode_sequence(&seq)));
    }

    #[test]
    fn test_parse_dirsync_more_flag_false() {
        let mut seq = Vec::new();
        ber_write_octet_string(&mut seq, b"");
        ber_write_integer(&mut seq, 0);
        assert!(!parse_dirsync_more_flag(&ber_encode_sequence(&seq)));
    }
}
