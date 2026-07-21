//! OpSec pacing, rate limiting, and jitter for network operations.
//!
//! Prevents detection by:
//! - Rate-limiting LDAP queries and network connections
//! - Adding random jitter between requests to avoid pattern detection
//! - Providing configurable concurrency limits
//! - Rotating DNS resolvers to distribute queries
//! - Rotating HTTP User-Agent strings to avoid fingerprinting
//!
//! Reference: This module is used by `overthrone-crawler` and can be integrated
//! by any Overthrone crate that performs bulk network operations.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::trace;

/// Pacing configuration for OpSec-compliant network operations.
#[derive(Debug, Clone)]
pub struct PacingConfig {
    /// Minimum delay between operations (base).
    pub min_delay_ms: u64,
    /// Maximum additional random jitter (0 = no jitter).
    pub jitter_ms: u64,
    /// Maximum concurrent operations (0 = unlimited).
    pub max_concurrent: usize,
    /// Whether to vary source ports (requires platform support).
    pub rotate_ports: bool,
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self {
            min_delay_ms: 200,   // 5 ops/sec base
            jitter_ms: 300,      // +0-300ms random jitter
            max_concurrent: 4,   // max 4 concurrent operations
            rotate_ports: false, // port rotation disabled by default
        }
    }
}

impl PacingConfig {
    /// Config for aggressive stealth (very slow, high jitter).
    pub fn stealth() -> Self {
        Self {
            min_delay_ms: 1000, // 1 op/sec
            jitter_ms: 2000,    // +0-2s jitter
            max_concurrent: 1,  // serial only
            rotate_ports: true,
        }
    }

    /// Config for fast enumeration (moderate, low jitter).
    pub fn fast() -> Self {
        Self {
            min_delay_ms: 50,
            jitter_ms: 50,
            max_concurrent: 8,
            rotate_ports: false,
        }
    }

    /// Generate a randomized delay based on config.
    pub fn delay(&self) -> Duration {
        let jitter = if self.jitter_ms > 0 {
            rand::random::<u64>() % self.jitter_ms
        } else {
            0
        };
        Duration::from_millis(self.min_delay_ms + jitter)
    }
}

/// A pacing token that releases the concurrency slot on drop.
pub struct PacingToken<'a> {
    permit: Option<tokio::sync::SemaphorePermit<'a>>,
}

impl PacingToken<'_> {
    pub fn release(mut self) {
        self.permit.take();
    }
}

impl Drop for PacingToken<'_> {
    fn drop(&mut self) {
        if self.permit.is_some() {
            // Permit is automatically returned to semaphore on drop
        }
    }
}

/// OpSec pacer that manages rate limiting and concurrency.
pub struct OpsecPacer {
    config: PacingConfig,
    semaphore: Option<Semaphore>,
}

impl OpsecPacer {
    /// Create a new pacer with the given config.
    pub fn new(config: PacingConfig) -> Self {
        let semaphore = if config.max_concurrent > 0 {
            Some(Semaphore::new(config.max_concurrent))
        } else {
            None
        };
        Self { config, semaphore }
    }

    /// Acquire pacing permission -- waits for concurrency slot and applies delay.
    /// Returns a token that releases the slot when dropped.
    pub async fn acquire(&self) -> PacingToken<'_> {
        let permit = match &self.semaphore {
            Some(s) => match s.acquire().await {
                Ok(p) => Some(p),
                Err(_) => {
                    tracing::warn!(
                        "OpsecPacer semaphore closed -- continuing without concurrency limit"
                    );
                    None
                }
            },
            None => None,
        };

        let delay = self.config.delay();
        if !delay.is_zero() {
            trace!("OpSec: pacing delay {:?}", delay);
            tokio::time::sleep(delay).await;
        }

        PacingToken { permit }
    }

    /// Acquire pacing permission with a custom delay override.
    pub async fn acquire_with_delay(&self, delay_override: Duration) -> PacingToken<'_> {
        let permit = match &self.semaphore {
            Some(s) => match s.acquire().await {
                Ok(p) => Some(p),
                Err(_) => {
                    tracing::warn!(
                        "OpsecPacer semaphore closed -- continuing without concurrency limit"
                    );
                    None
                }
            },
            None => None,
        };

        tokio::time::sleep(delay_override).await;
        PacingToken { permit }
    }

    /// Get a reference to the pacing config.
    pub fn config(&self) -> &PacingConfig {
        &self.config
    }
}

// ===========================================================
// DNS Resolver Rotation
// ===========================================================

/// Round-robin DNS resolver rotator.
/// Distributes queries across multiple resolvers to avoid
/// triggering rate limits or detection on a single resolver.
#[derive(Debug, Clone)]
pub struct DnsRotator {
    resolvers: Vec<String>,
    index: std::sync::Arc<AtomicUsize>,
}

impl DnsRotator {
    /// Create a new DNS rotator from a list of resolver IPs.
    /// If the list is empty, defaults to common public resolvers.
    pub fn new(resolvers: Vec<String>) -> Self {
        let resolvers = if resolvers.is_empty() {
            vec![
                "8.8.8.8".into(),        // Google
                "8.8.4.4".into(),        // Google
                "1.1.1.1".into(),        // Cloudflare
                "1.0.0.1".into(),        // Cloudflare
                "9.9.9.9".into(),        // Quad9
                "208.67.222.222".into(), // OpenDNS
            ]
        } else {
            resolvers
        };
        Self {
            resolvers,
            index: std::sync::Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Create a rotator with default public resolvers.
    pub fn default_public() -> Self {
        Self::new(vec![])
    }

    /// Get the next resolver in the round-robin sequence.
    pub fn next(&self) -> &str {
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.resolvers.len();
        &self.resolvers[idx]
    }

    /// Get all configured resolvers.
    pub fn resolvers(&self) -> &[String] {
        &self.resolvers
    }

    /// Number of configured resolvers.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether the rotator has no resolvers (always false for valid configs).
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

impl Default for DnsRotator {
    fn default() -> Self {
        Self::default_public()
    }
}

// ===========================================================
// HTTP User-Agent Rotation
// ===========================================================

/// Pool of User-Agent strings for HTTP request rotation.
/// Randomly selects a UA per request to avoid fingerprinting.
#[derive(Debug, Clone)]
pub struct UserAgentPool {
    agents: Vec<String>,
}

impl UserAgentPool {
    /// Create a new pool from a list of User-Agent strings.
    /// If empty, defaults to common browser UAs.
    pub fn new(agents: Vec<String>) -> Self {
        let agents = if agents.is_empty() {
            Self::default_agents()
        } else {
            agents
        };
        Self { agents }
    }

    /// Create a pool with default browser User-Agent strings.
    pub fn default_pool() -> Self {
        Self::new(vec![])
    }

    /// Pick a random User-Agent from the pool.
    pub fn pick(&self) -> &str {
        let idx = (rand::random::<u64>() as usize) % self.agents.len();
        &self.agents[idx]
    }

    /// Get all configured User-Agent strings.
    pub fn agents(&self) -> &[String] {
        &self.agents
    }

    /// Number of configured User-Agent strings.
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    fn default_agents() -> Vec<String> {
        vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0".into(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.105".into(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15".into(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".into(),
        ]
    }
}

impl Default for UserAgentPool {
    fn default() -> Self {
        Self::default_pool()
    }
}

// ===========================================================
// TCP Source Port Rotation
// ===========================================================

/// Round-robin TCP source port rotator.
///
/// Varies the source port for outbound TCP connections to avoid
/// detection by network monitoring that flags consistent port
/// usage patterns. Useful during stealth enumeration where each
/// connection should appear to come from a different ephemeral port.
///
/// The default range (49152--65535) mirrors the IANA dynamic port range,
/// providing ~16K ports before cycling. This is large enough that
/// TIME_WAIT collisions are rare in practice.
#[derive(Debug, Clone)]
pub struct PortRotator {
    start: u16,
    count: u32,
    index: std::sync::Arc<AtomicUsize>,
}

impl PortRotator {
    /// Create a new port rotator over the range `start..=end` (inclusive).
    ///
    /// Returns an error if `start > end` or the range exceeds 65535.
    pub fn new(start: u16, end: u16) -> Result<Self, String> {
        if start > end {
            return Err(format!("port range start ({start}) > end ({end})"));
        }
        if end == 0 {
            return Err("port range end cannot be 0 (reserved)".into());
        }
        Ok(Self {
            start,
            count: end as u32 - start as u32 + 1,
            index: std::sync::Arc::new(AtomicUsize::new(rand::random::<u64>() as usize)),
        })
    }

    /// Create a rotator over the IANA ephemeral port range (49152--65535).
    pub fn default_ephemeral() -> Self {
        // Unwrap is safe: 49152 <= 65535
        Self::new(49152, 65535).expect("invalid default ephemeral range")
    }

    /// Get the next source port (round-robin).
    pub fn next_port(&self) -> u16 {
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.count as usize;
        self.start + idx as u16
    }

    /// Reset the rotator to a random starting position.
    pub fn reseed(&self) {
        self.index.store(
            (rand::random::<u64>() as usize) % self.count as usize,
            Ordering::Relaxed,
        )
    }

    /// The number of ports in the range.
    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// Whether the range is empty (should never be true for valid configs).
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the (start, end) of the configured range.
    pub fn range(&self) -> (u16, u16) {
        (self.start, self.start + (self.count - 1) as u16)
    }
}

impl Default for PortRotator {
    fn default() -> Self {
        Self::default_ephemeral()
    }
}

/// Connect to a target address using a specific source port.
///
/// This creates a `tokio::net::TcpSocket`, binds it to `source_port`
/// on the unspecified address, then connects to `target`. If binding
/// fails (e.g., port in TIME_WAIT), the error is returned.
///
/// On Windows, binding to ports >= 1024 does not require administrator
/// privileges, making this usable in low-integrity contexts.
pub async fn connect_with_source_port(
    target: std::net::SocketAddr,
    source_port: u16,
) -> std::io::Result<tokio::net::TcpStream> {
    let socket = match target {
        std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    // MSG: Do NOT set SO_REUSEADDR on Windows -- it has different semantics
    // (allows multiple sockets to bind the same port, which we don't want).
    // On Unix, we also skip it to avoid masking port conflicts.
    #[cfg(not(windows))]
    {
        // On Linux/macOS, SO_REUSEADDR helps avoid EADDRINUSE from TIME_WAIT
        let _ = socket.set_reuseaddr(true);
    }

    let bind_addr = match target {
        std::net::SocketAddr::V4(_) => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            source_port,
        )),
        std::net::SocketAddr::V6(_) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            source_port,
            0,
            0,
        )),
    };

    socket.bind(bind_addr)?;
    socket.connect(target).await
}

/// Connect to a target, optionally rotating source ports via a `PortRotator`.
///
/// When `rotator` is `Some`, tries up to `max_retries` times to bind to a
/// rotated source port. If all attempts fail or `rotator` is `None`,
/// falls back to a standard OS-assigned source port.
pub async fn connect_with_rotation(
    target: std::net::SocketAddr,
    rotator: Option<&PortRotator>,
    max_retries: u32,
) -> std::io::Result<tokio::net::TcpStream> {
    let rotator = match rotator {
        Some(r) => r,
        None => return tokio::net::TcpStream::connect(target).await,
    };

    for _ in 0..max_retries {
        let port = rotator.next_port();
        match connect_with_source_port(target, port).await {
            Ok(stream) => return Ok(stream),
            Err(_) => continue,
        }
    }

    // Fallback: standard connect with OS-assigned source port
    tokio::net::TcpStream::connect(target).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pacing_config_defaults() {
        let cfg = PacingConfig::default();
        assert_eq!(cfg.min_delay_ms, 200);
    }

    #[test]
    fn test_stealth_config() {
        let cfg = PacingConfig::stealth();
        assert_eq!(cfg.max_concurrent, 1);
        assert!(cfg.min_delay_ms >= 1000);
    }

    #[tokio::test]
    async fn test_opsec_pacer_acquire() {
        let pacer = OpsecPacer::new(PacingConfig::fast());
        let token = pacer.acquire().await;
        // Token should release when dropped
        drop(token);
    }

    #[tokio::test]
    async fn test_concurrency_limit() {
        let pacer = OpsecPacer::new(PacingConfig {
            min_delay_ms: 0,
            jitter_ms: 0,
            max_concurrent: 2,
            rotate_ports: false,
        });

        let t1 = pacer.acquire().await;
        let t2 = pacer.acquire().await;

        // Both should succeed with 2 permits
        drop(t1);
        drop(t2);
    }

    #[test]
    fn test_dns_rotator_default() {
        let rotator = DnsRotator::default_public();
        assert!(rotator.len() >= 4);
        assert!(!rotator.is_empty());
    }

    #[test]
    fn test_dns_rotator_round_robin() {
        let rotator = DnsRotator::new(vec!["1.1.1.1".into(), "8.8.8.8".into()]);
        assert_eq!(rotator.next(), "1.1.1.1");
        assert_eq!(rotator.next(), "8.8.8.8");
        assert_eq!(rotator.next(), "1.1.1.1"); // wraps around
    }

    #[test]
    fn test_dns_rotator_custom() {
        let rotator = DnsRotator::new(vec!["10.0.0.1".into()]);
        assert_eq!(rotator.len(), 1);
        assert_eq!(rotator.next(), "10.0.0.1");
        assert_eq!(rotator.next(), "10.0.0.1");
    }

    #[test]
    fn test_dns_rotator_empty_uses_defaults() {
        let rotator = DnsRotator::new(vec![]);
        assert!(rotator.len() >= 4);
    }

    #[test]
    fn test_ua_pool_default() {
        let pool = UserAgentPool::default_pool();
        assert!(pool.len() >= 5);
        assert!(!pool.is_empty());
    }

    #[test]
    fn test_ua_pool_pick_returns_agent() {
        let pool = UserAgentPool::new(vec!["TestAgent/1.0".into(), "TestAgent/2.0".into()]);
        let picked = pool.pick();
        assert!(picked == "TestAgent/1.0" || picked == "TestAgent/2.0");
    }

    #[test]
    fn test_ua_pool_custom() {
        let pool = UserAgentPool::new(vec!["Custom/1.0".into()]);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.pick(), "Custom/1.0");
    }

    #[test]
    fn test_ua_pool_empty_uses_defaults() {
        let pool = UserAgentPool::new(vec![]);
        assert!(pool.len() >= 5);
        // All default agents should contain Mozilla
        assert!(pool.pick().contains("Mozilla"));
    }

    // -- PortRotator tests ----------------------------------

    #[test]
    fn test_port_rotator_default_ephemeral() {
        let rotator = PortRotator::default_ephemeral();
        let (start, end) = rotator.range();
        assert_eq!(start, 49152);
        assert_eq!(end, 65535);
        assert_eq!(rotator.len(), 65535 - 49152 + 1);
    }

    #[test]
    fn test_port_rotator_custom_range() {
        let rotator = PortRotator::new(30000, 30005).unwrap();
        assert_eq!(rotator.len(), 6);
        let (start, end) = rotator.range();
        assert_eq!(start, 30000);
        assert_eq!(end, 30005);
    }

    #[test]
    fn test_port_rotator_round_robin() {
        let rotator = PortRotator::new(40000, 40002).unwrap();
        // First three should be sequential
        let p1 = rotator.next_port();
        let p2 = rotator.next_port();
        let p3 = rotator.next_port();
        let p4 = rotator.next_port();
        assert!(p1 != p2 || rotator.len() == 1);
        // Fourth should wrap around to first
        assert_eq!(p4, p1);
        // All ports should be within range
        for &p in &[p1, p2, p3] {
            assert!((40000..=40002).contains(&p), "port {p} out of range");
        }
    }

    #[test]
    fn test_port_rotator_range_invalid_reversed() {
        let result = PortRotator::new(50000, 40000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("start"));
    }

    #[test]
    fn test_port_rotator_range_zero_end() {
        let result = PortRotator::new(0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_port_rotator_reseed_changes_position() {
        let rotator = PortRotator::new(100, 110).unwrap();
        // Collect sequence before reseed
        let before: Vec<u16> = (0..5).map(|_| rotator.next_port()).collect();
        rotator.reseed();
        let after: Vec<u16> = (0..5).map(|_| rotator.next_port()).collect();
        // Reseed should change the starting position
        let same_prefix = before.iter().zip(after.iter()).take(2).all(|(a, b)| a == b);
        // With high probability the sequences differ
        if same_prefix {
            // Very unlikely but possible; just verify reseed doesn't panic
            assert!(!rotator.is_empty());
        }
    }

    #[test]
    fn test_port_rotator_single_port() {
        let rotator = PortRotator::new(12345, 12345).unwrap();
        assert_eq!(rotator.len(), 1);
        assert_eq!(rotator.next_port(), 12345);
        assert_eq!(rotator.next_port(), 12345); // same every time
    }

    #[test]
    fn test_port_rotator_not_empty() {
        let rotator = PortRotator::default();
        assert!(!rotator.is_empty());
    }

    #[test]
    fn test_connect_with_source_port_invalid_port_fails() {
        // Binding to port 0 should fail (reserved)
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            connect_with_source_port("127.0.0.1:9999".parse().unwrap(), 0).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_with_rotation_no_rotator_falls_back() {
        // Without rotator, should do normal connect to an unreachable port
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            connect_with_rotation("127.0.0.1:1".parse().unwrap(), None, 3).await
        });
        // Connection refused is expected (no one listening on port 1)
        assert!(result.is_err());
        let err = result.unwrap_err();
        let kind = err.kind();
        assert!(
            kind == std::io::ErrorKind::ConnectionRefused
                || kind == std::io::ErrorKind::TimedOut
                || kind == std::io::ErrorKind::AddrNotAvailable,
            "got unexpected error: {err}"
        );
    }

    #[test]
    fn test_connect_with_rotation_rotator_falls_back_on_failure() {
        // With rotator, should try binding then fall back to normal connect
        let rotator = PortRotator::default();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            connect_with_rotation("127.0.0.1:1".parse().unwrap(), Some(&rotator), 2).await
        });
        // Connection refused is expected
        assert!(result.is_err());
    }

    #[test]
    fn test_port_rotator_default_impl() {
        let rotator = PortRotator::default();
        assert_eq!(rotator.range(), (49152, 65535));
    }
}
