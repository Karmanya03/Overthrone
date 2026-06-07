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

    /// Acquire pacing permission — waits for concurrency slot and applies delay.
    /// Returns a token that releases the slot when dropped.
    pub async fn acquire(&self) -> PacingToken<'_> {
        let permit = match &self.semaphore {
            Some(s) => Some(s.acquire().await.unwrap_or_else(|_| {
                // Semaphore closed — should not happen
                panic!("OpsecPacer semaphore closed")
            })),
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
            Some(s) => Some(
                s.acquire()
                    .await
                    .unwrap_or_else(|_| panic!("OpsecPacer semaphore closed")),
            ),
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

// ═══════════════════════════════════════════════════════════
// DNS Resolver Rotation
// ═══════════════════════════════════════════════════════════

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
                "8.8.8.8".into(),     // Google
                "8.8.4.4".into(),     // Google
                "1.1.1.1".into(),     // Cloudflare
                "1.0.0.1".into(),     // Cloudflare
                "9.9.9.9".into(),     // Quad9
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

// ═══════════════════════════════════════════════════════════
// HTTP User-Agent Rotation
// ═══════════════════════════════════════════════════════════

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
}
