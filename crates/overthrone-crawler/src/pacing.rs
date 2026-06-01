//! OpSec pacing, rate limiting, and jitter for network operations.
//!
//! Prevents detection by:
//! - Rate-limiting LDAP queries and network connections
//! - Adding random jitter between requests to avoid pattern detection
//! - Providing configurable concurrency limits
//!
//! Reference: This module is used by `overthrone-crawler` and can be integrated
//! by any Overthrone crate that performs bulk network operations.

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
}
