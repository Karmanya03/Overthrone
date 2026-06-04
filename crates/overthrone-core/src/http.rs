const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
];

/// A pool of realistic User-Agent strings for rotation.
///
/// Call [`pick`](Self::pick) or [`random`](Self::random) to get a value,
/// then pass it to `reqwest::Client::builder().user_agent(ua)`.
pub struct UserAgentPool;

impl UserAgentPool {
    /// Return the User-Agent at the given index (wraps around).
    pub fn pick(idx: usize) -> &'static str {
        USER_AGENTS[idx % USER_AGENTS.len()]
    }

    /// Return a random User-Agent from the pool.
    pub fn random() -> &'static str {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let idx = (nanos as usize) % USER_AGENTS.len();
        USER_AGENTS[idx]
    }

    /// Return the total number of User-Agent strings in the pool.
    pub fn len() -> usize {
        USER_AGENTS.len()
    }

    /// Return `true` if the pool is empty (never true for this built-in pool).
    pub fn is_empty() -> bool {
        USER_AGENTS.is_empty()
    }
}
