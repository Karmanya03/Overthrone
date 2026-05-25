//! Malleable C2 Profiles — traffic blending & evasion profiles.
//!
//! Provides pre-built and custom C2 communication profiles that shape
//! beacon traffic to blend with legitimate HTTP/HTTPS/DNS traffic.
//! These profiles mimic major C2 frameworks' malleable profiles
//! (Cobalt Strike Malleable C2, Sliver HTTP profiles, etc.).
//!
//! # Usage
//! ```rust,ignore
//! let profile = C2Profile::mimic_aws_cloudfront();
//! let config = profile.render();
//! // Use config.jitter, config.sleep, config.user_agent, etc.
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Malleable C2 profile — shapes traffic to blend with legitimate services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Profile {
    /// Profile name (for display/selection)
    pub name: String,
    /// Description of what this profile mimics
    pub description: String,
    /// Beacon sleep time range (min, max) with jitter
    pub sleep_range: (Duration, Duration),
    /// Jitter percentage (0-100) — how much to vary sleep
    pub jitter_percent: u8,
    /// User-Agent string to use
    pub user_agent: String,
    /// HTTP headers to include
    pub headers: HashMap<String, String>,
    /// URI paths for GET (callback)
    pub get_uris: Vec<String>,
    /// URI paths for POST (data exfil)
    pub post_uris: Vec<String>,
    /// URI path for staging
    pub staging_uri: Option<String>,
    /// DNS sleep (for DNS beacons)
    pub dns_sleep: Option<Duration>,
    /// DNS hostname pattern (for DNS beacons)
    pub dns_hostname_pattern: Option<String>,
    /// SSL/TLS configuration
    pub tls_config: Option<TlsConfig>,
    /// Whether to mask beacon data (base64, xor, etc.)
    pub data_mask: DataMasking,
    /// OPSEC rating (1-10, higher = more stealthy)
    pub opsec_rating: u8,
}

/// TLS/JARM fingerprint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// TLS version to mimic (e.g., "TLSv1.3")
    pub tls_version: String,
    /// Cipher suites to advertise
    pub cipher_suites: Vec<String>,
    /// Server name (SNI)
    pub sni: Option<String>,
    /// Whether to use TLS session tickets
    pub session_tickets: bool,
}

/// Data masking options for beacon traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataMasking {
    /// No masking
    None,
    /// Base64 encode
    Base64,
    /// XOR with a key
    Xor {
        /// The XOR key
        key: Vec<u8>,
    },
    /// AES-CBC encrypt
    AesCbc {
        /// AES key
        key: Vec<u8>,
        /// AES IV
        iv: Vec<u8>,
    },
}

impl C2Profile {
    /// Create a profile that mimics Amazon CloudFront CDN traffic.
    /// High OPSEC — blends with AWS edge traffic.
    pub fn mimic_aws_cloudfront() -> Self {
        let mut headers = HashMap::new();
        headers.insert(
            "Accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                .into(),
        );
        headers.insert("Accept-Language".into(), "en-US,en;q=0.9".into());
        headers.insert("Accept-Encoding".into(), "gzip, deflate, br".into());
        headers.insert("Cache-Control".into(), "no-cache".into());
        headers.insert("Pragma".into(), "no-cache".into());
        headers.insert("Sec-Fetch-Dest".into(), "document".into());
        headers.insert("Sec-Fetch-Mode".into(), "navigate".into());
        headers.insert("Sec-Fetch-Site".into(), "none".into());
        headers.insert("Sec-Fetch-User".into(), "?1".into());
        headers.insert("Upgrade-Insecure-Requests".into(), "1".into());

        Self {
            name: "AWS CloudFront".into(),
            description: "Mimics Amazon CloudFront CDN traffic with realistic browser headers".into(),
            sleep_range: (Duration::from_secs(30), Duration::from_secs(180)),
            jitter_percent: 35,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            headers,
            get_uris: vec![
                "/cdn-cgi/trace".into(),
                "/favicon.ico".into(),
                "/static/js/main.js".into(),
            ],
            post_uris: vec![
                "/api/collect".into(),
                "/analytics/report".into(),
            ],
            staging_uri: Some("/cdn-cgi/scripts/".into()),
            dns_sleep: None,
            dns_hostname_pattern: Some("*.cloudfront.net".to_string()),
            tls_config: Some(TlsConfig {
                tls_version: "TLSv1.3".into(),
                cipher_suites: vec![
                    "TLS_AES_256_GCM_SHA384".into(),
                    "TLS_CHACHA20_POLY1305_SHA256".into(),
                ],
                sni: Some("d1234.cloudfront.net".into()),
                session_tickets: true,
            }),
            data_mask: DataMasking::Base64,
            opsec_rating: 9,
        }
    }

    /// Create a profile that mimics Microsoft 365 / Office 365 traffic.
    /// Excellent for Windows environments where M365 is expected.
    pub fn mimic_microsoft_365() -> Self {
        let mut headers = HashMap::new();
        headers.insert("Accept".into(), "application/json".into());
        headers.insert("Accept-Language".into(), "en-US,en;q=0.9".into());
        headers.insert("Accept-Encoding".into(), "gzip, deflate".into());
        headers.insert("Authorization".into(), "Bearer".into());
        headers.insert("Client-Request-Id".into(), "".into());
        headers.insert("x-client-SKU".into(), "Win32".into());
        headers.insert("x-client-Ver".into(), "16.0.14326.20470".into());

        Self {
            name: "Microsoft 365".into(),
            description: "Mimics Microsoft 365 / Exchange Online API traffic — blends with legitimate M365 clients".into(),
            sleep_range: (Duration::from_secs(60), Duration::from_secs(300)),
            jitter_percent: 40,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0".into(),
            headers,
            get_uris: vec![
                "/api/v2.0/me/messages".into(),
                "/api/v2.0/me/events".into(),
                "/autodiscover/autodiscover.json".into(),
            ],
            post_uris: vec![
                "/api/v2.0/me/sendmail".into(),
                "/api/beta/me/export".into(),
            ],
            staging_uri: Some("/powershell/GetUpdate".into()),
            dns_sleep: None,
            dns_hostname_pattern: Some("*.outlook.office365.com".to_string()),
            tls_config: Some(TlsConfig {
                tls_version: "TLSv1.2".into(),
                cipher_suites: vec![
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
                ],
                sni: Some("outlook.office365.com".into()),
                session_tickets: true,
            }),
            data_mask: DataMasking::AesCbc {
                key: vec![0u8; 32],
                iv: vec![0u8; 16],
            },
            opsec_rating: 10,
        }
    }

    /// Create a profile that mimics Google/Gmail API traffic.
    pub fn mimic_google_api() -> Self {
        let mut headers = HashMap::new();
        headers.insert("Accept".into(), "*/*".into());
        headers.insert("Accept-Language".into(), "en-US,en;q=0.9".into());
        headers.insert("Content-Type".into(), "application/x-protobuf".into());
        headers.insert("X-Goog-Api-Key".into(), "".into());

        Self {
            name: "Google API".into(),
            description: "Mimics Google API / Gmail traffic with protobuf and REST patterns".into(),
            sleep_range: (Duration::from_secs(45), Duration::from_secs(200)),
            jitter_percent: 30,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            headers,
            get_uris: vec![
                "/gmail/v1/users/me/profile".into(),
                "/drive/v3/files".into(),
            ],
            post_uris: vec![
                "/gmail/v1/users/me/messages/send".into(),
                "/drive/v3/files/upload".into(),
            ],
            staging_uri: Some("/service-worker.js".into()),
            dns_sleep: None,
            dns_hostname_pattern: Some("*.googleapis.com".to_string()),
            tls_config: Some(TlsConfig {
                tls_version: "TLSv1.3".into(),
                cipher_suites: vec![
                    "TLS_AES_256_GCM_SHA384".into(),
                    "TLS_CHACHA20_POLY1305_SHA256".into(),
                ],
                sni: Some("www.googleapis.com".into()),
                session_tickets: true,
            }),
            data_mask: DataMasking::Base64,
            opsec_rating: 8,
        }
    }

    /// Create a profile that mimics generic Azure Blob Storage traffic.
    pub fn mimic_azure_blob() -> Self {
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".into(), "2021-08-06".into());
        headers.insert("x-ms-blob-type".into(), "BlockBlob".into());
        headers.insert("Accept".into(), "application/xml".into());

        Self {
            name: "Azure Blob".into(),
            description:
                "Mimics Azure Blob Storage API traffic — common in enterprise cloud environments"
                    .into(),
            sleep_range: (Duration::from_secs(60), Duration::from_secs(360)),
            jitter_percent: 50,
            user_agent: "Azure-Storage/2.0".into(),
            headers,
            get_uris: vec!["/container/blob.txt".into(), "/container/metadata".into()],
            post_uris: vec!["/container/block".into(), "/container/commit".into()],
            staging_uri: Some("/container/stage".into()),
            dns_sleep: None,
            dns_hostname_pattern: Some("*.blob.core.windows.net".to_string()),
            tls_config: Some(TlsConfig {
                tls_version: "TLSv1.2".into(),
                cipher_suites: vec!["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into()],
                sni: Some("storageaccount.blob.core.windows.net".into()),
                session_tickets: false,
            }),
            data_mask: DataMasking::Xor {
                key: b"Azur3Bl0b!".to_vec(),
            },
            opsec_rating: 7,
        }
    }

    /// DNS-only profile — for environments with strict egress filtering.
    /// Uses DNS TXT queries for callbacks with configurable sleep.
    pub fn mimic_dns_tunnel() -> Self {
        Self {
            name: "DNS Tunnel".into(),
            description:
                "DNS-based C2 with TXT query callbacks — bypasses HTTP/HTTPS egress filters".into(),
            sleep_range: (Duration::from_secs(10), Duration::from_secs(60)),
            jitter_percent: 25,
            user_agent: String::new(),
            headers: HashMap::new(),
            get_uris: vec![],
            post_uris: vec![],
            staging_uri: None,
            dns_sleep: Some(Duration::from_secs(30)),
            dns_hostname_pattern: Some("<id>.<domain>.<tld>".to_string()),
            tls_config: None,
            data_mask: DataMasking::Base64,
            opsec_rating: 6,
        }
    }

    /// Minimal profile — no masking, standard headers, fast sleep.
    /// Lowest OPSEC — use for initial access or short-lived operations.
    pub fn minimal() -> Self {
        let mut headers = HashMap::new();
        headers.insert("Accept".into(), "*/*".into());
        headers.insert("Connection".into(), "close".into());

        Self {
            name: "Minimal".into(),
            description: "Minimal HTTP profile — fast, low overhead, low OPSEC".into(),
            sleep_range: (Duration::from_secs(5), Duration::from_secs(30)),
            jitter_percent: 10,
            user_agent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
                    .into(),
            headers,
            get_uris: vec!["/".into(), "/ping".into()],
            post_uris: vec!["/submit".into(), "/data".into()],
            staging_uri: None,
            dns_sleep: None,
            dns_hostname_pattern: None,
            tls_config: None,
            data_mask: DataMasking::None,
            opsec_rating: 3,
        }
    }

    /// Render this profile into a configuration map usable by C2 channels.
    pub fn render(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("profile_name".into(), self.name.clone());
        map.insert("user_agent".into(), self.user_agent.clone());
        map.insert("jitter_percent".into(), self.jitter_percent.to_string());
        map.insert(
            "sleep_min_ms".into(),
            self.sleep_range.0.as_millis().to_string(),
        );
        map.insert(
            "sleep_max_ms".into(),
            self.sleep_range.1.as_millis().to_string(),
        );
        map.insert("get_uris".into(), self.get_uris.join(","));
        map.insert("post_uris".into(), self.post_uris.join(","));
        if let Some(ref staging) = self.staging_uri {
            map.insert("staging_uri".into(), staging.clone());
        }
        if let Some(ref dns_sleep) = self.dns_sleep {
            map.insert("dns_sleep_ms".into(), dns_sleep.as_millis().to_string());
        }
        if let Some(ref dns_pattern) = self.dns_hostname_pattern {
            map.insert("dns_pattern".into(), dns_pattern.clone());
        }
        if let Some(ref tls) = self.tls_config {
            map.insert("tls_version".into(), tls.tls_version.clone());
            if let Some(ref sni) = tls.sni {
                map.insert("sni".into(), sni.clone());
            }
        }
        map
    }

    /// Get all available pre-built profiles.
    pub fn all_profiles() -> Vec<C2Profile> {
        vec![
            Self::mimic_aws_cloudfront(),
            Self::mimic_microsoft_365(),
            Self::mimic_google_api(),
            Self::mimic_azure_blob(),
            Self::mimic_dns_tunnel(),
            Self::minimal(),
        ]
    }

    /// Find a profile by name (case-insensitive).
    pub fn find(name: &str) -> Option<C2Profile> {
        Self::all_profiles()
            .into_iter()
            .find(|p| p.name.to_lowercase() == name.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_cloudfront_profile() {
        let profile = C2Profile::mimic_aws_cloudfront();
        assert_eq!(profile.name, "AWS CloudFront");
        assert!(profile.opsec_rating >= 8);
        assert!(profile.headers.contains_key("Accept-Language"));
    }

    #[test]
    fn test_m365_profile() {
        let profile = C2Profile::mimic_microsoft_365();
        assert_eq!(profile.name, "Microsoft 365");
        assert_eq!(profile.opsec_rating, 10);
    }

    #[test]
    fn test_google_api_profile() {
        let profile = C2Profile::mimic_google_api();
        assert!(
            profile
                .get_uris
                .contains(&"/gmail/v1/users/me/profile".into())
        );
    }

    #[test]
    fn test_dns_tunnel_profile() {
        let profile = C2Profile::mimic_dns_tunnel();
        assert!(profile.dns_sleep.is_some());
        assert!(profile.dns_hostname_pattern.is_some());
    }

    #[test]
    fn test_render_has_required_keys() {
        let profile = C2Profile::mimic_aws_cloudfront();
        let map = profile.render();
        assert!(map.contains_key("user_agent"));
        assert!(map.contains_key("jitter_percent"));
        assert!(map.contains_key("sleep_min_ms"));
        assert!(map.contains_key("get_uris"));
    }

    #[test]
    fn test_find_profile_by_name() {
        let found = C2Profile::find("aws cloudfront");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "AWS CloudFront");

        let not_found = C2Profile::find("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_minimal_profile_has_low_rating() {
        let profile = C2Profile::minimal();
        assert!(profile.opsec_rating < 5);
        assert!(matches!(profile.data_mask, DataMasking::None));
    }

    #[test]
    fn test_all_profiles_returns_all() {
        let profiles = C2Profile::all_profiles();
        assert_eq!(profiles.len(), 6);
    }
}
