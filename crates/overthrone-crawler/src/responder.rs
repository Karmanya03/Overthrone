//! Integration module for driving the relay crate's responder/poisoner
//! from the crawler pipeline.
//!
//! When the `responder` feature is enabled, the crawler can optionally
//! start the LLMNR/NBT-NS/mDNS poisoner and/or the HTTP/SMB/LDAP/MSMQ
//! responder as background tasks during the crawl. Captured credentials
//! and queries are included in the crawler result.

use overthrone_relay::poisoner::{Poisoner, PoisonerConfig};
use overthrone_relay::responder::{Responder, ResponderConfig};

pub use overthrone_relay::poisoner::CapturedQuery;
pub use overthrone_relay::responder::CapturedCredential;

/// Combined configuration for background responder/poisoner services.
#[derive(Debug, Clone, Default)]
pub struct CrawlerResponderConfig {
    /// Optional poisoner configuration (LLMNR/NBT-NS/mDNS).
    pub poisoner: Option<PoisonerConfig>,
    /// Optional responder configuration (HTTP/SMB/LDAP/MSMQ capture).
    pub responder: Option<ResponderConfig>,
}

impl CrawlerResponderConfig {
    /// Build a config from simple CLI-style parameters.
    ///
    /// * `poison_ip` — if `Some`, enables LLMNR + NBT-NS poisoning with that response IP.
    /// * `respond` — if `true`, enables the HTTP/SMB/LDAP responder on default ports.
    pub fn from_cli(poison_ip: Option<String>, respond: bool) -> Self {
        Self {
            poisoner: poison_ip.map(|ip| PoisonerConfig {
                listen_ip: "::".into(),
                poison_ip: ip,
                llmnr: true,
                nbtns: true,
                mdns: false,
                ..PoisonerConfig::default()
            }),
            responder: if respond {
                Some(ResponderConfig::default())
            } else {
                None
            },
        }
    }
}

/// Combines an optional responder and poisoner that run during the crawl.
pub struct CrawlerResponder {
    poisoner: Option<Poisoner>,
    responder: Option<Responder>,
}

impl CrawlerResponder {
    /// Create a new `CrawlerResponder` from optional configs.
    pub fn new(config: &CrawlerResponderConfig) -> Result<Self, String> {
        let poisoner = match &config.poisoner {
            Some(cfg) => Some(
                Poisoner::new(cfg.clone())
                    .map_err(|e| format!("failed to create poisoner: {e}"))?,
            ),
            None => None,
        };
        let responder = config.responder.clone().map(Responder::new);
        Ok(Self {
            poisoner,
            responder,
        })
    }

    /// Start all configured services.
    pub async fn start(&mut self) -> Result<(), String> {
        if let Some(ref mut p) = self.poisoner {
            p.start()
                .await
                .map_err(|e| format!("poisoner start failed: {e}"))?;
        }
        if let Some(ref mut r) = self.responder {
            r.start()
                .await
                .map_err(|e| format!("responder start failed: {e}"))?;
        }
        Ok(())
    }

    /// Stop all services and return captured credentials.
    pub async fn stop(&mut self) -> Result<Vec<CapturedCredential>, String> {
        if let Some(ref mut r) = self.responder {
            r.stop()
                .await
                .map_err(|e| format!("responder stop failed: {e}"))?;
        }
        if let Some(ref mut p) = self.poisoner {
            p.stop()
                .await
                .map_err(|e| format!("poisoner stop failed: {e}"))?;
        }
        Ok(self.captured_credentials())
    }

    /// Get captured credentials without stopping.
    pub fn captured_credentials(&self) -> Vec<CapturedCredential> {
        self.responder
            .as_ref()
            .map(|r| r.get_captured_credentials())
            .unwrap_or_default()
    }

    /// Get captured queries without stopping.
    pub fn captured_queries(&self) -> Vec<CapturedQuery> {
        self.poisoner
            .as_ref()
            .map(|p| p.get_captured_queries())
            .unwrap_or_default()
    }

    /// Check if any service is running.
    pub fn is_running(&self) -> bool {
        self.poisoner
            .as_ref()
            .map(|p| p.is_running())
            .unwrap_or(false)
            || self
                .responder
                .as_ref()
                .map(|r| r.is_running())
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responder_config_default() {
        let cfg = CrawlerResponderConfig::default();
        assert!(cfg.poisoner.is_none());
        assert!(cfg.responder.is_none());
    }

    #[test]
    fn test_responder_config_custom() {
        let cfg = CrawlerResponderConfig {
            poisoner: Some(PoisonerConfig {
                listen_ip: "0.0.0.0".into(),
                poison_ip: "10.0.0.1".into(),
                llmnr: true,
                nbtns: false,
                mdns: false,
                ..PoisonerConfig::default()
            }),
            responder: Some(ResponderConfig {
                listen_ip: "0.0.0.0".into(),
                http: true,
                smb: false,
                ldap: false,
                msmq: false,
                ..ResponderConfig::default()
            }),
        };
        assert!(cfg.poisoner.is_some());
        assert!(cfg.responder.is_some());
        let poisoner_cfg = cfg.poisoner.unwrap();
        assert_eq!(poisoner_cfg.listen_ip, "0.0.0.0");
        assert!(poisoner_cfg.llmnr);
        assert!(!poisoner_cfg.nbtns);
    }

    #[test]
    fn test_responder_new_noop() {
        let cfg = CrawlerResponderConfig::default();
        let responder = CrawlerResponder::new(&cfg).expect("new should succeed with no config");
        assert!(responder.poisoner.is_none());
        assert!(responder.responder.is_none());
        assert!(!responder.is_running());
        assert!(responder.captured_credentials().is_empty());
        assert!(responder.captured_queries().is_empty());
    }

    #[test]
    fn test_captured_credential_hashcat_format() {
        let cred = CapturedCredential {
            client_ip: "10.0.0.1".into(),
            username: "admin".into(),
            domain: "CORP".into(),
            challenge: "1122334455667788".into(),
            lm_response: "".into(),
            nt_response: "aabbccdd".into(),
            protocol: "HTTP".into(),
            timestamp: chrono::Utc::now(),
        };
        let hashcat = cred.to_hashcat_format();
        assert_eq!(hashcat, "admin::CORP:1122334455667788::aabbccdd");
        assert_eq!(
            cred.to_john_format(),
            "admin::CORP:1122334455667788::aabbccdd"
        );
    }

    #[test]
    fn test_responder_config_from_cli_both() {
        let cfg = CrawlerResponderConfig::from_cli(Some("10.0.0.5".to_string()), true);
        assert!(cfg.poisoner.is_some());
        assert!(cfg.responder.is_some());
        let p = cfg.poisoner.unwrap();
        assert_eq!(p.poison_ip, "10.0.0.5");
        assert!(p.llmnr);
        assert!(p.nbtns);
        let r = cfg.responder.unwrap();
        assert!(r.http);
        assert!(r.smb);
    }

    #[test]
    fn test_responder_config_from_cli_poison_only() {
        let cfg = CrawlerResponderConfig::from_cli(Some("fe80::1".to_string()), false);
        assert!(cfg.poisoner.is_some());
        assert!(cfg.responder.is_none());
    }

    #[test]
    fn test_responder_config_from_cli_respond_only() {
        let cfg = CrawlerResponderConfig::from_cli(None, true);
        assert!(cfg.poisoner.is_none());
        assert!(cfg.responder.is_some());
    }

    #[test]
    fn test_responder_config_from_cli_none() {
        let cfg = CrawlerResponderConfig::from_cli(None, false);
        assert!(cfg.poisoner.is_none());
        assert!(cfg.responder.is_none());
    }

    #[test]
    fn test_captured_credential_defaults() {
        let cred = CapturedCredential {
            client_ip: "::1".into(),
            username: "user".into(),
            domain: "TEST".into(),
            challenge: "deadbeef".into(),
            lm_response: "".into(),
            nt_response: "cafe".into(),
            protocol: "SMB".into(),
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(cred.protocol, "SMB");
        assert_eq!(cred.domain, "TEST");
    }
}
