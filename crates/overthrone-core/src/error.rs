use thiserror::Error;

#[derive(Error, Debug)]
pub enum OverthroneError {
    // ── Protocol Errors ──

    #[error("LDAP error on '{target}': {reason}")]
    Ldap { target: String, reason: String },

    #[error("LDAP bind failed for user '{user}': {reason}")]
    LdapBind { user: String, reason: String },

    #[error("Kerberos error: {0}")]
    Kerberos(String),

    #[error("Kerberos pre-auth failed for principal '{principal}'")]
    KerberosPreAuth { principal: String },

    #[error("SMB error: {0}")]
    Smb(String),

    #[error("NTLM error: {0}")]
    Ntlm(String),

    #[error("DNS resolution failed for '{target}': {reason}")]
    Dns { target: String, reason: String },

    // ── Auth Errors ──

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("No credentials provided. Use --username/--password, --hash, or --ticket")]
    NoCredentials,

    #[error("Invalid NTLM hash format: expected 32 hex characters, got {0}")]
    InvalidHash(String),

   // ── Graph Errors ──

    #[error("Graph error: {0}")]
    Graph(String),

    #[error("No attack path found from '{from}' to '{to}'")]
    NoPath { from: String, to: String },

    #[error("Node not found in graph: {0}")]
    NodeNotFound(String),
    
    // ── Crypto Errors ──

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Ticket forging failed: {0}")]
    TicketForge(String),

    // ── I/O & Serialization ──

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Timeout after {0} seconds")]
    Timeout(u64),

    // ── General ──

    #[error("Module '{module}' not yet implemented")]
    NotImplemented { module: String },

    #[error("{0}")]
    Custom(String),
}

/// Convenience Result type for Overthrone operations
pub type Result<T> = std::result::Result<T, OverthroneError>;

impl OverthroneError {
    /// Create an LDAP error from any Display-able type (convenience wrapper)
    pub fn ldap(msg: impl std::fmt::Display) -> Self {
        Self::Ldap {
            target: "unknown".to_string(),
            reason: msg.to_string(),
        }
    }

    /// Create a structured LDAP error with target context
    pub fn ldap_with_target(target: impl std::fmt::Display, reason: impl std::fmt::Display) -> Self {
        Self::Ldap {
            target: target.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Create a Kerberos error from any Display-able type
    pub fn kerberos(msg: impl std::fmt::Display) -> Self {
        Self::Kerberos(msg.to_string())
    }

    /// Create a custom error
    pub fn custom(msg: impl std::fmt::Display) -> Self {
        Self::Custom(msg.to_string())
    }

    /// Check if this error is an authentication failure
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Self::Auth(_)
                | Self::NoCredentials
                | Self::LdapBind { .. }
                | Self::KerberosPreAuth { .. }
        )
    }

    /// Check if this error is a network/connectivity issue
    pub fn is_network_error(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Timeout(_) | Self::Dns { .. })
    }
}
