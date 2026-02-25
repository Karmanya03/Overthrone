use thiserror::Error;

#[derive(Error, Debug)]
pub enum OverthroneError {
    // Protocol Errors
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

    #[error("RPC error on '{target}': {reason}")]
    Rpc { target: String, reason: String },

    // ADCS Errors
    #[error("ADCS error: {0}")]
    Adcs(String),

    #[error("Certificate request failed: {0}")]
    CertificateRequest(String),

    #[error("ESC{esc_number} attack failed: {reason}")]
    EscAttack { esc_number: u8, reason: String },

    // Auth Errors
    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("No credentials provided. Use --username/--password, --hash, or --ticket")]
    NoCredentials,

    #[error("Invalid NTLM hash format: expected 32 hex characters, got {0}")]
    InvalidHash(String),

    // Graph Errors
    #[error("Graph error: {0}")]
    Graph(String),

    #[error("No attack path found from '{from}' to '{to}'")]
    NoPath { from: String, to: String },

    #[error("Node not found in graph: {0}")]
    NodeNotFound(String),

    // Crypto Errors
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Ticket forging failed: {0}")]
    TicketForge(String),

    // Execution Errors
    #[error("Execution failed on '{target}': {reason}")]
    Exec { target: String, reason: String },

    /// Simple string-based exec error (used by auto_exec and exec modules)
    #[error("Execution error: {0}")]
    ExecSimple(String),

    #[error("Shell error: {0}")]
    Shell(String),

    // ─── NEW: Plugin Errors ───────────────────────────────────
    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Plugin '{plugin_id}' command '{command}' failed: {reason}")]
    PluginCommand {
        plugin_id: String,
        command: String,
        reason: String,
    },

    #[error("Plugin loader error: {0}")]
    PluginLoader(String),

    // ─── NEW: C2 Integration Errors ──────────────────────────
    #[error("C2 error: {0}")]
    C2(String),

    #[error("C2 connection to {framework} at {target} failed: {reason}")]
    C2Connection {
        framework: String,
        target: String,
        reason: String,
    },

    #[error("C2 session '{session_id}' error: {reason}")]
    C2Session { session_id: String, reason: String },

    // Scan Errors
    #[error("Scan error: {0}")]
    Scan(String),

    #[error("Configuration error: {0}")]
    Config(String),

    // Connection Errors
    #[error("Connection to '{target}' failed: {reason}")]
    Connection { target: String, reason: String },

    #[error("Protocol error in {protocol}: {reason}")]
    Protocol { protocol: String, reason: String },

    // Relay Errors
    #[error("Relay error: {0}")]
    Relay(String),

    // I/O & Serialization
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Timeout after {0} seconds")]
    Timeout(u64),

    // General
    #[error("Internal error: {0}")]
    Internal(String),

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
    pub fn ldap_with_target(
        target: impl std::fmt::Display,
        reason: impl std::fmt::Display,
    ) -> Self {
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

    /// Create a plugin error
    pub fn plugin(msg: impl std::fmt::Display) -> Self {
        Self::Plugin(msg.to_string())
    }

    /// Create a C2 error
    pub fn c2(msg: impl std::fmt::Display) -> Self {
        Self::C2(msg.to_string())
    }

    /// Create a C2 connection error with context
    pub fn c2_connection(
        framework: impl std::fmt::Display,
        target: impl std::fmt::Display,
        reason: impl std::fmt::Display,
    ) -> Self {
        Self::C2Connection {
            framework: framework.to_string(),
            target: target.to_string(),
            reason: reason.to_string(),
        }
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

    /// Check if this error is plugin-related
    pub fn is_plugin_error(&self) -> bool {
        matches!(
            self,
            Self::Plugin(_) | Self::PluginCommand { .. } | Self::PluginLoader(_)
        )
    }

    /// Check if this error is C2-related
    pub fn is_c2_error(&self) -> bool {
        matches!(
            self,
            Self::C2(_) | Self::C2Connection { .. } | Self::C2Session { .. }
        )
    }
}

/// Relay error type for overthrone-relay crate
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Socket error: {0}")]
    Socket(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Authentication failed: {0}")]
    Authentication(String),
}

impl From<RelayError> for OverthroneError {
    fn from(err: RelayError) -> Self {
        OverthroneError::Relay(err.to_string())
    }
}
