//! Error types for Overthrone operations.

use thiserror::Error;

/// All Overthrone error variants.
#[derive(Error, Debug)]
pub enum OverthroneError {
    // Protocol Errors
    /// LDAP protocol error with target and reason context.
    #[error("LDAP error on '{target}': {reason}")]
    #[allow(missing_docs)]
    Ldap { target: String, reason: String },
    /// LDAP bind failure for a specific user.
    #[error("LDAP bind failed for user '{user}': {reason}")]
    #[allow(missing_docs)]
    LdapBind { user: String, reason: String },
    /// Generic Kerberos error.
    #[error("Kerberos error: {0}")]
    Kerberos(String),
    /// Kerberos pre-authentication failure for a principal.
    #[error("Kerberos pre-auth failed for principal '{principal}'")]
    #[allow(missing_docs)]
    KerberosPreAuth { principal: String },
    /// Generic SMB error.
    #[error("SMB error: {0}")]
    Smb(String),
    /// Generic NTLM error.
    #[error("NTLM error: {0}")]
    Ntlm(String),
    /// DNS resolution failure.
    #[error("DNS resolution failed for '{target}': {reason}")]
    #[allow(missing_docs)]
    Dns { target: String, reason: String },
    /// RPC communication error.
    #[error("RPC error on '{target}': {reason}")]
    #[allow(missing_docs)]
    Rpc { target: String, reason: String },

    // ADCS Errors
    /// ADCS certificate service error.
    #[error("ADCS error: {0}")]
    Adcs(String),
    /// Certificate request failure.
    #[error("Certificate request failed: {0}")]
    CertificateRequest(String),
    /// ESC (Escalation) attack failure with specific ESC number.
    #[error("ESC{esc_number} attack failed: {reason}")]
    #[allow(missing_docs)]
    EscAttack { esc_number: u8, reason: String },

    // Auth Errors
    /// Authentication failure.
    #[error("Authentication failed: {0}")]
    Auth(String),
    /// No credentials provided.
    #[error("No credentials provided. Use --username/--password, --hash, or --ticket")]
    NoCredentials,
    /// Invalid NTLM hash format.
    #[error("Invalid NTLM hash format: expected 32 hex characters, got {0}")]
    InvalidHash(String),

    // Graph Errors
    /// Graph computation error.
    #[error("Graph error: {0}")]
    Graph(String),
    /// No attack path found between two nodes.
    #[error("No attack path found from '{from}' to '{to}'")]
    #[allow(missing_docs)]
    NoPath { from: String, to: String },
    /// Node not found in graph.
    #[error("Node not found in graph: {0}")]
    NodeNotFound(String),

    // Crypto Errors
    /// Generic crypto operation failed.
    #[error("Crypto error: {0}")]
    Crypto(String),
    /// Encryption operation failed.
    #[error("Encryption error: {0}")]
    Encryption(String),
    /// Decryption operation failed.
    #[error("Decryption error: {0}")]
    Decryption(String),
    /// Kerberos ticket forging failed.
    #[error("Ticket forging failed: {0}")]
    TicketForge(String),

    // Execution Errors
    /// Remote command execution failure on a target.
    #[error("Execution failed on '{target}': {reason}")]
    #[allow(missing_docs)]
    Exec { target: String, reason: String },
    /// Simple string-based exec error.
    #[error("Execution error: {0}")]
    ExecSimple(String),
    /// Shell command error.
    #[error("Shell error: {0}")]
    Shell(String),

    // --- NEW: Plugin Errors -----------------------------------
    /// Plugin system error.
    #[error("Plugin error: {0}")]
    Plugin(String),
    /// Plugin command execution failure with context.
    #[error("Plugin '{plugin_id}' command '{command}' failed: {reason}")]
    #[allow(missing_docs)]
    PluginCommand {
        plugin_id: String,
        command: String,
        reason: String,
    },
    /// Plugin loader error.
    #[error("Plugin loader error: {0}")]
    PluginLoader(String),

    // --- NEW: C2 Integration Errors --------------------------
    /// C2 framework integration error.
    #[error("C2 error: {0}")]
    C2(String),
    /// C2 connection failure with framework and target context.
    #[error("C2 connection to {framework} at {target} failed: {reason}")]
    #[allow(missing_docs)]
    C2Connection {
        framework: String,
        target: String,
        reason: String,
    },
    /// C2 session error.
    #[error("C2 session '{session_id}' error: {reason}")]
    #[allow(missing_docs)]
    C2Session { session_id: String, reason: String },

    // Scan Errors
    /// Network scan error.
    #[error("Scan error: {0}")]
    Scan(String),
    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    // Connection Errors
    /// Network connection failure.
    #[error("Connection to '{target}' failed: {reason}")]
    #[allow(missing_docs)]
    Connection { target: String, reason: String },
    /// Protocol-level error.
    #[error("Protocol error in {protocol}: {reason}")]
    #[allow(missing_docs)]
    Protocol { protocol: String, reason: String },

    // Relay Errors
    /// Relay attack error.
    #[error("Relay error: {0}")]
    Relay(String),

    // Post-Exploitation Errors
    /// Post-exploitation operation failed.
    #[error("Post-exploitation error: {0}")]
    PostExploitation(String),
    /// LSASS manipulation failed.
    #[error("LSASS error: {0}")]
    Lsass(String),
    /// Memory injection failed.
    #[error("Injection error: {0}")]
    Injection(String),

    // I/O & Serialization
    /// Network I/O error.
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Operation timeout.
    #[error("Timeout after {0} seconds")]
    Timeout(u64),

    // General
    /// Internal invariant violation.
    #[error("Internal error: {0}")]
    Internal(String),
    /// Feature or module not yet implemented.
    #[error("Module '{module}' not yet implemented")]
    #[allow(missing_docs)]
    NotImplemented { module: String },
    /// Custom/user-provided error message.
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

    /// Create an internal invariant error.
    pub fn invariant(msg: impl std::fmt::Display) -> Self {
        Self::Internal(msg.to_string())
    }

    /// Check a condition and return `Ok(())` if true,
    /// otherwise return an `Internal` invariant error with the given message.
    pub fn check_invariant(
        condition: bool,
        msg: impl std::fmt::Display,
    ) -> std::result::Result<(), Self> {
        if condition {
            Ok(())
        } else {
            Err(Self::invariant(msg))
        }
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
    /// `Network` variant
    #[error("Network error: {0}")]
    Network(String),
    /// `Socket` variant
    #[error("Socket error: {0}")]
    Socket(String),
    /// `Protocol` variant
    #[error("Protocol error: {0}")]
    Protocol(String),
    /// `Auth` variant
    #[error("Authentication error: {0}")]
    Auth(String),
    /// `Config` variant
    #[error("Configuration error: {0}")]
    Config(String),
    /// `Connection` variant
    #[error("Connection error: {0}")]
    Connection(String),
    /// `Authentication` variant
    #[error("Authentication failed: {0}")]
    Authentication(String),
}

impl From<RelayError> for OverthroneError {
    fn from(err: RelayError) -> Self {
        OverthroneError::Relay(err.to_string())
    }
}

#[cfg(target_os = "windows")]
impl From<windows::core::Error> for OverthroneError {
    fn from(err: windows::core::Error) -> Self {
        OverthroneError::PostExploitation(format!("Windows API error: {err}"))
    }
}
