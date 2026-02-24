//! MSSQL Authentication Module
//!
//! Handles both SQL Server authentication and Windows/NTLM authentication
//! for MSSQL connections.

use crate::error::Result;
use crate::proto::ntlm;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Authentication type for MSSQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MssqlAuth {
    /// SQL Server authentication (username/password)
    Sql {
        username: String,
        password: String,
    },
    /// Windows/NTLM authentication
    Ntlm {
        domain: String,
        username: String,
        password: String,
    },
    /// Windows/NTLM with hash (pass-the-hash)
    NtlmHash {
        domain: String,
        username: String,
        nt_hash: Vec<u8>,
    },
    /// Access token (Azure AD, etc.)
    Token {
        token: String,
    },
    /// Trusted/Integrated (use current Windows credentials)
    Trusted,
}

impl MssqlAuth {
    /// Create SQL Server authentication
    pub fn sql(username: &str, password: &str) -> Self {
        Self::Sql {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Create Windows/NTLM authentication
    pub fn ntlm(domain: &str, username: &str, password: &str) -> Self {
        Self::Ntlm {
            domain: domain.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Create NTLM pass-the-hash
    pub fn ntlm_hash(domain: &str, username: &str, nt_hash: &[u8]) -> Self {
        Self::NtlmHash {
            domain: domain.to_string(),
            username: username.to_string(),
            nt_hash: nt_hash.to_vec(),
        }
    }

    /// Create token-based authentication
    pub fn token(token: &str) -> Self {
        Self::Token {
            token: token.to_string(),
        }
    }

    /// Create trusted/integrated authentication
    pub fn trusted() -> Self {
        Self::Trusted
    }

    /// Check if this is SQL authentication
    pub fn is_sql(&self) -> bool {
        matches!(self, Self::Sql { .. })
    }

    /// Check if this is NTLM authentication
    pub fn is_ntlm(&self) -> bool {
        matches!(self, Self::Ntlm { .. } | Self::NtlmHash { .. })
    }

    /// Get the username
    pub fn username(&self) -> Option<&str> {
        match self {
            Self::Sql { username, .. } => Some(username),
            Self::Ntlm { username, .. } => Some(username),
            Self::NtlmHash { username, .. } => Some(username),
            _ => None,
        }
    }

    /// Get the domain
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Ntlm { domain, .. } => Some(domain),
            Self::NtlmHash { domain, .. } => Some(domain),
            _ => None,
        }
    }
}

/// NTLM authentication handler for MSSQL
pub struct NtlmAuthHandler {
    domain: String,
    username: String,
    password: Option<String>,
    nt_hash: Option<Vec<u8>>,
    /// NTLM session nonce (from server challenge)
    server_challenge: Option<[u8; 8]>,
    /// NTLM negotiate message
    negotiate_message: Option<Vec<u8>>,
}

impl NtlmAuthHandler {
    /// Create new NTLM auth handler with password
    pub fn new(domain: &str, username: &str, password: &str) -> Self {
        Self {
            domain: domain.to_string(),
            username: username.to_string(),
            password: Some(password.to_string()),
            nt_hash: None,
            server_challenge: None,
            negotiate_message: None,
        }
    }

    /// Create new NTLM auth handler with NT hash (pass-the-hash)
    pub fn with_hash(domain: &str, username: &str, nt_hash: &[u8]) -> Self {
        Self {
            domain: domain.to_string(),
            username: username.to_string(),
            password: None,
            nt_hash: Some(nt_hash.to_vec()),
            server_challenge: None,
            negotiate_message: None,
        }
    }

    /// Build NTLM Type 1 (Negotiate) message
    pub fn build_negotiate(&mut self) -> Result<Vec<u8>> {
        debug!("Building NTLM Type 1 Negotiate message");

        let msg = ntlm::build_negotiate_message(&self.domain);
        self.negotiate_message = Some(msg.clone());
        Ok(msg)
    }

    /// Process NTLM Type 2 (Challenge) from server and build Type 3 (Authenticate)
    pub fn build_authenticate(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        debug!("Processing NTLM Type 2 Challenge and building Type 3 Authenticate");

        // Parse the challenge message
        let parsed = ntlm::parse_challenge_message(challenge)?;
        self.server_challenge = Some(parsed.challenge);

        // Get the NT hash (compute from password or use provided)
        let nt_hash = if let Some(ref hash) = self.nt_hash {
            hash.clone()
        } else if let Some(ref password) = self.password {
            ntlm::ntowfv1(password)
        } else {
            return Err(crate::error::OverthroneError::Auth("No password or NT hash provided".to_string()));
        };

        // Build the authenticate message
        let auth = ntlm::build_authenticate_message(
            &self.domain,
            &self.username,
            &nt_hash,
            &parsed.challenge,
            parsed.target_info.as_deref(),
            self.password.as_deref(),
        );

        Ok(auth)
    }
}

/// MSSQL password obfuscation (XOR with A5)
/// Used for TDS login packet - NOT for security, just for legacy compatibility
pub fn obfuscate_password(password: &str) -> Vec<u8> {
    // SQL Server password obfuscation for login packet
    // Password is UTF-16LE, XORed with 0x5A for each byte
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    
    utf16.into_iter().map(|b| b ^ 0x5A).collect()
}

/// De-obfuscate password (reverse of obfuscate)
pub fn deobfuscate_password(data: &[u8]) -> String {
    let decoded: Vec<u8> = data.iter().map(|b| b ^ 0x5A).collect();
    
    decoded
        .chunks(2)
        .filter_map(|c| {
            if c.len() == 2 {
                Some(char::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32)?)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mssql_auth_sql() {
        let auth = MssqlAuth::sql("sa", "password123");
        assert!(auth.is_sql());
        assert!(!auth.is_ntlm());
        assert_eq!(auth.username(), Some("sa"));
    }

    #[test]
    fn test_mssql_auth_ntlm() {
        let auth = MssqlAuth::ntlm("DOMAIN", "admin", "password");
        assert!(!auth.is_sql());
        assert!(auth.is_ntlm());
        assert_eq!(auth.username(), Some("admin"));
        assert_eq!(auth.domain(), Some("DOMAIN"));
    }

    #[test]
    fn test_password_obfuscation() {
        let password = "TestPassword123!";
        let obfuscated = obfuscate_password(password);
        let deobfuscated = deobfuscate_password(&obfuscated);
        assert_eq!(password, deobfuscated);
    }

    #[test]
    fn test_ntlm_auth_handler() {
        let mut handler = NtlmAuthHandler::new("DOMAIN", "user", "password");
        let negotiate = handler.build_negotiate().unwrap();
        
        // Check NTLM signature
        assert_eq!(&negotiate[0..8], b"NTLMSSP\x00");
        // Type 1 message
        assert_eq!(u32::from_le_bytes([negotiate[8], negotiate[9], negotiate[10], negotiate[11]]), 1);
    }
}