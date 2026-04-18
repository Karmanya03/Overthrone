//! Credential management and authentication helpers for the CLI.
use clap::ValueEnum;
use std::io::{self, Write};

#[derive(Debug, Clone, ValueEnum)]
pub enum AuthMethod {
    Password,
    Hash,
    Ticket,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::Hash => write!(f, "hash"),
            Self::Ticket => write!(f, "ticket"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub domain: String,
    pub username: String,
    pub auth: AuthData,
}

#[derive(Debug, Clone)]
pub enum AuthData {
    Password(String),
    NtlmHash(String),
    KerberosTicket(#[allow(dead_code)] String),
}

impl Credentials {
    pub fn from_args(
        domain: &str,
        username: &str,
        password: Option<&str>,
        nthash: Option<&str>,
        ticket_path: Option<&str>,
        auth_method: Option<AuthMethod>,
    ) -> Result<Self, String> {
        let auth = match auth_method {
            Some(AuthMethod::Hash) => {
                let env_hash = std::env::var("OT_NTHASH").ok();
                let hash = nthash
                    .or(env_hash.as_deref())
                    .ok_or("--nt-hash required for hash auth")?;
                validate_nthash(hash)?;
                AuthData::NtlmHash(hash.to_string())
            }
            Some(AuthMethod::Ticket) => {
                let path = ticket_path.ok_or("--ticket required for ticket auth")?;
                if !std::path::Path::new(path).exists() {
                    return Err(format!("Ticket file not found: {}", path));
                }
                AuthData::KerberosTicket(path.to_string())
            }
            Some(AuthMethod::Password) | None => {
                let pass = match password {
                    Some(p) => p.to_string(),
                    None => match std::env::var("OT_PASSWORD") {
                        Ok(p) => p,
                        Err(_) => prompt_password()?,
                    },
                };
                AuthData::Password(pass)
            }
        };
        let normalized_username =
            overthrone_core::proto::kerberos::normalize_username(username).to_string();

        Ok(Credentials {
            domain: domain.to_string(),
            username: normalized_username,
            auth,
        })
    }

    /// Get the secret string and whether it's a hash
    pub fn secret_and_hash_flag(&self) -> Result<(String, bool), String> {
        match &self.auth {
            AuthData::Password(p) => Ok((p.clone(), false)),
            AuthData::NtlmHash(h) => Ok((h.clone(), true)),
            AuthData::KerberosTicket(_) => {
                Err("Ticket auth not supported for this operation".into())
            }
        }
    }

    /// Build an ExecContext for overthrone-pilot
    #[allow(dead_code)] // Used by interactive shell
    pub fn to_exec_context(
        &self,
        dc_host: &str,
        use_ldaps: bool,
        dry_run: bool,
    ) -> Result<overthrone_pilot::executor::ExecContext, String> {
        let (secret, use_hash) = self.secret_and_hash_flag()?;
        Ok(overthrone_pilot::executor::ExecContext {
            dc_ip: dc_host.to_string(),
            domain: self.domain.clone(),
            username: self.username.clone(),
            secret,
            use_hash,
            use_ldaps,
            timeout: 10,
            jitter_ms: 0,
            dry_run,
            override_creds: None,
            ldap_available: true,
            preferred_method: "smbexec".to_string(),
        })
    }

    pub fn password(&self) -> Option<&str> {
        match &self.auth {
            AuthData::Password(p) => Some(p),
            _ => None,
        }
    }

    pub fn nthash(&self) -> Option<&str> {
        match &self.auth {
            AuthData::NtlmHash(h) => Some(h),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn ticket_path(&self) -> Option<&str> {
        match &self.auth {
            AuthData::KerberosTicket(p) => Some(p),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn display_summary(&self) -> String {
        let method = match &self.auth {
            AuthData::Password(_) => "password",
            AuthData::NtlmHash(_) => "NT hash",
            AuthData::KerberosTicket(p) => {
                return format!("{}\\{} (ticket: {})", self.domain, self.username, p);
            }
        };
        format!("{}\\{} ({})", self.domain, self.username, method)
    }
}

fn prompt_password() -> Result<String, String> {
    eprint!("  Password: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    rpassword::read_password().map_err(|e| format!("Failed to read password: {}", e))
}

fn validate_nthash(hash: &str) -> Result<(), String> {
    if hash.len() != 32 {
        return Err(format!("NT hash must be 32 hex chars, got {}", hash.len()));
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("NT hash must contain only hex characters".into());
    }
    Ok(())
}

#[allow(dead_code)] // Used in interactive shell for DOMAIN\user parsing
pub fn parse_user_string(input: &str) -> (String, String) {
    if let Some((domain, user)) = input.split_once('\\') {
        (domain.to_string(), user.to_string())
    } else if let Some((user, domain)) = input.split_once('@') {
        (domain.to_string(), user.to_string())
    } else {
        ("..".to_string(), input.to_string())
    }
}
