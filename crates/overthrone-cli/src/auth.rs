//! Credential management and authentication helpers for the CLI.
use clap::ValueEnum;
use std::io::{self, Write};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, ValueEnum)]
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

impl FromStr for AuthMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "password" => Ok(Self::Password),
            "hash" | "ntlm" | "ntlmhash" => Ok(Self::Hash),
            "ticket" | "kerberos" | "ccache" => Ok(Self::Ticket),
            _ => Err(format!(
                "Unknown auth method '{}' (expected: password|hash|ticket)",
                s
            )),
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

/// Resolve credentials from CLI args, supporting both single creds and credential lists.
/// Returns a Vec of Credentials to iterate over.
#[allow(clippy::too_many_arguments)]
pub fn resolve_credentials(
    domain: &str,
    username: Option<&str>,
    password: Option<&str>,
    nt_hash: Option<&str>,
    ticket_path: Option<&str>,
    auth_method: Option<AuthMethod>,
    user_list: Option<&str>,
    pass_list: Option<&str>,
    user_pass_list: Option<&str>,
) -> Result<Vec<Credentials>, String> {
    // Priority 1: user:pass list file
    if let Some(path) = user_pass_list {
        return load_user_pass_file(path, domain, auth_method.clone());
    }

    // Priority 2: separate user list + password list (cartesian product)
    if let (Some(ufile), Some(pfile)) = (user_list, pass_list) {
        let users = load_lines(ufile)?;
        let passwords = load_lines(pfile)?;
        let mut creds = Vec::new();
        for user in &users {
            for pass in &passwords {
                let c = Credentials::from_args(
                    domain,
                    user,
                    Some(pass),
                    None,
                    None,
                    auth_method.clone(),
                )?;
                creds.push(c);
            }
        }
        return Ok(creds);
    }

    // Priority 3: user list only (with single password or hash)
    if let Some(ufile) = user_list {
        let users = load_lines(ufile)?;
        let mut creds = Vec::new();
        for user in &users {
            let c = Credentials::from_args(
                domain,
                user,
                password,
                nt_hash,
                ticket_path,
                auth_method.clone(),
            )?;
            creds.push(c);
        }
        return Ok(creds);
    }

    // Priority 4: password list only (with single username)
    if let Some(pfile) = pass_list {
        let passwords = load_lines(pfile)?;
        let user = username.ok_or("--username required when using --pass-list")?;
        let mut creds = Vec::new();
        for pass in &passwords {
            let c =
                Credentials::from_args(domain, user, Some(pass), None, None, auth_method.clone())?;
            creds.push(c);
        }
        return Ok(creds);
    }

    // Priority 5: single credential
    let user = username.ok_or("No credentials provided. Use --username/--password, --user-list, --pass-list, or --user-pass-list")?;
    let c = Credentials::from_args(domain, user, password, nt_hash, ticket_path, auth_method)?;
    Ok(vec![c])
}

fn load_lines(path: &str) -> Result<Vec<String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
    let lines: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if lines.is_empty() {
        return Err(format!(
            "File '{}' is empty or contains no valid entries",
            path
        ));
    }
    Ok(lines)
}

fn load_user_pass_file(
    path: &str,
    default_domain: &str,
    auth_method: Option<AuthMethod>,
) -> Result<Vec<Credentials>, String> {
    let lines = load_lines(path)?;
    let mut creds = Vec::new();
    for line in &lines {
        if let Some((user, secret)) = line.split_once(':') {
            let user = user.trim();
            let secret = secret.trim();
            if user.is_empty() || secret.is_empty() {
                continue;
            }
            // Determine if secret is NT hash (32 hex chars) or password
            let is_hash = secret.len() == 32 && secret.chars().all(|c| c.is_ascii_hexdigit());
            let c = if is_hash && matches!(auth_method, Some(AuthMethod::Hash) | None) {
                Credentials::from_args(
                    default_domain,
                    user,
                    None,
                    Some(secret),
                    None,
                    Some(AuthMethod::Hash),
                )?
            } else {
                Credentials::from_args(
                    default_domain,
                    user,
                    Some(secret),
                    None,
                    None,
                    auth_method.clone(),
                )?
            };
            creds.push(c);
        }
    }
    if creds.is_empty() {
        return Err(format!("No valid user:pass pairs found in '{}'", path));
    }
    Ok(creds)
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

    pub fn _ticket_path(&self) -> Option<&str> {
        match &self.auth {
            AuthData::KerberosTicket(p) => Some(p),
            _ => None,
        }
    }

    pub fn _display_summary(&self) -> String {
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

impl Default for Credentials {
    fn default() -> Self {
        Self {
            domain: String::new(),
            username: String::new(),
            auth: AuthData::Password(String::new()),
        }
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
