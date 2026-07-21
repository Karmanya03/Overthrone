//! SMB OPLOCK (Opportunistic Lock) hijacking.
//!
//! An OPLOCK allows a client to lock a file on an SMB share.  When a second
//! client tries to access the same file the server sends an `OPLOCK_BREAK`
//! notification to the lock holder.  In an offensive context this is used
//! to **detect** when a coerced authentication (PrinterBug, PetitPotam, ...)
//! reaches a file on an attacker-controlled share.
//!
//! ## Usage
//!
//! 1. Set up an SMB share that the coerced target will access.
//! 2. Open a file on that share with `OplockLevel::Batch`.
//! 3. Trigger coercion (PrinterBug / PetitPotam).
//! 4. Call [`OplockSession::wait_for_break`] -- if it returns, the target
//!    has accessed the file and authentication has been captured/relayed.

use overthrone_core::proto::smb2::Smb2Connection;
use tracing::{debug, info};

/// OPLOCK levels that can be requested when opening a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OplockLevel {
    /// Level II oplock -- shared read cache.
    Ii,
    /// Exclusive oplock -- exclusive write cache.
    Exclusive,
    /// Batch oplock -- full caching, used for coercion detection.
    Batch,
}

impl OplockLevel {
    fn as_u8(self) -> u8 {
        match self {
            OplockLevel::Ii => 0x01,
            OplockLevel::Exclusive => 0x08,
            OplockLevel::Batch => 0x09,
        }
    }
}

/// Configuration for an OPLOCK session.
#[derive(Debug, Clone)]
pub struct OplockConfig {
    /// Target server (IP or hostname).
    pub server: String,
    /// Target port (usually 445).
    pub port: u16,
    /// SMB share (e.g. `"ADMIN$"`, `"C$"`, or a custom share).
    pub share: String,
    /// File path **on the share** (e.g. `"oplock_test.txt"`).
    pub file: String,
    /// Domain for authentication.
    pub domain: String,
    /// Username.
    pub username: String,
    /// Password (use either password or nt_hash).
    pub password: Option<String>,
    /// NTLM hash.
    pub nt_hash: Option<String>,
    /// OPLOCK level to request.
    pub oplock_level: OplockLevel,
    /// Timeout in seconds to wait for the break.
    pub timeout_secs: u64,
}

impl Default for OplockConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 445,
            share: "ADMIN$".into(),
            file: String::new(),
            domain: String::new(),
            username: String::new(),
            password: None,
            nt_hash: None,
            oplock_level: OplockLevel::Batch,
            timeout_secs: 30,
        }
    }
}

/// An active OPLOCK session holding a file open on a remote SMB share.
///
/// The session connects to the target, authenticates, mounts the share,
/// opens a file with the requested oplock, and waits for a break.
pub struct OplockSession {
    conn: Smb2Connection,
    file_id: [u8; 32],
    timeout_secs: u64,
}

impl OplockSession {
    /// Establish the OPLOCK session.
    ///
    /// 1. TCP connect to `config.server:config.port`.
    /// 2. SMB2 negotiate + session setup.
    /// 3. TreeConnect to `config.share`.
    /// 4. Create/open `config.file` with the requested oplock.
    ///
    /// Returns `None` if the server completely refused the oplock.
    pub async fn new(config: &OplockConfig) -> Result<Option<Self>, String> {
        let conn = Smb2Connection::connect(&config.server, config.port)
            .await
            .map_err(|e| {
                format!(
                    "SMB2 connect to {}:{} failed: {e}",
                    config.server, config.port
                )
            })?;

        conn.negotiate()
            .await
            .map_err(|e| format!("SMB2 negotiate failed: {e}"))?;

        if let Some(hash) = &config.nt_hash {
            conn.session_setup_hash(&config.domain, &config.username, hash)
                .await
                .map_err(|e| format!("SMB2 session setup (hash) failed: {e}"))?;
        } else {
            let pass = config.password.as_deref().unwrap_or("");
            conn.session_setup(&config.domain, &config.username, pass)
                .await
                .map_err(|e| format!("SMB2 session setup failed: {e}"))?;
        }

        let share_path = format!("\\\\{}\\{}", config.server, config.share);
        conn.tree_connect(&share_path)
            .await
            .map_err(|e| format!("SMB2 tree connect to '{share_path}' failed: {e}"))?;

        let (file_id, granted) = conn
            .create_with_oplock(
                &config.file,
                0x8000_0000 | 0x4000_0000, // GENERIC_READ | GENERIC_WRITE
                0x80,                      // FILE_ATTRIBUTE_NORMAL
                0x02,                      // FILE_SHARE_WRITE
                0x01,                      // FILE_OPEN
                0x20,                      // FILE_NON_DIRECTORY_FILE
                config.oplock_level.as_u8(),
            )
            .await
            .map_err(|e| format!("SMB2 create with oplock failed: {e}"))?;

        info!(
            "OPLOCK: opened '{}' on \\\\{}\\{} -- requested 0x{:02X}, granted 0x{:02X}",
            config.file,
            config.server,
            config.share,
            config.oplock_level.as_u8(),
            granted
        );

        if granted == 0 && config.oplock_level.as_u8() != 0 {
            let _ = conn.close(&file_id).await;
            debug!("OPLOCK: server refused oplock (granted 0x00)");
            return Ok(None);
        }

        Ok(Some(Self {
            conn,
            file_id,
            timeout_secs: config.timeout_secs,
        }))
    }

    /// Wait for an OPLOCK break notification.
    ///
    /// Blocks until the server sends an `OPLOCK_BREAK` or the
    /// configured timeout expires.  On success returns the new
    /// (downgraded) oplock level.
    pub async fn wait_for_break(&self) -> Result<u8, String> {
        let (new_level, _file_id) = self
            .conn
            .wait_for_oplock_break(self.timeout_secs)
            .await
            .map_err(|e| format!("OPLOCK break wait failed: {e}"))?;

        info!("OPLOCK: break received -- level downgraded to 0x{new_level:02X}");

        self.conn
            .acknowledge_oplock_break(&self.file_id, new_level)
            .await
            .map_err(|e| format!("OPLOCK ack failed: {e}"))?;

        debug!("OPLOCK: break acknowledged");
        Ok(new_level)
    }

    /// Close the file and release the oplock.
    pub async fn close(self) -> Result<(), String> {
        self.conn
            .close(&self.file_id)
            .await
            .map_err(|e| format!("OPLOCK close failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oplock_level_as_u8() {
        assert_eq!(OplockLevel::Ii.as_u8(), 0x01);
        assert_eq!(OplockLevel::Exclusive.as_u8(), 0x08);
        assert_eq!(OplockLevel::Batch.as_u8(), 0x09);
    }

    #[test]
    fn test_oplock_config_defaults() {
        let cfg = OplockConfig::default();
        assert_eq!(cfg.port, 445);
        assert_eq!(cfg.share, "ADMIN$");
        assert_eq!(cfg.oplock_level, OplockLevel::Batch);
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[test]
    fn test_oplock_config_custom() {
        let cfg = OplockConfig {
            server: "10.0.0.1".into(),
            port: 445,
            share: "C$".into(),
            file: "test.txt".into(),
            domain: "CORP".into(),
            username: "admin".into(),
            password: Some("pass".into()),
            nt_hash: None,
            oplock_level: OplockLevel::Exclusive,
            timeout_secs: 60,
        };
        assert_eq!(cfg.server, "10.0.0.1");
        assert_eq!(cfg.oplock_level, OplockLevel::Exclusive);
        assert_eq!(cfg.timeout_secs, 60);
    }
}
