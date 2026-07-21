use std::path::PathBuf;

use crate::error::{OverthroneError, Result};
use crate::proto::kerberos::{TicketGrantingData, kirbi_to_tgd, tgd_to_kirbi};

pub const CACHE_DIR_NAME: &str = "ccache";
pub const KIRBI_EXT: &str = "kirbi";

/// Resolve the standard cache directory for Kerberos credential caches.
/// Uses `$XDG_CACHE_HOME/overthrone/ccache` on any platform (when set),
/// then falls back to `%LOCALAPPDATA%/overthrone/ccache` on Windows
/// or `~/.cache/overthrone/ccache` on Unix.
fn default_cache_dir() -> PathBuf {
    // XDG_CACHE_HOME overrides everything on any platform (WSL/Cygwin compat)
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("overthrone").join(CACHE_DIR_NAME);
    }

    #[cfg(target_os = "windows")]
    if let Some(appdata) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(appdata)
            .join("overthrone")
            .join(CACHE_DIR_NAME);
    }

    #[cfg(not(target_os = "windows"))]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("overthrone")
            .join(CACHE_DIR_NAME);
    }

    dirs_fallback()
}

fn dirs_fallback() -> PathBuf {
    PathBuf::from(".").join(".overthrone").join(CACHE_DIR_NAME)
}

/// Manages a directory of cached Kerberos tickets (KRB-CRED/.kirbi format).
/// Each ticket is stored at `<cache_dir>/<realm>/<username>.kirbi`.
pub struct CredCache {
    /// Root directory for Kerberos credential caches
    pub cache_dir: PathBuf,
}

impl Default for CredCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CredCache {
    /// Create a new CredCache using the default platform-specific cache directory.
    /// Creates the directory if it doesn't exist.
    pub fn new() -> Self {
        Self {
            cache_dir: default_cache_dir(),
        }
    }

    /// Create a CredCache with an explicit cache directory.
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { cache_dir: dir }
    }

    /// Get the file path for a cached TGT for the given realm and username.
    pub fn tgt_path(&self, realm: &str, username: &str) -> PathBuf {
        self.cache_dir
            .join(realm)
            .join(format!("{username}.{KIRBI_EXT}"))
    }

    /// Load a cached TGT from disk. Returns `None` if the cache file doesn't exist,
    /// can't be parsed, or is expired.
    pub fn load_tgt(&self, realm: &str, username: &str) -> Option<TicketGrantingData> {
        let path = self.tgt_path(realm, username);
        if !path.exists() {
            return None;
        }
        match std::fs::read(&path) {
            Ok(data) => match kirbi_to_tgd(&data) {
                Ok(tgt) => {
                    if is_tgt_expired(&tgt) {
                        let _ = std::fs::remove_file(&path);
                        None
                    } else {
                        Some(tgt)
                    }
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                    None
                }
            },
            Err(_) => None,
        }
    }

    /// Save a TGT to the credential cache. Creates parent directories as needed.
    pub fn save_tgt(&self, tgt: &TicketGrantingData) -> Result<()> {
        let realm = &tgt.client_realm;
        let username = &tgt.client_principal;
        let path = self.tgt_path(realm, username);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                OverthroneError::Kerberos(format!("Failed to create cache dir {parent:?}: {e}"))
            })?;
        }

        let data = tgd_to_kirbi(tgt);
        std::fs::write(&path, &data).map_err(|e| {
            OverthroneError::Kerberos(format!("Failed to write cache file {path:?}: {e}"))
        })?;

        Ok(())
    }

    /// Delete a single cached TGT for the given realm and username.
    pub fn remove_tgt(&self, realm: &str, username: &str) -> Result<()> {
        let path = self.tgt_path(realm, username);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                OverthroneError::Kerberos(format!("Failed to remove {path:?}: {e}"))
            })?;
        }
        Ok(())
    }

    /// Clear all cached tickets for a given realm.
    pub fn clear_realm(&self, realm: &str) -> Result<usize> {
        let realm_dir = self.cache_dir.join(realm);
        if !realm_dir.exists() {
            return Ok(0);
        }
        let count = std::fs::read_dir(&realm_dir)
            .map_err(|e| OverthroneError::Kerberos(format!("Failed to list {realm_dir:?}: {e}")))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == KIRBI_EXT))
            .count();

        std::fs::remove_dir_all(&realm_dir).map_err(|e| {
            OverthroneError::Kerberos(format!("Failed to remove {realm_dir:?}: {e}"))
        })?;

        Ok(count)
    }

    /// Clear all cached tickets across all realms.
    pub fn clear_all(&self) -> Result<usize> {
        if !self.cache_dir.exists() {
            return Ok(0);
        }
        let mut total = 0;
        for entry in std::fs::read_dir(&self.cache_dir).map_err(|e| {
            OverthroneError::Kerberos(format!(
                "Failed to list cache dir {:?}: {e}",
                self.cache_dir
            ))
        })? {
            let entry = entry
                .map_err(|e| OverthroneError::Kerberos(format!("Failed to read entry: {e}")))?;
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                total += self
                    .clear_realm(&entry.file_name().to_string_lossy())
                    .unwrap_or(0);
            }
        }
        Ok(total)
    }

    /// List all cached tickets, returning (realm, username) pairs.
    pub fn list_tgts(&self) -> Vec<(String, String)> {
        if !self.cache_dir.exists() {
            return vec![];
        }
        let mut result = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let realm = match path.file_name().and_then(|n| n.to_str()) {
                    Some(r) if path.is_dir() => r.to_string(),
                    _ => continue,
                };
                let Ok(ticket_entries) = std::fs::read_dir(&path) else {
                    continue;
                };
                for te in ticket_entries.flatten() {
                    if te.path().extension().is_some_and(|e| e == KIRBI_EXT)
                        && let Some(stem) = te.path().file_stem().and_then(|s| s.to_str())
                    {
                        result.push((realm.clone(), stem.to_string()));
                    }
                }
            }
        }
        result
    }

    /// Get the total number of cached tickets.
    pub fn count(&self) -> usize {
        self.list_tgts().len()
    }

    /// Get the total size of all cached ticket files in bytes.
    pub fn total_size(&self) -> u64 {
        if !self.cache_dir.exists() {
            return 0;
        }
        let mut total = 0u64;
        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let Ok(ticket_entries) = std::fs::read_dir(&path) else {
                    continue;
                };
                for te in ticket_entries.flatten() {
                    if te.path().extension().is_some_and(|e| e == KIRBI_EXT) {
                        total += te.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                }
            }
        }
        total
    }
}

/// Check if a TGT is expired by comparing its end_time against the current time.
/// KerberosTime derefs through GeneralizedTime to chrono::DateTime<Utc>
fn is_tgt_expired(tgt: &TicketGrantingData) -> bool {
    use chrono::Utc;
    tgt.end_time.as_ref().is_some_and(|end| {
        let now_ts = Utc::now().timestamp();
        let end_ts = end.timestamp();
        now_ts >= end_ts
    })
}

// --- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::kerberos::NT_PRINCIPAL;
    use kerberos_asn1::{PrincipalName, Ticket};

    fn make_dummy_tgt(realm: &str, user: &str) -> TicketGrantingData {
        use chrono::Utc;
        TicketGrantingData {
            ticket: Ticket {
                tkt_vno: 5,
                realm: realm.to_string(),
                sname: PrincipalName {
                    name_type: NT_PRINCIPAL,
                    name_string: vec!["krbtgt".to_string(), realm.to_string()],
                },
                enc_part: kerberos_asn1::EncryptedData {
                    etype: 23,
                    kvno: Some(1),
                    cipher: vec![0u8; 100],
                },
            },
            session_key: vec![0xAB; 16],
            session_key_etype: 23,
            client_principal: user.to_string(),
            client_realm: realm.to_string(),
            end_time: Some(kerberos_asn1::KerberosTime::from(
                Utc::now() + chrono::Duration::hours(1),
            )),
        }
    }

    fn make_expired_tgt(realm: &str, user: &str) -> TicketGrantingData {
        use chrono::Utc;
        let mut tgt = make_dummy_tgt(realm, user);
        tgt.end_time = Some(kerberos_asn1::KerberosTime::from(
            Utc::now() - chrono::Duration::hours(1),
        ));
        tgt
    }

    #[test]
    fn test_tgd_to_kirbi_roundtrip() {
        let original = make_dummy_tgt("CORP.LOCAL", "Administrator");
        let kirbi = tgd_to_kirbi(&original);
        assert!(!kirbi.is_empty());
        let parsed = kirbi_to_tgd(&kirbi).unwrap();
        assert_eq!(parsed.client_principal, "Administrator");
        assert_eq!(parsed.client_realm, "CORP.LOCAL");
        assert_eq!(parsed.session_key, original.session_key);
        assert_eq!(parsed.session_key_etype, 23);
        assert_eq!(parsed.ticket.realm, "CORP.LOCAL");
    }

    #[test]
    fn test_kirbi_to_tgd_invalid_data() {
        let result = kirbi_to_tgd(b"not-a-kirbi");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_cache_dir_exists() {
        let dir = default_cache_dir();
        assert!(!dir.as_os_str().is_empty());
        assert!(dir.ends_with(CACHE_DIR_NAME));
    }

    #[test]
    fn test_cred_cache_save_load_roundtrip() {
        let dir = std::env::temp_dir()
            .join("cred_cache_test")
            .join("test_roundtrip");
        let _ = std::fs::remove_dir_all(&dir);

        let cache = CredCache::with_dir(dir.clone());
        let tgt = make_dummy_tgt("TEST.LOCAL", "User1");
        cache.save_tgt(&tgt).unwrap();

        let loaded = cache.load_tgt("TEST.LOCAL", "User1").unwrap();
        assert_eq!(loaded.client_principal, "User1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cred_cache_load_expired_returns_none() {
        let dir = std::env::temp_dir()
            .join("cred_cache_test")
            .join("test_expired");
        let _ = std::fs::remove_dir_all(&dir);

        let cache = CredCache::with_dir(dir.clone());
        let tgt = make_expired_tgt("TEST.LOCAL", "ExpiredUser");
        cache.save_tgt(&tgt).unwrap();

        let loaded = cache.load_tgt("TEST.LOCAL", "ExpiredUser");
        assert!(loaded.is_none(), "Expired TGT should not be loaded");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cred_cache_load_missing_returns_none() {
        let cache = CredCache::new();
        let loaded = cache.load_tgt("NONEXISTENT.LOCAL", "Nobody");
        assert!(loaded.is_none());
    }

    #[test]
    fn test_cred_cache_remove_tgt() {
        let dir = std::env::temp_dir()
            .join("cred_cache_test")
            .join("test_remove");
        let _ = std::fs::remove_dir_all(&dir);

        let cache = CredCache::with_dir(dir.clone());
        let tgt = make_dummy_tgt("TEST.LOCAL", "ToRemove");
        cache.save_tgt(&tgt).unwrap();
        assert!(cache.tgt_path("TEST.LOCAL", "ToRemove").exists());

        cache.remove_tgt("TEST.LOCAL", "ToRemove").unwrap();
        assert!(!cache.tgt_path("TEST.LOCAL", "ToRemove").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cred_cache_clear_realm() {
        let dir = std::env::temp_dir()
            .join("cred_cache_test")
            .join("test_clear_realm");
        let _ = std::fs::remove_dir_all(&dir);

        let cache = CredCache::with_dir(dir.clone());
        cache.save_tgt(&make_dummy_tgt("A.LOCAL", "U1")).unwrap();
        cache.save_tgt(&make_dummy_tgt("A.LOCAL", "U2")).unwrap();
        cache.save_tgt(&make_dummy_tgt("B.LOCAL", "U3")).unwrap();

        assert_eq!(cache.count(), 3);
        let cleared = cache.clear_realm("A.LOCAL").unwrap();
        assert_eq!(cleared, 2);
        assert_eq!(cache.count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cred_cache_clear_all() {
        let dir = std::env::temp_dir()
            .join("cred_cache_test")
            .join("test_clear_all");
        let _ = std::fs::remove_dir_all(&dir);

        let cache = CredCache::with_dir(dir.clone());
        cache.save_tgt(&make_dummy_tgt("A.LOCAL", "U1")).unwrap();
        cache.save_tgt(&make_dummy_tgt("B.LOCAL", "U2")).unwrap();

        assert_eq!(cache.count(), 2);
        let cleared = cache.clear_all().unwrap();
        assert_eq!(cleared, 2);
        assert_eq!(cache.count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cred_cache_list_tgts() {
        let dir = std::env::temp_dir()
            .join("cred_cache_test")
            .join("test_list");
        let _ = std::fs::remove_dir_all(&dir);

        let cache = CredCache::with_dir(dir.clone());
        cache.save_tgt(&make_dummy_tgt("X.LOCAL", "Alice")).unwrap();
        cache.save_tgt(&make_dummy_tgt("Y.LOCAL", "Bob")).unwrap();

        let list = cache.list_tgts();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&("X.LOCAL".to_string(), "Alice".to_string())));
        assert!(list.contains(&("Y.LOCAL".to_string(), "Bob".to_string())));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cred_cache_total_size() {
        let dir = std::env::temp_dir()
            .join("cred_cache_test")
            .join("test_size");
        let _ = std::fs::remove_dir_all(&dir);

        let cache = CredCache::with_dir(dir.clone());
        let size_before = cache.total_size();
        assert_eq!(size_before, 0);

        cache.save_tgt(&make_dummy_tgt("S.LOCAL", "User")).unwrap();
        let size_after = cache.total_size();
        assert!(size_after > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_is_tgt_expired_true() {
        let tgt = make_expired_tgt("R.LOCAL", "U");
        assert!(is_tgt_expired(&tgt));
    }

    #[test]
    fn test_is_tgt_expired_false() {
        let tgt = make_dummy_tgt("R.LOCAL", "U");
        assert!(!is_tgt_expired(&tgt));
    }

    #[test]
    fn test_is_tgt_expired_no_end_time() {
        let mut tgt = make_dummy_tgt("R.LOCAL", "U");
        tgt.end_time = None;
        assert!(!is_tgt_expired(&tgt));
    }

    #[test]
    fn test_cache_dir_uses_env() {
        // XDG_CACHE_HOME should influence the path
        let original = std::env::var("XDG_CACHE_HOME").ok();
        unsafe { std::env::set_var("XDG_CACHE_HOME", "/custom/cache") };
        let dir = default_cache_dir();
        assert!(dir.starts_with("/custom/cache"));
        if let Some(val) = original {
            unsafe { std::env::set_var("XDG_CACHE_HOME", val) };
        } else {
            unsafe { std::env::remove_var("XDG_CACHE_HOME") };
        }
    }
}
