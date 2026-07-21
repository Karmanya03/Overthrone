//! Session persistence -- save and restore EngagementState to/from disk.
//!
//! Saves engagement state as JSON to `~/.overthrone/sessions/<name>.json`
//! allowing interrupted runs to be resumed without re-doing recon/attack steps.

use std::path::{Path, PathBuf};

use crate::goals::EngagementState;

/// Default session directory: ~/.overthrone/sessions/
pub fn default_session_dir() -> PathBuf {
    let home = dirs_home();
    home.join(".overthrone").join("sessions")
}

fn dirs_home() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| {
                std::env::var("HOMEDRIVE")
                    .and_then(|d| std::env::var("HOMEPATH").map(|p| format!("{}{}", d, p)))
            })
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }

    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }
}

/// Serialize and save `EngagementState` to `path`.
/// Creates parent directories if needed.
pub fn save_session(path: &Path, state: &EngagementState) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Wrap in a versioned envelope for forward compat
    let envelope = SessionEnvelope {
        version: 1,
        overthrone_version: env!("CARGO_PKG_VERSION").to_string(),
        saved_at: chrono::Utc::now().to_rfc3339(),
        state: state.clone(),
    };

    let json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    std::fs::write(path, json)
}

/// Load and deserialize an `EngagementState` from `path`.
pub fn load_session(path: &Path) -> Result<EngagementState, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read session file {}: {}", path.display(), e))?;

    // Try versioned envelope first, fall back to bare EngagementState
    if let Ok(envelope) = serde_json::from_str::<SessionEnvelope>(&data) {
        Ok(envelope.state)
    } else {
        serde_json::from_str::<EngagementState>(&data)
            .map_err(|e| format!("Failed to parse session file: {}", e))
    }
}

/// Build a session file path for a given engagement name.
/// E.g. `session_path("corp.local")` -> `~/.overthrone/sessions/corp.local.json`
pub fn session_path(name: &str) -> PathBuf {
    // Sanitize name to avoid path traversal
    let safe_name: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    default_session_dir().join(format!("{}.json", safe_name))
}

/// Auto-save path derived from DC host + domain.
pub fn auto_session_path(dc_host: &str, domain: &str) -> PathBuf {
    let name = format!("{}-{}", domain, dc_host)
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    default_session_dir().join(format!("{}.json", name))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionEnvelope {
    version: u32,
    overthrone_version: String,
    saved_at: String,
    state: EngagementState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn dummy_state() -> EngagementState {
        EngagementState {
            domain: Some("test.local".into()),
            dc_ip: Some("192.168.1.1".into()),
            ..Default::default()
        }
    }

    #[test]
    fn test_default_session_dir_created() {
        let dir = default_session_dir();
        let components: Vec<_> = dir.components().collect();
        assert!(components.iter().any(|c| c.as_os_str() == ".overthrone"));
        assert!(components.iter().any(|c| c.as_os_str() == "sessions"));
    }

    #[test]
    fn test_save_and_load_session() {
        let dir = std::env::temp_dir().join("ovt_session_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test_session.json");
        let state = dummy_state();

        save_session(&path, &state).unwrap();
        assert!(path.exists());

        let loaded = load_session(&path).unwrap();
        assert_eq!(loaded.domain, Some("test.local".into()));
        assert_eq!(loaded.dc_ip, Some("192.168.1.1".into()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_bare_state_fallback() {
        let dir = std::env::temp_dir().join("ovt_session_bare_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("bare_state.json");
        let state = dummy_state();
        let json = serde_json::to_string_pretty(&state).unwrap();
        fs::write(&path, &json).unwrap();

        let loaded = load_session(&path).unwrap();
        assert_eq!(loaded.domain, Some("test.local".into()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_session_path_sanitizes_name() {
        let path = session_path("corp.local");
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(filename.contains("corp.local"));
        assert!(filename.ends_with(".json"));

        // Path traversal attempt: / replaced with _
        let path = session_path("../evil");
        let filename = path.file_name().unwrap().to_string_lossy();
        // Slash replaced with underscore -- no new path components introduced
        assert_eq!(filename, ".._evil.json");
        // The joined path should not go up directories
        let parent = path.parent().unwrap();
        let expected_parent = default_session_dir();
        assert_eq!(parent, expected_parent);
    }

    #[test]
    fn test_auto_session_path() {
        let path = auto_session_path("dc01.corp.local", "corp.local");
        let name = path.file_stem().unwrap().to_string_lossy();
        assert!(name.contains("corp.local"));
        assert!(name.contains("dc01.corp.local"));
    }

    #[test]
    fn test_load_nonexistent_session() {
        let result = load_session(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
    }
}
