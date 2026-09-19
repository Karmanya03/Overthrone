use chrono::Local;
use std::fs;
use std::path::{Path, PathBuf};

/// Try to resolve DC IP from domain name via DNS SRV lookup
/// Falls back to common patterns (dc1.domain, dc.domain, domain itself)
#[allow(dead_code)]
pub async fn detect_dc(domain: &str) -> Option<String> {
    // Try DNS SRV lookup for _ldap._tcp.dc._msdcs.{domain}
    let srv_name = format!("_ldap._tcp.dc._msdcs.{}", domain);
    if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:389", srv_name)).await
        && let Some(addr) = addrs.next()
    {
        let ip = addr.ip().to_string();
        if !ip.is_empty() {
            return Some(ip);
        }
    }
    // Try DNS A record for dc1.{domain}
    let dc_name = format!("dc1.{}", domain);
    if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:389", dc_name)).await
        && let Some(addr) = addrs.next()
    {
        return Some(addr.ip().to_string());
    }
    None
}

/// Base loot directory
#[allow(dead_code)]
const LOOT_DIR: &str = "./loot";

/// Ensure the loot directory exists
#[allow(dead_code)]
pub fn ensure_loot_dir() -> std::io::Result<PathBuf> {
    let dir = Path::new(LOOT_DIR);
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(dir.to_path_buf())
}

/// Generate a timestamped filename: `{name}_{YYYYMMDD_HHMMSS}.{ext}`
#[allow(dead_code)]
pub fn timestamped_path(name: &str, ext: &str) -> PathBuf {
    let ts = Local::now().format("%Y%m%d_%H%M%S");
    let dir = ensure_loot_dir().unwrap_or_else(|_| PathBuf::from(LOOT_DIR));
    dir.join(format!("{name}_{ts}.{ext}"))
}

/// Generate a timestamped path under a custom output dir
#[allow(dead_code)]
pub fn timestamped_path_in(output_dir: &str, name: &str, ext: &str) -> PathBuf {
    let ts = Local::now().format("%Y%m%d_%H%M%S");
    let dir = Path::new(output_dir);
    if !dir.exists() {
        let _ = fs::create_dir_all(dir);
    }
    dir.join(format!("{name}_{ts}.{ext}"))
}

/// Save text content to loot dir with timestamp
#[allow(dead_code)]
pub fn save_text(name: &str, content: &str) -> std::io::Result<PathBuf> {
    let path = timestamped_path(name, "txt");
    fs::write(&path, content)?;
    Ok(path)
}

/// Save JSON content to loot dir with timestamp  
#[allow(dead_code)]
pub fn save_json(name: &str, content: &serde_json::Value) -> std::io::Result<PathBuf> {
    let path = timestamped_path(name, "json");
    fs::write(&path, serde_json::to_string_pretty(content)?)?;
    Ok(path)
}

/// Save binary content to loot dir with timestamp
#[allow(dead_code)]
pub fn save_binary(name: &str, ext: &str, content: &[u8]) -> std::io::Result<PathBuf> {
    let path = timestamped_path(name, ext);
    fs::write(&path, content)?;
    Ok(path)
}

/// Save to a user-specified path or fall back to timestamped loot
#[allow(dead_code)]
pub fn save_to_or_loot(
    user_path: Option<&str>,
    name: &str,
    ext: &str,
    content: &[u8],
) -> std::io::Result<PathBuf> {
    if let Some(p) = user_path {
        let dir = Path::new(p).parent().unwrap_or(Path::new("."));
        if !dir.exists() {
            let _ = fs::create_dir_all(dir);
        }
        fs::write(p, content)?;
        Ok(PathBuf::from(p))
    } else {
        save_binary(name, ext, content)
    }
}
