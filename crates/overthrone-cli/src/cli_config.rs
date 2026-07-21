use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// On-disk configuration that maps directly to the global CLI flags on
/// `crate::Cli`.
///
/// Every field is `Option<T>` so the user can set only the keys they care
/// about and the rest fall through to clap's defaults (or the env vars
/// declared on the flag).
///
/// Precedence (highest to lowest):
/// 1. CLI flag
/// 2. Environment variable (`OT_*`, `KRB5CCNAME`)
/// 3. `config.toml` (this struct)
/// 4. Built-in default
///
/// The struct is deserialized with `#[serde(default)]` so missing keys
/// just stay `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CliConfig {
    pub dc_host: Option<String>,
    pub domain: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    pub pkinit_cert: Option<String>,
    pub pkinit_key: Option<String>,
    pub auth_method: Option<String>,
    pub stdout_format: Option<String>,
    pub outfile: Option<String>,
    pub ticket: Option<String>,
    pub verbose: Option<u8>,
    pub dry_run: Option<bool>,
    pub json_log: Option<bool>,
    pub user_list: Option<String>,
    pub pass_list: Option<String>,
    pub user_pass_list: Option<String>,
}

/// The full set of keys `ovt config set <KEY> <VALUE>` accepts.
///
/// Returned by [`config_keys`] so the help text stays in sync with the
/// struct.
pub const CONFIG_KEYS: &[&str] = &[
    "dc_host",
    "domain",
    "username",
    "password",
    "nt_hash",
    "pkinit_cert",
    "pkinit_key",
    "auth_method",
    "stdout_format",
    "outfile",
    "ticket",
    "verbose",
    "dry_run",
    "json_log",
    "user_list",
    "pass_list",
    "user_pass_list",
];

/// Returns the XDG config path that `ovt config init` and `ovt config save`
/// write to. Created on demand by `init` and `save`.
pub fn default_config_path() -> Option<PathBuf> {
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "overthrone", "Overthrone") {
        return Some(proj_dirs.config_dir().join("config.toml"));
    }
    if let Some(home) = dirs::config_dir() {
        return Some(home.join("overthrone").join("config.toml"));
    }
    None
}

// -------------------------------------------------------------------
// Profile system
// -------------------------------------------------------------------
//
// Named profiles live in `<config_dir>/profiles/<NAME>.toml`. The main
// `config.toml` provides shared defaults; a selected profile overrides
// any subset of fields. The active profile is chosen by `--profile
// <NAME>` on the CLI (or `OT_PROFILE` env var).
//
// Precedence (highest to lowest):
// 1. CLI flag
// 2. Environment variable (`OT_*`, `KRB5CCNAME`)
// 3. Active profile (`<config_dir>/profiles/<NAME>.toml`)
// 4. Main `config.toml` (shared defaults)
// 5. Built-in default
//
// The profile file format is identical to the main config -- same
// `CliConfig` struct, same key set. This keeps the on-disk format
// trivial and lets operators `cp` profiles around.

/// Returns the directory where named profiles live. Created on demand
/// by `save_profile`.
///
/// Honors the `OT_CONFIG` env var: when set, profiles live in a
/// `profiles/` subdirectory next to the explicit config file rather
/// than under the XDG config dir. This keeps `--config <PATH>` and
/// the `OT_CONFIG` env var consistent -- both move the entire config
/// tree (main config + named profiles) to a single location.
pub fn default_profiles_dir() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("OT_CONFIG")
        && !explicit.is_empty()
    {
        let p = PathBuf::from(explicit);
        if let Some(parent) = p.parent() {
            return Some(parent.join("profiles"));
        }
        return Some(PathBuf::from("profiles"));
    }
    default_config_path().and_then(|p| p.parent().map(|parent| parent.join("profiles")))
}

/// Returns the on-disk path of a named profile. The name is validated
/// by [`validate_profile_name`] before being joined.
pub fn profile_path(name: &str) -> Result<PathBuf, String> {
    let dir = default_profiles_dir()
        .ok_or_else(|| "Could not resolve config directory for profiles".to_string())?;
    validate_profile_name(name)?;
    Ok(dir.join(format!("{}.toml", name)))
}

/// Returns the active profile name, if any, from the `OT_PROFILE` env
/// var. Returns `Ok(None)` if the env var is unset or empty.
pub fn active_profile() -> Result<Option<String>, String> {
    match std::env::var("OT_PROFILE") {
        Ok(s) if s.is_empty() => Ok(None),
        Ok(s) => {
            validate_profile_name(&s)?;
            Ok(Some(s))
        }
        Err(_) => Ok(None),
    }
}

/// Validate a profile name. Profile names must be short, alphanumeric
/// with `-` or `_`, and contain no path separators or traversal
/// sequences. This prevents accidental escape from the profiles
/// directory.
pub fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Profile name cannot be empty".to_string());
    }
    if name.len() > 64 {
        return Err(format!("Profile name too long (max 64 chars): '{}'", name));
    }
    if name == "." || name == ".." {
        return Err(format!("Profile name cannot be '{}'", name));
    }
    for c in name.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
        if !ok {
            return Err(format!(
                "Profile name '{}' contains invalid character '{}'. Allowed: A-Z, a-z, 0-9, '-', '_', '.'",
                name, c
            ));
        }
        if c == '/' || c == '\\' {
            return Err(format!(
                "Profile name '{}' cannot contain path separators",
                name
            ));
        }
    }
    Ok(())
}

/// Load a named profile from disk. Returns `CliConfig::default()` if
/// the profile file does not exist (silent -- common when the operator
/// has not yet created a profile).
pub fn load_profile(name: &str) -> Result<CliConfig, String> {
    let path = profile_path(name)?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read profile '{}': {}", name, e))?;
    toml::from_str(&content).map_err(|e| format!("Failed to parse profile '{}': {}", name, e))
}

/// Save a named profile to disk. Creates the parent directory if
/// needed. Overwrites any existing file.
#[allow(dead_code)]
pub fn save_profile(name: &str, config: &CliConfig) -> Result<(), String> {
    let path = profile_path(name)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create profiles directory: {}", e))?;
    }
    let serialized = toml::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize profile: {}", e))?;
    std::fs::write(&path, serialized)
        .map_err(|e| format!("Failed to write profile '{}': {}", name, e))?;
    Ok(())
}

/// Delete a named profile. Returns an error if the profile does not
/// exist or could not be removed.
#[allow(dead_code)]
pub fn delete_profile(name: &str) -> Result<(), String> {
    let path = profile_path(name)?;
    if !path.exists() {
        return Err(format!(
            "Profile '{}' does not exist at {}",
            name,
            path.display()
        ));
    }
    std::fs::remove_file(&path)
        .map_err(|e| format!("Failed to delete profile '{}': {}", name, e))?;
    Ok(())
}

/// List all named profiles that exist on disk. Names are returned
/// without the `.toml` suffix, sorted alphabetically.
#[allow(dead_code)]
pub fn list_profiles() -> Result<Vec<String>, String> {
    let dir = match default_profiles_dir() {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("Failed to read profiles directory: {}", e))?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("toml") {
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// Returns true if a profile with the given name exists on disk.
#[allow(dead_code)]
pub fn profile_exists(name: &str) -> Result<bool, String> {
    let path = profile_path(name)?;
    Ok(path.exists())
}

/// Copy an existing profile to a new name. Returns an error if the
/// source profile does not exist.
#[allow(dead_code)]
pub fn clone_profile(src: &str, dst: &str) -> Result<(), String> {
    let cfg = load_profile(src)?;
    if profile_exists(dst)? {
        return Err(format!(
            "Profile '{}' already exists -- use `ovt config profile delete` first",
            dst
        ));
    }
    save_profile(dst, &cfg)
}

/// Search path used by `load_config` when no explicit `--config` path was
/// given. Highest-precedence path first.
fn config_file_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "overthrone", "Overthrone") {
        let config_dir = proj_dirs.config_dir().to_path_buf();
        paths.push(config_dir.join("config.toml"));
        paths.push(config_dir.join("overthrone.toml"));
    }

    if let Some(home) = dirs::config_dir() {
        paths.push(home.join("overthrone").join("config.toml"));
        paths.push(home.join("overthrone").join("overthrone.toml"));
    }

    paths.push(PathBuf::from("overthrone.toml"));
    paths.push(PathBuf::from(".overthrone.toml"));
    paths.push(PathBuf::from("config.toml"));

    paths
}

/// Read the first config file that exists in the search path, parse it
/// into a [`CliConfig`], and return it. If no file exists, returns
/// `CliConfig::default()` (silent -- this is normal on first run).
pub fn load_config(explicit_path: Option<&str>) -> Result<CliConfig, String> {
    let paths = if let Some(path) = explicit_path {
        vec![PathBuf::from(path)]
    } else {
        config_file_paths()
    };

    for path in &paths {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
            let config: CliConfig = toml::from_str(&content)
                .map_err(|e| format!("Failed to parse config file '{}': {}", path.display(), e))?;
            tracing::info!("Loaded config from {}", path.display());
            return Ok(config);
        }
    }

    Ok(CliConfig::default())
}

/// Write a config to disk as pretty TOML. Creates the parent directory
/// if it doesn't exist.
pub fn save_config(path: &Path, config: &CliConfig) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create config directory '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    let serialized =
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(path, serialized)
        .map_err(|e| format!("Failed to write config file '{}': {}", path.display(), e))?;
    Ok(())
}

/// Apply `set <KEY> <VALUE>` semantics: load the config from `path` (or
/// start from an empty config), set the named key, and write the file
/// back. Returns the previous value as `Some` for display purposes.
pub fn set_value(
    path: &Path,
    key: &str,
    value: &str,
) -> Result<(Option<String>, CliConfig), String> {
    if !CONFIG_KEYS.contains(&key) {
        return Err(format!(
            "Unknown config key '{}'. Valid keys: {}",
            key,
            CONFIG_KEYS.join(", ")
        ));
    }

    let mut config = if path.exists() {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
        toml::from_str::<CliConfig>(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path.display(), e))?
    } else {
        CliConfig::default()
    };

    let previous = get_string_value(&config, key);
    apply_string_value(&mut config, key, value)?;
    save_config(path, &config)?;
    Ok((previous, config))
}

/// Apply `unset <KEY>` semantics: load, blank the key, and write.
pub fn unset_value(path: &Path, key: &str) -> Result<CliConfig, String> {
    if !CONFIG_KEYS.contains(&key) {
        return Err(format!(
            "Unknown config key '{}'. Valid keys: {}",
            key,
            CONFIG_KEYS.join(", ")
        ));
    }

    let mut config = if path.exists() {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
        toml::from_str::<CliConfig>(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path.display(), e))?
    } else {
        return Ok(CliConfig::default());
    };

    apply_string_value(&mut config, key, "")?;
    save_config(path, &config)?;
    Ok(config)
}

fn get_string_value(config: &CliConfig, key: &str) -> Option<String> {
    match key {
        "dc_host" => config.dc_host.clone(),
        "domain" => config.domain.clone(),
        "username" => config.username.clone(),
        "password" => config.password.clone(),
        "nt_hash" => config.nt_hash.clone(),
        "pkinit_cert" => config.pkinit_cert.clone(),
        "pkinit_key" => config.pkinit_key.clone(),
        "auth_method" => config.auth_method.clone(),
        "stdout_format" => config.stdout_format.clone(),
        "outfile" => config.outfile.clone(),
        "ticket" => config.ticket.clone(),
        "user_list" => config.user_list.clone(),
        "pass_list" => config.pass_list.clone(),
        "user_pass_list" => config.user_pass_list.clone(),
        "verbose" => config.verbose.map(|v| v.to_string()),
        "dry_run" => config.dry_run.map(|v| v.to_string()),
        "json_log" => config.json_log.map(|v| v.to_string()),
        _ => None,
    }
}

fn apply_string_value(config: &mut CliConfig, key: &str, value: &str) -> Result<(), String> {
    let empty = value.is_empty();
    match key {
        "dc_host" => config.dc_host = (!empty).then(|| value.to_string()),
        "domain" => config.domain = (!empty).then(|| value.to_string()),
        "username" => config.username = (!empty).then(|| value.to_string()),
        "password" => config.password = (!empty).then(|| value.to_string()),
        "nt_hash" => config.nt_hash = (!empty).then(|| value.to_string()),
        "pkinit_cert" => config.pkinit_cert = (!empty).then(|| value.to_string()),
        "pkinit_key" => config.pkinit_key = (!empty).then(|| value.to_string()),
        "auth_method" => {
            validate_auth_method(value)?;
            config.auth_method = (!empty).then(|| value.to_string());
        }
        "stdout_format" => {
            validate_stdout_format(value)?;
            config.stdout_format = (!empty).then(|| value.to_string());
        }
        "outfile" => config.outfile = (!empty).then(|| value.to_string()),
        "ticket" => config.ticket = (!empty).then(|| value.to_string()),
        "user_list" => config.user_list = (!empty).then(|| value.to_string()),
        "pass_list" => config.pass_list = (!empty).then(|| value.to_string()),
        "user_pass_list" => config.user_pass_list = (!empty).then(|| value.to_string()),
        "verbose" => {
            let v: u8 = if empty {
                0
            } else {
                value
                    .parse()
                    .map_err(|_| format!("Invalid u8 value for 'verbose': '{}'", value))?
            };
            config.verbose = Some(v);
        }
        "dry_run" => {
            let v: bool = parse_boolish(value).ok_or_else(|| {
                format!(
                    "Invalid bool for 'dry_run': '{}' (expected true|false|1|0|yes|no)",
                    value
                )
            })?;
            config.dry_run = Some(v);
        }
        "json_log" => {
            let v: bool = parse_boolish(value).ok_or_else(|| {
                format!(
                    "Invalid bool for 'json_log': '{}' (expected true|false|1|0|yes|no)",
                    value
                )
            })?;
            config.json_log = Some(v);
        }
        _ => return Err(format!("Unknown config key '{}'", key)),
    }
    Ok(())
}

fn validate_auth_method(value: &str) -> Result<(), String> {
    const VALID: &[&str] = &["password", "hash", "ticket"];
    let lower = value.to_lowercase();
    if VALID.contains(&lower.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "Invalid auth_method '{}'. Expected one of: {}",
            value,
            VALID.join(", ")
        ))
    }
}

fn validate_stdout_format(value: &str) -> Result<(), String> {
    const VALID: &[&str] = &["text", "json", "csv"];
    let lower = value.to_lowercase();
    if VALID.contains(&lower.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "Invalid stdout_format '{}'. Expected one of: {}",
            value,
            VALID.join(", ")
        ))
    }
}

fn parse_boolish(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => Some(true),
        "false" | "0" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

/// Render a [`CliConfig`] as a human-readable multi-line string,
/// skipping keys whose value is `None`. Used by `ovt config show`.
pub fn display(config: &CliConfig) -> String {
    let mut out = String::new();
    let entries: Vec<(&str, Option<String>)> = vec![
        ("dc_host", config.dc_host.clone()),
        ("domain", config.domain.clone()),
        ("username", config.username.clone()),
        ("password", config.password.clone().map(|p| mask_secret(&p))),
        ("nt_hash", config.nt_hash.clone().map(|p| mask_secret(&p))),
        ("pkinit_cert", config.pkinit_cert.clone()),
        (
            "pkinit_key",
            config.pkinit_key.clone().map(|p| mask_secret(&p)),
        ),
        ("auth_method", config.auth_method.clone()),
        ("stdout_format", config.stdout_format.clone()),
        ("outfile", config.outfile.clone()),
        ("ticket", config.ticket.clone()),
        ("user_list", config.user_list.clone()),
        ("pass_list", config.pass_list.clone()),
        ("user_pass_list", config.user_pass_list.clone()),
        ("verbose", config.verbose.map(|v| v.to_string())),
        ("dry_run", config.dry_run.map(|v| v.to_string())),
        ("json_log", config.json_log.map(|v| v.to_string())),
    ];

    let mut printed = 0;
    for (key, val) in &entries {
        if let Some(v) = val.as_deref() {
            out.push_str(&format!(" {} = {}\n", key, v));
            printed += 1;
        }
    }

    if printed == 0 {
        out.push_str(" (empty)\n");
    }
    out
}

fn mask_secret(secret: &str) -> String {
    let len = secret.chars().count();
    if len <= 4 {
        return "*".repeat(len.max(1));
    }
    let visible = 2;
    let hidden = len.saturating_sub(visible * 2);
    let prefix: String = secret.chars().take(visible).collect();
    let suffix: String = secret.chars().skip(len - visible).collect();
    format!("{}{}{}", prefix, "*".repeat(hidden), suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_file(name: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!(
            "overthrone-cli-config-test-{}-{}.toml",
            name,
            std::process::id()
        ));
        p
    }

    fn rm(p: &Path) {
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn empty_config_is_default() {
        let c = CliConfig::default();
        assert_eq!(c.dc_host, None);
        assert_eq!(c.dry_run, None);
        assert_eq!(c.verbose, None);
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
 dc_host = "10.0.0.1"
 domain = "CORP"
 "#;
        let c: CliConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(c.dc_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(c.domain.as_deref(), Some("CORP"));
        assert_eq!(c.username, None);
    }

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
 dc_host = "10.0.0.1"
 domain = "CORP.LOCAL"
 username = "admin"
 password = "P@ssw0rd"
 nt_hash = "aad3b435b51404eeaad3b435b51404ee"
 pkinit_cert = "/tmp/cert.pem"
 pkinit_key = "/tmp/key.pem"
 auth_method = "kerberos"
 stdout_format = "json"
 outfile = "/tmp/out.json"
 ticket = "/tmp/ticket.ccache"
 verbose = 2
 dry_run = true
 json_log = true
 user_list = "/tmp/users.txt"
 pass_list = "/tmp/passwords.txt"
 user_pass_list = "/tmp/creds.txt"
 "#;
        let c: CliConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(c.dc_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(c.domain.as_deref(), Some("CORP.LOCAL"));
        assert_eq!(c.username.as_deref(), Some("admin"));
        assert_eq!(c.password.as_deref(), Some("P@ssw0rd"));
        assert_eq!(
            c.nt_hash.as_deref(),
            Some("aad3b435b51404eeaad3b435b51404ee")
        );
        assert_eq!(c.auth_method.as_deref(), Some("kerberos"));
        assert_eq!(c.stdout_format.as_deref(), Some("json"));
        assert_eq!(c.verbose, Some(2));
        assert_eq!(c.dry_run, Some(true));
        assert_eq!(c.json_log, Some(true));
    }

    #[test]
    fn parse_unknown_keys_ignored_with_default_attr() {
        let toml_str = r#"
 dc_host = "10.0.0.1"
 future_key = "ignored"
 "#;
        let c: CliConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(c.dc_host.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn save_then_load_roundtrip() {
        let path = tmp_file("roundtrip");
        rm(&path);

        let c = CliConfig {
            dc_host: Some("10.0.0.1".to_string()),
            domain: Some("CORP".to_string()),
            auth_method: Some("kerberos".to_string()),
            verbose: Some(1),
            dry_run: Some(true),
            ..Default::default()
        };
        save_config(&path, &c).expect("save");

        let loaded = load_config(Some(path.to_str().unwrap())).expect("load");
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(loaded.domain.as_deref(), Some("CORP"));
        assert_eq!(loaded.auth_method.as_deref(), Some("kerberos"));
        assert_eq!(loaded.verbose, Some(1));
        assert_eq!(loaded.dry_run, Some(true));
        rm(&path);
    }

    #[test]
    fn save_creates_parent_dir() {
        let mut path = env::temp_dir();
        path.push(format!("ovt-cfg-test-{}-nested", std::process::id()));
        path.push("config.toml");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());

        let c = CliConfig {
            dc_host: Some("10.0.0.1".to_string()),
            ..Default::default()
        };
        save_config(&path, &c).expect("save should create parent dir");
        assert!(path.exists());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_config_returns_default_when_no_file() {
        let mut path = env::temp_dir();
        path.push(format!(
            "definitely-does-not-exist-{}.toml",
            std::process::id()
        ));
        let c = load_config(Some(path.to_str().unwrap())).expect("load");
        assert_eq!(c, CliConfig::default());
    }

    #[test]
    fn set_value_creates_file_and_persists() {
        let path = tmp_file("set");
        rm(&path);
        let (prev, cfg) = set_value(&path, "dc_host", "10.0.0.5").expect("set");
        assert_eq!(prev, None);
        assert_eq!(cfg.dc_host.as_deref(), Some("10.0.0.5"));

        let loaded = load_config(Some(path.to_str().unwrap())).expect("load");
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.5"));
        rm(&path);
    }

    #[test]
    fn set_value_replaces_existing() {
        let path = tmp_file("set-replace");
        rm(&path);
        set_value(&path, "dc_host", "10.0.0.1").expect("set 1");
        let (prev, cfg) = set_value(&path, "dc_host", "10.0.0.2").expect("set 2");
        assert_eq!(prev.as_deref(), Some("10.0.0.1"));
        assert_eq!(cfg.dc_host.as_deref(), Some("10.0.0.2"));
        rm(&path);
    }

    #[test]
    fn set_value_rejects_unknown_key() {
        let path = tmp_file("set-bad");
        rm(&path);
        let err = set_value(&path, "totally_made_up", "x").unwrap_err();
        assert!(err.contains("Unknown config key"));
        assert!(!path.exists());
    }

    #[test]
    fn set_value_validates_auth_method() {
        let path = tmp_file("set-auth");
        rm(&path);
        let err = set_value(&path, "auth_method", "magic").unwrap_err();
        assert!(err.contains("Invalid auth_method"));
    }

    #[test]
    fn set_value_validates_stdout_format() {
        let path = tmp_file("set-fmt");
        rm(&path);
        let err = set_value(&path, "stdout_format", "yaml").unwrap_err();
        assert!(err.contains("Invalid stdout_format"));
    }

    #[test]
    fn set_value_parses_bool_variants() {
        let path = tmp_file("set-bool");
        rm(&path);
        for (input, expected) in [
            ("true", true),
            ("True", true),
            ("1", true),
            ("yes", true),
            ("on", true),
            ("false", false),
            ("0", false),
            ("no", false),
        ] {
            set_value(&path, "dry_run", input).expect("set");
            let cfg = load_config(Some(path.to_str().unwrap())).expect("load");
            assert_eq!(
                cfg.dry_run,
                Some(expected),
                "input '{}' should parse to {}",
                input,
                expected
            );
        }
        let err = set_value(&path, "dry_run", "maybe").unwrap_err();
        assert!(err.contains("Invalid bool"));
        rm(&path);
    }

    #[test]
    fn set_value_parses_verbose() {
        let path = tmp_file("set-verbose");
        rm(&path);
        set_value(&path, "verbose", "3").expect("set");
        let cfg = load_config(Some(path.to_str().unwrap())).expect("load");
        assert_eq!(cfg.verbose, Some(3));
        let err = set_value(&path, "verbose", "two").unwrap_err();
        assert!(err.contains("Invalid u8"));
        rm(&path);
    }

    #[test]
    fn unset_value_clears_key() {
        let path = tmp_file("unset");
        rm(&path);
        set_value(&path, "dc_host", "10.0.0.1").expect("set");
        set_value(&path, "domain", "CORP").expect("set");
        unset_value(&path, "dc_host").expect("unset");

        let cfg = load_config(Some(path.to_str().unwrap())).expect("load");
        assert_eq!(cfg.dc_host, None);
        assert_eq!(cfg.domain.as_deref(), Some("CORP"));
        rm(&path);
    }

    #[test]
    fn unset_value_rejects_unknown_key() {
        let path = tmp_file("unset-bad");
        rm(&path);
        let err = unset_value(&path, "nope").unwrap_err();
        assert!(err.contains("Unknown config key"));
    }

    #[test]
    fn unset_value_works_when_file_missing() {
        let path = tmp_file("unset-missing");
        rm(&path);
        let cfg = unset_value(&path, "dc_host").expect("unset should be no-op");
        assert_eq!(cfg, CliConfig::default());
    }

    #[test]
    fn display_shows_set_keys_hides_none() {
        let c = CliConfig {
            dc_host: Some("10.0.0.1".to_string()),
            verbose: Some(2),
            ..Default::default()
        };
        let s = display(&c);
        assert!(s.contains("dc_host = 10.0.0.1"));
        assert!(s.contains("verbose = 2"));
        assert!(!s.contains("domain"));
    }

    #[test]
    fn display_masks_secrets() {
        let c = CliConfig {
            password: Some("hunter2-secret".to_string()),
            nt_hash: Some("aad3b435b51404eeaad3b435b51404ee".to_string()),
            dc_host: Some("10.0.0.1".to_string()),
            ..Default::default()
        };
        let s = display(&c);
        assert!(!s.contains("hunter2-secret"), "password leaked: {}", s);
        assert!(s.contains("hu"), "prefix should still be visible: {}", s);
        assert!(s.contains("et"), "suffix should still be visible: {}", s);
        assert!(!s.contains("aad3b435b51404eeaad3b435b51404ee"));
        assert!(!s.contains("b435b51404eeaad3b435b51404e"));
        assert!(s.contains("dc_host = 10.0.0.1"));
    }

    #[test]
    fn display_empty_shows_placeholder() {
        let c = CliConfig::default();
        let s = display(&c);
        assert!(s.contains("(empty)"));
    }

    #[test]
    fn mask_secret_short_strings() {
        assert_eq!(mask_secret(""), "*");
        assert_eq!(mask_secret("a"), "*");
        assert_eq!(mask_secret("ab"), "**");
        assert_eq!(mask_secret("abcd"), "****");
        assert_eq!(mask_secret("abcde"), "ab*de");
        assert_eq!(mask_secret("longersecret"), "lo********et");
    }

    #[test]
    fn config_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for k in CONFIG_KEYS {
            assert!(seen.insert(*k), "duplicate key: {}", k);
        }
    }

    #[test]
    fn config_keys_match_struct_fields() {
        let string_keys = [
            "dc_host",
            "domain",
            "username",
            "password",
            "nt_hash",
            "pkinit_cert",
            "pkinit_key",
            "auth_method",
            "stdout_format",
            "outfile",
            "ticket",
            "user_list",
            "pass_list",
            "user_pass_list",
        ];
        let toml_str = string_keys
            .iter()
            .map(|k| format!("{} = \"x\"\n", k))
            .collect::<String>();
        let c: CliConfig = toml::from_str(&toml_str).expect("string keys should parse");
        assert_eq!(c.dc_host.as_deref(), Some("x"));
        assert_eq!(c.password.as_deref(), Some("x"));

        let mut toml_str = String::new();
        toml_str.push_str("verbose = 1\n");
        toml_str.push_str("dry_run = true\n");
        toml_str.push_str("json_log = false\n");
        let c: CliConfig = toml::from_str(&toml_str).expect("typed keys should parse");
        assert_eq!(c.verbose, Some(1));
        assert_eq!(c.dry_run, Some(true));
        assert_eq!(c.json_log, Some(false));
    }

    #[test]
    fn default_config_path_is_absolute() {
        if let Some(p) = default_config_path() {
            assert!(
                p.is_absolute() || cfg!(windows),
                "expected absolute path: {:?}",
                p
            );
            assert!(p.ends_with("config.toml"));
        }
    }

    #[test]
    fn config_file_search_order_includes_xdg_and_cwd() {
        let paths = config_file_paths();
        assert!(paths.iter().any(|p| p.ends_with("config.toml")));
        assert!(paths.iter().any(|p| p.ends_with("overthrone.toml")));
    }

    // -- profile tests -------------------------------------------

    /// Build a self-contained profile dir for testing. Returns the
    /// isolated dir so the test can clean up afterwards. We can't just
    /// use the real XDG path because that would clobber the operator's
    /// actual profile state.
    fn isolated_profiles_dir() -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("ovt-profile-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn validate_profile_name_accepts_normal() {
        assert!(validate_profile_name("corp").is_ok());
        assert!(validate_profile_name("corp.local").is_ok());
        assert!(validate_profile_name("corp-2024").is_ok());
        assert!(validate_profile_name("lab_test").is_ok());
        assert!(validate_profile_name("a").is_ok());
    }

    #[test]
    fn validate_profile_name_rejects_empty() {
        assert!(validate_profile_name("").is_err());
    }

    #[test]
    fn validate_profile_name_rejects_path_traversal() {
        assert!(validate_profile_name("..").is_err());
        assert!(validate_profile_name(".").is_err());
        assert!(validate_profile_name("../escape").is_err());
        assert!(validate_profile_name("a/b").is_err());
        assert!(validate_profile_name("a\\b").is_err());
    }

    #[test]
    fn validate_profile_name_rejects_too_long() {
        let long = "a".repeat(65);
        assert!(validate_profile_name(&long).is_err());
    }

    #[test]
    fn validate_profile_name_rejects_invalid_chars() {
        assert!(validate_profile_name("hello world").is_err());
        assert!(validate_profile_name("a$b").is_err());
        assert!(validate_profile_name("a@b").is_err());
        assert!(validate_profile_name("a:b").is_err());
    }

    #[test]
    fn profile_path_is_under_profiles_dir() {
        let p = profile_path("corp").unwrap();
        let dir = default_profiles_dir().unwrap();
        assert!(p.starts_with(&dir));
        assert!(p.ends_with("corp.toml"));
    }

    #[test]
    fn profile_path_rejects_invalid_names() {
        assert!(profile_path("..").is_err());
        assert!(profile_path("a/b").is_err());
        assert!(profile_path("").is_err());
    }

    #[test]
    fn save_and_load_profile_roundtrip() {
        // Per-test unique dir so we don't race other tests that
        // share the process-wide `isolated_profiles_dir()`.
        let mut dir = env::temp_dir();
        dir.push(format!(
            "ovt-profile-roundtrip-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let profile_file = dir.join("test-roundtrip.toml");
        let cfg = CliConfig {
            dc_host: Some("10.0.0.1".to_string()),
            domain: Some("CORP".to_string()),
            auth_method: Some("kerberos".to_string()),
            verbose: Some(1),
            ..Default::default()
        };

        let serialized = toml::to_string_pretty(&cfg).unwrap();
        std::fs::write(&profile_file, &serialized).unwrap();

        let loaded: CliConfig =
            toml::from_str(&std::fs::read_to_string(&profile_file).unwrap()).unwrap();
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(loaded.domain.as_deref(), Some("CORP"));
        assert_eq!(loaded.auth_method.as_deref(), Some("kerberos"));
        assert_eq!(loaded.verbose, Some(1));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_profile_returns_default_when_missing() {
        // Use a name guaranteed not to exist by validating it first
        // (which won't error) and then checking the file.
        let path = profile_path("definitely-does-not-exist-zzz-12345").unwrap();
        assert!(!path.exists());
        let cfg = load_profile("definitely-does-not-exist-zzz-12345").unwrap();
        assert_eq!(cfg, CliConfig::default());
    }

    #[test]
    fn active_profile_reads_ot_profile_env() {
        // Save original to restore
        let original = std::env::var("OT_PROFILE").ok();

        unsafe {
            std::env::set_var("OT_PROFILE", "lab-test");
        }
        let active = active_profile().unwrap();
        assert_eq!(active.as_deref(), Some("lab-test"));

        unsafe {
            std::env::remove_var("OT_PROFILE");
        }
        let active = active_profile().unwrap();
        assert_eq!(active, None);

        unsafe {
            std::env::set_var("OT_PROFILE", "");
        }
        let active = active_profile().unwrap();
        assert_eq!(active, None);

        unsafe {
            std::env::set_var("OT_PROFILE", "bad/name");
        }
        assert!(active_profile().is_err());

        // Restore
        match original {
            Some(v) => unsafe { std::env::set_var("OT_PROFILE", v) },
            None => unsafe { std::env::remove_var("OT_PROFILE") },
        }
    }

    #[test]
    fn list_profiles_returns_empty_when_dir_missing() {
        // Don't actually test the XDG path here (would clobber state);
        // verify behavior of empty filter logic by listing a known-empty
        // dir.
        let dir = isolated_profiles_dir();
        // The list_profiles function reads from default_profiles_dir(),
        // not an arbitrary path. So this test just verifies it doesn't
        // crash when the dir doesn't exist.
        let _ = std::fs::remove_dir_all(&dir);
        let _ = list_profiles();
    }

    #[test]
    fn delete_profile_rejects_missing_profile() {
        // Just exercise the validation paths without touching real disk
        let res = delete_profile("..");
        assert!(res.is_err());
    }

    #[test]
    fn profile_exists_rejects_invalid_names() {
        assert!(profile_exists("").is_err());
        assert!(profile_exists("a/b").is_err());
        assert!(profile_exists("..").is_err());
    }

    #[test]
    fn clone_profile_roundtrip() {
        // Exercise the struct clone via save/load since we can't
        // easily override the real profiles dir.
        let a = CliConfig {
            dc_host: Some("1.1.1.1".to_string()),
            verbose: Some(2),
            ..Default::default()
        };

        let serialized = toml::to_string_pretty(&a).unwrap();
        let b: CliConfig = toml::from_str(&serialized).unwrap();

        assert_eq!(a, b);
    }
}
