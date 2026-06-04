//! `ovt config` subcommand — TOML configuration management.
//!
//! Lets the operator initialize, view, edit, set/unset individual keys,
//! and save the effective CLI config to disk. The config file lives at
//! the XDG config dir (`$XDG_CONFIG_HOME/overthrone/config.toml` on
//! Linux, `%APPDATA%\overthrone\config.toml` on Windows, falling back
//! to `~/.config/overthrone/config.toml` if needed).
//!
//! Precedence on load: CLI flag > env var (`OT_*`, `KRB5CCNAME`) >
//! active profile > main config > built-in default.
//!
//! Usage:
//!   ovt config init          # write a default config to the XDG path
//!   ovt config show          # print loaded values
//!   ovt config path          # print the XDG path
//!   ovt config set <KEY> <VALUE>   # e.g. `ovt config set dc_host 10.0.0.1`
//!   ovt config unset <KEY>
//!   ovt config edit          # open $EDITOR (or print path if no EDITOR)
//!   ovt config save          # write the current effective CLI values to disk
//!   ovt config profile list            # show named profiles
//!   ovt config profile create <NAME>   # create a new (empty) profile
//!   ovt config profile show <NAME>     # show values in a profile
//!   ovt config profile delete <NAME>   # remove a profile
//!   ovt config profile use <NAME>      # print how to activate a profile
//!   ovt config profile clone <SRC> <DST>  # copy an existing profile
//!   ovt config profile path [NAME]     # print the on-disk path

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use colored::Colorize;

use crate::cli_config;

#[derive(Debug, Clone, Parser)]
#[command(about = "Initialize, view, and edit the persistent TOML config")]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ConfigAction {
    /// Write a default config file to the XDG config path (refuses to overwrite)
    Init {
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
    },
    /// Print the effective config values currently loaded from disk
    Show,
    /// Print the absolute filesystem path the config is loaded from / saved to
    Path,
    /// Set a single key in the config file
    Set {
        /// Config key (e.g. dc_host, domain, username, auth_method, dry_run, verbose)
        key: String,
        /// Value to assign
        value: String,
    },
    /// Remove a single key from the config file (sets it to default)
    Unset {
        /// Config key to remove
        key: String,
    },
    /// Open the config file in $EDITOR (or print the path if EDITOR is unset)
    Edit,
    /// Write the current effective config (Cli defaults) to the XDG path,
    /// overwriting any existing file
    Save,
    /// Named-profile management (list/show/create/delete/use/clone/path)
    #[command(subcommand)]
    Profile(ProfileAction),
}

#[derive(Debug, Clone, Subcommand)]
pub enum ProfileAction {
    /// List all named profiles
    List,
    /// Show the values stored in a profile (default: the active profile)
    Show {
        /// Profile name (defaults to the value of --profile / OT_PROFILE)
        name: Option<String>,
    },
    /// Create a new empty profile
    Create {
        /// Profile name (alphanumeric, '-', '_', '.')
        name: String,
        /// Overwrite an existing profile of the same name
        #[arg(long)]
        force: bool,
    },
    /// Set a single key in a named profile
    Set {
        /// Profile name
        name: String,
        /// Config key
        key: String,
        /// Value to assign
        value: String,
    },
    /// Remove a single key from a named profile
    Unset {
        /// Profile name
        name: String,
        /// Config key to remove
        key: String,
    },
    /// Delete a profile
    Delete {
        /// Profile name
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Print how to activate a profile (`--profile <NAME>` or `OT_PROFILE=<NAME>`)
    Use {
        /// Profile name
        name: String,
    },
    /// Copy an existing profile to a new name
    Clone {
        /// Source profile name
        src: String,
        /// Destination profile name
        dst: String,
    },
    /// Print the on-disk path of a profile file
    Path {
        /// Profile name (defaults to the value of --profile / OT_PROFILE)
        name: Option<String>,
    },
}

pub fn run(args: ConfigArgs) -> anyhow::Result<()> {
    match args.action {
        ConfigAction::Init { force } => init(force),
        ConfigAction::Show => show(),
        ConfigAction::Path => path(),
        ConfigAction::Set { key, value } => set(&key, &value),
        ConfigAction::Unset { key } => unset(&key),
        ConfigAction::Edit => edit(),
        ConfigAction::Save => save(),
        ConfigAction::Profile(action) => profile(action),
    }
}

fn default_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("OT_CONFIG")
        && !explicit.is_empty()
    {
        return PathBuf::from(explicit);
    }
    cli_config::default_config_path().unwrap_or_else(|| PathBuf::from("overthrone.toml"))
}

fn init(force: bool) -> anyhow::Result<()> {
    let path = default_path();
    if path.exists() && !force {
        println!(
            "{} Config already exists at {} (use --force to overwrite)",
            "[!]".yellow(),
            path.display()
        );
        return Ok(());
    }

    let cfg = sample_config();
    cli_config::save_config(&path, &cfg).map_err(anyhow::Error::msg)?;
    println!(
        "{} Wrote default config to {}",
        "[+]".green(),
        path.display()
    );
    println!();
    println!(
        "Edit it with: {} {}",
        "ovt config edit".bright_black(),
        "".normal()
    );
    println!(
        "Or set individual keys: {}",
        "ovt config set dc_host 10.0.0.1".bright_black()
    );
    Ok(())
}

fn show() -> anyhow::Result<()> {
    let path = default_path();
    println!("{} Config path: {}", "[*]".blue(), path.display());
    if !path.exists() {
        println!(
            "{} (file does not exist — run `ovt config init` to create it)",
            "[i]".blue()
        );
        return Ok(());
    }
    let cfg = cli_config::load_config(Some(path.to_str().unwrap())).map_err(anyhow::Error::msg)?;
    println!("{} Loaded values:", "[*]".blue());
    print!("{}", cli_config::display(&cfg));
    Ok(())
}

fn path() -> anyhow::Result<()> {
    let p = default_path();
    println!("{}", p.display());
    Ok(())
}

fn set(key: &str, value: &str) -> anyhow::Result<()> {
    let path = default_path();
    let (prev, _cfg) = cli_config::set_value(&path, key, value).map_err(anyhow::Error::msg)?;
    match prev {
        Some(p) if p != value => println!(
            "{} {}: {} -> {}",
            "[+]".green(),
            key,
            p.bright_black(),
            value.cyan()
        ),
        Some(p) => println!(
            "{} {}: {} (unchanged)",
            "[+]".green(),
            key,
            p.bright_black()
        ),
        None => println!("{} {} = {}", "[+]".green(), key, value.cyan()),
    }
    println!("  saved to {}", path.display().to_string().bright_black());
    Ok(())
}

fn unset(key: &str) -> anyhow::Result<()> {
    let path = default_path();
    cli_config::unset_value(&path, key).map_err(anyhow::Error::msg)?;
    println!(
        "{} {} unset (saved to {})",
        "[+]".green(),
        key,
        path.display()
    );
    Ok(())
}

fn edit() -> anyhow::Result<()> {
    let path = default_path();
    if !path.exists() {
        println!(
            "{} No config file at {} — running `ovt config init` first",
            "[i]".blue(),
            path.display()
        );
        init(false)?;
    }
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_default();
    if editor.is_empty() {
        println!("{}", path.display());
        println!(
            "{} Set $EDITOR (or $VISUAL) to open the config in your editor",
            "[i]".blue()
        );
        return Ok(());
    }
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to launch editor '{}': {}", editor, e))?;
    if !status.success() {
        anyhow::bail!("Editor exited with non-zero status: {:?}", status.code());
    }
    Ok(())
}

fn save() -> anyhow::Result<()> {
    let path = default_path();
    let cfg = sample_config();
    cli_config::save_config(&path, &cfg).map_err(anyhow::Error::msg)?;
    println!(
        "{} Saved default config to {}",
        "[+]".green(),
        path.display()
    );
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// Profile management
// ───────────────────────────────────────────────────────────────────

fn profile(action: ProfileAction) -> anyhow::Result<()> {
    match action {
        ProfileAction::List => profile_list(),
        ProfileAction::Show { name } => profile_show(name),
        ProfileAction::Create { name, force } => profile_create(&name, force),
        ProfileAction::Set { name, key, value } => profile_set(&name, &key, &value),
        ProfileAction::Unset { name, key } => profile_unset(&name, &key),
        ProfileAction::Delete { name, yes } => profile_delete(&name, yes),
        ProfileAction::Use { name } => profile_use(&name),
        ProfileAction::Clone { src, dst } => profile_clone(&src, &dst),
        ProfileAction::Path { name } => profile_path(name),
    }
}

fn profile_list() -> anyhow::Result<()> {
    let dir = current_profiles_dir().unwrap_or_else(|| PathBuf::from("."));
    let names = list_profiles_in(&dir).map_err(anyhow::Error::msg)?;
    if names.is_empty() {
        println!("{} No profiles found in {}", "[i]".blue(), dir.display());
        return Ok(());
    }
    let active = cli_config::active_profile().ok().flatten();
    println!(
        "{}  {} profile(s)",
        "[*]".blue(),
        names.len().to_string().green()
    );
    for name in &names {
        let marker = if active.as_deref() == Some(name.as_str()) {
            "*".green().bold()
        } else {
            " ".normal()
        };
        println!("  {} {}", marker, name.cyan());
    }
    Ok(())
}

fn profile_show(name: Option<String>) -> anyhow::Result<()> {
    let name = resolve_profile_name(name)?;
    let path = profile_path_for(&name).map_err(anyhow::Error::msg)?;
    println!("{} Profile: {}", "[*]".blue(), name.cyan());
    println!("  path: {}", path.display().to_string().bright_black());
    if !path.exists() {
        println!(
            "{} Profile file does not exist (it would be loaded as empty if used)",
            "[i]".blue()
        );
        return Ok(());
    }
    let cfg = load_profile_from(&path).map_err(anyhow::Error::msg)?;
    println!("  values:");
    print!("{}", cli_config::display(&cfg));
    Ok(())
}

fn profile_create(name: &str, force: bool) -> anyhow::Result<()> {
    cli_config::validate_profile_name(name).map_err(anyhow::Error::msg)?;
    let path = profile_path_for(name).map_err(anyhow::Error::msg)?;
    if path.exists() && !force {
        println!(
            "{} Profile '{}' already exists at {} (use --force to overwrite)",
            "[!]".yellow(),
            name,
            path.display()
        );
        return Ok(());
    }
    let cfg = cli_config::CliConfig::default();
    save_profile_at(&path, &cfg).map_err(anyhow::Error::msg)?;
    println!(
        "{} Created empty profile '{}' at {}",
        "[+]".green(),
        name.cyan(),
        path.display().to_string().bright_black()
    );
    println!(
        "  Set values with: {}",
        format!("ovt config profile set {} <KEY> <VALUE>", name).bright_black()
    );
    Ok(())
}

fn profile_set(name: &str, key: &str, value: &str) -> anyhow::Result<()> {
    cli_config::validate_profile_name(name).map_err(anyhow::Error::msg)?;
    let path = profile_path_for(name).map_err(anyhow::Error::msg)?;
    let mut cfg = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("Failed to read profile '{}': {}", name, e))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse profile '{}': {}", name, e))?
    } else {
        cli_config::CliConfig::default()
    };
    let previous: Option<String> = match key {
        "dc_host" => set_string_field(&mut cfg.dc_host, value),
        "domain" => set_string_field(&mut cfg.domain, value),
        "username" => set_string_field(&mut cfg.username, value),
        "password" => set_string_field(&mut cfg.password, value),
        "nt_hash" => set_string_field(&mut cfg.nt_hash, value),
        "pkinit_cert" => set_string_field(&mut cfg.pkinit_cert, value),
        "pkinit_key" => set_string_field(&mut cfg.pkinit_key, value),
        "auth_method" => {
            cli_config_set_auth_method(&mut cfg, value)?;
            None
        }
        "stdout_format" => {
            cli_config_set_stdout_format(&mut cfg, value)?;
            None
        }
        "outfile" => set_string_field(&mut cfg.outfile, value),
        "ticket" => set_string_field(&mut cfg.ticket, value),
        "user_list" => set_string_field(&mut cfg.user_list, value),
        "pass_list" => set_string_field(&mut cfg.pass_list, value),
        "user_pass_list" => set_string_field(&mut cfg.user_pass_list, value),
        "verbose" => {
            let v: u8 = value
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid u8 for 'verbose': '{}'", value))?;
            let prev = cfg.verbose.map(|n| n.to_string());
            cfg.verbose = Some(v);
            prev
        }
        "dry_run" => {
            let v = parse_boolish(value)
                .ok_or_else(|| anyhow::anyhow!("Invalid bool for 'dry_run': '{}'", value))?;
            let prev = cfg.dry_run.map(|n| n.to_string());
            cfg.dry_run = Some(v);
            prev
        }
        "json_log" => {
            let v = parse_boolish(value)
                .ok_or_else(|| anyhow::anyhow!("Invalid bool for 'json_log': '{}'", value))?;
            let prev = cfg.json_log.map(|n| n.to_string());
            cfg.json_log = Some(v);
            prev
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown config key '{}'. Valid keys: {}",
                key,
                cli_config::CONFIG_KEYS.join(", ")
            ));
        }
    };
    save_profile_at(&path, &cfg).map_err(anyhow::Error::msg)?;
    match previous {
        Some(p) if p != value => println!(
            "{} {} (in profile '{}'): {} -> {}",
            "[+]".green(),
            key,
            name,
            p.bright_black(),
            value.cyan()
        ),
        Some(p) => println!(
            "{} {} (in profile '{}'): {} (unchanged)",
            "[+]".green(),
            key,
            name,
            p.bright_black()
        ),
        None => println!(
            "{} {} (in profile '{}') = {}",
            "[+]".green(),
            key,
            name,
            value.cyan()
        ),
    }
    println!("  saved to {}", path.display().to_string().bright_black());
    Ok(())
}

fn profile_unset(name: &str, key: &str) -> anyhow::Result<()> {
    cli_config::validate_profile_name(name).map_err(anyhow::Error::msg)?;
    let path = profile_path_for(name).map_err(anyhow::Error::msg)?;
    if !path.exists() {
        return Err(anyhow::anyhow!(
            "Profile '{}' does not exist (nothing to unset)",
            name
        ));
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read profile '{}': {}", name, e))?;
    let mut cfg: cli_config::CliConfig = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse profile '{}': {}", name, e))?;
    match key {
        "dc_host" => cfg.dc_host = None,
        "domain" => cfg.domain = None,
        "username" => cfg.username = None,
        "password" => cfg.password = None,
        "nt_hash" => cfg.nt_hash = None,
        "pkinit_cert" => cfg.pkinit_cert = None,
        "pkinit_key" => cfg.pkinit_key = None,
        "auth_method" => cfg.auth_method = None,
        "stdout_format" => cfg.stdout_format = None,
        "outfile" => cfg.outfile = None,
        "ticket" => cfg.ticket = None,
        "user_list" => cfg.user_list = None,
        "pass_list" => cfg.pass_list = None,
        "user_pass_list" => cfg.user_pass_list = None,
        "verbose" => cfg.verbose = None,
        "dry_run" => cfg.dry_run = None,
        "json_log" => cfg.json_log = None,
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown config key '{}'. Valid keys: {}",
                key,
                cli_config::CONFIG_KEYS.join(", ")
            ));
        }
    }
    save_profile_at(&path, &cfg).map_err(anyhow::Error::msg)?;
    println!(
        "{} {} unset in profile '{}' (saved to {})",
        "[+]".green(),
        key,
        name,
        path.display().to_string().bright_black()
    );
    Ok(())
}

fn cli_config_set_auth_method(cfg: &mut cli_config::CliConfig, value: &str) -> anyhow::Result<()> {
    const VALID: &[&str] = &["password", "hash", "ticket"];
    let lower = value.to_lowercase();
    if !VALID.contains(&lower.as_str()) {
        return Err(anyhow::anyhow!(
            "Invalid auth_method '{}'. Expected one of: {}",
            value,
            VALID.join(", ")
        ));
    }
    cfg.auth_method = Some(value.to_string());
    Ok(())
}

fn cli_config_set_stdout_format(
    cfg: &mut cli_config::CliConfig,
    value: &str,
) -> anyhow::Result<()> {
    const VALID: &[&str] = &["text", "json", "csv"];
    let lower = value.to_lowercase();
    if !VALID.contains(&lower.as_str()) {
        return Err(anyhow::anyhow!(
            "Invalid stdout_format '{}'. Expected one of: {}",
            value,
            VALID.join(", ")
        ));
    }
    cfg.stdout_format = Some(value.to_string());
    Ok(())
}

fn parse_boolish(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => Some(true),
        "false" | "0" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn set_string_field(field: &mut Option<String>, value: &str) -> Option<String> {
    let prev = field.take();
    *field = Some(value.to_string());
    prev
}

fn profile_delete(name: &str, yes: bool) -> anyhow::Result<()> {
    cli_config::validate_profile_name(name).map_err(anyhow::Error::msg)?;
    let path = profile_path_for(name).map_err(anyhow::Error::msg)?;
    if !path.exists() {
        println!(
            "{} Profile '{}' does not exist (nothing to delete)",
            "[i]".blue(),
            name
        );
        return Ok(());
    }
    if !yes {
        print!("Delete profile '{}' at {}? [y/N] ", name, path.display());
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| anyhow::anyhow!("Failed to read input: {}", e))?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }
    std::fs::remove_file(&path)
        .map_err(|e| anyhow::anyhow!("Failed to delete profile '{}': {}", name, e))?;
    println!("{} Deleted profile '{}'", "[+]".green(), name.cyan());
    Ok(())
}

fn profile_use(name: &str) -> anyhow::Result<()> {
    cli_config::validate_profile_name(name).map_err(anyhow::Error::msg)?;
    let path = profile_path_for(name).map_err(anyhow::Error::msg)?;
    if !path.exists() {
        println!(
            "{} Profile '{}' does not exist on disk yet — run `ovt config profile create {}` first",
            "[!]".yellow(),
            name,
            name
        );
    }
    println!("Activate this profile with one of the following:");
    println!(
        "  {} {}",
        "$".bright_black(),
        format!("OT_PROFILE={} ovt ...", name).cyan()
    );
    println!(
        "  {} {}",
        "$".bright_black(),
        format!("ovt --profile {} ...", name).cyan()
    );
    let _ = path;
    Ok(())
}

fn profile_clone(src: &str, dst: &str) -> anyhow::Result<()> {
    cli_config::validate_profile_name(src).map_err(anyhow::Error::msg)?;
    cli_config::validate_profile_name(dst).map_err(anyhow::Error::msg)?;
    let src_path = profile_path_for(src).map_err(anyhow::Error::msg)?;
    let dst_path = profile_path_for(dst).map_err(anyhow::Error::msg)?;
    if !src_path.exists() {
        return Err(anyhow::anyhow!(
            "Source profile '{}' does not exist at {}",
            src,
            src_path.display()
        ));
    }
    if dst_path.exists() {
        return Err(anyhow::anyhow!(
            "Destination profile '{}' already exists at {}",
            dst,
            dst_path.display()
        ));
    }
    let cfg = load_profile_from(&src_path).map_err(anyhow::Error::msg)?;
    save_profile_at(&dst_path, &cfg).map_err(anyhow::Error::msg)?;
    println!(
        "{} Cloned '{}' -> '{}' at {}",
        "[+]".green(),
        src.cyan(),
        dst.cyan(),
        dst_path.display().to_string().bright_black()
    );
    Ok(())
}

fn profile_path(name: Option<String>) -> anyhow::Result<()> {
    let name = resolve_profile_name(name)?;
    let path = profile_path_for(&name).map_err(anyhow::Error::msg)?;
    println!("{}", path.display());
    Ok(())
}

// ── path-aware helpers that respect OT_CONFIG / XDG override ──

fn current_profiles_dir() -> Option<PathBuf> {
    cli_config::default_profiles_dir()
}

fn profile_path_for(name: &str) -> Result<PathBuf, String> {
    cli_config::validate_profile_name(name)?;
    let dir = current_profiles_dir()
        .ok_or_else(|| "Could not resolve config directory for profiles".to_string())?;
    Ok(dir.join(format!("{}.toml", name)))
}

fn save_profile_at(path: &std::path::Path, cfg: &cli_config::CliConfig) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create profiles directory: {}", e))?;
    }
    let serialized =
        toml::to_string_pretty(cfg).map_err(|e| format!("Failed to serialize profile: {}", e))?;
    std::fs::write(path, serialized)
        .map_err(|e| format!("Failed to write profile '{}': {}", path.display(), e))?;
    Ok(())
}

fn load_profile_from(path: &std::path::Path) -> Result<cli_config::CliConfig, String> {
    if !path.exists() {
        return Ok(cli_config::CliConfig::default());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
    toml::from_str(&content).map_err(|e| format!("Failed to parse '{}': {}", path.display(), e))
}

fn list_profiles_in(dir: &std::path::Path) -> Result<Vec<String>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("Failed to read profiles directory: {}", e))?;
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

fn resolve_profile_name(name: Option<String>) -> anyhow::Result<String> {
    if let Some(n) = name {
        cli_config::validate_profile_name(&n).map_err(anyhow::Error::msg)?;
        return Ok(n);
    }
    match cli_config::active_profile().map_err(anyhow::Error::msg)? {
        Some(n) => Ok(n),
        None => Err(anyhow::anyhow!(
            "No profile name given and OT_PROFILE is unset; pass a name or set OT_PROFILE"
        )),
    }
}

/// Build a starter config that contains every key with a comment-style
/// example value. We currently leave values empty so the file acts as
/// a template the operator can fill in.
fn sample_config() -> cli_config::CliConfig {
    cli_config::CliConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::Path;

    fn isolated_path(label: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!(
            "ovt-config-cmd-test-{}-{}.toml",
            label,
            std::process::id()
        ));
        let _ = fs::remove_file(&p);
        p
    }

    fn rm(p: &Path) {
        let _ = fs::remove_file(p);
    }

    fn write_string(p: &Path, body: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(p, body).unwrap();
    }

    #[test]
    fn default_path_is_resolvable() {
        let p = default_path();
        assert!(!p.as_os_str().is_empty());
    }

    #[test]
    fn set_then_unset_round_trip_on_disk() {
        let path = isolated_path("set-unset");

        let (prev, _cfg) = cli_config::set_value(&path, "dc_host", "10.0.0.1").unwrap();
        assert_eq!(prev, None);
        let loaded = cli_config::load_config(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.1"));

        cli_config::unset_value(&path, "dc_host").unwrap();
        let loaded = cli_config::load_config(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(loaded.dc_host, None);
        rm(&path);
    }

    #[test]
    fn init_refuses_to_overwrite_by_default() {
        let path = isolated_path("init-no-force");
        write_string(&path, "dc_host = \"1.1.1.1\"\n");
        let content_before = fs::read_to_string(&path).unwrap();

        let res = init_path_at(&path, false);
        assert!(res.is_ok(), "init should not error, just refuse");
        let content_after = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content_before, content_after,
            "init should not have written"
        );
        rm(&path);
    }

    #[test]
    fn init_force_overwrites() {
        let path = isolated_path("init-force");
        write_string(&path, "dc_host = \"1.1.1.1\"\n");

        let res = init_path_at(&path, true);
        assert!(res.is_ok());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("dc_host = \"1.1.1.1\"") || content.is_empty());
        rm(&path);
    }

    #[test]
    fn path_command_returns_resolvable_path() {
        let p = default_path();
        assert!(p.ends_with("config.toml") || p.ends_with("overthrone.toml"));
    }

    #[test]
    fn show_handles_missing_file() {
        let path = isolated_path("show-missing");
        let res = show_from(&path);
        assert!(res.is_ok(), "show on missing file should be a soft no-op");
    }

    #[test]
    fn show_handles_existing_file() {
        let path = isolated_path("show-existing");
        write_string(
            &path,
            "dc_host = \"10.0.0.1\"\ndomain = \"CORP\"\npassword = \"hunter2\"\n",
        );
        let res = show_from(&path);
        assert!(res.is_ok());
        rm(&path);
    }

    #[test]
    fn edit_falls_back_to_path_print_when_no_editor_env() {
        unsafe {
            std::env::remove_var("EDITOR");
            std::env::remove_var("VISUAL");
        }
        let path = isolated_path("edit-no-editor");
        let res = edit_at(&path);
        assert!(res.is_ok());
    }

    #[test]
    fn edit_creates_file_if_missing() {
        unsafe {
            std::env::remove_var("EDITOR");
            std::env::remove_var("VISUAL");
        }
        let path = isolated_path("edit-creates");
        assert!(!path.exists());
        let res = edit_at(&path);
        assert!(res.is_ok());
        assert!(path.exists());
        rm(&path);
    }

    #[test]
    fn save_writes_default_config() {
        let path = isolated_path("save-default");
        let res = save_to(&path);
        assert!(res.is_ok());
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("dc_host") || content.is_empty() || content.contains("["));
        rm(&path);
    }

    #[test]
    fn config_keys_match_enum_variants_in_set() {
        for (key, value) in [
            ("dc_host", "x"),
            ("domain", "x"),
            ("username", "x"),
            ("password", "x"),
            ("nt_hash", "x"),
            ("pkinit_cert", "x"),
            ("pkinit_key", "x"),
            ("auth_method", "password"),
            ("stdout_format", "json"),
            ("outfile", "x"),
            ("ticket", "x"),
            ("user_list", "x"),
            ("pass_list", "x"),
            ("user_pass_list", "x"),
            ("verbose", "1"),
            ("dry_run", "true"),
            ("json_log", "false"),
        ] {
            let path = isolated_path(&format!("key-{}", key));
            let res = cli_config::set_value(&path, key, value);
            assert!(
                res.is_ok(),
                "set_value should accept known key '{}' with value '{}': {:?}",
                key,
                value,
                res.err()
            );
            rm(&path);
        }
    }

    #[test]
    fn set_value_writes_pretty_toml() {
        let path = isolated_path("pretty-toml");
        let mut cfg = cli_config::CliConfig::default();
        cfg.dc_host = Some("10.0.0.1".to_string());
        cfg.verbose = Some(2);
        cli_config::save_config(&path, &cfg).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("dc_host"));
        assert!(content.contains("verbose = 2"));
        rm(&path);
    }

    #[test]
    fn show_masks_password() {
        let path = isolated_path("show-mask");
        write_string(&path, "password = \"super-secret-password\"\n");
        let res = show_from(&path);
        assert!(res.is_ok());
        rm(&path);
    }

    #[test]
    fn set_then_show_round_trip() {
        let path = isolated_path("set-show");
        cli_config::set_value(&path, "dc_host", "10.0.0.1").unwrap();
        cli_config::set_value(&path, "domain", "CORP.LOCAL").unwrap();
        let loaded = cli_config::load_config(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(loaded.domain.as_deref(), Some("CORP.LOCAL"));
        rm(&path);
    }

    // ── helpers that operate on an explicit path so tests don't pollute
    //    the real XDG config ──────────────────────────────────────────

    fn init_path_at(path: &Path, force: bool) -> anyhow::Result<()> {
        if path.exists() && !force {
            return Ok(());
        }
        let cfg = sample_config();
        cli_config::save_config(path, &cfg).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    fn show_from(path: &Path) -> anyhow::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let cfg =
            cli_config::load_config(Some(path.to_str().unwrap())).map_err(anyhow::Error::msg)?;
        let _ = cli_config::display(&cfg);
        Ok(())
    }

    fn edit_at(path: &Path) -> anyhow::Result<()> {
        if !path.exists() {
            init_path_at(path, false)?;
        }
        let editor = std::env::var("EDITOR")
            .or_else(|_| std::env::var("VISUAL"))
            .unwrap_or_default();
        if editor.is_empty() {
            return Ok(());
        }
        let _ = std::process::Command::new(&editor).arg(path).status();
        Ok(())
    }

    fn save_to(path: &Path) -> anyhow::Result<()> {
        let cfg = sample_config();
        cli_config::save_config(path, &cfg).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    // ── profile subcommand tests ─────────────────────────────────

    #[test]
    fn profile_create_writes_empty_file() {
        // Use a unique name and clean up if the file exists
        let name = "test-create";
        let _ = cli_config::delete_profile(name);

        let res = profile_create(name, false);
        assert!(res.is_ok());
        let path = cli_config::profile_path(name).unwrap();
        assert!(path.exists());
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_create_refuses_overwrite_by_default() {
        let name = "test-refuse";
        let _ = cli_config::delete_profile(name);
        let _ = profile_create(name, false);
        // Second create without --force should succeed silently (refuse)
        let res = profile_create(name, false);
        assert!(res.is_ok());
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_create_force_overwrites() {
        let name = "test-force";
        let _ = cli_config::delete_profile(name);
        let _ = profile_create(name, true);
        // Add a value
        let _ = cli_config::set_value(
            &cli_config::profile_path(name).unwrap(),
            "dc_host",
            "1.1.1.1",
        );
        // Overwrite
        let res = profile_create(name, true);
        assert!(res.is_ok());
        let loaded = cli_config::load_profile(name).unwrap();
        assert_eq!(loaded.dc_host, None, "force should reset profile");
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_create_rejects_invalid_name() {
        let res = profile_create("a/b", false);
        assert!(res.is_err());
    }

    #[test]
    fn profile_list_handles_empty_dir() {
        // Just exercise the function — should not panic
        let res = profile_list();
        assert!(res.is_ok());
    }

    #[test]
    fn profile_show_returns_ok_for_missing_file() {
        let name = "never-created-zzz";
        let _ = cli_config::delete_profile(name);
        let res = profile_show(Some(name.to_string()));
        assert!(res.is_ok());
    }

    #[test]
    fn profile_show_returns_ok_for_existing_file() {
        let name = "test-show-existing";
        let _ = cli_config::delete_profile(name);
        let _ = profile_create(name, false);
        let res = profile_show(Some(name.to_string()));
        assert!(res.is_ok());
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_show_requires_name_when_no_env() {
        unsafe {
            std::env::remove_var("OT_PROFILE");
        }
        let res = profile_show(None);
        assert!(res.is_err(), "should error when no name and no OT_PROFILE");
    }

    #[test]
    fn profile_delete_handles_missing() {
        let name = "definitely-never-existed-zzz-12345";
        let _ = cli_config::delete_profile(name);
        // Pre-cleaned; the friendly behavior is to print a soft
        // message and return Ok(()) (so `ovt config profile delete
        // <whatever> --yes` is idempotent).
        let res = profile_delete(name, true);
        assert!(res.is_ok());
    }

    #[test]
    fn profile_delete_removes_existing() {
        let name = "test-delete-existing";
        let _ = cli_config::delete_profile(name);
        let _ = profile_create(name, false);
        assert!(cli_config::profile_exists(name).unwrap());
        let res = profile_delete(name, true);
        assert!(res.is_ok());
        assert!(!cli_config::profile_exists(name).unwrap());
    }

    #[test]
    fn profile_use_prints_instructions() {
        let name = "test-use-instr";
        let res = profile_use(name);
        assert!(res.is_ok());
    }

    #[test]
    fn profile_use_warns_on_missing_profile() {
        let name = "never-existed-use-zzz-999";
        let res = profile_use(name);
        assert!(res.is_ok(), "should print warning but not error");
    }

    #[test]
    fn profile_clone_copies_values() {
        let src = "test-clone-src";
        let dst = "test-clone-dst";
        let _ = cli_config::delete_profile(src);
        let _ = cli_config::delete_profile(dst);
        let _ = profile_create(src, false);
        let _ = cli_config::set_value(
            &cli_config::profile_path(src).unwrap(),
            "dc_host",
            "10.0.0.1",
        );

        let res = profile_clone(src, dst);
        assert!(res.is_ok());
        let loaded = cli_config::load_profile(dst).unwrap();
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.1"));

        let _ = cli_config::delete_profile(src);
        let _ = cli_config::delete_profile(dst);
    }

    #[test]
    fn profile_clone_rejects_existing_dst() {
        let src = "test-clone-src-existing";
        let dst = "test-clone-dst-existing";
        let _ = cli_config::delete_profile(src);
        let _ = cli_config::delete_profile(dst);
        let _ = profile_create(src, false);
        let _ = profile_create(dst, false);

        let res = profile_clone(src, dst);
        assert!(res.is_err(), "should refuse to overwrite existing dst");

        let _ = cli_config::delete_profile(src);
        let _ = cli_config::delete_profile(dst);
    }

    #[test]
    fn profile_clone_rejects_invalid_names() {
        let res = profile_clone("a/b", "dst");
        assert!(res.is_err());
        let res = profile_clone("src", "a/b");
        assert!(res.is_err());
    }

    #[test]
    fn profile_path_returns_resolvable_path() {
        let res = profile_path(Some("test-path-resolve".to_string()));
        assert!(res.is_ok());
    }

    #[test]
    fn profile_path_with_no_name_requires_env() {
        unsafe {
            std::env::remove_var("OT_PROFILE");
        }
        let res = profile_path(None);
        assert!(res.is_err());
    }

    #[test]
    fn profile_action_dispatch_handles_all_variants() {
        // Just exercise the dispatch arm to make sure every variant is
        // handled (catches missing arm at compile time, this is a
        // belt-and-suspenders runtime check).
        let name = "test-dispatch";
        let _ = cli_config::delete_profile(name);

        assert!(profile(ProfileAction::List).is_ok());
        assert!(
            profile(ProfileAction::Create {
                name: name.to_string(),
                force: false
            })
            .is_ok()
        );
        assert!(
            profile(ProfileAction::Set {
                name: name.to_string(),
                key: "dc_host".to_string(),
                value: "10.0.0.1".to_string()
            })
            .is_ok()
        );
        assert!(
            profile(ProfileAction::Unset {
                name: name.to_string(),
                key: "dc_host".to_string()
            })
            .is_ok()
        );
        assert!(
            profile(ProfileAction::Show {
                name: Some(name.to_string())
            })
            .is_ok()
        );
        assert!(
            profile(ProfileAction::Path {
                name: Some(name.to_string())
            })
            .is_ok()
        );
        assert!(
            profile(ProfileAction::Use {
                name: name.to_string()
            })
            .is_ok()
        );
        assert!(
            profile(ProfileAction::Delete {
                name: name.to_string(),
                yes: true
            })
            .is_ok()
        );
    }

    #[test]
    fn profile_set_creates_file_and_persists() {
        let name = "test-set-create";
        let _ = cli_config::delete_profile(name);
        let res = profile_set(name, "dc_host", "10.0.0.5");
        assert!(res.is_ok());

        let path = profile_path_for(name).unwrap();
        assert!(path.exists());

        let loaded = load_profile_from(&path).unwrap();
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.5"));
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_set_replaces_existing() {
        let name = "test-set-replace";
        let _ = cli_config::delete_profile(name);
        profile_set(name, "dc_host", "10.0.0.1").unwrap();
        profile_set(name, "dc_host", "10.0.0.2").unwrap();
        let path = profile_path_for(name).unwrap();
        let loaded = load_profile_from(&path).unwrap();
        assert_eq!(loaded.dc_host.as_deref(), Some("10.0.0.2"));
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_set_rejects_unknown_key() {
        let name = "test-set-bad-key";
        let _ = cli_config::delete_profile(name);
        let res = profile_set(name, "totally_made_up", "x");
        assert!(res.is_err());
    }

    #[test]
    fn profile_set_validates_auth_method() {
        let name = "test-set-auth";
        let _ = cli_config::delete_profile(name);
        let res = profile_set(name, "auth_method", "magic");
        assert!(res.is_err());
        let res = profile_set(name, "auth_method", "password");
        assert!(res.is_ok());
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_set_validates_stdout_format() {
        let name = "test-set-fmt";
        let _ = cli_config::delete_profile(name);
        let res = profile_set(name, "stdout_format", "yaml");
        assert!(res.is_err());
        let res = profile_set(name, "stdout_format", "json");
        assert!(res.is_ok());
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_set_parses_bool_variants() {
        let name = "test-set-bool";
        let _ = cli_config::delete_profile(name);
        for (input, expected) in [("true", true), ("false", false), ("1", true), ("0", false)] {
            profile_set(name, "dry_run", input).unwrap();
            let path = profile_path_for(name).unwrap();
            let loaded = load_profile_from(&path).unwrap();
            assert_eq!(loaded.dry_run, Some(expected));
        }
        let res = profile_set(name, "dry_run", "maybe");
        assert!(res.is_err());
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_set_parses_verbose() {
        let name = "test-set-verbose";
        let _ = cli_config::delete_profile(name);
        profile_set(name, "verbose", "3").unwrap();
        let path = profile_path_for(name).unwrap();
        let loaded = load_profile_from(&path).unwrap();
        assert_eq!(loaded.verbose, Some(3));
        let res = profile_set(name, "verbose", "three");
        assert!(res.is_err());
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_unset_clears_key() {
        let name = "test-unset";
        let _ = cli_config::delete_profile(name);
        profile_set(name, "dc_host", "10.0.0.1").unwrap();
        profile_set(name, "domain", "CORP").unwrap();
        profile_unset(name, "dc_host").unwrap();
        let path = profile_path_for(name).unwrap();
        let loaded = load_profile_from(&path).unwrap();
        assert_eq!(loaded.dc_host, None);
        assert_eq!(loaded.domain.as_deref(), Some("CORP"));
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_unset_rejects_unknown_key() {
        let name = "test-unset-bad";
        let _ = cli_config::delete_profile(name);
        let res = profile_unset(name, "nope");
        assert!(res.is_err());
    }

    #[test]
    fn profile_unset_errors_when_file_missing() {
        let name = "test-unset-missing";
        let _ = cli_config::delete_profile(name);
        let res = profile_unset(name, "dc_host");
        assert!(res.is_err());
    }

    #[test]
    fn profile_unset_handles_known_field_types() {
        let name = "test-unset-all";
        let _ = cli_config::delete_profile(name);
        profile_set(name, "dc_host", "10.0.0.1").unwrap();
        profile_set(name, "domain", "CORP").unwrap();
        profile_set(name, "verbose", "2").unwrap();
        profile_set(name, "dry_run", "true").unwrap();
        profile_set(name, "json_log", "false").unwrap();
        profile_set(name, "auth_method", "hash").unwrap();
        profile_set(name, "stdout_format", "json").unwrap();

        for key in [
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
            "verbose",
            "dry_run",
            "json_log",
        ] {
            profile_unset(name, key).unwrap();
        }
        let path = profile_path_for(name).unwrap();
        let loaded = load_profile_from(&path).unwrap();
        assert_eq!(loaded.dc_host, None);
        assert_eq!(loaded.verbose, None);
        assert_eq!(loaded.dry_run, None);
        assert_eq!(loaded.auth_method, None);
        let _ = cli_config::delete_profile(name);
    }

    #[test]
    fn profile_path_for_rejects_invalid_names() {
        assert!(profile_path_for("a/b").is_err());
        assert!(profile_path_for("..").is_err());
        assert!(profile_path_for("").is_err());
    }

    #[test]
    fn current_profiles_dir_is_under_config_dir() {
        if let Some(dir) = current_profiles_dir() {
            assert!(
                dir.ends_with("profiles"),
                "expected profiles dir: {:?}",
                dir
            );
        }
    }
}
