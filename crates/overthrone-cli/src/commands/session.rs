//! Session management subcommand.
//!
//! The auto-pwn / wizard attack paths persist `EngagementState` to
//! `~/.overthrone/sessions/<name>.json` between runs. This subcommand
//! lets the operator inspect, inspect details of, and clean up those
//! saved sessions from the shell.
//!
//! Usage:
//!   ovt session list
//!   ovt session show corp.local-dc01
//!   ovt session delete corp.local-dc01
//!   ovt session clean --older-than 30d
//!   ovt session path corp.local-dc01
//!   ovt session stats

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use clap::{Parser, Subcommand};
use colored::Colorize;

use overthrone_pilot::goals::EngagementState;
use overthrone_pilot::session::{
    auto_session_path, default_session_dir, load_session, session_path,
};

#[derive(Debug, Clone, Parser)]
#[command(about = "List, inspect, and manage saved engagement sessions")]
pub struct SessionArgs {
    #[command(subcommand)]
    pub action: SessionAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SessionAction {
    /// List all saved engagement sessions
    List,
    /// Show details (counts, DA, target) for a saved session
    Show {
        /// Session name (the file stem inside ~/.overthrone/sessions/)
        name: String,
    },
    /// Delete a saved session file
    Delete {
        /// Session name
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Delete saved sessions older than the given age (e.g. 30d, 12h, 90m)
    Clean {
        /// Age threshold, formatted `<N><unit>` where unit is one of
        /// `m` (minutes), `h` (hours), `d` (days). Default: 30d
        #[arg(long, default_value = "30d")]
        older_than: String,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
        /// Dry run - print what would be deleted, do not delete
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the absolute filesystem path of a session file
    Path {
        /// Session name
        name: String,
    },
    /// Show summary statistics (count, total size, oldest/newest)
    Stats,
    /// Resolve a session name to its path and load+print summary
    /// (alias for `show`)
    Info {
        /// Session name
        name: String,
    },
}

pub fn run(args: SessionArgs) -> anyhow::Result<()> {
    match args.action {
        SessionAction::List => list_sessions(),
        SessionAction::Show { name } => show_session(&name, false),
        SessionAction::Info { name } => show_session(&name, false),
        SessionAction::Delete { name, yes } => delete_session(&name, yes),
        SessionAction::Clean {
            older_than,
            yes,
            dry_run,
        } => clean_sessions(&older_than, yes, dry_run),
        SessionAction::Path { name } => {
            let path = session_path(&name);
            println!("{}", path.display());
            Ok(())
        }
        SessionAction::Stats => show_stats(),
    }
}

// ───────────────────────────────────────────────────────────────────
// List
// ───────────────────────────────────────────────────────────────────

fn list_sessions() -> anyhow::Result<()> {
    let dir = default_session_dir();
    if !dir.exists() {
        println!(
            "{} Session directory does not exist: {}",
            "[i]".blue(),
            dir.display()
        );
        return Ok(());
    }

    let entries = read_session_dir(&dir)?;
    if entries.is_empty() {
        println!("{} No saved sessions in {}", "[i]".blue(), dir.display());
        return Ok(());
    }

    println!(
        "{}  {} saved session(s) in {}",
        "[*]".blue(),
        entries.len().to_string().green(),
        dir.display().to_string().bright_black()
    );
    println!();
    println!(
        "  {:<35}  {:<8}  {:<6}  {:<10}  {}",
        "NAME".bold(),
        "USERS".bold(),
        "CREDS".bold(),
        "DA".bold(),
        "SAVED".bold()
    );
    println!("  {}", "─".repeat(80).bright_black());

    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_by_key(|(name, _)| name.to_string());

    for (name, info) in sorted {
        let users = info
            .state
            .as_ref()
            .map(|s| s.users.len())
            .unwrap_or_default();
        let creds = info
            .state
            .as_ref()
            .map(|s| s.credentials.len())
            .unwrap_or_default();
        let da = info
            .state
            .as_ref()
            .map(|s| if s.has_domain_admin { "yes" } else { "no" })
            .unwrap_or("?");
        let saved = info
            .saved_at
            .as_deref()
            .map(|s| truncate(s, 19))
            .unwrap_or_else(|| "?".to_string());
        let da_colored = if da == "yes" {
            "yes".red().bold()
        } else {
            "no".dimmed()
        };
        println!(
            "  {:<35}  {:<8}  {:<6}  {:<10}  {}",
            truncate(name, 35),
            users,
            creds,
            da_colored,
            saved.bright_black()
        );
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// Show / Info
// ───────────────────────────────────────────────────────────────────

fn show_session(name: &str, _long: bool) -> anyhow::Result<()> {
    let path = session_path(name);
    if !path.exists() {
        anyhow::bail!("Session file does not exist: {}", path.display());
    }
    let state = load_session(&path).map_err(anyhow::Error::msg)?;
    print_session_summary(name, &path, &state);
    Ok(())
}

fn print_session_summary(name: &str, path: &Path, state: &EngagementState) {
    println!("{} Session: {}", "[*]".blue(), name.cyan().bold());
    println!("  Path:     {}", path.display().to_string().bright_black());
    if let Ok(meta) = fs::metadata(path) {
        if let Ok(modified) = meta.modified() {
            println!("  Modified: {}", format_systemtime(modified).bright_black());
        }
        println!("  Size:     {} bytes", meta.len());
    }
    println!();
    if let Some(d) = &state.domain {
        println!("  Domain:    {}", d.as_str().cyan());
    }
    if let Some(dc) = &state.dc_ip {
        println!("  DC IP:     {}", dc);
    }
    if let Some(dc_h) = &state.dc_hostname {
        println!("  DC Host:   {}", dc_h);
    }
    let da = if state.has_domain_admin {
        if let Some(u) = &state.da_user {
            format!("yes ({})", u)
        } else {
            "yes".to_string()
        }
    } else {
        "no".to_string()
    };
    let da_colored = if state.has_domain_admin {
        da.red().bold()
    } else {
        da.dimmed()
    };
    println!("  DA:        {}", da_colored);
    println!();
    println!("  Users:           {}", state.users.len());
    println!("  Computers:       {}", state.computers.len());
    println!("  Groups:          {}", state.groups.len());
    println!("  Credentials:     {}", state.credentials.len());
    println!("  Kerberoastable:  {}", state.kerberoastable.len());
    println!("  AS-REP roast:    {}", state.asrep_roastable.len());
    println!("  Cracked:         {}", state.cracked.len());
    println!("  LAPS:            {}", state.laps.len());
    println!("  GPOs:            {}", state.gpos.len());
    println!("  Trusts:          {}", state.trusts.len());
    println!("  Constrained:     {}", state.constrained_delegation.len());
    println!(
        "  Unconstrained:   {}",
        state.unconstrained_delegation.len()
    );
    println!("  RBCD targets:    {}", state.rbcd_targets.len());
    println!("  Loot items:      {}", state.loot.len());
    println!("  Action log:      {}", state.action_log.len());
    if let Some(policy) = &state.password_policy {
        println!();
        println!(
            "  Password policy: min_len={:?} complexity={} history={:?} lockout_threshold={:?}",
            policy.min_password_length,
            policy.password_complexity_enabled,
            policy.password_history_length,
            policy.lockout_threshold
        );
    }
}

// ───────────────────────────────────────────────────────────────────
// Delete
// ───────────────────────────────────────────────────────────────────

fn delete_session(name: &str, yes: bool) -> anyhow::Result<()> {
    let path = session_path(name);
    if !path.exists() {
        anyhow::bail!("Session file does not exist: {}", path.display());
    }
    if !yes {
        eprint!("Delete session file {} ? [y/N] ", path.display());
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to read confirmation: {}", e))?;
        if !matches!(buf.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }
    fs::remove_file(&path)
        .map_err(|e| anyhow::anyhow!("Failed to delete {}: {}", path.display(), e))?;
    println!("{} Deleted {}", "[+]".green(), path.display());
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// Clean (bulk age-based)
// ───────────────────────────────────────────────────────────────────

fn clean_sessions(spec: &str, yes: bool, dry_run: bool) -> anyhow::Result<()> {
    let threshold = parse_age(spec)
        .ok_or_else(|| anyhow::anyhow!("Invalid age spec '{}': expected <N><m|h|d>", spec))?;
    let dir = default_session_dir();
    if !dir.exists() {
        println!(
            "{} Session directory does not exist: {}",
            "[i]".blue(),
            dir.display()
        );
        return Ok(());
    }
    let entries = read_session_dir(&dir)?;
    if entries.is_empty() {
        println!("{} No saved sessions.", "[i]".blue());
        return Ok(());
    }

    let now = SystemTime::now();
    let mut to_delete: Vec<(String, PathBuf, SystemTime)> = Vec::new();
    for (name, info) in &entries {
        let Some(modified) = info.modified else {
            continue;
        };
        if let Ok(age) = now.duration_since(modified)
            && age >= threshold
        {
            to_delete.push((name.clone(), info.path.clone(), modified));
        }
    }
    if to_delete.is_empty() {
        println!(
            "{} No sessions older than {}",
            "[i]".blue(),
            humanize_duration(threshold)
        );
        return Ok(());
    }

    println!(
        "{} Found {} session(s) older than {}",
        "[*]".blue(),
        to_delete.len().to_string().yellow(),
        humanize_duration(threshold)
    );
    for (name, path, modified) in &to_delete {
        println!(
            "  {} {} (saved {})",
            if dry_run { "→".dimmed() } else { "✗".red() },
            name,
            format_systemtime(*modified).bright_black()
        );
        if !dry_run {
            let _ = path; // path is shown via name
        }
    }

    if dry_run {
        println!();
        println!("{} Dry run - no files deleted.", "[i]".blue());
        return Ok(());
    }
    if !yes {
        eprint!("Delete {} session(s)? [y/N] ", to_delete.len());
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to read confirmation: {}", e))?;
        if !matches!(buf.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let mut deleted = 0usize;
    for (_, path, _) in &to_delete {
        if fs::remove_file(path).is_ok() {
            deleted += 1;
        }
    }
    println!();
    println!(
        "{} Deleted {} session(s).",
        "[+]".green(),
        deleted.to_string().green()
    );
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// Stats
// ───────────────────────────────────────────────────────────────────

fn show_stats() -> anyhow::Result<()> {
    let dir = default_session_dir();
    if !dir.exists() {
        println!(
            "{} Session directory does not exist: {}",
            "[i]".blue(),
            dir.display()
        );
        return Ok(());
    }
    let entries = read_session_dir(&dir)?;
    if entries.is_empty() {
        println!("{} No saved sessions in {}", "[i]".blue(), dir.display());
        return Ok(());
    }

    let total_size: u64 = entries.values().map(|i| i.size_bytes).sum();
    let total_users: usize = entries
        .values()
        .filter_map(|i| i.state.as_ref().map(|s| s.users.len()))
        .sum();
    let total_creds: usize = entries
        .values()
        .filter_map(|i| i.state.as_ref().map(|s| s.credentials.len()))
        .sum();
    let da_sessions = entries
        .values()
        .filter(|i| {
            i.state
                .as_ref()
                .map(|s| s.has_domain_admin)
                .unwrap_or(false)
        })
        .count();

    let mut times: Vec<SystemTime> = entries.values().filter_map(|i| i.modified).collect();
    times.sort();

    println!(
        "{} Session directory: {}",
        "[*]".blue(),
        dir.display().to_string().bright_black()
    );
    println!("  Sessions:      {}", entries.len());
    println!(
        "  Total size:    {} ({})",
        total_size,
        humanize_bytes(total_size)
    );
    println!("  DA sessions:   {}", da_sessions);
    println!("  Sum users:     {}", total_users);
    println!("  Sum creds:     {}", total_creds);
    if let Some(oldest) = times.first() {
        println!("  Oldest:        {}", format_systemtime(*oldest));
    }
    if let Some(newest) = times.last() {
        println!("  Newest:        {}", format_systemtime(*newest));
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

struct SessionInfo {
    path: PathBuf,
    size_bytes: u64,
    modified: Option<SystemTime>,
    saved_at: Option<String>,
    state: Option<EngagementState>,
}

fn read_session_dir(dir: &Path) -> anyhow::Result<std::collections::BTreeMap<String, SessionInfo>> {
    let mut out = std::collections::BTreeMap::new();
    for entry in
        fs::read_dir(dir).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", dir.display(), e))?
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = meta.modified().ok();
        let size_bytes = meta.len();
        // Try to read envelope saved_at without loading the whole state
        let (saved_at, state) = match load_session(&path) {
            Ok(s) => {
                let saved_at = read_saved_at(&path);
                (saved_at, Some(s))
            }
            Err(_) => (None, None),
        };
        out.insert(
            name,
            SessionInfo {
                path,
                size_bytes,
                modified,
                saved_at,
                state,
            },
        );
    }
    Ok(out)
}

fn read_saved_at(path: &Path) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        saved_at: String,
    }
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str::<Envelope>(&data)
        .ok()
        .map(|e| e.saved_at)
}

fn parse_age(spec: &str) -> Option<Duration> {
    if spec.is_empty() {
        return None;
    }
    let (num, unit) = spec.split_at(spec.len() - 1);
    let n: u64 = num.parse().ok()?;
    match unit {
        "m" => Some(Duration::from_secs(n * 60)),
        "h" => Some(Duration::from_secs(n * 60 * 60)),
        "d" => Some(Duration::from_secs(n * 60 * 60 * 24)),
        _ => None,
    }
}

fn humanize_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

fn humanize_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if b >= GB {
        format!("{:.2} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.2} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.2} KB", b as f64 / KB as f64)
    } else {
        format!("{} B", b)
    }
}

fn format_systemtime(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.to_rfc3339()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

// Expose auto_session_path so other modules can use the canonical name
#[allow(dead_code)]
pub fn auto_path(dc_host: &str, domain: &str) -> PathBuf {
    auto_session_path(dc_host, domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use overthrone_pilot::goals::EngagementState;

    #[test]
    fn parse_age_minutes() {
        assert_eq!(parse_age("30m"), Some(Duration::from_secs(30 * 60)));
    }
    #[test]
    fn parse_age_hours() {
        assert_eq!(parse_age("2h"), Some(Duration::from_secs(2 * 60 * 60)));
    }
    #[test]
    fn parse_age_days() {
        assert_eq!(parse_age("7d"), Some(Duration::from_secs(7 * 60 * 60 * 24)));
    }
    #[test]
    fn parse_age_invalid() {
        assert!(parse_age("30").is_none());
        assert!(parse_age("x").is_none());
        assert!(parse_age("").is_none());
        assert!(parse_age("30s").is_none());
    }

    #[test]
    fn truncate_under_limit() {
        assert_eq!(truncate("hello", 10), "hello");
    }
    #[test]
    fn truncate_over_limit() {
        let s = truncate("hello world this is long", 10);
        assert!(s.chars().count() <= 10);
        assert!(s.ends_with('…'));
    }
    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn humanize_bytes_units() {
        assert_eq!(humanize_bytes(512), "512 B");
        assert!(humanize_bytes(2048).contains("KB"));
        assert!(humanize_bytes(5 * 1024 * 1024).contains("MB"));
        assert!(humanize_bytes(2 * 1024 * 1024 * 1024).contains("GB"));
    }

    #[test]
    fn humanize_duration_units() {
        assert_eq!(humanize_duration(Duration::from_secs(30)), "30s");
        assert_eq!(humanize_duration(Duration::from_secs(120)), "2m");
        assert_eq!(humanize_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(humanize_duration(Duration::from_secs(86_400)), "1d");
    }

    #[test]
    fn auto_path_delegates() {
        let p = auto_path("dc01.corp.local", "corp.local");
        assert!(p.to_string_lossy().contains("corp.local"));
        assert!(p.to_string_lossy().contains("dc01.corp.local"));
    }

    #[test]
    fn session_path_for_known_name() {
        let p = session_path("corp.local-dc01");
        let name = p.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "corp.local-dc01.json");
    }

    #[test]
    fn save_load_roundtrip_via_session_module() {
        let dir = std::env::temp_dir().join("ovt_session_cmd_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.json");
        let mut s = EngagementState {
            domain: Some("round.trip".into()),
            ..Default::default()
        };
        s.users.push(Default::default());
        overthrone_pilot::session::save_session(&path, &s).unwrap();
        let loaded = load_session(&path).unwrap();
        assert_eq!(loaded.domain, Some("round.trip".into()));
        assert_eq!(loaded.users.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_sessions_empty_dir_does_not_panic() {
        let dir = std::env::temp_dir().join("ovt_session_list_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // We can't redirect default_session_dir, but we can exercise
        // read_session_dir against a known-empty dir.
        let entries = read_session_dir(&dir).unwrap();
        assert!(entries.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_sessions_finds_written_files() {
        let dir = std::env::temp_dir().join("ovt_session_list_full");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Write one non-session file to ensure it's filtered out
        fs::write(dir.join("ignore.txt"), "noise").unwrap();
        // Write two session files
        let mut s1 = EngagementState {
            domain: Some("one.local".into()),
            ..Default::default()
        };
        s1.users.push(Default::default());
        overthrone_pilot::session::save_session(&dir.join("one.json"), &s1).unwrap();
        let s2 = EngagementState {
            domain: Some("two.local".into()),
            ..Default::default()
        };
        overthrone_pilot::session::save_session(&dir.join("two.json"), &s2).unwrap();
        let entries = read_session_dir(&dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains_key("one"));
        assert!(entries.contains_key("two"));
        assert!(!entries.contains_key("ignore"));
        let _ = fs::remove_dir_all(&dir);
    }
}
