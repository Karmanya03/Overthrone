//! Wordlist Auto-Discovery for SecLists, rockyou, and other wordlist sources.
//!
//! Provides a unified API for finding wordlists on the attacker's system.
//! Checks common paths for:
//! - SecLists (passwords, usernames, rules)
//! - rockyou.txt
//! - Custom user-specified paths
//!
//! Supports environment variable overrides via `OT_SECLISTS_DIR` and `OT_WORDLIST_DIR`.

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

/// Discovered wordlist path with metadata.
#[derive(Debug, Clone)]
pub struct WordlistPath {
    pub path: PathBuf,
    pub source: &'static str,
}

/// Category of wordlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordlistCategory {
    /// Password lists (rockyou, Common-Credentials, etc.)
    Password,
    /// Username lists (names, top-usernames, etc.)
    Username,
    /// Hashcat/John rules
    Rules,
}

/// Auto-detect wordlist paths for password attacks.
///
/// Priority:
/// 1. User-specified `custom_path` if provided and exists
/// 2. `OT_SECLISTS_DIR` / `OT_WORDLIST_DIR` env vars
/// 3. Common paths on Kali, Parrot, Ubuntu, Debian, Arch
pub fn find_password_wordlist(custom_path: Option<&str>) -> Option<WordlistPath> {
    // 1. Custom path
    if let Some(p) = custom_path {
        let path = PathBuf::from(p);
        if path.exists() {
            info!("Using custom password wordlist: {}", path.display());
            return Some(WordlistPath {
                path,
                source: "custom",
            });
        }
        warn!("Custom wordlist not found: {}", p);
    }

    // 2. Env var override
    if let Ok(dir) = std::env::var("OT_SECLISTS_DIR")
        && let Some(p) = find_in_seclists(&dir, WordlistCategory::Password)
    {
        return Some(p);
    }
    if let Ok(dir) = std::env::var("OT_WORDLIST_DIR") {
        let path = PathBuf::from(&dir).join("rockyou.txt");
        if path.exists() {
            return Some(WordlistPath {
                path,
                source: "OT_WORDLIST_DIR",
            });
        }
    }

    // 3. Common system paths
    let candidates = [
        // SecLists paths
        "/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt",
        "/usr/share/seclists/Passwords/rockyou.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/seclists/Passwords/bt2-password.txt",
        "/usr/share/seclists/Common-Credentials/rockyou.txt",
        "/usr/share/seclists/Passwords/10k-most-common.txt",
        "/opt/seclists/Passwords/Common-Credentials/rockyou.txt",
        "/opt/seclists/Passwords/rockyou.txt",
        // Kali / Parrot paths
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/rockyou/rockyou.txt",
        "/usr/share/wordlists/seclists/Passwords/Common-Credentials/rockyou.txt",
        // Other common locations
        "/opt/wordlists/rockyou.txt",
        "/opt/SecLists/Passwords/Common-Credentials/rockyou.txt",
        // wfuzz
        "/usr/share/wfuzz/wordlist/general/common.txt",
    ];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() {
            let source = if path.contains("seclists") || path.contains("SecLists") {
                "seclists"
            } else if path.contains("wordlist") {
                "system-wordlist"
            } else {
                "other"
            };
            info!("Found password wordlist: {} ({})", path, source);
            return Some(WordlistPath {
                path: p.to_path_buf(),
                source,
            });
        }
    }

    // Fallback: check if embedded wordlist is available
    debug!("No external password wordlist found; will use embedded fallback");
    None
}

/// Auto-detect username wordlist paths.
pub fn find_username_wordlist(custom_path: Option<&str>) -> Option<WordlistPath> {
    // 1. Custom path
    if let Some(p) = custom_path {
        let path = PathBuf::from(p);
        if path.exists() {
            info!("Using custom username wordlist: {}", path.display());
            return Some(WordlistPath {
                path,
                source: "custom",
            });
        }
        warn!("Custom username wordlist not found: {}", p);
    }

    // 2. Env var override
    if let Ok(dir) = std::env::var("OT_SECLISTS_DIR")
        && let Some(p) = find_in_seclists(&dir, WordlistCategory::Username)
    {
        return Some(p);
    }
    if let Ok(dir) = std::env::var("OT_WORDLIST_DIR") {
        let path = PathBuf::from(&dir).join("usernames.txt");
        if path.exists() {
            return Some(WordlistPath {
                path,
                source: "OT_WORDLIST_DIR",
            });
        }
    }

    // 3. Common system paths
    let candidates = [
        // SecLists usernames
        "/usr/share/seclists/Usernames/Names/names.txt",
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/seclists/Usernames/Names/name-rank-top100000.txt",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
        "/usr/share/seclists/Usernames/HackerOne-Hackerlist.txt",
        "/opt/seclists/Usernames/Names/names.txt",
        "/opt/seclists/Usernames/top-usernames-shortlist.txt",
        // System paths
        "/usr/share/wordlists/seclists/Usernames/Names/names.txt",
        "/usr/share/wordlists/names.txt",
        "/usr/share/dict/words",
        "/opt/wordlists/usernames.txt",
        "/usr/share/SecLists/Usernames/Names/names.txt",
    ];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() {
            let source = if path.contains("seclists") || path.contains("SecLists") {
                "seclists"
            } else {
                "system"
            };
            info!("Found username wordlist: {} ({})", path, source);
            return Some(WordlistPath {
                path: p.to_path_buf(),
                source,
            });
        }
    }

    debug!("No external username wordlist found; will use built-in list");
    None
}

/// Auto-detect hashcat/John rules files.
pub fn find_rules_file(custom_path: Option<&str>) -> Option<WordlistPath> {
    // 1. Custom path
    if let Some(p) = custom_path {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(WordlistPath {
                path,
                source: "custom",
            });
        }
        warn!("Custom rules file not found: {}", p);
    }

    // 2. Env var override
    if let Ok(dir) = std::env::var("OT_SECLISTS_DIR")
        && let Some(p) = find_in_seclists(&dir, WordlistCategory::Rules)
    {
        return Some(p);
    }

    // 3. Common system paths
    let candidates = [
        "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
        "/opt/hashcat/rules/OneRuleToRuleThemAll.rule",
        "/usr/share/wordlists/OneRuleToRuleThemAll.rule",
        "/usr/share/hashcat/rules/best64.rule",
        "/usr/share/hashcat/rules/d3ad0ne.rule",
        "/usr/share/hashcat/rules/toggles1.rule",
        "/usr/share/john/rules/john.lst",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz", // not a rule but sometimes used
    ];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() && path.ends_with(".rule") {
            info!("Found rules file: {}", path);
            return Some(WordlistPath {
                path: p.to_path_buf(),
                source: "system",
            });
        }
    }

    None
}

/// Probe the SecLists installation and return the root directory if found.
pub fn find_seclists_root() -> Option<PathBuf> {
    let candidates = [
        "/usr/share/seclists",
        "/opt/seclists",
        "/usr/share/SecLists",
        "/opt/SecLists",
        "/home/*/seclists",
        "/root/seclists",
    ];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() && p.is_dir() {
            return Some(p.to_path_buf());
        }
    }

    // Also check home directory
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let home_seclists = PathBuf::from(home).join("seclists");
        if home_seclists.exists() && home_seclists.is_dir() {
            return Some(home_seclists);
        }
    }

    None
}

/// Search within a SecLists directory for a wordlist matching the given category.
fn find_in_seclists(seclists_dir: &str, category: WordlistCategory) -> Option<WordlistPath> {
    let base = Path::new(seclists_dir);
    if !base.exists() {
        return None;
    }

    let subdirs = match category {
        WordlistCategory::Password => &[
            "Passwords/Common-Credentials",
            "Passwords",
            "Common-Credentials",
        ][..],
        WordlistCategory::Username => &["Usernames/Names", "Usernames"][..],
        WordlistCategory::Rules => &["Passwords/Rules", "Rules"][..],
    };

    let filenames = match category {
        WordlistCategory::Password => &[
            "rockyou.txt",
            "Common-Credentials.txt",
            "10k-most-common.txt",
            "bt2-password.txt",
        ][..],
        WordlistCategory::Username => &["names.txt", "top-usernames-shortlist.txt"][..],
        WordlistCategory::Rules => &["OneRuleToRuleThemAll.rule", "best64.rule"][..],
    };

    for subdir in subdirs {
        for filename in filenames {
            let path = base.join(subdir).join(filename);
            if path.exists() {
                info!(
                    "Found {} wordlist in SecLists: {}",
                    category_as_str(category),
                    path.display()
                );
                return Some(WordlistPath {
                    path,
                    source: "seclists",
                });
            }
        }
    }

    None
}

fn category_as_str(cat: WordlistCategory) -> &'static str {
    match cat {
        WordlistCategory::Password => "password",
        WordlistCategory::Username => "username",
        WordlistCategory::Rules => "rules",
    }
}

/// Print wordlist discovery status to the user.
pub fn print_wordlist_status(custom_password: Option<&str>, custom_username: Option<&str>) {
    println!("  {}", "--- Wordlist Discovery ---".bright_cyan());

    match find_password_wordlist(custom_password) {
        Some(wl) => println!(
            "    {} {} ({})",
            "[+]".green(),
            format!("Password wordlist: {}", wl.path.display()).green(),
            wl.source.bright_black()
        ),
        None => {
            if custom_password.is_some() {
                println!(
                    "    {} {}",
                    "[-]".red(),
                    "Custom password wordlist not found".red()
                );
            } else {
                println!(
                    "    {} {} {}",
                    "[*]".yellow(),
                    "No external password wordlist found.".yellow(),
                    "Using embedded fallback.".bright_black()
                );
                println!(
                    "    {} {}",
                    "    Tip:".bright_black(),
                    "Set OT_SECLISTS_DIR=/path/to/SecLists or install seclists.".bright_black()
                );
            }
        }
    }

    match find_username_wordlist(custom_username) {
        Some(wl) => println!(
            "    {} {} ({})",
            "[+]".green(),
            format!("Username wordlist: {}", wl.path.display()).green(),
            wl.source.bright_black()
        ),
        None => {
            if custom_username.is_some() {
                println!(
                    "    {} {}",
                    "[-]".red(),
                    "Custom username wordlist not found".red()
                );
            } else {
                println!(
                    "    {} {}",
                    "[*]".yellow(),
                    "No external username wordlist found. Using built-in list.".yellow()
                );
            }
        }
    }

    // Check seclists root
    match find_seclists_root() {
        Some(root) => println!("    {} SecLists root: {}", "[+]".green(), root.display()),
        None => println!(
            "    {} {}",
            "[*]".yellow(),
            "SecLists not installed (optional, improves wordlist coverage)".bright_black()
        ),
    }
}

use colored::Colorize;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ================================================================
    // Helper: create a temp dir with mock SecLists structure
    // ================================================================
    struct MockSecLists {
        root: tempfile::TempDir,
    }

    impl MockSecLists {
        /// Create a full SecLists tree with password, username, and rules files.
        fn create_full() -> Self {
            let root = tempfile::TempDir::new().unwrap();
            let r = root.path();

            // Password lists
            fs::create_dir_all(r.join("Passwords/Common-Credentials")).unwrap();
            fs::write(
                r.join("Passwords/Common-Credentials/rockyou.txt"),
                "password1\nletmein\nadmin\n",
            )
            .unwrap();
            fs::write(
                r.join("Passwords/Common-Credentials/10k-most-common.txt"),
                "pass1\nword2\n",
            )
            .unwrap();
            fs::write(
                r.join("Passwords/Common-Credentials/bt2-password.txt"),
                "bt2pass\n",
            )
            .unwrap();
            fs::write(r.join("Passwords/rockyou.txt"), "rockyou1\n").unwrap();
            fs::create_dir_all(r.join("Passwords/Leaked-Databases")).unwrap();
            fs::write(
                r.join("Passwords/Leaked-Databases/rockyou.txt"),
                "leaked1\n",
            )
            .unwrap();

            // Username lists
            fs::create_dir_all(r.join("Usernames/Names")).unwrap();
            fs::write(r.join("Usernames/Names/names.txt"), "alice\nbob\ncharlie\n").unwrap();
            fs::write(
                r.join("Usernames/top-usernames-shortlist.txt"),
                "admin\nroot\nuser\n",
            )
            .unwrap();
            fs::write(
                r.join("Usernames/Names/name-rank-top100000.txt"),
                "name1\nname2\n",
            )
            .unwrap();

            // Rules
            fs::create_dir_all(r.join("Passwords/Rules")).unwrap();
            fs::write(
                r.join("Passwords/Rules/OneRuleToRuleThemAll.rule"),
                ":\nc\ncu\n",
            )
            .unwrap();
            fs::write(r.join("Passwords/Rules/best64.rule"), ":\n!").unwrap();

            // Common-Credentials dir at root level
            fs::create_dir_all(r.join("Common-Credentials")).unwrap();
            fs::write(r.join("Common-Credentials/rockyou.txt"), "commonpass\n").unwrap();

            Self { root }
        }

        /// Create a minimal SecLists with only password files.
        fn create_passwords_only() -> Self {
            let root = tempfile::TempDir::new().unwrap();
            let r = root.path();
            fs::create_dir_all(r.join("Passwords/Common-Credentials")).unwrap();
            fs::write(
                r.join("Passwords/Common-Credentials/rockyou.txt"),
                "testpass\n",
            )
            .unwrap();
            Self { root }
        }

        /// Create a minimal SecLists with only username files.
        fn create_usernames_only() -> Self {
            let root = tempfile::TempDir::new().unwrap();
            let r = root.path();
            fs::create_dir_all(r.join("Usernames/Names")).unwrap();
            fs::write(r.join("Usernames/Names/names.txt"), "alice\nbob\n").unwrap();
            Self { root }
        }

        /// Create an empty SecLists (dir exists but no wordlists).
        fn create_empty() -> Self {
            let root = tempfile::TempDir::new().unwrap();
            fs::create_dir_all(root.path().join("Passwords")).unwrap();
            Self { root }
        }

        fn path_str(&self) -> &str {
            self.root.path().to_str().unwrap()
        }
    }

    // ================================================================
    // ================================================================
    // find_in_seclists tests (private fn, tested via env var manipulation)
    // ================================================================

    #[test]
    fn test_find_in_seclists_password_full() {
        let mock = MockSecLists::create_full();
        let result = find_in_seclists(mock.path_str(), WordlistCategory::Password);
        assert!(
            result.is_some(),
            "Should find password wordlist in full SecLists"
        );
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "seclists");
        // Should find rockyou.txt in Common-Credentials first
        assert!(
            wl.path.to_string_lossy().contains("rockyou.txt"),
            "Should find rockyou.txt, got: {}",
            wl.path.display()
        );
    }

    #[test]
    fn test_find_in_seclists_username_full() {
        let mock = MockSecLists::create_full();
        let result = find_in_seclists(mock.path_str(), WordlistCategory::Username);
        assert!(
            result.is_some(),
            "Should find username wordlist in full SecLists"
        );
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "seclists");
        assert!(
            wl.path.to_string_lossy().contains("names.txt"),
            "Should find names.txt, got: {}",
            wl.path.display()
        );
    }

    #[test]
    fn test_find_in_seclists_rules_full() {
        let mock = MockSecLists::create_full();
        let result = find_in_seclists(mock.path_str(), WordlistCategory::Rules);
        assert!(result.is_some(), "Should find rules in full SecLists");
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "seclists");
        assert!(wl.path.to_string_lossy().ends_with(".rule"));
    }

    #[test]
    fn test_find_in_seclists_passwords_only_no_username() {
        let mock = MockSecLists::create_passwords_only();
        // Password should work
        assert!(find_in_seclists(mock.path_str(), WordlistCategory::Password).is_some());
        // Username should fail
        assert!(find_in_seclists(mock.path_str(), WordlistCategory::Username).is_none());
    }

    #[test]
    fn test_find_in_seclists_usernames_only_no_password() {
        let mock = MockSecLists::create_usernames_only();
        // Username should work
        assert!(find_in_seclists(mock.path_str(), WordlistCategory::Username).is_some());
        // Password should fail
        assert!(find_in_seclists(mock.path_str(), WordlistCategory::Password).is_none());
    }

    #[test]
    fn test_find_in_seclists_empty_dir() {
        let mock = MockSecLists::create_empty();
        assert!(find_in_seclists(mock.path_str(), WordlistCategory::Password).is_none());
        assert!(find_in_seclists(mock.path_str(), WordlistCategory::Username).is_none());
        assert!(find_in_seclists(mock.path_str(), WordlistCategory::Rules).is_none());
    }

    #[test]
    fn test_find_in_seclists_nonexistent_dir() {
        assert!(
            find_in_seclists("/nonexistent/path/to/seclists", WordlistCategory::Password).is_none()
        );
    }

    // ================================================================
    // find_password_wordlist tests
    // ================================================================

    #[test]
    fn test_find_password_wordlist_custom_path_takes_priority() {
        let mock = MockSecLists::create_full();
        let custom = mock
            .root
            .path()
            .join("Passwords/Common-Credentials/rockyou.txt");
        let result = find_password_wordlist(Some(custom.to_str().unwrap()));
        assert!(result.is_some());
        let wl = result.unwrap();
        assert_eq!(wl.source, "custom");
        assert_eq!(wl.path, custom);
    }

    #[test]
    fn test_find_password_wordlist_custom_path_nonexistent() {
        let result = find_password_wordlist(Some("/nonexistent/path/wordlist.txt"));
        // Should not panic, should return None (or fall back to env/system paths)
        // On CI, there might be a real rockyou.txt so we just check no panic
        let _ = result;
    }

    #[test]
    fn test_find_password_wordlist_no_custom_no_panic() {
        // Without custom path, should either find system wordlist or return None
        let result = find_password_wordlist(None);
        if let Some(wl) = result {
            assert!(wl.path.exists());
        }
    }

    #[test]
    fn test_find_password_wordlist_via_env_seclists_dir() {
        let mock = MockSecLists::create_full();
        let orig = std::env::var("OT_SECLISTS_DIR").ok();

        unsafe {
            std::env::set_var("OT_SECLISTS_DIR", mock.path_str());
        }
        let result = find_password_wordlist(None);
        unsafe {
            std::env::remove_var("OT_SECLISTS_DIR");
        }

        assert!(result.is_some(), "Should find via OT_SECLISTS_DIR");
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "seclists");

        // Restore
        if let Some(v) = orig {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
    }

    #[test]
    fn test_find_password_wordlist_via_env_wordlist_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("rockyou.txt"), "word1\nword2\n").unwrap();
        let orig = std::env::var("OT_WORDLIST_DIR").ok();
        // Make sure OT_SECLISTS_DIR doesn't interfere
        let orig_seclists = std::env::var("OT_SECLISTS_DIR").ok();
        unsafe {
            std::env::remove_var("OT_SECLISTS_DIR");
        }

        unsafe {
            std::env::set_var("OT_WORDLIST_DIR", tmp.path().to_str().unwrap());
        }
        let result = find_password_wordlist(None);
        unsafe {
            std::env::remove_var("OT_WORDLIST_DIR");
        }

        assert!(result.is_some(), "Should find via OT_WORDLIST_DIR");
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "OT_WORDLIST_DIR");
        assert!(wl.path.to_string_lossy().contains("rockyou.txt"));

        // Restore
        if let Some(v) = orig {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
        if let Some(v) = orig_seclists {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
    }

    // ================================================================
    // find_username_wordlist tests
    // ================================================================

    #[test]
    fn test_find_username_wordlist_custom_path() {
        let mock = MockSecLists::create_full();
        let custom = mock.root.path().join("Usernames/Names/names.txt");
        let result = find_username_wordlist(Some(custom.to_str().unwrap()));
        assert!(result.is_some());
        let wl = result.unwrap();
        assert_eq!(wl.source, "custom");
    }

    #[test]
    fn test_find_username_wordlist_via_env_seclists_dir() {
        let mock = MockSecLists::create_full();
        let orig = std::env::var("OT_SECLISTS_DIR").ok();

        unsafe {
            std::env::set_var("OT_SECLISTS_DIR", mock.path_str());
        }
        let result = find_username_wordlist(None);
        unsafe {
            std::env::remove_var("OT_SECLISTS_DIR");
        }

        assert!(result.is_some(), "Should find via OT_SECLISTS_DIR");
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "seclists");

        if let Some(v) = orig {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
    }

    #[test]
    fn test_find_username_wordlist_via_env_wordlist_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("usernames.txt"), "alice\nbob\n").unwrap();
        let orig = std::env::var("OT_WORDLIST_DIR").ok();
        let orig_seclists = std::env::var("OT_SECLISTS_DIR").ok();
        unsafe {
            std::env::remove_var("OT_SECLISTS_DIR");
        }

        unsafe {
            std::env::set_var("OT_WORDLIST_DIR", tmp.path().to_str().unwrap());
        }
        let result = find_username_wordlist(None);
        unsafe {
            std::env::remove_var("OT_WORDLIST_DIR");
        }

        assert!(result.is_some(), "Should find via OT_WORDLIST_DIR");
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "OT_WORDLIST_DIR");

        if let Some(v) = orig {
            unsafe {
                std::env::set_var("OT_WORDLIST_DIR", v);
            }
        }
        if let Some(v) = orig_seclists {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
    }

    #[test]
    fn test_find_username_wordlist_no_seclists_fallback() {
        let orig = std::env::var("OT_SECLISTS_DIR").ok();
        let orig_wl = std::env::var("OT_WORDLIST_DIR").ok();
        unsafe {
            std::env::remove_var("OT_SECLISTS_DIR");
        }
        unsafe {
            std::env::remove_var("OT_WORDLIST_DIR");
        }

        // No env vars, no custom path — may or may not find system wordlist
        let result = find_username_wordlist(None);
        let _ = result; // Just verify no panic

        if let Some(v) = orig {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
        if let Some(v) = orig_wl {
            unsafe {
                std::env::set_var("OT_WORDLIST_DIR", v);
            }
        }
    }

    // ================================================================
    // find_rules_file tests
    // ================================================================

    #[test]
    fn test_find_rules_custom_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rule_file = tmp.path().join("custom.rule");
        fs::write(&rule_file, ":\nc\n").unwrap();

        let result = find_rules_file(Some(rule_file.to_str().unwrap()));
        assert!(result.is_some());
        let wl = result.unwrap();
        assert_eq!(wl.source, "custom");
        assert_eq!(wl.path, rule_file);
    }

    #[test]
    fn test_find_rules_nonexistent_custom() {
        let result = find_rules_file(Some("/nonexistent/rules.rule"));
        assert!(result.is_none());
    }

    #[test]
    fn test_find_rules_via_env_seclists() {
        let mock = MockSecLists::create_full();
        let orig = std::env::var("OT_SECLISTS_DIR").ok();

        unsafe {
            std::env::set_var("OT_SECLISTS_DIR", mock.path_str());
        }
        let result = find_rules_file(None);
        unsafe {
            std::env::remove_var("OT_SECLISTS_DIR");
        }

        assert!(result.is_some(), "Should find rules via OT_SECLISTS_DIR");
        let wl = result.unwrap();
        assert!(wl.path.exists());
        assert_eq!(wl.source, "seclists");

        if let Some(v) = orig {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
    }

    // ================================================================
    // find_seclists_root tests
    // ================================================================

    #[test]
    fn test_find_seclists_root_via_home() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fake_home = tmp.path().join("fakeuser");
        fs::create_dir_all(fake_home.join("seclists")).unwrap();

        let orig_home = std::env::var("HOME").ok();
        let orig_profile = std::env::var("USERPROFILE").ok();

        unsafe {
            std::env::set_var("HOME", fake_home.to_str().unwrap());
        }
        unsafe {
            std::env::remove_var("USERPROFILE");
        }
        // Remove standard paths so they don't interfere
        let orig_seclists = std::env::var("OT_SECLISTS_DIR").ok();

        let result = find_seclists_root();

        // Restore env
        if let Some(v) = orig_home {
            unsafe {
                std::env::set_var("HOME", v);
            }
        }
        if let Some(v) = orig_profile {
            unsafe {
                std::env::set_var("USERPROFILE", v);
            }
        }
        if let Some(v) = orig_seclists {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }

        // The result depends on whether standard paths exist on the test machine.
        // We just verify no panic.
        let _ = result;
    }

    // ================================================================
    // Edge case tests
    // ================================================================

    #[test]
    fn test_empty_string_custom_path() {
        // Empty string is not a valid path
        let result = find_password_wordlist(Some(""));
        // Should not panic
        let _ = result;
    }

    #[test]
    fn test_wordlist_path_clone() {
        let wp = WordlistPath {
            path: PathBuf::from("/test/path.txt"),
            source: "test",
        };
        let cloned = wp.clone();
        assert_eq!(cloned.path, wp.path);
        assert_eq!(cloned.source, wp.source);
    }

    #[test]
    fn test_wordlist_category_equality() {
        assert_eq!(WordlistCategory::Password, WordlistCategory::Password);
        assert_ne!(WordlistCategory::Password, WordlistCategory::Username);
        assert_ne!(WordlistCategory::Username, WordlistCategory::Rules);
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(category_as_str(WordlistCategory::Password), "password");
        assert_eq!(category_as_str(WordlistCategory::Username), "username");
        assert_eq!(category_as_str(WordlistCategory::Rules), "rules");
    }

    #[test]
    fn test_custom_path_overrides_env() {
        // Custom path should take priority even if env is set
        let mock = MockSecLists::create_full();
        let tmp = tempfile::TempDir::new().unwrap();
        let custom = tmp.path().join("my_wordlist.txt");
        fs::write(&custom, "custom_pass\n").unwrap();

        let orig = std::env::var("OT_SECLISTS_DIR").ok();
        unsafe {
            std::env::set_var("OT_SECLISTS_DIR", mock.path_str());
        }

        let result = find_password_wordlist(Some(custom.to_str().unwrap()));
        unsafe {
            std::env::remove_var("OT_SECLISTS_DIR");
        }

        assert!(result.is_some());
        let wl = result.unwrap();
        assert_eq!(wl.source, "custom");
        assert_eq!(wl.path, custom);

        if let Some(v) = orig {
            unsafe {
                std::env::set_var("OT_SECLISTS_DIR", v);
            }
        }
    }

    #[test]
    fn test_seclists_password_priority_order() {
        // Verify that Common-Credentials/rockyou.txt is found before Passwords/rockyou.txt
        let tmp = tempfile::TempDir::new().unwrap();
        let r = tmp.path();

        // Create both paths
        fs::create_dir_all(r.join("Passwords/Common-Credentials")).unwrap();
        fs::write(
            r.join("Passwords/Common-Credentials/rockyou.txt"),
            "commoncred_pass\n",
        )
        .unwrap();
        fs::write(r.join("Passwords/rockyou.txt"), "passwords_pass\n").unwrap();

        let result = find_in_seclists(r.to_str().unwrap(), WordlistCategory::Password);
        assert!(result.is_some());
        let wl = result.unwrap();
        // Should find Common-Credentials first
        assert!(
            wl.path.to_string_lossy().contains("Common-Credentials"),
            "Should prefer Common-Credentials/rockyou.txt, got: {}",
            wl.path.display()
        );
    }

    #[test]
    fn test_seclists_username_priority_order() {
        // Verify that Usernames/Names/names.txt is found before Usernames/top-usernames
        let tmp = tempfile::TempDir::new().unwrap();
        let r = tmp.path();

        fs::create_dir_all(r.join("Usernames/Names")).unwrap();
        fs::write(r.join("Usernames/Names/names.txt"), "alice\n").unwrap();
        fs::write(r.join("Usernames/top-usernames-shortlist.txt"), "admin\n").unwrap();

        let result = find_in_seclists(r.to_str().unwrap(), WordlistCategory::Username);
        assert!(result.is_some());
        let wl = result.unwrap();
        // Check that it found names.txt in the Names subdirectory (cross-platform)
        let path_str = wl.path.to_string_lossy().replace('\\', "/");
        assert!(
            path_str.contains("Usernames/Names/names.txt") || path_str.contains("Names/names.txt"),
            "Should prefer Usernames/Names/names.txt, got: {}",
            wl.path.display()
        );
    }

    #[test]
    fn test_seclists_rules_priority_order() {
        // Verify Passwords/Rules/OneRuleToRuleThemAll.rule is found first
        let tmp = tempfile::TempDir::new().unwrap();
        let r = tmp.path();

        fs::create_dir_all(r.join("Passwords/Rules")).unwrap();
        fs::write(r.join("Passwords/Rules/OneRuleToRuleThemAll.rule"), ":\n").unwrap();
        fs::create_dir_all(r.join("Rules")).unwrap();
        fs::write(r.join("Rules/best64.rule"), ":\n").unwrap();

        let result = find_in_seclists(r.to_str().unwrap(), WordlistCategory::Rules);
        assert!(result.is_some());
        let wl = result.unwrap();
        assert!(
            wl.path.to_string_lossy().contains("OneRuleToRuleThemAll"),
            "Should prefer OneRuleToRuleThemAll.rule, got: {}",
            wl.path.display()
        );
    }
}
