//! Smart Wordlist Generation from LDAP Enumeration Data
//!
//! Builds context-aware password candidate lists from AD enumeration results.
//! Enterprise passwords commonly follow predictable patterns based on:
//! - Company names and domain DNS names
//! - Seasonal patterns (Season + Year)
//! - Username-based variations
//! - Department, city, and description fields from AD attributes
//! - Common enterprise password mutations
//!
//! This replaces the static 10K embedded wordlist with a dynamic, targeted
//! generator that produces far higher cracking rates in real engagements.

use crate::proto::ldap::AdUser;
use std::collections::BTreeSet;
use tracing::debug;

/// A generator that builds context-aware password candidates from AD data.
///
/// # Example
/// ```ignore
/// let users = ldap_session.enumerate_users().await?;
/// let mut generator = SmartWordlist::new("corp.local");
/// generator.add_users(&users);
/// let wordlist = generator.generate();
/// ```
#[derive(Debug, Clone)]
pub struct SmartWordlist {
    /// Company name extracted from domain
    company: String,
    /// Set of password candidates (deduplicated, sorted)
    candidates: BTreeSet<String>,
    /// Minimum password length to include
    min_length: usize,
    /// Maximum password length to include
    max_length: usize,
    /// Include seasonal patterns (e.g., "Spring2025")
    include_seasonal: bool,
    /// Include username-based patterns
    include_username_patterns: bool,
    /// Include company name patterns
    include_company_patterns: bool,
    /// Include year-based patterns from 2019 to current year
    include_year_patterns: bool,
    /// Include common enterprise password suffixes
    include_common_suffixes: bool,
    /// Include AD description/city fields
    include_ad_attributes: bool,
}

impl SmartWordlist {
    /// Create a new wordlist generator for the given domain.
    pub fn new(domain: &str) -> Self {
        let company = domain.split('.').next().unwrap_or(domain).to_lowercase();

        Self {
            company,
            candidates: BTreeSet::new(),
            min_length: 4,
            max_length: 64,
            include_seasonal: true,
            include_username_patterns: true,
            include_company_patterns: true,
            include_year_patterns: true,
            include_common_suffixes: true,
            include_ad_attributes: true,
        }
    }

    /// Set minimum password length.
    pub fn with_min_length(mut self, min: usize) -> Self {
        self.min_length = min;
        self
    }

    /// Set maximum password length.
    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_length = max;
        self
    }

    /// Add all users from AD enumeration to generate username-based patterns.
    pub fn add_users(&mut self, users: &[AdUser]) {
        for user in users {
            let name = user.sam_account_name.to_lowercase();

            // Username itself as password (very common)
            self.insert(&name);

            // Username with common suffixes
            if self.include_common_suffixes {
                for suffix in COMMON_SUFFIXES {
                    self.insert(&format!("{name}{suffix}"));
                }
            }

            // Extract base username (before any numbers)
            let base: String = name.chars().take_while(|c| !c.is_ascii_digit()).collect();
            if !base.is_empty() && base.len() >= 3 {
                if self.include_year_patterns {
                    for year in COMMON_YEARS {
                        self.insert(&format!("{base}{year}"));
                        self.insert(&format!("{base}{year}!"));
                    }
                }
                if self.include_common_suffixes {
                    self.insert(&format!("{base}123"));
                    self.insert(&format!("{base}123!"));
                }
            }

            // Description field often contains hints
            if self.include_ad_attributes
                && let Some(desc) = &user.description
            {
                let desc = desc.to_lowercase();
                // Extract words from description (potential password hints)
                for word in desc.split(|c: char| !c.is_alphanumeric()) {
                    if word.len() >= 4 && !COMMON_DESC_WORDS.contains(&word) {
                        self.insert(word);
                    }
                }
            }
        }
    }

    /// Add multiple static keywords (company names, departments, etc.).
    /// Each keyword is also expanded into common password patterns.
    pub fn add_static_keywords(&mut self, keywords: &[&str]) {
        for keyword in keywords {
            let lower = keyword.to_lowercase();
            self.insert(&lower);
            self.insert(&keyword.to_uppercase());
            // Capitalized form
            let mut chars: Vec<char> = keyword.chars().collect();
            if let Some(c) = chars.first_mut() {
                *c = c.to_uppercase().next().unwrap_or(*c);
            }
            self.insert(&chars.into_iter().collect::<String>());
            // Append common years
            for year in 2020..=2026 {
                self.insert(&format!("{keyword}{year}"));
                self.insert(&format!("{keyword}_{year}"));
            }
            // Append digits
            for d in 0..=9 {
                self.insert(&format!("{keyword}{d}"));
                self.insert(&format!("{keyword}!{d}"));
            }
        }
    }

    /// Add a single candidate.
    pub fn insert(&mut self, word: &str) {
        let len = word.len();
        if len >= self.min_length && len <= self.max_length {
            self.candidates.insert(word.to_string());
        }
    }

    /// Generate the full wordlist.
    pub fn generate(&mut self) -> Vec<String> {
        // Company-based patterns
        if self.include_company_patterns {
            self.generate_company_patterns();
        }

        // Seasonal patterns
        if self.include_seasonal {
            self.generate_seasonal_patterns();
        }

        // Year-based patterns
        if self.include_year_patterns {
            self.generate_year_patterns();
        }

        // Common enterprise passwords
        if self.include_common_suffixes {
            for common in COMMON_ENTERPRISE_PASSWORDS {
                self.insert(common);
            }
        }

        let result: Vec<String> = self.candidates.iter().cloned().collect();
        debug!("Smart wordlist generated {} candidates", result.len());
        result
    }

    fn generate_company_patterns(&mut self) {
        let company = self.company.clone();
        let capitalized = capitalize_first(&company);

        // Company name variations
        for year in 2019..=2026 {
            let s = format!("{company}{year}");
            self.insert(&s);
            let s = format!("{company}@{year}");
            self.insert(&s);
            let s = format!("{capitalized}{year}");
            self.insert(&s);
            let s = format!("{capitalized}@{year}");
            self.insert(&s);
            let s = format!("{capitalized}@{year}!");
            self.insert(&s);
        }

        // Company + common words
        for suffix in &[
            "123", "123!", "1234", "2024!", "2025!", "admin", "it", "corp",
        ] {
            let s = format!("{company}{suffix}");
            self.insert(&s);
            let s = format!("{capitalized}{suffix}");
            self.insert(&s);
        }
    }

    fn generate_seasonal_patterns(&mut self) {
        for season in &["Winter", "Spring", "Summer", "Fall", "Autumn"] {
            for year in 2019..=2026 {
                self.insert(&format!("{season}{year}"));
                self.insert(&format!("{season}{year}!"));
                self.insert(&format!("{season}{year}#"));
                self.insert(&format!("{season}{year}@"));
                let lower = season.to_lowercase();
                self.insert(&format!("{lower}{year}"));
                self.insert(&format!("{lower}{year}!"));
            }
            // Seasonal with month variations
            for month in &["Jan", "Feb", "Mar", "Apr"] {
                for year in 2021..=2026 {
                    self.insert(&format!("{season}{month}{year}"));
                }
            }
        }
    }

    fn generate_year_patterns(&mut self) {
        for year in 2019..=2026 {
            // Year alone
            self.insert(&format!("{year}"));
            // Year with common prefixes
            for prefix in &[
                "Welcome", "ChangeMe", "changeme", "Password", "password", "P@ssw0rd",
            ] {
                self.insert(&format!("{prefix}{year}"));
                self.insert(&format!("{prefix}{year}!"));
            }
            // Common enterprise patterns
            self.insert(&format!("Pass{year}"));
            self.insert(&format!("pass{year}!"));
            self.insert(&format!("Pass{year}!"));
            self.insert(&format!("Qwerty{year}"));
            self.insert(&format!("{year}Pass"));
        }
    }

    /// Return the number of generated candidates.
    pub fn count(&self) -> usize {
        self.candidates.len()
    }

    /// Clear all candidates and regenerate from scratch.
    pub fn reset(&mut self) {
        self.candidates.clear();
    }

    /// Set whether to generate seasonal patterns.
    pub fn set_seasonal(&mut self, val: bool) {
        self.include_seasonal = val;
    }

    /// Set whether to generate username patterns.
    pub fn set_username_patterns(&mut self, val: bool) {
        self.include_username_patterns = val;
    }

    /// Set whether to generate company patterns.
    pub fn set_company_patterns(&mut self, val: bool) {
        self.include_company_patterns = val;
    }
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

/// Years commonly used in enterprise passwords.
const COMMON_YEARS: &[u32] = &[2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026];

/// Common password suffixes in enterprise environments.
const COMMON_SUFFIXES: &[&str] = &[
    "1", "12", "123", "1234", "12345", "123!", "123!", "!", "@", "#", "1!", "12!", "123!", "2024",
    "2025", "2026",
];

/// Common enterprise passwords that appear in breached corp environments.
const COMMON_ENTERPRISE_PASSWORDS: &[&str] = &[
    "Password1",
    "Password123",
    "Password123!",
    "Password1234",
    "Password2024!",
    "Password2025!",
    "P@ssw0rd",
    "P@ssw0rd1",
    "P@ssw0rd123",
    "Welcome1",
    "Welcome123",
    "Welcome2024!",
    "Welcome2025!",
    "ChangeMe1",
    "ChangeMe123",
    "ChangeMe2024!",
    "changeme",
    "changeme123",
    "Summer2024!",
    "Summer2025!",
    "Winter2024!",
    "Winter2025!",
    "Spring2024!",
    "Spring2025!",
    "Fall2024!",
    "Fall2025!",
    "letmein",
    "letmein123",
    "qwerty1",
    "qwerty123",
    "Qwerty123",
    "admin123",
    "Admin123",
    "Administrator1",
    "Passw0rd!",
    "Passw0rd123",
    "Season2024!",
    "Season2025!",
    "Company2024!",
    "Company2025!",
    "DefaultPassword",
    "defaultpassword",
    "TempPassword1",
    "temppassword",
    "Initial1",
    "init123",
    "P@ss1234",
    "Pass@1234",
    "ITAdmin1",
    "svcadmin1",
    "Backup2024!",
    "BackupAdmin1",
];

/// Common words in AD descriptions that are NOT password hints.
const COMMON_DESC_WORDS: &[&str] = &[
    "user",
    "account",
    "service",
    "admin",
    "administrator",
    "manager",
    "employee",
    "staff",
    "temporary",
    "contract",
    "vendor",
    "consultant",
    "disabled",
    "enabled",
    "active",
    "inactive",
    "domain",
    "group",
    "mailbox",
    "shared",
    "description",
    "purpose",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_user(name: &str, desc: Option<&str>) -> AdUser {
        AdUser {
            sam_account_name: name.to_string(),
            distinguished_name: format!("CN={name},DC=corp,DC=local"),
            user_principal_name: Some(format!("{name}@corp.local")),
            user_account_control: 512,
            member_of: vec![],
            service_principal_names: vec![],
            admin_count: false,
            pwd_last_set: None,
            last_logon: None,
            description: desc.map(|s| s.to_string()),
            allowed_to_delegate_to: vec![],
            enabled: true,
            dont_req_preauth: false,
            trusted_for_delegation: false,
            constrained_delegation: false,
        }
    }

    #[test]
    fn test_smart_wordlist_basic() {
        let mut wl = SmartWordlist::new("corp.local");
        wl.add_users(&[make_test_user("jsmith", None)]);
        let list = wl.generate();
        assert!(!list.is_empty());
        assert!(list.contains(&"jsmith".to_string()));
    }

    #[test]
    fn test_company_patterns() {
        let mut wl = SmartWordlist::new("acmecorp.local");
        wl.include_username_patterns = false;
        wl.include_seasonal = false;
        wl.include_year_patterns = false;
        wl.include_common_suffixes = false;
        wl.include_company_patterns = true;
        let list = wl.generate();
        assert!(list.contains(&"acmecorp2024".to_string()));
    }

    #[test]
    fn test_seasonal_patterns() {
        let mut wl = SmartWordlist::new("test.local");
        wl.include_username_patterns = false;
        wl.include_company_patterns = false;
        wl.include_seasonal = true;
        let list = wl.generate();
        assert!(list.iter().any(|w| w.contains("Spring")));
        assert!(list.iter().any(|w| w.contains("2025")));
    }

    #[test]
    fn test_username_variations() {
        let mut wl = SmartWordlist::new("test.local");
        wl.add_users(&[make_test_user("bob", None)]);
        let list = wl.generate();
        assert!(list.contains(&"bob123".to_string()));
        assert!(list.contains(&"bob1".to_string()));
    }

    #[test]
    fn test_description_words() {
        let mut wl = SmartWordlist::new("test.local");
        wl.add_users(&[make_test_user("alice", Some("Password2024!"))]);
        let list = wl.generate();
        assert!(list.contains(&"password2024".to_string()));
    }

    #[test]
    fn test_deduplication() {
        let mut wl = SmartWordlist::new("test.local");
        wl.add_users(&[make_test_user("admin", None)]);
        let list = wl.generate();
        let unique: std::collections::HashSet<_> = list.iter().cloned().collect();
        assert_eq!(list.len(), unique.len());
    }

    #[test]
    fn test_min_length_filter() {
        let mut wl = SmartWordlist::new("test.local").with_min_length(8);
        wl.add_users(&[make_test_user("ab", None)]);
        let list = wl.generate();
        assert!(!list.contains(&"ab".to_string()));
    }

    #[test]
    fn test_count() {
        let mut wl = SmartWordlist::new("test.local");
        let count_before = wl.count();
        wl.add_users(&[make_test_user("jsmith", Some("engineer"))]);
        wl.generate();
        assert!(wl.count() > count_before);
    }
}
