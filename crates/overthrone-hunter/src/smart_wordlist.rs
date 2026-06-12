//! Smart wordlist generation from LDAP enumeration data.
//!
//! Instead of using generic wordlists (rockyou.txt, etc.), this module
//! generates targeted password dictionaries based on:
//! - Organization name, domain name, department names
//! - Seasonal patterns (Summer2024!, Winter2025!)
//! - Common AD password patterns (Company123!, DomainName2024!)
//! - Usernames and variations (admin, Admin1, admin2024!)
//! - Service account patterns (svc_SQL, Service123!)
//!
//! This dramatically increases crack success rates while reducing
//! wordlist size from millions to thousands of highly-targeted candidates.

use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::info;

// ═══════════════════════════════════════════════════════════
// Result Structures
// ═══════════════════════════════════════════════════════════

/// Generated wordlist result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartWordlistResult {
    /// Generated password candidates
    pub passwords: Vec<String>,
    /// Statistics about generation
    pub stats: WordlistStats,
}

/// Wordlist generation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistStats {
    /// Total unique passwords generated
    pub total_passwords: usize,
    /// Number of patterns applied
    pub patterns_applied: usize,
    /// Base words used (org name, domain, etc.)
    pub base_words: usize,
}

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for smart wordlist generation
#[derive(Debug, Clone)]
pub struct WordlistConfig {
    /// Organization name (e.g., "Contoso")
    pub org_name: Option<String>,
    /// Domain name (e.g., "corp.local")
    pub domain: Option<String>,
    /// Include seasonal patterns (Summer2024!, etc.)
    pub include_seasonal: bool,
    /// Include username-based patterns
    pub include_username_patterns: bool,
    /// Include service account patterns
    pub include_service_patterns: bool,
    /// Maximum passwords to generate (0 = unlimited)
    pub max_passwords: usize,
}

impl Default for WordlistConfig {
    fn default() -> Self {
        Self {
            org_name: None,
            domain: None,
            include_seasonal: true,
            include_username_patterns: true,
            include_service_patterns: true,
            max_passwords: 10000, // Reasonable default
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════

/// Generate a smart wordlist based on LDAP enumeration data
///
/// This function:
/// 1. Extracts organization/domain info from LDAP
/// 2. Enumerates users, groups, computers for context words
/// 3. Applies password pattern rules
/// 4. Returns targeted wordlist for cracking
pub async fn generate_smart_wordlist(
    hunt_config: &crate::runner::HuntConfig,
    wordlist_config: &WordlistConfig,
) -> Result<SmartWordlistResult, overthrone_core::error::OverthroneError> {
    info!(
        "{}",
        "═══ SMART WORDLIST GENERATION ═══".bright_cyan().bold()
    );

    let mut passwords = HashSet::new();
    let mut base_words = Vec::new();
    let mut patterns_applied = 0;

    // Step 1: Extract base words from domain/org
    if let Some(domain) = &wordlist_config.domain {
        let domain_words = extract_domain_words(domain);
        base_words.extend(domain_words);
    }

    if let Some(org) = &wordlist_config.org_name {
        base_words.push(org.clone());
        base_words.push(org.to_lowercase());
        base_words.push(org.to_uppercase());
    }

    // Step 2: Connect to LDAP and enumerate context
    let mut conn = if hunt_config.use_hash {
        ldap::LdapSession::connect_with_hash(
            &hunt_config.dc_ip,
            &hunt_config.domain,
            &hunt_config.username,
            &hunt_config.secret,
            hunt_config.use_ldaps,
        )
        .await?
    } else {
        ldap::LdapSession::connect(
            &hunt_config.dc_ip,
            &hunt_config.domain,
            &hunt_config.username,
            &hunt_config.secret,
            hunt_config.use_ldaps,
        )
        .await?
    };

    // Get users for username-based patterns
    if wordlist_config.include_username_patterns {
        info!("  Enumerating users for username-based patterns...");
        let users = conn.enumerate_users().await?;
        patterns_applied += 1;

        for user in &users {
            let username = &user.sam_account_name;

            // Add username variations
            passwords.insert(username.clone());
            passwords.insert(username.to_lowercase());
            passwords.insert(username.to_uppercase());

            // Username + number patterns
            for num in &[1, 123, 2024, 2025] {
                passwords.insert(format!("{}{}", username, num));
                passwords.insert(format!("{}!{}", username, num));
                passwords.insert(format!("{}#{}", username, num));
            }
        }

        info!("    Added username patterns for {} users", users.len());
    }

    // Get computers for service account patterns
    if wordlist_config.include_service_patterns {
        info!("  Enumerating computers for service patterns...");
        let computers = conn.enumerate_computers().await?;
        patterns_applied += 1;

        for computer in &computers {
            // Remove trailing $ for base name
            let base_name = computer.sam_account_name.trim_end_matches('$');

            // Service account patterns
            passwords.insert(format!("svc_{}", base_name));
            passwords.insert(format!("service_{}", base_name));
            passwords.insert(format!("{}svc", base_name));

            // Computer name patterns
            if let Some(hostname) = &computer.dns_hostname {
                let hostname_base = hostname.split('.').next().unwrap_or(hostname);
                passwords.insert(hostname_base.to_string());
                passwords.insert(hostname_base.to_uppercase());
            }
        }

        info!(
            "    Added service patterns for {} computers",
            computers.len()
        );
    }

    // Step 3: Apply base word patterns
    patterns_applied += apply_base_word_patterns(&base_words, &mut passwords);

    // Step 4: Apply seasonal patterns
    if wordlist_config.include_seasonal {
        patterns_applied += 1;
        apply_seasonal_patterns(&base_words, &mut passwords);
    }

    // Step 5: Apply common AD password patterns
    patterns_applied += 1;
    apply_common_ad_patterns(&base_words, &mut passwords);

    // Step 6: Apply leet speak transformations
    patterns_applied += 1;
    apply_leet_speak(&mut passwords);

    // Convert to vector and limit
    let mut password_vec: Vec<String> = passwords.into_iter().collect();

    if wordlist_config.max_passwords > 0 && password_vec.len() > wordlist_config.max_passwords {
        info!(
            "  Truncating wordlist from {} to {} passwords",
            password_vec.len(),
            wordlist_config.max_passwords
        );
        password_vec.truncate(wordlist_config.max_passwords);
    }

    let stats = WordlistStats {
        total_passwords: password_vec.len(),
        patterns_applied,
        base_words: base_words.len(),
    };

    info!(
        "Wordlist complete: {} passwords, {} patterns applied",
        stats.total_passwords, stats.patterns_applied
    );

    Ok(SmartWordlistResult {
        passwords: password_vec,
        stats,
    })
}

// ═══════════════════════════════════════════════════════════
// Pattern Generators
// ═══════════════════════════════════════════════════════════

fn extract_domain_words(domain: &str) -> Vec<String> {
    let mut words = Vec::new();

    // Split domain: corp.local -> ["corp", "local"]
    let parts: Vec<&str> = domain.split('.').collect();
    if !parts.is_empty() {
        let org = parts[0];
        words.push(org.to_string());
        words.push(org.to_lowercase());
        words.push(org.to_uppercase());
        words.push(org.to_owned() + "123");
        words.push(org.to_owned() + "2024");
        words.push(org.to_owned() + "2025");
    }

    words
}

fn apply_base_word_patterns(base_words: &[String], passwords: &mut HashSet<String>) -> usize {
    let mut count = 0;

    for word in base_words {
        // Word + common suffixes
        for suffix in &["123", "123!", "1234", "12345", "!", "#", "@"] {
            passwords.insert(format!("{}{}", word, suffix));
        }

        // Word + year
        for year in &["2023", "2024", "2025", "2026"] {
            passwords.insert(format!("{}{}", word, year));
            passwords.insert(format!("{}!{}", word, year));
        }

        // Capitalized variations
        if word.len() > 1 {
            let mut capitalized = word.clone();
            capitalized[..1].make_ascii_uppercase();
            passwords.insert(capitalized.clone());
            passwords.insert(format!("{}123", capitalized));
            passwords.insert(format!("{}2024", capitalized));
        }

        count += 1;
    }

    count
}

fn apply_seasonal_patterns(base_words: &[String], passwords: &mut HashSet<String>) {
    let seasons = &[
        ("Spring", "03", "04", "05"),
        ("Summer", "06", "07", "08"),
        ("Autumn", "09", "10", "11"),
        ("Fall", "09", "10", "11"),
        ("Winter", "12", "01", "02"),
    ];

    let years = &["2024", "2025", "2026"];

    for (season, _start, _mid, _end) in seasons {
        for year in years {
            // Season + Year patterns
            passwords.insert(format!("{}{}!", season, year));
            passwords.insert(format!("{}{}", season, year));
            passwords.insert(format!("{}#{}", season, year));

            // Base words + season
            for word in base_words {
                passwords.insert(format!("{}{}!", word, season));
                passwords.insert(format!("{}{}{}", word, season, year));
            }
        }
    }
}

fn apply_common_ad_patterns(base_words: &[String], passwords: &mut HashSet<String>) {
    // Most common AD passwords (security studies show these appear frequently)
    let common_passwords = &[
        "Password1",
        "Password1!",
        "Password123",
        "Password123!",
        "Welcome1",
        "Welcome123",
        "Welcome2024!",
        "P@ssw0rd",
        "P@ssw0rd1",
        "P@ssw0rd123",
        "Company123!",
        "Domain123!",
        "Admin123!",
        "Default1",
        "Default123!",
        "Changeme1",
        "Changeme123!",
        "Letmein1",
        "Letmein123!",
    ];

    for pwd in common_passwords {
        passwords.insert(pwd.to_string());

        // Replace with org name
        for word in base_words {
            let customized = pwd
                .replace("Company", word)
                .replace("Domain", word)
                .replace("company", &word.to_lowercase())
                .replace("domain", &word.to_lowercase());
            passwords.insert(customized);
        }
    }

    // Common patterns with symbols
    let patterns = &[("Pass", "w0rd"), ("Adm", "in"), ("Svc", "Account")];

    for (prefix, suffix) in patterns {
        for word in base_words {
            passwords.insert(format!("{}{}{}123!", word, prefix, suffix));
            passwords.insert(format!("{}{}{}2024!", word, prefix, suffix));
        }
    }
}

fn apply_leet_speak(passwords: &mut HashSet<String>) {
    let leet_map = [
        ('a', '@'),
        ('a', '4'),
        ('e', '3'),
        ('i', '1'),
        ('o', '0'),
        ('s', '$'),
        ('s', '5'),
    ];

    let existing: Vec<String> = passwords.iter().cloned().collect();

    for pwd in &existing {
        for &(char_from, char_to) in &leet_map {
            if pwd.contains(char_from) {
                let leet_pwd = pwd.replace(char_from, &char_to.to_string());
                passwords.insert(leet_pwd);
            }
        }
    }
}

use colored::Colorize;
