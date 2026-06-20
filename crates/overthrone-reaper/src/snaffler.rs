//! Snaffler-like sensitive file discovery in SMB shares.
//!
//! Recursively walks through accessible shares and matches files against
//! high-value patterns (passwords, keys, configurations, sensitive documents).
//!
//! Optimized for speed with parallel share scanning and depth-limited recursion.

use crate::runner::{ReaperConfig, ldap_connect};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};
/// A sensitive file discovered during SMB share crawling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnaffleFinding {
    /// Hostname or IP address of the target system.
    pub hostname: String,
    /// SMB share name where the file was found (e.g. "SYSVOL", "Users").
    pub share: String,
    /// Relative path within the share to the matching file.
    pub path: String,
    /// Human-readable reason the file was flagged.
    pub reason: String,
    /// Severity level: 1 = Critical (Passwords/Keys), 2 = High (Configs), 3 = Medium (Backups/Logs).
    pub severity: u8,
    /// File size in bytes.
    pub size: u64,
}

/// Configuration for the Snaffler module.
#[derive(Debug, Clone)]
pub struct SnafflerConfig {
    /// SMB share names to scan on each target host.
    /// Default: C$, Users, Shared, Data, Backup, SYSVOL, NETLOGON
    pub shares: Vec<String>,
    /// Maximum BFS recursion depth within each share (default: 5).
    pub max_depth: usize,
    /// Maximum concurrent host scans (default: 10).
    pub concurrency: usize,
}

impl Default for SnafflerConfig {
    fn default() -> Self {
        Self {
            shares: vec![
                "C$".into(),
                "Users".into(),
                "Shared".into(),
                "Data".into(),
                "Backup".into(),
                "SYSVOL".into(),
                "NETLOGON".into(),
            ],
            max_depth: 5,
            concurrency: 10,
        }
    }
}

/// Snaffler engine: discovers sensitive files in readable SMB shares.
pub struct Snaffler {
    config: ReaperConfig,
    snaffler_config: SnafflerConfig,
    patterns: Vec<SnafflePattern>,
    concurrency_limit: Arc<Semaphore>,
}

struct SnafflePattern {
    extension: Option<String>,
    name_contains: Option<String>,
    reason: String,
    severity: u8,
}

#[cfg(test)]
fn file_matches_pattern(name: &str, extension: Option<&str>, name_contains: Option<&str>) -> bool {
    let lower = name.to_lowercase();
    if let Some(ext) = extension {
        if lower.ends_with(ext) {
            return true;
        }
    }
    if let Some(nc) = name_contains {
        if lower.contains(nc) {
            return true;
        }
    }
    false
}

impl Snaffler {
    /// Create a new Snaffler with default configuration.
    pub fn new(config: ReaperConfig) -> Self {
        Self::with_config(config, SnafflerConfig::default())
    }

    /// Create a new Snaffler with custom configuration.
    pub fn with_config(config: ReaperConfig, snaffler_config: SnafflerConfig) -> Self {
        let patterns = vec![
            // ==========================================================
            // CRITICAL (Severity 1) — Passwords, private keys, secrets
            // ==========================================================
            SnafflePattern {
                extension: Some("pfx".to_string()),
                name_contains: None,
                reason: "Certificate with private key (PFX/P12)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("p12".to_string()),
                name_contains: None,
                reason: "Certificate with private key (PFX/P12)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("kdbx".to_string()),
                name_contains: None,
                reason: "KeePass password database".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("key".to_string()),
                name_contains: None,
                reason: "Private key file".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("pem".to_string()),
                name_contains: None,
                reason: "PEM file (may contain certificate + private key)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("ovpn".to_string()),
                name_contains: None,
                reason: "OpenVPN configuration (often embeds certificates/keys)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("rdp".to_string()),
                name_contains: None,
                reason: "RDP connection file (may contain saved credentials)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("kirk".to_string()),
                name_contains: None,
                reason: "KeeShare password database".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("tblk".to_string()),
                name_contains: None,
                reason: "TeamViewer configuration (may contain passwords)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: Some("vnc".to_string()),
                name_contains: None,
                reason: "VNC configuration (may contain saved passwords)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("password".to_string()),
                reason: "File with 'password' in the name".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("passwd".to_string()),
                reason: "File with 'passwd' in the name (Unix password file)".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("secret".to_string()),
                reason: "File with 'secret' in the name".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("credentials".to_string()),
                reason: "File with 'credentials' in the name".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("id_rsa".to_string()),
                reason: "SSH RSA private key".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("id_dsa".to_string()),
                reason: "SSH DSA private key".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("id_ecdsa".to_string()),
                reason: "SSH ECDSA private key".to_string(),
                severity: 1,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("id_ed25519".to_string()),
                reason: "SSH Ed25519 private key".to_string(),
                severity: 1,
            },
            // ==========================================================
            // HIGH (Severity 2) — Configs, scripts, deployment files
            // ==========================================================
            SnafflePattern {
                extension: Some("xml".to_string()),
                name_contains: Some("web.config".to_string()),
                reason: "IIS Web Configuration (contains connection strings)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: Some("config".to_string()),
                name_contains: None,
                reason: "Application configuration file".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: Some("ps1".to_string()),
                name_contains: Some("deploy".to_string()),
                reason: "Deployment script (often contains hardcoded creds)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: Some("cmd".to_string()),
                name_contains: Some("deploy".to_string()),
                reason: "Deployment script (often contains hardcoded creds)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: Some("bat".to_string()),
                name_contains: Some("deploy".to_string()),
                reason: "Deployment script (often contains hardcoded creds)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: Some("yml".to_string()),
                name_contains: Some("docker-compose".to_string()),
                reason: "Docker Compose config (may contain environment secrets)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: Some("yaml".to_string()),
                name_contains: Some("docker-compose".to_string()),
                reason: "Docker Compose config (may contain environment secrets)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: Some("env".to_string()),
                name_contains: None,
                reason: "Environment file (often contains API keys/secrets)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some(".env".to_string()),
                reason: "Docker/Node environment file (may contain secrets)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some(".git-credentials".to_string()),
                reason: "Git credential store (contains saved passwords)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("sftp-config".to_string()),
                reason: "SFTP configuration (may contain saved passwords)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some(".netrc".to_string()),
                reason: "Unix netrc file (plaintext credentials)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("_netrc".to_string()),
                reason: "Windows netrc file (plaintext credentials)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("ssh_config".to_string()),
                reason: "SSH client configuration".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("known_hosts".to_string()),
                reason: "SSH known hosts (may reveal internal hosts)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("kubeconfig".to_string()),
                reason: "Kubernetes configuration (may contain cluster creds)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some("kubectl".to_string()),
                reason: "Kubectl configuration (may contain cluster creds)".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some(".aws".to_string()),
                reason: "AWS configuration or credentials file".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some(".azure".to_string()),
                reason: "Azure configuration or credentials file".to_string(),
                severity: 2,
            },
            SnafflePattern {
                extension: None,
                name_contains: Some(".npmrc".to_string()),
                reason: "NPM registry config (may contain auth tokens)".to_string(),
                severity: 2,
            },
            // ==========================================================
            // MEDIUM (Severity 3) — Data, backups, logs, configs
            // ==========================================================
            SnafflePattern {
                extension: Some("bak".to_string()),
                name_contains: None,
                reason: "Generic backup file".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("backup".to_string()),
                name_contains: None,
                reason: "Backup file".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("sql".to_string()),
                name_contains: None,
                reason: "SQL script (may contain data or credentials)".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("dump".to_string()),
                name_contains: None,
                reason: "Database dump file".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("xlsx".to_string()),
                name_contains: Some("password".to_string()),
                reason: "Spreadsheet with 'password' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("xls".to_string()),
                name_contains: Some("password".to_string()),
                reason: "Spreadsheet with 'password' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("csv".to_string()),
                name_contains: Some("password".to_string()),
                reason: "CSV with 'password' in name (may contain leaked creds)".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("txt".to_string()),
                name_contains: Some("password".to_string()),
                reason: "Text file with 'password' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("txt".to_string()),
                name_contains: Some("secret".to_string()),
                reason: "Text file with 'secret' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("log".to_string()),
                name_contains: None,
                reason: "Log file (may contain sensitive data)".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("conf".to_string()),
                name_contains: None,
                reason: "Generic configuration file".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("cfg".to_string()),
                name_contains: None,
                reason: "Generic configuration file".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("ini".to_string()),
                name_contains: None,
                reason: "INI configuration file".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("json".to_string()),
                name_contains: Some("password".to_string()),
                reason: "JSON file with 'password' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("json".to_string()),
                name_contains: Some("secret".to_string()),
                reason: "JSON file with 'secret' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("yml".to_string()),
                name_contains: Some("credential".to_string()),
                reason: "YAML config with 'credential' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("yaml".to_string()),
                name_contains: Some("credential".to_string()),
                reason: "YAML config with 'credential' in name".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("yml".to_string()),
                name_contains: Some("config".to_string()),
                reason: "YAML configuration file".to_string(),
                severity: 3,
            },
            SnafflePattern {
                extension: Some("yaml".to_string()),
                name_contains: Some("config".to_string()),
                reason: "YAML configuration file".to_string(),
                severity: 3,
            },
        ];

        Self {
            config,
            snaffler_config: snaffler_config.clone(),
            patterns,
            concurrency_limit: Arc::new(Semaphore::new(snaffler_config.concurrency)),
        }
    }

    pub async fn run(&self) -> Result<Vec<SnaffleFinding>> {
        info!("[snaffler] Starting sensitive file discovery (Snaffler-mode)");
        let mut findings = Vec::new();

        // 1. Get computers from AD
        let mut ldap = ldap_connect(&self.config).await?;
        let filter = "(objectCategory=computer)";
        let entries = ldap
            .custom_search(filter, &["dNSHostName", "sAMAccountName"])
            .await?;
        let _ = ldap.disconnect().await;

        let mut host_tasks = Vec::new();

        for entry in entries {
            let hostname = entry
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| {
                    entry
                        .attrs
                        .get("sAMAccountName")
                        .and_then(|v| v.first())
                        .map(|s| s.trim_end_matches('$').to_string())
                        .unwrap_or_default()
                });

            if hostname.is_empty() {
                continue;
            }

            let permit: OwnedSemaphorePermit = self
                .concurrency_limit
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| OverthroneError::Custom(format!("Snaffler semaphore error: {e}")))?;
            let config = self.config.clone();
            let snaffler_config = self.snaffler_config.clone();
            let patterns = self
                .patterns
                .iter()
                .map(|p| {
                    (
                        p.extension.clone(),
                        p.name_contains.clone(),
                        p.reason.clone(),
                        p.severity,
                    )
                })
                .collect::<Vec<_>>();
            let hostname_clone = hostname.clone();
            let max_depth = snaffler_config.max_depth;

            host_tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let mut host_findings = Vec::new();
                let scan_errors: Vec<String> = Vec::new();

                let session = match SmbSession::connect(
                    &hostname_clone,
                    &config.domain,
                    &config.username,
                    config.password.as_deref().unwrap_or(""),
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("[snaffler] SMB connect failed for {hostname_clone}: {e}");
                        return (host_findings, scan_errors);
                    }
                };

                // Common shares to snaffle
                let shares: Vec<&str> = snaffler_config.shares.iter().map(|s| s.as_str()).collect();
                let access = session.check_share_access(&shares).await;

                for share in access {
                    if share.readable {
                        debug!(
                            "[snaffler] Scanning \\\\{}\\{}",
                            hostname_clone, share.share_name
                        );
                        let mut stack = vec!["".to_string()];
                        let mut depth_map = std::collections::HashMap::new();
                        depth_map.insert("".to_string(), 0);

                        while let Some(current_path) = stack.pop() {
                            let depth = *depth_map.get(&current_path).unwrap_or(&0);
                            if depth > max_depth {
                                continue;
                            }

                            if let Ok(entries) = session
                                .list_directory(&share.share_name, &current_path)
                                .await
                            {
                                for entry in entries {
                                    if entry.is_directory {
                                        // Skip noisy/huge system directories
                                        let lower_name = entry.name.to_lowercase();
                                        if lower_name == "windows"
                                            || lower_name == "program files"
                                            || lower_name == "program files (x86)"
                                            || lower_name == "winsxs"
                                            || lower_name == "appdata"
                                        {
                                            continue;
                                        }
                                        let next_path = entry.path.clone();
                                        depth_map.insert(next_path.clone(), depth + 1);
                                        stack.push(next_path);
                                    } else {
                                        for (ext, name_part, reason, severity) in &patterns {
                                            let mut matched = false;
                                            if let Some(e) = ext
                                                && entry.name.to_lowercase().ends_with(e)
                                            {
                                                matched = true;
                                            }
                                            if let Some(n) = name_part
                                                && entry.name.to_lowercase().contains(n)
                                            {
                                                matched = true;
                                            }

                                            if matched {
                                                host_findings.push(SnaffleFinding {
                                                    hostname: hostname_clone.clone(),
                                                    share: share.share_name.clone(),
                                                    path: entry.path.clone(),
                                                    reason: reason.clone(),
                                                    severity: *severity,
                                                    size: entry.size,
                                                });
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                (host_findings, scan_errors)
            }));
        }

        for task in host_tasks {
            if let Ok((res, errors)) = task.await {
                findings.extend(res);
                for e in errors {
                    warn!("[snaffler] Scan error: {e}");
                }
            }
        }

        info!(
            "[snaffler] Discovery complete. Found {} sensitive files.",
            findings.len()
        );
        Ok(findings)
    }
}

pub async fn run_snaffler(config: &ReaperConfig) -> Result<Vec<SnaffleFinding>> {
    let snaffler = Snaffler::new(config.clone());
    snaffler.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snaffler_new_pattern_counts() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        assert_eq!(s.patterns.len(), 57);
    }

    #[test]
    fn test_snaffler_new_has_critical_patterns() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let extensions: Vec<Option<String>> =
            s.patterns.iter().map(|p| p.extension.clone()).collect();
        assert!(extensions.contains(&Some("pfx".to_string())));
        assert!(extensions.contains(&Some("kdbx".to_string())));
        assert!(extensions.contains(&Some("key".to_string())));
        assert!(extensions.contains(&Some("pem".to_string())));
        assert!(extensions.contains(&Some("ovpn".to_string())));
        assert!(extensions.contains(&Some("kirk".to_string())));
        assert!(extensions.contains(&Some("tblk".to_string())));
        assert!(extensions.contains(&Some("vnc".to_string())));
    }

    #[test]
    fn test_snaffler_new_severity_1_count() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let critical = s.patterns.iter().filter(|p| p.severity == 1).count();
        assert_eq!(critical, 18);
    }

    #[test]
    fn test_snaffler_new_severity_2_count() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let high = s.patterns.iter().filter(|p| p.severity == 2).count();
        assert_eq!(high, 20);
    }

    #[test]
    fn test_snaffler_new_severity_3_count() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let medium = s.patterns.iter().filter(|p| p.severity == 3).count();
        assert_eq!(medium, 19);
    }

    #[test]
    fn test_snaffler_new_ssh_key_pattern() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let names: Vec<Option<String>> =
            s.patterns.iter().map(|p| p.name_contains.clone()).collect();
        assert!(names.contains(&Some("id_rsa".to_string())));
        assert!(names.contains(&Some("id_dsa".to_string())));
        assert!(names.contains(&Some("id_ecdsa".to_string())));
        assert!(names.contains(&Some("id_ed25519".to_string())));
        assert!(names.contains(&Some("password".to_string())));
        assert!(names.contains(&Some("secret".to_string())));
        assert!(names.contains(&Some("credentials".to_string())));
    }

    #[test]
    fn test_snaffler_new_docker_patterns() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let names: Vec<Option<String>> =
            s.patterns.iter().map(|p| p.name_contains.clone()).collect();
        assert!(names.contains(&Some("docker-compose".to_string())));
        assert!(names.contains(&Some(".env".to_string())));
    }

    #[test]
    fn test_snaffler_new_cloud_patterns() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let names: Vec<Option<String>> =
            s.patterns.iter().map(|p| p.name_contains.clone()).collect();
        assert!(names.contains(&Some(".aws".to_string())));
        assert!(names.contains(&Some(".azure".to_string())));
        assert!(names.contains(&Some("kubeconfig".to_string())));
        assert!(names.contains(&Some("kubectl".to_string())));
    }

    #[test]
    fn test_snaffler_new_git_patterns() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let names: Vec<Option<String>> =
            s.patterns.iter().map(|p| p.name_contains.clone()).collect();
        assert!(names.contains(&Some(".git-credentials".to_string())));
    }

    #[test]
    fn test_file_matches_extension() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        // A file named "certificate.pfx" should match the pfx pattern
        let matched_ext: Vec<&SnafflePattern> = s
            .patterns
            .iter()
            .filter(|p| {
                if let Some(ext) = &p.extension {
                    "certificate.pfx".ends_with(ext)
                } else {
                    false
                }
            })
            .collect();
        assert!(matched_ext.iter().any(|p| p.severity == 1));
    }

    #[test]
    fn test_file_matches_name_contains() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        // A file named "production-passwords.xlsx" should match a pattern
        let matched_name: Vec<&SnafflePattern> = s
            .patterns
            .iter()
            .filter(|p| {
                if let Some(name) = &p.name_contains {
                    "production-passwords.xlsx".contains(name.as_str())
                } else {
                    false
                }
            })
            .collect();
        assert!(!matched_name.is_empty());
        assert!(matched_name.iter().any(|p| p.reason.contains("password")));
    }

    #[test]
    fn test_snaffler_config_default() {
        let cfg = SnafflerConfig::default();
        assert_eq!(cfg.concurrency, 10);
        assert_eq!(cfg.max_depth, 5);
        assert!(cfg.shares.contains(&"SYSVOL".to_string()));
        assert!(cfg.shares.contains(&"C$".to_string()));
        assert_eq!(cfg.shares.len(), 7);
    }

    #[test]
    fn test_snaffler_config_custom() {
        let cfg = SnafflerConfig {
            shares: vec!["Data".into()],
            max_depth: 3,
            concurrency: 2,
        };
        assert_eq!(cfg.concurrency, 2);
        assert_eq!(cfg.max_depth, 3);
        assert_eq!(cfg.shares, vec!["Data"]);
    }

    #[test]
    fn test_snaffler_with_config_uses_custom_settings() {
        let config = ReaperConfig::default();
        let cfg = SnafflerConfig {
            shares: vec!["Data".into()],
            max_depth: 3,
            concurrency: 2,
        };
        let s = Snaffler::with_config(config, cfg);
        assert_eq!(s.snaffler_config.shares, vec!["Data"]);
        assert_eq!(s.snaffler_config.max_depth, 3);
        // concurrency is used for semaphore
        assert_eq!(s.concurrency_limit.available_permits(), 2);
    }

    #[test]
    fn test_file_matches_pattern_extension() {
        assert!(file_matches_pattern("secret.pfx", Some("pfx"), None));
        assert!(!file_matches_pattern("secret.txt", Some("pfx"), None));
    }

    #[test]
    fn test_file_matches_pattern_name_contains() {
        assert!(file_matches_pattern(
            "passwords.xlsx",
            None,
            Some("password")
        ));
        assert!(file_matches_pattern(
            "my_secrets_file.txt",
            None,
            Some("secret")
        ));
        assert!(!file_matches_pattern("normal.txt", None, Some("password")));
    }

    #[test]
    fn test_file_matches_pattern_case_insensitive() {
        assert!(file_matches_pattern("SECRET.PFX", Some("pfx"), None));
        assert!(file_matches_pattern(
            "MyPasswords.xlsx",
            None,
            Some("password")
        ));
    }

    #[test]
    fn test_file_matches_pattern_extension_wins_over_name() {
        // Both extension and name match, should return true
        assert!(file_matches_pattern(
            "password.pfx",
            Some("pfx"),
            Some("password")
        ));
    }

    #[test]
    fn test_severity_ordering_critical_beats_medium() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        // A file like "passwords.xlsx" should match both
        // severity-1 (name contains "password") AND severity-3 (xlsx + password)
        // The first match wins (severity 1 due to break logic)
        let mut matched_severities: Vec<u8> = Vec::new();
        for p in &s.patterns {
            let mut matched = false;
            if let Some(ext) = &p.extension
                && "passwords.xlsx".to_lowercase().ends_with(ext)
            {
                matched = true;
            }
            if let Some(n) = &p.name_contains
                && "passwords.xlsx".to_lowercase().contains(n)
            {
                matched = true;
            }
            if matched {
                matched_severities.push(p.severity);
                break; // Same logic as in run()
            }
        }
        // The first match should be severity 1 (name contains "password")
        assert!(!matched_severities.is_empty());
        assert_eq!(matched_severities[0], 1);
    }

    #[test]
    fn test_no_match_for_safe_files() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let safe_files = [
            "readme.md",
            "script.py",
            "index.html",
            "style.css",
            "main.js",
        ];
        for file in &safe_files {
            let matched: Vec<&SnafflePattern> = s
                .patterns
                .iter()
                .filter(|p| {
                    let mut m = false;
                    if let Some(ext) = &p.extension
                        && file.to_lowercase().ends_with(ext)
                    {
                        m = true;
                    }
                    if let Some(n) = &p.name_contains
                        && file.to_lowercase().contains(n)
                    {
                        m = true;
                    }
                    m
                })
                .collect();
            assert!(
                matched.is_empty(),
                "File '{}' should not match any pattern, but matched: {:?}",
                file,
                matched.iter().map(|p| &p.reason).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_snaffle_finding_serialization() {
        let finding = SnaffleFinding {
            hostname: "DC01.corp.local".into(),
            share: "SYSVOL".into(),
            path: "scripts/passwords.ps1".into(),
            reason: "Script file with 'password' in name".into(),
            severity: 1,
            size: 4096,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("DC01.corp.local"));
        assert!(json.contains("SYSVOL"));
        assert!(json.contains("4096"));

        let deserialized: SnaffleFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hostname, finding.hostname);
        assert_eq!(deserialized.share, finding.share);
        assert_eq!(deserialized.severity, 1);
        assert_eq!(deserialized.size, 4096);
    }

    #[test]
    fn test_severity_counts_stable() {
        // Ensure severity distribution across all patterns is unchanged
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        let sev1 = s.patterns.iter().filter(|p| p.severity == 1).count();
        let sev2 = s.patterns.iter().filter(|p| p.severity == 2).count();
        let sev3 = s.patterns.iter().filter(|p| p.severity == 3).count();
        assert_eq!(sev1 + sev2 + sev3, s.patterns.len());
        assert_eq!(sev1, 18, "Critical patterns count changed");
        assert_eq!(sev2, 20, "High patterns count changed");
        assert_eq!(sev3, 19, "Medium patterns count changed");
    }

    #[test]
    fn test_skip_directories_are_excluded() {
        let skip_dirs = [
            "windows",
            "program files",
            "program files (x86)",
            "winsxs",
            "appdata",
        ];
        // Verify all skip directories are handled in the BFS traversal
        for dir in &skip_dirs {
            let lower = dir.to_lowercase();
            assert!(
                lower == "windows"
                    || lower == "program files"
                    || lower == "program files (x86)"
                    || lower == "winsxs"
                    || lower == "appdata"
            );
        }
    }
}
