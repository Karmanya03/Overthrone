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
use tracing::{debug, info};
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnaffleFinding {
    /// Object or account name.
    pub hostname: String,
    /// share field
    pub share: String,
    /// Filesystem path.
    pub path: String,
    /// reason field
    pub reason: String,
    /// severity field
    pub severity: u8, // 1 = Critical (Passwords, Keys), 2 = High (Config), 3 = Medium (Backups)
    /// Size in bytes
    pub size: u64,
}
/// Structure
pub struct Snaffler {
    config: ReaperConfig,
    patterns: Vec<SnafflePattern>,
    concurrency_limit: Arc<Semaphore>,
}

struct SnafflePattern {
    extension: Option<String>,
    name_contains: Option<String>,
    reason: String,
    severity: u8,
}

impl Snaffler {
    /// Runs this module operation.
    pub fn new(config: ReaperConfig) -> Self {
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
            patterns,
            concurrency_limit: Arc::new(Semaphore::new(10)), // Scan 10 hosts in parallel
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

            host_tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let mut host_findings = Vec::new();

                let session = match SmbSession::connect(
                    &hostname_clone,
                    &config.domain,
                    &config.username,
                    config.password.as_deref().unwrap_or(""),
                )
                .await
                {
                    Ok(s) => s,
                    Err(_) => return host_findings,
                };

                // Common shares to snaffle
                let shares = [
                    "C$", "Users", "Shared", "Data", "Backup", "SYSVOL", "NETLOGON",
                ];
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
                            if depth > 5 {
                                continue;
                            } // Limit recursion depth to 5

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
                host_findings
            }));
        }

        for task in host_tasks {
            if let Ok(res) = task.await {
                findings.extend(res);
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
        let matched_ext: Vec<&SnafflePattern> = s.patterns.iter().filter(|p| {
            if let Some(ext) = &p.extension {
                "certificate.pfx".ends_with(ext)
            } else {
                false
            }
        }).collect();
        assert!(matched_ext.iter().any(|p| p.severity == 1));
    }

    #[test]
    fn test_file_matches_name_contains() {
        let config = ReaperConfig::default();
        let s = Snaffler::new(config);
        // A file named "production-passwords.xlsx" should match a pattern
        let matched_name: Vec<&SnafflePattern> = s.patterns.iter().filter(|p| {
            if let Some(name) = &p.name_contains {
                "production-passwords.xlsx".contains(name.as_str())
            } else {
                false
            }
        }).collect();
        assert!(!matched_name.is_empty());
        assert!(matched_name.iter().any(|p| p.reason.contains("password")));
    }
}
