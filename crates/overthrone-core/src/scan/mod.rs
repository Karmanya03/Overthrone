//! Port scanner module
//!
//! Lightweight SYN/TCP/ACK scanner for self-contained operation.
//! Supports CIDR notation, ranges, and hostname targets.

use crate::error::{OverthroneError, Result};
use futures::stream::{StreamExt, iter};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

/// Scan type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    /// SYN scan (half-open, requires raw sockets on some platforms)
    Syn,
    /// Connect scan (full TCP handshake)
    Connect,
    /// ACK scan (firewall mapping)
    Ack,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syn => write!(f, "SYN"),
            Self::Connect => write!(f, "Connect"),
            Self::Ack => write!(f, "ACK"),
        }
    }
}

/// Scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: String,
    pub ports: String,
    pub scan_type: ScanType,
    pub timeout_ms: u64,
    pub concurrency: usize,
}

/// Scan result for a single port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
    pub response_time_ms: u64,
    pub banner: Option<String>,
}

/// Port scanner
pub struct PortScanner {
    config: ScanConfig,
}

/// Target specification
#[derive(Debug, Clone)]
pub enum TargetSpec {
    Single(String),
    Range(Ipv4Addr, Ipv4Addr),
    Cidr(Ipv4Addr, u8),
    List(Vec<String>),
}

// ═══════════════════════════════════════════════════════════
// Port Scanner Implementation
// ═══════════════════════════════════════════════════════════

impl PortScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Execute port scan
    pub async fn scan(&self) -> Result<Vec<ScanResult>> {
        info!(
            "Starting {} scan of targets: {} ports: {}",
            self.config.scan_type, self.config.targets, self.config.ports
        );

        // Parse targets
        let targets = self.parse_targets(&self.config.targets)?;

        // Parse ports
        let ports = self.parse_ports(&self.config.ports)?;

        debug!("Parsed {} targets and {} ports", targets.len(), ports.len());

        // Execute scan based on type
        let results = match self.config.scan_type {
            ScanType::Syn => self.syn_scan(&targets, &ports).await,
            ScanType::Connect => self.connect_scan(&targets, &ports).await,
            ScanType::Ack => self.ack_scan(&targets, &ports).await,
        }?;

        info!("Scan complete: {} results", results.len());

        Ok(results)
    }

    // ═══════════════════════════════════════════════════════
    // Scan implementations
    // ═══════════════════════════════════════════════════════

    async fn connect_scan(&self, targets: &[TargetSpec], ports: &[u16]) -> Result<Vec<ScanResult>> {
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        // First, resolve all targets into a flat list of hostnames
        let mut all_hostnames = Vec::new();
        for target in targets {
            let hostnames = self.resolve_targets(target).await?;
            all_hostnames.extend(hostnames);
        }

        // Build the full flat list of target/port pairs to scan
        let mut scan_tasks = Vec::new();
        for host in all_hostnames {
            for &port in ports {
                scan_tasks.push((host.clone(), port));
            }
        }

        let concurrency_limit = if self.config.concurrency > 0 {
            self.config.concurrency
        } else {
            100 // Fallback default
        };

        info!(
            "Starting concurrent scan of {} endpoints (limit: {})",
            scan_tasks.len(),
            concurrency_limit
        );

        // Process tasks concurrently using futures streams
        let results: Vec<ScanResult> = futures::stream::iter(scan_tasks)
            .map(|(hostname, port)| {
                let addr = format!("{}:{}", hostname, port);

                async move {
                    let start = std::time::Instant::now();

                    match timeout(timeout_duration, TcpStream::connect(&addr)).await {
                        Ok(Ok(_stream)) => {
                            let elapsed = start.elapsed().as_millis() as u64;

                            // Try to grab banner
                            let banner = self.grab_banner(&hostname, port).await.ok();

                            ScanResult {
                                host: hostname.clone(),
                                port,
                                open: true,
                                service: self.identify_service(port),
                                response_time_ms: elapsed,
                                banner,
                            }
                        }
                        Ok(Err(_)) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            ScanResult {
                                host: hostname.clone(),
                                port,
                                open: false,
                                service: None,
                                response_time_ms: elapsed,
                                banner: None,
                            }
                        }
                        Err(_) => {
                            // Timeout
                            ScanResult {
                                host: hostname.clone(),
                                port,
                                open: false,
                                service: None,
                                response_time_ms: self.config.timeout_ms,
                                banner: None,
                            }
                        }
                    }
                }
            })
            .buffer_unordered(concurrency_limit)
            .collect::<Vec<ScanResult>>()
            .await;

        // Filter for open ports only as per previous behavior
        let open_results: Vec<ScanResult> = results.into_iter().filter(|r| r.open).collect();
        Ok(open_results)
    }

    async fn syn_scan(&self, targets: &[TargetSpec], ports: &[u16]) -> Result<Vec<ScanResult>> {
        info!("Attempting to use rustscan for high-speed SYN scanning");

        let target_str = &self.config.targets;
        let port_str = &self.config.ports;
        let batch_size = if self.config.concurrency > 0 {
            self.config.concurrency.to_string()
        } else {
            "1000".to_string()
        };

        // Try to spawn rustscan
        let output = tokio::process::Command::new("rustscan")
            .arg("-a")
            .arg(target_str)
            .arg("-p")
            .arg(port_str)
            .arg("-b")
            .arg(&batch_size)
            .arg("-g")
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut results = Vec::new();

                // Parse rustscan grepable output: "192.168.1.1 -> [80,443]"
                for line in stdout.lines() {
                    if let Some(idx) = line.find(" -> [") {
                        let ip = line[..idx].trim();
                        if let Some(end_idx) = line.find(']') {
                            let ports_str = &line[idx + 5..end_idx];
                            for p in ports_str.split(',') {
                                if let Ok(port) = p.trim().parse::<u16>() {
                                    results.push(ScanResult {
                                        host: ip.to_string(),
                                        port,
                                        open: true,
                                        service: self.identify_service(port),
                                        response_time_ms: 0, // Rustscan doesn't output per-port latency
                                        banner: None,
                                    });
                                }
                            }
                        }
                    }
                }

                info!(
                    "Rustscan completed successfully. Found {} open ports.",
                    results.len()
                );
                Ok(results)
            }
            Ok(out) => {
                warn!(
                    "Rustscan failed with exit code {:?}. Standard error: {}. Falling back to internal connect scan.",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                self.connect_scan(targets, ports).await
            }
            Err(e) => {
                warn!(
                    "Rustscan not found or failed to execute ({}). Make sure 'rustscan' is in your PATH. Falling back to internal connect scan.",
                    e
                );
                self.connect_scan(targets, ports).await
            }
        }
    }

    async fn ack_scan(&self, _targets: &[TargetSpec], _ports: &[u16]) -> Result<Vec<ScanResult>> {
        // ACK scan is used for firewall mapping
        // Also requires raw sockets

        warn!("ACK scan requires elevated privileges, falling back to connect scan");

        self.connect_scan(_targets, _ports).await
    }

    // ═══════════════════════════════════════════════════════
    // Helper methods
    // ═══════════════════════════════════════════════════════

    fn parse_targets(&self, targets: &str) -> Result<Vec<TargetSpec>> {
        let mut specs = Vec::new();

        for target in targets.split(',') {
            let target = target.trim();

            if target.is_empty() {
                continue;
            }

            // Check for CIDR notation (e.g., 192.168.1.0/24)
            if target.contains('/') {
                let parts: Vec<&str> = target.split('/').collect();
                if parts.len() == 2 {
                    let ip: Ipv4Addr = parts[0].parse().map_err(|e| {
                        OverthroneError::Config(format!("Invalid IP address: {}", e))
                    })?;
                    let prefix: u8 = parts[1].parse().map_err(|e| {
                        OverthroneError::Config(format!("Invalid CIDR prefix: {}", e))
                    })?;
                    specs.push(TargetSpec::Cidr(ip, prefix));
                }
            }
            // Check for range notation (e.g., 192.168.1.1-192.168.1.10)
            else if target.contains('-') {
                let parts: Vec<&str> = target.split('-').collect();
                if parts.len() == 2 {
                    let start: Ipv4Addr = parts[0]
                        .parse()
                        .map_err(|e| OverthroneError::Config(format!("Invalid start IP: {}", e)))?;
                    let end: Ipv4Addr = parts[1]
                        .parse()
                        .map_err(|e| OverthroneError::Config(format!("Invalid end IP: {}", e)))?;
                    specs.push(TargetSpec::Range(start, end));
                }
            }
            // Single target (IP or hostname)
            else {
                specs.push(TargetSpec::Single(target.to_string()));
            }
        }

        if specs.is_empty() {
            return Err(OverthroneError::Config(
                "No valid targets specified".to_string(),
            ));
        }

        Ok(specs)
    }

    fn parse_ports(&self, ports: &str) -> Result<Vec<u16>> {
        let mut port_list = Vec::new();

        for part in ports.split(',') {
            let part = part.trim();

            if part.is_empty() {
                continue;
            }

            // Check for range (e.g., 1-1000)
            if part.contains('-') {
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() == 2 {
                    let start: u16 = range_parts[0].parse().map_err(|e| {
                        OverthroneError::Config(format!("Invalid port range start: {}", e))
                    })?;
                    let end: u16 = range_parts[1].parse().map_err(|e| {
                        OverthroneError::Config(format!("Invalid port range end: {}", e))
                    })?;

                    for p in start..=end {
                        port_list.push(p);
                    }
                }
            }
            // Single port
            else {
                let port: u16 = part
                    .parse()
                    .map_err(|e| OverthroneError::Config(format!("Invalid port: {}", e)))?;
                port_list.push(port);
            }
        }

        // Remove duplicates and sort
        port_list.sort_unstable();
        port_list.dedup();

        if port_list.is_empty() {
            return Err(OverthroneError::Config(
                "No valid ports specified".to_string(),
            ));
        }

        Ok(port_list)
    }

    async fn resolve_targets(&self, spec: &TargetSpec) -> Result<Vec<String>> {
        match spec {
            TargetSpec::Single(host) => {
                // Try to resolve hostname to IP
                match tokio::net::lookup_host(format!("{}:0", host)).await {
                    Ok(addrs) => {
                        let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                        if ips.is_empty() {
                            Ok(vec![host.clone()])
                        } else {
                            Ok(ips)
                        }
                    }
                    Err(_) => Ok(vec![host.clone()]),
                }
            }
            TargetSpec::Range(start, end) => {
                let mut ips = Vec::new();
                let start_u32 = u32::from_be_bytes(start.octets());
                let end_u32 = u32::from_be_bytes(end.octets());

                for ip_u32 in start_u32..=end_u32 {
                    let ip = Ipv4Addr::from(u32::to_be_bytes(ip_u32));
                    ips.push(ip.to_string());
                }

                Ok(ips)
            }
            TargetSpec::Cidr(network, prefix) => {
                let mut ips = Vec::new();
                let network_u32 = u32::from_be_bytes(network.octets());
                let host_bits = 32 - prefix;
                let num_hosts = if *prefix == 32 {
                    1
                } else {
                    (1u32 << host_bits) - 2 // Exclude network and broadcast
                };

                let start_ip = network_u32 + 1;

                for i in 0..num_hosts {
                    let ip = Ipv4Addr::from(u32::to_be_bytes(start_ip + i));
                    ips.push(ip.to_string());
                }

                Ok(ips)
            }
            TargetSpec::List(list) => Ok(list.clone()),
        }
    }

    fn identify_service(&self, port: u16) -> Option<String> {
        match port {
            21 => Some("ftp".to_string()),
            22 => Some("ssh".to_string()),
            23 => Some("telnet".to_string()),
            25 => Some("smtp".to_string()),
            53 => Some("dns".to_string()),
            80 => Some("http".to_string()),
            88 => Some("kerberos".to_string()),
            110 => Some("pop3".to_string()),
            135 => Some("msrpc".to_string()),
            139 => Some("netbios-ssn".to_string()),
            143 => Some("imap".to_string()),
            389 => Some("ldap".to_string()),
            443 => Some("https".to_string()),
            445 => Some("smb".to_string()),
            464 => Some("kpasswd".to_string()),
            593 => Some("http-rpc-epmap".to_string()),
            636 => Some("ldaps".to_string()),
            1433 => Some("mssql".to_string()),
            3268 => Some("globalcatLDAP".to_string()),
            3269 => Some("globalcatLDAPssl".to_string()),
            3389 => Some("rdp".to_string()),
            5985 => Some("winrm".to_string()),
            5986 => Some("winrm-ssl".to_string()),
            9389 => Some("adws".to_string()),
            _ => None,
        }
    }

    async fn grab_banner(&self, host: &str, port: u16) -> Result<String> {
        let addr = format!("{}:{}", host, port);
        let timeout_duration = Duration::from_millis(2000);

        match timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // Send a probe based on service type
                let probe: &[u8] = match port {
                    21 => b"USER anonymous\r\n",
                    25 => b"EHLO scanner\r\n",
                    80 | 443 | 5985 | 5986 => b"HEAD / HTTP/1.0\r\n\r\n",
                    _ => b"\r\n",
                };

                if let Err(e) = stream.write_all(probe).await {
                    debug!("Failed to send probe: {}", e);
                    return Ok(String::new());
                }

                let mut buffer = vec![0u8; 1024];
                match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        buffer.truncate(n);
                        let banner = String::from_utf8_lossy(&buffer)
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_string();
                        Ok(banner)
                    }
                    _ => Ok(String::new()),
                }
            }
            _ => Ok(String::new()),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Convenience functions
// ═══════════════════════════════════════════════════════════

/// Quick scan of common AD ports
pub async fn quick_scan(target: &str) -> Result<Vec<ScanResult>> {
    let config = ScanConfig {
        targets: target.to_string(),
        ports: "88,135,139,389,445,464,636,3268,3269,3389,5985,5986,9389".to_string(),
        scan_type: ScanType::Connect,
        timeout_ms: 1000,
        concurrency: 50,
    };

    let scanner = PortScanner::new(config);
    scanner.scan().await
}

/// Scan for SMB (port 445) on a target
pub async fn scan_smb(target: &str) -> Result<bool> {
    let config = ScanConfig {
        targets: target.to_string(),
        ports: "445".to_string(),
        scan_type: ScanType::Connect,
        timeout_ms: 2000,
        concurrency: 1,
    };

    let scanner = PortScanner::new(config);
    let results = scanner.scan().await?;

    Ok(results.iter().any(|r| r.open))
}

/// Scan for WinRM (ports 5985/5986) on a target
pub async fn scan_winrm(target: &str) -> Result<(bool, bool)> {
    let config = ScanConfig {
        targets: target.to_string(),
        ports: "5985,5986".to_string(),
        scan_type: ScanType::Connect,
        timeout_ms: 2000,
        concurrency: 2,
    };

    let scanner = PortScanner::new(config);
    let results = scanner.scan().await?;

    let http = results.iter().any(|r| r.port == 5985 && r.open);
    let https = results.iter().any(|r| r.port == 5986 && r.open);

    Ok((http, https))
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        let scanner = PortScanner::new(ScanConfig {
            targets: "127.0.0.1".to_string(),
            ports: "80,443,445".to_string(),
            scan_type: ScanType::Connect,
            timeout_ms: 1000,
            concurrency: 10,
        });

        let ports = scanner.parse_ports("80,443,445").unwrap();
        assert_eq!(ports, vec![80, 443, 445]);
    }

    #[test]
    fn test_parse_ports_range() {
        let scanner = PortScanner::new(ScanConfig {
            targets: "127.0.0.1".to_string(),
            ports: "1-5".to_string(),
            scan_type: ScanType::Connect,
            timeout_ms: 1000,
            concurrency: 10,
        });

        let ports = scanner.parse_ports("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        let scanner = PortScanner::new(ScanConfig {
            targets: "127.0.0.1".to_string(),
            ports: "80,100-102,443".to_string(),
            scan_type: ScanType::Connect,
            timeout_ms: 1000,
            concurrency: 10,
        });

        let ports = scanner.parse_ports("80,100-102,443").unwrap();
        assert_eq!(ports, vec![80, 100, 101, 102, 443]);
    }

    #[test]
    fn test_parse_targets_single() {
        let scanner = PortScanner::new(ScanConfig {
            targets: "127.0.0.1".to_string(),
            ports: "80".to_string(),
            scan_type: ScanType::Connect,
            timeout_ms: 1000,
            concurrency: 10,
        });

        let targets = scanner.parse_targets("192.168.1.1").unwrap();
        assert_eq!(targets.len(), 1);
        match &targets[0] {
            TargetSpec::Single(host) => assert_eq!(host, "192.168.1.1"),
            _ => panic!("Expected single target"),
        }
    }

    #[test]
    fn test_parse_targets_cidr() {
        let scanner = PortScanner::new(ScanConfig {
            targets: "127.0.0.1".to_string(),
            ports: "80".to_string(),
            scan_type: ScanType::Connect,
            timeout_ms: 1000,
            concurrency: 10,
        });

        let targets = scanner.parse_targets("192.168.1.0/30").unwrap();
        assert_eq!(targets.len(), 1);
        match &targets[0] {
            TargetSpec::Cidr(ip, prefix) => {
                assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 0));
                assert_eq!(*prefix, 30);
            }
            _ => panic!("Expected CIDR target"),
        }
    }

    #[test]
    fn test_service_identification() {
        let scanner = PortScanner::new(ScanConfig {
            targets: "127.0.0.1".to_string(),
            ports: "80".to_string(),
            scan_type: ScanType::Connect,
            timeout_ms: 1000,
            concurrency: 10,
        });

        assert_eq!(scanner.identify_service(80), Some("http".to_string()));
        assert_eq!(scanner.identify_service(445), Some("smb".to_string()));
        assert_eq!(scanner.identify_service(3389), Some("rdp".to_string()));
        assert_eq!(scanner.identify_service(65000), None);
    }

    #[tokio::test]
    async fn test_resolve_targets() {
        let scanner = PortScanner::new(ScanConfig {
            targets: "127.0.0.1".to_string(),
            ports: "80".to_string(),
            scan_type: ScanType::Connect,
            timeout_ms: 1000,
            concurrency: 10,
        });

        let spec = TargetSpec::Single("127.0.0.1".to_string());
        let resolved = scanner.resolve_targets(&spec).await.unwrap();
        assert!(resolved.contains(&"127.0.0.1".to_string()));
    }
}
