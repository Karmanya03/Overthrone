//! Port scanner module
//!
//! Lightweight SYN/TCP/ACK scanner for self-contained operation.
//! Supports CIDR notation, ranges, and hostname targets.

pub mod discovery;
pub mod preauth_discovery;
use crate::error::{OverthroneError, Result};
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ===========================================================
// Types
// ===========================================================

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

// ===========================================================
// Named Port Sets
// ===========================================================

/// Top 100 most commonly scanned ports (nmap top-100)
const TOP_100_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 162, 389, 443, 445, 465, 512, 513, 514,
    515, 548, 554, 587, 631, 636, 873, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008,
    8009, 8080, 8081, 8443, 8888, 9090, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155,
    49156, 49157,
];

/// Top 1000 most commonly scanned ports (nmap top-1000)
const TOP_1000_PORTS: &[u16] = &[
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 67,
    68, 69, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125,
    135, 139, 143, 144, 146, 161, 162, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280,
    301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481,
    497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617,
    625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749,
    765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981,
    987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056,
    1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072,
    1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088,
    1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106,
    1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131,
    1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169,
    1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234,
    1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322,
    1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533,
    1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721,
    1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914,
    1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
    2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043,
    2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121,
    2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301,
    2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602,
    2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875,
    2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030,
    3031, 3050, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301,
    3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476,
    3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809,
    3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971,
    3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224,
    4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998,
    5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100,
    5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414,
    5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730,
    5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903,
    5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987,
    5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100,
    6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580,
    6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969,
    7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443,
    7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000,
    8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200,
    8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652,
    8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050,
    9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290,
    9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878,
    9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009,
    10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626,
    10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
    13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001,
    16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101,
    19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
    22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715,
    28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
    32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899,
    34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501,
    45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163,
    49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389,
    50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056,
    55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331,
    64623, 64680, 65000, 65129, 65389,
];

/// Scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// targets field
    pub targets: String,
    /// Port number
    pub ports: String,
    /// Classification for this object.
    pub scan_type: ScanType,
    /// Timeout in seconds
    pub timeout_ms: u64,
    /// concurrency field
    pub concurrency: usize,
}

/// Scan result for a single port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Target host address
    pub host: String,
    /// Port number
    pub port: u16,
    /// open field
    pub open: bool,
    /// service field
    pub service: Option<String>,
    /// response time ms field
    pub response_time_ms: u64,
    /// banner field
    pub banner: Option<String>,
}

/// Port scanner
pub struct PortScanner {
    config: ScanConfig,
}

/// Target specification
#[derive(Debug, Clone)]
pub enum TargetSpec {
    /// `Single` variant
    Single(String),
    /// `Range` variant
    Range(Ipv4Addr, Ipv4Addr),
    /// `Cidr` variant
    Cidr(Ipv4Addr, u8),
    /// `List` variant
    List(Vec<String>),
}

// ===========================================================
// Port Scanner Implementation
// ===========================================================

impl PortScanner {
    /// Runs this module operation.
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

    // =======================================================
    // Scan implementations
    // =======================================================

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

    // =======================================================
    // Helper methods
    // =======================================================

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

    /// Resolve a named port set to a list of ports.
    /// Recognised names: `top1000`, `top100`, `ad-ports`, `all`.
    fn resolve_port_set(name: &str) -> Option<Vec<u16>> {
        Some(match name.to_ascii_lowercase().trim() {
            "top1000" | "top-1000" => TOP_1000_PORTS.to_vec(),
            "top100" | "top-100" => TOP_100_PORTS.to_vec(),
            "ad-ports" | "ad" | "activedirectory" => {
                vec![88, 135, 139, 389, 445, 464, 636, 3268, 3269, 9389]
            }
            "all" | "full" | "1-65535" => (1..=65535).collect(),
            _ => return None,
        })
    }

    fn parse_ports(&self, ports: &str) -> Result<Vec<u16>> {
        let mut port_list = Vec::new();

        for part in ports.split(',') {
            let part = part.trim();

            if part.is_empty() {
                continue;
            }

            // Check for named port set (e.g., top1000, ad-ports, all)
            if let Some(resolved) = Self::resolve_port_set(part) {
                port_list.extend(resolved);
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
                    .map_err(|_| OverthroneError::Config(format!(
                        "Invalid port: '{}'. Use numeric ports (e.g. 80,443), ranges (1-1000), or named sets: top1000, top100, ad-ports, all",
                        part
                    )))?;
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

// ===========================================================
// Convenience functions
// ===========================================================

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

// ===========================================================
// Tests
// ===========================================================

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
