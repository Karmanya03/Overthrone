//! Hashcat GPU Subprocess — rockyou + OneRuleToRuleThemAll integration.
//!
//! Spawns `hashcat` as a subprocess with configurable hash type, rules,
//! wordlist, and device selection. Supports all hash modes relevant to
//! AD attacks (1000 NTLM, 13100 Kerberoast, 18200 AS-REP).
//!
//! # Usage
//! 1. Ensure hashcat is installed and discoverable in PATH
//! 2. Configure device IDs (GPU: 1, CPU: 2, etc.)
//! 3. Select wordlist (rockyou, embedded, custom)
//! 4. Select rules (OneRuleToRuleThemAll, best64, etc.)
//! 5. Start the crack and monitor progress via the result channel

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Minimum timeout for hashcat runs (24 hours default).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(86400);
/// Progress polling interval.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Hash modes relevant to AD attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuHashMode {
    /// NTLM (mode 1000)
    Ntlm,
    /// Kerberoast RC4-HMAC (mode 13100)
    KerberoastRc4,
    /// Kerberoast AES128 (mode 19600)
    KerberoastAes128,
    /// Kerberoast AES256 (mode 19700)
    KerberoastAes256,
    /// AS-REP roast (mode 18200)
    AsRep,
}

impl GpuHashMode {
    /// hashcat numeric mode.
    pub fn mode_number(&self) -> u32 {
        match self {
            Self::Ntlm => 1000,
            Self::KerberoastRc4 => 13100,
            Self::KerberoastAes128 => 19600,
            Self::KerberoastAes256 => 19700,
            Self::AsRep => 18200,
        }
    }

    /// Description for logging.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Ntlm => "NTLM (1000)",
            Self::KerberoastRc4 => "Kerberoast RC4 (13100)",
            Self::KerberoastAes128 => "Kerberoast AES128 (19600)",
            Self::KerberoastAes256 => "Kerberoast AES256 (19700)",
            Self::AsRep => "AS-REP (18200)",
        }
    }
}

/// Pre-built rule sets for hashcat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuRuleSet {
    /// No rules (straight dictionary)
    None,
    /// best64.rule (64 most effective rules)
    Best64,
    /// OneRuleToRuleThemAll.rule (comprehensive)
    OneRuleToRuleThemAll,
    /// d3ad0ne.rule (aggressive)
    D3ad0ne,
    /// T0XICv1.rule (toxic patterns)
    Toxic,
    /// Custom rules file
    Custom(String),
}

impl GpuRuleSet {
    /// Filename of the rule set.
    pub fn filename(&self) -> &str {
        match self {
            Self::None => "",
            Self::Best64 => "best64.rule",
            Self::OneRuleToRuleThemAll => "OneRuleToRuleThemAll.rule",
            Self::D3ad0ne => "d3ad0ne.rule",
            Self::Toxic => "T0XICv1.rule",
            Self::Custom(name) => name.as_str(),
        }
    }
}

/// Configuration for hashcat GPU subprocess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashcatGpuConfig {
    /// Path to hashcat binary (default: "hashcat" from PATH).
    pub hashcat_path: String,
    /// Hash mode.
    pub mode: GpuHashMode,
    /// Path to wordlist file (e.g., "/usr/share/wordlists/rockyou.txt").
    pub wordlist_path: PathBuf,
    /// Rule set to apply.
    pub rules: GpuRuleSet,
    /// Path to hash file to crack.
    pub hash_file: PathBuf,
    /// Output file for cracked hashes.
    pub output_file: PathBuf,
    /// GPU device IDs to use (e.g., vec![1] for first GPU).
    pub device_ids: Vec<u32>,
    /// Whether to use CPU devices as well.
    pub use_cpu: bool,
    /// Maximum runtime before abort.
    pub timeout: Duration,
    /// OpenCL platform ID (default: 0).
    pub platform_id: u32,
    /// Additional hashcat flags.
    pub extra_flags: Vec<String>,
}

impl Default for HashcatGpuConfig {
    fn default() -> Self {
        Self {
            hashcat_path: "hashcat".into(),
            mode: GpuHashMode::Ntlm,
            wordlist_path: PathBuf::from("/usr/share/wordlists/rockyou.txt"),
            rules: GpuRuleSet::OneRuleToRuleThemAll,
            hash_file: PathBuf::from("hashes.txt"),
            output_file: PathBuf::from("cracked.txt"),
            device_ids: vec![1],
            use_cpu: false,
            timeout: DEFAULT_TIMEOUT,
            platform_id: 0,
            extra_flags: vec![],
        }
    }
}

/// Result of a hashcat subprocess run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashcatGpuResult {
    /// Whether hashcat was found.
    pub hashcat_available: bool,
    /// Whether the crack completed.
    pub completed: bool,
    /// Number of hashes cracked.
    pub cracked_count: u32,
    /// Total hashes in input.
    pub total_hashes: u32,
    /// Cracking speed (hashes/sec estimated).
    pub speed_hs: u64,
    /// Runtime duration.
    pub runtime_secs: u64,
    /// Path to output file.
    pub output_file: PathBuf,
    /// Cracked passwords (loaded from output file).
    pub cracked_passwords: Vec<(String, String)>,
    /// Detailed log.
    pub log: Vec<String>,
}

/// Run hashcat as a GPU-accelerated subprocess.
pub async fn run_hashcat_gpu(
    config: &HashcatGpuConfig,
    stop_flag: Option<Arc<AtomicBool>>,
) -> HashcatGpuResult {
    let mut log = Vec::new();
    let started = Instant::now();

    log.push(format!(
        "Hashcat GPU: mode={}, wordlist={:?}, rules={}",
        config.mode.description(),
        config.wordlist_path,
        config.rules.filename()
    ));

    // Check hashcat availability
    let available = which_hashcat(&config.hashcat_path);
    log.push(format!("Hashcat available: {available}"));

    if !available {
        return HashcatGpuResult {
            hashcat_available: false,
            completed: false,
            cracked_count: 0,
            total_hashes: 0,
            speed_hs: 0,
            runtime_secs: started.elapsed().as_secs(),
            output_file: config.output_file.clone(),
            cracked_passwords: vec![],
            log,
        };
    }

    // Build hashcat command
    let mut cmd = match build_hashcat_command(config, &log) {
        Ok(c) => c,
        Err(e) => {
            log.push(format!("Failed to build command: {e}"));
            return HashcatGpuResult {
                hashcat_available: true,
                completed: false,
                cracked_count: 0,
                total_hashes: 0,
                speed_hs: 0,
                runtime_secs: started.elapsed().as_secs(),
                output_file: config.output_file.clone(),
                cracked_passwords: vec![],
                log,
            };
        }
    };

    log.push(format!("Command: {:?}", cmd));

    // Spawn hashcat
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log.push(format!("Failed to spawn hashcat: {e}"));
            return HashcatGpuResult {
                hashcat_available: true,
                completed: false,
                cracked_count: 0,
                total_hashes: 0,
                speed_hs: 0,
                runtime_secs: started.elapsed().as_secs(),
                output_file: config.output_file.clone(),
                cracked_passwords: vec![],
                log,
            };
        }
    };

    log.push("Hashcat subprocess started".to_string());

    // Monitor with timeout + stop flag
    let timeout = config.timeout;
    let poll = POLL_INTERVAL;

    loop {
        tokio::time::sleep(poll).await;

        let elapsed = started.elapsed();

        // Check stop flag
        if let Some(ref flag) = stop_flag
            && !flag.load(Ordering::SeqCst)
        {
            log.push("Stop flag received — killing hashcat".to_string());
            let _ = child.kill();
            let _ = child.wait();
            break;
        }

        // Check timeout
        if elapsed > timeout {
            log.push(format!("Timeout reached ({timeout:?}) — killing hashcat"));
            let _ = child.kill();
            let _ = child.wait();
            break;
        }

        // Check if process exited
        match child.try_wait() {
            Ok(Some(status)) => {
                log.push(format!("Hashcat exited with status: {status}"));
                break;
            }
            Ok(None) => {
                // Still running
                debug!("Hashcat running for {elapsed:?}");
            }
            Err(e) => {
                log.push(format!("Error checking hashcat status: {e}"));
                break;
            }
        }
    }

    let runtime = started.elapsed();

    // Read output file
    let cracked_passwords = read_cracked_file(&config.output_file);
    log.push(format!("Cracked {} passwords", cracked_passwords.len()));

    // Count total hashes from input
    let total_hashes = count_hash_lines(&config.hash_file);

    let speed_hs = if runtime.as_secs() > 0 {
        (cracked_passwords.len() as u64) / runtime.as_secs()
    } else {
        0
    };

    info!(
        "Hashcat GPU: cracked={}/{} hashes in {:?}",
        cracked_passwords.len(),
        total_hashes,
        runtime
    );

    HashcatGpuResult {
        hashcat_available: true,
        completed: true,
        cracked_count: cracked_passwords.len() as u32,
        total_hashes,
        speed_hs,
        runtime_secs: runtime.as_secs(),
        output_file: config.output_file.clone(),
        cracked_passwords,
        log,
    }
}

/// Build the hashcat command from config.
fn build_hashcat_command(
    config: &HashcatGpuConfig,
    _log: &[String],
) -> Result<std::process::Command> {
    let mut cmd = Command::new(&config.hashcat_path);

    // Mode
    cmd.arg("-m").arg(config.mode.mode_number().to_string());

    // Hash file
    cmd.arg(&config.hash_file);

    // Wordlist
    cmd.arg(&config.wordlist_path);

    // Output file
    cmd.arg("--outfile").arg(&config.output_file);

    // Rules
    if config.rules != GpuRuleSet::None {
        cmd.arg("-r").arg(config.rules.filename());
    }

    // Device selection
    if !config.device_ids.is_empty() {
        let devices: Vec<String> = config.device_ids.iter().map(|d| d.to_string()).collect();
        cmd.arg("-D").arg(if config.use_cpu { "2" } else { "1" });
        cmd.arg("--opencl-devices").arg(devices.join(","));
    }

    // Platform
    cmd.arg("--opencl-platforms")
        .arg(config.platform_id.to_string());

    // Performance
    cmd.arg("--optimized-kernel-enable");
    cmd.arg("--workload-profile").arg("3"); // High

    // Potfile disable (we manage our own)
    cmd.arg("--potfile-disable");

    // Show cracked
    cmd.arg("--show");

    // Extra flags
    for flag in &config.extra_flags {
        cmd.arg(flag);
    }

    // Quiet stdout, redirect stderr
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    Ok(cmd)
}

/// Check if hashcat is available in PATH.
fn which_hashcat(path: &str) -> bool {
    if path == "hashcat" {
        Command::new("hashcat")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    } else {
        Path::new(path).exists()
    }
}

/// Read cracked passwords from output file.
fn read_cracked_file(path: &Path) -> Vec<(String, String)> {
    if !path.exists() {
        return vec![];
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            // Format: hash:password
            let mut parts = line.splitn(2, ':');
            match (parts.next(), parts.next()) {
                (Some(hash), Some(password)) => Some((hash.to_string(), password.to_string())),
                _ => None,
            }
        })
        .collect()
}

/// Count lines in hash file.
fn count_hash_lines(path: &Path) -> u32 {
    if !path.exists() {
        return 0;
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    content.lines().count() as u32
}

/// Default rockyou path detection.
pub fn default_rockyou_path() -> PathBuf {
    let candidates = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/rockyou/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt",
        "/usr/share/seclists/Passwords/rockyou.txt",
        "/opt/wordlists/rockyou.txt",
    ];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() {
            return p.to_path_buf();
        }
    }

    PathBuf::from("/usr/share/wordlists/rockyou.txt")
}

/// Default OneRuleToRuleThemAll path detection.
pub fn default_onerule_path() -> PathBuf {
    let candidates = [
        "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
        "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
        "/opt/hashcat/rules/OneRuleToRuleThemAll.rule",
        "/usr/share/wordlists/OneRuleToRuleThemAll.rule",
    ];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() {
            return p.to_path_buf();
        }
    }

    PathBuf::from("OneRuleToRuleThemAll.rule")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_hash_mode_numbers() {
        assert_eq!(GpuHashMode::Ntlm.mode_number(), 1000);
        assert_eq!(GpuHashMode::KerberoastRc4.mode_number(), 13100);
        assert_eq!(GpuHashMode::AsRep.mode_number(), 18200);
    }

    #[test]
    fn test_mode_descriptions() {
        assert_eq!(GpuHashMode::Ntlm.description(), "NTLM (1000)");
        assert!(
            GpuHashMode::KerberoastAes256
                .description()
                .contains("19700")
        );
    }

    #[test]
    fn test_rule_set_filenames() {
        assert_eq!(GpuRuleSet::Best64.filename(), "best64.rule");
        assert_eq!(
            GpuRuleSet::OneRuleToRuleThemAll.filename(),
            "OneRuleToRuleThemAll.rule"
        );
        assert_eq!(GpuRuleSet::None.filename(), "");
    }

    #[test]
    fn test_hashcat_result_serde() {
        let result = HashcatGpuResult {
            hashcat_available: true,
            completed: true,
            cracked_count: 42,
            total_hashes: 1000,
            speed_hs: 500_000,
            runtime_secs: 120,
            output_file: PathBuf::from("cracked.txt"),
            cracked_passwords: vec![("hash1".into(), "pass1".into())],
            log: vec!["hashcat completed".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("500000"));
        assert!(json.contains("pass1"));
        let deserialized: HashcatGpuResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cracked_count, 42);
    }
}
