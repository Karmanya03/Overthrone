//! MS-WCCE DCOM implementation -- ICertRequestD + ICertAdmin2 over DCOM.
//!
//! Provides DCOM-based certificate enrollment and CA management operations
//! using the native Windows COM interfaces, accessible over SMB named pipes.
//!
//! This is the "full DCOM path" for ADCS operations, as opposed to raw RPC
//! (which is in `cert_store.rs`). DCOM activation goes through:
//!   \pipe\epmapper -> IRemoteSCMActivator -> RemoteCreateInstance ->
//!   OBJREF with IPID -> DCOM method calls on \pipe\cert
//!
//! References:
//! - MS-WCCE: Windows Client Certificate Enrollment Protocol
//! - MS-ICPR: ICertPassage Protocol
//! - ICertRequestD: d99e6e74-fc88-11d0-b498-00a0c90312f3
//! - ICertAdmin2: 34df9e82-0e8b-11d3-8abd-00c04f7971e2

use overthrone_core::crypto::ntlm_hash;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::dcom;
use overthrone_core::proto::epm::{
    build_auth3_pdu, build_rpc_bind_auth, build_rpc_request, extract_auth_body,
};
use overthrone_core::proto::ldap::LdapSession;
use overthrone_core::proto::smb::SmbSession;
use overthrone_core::proto::smb2::{
    build_ntlmssp_authenticate_hash, build_ntlmssp_negotiate, parse_ntlmssp_challenge,
};
use tracing::{debug, info, warn};

// ===========================================================
//  COM Interface Definitions
// ===========================================================

/// CLSID_CCertRequest (certcli.dll): {98c4bd30-fa7c-11d0-88b3-00a0c90312f3}
const CLSID_CCERTREQUEST: [u8; 16] = [
    0x30, 0xBD, 0xC4, 0x98, 0x7C, 0xFA, 0xD0, 0x11, 0x88, 0xB3, 0x00, 0xA0, 0xC9, 0x03, 0x12, 0xF3,
];

/// IID_ICertRequestD: {d99e6e74-fc88-11d0-b498-00a0c90312f3}
pub const IID_ICERTREQUESTD: [u8; 16] = [
    0x74, 0x6E, 0x9E, 0xD9, 0x88, 0xFC, 0xD0, 0x11, 0xB4, 0x98, 0x00, 0xA0, 0xC9, 0x03, 0x12, 0xF3,
];

/// CLSID_CCertAdmin (certadm.dll): {005b8a22-a80b-4a8b-a1fc-054aaab53e06}
const CLSID_CCERTADMIN: [u8; 16] = [
    0x22, 0x8A, 0x5B, 0x00, 0x0B, 0xA8, 0x8B, 0x4A, 0xA1, 0xFC, 0x05, 0x4A, 0xAA, 0xB5, 0x3E, 0x06,
];

/// IID_ICertAdmin2: {34df9e82-0e8b-11d3-8abd-00c04f7971e2}
pub const IID_ICERTADMIN2: [u8; 16] = [
    0x82, 0x9E, 0xDF, 0x34, 0x8B, 0x0E, 0xD3, 0x11, 0x8A, 0xBD, 0x00, 0xC0, 0x4F, 0x79, 0x71, 0xE2,
];

/// ICPR named pipe for certificate operations
const ICPR_NAMED_PIPE: &str = "cert";

/// ICertRequestD opnums
const OPNUM_REQUEST_CERTIFICATE: u16 = 1;
#[cfg_attr(not(test), allow(dead_code))]
const OPNUM_GET_CERTIFICATE: u16 = 2;

/// ICertAdmin2 opnums -- from MS-ICDH (Certificate Services Backup/Admin)
const OPNUM_GET_CA_PROPERTY: u16 = 18;
#[cfg_attr(not(test), allow(dead_code))]
const OPNUM_SET_CA_PROPERTY: u16 = 19;
#[cfg_attr(not(test), allow(dead_code))]
const OPNUM_BACKUP_CA: u16 = 21;
#[cfg_attr(not(test), allow(dead_code))]
const OPNUM_GET_CA_CRLS: u16 = 24;

// ===========================================================
//  Public API
// ===========================================================

/// Request a certificate via DCOM (ICertRequestD) over SMB named pipe.
///
/// This is the "full DCOM path": activates CCertRequest via
/// IRemoteSCMActivator on \pipe\epmapper, gets an OBJREF with IPID,
/// then calls ICertRequestD::RequestCertificate on \pipe\cert.
///
/// # Arguments
/// * `smb` - Authenticated SMB session to the CA server
/// * `ca_name` - CA common name, e.g. "domain-CA"
/// * `template` - Certificate template name, e.g. "User"
/// * `subject` - Subject for the certificate, e.g. "CN=attacker"
/// * `csr_der` - PKCS#10 DER-encoded Certificate Signing Request
///
/// # Returns
/// Raw DER-encoded X.509 certificate bytes
pub async fn request_cert_via_dcom(
    smb: &SmbSession,
    ca_name: &str,
    _template: &str,
    _subject: &str,
    csr_der: &[u8],
) -> Result<Vec<u8>> {
    info!(
        "[DCOM/ICertRequestD] Activating CCertRequest on {}",
        smb.target
    );

    // Step 1: DCOM activate CCertRequest -> get IPID for ICertRequestD
    let (ipid, _oxid, _oid) =
        dcom::dcom_activate(smb, &CLSID_CCERTREQUEST, &IID_ICERTREQUESTD).await?;

    debug!("[DCOM/ICertRequestD] Activated -- IPID={:02x?}", ipid);

    // Step 2: Build RequestCertificate stub data
    let mut stub = Vec::new();
    stub.extend(dcom::build_orpc_this());

    // pwszAuthority -- NDR conformant string (CA name)
    dcom::write_ndr_string(&mut stub, ca_name);

    // dwFlags = 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // dwRequestIdOffset = 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ctbRequest -- CERTTRANSBLOB { cbCount, pbData }
    let count = csr_der.len() as u32;
    stub.extend_from_slice(&count.to_le_bytes()); // cbCount
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pbData pointer
    while stub.len() % 8 != 0 {
        stub.push(0);
    }
    stub.extend_from_slice(&count.to_le_bytes()); // max count
    stub.extend_from_slice(&0u32.to_le_bytes()); // offset
    stub.extend_from_slice(&count.to_le_bytes()); // actual count
    stub.extend_from_slice(csr_der);

    // pwszAttributes -- empty conformant string
    dcom::write_ndr_string(&mut stub, "");

    // Output argument pointers with placeholders
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwRequestId ptr
    stub.extend_from_slice(&0u32.to_le_bytes()); // requestId placeholder
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwDisposition ptr
    stub.extend_from_slice(&0u32.to_le_bytes()); // disposition placeholder
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pctbCertChain ptr
    stub.extend_from_slice(&0u32.to_le_bytes()); // cbCount placeholder
    stub.extend_from_slice(&0u32.to_le_bytes()); // pbData placeholder
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwEncodedDisposition ptr
    stub.extend_from_slice(&0u32.to_le_bytes()); // encoded disposition placeholder

    // Pad to 8-byte boundary
    while stub.len() % 8 != 0 {
        stub.push(0);
    }

    // Step 3: Send DCOM call to \pipe\cert
    let resp = dcom::dcom_call(
        smb,
        ICPR_NAMED_PIPE,
        &ipid,
        OPNUM_REQUEST_CERTIFICATE,
        &stub,
        4,
    )
    .await?;

    // Step 4: Parse response (same format as raw RPC)
    parse_dcom_cert_response(&resp, ca_name)
}

/// Backup the CA certificate via ICertAdmin2 DCOM.
///
/// Retrieves the CA certificate chain and optionally the private key
/// (if the caller has sufficient privileges -- typically requires
/// local administrator on the CA server or Backup Operator rights).
///
/// # Arguments
/// * `smb` - Authenticated SMB session to the CA server
/// * `output_path` - Optional file path to save the exported PFX/P12
///
/// # Returns
/// Raw DER bytes of the CA certificate
pub async fn backup_ca_via_dcom(smb: &SmbSession, _output_path: Option<&str>) -> Result<Vec<u8>> {
    info!("[DCOM/ICertAdmin2] Backing up CA on {}", smb.target);

    // Step 1: DCOM activate CCertAdmin -> get IPID for ICertAdmin2
    let (ipid, _oxid, _oid) = dcom::dcom_activate(smb, &CLSID_CCERTADMIN, &IID_ICERTADMIN2).await?;

    debug!("[DCOM/ICertAdmin2] Activated -- IPID={:02x?}", ipid);

    // Step 2: Get CA configuration name first (GetCAProperty with CR_PROP_CANAME)
    let ca_name = get_ca_name_internal(smb, &ipid).await?;

    info!("[DCOM/ICertAdmin2] Backing up CA: {}", ca_name);

    // Step 3: Backup CA -- retrieves the CA certificate
    let ca_cert = backup_ca_internal(smb, &ipid, &ca_name).await?;

    Ok(ca_cert)
}

/// Get the CA certificate via ICertAdmin2::GetCAProperty.
///
/// Retrieves the CA's own certificate (CR_PROP_CASIGCERT = 26).
pub async fn get_ca_certificate(smb: &SmbSession) -> Result<Vec<u8>> {
    info!(
        "[DCOM/ICertAdmin2] Getting CA certificate from {}",
        smb.target
    );

    // Step 1: DCOM activate CCertAdmin
    let (ipid, _oxid, _oid) = dcom::dcom_activate(smb, &CLSID_CCERTADMIN, &IID_ICERTADMIN2).await?;

    debug!(
        "[DCOM/ICertAdmin2] Activated for CA cert retrieval -- IPID={:02x?}",
        ipid
    );

    // Step 2: Get CA name
    let ca_name = get_ca_name_internal(smb, &ipid).await?;

    // Step 3: Get CR_PROP_CASIGCERT (26)
    let ca_cert = get_ca_property_internal(smb, &ipid, &ca_name, 26).await?;

    info!(
        "[DCOM/ICertAdmin2] CA certificate obtained ({} bytes)",
        ca_cert.len()
    );
    Ok(ca_cert)
}

// ===========================================================
//  Internal Helpers
// ===========================================================

/// Get the CA name via ICertAdmin2::GetCAProperty(CR_PROP_CANAME = 14).
async fn get_ca_name_internal(smb: &SmbSession, ipid: &[u8; 16]) -> Result<String> {
    let prop_id = 14u32; // CR_PROP_CANAME

    let ca_name_raw = get_ca_property_internal(smb, ipid, "", prop_id).await?;

    // CA name is a null-terminated UTF-16 string
    let ca_name_utf16: Vec<u16> = ca_name_raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();

    let ca_name = String::from_utf16_lossy(&ca_name_utf16);
    Ok(ca_name)
}

/// Get a CA property via ICertAdmin2::GetCAProperty (opnum 18).
///
/// ICertAdmin2::GetCAProperty signature (DCOM):
///   HRESULT GetCAProperty(
///     [in]  BSTR     strConfig,     // "hostname\CA-Name"
///     [in]  LONG     propId,        // CR_PROP_* constant
///     [in]  LONG     propIndex,     // 0 for single-valued properties
///     [in]  LONG     propType,      // 0xFFFF (autodetect) or PROPTYPE_*
///     [out] VARIANT* pvarPropertyValue
///   );
///
/// Returns the raw bytes from the VARIANT (converted from BSTR/SAFEARRAY to Vec<u8>).
async fn get_ca_property_internal(
    smb: &SmbSession,
    ipid: &[u8; 16],
    ca_name: &str,
    prop_id: u32,
) -> Result<Vec<u8>> {
    // Build CA config string: "hostname\CA-Name"
    // If ca_name is empty, just use the hostname with trailing backslash
    let config_str = if ca_name.is_empty() {
        format!("{}\\", smb.target)
    } else {
        format!("{}\\{}", smb.target, ca_name)
    };

    // Build the NDR stub for GetCAProperty
    let mut stub = Vec::new();
    stub.extend(dcom::build_orpc_this());

    // [in] BSTR strConfig
    dcom::write_bstr(&mut stub, &config_str);

    // [in] LONG propId
    stub.extend_from_slice(&prop_id.to_le_bytes());

    // [in] LONG propIndex = 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // [in] LONG propType = PROPTYPE_BINARY (3) for raw bytes, or -1 for autodetect
    // Using autodetect (0xFFFF as LONG = -1)
    stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // [out] VARIANT* pvarPropertyValue -- non-null conformant pointer
    stub.extend_from_slice(&0x0002_0004u32.to_le_bytes());

    // Padding to 8 bytes
    while stub.len() % 8 != 0 {
        stub.push(0);
    }

    // Send DCOM call
    let resp = dcom::dcom_call(smb, ICPR_NAMED_PIPE, ipid, OPNUM_GET_CA_PROPERTY, &stub, 2).await?;

    // Parse the response
    parse_variant_response(&resp)
}

/// Parse a DCOM VARIANT from an ICertAdmin2::GetCAProperty response.
///
/// Response layout:
///   [0-23]  RPC header (24 bytes)
///   [24-35] ORPC_THAT (12 bytes: flags + extPtr + hresult)
///   [36-39] Return HRESULT (4 bytes)
///   [40-43] [out] VARIANT* pointer (4 bytes, should be 0x00020004)
///   [44+]   VARIANT inline
///
/// VARIANT layout (NDR, 24 bytes on wire for fixed part):
///   [0-1]   vt (VARTYPE u16)
///   [2-3]   wReserved1 (u16)
///   [4-5]   wReserved2 (u16)
///   [6-7]   wReserved3 (u16)
///   [8-15]  Union: pointer to BSTR/SAFEARRAY (with NDR conformant pointer marker)
/// After the 16-byte VARIANT fixed part, the referent data follows inline:
///   For VT_BSTR: maxCount(4) + offset(4) + actualCount(4) + utf16 data
///   For VT_ARRAY|VT_UI1: cDims(2) + fFeatures(2) + cbElements(4) + cLocks(4) + pvData pointer(4) + rgsabound + array data
fn parse_variant_response(resp: &[u8]) -> Result<Vec<u8>> {
    // Minimum: RPC header (24) + ORPC_THAT (12) + HRESULT (4) + VARPTR (4) = 44
    if resp.len() < 48 {
        return Err(OverthroneError::Adcs(format!(
            "GetCAProperty response too short: {} bytes (expected >= 48)",
            resp.len()
        )));
    }

    // Skip RPC response header (24 bytes) + ORPC_THAT (12 bytes) + HRESULT (4 bytes) + VARPTR (4 bytes)
    let variant_offset: usize = 44;

    // Read vt (VARTYPE) at offset 0 of the VARIANT structure
    let vt = u16::from_le_bytes([resp[variant_offset], resp[variant_offset + 1]]);

    debug!(
        "[DCOM/ICertAdmin2] GetCAProperty response: vt=0x{vt:04x}, total_len={}",
        resp.len()
    );

    // The VARIANT union data starts at offset 8 from the variant base
    // For reference types (BSTR, SAFEARRAY), the union contains a pointer to the referent
    let union_offset = variant_offset + 8;

    match vt {
        0x0000 => {
            // VT_EMPTY
            Err(OverthroneError::Adcs(
                "GetCAProperty returned VT_EMPTY -- property not found or CA unavailable".to_string(),
            ))
        }
        0x0008 => {
            // VT_BSTR
            // Union contains a BSTR* pointer (4 bytes = 0x00020004 for non-null)
            // BSTR referent follows: maxCount(4) + offset(4) + actualCount(4) + utf16
            if union_offset + 4 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty BSTR response truncated".to_string(),
                ));
            }
            let bstr_ptr = u32::from_le_bytes([
                resp[union_offset],
                resp[union_offset + 1],
                resp[union_offset + 2],
                resp[union_offset + 3],
            ]);
            if bstr_ptr != 0x0002_0004 {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty BSTR: unexpected pointer marker: 0x{bstr_ptr:08x}"
                )));
            }
            let bstr_body = union_offset + 4;
            if bstr_body + 12 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty BSTR body too short".to_string(),
                ));
            }
            let _max_count = u32::from_le_bytes([
                resp[bstr_body],
                resp[bstr_body + 1],
                resp[bstr_body + 2],
                resp[bstr_body + 3],
            ]);
            let _offset = u32::from_le_bytes([
                resp[bstr_body + 4],
                resp[bstr_body + 5],
                resp[bstr_body + 6],
                resp[bstr_body + 7],
            ]);
            let actual_count = u32::from_le_bytes([
                resp[bstr_body + 8],
                resp[bstr_body + 9],
                resp[bstr_body + 10],
                resp[bstr_body + 11],
            ]);
            let str_data_start = bstr_body + 12;
            let str_byte_len = (actual_count as usize).saturating_mul(2); // UTF-16 chars * 2 bytes
            if str_data_start + str_byte_len > resp.len() {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty BSTR data truncated: needed {} bytes, have {}",
                    str_byte_len,
                    resp.len().saturating_sub(str_data_start)
                )));
            }
            let utf16_bytes = &resp[str_data_start..str_data_start + str_byte_len];
            // Convert UTF-16 to Vec<u8> (raw bytes for the caller)
            // For CA name, we return the raw UTF-16 bytes which get_ca_name_internal converts
            Ok(utf16_bytes.to_vec())
        }
        0x0011 | 0x1011 => {
            // VT_ARRAY | VT_UI1 (0x1011) or VT_VECTOR | VT_UI1 (0x1011)
            // Union contains a SAFEARRAY* pointer
            if union_offset + 4 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty SAFEARRAY response truncated".to_string(),
                ));
            }
            let sa_ptr = u32::from_le_bytes([
                resp[union_offset],
                resp[union_offset + 1],
                resp[union_offset + 2],
                resp[union_offset + 3],
            ]);
            if sa_ptr != 0x0002_0004 {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty SAFEARRAY: unexpected pointer marker: 0x{sa_ptr:08x}"
                )));
            }
            let sa_body = union_offset + 4;
            if sa_body + 16 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty SAFEARRAY header too short".to_string(),
                ));
            }
            let _c_dims = u16::from_le_bytes([resp[sa_body], resp[sa_body + 1]]);
            let _f_features = u16::from_le_bytes([resp[sa_body + 2], resp[sa_body + 3]]);
            let _cb_elements = u32::from_le_bytes([
                resp[sa_body + 4],
                resp[sa_body + 5],
                resp[sa_body + 6],
                resp[sa_body + 7],
            ]);
            let _c_locks = u32::from_le_bytes([
                resp[sa_body + 8],
                resp[sa_body + 9],
                resp[sa_body + 10],
                resp[sa_body + 11],
            ]);
            // pvData pointer (4 bytes = 0x00020004 or actual pointer)
            let _pv_data_ptr = u32::from_le_bytes([
                resp[sa_body + 12],
                resp[sa_body + 13],
                resp[sa_body + 14],
                resp[sa_body + 15],
            ]);
            // After the SAFEARRAY struct, rgsabound follows:
            //   cElements (4 bytes) + lLbound (4 bytes) per dimension
            let rgsabound_start = sa_body + 16;
            let element_count = if rgsabound_start + 4 <= resp.len() {
                u32::from_le_bytes([
                    resp[rgsabound_start],
                    resp[rgsabound_start + 1],
                    resp[rgsabound_start + 2],
                    resp[rgsabound_start + 3],
                ]) as usize
            } else {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty SAFEARRAY rgsabound truncated".to_string(),
                ));
            };
            // Array data follows rgsabound (after cElements + lLbound = 8 bytes)
            let array_data_start = rgsabound_start + 8;
            if array_data_start + element_count > resp.len() {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty SAFEARRAY data truncated: expected {element_count} bytes, have {}",
                    resp.len().saturating_sub(array_data_start)
                )));
            }
            Ok(resp[array_data_start..array_data_start + element_count].to_vec())
        }
        0x0013 => {
            // VT_UI4 -- 4-byte unsigned int
            if union_offset + 8 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty VT_UI4 response truncated".to_string(),
                ));
            }
            let val = u32::from_le_bytes([
                resp[union_offset],
                resp[union_offset + 1],
                resp[union_offset + 2],
                resp[union_offset + 3],
            ]);
            Ok(val.to_le_bytes().to_vec())
        }
        _ => {
            // Unknown variant type -- try scanning for DER certificate in response
            warn!(
                "[DCOM/ICertAdmin2] Unknown VARIANT type 0x{vt:04x} -- scanning for DER data"
            );
            // Search for ASN.1 DER certificate (starts with 0x30)
            for i in (variant_offset..resp.len().saturating_sub(8)).step_by(4) {
                if resp[i] == 0x30 && (resp[i + 1] & 0x80) != 0 {
                    let num_len_bytes = resp[i + 1] as usize & 0x7f;
                    let mut der_len = 0usize;
                    for j in 0..num_len_bytes.min(4) {
                        if i + 2 + j < resp.len() {
                            der_len = (der_len << 8) | resp[i + 2 + j] as usize;
                        }
                    }
                    let total_size = der_len + 2 + num_len_bytes.min(4);
                    if i + total_size <= resp.len() {
                        let cert_der = resp[i..i + total_size].to_vec();
                        info!(
                            "[DCOM/ICertAdmin2] CA certificate found via DER scan ({} bytes)",
                            cert_der.len()
                        );
                        return Ok(cert_der);
                    }
                }
            }
            Err(OverthroneError::Adcs(format!(
                "GetCAProperty unsupported VARIANT type 0x{vt:04x}",
            )))
        }
    }
}

/// Internal CA backup helper.
///
/// Retrieves the CA signing certificate via ICertAdmin2::GetCAProperty
/// (opnum 18) with CR_PROP_CASIGCERT (26).
/// This is the same path as get_ca_certificate() but callable
/// from within backup_ca_via_dcom() without an extra DCOM activation.
async fn backup_ca_internal(smb: &SmbSession, ipid: &[u8; 16], ca_name: &str) -> Result<Vec<u8>> {
    info!("[DCOM/ICertAdmin2] Performing CA backup for {ca_name}");

    // Retrieve CA signing certificate via GetCAProperty(CR_PROP_CASIGCERT = 26)
    let ca_cert = get_ca_property_internal(smb, ipid, ca_name, 26).await?;

    info!(
        "[DCOM/ICertAdmin2] CA certificate retrieved via GetCAProperty ({} bytes)",
        ca_cert.len()
    );

    Ok(ca_cert)
}

// ===========================================================
//  TCP RPC Path (bypasses DCOM activation)
// ===========================================================

/// ICertAdmin2 interface UUID (little-endian byte order)
/// UUID: 34df9e82-0e8b-11d3-8abd-00c04f7971e2
const ICERTADMIN2_UUID_LE: [u8; 16] = [
    0x82, 0x9e, 0xdf, 0x34, 0x8b, 0x0e, 0xd3, 0x11, 0x8a, 0xbd, 0x00, 0xc0, 0x4f, 0x79, 0x71, 0xe2,
];

/// Get the CA certificate via direct RPC on \pipe\cert (bypasses DCOM activation).
///
/// Opens an SMB session, binds directly to the ICertAdmin2 interface on the CA's
/// \pipe\cert named pipe, and calls GetCAProperty(CR_PROP_CASIGCERT = 26).
///
/// This bypasses DCOM activation entirely, making it suitable for Windows Server
/// 2025+ where anonymous DCOM activation via the SCM activator may be denied.
///
/// # Arguments
/// * `ca_host` - CA server hostname or IP address
/// * `domain` - NTLM domain name
/// * `username` - Username for SMB authentication
/// * `password` - Password for SMB authentication
///
/// # Returns
/// Raw DER-encoded CA certificate bytes
pub async fn get_ca_certificate_via_tcp_rpc(
    ca_host: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> Result<Vec<u8>> {
    info!(
        "[ICertAdmin2/SMB+RPC] Getting CA certificate from {} via direct RPC on \\pipe\\cert",
        ca_host
    );

    // 1. Connect via SMB
    let smb = SmbSession::connect(ca_host, domain, username, password).await.map_err(|e| {
        OverthroneError::Rpc {
            target: ca_host.to_string(),
            reason: format!("SMB connect failed: {e}"),
        }
    })?;

    // Compute NT hash from password
    let nt_hash_bytes = ntlm_hash(password);
    let nt_hash_slice = nt_hash_bytes.as_ref();

    // 2. Bind with NTLMSSP Type 1 (Negotiate)
    info!("[ICertAdmin2/SMB+RPC] Binding with NTLM auth on \\pipe\\cert");
    let ntlmssp_type1 = build_ntlmssp_negotiate();
    let bind_req = build_rpc_bind_auth(
        &ICERTADMIN2_UUID_LE,
        0,
        0,
        Some(&ntlmssp_type1),
        2, // RPC_C_AUTHN_LEVEL_CONNECT
    );
    let bind_resp = smb
        .pipe_transact(ICPR_NAMED_PIPE, &bind_req)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:cert", smb.target),
            reason: format!("ICertAdmin2 NTLM bind failed: {e}"),
        })?;

    if !overthrone_core::proto::epm::is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: format!("{}:cert", smb.target),
            reason: "ICertAdmin2 NTLM bind rejected".to_string(),
        });
    }

    // Extract NTLMSSP Type 2 (Challenge) from bind_ack auth verifier
    let challenge_bytes = extract_auth_body(&bind_resp).ok_or_else(|| {
        OverthroneError::Ntlm(
            "ICertAdmin2 bind_ack missing NTLMSSP challenge in auth verifier".to_string(),
        )
    })?;
    let challenge = parse_ntlmssp_challenge(challenge_bytes)?;

    // Build NTLMSSP Type 3 (Authenticate) and send AUTH3 PDU
    let (type3, _session_key, _session_base_key) =
        build_ntlmssp_authenticate_hash(domain, username, nt_hash_slice, &challenge)?;
    let auth3 = build_auth3_pdu(&type3, 2);
    let _auth_resp = smb
        .pipe_transact(ICPR_NAMED_PIPE, &auth3)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:cert", smb.target),
            reason: format!("ICertAdmin2 AUTH3 failed: {e}"),
        })?;

    info!("[ICertAdmin2/SMB+RPC] NTLM auth complete");

    // 3. Call GetCAProperty with CR_PROP_CASIGCERT = 26
    let config_str = format!("{}\\", ca_host);

    let mut stub = Vec::new();
    stub.extend_from_slice(&[0u8; 20]); // context handle
    dcom::write_bstr(&mut stub, &config_str); // BSTR strConfig
    stub.extend_from_slice(&26u32.to_le_bytes()); // CR_PROP_CASIGCERT
    stub.extend_from_slice(&0u32.to_le_bytes()); // propIndex
    stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // propType = autodetect
    stub.extend_from_slice(&0x0002_0004u32.to_le_bytes()); // [out] VARIANT*
    while stub.len() % 8 != 0 {
        stub.push(0);
    }

    let req = build_rpc_request(OPNUM_GET_CA_PROPERTY, &stub);
    let resp = smb
        .pipe_transact(ICPR_NAMED_PIPE, &req)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:cert", smb.target),
            reason: format!("GetCAProperty failed: {e}"),
        })?;

    // 4. Parse response -- direct RPC format:
    //    RPC header (24 bytes) + context handle (20 bytes) + HRESULT (4 bytes) + VARIANT inline
    parse_variant_response_rpc(&resp)
}

/// Parse a direct RPC response from ICertAdmin2::GetCAProperty.
///
/// Direct RPC response format (no DCOM wrapping):
///   RPC header (24 bytes)
///   Context handle (20 bytes) - [in,out]
///   HRESULT (4 bytes)
///   [out] VARIANT inline
///
/// The VARIANT has the same NDR encoding as in DCOM.
fn parse_variant_response_rpc(resp: &[u8]) -> Result<Vec<u8>> {
    // Minimum: RPC header (24) + context handle (20) + HRESULT (4) + VARPTR (4) + vt(2) = 54
    if resp.len() < 54 {
        return Err(OverthroneError::Adcs(format!(
            "GetCAProperty RPC response too short: {} bytes (expected >= 54)",
            resp.len()
        )));
    }

    // The VARIANT starts after RPC header (24) + context handle (20) + HRESULT (4) = 48
    let variant_offset: usize = 48;

    // Read vt (VARTYPE) at offset 0 of the VARIANT structure
    let vt = u16::from_le_bytes([resp[variant_offset], resp[variant_offset + 1]]);

    debug!(
        "[ICertAdmin2/RPC] GetCAProperty response: vt=0x{vt:04x}, total_len={}",
        resp.len()
    );

    // The VARIANT union data starts at offset 8 from the variant base
    let union_offset = variant_offset + 8;

    match vt {
        0x0000 => {
            Err(OverthroneError::Adcs(
                "GetCAProperty returned VT_EMPTY -- property not found or CA unavailable".to_string(),
            ))
        }
        0x0008 => {
            // VT_BSTR
            if union_offset + 4 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty BSTR response truncated".to_string(),
                ));
            }
            let bstr_ptr = u32::from_le_bytes([
                resp[union_offset],
                resp[union_offset + 1],
                resp[union_offset + 2],
                resp[union_offset + 3],
            ]);
            if bstr_ptr != 0x0002_0004 {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty BSTR: unexpected pointer marker: 0x{bstr_ptr:08x}"
                )));
            }
            let bstr_body = union_offset + 4;
            if bstr_body + 12 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty BSTR body too short".to_string(),
                ));
            }
            let _max_count = u32::from_le_bytes([
                resp[bstr_body], resp[bstr_body + 1], resp[bstr_body + 2], resp[bstr_body + 3],
            ]);
            let _offset = u32::from_le_bytes([
                resp[bstr_body + 4], resp[bstr_body + 5], resp[bstr_body + 6], resp[bstr_body + 7],
            ]);
            let actual_count = u32::from_le_bytes([
                resp[bstr_body + 8], resp[bstr_body + 9], resp[bstr_body + 10], resp[bstr_body + 11],
            ]);
            let str_data_start = bstr_body + 12;
            let str_byte_len = (actual_count as usize).saturating_mul(2);
            if str_data_start + str_byte_len > resp.len() {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty BSTR data truncated: needed {} bytes, have {}",
                    str_byte_len,
                    resp.len().saturating_sub(str_data_start)
                )));
            }
            let utf16_bytes = &resp[str_data_start..str_data_start + str_byte_len];
            Ok(utf16_bytes.to_vec())
        }
        0x0011 | 0x1011 => {
            // VT_ARRAY | VT_UI1
            if union_offset + 4 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty SAFEARRAY response truncated".to_string(),
                ));
            }
            let sa_ptr = u32::from_le_bytes([
                resp[union_offset],
                resp[union_offset + 1],
                resp[union_offset + 2],
                resp[union_offset + 3],
            ]);
            if sa_ptr != 0x0002_0004 {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty SAFEARRAY: unexpected pointer marker: 0x{sa_ptr:08x}"
                )));
            }
            let sa_body = union_offset + 4;
            if sa_body + 16 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty SAFEARRAY header too short".to_string(),
                ));
            }
            let _c_dims = u16::from_le_bytes([resp[sa_body], resp[sa_body + 1]]);
            let _f_features = u16::from_le_bytes([resp[sa_body + 2], resp[sa_body + 3]]);
            let _cb_elements = u32::from_le_bytes([
                resp[sa_body + 4], resp[sa_body + 5], resp[sa_body + 6], resp[sa_body + 7],
            ]);
            let _c_locks = u32::from_le_bytes([
                resp[sa_body + 8], resp[sa_body + 9], resp[sa_body + 10], resp[sa_body + 11],
            ]);
            let _pv_data_ptr = u32::from_le_bytes([
                resp[sa_body + 12], resp[sa_body + 13], resp[sa_body + 14], resp[sa_body + 15],
            ]);
            let rgsabound_start = sa_body + 16;
            let element_count = if rgsabound_start + 4 <= resp.len() {
                u32::from_le_bytes([
                    resp[rgsabound_start],
                    resp[rgsabound_start + 1],
                    resp[rgsabound_start + 2],
                    resp[rgsabound_start + 3],
                ]) as usize
            } else {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty SAFEARRAY rgsabound truncated".to_string(),
                ));
            };
            let array_data_start = rgsabound_start + 8;
            if array_data_start + element_count > resp.len() {
                return Err(OverthroneError::Adcs(format!(
                    "GetCAProperty SAFEARRAY data truncated: expected {element_count} bytes, have {}",
                    resp.len().saturating_sub(array_data_start)
                )));
            }
            Ok(resp[array_data_start..array_data_start + element_count].to_vec())
        }
        0x0013 => {
            // VT_UI4
            if union_offset + 8 > resp.len() {
                return Err(OverthroneError::Adcs(
                    "GetCAProperty VT_UI4 response truncated".to_string(),
                ));
            }
            let val = u32::from_le_bytes([
                resp[union_offset],
                resp[union_offset + 1],
                resp[union_offset + 2],
                resp[union_offset + 3],
            ]);
            Ok(val.to_le_bytes().to_vec())
        }
        _ => {
            warn!(
                "[ICertAdmin2/RPC] Unknown VARIANT type 0x{vt:04x} -- scanning for DER data"
            );
            for i in (variant_offset..resp.len().saturating_sub(8)).step_by(4) {
                if resp[i] == 0x30 && (resp[i + 1] & 0x80) != 0 {
                    let num_len_bytes = resp[i + 1] as usize & 0x7f;
                    let mut der_len = 0usize;
                    for j in 0..num_len_bytes.min(4) {
                        if i + 2 + j < resp.len() {
                            der_len = (der_len << 8) | resp[i + 2 + j] as usize;
                        }
                    }
                    let total_size = der_len + 2 + num_len_bytes.min(4);
                    if i + total_size <= resp.len() {
                        let cert_der = resp[i..i + total_size].to_vec();
                        info!(
                            "[ICertAdmin2/RPC] CA certificate found via DER scan ({} bytes)",
                            cert_der.len()
                        );
                        return Ok(cert_der);
                    }
                }
            }
            Err(OverthroneError::Adcs(format!(
                "GetCAProperty unsupported VARIANT type 0x{vt:04x}",
            )))
        }
    }
}

/// Get the CA certificate via LDAP from Active Directory.
///
/// The CA certificate is published in the `cACertificate` attribute of
/// the CA object in the Configuration Naming Context. This avoids any
/// DCOM or RPC calls to the CA server itself.
///
/// # Arguments
/// * `dc_host` - Domain controller hostname or IP address
/// * `domain` - NTLM domain name
/// * `username` - Username for LDAP authentication
/// * `password` - Password for LDAP authentication
///
/// # Returns
/// Raw DER-encoded CA certificate bytes
pub async fn get_ca_certificate_via_ldap(
    dc_host: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> Result<Vec<u8>> {
    info!(
        "[CA/LDAP] Getting CA certificate from {dc_host} via LDAP (Configuration NC)"
    );

    // Connect to LDAP (without TLS -- works with self-signed certs)
    let mut ldap = LdapSession::connect(dc_host, domain, username, password, false)
        .await
        .map_err(|e| OverthroneError::Adcs(format!("LDAP connect failed: {e}")))?;

    // Query the Configuration NC for the CA object
    let config_nc = format!("CN=Configuration,{}", ldap.base_dn);
    let filter = "(objectClass=certificationAuthority)".to_string();

    let entries = ldap
        .custom_search_with_base(&config_nc, &filter, &["cACertificate", "cn"])
        .await
        .map_err(|e| OverthroneError::Adcs(format!("LDAP CA search failed: {e}")))?;

    if entries.is_empty() {
        return Err(OverthroneError::Adcs(
            "No certificationAuthority objects found in Configuration NC".to_string(),
        ));
    }

    // Use the first CA's certificate
    let entry = &entries[0];
    let ca_name = entry
        .attrs
        .get("cn")
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("UnknownCA");

    // Try attrs first (string-based), then bin_attrs (binary).
    // ldap3 stores binary attributes in bin_attrs when the raw bytes
    // are not valid UTF-8.
    let cert_der = entry
        .attrs
        .get("cACertificate")
        .and_then(|v| v.first())
        .map(|s| s.as_bytes().to_vec())
        .or_else(|| {
            entry
                .bin_attrs
                .get("cacertificate")
                .or_else(|| entry.bin_attrs.get("cACertificate"))
                .and_then(|v| v.first())
                .cloned()
        })
        .ok_or_else(|| {
            OverthroneError::Adcs(format!(
                "CA '{ca_name}' has no cACertificate attribute"
            ))
        })?;

    info!(
        "[CA/LDAP] CA certificate for '{ca_name}' obtained via LDAP ({} bytes)",
        cert_der.len()
    );
    Ok(cert_der)
}

/// Backup CA certificate via TCP-based authenticated RPC.
///
/// Same flow as `get_ca_certificate_via_tcp_rpc()` but wraps the result
/// as a backup operation for reporting purposes.
pub async fn backup_ca_via_tcp_rpc(
    ca_host: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> Result<Vec<u8>> {
    info!(
        "[ICertAdmin2/TCP] Backing up CA certificate from {} via TCP RPC",
        ca_host
    );

    let ca_cert = get_ca_certificate_via_tcp_rpc(ca_host, domain, username, password).await?;

    info!(
        "[ICertAdmin2/TCP] CA certificate backed up ({} bytes)",
        ca_cert.len()
    );

    Ok(ca_cert)
}

// ===========================================================
//  Response Parsing
// ===========================================================

/// Parse a DCOM ICertRequestD::RequestCertificate response.
///
/// The response contains:
/// - RPC header (24 bytes)
/// - ORPC_THAT (8+ bytes: flags + extensions ptr + hresult)
/// - Return value (4 bytes)
/// - Output parameters: pdwRequestId, pdwDisposition, pctbCertChain, pdwEncodedDisposition
fn parse_dcom_cert_response(resp: &[u8], _ca_name: &str) -> Result<Vec<u8>> {
    if resp.len() < 28 {
        return Err(OverthroneError::CertificateRequest(
            "DCOM response too short (no RPC header)".to_string(),
        ));
    }

    // Skip RPC response header (24 bytes) + ORPC_THAT (flags 4 + ext ptr 4 + hresult 4 = 12 bytes)
    let stub_start: usize = 24;

    if stub_start + 4 > resp.len() {
        return Err(OverthroneError::CertificateRequest(
            "Response too short for stub data".to_string(),
        ));
    }

    // HRESULT from ORPC_THAT
    let _orpc_hresult = u32::from_le_bytes([
        resp[stub_start + 8],
        resp[stub_start + 9],
        resp[stub_start + 10],
        resp[stub_start + 11],
    ]);

    // After ORPC_THAT, the stub data begins
    let data_start = stub_start + 12;

    if data_start + 4 > resp.len() {
        return Err(OverthroneError::CertificateRequest(
            "Response too short for output parameters".to_string(),
        ));
    }

    // pdwRequestId (4 bytes)
    let _request_id = u32::from_le_bytes([
        resp[data_start],
        resp[data_start + 1],
        resp[data_start + 2],
        resp[data_start + 3],
    ]);

    if data_start + 8 > resp.len() {
        return Err(OverthroneError::CertificateRequest(
            "Response too short for disposition".to_string(),
        ));
    }

    // pdwDisposition (4 bytes)
    let disposition = u32::from_le_bytes([
        resp[data_start + 4],
        resp[data_start + 5],
        resp[data_start + 6],
        resp[data_start + 7],
    ]);

    debug!("[DCOM/ICertRequestD] Disposition: {disposition}");

    match disposition {
        1 => {
            return Err(OverthroneError::CertificateRequest(
                "Certificate request denied by CA".to_string(),
            ));
        }
        2 => {
            return Err(OverthroneError::CertificateRequest(
                "Certificate request pending (requires manager approval)".to_string(),
            ));
        }
        4 => {
            return Err(OverthroneError::CertificateRequest(
                "Certificate request denied by policy".to_string(),
            ));
        }
        _ => {}
    }

    // pctbCertChain -- scan for DER certificate (starts with 0x30)
    for i in (data_start + 12..resp.len().saturating_sub(8)).step_by(4) {
        if resp[i] == 0x30 && (resp[i + 1] & 0x80) != 0 {
            let num_len_bytes = resp[i + 1] as usize & 0x7f;
            let mut der_len = 0;
            for j in 0..num_len_bytes.min(4) {
                if i + 2 + j < resp.len() {
                    der_len = (der_len << 8) | resp[i + 2 + j] as usize;
                }
            }
            let total_size = der_len + 2 + num_len_bytes.min(4); // tag + length + content
            if i + total_size <= resp.len() {
                let cert_der = resp[i..i + total_size].to_vec();
                info!(
                    "[DCOM/ICertRequestD] Certificate obtained ({} bytes)",
                    cert_der.len()
                );
                return Ok(cert_der);
            }
        }
    }

    // Fallback: scan for NDR blob patterns
    let mut idx = data_start + 16;
    while idx + 12 < resp.len() {
        let max_count = u32::from_le_bytes(resp[idx..idx + 4].try_into().unwrap_or([0; 4]));
        let offset = u32::from_le_bytes(resp[idx + 4..idx + 8].try_into().unwrap_or([0; 4]));
        let actual = u32::from_le_bytes(resp[idx + 8..idx + 12].try_into().unwrap_or([0; 4]));

        if offset == 0 && actual > 200 && actual < 50000 && max_count >= actual {
            let data_start2 = idx + 12;
            if data_start2 + actual as usize <= resp.len() && resp[data_start2] == 0x30 {
                let cert_der = resp[data_start2..data_start2 + actual as usize].to_vec();
                info!(
                    "[DCOM/ICertRequestD] Certificate obtained via blob scan ({} bytes)",
                    cert_der.len()
                );
                return Ok(cert_der);
            }
        }
        idx += 4;
    }

    Err(OverthroneError::CertificateRequest(
        "Failed to extract certificate from DCOM response".to_string(),
    ))
}

// ===========================================================
//  Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clsid_ccertrequest_le_bytes() {
        // Verify CLSID_CCERTREQUEST matches {98c4bd30-fa7c-11d0-88b3-00a0c90312f3}
        let expected = [
            0x30, 0xBD, 0xC4, 0x98, 0x7C, 0xFA, 0xD0, 0x11, 0x88, 0xB3, 0x00, 0xA0, 0xC9, 0x03,
            0x12, 0xF3,
        ];
        assert_eq!(CLSID_CCERTREQUEST, expected);
    }

    #[test]
    fn test_clsid_ccertadmin_le_bytes() {
        // Verify CLSID_CCERTADMIN matches {005b8a22-a80b-4a8b-a1fc-054aaab53e06}
        let expected = [
            0x22, 0x8A, 0x5B, 0x00, 0x0B, 0xA8, 0x8B, 0x4A, 0xA1, 0xFC, 0x05, 0x4A, 0xAA, 0xB5,
            0x3E, 0x06,
        ];
        assert_eq!(CLSID_CCERTADMIN, expected);
    }

    #[test]
    fn test_iid_icertrequestd_le_bytes() {
        // Verify IID_ICERTREQUESTD matches {d99e6e74-fc88-11d0-b498-00a0c90312f3}
        let expected = [
            0x74, 0x6E, 0x9E, 0xD9, 0x88, 0xFC, 0xD0, 0x11, 0xB4, 0x98, 0x00, 0xA0, 0xC9, 0x03,
            0x12, 0xF3,
        ];
        assert_eq!(IID_ICERTREQUESTD, expected);
    }

    #[test]
    fn test_iid_icertadmin2_le_bytes() {
        // Verify IID_ICERTADMIN2 matches {34df9e82-0e8b-11d3-8abd-00c04f7971e2}
        let expected = [
            0x82, 0x9E, 0xDF, 0x34, 0x8B, 0x0E, 0xD3, 0x11, 0x8A, 0xBD, 0x00, 0xC0, 0x4F, 0x79,
            0x71, 0xE2,
        ];
        assert_eq!(IID_ICERTADMIN2, expected);
    }

    #[test]
    fn test_opnum_constants() {
        assert_eq!(OPNUM_REQUEST_CERTIFICATE, 1);
        assert_eq!(OPNUM_GET_CERTIFICATE, 2);
        assert_eq!(OPNUM_GET_CA_PROPERTY, 18);
        assert_eq!(OPNUM_SET_CA_PROPERTY, 19);
        assert_eq!(OPNUM_BACKUP_CA, 21);
        assert_eq!(OPNUM_GET_CA_CRLS, 24);
    }

    #[test]
    fn test_parse_dcom_cert_response_short() {
        let resp = vec![0u8; 10];
        assert!(parse_dcom_cert_response(&resp, "test-CA").is_err());
    }

    #[test]
    fn test_parse_dcom_cert_response_denied() {
        // Response with disposition = 4 (denied by policy)
        let mut resp = vec![0u8; 60];
        // RPC header: 24 bytes filled with zeros
        // ORPC_THAT: flags(4) + ext_ptr(4) + hresult(4) at offset 24
        // Stub data at offset 36
        // Disposition at offset 40
        resp[40] = 4;
        resp[41] = 0;
        resp[42] = 0;
        resp[43] = 0;
        assert!(parse_dcom_cert_response(&resp, "test-CA").is_err());
        assert!(
            parse_dcom_cert_response(&resp, "test-CA")
                .unwrap_err()
                .to_string()
                .contains("denied by policy")
        );
    }

    #[test]
    fn test_parse_dcom_cert_response_pending() {
        let mut resp = vec![0u8; 60];
        resp[40] = 2;
        resp[41] = 0;
        resp[42] = 0;
        resp[43] = 0; // disposition = 2
        assert!(parse_dcom_cert_response(&resp, "test-CA").is_err());
        assert!(
            parse_dcom_cert_response(&resp, "test-CA")
                .unwrap_err()
                .to_string()
                .contains("pending")
        );
    }

    #[test]
    fn test_parse_dcom_cert_response_issued() {
        // Valid response with disposition = 3 and a DER certificate
        let mut resp = vec![0u8; 100];
        // RPC header (24 bytes) -- ensure no DER marker (0x30) in header
        for i in 0..24 {
            resp[i] = 0xFF;
        }
        // ORPC_THAT at offset 24 (flags + ext_ptr + hresult = 12 bytes)
        for i in 24..36 {
            resp[i] = 0xAA;
        }
        // Stub starts at offset 36:
        //   requestId at 36
        resp[36] = 1;
        resp[37] = 0;
        resp[38] = 0;
        resp[39] = 0;
        //   disposition at 40
        resp[40] = 3;
        resp[41] = 0;
        resp[42] = 0;
        resp[43] = 0;
        // Place a valid DER cert marker at offset 64 (16-byte aligned past stub data)
        let cert_start = 64usize;
        resp[cert_start] = 0x30;
        resp[cert_start + 1] = 0x82;
        resp[cert_start + 2] = 0x00;
        resp[cert_start + 3] = 0x08; // length = 8
        for i in 0..8 {
            resp[cert_start + 4 + i] = i as u8;
        }

        let result = parse_dcom_cert_response(&resp, "test-CA");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 12);
    }

    #[test]
    fn test_parse_dcom_cert_response_blob_scan() {
        // Test the fallback blob scan path
        let mut resp = vec![0xFFu8; 200];
        // RPC header (24 bytes) + ORPC_THAT (12 bytes) = 36 bytes
        // Ensure no 0x30 bytes in header/rpc/orpc regions
        // Stub at 36: requestId + disposition
        resp[36] = 5;
        resp[37] = 0;
        resp[38] = 0;
        resp[39] = 0; // requestId
        resp[40] = 3;
        resp[41] = 0;
        resp[42] = 0;
        resp[43] = 0; // disposition = 3
        // At offset 80, place a NDR blob structure
        let blob_offset = 80usize;
        let cert_data = vec![
            0x30, 0x82, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let actual_count = cert_data.len() as u32;
        resp[blob_offset..blob_offset + 4].copy_from_slice(&actual_count.to_le_bytes());
        resp[blob_offset + 4..blob_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        resp[blob_offset + 8..blob_offset + 12].copy_from_slice(&actual_count.to_le_bytes());
        resp[blob_offset + 12..blob_offset + 12 + cert_data.len()].copy_from_slice(&cert_data);

        let result = parse_dcom_cert_response(&resp, "test-CA");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), cert_data.len());
    }

    #[test]
    fn test_dcom_stub_encoding() {
        // Verify the DCOM RequestCertificate stub encoding produces valid output
        let mut stub = Vec::new();
        stub.extend(dcom::build_orpc_this());
        dcom::write_ndr_string(&mut stub, "test-CA");
        stub.extend_from_slice(&0u32.to_le_bytes()); // dwFlags
        stub.extend_from_slice(&0u32.to_le_bytes()); // dwRequestIdOffset
        let csr = vec![0x30u8; 256];
        let count = csr.len() as u32;
        stub.extend_from_slice(&count.to_le_bytes()); // cbCount
        stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pbData pointer
        while stub.len() % 8 != 0 {
            stub.push(0);
        }
        stub.extend_from_slice(&count.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&count.to_le_bytes());
        stub.extend_from_slice(&csr);
        dcom::write_ndr_string(&mut stub, "");
        stub.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        while stub.len() % 8 != 0 {
            stub.push(0);
        }

        // Verify the ORPC_THIS header is at the start
        assert!(stub.len() > 40);
        // ORPC version: major=5 (LE u16: 5,0), minor=7 (LE u16: 7,0)
        assert_eq!(stub[0], 5);
        assert_eq!(stub[1], 0);
        assert_eq!(stub[2], 7);
        assert_eq!(stub[3], 0);
    }
}
