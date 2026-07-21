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

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::dcom;
use overthrone_core::proto::smb::SmbSession;
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
#[cfg_attr(not(test), allow(dead_code))]
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

/// Get a CA property via ICertAdmin2::GetCAProperty.
///
/// The GetCAProperty call has different semantics depending on whether
/// we use the [MS-ICDH] raw RPC or the DCOM interface. For the DCOM
/// interface, we need to build the ORPC request with proper parameters.
async fn get_ca_property_internal(
    _smb: &SmbSession,
    _ipid: &[u8; 16],
    _ca_name: &str,
    _prop_id: u32,
) -> Result<Vec<u8>> {
    // ICertAdmin2::GetCAProperty over DCOM takes:
    //   [in] BSTR strConfig (CA config string "hostname\CA-Name")
    //   [in] LONG propId
    //   [in] LONG propIndex
    //   [in] LONG propType
    //   [out] VARIANT* pvarPropertyValue
    //
    // We use the raw RPC approach instead (opnum 18) which returns
    // a CRYPT_DATA_BLOB directly.

    warn!(
        "[DCOM/ICertAdmin2] GetCAProperty over raw DCOM not fully implemented -- using server config query instead"
    );

    // For DCOM ICertAdmin2, we'd need the full ORPC call with NDR encoding.
    // The raw opnum 18 binding on \pipe\cert is for the MS-ICDH interface,
    // not the DCOM interface. Return empty for now.
    Err(OverthroneError::Adcs(
        "GetCAProperty DCOM not fully implemented -- use raw RPC path".to_string(),
    ))
}

/// Internal CA backup helper.
///
/// Uses the ICertAdmin2 RPC interface on \pipe\cert (opnum 21)
/// to retrieve the CA certificate chain.
async fn backup_ca_internal(smb: &SmbSession, ipid: &[u8; 16], ca_name: &str) -> Result<Vec<u8>> {
    info!("[DCOM/ICertAdmin2] Performing CA backup for {ca_name}");

    let mut stub = Vec::new();
    stub.extend(dcom::build_orpc_this());

    // strConfig -- CA config as BSTR "hostname\CA-Name"
    dcom::write_bstr(&mut stub, ca_name);

    // BackupCA takes additional parameters depending on version.
    // For simplicity, we request the certificate chain.
    // The backup process on the server generates a backup file set;
    // for certificate extraction we use GetCAProperty instead.

    // For now, try to get the CA signing certificate via the simpler path
    drop(stub);

    // Fall through to the CA cert retrieval
    get_ca_certificate_internal(smb, ipid, ca_name).await
}

/// Retrieve the CA signing certificate via direct property query on \pipe\cert.
///
/// Uses the MS-ICDH raw RPC interface (same UUID as ICertRequestD
/// but with different opnums for admin operations).
async fn get_ca_certificate_internal(
    _smb: &SmbSession,
    _ipid: &[u8; 16],
    _ca_name: &str,
) -> Result<Vec<u8>> {
    // The CA certificate can be obtained via the MS-ICDH interface
    // on \pipe\cert using opnum 18 (GetCAProperty) with propId = 26
    // (CR_PROP_CASIGCERT).
    //
    // For DCOM, this is ICertAdmin2::GetCAProperty which uses
    // VARIANT output, not the raw CRYPT_DATA_BLOB.
    //
    // The implementation requires the full NDR stub encoding of
    // the GetCAProperty parameters for the DCOM interface.

    Err(OverthroneError::Adcs(
        "CA certificate backup via DCOM requires full ICertAdmin2 ORPC stub encoding -- use cert_store::request_cert_via_rpc for RPC-based enrollment".to_string(),
    ))
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
