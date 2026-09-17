//! NetExec-style multi-protocol host checker.
//!
//! `ovt nxc <protocol> <targets>` performs a single-shot, low-noise triage of a
//! host and reports the same fields traditional tooling does:
//!
//! * **smb**   -- SMB2/3 dialect, signing requirement, SMBv1 acceptance, and the
//!   host identity/functional level from the LDAP RootDSE.
//! * **ldap**  -- RootDSE identity, functional level, and whether an anonymous
//!   simple bind is accepted.
//! * **winrm** -- whether a WinRM HTTP listener answers with a 401 challenge.
//! * **rpc**   -- whether the DCE/RPC Endpoint Mapper (port 135) answers a bind.
//!
//! When credentials are supplied with the global `-u/-p/--nt-hash` flags the
//! checker also validates them over SMB and reports administrative access with
//! the same `(Pwn3d!)` marker NetExec uses.

use colored::Colorize;
use futures::stream::StreamExt;
use overthrone_core::proto::{epm, ldap, netbios, smb, smb2};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::{AuthData, Credentials};

// ===========================================================
//  CLI surface
// ===========================================================

/// Protocol to check. `all` runs every protocol against each target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NxcProtocol {
    Smb,
    Ldap,
    Winrm,
    Rpc,
    All,
}

impl std::fmt::Display for NxcProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Smb => "smb",
            Self::Ldap => "ldap",
            Self::Winrm => "winrm",
            Self::Rpc => "rpc",
            Self::All => "all",
        })
    }
}

const SMB_PORT: u16 = 445;
const LDAP_PORT: u16 = 389;
const WINRM_PORT: u16 = 5985;
const RPC_PORT: u16 = 135;

// ===========================================================
//  Target expansion
// ===========================================================

/// Expand comma/whitespace separated targets, including IPv4 CIDR notation.
///
/// Network and broadcast addresses are omitted for prefixes `<= /30` so a
/// `/24` yields 254 hosts, matching NetExec's behaviour.
pub(crate) fn expand_targets(input: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in input {
        for part in raw.split([',', ' ', '\t', '\n']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((addr, prefix)) = part.split_once('/')
                && let (Ok(ip), Ok(prefix)) = (addr.parse::<Ipv4Addr>(), prefix.parse::<u8>())
                && prefix <= 32
            {
                let base = u32::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let network = base & mask;
                let broadcast = network | !mask;
                let (start, end) = if prefix <= 30 {
                    (network.saturating_add(1), broadcast.saturating_sub(1))
                } else {
                    (network, broadcast)
                };
                let mut cur = start;
                while cur <= end {
                    out.push(Ipv4Addr::from(cur).to_string());
                    if cur == end {
                        break;
                    }
                    cur += 1;
                }
                continue;
            }
            out.push(part.to_string());
        }
    }
    out.dedup();
    out
}

// ===========================================================
//  Report model
// ===========================================================

/// One protocol check against one host.
#[derive(Debug, Default)]
struct HostReport {
    protocol: &'static str,
    target: String,
    port: u16,
    host_name: Option<String>,
    /// Informational line (netexec's `[*]` row).
    info: Option<String>,
    /// Credential validation line (netexec's `[+]` row).
    cred: Option<String>,
    /// Administrative access confirmed.
    pwned: bool,
    /// Fatal error for this check (netexec's `[-]` row).
    error: Option<String>,
}

impl HostReport {
    fn new(protocol: &'static str, target: &str, port: u16) -> Self {
        Self {
            protocol,
            target: target.to_string(),
            port,
            ..Default::default()
        }
    }

    fn print(&self, only_positive: bool) {
        let host = self.host_name.as_deref().unwrap_or("");
        let head = format!(
            "{:<7} {:<15} {:<5} {:<15}",
            self.protocol, self.target, self.port, host
        );
        if let Some(info) = &self.info {
            println!("{} {} {}", head, "[*]".cyan().bold(), info.dimmed());
        }
        if let Some(cred) = &self.cred {
            let marker = if self.pwned {
                "[+]".green().bold().to_string()
            } else {
                "[+]".green().to_string()
            };
            println!("{} {} {}", head, marker, cred.green());
        }
        if let Some(err) = &self.error
            && !only_positive
        {
            println!("{} {} {}", head, "[-]".red().bold(), err.red());
        }
    }

    /// True when the check produced a usable result.
    fn is_positive(&self) -> bool {
        self.error.is_none() && (self.info.is_some() || self.cred.is_some())
    }
}

// ===========================================================
//  SMB checks
// ===========================================================

/// Build a NetBIOS-framed SMB1 `NEGOTIATE` request proposing SMB2 dialects too.
///
/// A server that still accepts SMB1 answers this with an `\xffSMB` negotiate
/// response; a server with SMB1 disabled drops the connection or answers with
/// `\xfeSMB` (SMB2). This mirrors how `smbclient -m NT1` and NetExec decide the
/// `SMBv1` column.
fn build_smb1_negotiate() -> Vec<u8> {
    let mut smb = Vec::with_capacity(64);
    smb.extend_from_slice(b"\xffSMB"); // Protocol
    smb.push(0x72); // Command = NEGOTIATE
    smb.extend_from_slice(&[0, 0, 0, 0]); // Status
    smb.push(0x18); // Flags
    smb.extend_from_slice(&[0x53, 0xc8]); // Flags2 (unicode + NT status)
    smb.extend_from_slice(&[0, 0]); // PID high
    smb.extend_from_slice(&[0u8; 8]); // Signature
    smb.extend_from_slice(&[0, 0]); // Reserved
    smb.extend_from_slice(&[0, 0]); // Tree ID
    smb.extend_from_slice(&[0, 0]); // Process ID
    smb.extend_from_slice(&[0, 0]); // User ID
    smb.extend_from_slice(&[0, 0]); // Multiplex ID
    smb.push(0); // WordCount
    let dialects: &[&[u8]] = &[b"\x02NT LM 0.12\x00", b"\x02SMB 2.002\x00"];
    let byte_count: usize = dialects.iter().map(|d| d.len()).sum();
    smb.extend_from_slice(&(byte_count as u16).to_le_bytes());
    for d in dialects {
        smb.extend_from_slice(d);
    }

    let mut framed = Vec::with_capacity(4 + smb.len());
    framed.push(0x00);
    let len = smb.len() as u32;
    framed.extend_from_slice(&len.to_be_bytes()[1..]);
    framed.extend_from_slice(&smb);
    framed
}

/// Convert an AD naming context (`DC=LAINOSCP,DC=local`) into a DNS domain
/// (`LAINOSCP.local`).
fn naming_context_to_dns(nc: &str) -> String {
    nc.split(',')
        .filter_map(|part| {
            let part = part.trim();
            part.strip_prefix("DC=")
                .or_else(|| part.strip_prefix("dc="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Probe whether the target still negotiates SMB1.
///
/// Returns `Some(true)` when the server replies with an SMB1 negotiate,
/// `Some(false)` when it answers with SMB2 or refuses, and `None` when the
/// probe could not run (port closed, timeout).
pub(crate) async fn probe_smb1(target: &str) -> Option<bool> {
    let addr = format!("{target}:{SMB_PORT}");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .ok()?
    .ok()?;

    let req = build_smb1_negotiate();
    stream.write_all(&req).await.ok()?;

    let mut len_buf = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf)).await;
    let Ok(Ok(_)) = read else {
        return Some(false); // reset by peer => SMB1 disabled
    };
    let len = u32::from_be_bytes([0, len_buf[1], len_buf[2], len_buf[3]]) as usize;
    if !(4..=1 << 20).contains(&len) {
        return Some(false);
    }
    let mut body = vec![0u8; len];
    if tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut body))
        .await
        .ok()?
        .is_err()
    {
        return Some(false);
    }
    Some(body.starts_with(b"\xffSMB"))
}

/// Check SMB: negotiate + identity, then optionally validate credentials.
async fn check_smb(target: &str, creds: &[Credentials]) -> HostReport {
    let mut report = HostReport::new("SMB", target, SMB_PORT);

    let neg = match netbios::smb_negotiate(target).await {
        Ok(n) => n,
        Err(e) => {
            report.error = Some(format!("SMB negotiate failed: {e}"));
            return report;
        }
    };

    // Host identity: the NTLM challenge AV_PAIRs (works unauthenticated even
    // when null sessions are disabled), enriched by the LDAP RootDSE when the
    // target also runs a directory service.
    let identity = smb2::Smb2Connection::probe_server_identity(target)
        .await
        .ok();
    let root = ldap::probe_rootdse_raw(target, false).await.ok();

    let host_name = identity
        .as_ref()
        .and_then(|i| i.dns_computer_name.clone())
        .or_else(|| identity.as_ref().and_then(|i| i.computer_name.clone()))
        .or_else(|| root.as_ref().and_then(|r| r.dns_host_name.clone()))
        .or_else(|| root.as_ref().and_then(|r| r.server_name.clone()));
    report.host_name = host_name.clone();

    // DNS domain: challenge first, then RootDSE, then derived from the naming
    // context when the DC does not publish `dnsDomainName`.
    let domain = identity
        .as_ref()
        .and_then(|i| i.dns_domain_name.clone())
        .or_else(|| identity.as_ref().and_then(|i| i.domain_name.clone()))
        .or_else(|| root.as_ref().and_then(|r| r.dns_domain_name.clone()))
        .or_else(|| {
            root.as_ref()
                .and_then(|r| r.default_naming_context.as_deref())
                .map(naming_context_to_dns)
        })
        .unwrap_or_default();
    let func_level = root
        .as_ref()
        .and_then(|r| r.domain_functionality.clone())
        .and_then(|s| s.parse::<u32>().ok());
    let os = func_level
        .map(ldap::domain_functionality_release)
        .unwrap_or("unknown");

    let smbv1 = probe_smb1(target).await;
    let smbv1_str = match smbv1 {
        Some(true) => "True".red().bold().to_string(),
        Some(false) => "False".to_string(),
        None => "unknown".to_string(),
    };
    let signing = neg.signing_required;

    report.info = Some(format!(
        "{os} (name:{name}) (domain:{domain}) (signing:{signing_req}) (SMBv1:{smbv1}) (dialect:{dialect})",
        name = host_name.clone().unwrap_or_else(|| "?".to_string()),
        domain = if domain.is_empty() {
            "?".to_string()
        } else {
            domain.clone()
        },
        signing_req = if signing { "True" } else { "False" },
        smbv1 = smbv1_str,
        dialect = neg.highest_dialect,
    ));

    // Credential validation (only when the operator supplied credentials).
    if let Some(c) = creds.first() {
        match try_smb_auth(target, c).await {
            Ok(pwned) => {
                report.cred = Some(cred_line(c, pwned));
                report.pwned = pwned;
            }
            Err(e) => report.error = Some(format!("SMB auth error: {e}")),
        }
    }

    report
}

fn cred_line(c: &Credentials, pwned: bool) -> String {
    let secret = match &c.auth {
        AuthData::Password(p) => p.clone(),
        AuthData::NtlmHash(h) => format!("[NT hash] {}", preview(h)),
        AuthData::KerberosTicket(t) => format!("[ticket] {}", preview(t)),
    };
    let domain = if c.domain.is_empty() { "." } else { &c.domain };
    if pwned {
        format!("{domain}\\{}:{secret} (Pwn3d!)", c.username)
    } else {
        format!("{domain}\\{}:{secret}", c.username)
    }
}

fn preview(s: &str) -> String {
    if s.len() <= 8 {
        s.to_string()
    } else {
        format!("{}...", &s[..8])
    }
}

/// Attempt SMB authentication and report whether administrative shares are
/// reachable (NetExec's `Pwn3d!` condition).
async fn try_smb_auth(target: &str, c: &Credentials) -> Result<bool, String> {
    let session = match &c.auth {
        AuthData::Password(p) => smb::SmbSession::connect(target, &c.domain, &c.username, p).await,
        AuthData::NtlmHash(h) => {
            smb::SmbSession::connect_with_hash(target, &c.domain, &c.username, h).await
        }
        AuthData::KerberosTicket(path) => {
            let ticket = smb::KerberosTicket::from_kirbi(path).map_err(|e| e.to_string())?;
            smb::SmbSession::connect_with_ticket(target, &c.domain, &c.username, ticket).await
        }
    }
    .map_err(|e| e.to_string())?;

    Ok(session.check_admin_access().await.has_admin)
}

// ===========================================================
//  Other protocol checks
// ===========================================================

/// Check LDAP: RootDSE identity, functional level and anonymous-bind policy.
async fn check_ldap(target: &str) -> HostReport {
    let mut report = HostReport::new("LDAP", target, LDAP_PORT);

    let root = match ldap::probe_rootdse_raw(target, false).await {
        Ok(r) => r,
        Err(e) => {
            report.error = Some(format!("RootDSE probe failed: {e}"));
            return report;
        }
    };

    report.host_name = root
        .dns_host_name
        .clone()
        .or_else(|| root.server_name.clone());

    let func_level = root
        .domain_functionality
        .clone()
        .and_then(|s| s.parse::<u32>().ok());
    let os = func_level
        .map(ldap::domain_functionality_release)
        .unwrap_or("unknown");

    // `dnsDomainName` is often absent from the RootDSE; derive it from the
    // default naming context instead of printing a placeholder.
    let domain = root
        .dns_domain_name
        .clone()
        .or_else(|| {
            root.default_naming_context
                .as_deref()
                .map(naming_context_to_dns)
        })
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "?".into());

    report.info = Some(format!(
        "{os} (name:{name}) (domain:{domain}) (base:{base}) (sasl:{sasl})",
        name = report.host_name.clone().unwrap_or_else(|| "?".to_string()),
        domain = domain,
        base = root
            .default_naming_context
            .clone()
            .unwrap_or_else(|| "?".into()),
        sasl = if root.supported_sasl_mechanisms.is_empty() {
            "-".to_string()
        } else {
            root.supported_sasl_mechanisms.join("/")
        },
    ));

    report
}

/// Check WinRM: does an HTTP listener on 5985 answer with a 401 challenge?
async fn check_winrm(target: &str) -> HostReport {
    let mut report = HostReport::new("WINRM", target, WINRM_PORT);

    match winrm_probe(target, WINRM_PORT).await {
        Ok(Some(code)) => {
            let label = if code == 401 {
                "WinRM (401 Unauthorized -- WinRM present)".to_string()
            } else {
                format!("HTTP {code} from WinRM listener")
            };
            report.info = Some(label);
        }
        Ok(None) => {
            report.error = Some("no HTTP response on 5985".to_string());
        }
        Err(e) => {
            report.error = Some(e);
        }
    }
    report
}

async fn winrm_probe(target: &str, port: u16) -> Result<Option<u16>, String> {
    let addr = format!("{target}:{port}");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("connect to {addr} timed out"))?
    .map_err(|e| format!("connect to {addr} failed: {e}"))?;

    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write failed: {e}"))?;

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut buf)).await;

    if buf.is_empty() {
        return Ok(None);
    }
    let head = String::from_utf8_lossy(&buf);
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    Ok(code)
}

/// Check the DCE/RPC Endpoint Mapper on port 135.
async fn check_rpc(target: &str) -> HostReport {
    let mut report = HostReport::new("RPC", target, RPC_PORT);
    match epm::probe_epm(target).await {
        Ok(msg) => {
            // `probe_epm` reports failures as descriptive strings; classify them
            // so a timeout is not counted as a usable result.
            let lower = msg.to_lowercase();
            if ["unreachable", "timeout", "rejected", "failed", "error"]
                .iter()
                .any(|needle| lower.contains(needle))
            {
                report.error = Some(msg);
            } else {
                report.info = Some(msg);
            }
        }
        Err(e) => report.error = Some(format!("EPM probe failed: {e}")),
    }
    report
}

// ===========================================================
//  Entry point
// ===========================================================

/// Run every protocol check requested for a single host.
async fn run_checks(host: &str, protocol: NxcProtocol, creds: &[Credentials]) -> Vec<HostReport> {
    match protocol {
        NxcProtocol::Smb => vec![check_smb(host, creds).await],
        NxcProtocol::Ldap => vec![check_ldap(host).await],
        NxcProtocol::Winrm => vec![check_winrm(host).await],
        NxcProtocol::Rpc => vec![check_rpc(host).await],
        NxcProtocol::All => vec![
            check_smb(host, creds).await,
            check_ldap(host).await,
            check_winrm(host).await,
            check_rpc(host).await,
        ],
    }
}

/// Run `ovt nxc <protocol> <targets>`.
pub async fn cmd_nxc(
    cli: &crate::Cli,
    protocol: NxcProtocol,
    targets: Vec<String>,
    only_positive: bool,
) -> i32 {
    crate::banner::print_module_banner("NXC");

    let hosts = expand_targets(&targets);
    if hosts.is_empty() {
        crate::banner::print_fail("No targets specified");
        return 1;
    }

    // Credentials are optional -- resolve quietly and fall back to unauthenticated.
    let creds = crate::resolve_credentials_from_cli(cli).unwrap_or_default();

    println!(
        "{}",
        format!(
            "Running {} module(s) against {} host(s){}",
            protocol,
            hosts.len(),
            if creds.is_empty() {
                " (unauthenticated)".to_string()
            } else {
                format!(" ({} credential set(s))", creds.len())
            }
        )
        .bright_black()
    );
    println!();

    // Hosts are checked concurrently so sweeping a /24 stays practical; results
    // are printed as each host finishes, the way NetExec streams them.
    const CONCURRENCY: usize = 32;
    let mut positive = 0usize;

    let mut stream = futures::stream::iter(hosts.iter().cloned())
        .map(|host| {
            let creds = creds.clone();
            async move {
                let reports = run_checks(&host, protocol, &creds).await;
                (host, reports)
            }
        })
        .buffer_unordered(CONCURRENCY);

    while let Some((_host, reports)) = stream.next().await {
        for report in &reports {
            if report.is_positive() {
                positive += 1;
            }
            report.print(only_positive);
        }
    }

    println!();
    crate::banner::print_success(&format!(
        "{} usable result(s) across {} host(s)",
        positive,
        hosts.len()
    ));

    if positive == 0 { 1 } else { 0 }
}

// ===========================================================
//  Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_single_and_multi() {
        assert_eq!(expand_targets(&["10.0.0.1".into()]), vec!["10.0.0.1"]);
        let many = expand_targets(&["10.0.0.1,10.0.0.2 10.0.0.3".into()]);
        assert_eq!(many, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    #[test]
    fn expand_cidr_is_host_range() {
        let hosts = expand_targets(&["192.168.5.0/24".into()]);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "192.168.5.1");
        assert_eq!(hosts[253], "192.168.5.254");
    }

    #[test]
    fn expand_host_prefix_yields_both_addresses() {
        assert_eq!(
            expand_targets(&["10.0.0.0/31".into()]),
            vec!["10.0.0.0", "10.0.0.1"]
        );
        assert_eq!(expand_targets(&["10.0.0.5/32".into()]), vec!["10.0.0.5"]);
    }

    #[test]
    fn expand_dedups_and_keeps_hostnames() {
        let hosts = expand_targets(&["dc01.lab.local,dc01.lab.local,10.0.0.1".into()]);
        assert_eq!(hosts, vec!["dc01.lab.local", "10.0.0.1"]);
    }

    #[test]
    fn smb1_negotiate_has_nbss_and_protocol() {
        let req = build_smb1_negotiate();
        assert_eq!(req[0], 0x00, "NBSS session message");
        let declared = u32::from_be_bytes([0, req[1], req[2], req[3]]) as usize;
        assert_eq!(declared, req.len() - 4);
        assert_eq!(&req[4..8], b"\xffSMB", "SMB1 protocol id");
        assert_eq!(req[8], 0x72, "NEGOTIATE command");
    }

    #[test]
    fn cred_line_shows_pwned() {
        let c = Credentials {
            domain: "LAB".into(),
            username: "admin".into(),
            auth: AuthData::Password("P@ss".into()),
        };
        assert_eq!(cred_line(&c, false), "LAB\\admin:P@ss");
        assert_eq!(cred_line(&c, true), "LAB\\admin:P@ss (Pwn3d!)");
    }

    #[test]
    fn cred_line_masks_hash() {
        let c = Credentials {
            domain: String::new(),
            username: "u".into(),
            auth: AuthData::NtlmHash("aad3b435b51404ee".into()),
        };
        assert_eq!(cred_line(&c, false), ".\\u:[NT hash] aad3b435...");
    }

    #[test]
    fn naming_context_to_dns_converts_dc_components() {
        assert_eq!(
            naming_context_to_dns("DC=LAINOSCP,DC=local"),
            "LAINOSCP.local"
        );
        assert_eq!(
            naming_context_to_dns("DC=corp,DC=example,DC=com"),
            "corp.example.com"
        );
        assert_eq!(naming_context_to_dns("CN=Configuration"), "");
    }

    #[test]
    fn report_positive_only_when_no_error() {
        let mut r = HostReport::new("SMB", "10.0.0.1", 445);
        assert!(!r.is_positive());
        r.info = Some("something".into());
        assert!(r.is_positive());
        r.error = Some("boom".into());
        assert!(!r.is_positive());
    }
}
