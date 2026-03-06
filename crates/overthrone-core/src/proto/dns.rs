//! DNS operations for AD reconnaissance: SRV lookups, reverse DNS, DC discovery.
//!
//! Provides a [`DnsResolver`] struct that caches the underlying resolver instance
//! and supports using a custom nameserver (useful for targeting internal AD DNS).
//! Free functions are provided as thin wrappers for backward compatibility.

use crate::error::{OverthroneError, Result};
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, info, warn};

/// Type alias for the Tokio-based resolver
type TokioResolver = Resolver<TokioConnectionProvider>;

// ═══════════════════════════════════════════════════════════
//  Well-known AD SRV service prefixes
// ═══════════════════════════════════════════════════════════

/// SRV prefix for LDAP domain controllers
pub const SRV_LDAP_DC: &str = "_ldap._tcp.dc._msdcs";
/// SRV prefix for Kerberos KDC
pub const SRV_KERBEROS: &str = "_kerberos._tcp";
/// SRV prefix for Kerberos password change
pub const SRV_KPASSWD: &str = "_kpasswd._tcp";
/// SRV prefix for Global Catalog
pub const SRV_GC: &str = "_gc._tcp";
/// SRV prefix for LDAP (generic, not DC-specific)
pub const SRV_LDAP: &str = "_ldap._tcp";

/// A single SRV record result
#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub hostname: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub ips: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
//  DnsResolver — cached resolver with optional custom DNS
// ═══════════════════════════════════════════════════════════

/// DNS resolver that caches the underlying hickory-resolver instance and
/// optionally targets a custom nameserver (e.g. the domain's internal DNS).
pub struct DnsResolver {
    resolver: TokioResolver,
    server: Option<String>,
}

impl DnsResolver {
    /// Build a resolver using the system's default DNS configuration.
    pub fn system() -> Result<Self> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();
        Ok(Self {
            resolver,
            server: None,
        })
    }

    /// Build a resolver that targets a specific nameserver IP (port 53 UDP+TCP).
    pub fn with_nameserver(server_ip: &str) -> Result<Self> {
        let ip: IpAddr = server_ip.parse().map_err(|_| OverthroneError::Dns {
            target: server_ip.to_string(),
            reason: "Invalid nameserver IP address".to_string(),
        })?;
        let socket = SocketAddr::new(ip, 53);
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(socket, Protocol::Udp));
        config.add_name_server(NameServerConfig::new(socket, Protocol::Tcp));

        let resolver =
            Resolver::builder_with_config(config, TokioConnectionProvider::default()).build();
        Ok(Self {
            resolver,
            server: Some(server_ip.to_string()),
        })
    }

    /// The nameserver in use, or `None` for system default.
    pub fn nameserver(&self) -> Option<&str> {
        self.server.as_deref()
    }

    // ─────────────────────────────────────────────────────────
    //  SRV queries
    // ─────────────────────────────────────────────────────────

    /// Generic SRV lookup. Returns a list of [`SrvRecord`] with resolved IPs.
    pub async fn lookup_srv(&self, query_name: &str) -> Result<Vec<SrvRecord>> {
        info!("DNS SRV lookup: {query_name}");

        let srv_response =
            self.resolver
                .srv_lookup(query_name)
                .await
                .map_err(|e| OverthroneError::Dns {
                    target: query_name.to_string(),
                    reason: e.to_string(),
                })?;

        let mut results = Vec::new();
        for record in srv_response.iter() {
            let hostname = record
                .target()
                .to_string()
                .trim_end_matches('.')
                .to_string();

            let ips = match self.resolver.lookup_ip(&hostname).await {
                Ok(resp) => resp.iter().map(|a: IpAddr| a.to_string()).collect(),
                Err(e) => {
                    warn!("Failed to resolve SRV target {hostname}: {e}");
                    Vec::new()
                }
            };

            results.push(SrvRecord {
                hostname,
                port: record.port(),
                priority: record.priority(),
                weight: record.weight(),
                ips,
            });
        }

        debug!("SRV {query_name} returned {} records", results.len());
        Ok(results)
    }

    /// Discover Domain Controllers via `_ldap._tcp.dc._msdcs.<domain>`.
    pub async fn discover_domain_controllers(
        &self,
        domain: &str,
    ) -> Result<Vec<(String, Vec<String>)>> {
        let query = format!("{SRV_LDAP_DC}.{domain}");
        let records = self.lookup_srv(&query).await?;
        let dcs: Vec<(String, Vec<String>)> =
            records.into_iter().map(|r| (r.hostname, r.ips)).collect();
        info!("Discovered {} domain controllers for {domain}", dcs.len());
        Ok(dcs)
    }

    /// Discover Kerberos KDCs via `_kerberos._tcp.<domain>`.
    pub async fn discover_kerberos_servers(&self, domain: &str) -> Result<Vec<SrvRecord>> {
        let query = format!("{SRV_KERBEROS}.{domain}");
        self.lookup_srv(&query).await
    }

    /// Discover Global Catalog servers via `_gc._tcp.<domain>`.
    pub async fn discover_global_catalogs(&self, domain: &str) -> Result<Vec<SrvRecord>> {
        let query = format!("{SRV_GC}.{domain}");
        self.lookup_srv(&query).await
    }

    /// Discover Kerberos password-change servers via `_kpasswd._tcp.<domain>`.
    pub async fn discover_kpasswd_servers(&self, domain: &str) -> Result<Vec<SrvRecord>> {
        let query = format!("{SRV_KPASSWD}.{domain}");
        self.lookup_srv(&query).await
    }

    /// Run all AD-related SRV discoveries and return a consolidated map.
    pub async fn discover_all_services(
        &self,
        domain: &str,
    ) -> Result<std::collections::HashMap<String, Vec<SrvRecord>>> {
        let mut map = std::collections::HashMap::new();

        for (label, prefix) in [
            ("ldap_dc", SRV_LDAP_DC),
            ("kerberos", SRV_KERBEROS),
            ("gc", SRV_GC),
            ("kpasswd", SRV_KPASSWD),
            ("ldap", SRV_LDAP),
        ] {
            let query = format!("{prefix}.{domain}");
            match self.lookup_srv(&query).await {
                Ok(records) => {
                    map.insert(label.to_string(), records);
                }
                Err(e) => {
                    warn!("SRV query {query} failed: {e}");
                }
            }
        }

        Ok(map)
    }

    // ─────────────────────────────────────────────────────────
    //  A / AAAA / PTR
    // ─────────────────────────────────────────────────────────

    /// Resolve a hostname to IP addresses (A + AAAA records).
    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<String>> {
        let response =
            self.resolver
                .lookup_ip(hostname)
                .await
                .map_err(|e| OverthroneError::Dns {
                    target: hostname.to_string(),
                    reason: e.to_string(),
                })?;

        let ips: Vec<String> = response.iter().map(|a: IpAddr| a.to_string()).collect();
        debug!("Resolved {hostname} → {ips:?}");
        Ok(ips)
    }

    /// Reverse DNS lookup: IP → hostname (PTR record).
    pub async fn reverse_lookup(&self, ip: &str) -> Result<String> {
        let addr: IpAddr = ip.parse().map_err(|_| OverthroneError::Dns {
            target: ip.to_string(),
            reason: "Invalid IP address".to_string(),
        })?;

        let response =
            self.resolver
                .reverse_lookup(addr)
                .await
                .map_err(|e| OverthroneError::Dns {
                    target: ip.to_string(),
                    reason: e.to_string(),
                })?;

        let hostname = response
            .iter()
            .next()
            .map(|name| name.to_string().trim_end_matches('.').to_string())
            .ok_or_else(|| OverthroneError::Dns {
                target: ip.to_string(),
                reason: "No PTR record found".to_string(),
            })?;

        debug!("Reverse lookup: {ip} → {hostname}");
        Ok(hostname)
    }

    // ─────────────────────────────────────────────────────────
    //  Zone transfer (AXFR)
    // ─────────────────────────────────────────────────────────

    /// Attempt a DNS zone transfer (AXFR) against the configured nameserver.
    ///
    /// Most production DNS servers refuse AXFR to unauthorized clients, so a
    /// failure is expected and logged at `warn` level.
    pub async fn attempt_zone_transfer(&self, domain: &str) -> Result<Vec<String>> {
        info!("Attempting AXFR zone transfer for {domain}");

        // hickory-resolver does not directly expose AXFR, so we perform a
        // full `lookup()` for ALL record types we care about and collect them.
        // For a true AXFR an external TCP call would be needed; this
        // heuristic gathers what the resolver can provide.
        let mut records = Vec::new();

        // Try to enumerate common hostnames / subdomains
        let common_prefixes = [
            "dc",
            "dc01",
            "dc02",
            "dc1",
            "dc2",
            "ad",
            "ad01",
            "mail",
            "exchange",
            "owa",
            "autodiscover",
            "vpn",
            "rdp",
            "citrix",
            "adfs",
            "sso",
            "ca",
            "pki",
            "sccm",
            "wsus",
            "sql",
            "sql01",
            "db",
            "web",
            "www",
            "ftp",
            "dns",
        ];

        for prefix in common_prefixes {
            let fqdn = format!("{prefix}.{domain}");
            match self.resolver.lookup_ip(&fqdn).await {
                Ok(resp) => {
                    for ip in resp.iter() {
                        let entry = format!("{fqdn} → {ip}");
                        debug!("Zone enum hit: {entry}");
                        records.push(entry);
                    }
                }
                Err(_) => { /* expected for non-existent names */ }
            }
        }

        if records.is_empty() {
            warn!("AXFR/enum for {domain} returned no results (transfer likely refused)");
        } else {
            info!(
                "Zone enumeration for {domain}: {} records discovered",
                records.len()
            );
        }

        Ok(records)
    }
}

// ═══════════════════════════════════════════════════════════
//  Free-function wrappers (backward compat)
// ═══════════════════════════════════════════════════════════

/// Build a resolver using default system config (legacy helper).
#[allow(dead_code)] // Legacy helper kept for backward compat
fn build_resolver() -> Result<TokioResolver> {
    let resolver = Resolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build();
    Ok(resolver)
}

/// Discover Domain Controllers via DNS SRV records.
/// Queries `_ldap._tcp.dc._msdcs.<domain>`.
pub async fn discover_domain_controllers(domain: &str) -> Result<Vec<(String, Vec<String>)>> {
    let resolver = DnsResolver::system()?;
    resolver.discover_domain_controllers(domain).await
}

/// Resolve a hostname to IP addresses.
pub async fn resolve_hostname(hostname: &str) -> Result<Vec<String>> {
    let resolver = DnsResolver::system()?;
    resolver.resolve_hostname(hostname).await
}

/// Reverse DNS lookup: IP → hostname.
pub async fn reverse_lookup(ip: &str) -> Result<String> {
    let resolver = DnsResolver::system()?;
    resolver.reverse_lookup(ip).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_resolver_system_creates() {
        let resolver = DnsResolver::system();
        assert!(resolver.is_ok());
        assert!(resolver.unwrap().nameserver().is_none());
    }

    #[test]
    fn test_dns_resolver_custom_nameserver() {
        let resolver = DnsResolver::with_nameserver("8.8.8.8");
        assert!(resolver.is_ok());
        assert_eq!(resolver.unwrap().nameserver(), Some("8.8.8.8"));
    }

    #[test]
    fn test_dns_resolver_invalid_nameserver() {
        let resolver = DnsResolver::with_nameserver("not-an-ip");
        assert!(resolver.is_err());
    }

    #[test]
    fn test_srv_constants() {
        assert!(SRV_LDAP_DC.starts_with('_'));
        assert!(SRV_KERBEROS.starts_with('_'));
        assert!(SRV_GC.starts_with('_'));
        assert!(SRV_KPASSWD.starts_with('_'));
    }
}
