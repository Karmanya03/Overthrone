//! DNS operations for AD reconnaissance: SRV lookups, reverse DNS, DC discovery.

use crate::error::{OverthroneError, Result};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Type alias for the Tokio-based resolver
type TokioResolver = Resolver<TokioConnectionProvider>;

/// Build a resolver using default system config
fn build_resolver() -> Result<TokioResolver> {
    let resolver = Resolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build();
    Ok(resolver)
}

/// Discover Domain Controllers via DNS SRV records
/// Queries _ldap._tcp.dc._msdcs.<domain>
pub async fn discover_domain_controllers(domain: &str) -> Result<Vec<(String, Vec<String>)>> {
    let srv_query = format!("_ldap._tcp.dc._msdcs.{domain}");
    info!("DNS SRV lookup: {srv_query}");

    let resolver = build_resolver()?;

    let srv_response = resolver
        .srv_lookup(&srv_query)
        .await
        .map_err(|e| OverthroneError::Dns {
            target: srv_query.clone(),
            reason: e.to_string(),
        })?;

    let mut dcs: Vec<(String, Vec<String>)> = Vec::new();

    for record in srv_response.iter() {
        let hostname = record.target().to_string().trim_end_matches('.').to_string();

        let ips: Vec<String> = match resolver.lookup_ip(&hostname).await {
            Ok(response) => response
                .iter()
                .map(|addr: IpAddr| addr.to_string())
                .collect(),
            Err(e) => {
                warn!("Failed to resolve {hostname}: {e}");
                Vec::new()
            }
        };

        debug!("DC found: {hostname} → {ips:?}");
        dcs.push((hostname, ips));
    }

    info!("Discovered {} domain controllers", dcs.len());
    Ok(dcs)
}

/// Resolve a hostname to IP addresses
pub async fn resolve_hostname(hostname: &str) -> Result<Vec<String>> {
    let resolver = build_resolver()?;

    let response = resolver
        .lookup_ip(hostname)
        .await
        .map_err(|e| OverthroneError::Dns {
            target: hostname.to_string(),
            reason: e.to_string(),
        })?;

    let ips: Vec<String> = response
        .iter()
        .map(|addr: IpAddr| addr.to_string())
        .collect();

    debug!("Resolved {hostname} → {ips:?}");
    Ok(ips)
}

/// Reverse DNS lookup: IP → hostname
pub async fn reverse_lookup(ip: &str) -> Result<String> {
    let resolver = build_resolver()?;

    let addr: IpAddr = ip
        .parse()
        .map_err(|_| OverthroneError::Dns {
            target: ip.to_string(),
            reason: "Invalid IP address".to_string(),
        })?;

    let response = resolver
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
