//! MSSQL linked server chain analysis.
//!
//! Groups MSSQL instances discovered by reaper and identifies
//! potential cross-domain link chains based on SPN analysis.

use overthrone_reaper::mssql::MssqlInstance;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlLink {
    pub source_server: String,
    pub source_domain: String,
    pub target_server: String,
    pub target_domain: Option<String>,
    pub link_login: LinkLoginType,
    pub rpc_out_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkLoginType {
    CurrentContext,
    MappedLogin(String),
    SysAdmin(String),
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlLinkChain {
    pub links: Vec<MssqlLink>,
    pub start_server: String,
    pub end_server: String,
    pub service_account: String,
    pub crosses_domain: bool,
    pub depth: usize,
    pub risk_level: String,
    pub description: String,
}

impl MssqlLinkChain {
    pub fn is_high_value(&self) -> bool {
        self.crosses_domain
    }

    /// Generate nested OPENQUERY payload for the chain
    pub fn to_openquery(&self, inner_query: &str) -> String {
        let mut query = inner_query.to_string();
        for link in self.links.iter().rev() {
            query = query.replace('\'', "''");
            query = format!(
                "SELECT * FROM OPENQUERY([{}], '{}')",
                link.target_server, query
            );
        }
        query
    }
}

/// Build potential MSSQL link chains from reaper instance data.
///
/// Since we can't connect to SQL servers directly, we analyze SPNs
/// to identify cross-domain MSSQL instances and group them by
/// service account (same account = potential link chain).
pub fn build_mssql_chains(
    source_domain: &str,
    instances: &[MssqlInstance],
) -> Vec<MssqlLinkChain> {
    let mut chains = Vec::new();
    let source_upper = source_domain.to_uppercase();

    info!("[mssql_links] Analyzing {} MSSQL instances for link chains", instances.len());

    if instances.is_empty() {
        return chains;
    }

    // Group instances by service account — same SA often means linked servers
    let mut by_account: std::collections::HashMap<String, Vec<&MssqlInstance>> =
        std::collections::HashMap::new();

    for inst in instances {
        by_account
            .entry(inst.service_account.to_uppercase())
            .or_default()
            .push(inst);
    }

    // For each service account with multiple instances, build potential chains
    for account_instances in by_account.values() {
        if account_instances.len() < 2 {
            // Single instance — check if it's cross-domain
            let inst = account_instances[0];
            if let Some(ref host) = inst.hostname {
                let inst_domain = domain_from_hostname(host);
                if let Some(ref dom) = inst_domain
                    && dom.to_uppercase() != source_upper {
                        chains.push(MssqlLinkChain {
                            links: vec![MssqlLink {
                                source_server: format!("(local {source_domain})"),
                                source_domain: source_domain.to_string(),
                                target_server: host.clone(),
                                target_domain: Some(dom.clone()),
                                link_login: LinkLoginType::Unknown,
                                rpc_out_enabled: false,
                            }],
                            start_server: source_domain.to_string(),
                            end_server: host.clone(),
                            service_account: inst.service_account.clone(),
                            crosses_domain: true,
                            depth: 1,
                            risk_level: "MEDIUM".into(),
                            description: format!(
                                "Cross-domain MSSQL: service account '{}' has SPN for {} (domain: {}). \
                                 If Kerberoasted, provides access across trust boundary.",
                                inst.service_account, host, dom
                            ),
                        });
                    }
            }
            continue;
        }

        // Multiple instances under same service account — potential chain
        let mut chain_links = Vec::new();
        let mut crosses_domain = false;
        let mut domains_seen = std::collections::HashSet::new();
        domains_seen.insert(source_upper.clone());

        let mut sorted_instances = account_instances.clone();
        sorted_instances.sort_by_key(|i| i.hostname.clone());

        for window in sorted_instances.windows(2) {
            let src = window[0];
            let tgt = window[1];

            let src_host = src.hostname.as_deref().unwrap_or("unknown");
            let tgt_host = tgt.hostname.as_deref().unwrap_or("unknown");
            let src_dom = domain_from_hostname(src_host).unwrap_or(source_domain.to_string());
            let tgt_dom = domain_from_hostname(tgt_host).unwrap_or(source_domain.to_string());

            if src_dom.to_uppercase() != tgt_dom.to_uppercase() {
                crosses_domain = true;
            }
            domains_seen.insert(src_dom.to_uppercase());
            domains_seen.insert(tgt_dom.to_uppercase());

            chain_links.push(MssqlLink {
                source_server: src_host.to_string(),
                source_domain: src_dom,
                target_server: tgt_host.to_string(),
                target_domain: Some(tgt_dom),
                link_login: LinkLoginType::Unknown,
                rpc_out_enabled: false,
            });
        }

        if !chain_links.is_empty() {
            let start = sorted_instances.first()
                .and_then(|i| i.hostname.clone())
                .unwrap_or_default();
            let end = sorted_instances.last()
                .and_then(|i| i.hostname.clone())
                .unwrap_or_default();

            let risk = if crosses_domain { "HIGH" } else { "MEDIUM" };

            chains.push(MssqlLinkChain {
                depth: chain_links.len(),
                links: chain_links,
                start_server: start,
                end_server: end,
                service_account: account_instances[0].service_account.clone(),
                crosses_domain,
                risk_level: risk.into(),
                description: format!(
                    "MSSQL chain ({} hops) under service account '{}' spanning {} domain(s){}",
                    sorted_instances.len() - 1,
                    account_instances[0].service_account,
                    domains_seen.len(),
                    if crosses_domain { " — CROSSES TRUST BOUNDARY" } else { "" }
                ),
            });
        }
    }

    // Sort: cross-domain chains first
    chains.sort_by(|a, b| b.crosses_domain.cmp(&a.crosses_domain));

    info!("[mssql_links] Found {} potential MSSQL chains ({} cross-domain)",
        chains.len(),
        chains.iter().filter(|c| c.crosses_domain).count()
    );

    chains
}

fn domain_from_hostname(hostname: &str) -> Option<String> {
    let parts: Vec<&str> = hostname.splitn(2, '.').collect();
    if parts.len() == 2 { Some(parts[1].to_string()) } else { None }
}
