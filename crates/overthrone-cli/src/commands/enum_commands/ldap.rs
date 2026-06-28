use std::collections::HashMap;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, drive};
use overthrone_core::error::{OverthroneError, Result};
use tracing::info;

pub struct LdapEnumerator {
    server: String,
    ldap: Option<Ldap>,
    connected: bool,
}

impl LdapEnumerator {
    pub fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
            ldap: None,
            connected: false,
        }
    }

    pub async fn connect_anonymous(&mut self) -> Result<()> {
        let url = format!("ldap://{}", self.server);
        let settings = LdapConnSettings::new()
            .set_starttls(false)
            .set_no_tls_verify(true);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: self.server.clone(),
                reason: format!("LDAP connect failed: {e}"),
            })?;
        drive!(conn);
        let res = ldap.simple_bind("", "").await.map_err(|e| OverthroneError::LdapBind {
            user: "anonymous".to_string(),
            reason: format!("Anonymous bind failed: {e}"),
        })?;
        if res.rc != 0 {
            return Err(OverthroneError::LdapBind {
                user: "anonymous".to_string(),
                reason: format!("Bind rejected (rc={})", res.rc),
            });
        }
        self.ldap = Some(ldap);
        self.connected = true;
        info!("[LDAP] Connected anonymously to {}", self.server);
        Ok(())
    }

    pub async fn connect_auth(&mut self, domain: &str, username: &str, password: &str) -> Result<()> {
        let url = format!("ldap://{}", self.server);
        let settings = LdapConnSettings::new()
            .set_starttls(false)
            .set_no_tls_verify(true);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: self.server.clone(),
                reason: format!("LDAP connect failed: {e}"),
            })?;
        drive!(conn);
        let bind_dn = format!("{}\\{}", domain, username);
        let res = ldap.simple_bind(&bind_dn, password).await.map_err(|e| OverthroneError::LdapBind {
            user: bind_dn.clone(),
            reason: format!("Auth bind failed: {e}"),
        })?;
        if res.rc != 0 {
            return Err(OverthroneError::LdapBind {
                user: bind_dn.clone(),
                reason: format!("Bind rejected (rc={}): {}", res.rc, res.text),
            });
        }
        self.ldap = Some(ldap);
        self.connected = true;
        info!("[LDAP] Authenticated as {bind_dn} on {}", self.server);
        Ok(())
    }

    pub async fn query_root_dse(&mut self) -> Result<HashMap<String, Vec<String>>> {
        let ldap = self.ldap()?;
        let attrs = vec![
            "defaultNamingContext",
            "schemaNamingContext",
            "configurationNamingContext",
            "dnsHostName",
            "ldapServiceName",
            "serverName",
            "supportedCapabilities",
            "supportedLDAPVersion",
            "supportedSASLMechanisms",
        ];
        let search_result = ldap
            .search("", Scope::Base, "(objectClass=*)", attrs)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: self.server.clone(),
                reason: format!("RootDSE query failed: {e}"),
            })?;
        let (entries, _) = search_result.success().map_err(|e| OverthroneError::Ldap {
            target: self.server.clone(),
            reason: format!("RootDSE search failed: {e}"),
        })?;
        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        for entry in entries {
            let se = SearchEntry::construct(entry);
            for (attr, vals) in se.attrs {
                result.entry(attr).or_default().extend(vals);
            }
        }
        Ok(result)
    }

    pub async fn count_objects(&mut self, base_dn: &str) -> Result<u64> {
        let ldap = self.ldap()?;
        let search_result = ldap
            .search(base_dn, Scope::Subtree, "(objectClass=*)", vec!["1.1"])
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: self.server.clone(),
                reason: format!("Count search failed: {e}"),
            })?;
        let (entries, _) = search_result.success().map_err(|e| OverthroneError::Ldap {
            target: self.server.clone(),
            reason: format!("Count search on base={base_dn} failed: {e}"),
        })?;
        Ok(entries.len() as u64)
    }

    pub async fn search(
        &mut self,
        base_dn: &str,
        filter: &str,
        attributes: &[&str],
    ) -> Result<Vec<HashMap<String, Vec<String>>>> {
        let ldap = self.ldap()?;
        let attrs: Vec<&str> = if attributes.is_empty() {
            vec!["*"]
        } else {
            attributes.to_vec()
        };
        let search_result = ldap
            .search(base_dn, Scope::Subtree, filter, attrs)
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: self.server.clone(),
                reason: format!("LDAP search failed: {e}"),
            })?;
        let (entries, _) = search_result.success().map_err(|e| OverthroneError::Ldap {
            target: self.server.clone(),
            reason: format!("LDAP search failed for base={base_dn} filter={filter}: {e}"),
        })?;
        let mut results = Vec::new();
        for entry in entries {
            let se = SearchEntry::construct(entry);
            let mut map = HashMap::new();
            for (attr, vals) in se.attrs {
                map.entry(attr).or_insert_with(Vec::new).extend(vals);
            }
            if !map.is_empty() {
                results.push(map);
            }
        }
        Ok(results)
    }

    pub async fn disconnect(&mut self) {
        if let Some(mut ldap) = self.ldap.take() {
            let _ = ldap.unbind().await;
        }
        self.connected = false;
        info!("[LDAP] Disconnected");
    }

    pub async fn run_interactive(&mut self) -> Result<()> {
        println!("LDAP Browser interactive shell for {}", self.server);
        println!("Commands: connect_anon, connect_auth <domain> <user> <pass>, rootdse, count <base_dn>, search <base_dn> <filter> [attrs...], quit");
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();
        loop {
            print!("ldap> ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let line = match lines.next_line().await {
                Ok(Some(l)) => l,
                Ok(None) => break,
                Err(_) => break,
            };
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() { continue; }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            match parts[0] {
                "connect_anon" => {
                    match self.connect_anonymous().await {
                        Ok(()) => println!("Connected anonymously"),
                        Err(e) => println!("Connect failed: {e}"),
                    }
                }
                "connect_auth" => {
                    if parts.len() < 4 {
                        println!("Usage: connect_auth <domain> <username> <password>");
                        continue;
                    }
                    match self.connect_auth(parts[1], parts[2], parts[3]).await {
                        Ok(()) => println!("Connected as {}\\{}", parts[1], parts[2]),
                        Err(e) => println!("Connect failed: {e}"),
                    }
                }
                "rootdse" => {
                    if !self.connected { println!("Not connected. Use 'connect_anon' or 'connect_auth' first."); continue; }
                    match self.query_root_dse().await {
                        Ok(dse) => {
                            println!("RootDSE attributes:");
                            let mut keys: Vec<&String> = dse.keys().collect();
                            keys.sort();
                            for k in keys {
                                if let Some(vals) = dse.get(k) {
                                    println!("  {}: {}", k, vals.join(", "));
                                }
                            }
                        }
                        Err(e) => println!("RootDSE query failed: {e}"),
                    }
                }
                "count" => {
                    if !self.connected { println!("Not connected. Use 'connect_anon' or 'connect_auth' first."); continue; }
                    if parts.len() < 2 {
                        println!("Usage: count <base_dn>");
                        continue;
                    }
                    match self.count_objects(parts[1]).await {
                        Ok(cnt) => println!("Object count: {}", cnt),
                        Err(e) => println!("Count failed: {e}"),
                    }
                }
                "search" => {
                    if !self.connected { println!("Not connected. Use 'connect_anon' or 'connect_auth' first."); continue; }
                    if parts.len() < 3 {
                        println!("Usage: search <base_dn> <filter> [attr1 attr2 ...]");
                        continue;
                    }
                    let attrs: Vec<&str> = parts[3..].to_vec();
                    match self.search(parts[1], parts[2], &attrs).await {
                        Ok(results) => {
                            println!("Search results ({}):", results.len());
                            for (i, entry) in results.iter().enumerate() {
                                println!("--- Entry {} ---", i + 1);
                                let mut keys: Vec<&String> = entry.keys().collect();
                                keys.sort();
                                for k in keys {
                                    if let Some(vals) = entry.get(k) {
                                        println!("  {}: {}", k, vals.join(", "));
                                    }
                                }
                            }
                        }
                        Err(e) => println!("Search failed: {e}"),
                    }
                }
                "quit" | "exit" => break,
                _ => println!("Unknown command: {}", parts[0]),
            }
        }
        self.disconnect().await;
        Ok(())
    }

    fn ldap(&mut self) -> Result<&mut Ldap> {
        self.ldap.as_mut().ok_or_else(|| OverthroneError::Ldap {
            target: self.server.clone(),
            reason: format!("LDAP not connected to {}", self.server),
        })
    }
}
