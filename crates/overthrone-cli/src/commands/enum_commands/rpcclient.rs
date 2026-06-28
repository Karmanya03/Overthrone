use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::epm::{
    LSARPC_UUID, SAMR_UUID, build_rpc_bind, build_rpc_request, is_bind_accepted, extract_handle,
    ndr_conformant_string,
};
use overthrone_core::proto::smb::SmbSession;
use tracing::{info, warn};

pub struct RpcClient {
    target: String,
    smb_session: Option<SmbSession>,
    connected: bool,
}

impl RpcClient {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            smb_session: None,
            connected: false,
        }
    }

    pub async fn connect(&mut self, domain: &str, username: &str, password: &str) -> Result<()> {
        info!("[RPC] Connecting to {} as {}\\{}", self.target, domain, username);
        let session = SmbSession::connect(&self.target, domain, username, password)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB connect failed: {}", e)))?;

        let bind_req = build_rpc_bind(&LSARPC_UUID, 0, 0);
        let bind_resp = session.pipe_transact("lsarpc", &bind_req).await?;
        if !is_bind_accepted(&bind_resp) {
            return Err(OverthroneError::Rpc {
                target: "lsarpc".to_string(),
                reason: "LSARPC bind rejected".to_string(),
            });
        }

        info!("[RPC] LSARPC bind accepted");
        self.smb_session = Some(session);
        self.connected = true;
        Ok(())
    }

    pub async fn enum_domains(&mut self) -> Result<Vec<String>> {
        let session = self.session()?;

        let policy_handle = self.lsa_open_policy2(session, "").await?;
        let query_req = self.lsa_query_info_policy_req(&policy_handle, 5);
        let query_resp = session.pipe_transact("lsarpc", &query_req).await?;
        let domain_names = self.parse_domain_names(&query_resp);
        let _ = session.pipe_transact("lsarpc", &self.lsa_close_req(&policy_handle)).await;

        if domain_names.is_empty() && !query_resp.is_empty() {
            let domain = self.extract_domain_string(&query_resp, 28);
            if !domain.is_empty() {
                return Ok(vec![domain]);
            }
        }

        Ok(domain_names)
    }

    pub async fn enum_users(&mut self) -> Result<Vec<String>> {
        let session = self.session()?;

        let samr_bind_req = build_rpc_bind(&SAMR_UUID, 1, 0);
        let samr_bind_resp = session.pipe_transact("samr", &samr_bind_req).await?;
        if !is_bind_accepted(&samr_bind_resp) {
            return Err(OverthroneError::Rpc {
                target: "samr".to_string(),
                reason: "SAMR bind rejected".to_string(),
            });
        }

        let server_handle = self.samr_connect(session).await?;
        let domains = self.samr_enumerate_domains(session, &server_handle).await?;

        let mut all_users = Vec::new();
        for domain_name in &domains {
            let domain_handle = self.samr_open_domain(session, &server_handle, domain_name).await;
            if let Ok(handle) = domain_handle {
                match self.samr_enum_users(session, &handle).await {
                    Ok(users) => all_users.extend(users),
                    Err(e) => warn!("[RPC] SamrEnumUsers failed for domain '{}': {}", domain_name, e),
                }
                let _ = session.pipe_transact("samr", &self.samr_close_req(&handle)).await;
            }
        }

        let _ = session.pipe_transact("samr", &self.samr_close_req(&server_handle)).await;
        Ok(all_users)
    }

    pub async fn enum_trusts(&mut self) -> Result<Vec<String>> {
        let session = self.session()?;

        let policy_handle = self.lsa_open_policy2(session, "").await?;
        let query_req = self.lsa_query_info_policy_req(&policy_handle, 7);
        let query_resp = session.pipe_transact("lsarpc", &query_req).await?;
        let _ = session.pipe_transact("lsarpc", &self.lsa_close_req(&policy_handle)).await;

        let mut trusts = Vec::new();
        let stub_start = 24usize;
        if query_resp.len() < stub_start + 8 {
            return Ok(trusts);
        }

        let trust_count = u32::from_le_bytes([
            query_resp[stub_start],
            query_resp[stub_start + 1],
            query_resp[stub_start + 2],
            query_resp[stub_start + 3],
        ]) as usize;

        if trust_count == 0 || trust_count > 200 {
            return Ok(trusts);
        }

        let mut pos = stub_start + 8;
        for _ in 0..trust_count {
            if pos + 12 > query_resp.len() {
                break;
            }
            let max_count = u32::from_le_bytes([query_resp[pos], query_resp[pos + 1], query_resp[pos + 2], query_resp[pos + 3]]);
            let actual = u32::from_le_bytes([query_resp[pos + 8], query_resp[pos + 9], query_resp[pos + 10], query_resp[pos + 11]]);
            if actual > 0 && actual <= 128 {
                let data_start = pos + 12;
                if data_start + (actual as usize) * 2 <= query_resp.len() {
                    let bytes = &query_resp[data_start..data_start + (actual as usize) * 2];
                    let name = String::from_utf16_lossy(
                        &bytes.chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>()
                    );
                    let trimmed = name.trim_matches('\0').to_string();
                    if !trimmed.is_empty() {
                        trusts.push(trimmed);
                    }
                }
            }
            let skip = if max_count > 0 && max_count <= 128 { 12 + (max_count as usize) * 2 } else { 4 };
            pos += skip.max(4);
            while pos % 4 != 0 { pos += 1; }
        }

        Ok(trusts)
    }

    pub fn disconnect(&mut self) {
        self.smb_session = None;
        self.connected = false;
        info!("[RPC] Disconnected");
    }

    pub async fn run_interactive(&mut self) -> Result<()> {
        println!("RPC Client interactive shell for {}", self.target);
        println!("Commands: connect <domain> <user> <pass>, domains, users, trusts, quit");
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();
        loop {
            print!("rpc> ");
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
                "connect" => {
                    if parts.len() < 4 {
                        println!("Usage: connect <domain> <username> <password>");
                        continue;
                    }
                    match self.connect(parts[1], parts[2], parts[3]).await {
                        Ok(()) => println!("Connected to {}", self.target),
                        Err(e) => println!("Connect failed: {e}"),
                    }
                }
                "domains" => {
                    if !self.connected { println!("Not connected. Use 'connect' first."); continue; }
                    match self.enum_domains().await {
                        Ok(domains) => {
                            println!("Domains ({}):", domains.len());
                            for d in domains { println!("  {d}"); }
                        }
                        Err(e) => println!("Enum failed: {e}"),
                    }
                }
                "users" => {
                    if !self.connected { println!("Not connected. Use 'connect' first."); continue; }
                    match self.enum_users().await {
                        Ok(users) => {
                            println!("Users ({}):", users.len());
                            for u in users { println!("  {u}"); }
                        }
                        Err(e) => println!("Enum failed: {e}"),
                    }
                }
                "trusts" => {
                    if !self.connected { println!("Not connected. Use 'connect' first."); continue; }
                    match self.enum_trusts().await {
                        Ok(trusts) => {
                            println!("Trusts ({}):", trusts.len());
                            for t in trusts { println!("  {t}"); }
                        }
                        Err(e) => println!("Enum failed: {e}"),
                    }
                }
                "quit" | "exit" => break,
                _ => println!("Unknown command: {}", parts[0]),
            }
        }
        self.disconnect();
        Ok(())
    }

    fn session(&self) -> Result<&SmbSession> {
        self.smb_session.as_ref().ok_or_else(|| OverthroneError::Smb(format!(
            "RPC not connected to {}", self.target
        )))
    }

    async fn lsa_open_policy2(&self, session: &SmbSession, system_name: &str) -> Result<[u8; 20]> {
        let mut stub = Vec::new();
        stub.extend_from_slice(&[0u8; 20]);
        stub.extend_from_slice(&0x18u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        let sys_ptr = if system_name.is_empty() { 0u32 } else { 0x00020000u32 };
        stub.extend_from_slice(&sys_ptr.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        if !system_name.is_empty() {
            stub.extend_from_slice(&ndr_conformant_string(system_name));
        }
        stub.extend_from_slice(&0x00020000u32.to_le_bytes());
        let req = build_rpc_request(44, &stub);
        let resp = session.pipe_transact("lsarpc", &req).await?;
        extract_handle(&resp).ok_or_else(|| OverthroneError::Rpc {
            target: "lsarpc".to_string(),
            reason: "OpenPolicy2 failed".to_string(),
        })
    }

    fn lsa_query_info_policy_req(&self, handle: &[u8; 20], info_class: u16) -> Vec<u8> {
        let mut stub = Vec::new();
        stub.extend_from_slice(handle);
        stub.extend_from_slice(&info_class.to_le_bytes());
        build_rpc_request(6, &stub)
    }

    fn lsa_close_req(&self, handle: &[u8; 20]) -> Vec<u8> {
        let mut stub = Vec::new();
        stub.extend_from_slice(handle);
        build_rpc_request(0, &stub)
    }

    fn parse_domain_names(&self, resp: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        if resp.len() < 32 { return names; }
        for i in (24..resp.len().saturating_sub(12)).step_by(4) {
            let max_count = u32::from_le_bytes([resp[i], resp[i + 1], resp[i + 2], resp[i + 3]]);
            if max_count == 0 || max_count > 256 { continue; }
            let offset = u32::from_le_bytes([resp[i + 4], resp[i + 5], resp[i + 6], resp[i + 7]]);
            let actual = u32::from_le_bytes([resp[i + 8], resp[i + 9], resp[i + 10], resp[i + 11]]);
            if actual > 0 && actual == max_count && offset == 0 {
                let data_start = i + 12;
                if data_start + (actual as usize) * 2 <= resp.len() {
                    let bytes = &resp[data_start..data_start + (actual as usize) * 2];
                    let name = String::from_utf16_lossy(
                        &bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()
                    );
                    let trimmed = name.trim_matches('\0').to_string();
                    if !trimmed.is_empty() { names.push(trimmed); }
                }
            }
        }
        names
    }

    fn extract_domain_string(&self, resp: &[u8], start: usize) -> String {
        if start + 12 > resp.len() { return String::new(); }
        let actual = u32::from_le_bytes([resp[start + 8], resp[start + 9], resp[start + 10], resp[start + 11]]);
        if actual == 0 || actual > 128 { return String::new(); }
        let data_start = start + 12;
        if data_start + (actual as usize) * 2 > resp.len() { return String::new(); }
        let bytes = &resp[data_start..data_start + (actual as usize) * 2];
        String::from_utf16_lossy(
            &bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()
        ).trim_matches('\0').to_string()
    }

    async fn samr_connect(&self, session: &SmbSession) -> Result<[u8; 20]> {
        let mut stub = Vec::new();
        stub.extend_from_slice(&0x00020000u32.to_le_bytes());
        stub.extend_from_slice(&0x000f000fu32.to_le_bytes());
        let req = build_rpc_request(0, &stub);
        let resp = session.pipe_transact("samr", &req).await?;
        extract_handle(&resp).ok_or_else(|| OverthroneError::Rpc {
            target: "samr".to_string(),
            reason: "SamrConnect failed".to_string(),
        })
    }

    async fn samr_enumerate_domains(&self, session: &SmbSession, handle: &[u8; 20]) -> Result<Vec<String>> {
        let mut stub = Vec::new();
        stub.extend_from_slice(handle);
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let req = build_rpc_request(6, &stub);
        let resp = session.pipe_transact("samr", &req).await?;
        let mut domains = Vec::new();
        let stub_start = 24usize;
        if resp.len() < stub_start + 4 { return Ok(domains); }
        let count = u32::from_le_bytes([resp[stub_start], resp[stub_start + 1], resp[stub_start + 2], resp[stub_start + 3]]) as usize;
        if count == 0 || count > 100 { return Ok(domains); }
        let string_start = stub_start + 4 + count * 8;
        for i in 0..count {
            let str_off = string_start + i * 12;
            if str_off + 12 > resp.len() { break; }
            let actual = u32::from_le_bytes([resp[str_off + 8], resp[str_off + 9], resp[str_off + 10], resp[str_off + 11]]) as usize;
            if actual > 0 && str_off + 12 + actual * 2 <= resp.len() {
                let name = String::from_utf16_lossy(
                    &resp[str_off + 12..str_off + 12 + actual * 2]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>()
                ).trim_matches('\0').to_string();
                if !name.is_empty() { domains.push(name); }
            }
        }
        Ok(domains)
    }

    async fn samr_open_domain(&self, session: &SmbSession, server_handle: &[u8; 20], _domain: &str) -> Result<[u8; 20]> {
        let mut stub = Vec::new();
        stub.extend_from_slice(server_handle);
        stub.extend_from_slice(&0x00020000u32.to_le_bytes());
        stub.extend_from_slice(&1u32.to_le_bytes());
        stub.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        stub.extend_from_slice(&5u32.to_le_bytes());
        stub.extend_from_slice(&0x0000000au32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes());
        let req = build_rpc_request(5, &stub);
        let resp = session.pipe_transact("samr", &req).await?;
        extract_handle(&resp).ok_or_else(|| OverthroneError::Rpc {
            target: "samr".to_string(),
            reason: "SamrOpenDomain failed".to_string(),
        })
    }

    async fn samr_enum_users(&self, session: &SmbSession, domain_handle: &[u8; 20]) -> Result<Vec<String>> {
        let mut all_users = Vec::new();
        let mut resume_handle = 0u32;
        loop {
            let mut stub = Vec::new();
            stub.extend_from_slice(domain_handle);
            stub.extend_from_slice(&resume_handle.to_le_bytes());
            stub.extend_from_slice(&0u32.to_le_bytes());
            stub.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
            let req = build_rpc_request(13, &stub);
            let resp = session.pipe_transact("samr", &req).await?;
            let stub_start = 24usize;
            if resp.len() < stub_start + 8 { break; }
            let count = u32::from_le_bytes([resp[stub_start], resp[stub_start + 1], resp[stub_start + 2], resp[stub_start + 3]]) as usize;
            resume_handle = u32::from_le_bytes([resp[stub_start + 4], resp[stub_start + 5], resp[stub_start + 6], resp[stub_start + 7]]);
            if count == 0 || count > 1000 { break; }
            let string_start = stub_start + 12 + count * 8;
            for i in 0..count {
                let str_off = string_start + i * 12;
                if str_off + 12 > resp.len() { break; }
                let actual = u32::from_le_bytes([resp[str_off + 8], resp[str_off + 9], resp[str_off + 10], resp[str_off + 11]]) as usize;
                if actual > 0 && str_off + 12 + actual * 2 <= resp.len() {
                    let name = String::from_utf16_lossy(
                        &resp[str_off + 12..str_off + 12 + actual * 2]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>()
                    ).trim_matches('\0').to_string();
                    if !name.is_empty() { all_users.push(name); }
                }
            }
            if resume_handle == 0 { break; }
        }
        Ok(all_users)
    }

    fn samr_close_req(&self, handle: &[u8; 20]) -> Vec<u8> {
        let mut stub = Vec::new();
        stub.extend_from_slice(handle);
        build_rpc_request(0, &stub)
    }
}
