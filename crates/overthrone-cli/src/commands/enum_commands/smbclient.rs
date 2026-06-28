use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::epm::{
    SRVSVC_UUID, build_rpc_bind, build_rpc_request, is_bind_accepted,
};
use overthrone_core::proto::smb::SmbSession;
use tracing::info;

pub struct SmbClient {
    target: String,
    domain: String,
    username: String,
    password: String,
    smb_session: Option<SmbSession>,
    connected: bool,
}

impl SmbClient {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            domain: String::new(),
            username: String::new(),
            password: String::new(),
            smb_session: None,
            connected: false,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("[SMB] Connecting to \\\\{}", self.target);
        let domain = if self.domain.is_empty() { "." } else { &self.domain };
        let session = SmbSession::connect(&self.target, domain, &self.username, &self.password)
            .await
            .map_err(|e| OverthroneError::Smb(format!("SMB connect failed: {}", e)))?;
        info!("[SMB] Connected to \\\\{}", self.target);
        self.smb_session = Some(session);
        self.connected = true;
        Ok(())
    }

    pub async fn list_shares(&mut self) -> Result<Vec<String>> {
        let session = self.session()?;

        let bind_req = build_rpc_bind(&SRVSVC_UUID, 3, 0);
        let bind_resp = session.pipe_transact("srvsvc", &bind_req).await?;
        if !is_bind_accepted(&bind_resp) {
            return Err(OverthroneError::Rpc {
                target: "srvsvc".to_string(),
                reason: "SRVSVC bind rejected".to_string(),
            });
        }

        let mut stub = Vec::new();
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&1u32.to_le_bytes());
        stub.extend_from_slice(&0x00020004u32.to_le_bytes());
        stub.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        let req = build_rpc_request(15, &stub);
        let resp = session.pipe_transact("srvsvc", &req).await?;

        let mut shares = Vec::new();
        let stub_start = 24usize;
        if resp.len() < stub_start + 8 { return Ok(shares); }
        let count = u32::from_le_bytes([resp[stub_start + 4], resp[stub_start + 5], resp[stub_start + 6], resp[stub_start + 7]]) as usize;
        if count == 0 || count > 500 { return Ok(shares); }

        let entries_start = stub_start + 8;
        let string_start = entries_start + count * 12;
        for i in 0..count {
            let entry_off = entries_start + i * 12;
            if entry_off + 12 > resp.len() { break; }
            let name_ptr = u32::from_le_bytes([resp[entry_off], resp[entry_off + 1], resp[entry_off + 2], resp[entry_off + 3]]);
            if name_ptr == 0 { continue; }
            let str_off = string_start + ((name_ptr & 0xFFFF) as usize) * 2;
            if str_off + 12 > resp.len() { continue; }
            let actual = u32::from_le_bytes([resp[str_off + 8], resp[str_off + 9], resp[str_off + 10], resp[str_off + 11]]) as usize;
            if actual > 0 && str_off + 12 + actual * 2 <= resp.len() {
                let name = String::from_utf16_lossy(
                    &resp[str_off + 12..str_off + 12 + actual * 2]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>()
                ).trim_matches('\0').to_string();
                if !name.is_empty() { shares.push(name); }
            }
        }
        Ok(shares)
    }

    pub async fn spider_share(&mut self, share: &str, path: &str) -> Result<Vec<String>> {
        let session = self.session()?;
        let entries = session.list_directory(share, path).await?;
        let results: Vec<String> = entries
            .into_iter()
            .map(|e| {
                let kind = if e.is_directory { 'd' } else { '-' };
                format!("{} {}  {}  {}", kind, e.size, e.path, e.name)
            })
            .collect();
        Ok(results)
    }

    pub fn disconnect(&mut self) {
        self.smb_session = None;
        self.connected = false;
        info!("[SMB] Disconnected");
    }

    pub fn set_credentials(&mut self, domain: &str, username: &str, password: &str) {
        self.domain = domain.to_string();
        self.username = username.to_string();
        self.password = password.to_string();
    }

    pub async fn run_interactive(&mut self) -> Result<()> {
        println!("SMB Client interactive shell for {}", self.target);
        println!("Commands: connect, shares, spider <share> [path], creds <domain> <user> <pass>, quit");
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();
        loop {
            print!("smb> ");
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
                    match self.connect().await {
                        Ok(()) => println!("Connected to {}", self.target),
                        Err(e) => println!("Connect failed: {e}"),
                    }
                }
                "creds" => {
                    if parts.len() < 4 {
                        println!("Usage: creds <domain> <username> <password>");
                        continue;
                    }
                    self.set_credentials(parts[1], parts[2], parts[3]);
                    println!("Credentials set");
                }
                "shares" => {
                    if !self.connected { println!("Not connected. Use 'connect' first."); continue; }
                    match self.list_shares().await {
                        Ok(shares) => {
                            println!("Shares ({}):", shares.len());
                            for s in shares { println!("  {}", s); }
                        }
                        Err(e) => println!("Share enum failed: {e}"),
                    }
                }
                "spider" => {
                    if !self.connected { println!("Not connected. Use 'connect' first."); continue; }
                    if parts.len() < 2 {
                        println!("Usage: spider <share> [path]");
                        continue;
                    }
                    let spath = if parts.len() > 2 { parts[2] } else { "" };
                    match self.spider_share(parts[1], spath).await {
                        Ok(entries) => {
                            println!("Entries in {}\\{} ({}):", parts[1], spath, entries.len());
                            for e in entries { println!("  {}", e); }
                        }
                        Err(e) => println!("Spider failed: {e}"),
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
        self.smb_session.as_ref().ok_or_else(|| {
    let msg = if let Some(ref cfg) = self.config {
        format!("SMB not connected to {}", cfg.server)
    } else {
        "SMB not connected (no config)".to_string()
    };
    OverthroneError::Smb(msg)
})
    }
}
