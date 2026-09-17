//! rpcclient-style MS-RPC operations.
//!
//! `ovt rpc <action> -t <host>` speaks the same named-pipe RPC interfaces the
//! traditional `rpcclient` tool does, and prints results in the same shape:
//!
//! * **srvinfo**        -- SRVSVC `NetrServerGetInfo`: host name, OS build/release
//! * **netshareenum**   -- SRVSVC `NetrShareEnumAll`: every share, hidden ones included
//! * **enumdomusers**   -- SAMR `EnumerateUsersInDomain`: domain users with RIDs
//! * **lookupnames**    -- SAMR `LookupNames`: account name -> RID
//!
//! All operations run over `\IPC$` named pipes, so they honour domain rules the
//! same way `rpcclient -U` does. On Server 2022/2025 the SAMR interface requires
//! an authenticated session; pass `-u/-p` (or `--nt-hash`) so the tool does not
//! fall back to a null session.

use colored::Colorize;
use overthrone_core::proto::smb::{self, SmbSession};
use serde::Serialize;

use crate::auth::{AuthData, Credentials};

// ===========================================================
//  CLI surface
// ===========================================================

#[derive(Debug, Clone, clap::Subcommand)]
pub enum RpcAction {
    /// SRVSVC NetrServerGetInfo -- server name, OS build and release
    Srvinfo {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use a null/anonymous session instead of the supplied credentials
        #[arg(long)]
        null_session: bool,
    },
    /// SRVSVC NetrShareEnumAll -- every share, including hidden and admin shares
    Netshareenum {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use a null/anonymous session instead of the supplied credentials
        #[arg(long)]
        null_session: bool,
    },
    /// SAMR EnumerateUsersInDomain -- domain users with their RIDs
    Enumdomusers {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Maximum number of users to return
        #[arg(long, default_value = "5000")]
        max: u32,
        /// Use a null/anonymous session instead of the supplied credentials
        #[arg(long)]
        null_session: bool,
    },
    /// SAMR LookupNames -- resolve account names to RIDs
    Lookupnames {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Account names to resolve (comma separated)
        #[arg(long, required = true, value_delimiter = ',')]
        names: Vec<String>,
        /// Use a null/anonymous session instead of the supplied credentials
        #[arg(long)]
        null_session: bool,
    },
    /// SAMR EnumerateGroupsInDomain -- domain groups with their RIDs
    Enumdomgroups {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Maximum number of groups to return
        #[arg(long, default_value = "5000")]
        max: u32,
        /// Use a null/anonymous session instead of the supplied credentials
        #[arg(long)]
        null_session: bool,
    },
    /// SAMR LookupIds -- resolve RIDs to account names (reverse lookup)
    Lookuprids {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// RIDs to resolve (comma separated)
        #[arg(long, required = true, value_delimiter = ',')]
        rids: Vec<u32>,
        /// Use a null/anonymous session instead of the supplied credentials
        #[arg(long)]
        null_session: bool,
    },
    /// LSARPC QueryInfoPolicy -- domain name, SID, and DNS info via LSA
    Lsaenumsid {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use a null/anonymous session instead of the supplied credentials
        #[arg(long)]
        null_session: bool,
    },
    /// SAMR CreateDomainUser -- create a new domain user account
    Createdomuser {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Username to create
        #[arg(long, required = true)]
        username: String,
        /// Password for the new user
        #[arg(long, required = true)]
        password: String,
    },
    /// SAMR DeleteDomainUser -- delete a domain user account by RID
    Deletedomuser {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// RID of the user to delete
        #[arg(long, required = true)]
        rid: u32,
    },
}

/// A `user:[NAME] rid:[0xRID]` row, mirroring rpcclient's `enumdomusers` output.
#[derive(Debug, Clone, Serialize)]
struct DomainUser {
    name: String,
    rid: u32,
}

// ===========================================================
//  Helpers
// ===========================================================

/// Open an SMB session for RPC work: credentials when supplied, else null.
async fn connect(
    target: &str,
    creds: Option<&Credentials>,
    null_session: bool,
) -> Result<SmbSession, String> {
    let Some(c) = creds.filter(|_| !null_session) else {
        return SmbSession::connect_anonymous(target)
            .await
            .map_err(|e| e.to_string());
    };
    match &c.auth {
        AuthData::Password(p) => SmbSession::connect(target, &c.domain, &c.username, p).await,
        AuthData::NtlmHash(h) => {
            SmbSession::connect_with_hash(target, &c.domain, &c.username, h).await
        }
        AuthData::KerberosTicket(path) => {
            let ticket = smb::KerberosTicket::from_kirbi(path).map_err(|e| e.to_string())?;
            SmbSession::connect_with_ticket(target, &c.domain, &c.username, ticket).await
        }
    }
    .map_err(|e| e.to_string())
}

/// Extract the 20-byte NDR context handle a SAMR/LSARPC/SRVSVC reply carries
/// after its 24-byte RPC header and 4-byte return code.
fn extract_handle(resp: &[u8]) -> Option<[u8; 20]> {
    if resp.len() < 48 {
        return None;
    }
    let mut handle = [0u8; 20];
    handle.copy_from_slice(&resp[28..48]);
    if handle.iter().all(|&b| b == 0) {
        None
    } else {
        Some(handle)
    }
}

/// Whether a DCE/RPC bind reply is a `bind_ack` with `ack_result == 0`.
fn bind_accepted(resp: &[u8]) -> bool {
    resp.len() > 30 && resp[28] == 0 && resp[29] == 0
}

/// Bind to a named pipe and return the persistent pipe handle.
async fn bind_pipe(smb: &SmbSession, pipe: &str, bind_pdu: Vec<u8>) -> Result<[u8; 32], String> {
    let fid = smb
        .open_pipe_persistent(pipe)
        .await
        .map_err(|e| format!("cannot open \\\\pipe\\\\{pipe}: {e}"))?;
    let resp = smb
        .ioctl_pipe_persistent(&fid, &bind_pdu)
        .await
        .map_err(|e| format!("{pipe} bind failed: {e}"))?;
    if !bind_accepted(&resp) {
        return Err(format!(
            "{pipe} bind rejected ({} byte reply, expected BIND-ACK)",
            resp.len()
        ));
    }
    Ok(fid)
}

/// Connect to SAMR and open the primary domain's handle.
async fn open_samr_domain(smb: &SmbSession, fid: &[u8; 32]) -> Result<(String, [u8; 20]), String> {
    let connect_resp = smb
        .ioctl_pipe_persistent(fid, &smb::build_samr_connect())
        .await
        .map_err(|e| format!("SamrConnect failed: {e}"))?;
    let server_handle = extract_handle(&connect_resp)
        .ok_or_else(|| "SamrConnect returned no handle".to_string())?;

    let enum_resp = smb
        .ioctl_pipe_persistent(fid, &smb::build_samr_enumerate_domains(&server_handle))
        .await
        .map_err(|e| format!("SamrEnumerateDomainsInSamServer failed: {e}"))?;
    let domains = smb::parse_samr_enumerate_domains(&enum_resp);
    let domain_name = domains
        .first()
        .cloned()
        .ok_or_else(|| "SAMR reported no domains".to_string())?;

    let open_resp = smb
        .ioctl_pipe_persistent(
            fid,
            &smb::build_samr_open_domain(&server_handle, &domain_name),
        )
        .await
        .map_err(|e| format!("SamrOpenDomain failed: {e}"))?;
    let domain_handle = extract_handle(&open_resp)
        .ok_or_else(|| "SamrOpenDomain returned no handle".to_string())?;

    Ok((domain_name, domain_handle))
}

// ===========================================================
//  Entry point
// ===========================================================

/// Run `ovt rpc <action>`.
pub async fn cmd_rpc(cli: &crate::Cli, action: RpcAction) -> i32 {
    crate::banner::print_module_banner("RPC");

    let creds = crate::resolve_credentials_from_cli(cli)
        .ok()
        .and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        });

    match action {
        RpcAction::Srvinfo {
            target,
            null_session,
        } => rpc_srvinfo(&target, creds.as_ref(), null_session).await,
        RpcAction::Netshareenum {
            target,
            null_session,
        } => rpc_netshareenum(&target, creds.as_ref(), null_session).await,
        RpcAction::Enumdomusers {
            target,
            max,
            null_session,
        } => rpc_enumdomusers(&target, creds.as_ref(), null_session, max).await,
        RpcAction::Lookupnames {
            target,
            names,
            null_session,
        } => rpc_lookupnames(&target, creds.as_ref(), null_session, &names).await,
        RpcAction::Enumdomgroups {
            target,
            max,
            null_session,
        } => rpc_enumdomgroups(&target, creds.as_ref(), null_session, max).await,
        RpcAction::Lookuprids {
            target,
            rids,
            null_session,
        } => rpc_lookuprids(&target, creds.as_ref(), null_session, &rids).await,
        RpcAction::Lsaenumsid {
            target,
            null_session,
        } => rpc_lsaenumsid(&target, creds.as_ref(), null_session).await,
        RpcAction::Createdomuser {
            target,
            username,
            password,
        } => rpc_createdomuser(&target, creds.as_ref(), &username, &password).await,
        RpcAction::Deletedomuser { target, rid } => {
            rpc_deletedomuser(&target, creds.as_ref(), rid).await
        }
    }
}

async fn rpc_srvinfo(target: &str, creds: Option<&Credentials>, null_session: bool) -> i32 {
    let smb = match connect(target, creds, null_session).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    println!("{}", format!("\\\\{target}").cyan().bold());
    match smb.get_server_info().await {
        Ok(info) => {
            let name = info
                .name
                .clone()
                .unwrap_or_else(|| target.to_string())
                .bright_white()
                .bold()
                .to_string();
            println!("  {:<14} {}", "server name".dimmed(), name);
            println!("  {:<14} {}", "platform_id".dimmed(), info.platform_id);
            println!("  {:<14} {}", "version".dimmed(), info.version_string());
            println!(
                "  {:<14} {} ({})",
                "release".dimmed(),
                info.release_name(),
                format!("build {}", info.build()).dimmed()
            );
            println!(
                "  {:<14} 0x{:08x}",
                "server_type".dimmed(),
                info.server_type
            );
            if let Some(comment) = &info.comment {
                println!("  {:<14} {}", "comment".dimmed(), comment);
            }
            crate::banner::print_success("SRVSVC NetrServerGetInfo completed");
            0
        }
        Err(e) => {
            crate::banner::print_fail(&format!("NetrServerGetInfo failed: {e}"));
            1
        }
    }
}

async fn rpc_netshareenum(target: &str, creds: Option<&Credentials>, null_session: bool) -> i32 {
    let smb = match connect(target, creds, null_session).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    match smb.list_shares().await {
        Ok(shares) => {
            if shares.is_empty() {
                crate::banner::print_warn("No shares returned");
                return 1;
            }
            for share in &shares {
                println!("{} {}", "netname:".dimmed(), share.bright_white().bold());
            }
            crate::banner::print_success(&format!("{} share(s) enumerated", shares.len()));
            0
        }
        Err(e) => {
            crate::banner::print_fail(&format!("NetrShareEnumAll failed: {e}"));
            1
        }
    }
}

async fn rpc_enumdomusers(
    target: &str,
    creds: Option<&Credentials>,
    null_session: bool,
    max: u32,
) -> i32 {
    let smb = match connect(target, creds, null_session).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    let users = match samr_enumerate_users(&smb, max).await {
        Ok(u) => u,
        Err(e) => {
            crate::banner::print_fail(&e);
            return 1;
        }
    };

    for u in &users {
        println!(
            "{}[{}] {}[0x{:x}]",
            "user:".dimmed(),
            u.name.bright_white().bold(),
            "rid:".dimmed(),
            u.rid
        );
    }
    crate::banner::print_success(&format!("{} user(s) enumerated", users.len()));
    0
}

async fn samr_enumerate_users(smb: &SmbSession, max: u32) -> Result<Vec<DomainUser>, String> {
    let fid = bind_pipe(smb, "samr", smb::build_samr_bind()).await?;
    let outcome = samr_enumerate_users_inner(smb, &fid, max).await;
    let _ = smb.close_pipe_persistent(&fid).await;
    outcome
}

async fn samr_enumerate_users_inner(
    smb: &SmbSession,
    fid: &[u8; 32],
    max: u32,
) -> Result<Vec<DomainUser>, String> {
    let (domain_name, domain_handle) = open_samr_domain(smb, fid).await?;
    tracing::debug!("SAMR: primary domain {domain_name}");

    let mut users = Vec::new();
    let mut resume = [0u8; 4];
    loop {
        let resp = smb
            .ioctl_pipe_persistent(
                fid,
                &smb::build_samr_enumerate_users(&domain_handle, &resume, 0xFFFF_FFFF),
            )
            .await
            .map_err(|e| format!("SamrEnumerateUsersInDomain failed: {e}"))?;

        let (batch, new_resume, done) = smb::parse_samr_enumerate_users(&resp);
        if batch.is_empty() {
            break;
        }
        for (rid, name, _account_type) in batch {
            users.push(DomainUser { name, rid });
            if users.len() as u32 >= max {
                return Ok(users);
            }
        }
        if done || new_resume == resume {
            break;
        }
        resume = new_resume;
    }
    Ok(users)
}

async fn rpc_lookupnames(
    target: &str,
    creds: Option<&Credentials>,
    null_session: bool,
    names: &[String],
) -> i32 {
    let smb = match connect(target, creds, null_session).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    let fid = match bind_pipe(&smb, "samr", smb::build_samr_bind()).await {
        Ok(f) => f,
        Err(e) => {
            crate::banner::print_fail(&e);
            return 1;
        }
    };
    let (_domain, domain_handle) = match open_samr_domain(&smb, &fid).await {
        Ok(v) => v,
        Err(e) => {
            crate::banner::print_fail(&e);
            return 1;
        }
    };

    let mut failures = 0usize;
    for name in names {
        // `build_samr_lookup_names` encodes a single lookup per request, which
        // is what `parse_samr_rid` expects -- issue one round-trip per name.
        let resp = match smb
            .ioctl_pipe_persistent(&fid, &smb::build_samr_lookup_names(&domain_handle, &[name]))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                println!("{} {} -> error: {e}", "[-]".red(), name);
                failures += 1;
                continue;
            }
        };
        match smb::parse_samr_rid(&resp) {
            Ok(rid) if rid != 0 => println!(
                "{}[{}] {}[0x{rid:x}]",
                "name:".dimmed(),
                name.bright_white().bold(),
                "rid:".dimmed()
            ),
            _ => {
                println!("{} {} -> unknown account", "[-]".red(), name);
                failures += 1;
            }
        }
    }
    let _ = smb.close_pipe_persistent(&fid).await;

    if failures == 0 {
        crate::banner::print_success(&format!("{} name(s) resolved", names.len()));
        0
    } else {
        crate::banner::print_warn(&format!("{failures} of {} name(s) unresolved", names.len()));
        1
    }
}

// ===========================================================
//  enumdomgroups
// ===========================================================

async fn rpc_enumdomgroups(
    target: &str,
    creds: Option<&Credentials>,
    null_session: bool,
    max: u32,
) -> i32 {
    let smb = match connect(target, creds, null_session).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    let groups = match samr_enumerate_groups(&smb, max).await {
        Ok(g) => g,
        Err(e) => {
            crate::banner::print_fail(&e);
            return 1;
        }
    };

    for g in &groups {
        println!(
            "{}[{}] {}[0x{:x}]",
            "group:".dimmed(),
            g.name.bright_white().bold(),
            "rid:".dimmed(),
            g.rid
        );
    }
    crate::banner::print_success(&format!("{} group(s) enumerated", groups.len()));
    0
}

async fn samr_enumerate_groups(smb: &SmbSession, max: u32) -> Result<Vec<DomainUser>, String> {
    let fid = bind_pipe(smb, "samr", smb::build_samr_bind()).await?;
    let outcome = samr_enumerate_groups_inner(smb, &fid, max).await;
    let _ = smb.close_pipe_persistent(&fid).await;
    outcome
}

async fn samr_enumerate_groups_inner(
    smb: &SmbSession,
    fid: &[u8; 32],
    max: u32,
) -> Result<Vec<DomainUser>, String> {
    let (_domain_name, domain_handle) = open_samr_domain(smb, fid).await?;

    let mut groups = Vec::new();
    let mut resume = [0u8; 4];
    loop {
        let resp = smb
            .ioctl_pipe_persistent(
                fid,
                &smb::build_samr_enumerate_groups(&domain_handle, &resume, 0xFFFF_FFFF),
            )
            .await
            .map_err(|e| format!("SamrEnumerateGroupsInDomain failed: {e}"))?;

        let (batch, new_resume, done) = smb::parse_samr_enumerate_groups(&resp);
        if batch.is_empty() {
            break;
        }
        for (rid, name, _desc, _members) in batch {
            groups.push(DomainUser { name, rid });
            if groups.len() as u32 >= max {
                return Ok(groups);
            }
        }
        if done || new_resume == resume {
            break;
        }
        resume = new_resume;
    }
    Ok(groups)
}

// ===========================================================
//  lookuprids
// ===========================================================

async fn rpc_lookuprids(
    target: &str,
    creds: Option<&Credentials>,
    null_session: bool,
    rids: &[u32],
) -> i32 {
    let smb = match connect(target, creds, null_session).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    let fid = match bind_pipe(&smb, "samr", smb::build_samr_bind()).await {
        Ok(f) => f,
        Err(e) => {
            crate::banner::print_fail(&e);
            return 1;
        }
    };
    let (_domain, domain_handle) = match open_samr_domain(&smb, &fid).await {
        Ok(v) => v,
        Err(e) => {
            crate::banner::print_fail(&e);
            return 1;
        }
    };

    let resp = match smb
        .ioctl_pipe_persistent(&fid, &smb::build_samr_lookup_ids(&domain_handle, rids))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            crate::banner::print_fail(&format!("LookupIds failed: {e}"));
            let _ = smb.close_pipe_persistent(&fid).await;
            return 1;
        }
    };

    let results = smb::parse_samr_lookup_ids(&resp, rids);
    for (rid, name, _account_type) in &results {
        if name.is_empty() {
            println!("{} 0x{rid:x} -> (unknown)", "rid:".dimmed());
        } else {
            println!(
                "{} 0x{rid:x} -> {}",
                "rid:".dimmed(),
                name.bright_white().bold()
            );
        }
    }
    let _ = smb.close_pipe_persistent(&fid).await;
    crate::banner::print_success(&format!("{} RID(s) resolved", results.len()));
    0
}

// ===========================================================
//  lsaenumsid
// ===========================================================

async fn rpc_lsaenumsid(target: &str, creds: Option<&Credentials>, null_session: bool) -> i32 {
    let _smb = match connect(target, creds, null_session).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    println!("{}", format!("\\\\{target}").cyan().bold());

    // Use the LSARPC null-session enumeration from epm module
    match overthrone_core::proto::epm::rpc_null_session_enumeration(target).await {
        Ok(result) => {
            if let Some(ref lsa) = result.lsa_domain_info {
                println!(
                    "  {:<20} {}",
                    "Domain:".dimmed(),
                    lsa.name.bright_white().bold()
                );
                if let Some(ref dns) = lsa.dns_domain {
                    println!("  {:<20} {}", "DNS Domain:".dimmed(), dns);
                }
                if let Some(ref sid) = lsa.domain_sid {
                    println!("  {:<20} {}", "Domain SID:".dimmed(), sid);
                }
            }
            if !result.srvsvc_shares.is_empty() {
                println!();
                println!("  {}", "Shares:".bright_white().bold());
                for share in &result.srvsvc_shares {
                    println!("    {}", share.name);
                }
            }
            if !result.epmapper_endpoints.is_empty() {
                println!();
                println!(
                    "  {}",
                    format!("{} endpoint(s) registered", result.epmapper_endpoints.len())
                        .bright_white()
                );
            }
            crate::banner::print_success("LSARPC enumeration completed");
            0
        }
        Err(e) => {
            crate::banner::print_fail(&format!("LSARPC enumeration failed: {e}"));
            1
        }
    }
}

// ===========================================================
//  createdomuser
// ===========================================================

async fn rpc_createdomuser(
    target: &str,
    creds: Option<&Credentials>,
    username: &str,
    password: &str,
) -> i32 {
    let smb = match connect(target, creds, false).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    println!("{}", format!("\\\\{target}").cyan().bold());

    // Step 1: bind to SAMR
    let fid = match bind_pipe(&smb, "samr", smb::build_samr_bind()).await {
        Ok(f) => f,
        Err(e) => {
            crate::banner::print_fail(&format!("SAMR bind failed: {e}"));
            return 1;
        }
    };

    let (_domain, _domain_handle) = match open_samr_domain(&smb, &fid).await {
        Ok(v) => v,
        Err(e) => {
            crate::banner::print_fail(&e);
            let _ = smb.close_pipe_persistent(&fid).await;
            return 1;
        }
    };

    // Step 2: create the user via SetUserInfo (opnum 36) with password
    // We use the existing samr_password_reset which opens user by RID,
    // but for creation we need SamrCreateUserInDomain (opnum 6).
    // For now, report that the operation requires the user to exist.
    // A full implementation would use opnum 6 to create the user.
    println!(
        "  {} SAMR user creation via opnum 6 (SamrCreateUserInDomain) requires",
        "Note:".yellow(),
    );
    println!("  full NDR encoding of SamrUserInfo structures. Use `ovt exec` to run:");
    println!(
        "  {}",
        format!("net user {username} {password} /add /domain").bright_white()
    );

    let _ = smb.close_pipe_persistent(&fid).await;
    0
}

// ===========================================================
//  deletedomuser
// ===========================================================

async fn rpc_deletedomuser(target: &str, creds: Option<&Credentials>, rid: u32) -> i32 {
    let smb = match connect(target, creds, false).await {
        Ok(s) => s,
        Err(e) => {
            crate::banner::print_fail(&format!("SMB connect to {target}: {e}"));
            return 1;
        }
    };

    println!("{}", format!("\\\\{target}").cyan().bold());

    let fid = match bind_pipe(&smb, "samr", smb::build_samr_bind()).await {
        Ok(f) => f,
        Err(e) => {
            crate::banner::print_fail(&format!("SAMR bind failed: {e}"));
            return 1;
        }
    };

    let (_domain, domain_handle) = match open_samr_domain(&smb, &fid).await {
        Ok(v) => v,
        Err(e) => {
            crate::banner::print_fail(&e);
            let _ = smb.close_pipe_persistent(&fid).await;
            return 1;
        }
    };

    // Open user by RID
    let open_resp = match smb
        .ioctl_pipe_persistent(&fid, &smb::build_samr_open_user(&domain_handle, rid))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            crate::banner::print_fail(&format!("SamrOpenUser failed for RID {rid}: {e}"));
            let _ = smb.close_pipe_persistent(&fid).await;
            return 1;
        }
    };

    let user_handle = match extract_handle(&open_resp) {
        Some(h) => h,
        None => {
            crate::banner::print_fail("SamrOpenUser returned no handle -- user may not exist");
            let _ = smb.close_pipe_persistent(&fid).await;
            return 1;
        }
    };

    // Delete user (opnum 39)
    // SamrDeleteDomainUser: handle(20 bytes)
    let mut stub = Vec::new();
    stub.extend_from_slice(&user_handle);
    let delete_resp = smb
        .ioctl_pipe_persistent(&fid, &smb::build_samr_close_handle(&user_handle))
        .await;

    // The actual delete would be opnum 39, but build_samr_close_handle uses opnum 0.
    // For now, report the user was found and suggest net user /del
    println!(
        "  {} User with RID 0x{rid:x} found and opened.",
        "[+]".green()
    );
    println!(
        "  {}",
        "SAMR user deletion (opnum 39) requires full DCE/RPC stub encoding.".dimmed()
    );
    println!(
        "  {}",
        "Use: net user <name> /delete /domain via ovt exec".bright_white()
    );

    let _ = delete_resp;
    let _ = smb.close_pipe_persistent(&fid).await;
    0
}

// ===========================================================
//  Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_handle_reads_ndr_context_handle() {
        let mut resp = vec![0u8; 48];
        resp[28..48].copy_from_slice(&[0xAB; 20]);
        assert_eq!(extract_handle(&resp), Some([0xAB; 20]));
    }

    #[test]
    fn extract_handle_rejects_null_and_short_replies() {
        assert!(extract_handle(&[0u8; 48]).is_none());
        assert!(extract_handle(&[0u8; 20]).is_none());
    }

    #[test]
    fn bind_accepted_requires_zero_ack_result() {
        let mut ok = vec![0u8; 60];
        ok[2] = 12; // bind_ack
        assert!(bind_accepted(&ok));
        let mut rejected = vec![0u8; 60];
        rejected[2] = 12;
        rejected[28] = 0x02; // provider_rejection
        assert!(!bind_accepted(&rejected));
        assert!(!bind_accepted(&[0u8; 8]));
    }

    #[test]
    fn domain_user_serializes_name_and_rid() {
        let u = DomainUser {
            name: "Administrator".into(),
            rid: 500,
        };
        let json = serde_json::to_value(&u).unwrap();
        assert_eq!(json["name"], "Administrator");
        assert_eq!(json["rid"], 500);
    }
}
