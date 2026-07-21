//! Kerberos credential cache management subcommand.
//!
//! Manages cached TGTs stored in `~/.cache/overthrone/ccache/<realm>/<user>.kirbi`
//! (or equivalent platform path). Supports listing, inspecting, and clearing cached tickets.
//!
//! Usage:
//! ovt ccache list
//! ovt ccache show realm user
//! ovt ccache path
//! ovt ccache stats
//! ovt ccache clear [--all | <realm>]

use clap::{Parser, Subcommand};
use colored::Colorize;

use overthrone_core::cred_cache::CredCache;

#[derive(Debug, Clone, Parser)]
#[command(about = "Manage cached Kerberos tickets (KRB5CCNAME-style cache)")]
pub struct CcacheArgs {
    #[command(subcommand)]
    pub action: CcacheAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum CcacheAction {
    /// List all cached tickets by realm and username
    List,
    /// Show details of a cached ticket
    Show {
        /// Kerberos realm (domain FQDN)
        realm: String,
        /// Username
        username: String,
    },
    /// Show the cache directory path
    Path,
    /// Show cache statistics (count, total size)
    Stats,
    /// Clear cached tickets
    Clear {
        /// Realm to clear (omit to clear all)
        realm: Option<String>,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

/// Run the ccache subcommand.
pub fn run(args: CcacheArgs) -> i32 {
    let cache = CredCache::new();

    match args.action {
        CcacheAction::List => cmd_list(&cache),
        CcacheAction::Show { realm, username } => cmd_show(&cache, &realm, &username),
        CcacheAction::Path => cmd_path(&cache),
        CcacheAction::Stats => cmd_stats(&cache),
        CcacheAction::Clear { realm, yes } => cmd_clear(&cache, realm.as_deref(), yes),
    }
}

fn cmd_list(cache: &CredCache) -> i32 {
    let tickets = cache.list_tgts();
    if tickets.is_empty() {
        println!("{}", "No cached tickets found".dimmed());
        return 0;
    }
    println!("{}", "Cached Kerberos tickets:".bold());
    println!("{}", "-----------------------------".dimmed());
    for (realm, user) in &tickets {
        println!(" {}@{}", user.bold(), realm);
    }
    println!();
    println!(" Total: {} ticket(s)", tickets.len());
    0
}

fn cmd_show(cache: &CredCache, realm: &str, username: &str) -> i32 {
    let tgt = cache.load_tgt(realm, username);
    match tgt {
        Some(ticket) => {
            println!("{}", "Cached Ticket:".bold());
            println!(" Username: {}", ticket.client_principal.green());
            println!(" Realm: {}", ticket.client_realm.green());
            let end_str = ticket
                .end_time
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string());
            println!(" Expires: {}", end_str.yellow());
            println!(" EType: {}", ticket.session_key_etype);
            println!(" SName: {:?}", ticket.ticket.sname);
            0
        }
        None => {
            println!(
                "{}",
                format!("No cached ticket found for {username}@{realm}").red()
            );
            1
        }
    }
}

fn cmd_path(_cache: &CredCache) -> i32 {
    let cache = CredCache::new();
    println!("{}", cache.cache_dir.display());
    0
}

fn cmd_stats(cache: &CredCache) -> i32 {
    let count = cache.count();
    let size = cache.total_size();
    let size_str = if size > 1024 * 1024 {
        format!("{:.1} MiB", size as f64 / (1024.0 * 1024.0))
    } else if size > 1024 {
        format!("{:.1} KiB", size as f64 / 1024.0)
    } else {
        format!("{size} B")
    };
    println!("{}", "Credential Cache Statistics:".bold());
    println!(" Directory: {}", cache.cache_dir.display());
    println!(" Cached tickets: {}", count);
    println!(" Total size: {}", size_str);
    0
}

fn cmd_clear(cache: &CredCache, realm: Option<&str>, yes: bool) -> i32 {
    match realm {
        Some(r) => {
            let count = cache.list_tgts();
            let realm_count = count.iter().filter(|(r2, _)| r2 == r).count();
            if realm_count == 0 {
                println!("{}", format!("No cached tickets for realm '{r}'").yellow());
                return 0;
            }
            if !yes {
                eprint!(
                    "{}",
                    format!("Clear {realm_count} cached ticket(s) for realm '{r}'? [y/N] ")
                        .yellow()
                );
                use std::io::Write;
                std::io::stdout().flush().ok();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).ok();
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled");
                    return 0;
                }
            }
            match cache.clear_realm(r) {
                Ok(n) => {
                    println!("Cleared {n} cached ticket(s) for realm '{r}'");
                    0
                }
                Err(e) => {
                    eprintln!("{}", format!("Error clearing realm '{r}': {e}").red());
                    1
                }
            }
        }
        None => {
            let count = cache.count();
            if count == 0 {
                println!("{}", "No cached tickets to clear".dimmed());
                return 0;
            }
            if !yes {
                eprint!(
                    "{}",
                    format!("Clear ALL {count} cached ticket(s)? [y/N] ").yellow()
                );
                use std::io::Write;
                std::io::stdout().flush().ok();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).ok();
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled");
                    return 0;
                }
            }
            match cache.clear_all() {
                Ok(n) => {
                    println!("Cleared all {n} cached ticket(s)");
                    0
                }
                Err(e) => {
                    eprintln!("{}", format!("Error clearing cache: {e}").red());
                    1
                }
            }
        }
    }
}
