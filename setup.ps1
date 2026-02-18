# ============================================================
#  Overthrone - Full Project Scaffolding (PowerShell)
#  Run from: C:\Users\ACER\Documents\VSCFiles1\Overthrone
# ============================================================

Write-Host "`n[*] Scaffolding Overthrone..." -ForegroundColor Cyan

# --- Create all directories ---
$dirs = @(
    "crates\overthrone-core\src\proto",
    "crates\overthrone-core\src\crypto",
    "crates\overthrone-core\src\graph",
    "crates\overthrone-reaper\src",
    "crates\overthrone-hunter\src",
    "crates\overthrone-pilot\src",
    "crates\overthrone-crawler\src",
    "crates\overthrone-forge\src",
    "crates\overthrone-scribe\src",
    "crates\overthrone-cli\src",
    "assets",
    "configs",
    "docs\modules",
    "tests\integration",
    "tests\fixtures"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
Write-Host "[+] Directories created" -ForegroundColor Green

# ============================================================
#  ROOT FILES
# ============================================================

# --- Root Cargo.toml ---
@'
[workspace]
resolver = "2"
members = [
    "crates/overthrone-core",
    "crates/overthrone-reaper",
    "crates/overthrone-hunter",
    "crates/overthrone-pilot",
    "crates/overthrone-crawler",
    "crates/overthrone-forge",
    "crates/overthrone-scribe",
    "crates/overthrone-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
authors = ["Karmanya03"]
license = "MIT"
repository = "https://github.com/Karmanya03/Overthrone"
description = "Autonomous Active Directory Red Team Framework built in Rust"
rust-version = "1.85"

[workspace.dependencies]
# Async Runtime
tokio = { version = "1.49", features = ["full"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# Error Handling
thiserror = "2.0"
anyhow = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# CLI
clap = { version = "4.5", features = ["derive", "color", "env", "wrap_help"] }

# LDAP
ldap3 = "0.11"

# Graph Engine
petgraph = "0.7"

# TUI
ratatui = "0.29"
crossterm = "0.28"

# Report Generation
genpdf = "0.2"
pulldown-cmark = "0.12"

# Date/Time
chrono = { version = "0.4", features = ["serde"] }

# UUID
uuid = { version = "1.0", features = ["v4", "serde"] }

# Terminal Output
colored = "3.0"
indicatif = "0.17"
console = "0.15"

# Crypto
aes = "0.8"
cbc = "0.1"
hmac = "0.12"
md-5 = "0.10"
sha2 = "0.10"
rand = "0.8"
base64 = "0.22"

# Networking
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
hickory-resolver = "0.25"

# ASN.1 / Kerberos
rasn = "0.21"
rasn-der = "0.21"

# Byte Handling
bytes = "1.9"
byteorder = "1.5"

# Async Utilities
futures = "0.3"
tokio-util = { version = "0.7", features = ["full"] }

# Config
directories = "6.0"

# Testing
tokio-test = "0.4"
tempfile = "3.14"
pretty_assertions = "1.4"
'@ | Set-Content -Path "Cargo.toml" -Encoding UTF8

# --- .gitignore ---
@'
/target
**/*.rs.bk
*.pdb
*.exe
*.log
.env
*.pdf
/output/
.DS_Store
.vscode/settings.json
'@ | Set-Content -Path ".gitignore" -Encoding UTF8

# --- rustfmt.toml ---
@'
edition = "2024"
max_width = 100
tab_spaces = 4
use_field_init_shorthand = true
'@ | Set-Content -Path "rustfmt.toml" -Encoding UTF8

# --- clippy.toml ---
@'
too-many-arguments-threshold = 10
type-complexity-threshold = 350
'@ | Set-Content -Path "clippy.toml" -Encoding UTF8

# --- LICENSE (MIT) ---
@'
MIT License

Copyright (c) 2026 Karmanya03

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'@ | Set-Content -Path "LICENSE" -Encoding UTF8

# --- README.md ---
@'
# Overthrone

> Autonomous Active Directory Red Team Framework - Built in Rust

Every throne falls. Overthrone makes sure of it.
'@ | Set-Content -Path "README.md" -Encoding UTF8

Write-Host "[+] Root files created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-core
# ============================================================

@'
[package]
name = "overthrone-core"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Core library: protocols, crypto, types, graph engine"

[dependencies]
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tracing.workspace = true
ldap3.workspace = true
petgraph.workspace = true
chrono.workspace = true
uuid.workspace = true
bytes.workspace = true
byteorder.workspace = true
futures.workspace = true
aes.workspace = true
cbc.workspace = true
hmac.workspace = true
md-5.workspace = true
sha2.workspace = true
rand.workspace = true
base64.workspace = true
rasn.workspace = true
rasn-der.workspace = true
hickory-resolver.workspace = true

[dev-dependencies]
tokio-test.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-core\Cargo.toml" -Encoding UTF8

# --- core/src/lib.rs ---
@'
pub mod config;
pub mod crypto;
pub mod error;
pub mod graph;
pub mod output;
pub mod proto;
pub mod types;
'@ | Set-Content -Path "crates\overthrone-core\src\lib.rs" -Encoding UTF8

# --- core/src/error.rs ---
@'
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OverthroneError {
    #[error("LDAP error: {0}")]
    Ldap(String),

    #[error("Kerberos error: {0}")]
    Kerberos(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("SMB error: {0}")]
    Smb(String),

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Graph error: {0}")]
    Graph(String),

    #[error("No attack path found to target: {0}")]
    NoPath(String),

    #[error("{0}")]
    Custom(String),
}

pub type Result<T> = std::result::Result<T, OverthroneError>;
'@ | Set-Content -Path "crates\overthrone-core\src\error.rs" -Encoding UTF8

# --- core/src/config.rs ---
@'
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverthroneConfig {
    pub target: String,
    pub domain: String,
    pub auth: AuthConfig,
    pub output_format: OutputFormat,
    pub verbose: bool,
    pub threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthConfig {
    Password { username: String, password: String },
    NtlmHash { username: String, hash: String },
    Ticket { path: String },
    Certificate { pfx_path: String, password: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Table,
    Raw,
    BloodHound,
}

impl Default for OverthroneConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            domain: String::new(),
            auth: AuthConfig::Password {
                username: String::new(),
                password: String::new(),
            },
            output_format: OutputFormat::Json,
            verbose: false,
            threads: 10,
        }
    }
}
'@ | Set-Content -Path "crates\overthrone-core\src\config.rs" -Encoding UTF8

# --- core/src/types.rs ---
@'
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub name: String,
    pub netbios: String,
    pub sid: String,
    pub functional_level: String,
    pub domain_controllers: Vec<Computer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub sid: String,
    pub enabled: bool,
    pub admin_count: bool,
    pub spn: Vec<String>,
    pub dont_req_preauth: bool,
    pub password_last_set: Option<DateTime<Utc>>,
    pub last_logon: Option<DateTime<Utc>>,
    pub member_of: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Computer {
    pub sam_account_name: String,
    pub dns_hostname: String,
    pub os: String,
    pub os_version: String,
    pub sid: String,
    pub unconstrained_delegation: bool,
    pub constrained_delegation: Vec<String>,
    pub rbcd: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub sid: String,
    pub members: Vec<String>,
    pub admin_count: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trust {
    pub source_domain: String,
    pub target_domain: String,
    pub trust_type: TrustType,
    pub trust_direction: TrustDirection,
    pub sid_filtering: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustType {
    ParentChild,
    External,
    Forest,
    Realm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    pub name: String,
    pub oid: String,
    pub enrollee_supplies_subject: bool,
    pub client_auth: bool,
    pub enrollment_agent: bool,
    pub any_purpose: bool,
    pub vulnerable_esc: Vec<String>,
}
'@ | Set-Content -Path "crates\overthrone-core\src\types.rs" -Encoding UTF8

# --- core/src/output.rs ---
@'
use serde::Serialize;

pub fn print_json<T: Serialize>(data: &T) -> crate::error::Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    println!("{json}");
    Ok(())
}

pub fn print_banner_line(label: &str, value: &str) {
    println!("  {:<20} {}", label, value);
}
'@ | Set-Content -Path "crates\overthrone-core\src\output.rs" -Encoding UTF8

# --- core/src/proto/mod.rs ---
@'
pub mod dns;
pub mod kerberos;
pub mod ldap;
pub mod ntlm;
pub mod smb;
'@ | Set-Content -Path "crates\overthrone-core\src\proto\mod.rs" -Encoding UTF8

# --- core/src/proto stubs ---
@'
//! LDAP client wrapper around ldap3
'@ | Set-Content -Path "crates\overthrone-core\src\proto\ldap.rs" -Encoding UTF8

@'
//! Native Rust Kerberos implementation (AS-REQ, TGS-REQ, S4U2Self, S4U2Proxy)
'@ | Set-Content -Path "crates\overthrone-core\src\proto\kerberos.rs" -Encoding UTF8

@'
//! SMB2/3 client + RPC interface
'@ | Set-Content -Path "crates\overthrone-core\src\proto\smb.rs" -Encoding UTF8

@'
//! NTLM authentication + hash computation
'@ | Set-Content -Path "crates\overthrone-core\src\proto\ntlm.rs" -Encoding UTF8

@'
//! DNS resolution + SRV record lookup for DC discovery
'@ | Set-Content -Path "crates\overthrone-core\src\proto\dns.rs" -Encoding UTF8

# --- core/src/crypto/mod.rs ---
@'
pub mod aes_cts;
pub mod hmac_util;
pub mod md4;
pub mod rc4_util;
pub mod ticket;
'@ | Set-Content -Path "crates\overthrone-core\src\crypto\mod.rs" -Encoding UTF8

# --- crypto stubs ---
@'
//! RC4 encryption for Kerberos etype 23
'@ | Set-Content -Path "crates\overthrone-core\src\crypto\rc4_util.rs" -Encoding UTF8

@'
//! AES256-CTS-HMAC-SHA1 for Kerberos etype 17/18
'@ | Set-Content -Path "crates\overthrone-core\src\crypto\aes_cts.rs" -Encoding UTF8

@'
//! MD4 hash for NTLM password hashing
'@ | Set-Content -Path "crates\overthrone-core\src\crypto\md4.rs" -Encoding UTF8

@'
//! HMAC utilities for ticket validation
'@ | Set-Content -Path "crates\overthrone-core\src\crypto\hmac_util.rs" -Encoding UTF8

@'
//! Ticket forging: Golden, Silver, Diamond
'@ | Set-Content -Path "crates\overthrone-core\src\crypto\ticket.rs" -Encoding UTF8

# --- core/src/graph/mod.rs ---
@'
pub mod builder;
pub mod edge;
pub mod node;
pub mod pathfinder;
'@ | Set-Content -Path "crates\overthrone-core\src\graph\mod.rs" -Encoding UTF8

@'
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeType {
    User(String),
    Computer(String),
    Group(String),
    Domain(String),
    Gpo(String),
    Ou(String),
    CertTemplate(String),
}
'@ | Set-Content -Path "crates\overthrone-core\src\graph\node.rs" -Encoding UTF8

@'
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    MemberOf,
    AdminTo,
    HasSession,
    CanRDP,
    CanPSRemote,
    ExecuteDCOM,
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    ForceChangePassword,
    AddMember,
    AllExtendedRights,
    Owns,
    Contains,
    GpLink,
    TrustedBy,
    AllowedToDelegate,
    AllowedToAct,
    HasSPN,
    DontReqPreauth,
    EnrollOnBehalfOf,
}
'@ | Set-Content -Path "crates\overthrone-core\src\graph\edge.rs" -Encoding UTF8

@'
//! Graph construction from enumeration data
'@ | Set-Content -Path "crates\overthrone-core\src\graph\builder.rs" -Encoding UTF8

@'
//! Shortest path and all-paths computation using petgraph
'@ | Set-Content -Path "crates\overthrone-core\src\graph\pathfinder.rs" -Encoding UTF8

Write-Host "[+] overthrone-core created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-reaper
# ============================================================

@'
[package]
name = "overthrone-reaper"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Autonomous AD enumeration engine"

[dependencies]
overthrone-core = { path = "../overthrone-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
chrono.workspace = true
indicatif.workspace = true
colored.workspace = true
uuid.workspace = true

[dev-dependencies]
tokio-test.workspace = true
tempfile.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-reaper\Cargo.toml" -Encoding UTF8

@'
pub mod acls;
pub mod adcs;
pub mod computers;
pub mod delegations;
pub mod export;
pub mod gpos;
pub mod groups;
pub mod laps;
pub mod mssql;
pub mod ous;
pub mod runner;
pub mod spns;
pub mod trusts;
pub mod users;
'@ | Set-Content -Path "crates\overthrone-reaper\src\lib.rs" -Encoding UTF8

$reaperFiles = @("runner","users","groups","computers","acls","gpos","ous","delegations","trusts","spns","laps","adcs","mssql","export")
foreach ($f in $reaperFiles) {
    "//! Reaper module: $f" | Set-Content -Path "crates\overthrone-reaper\src\$f.rs" -Encoding UTF8
}

Write-Host "[+] overthrone-reaper created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-hunter
# ============================================================

@'
[package]
name = "overthrone-hunter"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Kerberos delegation discovery and exploitation"

[dependencies]
overthrone-core = { path = "../overthrone-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
chrono.workspace = true
indicatif.workspace = true
colored.workspace = true

[dev-dependencies]
tokio-test.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-hunter\Cargo.toml" -Encoding UTF8

@'
pub mod asreproast;
pub mod coerce;
pub mod constrained;
pub mod kerberoast;
pub mod rbcd;
pub mod runner;
pub mod tickets;
pub mod unconstrained;
'@ | Set-Content -Path "crates\overthrone-hunter\src\lib.rs" -Encoding UTF8

$hunterFiles = @("runner","unconstrained","constrained","rbcd","kerberoast","asreproast","coerce","tickets")
foreach ($f in $hunterFiles) {
    "//! Hunter module: $f" | Set-Content -Path "crates\overthrone-hunter\src\$f.rs" -Encoding UTF8
}

Write-Host "[+] overthrone-hunter created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-pilot
# ============================================================

@'
[package]
name = "overthrone-pilot"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Attack path computation and autonomous exploitation"

[dependencies]
overthrone-core = { path = "../overthrone-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
petgraph.workspace = true
indicatif.workspace = true
colored.workspace = true

[dev-dependencies]
tokio-test.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-pilot\Cargo.toml" -Encoding UTF8

@'
pub mod adaptive;
pub mod executor;
pub mod goals;
pub mod planner;
pub mod playbook;
pub mod runner;
'@ | Set-Content -Path "crates\overthrone-pilot\src\lib.rs" -Encoding UTF8

$pilotFiles = @("runner","planner","executor","goals","playbook","adaptive")
foreach ($f in $pilotFiles) {
    "//! Pilot module: $f" | Set-Content -Path "crates\overthrone-pilot\src\$f.rs" -Encoding UTF8
}

Write-Host "[+] overthrone-pilot created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-crawler
# ============================================================

@'
[package]
name = "overthrone-crawler"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Cross-forest trust mapping and exploitation"

[dependencies]
overthrone-core = { path = "../overthrone-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
chrono.workspace = true
indicatif.workspace = true
colored.workspace = true

[dev-dependencies]
tokio-test.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-crawler\Cargo.toml" -Encoding UTF8

@'
pub mod escalation;
pub mod foreign;
pub mod interrealm;
pub mod mssql_links;
pub mod pam;
pub mod runner;
pub mod sid_filter;
pub mod trust_map;
'@ | Set-Content -Path "crates\overthrone-crawler\src\lib.rs" -Encoding UTF8

$crawlerFiles = @("runner","trust_map","sid_filter","foreign","pam","escalation","interrealm","mssql_links")
foreach ($f in $crawlerFiles) {
    "//! Crawler module: $f" | Set-Content -Path "crates\overthrone-crawler\src\$f.rs" -Encoding UTF8
}

Write-Host "[+] overthrone-crawler created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-forge
# ============================================================

@'
[package]
name = "overthrone-forge"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Persistence planting, validation, and cleanup"

[dependencies]
overthrone-core = { path = "../overthrone-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
chrono.workspace = true
indicatif.workspace = true
colored.workspace = true

[dev-dependencies]
tokio-test.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-forge\Cargo.toml" -Encoding UTF8

@'
pub mod acl_backdoor;
pub mod cleanup;
pub mod dcsync_user;
pub mod diamond;
pub mod dsrm;
pub mod golden;
pub mod runner;
pub mod silver;
pub mod skeleton;
pub mod validate;
'@ | Set-Content -Path "crates\overthrone-forge\src\lib.rs" -Encoding UTF8

$forgeFiles = @("runner","golden","silver","diamond","skeleton","dsrm","acl_backdoor","dcsync_user","validate","cleanup")
foreach ($f in $forgeFiles) {
    "//! Forge module: $f" | Set-Content -Path "crates\overthrone-forge\src\$f.rs" -Encoding UTF8
}

Write-Host "[+] overthrone-forge created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-scribe
# ============================================================

@'
[package]
name = "overthrone-scribe"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Auto report generation with MITRE ATT&CK mapping"

[dependencies]
overthrone-core = { path = "../overthrone-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
chrono.workspace = true
genpdf.workspace = true
pulldown-cmark.workspace = true
indicatif.workspace = true
colored.workspace = true

[dev-dependencies]
tokio-test.workspace = true
tempfile.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-scribe\Cargo.toml" -Encoding UTF8

@'
pub mod mapper;
pub mod markdown;
pub mod mitigations;
pub mod narrative;
pub mod pdf;
pub mod runner;
pub mod session;
'@ | Set-Content -Path "crates\overthrone-scribe\src\lib.rs" -Encoding UTF8

$scribeFiles = @("runner","session","mapper","narrative","mitigations","markdown","pdf")
foreach ($f in $scribeFiles) {
    "//! Scribe module: $f" | Set-Content -Path "crates\overthrone-scribe\src\$f.rs" -Encoding UTF8
}

Write-Host "[+] overthrone-scribe created" -ForegroundColor Green

# ============================================================
#  CRATE: overthrone-cli (main binary)
# ============================================================

@'
[package]
name = "overthrone"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Autonomous Active Directory Red Team Framework"

[[bin]]
name = "overthrone"
path = "src/main.rs"

[dependencies]
overthrone-core = { path = "../overthrone-core" }
overthrone-reaper = { path = "../overthrone-reaper" }
overthrone-hunter = { path = "../overthrone-hunter" }
overthrone-pilot = { path = "../overthrone-pilot" }
overthrone-crawler = { path = "../overthrone-crawler" }
overthrone-forge = { path = "../overthrone-forge" }
overthrone-scribe = { path = "../overthrone-scribe" }
clap.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
colored.workspace = true
anyhow.workspace = true
console.workspace = true
indicatif.workspace = true
toml.workspace = true
directories.workspace = true

[dev-dependencies]
tokio-test.workspace = true
pretty_assertions.workspace = true
'@ | Set-Content -Path "crates\overthrone-cli\Cargo.toml" -Encoding UTF8

# --- cli/src/main.rs ---
@'
mod auth;
mod autopwn;
mod banner;

use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(
    name = "overthrone",
    version,
    about = "Autonomous Active Directory Red Team Framework",
    long_about = "Every throne falls. Overthrone makes sure of it."
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, global = true)]
    target: Option<String>,

    #[arg(short, long, global = true)]
    domain: Option<String>,

    #[arg(short, long, global = true)]
    username: Option<String>,

    #[arg(short, long, global = true)]
    password: Option<String>,

    #[arg(long, global = true)]
    hash: Option<String>,

    #[arg(long, global = true, default_value = "json")]
    output_format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Autonomous AD enumeration
    Reaper {
        #[arg(long)]
        bloodhound: bool,
        #[arg(long)]
        full: bool,
    },
    /// Kerberos delegation exploitation
    Hunter {
        #[arg(long)]
        auto_exploit: bool,
        #[arg(long)]
        all: bool,
    },
    /// Attack path autopilot
    Pilot {
        #[arg(long)]
        goal: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Cross-forest trust engine
    Crawler {
        #[arg(long)]
        map_all: bool,
        #[arg(long)]
        exploit: bool,
    },
    /// Persistence engine
    Forge {
        #[arg(long)]
        plant: Option<String>,
        #[arg(long)]
        validate: bool,
        #[arg(long)]
        cleanup: bool,
    },
    /// Auto report generator
    Scribe {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = "markdown")]
        format: String,
    },
    /// Full autonomous kill chain
    Autopwn {
        #[arg(long)]
        goal: String,
        #[arg(long)]
        stealth: bool,
        #[arg(long)]
        report: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(if cli.verbose { "debug" } else { "info" })
        .init();

    banner::print_banner();

    match cli.command {
        Commands::Reaper { bloodhound, full } => {
            tracing::info!("Starting Reaper enumeration...");
            todo!("Reaper module")
        }
        Commands::Hunter { auto_exploit, all } => {
            todo!("Hunter module")
        }
        Commands::Pilot { goal, output } => {
            todo!("Pilot module")
        }
        Commands::Crawler { map_all, exploit } => {
            todo!("Crawler module")
        }
        Commands::Forge { plant, validate, cleanup } => {
            todo!("Forge module")
        }
        Commands::Scribe { session, format } => {
            todo!("Scribe module")
        }
        Commands::Autopwn { goal, stealth, report } => {
            todo!("Autopwn module")
        }
    }
}
'@ | Set-Content -Path "crates\overthrone-cli\src\main.rs" -Encoding UTF8

# --- cli/src/banner.rs ---
@'
use colored::Colorize;

pub fn print_banner() {
    let banner = r#"
   ___                 _   _
  / _ \__   _____ _ __| |_| |__  _ __ ___  _ __   ___
 | | | \ \ / / _ \ '__| __| '_ \| '__/ _ \| '_ \ / _ \
 | |_| |\ V /  __/ |  | |_| | | | | | (_) | | | |  __/
  \___/  \_/ \___|_|   \__|_| |_|_|  \___/|_| |_|\___|
    "#;
    println!("{}", banner.red().bold());
    println!("  {} {}", "Version:".dimmed(), env!("CARGO_PKG_VERSION").yellow());
    println!("  {} {}", "Author:".dimmed(), "Karmanya03".cyan());
    println!("  {} {}\n", "Motto:".dimmed(), "Every throne falls.".red());
}
'@ | Set-Content -Path "crates\overthrone-cli\src\banner.rs" -Encoding UTF8

# --- cli/src/auth.rs ---
@'
//! Authentication handler: password, NTLM hash, Kerberos ticket, certificate

use overthrone_core::config::AuthConfig;

pub fn resolve_auth(
    username: Option<&str>,
    password: Option<&str>,
    hash: Option<&str>,
) -> AuthConfig {
    if let Some(h) = hash {
        AuthConfig::NtlmHash {
            username: username.unwrap_or("").to_string(),
            hash: h.to_string(),
        }
    } else {
        AuthConfig::Password {
            username: username.unwrap_or("").to_string(),
            password: password.unwrap_or("").to_string(),
        }
    }
}
'@ | Set-Content -Path "crates\overthrone-cli\src\auth.rs" -Encoding UTF8

# --- cli/src/autopwn.rs ---
@'
//! Full kill chain orchestrator: reaper -> pilot -> hunter -> crawler -> forge -> scribe
'@ | Set-Content -Path "crates\overthrone-cli\src\autopwn.rs" -Encoding UTF8

Write-Host "[+] overthrone-cli created" -ForegroundColor Green

# ============================================================
#  ASSETS, CONFIGS, DOCS, TESTS
# ============================================================

@'
{
  "techniques": {
    "T1558.003": "Kerberoasting",
    "T1558.004": "AS-REP Roasting",
    "T1003.006": "DCSync",
    "T1134.001": "Token Impersonation",
    "T1550.003": "Pass the Ticket",
    "T1558.001": "Golden Ticket",
    "T1558.002": "Silver Ticket",
    "T1484.001": "Group Policy Modification",
    "T1207": "Rogue Domain Controller",
    "T1003.001": "LSASS Memory"
  }
}
'@ | Set-Content -Path "assets\mitre_attack.json" -Encoding UTF8

@'
[general]
threads = 10
timeout_secs = 30
output_format = "json"
verbose = false

[stealth]
jitter_ms = 500
randomize_order = true
avoid_honeypots = true
'@ | Set-Content -Path "configs\default.toml" -Encoding UTF8

"# Architecture Overview" | Set-Content -Path "docs\ARCHITECTURE.md" -Encoding UTF8
"# Contributing to Overthrone" | Set-Content -Path "docs\CONTRIBUTING.md" -Encoding UTF8
"# Usage Guide" | Set-Content -Path "docs\USAGE.md" -Encoding UTF8

$modules = @("reaper","hunter","pilot","crawler","forge","scribe")
foreach ($m in $modules) {
    "# $m Module" | Set-Content -Path "docs\modules\$m.md" -Encoding UTF8
}

# Test stubs
$testModules = @("reaper","hunter","pilot","crawler","forge","scribe")
foreach ($t in $testModules) {
    "//! Integration tests for $t" | Set-Content -Path "tests\integration\${t}_test.rs" -Encoding UTF8
}

'{}' | Set-Content -Path "tests\fixtures\mock_ldap_response.json" -Encoding UTF8
'{}' | Set-Content -Path "tests\fixtures\mock_domain.json" -Encoding UTF8
'{}' | Set-Content -Path "tests\fixtures\mock_trusts.json" -Encoding UTF8

# ASCII banner
@'
   ___                 _   _
  / _ \__   _____ _ __| |_| |__  _ __ ___  _ __   ___
 | | | \ \ / / _ \ '__| __| '_ \| '__/ _ \| '_ \ / _ \
 | |_| |\ V /  __/ |  | |_| | | | | | (_) | | | |  __/
  \___/  \_/ \___|_|   \__|_| |_|_|  \___/|_| |_|\___|

  Every throne falls.
'@ | Set-Content -Path "assets\banner.txt" -Encoding UTF8

Write-Host "[+] Assets, configs, docs, tests created" -ForegroundColor Green

# ============================================================
Write-Host "`n[*] DONE! Run 'cargo check' now." -ForegroundColor Cyan
Write-Host ""
