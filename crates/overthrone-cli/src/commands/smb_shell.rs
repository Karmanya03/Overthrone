//! An `smbclient`-compatible interactive SMB shell.
//!
//! Design goal: a user who knows `smbclient //host/share -U user%pass` should be
//! able to type `ovt smb shell -t host -s share` and get the same experience --
//! the shell opens *directly on the share*, the prompt is the current remote
//! directory, and the command set mirrors `smbclient`'s file-management
//! commands (`ls`, `cd`, `lcd`, `get`, `mget`, `put`, `mput`, `recurse`,
//! `prompt`, `mask`, `del`, `mkdir`, `rmdir`, `rename`, `du`, `stat`,
//! `allinfo`, `more`, `!` for a local shell, ...).
//!
//! Everything is implemented on top of the pure-Rust SMB2 client
//! (`overthrone_core::proto::smb::SmbSession`), so no external `smbclient`
//! binary is required.
//!
//! Two entry points:
//!
//! * [`SmbShell::run`] -- interactive REPL reading from stdin.
//! * [`SmbShell::run_script`] -- one-shot `-c "ls; get a.txt; exit"` mode,
//!   matching `smbclient -c`.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::{RemoteFileInfo, SmbSession};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Default download mask -- `smbclient` starts with `*`.
const DEFAULT_MASK: &str = "*";

/// Shares that are never a sensible default target for an interactive shell.
const NON_DATA_SHARES: &[&str] = &["IPC$"];

// ==========================================================
//  Shell
// ==========================================================

/// A stateful `smbclient`-style session.
pub struct SmbShell {
    session: SmbSession,
    target: String,
    share: String,
    /// Current remote directory inside `share`, using `\` separators.
    /// Empty string means the share root.
    cwd: String,
    /// Current local working directory (`lcd`).
    local_cwd: PathBuf,
    /// `recurse` toggle -- makes `mget`/`mput`/`del`/`du` descend.
    recurse: bool,
    /// `prompt` toggle -- ask before each transfer in a wildcard operation.
    prompt: bool,
    /// `mask` -- the pattern used when a command is given no argument.
    mask: String,
    /// Suppress informational output (set for `-c` one-shot runs).
    quiet: bool,
    /// Exit flag set by `quit`/`exit`.
    done: bool,
}

impl SmbShell {
    /// Wrap an authenticated session in an interactive shell.
    pub fn new(session: SmbSession, target: &str, share: &str, cwd: &str) -> Self {
        Self {
            session,
            target: target.to_string(),
            share: share.to_string(),
            cwd: cwd.trim_matches('\\').to_string(),
            local_cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            recurse: false,
            prompt: true,
            mask: DEFAULT_MASK.to_string(),
            quiet: false,
            done: false,
        }
    }

    /// Set the quiet flag (used by one-shot `-c` runs).
    pub fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }

    /// Pick a share when the caller did not supply one.
    ///
    /// Preference order: the first readable non-`IPC$` share, then the first
    /// readable share of any kind, then `C$`. The chosen share is printed so
    /// the operator knows where the shell landed.
    pub async fn choose_share(session: &SmbSession, requested: Option<&str>) -> String {
        if let Some(s) = requested {
            return s.to_string();
        }
        if let Ok(shares) = session.list_shares().await
            && let Some(s) = shares
                .iter()
                .find(|s| !NON_DATA_SHARES.contains(&s.as_str()))
                .or_else(|| shares.first())
        {
            return s.clone();
        }
        "C$".to_string()
    }

    /// The UNC path the shell is currently sitting in, for display.
    fn unc(&self) -> String {
        if self.cwd.is_empty() {
            format!(r"\\{}\{}", self.target, self.share)
        } else {
            format!(r"\\{}\{}{}", self.target, self.share, self.remote_path(""))
        }
    }

    /// Join `name` onto the current remote directory, honouring absolute paths
    /// (`\foo`, `/foo`, `share\sub`, `..` and `.`).
    fn remote_path(&self, name: &str) -> String {
        let cleaned = normalize_remote(&self.cwd, name);
        if cleaned.is_empty() {
            String::new()
        } else {
            format!("\\{cleaned}")
        }
    }

    /// Remote directory + leaf name for a single-file operation.
    fn split_leaf(&self, spec: &str) -> (String, String) {
        let cleaned = normalize_remote(&self.cwd, spec);
        match cleaned.rsplit_once('\\') {
            Some((dir, leaf)) => (dir.to_string(), leaf.to_string()),
            None => (String::new(), cleaned),
        }
    }

    // ------------------------------------------------------
    //  Entry points
    // ------------------------------------------------------

    /// One-shot mode: run a `;`-separated command list and return.
    pub async fn run_script(&mut self, script: &str) -> Result<()> {
        for raw in script.split(';') {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            self.dispatch(line).await?;
            if self.done {
                break;
            }
        }
        Ok(())
    }

    /// Interactive REPL. Blocks on stdin until `quit`/`exit`/EOF.
    pub async fn run(&mut self) -> Result<()> {
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();

        loop {
            print!("{}", self.prompt_string());
            use std::io::Write;
            let _ = std::io::stdout().flush();

            let line = match lines.next_line().await {
                Ok(Some(l)) => l,
                Ok(None) => break,
                Err(e) => {
                    println!("{} stdin: {e}", "[-]".red_or_plain());
                    break;
                }
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Err(e) = self.dispatch(line).await {
                println!("{} {e}", "[-]".red_or_plain());
            }
            if self.done {
                break;
            }
        }
        Ok(())
    }

    fn prompt_string(&self) -> String {
        let dir = if self.cwd.is_empty() {
            "\\".to_string()
        } else {
            format!("\\{}\\", self.cwd)
        };
        format!("smb: {dir}> ")
    }

    // ------------------------------------------------------
    //  Command dispatch
    // ------------------------------------------------------

    /// Execute one shell line. Handles a leading `!` (local shell escape) and
    /// quotes exactly the way `smbclient` does.
    pub async fn dispatch(&mut self, line: &str) -> Result<()> {
        let line = line.trim();
        if let Some(local) = line.strip_prefix('!') {
            return self.local_shell(local.trim());
        }

        let mut parts = tokenize(line);
        if parts.is_empty() {
            return Ok(());
        }
        let cmd = parts.remove(0).to_lowercase();
        let args = parts;

        match cmd.as_str() {
            "?" | "help" => self.cmd_help(args.first().map(String::as_str))?,
            "exit" | "quit" | "q" => {
                self.done = true;
                if !self.quiet {
                    println!("{} closing session", "[+]".green_or_plain());
                }
            }

            // ---- directory navigation ----
            "ls" | "dir" | "list" => self.cmd_ls(args.first().map(String::as_str)).await?,
            "cd" | "chdir" => self.cmd_cd(args.first().map(String::as_str)).await?,
            "pwd" => println!("{}", self.unc()),
            "lcd" => self.cmd_lcd(args.first().map(String::as_str))?,
            "lpwd" => println!("{}", self.local_cwd.display()),
            "shares" | "lsshares" => self.cmd_shares().await?,
            "use" => self.cmd_use(args.first().map(String::as_str)).await?,
            "showconnect" => self.cmd_showconnect().await?,

            // ---- file transfer ----
            "get" => {
                let remote = args.first().cloned().unwrap_or_else(|| self.mask.clone());
                let local = args.get(1).cloned();
                self.cmd_get(&remote, local.as_deref()).await?
            }
            "put" => {
                let local = match args.first() {
                    Some(l) => l.clone(),
                    None => {
                        println!("{} Usage: put <local> [remote]", "Error:".red_or_plain());
                        return Ok(());
                    }
                };
                self.cmd_put(&local, args.get(1).map(String::as_str))
                    .await?
            }
            "mget" => {
                let mask = args.first().cloned().unwrap_or_else(|| self.mask.clone());
                self.cmd_mget(&mask).await?
            }
            "mput" => {
                let mask = args.first().cloned().unwrap_or_else(|| self.mask.clone());
                self.cmd_mput(&mask).await?
            }

            // ---- local command helpers ----
            "more" => self.cmd_more(args.first().map(String::as_str)).await?,
            "cat" => self.cmd_more(args.first().map(String::as_str)).await?,
            "du" => self.cmd_du(args.first().map(String::as_str)).await?,
            "stat" | "allinfo" => self.cmd_stat(args.first().map(String::as_str)).await?,

            // ---- mutation ----
            "del" | "rm" => {
                let mask = args.first().cloned().unwrap_or_else(|| self.mask.clone());
                self.cmd_del(&mask).await?
            }
            "mkdir" | "md" => self.cmd_mkdir(args.first().map(String::as_str)).await?,
            "rmdir" | "rd" => self.cmd_rmdir(args.first().map(String::as_str)).await?,
            "rename" | "mv" => {
                if args.len() < 2 {
                    println!("{} Usage: rename <old> <new>", "Error:".red_or_plain());
                } else {
                    self.cmd_rename(&args[0], &args[1]).await?;
                }
            }

            // ---- session options ----
            "recurse" => {
                self.recurse = !self.recurse;
                println!("recurse is {}", on_off(self.recurse));
            }
            "prompt" => {
                self.prompt = !self.prompt;
                println!("prompting is {}", on_off(self.prompt));
            }
            "mask" => match args.first() {
                Some(m) => {
                    self.mask = m.clone();
                    println!("mask is {}", self.mask);
                }
                None => println!("mask is {}", self.mask),
            },
            "tarmode" => println!(
                "{} tarmode is accepted for compatibility; Overthrone does not \
                 implement smbclient's tar/archive streaming",
                "[!]".yellow_or_plain()
            ),
            "setmode" => println!(
                "{} setmode is accepted for compatibility; Overthrone does not \
                 change the remote client-side mode mapping",
                "[!]".yellow_or_plain()
            ),
            "logon" => {
                println!(
                    "{} Re-authentication is handled by the parent command; rerun \
                     `ovt smb shell` with different credentials to change identity",
                    "[!]".yellow_or_plain()
                );
            }
            "reconnect" | "reset" => self.cmd_reconnect().await?,

            other => {
                println!("{} Unknown command: {other}", "Error:".red_or_plain());
                println!("Type 'help' for the command list.");
            }
        }
        Ok(())
    }

    /// Run a command in the operator's local shell (`!` prefix or `local`).
    fn local_shell(&mut self, command: &str) -> Result<()> {
        // `lcd` and `lpwd` need to mutate/read our local state, so intercept them.
        if command.is_empty() {
            println!("local cwd: {}", self.local_cwd.display());
            return Ok(());
        }
        if let Some(dir) = command.strip_prefix("cd ") {
            return self.cmd_lcd(Some(dir.trim()));
        }
        let status = if cfg!(windows) {
            std::process::Command::new("cmd")
                .arg("/C")
                .arg(command)
                .current_dir(&self.local_cwd)
                .status()
        } else {
            std::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .current_dir(&self.local_cwd)
                .status()
        };
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => {
                println!("{} local command exited with {s}", "[-]".red_or_plain());
                Ok(())
            }
            Err(e) => Err(OverthroneError::Smb(format!("local command failed: {e}"))),
        }
    }

    // ------------------------------------------------------
    //  Directory commands
    // ------------------------------------------------------

    async fn cmd_ls(&mut self, arg: Option<&str>) -> Result<()> {
        let spec = arg.unwrap_or("");
        let (dir, pattern) = if spec.is_empty() {
            (self.cwd.clone(), None)
        } else if spec.contains('*') || spec.contains('?') {
            let (d, leaf) = self.split_leaf(spec);
            (d, Some(leaf))
        } else {
            (normalize_remote(&self.cwd, spec), None)
        };

        let entries = match self.session.list_directory(&self.share, &dir).await {
            Ok(e) => e,
            Err(e) => {
                // `ls` on a file name is common; report it as a "not a directory".
                println!("{} {e}", "[-]".red_or_plain());
                return Ok(());
            }
        };

        let filtered: Vec<RemoteFileInfo> = match &pattern {
            Some(p) => entries
                .into_iter()
                .filter(|e| wildcard_match(p, &e.name))
                .collect(),
            None => entries,
        };
        self.print_entries(&dir, &filtered);
        Ok(())
    }

    fn print_entries(&self, dir: &str, entries: &[RemoteFileInfo]) {
        let header = if dir.is_empty() {
            format!(r"  \\{}\{}", self.target, self.share)
        } else {
            format!(r"  \\{}\{}\{}", self.target, self.share, dir)
        };
        println!("{header}");
        let mut total: u64 = 0;
        for e in entries {
            if !e.is_directory {
                total += e.size;
            }
            let attrs = e.attribute_string();
            let when = e
                .modified
                .clone()
                .or_else(|| e.created.clone())
                .unwrap_or_else(|| "?".to_string());
            println!("  {:<40} {:<5} {:>12}  {}", e.name, attrs, e.size, when);
        }
        let (n, d) = (
            entries.iter().filter(|e| !e.is_directory).count(),
            entries.iter().filter(|e| e.is_directory).count(),
        );
        println!("    {n} file(s), {d} directory(ies), {total} bytes total\n");
    }

    async fn cmd_cd(&mut self, arg: Option<&str>) -> Result<()> {
        let target = match arg {
            None | Some("") => String::new(),
            Some(a) => normalize_remote(&self.cwd, a),
        };
        // Verify the directory exists before moving.
        match self.session.list_directory(&self.share, &target).await {
            Ok(_) => {
                self.cwd = target;
                Ok(())
            }
            Err(e) => {
                println!(
                    "{} cd {}: {e}",
                    "[-]".red_or_plain(),
                    if target.is_empty() { "\\" } else { &target }
                );
                Ok(())
            }
        }
    }

    fn cmd_lcd(&mut self, arg: Option<&str>) -> Result<()> {
        let joined = match arg {
            None | Some("") => home_dir(),
            Some(a) => {
                let p = Path::new(a);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    self.local_cwd.join(p)
                }
            }
        };
        match std::fs::canonicalize(&joined) {
            Ok(p) if p.is_dir() => {
                self.local_cwd = p;
                println!("{}", self.local_cwd.display());
                Ok(())
            }
            Ok(_) => {
                println!(
                    "{} not a directory: {}",
                    "[-]".red_or_plain(),
                    joined.display()
                );
                Ok(())
            }
            Err(e) => {
                println!("{} lcd {}: {e}", "[-]".red_or_plain(), joined.display());
                Ok(())
            }
        }
    }

    async fn cmd_shares(&mut self) -> Result<()> {
        match self.session.list_shares().await {
            Ok(shares) => {
                println!("\n  {} share(s) on \\\\{}:", shares.len(), self.target);
                for s in &shares {
                    let marker = if s.eq_ignore_ascii_case(&self.share) {
                        "*"
                    } else {
                        " "
                    };
                    let readable = if self.session.check_share_read(s).await {
                        "R"
                    } else {
                        "-"
                    };
                    println!("   {marker} {s}  [{readable}]");
                }
                println!();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn cmd_use(&mut self, share: Option<&str>) -> Result<()> {
        let Some(share) = share.filter(|s| !s.is_empty()) else {
            println!("{} Usage: use <share>", "Error:".red_or_plain());
            return Ok(());
        };
        match self.session.list_directory(share, "").await {
            Ok(_) => {
                self.share = share.to_string();
                self.cwd.clear();
                println!("Now using share {}", share);
                Ok(())
            }
            Err(e) => {
                println!("{} use {share}: {e}", "[-]".red_or_plain());
                Ok(())
            }
        }
    }

    async fn cmd_showconnect(&mut self) -> Result<()> {
        let diag = self.session.signing_diagnostics().await;
        println!("  target          : {}", self.target);
        println!("  share           : {}", self.share);
        println!(
            "  remote dir      : {}",
            if self.cwd.is_empty() { "\\" } else { &self.cwd }
        );
        println!("  local dir       : {}", self.local_cwd.display());
        println!("  recurse/prompt  : {}", on_off(self.recurse));
        println!("  default mask    : {}", self.mask);
        if let Some(d) = diag {
            println!("  dialect         : 0x{:04X}", d.dialect);
            println!("  signing required: {}", d.signing_required);
            println!("  cipher          : {}", d.cipher);
            println!(
                "  signing variant : {}",
                d.detected_variant.unwrap_or(d.expected_variant).name()
            );
        }
        Ok(())
    }

    async fn cmd_reconnect(&mut self) -> Result<()> {
        self.session.reconnect_inner().await?;
        println!("{} session re-established", "[+]".green_or_plain());
        Ok(())
    }

    // ------------------------------------------------------
    //  Transfer commands
    // ------------------------------------------------------

    async fn cmd_get(&mut self, remote: &str, local: Option<&str>) -> Result<()> {
        let (dir, leaf) = self.split_leaf(remote);
        if leaf.contains('*') || leaf.contains('?') {
            return self.cmd_mget_in(&dir, &leaf).await;
        }
        let remote_full = join_remote(&dir, &leaf);
        let local_path = match local {
            Some(l) => {
                let p = Path::new(l);
                if p.is_dir() {
                    p.join(&leaf)
                } else {
                    p.to_path_buf()
                }
            }
            None => self.local_cwd.join(&leaf),
        };
        let data = self.session.read_file(&self.share, &remote_full).await?;
        if let Some(parent) = local_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                OverthroneError::Smb(format!("create local dir {}: {e}", parent.display()))
            })?;
        }
        std::fs::write(&local_path, &data)
            .map_err(|e| OverthroneError::Smb(format!("write {}: {e}", local_path.display())))?;
        println!(
            "{} getting {} ({}) -> {}",
            "[+]".green_or_plain(),
            remote_full,
            human_size(data.len() as u64),
            local_path.display()
        );
        Ok(())
    }

    async fn cmd_put(&mut self, local: &str, remote: Option<&str>) -> Result<()> {
        let local_path = {
            let p = Path::new(local);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                self.local_cwd.join(p)
            }
        };
        if !local_path.is_file() {
            println!(
                "{} not a file: {}",
                "[-]".red_or_plain(),
                local_path.display()
            );
            return Ok(());
        }
        let leaf = local_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "upload.bin".to_string());
        let remote_full = match remote {
            Some(r) if r.ends_with('\\') || r.ends_with('/') => {
                let (d, _) = self.split_leaf(r);
                join_remote(&d, &leaf)
            }
            Some(r) => normalize_remote(&self.cwd, r),
            None => join_remote(&self.cwd, &leaf),
        };
        let data = std::fs::read(&local_path)
            .map_err(|e| OverthroneError::Smb(format!("read {}: {e}", local_path.display())))?;
        self.session
            .write_file(&self.share, &remote_full, &data)
            .await?;
        println!(
            "{} putting {} ({}) -> {}",
            "[+]".green_or_plain(),
            local_path.display(),
            human_size(data.len() as u64),
            remote_full
        );
        Ok(())
    }

    /// `mget <mask>` -- download every matching file in the current directory,
    /// descending recursively when `recurse` is on.
    async fn cmd_mget(&mut self, mask: &str) -> Result<()> {
        let (dir, leaf) = self.split_leaf(mask);
        self.cmd_mget_in(&dir, &leaf).await
    }

    /// Download every file matching `mask` beneath `dir`.
    async fn cmd_mget_in(&mut self, dir: &str, mask: &str) -> Result<()> {
        let mut queue: VecDeque<(String, PathBuf)> =
            VecDeque::from([(dir.to_string(), self.local_cwd.clone())]);
        let mut downloaded = 0usize;

        while let Some((remote_dir, local_dir)) = queue.pop_front() {
            let entries = match self.session.list_directory(&self.share, &remote_dir).await {
                Ok(e) => e,
                Err(e) => {
                    println!("{} {}: {e}", "[-]".red_or_plain(), remote_dir);
                    continue;
                }
            };
            for entry in entries {
                let remote_full = join_remote(&remote_dir, &entry.name);
                if entry.is_directory {
                    if self.recurse {
                        queue.push_back((remote_full, local_dir.join(&entry.name)));
                    }
                    continue;
                }
                if !wildcard_match(mask, &entry.name) {
                    continue;
                }
                let local_path = local_dir.join(&entry.name);
                if !self.confirm_transfer("get", &entry.name, entry.size)? {
                    continue;
                }
                match self.session.read_file(&self.share, &remote_full).await {
                    Ok(data) => {
                        if let Err(e) = std::fs::create_dir_all(&local_dir) {
                            println!(
                                "{} mkdir {}: {e}",
                                "[-]".red_or_plain(),
                                local_dir.display()
                            );
                            continue;
                        }
                        match std::fs::write(&local_path, &data) {
                            Ok(_) => {
                                downloaded += 1;
                                println!(
                                    "{} {} ({})",
                                    "[+]".green_or_plain(),
                                    remote_full,
                                    human_size(data.len() as u64)
                                );
                            }
                            Err(e) => println!(
                                "{} write {}: {e}",
                                "[-]".red_or_plain(),
                                local_path.display()
                            ),
                        }
                    }
                    Err(e) => println!("{} {remote_full}: {e}", "[-]".red_or_plain()),
                }
            }
        }
        println!("{downloaded} file(s) retrieved");
        Ok(())
    }

    /// `mput <mask>` -- upload every matching file from the local directory,
    /// descending recursively when `recurse` is on.
    async fn cmd_mput(&mut self, mask: &str) -> Result<()> {
        let mut files = Vec::new();
        collect_local_files(&self.local_cwd, self.recurse, &mut files)
            .map_err(|e| OverthroneError::Smb(format!("walk {}: {e}", self.local_cwd.display())))?;

        let mut uploaded = 0usize;
        for path in files {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !wildcard_match(mask, &name) {
                continue;
            }
            let rel = path
                .strip_prefix(&self.local_cwd)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('/', "\\");
            let remote_full = join_remote(&self.cwd, &rel);
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if !self.confirm_transfer("put", &name, size)? {
                continue;
            }
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    println!("{} read {}: {e}", "[-]".red_or_plain(), path.display());
                    continue;
                }
            };
            // Create intermediate directories when uploading a tree.
            if let Some((dir, _)) = remote_full.rsplit_once('\\')
                && !dir.is_empty()
                && dir != self.cwd
            {
                let _ = self.session.create_dir(&self.share, dir).await;
            }
            match self
                .session
                .write_file(&self.share, &remote_full, &data)
                .await
            {
                Ok(_) => {
                    uploaded += 1;
                    println!(
                        "{} {} ({})",
                        "[+]".green_or_plain(),
                        remote_full,
                        human_size(data.len() as u64)
                    );
                }
                Err(e) => println!("{} {remote_full}: {e}", "[-]".red_or_plain()),
            }
        }
        println!("{uploaded} file(s) sent");
        Ok(())
    }

    /// Ask before a wildcard transfer when `prompt` is enabled.
    fn confirm_transfer(&self, verb: &str, name: &str, size: u64) -> Result<bool> {
        if !self.prompt {
            return Ok(true);
        }
        print!("{} {} ({})? [y/N] ", verb, name, human_size(size));
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() {
            return Ok(false);
        }
        Ok(matches!(
            answer.trim().chars().next(),
            Some('y') | Some('Y')
        ))
    }

    // ------------------------------------------------------
    //  Read / inspect / mutate
    // ------------------------------------------------------

    async fn cmd_more(&mut self, arg: Option<&str>) -> Result<()> {
        let Some(spec) = arg else {
            println!("{} Usage: more <file>", "Error:".red_or_plain());
            return Ok(());
        };
        let (dir, leaf) = self.split_leaf(spec);
        let remote_full = join_remote(&dir, &leaf);
        let data = self.session.read_file(&self.share, &remote_full).await?;
        let shown = if data.len() > 65_536 {
            println!(
                "{} showing first 64 KiB of {}",
                "[!]".yellow_or_plain(),
                human_size(data.len() as u64)
            );
            &data[..65_536]
        } else {
            &data[..]
        };
        match std::str::from_utf8(shown) {
            Ok(text) => print!("{text}"),
            Err(_) => {
                for chunk in shown.chunks(16) {
                    let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    let ascii: String = chunk
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7f).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    println!("  {:<47}  {}", hex.join(" "), ascii);
                }
            }
        }
        if !shown.ends_with(b"\n") {
            println!();
        }
        Ok(())
    }

    async fn cmd_du(&mut self, arg: Option<&str>) -> Result<()> {
        let start = normalize_remote(&self.cwd, arg.unwrap_or(""));
        let mut stack = vec![start.clone()];
        let mut files = 0u64;
        let mut dirs = 0u64;
        let mut bytes = 0u64;

        while let Some(dir) = stack.pop() {
            let entries = match self.session.list_directory(&self.share, &dir).await {
                Ok(e) => e,
                Err(e) => {
                    println!("{} {}: {e}", "[-]".red_or_plain(), dir);
                    continue;
                }
            };
            for entry in entries {
                if entry.is_directory {
                    dirs += 1;
                    if self.recurse {
                        stack.push(join_remote(&dir, &entry.name));
                    }
                } else {
                    files += 1;
                    bytes += entry.size;
                }
            }
        }
        let where_ = if start.is_empty() {
            "share root".to_string()
        } else {
            start
        };
        println!(
            "{}: {files} file(s) in {dirs} director(ies), {} total{}",
            where_,
            human_size(bytes),
            if self.recurse {
                ""
            } else {
                " (recurse off -- top level only)"
            }
        );
        Ok(())
    }

    async fn cmd_stat(&mut self, arg: Option<&str>) -> Result<()> {
        let Some(spec) = arg else {
            println!("{} Usage: stat <file> [file...]", "Error:".red_or_plain());
            return Ok(());
        };
        let (dir, leaf) = self.split_leaf(spec);
        let entries = self.session.list_directory(&self.share, &dir).await?;
        let mut found = false;
        for entry in entries.iter().filter(|e| wildcard_match(&leaf, &e.name)) {
            found = true;
            println!("  name        : {}", entry.name);
            println!("  path        : {}", self.unc_of(&dir, &entry.name));
            println!(
                "  type        : {}",
                if entry.is_directory {
                    "directory"
                } else {
                    "file"
                }
            );
            println!("  size        : {} bytes", entry.size);
            println!("  attributes  : {}", entry.attribute_string());
            println!(
                "  created     : {}",
                entry.created.clone().unwrap_or_else(|| "?".into())
            );
            println!(
                "  modified    : {}",
                entry.modified.clone().unwrap_or_else(|| "?".into())
            );
            println!("  share       : {}", self.share);
            println!();
        }
        if !found {
            println!(
                "{} no entry matching '{}' in {}",
                "[-]".red_or_plain(),
                leaf,
                if dir.is_empty() { "\\" } else { &dir }
            );
        }
        Ok(())
    }

    fn unc_of(&self, dir: &str, name: &str) -> String {
        if dir.is_empty() {
            format!(r"\\{}\{}\{}", self.target, self.share, name)
        } else {
            format!(r"\\{}\{}\{}\{}", self.target, self.share, dir, name)
        }
    }

    async fn cmd_del(&mut self, mask: &str) -> Result<()> {
        let (dir, leaf) = self.split_leaf(mask);
        let entries = self.session.list_directory(&self.share, &dir).await?;
        let matches: Vec<RemoteFileInfo> = entries
            .into_iter()
            .filter(|e| !e.is_directory && wildcard_match(&leaf, &e.name))
            .collect();
        if matches.is_empty() {
            println!(
                "{} nothing matching '{}' in {}",
                "[-]".red_or_plain(),
                leaf,
                if dir.is_empty() { "\\" } else { &dir }
            );
            return Ok(());
        }
        let mut deleted = 0usize;
        for entry in matches {
            if self.prompt && !confirm_default_yes(&format!("delete {}?", entry.name))? {
                continue;
            }
            let remote_full = join_remote(&dir, &entry.name);
            match self.session.delete_file(&self.share, &remote_full).await {
                Ok(_) => {
                    deleted += 1;
                    println!("{} deleted {}", "[+]".green_or_plain(), remote_full);
                }
                Err(e) => println!("{} {remote_full}: {e}", "[-]".red_or_plain()),
            }
        }
        println!("{deleted} file(s) deleted");
        Ok(())
    }

    async fn cmd_mkdir(&mut self, arg: Option<&str>) -> Result<()> {
        let Some(spec) = arg else {
            println!("{} Usage: mkdir <dir>", "Error:".red_or_plain());
            return Ok(());
        };
        let path = normalize_remote(&self.cwd, spec);
        self.session.create_dir(&self.share, &path).await?;
        println!("{} created {}", "[+]".green_or_plain(), path);
        Ok(())
    }

    async fn cmd_rmdir(&mut self, arg: Option<&str>) -> Result<()> {
        let Some(spec) = arg else {
            println!("{} Usage: rmdir <dir>", "Error:".red_or_plain());
            return Ok(());
        };
        let path = normalize_remote(&self.cwd, spec);
        // SMB2 has no rmdir primitive here; open-as-directory with
        // FILE_DELETE_ON_CLOSE is what `smbclient rmdir` issues under the hood.
        match self.session.delete_dir(&self.share, &path).await {
            Ok(_) => println!("{} removed {}", "[+]".green_or_plain(), path),
            Err(e) => println!("{} rmdir {path}: {e}", "[-]".red_or_plain()),
        }
        Ok(())
    }

    async fn cmd_rename(&mut self, old: &str, new: &str) -> Result<()> {
        let (old_dir, old_leaf) = self.split_leaf(old);
        let (new_dir, new_leaf) = self.split_leaf(new);
        let old_full = join_remote(&old_dir, &old_leaf);
        let new_full = join_remote(&new_dir, &new_leaf);
        self.session
            .rename(&self.share, &old_full, &new_full)
            .await?;
        println!(
            "{} renamed {} -> {}",
            "[+]".green_or_plain(),
            old_full,
            new_full
        );
        Ok(())
    }

    // ------------------------------------------------------
    //  Help
    // ------------------------------------------------------

    fn cmd_help(&self, topic: Option<&str>) -> Result<()> {
        if let Some(t) = topic {
            match t {
                "get" => println!(
                    "get <remote> [local]\n  Retrieve one file. With no local name the file is\n  \
                     written to the local directory (lcd). Shell wildcards in the remote\n  \
                     name are routed to mget."
                ),
                "put" => println!(
                    "put <local> [remote]\n  Send one file. A remote name ending in '\\' or '/'\n  \
                     means 'into this directory'."
                ),
                "mget" => println!(
                    "mget <mask>\n  Retrieve every matching file in the current remote directory.\n  \
                     Honours 'recurse' (descend) and 'prompt' (confirm each file)."
                ),
                "mput" => println!(
                    "mput <mask>\n  Send every matching file from the local directory.\n  \
                     Honours 'recurse' and 'prompt'."
                ),
                "ls" => println!(
                    "ls [mask|dir]\n  Long listing with DOS attributes, size and mtime.\n  \
                     With a wildcard the pattern is matched in the current directory."
                ),
                "cd" => println!(
                    "cd [dir]\n  Change remote directory. No argument goes to the share root.\n  \
                     '.' and '..' are supported."
                ),
                "lcd" => println!("lcd [dir]\n  Change the local directory used by get/put."),
                "du" => {
                    println!("du [dir]\n  Disk usage summary. Set 'recurse' for a full tree walk.")
                }
                "stat" => println!("stat <file>\nallinfo <file>\n  Attributes and timestamps."),
                "recurse" => println!("recurse\n  Toggle recursive operation for mget/mput/du."),
                "prompt" => {
                    println!("prompt\n  Toggle per-file confirmation in wildcard operations.")
                }
                "use" => println!("use <share>\n  Switch to another share without reconnecting."),
                "!" => {
                    println!("!<command>\n  Run a command in the local shell. Bare '!' prints lcd.")
                }
                _ => {
                    println!("No detailed help for '{t}'.");
                    self.print_help();
                }
            }
            return Ok(());
        }
        self.print_help();
        Ok(())
    }

    fn print_help(&self) {
        println!(
            "\n  SMB shell -- smbclient-compatible command set\n  \
             -------------------------------------------------------------\n  \
             Navigation : ls, dir, cd, pwd, lcd, lpwd, shares, use <share>, showconnect\n  \
             Transfer   : get, mget, put, mput, more, cat, du, stat, allinfo\n  \
             Modify     : del, rm, mkdir, md, rmdir, rd, rename, mv\n  \
             Options    : recurse, prompt, mask [pattern], tarmode, setmode\n  \
             Session    : reconnect, reset, logon, help, exit, quit\n  \
             Local shell: !<command>   (e.g. !ls, !cd /tmp)\n\n  \
             Values: recurse={}, prompt={}, mask={}\n  \
             Remote: {}\n  Local : {}\n",
            on_off(self.recurse),
            on_off(self.prompt),
            self.mask,
            self.unc(),
            self.local_cwd.display()
        );
    }
}

// ==========================================================
//  Helpers
// ==========================================================

/// Percent-decode-free tokenizer that respects double and single quotes the way
/// `smbclient`'s command parser does.
pub fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => cur.push(ch),
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Resolve `spec` relative to `cwd`, returning a `\`-separated path with no
/// drive/share prefix. Leading `\` or `/` means "relative to the share root".
pub fn normalize_remote(cwd: &str, spec: &str) -> String {
    let spec = spec.trim();
    let absolute = spec.starts_with('\\') || spec.starts_with('/');
    let base: Vec<&str> = if absolute {
        Vec::new()
    } else {
        cwd.split('\\').filter(|c| !c.is_empty()).collect()
    };

    let mut stack: Vec<String> = base.iter().map(|s| s.to_string()).collect();
    for part in spec.replace('/', "\\").split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other.to_string()),
        }
    }
    stack.join("\\")
}

/// Join a directory and a leaf name with a single `\`.
pub fn join_remote(dir: &str, leaf: &str) -> String {
    if dir.is_empty() {
        leaf.to_string()
    } else if leaf.is_empty() {
        dir.to_string()
    } else {
        format!("{dir}\\{leaf}")
    }
}

/// Case-insensitive glob matching supporting `*`, `?` and `[abc]`/`[a-z]`.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    wildcard_inner(&p, &t)
}

fn wildcard_inner(p: &[char], t: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '[' {
            // Parse a character class.
            let mut end = pi + 1;
            while end < p.len() && p[end] != ']' {
                end += 1;
            }
            if end >= p.len() {
                // Unterminated class -- treat '[' literally.
                if t[ti] == '[' {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                return false;
            }
            let class = &p[pi + 1..end];
            let mut matched = false;
            let mut idx = 0usize;
            let negate = class.first() == Some(&'!') || class.first() == Some(&'^');
            if negate {
                idx = 1;
            }
            while idx < class.len() {
                if idx + 2 < class.len() && class[idx + 1] == '-' {
                    let (lo, hi) = (class[idx], class[idx + 2]);
                    if lo <= t[ti] && t[ti] <= hi {
                        matched = true;
                    }
                    idx += 3;
                } else {
                    if class[idx] == t[ti] {
                        matched = true;
                    }
                    idx += 1;
                }
            }
            if matched != negate {
                pi = end + 1;
                ti += 1;
            } else if let Some(s) = star {
                pi = s + 1;
                mark += 1;
                ti = mark;
            } else {
                return false;
            }
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Recursively collect local files under `root`.
fn collect_local_files(root: &Path, recurse: bool, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if recurse {
                    stack.push(path);
                }
            } else {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn on_off(v: bool) -> &'static str {
    if v { "ON" } else { "OFF" }
}

/// Human-readable byte count used in transfer lines and `du`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

/// Prompt with a default of "no".
fn confirm_default_yes(question: &str) -> Result<bool> {
    print!("{question} [y/N] ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return Ok(false);
    }
    Ok(matches!(
        answer.trim().chars().next(),
        Some('y') | Some('Y')
    ))
}

// ----------------------------------------------------------
//  Minimal colour helpers
//
//  The rest of the CLI uses `colored`, but the shell also runs in one-shot
//  (`-c`) mode where colour would pollute captured output. These wrappers keep
//  behaviour identical to the rest of the tool without pulling `colored` into
//  every call site.
// ----------------------------------------------------------

trait PlainColour {
    fn red_or_plain(&self) -> String;
    fn green_or_plain(&self) -> String;
    fn yellow_or_plain(&self) -> String;
}

impl PlainColour for str {
    fn red_or_plain(&self) -> String {
        use colored::Colorize;
        self.red().to_string()
    }
    fn green_or_plain(&self) -> String {
        use colored::Colorize;
        self.green().to_string()
    }
    fn yellow_or_plain(&self) -> String {
        use colored::Colorize;
        self.yellow().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_relative_and_absolute() {
        assert_eq!(
            normalize_remote("Users\\Administrator", "Desktop"),
            "Users\\Administrator\\Desktop"
        );
        assert_eq!(normalize_remote("Users\\Administrator", ".."), "Users");
        assert_eq!(
            normalize_remote("Users\\Administrator", "\\Windows"),
            "Windows"
        );
        assert_eq!(
            normalize_remote("Users", "/Windows/System32"),
            "Windows\\System32"
        );
        assert_eq!(normalize_remote("", ".."), "");
        assert_eq!(normalize_remote("a\\b", "..\\..\\c"), "c");
    }

    #[test]
    fn join_remote_variants() {
        assert_eq!(join_remote("", "a.txt"), "a.txt");
        assert_eq!(join_remote("Windows", "a.txt"), "Windows\\a.txt");
        assert_eq!(join_remote("Windows", ""), "Windows");
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*.txt", "notes.TXT"));
        assert!(wildcard_match("report_?.pdf", "report_1.pdf"));
        assert!(wildcard_match("a[bc]d", "abd"));
        assert!(wildcard_match("a[!bc]d", "axd"));
        assert!(!wildcard_match("*.txt", "notes.doc"));
        assert!(!wildcard_match("report_?.pdf", "report_12.pdf"));
        assert!(wildcard_match("foo*bar*baz", "fooXXbarYYbaz"));
        assert!(wildcard_match("*mid*", "xxmidyy"));
    }

    #[test]
    fn tokenizer_handles_quotes() {
        assert_eq!(
            tokenize(r#"get "my file.txt" out.txt"#),
            vec!["get", "my file.txt", "out.txt"]
        );
        assert_eq!(tokenize("ls   *.txt"), vec!["ls", "*.txt"]);
        assert_eq!(tokenize("  "), Vec::<String>::new());
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.00 KiB");
        assert_eq!(human_size(1024 * 1024 * 3), "3.00 MiB");
    }
}
