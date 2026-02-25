//! ASCII art banner and version display for Overthrone.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use colored::Colorize;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn print_banner() {
    let banner = r#"
   ____                 __  __
  / __ \_   _____ _____/ /_/ /_  _________  ____  ___
 / / / / | / / _ / ___/ __/ __ \/ ___/ __ \/ __ \/ _ \
/ /_/ /| |/ /  __/ /  / /_/ / / / /  / /_/ / / / /  __/
\____/ |___/\___/_/   \__/_/ /_/_/   \____/_/ /_/\___/
"#;
    println!("{}", banner.red().bold());
    println!(
        "  {} {} | {} | {}",
        "⚔".red(),
        format!("v{VERSION}").yellow().bold(),
        "Active Directory Offensive Toolkit".white(),
        "by Karmanya03".bright_black(),
    );
}

pub fn print_module_banner(module: &str) {
    println!(
        "\n{} {} {}\n",
        "━━━".red(),
        module.to_uppercase().yellow().bold(),
        "━━━".red(),
    );
}

pub fn print_success(msg: &str) {
    println!("  {} {}", "[✓]".green().bold(), msg);
}

pub fn print_fail(msg: &str) {
    println!("  {} {}", "[✗]".red().bold(), msg);
}

pub fn print_info(msg: &str) {
    println!("  {} {}", "[*]".blue().bold(), msg);
}

pub fn print_warn(msg: &str) {
    println!("  {} {}", "[!]".yellow().bold(), msg);
}

// ═══════════════════════════════════════════════════════
// Enhanced Error Reporting with Context & Remediation
// ═══════════════════════════════════════════════════════

/// Print a detailed error with context and remediation hint
pub fn print_fail_detail(context: &str, error: &str, hint: &str) {
    println!();
    println!("  {} {}", "✗ ERROR:".red().bold(), context.red());
    println!("  {} {}", "  Cause:".bright_black(), error.white());
    println!("  {} {}", "  → Hint:".yellow(), hint.yellow().bold());
    println!();
}

/// Print a critical finding (high-value target, DA access, etc.)
pub fn print_critical(title: &str, details: &str) {
    println!();
    println!("  {} {}", "⭐ CRITICAL:".red().bold().blink(), title.red().bold());
    println!("  {}", details.yellow());
    println!();
}

/// Print a high-value finding
pub fn print_high_value(title: &str, details: &str) {
    println!("  {} {}: {}", "💎".cyan(), title.white().bold(), details.cyan());
}

/// Print an attack path discovery
pub fn print_attack_path(from: &str, to: &str, hops: usize, cost: u32) {
    println!();
    println!("  {} ATTACK PATH FOUND", "🎯".green().bold());
    println!("  {} {} → {}", "•".white(), from.cyan(), to.red().bold());
    println!("  {} {} hops, cost {}", "•".white(), hops.to_string().yellow(), cost.to_string().yellow());
    println!();
}

/// Print credential capture
pub fn print_credential(username: &str, cred_type: &str, source: &str) {
    println!(
        "  {} {}: {} ({})",
        "🔑".green(),
        username.white().bold(),
        cred_type.yellow(),
        source.bright_black()
    );
}

/// Print hash capture for cracking
pub fn print_hash_capture(hash_type: &str, username: &str, hash_preview: &str) {
    println!(
        "  {} {} hash: {} → {}",
        "🔓".red(),
        hash_type.yellow().bold(),
        username.white().bold(),
        hash_preview.bright_black()
    );
}

/// Print DA achieved banner
pub fn print_da_achieved(username: &str, host: &str) {
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════╗".green());
    println!("{}", "║        🎉 DOMAIN ADMIN ACCESS ACHIEVED 🎉              ║".green());
    println!("{}", "╚═══════════════════════════════════════════════════════╝".green());
    println!();
    println!("  {} User: {}", "⭐".yellow().bold(), username.white().bold());
    println!("  {} Host: {}", "💻".cyan(), host.cyan());
    println!();
}

/// Print stage completion summary
pub fn print_stage_summary(stage: &str, succeeded: usize, failed: usize) {
    let status = if failed == 0 {
        "✓".green()
    } else {
        "!".yellow()
    };
    println!(
        "  {} {}: {} succeeded, {} failed",
        status,
        stage.white().bold(),
        succeeded.to_string().green(),
        if failed > 0 { failed.to_string().red() } else { failed.to_string().green() }
    );
}
