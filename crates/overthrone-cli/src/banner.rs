//! ASCII art banner and version display for Overthrone.
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
