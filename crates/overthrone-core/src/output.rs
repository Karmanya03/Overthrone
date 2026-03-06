use crate::error::Result;
use colored::Colorize;
use serde::Serialize;

/// Print data as formatted JSON
pub fn print_json<T: Serialize>(data: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    println!("{json}");
    Ok(())
}

/// Write data as JSON to a file
pub fn write_json<T: Serialize>(data: &T, path: &std::path::Path) -> Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    std::fs::write(path, json)?;
    tracing::info!("Written output to {}", path.display());
    Ok(())
}

/// Print a status banner line
pub fn status(icon: &str, label: &str, value: &str) {
    println!("  {} {:<22} {}", icon, label.dimmed(), value.white().bold());
}

/// Print a section header
pub fn section(title: &str) {
    println!("\n{}", format!("═══ {title} ═══").cyan().bold());
}

/// Print a success message
pub fn success(msg: &str) {
    println!("  {} {}", "[+]".green().bold(), msg);
}

/// Print a warning message
pub fn warning(msg: &str) {
    println!("  {} {}", "[!]".yellow().bold(), msg);
}

/// Print an error message
pub fn error(msg: &str) {
    println!("  {} {}", "[-]".red().bold(), msg);
}

/// Print an info message
pub fn info(msg: &str) {
    println!("  {} {}", "[*]".blue().bold(), msg);
}

/// Print a finding (vulnerability/misconfiguration)
pub fn finding(severity: Severity, title: &str, detail: &str) {
    let icon = match severity {
        Severity::Critical => "[!!!]".red().bold(),
        Severity::High => "[!!]".red(),
        Severity::Medium => "[!]".yellow(),
        Severity::Low => "[~]".blue(),
        Severity::Info => "[i]".dimmed(),
    };
    println!("  {icon} {}", title.white().bold());
    if !detail.is_empty() {
        println!("       {}", detail.dimmed());
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Print a simple table from headers and rows
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Print header
    let header_line: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i] + 2))
        .collect();
    println!("  {}", header_line.cyan().bold());
    let sep: String = widths
        .iter()
        .map(|w| "─".repeat(w + 2))
        .collect::<Vec<_>>()
        .join("");
    println!("  {}", sep.dimmed());

    // Print rows
    for row in rows {
        let line: String = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(10);
                format!("{:<width$}", cell, width = w + 2)
            })
            .collect();
        println!("  {line}");
    }
}
