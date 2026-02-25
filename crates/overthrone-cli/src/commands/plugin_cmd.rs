//! CLI commands for the plugin system

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use colored::Colorize;
use overthrone_core::plugin::{PluginRegistry, PluginContext, PluginType};
use overthrone_core::graph::AttackGraph;
use overthrone_core::exec::ExecCredentials;

/// List all loaded plugins
pub fn cmd_plugin_list(registry: &PluginRegistry) {
    let plugins = registry.list();

    if plugins.is_empty() {
        println!("{}", "No plugins loaded.".yellow());
        println!("  Plugin search paths: ./plugins, ~/.overthrone/plugins");
        println!("  Place .so/.dll/.wasm files in those directories, or use 'plugin load <path>'");
        return;
    }

    println!("{}", format!("Loaded plugins ({}):", plugins.len()).cyan().bold());
    println!(
        "  {:<30} {:<10} {:<10} {:<8} {}",
        "ID", "Version", "Type", "Cmds", "Description"
    );
    println!("  {}", "─".repeat(90));

    for manifest in &plugins {
        let type_str = match manifest.plugin_type {
            PluginType::Native  => "native".green(),
            PluginType::Wasm    => "wasm".blue(),
            PluginType::Script  => "script".yellow(),
            PluginType::Builtin => "builtin".cyan(),
        };

        println!(
            "  {:<30} {:<10} {:<10} {:<8} {}",
            manifest.id.white().bold(),
            manifest.version,
            type_str,
            manifest.commands.len(),
            manifest.description.chars().take(40).collect::<String>(),
        );
    }

    println!();
    let commands = registry.commands();
    if !commands.is_empty() {
        println!("{}", "Available plugin commands:".cyan());
        for (cmd, plugin_id) in &commands {
            println!("  {} (from {})", cmd.white().bold(), plugin_id.dimmed());
        }
    }
}

/// Execute a plugin command
pub async fn cmd_plugin_exec(
    registry: &PluginRegistry,
    command: &str,
    raw_args: &[String],
    domain: &str,
    credentials: Option<&ExecCredentials>,
    graph: Arc<RwLock<AttackGraph>>,
) -> overthrone_core::error::Result<()> {
    // Parse args from ["--key", "value", ...] into HashMap
    let mut args = HashMap::new();
    let mut i = 0;
    while i < raw_args.len() {
        let key = raw_args[i].trim_start_matches('-').to_string();
        let value = if i + 1 < raw_args.len() && !raw_args[i + 1].starts_with('-') {
            i += 1;
            raw_args[i].clone()
        } else {
            "true".to_string()
        };
        args.insert(key, value);
        i += 1;
    }

    let ctx = PluginContext {
        domain: domain.to_string(),
        dc_ip: None,
        credentials: credentials.cloned(),
        graph,
        state: Arc::new(RwLock::new(HashMap::new())),
        log_prefix: command.to_string(),
    };

    println!(
        "{} {} {}",
        "⚡".yellow(),
        "Running plugin command:".cyan(),
        command.white().bold()
    );

    let result = registry.execute_command(command, &args, &ctx).await?;

    if result.success {
        println!("{} {}", "✓".green().bold(), result.output);
    } else {
        println!("{} {}", "✗".red().bold(), result.output);
    }

    // Show artifacts if any
    for artifact in &result.artifacts {
        println!(
            "  {} {:?}: {} ({} bytes)",
            "📎".yellow(),
            artifact.artifact_type,
            artifact.name,
            artifact.data.len()
        );
    }

    Ok(())
}

/// Show info about a specific plugin
pub fn cmd_plugin_info(registry: &PluginRegistry, plugin_id: &str) {
    match registry.get(plugin_id) {
        Some(plugin) => {
            let m = plugin.manifest();
            println!("{}", format!("Plugin: {}", m.name).cyan().bold());
            println!("  ID:          {}", m.id);
            println!("  Version:     {}", m.version);
            println!("  Author:      {}", m.author);
            println!("  Type:        {:?}", m.plugin_type);
            println!("  Description: {}", m.description);
            println!("  Network:     {}", if m.needs_network { "yes" } else { "no" });
            println!("  Admin:       {}", if m.needs_admin { "yes" } else { "no" });
            println!();

            if !m.capabilities.is_empty() {
                println!("  {}", "Capabilities:".yellow());
                for cap in &m.capabilities {
                    println!("    • {:?}", cap);
                }
            }

            if !m.commands.is_empty() {
                println!("  {}", "Commands:".yellow());
                for cmd in &m.commands {
                    println!("    {} — {}", cmd.name.white().bold(), cmd.description);
                    println!("      Usage: {}", cmd.usage.dimmed());
                    for arg in &cmd.args {
                        let req = if arg.required { "required" } else { "optional" };
                        let def = arg.default.as_deref().unwrap_or("-");
                        println!(
                            "      --{:<15} {:?} ({}, default={})",
                            arg.name, arg.arg_type, req, def
                        );
                    }
                }
            }
        }
        None => {
            println!("{} Plugin '{}' not found", "✗".red(), plugin_id);
            println!("  Use 'plugin list' to see loaded plugins");
        }
    }
}
