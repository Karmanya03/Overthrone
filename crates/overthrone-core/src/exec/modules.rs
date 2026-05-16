use crate::error::OverthroneError;
use crate::error::Result;
use crate::exec::RemoteExecutor;
use crate::proto::smb::SmbSession;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{ExecCredentials, ExecOutput};

/// Trait implemented by built-in or plugin-like modules.
#[async_trait]
pub trait OvtModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// Run the module against a single target. The `params` value can contain
    /// module-specific parameters (e.g. `command`, `port`, etc.).
    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput>;
}

/// Simple registry for modules. Modules are stored as `Arc<dyn OvtModule>` so
/// they can be shared and cloned cheaply.
static MODULE_REGISTRY: Lazy<RwLock<HashMap<String, Arc<dyn OvtModule>>>> =
    Lazy::new(|| RwLock::new(HashMap::<String, Arc<dyn OvtModule>>::new()));

/// Register a module (usually called at startup by the crate that defines
/// built-in modules).
pub async fn register_module(module: Arc<dyn OvtModule>) {
    let name = module.name().to_string();
    MODULE_REGISTRY.write().await.insert(name, module);
}

/// Retrieve a module by name
pub async fn get_module(name: &str) -> Option<Arc<dyn OvtModule>> {
    MODULE_REGISTRY.read().await.get(name).cloned()
}

/// List registered module names
pub async fn list_modules() -> Vec<String> {
    MODULE_REGISTRY.read().await.keys().cloned().collect()
}

// Example: a tiny WinRM-backed exec module that delegates to the existing
// WinRmExecutor. This demonstrates how modules can reuse the remote executor
// primitives already present in the crate.
pub struct WinRmExecModule;

#[async_trait]
impl OvtModule for WinRmExecModule {
    fn name(&self) -> &'static str {
        "winrm-exec"
    }

    fn description(&self) -> &'static str {
        "Execute a command via WinRM (uses existing WinRmExecutor)"
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        // Extract `command` from params or default to `whoami`
        let command = params
            .and_then(|v| {
                v.get("command")
                    .and_then(|c| c.as_str().map(|s| s.to_string()))
            })
            .unwrap_or_else(|| "whoami".to_string());

        // Defer to the WinRmExecutor already implemented in this crate.
        let executor = crate::exec::winrm::WinRmExecutor::new(creds);
        executor.execute(target, &command).await
    }
}

/// Register built-in modules. Call this during application startup.
pub async fn register_builtin_modules() {
    register_module(Arc::new(WinRmExecModule)).await;
    // Register SMB and PsExec wrappers
    register_module(Arc::new(SmbExecModule)).await;
    register_module(Arc::new(PsExecModule)).await;
}

// SMB exec module — delegates to existing SmbExecutor
pub struct SmbExecModule;

#[async_trait]
impl OvtModule for SmbExecModule {
    fn name(&self) -> &'static str {
        "smb-exec"
    }

    fn description(&self) -> &'static str {
        "Execute a command via SMBExec (creates minimal artifacts)"
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let command = params
            .as_ref()
            .and_then(|v| {
                v.get("command")
                    .and_then(|c| c.as_str().map(|s| s.to_string()))
            })
            .unwrap_or_else(|| "whoami".to_string());

        let cleanup = params
            .as_ref()
            .and_then(|v| v.get("cleanup").and_then(|c| c.as_bool()))
            .unwrap_or(true);

        let output_share = params.as_ref().and_then(|v| {
            v.get("output_share")
                .and_then(|c| c.as_str().map(|s| s.to_string()))
        });

        let output_path = params.as_ref().and_then(|v| {
            v.get("output_path")
                .and_then(|c| c.as_str().map(|s| s.to_string()))
        });

        // Connect SMB session
        let session = if let Some(nt) = creds.nt_hash.as_deref() {
            SmbSession::connect_with_hash(target, &creds.domain, &creds.username, nt).await?
        } else {
            SmbSession::connect(target, &creds.domain, &creds.username, &creds.password).await?
        };

        // Build SMBExecConfig
        let mut cfg = crate::exec::smbexec::SmbExecConfig::default();
        if let Some(s) = output_share {
            cfg.output_share = s;
        }
        if let Some(p) = output_path {
            cfg.output_path = p;
        }
        cfg.cleanup = cleanup;

        let res = crate::exec::smbexec::execute(&session, &command, &cfg).await?;

        Ok(ExecOutput {
            stdout: res.output,
            stderr: String::new(),
            exit_code: Some(if res.success { 0 } else { 1 }),
            method: super::ExecMethod::SmbExec,
        })
    }
}

// PsExec module — delegates to existing PsExecutor (service creation method)
pub struct PsExecModule;

#[async_trait]
impl OvtModule for PsExecModule {
    fn name(&self) -> &'static str {
        "psexec"
    }

    fn description(&self) -> &'static str {
        "Execute a command via PsExec-style service creation"
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        // Parse parameters
        let command = params.as_ref().and_then(|v| {
            v.get("command")
                .and_then(|c| c.as_str().map(|s| s.to_string()))
        });
        let upload_path = params.as_ref().and_then(|v| {
            v.get("upload")
                .and_then(|c| c.as_str().map(|s| s.to_string()))
        });
        let remote_filename = params.as_ref().and_then(|v| {
            v.get("remote_filename")
                .and_then(|c| c.as_str().map(|s| s.to_string()))
        });
        let cleanup = params
            .as_ref()
            .and_then(|v| v.get("cleanup").and_then(|c| c.as_bool()))
            .unwrap_or(true);

        // Establish SMB session (use hash if provided)
        let session = if let Some(nt) = creds.nt_hash.as_deref() {
            SmbSession::connect_with_hash(target, &creds.domain, &creds.username, nt).await?
        } else {
            SmbSession::connect(target, &creds.domain, &creds.username, &creds.password).await?
        };

        // If upload requested, deploy payload
        let mut deployed_name: Option<String> = None;
        if let Some(local) = upload_path {
            // Determine filename to use
            let fname = if let Some(rfn) = remote_filename {
                rfn
            } else {
                match std::path::Path::new(&local).file_name() {
                    Some(n) => n.to_string_lossy().to_string(),
                    None => format!("ovt_payload_{:08X}.bin", rand::random::<u32>()),
                }
            };

            let data = tokio::fs::read(&local).await.map_err(|e| {
                OverthroneError::custom(format!("Failed to read upload '{}': {}", local, e))
            })?;
            let full_path = session.deploy_payload(&data, &fname).await?;
            deployed_name = Some(fname);
            // Use deployed binary as command if none provided
            if command.is_none() {
                // Execute the binary directly
                let cfg = crate::exec::psexec::PsExecConfig {
                    service_name: format!("Exec{:04X}", rand::random::<u16>()),
                    display_name: format!("Exec{:04X}", rand::random::<u16>()),
                    command: full_path.clone(),
                    cleanup,
                };

                let res = crate::exec::psexec::execute(&session, &cfg).await;
                // Attempt payload cleanup
                if cleanup {
                    if let Some(ref name) = deployed_name {
                        let _ = session.cleanup_payload(name).await;
                    }
                }
                return match res {
                    Ok(r) => Ok(ExecOutput {
                        stdout: r.output.unwrap_or_default(),
                        stderr: String::new(),
                        exit_code: Some(if r.success { 0 } else { 1 }),
                        method: super::ExecMethod::PsExec,
                    }),
                    Err(e) => Err(e),
                };
            }
        }

        // Fallback: if command provided, run via PsExecutor
        if let Some(cmd) = command {
            let executor = crate::exec::psexec::PsExecutor::new(creds);
            let out = executor.execute(target, &cmd).await;

            // Cleanup deployed payload if requested
            if cleanup {
                if let Some(ref name) = deployed_name {
                    let _ = session.cleanup_payload(name).await;
                }
            }

            return out;
        }

        Err(crate::error::OverthroneError::ExecSimple(
            "No command or upload specified".to_string(),
        ))
    }
}
