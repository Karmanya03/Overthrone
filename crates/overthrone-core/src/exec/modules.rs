use crate::error::Result;
use crate::exec::RemoteExecutor;
use crate::proto::smb::SmbSession;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tracing::{info, warn};

use super::{ExecCredentials, ExecOutput};

// ═══════════════════════════════════════════════════════════
// Module Category & Metadata
// ═══════════════════════════════════════════════════════════

/// High-level category for grouping modules in CLI and help output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleCategory {
    Execute,
    Dump,
    Enum,
    Kerberos,
    Secrets,
    Scan,
    Coerce,
}

impl ModuleCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Execute => "Execute",
            Self::Dump => "Dump",
            Self::Enum => "Enum",
            Self::Kerberos => "Kerberos",
            Self::Secrets => "Secrets",
            Self::Scan => "Scan",
            Self::Coerce => "Coerce",
        }
    }
}

impl std::fmt::Display for ModuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Rich metadata returned by each module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub name: &'static str,
    pub description: &'static str,
    pub category: ModuleCategory,
    pub requires_creds: bool,
    pub requires_target: bool,
}

// ═══════════════════════════════════════════════════════════
// Enhanced Module Trait
// ═══════════════════════════════════════════════════════════

/// Trait implemented by built-in or plugin-like modules.
///
/// # Example
///
/// ```ignore
/// use async_trait::async_trait;
/// use overthrone_core::exec::modules::{ModuleCategory, OvtModule};
/// use overthrone_core::exec::{ExecCredentials, ExecOutput};
/// use overthrone_core::Result;
/// use serde_json::Value;
///
/// pub struct HelloModule;
///
/// #[async_trait]
/// impl OvtModule for HelloModule {
///     fn name(&self) -> &'static str {
///         "hello"
///     }
///     fn description(&self) -> &'static str {
///         "A custom hello-world module"
///     }
///     fn category(&self) -> ModuleCategory {
///         ModuleCategory::Enum
///     }
///     async fn run(
///         &self,
///         _target: &str,
///         _creds: ExecCredentials,
///         _params: Option<Value>,
///     ) -> Result<ExecOutput> {
///         Ok(ExecOutput {
///             stdout: "Hello from custom module!".into(),
///             stderr: String::new(),
///             exit_code: Some(0),
///             method: overthrone_core::exec::ExecMethod::WinRM,
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait OvtModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Execute
    }
    fn requires_creds(&self) -> bool {
        true
    }
    fn requires_target(&self) -> bool {
        true
    }

    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            name: self.name(),
            description: self.description(),
            category: self.category(),
            requires_creds: self.requires_creds(),
            requires_target: self.requires_target(),
        }
    }

    /// Run the module against a single target.
    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput>;
}

// ═══════════════════════════════════════════════════════════
// Global Module Registry
// ═══════════════════════════════════════════════════════════

static MODULE_REGISTRY: Lazy<RwLock<HashMap<String, Arc<dyn OvtModule>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Register a module in the global registry.
pub async fn register_module(module: Arc<dyn OvtModule>) {
    let name = module.name().to_string();
    MODULE_REGISTRY.write().await.insert(name, module);
}

pub async fn get_module(name: &str) -> Option<Arc<dyn OvtModule>> {
    MODULE_REGISTRY.read().await.get(name).cloned()
}

pub async fn list_modules() -> Vec<String> {
    MODULE_REGISTRY.read().await.keys().cloned().collect()
}

pub async fn list_module_metadata() -> Vec<ModuleMetadata> {
    MODULE_REGISTRY
        .read()
        .await
        .values()
        .map(|m| m.metadata())
        .collect()
}

pub async fn list_modules_by_category(cat: ModuleCategory) -> Vec<String> {
    MODULE_REGISTRY
        .read()
        .await
        .values()
        .filter(|m| m.category() == cat)
        .map(|m| m.name().to_string())
        .collect()
}

/// Number of registered modules
pub async fn module_count() -> usize {
    MODULE_REGISTRY.read().await.len()
}

// ═══════════════════════════════════════════════════════════
// Parallel Execution Support
// ═══════════════════════════════════════════════════════════

/// Result of running a module against a single target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRunResult {
    pub target: String,
    pub module_name: String,
    pub success: bool,
    pub output: ExecOutput,
    pub error: Option<String>,
}

/// Configuration for parallel module execution.
#[derive(Debug, Clone)]
pub struct ParallelModuleConfig {
    pub concurrency: usize,
    pub timeout_secs: u64,
}

impl Default for ParallelModuleConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            timeout_secs: 30,
        }
    }
}

/// Run a module against multiple targets in parallel.
pub async fn run_module_parallel(
    module: &Arc<dyn OvtModule>,
    targets: &[String],
    creds: ExecCredentials,
    params: Option<Value>,
    config: ParallelModuleConfig,
) -> Vec<ModuleRunResult> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut handles = Vec::with_capacity(targets.len());

    for target in targets {
        let t = target.clone();
        let c = creds.clone();
        let p = params.clone();
        let m = Arc::clone(module);
        let sem = Arc::clone(&semaphore);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            match m.run(&t, c, p).await {
                Ok(output) => ModuleRunResult {
                    target: t,
                    module_name: m.name().to_string(),
                    success: true,
                    output,
                    error: None,
                },
                Err(e) => ModuleRunResult {
                    target: t,
                    module_name: m.name().to_string(),
                    success: false,
                    output: ExecOutput {
                        stdout: String::new(),
                        stderr: format!("{}", e),
                        exit_code: Some(1),
                        method: super::ExecMethod::Plugin {
                            plugin_id: m.name().to_string(),
                        },
                    },
                    error: Some(format!("{}", e)),
                },
            }
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(r) => results.push(r),
            Err(e) => {
                warn!("Module parallel task panicked: {}", e);
            }
        }
    }
    results
}

// ═══════════════════════════════════════════════════════════
// Parameter Helpers
// ═══════════════════════════════════════════════════════════

fn get_param_str(params: &Option<Value>, key: &str, default: &str) -> String {
    params
        .as_ref()
        .and_then(|v| v.get(key).and_then(|c| c.as_str().map(|s| s.to_string())))
        .unwrap_or_else(|| default.to_string())
}

fn get_param_bool(params: &Option<Value>, key: &str, default: bool) -> bool {
    params
        .as_ref()
        .and_then(|v| v.get(key).and_then(|c| c.as_bool()))
        .unwrap_or(default)
}

// ═══════════════════════════════════════════════════════════
// BUILT-IN EXECUTION MODULES
// These modules depend only on crate-internal executors
// ═══════════════════════════════════════════════════════════

// ── WinRM Exec Module ────────────────────────────────────

pub struct WinRmExecModule;

#[async_trait]
impl OvtModule for WinRmExecModule {
    fn name(&self) -> &'static str {
        "winrm-exec"
    }
    fn description(&self) -> &'static str {
        "Execute a command via WinRM"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Execute
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let command = get_param_str(&params, "command", "whoami");
        let executor = crate::exec::winrm::WinRmExecutor::new(creds);
        executor.execute(target, &command).await
    }
}

// ── SMB Exec Module ──────────────────────────────────────

pub struct SmbExecModule;

#[async_trait]
impl OvtModule for SmbExecModule {
    fn name(&self) -> &'static str {
        "smb-exec"
    }
    fn description(&self) -> &'static str {
        "Execute a command via SMBExec"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Execute
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let command = get_param_str(&params, "command", "whoami");

        let session = if let Some(nt) = creds.nt_hash.as_deref() {
            SmbSession::connect_with_hash(target, &creds.domain, &creds.username, nt).await?
        } else {
            SmbSession::connect(target, &creds.domain, &creds.username, &creds.password).await?
        };

        let res = crate::exec::smbexec::exec_command(&session, &command).await?;

        Ok(ExecOutput {
            stdout: res.output,
            stderr: String::new(),
            exit_code: Some(if res.success { 0 } else { 1 }),
            method: super::ExecMethod::SmbExec,
        })
    }
}

// ── PsExec Module ────────────────────────────────────────

pub struct PsExecModule;

#[async_trait]
impl OvtModule for PsExecModule {
    fn name(&self) -> &'static str {
        "psexec"
    }
    fn description(&self) -> &'static str {
        "Execute a command via PsExec-style service creation"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Execute
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let command = get_param_str(&params, "command", "whoami");
        let executor = crate::exec::psexec::PsExecutor::new(creds);
        executor.execute(target, &command).await
    }
}

// ── WMI Exec Module ──────────────────────────────────────

pub struct WmiExecModule;

#[async_trait]
impl OvtModule for WmiExecModule {
    fn name(&self) -> &'static str {
        "wmi-exec"
    }
    fn description(&self) -> &'static str {
        "Execute a command via WMI (SCM fallback)"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Execute
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let command = get_param_str(&params, "command", "whoami");

        let session = if let Some(nt) = creds.nt_hash.as_deref() {
            SmbSession::connect_with_hash(target, &creds.domain, &creds.username, nt).await?
        } else {
            SmbSession::connect(target, &creds.domain, &creds.username, &creds.password).await?
        };

        let result = crate::exec::wmiexec::exec_command(&session, &command).await?;

        Ok(ExecOutput {
            stdout: result.output,
            stderr: String::new(),
            exit_code: Some(if result.success { 0 } else { 1 }),
            method: super::ExecMethod::WmiExec,
        })
    }
}

// ── AtExec Module ────────────────────────────────────────

pub struct AtExecModule;

#[async_trait]
impl OvtModule for AtExecModule {
    fn name(&self) -> &'static str {
        "atexec"
    }
    fn description(&self) -> &'static str {
        "Execute a command via Scheduled Tasks (ATSVC)"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Execute
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let command = get_param_str(&params, "command", "whoami");
        let executor = crate::exec::atexec::AtExecutor::new(creds);
        executor.execute(target, &command).await
    }
}

// ── RDP Scanner Module ───────────────────────────────────

pub struct RdpModule;

#[async_trait]
impl OvtModule for RdpModule {
    fn name(&self) -> &'static str {
        "rdp"
    }
    fn description(&self) -> &'static str {
        "Check if RDP is available on target (port 3389)"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scan
    }
    fn requires_creds(&self) -> bool {
        false
    }

    async fn run(
        &self,
        target: &str,
        _creds: ExecCredentials,
        _params: Option<Value>,
    ) -> Result<ExecOutput> {
        use tokio::net::TcpStream;
        use tokio::time::{Duration, timeout};

        match timeout(
            Duration::from_secs(3),
            TcpStream::connect(format!("{}:3389", target)),
        )
        .await
        {
            Ok(Ok(_)) => Ok(ExecOutput {
                stdout: format!("RDP is OPEN on {}:3389", target),
                stderr: String::new(),
                exit_code: Some(0),
                method: super::ExecMethod::WinRM,
            }),
            Ok(Err(_)) => Ok(ExecOutput {
                stdout: format!("RDP is CLOSED on {}:3389", target),
                stderr: String::new(),
                exit_code: Some(1),
                method: super::ExecMethod::WinRM,
            }),
            Err(_) => Ok(ExecOutput {
                stdout: format!("RDP connection timed out on {}:3389", target),
                stderr: String::new(),
                exit_code: Some(1),
                method: super::ExecMethod::WinRM,
            }),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// REGISTRATION — core built-in modules only
// ═══════════════════════════════════════════════════════════

/// Register all built-in modules that depend only on core crate internals.
/// CME/NetExec-style modules that reference other crates (reaper, hunter, etc.)
/// are registered separately by the CLI crate via `register_module()`.
pub async fn register_core_modules() {
    register_module(Arc::new(WinRmExecModule)).await;
    register_module(Arc::new(SmbExecModule)).await;
    register_module(Arc::new(PsExecModule)).await;
    register_module(Arc::new(WmiExecModule)).await;
    register_module(Arc::new(AtExecModule)).await;
    register_module(Arc::new(RdpModule)).await;
    info!("Registered {} core execution modules", module_count().await);
}

/// Legacy alias for backwards compatibility — registers only core exec modules.
pub async fn register_builtin_modules() {
    register_core_modules().await;
}

// ═══════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_module_registry_core() {
        register_core_modules().await;
        let modules = list_modules().await;
        assert!(modules.contains(&"winrm-exec".to_string()));
        assert!(modules.contains(&"smb-exec".to_string()));
        assert!(modules.contains(&"psexec".to_string()));
        assert!(modules.contains(&"wmi-exec".to_string()));
        assert!(modules.contains(&"atexec".to_string()));
        assert!(modules.contains(&"rdp".to_string()));
    }

    #[tokio::test]
    async fn test_parallel_execution_utilities() {
        let cfg = ParallelModuleConfig::default();
        assert_eq!(cfg.concurrency, 10);
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[test]
    fn test_module_display() {
        assert_eq!(ModuleCategory::Execute.to_string(), "Execute");
        assert_eq!(ModuleCategory::Dump.to_string(), "Dump");
        assert_eq!(ModuleCategory::Kerberos.to_string(), "Kerberos");
    }

    #[test]
    fn test_module_metadata_defaults() {
        let m = WinRmExecModule;
        let meta = m.metadata();
        assert_eq!(meta.name, "winrm-exec");
        assert!(meta.requires_creds);
        assert!(meta.requires_target);
    }
}
