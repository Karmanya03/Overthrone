//! Plugin system for Overthrone
//!
//! Supports three plugin types:
//! 1. **Native** — dynamically loaded .dll/.so shared libraries (fastest, full access)
//! 2. **WASM** — sandboxed WebAssembly modules (safe for untrusted plugins)
//! 3. **Script** — Lua/Rhai scripts for quick automation (planned)
//!
//! Plugins can:
//! - Add new attack modules (custom Kerberos attacks, LDAP queries, etc.)
//! - Add new execution methods (implements RemoteExecutor)
//! - Hook into the attack graph (add custom nodes/edges)
//! - Provide custom output formatters
//! - React to events (on_node_compromised, on_credential_found, etc.)

pub mod builtin;
pub mod loader;

use crate::error::{OverthroneError, Result};
use crate::exec::{ExecCredentials, ExecMethod, ExecOutput, RemoteExecutor};
use crate::graph::AttackGraph;
use crate::types::Sid;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ──────────────────────────────────────────────────────────
// Plugin manifest (metadata)
// ──────────────────────────────────────────────────────────

/// Plugin metadata — loaded from plugin.toml or declared in code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique plugin identifier (e.g. "com.example.custom-kerberoast")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Version string (semver)
    pub version: String,
    /// Author
    pub author: String,
    /// Description
    pub description: String,
    /// Minimum Overthrone version required
    pub min_overthrone_version: Option<String>,
    /// Plugin type
    pub plugin_type: PluginType,
    /// Capabilities this plugin provides
    pub capabilities: Vec<PluginCapability>,
    /// Commands this plugin registers
    pub commands: Vec<PluginCommand>,
    /// Whether this plugin requires network access
    pub needs_network: bool,
    /// Whether this plugin requires elevated privileges
    pub needs_admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginType {
    /// Native shared library (.dll/.so)
    Native,
    /// WebAssembly module (.wasm)
    Wasm,
    /// Script (Lua/Rhai)
    Script,
    /// Built-in (compiled into the binary)
    Builtin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginCapability {
    /// Can execute commands on remote targets
    Execution,
    /// Can enumerate/crawl AD objects
    Enumeration,
    /// Can perform attacks (Kerberoast, etc.)
    Attack,
    /// Can modify the attack graph
    GraphMutation,
    /// Can format/export output
    OutputFormat,
    /// Can react to events
    EventHandler,
    /// Provides C2 channel integration
    C2Integration,
}

/// A command registered by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCommand {
    /// Command name (e.g. "custom-spray")
    pub name: String,
    /// Help text
    pub description: String,
    /// Usage example
    pub usage: String,
    /// Arguments this command accepts
    pub args: Vec<PluginArgDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginArgDef {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub arg_type: PluginArgType,
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginArgType {
    String,
    Integer,
    Boolean,
    FilePath,
    IpAddress,
    Sid,
}

// ──────────────────────────────────────────────────────────
// Plugin trait — the core interface every plugin must implement
// ──────────────────────────────────────────────────────────

/// Context passed to plugins — provides controlled access to Overthrone internals
pub struct PluginContext {
    /// Read-only snapshot of current config
    pub domain: String,
    pub dc_ip: Option<String>,
    /// Credentials (if the plugin has Execution capability)
    pub credentials: Option<ExecCredentials>,
    /// Shared attack graph reference
    pub graph: Arc<RwLock<AttackGraph>>,
    /// Key-value store for plugin state persistence
    pub state: Arc<RwLock<HashMap<String, String>>>,
    /// Logger handle
    pub log_prefix: String,
}

impl PluginContext {
    pub fn log_info(&self, msg: &str) {
        log::info!("[plugin:{}] {}", self.log_prefix, msg);
    }

    pub fn log_warn(&self, msg: &str) {
        log::warn!("[plugin:{}] {}", self.log_prefix, msg);
    }

    pub fn log_error(&self, msg: &str) {
        log::error!("[plugin:{}] {}", self.log_prefix, msg);
    }

    pub fn log_attack(&self, msg: &str) {
        log::info!("[plugin:{}] ⚡ {}", self.log_prefix, msg);
    }

    /// Store a value in persistent plugin state
    pub fn set_state(&self, key: &str, value: &str) {
        if let Ok(mut state) = self.state.write() {
            state.insert(key.to_string(), value.to_string());
        }
    }

    /// Retrieve a value from persistent plugin state
    pub fn get_state(&self, key: &str) -> Option<String> {
        self.state.read().ok()?.get(key).cloned()
    }
}

/// Event types that plugins can subscribe to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginEvent {
    /// A new AD node was discovered
    NodeDiscovered {
        node_id: u64,
        node_type: String,
        name: String,
    },
    /// A credential was recovered (hash, password, ticket)
    CredentialFound {
        username: String,
        credential_type: String,
        domain: String,
    },
    /// A new attack path was identified
    AttackPathFound {
        source: String,
        target: String,
        hops: usize,
    },
    /// A node was compromised (code execution achieved)
    NodeCompromised { hostname: String, method: String },
    /// Scan phase completed
    PhaseCompleted { phase: String, duration_secs: u64 },
    /// User-triggered custom event
    Custom {
        event_type: String,
        data: HashMap<String, String>,
    },
}

/// Result from a plugin command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub success: bool,
    pub output: String,
    pub data: HashMap<String, serde_json::Value>,
    /// Artifacts produced (files, tickets, etc.)
    pub artifacts: Vec<PluginArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginArtifact {
    pub name: String,
    pub artifact_type: ArtifactType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactType {
    KerberosTicket,
    NtlmHash,
    Password,
    Certificate,
    Report,
    Custom(String),
}

/// The main plugin trait — all plugins must implement this
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Return the plugin's manifest (metadata)
    fn manifest(&self) -> &PluginManifest;

    /// Initialize the plugin with context
    /// Called once when the plugin is loaded
    async fn init(&mut self, ctx: &PluginContext) -> Result<()>;

    /// Execute a named command registered by this plugin
    async fn execute_command(
        &mut self,
        command: &str,
        args: &HashMap<String, String>,
        ctx: &PluginContext,
    ) -> Result<PluginResult>;

    /// Handle an event (optional — only if EventHandler capability)
    async fn on_event(&self, event: &PluginEvent, ctx: &PluginContext) -> Result<()> {
        let _ = (event, ctx);
        Ok(())
    }

    /// Shutdown / cleanup (called when plugin is unloaded)
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    /// Health check — is the plugin still functional?
    fn is_healthy(&self) -> bool {
        true
    }
}

/// For plugins that provide execution capabilities
#[async_trait]
pub trait PluginExecutor: Plugin {
    /// Get a RemoteExecutor implementation from this plugin
    fn as_executor(&self) -> Option<Box<dyn RemoteExecutor>>;
}

// ──────────────────────────────────────────────────────────
// Plugin Registry — manages all loaded plugins
// ──────────────────────────────────────────────────────────

/// Central plugin registry
pub struct PluginRegistry {
    /// All loaded plugins, keyed by manifest ID
    plugins: HashMap<String, Box<dyn Plugin>>,
    /// Command → plugin ID mapping (for routing CLI commands)
    command_map: HashMap<String, String>,
    /// Plugin load order (for deterministic shutdown)
    load_order: Vec<String>,
    /// Disabled plugin IDs
    disabled: Vec<String>,
    /// Plugin search paths
    search_paths: Vec<String>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            command_map: HashMap::new(),
            load_order: Vec::new(),
            disabled: Vec::new(),
            search_paths: vec!["./plugins".to_string(), "~/.overthrone/plugins".to_string()],
        }
    }

    /// Add a custom search path for plugins
    pub fn add_search_path(&mut self, path: &str) {
        self.search_paths.push(path.to_string());
    }

    /// Register a plugin instance
    pub async fn register(
        &mut self,
        mut plugin: Box<dyn Plugin>,
        ctx: &PluginContext,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let id = manifest.id.clone();

        // Check for conflicts
        if self.plugins.contains_key(&id) {
            return Err(OverthroneError::Plugin(format!(
                "Plugin '{}' already registered",
                id
            )));
        }

        // Check version compatibility
        if let Some(ref min_ver) = manifest.min_overthrone_version {
            if !is_version_compatible(min_ver) {
                return Err(OverthroneError::Plugin(format!(
                    "Plugin '{}' requires Overthrone >= {}, current is {}",
                    id,
                    min_ver,
                    env!("CARGO_PKG_VERSION")
                )));
            }
        }

        // Initialize
        log::info!(
            "[plugin] Loading '{}' v{} by {} ({:?})",
            manifest.name,
            manifest.version,
            manifest.author,
            manifest.plugin_type
        );

        plugin.init(ctx).await?;

        // Register commands
        for cmd in &manifest.commands {
            if self.command_map.contains_key(&cmd.name) {
                log::warn!(
                    "[plugin] Command '{}' already registered by another plugin, skipping",
                    cmd.name
                );
                continue;
            }
            self.command_map.insert(cmd.name.clone(), id.clone());
            log::info!("[plugin] Registered command: {}", cmd.name);
        }

        self.load_order.push(id.clone());
        self.plugins.insert(id, plugin);

        log::info!(
            "[plugin] Successfully loaded '{}' ({} commands)",
            manifest.name,
            manifest.commands.len()
        );

        Ok(())
    }

    /// Unload a plugin by ID
    pub async fn unload(&mut self, plugin_id: &str) -> Result<()> {
        if let Some(plugin) = self.plugins.remove(plugin_id) {
            plugin.shutdown().await?;

            // Remove command mappings
            self.command_map.retain(|_, v| v != plugin_id);
            self.load_order.retain(|id| id != plugin_id);

            log::info!("[plugin] Unloaded '{}'", plugin_id);
            Ok(())
        } else {
            Err(OverthroneError::Plugin(format!(
                "Plugin '{}' not found",
                plugin_id
            )))
        }
    }

    /// Execute a plugin command by name
    pub async fn execute_command(
        &mut self,
        command: &str,
        args: &HashMap<String, String>,
        ctx: &PluginContext,
    ) -> Result<PluginResult> {
        let plugin_id = self.command_map.get(command).ok_or_else(|| {
            OverthroneError::Plugin(format!(
                "Unknown plugin command: '{}'. Available: {:?}",
                command,
                self.command_map.keys().collect::<Vec<_>>()
            ))
        })?;

        if self.disabled.contains(plugin_id) {
            return Err(OverthroneError::Plugin(format!(
                "Plugin '{}' is disabled",
                plugin_id
            )));
        }

        let plugin_id_owned = plugin_id.clone();
        let plugin = self
            .plugins
            .get_mut(&plugin_id_owned)
            .ok_or_else(|| OverthroneError::Plugin(format!("Plugin '{}' not loaded", plugin_id_owned)))?;

        plugin.execute_command(command, args, ctx).await
    }

    /// Broadcast an event to all plugins with EventHandler capability
    pub async fn broadcast_event(&self, event: &PluginEvent, ctx: &PluginContext) {
        for (id, plugin) in &self.plugins {
            if self.disabled.contains(id) {
                continue;
            }

            let manifest = plugin.manifest();
            if manifest
                .capabilities
                .contains(&PluginCapability::EventHandler)
            {
                if let Err(e) = plugin.on_event(event, ctx).await {
                    log::warn!("[plugin] Event handler error in '{}': {}", manifest.name, e);
                }
            }
        }
    }

    /// List all loaded plugins
    pub fn list(&self) -> Vec<&PluginManifest> {
        self.plugins.values().map(|p| p.manifest()).collect()
    }

    /// List all available plugin commands
    pub fn commands(&self) -> Vec<(&str, &str)> {
        self.command_map
            .iter()
            .map(|(cmd, plugin_id)| (cmd.as_str(), plugin_id.as_str()))
            .collect()
    }

    /// Get a specific plugin by ID
    pub fn get(&self, plugin_id: &str) -> Option<&dyn Plugin> {
        self.plugins.get(plugin_id).map(|p| p.as_ref())
    }

    /// Disable a plugin without unloading
    pub fn disable(&mut self, plugin_id: &str) {
        if !self.disabled.contains(&plugin_id.to_string()) {
            self.disabled.push(plugin_id.to_string());
            log::info!("[plugin] Disabled '{}'", plugin_id);
        }
    }

    /// Re-enable a disabled plugin
    pub fn enable(&mut self, plugin_id: &str) {
        self.disabled.retain(|id| id != plugin_id);
        log::info!("[plugin] Enabled '{}'", plugin_id);
    }

    /// Shutdown all plugins in reverse load order
    pub async fn shutdown_all(&mut self) {
        for id in self.load_order.iter().rev() {
            if let Some(plugin) = self.plugins.get(id) {
                if let Err(e) = plugin.shutdown().await {
                    log::warn!("[plugin] Shutdown error for '{}': {}", id, e);
                }
            }
        }
        self.plugins.clear();
        self.command_map.clear();
        self.load_order.clear();
        log::info!("[plugin] All plugins shut down");
    }

    /// Load all plugins from search paths
    pub async fn discover_and_load(&mut self, ctx: &PluginContext) -> Result<usize> {
        let mut loaded = 0;

        for search_path in self.search_paths.clone() {
            let expanded = shellexpand::tilde(&search_path).to_string();
            let path = std::path::Path::new(&expanded);

            if !path.exists() {
                log::debug!("[plugin] Search path does not exist: {}", expanded);
                continue;
            }

            log::info!("[plugin] Scanning for plugins in: {}", expanded);

            let entries = match std::fs::read_dir(path) {
                Ok(e) => e,
                Err(e) => {
                    log::warn!("[plugin] Cannot read plugin dir {}: {}", expanded, e);
                    continue;
                }
            };

            for entry in entries.flatten() {
                let file_path = entry.path();

                let plugin = if file_path
                    .extension()
                    .map_or(false, |e| e == "so" || e == "dll" || e == "dylib")
                {
                    // Native plugin
                    match loader::load_native_plugin(&file_path) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            log::warn!("[plugin] Failed to load {:?}: {}", file_path, e);
                            None
                        }
                    }
                } else if file_path.extension().map_or(false, |e| e == "wasm") {
                    // WASM plugin
                    match loader::load_wasm_plugin(&file_path) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            log::warn!("[plugin] Failed to load WASM {:?}: {}", file_path, e);
                            None
                        }
                    }
                } else {
                    None
                };

                if let Some(plugin) = plugin {
                    match self.register(plugin, ctx).await {
                        Ok(()) => loaded += 1,
                        Err(e) => log::warn!("[plugin] Registration failed: {}", e),
                    }
                }
            }
        }

        log::info!(
            "[plugin] Loaded {} plugin(s) from {} search path(s)",
            loaded,
            self.search_paths.len()
        );
        Ok(loaded)
    }
}

fn is_version_compatible(min_version: &str) -> bool {
    // Simple semver check — compare against crate version
    let current = env!("CARGO_PKG_VERSION");
    // For now, accept all. Proper semver comparison would use the `semver` crate.
    let _ = (current, min_version);
    true
}

// ──────────────────────────────────────────────────────────
// Native plugin FFI interface
// ──────────────────────────────────────────────────────────

/// FFI-safe plugin info returned by native plugins
/// Native .dll/.so plugins must export these C functions:
///
/// ```c
/// extern "C" OverthronePluginInfo* overthrone_plugin_info();
/// extern "C" OverthronePluginHandle* overthrone_plugin_create();
/// extern "C" void overthrone_plugin_destroy(OverthronePluginHandle*);
/// ```
#[repr(C)]
pub struct NativePluginInfo {
    pub id: *const std::ffi::c_char,
    pub name: *const std::ffi::c_char,
    pub version: *const std::ffi::c_char,
    pub author: *const std::ffi::c_char,
    pub description: *const std::ffi::c_char,
    pub api_version: u32,
}

/// Current plugin API version — plugins compiled against a different
/// major version won't load
pub const PLUGIN_API_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_registry_new() {
        let registry = PluginRegistry::new();
        assert!(registry.plugins.is_empty());
        assert!(registry.command_map.is_empty());
        assert_eq!(registry.search_paths.len(), 2);
    }

    #[test]
    fn test_plugin_manifest_serde() {
        let manifest = PluginManifest {
            id: "test.plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Tester".to_string(),
            description: "A test plugin".to_string(),
            min_overthrone_version: None,
            plugin_type: PluginType::Builtin,
            capabilities: vec![PluginCapability::Attack],
            commands: vec![],
            needs_network: false,
            needs_admin: false,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let deser: PluginManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, "test.plugin");
    }
}
