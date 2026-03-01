//! Plugin loader — handles dynamic loading of native (.dll/.so) and WASM plugins

use super::{
    NativePluginInfo, PLUGIN_API_VERSION, Plugin, PluginContext, PluginEvent, PluginManifest,
    PluginResult, PluginType,
};
use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::ffi::CStr;
use std::path::Path;

// ──────────────────────────────────────────────────────────
// Native plugin loader (libloading)
// ──────────────────────────────────────────────────────────

/// A native plugin loaded from a shared library
pub struct NativePlugin {
    manifest: PluginManifest,
    #[allow(dead_code)]
    library: libloading::Library,
    // Function pointers cached from the loaded library
    fn_execute: libloading::Symbol<
        'static,
        unsafe extern "C" fn(
            command: *const std::ffi::c_char,
            args_json: *const std::ffi::c_char,
            ctx_json: *const std::ffi::c_char,
        ) -> *mut std::ffi::c_char,
    >,
    fn_on_event: Option<
        libloading::Symbol<
            'static,
            unsafe extern "C" fn(event_json: *const std::ffi::c_char) -> i32,
        >,
    >,
    fn_shutdown: Option<libloading::Symbol<'static, unsafe extern "C" fn() -> i32>>,
}

// Safety: The library handle and symbols are Send+Sync because we control
// the FFI contract and ensure the library stays loaded for the plugin lifetime
unsafe impl Send for NativePlugin {}
unsafe impl Sync for NativePlugin {}

/// Load a native plugin from a shared library file
pub fn load_native_plugin(path: &Path) -> Result<Box<dyn Plugin>> {
    log::info!("[plugin:loader] Loading native plugin from {:?}", path);

    unsafe {
        let library = libloading::Library::new(path).map_err(|e| {
            OverthroneError::Plugin(format!("Failed to load library {:?}: {}", path, e))
        })?;

        // Get plugin info
        let info_fn: libloading::Symbol<unsafe extern "C" fn() -> *const NativePluginInfo> =
            library.get(b"overthrone_plugin_info").map_err(|e| {
                OverthroneError::Plugin(format!(
                    "Missing overthrone_plugin_info export in {:?}: {}",
                    path, e
                ))
            })?;

        let info_ptr = info_fn();
        if info_ptr.is_null() {
            return Err(OverthroneError::Plugin(format!(
                "overthrone_plugin_info returned null in {:?}",
                path
            )));
        }

        let info = &*info_ptr;

        // Check API version
        if info.api_version != PLUGIN_API_VERSION {
            return Err(OverthroneError::Plugin(format!(
                "Plugin API version mismatch: plugin={}, expected={} in {:?}",
                info.api_version, PLUGIN_API_VERSION, path
            )));
        }

        // Extract strings from C pointers
        let id = cstr_to_string(info.id)?;
        let name = cstr_to_string(info.name)?;
        let version = cstr_to_string(info.version)?;
        let author = cstr_to_string(info.author)?;
        let description = cstr_to_string(info.description)?;

        // Get the manifest (extended info if available)
        let manifest_fn: std::result::Result<
            libloading::Symbol<unsafe extern "C" fn() -> *const std::ffi::c_char>,
            _,
        > = library.get(b"overthrone_plugin_manifest_json");

        let manifest = if let Ok(mfn) = manifest_fn {
            let json_ptr = mfn();
            if !json_ptr.is_null() {
                let json_str = CStr::from_ptr(json_ptr).to_string_lossy();
                serde_json::from_str(&json_str).unwrap_or_else(|_| {
                    default_manifest(&id, &name, &version, &author, &description)
                })
            } else {
                default_manifest(&id, &name, &version, &author, &description)
            }
        } else {
            default_manifest(&id, &name, &version, &author, &description)
        };

        // Get function pointers
        // We need to transmute lifetimes because libloading Symbols borrow the Library,
        // but we're storing both together
        let fn_execute: libloading::Symbol<
            unsafe extern "C" fn(
                *const std::ffi::c_char,
                *const std::ffi::c_char,
                *const std::ffi::c_char,
            ) -> *mut std::ffi::c_char,
        > = library.get(b"overthrone_plugin_execute").map_err(|e| {
            OverthroneError::Plugin(format!(
                "Missing overthrone_plugin_execute in {:?}: {}",
                path, e
            ))
        })?;
        let fn_execute = std::mem::transmute(fn_execute);

        let fn_on_event = library
            .get::<unsafe extern "C" fn(*const std::ffi::c_char) -> i32>(
                b"overthrone_plugin_on_event",
            )
            .ok();
        let fn_on_event = fn_on_event.map(|s| unsafe {
            std::mem::transmute::<
                _,
                libloading::Symbol<'static, unsafe extern "C" fn(*const std::ffi::c_char) -> i32>,
            >(s)
        });

        let fn_shutdown = library
            .get::<unsafe extern "C" fn() -> i32>(b"overthrone_plugin_shutdown")
            .ok();
        let fn_shutdown = fn_shutdown.map(|s| unsafe {
            std::mem::transmute::<_, libloading::Symbol<'static, unsafe extern "C" fn() -> i32>>(s)
        });

        Ok(Box::new(NativePlugin {
            manifest,
            library,
            fn_execute,
            fn_on_event,
            fn_shutdown,
        }))
    }
}

#[async_trait]
impl Plugin for NativePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, ctx: &PluginContext) -> Result<()> {
        ctx.log_info(&format!(
            "Native plugin '{}' v{} initialized",
            self.manifest.name, self.manifest.version
        ));
        Ok(())
    }

    async fn execute_command(
        &self,
        command: &str,
        args: &HashMap<String, String>,
        _ctx: &PluginContext,
    ) -> Result<PluginResult> {
        use std::ffi::CString;

        let cmd_c = CString::new(command)
            .map_err(|e| OverthroneError::Plugin(format!("Invalid command string: {}", e)))?;
        let args_json = serde_json::to_string(args)
            .map_err(|e| OverthroneError::Plugin(format!("Args serialization error: {}", e)))?;
        let args_c = CString::new(args_json)
            .map_err(|e| OverthroneError::Plugin(format!("Invalid args string: {}", e)))?;
        let ctx_c = CString::new("{}")
            .map_err(|e| OverthroneError::Plugin(format!("Invalid ctx string: {}", e)))?;

        let result_ptr =
            unsafe { (self.fn_execute)(cmd_c.as_ptr(), args_c.as_ptr(), ctx_c.as_ptr()) };

        if result_ptr.is_null() {
            return Err(OverthroneError::Plugin(
                "Plugin returned null result".to_string(),
            ));
        }

        let result_str = unsafe {
            let s = CStr::from_ptr(result_ptr).to_string_lossy().to_string();
            // Free the string (plugin must use overthrone_alloc or compatible allocator)
            libc_free(result_ptr as *mut std::ffi::c_void);
            s
        };

        serde_json::from_str(&result_str)
            .map_err(|e| OverthroneError::Plugin(format!("Invalid plugin result JSON: {}", e)))
    }

    async fn on_event(&self, event: &PluginEvent, _ctx: &PluginContext) -> Result<()> {
        if let Some(ref fn_event) = self.fn_on_event {
            let event_json = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string());
            let event_c = std::ffi::CString::new(event_json)
                .map_err(|e| OverthroneError::Plugin(format!("Event string error: {}", e)))?;

            let rc = unsafe { fn_event(event_c.as_ptr()) };
            if rc != 0 {
                return Err(OverthroneError::Plugin(format!(
                    "Plugin event handler returned error code: {}",
                    rc
                )));
            }
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(ref fn_shut) = self.fn_shutdown {
            let rc = unsafe { fn_shut() };
            if rc != 0 {
                log::warn!(
                    "[plugin] Shutdown of '{}' returned error code: {}",
                    self.manifest.name,
                    rc
                );
            }
        }
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────
// WASM plugin loader (wasmtime integration)
// ──────────────────────────────────────────────────────────

use wasmtime::*;

/// A sandboxed WASM plugin
pub struct WasmPlugin {
    manifest: PluginManifest,
    engine: Engine,
    module: Module,
    store: Option<Store<WasmPluginState>>,
}

/// State accessible to WASM plugin via host functions
struct WasmPluginState {
    log_buffer: Vec<String>,
    graph_operations: Vec<String>,
}

pub fn load_wasm_plugin(path: &Path) -> Result<Box<dyn Plugin>> {
    log::info!("[plugin:loader] Loading WASM plugin from {:?}", path);

    let wasm_bytes = std::fs::read(path)
        .map_err(|e| OverthroneError::Plugin(format!("Cannot read WASM file {:?}: {}", path, e)))?;

    // Create wasmtime engine with default configuration
    let engine = Engine::default();

    // Compile the WASM module
    let module = Module::new(&engine, &wasm_bytes)
        .map_err(|e| OverthroneError::Plugin(format!("Failed to compile WASM module: {}", e)))?;

    // Parse custom section for manifest
    let manifest = extract_wasm_manifest(&wasm_bytes).unwrap_or_else(|| {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        PluginManifest {
            id: format!("wasm.{}", stem),
            name: stem.to_string(),
            version: "0.1.0".to_string(),
            author: "Unknown".to_string(),
            description: format!("WASM plugin from {:?}", path),
            min_overthrone_version: None,
            plugin_type: PluginType::Wasm,
            capabilities: vec![],
            commands: vec![],
            needs_network: false,
            needs_admin: false,
        }
    });

    Ok(Box::new(WasmPlugin {
        manifest,
        engine,
        module,
        store: None,
    }))
}

#[async_trait]
impl Plugin for WasmPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, ctx: &PluginContext) -> Result<()> {
        ctx.log_info(&format!(
            "WASM plugin '{}' initializing",
            self.manifest.name
        ));

        // Create a new store with plugin state
        let state = WasmPluginState {
            log_buffer: Vec::new(),
            graph_operations: Vec::new(),
        };
        let mut store = Store::new(&self.engine, state);

        // Create a linker to define host functions
        let mut linker = Linker::new(&self.engine);

        // Define host function: log(ptr: i32, len: i32)
        linker
            .func_wrap("env", "log", |mut caller: Caller<'_, WasmPluginState>, ptr: i32, len: i32| -> anyhow::Result<()> {
                let mem = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => anyhow::bail!("failed to find memory export"),
                };

                let data = mem.data(&caller);
                let start = ptr as usize;
                let end = start + len as usize;

                if end > data.len() {
                    anyhow::bail!("memory access out of bounds");
                }

                let message = String::from_utf8_lossy(&data[start..end]).to_string();
                caller.data_mut().log_buffer.push(message.clone());
                log::info!("[plugin:wasm] {}", message);
                Ok(())
            })
            .map_err(|e| OverthroneError::Plugin(format!("Failed to define log function: {}", e)))?;

        // Define host function: graph_add_node(name_ptr: i32, name_len: i32, node_type_ptr: i32, node_type_len: i32) -> i64
        linker
            .func_wrap(
                "env",
                "graph_add_node",
                |mut caller: Caller<'_, WasmPluginState>, name_ptr: i32, name_len: i32, type_ptr: i32, type_len: i32| -> i64 {
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => return -1,
                    };

                    let data = mem.data(&caller);
                    
                    let name_start = name_ptr as usize;
                    let name_end = name_start + name_len as usize;
                    let type_start = type_ptr as usize;
                    let type_end = type_start + type_len as usize;

                    if name_end > data.len() || type_end > data.len() {
                        return -1;
                    }

                    let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
                    let node_type = String::from_utf8_lossy(&data[type_start..type_end]).to_string();

                    let op = format!("add_node({}, {})", name, node_type);
                    caller.data_mut().graph_operations.push(op);
                    
                    // Return a dummy node ID
                    1000
                },
            )
            .map_err(|e| OverthroneError::Plugin(format!("Failed to define graph_add_node: {}", e)))?;

        // Define host function: graph_add_edge(from: i64, to: i64, edge_type_ptr: i32, edge_type_len: i32)
        linker
            .func_wrap(
                "env",
                "graph_add_edge",
                |mut caller: Caller<'_, WasmPluginState>, from: i64, to: i64, type_ptr: i32, type_len: i32| {
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => return,
                    };

                    let data = mem.data(&caller);
                    let type_start = type_ptr as usize;
                    let type_end = type_start + type_len as usize;

                    if type_end > data.len() {
                        return;
                    }

                    let edge_type = String::from_utf8_lossy(&data[type_start..type_end]).to_string();
                    let op = format!("add_edge({}, {}, {})", from, to, edge_type);
                    caller.data_mut().graph_operations.push(op);
                },
            )
            .map_err(|e| OverthroneError::Plugin(format!("Failed to define graph_add_edge: {}", e)))?;

        // Instantiate the module with the linker
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| OverthroneError::Plugin(format!("Failed to instantiate WASM module: {}", e)))?;

        // Call the plugin's init function if it exists
        if let Ok(init_func) = instance.get_typed_func::<(), ()>(&mut store, "plugin_init") {
            init_func
                .call(&mut store, ())
                .map_err(|e| OverthroneError::Plugin(format!("WASM plugin_init failed: {}", e)))?;
        }

        // Store the initialized store
        self.store = Some(store);

        ctx.log_info(&format!(
            "WASM plugin '{}' initialized successfully",
            self.manifest.name
        ));
        Ok(())
    }

    async fn execute_command(
        &self,
        command: &str,
        args: &HashMap<String, String>,
        ctx: &PluginContext,
    ) -> Result<PluginResult> {
        let store = self.store.as_ref().ok_or_else(|| {
            OverthroneError::Plugin("WASM plugin not initialized".to_string())
        })?;

        // Get a mutable reference to the store
        // Note: This is a simplified implementation. In a real scenario, we'd need to handle
        // the store mutability more carefully, possibly using RefCell or similar
        let mut store_clone = Store::new(&self.engine, WasmPluginState {
            log_buffer: Vec::new(),
            graph_operations: Vec::new(),
        });

        // Re-instantiate for this execution
        let mut linker = Linker::new(&self.engine);
        
        // Re-define host functions (same as in init)
        linker
            .func_wrap("env", "log", |mut caller: Caller<'_, WasmPluginState>, ptr: i32, len: i32| -> anyhow::Result<()> {
                let mem = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => anyhow::bail!("failed to find memory export"),
                };

                let data = mem.data(&caller);
                let start = ptr as usize;
                let end = start + len as usize;

                if end > data.len() {
                    anyhow::bail!("memory access out of bounds");
                }

                let message = String::from_utf8_lossy(&data[start..end]).to_string();
                caller.data_mut().log_buffer.push(message.clone());
                log::info!("[plugin:wasm] {}", message);
                Ok(())
            })
            .map_err(|e| OverthroneError::Plugin(format!("Failed to define log function: {}", e)))?;

        let instance = linker
            .instantiate(&mut store_clone, &self.module)
            .map_err(|e| OverthroneError::Plugin(format!("Failed to instantiate WASM module: {}", e)))?;

        // Serialize args to JSON
        let args_json = serde_json::to_string(args)
            .map_err(|e| OverthroneError::Plugin(format!("Failed to serialize args: {}", e)))?;

        // Get memory export
        let memory = instance
            .get_memory(&mut store_clone, "memory")
            .ok_or_else(|| OverthroneError::Plugin("WASM module missing memory export".to_string()))?;

        // Allocate memory for command and args
        // For simplicity, we'll use a fixed offset. A real implementation would call an allocator function
        let command_offset = 1024;
        let args_offset = command_offset + command.len() + 1;

        // Write command to memory
        memory.write(&mut store_clone, command_offset, command.as_bytes())
            .map_err(|e| OverthroneError::Plugin(format!("Failed to write command to WASM memory: {}", e)))?;

        // Write args to memory
        memory.write(&mut store_clone, args_offset, args_json.as_bytes())
            .map_err(|e| OverthroneError::Plugin(format!("Failed to write args to WASM memory: {}", e)))?;

        // Call the plugin's execute function
        // Expected signature: execute(command_ptr: i32, command_len: i32, args_ptr: i32, args_len: i32) -> i32
        if let Ok(execute_func) = instance.get_typed_func::<(i32, i32, i32, i32), i32>(&mut store_clone, "plugin_execute") {
            let result_code = execute_func
                .call(
                    &mut store_clone,
                    (
                        command_offset as i32,
                        command.len() as i32,
                        args_offset as i32,
                        args_json.len() as i32,
                    ),
                )
                .map_err(|e| OverthroneError::Plugin(format!("WASM plugin_execute failed: {}", e)))?;

            // Collect logs from the execution
            let logs = store_clone.data().log_buffer.join("\n");

            Ok(PluginResult {
                success: result_code == 0,
                output: logs,
                data: HashMap::new(),
                artifacts: Vec::new(),
            })
        } else {
            Err(OverthroneError::Plugin(format!(
                "WASM module missing plugin_execute function for command '{}'",
                command
            )))
        }
    }

    async fn on_event(&self, event: &PluginEvent, _ctx: &PluginContext) -> Result<()> {
        // WASM event handling would follow a similar pattern to execute_command
        // For now, we'll just log it
        log::debug!("[plugin:wasm] Event received: {:?}", event);
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        log::info!("[plugin:wasm] Shutting down WASM plugin '{}'", self.manifest.name);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────

unsafe fn cstr_to_string(ptr: *const std::ffi::c_char) -> Result<String> {
    if ptr.is_null() {
        return Err(OverthroneError::Plugin("Null C string pointer".to_string()));
    }
    // Using unsafe block as required by #[warn(unsafe_op_in_unsafe_fn)]
    Ok(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().to_string())
}

fn default_manifest(
    id: &str,
    name: &str,
    version: &str,
    author: &str,
    desc: &str,
) -> PluginManifest {
    PluginManifest {
        id: id.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        author: author.to_string(),
        description: desc.to_string(),
        min_overthrone_version: None,
        plugin_type: PluginType::Native,
        capabilities: vec![],
        commands: vec![],
        needs_network: false,
        needs_admin: false,
    }
}

fn extract_wasm_manifest(wasm_bytes: &[u8]) -> Option<PluginManifest> {
    // WASM custom sections: look for "overthrone_manifest"
    // This is a simplified parser — a real impl would use wasmparser
    let _ = wasm_bytes;
    None
}

unsafe extern "C" {
    fn free(ptr: *mut std::ffi::c_void);
}

unsafe fn libc_free(ptr: *mut std::ffi::c_void) {
    // Wrap FFI call in unsafe block as required by #[warn(unsafe_op_in_unsafe_fn)]
    unsafe { free(ptr) };
}
