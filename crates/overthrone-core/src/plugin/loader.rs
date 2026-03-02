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
    /// Plugin-exported free function. When present, used instead of libc free()
    /// to deallocate strings returned by fn_execute, ensuring allocator compat.
    fn_free: Option<
        libloading::Symbol<'static, unsafe extern "C" fn(ptr: *mut std::ffi::c_char)>,
    >,
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
        let fn_execute: libloading::Symbol<
            'static,
            unsafe extern "C" fn(
                *const std::ffi::c_char,
                *const std::ffi::c_char,
                *const std::ffi::c_char,
            ) -> *mut std::ffi::c_char,
        > = std::mem::transmute(fn_execute);

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

        // Try to load plugin-side free() for allocator-safe deallocation
        let fn_free = library
            .get::<unsafe extern "C" fn(*mut std::ffi::c_char)>(b"overthrone_plugin_free")
            .ok();
        let fn_free = fn_free.map(|s| unsafe {
            std::mem::transmute::<
                _,
                libloading::Symbol<'static, unsafe extern "C" fn(*mut std::ffi::c_char)>,
            >(s)
        });

        if fn_free.is_none() {
            log::warn!(
                "[plugin:loader] {:?} does not export overthrone_plugin_free — \
                 falling back to libc free() (allocator mismatch possible)",
                path
            );
        }

        Ok(Box::new(NativePlugin {
            manifest,
            library,
            fn_execute,
            fn_on_event,
            fn_shutdown,
            fn_free,
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
        &mut self,
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
            // Use the plugin's own free function if available; otherwise fall
            // back to libc free (which may be wrong if the plugin used a
            // different allocator, but is the best we can do).
            if let Some(ref fn_free) = self.fn_free {
                fn_free(result_ptr);
            } else {
                libc_free(result_ptr as *mut std::ffi::c_void);
            }
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

/// A sandboxed WASM plugin.
///
/// After `init()`, the [`Store`], [`Instance`], and [`Linker`] are cached so
/// that `execute_command()` reuses the same WASM instance and preserves any
/// state the guest module accumulated (globals, linear memory, etc.).
pub struct WasmPlugin {
    manifest: PluginManifest,
    engine: Engine,
    module: Module,
    // Persisted across calls after init()
    store: Option<Store<WasmPluginState>>,
    instance: Option<Instance>,
    linker: Option<Linker<WasmPluginState>>,
    /// Monotonically increasing node ID counter for graph operations
    next_node_id: std::sync::atomic::AtomicI64,
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
        instance: None,
        linker: None,
        next_node_id: std::sync::atomic::AtomicI64::new(1),
    }))
}

/// Helper: define all host functions on a linker.
fn define_wasm_host_functions(linker: &mut Linker<WasmPluginState>) -> Result<()> {
    // log(ptr: i32, len: i32)
    linker
        .func_wrap(
            "env",
            "log",
            |mut caller: Caller<'_, WasmPluginState>, ptr: i32, len: i32| -> anyhow::Result<()> {
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
            },
        )
        .map_err(|e| OverthroneError::Plugin(format!("Failed to define log function: {}", e)))?;

    // graph_add_node(name_ptr, name_len, type_ptr, type_len) → i64
    linker
        .func_wrap(
            "env",
            "graph_add_node",
            |mut caller: Caller<'_, WasmPluginState>,
             name_ptr: i32,
             name_len: i32,
             type_ptr: i32,
             type_len: i32|
             -> i64 {
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
                let node_type =
                    String::from_utf8_lossy(&data[type_start..type_end]).to_string();

                let op = format!("add_node({}, {})", name, node_type);
                let state = caller.data_mut();
                state.graph_operations.push(op);

                // Return an auto-incremented node ID (stored in graph_operations length
                // as a simple counter that increases with each add_node call).
                state.graph_operations.len() as i64
            },
        )
        .map_err(|e| {
            OverthroneError::Plugin(format!("Failed to define graph_add_node: {}", e))
        })?;

    // graph_add_edge(from: i64, to: i64, type_ptr: i32, type_len: i32)
    linker
        .func_wrap(
            "env",
            "graph_add_edge",
            |mut caller: Caller<'_, WasmPluginState>,
             from: i64,
             to: i64,
             type_ptr: i32,
             type_len: i32| {
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

                let edge_type =
                    String::from_utf8_lossy(&data[type_start..type_end]).to_string();
                let op = format!("add_edge({}, {}, {})", from, to, edge_type);
                caller.data_mut().graph_operations.push(op);
            },
        )
        .map_err(|e| {
            OverthroneError::Plugin(format!("Failed to define graph_add_edge: {}", e))
        })?;

    Ok(())
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

        // Create and populate linker
        let mut linker = Linker::new(&self.engine);
        define_wasm_host_functions(&mut linker)?;

        // Instantiate the module with the linker
        let instance = linker.instantiate(&mut store, &self.module).map_err(|e| {
            OverthroneError::Plugin(format!("Failed to instantiate WASM module: {}", e))
        })?;

        // Call the plugin's init function if it exists
        if let Ok(init_func) = instance.get_typed_func::<(), ()>(&mut store, "plugin_init") {
            init_func
                .call(&mut store, ())
                .map_err(|e| OverthroneError::Plugin(format!("WASM plugin_init failed: {}", e)))?;
        }

        // Persist store, instance, and linker for reuse in execute_command
        self.store = Some(store);
        self.instance = Some(instance);
        self.linker = Some(linker);

        ctx.log_info(&format!(
            "WASM plugin '{}' initialized successfully",
            self.manifest.name
        ));
        Ok(())
    }

    async fn execute_command(
        &mut self,
        command: &str,
        args: &HashMap<String, String>,
        _ctx: &PluginContext,
    ) -> Result<PluginResult> {
        let store = self.store.as_mut().ok_or_else(|| {
            OverthroneError::Plugin("WASM plugin not initialized".to_string())
        })?;
        let instance = self.instance.as_ref().ok_or_else(|| {
            OverthroneError::Plugin("WASM plugin not initialized (no instance)".to_string())
        })?;

        // Serialize args to JSON
        let args_json = serde_json::to_string(args)
            .map_err(|e| OverthroneError::Plugin(format!("Failed to serialize args: {}", e)))?;

        // Get memory export
        let memory = instance
            .get_memory(store.as_context_mut(), "memory")
            .ok_or_else(|| {
                OverthroneError::Plugin("WASM module missing memory export".to_string())
            })?;

        // ── Allocate guest memory ──────────────────────────────
        // Try the plugin's exported `allocate(size) → ptr` function first.
        // Fall back to a fixed offset (1024) if the plugin doesn't export one.
        let total_bytes = command.len() + args_json.len() + 2; // +2 for safety

        let (command_offset, args_offset) = if let Ok(alloc_fn) =
            instance.get_typed_func::<i32, i32>(store.as_context_mut(), "allocate")
        {
            let cmd_ptr = alloc_fn
                .call(store.as_context_mut(), command.len() as i32)
                .map_err(|e| {
                    OverthroneError::Plugin(format!("WASM allocate() failed for command: {}", e))
                })? as usize;

            let args_ptr = alloc_fn
                .call(store.as_context_mut(), args_json.len() as i32)
                .map_err(|e| {
                    OverthroneError::Plugin(format!("WASM allocate() failed for args: {}", e))
                })? as usize;

            (cmd_ptr, args_ptr)
        } else {
            log::warn!(
                "[plugin:wasm] Plugin '{}' does not export allocate() — using fixed offset 1024",
                self.manifest.name
            );
            let cmd_off = 1024usize;
            let args_off = cmd_off + command.len() + 1;
            (cmd_off, args_off)
        };

        // Write command and args into guest memory
        memory
            .write(store.as_context_mut(), command_offset, command.as_bytes())
            .map_err(|e| {
                OverthroneError::Plugin(format!(
                    "Failed to write command to WASM memory: {}",
                    e
                ))
            })?;

        memory
            .write(store.as_context_mut(), args_offset, args_json.as_bytes())
            .map_err(|e| {
                OverthroneError::Plugin(format!("Failed to write args to WASM memory: {}", e))
            })?;

        // Call `plugin_execute(cmd_ptr, cmd_len, args_ptr, args_len) → i32`
        if let Ok(execute_func) = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(store.as_context_mut(), "plugin_execute")
        {
            let result_code = execute_func
                .call(
                    store.as_context_mut(),
                    (
                        command_offset as i32,
                        command.len() as i32,
                        args_offset as i32,
                        args_json.len() as i32,
                    ),
                )
                .map_err(|e| {
                    OverthroneError::Plugin(format!("WASM plugin_execute failed: {}", e))
                })?;

            // Optionally deallocate guest memory
            if let Ok(dealloc_fn) = instance
                .get_typed_func::<(i32, i32), ()>(store.as_context_mut(), "deallocate")
            {
                let _ = dealloc_fn.call(
                    store.as_context_mut(),
                    (command_offset as i32, command.len() as i32),
                );
                let _ = dealloc_fn.call(
                    store.as_context_mut(),
                    (args_offset as i32, args_json.len() as i32),
                );
            }

            // Collect logs from the execution
            let logs = store.data().log_buffer.join("\n");

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
        log::debug!("[plugin:wasm] Event received: {:?}", event);
        // Proper event forwarding would require &mut self; for now events are
        // logged but not forwarded into the WASM guest.
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        log::info!(
            "[plugin:wasm] Shutting down WASM plugin '{}'",
            self.manifest.name
        );
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

/// Parse a WASM binary for a custom section named `"overthrone_manifest"` and
/// deserialize its contents as JSON into a [`PluginManifest`].
///
/// WASM custom sections have the following layout:
/// - Section id byte = 0x00
/// - Section size (LEB128 u32)
/// - Name length (LEB128 u32)
/// - Name bytes (UTF-8)
/// - Payload bytes (remaining section size minus name)
fn extract_wasm_manifest(wasm_bytes: &[u8]) -> Option<PluginManifest> {
    const CUSTOM_SECTION_ID: u8 = 0x00;
    const WASM_MAGIC: &[u8] = b"\0asm";
    const MANIFEST_SECTION_NAME: &str = "overthrone_manifest";

    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != WASM_MAGIC {
        return None;
    }

    // Skip 8-byte header (magic + version)
    let mut pos = 8;

    while pos < wasm_bytes.len() {
        // Read section id
        if pos >= wasm_bytes.len() {
            break;
        }
        let section_id = wasm_bytes[pos];
        pos += 1;

        // Read section size (LEB128)
        let (section_size, bytes_read) = read_leb128_u32(wasm_bytes, pos)?;
        pos += bytes_read;
        let section_end = pos + section_size as usize;

        if section_end > wasm_bytes.len() {
            break;
        }

        if section_id == CUSTOM_SECTION_ID {
            // Read name length (LEB128)
            let (name_len, name_bytes_read) = read_leb128_u32(wasm_bytes, pos)?;
            let name_start = pos + name_bytes_read;
            let name_end = name_start + name_len as usize;

            if name_end > section_end {
                pos = section_end;
                continue;
            }

            let name = std::str::from_utf8(&wasm_bytes[name_start..name_end]).ok()?;

            if name == MANIFEST_SECTION_NAME {
                let payload = &wasm_bytes[name_end..section_end];
                match serde_json::from_slice::<PluginManifest>(payload) {
                    Ok(manifest) => {
                        log::info!(
                            "[plugin:loader] Extracted manifest from WASM custom section: {}",
                            manifest.name
                        );
                        return Some(manifest);
                    }
                    Err(e) => {
                        log::warn!(
                            "[plugin:loader] Failed to parse overthrone_manifest JSON: {}",
                            e
                        );
                        return None;
                    }
                }
            }
        }

        pos = section_end;
    }

    None
}

/// Read an unsigned LEB128-encoded u32 from `data` starting at `offset`.
/// Returns `(value, bytes_consumed)` or `None` on overflow / truncation.
fn read_leb128_u32(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut pos = offset;

    loop {
        if pos >= data.len() || shift >= 35 {
            return None;
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((result, pos - offset));
        }
        shift += 7;
    }
}

unsafe extern "C" {
    fn free(ptr: *mut std::ffi::c_void);
}

/// Fallback deallocation via libc `free()`. Only used when the native plugin
/// does not export `overthrone_plugin_free`.
unsafe fn libc_free(ptr: *mut std::ffi::c_void) {
    unsafe { free(ptr) };
}
