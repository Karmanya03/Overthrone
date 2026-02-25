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
// WASM plugin loader (placeholder — wasmtime integration)
// ──────────────────────────────────────────────────────────

/// A sandboxed WASM plugin
pub struct WasmPlugin {
    manifest: PluginManifest,
    #[allow(dead_code)]
    wasm_bytes: Vec<u8>,
}

pub fn load_wasm_plugin(path: &Path) -> Result<Box<dyn Plugin>> {
    log::info!("[plugin:loader] Loading WASM plugin from {:?}", path);

    let wasm_bytes = std::fs::read(path)
        .map_err(|e| OverthroneError::Plugin(format!("Cannot read WASM file {:?}: {}", path, e)))?;

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
        wasm_bytes,
    }))
}

#[async_trait]
impl Plugin for WasmPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, ctx: &PluginContext) -> Result<()> {
        ctx.log_info(&format!(
            "WASM plugin '{}' initialized ({} bytes)",
            self.manifest.name,
            self.wasm_bytes.len()
        ));
        // TODO: Initialize wasmtime::Engine, Module, Store, Instance
        // Expose host functions: log, graph_add_node, graph_add_edge, etc.
        Ok(())
    }

    async fn execute_command(
        &self,
        command: &str,
        args: &HashMap<String, String>,
        _ctx: &PluginContext,
    ) -> Result<PluginResult> {
        // TODO: Call WASM exported function via wasmtime
        // For now, return a stub
        Err(OverthroneError::Plugin(format!(
            "WASM execution not yet implemented for command '{}'",
            command
        )))
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
