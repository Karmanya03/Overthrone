//! WinRM execution via native Win32 WSMan API (Windows only).
//!
//! Uses the `windows` crate (0.62.x) WSMan API with async callbacks
//! and Win32 Events for synchronization.  Full output collection via
//! `WSManReceiveShellOutput` loop.

use crate::error::{OverthroneError, Result};
use crate::exec::{ExecCredentials, ExecMethod, ExecOutput, RemoteExecutor};
use async_trait::async_trait;
use std::ffi::c_void;
use tracing::{debug, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::RemoteManagement::*;
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject};

// ── Constants ───────────────────────────────────────────────────

/// Negotiate (SPNEGO) auth — works for NTLM and Kerberos
const AUTH_NEGOTIATE: u32 = 2;

/// WS-Man shell URI for cmd.exe
const SHELL_URI: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

/// CommandState returned when a command finishes
const CMD_STATE_DONE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done";

/// Per-operation timeout in milliseconds
const OP_TIMEOUT_MS: u32 = 60_000;

// ── Helpers ─────────────────────────────────────────────────────

/// Create a null-terminated UTF-16 wide string.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn exec_err(target: &str, reason: &str) -> OverthroneError {
    OverthroneError::Exec {
        target: target.to_string(),
        reason: reason.to_string(),
    }
}

// ── Callback Context ────────────────────────────────────────────

/// Shared state between the WSMan callback and the calling thread.
///
/// The calling thread:
///   1. Resets the event + error fields
///   2. Calls a WSMan async function (passing `&async_op`)
///   3. `WaitForSingleObject(event, …)` blocks until the callback fires
///   4. Reads the results written by the callback
///
/// The WSMan runtime invokes `wsman_callback` on its own thread, writes
/// results into this struct, then signals the event.
struct WsCallbackCtx {
    event: HANDLE,
    error_code: u32,
    error_detail: String,
    shell: WSMAN_SHELL_HANDLE,
    command: WSMAN_COMMAND_HANDLE,
    stdout_buf: Vec<u8>,
    stderr_buf: Vec<u8>,
    cmd_done: bool,
    exit_code: u32,
}

impl WsCallbackCtx {
    fn new(event: HANDLE) -> Self {
        Self {
            event,
            error_code: 0,
            error_detail: String::new(),
            shell: WSMAN_SHELL_HANDLE::default(),
            command: WSMAN_COMMAND_HANDLE::default(),
            stdout_buf: Vec::new(),
            stderr_buf: Vec::new(),
            cmd_done: false,
            exit_code: 0,
        }
    }

    /// Reset per-operation state between WSMan calls.
    fn reset_op(&mut self) {
        self.error_code = 0;
        self.error_detail.clear();
        unsafe {
            let _ = ResetEvent(self.event);
        }
    }

    fn has_error(&self) -> bool {
        self.error_code != 0
    }
}

/// WSMan completion callback invoked by the WSMan runtime.
///
/// # Safety
///
/// `context` must point to a valid `WsCallbackCtx` that outlives all pending
/// WSMan operations.
unsafe extern "system" fn wsman_callback(
    context: *const c_void,
    _flags: u32,
    error: *const WSMAN_ERROR,
    shell: WSMAN_SHELL_HANDLE,
    command: WSMAN_COMMAND_HANDLE,
    _operation_handle: WSMAN_OPERATION_HANDLE,
    data: *const WSMAN_RESPONSE_DATA,
) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut WsCallbackCtx) };

    // ── Capture error ───────────────────────────────────────
    if !error.is_null() {
        let e = unsafe { &*error };
        ctx.error_code = e.code;
        if !e.errorDetail.0.is_null() {
            ctx.error_detail = unsafe { e.errorDetail.to_string() }.unwrap_or_default();
        }
    }

    // ── Capture handles (CreateShell / RunShellCommand) ─────
    if shell.0 != 0 {
        ctx.shell = shell;
    }
    if command.0 != 0 {
        ctx.command = command;
    }

    // ── Capture receive data (ReceiveShellOutput) ───────────
    if !data.is_null() {
        let resp = unsafe { &*data };
        let recv = unsafe { &resp.receiveData };

        // Check command state
        if !recv.commandState.0.is_null() {
            let state = unsafe { recv.commandState.to_string() }.unwrap_or_default();
            if state == CMD_STATE_DONE {
                ctx.cmd_done = true;
                ctx.exit_code = recv.exitCode;
            }
        }

        // Extract binary stream data
        if recv.streamData.r#type == WSMAN_DATA_TYPE_BINARY {
            let binary = unsafe { &recv.streamData.Anonymous.binaryData };
            if binary.dataLength > 0 && !binary.data.is_null() {
                let bytes =
                    unsafe { std::slice::from_raw_parts(binary.data, binary.dataLength as usize) };
                // Route to stdout or stderr based on stream ID
                let is_stderr = if !recv.streamId.0.is_null() {
                    let id = unsafe { recv.streamId.to_string() }.unwrap_or_default();
                    id.eq_ignore_ascii_case("stderr")
                } else {
                    false
                };
                if is_stderr {
                    ctx.stderr_buf.extend_from_slice(bytes);
                } else {
                    ctx.stdout_buf.extend_from_slice(bytes);
                }
            }
        }
    }

    // ── Signal caller ───────────────────────────────────────
    unsafe {
        let _ = SetEvent(ctx.event);
    }
}

// ── Executor ────────────────────────────────────────────────────

pub struct WinRmExecutor {
    creds: ExecCredentials,
}

impl WinRmExecutor {
    pub fn new(creds: ExecCredentials) -> Self {
        Self { creds }
    }
}

#[async_trait]
impl RemoteExecutor for WinRmExecutor {
    fn method(&self) -> ExecMethod {
        ExecMethod::WinRM
    }

    async fn execute(&self, target: &str, command: &str) -> Result<ExecOutput> {
        let target = target.to_string();
        let command = command.to_string();
        let creds = self.creds.clone();

        let t = target.clone();
        tokio::task::spawn_blocking(move || unsafe { execute_wsm(&t, &command, &creds) })
            .await
            .map_err(|e| exec_err(&target, &format!("WinRM task panic: {e}")))?
    }

    async fn check_available(&self, target: &str) -> bool {
        tokio::net::TcpStream::connect(format!("{target}:5985"))
            .await
            .is_ok()
            || tokio::net::TcpStream::connect(format!("{target}:5986"))
                .await
                .is_ok()
    }
}

// ── Core sync implementation ────────────────────────────────────

/// Wait for event or return timeout error.
unsafe fn wait_or_err(event: HANDLE, target: &str, op: &str) -> Result<()> {
    let rc = unsafe { WaitForSingleObject(event, OP_TIMEOUT_MS) };
    // WAIT_OBJECT_0 == 0
    if rc.0 != 0 {
        Err(exec_err(target, &format!("{op} timed out ({OP_TIMEOUT_MS}ms)")))
    } else {
        Ok(())
    }
}

/// Execute a command on `target` via the Win32 WSMan API.
///
/// # Safety
///
/// Calls Win32 FFI – valid parameters and correct handle lifetimes are ensured
/// by the implementation.
unsafe fn execute_wsm(
    target: &str,
    command: &str,
    creds: &ExecCredentials,
) -> Result<ExecOutput> {
    info!("[winrm/native] Executing on {target}: {command}");

    // ── Synchronization event (manual-reset, initially non-signaled) ──
    let event = unsafe { CreateEventW(None, true, false, None) }
        .map_err(|e| exec_err(target, &format!("CreateEventW: {e}")))?;

    let mut ctx = WsCallbackCtx::new(event);
    let ctx_ptr: *mut c_void = &mut ctx as *mut WsCallbackCtx as *mut c_void;
    let async_op = WSMAN_SHELL_ASYNC {
        operationContext: ctx_ptr,
        completionFunction: Some(wsman_callback as unsafe extern "system" fn(*const c_void, u32, *const WSMAN_ERROR, WSMAN_SHELL_HANDLE, WSMAN_COMMAND_HANDLE, WSMAN_OPERATION_HANDLE, *const WSMAN_RESPONSE_DATA)),
    };

    // ── 1  WSManInitialize ──────────────────────────────────────
    let mut api = WSMAN_API_HANDLE::default();
    let rc = unsafe { WSManInitialize(0, &mut api) };
    if rc != 0 {
        return Err(exec_err(target, &format!("WSManInitialize: {rc:#010x}")));
    }

    // ── 2  WSManCreateSession (with Negotiate auth) ─────────────
    let url = format!("http://{}:5985/wsman", target);
    let url_w = to_wide(&url);
    let qualified_user = if creds.domain.is_empty() {
        creds.username.clone()
    } else {
        format!("{}\\{}", creds.domain, creds.username)
    };
    let user_w = to_wide(&qualified_user);
    let pass_w = to_wide(&creds.password);

    let user_pw = WSMAN_USERNAME_PASSWORD_CREDS {
        username: PCWSTR(user_w.as_ptr()),
        password: PCWSTR(pass_w.as_ptr()),
    };
    let auth = WSMAN_AUTHENTICATION_CREDENTIALS {
        authenticationMechanism: AUTH_NEGOTIATE,
        Anonymous: WSMAN_AUTHENTICATION_CREDENTIALS_0 {
            userAccount: user_pw,
        },
    };

    let mut session = WSMAN_SESSION_HANDLE::default();
    let rc = unsafe {
        WSManCreateSession(
            api,
            PCWSTR(url_w.as_ptr()),
            0,
            Some(&auth),
            None,
            &mut session,
        )
    };
    if rc != 0 {
        unsafe { WSManDeinitialize(Some(api), 0) };
        return Err(exec_err(target, &format!("WSManCreateSession: {rc:#010x}")));
    }
    debug!("[winrm/native] Session created");

    // ── 3  WSManCreateShell ─────────────────────────────────────
    let uri_w = to_wide(SHELL_URI);
    ctx.reset_op();

    unsafe {
        WSManCreateShell(
            session,
            0,
            PCWSTR(uri_w.as_ptr()),
            None,
            None,
            None,
            &async_op,
        );
    }

    if let Err(e) = unsafe { wait_or_err(event, target, "CreateShell") } {
        unsafe { cleanup_api(api, session) };
        return Err(e);
    }
    if ctx.has_error() {
        let msg = format!("CreateShell: {} ({:#010x})", ctx.error_detail, ctx.error_code);
        unsafe { cleanup_api(api, session) };
        return Err(exec_err(target, &msg));
    }
    let shell = ctx.shell;
    debug!("[winrm/native] Shell created");

    // ── 4  WSManRunShellCommand ─────────────────────────────────
    let cmd_w = to_wide(command);
    ctx.reset_op();

    unsafe {
        WSManRunShellCommand(shell, 0, PCWSTR(cmd_w.as_ptr()), None, None, &async_op);
    }

    if let Err(e) = unsafe { wait_or_err(event, target, "RunShellCommand") } {
        unsafe { cleanup_shell(&async_op, event, api, session, shell) };
        return Err(e);
    }
    if ctx.has_error() {
        let msg = format!(
            "RunShellCommand: {} ({:#010x})",
            ctx.error_detail, ctx.error_code
        );
        unsafe { cleanup_shell(&async_op, event, api, session, shell) };
        return Err(exec_err(target, &msg));
    }
    let cmd_h = ctx.command;
    debug!("[winrm/native] Command started");

    // ── 5  WSManReceiveShellOutput loop ─────────────────────────
    let stdout_id_w = to_wide("stdout");
    let stderr_id_w = to_wide("stderr");
    let stream_ids = [
        PCWSTR(stdout_id_w.as_ptr()),
        PCWSTR(stderr_id_w.as_ptr()),
    ];
    let stream_set = WSMAN_STREAM_ID_SET {
        streamIDsCount: 2,
        streamIDs: stream_ids.as_ptr(),
    };

    loop {
        ctx.reset_op();

        unsafe {
            WSManReceiveShellOutput(shell, Some(cmd_h), 0, Some(&stream_set), &async_op);
        }

        if unsafe { wait_or_err(event, target, "ReceiveShellOutput") }.is_err() {
            warn!("[winrm/native] ReceiveShellOutput timed out — breaking");
            break;
        }
        if ctx.has_error() {
            debug!(
                "[winrm/native] Receive error: {} ({:#010x})",
                ctx.error_detail, ctx.error_code
            );
            break;
        }
        if ctx.cmd_done {
            debug!("[winrm/native] Command done (exit={})", ctx.exit_code);
            break;
        }
    }

    // Collect output
    let stdout = String::from_utf8_lossy(&ctx.stdout_buf).to_string();
    let stderr = String::from_utf8_lossy(&ctx.stderr_buf).to_string();
    let exit_code = ctx.exit_code as i32;

    // ── 6  Cleanup ──────────────────────────────────────────────
    // CloseCommand
    ctx.reset_op();
    unsafe {
        WSManCloseCommand(Some(cmd_h), 0, &async_op);
    }
    let _ = unsafe { WaitForSingleObject(event, 5_000) };

    // CloseShell
    ctx.reset_op();
    unsafe {
        WSManCloseShell(Some(shell), 0, &async_op);
    }
    let _ = unsafe { WaitForSingleObject(event, 5_000) };

    // CloseSession + Deinitialize
    unsafe {
        WSManCloseSession(Some(session), 0);
        WSManDeinitialize(Some(api), 0);
    }

    // Close event handle
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(event);
    }

    info!(
        "[winrm/native] Done: {} bytes stdout, {} bytes stderr, exit={}",
        stdout.len(),
        stderr.len(),
        exit_code
    );

    Ok(ExecOutput {
        stdout,
        stderr,
        exit_code: Some(exit_code),
        method: ExecMethod::WinRM,
    })
}

// ── Cleanup helpers ─────────────────────────────────────────────

/// Cleanup: session + API only (no shell yet).
unsafe fn cleanup_api(api: WSMAN_API_HANDLE, session: WSMAN_SESSION_HANDLE) {
    unsafe {
        WSManCloseSession(Some(session), 0);
        WSManDeinitialize(Some(api), 0);
    }
}

/// Cleanup: shell + session + API.
unsafe fn cleanup_shell(
    async_op: &WSMAN_SHELL_ASYNC,
    event: HANDLE,
    api: WSMAN_API_HANDLE,
    session: WSMAN_SESSION_HANDLE,
    shell: WSMAN_SHELL_HANDLE,
) {
    unsafe {
        WSManCloseShell(Some(shell), 0, async_op as *const WSMAN_SHELL_ASYNC);
        let _ = WaitForSingleObject(event, 5_000);
        WSManCloseSession(Some(session), 0);
        WSManDeinitialize(Some(api), 0);
    }
}
