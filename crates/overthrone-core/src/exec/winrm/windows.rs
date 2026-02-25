//! WinRM execution via native Win32 WSMan API (Windows only).
//!
//! Uses the `windows` crate (0.62.x) typed handle API.

#![cfg(windows)]

use crate::error::{OverthroneError, Result};
use crate::exec::{ExecCredentials, ExecMethod, ExecOutput, RemoteExecutor};
use async_trait::async_trait;
use std::sync::Arc;
use windows::Win32::System::RemoteManagement::*;
use windows::core::PCWSTR;

/// Helper: create a null-terminated UTF-16 wide string
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Helper: create exec error with struct variant
fn exec_err(target: &str, reason: &str) -> OverthroneError {
    OverthroneError::Exec {
        target: target.to_string(),
        reason: reason.to_string(),
    }
}

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

        let target_clone = target.clone();
        let command_clone = command.clone();

        // WSMan API is blocking + COM, run on a blocking thread
        let result = tokio::task::spawn_blocking(move || unsafe {
            execute_winrm_sync(&target_clone, &command_clone, &creds)
        })
        .await
        .map_err(|e| exec_err(&target, &format!("WinRM task panic: {e}")))?;

        result
    }

    async fn check_available(&self, target: &str) -> bool {
        // Check if WinRM port (5985/5986) is reachable
        tokio::net::TcpStream::connect(format!("{target}:5985"))
            .await
            .is_ok()
            || tokio::net::TcpStream::connect(format!("{target}:5986"))
                .await
                .is_ok()
    }
}

unsafe fn execute_winrm_sync(
    target: &str,
    command: &str,
    creds: &ExecCredentials,
) -> Result<ExecOutput> {
    // 1. Initialize WSMan API
    let mut api_handle = WSMAN_API_HANDLE::default();
    let init_result = unsafe { WSManInitialize(0, &mut api_handle as *mut WSMAN_API_HANDLE) };
    if init_result != 0 {
        return Err(exec_err(
            target,
            &format!("WSManInitialize failed: {init_result}"),
        ));
    }

    // 2. Create session
    let conn_str = format!("http://{}:5985/wsman", target);
    let conn_wide = to_wide(&conn_str);

    let mut session_handle = WSMAN_SESSION_HANDLE::default();
    let session_result = unsafe {
        WSManCreateSession(
            api_handle,
            PCWSTR(conn_wide.as_ptr()),
            0,
            None, // auth credentials (None = current user / Negotiate)
            None, // proxy info
            &mut session_handle as *mut WSMAN_SESSION_HANDLE,
        )
    };
    if session_result != 0 {
        unsafe { WSManDeinitialize(Some(api_handle), 0) };
        return Err(exec_err(
            target,
            &format!("WSManCreateSession failed: {session_result}"),
        ));
    }

    // 3. Create shell
    let shell_uri = to_wide("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd");

    let mut async_data = WSMAN_SHELL_ASYNC::default();
    let mut shell_handle = WSMAN_SHELL_HANDLE::default();

    unsafe {
        WSManCreateShell(
            session_handle,
            0,
            PCWSTR(shell_uri.as_ptr()),
            None, // startup info
            None, // options
            None, // create xml
            &mut async_data as *const WSMAN_SHELL_ASYNC,
        )
    };

    // 4. Run command
    let command_wide = to_wide(command);
    let mut command_handle = WSMAN_COMMAND_HANDLE::default();

    unsafe {
        WSManRunShellCommand(
            shell_handle,
            0,
            PCWSTR(command_wide.as_ptr()),
            None, // args
            None, // options
            &mut async_data as *const WSMAN_SHELL_ASYNC,
        )
    };

    // 5. Receive output (simplified — real impl needs async callback loop)
    let stdout = String::from("(WinRM output collection not yet implemented)");
    let stderr = String::new();

    // 6. Cleanup
    unsafe {
        WSManCloseCommand(
            Some(command_handle),
            0,
            &async_data as *const WSMAN_SHELL_ASYNC,
        );
        WSManCloseShell(
            Some(shell_handle),
            0,
            &async_data as *const WSMAN_SHELL_ASYNC,
        );
        WSManCloseSession(Some(session_handle), 0);
        WSManDeinitialize(Some(api_handle), 0);
    }

    Ok(ExecOutput {
        stdout,
        stderr,
        exit_code: Some(0),
        method: ExecMethod::WinRM,
    })
}
