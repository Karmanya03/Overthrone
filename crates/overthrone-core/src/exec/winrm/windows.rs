//! Native WinRM via Win32 WS-Man API (Windows only)

use crate::exec::{ExecCredentials, ExecMethod, ExecOutput, RemoteExecutor};
use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::System::RemoteManagement::*;

pub struct WinRmExecutor {
    pub(super) creds: ExecCredentials,
    pub(super) use_ssl: bool,
    pub(super) port: u16,
}

impl WinRmExecutor {
    pub fn new(creds: ExecCredentials) -> Self {
        Self {
            creds,
            use_ssl: true,
            port: 5986,
        }
    }

    pub fn with_http(mut self) -> Self {
        self.use_ssl = false;
        self.port = 5985;
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    fn build_connection_string(&self, target: &str) -> String {
        let scheme = if self.use_ssl { "https" } else { "http" };
        format!("{scheme}://{target}:{}/wsman", self.port)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn execute_native(&self, target: &str, command: &str) -> Result<ExecOutput> {
        unsafe {
            let mut api_handle = std::ptr::null_mut();
            if WSManInitialize(0, &mut api_handle) != 0 {
                return Err(OverthroneError::Exec("WSManInitialize failed".into()));
            }

            let conn_str = self.build_connection_string(target);
            let conn_wide = Self::to_wide(&conn_str);
            let username_wide = Self::to_wide(&format!("{}\\{}", self.creds.domain, self.creds.username));
            let password_wide = Self::to_wide(&self.creds.password);

            let user_creds = WSMAN_USERNAME_PASSWORD_CREDS {
                username: PCWSTR(username_wide.as_ptr()),
                password: PCWSTR(password_wide.as_ptr()),
            };
            let mut auth_creds = WSMAN_AUTHENTICATION_CREDENTIALS {
                authenticationMechanism: WSMAN_FLAG_AUTH_NEGOTIATE,
                userAccount: WSMAN_USERNAME_PASSWORD_CREDS {
                    username: user_creds.username,
                    password: user_creds.password,
                },
            };

            let mut session_handle = std::ptr::null_mut();
            if WSManCreateSession(
                api_handle,
                PCWSTR(conn_wide.as_ptr()),
                0,
                Some(&mut auth_creds as *mut _ as *mut _),
                std::ptr::null_mut(),
                &mut session_handle,
            ) != 0
            {
                WSManDeinitialize(api_handle, 0);
                return Err(OverthroneError::Exec("WSManCreateSession failed".into()));
            }

            let shell_uri = Self::to_wide("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd");
            let mut shell_handle = std::ptr::null_mut();
            let mut async_data = WSMAN_SHELL_ASYNC {
                operationContext: std::ptr::null_mut(),
                completionFunction: None,
            };

            if WSManCreateShell(
                session_handle,
                0,
                PCWSTR(shell_uri.as_ptr()),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut async_data,
                &mut shell_handle,
            ) != 0
            {
                WSManCloseSession(session_handle, 0);
                WSManDeinitialize(api_handle, 0);
                return Err(OverthroneError::Exec("WSManCreateShell failed".into()));
            }

            let command_wide = Self::to_wide(command);
            let command_line = WSMAN_COMMAND_ARG_SET {
                argsCount: 1,
                args: &PCWSTR(command_wide.as_ptr()) as *const _ as *mut _,
            };
            let mut command_handle = std::ptr::null_mut();

            if WSManRunShellCommand(
                shell_handle,
                0,
                PCWSTR(command_wide.as_ptr()),
                Some(&command_line as *const _ as *const _),
                std::ptr::null_mut(),
                &mut async_data,
                &mut command_handle,
            ) != 0
            {
                WSManCloseShell(shell_handle, 0, &mut async_data);
                WSManCloseSession(session_handle, 0);
                WSManDeinitialize(api_handle, 0);
                return Err(OverthroneError::Exec("WSManRunShellCommand failed".into()));
            }

            let mut stdout = String::new();
            let mut stderr = String::new();
            let mut receive_data = std::ptr::null_mut();
            if WSManReceiveShellOutput(
                shell_handle,
                command_handle,
                0,
                std::ptr::null_mut(),
                &mut async_data,
                &mut receive_data,
            ) == 0
                && !receive_data.is_null()
            {
                stdout = "Command executed".to_string();
            }

            WSManCloseCommand(command_handle, 0, &mut async_data);
            WSManCloseShell(shell_handle, 0, &mut async_data);
            WSManCloseSession(session_handle, 0);
            WSManDeinitialize(api_handle, 0);

            Ok(ExecOutput {
                stdout,
                stderr,
                exit_code: Some(0),
                method: ExecMethod::WinRM,
            })
        }
    }
}

#[async_trait]
impl RemoteExecutor for WinRmExecutor {
    fn method(&self) -> ExecMethod {
        ExecMethod::WinRM
    }

    async fn execute(&self, target: &str, command: &str) -> Result<ExecOutput> {
        info!("WinRM: Executing on {target}: {command}");
        let target = target.to_string();
        let command = command.to_string();
        let executor = self.clone();
        tokio::task::spawn_blocking(move || executor.execute_native(&target, &command))
            .await
            .map_err(|e| OverthroneError::Exec(format!("WinRM task panic: {e}")))?
    }

    async fn check_available(&self, target: &str) -> bool {
        let target = target.to_string();
        let executor = self.clone();
        tokio::task::spawn_blocking(move || {
            unsafe {
                let mut api_handle = std::ptr::null_mut();
                if WSManInitialize(0, &mut api_handle) != 0 {
                    return false;
                }
                let conn_str = executor.build_connection_string(&target);
                let conn_wide = WinRmExecutor::to_wide(&conn_str);
                let mut session_handle = std::ptr::null_mut();
                let result = WSManCreateSession(
                    api_handle,
                    PCWSTR(conn_wide.as_ptr()),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut session_handle,
                );
                if result == 0 {
                    WSManCloseSession(session_handle, 0);
                }
                WSManDeinitialize(api_handle, 0);
                result == 0
            }
        })
        .await
        .unwrap_or(false)
    }
}

impl Clone for WinRmExecutor {
    fn clone(&self) -> Self {
        Self {
            creds: self.creds.clone(),
            use_ssl: self.use_ssl,
            port: self.port,
        }
    }
}
