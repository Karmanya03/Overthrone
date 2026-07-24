//! Post-Exploitation Modules
//!
//! Implements post-exploitation techniques that require active access
//! to a compromised system (typically domain controller admin access).
//!
//! # Modules
//! - `skeleton_key`: LSASS authentication bypass via msv1_0.dll patching
//! - `skeleton_key_dll`: Embedded native DLL bytes for reflective injection
//! - `opsec`: AMSI bypass, ETW patching, direct syscall infrastructure
//! - `edr_bypass`: Next-gen EDR detection, ntdll unhooking, ETW abolition, sleep masking
//! - `cves`: CVE exploit modules (sAMAccountName spoofing, Shadow Credentials, RBCD)
//! - `litterbox`: Compile-time string obfuscation (static signature evasion)

pub mod cg_check;
pub mod cred_dump;
pub mod cves;
pub mod dpapi_extract;
pub mod edr_bypass;
pub mod litterbox;
pub mod lsaiso;
pub mod opsec;
pub mod skeleton_key;
pub mod skeleton_key_dll;
pub mod syscall;

pub use cg_check::{
    CgPreflightResult, CgSignal, ComprehensiveCgResult, CredentialGuardStatus, DomainCgAssessment,
    DomainCgPosture, ExtractionDecision, assess_domain_credential_guard,
    check_credential_guard_preflight, check_credential_guard_remote,
    check_credential_guard_via_wmi, choose_cred_extraction, comprehensive_cg_check,
};
pub use cred_dump::{
    CredDumpConfig, CredDumpResult, DumpMethod, ExtractedCredential, extract_lsass_creds,
};
pub use cves::{
    RbcdResult, SamAccountNameSpoofResult, ShadowCredentialsResult, cleanup_rbcd,
    cleanup_samname_spoof, cleanup_shadow_credentials, exploit_rbcd, exploit_samname_spoof,
    exploit_shadow_credentials, try_exploit_shadow_credentials,
};
pub use dpapi_extract::{
    DecryptedCredential, DecryptedMasterkeyInfo, DpapiExtractConfig, DpapiExtractResult,
    extract_dpapi_credentials,
};
pub use edr_bypass::{
    EdrAssessment, EdrProduct, EtwAbolitionResult, EvasionStrategy, HookDetection, SleepMaskConfig,
    StealthResult, UnhookResult, abolish_etw_providers, apply_stealth_profile,
    assess_edr_landscape, deobfuscate_memory, detect_edr_drivers, detect_edr_processes,
    obfuscate_memory, resolve_clean_syscall_numbers, scan_ntdll_hooks, unhook_ntdll,
};
pub use lsaiso::{
    CgBypassResult, LsaIsoBypassMethod, LsaIsoCredType, LsaIsoCredential, LsaIsoExtractionResult,
    LsaIsoExtractionStats, LsaIsoOpCode, LsaisoBypassConfig, extract_credentials_cg_bypass,
    extract_credentials_via_lsaiso, extract_credentials_via_lsaiso_memory, is_lsaiso_available,
};
pub use opsec::{
    AmsiBypassResult, EtwSuppressResult, HONEYPOT_ATTRS, OpsecConfig, OpsecPatchReport,
    SyscallResult, apply_opsec, check_credential_guard, contains_honeypot_attrs,
    early_bird_apc_injection, module_stomping_injection, patch_amsi, patch_amsi_direct,
    prefer_kerberos_etype, process_hollowing_injection, resolve_syscall_numbers,
    strip_honeypot_attrs, suppress_etw, suppress_etw_direct,
};
pub use skeleton_key::{
    DeploymentMethod, SkeletonKeyConfig, SkeletonKeyExploiter, SkeletonKeyPreflight,
    SkeletonKeyPreflightStatus, SkeletonKeyResult, assess_lsa_protection_values,
    assess_lsa_protection_values_with_isolated_secret, assess_skeleton_key_preflight_from_registry,
    default_skeleton_key,
};
pub use syscall::{
    DynamicSyscallStub, SyscallNumbers, SyscallStatus, syscall_0, syscall_1, syscall_2, syscall_3,
    syscall_4,
};
#[cfg(target_os = "windows")]
pub use syscall::{
    nt_allocate_virtual_memory, nt_close, nt_delay_execution, nt_open_key, nt_open_process,
    nt_protect_virtual_memory, nt_query_system_information, nt_query_value_key,
    nt_query_virtual_memory, nt_read_virtual_memory, nt_write_virtual_memory, prepare_syscall_stub,
};
