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
//! - `vault`: Windows Vault / Credential Manager extraction (mimikatz vault::list + vault::cred)
//! - `browser_creds`: Browser credential extraction (Chrome, Edge, Brave, Firefox)
//! - `wifi_creds`: Wi-Fi profile credential decryption

pub mod bad_successor;
pub mod browser_creds;
pub mod certighost;
pub mod cg_check;
pub mod cred_dump;
pub mod cves;
pub mod dcshadow;
pub use dcshadow::{
    DcShadowConfig, DcShadowError, DcShadowPreflight, DcShadowResult, ShadowObject,
    build_dce_rpc_header, build_drs_add_entry_request, build_drs_bind_request,
    build_drs_replica_add_request, build_group_member_shadow_object, build_oxid_resolver_request,
    build_user_shadow_object, preflight_dcshadow, run_dcshadow,
};
pub mod dirsync;
pub mod dpapi_extract;
pub mod edr_bypass;
pub mod golden_dmsa;
pub mod ldap_force_update;
pub mod litterbox;
pub mod lsaiso;
pub mod opsec;
pub mod sherlock;
pub mod skeleton_key;
pub mod skeleton_key_dll;
pub mod syscall;
pub mod vault;
pub mod wifi_creds;
pub use bad_successor::{
    BadSuccessorConfig, BadSuccessorResult, cleanup_bad_successor, exploit_bad_successor,
};
pub use browser_creds::{
    BrowserCredential, BrowserExtractConfig, BrowserExtractResult, BrowserType,
    extract_browser_credentials,
};
pub use certighost::{
    CertighostConfig, CertighostError, CertighostResult, build_csr, certighost_auto_enroll,
    certighost_enroll,
};
pub use cg_check::{
    CgPreflightResult, CgSignal, ComprehensiveCgResult, CredentialGuardStatus, DomainCgAssessment,
    DomainCgPosture, ExtractionDecision, assess_domain_credential_guard,
    check_credential_guard_preflight, check_credential_guard_remote,
    check_credential_guard_via_wmi, choose_cred_extraction, comprehensive_cg_check,
};
pub use cred_dump::{
    CredDumpConfig, CredDumpResult, DumpMethod, ExtractedCredential, LocalCredDumper,
    LocalCredDumperConfig, LocalCredDumperResult, dump_local_credentials,
    dump_local_credentials_all, extract_lsass_creds,
};
pub use cves::{
    RbcdResult, SamAccountNameSpoofResult, ShadowCredentialsResult, cleanup_rbcd,
    cleanup_samname_spoof, cleanup_shadow_credentials, exploit_rbcd, exploit_samname_spoof,
    exploit_shadow_credentials, try_exploit_shadow_credentials,
};
pub use dirsync::{
    DIRSYNC_OID, DirSyncConfig, DirSyncEntry, DirSyncError, DirSyncResult, MAX_DIRSYNC_BYTES,
    OBJECT_SECURITY, build_dirsync_control, dirsync_enum, dirsync_full_sync, parse_dirsync_cookie,
};
pub use dpapi_extract::{
    DecryptedCredential, DecryptedMasterkeyInfo, DpapiExtractConfig, DpapiExtractResult,
    extract_dpapi_credentials, get_dpapi_backup_key_via_dcsync,
};
pub use edr_bypass::{
    EdrAssessment, EdrProduct, EtwAbolitionResult, EvasionStrategy, HookDetection, SleepMaskConfig,
    StealthResult, UnhookResult, abolish_etw_providers, apply_stealth_profile,
    assess_edr_landscape, deobfuscate_memory, detect_edr_drivers, detect_edr_processes,
    obfuscate_memory, resolve_clean_syscall_numbers, scan_ntdll_hooks, unhook_ntdll,
};
pub use golden_dmsa::{
    GoldenDmsaResult, KdsRootKey, ManagedServiceAccount, MsaPassword, derive_kds_msa_key,
    derive_nt_hash_from_kds_key, enumerate_msas, generate_msa_passwords, parse_kds_root_key,
};
pub use ldap_force_update::{
    ForceUpdateAttr, ForceUpdateConfig, ForceUpdateError, ForceUpdateResult, apply_force_update,
    check_force_update, remove_force_update,
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
pub use sherlock::{
    CveEntry, ExploitRecommendation, SherlockConfig, SherlockError, SherlockFinding,
    SherlockOutputFormat, SherlockResult, build_cve_database, check_cve_vulnerability,
    detect_os_version, enumerate_installed_kbs, format_sherlock_output,
    generate_exploit_recommendation, is_kb_installed, result_risk_score, run_sherlock,
    severity_score,
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
pub use vault::{
    VaultCredentialEntry, VaultExtractConfig, VaultExtractResult, WindowsVault,
    extract_vault_credentials,
};
pub use wifi_creds::{WifiExtractConfig, WifiExtractResult, WifiProfile, extract_wifi_credentials};
