//! Post-Exploitation Modules
//!
//! Implements post-exploitation techniques that require active access
//! to a compromised system (typically domain controller admin access).
//!
//! # Modules
//! - `skeleton_key`: LSASS authentication bypass via msv1_0.dll patching
//! - `skeleton_key_dll`: Embedded native DLL bytes for reflective injection
//! - `opsec`: AMSI bypass, ETW patching, direct syscall infrastructure

pub mod cg_check;
pub mod opsec;
pub mod skeleton_key;
pub mod skeleton_key_dll;

pub use cg_check::{
    CgPreflightResult, CredentialGuardStatus, check_credential_guard_preflight,
    choose_cred_extraction,
};
pub use opsec::{
    AmsiBypassResult, EtwSuppressResult, HONEYPOT_ATTRS, OpsecConfig, OpsecPatchReport,
    SyscallResult, apply_opsec, check_credential_guard, contains_honeypot_attrs,
    early_bird_apc_injection, module_stomping_injection, patch_amsi, prefer_kerberos_etype,
    process_hollowing_injection, resolve_syscall_numbers, strip_honeypot_attrs, suppress_etw,
};
pub use skeleton_key::{
    DEFAULT_SKELETON_KEY, DeploymentMethod, SkeletonKeyConfig, SkeletonKeyExploiter,
    SkeletonKeyPreflight, SkeletonKeyPreflightStatus, SkeletonKeyResult,
    assess_lsa_protection_values, assess_lsa_protection_values_with_isolated_secret,
    assess_skeleton_key_preflight_from_registry,
};
