//! Post-Exploitation Modules
//!
//! Implements post-exploitation techniques that require active access
//! to a compromised system (typically domain controller admin access).
//!
//! # Modules
//! - `skeleton_key`: LSASS authentication bypass via msv1_0.dll patching
//! - `skeleton_key_dll`: Embedded native DLL bytes for reflective injection

pub mod skeleton_key;
pub mod skeleton_key_dll;

pub use skeleton_key::{
    DEFAULT_SKELETON_KEY, DeploymentMethod, SkeletonKeyConfig, SkeletonKeyExploiter,
    SkeletonKeyPreflight, SkeletonKeyPreflightStatus, SkeletonKeyResult,
    assess_lsa_protection_values, assess_lsa_protection_values_with_isolated_secret,
    assess_skeleton_key_preflight_from_registry,
};
