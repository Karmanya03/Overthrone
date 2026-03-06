//! overthrone-forge — Kerberos ticket forging & persistence engine.
//!
//! Forges Golden Tickets (krbtgt), Silver Tickets (service keys),
//! Diamond Tickets (legitimate TGT modification), inter-realm TGTs,
//! and persistence mechanisms:
//!
//! ## Ticket Forging
//! - **Golden Ticket** (`golden`): Forge TGT with krbtgt hash
//! - **Silver Ticket** (`silver`): Forge TGS for specific service
//! - **Diamond Ticket** (`diamond`): Modify legitimate TGT's PAC
//!
//! ## Persistence (Cross-Platform)
//! - **Shadow Credentials** (`shadow_credentials`): msDS-KeyCredentialLink manipulation
//! - **DSRM Backdoor** (`dsrm`): Sync DSRM password with domain account
//! - **DCSync User** (`dcsync_user`): Create hidden replication account
//! - **ACL Backdoor** (`acl_backdoor`): Inject DCSync rights
//!
//! ## Windows-Only (Requires C2 Session on DC)
//! - **Skeleton Key** (`skeleton`): LSASS patching (orchestration only)
//!
//! ## Cleanup
//! - **Cleanup** (`cleanup`): Remove artifacts and backdoors
//! - **Validate** (`validate`): Verify ticket validity

pub mod acl_backdoor;
pub mod cleanup;
pub mod dcsync_user;
pub mod diamond;
pub mod dsrm;
pub mod exec_util;
pub mod golden;
pub mod runner;
pub mod shadow_credentials;
pub mod silver;
pub mod skeleton;
pub mod validate;

pub use runner::{ForgeConfig, ForgeResult, run_forge};
pub use shadow_credentials::{ShadowCredentialsConfig, ShadowCredentialsResult, execute as shadow_credentials_attack};
