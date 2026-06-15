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
pub mod adcs_dispatcher;
pub mod bronze_bit;
pub mod cert_auto_enroll;
pub mod cert_store;
pub mod cleanup;
pub mod convert;
pub mod dcsync_user;
pub mod diamond;
pub mod dsrm;
pub mod exec_util;
pub mod golden;
pub mod icert_passage;
pub mod ms_wcce_dcom;
pub mod nopac;
pub mod pkinit_auth;
pub mod runner;
pub mod s4u2self_pkinit;
pub mod sapphire;
pub mod shadow_credentials;
pub mod silver;
pub mod skeleton;
pub mod stealth;
pub mod validate;

pub use adcs_dispatcher::{AdcsAction, AdcsConfig, AdcsResult, run_adcs};
pub use cert_store::{
    parse_icertrequest_response, request_cert_via_rpc, request_cert_via_rpc_with_creds,
    request_cert_via_tcp_rpc,
};
pub use ms_wcce_dcom::{backup_ca_via_dcom, get_ca_certificate, request_cert_via_dcom};
pub use runner::{ForgeConfig, ForgeResult, run_forge};
pub use s4u2self_pkinit::{
    S4U2SelfPkinitConfig, S4U2SelfPkinitResult, run_s4u2self_pkinit, s4u2self_pkinit_only,
    s4u2self_pkinit_with_proxy,
};
pub use shadow_credentials::{
    ShadowCredentialsConfig, ShadowCredentialsResult, execute as shadow_credentials_attack,
};
