//! overthrone-forge — Kerberos ticket forging & persistence engine.
//!
//! Forges Golden Tickets (krbtgt), Silver Tickets (service keys),
//! Diamond Tickets (legitimate TGT modification), inter-realm TGTs,
//! and persistence mechanisms (Skeleton Key, DSRM, DCSync users, ACL backdoors).

#![allow(dead_code, unused_imports)]

pub mod acl_backdoor;
pub mod cleanup;
pub mod dcsync_user;
pub mod diamond;
pub mod dsrm;
pub mod golden;
pub mod runner;
pub mod silver;
pub mod skeleton;
pub mod validate;

pub use runner::{ForgeConfig, ForgeResult, run_forge};
