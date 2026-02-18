//! overthrone-crawler — AD trust traversal & cross-domain escalation engine.
//!
//! Analyzes reaper enumeration data to map trust relationships,
//! detect cross-domain attack paths, SID filtering gaps, foreign
//! group memberships, MSSQL link chains, and PAM trust abuse.

#![allow(dead_code, unused_imports, unused_variables)]

pub mod escalation;
pub mod foreign;
pub mod interrealm;
pub mod mssql_links;
pub mod pam;
pub mod runner;
pub mod sid_filter;
pub mod trust_map;

pub use runner::{CrawlerConfig, CrawlerResult, run_crawler};
