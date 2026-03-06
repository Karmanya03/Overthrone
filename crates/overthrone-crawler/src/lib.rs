//! overthrone-crawler — AD trust traversal & cross-domain escalation engine.
//!
//! Analyzes reaper enumeration data to map trust relationships,
//! detect cross-domain attack paths, SID filtering gaps, foreign
//! group memberships, MSSQL link chains, and PAM trust abuse.

pub mod escalation;
pub mod foreign;
pub mod mssql_links;
pub mod pam;
pub mod runner;
pub mod sid_filter;
pub mod trust_map;

// interrealm requires kerberos/crypto APIs not yet built
#[cfg(feature = "interrealm")]
pub mod interrealm;

pub use runner::{CrawlerConfig, CrawlerResult, run_crawler};

// Re-export the main analysis types (always available)
pub use foreign::{
    CrossForestMembership, ForeignMembership, ForeignSecurityPrincipal, TrustRelationship,
    analyze_foreign_memberships, enumerate_foreign_principals, enumerate_trusts,
};

// Re-export interrealm types only when feature is enabled
#[cfg(feature = "interrealm")]
pub use interrealm::{
    CrossForestAttack, ExtraSids, ForgedInterRealmTgt, InterRealmForgeConfig, SidFilteringStatus,
    SidHistoryEntry,
};
