//! overthrone-hunter — Kerberos attack toolkit for Active Directory.
//!
//! Modules:
//! - `asreproast`    — Enumerate DONT_REQ_PREAUTH accounts, bulk AS-REP roast
//! - `kerberoast`    — Enumerate SPN accounts, bulk TGS extraction for offline cracking
//! - `constrained`   — Constrained delegation abuse via S4U2Self → S4U2Proxy chain
//! - `unconstrained` — Unconstrained delegation discovery & TGT capture
//! - `rbcd`          — Resource-Based Constrained Delegation via msDS-AllowedToActOnBehalfOfOtherIdentity
//! - `coerce`        — Authentication coercion (PetitPotam, PrinterBug, DFSCoerce)
//! - `tickets`       — Ticket management (import/export kirbi/ccache, request TGT/TGS)
//! - `crack`         — Inline hash cracking for AS-REP/Kerberoast/NTLM hashes
//! - `adidns`        — AD-Integrated DNS abuse (wildcard injection, record poisoning)
//! - `runner`        — Top-level orchestrator dispatching all hunt actions

pub mod adidns;
pub mod asreproast;
pub mod bad_successor;
pub mod coerce;
pub mod constrained;
pub mod crack;
pub mod kerberoast;
pub mod rbcd;
pub mod runner;
pub mod spray;
pub mod tickets;
pub mod unconstrained;
pub mod userenum;
pub mod attacks;
pub mod xp_dirtree;

// Re-exports for ergonomic use
pub use adidns::{
    AdidnsEnumResult, AdidnsInjectionResult, AdidnsRecord, DnsRecordType,
    check_permissions, enumerate_zone, inject_a_record, inject_aaaa_record,
    inject_wildcard, inject_wildcard_default, print_enum_summary, remove_record,
};
pub use bad_successor::{BadSuccessorExposure, DmsaObjectSignal, assess_bad_successor_exposure};
pub use crack::{
    CrackReport, CrackSource, CrackedCredential, crack_asrep_hashes, crack_hash, crack_hashes,
    crack_kerberoast_hashes,
};
pub use runner::{HuntAction, HuntConfig, HuntReport, run_hunt};
pub use spray::{SprayConfig, SprayResult, run_spray};
pub use tickets::{TicketFormat, TicketOps};
pub use userenum::{UserEnumConfig, UserEnumResult};
