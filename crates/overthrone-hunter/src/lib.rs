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
//! - `runner`        — Top-level orchestrator dispatching all hunt actions

pub mod asreproast;
pub mod coerce;
pub mod constrained;
pub mod crack;
pub mod kerberoast;
pub mod rbcd;
pub mod runner;
pub mod tickets;
pub mod unconstrained;

// Re-exports for ergonomic use
pub use crack::{
    CrackReport, CrackSource, CrackedCredential, crack_asrep_hashes, crack_hash, crack_hashes,
    crack_kerberoast_hashes,
};
pub use runner::{HuntAction, HuntConfig, HuntReport, run_hunt};
pub use tickets::{TicketFormat, TicketOps};
