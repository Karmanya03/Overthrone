//! overthrone-scribe — Pentest report generation engine.
//!
//! Consumes engagement data from overthrone-pilot (and other crates)
//! and produces professional penetration testing reports in multiple
//! formats: Markdown, PDF, and JSON.
//!
//! Features:
//! - `session`     — Engagement session metadata, scope, and configuration
//! - `mapper`      — Map findings to MITRE ATT&CK techniques + CVSS scoring
//! - `mitigations` — Remediation recommendations per finding type
//! - `narrative`    — Human-readable narrative generation for findings
//! - `markdown`    — Markdown report renderer
//! - `pdf`         — PDF report renderer (via printpdf)
//! - `runner`      — Top-level report generation orchestrator

#![allow(dead_code, unused_imports)]

pub mod mapper;
pub mod markdown;
pub mod mitigations;
pub mod narrative;
pub mod pdf;
pub mod runner;
pub mod session;

// Re-exports
pub use runner::{
    generate_from_file, generate_from_session, generate_report, load_session,
    merge_sessions, save_session, ReportConfig, ReportFormat, ReportOutput,
};
pub use session::{EngagementSession, Finding, Severity};
