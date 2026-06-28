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
//! - `html`        — HTML report renderer (standalone, embedded CSS)
//! - `pdf`         — PDF report renderer (via printpdf)
//! - `runner`      — Top-level report generation orchestrator

pub mod html;
pub mod mapper;
pub mod markdown;
pub mod mitigations;
pub mod narrative;
pub mod pdf;
pub mod pipeline;
pub mod runner;
pub mod session;
pub mod xlsx;

// Re-exports
pub use runner::{
    ReportConfig, ReportFormat, ReportOutput, generate_from_file, generate_from_session,
    generate_report, load_session, merge_sessions, save_session,
};
pub use session::{
    EngagementSession, EvidenceItem, Finding, OperatorMetadata, Severity, TimelineDay,
};
pub use xlsx::generate_xlsx_report;

#[cfg(test)]
mod tests {
    #[test]
    fn test_modules_accessible() {
        let _ = crate::mapper::MitreMapping::new("T0000", "Test", "TA0000", None);
        let _ = crate::mitigations::MitigationPriority::Immediate;
        let _ = crate::session::Severity::Critical;
        let _ = crate::narrative::executive_summary;
        let _ = crate::markdown::render;
    }
}
