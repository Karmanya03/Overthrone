//! overthrone-reaper -- Active Directory enumeration engine.
//!
//! Queries LDAP to enumerate users, groups, computers, OUs, GPOs,
//! ACLs, SPNs, delegations, trusts, LAPS, and MSSQL SPNs.
//! Feeds results into overthrone-core's AttackGraph.

pub mod acls;
pub mod adcs;
pub mod computers;
pub mod delegations;
pub mod export;
pub mod file_carver;
pub mod gmsa;
pub mod gpos;
pub mod gpp_fetch;
pub mod groups;
pub mod laps;
pub mod laps_gmsa;
pub mod mssql;
pub mod mssql_audit;
pub mod ntlm_to_tgt;
pub mod ntlmv1_detection;
pub mod ous;
pub mod policy;
pub mod powerview;
pub mod risk_assessment;
pub mod runner;
pub mod snaffler;
pub mod spns;
pub mod trusts;
pub mod users;

pub use file_carver::{CarveResult, CarvedSecret, FileCarver, FileCarverConfig, carve_files};
pub use laps_gmsa::{
    CredentialEntry, CredentialSource, LapsGmsaResult, LapsGmsaStats, enumerate_laps_and_gmsa,
    format_entry,
};
pub use mssql_audit::{
    ConfigCategory, MssqlAuditSummary, MssqlConfigAudit, MssqlConfigCheck, audit_summary,
    build_mssql_audit_checks, categorize_check,
};
pub use ntlm_to_tgt::{NtlmToTgtConfig, NtlmToTgtResult, TgtCredential, run_ntlm_to_tgt};
pub use ntlmv1_detection::{
    DowngradeGuidance, NtlmV1Analysis, NtlmV1WorkflowResult, analyze_ntlm_hashes,
    generate_downgrade_guidance, run_ntlmv1_workflow,
};
pub use risk_assessment::{
    CategoryScore, RiskAssessmentResult, RiskCategory, RiskFinding, RiskLevel, assess_reaper_result,
};
pub use runner::{ReaperConfig, ReaperResult, run_reaper};
pub use snaffler::{SnaffleFinding, SnafflerConfig, run_snaffler};
