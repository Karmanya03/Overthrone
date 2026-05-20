//! overthrone-crawler — AD trust traversal & cross-domain escalation engine.
//!
//! Analyzes reaper enumeration data to map trust relationships,
//! detect cross-domain attack paths, SID filtering gaps, foreign
//! group memberships, MSSQL link chains, and PAM trust abuse.

pub mod cross_forest;
pub mod escalation;
pub mod foreign;
pub mod mssql_links;
pub mod pam;
pub mod pivot;
pub mod runner;
pub mod sid_filter;
pub mod trust_map;

// interrealm requires kerberos/crypto APIs not yet built
#[cfg(feature = "interrealm")]
pub mod interrealm;

pub use runner::{CrawlerConfig, CrawlerResult, run_crawler};

// Re-export cross-forest analysis types
pub use cross_forest::{
    CrossForestAssessment, CrossForestOpportunity, CrossForestTechnique, Severity,
    TrustKeyGuidance, build_trust_key_guidance, find_cross_forest_opportunities,
    run_cross_forest_assessment,
};

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

#[cfg(test)]
mod tests {
    #[test]
    fn test_modules_accessible() {
        let _ = crate::cross_forest::Severity::Critical;
        let _ = crate::escalation::EscalationTechnique::SidHistoryInjection;
        let _ = crate::foreign::TrustRelationship {
            name: "".into(),
            fqdn: "".into(),
            domain_sid: "".into(),
            direction: "".into(),
            trust_type: "".into(),
            trust_attributes: 0,
            sid_filtering: false,
            selective_auth: false,
            forest_transitive: false,
            tgt_delegation: false,
            tdo_dn: "".into(),
            attack_notes: vec![],
        };
        let _ = crate::mssql_links::LinkLoginType::Unknown;
        let _ = crate::pam::PamFindingType::NoPamTrustsFound;
        let _ = crate::runner::CrawlerResult {
            domain: "".into(),
            trust_map: crate::trust_map::TrustGraph::new(),
            foreign_memberships: vec![],
            escalation_paths: vec![],
            sid_filter_findings: vec![],
            mssql_chains: vec![],
            pam_findings: vec![],
            #[cfg(feature = "interrealm")]
            interrealm_attacks: vec![],
        };
        let _ = crate::sid_filter::SidFilterStatus::Enabled;
        let _ = crate::trust_map::TrustDirection::Bidirectional;
    }

    #[test]
    fn test_re_exports() {
        let _ = crate::CrawlerConfig {
            dc_ip: "".into(),
            domain: "".into(),
            base_dn: "".into(),
            username: "".into(),
            password: None,
            nt_hash: None,
            trusted_dc_ips: vec![],
            modules: vec![],
            max_depth: 5,
            auto_pivot: false,
        };
        let _ = crate::Severity::High;
        let _ = crate::build_trust_key_guidance("a", "b", "c");
    }
}
