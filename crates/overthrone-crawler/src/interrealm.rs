//! Inter-realm trust assessment surface.
//!
//! The live ticket-forging path is intentionally represented as a typed,
//! not-implemented API until the required Kerberos/PAC primitives exist in
//! `overthrone-core`. The assessment helpers still compile under
//! `--all-features` and report which trusts would require SID-filtering and
//! policy review before any operator action.

use crate::trust_map::{TrustDirection, TrustGraph, TrustKind};
use overthrone_core::{
    OverthroneError, Result,
    types::{DomainInfo, Sid},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidHistoryEntry {
    pub sid: Sid,
    pub attributes: u32,
}

pub const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

impl SidHistoryEntry {
    pub fn enabled(sid: Sid) -> Self {
        Self {
            sid,
            attributes: SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
        }
    }

    pub fn to_ndr_bytes(&self) -> Vec<u8> {
        let sid_bytes = self.sid.to_bytes();
        let mut buf = Vec::with_capacity(12 + sid_bytes.len());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&self.attributes.to_le_bytes());
        buf.extend_from_slice(&(self.sid.sub_authorities.len() as u32).to_le_bytes());
        buf.extend_from_slice(&sid_bytes);
        buf
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtraSids {
    pub entries: Vec<SidHistoryEntry>,
}

impl ExtraSids {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_enterprise_admin(&mut self, domain_sid: &Sid) {
        self.add_rid(domain_sid, 519);
    }

    pub fn add_domain_admin(&mut self, domain_sid: &Sid) {
        self.add_rid(domain_sid, 512);
    }

    pub fn add_schema_admin(&mut self, domain_sid: &Sid) {
        self.add_rid(domain_sid, 518);
    }

    pub fn add_sid(&mut self, sid: Sid) {
        self.entries.push(SidHistoryEntry::enabled(sid));
    }

    fn add_rid(&mut self, domain_sid: &Sid, rid: u32) {
        let mut sid = domain_sid.clone();
        sid.sub_authorities.push(rid);
        self.add_sid(sid);
    }

    pub fn to_ndr_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_ndr_bytes());
        }
        buf
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterRealmForgeConfig {
    pub source_domain: String,
    pub source_domain_sid: Sid,
    pub target_domain: String,
    pub target_domain_sid: Sid,
    pub trust_key: Vec<u8>,
    pub trust_key_etype: i32,
    pub impersonate_user: String,
    pub extra_sids: ExtraSids,
    pub lifetime_hours: u32,
}

impl InterRealmForgeConfig {
    pub fn enterprise_admin_attack(
        source_domain: &str,
        source_domain_sid: Sid,
        target_domain: &str,
        target_domain_sid: Sid,
        trust_key: Vec<u8>,
        trust_key_etype: i32,
        impersonate_user: &str,
    ) -> Self {
        let mut extra_sids = ExtraSids::new();
        extra_sids.add_enterprise_admin(&target_domain_sid);
        Self {
            source_domain: source_domain.to_string(),
            source_domain_sid,
            target_domain: target_domain.to_string(),
            target_domain_sid,
            trust_key,
            trust_key_etype,
            impersonate_user: impersonate_user.to_string(),
            extra_sids,
            lifetime_hours: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgedInterRealmTgt {
    pub ticket_bytes: Vec<u8>,
    pub session_key: Vec<u8>,
    pub service_principal: String,
    pub client_principal: String,
    pub kirbi: Vec<u8>,
    pub ccache: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidFilteringStatus {
    pub quarantine_enabled: bool,
    pub selective_auth: bool,
    pub trust_attributes: u32,
    pub trust_direction: TrustDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossForestResult {
    pub forged_tgt: Option<ForgedInterRealmTgt>,
    pub service_ticket: Option<Vec<u8>>,
    pub sid_filtering: SidFilteringStatus,
    pub attack_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossForestAttack {
    config: InterRealmForgeConfig,
}

impl CrossForestAttack {
    pub fn new(config: InterRealmForgeConfig) -> Self {
        Self { config }
    }

    pub async fn execute(&self) -> Result<CrossForestResult> {
        Err(OverthroneError::NotImplemented {
            module: format!(
                "interrealm live execution for {} -> {}",
                self.config.source_domain, self.config.target_domain
            ),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterRealmAttack {
    pub source_domain: String,
    pub target_domain: String,
    pub trust_kind: TrustKind,
    pub direction: TrustDirection,
    pub sid_filtering: bool,
    pub transitive: bool,
    pub uses_aes: bool,
    pub uses_rc4: bool,
    pub risk: String,
    pub operator_note: String,
}

pub fn find_interrealm_attacks(source_domain: &str, graph: &TrustGraph) -> Vec<InterRealmAttack> {
    let source = source_domain.to_uppercase();
    graph
        .trusts
        .iter()
        .filter(|trust| trust.source_domain == source)
        .filter(|trust| trust.direction.allows_outbound())
        .map(|trust| {
            let risk = if trust.sid_filtering {
                "blocked-by-sid-filtering"
            } else if trust.transitive {
                "review-required"
            } else {
                "non-transitive"
            };
            let operator_note = if trust.sid_filtering {
                "SID filtering is enabled; ExtraSids-style escalation should be treated as blocked."
            } else if trust.trust_type == TrustKind::Forest {
                "Forest trust without SID filtering requires explicit operator and policy review."
            } else {
                "Trust is outbound but may need additional policy and selective-auth review."
            };
            InterRealmAttack {
                source_domain: trust.source_domain.clone(),
                target_domain: trust.target_domain.clone(),
                trust_kind: trust.trust_type.clone(),
                direction: trust.direction.clone(),
                sid_filtering: trust.sid_filtering,
                transitive: trust.transitive,
                uses_aes: trust.uses_aes,
                uses_rc4: trust.uses_rc4,
                risk: risk.to_string(),
                operator_note: operator_note.to_string(),
            }
        })
        .collect()
}

pub fn forge_inter_realm_tgt(_config: &InterRealmForgeConfig) -> Result<ForgedInterRealmTgt> {
    Err(OverthroneError::NotImplemented {
        module: "interrealm ticket forging".to_string(),
    })
}

pub fn domain_to_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn domain_info_to_sid(domain: &DomainInfo) -> Option<Sid> {
    Sid::from_string(&domain.sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extra_sids_encoding_has_count_and_entries() {
        let sid = Sid::from_string("S-1-5-21-111-222-333").unwrap();
        let mut extra = ExtraSids::new();
        extra.add_enterprise_admin(&sid);

        let bytes = extra.to_ndr_bytes();
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert!(bytes.len() > sid.to_bytes().len());
    }

    #[test]
    fn test_find_interrealm_attacks_reports_outbound_trusts() {
        let graph = TrustGraph {
            domains: Vec::new(),
            trusts: vec![crate::trust_map::TrustEdge {
                source_domain: "CORP.LOCAL".to_string(),
                target_domain: "FOREST.LOCAL".to_string(),
                direction: TrustDirection::Outbound,
                trust_type: TrustKind::Forest,
                transitive: true,
                sid_filtering: false,
                tgt_delegation: false,
                is_within_forest: false,
                uses_aes: true,
                uses_rc4: false,
                is_pam_trust: false,
            }],
        };

        let findings = find_interrealm_attacks("corp.local", &graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, "review-required");
    }
}
