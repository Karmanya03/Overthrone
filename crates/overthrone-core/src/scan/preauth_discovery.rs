//! Unified pre-authentication discovery module (Phase 3.5).
//!
//! Runs all unauthenticated reconnaissance checks in a single parallel pass:
//! - Port triage (AD common ports)
//! - NBNS node status query
//! - SMB protocol negotiation (dialect, signing, capabilities)
//! - SMB null session / guest session (share enumeration)
//! - LDAP rootDSE pre-bind probe (no auth required)
//! - LDAP anonymous bind (null session)
//! - MS-RPC null session enumeration (LSARPC, SRVSVC, EPMAPPER)
//! - Coercion endpoint detection (MS-RPRN, MS-EFSR, DFS)
//!
//! All checks run concurrently via `tokio::join!` for maximum speed.

use crate::error::Result;
use crate::proto::coerce::{CoercionResult, detect_coercion_endpoints};
use crate::proto::epm::{RpcNullSessionResult, rpc_null_session_enumeration};
use crate::proto::ldap::{LdapSession, RootDseInfo, probe_rootdse_raw};
use crate::proto::netbios::{NbnsNodeStatus, SmbNegotiateResult, netbios_discovery};
use crate::proto::smb::SmbSession;
use crate::scan::{ScanResult, quick_scan};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════

/// Complete pre-authentication discovery result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthDiscoveryResult {
    /// Target host or domain
    pub target: String,
    /// Duration of the entire discovery run
    pub duration_ms: u64,
    /// Port triage results
    pub port_triage: PortTriageResult,
    /// NetBIOS and SMB negotiation results
    pub netbios_smb: NetBiosSmbResult,
    /// LDAP discovery results
    pub ldap: LdapDiscoveryResult,
    /// RPC null session results
    pub rpc_null_session: RpcNullSessionResult,
    /// Coercion endpoint detection results
    pub coercion: CoercionDiscoveryResult,
    /// Summary of findings for quick review
    pub summary: DiscoverySummary,
}

/// Port triage result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortTriageResult {
    /// Whether port scanning succeeded
    pub success: bool,
    /// Open ports found
    pub open_ports: Vec<ScanResult>,
    /// LDAP (389) is open
    pub ldap_open: bool,
    /// LDAPS (636) is open
    pub ldaps_open: bool,
    /// SMB (445) is open
    pub smb_open: bool,
    /// Kerberos (88) is open
    pub kerberos_open: bool,
    /// RPC (135) is open
    pub rpc_open: bool,
}

/// Combined NetBIOS and SMB negotiation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetBiosSmbResult {
    /// NBNS node status (if available)
    pub nbns: Option<NbnsNodeStatus>,
    /// SMB negotiation details
    pub smb_negotiate: Option<SmbNegotiateResult>,
    /// SMB null/guest session result
    pub smb_session: SmbSessionResult,
}

/// SMB session discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbSessionResult {
    /// Session type: null, guest, or denied
    pub session_type: String,
    /// Accessible shares
    pub accessible_shares: Vec<String>,
    /// Whether IPC$ is accessible
    pub ipc_accessible: bool,
}

/// LDAP discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapDiscoveryResult {
    /// rootDSE pre-bind probe result
    pub rootdse_probe: Option<RootDseInfo>,
    /// Whether anonymous bind succeeded
    pub anonymous_bind: bool,
    /// Naming contexts from anonymous session
    pub naming_contexts: Vec<String>,
    /// Supported SASL mechanisms
    pub sasl_mechanisms: Vec<String>,
    /// DNS hostname from rootDSE
    pub dns_hostname: Option<String>,
    /// Domain functionality level
    pub domain_functionality: Option<String>,
}

/// Coercion endpoint discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoercionDiscoveryResult {
    /// Whether coercion detection was attempted
    pub attempted: bool,
    /// Detected coercion endpoints
    pub endpoints: Vec<CoercionResult>,
    /// MS-RPRN (PrinterBug) available
    pub rprn_available: bool,
    /// MS-EFSR (PetitPotam) available
    pub efsr_available: bool,
    /// DFS coerce available
    pub dfs_available: bool,
}

/// Quick summary of findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverySummary {
    /// Discovered domain name
    pub domain: Option<String>,
    /// Discovered DC hostname
    pub dc_hostname: Option<String>,
    /// OS name (if detected)
    pub os_name: Option<String>,
    /// SMB dialect
    pub smb_dialect: Option<String>,
    /// SMB signing required
    pub smb_signing_required: bool,
    /// Null session allowed
    pub null_session_allowed: bool,
    /// Anonymous LDAP allowed
    pub anonymous_ldap: bool,
    /// Coercion possible
    pub coercion_possible: bool,
    /// Accessible share count
    pub accessible_share_count: usize,
    /// RPC endpoint count
    pub rpc_endpoint_count: usize,
    /// Risk score (0-10)
    pub risk_score: u8,
}

// ═══════════════════════════════════════════════════════════
//  Unified Discovery
// ═══════════════════════════════════════════════════════════

/// Run complete pre-authentication discovery against a target.
/// All checks run in parallel for maximum speed.
pub async fn run_preauth_discovery(target: &str) -> Result<PreAuthDiscoveryResult> {
    let start = Instant::now();
    info!("[preauth-discovery] Starting unified pre-auth discovery on {target}");

    // Phase 1: Port triage (sequential, needed for conditional checks)
    let port_triage = run_port_triage(target).await;

    // Phase 2: Run all independent checks in parallel
    let nbns_smb_fut = run_netbios_smb(target, port_triage.smb_open);
    let ldap_fut = run_ldap_discovery(target, port_triage.ldap_open, port_triage.ldaps_open);
    let rpc_fut = run_rpc_null_session(target, port_triage.smb_open);
    let coercion_fut = run_coercion_detection(target, port_triage.rpc_open);

    let (netbios_smb, ldap, rpc_null_session, coercion) =
        tokio::join!(nbns_smb_fut, ldap_fut, rpc_fut, coercion_fut);

    // Build summary
    let summary = build_summary(
        &port_triage,
        &netbios_smb,
        &ldap,
        &rpc_null_session,
        &coercion,
    );

    let duration_ms = start.elapsed().as_millis() as u64;

    let result = PreAuthDiscoveryResult {
        target: target.to_string(),
        duration_ms,
        port_triage,
        netbios_smb,
        ldap,
        rpc_null_session,
        coercion,
        summary,
    };

    info!(
        "[preauth-discovery] Completed in {}ms. Risk score: {}/10",
        result.duration_ms, result.summary.risk_score
    );

    Ok(result)
}

// ═══════════════════════════════════════════════════════════
//  Individual Check Runners
// ═══════════════════════════════════════════════════════════

async fn run_port_triage(target: &str) -> PortTriageResult {
    info!("[preauth-discovery] Running port triage on {target}");

    match quick_scan(target).await {
        Ok(results) => {
            let open_ports: Vec<ScanResult> = results.into_iter().filter(|r| r.open).collect();
            let ldap_open = open_ports.iter().any(|r| r.port == 389);
            let ldaps_open = open_ports.iter().any(|r| r.port == 636);
            let smb_open = open_ports.iter().any(|r| r.port == 445);
            let kerberos_open = open_ports.iter().any(|r| r.port == 88);
            let rpc_open = open_ports.iter().any(|r| r.port == 135);

            PortTriageResult {
                success: true,
                open_ports,
                ldap_open,
                ldaps_open,
                smb_open,
                kerberos_open,
                rpc_open,
            }
        }
        Err(e) => {
            warn!("[preauth-discovery] Port triage failed: {e}");
            PortTriageResult {
                success: false,
                open_ports: Vec::new(),
                ldap_open: false,
                ldaps_open: false,
                smb_open: false,
                kerberos_open: false,
                rpc_open: false,
            }
        }
    }
}

async fn run_netbios_smb(target: &str, smb_open: bool) -> NetBiosSmbResult {
    if !smb_open {
        debug!("[preauth-discovery] SMB not open, skipping NetBIOS/SMB checks");
        return NetBiosSmbResult {
            nbns: None,
            smb_negotiate: None,
            smb_session: SmbSessionResult {
                session_type: "skipped".to_string(),
                accessible_shares: Vec::new(),
                ipc_accessible: false,
            },
        };
    }

    info!("[preauth-discovery] Running NetBIOS/SMB discovery on {target}");

    // NBNS + SMB negotiate (combined in netbios_discovery)
    let nb_result = netbios_discovery(target).await;
    let nbns = nb_result.nbns;
    let smb_negotiate = nb_result.smb_negotiate;

    // SMB null/guest session
    let smb_session = run_smb_session(target).await;

    NetBiosSmbResult {
        nbns,
        smb_negotiate,
        smb_session,
    }
}

async fn run_smb_session(target: &str) -> SmbSessionResult {
    // Try null session first
    match SmbSession::connect(target, "", "", "").await {
        Ok(smb) => {
            let shares = ["IPC$", "NETLOGON", "SYSVOL", "C$", "ADMIN$"];
            let mut accessible = Vec::new();
            for share in &shares {
                if smb.check_share_read(share).await {
                    accessible.push(share.to_string());
                }
            }
            let ipc_accessible = accessible.iter().any(|s| s == "IPC$");
            SmbSessionResult {
                session_type: "null".to_string(),
                accessible_shares: accessible,
                ipc_accessible,
            }
        }
        Err(_) => {
            // Try guest session
            match SmbSession::connect(target, ".", "guest", "").await {
                Ok(smb) => {
                    let shares = ["IPC$", "NETLOGON", "SYSVOL"];
                    let mut accessible = Vec::new();
                    for share in &shares {
                        if smb.check_share_read(share).await {
                            accessible.push(share.to_string());
                        }
                    }
                    let ipc_accessible = accessible.iter().any(|s| s == "IPC$");
                    SmbSessionResult {
                        session_type: "guest".to_string(),
                        accessible_shares: accessible,
                        ipc_accessible,
                    }
                }
                Err(e) => {
                    debug!("[preauth-discovery] SMB guest session failed: {e}");
                    SmbSessionResult {
                        session_type: "denied".to_string(),
                        accessible_shares: Vec::new(),
                        ipc_accessible: false,
                    }
                }
            }
        }
    }
}

async fn run_ldap_discovery(
    target: &str,
    ldap_open: bool,
    ldaps_open: bool,
) -> LdapDiscoveryResult {
    if !ldap_open && !ldaps_open {
        debug!("[preauth-discovery] LDAP/LDAPS not open, skipping LDAP checks");
        return LdapDiscoveryResult {
            rootdse_probe: None,
            anonymous_bind: false,
            naming_contexts: Vec::new(),
            sasl_mechanisms: Vec::new(),
            dns_hostname: None,
            domain_functionality: None,
        };
    }

    info!("[preauth-discovery] Running LDAP discovery on {target}");

    let mut result = LdapDiscoveryResult {
        rootdse_probe: None,
        anonymous_bind: false,
        naming_contexts: Vec::new(),
        sasl_mechanisms: Vec::new(),
        dns_hostname: None,
        domain_functionality: None,
    };

    // Try rootDSE pre-bind probe (works even when anonymous bind is disabled)
    if ldap_open {
        match probe_rootdse_raw(target, false).await {
            Ok(rootdse) => {
                result.rootdse_probe = Some(rootdse.clone());
                result.dns_hostname = rootdse.dns_domain_name.clone();
                result.sasl_mechanisms = rootdse.supported_sasl_mechanisms.clone();
                result.naming_contexts = rootdse.naming_contexts.clone();
                result.domain_functionality = rootdse.domain_functionality.clone();
                debug!("[preauth-discovery] rootDSE probe succeeded");
            }
            Err(e) => {
                debug!("[preauth-discovery] rootDSE probe failed: {e}");
            }
        }
    }

    // Try LDAPS rootDSE probe if LDAPS is open
    if ldaps_open && result.rootdse_probe.is_none() {
        match probe_rootdse_raw(target, true).await {
            Ok(rootdse) => {
                result.rootdse_probe = Some(rootdse.clone());
                result.dns_hostname = rootdse.dns_domain_name.clone();
                result.sasl_mechanisms = rootdse.supported_sasl_mechanisms.clone();
                result.naming_contexts = rootdse.naming_contexts.clone();
                result.domain_functionality = rootdse.domain_functionality.clone();
                debug!("[preauth-discovery] LDAPS rootDSE probe succeeded");
            }
            Err(e) => {
                debug!("[preauth-discovery] LDAPS rootDSE probe failed: {e}");
            }
        }
    }

    // Try anonymous LDAP bind (may fail on Windows 2025)
    if ldap_open && let Ok(mut ldap) = LdapSession::connect_anonymous(target, "", false).await {
        result.anonymous_bind = true;
        if result.naming_contexts.is_empty()
            && let Ok(entries) = ldap
                .custom_search_with_base(
                    "",
                    "(objectClass=*)",
                    &["namingContexts", "defaultNamingContext"],
                )
                .await
            && let Some(entry) = entries.first()
            && let Some(contexts) = entry.attrs.get("namingContexts")
        {
            result.naming_contexts = contexts.clone();
        }
        let _ = ldap.disconnect().await;
    }

    result
}

async fn run_rpc_null_session(target: &str, smb_open: bool) -> RpcNullSessionResult {
    if !smb_open {
        debug!("[preauth-discovery] SMB not open, skipping RPC null session");
        return RpcNullSessionResult {
            target: target.to_string(),
            lsa_domain_info: None,
            lsa_policy_info: None,
            srvsvc_shares: Vec::new(),
            epmapper_endpoints: Vec::new(),
        };
    }

    info!("[preauth-discovery] Running RPC null session enumeration on {target}");

    match rpc_null_session_enumeration(target).await {
        Ok(result) => result,
        Err(e) => {
            debug!("[preauth-discovery] RPC null session failed: {e}");
            RpcNullSessionResult {
                target: target.to_string(),
                lsa_domain_info: None,
                lsa_policy_info: None,
                srvsvc_shares: Vec::new(),
                epmapper_endpoints: Vec::new(),
            }
        }
    }
}

async fn run_coercion_detection(target: &str, rpc_open: bool) -> CoercionDiscoveryResult {
    if !rpc_open {
        debug!("[preauth-discovery] RPC not open, skipping coercion detection");
        return CoercionDiscoveryResult {
            attempted: false,
            endpoints: Vec::new(),
            rprn_available: false,
            efsr_available: false,
            dfs_available: false,
        };
    }

    info!("[preauth-discovery] Running coercion endpoint detection on {target}");

    match detect_coercion_endpoints(target).await {
        Ok(endpoints) => {
            let rprn_available = endpoints.iter().any(|e| e.technique.contains("rprn"));
            let efsr_available = endpoints.iter().any(|e| e.technique.contains("efsr"));
            let dfs_available = endpoints.iter().any(|e| e.technique.contains("dfs"));

            CoercionDiscoveryResult {
                attempted: true,
                endpoints,
                rprn_available,
                efsr_available,
                dfs_available,
            }
        }
        Err(e) => {
            debug!("[preauth-discovery] Coercion detection failed: {e}");
            CoercionDiscoveryResult {
                attempted: true,
                endpoints: Vec::new(),
                rprn_available: false,
                efsr_available: false,
                dfs_available: false,
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Summary Builder
// ═══════════════════════════════════════════════════════════

fn build_summary(
    _ports: &PortTriageResult,
    netbios_smb: &NetBiosSmbResult,
    ldap: &LdapDiscoveryResult,
    rpc: &RpcNullSessionResult,
    coercion: &CoercionDiscoveryResult,
) -> DiscoverySummary {
    let domain = ldap
        .rootdse_probe
        .as_ref()
        .and_then(|r| r.dns_domain_name.clone())
        .or_else(|| {
            rpc.lsa_domain_info
                .as_ref()
                .and_then(|d| d.dns_domain.clone())
        });

    let dc_hostname = ldap
        .rootdse_probe
        .as_ref()
        .and_then(|r| r.dns_host_name.clone())
        .or_else(|| netbios_smb.nbns.as_ref().map(|n| n.computer_name.clone()));

    let os_name = netbios_smb
        .smb_negotiate
        .as_ref()
        .and_then(|s| s.os_name.clone());

    let smb_dialect = netbios_smb
        .smb_negotiate
        .as_ref()
        .map(|s| s.highest_dialect.clone());

    let smb_signing_required = netbios_smb
        .smb_negotiate
        .as_ref()
        .map(|s| s.signing_required)
        .unwrap_or(false);

    let null_session_allowed = netbios_smb.smb_session.session_type == "null"
        || netbios_smb.smb_session.session_type == "guest";

    let anonymous_ldap = ldap.anonymous_bind;

    let coercion_possible =
        coercion.rprn_available || coercion.efsr_available || coercion.dfs_available;

    let accessible_share_count = netbios_smb.smb_session.accessible_shares.len();
    let rpc_endpoint_count = rpc.epmapper_endpoints.len();

    // Calculate risk score (0-10)
    let mut risk_score: u8 = 0;
    if null_session_allowed {
        risk_score += 2;
    }
    if anonymous_ldap {
        risk_score += 2;
    }
    if coercion_possible {
        risk_score += 2;
    }
    if !smb_signing_required {
        risk_score += 1;
    }
    if accessible_share_count > 2 {
        risk_score += 1;
    }
    if rpc_endpoint_count > 5 {
        risk_score += 1;
    }
    if ldap.anonymous_bind && !ldap.naming_contexts.is_empty() {
        risk_score += 1;
    }

    DiscoverySummary {
        domain,
        dc_hostname,
        os_name,
        smb_dialect,
        smb_signing_required,
        null_session_allowed,
        anonymous_ldap,
        coercion_possible,
        accessible_share_count,
        rpc_endpoint_count,
        risk_score,
    }
}
